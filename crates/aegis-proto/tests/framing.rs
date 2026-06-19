//! Wire-protocol robustness tests for `aegis-proto`'s length-prefixed JSON
//! framing (`write_message` / `read_message`).
//!
//! This target combines two complementary techniques:
//!
//!   * **Generative (`proptest`)** — a bottom-up strategy builds arbitrary
//!     [`Message`] values (every variant, including `EventBatch` carrying every
//!     `EventPayload` variant and the self-describing `Custom` escape hatch),
//!     and asserts that `write_message` -> `read_message` round-trips them
//!     losslessly, that two frames back-to-back decode without bleed, that any
//!     truncation of a valid frame yields `Closed`/`Io` (never a hang), and
//!     that arbitrary garbage bodies never panic.
//!
//!   * **Hand-written adversarial (`#[tokio::test]`)** — fixed byte streams and
//!     bespoke `AsyncRead` impls pin exact error variants and behaviors that
//!     randomness would only hit by luck: empty/partial headers, header-only,
//!     partial bodies, oversized/`u32::MAX` length prefixes (asserting
//!     `FrameTooLarge` *and* that no large allocation/read is performed),
//!     trickled bodies, chunk-boundary splits, the write-side over-cap guard,
//!     zero-length frames, trailing garbage, and the non-finite-float wire
//!     behavior that dictates why the generators emit only finite floats.
//!
//! ## Why the oracle is a float-aware `serde_json::Value` comparison
//!
//! Neither [`Message`], `Event`, nor `EventPayload` derives `PartialEq`, so the
//! round-trip cannot be checked with `==` on the message. It is checked by
//! converting both sides to `serde_json::Value` and comparing them with
//! `values_diff`, which is structural/exact for every JSON kind *except*
//! numbers stored as f64, which it compares numerically (exact, or within a
//! tiny relative tolerance).
//!
//! Plain `Value` equality (`==`) is *not* sufficient, and neither is a
//! "canonicalize once then compare" trick: serde_json's f64 text format and its
//! f64 parser are not mutual inverses for a meaningful fraction of values. For
//! example `-3.1791611711091207e-159` formats to that string, which *parses
//! back to a 1-ULP-different f64*, which then formats to a *different* string
//! (`-3.179161171109121e-159`) -- a stable 2-cycle with no fixed point. So no
//! number of canonicalizing passes makes a direct `Value` `==` reliable; any
//! such comparator is ~flaky on those values. The protocol nonetheless
//! round-trips the *number* to full f64 precision (the discrepancy is purely
//! serde_json's non-canonical float printing), which is exactly what the
//! numeric comparison in `values_diff` asserts. A bit-level f64 oracle would
//! be even more wrong for the same reason.
//!
//! ## Why every float strategy is finite
//!
//! The serde_json resolved in this workspace serializes non-finite f64
//! (`NaN`, `+/-Infinity`) as JSON `null`, which then fails to deserialize back
//! into the non-`Option<f64>` fields (`Score.score`, `Detection.confidence`,
//! `CommandObserved.shannon_entropy`, and `f64` map values). Generating
//! arbitrary f64 would therefore make the round-trip fail for a reason
//! unrelated to framing. The generators emit only finite floats; the exact
//! non-finite wire behavior is pinned separately by
//! `nonfinite_float_serializes_to_null_then_fails_decode`.
//!
//! ## Why `EventPayload::Custom` payloads are objects/null only
//!
//! `EventPayload` is an internally-tagged enum (`#[serde(tag = "type")]`) and
//! `Custom(serde_json::Value)` is a newtype variant; serde can only splice the
//! `"type"` tag into an object (or a `null`), so a `Custom` wrapping a
//! bool/number/string/array fails to *serialize* at all. The `Custom` generator
//! emits objects (or null) accordingly, and the limitation is pinned by
//! `custom_nonobject_payload_fails_to_serialize`. (`ServerCommand::SetConfig`'s
//! `config` is a plain field, not a tagged-newtype payload, so it accepts any
//! JSON value -- the broader `arb_json_value` is used there.)

use aegis_proto::{
    read_message, write_message, Message, ProtoError, ServerCommand, MAX_FRAME_BYTES,
};
use aegis_sdk::event::{Event, EventPayload, Severity, Verdict};
use proptest::collection::{btree_map, vec};
use proptest::option;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use uuid::Uuid;

// ===========================================================================
// Round-trip oracle (shared by every generative case)
// ===========================================================================

/// Canonicalize `msg` through one JSON encode/decode so any floats land on
/// their shortest-decimal fixed point, then assert that a real `write_message`
/// -> `read_message` round-trip over an in-memory duplex preserves the
/// canonical `serde_json::Value`.
///
/// Returns a `TestCaseError` rather than panicking so it can be `?`-propagated
/// inside `proptest!` bodies (which is how proptest records shrinkable
/// failures). The writer half is dropped as soon as the frame is written, so a
/// buggy reader that waits for more bytes cannot hang.
async fn check_roundtrips(msg: Message) -> Result<(), TestCaseError> {
    // The generators emit only serializable messages (finite floats; Custom
    // payloads are objects/null), so serialization is infallible here.
    let want = serde_json::to_value(&msg).expect("to_value(sent)");

    // Wire round-trip over an in-memory duplex.
    let (mut w, mut r) = tokio::io::duplex(1024 * 1024);
    let sent = msg;
    let writer = tokio::spawn(async move {
        write_message(&mut w, &sent).await.expect("write_message");
        // `w` is dropped here -> the write half closes, so a reader that expects
        // more bytes observes EOF instead of blocking forever.
    });
    let got = read_message(&mut r)
        .await
        .map_err(|e| TestCaseError::fail(format!("read_message failed on a valid frame: {e:?}")))?;
    writer
        .await
        .map_err(|e| TestCaseError::fail(format!("writer task panicked: {e:?}")))?;

    // Float-aware structural comparison (see `values_diff` / module docs).
    let got_val = serde_json::to_value(&got).expect("to_value(got)");
    if let Some(path) = values_diff(&want, &got_val) {
        return Err(TestCaseError::fail(format!(
            "round-trip mismatch at {path}\n  sent: {want}\n   got: {got_val}"
        )));
    }
    Ok(())
}

/// Compare two JSON values for round-trip equivalence. Everything is exact
/// except numbers stored as f64, which are compared numerically to absorb
/// serde_json's non-canonical float printing (see module docs): two f64 are
/// equivalent if they are bit-equal, or equal in value, or within a tiny
/// relative tolerance (`<= 1e-12 * max(|a|, |b|)`), which covers the ~1-ULP
/// serialize/parse oscillation while still catching any gross corruption. The
/// sign of zero must match exactly. Returns `Some(path)` describing the first
/// difference, or `None` if equivalent.
fn values_diff(a: &serde_json::Value, b: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match (a, b) {
        (Value::Null, Value::Null) => None,
        (Value::Bool(x), Value::Bool(y)) if x == y => None,
        (Value::String(x), Value::String(y)) if x == y => None,
        (Value::Number(x), Value::Number(y)) => {
            if numbers_equiv(x, y) {
                None
            } else {
                Some(format!("number ({x} vs {y})"))
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                return Some(format!("array length ({} vs {})", x.len(), y.len()));
            }
            for (i, (xe, ye)) in x.iter().zip(y).enumerate() {
                if let Some(p) = values_diff(xe, ye) {
                    return Some(format!("[{i}]{}{p}", path_sep(&p)));
                }
            }
            None
        }
        (Value::Object(x), Value::Object(y)) => {
            if x.len() != y.len() {
                return Some(format!("object size ({} vs {})", x.len(), y.len()));
            }
            for (k, xv) in x {
                match y.get(k) {
                    None => return Some(format!("missing key {k:?}")),
                    Some(yv) => {
                        if let Some(p) = values_diff(xv, yv) {
                            return Some(format!(".{k}{}{p}", path_sep(&p)));
                        }
                    }
                }
            }
            None
        }
        _ => Some(format!("kind mismatch ({a} vs {b})")),
    }
}

fn path_sep(rest: &str) -> &'static str {
    if rest.starts_with('[') || rest.starts_with('.') {
        ""
    } else {
        ": "
    }
}

/// True if two `serde_json::Number`s are round-trip equivalent. Integers (i64 /
/// u64) must be exactly equal. Floats are compared numerically with a tiny
/// relative tolerance and an exact sign-of-zero check.
fn numbers_equiv(x: &serde_json::Number, y: &serde_json::Number) -> bool {
    // Integer paths: require exact equality (no float fuzz for integers).
    if let (Some(xi), Some(yi)) = (x.as_i64(), y.as_i64()) {
        return xi == yi;
    }
    if let (Some(xu), Some(yu)) = (x.as_u64(), y.as_u64()) {
        return xu == yu;
    }
    match (x.as_f64(), y.as_f64()) {
        (Some(xf), Some(yf)) => floats_equiv(xf, yf),
        // Mixed integer/float (one fit i64/u64, the other didn't): fall back to
        // f64 value comparison if both convert, else not equivalent.
        _ => false,
    }
}

fn floats_equiv(a: f64, b: f64) -> bool {
    if a == b {
        // Distinguish +0.0 from -0.0: their sign bits must match.
        if a == 0.0 {
            return a.is_sign_negative() == b.is_sign_negative();
        }
        return true;
    }
    // Both finite (generators never emit non-finite); accept a ~1-ULP-class
    // relative difference from serde_json's float printing.
    let scale = a.abs().max(b.abs());
    (a - b).abs() <= 1e-12 * scale
}

/// A fresh single-threaded Tokio runtime per proptest case. Cheap because all
/// I/O here is in-memory; `proptest!` bodies are synchronous so each case drives
/// its async work to completion on this runtime.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
}

/// Frame `msg` by hand: a 4-byte big-endian length prefix followed by the JSON
/// body. Mirrors what `write_message` puts on the wire, but usable from sync
/// code and against `Cursor`.
fn frame_message(msg: &Message) -> Vec<u8> {
    let body = serde_json::to_vec(msg).expect("serialize");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

// ===========================================================================
// Leaf strategies
// ===========================================================================

/// FINITE f64 only (see module docs). Biased toward edge magnitudes that have
/// historically broken shortest-repr round-trips, plus a dense mid-range band.
fn finite_f64() -> impl Strategy<Value = f64> {
    prop_oneof![
        8 => any::<f64>().prop_filter("finite", |x| x.is_finite()),
        1 => Just(0.0_f64),
        1 => Just(-0.0_f64),
        1 => Just(f64::MIN_POSITIVE),
        1 => Just(f64::MAX),
        1 => Just(f64::MIN),
        1 => -1e308_f64..1e308_f64,
    ]
}

/// UUIDs from 16 arbitrary bytes (proptest has no built-in `Uuid` strategy).
fn arb_uuid() -> impl Strategy<Value = Uuid> {
    any::<[u8; 16]>().prop_map(Uuid::from_bytes)
}

/// `agent_pubkey` is typed `Vec<u8>`; exercise both the canonical 32-byte
/// length and arbitrary lengths (the codec must not care about the contents).
fn arb_pubkey() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => vec(any::<u8>(), 32..=32),
        1 => vec(any::<u8>(), 0..64),
    ]
}

/// Strings: arbitrary unicode plus deliberate JSON-escaping hazards (quotes,
/// backslashes, control chars, multibyte/emoji) and a few long ones.
fn arb_string() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => any::<String>(),
        1 => Just(String::new()),
        1 => Just("\"\\\n\t\r\u{0008}\u{001f}".to_string()),
        1 => Just("\u{1f600}\u{10FFFF}emoji-\u{975e}ascii".to_string()),
        1 => proptest::string::string_regex(".{200,400}").expect("valid regex"),
    ]
}

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn arb_verdict() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Human),
        Just(Verdict::Agent),
        Just(Verdict::Uncertain),
    ]
}

fn arb_features() -> impl Strategy<Value = BTreeMap<String, f64>> {
    btree_map(arb_string(), finite_f64(), 0..6)
}

// ===========================================================================
// Arbitrary serde_json::Value (drives EventPayload::Custom and
// ServerCommand::SetConfig.config)
// ===========================================================================

/// Recursive JSON value of any kind. Numbers are restricted to finite f64 /
/// i64 / u64 so the whole value is serializable and round-trips (see module
/// docs). Depth and node count are bounded so frames stay well under
/// `MAX_FRAME_BYTES` and shrinking stays fast.
///
/// This is the right strategy for `ServerCommand::SetConfig.config`, which is a
/// *named field* (any JSON value nests fine under the `"cmd"` tag). It is NOT
/// suitable as-is for `EventPayload::Custom` -- see `arb_custom_value`.
fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        any::<u64>().prop_map(|n| serde_json::json!(n)),
        finite_f64().prop_map(|f| {
            // `Number::from_f64` returns `None` only for non-finite input; we
            // feed finite only, so this never drops a value.
            serde_json::Value::Number(serde_json::Number::from_f64(f).expect("finite"))
        }),
        arb_string().prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
            btree_map(arb_string(), inner, 0..6)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

/// JSON values valid inside `EventPayload::Custom`.
///
/// `EventPayload` is an **internally-tagged** enum (`#[serde(tag = "type")]`),
/// and `Custom(serde_json::Value)` is a *newtype variant*. serde's internal
/// tagging has to splice the `"type"` key into the serialized payload, which it
/// can only do when the payload is a JSON **object** (or `null`, which serde
/// treats as a unit-like payload). A `Custom` wrapping a bool / number / string
/// / array therefore **fails to serialize** ("cannot serialize tagged newtype
/// variant ... containing a {kind}"). This is a real constraint of the wire
/// format and is pinned explicitly by
/// `custom_nonobject_payload_fails_to_serialize`; the generator must respect it
/// or it would emit `Message`s the protocol cannot put on the wire.
///
/// Top level is thus restricted to an object (whose *values* may be arbitrary
/// JSON via [`arb_json_value`]) or `null`.
fn arb_custom_value() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        8 => btree_map(arb_string(), arb_json_value(), 0..6)
            .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        1 => Just(serde_json::Value::Null),
    ]
}

// ===========================================================================
// EventPayload (every variant, including Custom)
// ===========================================================================

fn arb_payload() -> impl Strategy<Value = EventPayload> {
    prop_oneof![
        (
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            arb_string(),
            vec(arb_string(), 0..6),
            option::of(arb_string())
        )
            .prop_map(
                |(pid, ppid, uid, exe, cmdline, cwd)| EventPayload::ProcessExec {
                    pid,
                    ppid,
                    uid,
                    exe,
                    cmdline,
                    cwd
                }
            ),
        (
            arb_string(),
            option::of(arb_string()),
            arb_string(),
            option::of(arb_string())
        )
            .prop_map(
                |(session_id, tty, user, remote)| EventPayload::SessionStart {
                    session_id,
                    tty,
                    user,
                    remote
                }
            ),
        arb_string().prop_map(|session_id| EventPayload::SessionEnd { session_id }),
        (arb_string(), any::<u64>(), any::<bool>(), any::<u32>()).prop_map(
            |(session_id, inter_arrival_ns, is_paste, burst_len)| EventPayload::Keystroke {
                session_id,
                inter_arrival_ns,
                is_paste,
                burst_len
            }
        ),
        (
            arb_string(),
            any::<u32>(),
            any::<u32>(),
            finite_f64(),
            any::<bool>(),
            any::<u32>(),
            any::<u64>(),
            arb_string()
        )
            .prop_map(
                |(
                    session_id,
                    command_len,
                    token_count,
                    shannon_entropy,
                    had_backspace,
                    edit_distance_prev,
                    inter_command_ns,
                    command_hash,
                )| EventPayload::CommandObserved {
                    session_id,
                    command_len,
                    token_count,
                    shannon_entropy,
                    had_backspace,
                    edit_distance_prev,
                    inter_command_ns,
                    command_hash,
                }
            ),
        (arb_string(), arb_string(), finite_f64(), arb_features()).prop_map(
            |(subject, model, score, features)| EventPayload::Score {
                subject,
                model,
                score,
                features
            }
        ),
        (
            arb_string(),
            arb_verdict(),
            finite_f64(),
            arb_string(),
            vec(arb_string(), 0..5),
            arb_features()
        )
            .prop_map(|(subject, verdict, confidence, model, reasons, features)| {
                EventPayload::Detection {
                    subject,
                    verdict,
                    confidence,
                    model,
                    reasons,
                    features,
                }
            }),
        (
            arb_severity(),
            arb_string(),
            arb_string(),
            option::of(arb_string())
        )
            .prop_map(|(severity, title, detail, subject)| EventPayload::Alert {
                severity,
                title,
                detail,
                subject
            }),
        any::<u64>().prop_map(|uptime_s| EventPayload::Heartbeat { uptime_s }),
        // The self-describing escape hatch the whole JSON wire choice exists for.
        // Restricted to object/null payloads (see `arb_custom_value`).
        arb_custom_value().prop_map(EventPayload::Custom),
    ]
}

// ===========================================================================
// Event
// ===========================================================================

fn arb_event() -> impl Strategy<Value = Event> {
    (
        arb_uuid(),
        any::<u64>(),
        arb_string(),
        arb_string(),
        option::of(arb_string()),
        arb_payload(),
        btree_map(arb_string(), arb_string(), 0..5),
    )
        .prop_map(
            |(id, ts_ns, agent_id, source, kind_override, payload, labels)| {
                // Default kind from the payload, but sometimes override it to
                // exercise the `with_kind` path / a mismatched routing topic.
                let kind = kind_override.unwrap_or_else(|| payload.default_kind().to_string());
                Event {
                    id,
                    ts_ns,
                    agent_id,
                    source,
                    kind,
                    payload,
                    labels,
                }
            },
        )
}

// ===========================================================================
// ServerCommand (tagged JSON; derives PartialEq)
// ===========================================================================

fn arb_server_command() -> impl Strategy<Value = ServerCommand> {
    prop_oneof![
        arb_string().prop_map(|subject| ServerCommand::Rescore { subject }),
        (arb_string(), arb_json_value())
            .prop_map(|(plugin, config)| ServerCommand::SetConfig { plugin, config }),
        arb_string().prop_map(|reason| ServerCommand::Isolate { reason }),
        Just(ServerCommand::Noop),
    ]
}

// ===========================================================================
// Message (every variant)
// ===========================================================================

fn arb_message() -> impl Strategy<Value = Message> {
    // `EventBatch` is kept small (0..8 events) so frames stay well under
    // `MAX_FRAME_BYTES` and shrinking is fast; large-frame chunk growth is
    // exercised deterministically by the hand-written adversarial cases.
    prop_oneof![
        (
            // Bias `proto_version` toward the real PROTO_VERSION but also cover
            // 0 and u16::MAX.
            prop_oneof![3 => Just(aegis_proto::PROTO_VERSION), 1 => any::<u16>()],
            arb_string(),
            arb_string(),
            arb_string(),
            arb_pubkey()
        )
            .prop_map(|(proto_version, agent_id, hostname, os, agent_pubkey)| {
                Message::ClientHello {
                    proto_version,
                    agent_id,
                    hostname,
                    os,
                    agent_pubkey,
                }
            }),
        (
            prop_oneof![3 => Just(aegis_proto::PROTO_VERSION), 1 => any::<u16>()],
            any::<bool>(),
            option::of(arb_string())
        )
            .prop_map(|(proto_version, accepted, reason)| Message::ServerHello {
                proto_version,
                accepted,
                reason
            }),
        (arb_string(), arb_string(), arb_string(), arb_pubkey()).prop_map(
            |(token, hostname, os, agent_pubkey)| Message::EnrollRequest {
                token,
                hostname,
                os,
                agent_pubkey
            }
        ),
        (any::<bool>(), arb_string(), option::of(arb_string())).prop_map(
            |(accepted, agent_id, reason)| Message::EnrollResponse {
                accepted,
                agent_id,
                reason
            }
        ),
        (arb_uuid(), vec(arb_event(), 0..8))
            .prop_map(|(batch_id, events)| Message::EventBatch { batch_id, events }),
        (arb_uuid(), any::<u32>())
            .prop_map(|(batch_id, accepted)| Message::BatchAck { batch_id, accepted }),
        (arb_uuid(), arb_server_command())
            .prop_map(|(id, command)| Message::Command { id, command }),
        (arb_uuid(), any::<bool>(), option::of(arb_string()))
            .prop_map(|(id, ok, detail)| Message::CommandResult { id, ok, detail }),
        Just(Message::Ping),
        Just(Message::Pong),
    ]
}

// ===========================================================================
// Generative property tests
//
// These are driven via an explicit `TestRunner` on a worker thread with a large
// stack rather than the `proptest!` macro's auto-generated `#[test]`. Reason:
// the deeply-composed `arb_message` strategy (a 10-way `prop_oneof!` whose
// EventBatch arm nests `arb_event` -> `arb_payload` -> the *recursive*
// `arb_json_value`) makes proptest's `new_tree` recurse deeply enough to blow
// the default ~2 MiB test-harness stack during value *generation*. Giving the
// generator a generous stack is the robust fix and does not depend on the
// `RUST_MIN_STACK` env var being set in CI.
// ===========================================================================

/// Number of generated cases per property. Overridable via `PROPTEST_CASES`
/// (we honor it explicitly since we build the `Config` by hand).
fn case_count() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512)
}

/// Run `body` over values drawn from the strategy built by `make_strategy`,
/// using a `proptest` `TestRunner` on a thread with a 32 MiB stack. Panics
/// (failing the enclosing `#[test]`) with proptest's minimized counterexample if
/// any case fails.
///
/// The *strategy* is built inside the worker thread rather than passed in,
/// because strategies composed with `prop_recursive` contain a (non-`Send`)
/// `BoxedStrategy` and so cannot cross a thread boundary; the builder closure
/// (non-capturing) is `Send`, and the strategy lives and dies on the worker.
/// `fork`/`timeout` are forced off so this composes cleanly with the per-case
/// Tokio runtimes and our own in-test timeouts.
fn run_prop<S, Mk, F>(make_strategy: Mk, body: F)
where
    S: Strategy,
    Mk: FnOnce() -> S + Send + 'static,
    F: Fn(S::Value) -> proptest::test_runner::TestCaseResult + Send + 'static,
{
    let config = ProptestConfig {
        cases: case_count(),
        fork: false,
        timeout: 0,
        // We drive the runner by hand (not via the `proptest!` macro), so no
        // source file is registered; disable on-disk failure persistence to
        // avoid the "no source file known" warning. Counterexamples are still
        // printed (and minimized) on failure.
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    std::thread::Builder::new()
        .name("proptest-bigstack".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let strategy = make_strategy();
            let mut runner = proptest::test_runner::TestRunner::new(config);
            if let Err(e) = runner.run(&strategy, body) {
                panic!("{e}");
            }
        })
        .expect("spawn proptest worker thread")
        .join()
        .expect("proptest worker thread panicked (property failed)");
}

/// I1: every `Message` variant round-trips losslessly over the real codec
/// (float-aware structural oracle; see module docs).
#[test]
fn prop_message_roundtrips() {
    run_prop(arb_message, |msg| rt().block_on(check_roundtrips(msg)));
}

/// I5: `ServerCommand` tagged JSON round-trips and carries the `"cmd"` tag.
///
/// `ServerCommand` *does* derive `PartialEq`, but its `SetConfig.config` is an
/// arbitrary `serde_json::Value` that may contain floats, and `Value`'s
/// `PartialEq` compares those f64 exactly -- so a direct `==` is subject to the
/// same serialize/parse 1-ULP oscillation as the message oracle. We therefore
/// compare through the float-aware `values_diff` instead.
#[test]
fn prop_server_command_tagged_json() {
    run_prop(arb_server_command, |cmd| {
        let s = serde_json::to_string(&cmd).expect("serialize");
        prop_assert!(s.contains("\"cmd\":"), "missing cmd tag in {s}");
        let back: ServerCommand = serde_json::from_str(&s).expect("deserialize");
        let want = serde_json::to_value(&cmd).expect("to_value(cmd)");
        let got = serde_json::to_value(&back).expect("to_value(back)");
        if let Some(p) = values_diff(&want, &got) {
            return Err(TestCaseError::fail(format!(
                "ServerCommand mismatch at {p}"
            )));
        }
        Ok(())
    });
}

/// I4: an arbitrary byte body behind a correct length prefix never panics. The
/// outcome is `Serde` (invalid JSON / wrong shape) or, very rarely, `Ok` if the
/// random bytes happen to form a valid `Message`.
#[test]
fn prop_random_body_never_panics() {
    run_prop(
        || vec(any::<u8>(), 0..4096),
        |body| {
            let mut framed = Vec::with_capacity(4 + body.len());
            framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
            framed.extend_from_slice(&body);
            rt().block_on(async move {
                let mut cur = Cursor::new(framed);
                match read_message(&mut cur).await {
                    Ok(_) | Err(ProtoError::Serde(_)) => Ok(()),
                    other => Err(TestCaseError::fail(format!(
                        "random body produced unexpected outcome: {other:?}"
                    ))),
                }
            })
        },
    );
}

/// I2 (generative): any valid frame truncated to `keep` bytes yields `Closed`
/// or `Io` -- never a hang, never `Serde`. Each case runs under a timeout so a
/// hang regression fails loudly.
#[test]
fn prop_truncated_frame_is_closed_or_io() {
    run_prop(
        || (arb_message(), 0usize..96),
        |(msg, keep)| {
            rt().block_on(async move {
                let full = frame_message(&msg);
                // Strictly truncate (never deliver the whole frame).
                let k = keep.min(full.len().saturating_sub(1));
                let truncated = full[..k].to_vec();
                let mut cur = Cursor::new(truncated);
                let res =
                    tokio::time::timeout(Duration::from_secs(5), read_message(&mut cur)).await;
                match res {
                    Ok(Err(ProtoError::Closed)) | Ok(Err(ProtoError::Io(_))) => Ok(()),
                    Ok(other) => Err(TestCaseError::fail(format!(
                        "truncated frame (keep={k}) gave {other:?}"
                    ))),
                    Err(_) => Err(TestCaseError::fail(format!(
                        "read_message HUNG on a truncated frame (keep={k})"
                    ))),
                }
            })
        },
    );
}

/// I6: two frames written back-to-back decode to exactly two messages with no
/// bleed, and the reader consumes each frame exactly.
#[test]
fn prop_two_frames_no_bleed() {
    run_prop(
        || (arb_message(), arb_message()),
        |(m1, m2)| {
            rt().block_on(async move {
                let want1 = serde_json::to_value(&m1).expect("v1");
                let want2 = serde_json::to_value(&m2).expect("v2");

                let (mut w, mut r) = tokio::io::duplex(1024 * 1024);
                let writer = tokio::spawn(async move {
                    write_message(&mut w, &m1).await.expect("write1");
                    write_message(&mut w, &m2).await.expect("write2");
                });
                let g1 = read_message(&mut r).await.expect("read1");
                let g2 = read_message(&mut r).await.expect("read2");
                writer.await.expect("writer joins");

                let gv1 = serde_json::to_value(&g1).expect("gv1");
                let gv2 = serde_json::to_value(&g2).expect("gv2");
                if let Some(p) = values_diff(&want1, &gv1) {
                    return Err(TestCaseError::fail(format!("frame 1 mismatch at {p}")));
                }
                if let Some(p) = values_diff(&want2, &gv2) {
                    return Err(TestCaseError::fail(format!("frame 2 mismatch at {p}")));
                }
                Ok(())
            })
        },
    );
}

// ===========================================================================
// Adversarial test helpers
// ===========================================================================

/// Wraps an inner reader and records the largest single read length ever
/// *requested* of it. Used to prove that an oversized length prefix is rejected
/// before the body-read loop runs, so no `MAX_FRAME_BYTES`-class buffer is ever
/// demanded.
struct CountingReader<R> {
    inner: R,
    max_req: Arc<AtomicUsize>,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> (Self, Arc<AtomicUsize>) {
        let max_req = Arc::new(AtomicUsize::new(0));
        (
            CountingReader {
                inner,
                max_req: max_req.clone(),
            },
            max_req,
        )
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.max_req.fetch_max(buf.remaining(), Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Delivers `data` in small steps to model a slow/trickling peer: the first
/// poll returns `Pending` (after self-waking) to exercise the await path, and
/// every subsequent poll yields at most `per_poll` bytes. When the data is
/// exhausted, further polls return `Ready(Ok)` with no bytes written, i.e. EOF.
struct TrickleReader {
    data: std::collections::VecDeque<u8>,
    per_poll: usize,
    pended: bool,
}

impl TrickleReader {
    fn new(data: Vec<u8>, per_poll: usize) -> Self {
        TrickleReader {
            data: data.into(),
            per_poll: per_poll.max(1),
            pended: false,
        }
    }
}

impl AsyncRead for TrickleReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.pended {
            // One spurious Pending up front to make sure the read loop correctly
            // suspends and resumes rather than busy-spinning.
            self.pended = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = self.per_poll.min(buf.remaining()).min(self.data.len());
        for _ in 0..n {
            buf.put_slice(&[self.data.pop_front().expect("nonempty")]);
        }
        // n == 0 with an empty queue signals EOF (read of length 0).
        Poll::Ready(Ok(()))
    }
}

/// Announces `announced_len` in the 4-byte prefix but then yields no body bytes
/// and immediately reports EOF. Models the "announce a huge frame, send
/// nothing" denial-of-service attempt.
struct AnnounceThenEof {
    prefix: std::collections::VecDeque<u8>,
}

impl AnnounceThenEof {
    fn new(announced_len: u32) -> Self {
        AnnounceThenEof {
            prefix: announced_len.to_be_bytes().to_vec().into(),
        }
    }
}

impl AsyncRead for AnnounceThenEof {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        while buf.remaining() > 0 {
            match self.prefix.pop_front() {
                Some(b) => buf.put_slice(&[b]),
                // Prefix exhausted: report EOF (no body will ever arrive).
                None => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Run an async body under a hard timeout so any hang regression surfaces as a
/// test failure rather than a stuck CI job.
async fn with_timeout<F: std::future::Future<Output = T>, T>(fut: F) -> T {
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("operation must complete promptly (no hang)")
}

// ===========================================================================
// Adversarial tests (fixed byte streams / bespoke readers)
// ===========================================================================

/// A1: empty stream -> `Closed` (EOF on the 4-byte length read).
#[tokio::test]
async fn empty_stream_is_closed() {
    let mut cur = Cursor::new(Vec::<u8>::new());
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(matches!(err, ProtoError::Closed), "got {err:?}");
}

/// A2: 1, 2, or 3 header bytes then EOF -> `Closed` (partial length prefix).
#[tokio::test]
async fn partial_length_prefix_is_closed() {
    for n in 1..4usize {
        let mut cur = Cursor::new(vec![0u8; n]);
        let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
        assert!(
            matches!(err, ProtoError::Closed),
            "{n} header bytes then EOF must be Closed, got {err:?}"
        );
    }
}

/// A3: a valid prefix announcing a body, then immediate EOF -> `Closed`.
#[tokio::test]
async fn header_only_no_body_is_closed() {
    let mut stream = Vec::new();
    stream.extend_from_slice(&50u32.to_be_bytes());
    let mut cur = Cursor::new(stream);
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(matches!(err, ProtoError::Closed), "got {err:?}");
}

/// A4: prefix announces a large body, only a few bytes arrive, then EOF ->
/// `Closed` (the M2 regression scenario, exercised here via a custom reader as
/// well as the lib-level fixed-stream test).
#[tokio::test]
async fn partial_body_then_eof_is_closed() {
    let mut stream = Vec::new();
    stream.extend_from_slice(&(1024u32 * 1024).to_be_bytes());
    stream.extend_from_slice(b"abc");
    let mut cur = Cursor::new(stream);
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(matches!(err, ProtoError::Closed), "got {err:?}");
}

/// A5: an oversized length prefix is rejected with `FrameTooLarge` *before* the
/// body-read loop, so no large allocation/read is performed. We prove "no large
/// read" by feeding only the prefix through a `CountingReader` and asserting the
/// maximum requested read length never exceeded the 4-byte prefix read, and that
/// the body cursor was consumed by exactly 4 bytes.
#[tokio::test]
async fn oversized_prefix_rejected_without_large_read() {
    let announced: u32 = (MAX_FRAME_BYTES as u32).saturating_add(1);
    let stream = announced.to_be_bytes().to_vec(); // prefix only, no body
    let inner = Cursor::new(stream);
    let (mut reader, max_req) = CountingReader::new(inner);

    let err = with_timeout(read_message(&mut reader)).await.unwrap_err();
    match err {
        ProtoError::FrameTooLarge(n) => assert_eq!(n, announced as usize),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
    // The only read performed is the 4-byte length prefix; the body loop (which
    // would request up to READ_CHUNK_BYTES) never runs.
    let observed = max_req.load(Ordering::SeqCst);
    assert!(
        observed <= 4,
        "oversized prefix must not trigger a large read; max requested = {observed}"
    );
    // And exactly the 4 prefix bytes were consumed.
    assert_eq!(reader.inner.position(), 4);
}

/// A6: a `u32::MAX` prefix -> `FrameTooLarge(4294967295)`, with no body read and
/// no `usize` overflow (`len as usize` is exact on 64-bit).
#[tokio::test]
async fn u32_max_prefix_is_frame_too_large() {
    let stream = u32::MAX.to_be_bytes().to_vec();
    let (mut reader, max_req) = CountingReader::new(Cursor::new(stream));
    let err = with_timeout(read_message(&mut reader)).await.unwrap_err();
    match err {
        ProtoError::FrameTooLarge(n) => assert_eq!(n, u32::MAX as usize),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
    assert!(max_req.load(Ordering::SeqCst) <= 4);
}

/// A5b: announce a 16 MiB frame but send nothing (immediate EOF after the
/// prefix). Because `MAX_FRAME_BYTES` is the cap, this is *not* rejected by the
/// length check (it equals the cap, not exceeds it) -- so the read loop starts
/// but observes EOF on the first body read and returns `Closed`. This proves a
/// "announce huge, deliver nothing" peer cannot wedge the reader.
#[tokio::test]
async fn announce_max_send_nothing_is_closed() {
    let mut reader = AnnounceThenEof::new(MAX_FRAME_BYTES as u32);
    let err = with_timeout(read_message(&mut reader)).await.unwrap_err();
    assert!(
        matches!(err, ProtoError::Closed),
        "announce-max/send-nothing must be Closed, got {err:?}"
    );
}

/// A7: documents the non-finite-float wire behavior that dictates why every
/// generator emits finite floats only. `serde_json` here serializes `NaN` as
/// JSON `null`, which then fails to deserialize into the non-`Option<f64>`
/// `score` field -> `read_message` returns `Serde`. This is a guardrail: if the
/// behavior ever changes, this test breaks and forces a conscious decision.
#[tokio::test]
async fn nonfinite_float_serializes_to_null_then_fails_decode() {
    let batch = Message::EventBatch {
        batch_id: Uuid::new_v4(),
        events: vec![Event::new(
            "agent-1",
            "plugin-score",
            EventPayload::Score {
                subject: "s".into(),
                model: "m".into(),
                score: f64::NAN,
                features: BTreeMap::new(),
            },
        )],
    };

    // Serialization succeeds and emits `null` for the non-finite score.
    let bytes = serde_json::to_vec(&batch).expect("serialize succeeds (emits null)");
    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(
        text.contains("\"score\":null"),
        "expected score to serialize as null, body was: {text}"
    );

    // Framing that body and reading it back fails at JSON decode: `null` is not
    // a valid `f64`.
    let mut framed = Vec::new();
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    let mut cur = Cursor::new(framed);
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(
        matches!(err, ProtoError::Serde(_)),
        "null score must fail to decode into f64, got {err:?}"
    );
}

/// A7b: pins the internal-tagging constraint on `EventPayload::Custom`. A
/// `Custom` wrapping a JSON **object** (or `null`) serializes and round-trips,
/// but a `Custom` wrapping a bool/number/string/array **fails to serialize**
/// (serde cannot splice the `"type"` tag into a non-object). This is why the
/// generators restrict `Custom` payloads to objects/null; if serde's behavior
/// ever changes (e.g. an `arbitrary_precision`/`untagged` refactor), this test
/// breaks and forces a conscious decision.
#[test]
fn custom_nonobject_payload_fails_to_serialize() {
    let mk = |v: serde_json::Value| Message::EventBatch {
        batch_id: Uuid::new_v4(),
        events: vec![Event::new("a", "s", EventPayload::Custom(v))],
    };

    // Object and null payloads serialize and round-trip cleanly.
    for ok in [
        serde_json::json!({"k": "v", "nested": [1, 2, 3]}),
        serde_json::json!({}),
        serde_json::Value::Null,
    ] {
        let msg = mk(ok.clone());
        let bytes = serde_json::to_vec(&msg)
            .unwrap_or_else(|e| panic!("Custom({ok}) should serialize: {e}"));
        let back: Message = serde_json::from_slice(&bytes).expect("re-parse");
        assert_eq!(
            serde_json::to_value(&back).expect("v"),
            serde_json::to_value(&msg).expect("v")
        );
    }

    // Non-object, non-null payloads cannot be serialized under internal tagging.
    for bad in [
        serde_json::json!(true),
        serde_json::json!(42),
        serde_json::json!(3.5),
        serde_json::json!("text"),
        serde_json::json!([1, 2, 3]),
    ] {
        let msg = mk(bad.clone());
        let err = serde_json::to_vec(&msg).expect_err(&format!(
            "Custom({bad}) must fail to serialize under internal tagging"
        ));
        assert!(
            err.to_string().contains("tagged newtype variant"),
            "unexpected serialize error for Custom({bad}): {err}"
        );
    }
}

/// A8: a slow peer that trickles the body one byte per poll (after an initial
/// spurious `Pending`) still decodes correctly and terminates promptly.
#[tokio::test]
async fn trickled_body_one_byte_per_poll_roundtrips() {
    let msg = Message::Command {
        id: Uuid::new_v4(),
        command: ServerCommand::Isolate {
            reason: "trickle-test".into(),
        },
    };
    let framed = frame_message(&msg);
    let want = serde_json::to_value(&msg).expect("to_value");

    let mut reader = TrickleReader::new(framed, 1);
    let got = with_timeout(read_message(&mut reader))
        .await
        .expect("decode");
    assert_eq!(serde_json::to_value(&got).expect("to_value(got)"), want);
}

/// A9: deliver the body in slices aligned to `READ_CHUNK_BYTES` (and +/-1) to
/// exercise the buffer-growth arithmetic at chunk edges. We build a frame that
/// spans multiple chunks and feed it through a `TrickleReader` whose step size
/// straddles the chunk boundary.
#[tokio::test]
async fn body_split_on_chunk_boundaries_roundtrips() {
    const CHUNK: usize = 64 * 1024; // mirrors READ_CHUNK_BYTES (private const)
                                    // Build an EventBatch large enough to cross several chunks.
    let events: Vec<Event> = (0..5000u64)
        .map(|i| {
            Event::new(
                "agent-1",
                "plugin-session",
                EventPayload::Heartbeat { uptime_s: i },
            )
        })
        .collect();
    let msg = Message::EventBatch {
        batch_id: Uuid::new_v4(),
        events,
    };
    let framed = frame_message(&msg);
    assert!(
        framed.len() > 4 + CHUNK,
        "test frame must exceed one chunk to exercise growth (len={})",
        framed.len()
    );
    let want = serde_json::to_value(&msg).expect("to_value");

    // Step sizes that straddle the chunk boundary: exactly CHUNK, and CHUNK +/- 1.
    for step in [CHUNK - 1, CHUNK, CHUNK + 1] {
        let mut reader = TrickleReader::new(framed.clone(), step);
        let got = with_timeout(read_message(&mut reader))
            .await
            .unwrap_or_else(|e| panic!("decode failed at step {step}: {e:?}"));
        assert_eq!(
            serde_json::to_value(&got).expect("to_value(got)"),
            want,
            "value mismatch at step {step}"
        );
    }
}

/// A10: the write-side guard rejects a message whose serialized form exceeds
/// `MAX_FRAME_BYTES` with `FrameTooLarge`, and nothing is written past the guard
/// (the sink stays empty).
#[tokio::test]
async fn write_side_rejects_oversized_frame() {
    // A huge string in an ordinary string field forces the serialized Message
    // over MAX_FRAME_BYTES. (A `Custom` payload would have to be an object to
    // even serialize -- see `custom_nonobject_payload_fails_to_serialize` -- so
    // we use `Alert.detail`, which has no such restriction, to make sure the
    // size guard, not a serialization error, is what fires.)
    let huge = "x".repeat(MAX_FRAME_BYTES + 1024);
    let msg = Message::EventBatch {
        batch_id: Uuid::new_v4(),
        events: vec![Event::new(
            "agent-1",
            "plugin-alert",
            EventPayload::Alert {
                severity: Severity::Critical,
                title: "huge".into(),
                detail: huge,
                subject: None,
            },
        )],
    };

    let mut sink: Vec<u8> = Vec::new();
    let err = with_timeout(write_message(&mut sink, &msg))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProtoError::FrameTooLarge(_)),
        "oversized write must be FrameTooLarge, got {err:?}"
    );
    assert!(
        sink.is_empty(),
        "nothing must be written past the size guard, sink had {} bytes",
        sink.len()
    );
}

/// A11: a zero-length frame (prefix says 0, no body). The body loop never runs,
/// then `serde_json::from_slice(&[])` fails -> `Serde` (empty input is invalid
/// JSON). Confirms the `len == 0` edge neither panics nor hangs.
#[tokio::test]
async fn zero_length_frame_is_serde_error() {
    let stream = 0u32.to_be_bytes().to_vec();
    let mut cur = Cursor::new(stream);
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(
        matches!(err, ProtoError::Serde(_)),
        "empty body must be a Serde error, got {err:?}"
    );
}

/// A12: a valid frame followed by trailing garbage. The first read returns the
/// message (proving exact consumption, no over-read corrupting the decode); a
/// second read then operates on the garbage and yields `Serde` or `Closed`.
#[tokio::test]
async fn valid_frame_then_trailing_garbage() {
    let msg = Message::Ping;
    let mut stream = frame_message(&msg);
    let first_frame_len = stream.len();
    // Append garbage: a bogus length prefix and some random-ish bytes.
    stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02]);

    let mut cur = Cursor::new(stream);
    let got = with_timeout(read_message(&mut cur))
        .await
        .expect("first read");
    assert_eq!(
        serde_json::to_value(&got).expect("v"),
        serde_json::to_value(&msg).expect("v")
    );
    // Exactly the first frame was consumed.
    assert_eq!(cur.position() as usize, first_frame_len);

    // The second read sees the garbage; it must not panic, and yields an error.
    let err = with_timeout(read_message(&mut cur)).await.unwrap_err();
    assert!(
        matches!(
            err,
            ProtoError::Serde(_) | ProtoError::Closed | ProtoError::FrameTooLarge(_)
        ),
        "trailing garbage must yield an error, got {err:?}"
    );
}
