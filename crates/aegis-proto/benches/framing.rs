//! Bench 3 — proto `EventBatch` encode + decode round-trip.
//!
//! Every agent->server hop serializes an `EventBatch` and the server
//! deserializes it; this is the network hot path, dominated by JSON
//! (serde_json) cost that scales with batch size.
//!
//! Two variants:
//!  * **3a `serialize_roundtrip`** (sync, no runtime): `serde_json::to_vec` +
//!    a 4-byte big-endian length prefix + `serde_json::from_slice`. This is
//!    exactly the work `write_message`/`read_message` do minus the socket, and
//!    is the lowest-variance headline number.
//!  * **3b `framing_roundtrip`** (async): drive the real `write_message` /
//!    `read_message` over `tokio::io::duplex`, exercising the incremental
//!    chunked-read growth loop on large frames. The writer runs on a spawned
//!    task (as the crate's own round-trip test does) so a frame larger than the
//!    duplex buffer cannot deadlock a single-task write-then-read.
//!
//! Batches use a realistic mixed payload (Keystroke + CommandObserved + a
//! Detection with a populated features map) so serialized size reflects
//! production traffic. All batches are built once, outside the timed closure.

use std::collections::BTreeMap;

use aegis_proto::{read_message, write_message, Message};
use aegis_sdk::{Event, EventPayload, Verdict};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use uuid::Uuid;

/// Build one realistic mixed-payload event, cycling kinds by index so a batch
/// resembles production traffic rather than a single repeated heartbeat.
fn mixed_event(i: usize) -> Event {
    let session_id = format!("sess-{}", i % 8);
    match i % 3 {
        0 => Event::new(
            "agent-1",
            "plugin-tty",
            EventPayload::Keystroke {
                session_id,
                inter_arrival_ns: 150_000_000 + (i as u64 % 97) * 1_000_000,
                is_paste: i.is_multiple_of(11),
                burst_len: 1 + (i as u32 % 4),
            },
        ),
        1 => Event::new(
            "agent-1",
            "plugin-session",
            EventPayload::CommandObserved {
                session_id,
                command_len: 12 + (i as u32 % 40),
                token_count: 2 + (i as u32 % 6),
                shannon_entropy: 3.2 + (i as f64 % 10.0) * 0.15,
                had_backspace: i.is_multiple_of(3),
                edit_distance_prev: (i as u32) % 9,
                inter_command_ns: 800_000_000 + (i as u64 % 53) * 10_000_000,
                command_hash: format!("{:016x}", (i as u64).wrapping_mul(0x9E37_79B9)),
            },
        ),
        _ => {
            let mut features = BTreeMap::new();
            features.insert("keystroke_cv".to_string(), 0.42 + (i as f64 % 7.0) * 0.01);
            features.insert("paste_ratio".to_string(), (i as f64 % 5.0) * 0.1);
            features.insert("mean_inter_command_ms".to_string(), 1200.0 + i as f64);
            features.insert("backspace_ratio".to_string(), 0.05);
            features.insert("entropy_mean".to_string(), 4.1);
            features.insert("cadence_regularity".to_string(), 0.3);
            features.insert("gap_autocorr".to_string(), 0.22);
            features.insert("think_tail_ratio".to_string(), 4.5);
            Event::new(
                "agent-1",
                "plugin-agent-detect",
                EventPayload::Detection {
                    subject: format!("sess-{}", i % 8),
                    verdict: Verdict::Uncertain,
                    confidence: 0.5 + (i as f64 % 4.0) * 0.1,
                    model: "transparent-additive/v1".to_string(),
                    reasons: vec![
                        "gap-non-autocorrelation".to_string(),
                        "dense-commands".to_string(),
                    ],
                    features,
                },
            )
        }
    }
}

fn batch_of(n: usize) -> Message {
    Message::EventBatch {
        batch_id: Uuid::new_v4(),
        events: (0..n).map(mixed_event).collect(),
    }
}

const SIZES: [usize; 4] = [1, 100, 1000, 4000];

/// 3a: serialization-only round-trip with manual BE-length framing (no runtime).
fn bench_serialize_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto_serialize_roundtrip");
    for &n in &SIZES {
        let msg = batch_of(n);
        // Report throughput in bytes of the serialized frame body.
        let body = serde_json::to_vec(&msg).expect("serialize");
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &msg, |b, msg| {
            b.iter(|| {
                // Encode: JSON body + 4-byte big-endian length prefix.
                let body = serde_json::to_vec(black_box(msg)).expect("serialize");
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
                framed.extend_from_slice(&body);
                // Decode: strip the prefix, parse the body back to a Message.
                let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
                let decoded: Message =
                    serde_json::from_slice(&framed[4..4 + len]).expect("deserialize");
                black_box(decoded)
            });
        });
    }
    group.finish();
}

/// 3b: through the real `write_message`/`read_message` framing API over a duplex.
fn bench_framing_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");

    let mut group = c.benchmark_group("proto_framing_roundtrip");
    for &n in &SIZES {
        let msg = batch_of(n);
        let body = serde_json::to_vec(&msg).expect("serialize");
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &msg, |b, msg| {
            b.to_async(&rt).iter(|| {
                let msg = msg.clone();
                async move {
                    // A duplex smaller than the largest frame forces the
                    // incremental chunked-read growth loop; the writer runs on
                    // its own task so the write side cannot block the reader.
                    let (mut wr, mut rd) = tokio::io::duplex(64 * 1024);
                    let writer = tokio::spawn(async move {
                        write_message(&mut wr, &msg).await.expect("write");
                    });
                    let got = read_message(&mut rd).await.expect("read");
                    writer.await.expect("writer task");
                    black_box(got)
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_serialize_roundtrip, bench_framing_roundtrip);
criterion_main!(benches);
