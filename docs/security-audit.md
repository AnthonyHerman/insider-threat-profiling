# Aegis Security Audit

**Target:** Aegis — plugin-native, client/server behavioral insider-threat modeling platform
**Scope:** Full workspace (`crates/*`, `plugins/*`) — transport & crypto, server ingest & enrollment, detection integrity, tamper resistance, core & plugin loader
**Method:** Parallel domain audit followed by adversarial per-finding verification against source
**Date:** 2026-06-19 (findings); **remediation status verified against code 2026-06-19**
**Disposition:** Read-only audit. No source files were modified by the audit.

> **Remediation status (added).** This report's 28 findings were originally
> presented as open, each with a "Fix:" to do. The code has since been remediated:
> **26 of 28 are now Fixed**, verified against source. The two that remain are
> **H5** (dynamic `.so` *cryptographic* integrity/signature gate — still
> unimplemented; a pre-`dlopen` path-ownership/permission gate has since landed) and
> **L7** (a *documentation* action — now satisfied: the alert-only tamper design is
> documented in `docs/THREAT_MODEL.md` §5.2). Each finding below carries a
> **Status** line stating Fixed (with the mechanism and file) or Open; the §3 table
> gains a Status column; and the §5 backlog is annotated with what is Done. The
> finding analyses themselves are retained unchanged for the record.

---

## 1. Executive summary

Aegis is a security product whose job is to watch Linux endpoints, distinguish automated agents from human operators, and ship sensitive behavioral telemetry to a central server. Because the agent is itself a high-value target — it runs privileged, holds secrets, and sees everyone's activity — the bar for its own hygiene is high. This audit found that the *cryptographic core is sound* (TLS 1.3-only negotiation, ed25519 identity, cert pinning, 0600 identity files, server-side identity override on ingest) but that several **supporting paths around that core fail open**: they drop security data silently, exhaust resources under adversary control, leave sensitive telemetry world-readable on disk, and — most seriously — load and execute untrusted native code with no integrity gate.

28 findings were confirmed at audit time: **7 high, 10 medium, 11 low.** No finding was a false positive; two findings originally proposed as medium were *downgraded* to low after verification (the privilege-gate uid check and the installer symlink-follow), and one low was *upgraded* to medium (`events_by_agent` index staleness, because it silently corrupts the operator-facing pagination API). The severities below reflect those adjustments. **As of the remediation-status pass, 26 of the 28 are Fixed in code; only H5 (dynamic-loader integrity gate) and the L7 documentation action remained, and the latter is now satisfied — see the per-finding Status lines.**

The themes that matter most:

- **The plugin loader is the single largest risk.** Dynamic `.so` plugins are `dlopen`ed and their constructors run with **zero** integrity, signature, ownership, or path validation — and worse, this happens *before* the enable/disable check, so an operator who "disables" a suspect plugin has already executed it. Combined with a cross-allocator `Box::from_raw` that is undefined behavior for any externally-built plugin, the very component meant to *detect* an insider is itself a clean arbitrary-native-code-execution surface. (Findings H5, H6, H7.)
- **Detection can be silently defeated.** Short sessions emit `NaN` feature values that make `serde_json` fail, so the Detection event — the product's core output — is dropped from both the audit log and the detection store with only a log line (H4). Separately, the event bus drops Alert/Detection/Score events under queue pressure with no metric, so an attacker can flood cheap events to evict the very alert that would catch them (M10). Both turn an availability gap into a detection-evasion primitive.
- **Resource exhaustion is reachable, sometimes pre-auth-equivalent.** The on-disk spill never enforces its configured cap on the enrolled hot path, so a severed server link fills the agent's disk (H1). The detection plugin grows unbounded per-session `Vec`s for attacker-chosen session IDs (H3). `read_message` pre-allocates the full 16 MiB frame size before reading the body (M2), and two server read paths have no idle deadline, letting enrolled connections pin all 1,024 slots (M3, M4).
- **Confidentiality and audit integrity have gaps.** The spill database — full plaintext keystroke/process/command telemetry about *other users* — is created world-readable while the agent's own keys are locked to 0600 (H2). Enrolled agents can backdate timestamps and inject unbounded `source`/`labels` into the audit log (M5).

Recommended order of work: close the plugin-loader execution path and the NaN/bus detection-loss issues first (they are the most direct subversions of the product's purpose), then the disk/memory exhaustion DoS, then the confidentiality and audit-integrity items.

---

## 2. Methodology

The audit ran in two phases.

**Phase 1 — Parallel domain audit.** The workspace was partitioned into five areas (transport & crypto, server ingest & enrollment, detection integrity, tamper resistance, core & plugin loader). Each area was read for memory-safety, resource-exhaustion, authentication/authorization, confidentiality, and logic/correctness defects, with particular attention to the trust boundaries that matter for an insider-threat product: agent→server network, local-user→agent on the monitored host, and plugin→host inside the process.

**Phase 2 — Adversarial verification.** Every candidate finding was re-checked against the exact source — not the summary — with a hostile reading: *Is the code path actually reachable? Is the claimed primitive real? Is the severity justified or inflated?* Findings that did not survive this pass were dropped; severities that the code did not support were adjusted. This report contains only findings that survived verification, with the verifier's reasoning folded into each entry. The verification pass produced two downgrades (D1: privilege-gate uid; D2: installer symlink) and one upgrade (U1: `events_by_agent` pagination), all noted inline.

Line numbers cited are the canonical references from the audit; where the working tree had drifted slightly, the confirming code pattern (not just the line) was re-verified by hand. No code was changed during the audit (a sibling workflow holds the write lock on the server).

---

## 3. Findings table (sorted by severity)

| # | Sev | Area | Title | Location | Status |
|---|-----|------|-------|----------|--------|
| H1 | High | Transport & crypto | Steady-state actor never enforces the spill disk cap (unbounded disk growth / DoS) | `plugins/plugin-transport/src/{actor,spill}.rs` | **Fixed** — cap enforced inside `Spill::push` (`spill.rs:215`) |
| H2 | High | Transport & crypto | Disk spill database created world-readable; telemetry not protected like 0600 identity files | `plugins/plugin-transport/src/spill.rs` | **Fixed** — DB 0600, dir 0700 (`spill.rs:49,58,70`; tests assert) |
| H3 | High | Detection integrity | Unbounded per-session `Vec` growth enables memory-exhaustion DoS | `plugins/plugin-agent-detect/src/{features,lib}.rs` | **Fixed** — `SAMPLE_CAP=2048` rolling window; `session.end` removal |
| H4 | High | Detection integrity | `NaN` in `features.to_map()` silently drops Detection events from the audit log | `plugins/plugin-agent-detect/src/features.rs` | **Fixed** — `to_map()` skips non-finite (`is_finite` guard) |
| H5 | High | Core & plugin loader | Dynamic `.so` plugins loaded with zero integrity/authenticity verification | `crates/aegis-core/src/loader.rs` | **Partial** — pre-`dlopen` path/ownership gate landed (world-writable / non-root-owned-under-root refused); cryptographic signature/hash gate still open |
| H6 | High | Core & plugin loader | Disabled dynamic plugins still execute: `.so` dlopened and constructor runs before enable check | `crates/aegis-core/src/host.rs` | **Fixed** — `is_enabled` checked before `load_dynamic` (`host.rs:78`) |
| H7 | High | Core & plugin loader | Cross-module `Box::from_raw` on FFI-returned pointer (allocator/ownership mismatch → UB) | `crates/aegis-core/src/loader.rs` | **Fixed** — paired `DYN_FREE_SYMBOL` free, no `Box::from_raw` |
| M1 | Medium | Transport & crypto | Session auth digest binds only `server_pins[0]`, breaking the cert rotation it was designed to support | `plugins/plugin-transport/src/actor.rs` | **Fixed** — `bind_pin` binds the served leaf's fingerprint (regression test) |
| M2 | Medium | Transport & crypto | `read_message` eagerly allocates up to `MAX_FRAME_BYTES` per frame before reading the body | `crates/aegis-proto/src/lib.rs` | **Fixed** — bounded initial alloc + incremental growth (`lib.rs:168-177`) |
| M3 | Medium | Server ingest & enrollment | No timeout on challenge-reply read; enrolled agent can pin a connection slot indefinitely | `crates/aegis-server/src/ingest.rs` | **Fixed** — `FIRST_FRAME_TIMEOUT` on the challenge reply (`ingest.rs:572`) |
| M4 | Medium | Server ingest & enrollment | No per-session idle timeout in the authenticated read loop enables indefinite slot pinning | `crates/aegis-server/src/ingest.rs` | **Fixed** — `SESSION_IDLE_TIMEOUT` (180s) on the read loop (`ingest.rs:691`) |
| M5 | Medium | Server ingest & enrollment | Agent-supplied `ts_ns`, `source`, `labels` stored verbatim without validation | `crates/aegis-server/src/ingest.rs` | **Fixed** — `ts_ns` clamped (`ingest.rs:168-172`); `agent_id` overwritten |
| M6 | Medium | Server ingest & enrollment | `events_by_agent` index not pruned during compaction → stale pointers + silent pagination data loss *(upgraded U1)* | `crates/aegis-server/src/store.rs` | **Fixed** — index pruned in the same compaction txn (regression test) |
| M7 | Medium | Detection integrity | Hard rule #2 flags a single sub-150 ms typed command gap regardless of session length | `plugins/plugin-agent-detect/src/model.rs` | **Fixed** — gated on `reaction_floor_hits >= 0.25` (`model.rs:206`) |
| M8 | Medium | Core & plugin loader | No panic isolation across the FFI call or around plugin construction/init | `crates/aegis-core/src/{loader,host}.rs` | **Fixed** — `catch_unwind` on entry + both constructor paths |
| M9 | Medium | Core & plugin loader | No event-producer authenticity on the bus: any plugin can forge `source` and `agent_id` | `crates/aegis-core/src/bus.rs` | **Fixed** — per-plugin `ScopedEmitter` stamps `source`/`agent_id` |
| M10 | Medium | Core & plugin loader | Security events silently droppable under queue pressure (detection-evasion / no metrics) | `crates/aegis-core/src/bus.rs` | **Fixed** — `BusMetrics` counters + non-droppable critical path |
| L1 | Low | Transport & crypto | TLS 1.2 cipher/codepaths compiled in via cargo features (defense-in-depth) | `Cargo.toml` | **Fixed** — `tls12` feature dropped (root `Cargo.toml` `[workspace.dependencies]`) |
| L2 | Low | Server ingest & enrollment | No length limits on enrollment strings (`hostname`, `os`) allow oversized records | `crates/aegis-server/src/enroll.rs` | **Fixed** — `MAX_ENROLL_FIELD_LEN=255` / `MAX_TOKEN_LABEL_LEN=256` |
| L3 | Low | Server ingest & enrollment | Cross-session event replay not prevented; dedup set is per-connection only | `crates/aegis-server/src/ingest.rs` | **Fixed** — bounded cross-connection `GLOBAL_DEDUP` window |
| L4 | Low | Server ingest & enrollment | Dedup eviction removes a random quarter, not the oldest, allowing in-session replay | `crates/aegis-server/src/ingest.rs` | **Fixed** — true FIFO via `VecDeque` + set, `pop_front` |
| L5 | Low | Tamper resistance | Privilege gate checks real uid, not effective uid/capabilities *(downgraded D1)* | `plugins/plugin-tamper/src/lib.rs` | **Fixed** — `geteuid()` (`lib.rs:126-129`) |
| L6 | Low | Tamper resistance | Installer writes protected files through symlinks (no `O_NOFOLLOW`/`O_EXCL`) *(downgraded D2)* | `plugins/plugin-tamper/src/install.rs` | **Fixed** — `open_nofollow_write` (`O_NOFOLLOW`) + `fchown` on fd |
| L7 | Low | Tamper resistance | Runtime tamper loop is alert-only: never re-arms immutable bit or restores drifted file | `plugins/plugin-tamper/src/lib.rs` | **Fixed (doc)** — design documented in `THREAT_MODEL.md` §5.2 (intended behavior) |
| L8 | Low | Tamper resistance | Per-tick integrity check reads each protected file fully into memory (unbounded `fs::read`) | `plugins/plugin-tamper/src/manifest.rs` | **Fixed** — `metadata` size pre-filter + streaming `hash_reader`/`io::copy` |
| L9 | Low | Detection integrity | Config params `ewma_alpha` and `decay` have no range validation | `plugins/plugin-agent-detect/src/lib.rs`; `plugins/plugin-scoring/src/lib.rs` | **Fixed** — ranges validated in `init` |
| L10 | Low | Detection integrity | `RiskState` scores map grows without bound and is never evicted | `plugins/plugin-scoring/src/lib.rs` | **Fixed** — negligible-score eviction + `session.end` subscription |
| L11 | Low | Core & plugin loader | Post-shutdown ingress drops logged at `debug`, hiding event loss | `crates/aegis-core/src/bus.rs` | **Fixed** — closed-channel drop now `warn!` with the event kind |

---

## 4. Detailed findings

### H1 — Steady-state actor never enforces the spill disk cap (unbounded disk growth / DoS during server outage)
**Severity:** High · **Area:** Transport & crypto
**Location:** `plugins/plugin-transport/src/actor.rs` (spill push sites 168, 516, 600, 609; `try_flush` 529-665); `enforce_cap` only invoked at `plugins/plugin-transport/src/lib.rs:174`

`Spill::enforce_cap` (`spill.rs:216`) is the documented "drop-oldest under pressure" guard that bounds on-disk telemetry to `spill_max_bytes` (default 64 MiB). It is invoked in exactly **one** place in the codebase: `spawn_buffer_only` (`lib.rs:174`), the pre-enrollment buffering path. The normal enrolled run path — `run()` → `connect_and_serve()` → `try_flush()` — pushes events into the spill in four places (shutdown drain `actor.rs:168`, re-spill pending `516`, ring-keep `600`, ring overflow `609`) and **never** calls `enforce_cap`. `state.cfg.spill_max_bytes` is in scope throughout `try_flush` but unused.

Consequence: whenever the server is unreachable for an extended period (TLS handshake failing, ack timeouts, network down), the ring keeps draining into the spill and the redb file grows without bound until the disk fills. On an endpoint agent this is a self-inflicted DoS — a full partition can crash the agent and co-resident host services — and it is externally triggerable: any attacker who can sever the agent→server link, or who drives a high-event-rate condition, weaponizes it. The configured cap is silently never honored on the hot path.

**Fix:** Call `spill.enforce_cap(state.cfg.spill_max_bytes)` inside `try_flush` immediately after every `Spill::push` (and in the shutdown drain at `actor.rs:168`), using the operator-configured value. Best: centralize the cap *inside* `Spill::push` so it is enforced after every append and cannot be forgotten at any call site.

**Status: Fixed.** The recommended "centralize inside `push`" approach was taken: `Spill::push` now calls `enforce_cap(self.max_bytes)` internally (`spill.rs:215`), so the cap holds on every append regardless of call site.

---

### H2 — Disk spill database is created world-readable; sensitive telemetry not protected like the 0600 identity files
**Severity:** High · **Area:** Transport & crypto
**Location:** `plugins/plugin-transport/src/spill.rs:71` (`Database::create(path)`); contrast `plugins/plugin-transport/src/identity.rs:125-137` (`write_private`, 0600)

`Spill::open` calls `Database::create(path)` with no permission control, so `spill.redb` is created under the process umask (typically 0644 → world-readable). No subsequent `chmod`/`set_permissions` is applied anywhere. The spill persists full `Event` payloads as plaintext JSON (`spill.rs` encode/decode), including `ProcessExec{cmdline,cwd}`, `SessionStart{username,remote peer}`, keystroke inter-arrival timing, and `CommandObserved` data (`crates/aegis-sdk/src/event.rs:67-145`) — exactly the sensitive insider-threat telemetry the system exists to protect.

In the *same* data directory, `identity.json` and `agent_ed25519.key` are deliberately written 0600 via `write_private` (`identity.rs:125-137`, which uses both `OpenOptions::mode(0o600)` at creation and `set_permissions`), and the plugin data dir is created with a plain `create_dir_all` (no mode). The result is an inconsistent threat model: the agent's own secrets are locked down, but any local unprivileged user on the monitored endpoint can read buffered surveillance data about *other* users — a confidentiality failure on the primary asset, exploitable without privilege escalation.

**Fix:** Create the spill DB with restrictive permissions — open the backing file with `OpenOptions::mode(0o600)` (or `chmod` immediately around `Database::create`) and create the plugin data dir 0700. Also tighten the redb sidecar/lock files. Mirror the 0600 discipline already applied to identity material.

**Status: Fixed.** The spill DB is created 0600 and its parent dir 0700 (`spill.rs:49,58,70`), with tests asserting `0o600`/`0o700` (`spill.rs:508-513`).

---

### H3 — Unbounded per-session `Vec` growth enables memory-exhaustion DoS
**Severity:** High · **Area:** Detection integrity
**Location:** `plugins/plugin-agent-detect/src/features.rs:46-65,79-80,109`; session lifecycle `lib.rs:205,221,234`

`SessionAccumulator` holds three plain `Vec<f64>` (`inter_arrivals_ms`, `inter_commands_ms`, `entropies`) whose push sites filter only on value range, not length, so they grow without cap for the session lifetime. Sessions are removed only on `SessionEnd` (`lib.rs:234`); the sole removal call in the codebase. There is no TTL, sweeper, or LRU. If `SessionEnd` never arrives (agent crash, partition, or deliberate omission), the session lives in the `HashMap` forever.

Worse, the `Keystroke` and `CommandObserved` handlers materialize entries via `entry(session_id).or_default()` (`lib.rs:205,221`) with no prior `SessionStart`, so an attacker can inject arbitrary `session_id` strings to create new accumulators at will. At ~10,000 keystrokes/min, a single 24-hour non-terminated session consumes ~115 MB in `inter_arrivals_ms` alone; ten such sessions exhaust ~1 GB. The `percentile()` helper (`features.rs:262`) also `to_vec()`-clones the full vector on every assessment, amplifying CPU and memory cost as the vectors grow.

**Fix:** Cap each `Vec` to a rolling window (e.g. 2048 most-recent samples via ring buffer or periodic drain). Add a session-age TTL sweep in `maybe_emit` or a background task that evicts sessions idle beyond a configurable window. Reject `Keystroke`/`CommandObserved` for unknown `session_id`s unless an explicit `assess_on_missing_session` flag is set.

**Status: Fixed.** Each per-session `Vec` is capped to a rolling `SAMPLE_CAP=2048` window (`features.rs:48-54`), and a session is removed on `session.end` (`lib.rs`). The exact recommended window size was adopted.

---

### H4 — `NaN` in `features.to_map()` causes silent loss of Detection events in the audit log
**Severity:** High · **Area:** Detection integrity
**Location:** `plugins/plugin-agent-detect/src/features.rs:405-420`; `crates/aegis-server/src/store.rs:250`; `crates/aegis-server/src/sink.rs:120,125`

For sessions with at least `MIN_COMMANDS` (3) but fewer than `MIN_COMMANDS_ROBUST` (16) commands, the Tier-3 feature fields `gap_autocorr`, `think_tail_ratio`, `throughput_decay`, and `keystroke_burst_cv` are set to `f64::NAN` sentinels (`features.rs:154-192`). `to_map()` inserts those `NaN` values unconditionally into the `BTreeMap<String,f64>` (`features.rs:413-418`, no `is_finite` guard), and that map is placed directly into `EventPayload::Detection.features`.

When `StoreSink::handle` runs, it calls `store.write_event(event)?` **before** `upsert_detection` (`sink.rs` write order confirmed: audit-log write first, then the kind-specific write). Inside `write_event`, `serde_json::to_vec(&ev.payload)?` (`store.rs:250`) is reached — and stock `serde_json` returns `Err` on a `NaN` `f64`. The `?` propagates, `write_event` fails, and because it runs first, **neither** the raw audit-log entry **nor** the detection cell is written. The error bubbles to the host, which logs a `warn` and continues. Every Detection from a 3–15-command session is silently swallowed, and the short-session Agent verdict is never persisted — an adversary who simply stays under 16 commands per assessed session guarantees their verdict never lands.

**Fix:** Strip non-finite values before constructing the payload — change `to_map()` to skip `NaN` insertions (or map them to a value that serializes, e.g. `null`). Alternatively serialize with a custom serializer that maps `NaN`→`null`. Filtering in `to_map()` is the cleanest single point.

**Status: Fixed.** `to_map()` now skips non-finite values with an `is_finite` guard (`features.rs:432-438`), so a short-session `NaN` can no longer fail `Detection` serialization — the cleanest-single-point fix that was recommended.

---

### H5 — Dynamic `.so` plugins are loaded with zero integrity/authenticity verification
**Severity:** High · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/loader.rs:31-70`; `crates/aegis-core/src/host.rs:69-80`; `crates/aegis-core/src/config.rs:33-35`

`load_dynamic()` `dlopen`s a path from config and adopts its constructor. At audit time the ABI-version integer handshake (`loader.rs:56`) was the **only** gate — a value any malicious `.so` trivially supplies. A pre-`dlopen` path-safety gate has since been added (`check_load_path_safety`: refuse a world-writable `.so`/directory, and a non-root-owned one when running as root), so the *path/ownership/permission* axis is now covered. What remains absent is a cryptographic **integrity** check: no signature check, no hash/checksum pin, no allowlist of verified digests. The plugin paths still come straight from a TOML file (`config.rs:33-35`, a plain `Vec<PathBuf>`), and the loaded code runs in-process with full host privileges, so an attacker who can place a root-owned, non-world-writable malicious `.so` at a configured path (e.g. a supply-chain swap of a trusted file) still achieves code execution.

For an insider-threat product this is the most acute trust-boundary violation in the system: anyone who can write to a configured plugin path, or tamper with the config file (an insider, a writable `/opt`, a world-writable dir, a supply-chain `.so` swap), achieves arbitrary native code execution inside the security agent itself — the very component meant to detect them. The doc comment states the trust requirement but the code enforces none of it.

**Fix:** Before `dlopen`: (1) canonicalize the path and reject if the file or any parent dir is writable by non-root / not owned by the expected principal; (2) verify a configured SHA-256 (or an ed25519 detached signature against a pinned host public key) of the `.so` bytes and fail closed on mismatch; (3) optionally confine `dynamic_plugins` to one locked-down directory. Make verification mandatory, refuse to load on any failure, and log the verified digest for audit.

**Status: PARTIAL — path/ownership gate landed; cryptographic gate still open.** Fix step (1) is now implemented: `load_dynamic` applies a pre-`dlopen` path-safety gate (`check_load_path_safety`) that refuses a world-writable `.so` (or one in a world-writable directory), and — when the host runs as root — one not owned by root (uid 0). This blocks the "writable `/opt` / world-writable dir / supply-chain swap into a loose path" escalation an unprivileged or co-located writer could mount. Fix steps (2)–(3) — a SHA-256/ed25519 **integrity** verification against a pinned key, and confinement to a locked-down directory — remain **open** and are the substantive part of this finding: the path gate authenticates *who could write the file*, not *what the code is*. *Related* loader hardening also landed: enablement is checked before the library is opened (closing H6), the entrypoint and constructors are wrapped in `catch_unwind` (M8), the registration is freed in the plugin's own allocator (H7), and a name-mismatched `.so` is rejected. Tracked as ARCHITECTURE.md ADR #15.

---

### H6 — Disabled dynamic plugins still execute: `.so` is dlopened and its constructor runs before the enable check
**Severity:** High · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/host.rs:69-80` (load at 70, constructor at 72, `is_enabled` only at 76)

For every path in `config.dynamic_plugins`, the host calls `loader::load_dynamic(path)` at `host.rs:70` — which `dlopen`s the library (running static initializers) and invokes its exported `aegis_plugin_entry` symbol at `loader.rs:47` (arbitrary attacker code) — then unconditionally calls `(dynamic.constructor)()` at `host.rs:72`. **All** of this runs *before* `config.is_enabled(&name)` is evaluated at `host.rs:76`. The enable check only decides whether the already-constructed plugin is appended to `loaded`; it cannot retract the `dlopen`, the entrypoint execution, or the constructor.

By contrast, static inventory plugins are gated correctly: `is_enabled` is checked at `host.rs:95` *before* `(reg.constructor)()` at `host.rs:99`. This asymmetry means an operator who lists a suspect `.so` and tries to neutralize it via `disabled_plugins` (or by omitting it from `enabled_plugins`) gets **false containment** — the malicious native code has already run. `disabled_plugins` is least trustworthy for exactly the highest-risk plugin class.

**Fix:** Resolve the intended plugin identity from config (require `dynamic_plugins` entries to carry an expected name) and check `is_enabled()` *before* calling `load_dynamic` — skip the `dlopen` entirely for disabled entries. If the name must come from the library, perform the `is_enabled` check immediately after symbol resolution and before invoking the constructor, and document that loading itself executes code so "disabled" cannot retract a configured path.

**Status: Fixed.** Exactly the recommended fix: `dynamic_plugins` entries now carry a declared `name`, and `is_enabled(&spec.name)` is checked *before* `load_dynamic` (`host.rs:78`), so a disabled-but-listed path is never `dlopen`ed; the library-reported name is additionally asserted against the declared name (`host.rs:109`).

---

### H7 — Cross-module `Box::from_raw` on an FFI-returned pointer (allocator/ownership mismatch → UB)
**Severity:** High · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/loader.rs:54`; contract `crates/aegis-sdk/src/plugin.rs:205,210-215`

The host reconstitutes ownership of the `DynPluginRegistration` with `Box::from_raw(reg_ptr)` (`loader.rs:54`), where `reg_ptr` was allocated *inside* the plugin cdylib (documented pattern: the plugin does `Box::into_raw(Box::new(...))`). The `Box` is dropped at the end of `load_dynamic`, freeing the memory with the **host's** global allocator. For any externally-built cdylib — which is the entire stated purpose of this loader — the plugin allocated the memory and the host frees it, with no guarantee the two share an allocator instance. That is undefined behavior (heap corruption), particularly across mixed toolchains (musl vs glibc), a separately-built cdylib, or a non-Rust producer of the C-ABI symbol. No paired free function exists, and the allocator invariant is undocumented.

Caveat on the secondary claim: `PluginConstructor` is a *Rust*-ABI `fn() -> Box<dyn Plugin>` stored in a `#[repr(C)]` struct and called with the Rust calling convention — it is not actually invoked *through* the C ABI, so that sub-point does not add unsoundness on its own. Note also that no in-tree plugin currently declares `crate-type = ["cdylib"]`, so the bug is **latent** today; but the loader subsystem exists precisely to load external cdylibs, and the ownership pattern is wrong by design.

**Fix:** Have the plugin expose a paired C-ABI free function (e.g. `aegis_plugin_free_registration(*mut DynPluginRegistration)`) and call it instead of `Box::from_raw`, so memory is freed by its owning allocator; or pass the registration by value into a host-provided callback. Prefer not returning `Box<dyn Plugin>` across the boundary — return an opaque handle plus a C-ABI vtable of `extern "C"` fns. Document the same-toolchain/same-allocator invariant until the ABI is hardened.

**Status: Fixed.** The recommended paired free function was added: the SDK defines `DYN_FREE_SYMBOL`, the loader resolves it up front, copies the `Copy` fields out of the raw pointer, and hands the pointer back to the plugin's free function — `Box::from_raw` is gone (`loader.rs:60-89`). The same-allocator invariant is documented on `load_dynamic`.

---

### M1 — Session auth digest binds only `server_pins[0]`, breaking the cert rotation it was designed to support (lockout / availability)
**Severity:** Medium · **Area:** Transport & crypto
**Location:** `plugins/plugin-transport/src/actor.rs:352-363`; `crates/aegis-server/src/ingest.rs:144,191,205,256,432`; `crates/aegis-proto/src/pin.rs:69-70`

`PinnedVerifier` accepts a *set* of pins explicitly to support cert rotation (`pin.rs:69-70`): mid-rotation the agent holds both old and new pins so the TLS handshake succeeds against either served cert. The application-layer auth digest does **not** share that flexibility. The agent unconditionally signs `auth_challenge_digest` with `server_pins[0]` (`actor.rs:355`), while the server rebuilds the digest from the SHA-256 of the single leaf it is currently serving (`ingest.rs:144` `leaf_pin` → `verify_challenge` at `432`).

During a rotation where the agent's `server_pins[0]` is the **old** pin but the server already serves the **new** cert, the TLS handshake still succeeds (pin-set match) but the two digests differ, `verify_strict` fails, the server returns `ServerHello{accepted:false}`, and the agent treats it as `HandshakeErr::Fatal` (`actor.rs:383-385`) → `SessionEnd::Fatal` → the outer loop breaks and stops retrying entirely (`actor.rs:133-139`). The very rotation the pin set enables bricks the agent until a human re-enrolls. It is also order-sensitive: behavior depends on which pin happens to be first in `identity.json`.

**Fix:** Make the pin binding rotation-aware. Best: derive the bound pin from the cert actually presented in *this* handshake (compute `fingerprint(leaf)` from the verified peer cert) so the agent binds exactly what the server computes from the cert it served. At minimum, treat an auth rejection during a known rotation window as `Retry` not `Fatal`, and document that `server_pins[0]` must be the currently-served cert.

**Status: Fixed.** The recommended best fix was taken: `bind_pin(conn.peer_certificates(), …)` derives the bound pin from the **served leaf's** `pin::fingerprint` (`actor.rs:319`), falling back to `server_pins[0]` only if no peer cert is present. A regression test (`bind_pin_uses_served_leaf_not_fallback`) asserts it binds the served leaf rather than the configured fallback, so a rotation no longer bricks the agent.

---

### M2 — `read_message` eagerly allocates up to `MAX_FRAME_BYTES` per frame before reading the body
**Severity:** Medium · **Area:** Transport & crypto
**Location:** `crates/aegis-proto/src/lib.rs:149-155`

`read_message` reads the 4-byte length prefix, checks it against `MAX_FRAME_BYTES` (16 MiB), then does `let mut buf = vec![0u8; len]` and only afterwards `read_exact`s the body. A peer can send a 16 MiB length prefix and then trickle (or never send) the body, forcing a full 16 MiB zeroed allocation up front. On the server this multiplies by the connection cap `MAX_CONNECTIONS = 1024` (`ingest.rs:61`), so coordinated clients can pin ~16 GiB of RAM with frames that never complete — a low-effort memory-exhaustion DoS.

The frame cap bounds a single legitimate frame but not the amplification across many slow/incomplete frames. Mitigations exist but are partial: mutual-TLS + pinning means only enrolled peers reach the session loop, and there is a 30 s first-frame timeout (`ingest.rs:299`) — but the only `tokio::time::timeout` in the file guards the first frame; the per-frame allocation happens for *every* frame, and the session `read_loop` (`ingest.rs:525`) has no body-read deadline. A single compromised enrolled agent can exploit it across all 1,024 slots.

**Fix:** Do not trust the length prefix for the allocation size: read the body incrementally into a reused/capped buffer, growing only as bytes arrive; and/or lower `MAX_FRAME_BYTES` toward the realistic `batch_max_bytes` (1 MiB default). Add a read deadline around the body read, not just the first frame.

**Status: Fixed.** `read_message` no longer pre-allocates the announced length: it starts with `Vec::with_capacity(len.min(READ_CHUNK_BYTES))` and grows incrementally as bytes arrive (`lib.rs:168-177`), so a large length prefix with a slow/absent body cannot force a full `MAX_FRAME_BYTES` allocation. (Body-read deadlines are additionally covered by M3/M4.)

---

### M3 — No timeout on challenge-reply read; enrolled agent can pin a connection slot indefinitely
**Severity:** Medium · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/ingest.rs:413`

The first-frame read is wrapped in `tokio::time::timeout(FIRST_FRAME_TIMEOUT, ...)` (`ingest.rs:299`), but the immediately-following challenge reply — `let reply = read_message(&mut tls).await?` (`ingest.rs:413`) — has no deadline. An adversary holding a valid enrolled key (or a stolen one) can send a correct `ClientHello`, receive the `Noop` challenge, and then stall indefinitely without replying. A `Semaphore` permit is already held at that point (acquired at `ingest.rs:240`), so each stalled connection consumes one of the 1,024 slots plus a Tokio task for its lifetime. With 1,024 such connections the cap is exhausted and legitimate agents are denied service. The attack requires valid credentials, consistent with medium severity (insider / key-theft).

**Fix:** Wrap the challenge-reply read in `tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_message(&mut tls)).await` with the same (or a configurable) deadline, and apply the same pattern to the session `read_loop` (see M4).

**Status: Fixed.** The challenge-reply read is now wrapped in `tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_message(&mut tls))` (`ingest.rs:572`), exactly as recommended.

---

### M4 — No per-session idle timeout in the authenticated read loop enables indefinite slot pinning
**Severity:** Medium · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/ingest.rs:525`

`read_loop` calls `read_message(rd).await` in an unbounded loop (`ingest.rs:525`) with no deadline — this is the post-auth read path, entered only after a successful ClientHello/Noop-challenge/signature exchange. An authenticated agent that goes silent holds a `Semaphore` permit, a task, and a redb handle clone until the peer closes TCP. TCP keepalives are off by default on Tokio `TcpStream` (no `set_keepalive`/`TcpKeepalive` anywhere in the server), so a silently-dropped network path keeps the slot open indefinitely. The server does answer inbound `Ping` with `Pong` but never sends proactive pings or enforces an arrival window. With enough such connections the 1,024-permit cap is exhausted. Reachable only by an already-enrolled agent, but a compromised or buggy agent triggers it. The developers clearly knew the pattern (the 30 s first-frame timeout) but did not extend it to the authenticated phase.

**Fix:** Wrap `read_message` in `tokio::time::timeout` tuned to a reasonable idle window (e.g. 2–5 minutes), or drive a periodic ping probe and tear down sessions that miss the window. Consider `TcpStream` keepalives as a backstop.

**Status: Fixed.** The authenticated `read_loop` now wraps each read in `tokio::time::timeout(SESSION_IDLE_TIMEOUT, read_message(rd))` with a 180s idle window (`ingest.rs:74,691`), tearing down a silent session rather than pinning its slot.

---

### M5 — Agent-supplied `ts_ns`, `source`, and `labels` are stored verbatim without validation
**Severity:** Medium · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/ingest.rs:569`; `crates/aegis-server/src/store.rs:244-251`

After authenticating an agent, `ingest` overwrites `event.agent_id` (`ingest.rs:569`) and validates `event.kind` against the ingestible allowlist, but `event.ts_ns`, `event.source`, and `event.labels` pass through verbatim to `store.write_event` and the event bus. An enrolled agent can therefore: (1) **back-date** events to arbitrary timestamps — `ts_ns` is stored as-is *and* used as the B-tree sort key via `composite_key(ev.ts_ns, ev.id)` (`store.rs:244-251`), silently corrupting the time-ordered audit index and inserting `events_by_agent` entries out of order; (2) supply arbitrarily long `source` strings or unbounded `labels` maps, bloating the DB per write; (3) inject misleading `source` values (e.g. `"host"` or another plugin name) that confuse downstream processors and future alert correlation. Requires an enrolled (authenticated) agent, so not remotely exploitable — but a compromised endpoint can corrupt audit ordering and attribution.

**Fix:** Clamp `ts_ns` to a sane window around `now_ns()` (reject events too far in the future/past); enforce a max length on `event.source`; reject or truncate `labels` maps that exceed a size budget. These checks belong in the per-event loop alongside the existing `agent_id` and `kind` overrides.

**Status: Fixed.** `ts_ns` is clamped to a window around `now_ns()` (`ingest.rs:168-172`, `MAX_TS_SKEW_NS`; regression test `sanitize_clamps_ts_ns`) and `agent_id` is overwritten with the authenticated identity (`ingest.rs:738`), so back-dating the audit sort key and identity-spoofing are closed. (Note: `source` is also host-asserted in-process via `ScopedEmitter`; explicit `source`/`labels` length caps on ingest are a smaller residual.)

---

### M6 — `events_by_agent` index is not pruned during compaction → stale pointers and silent pagination data loss
**Severity:** Medium *(upgraded from low — U1)* · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/store.rs:604-628` (compaction; index update absent)

`Store::compact` prunes old rows from `events` (and `alerts`) via `retain_in` but never touches `events_by_agent`. The store test acknowledges this directly: *"events_by_agent still references both keys, but the pruned event row is gone from `events`, so only the recent one comes back."* Over time an active agent's index vector accumulates composite keys pointing to deleted event rows.

Two effects. First, the eviction cap (`AGENT_EVENT_INDEX_LIMIT` = 10,000) drains oldest-first, so stale low-timestamp keys accumulate at the front; in practice they are evicted before valid recent keys, so cap-driven loss is unlikely. The **concrete, immediate harm** — and the reason for the upgrade — is in pagination: `events_for_agent` computes `total = keys.len()` from the raw index length *including* stale pointers, then slices `keys[start..end]`. Stale pointers silently resolve to nothing, so a requested page of N events can return far fewer (or zero) even though valid events exist deeper in the index. Page offsets (`skip = page * page_size`) are computed against an inflated `total`, so operators see empty/sparse pages and cannot distinguish "no more data" from "stale index holes." That is silent data loss in the operator-facing audit API.

**Fix:** In `compact`, after deleting events older than the cutoff, iterate `events_by_agent` and remove composite keys whose `ts_ns` prefix falls below the same cutoff. Both tables share the write transaction, so the update is atomic.

**Status: Fixed.** `compact` now prunes `events_by_agent` in the **same write transaction** as the event/alert pruning (`store.rs:723-755`), exactly as recommended, with a regression test (`compact_prunes_secondary_index_so_pagination_is_dense`) confirming pagination is dense afterward.

---

### M7 — Hard rule #2 flags a single sub-150 ms typed command gap regardless of session length
**Severity:** Medium · **Area:** Detection integrity
**Location:** `plugins/plugin-agent-detect/src/model.rs:201-203`; `plugins/plugin-agent-detect/src/features.rs:102-103`

Hard rule #2 (`model.rs:201-203`) fires on `f.reaction_floor_hits > 0.0` with no minimum count or fraction threshold: any strictly-positive value raises `p_agent` to at least 0.80, producing a near-certain Agent verdict and adding ~48 risk points. Because `reaction_floor_hits = ratio(sub_floor_nonpaste_gaps, commands.max(1))` (`features.rs:168`), a **single** sub-150 ms non-paste command gap in a 100,000-command session yields `1e-5 > 0.0` and trips the rule; `0.80 > agent_threshold (0.62)` ⇒ `Verdict::Agent`. The code comments document this as an intended "perfection tax," and a test validates it — but it is a real false-positive path: a human pressing arrow-up + Enter right after a fast-returning command (`echo foo`) can legitimately produce a sub-150 ms typed inter-command gap, pushing a genuine human session over the threshold. Not critical (it requires an actual sub-floor typed gap, and the weighted score must be below 0.80 for the rule to be the deciding factor), but it undermines detection precision.

**Fix:** Apply a minimum-evidence threshold: fire only when `sub_floor_nonpaste_gaps >= N` (e.g. 3) or when `reaction_floor_hits` exceeds a small fraction (e.g. 0.01). A single isolated slip in a long, otherwise human-consistent session should nudge `p_agent` modestly and let the weighted average and the sustained-Uncertain path accumulate evidence, not produce a definitive verdict.

**Status: Fixed.** The hard rule now requires minimum evidence: it fires only on `reaction_floor_hits >= 0.25` (`model.rs:206`), mirroring rule #1's gate. A regression test (`single_isolated_floor_slip_does_not_force_agent`) confirms a single isolated slip nudges via the weighted average rather than forcing an Agent verdict.

---

### M8 — No panic isolation across the FFI call or around plugin construction/init
**Severity:** Medium · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/loader.rs:47`; `crates/aegis-core/src/host.rs:72,99,169-172`

Three unprotected failure surfaces (no `catch_unwind` exists anywhere in the crate):
1. The FFI entrypoint is invoked as `entry()` at `loader.rs:47` with no `std::panic::catch_unwind`. If a dynamic plugin's `extern "C"` function unwinds across the FFI boundary, that is undefined behavior.
2. Plugin constructors are called at `host.rs:72` (dynamic) and `host.rs:99` (static) sequentially in `HostBuilder::build`; a panic in a constructor unwinds `build` and tears down host startup.
3. `plugin.init()` is awaited in a sequential loop at `host.rs:169-172`; a panic in any one plugin's init aborts `Host::run` before any plugin starts, so one buggy/hostile plugin denies service to all.

The per-plugin `handle()` loop *is* isolated by the tokio task boundary (good), but `shutdown()` discards every `JoinHandle` with `let _ = handle.await` (`host.rs:290-291`), silently swallowing task panics — an observability gap even where it is not a crash.

**Fix:** Wrap the FFI `entry()` call in `catch_unwind` (and require the SDK's `extern "C"` entry to itself `catch_unwind` and return null on panic). Wrap each constructor and each `plugin.init()` in per-plugin `catch_unwind`/error handling so one plugin's panic is logged and skipped rather than aborting the host. Join `handle()` tasks and log `JoinError` panics instead of discarding them.

**Status: Fixed.** `catch_unwind` now wraps the FFI entrypoint (`loader.rs:71`) and both the dynamic and static constructor paths (`host.rs:91,141`), so a panicking plugin is logged and skipped rather than aborting host startup (five `catch_unwind` sites in `aegis-core`).

---

### M9 — No event-producer authenticity on the bus: any plugin can forge `source` and `agent_id`
**Severity:** Medium · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/host.rs:149-167`; `crates/aegis-core/src/bus.rs:27-41`; `crates/aegis-sdk/src/event.rs:172-199`

Every plugin receives a clone of the same `Arc<dyn Emitter>` (`host.rs:150,166`) and can `emit()` a fully attacker-controlled `Event`, including arbitrary `source` and `agent_id` (both plain `pub String`, `event.rs:172-199`). `BusEmitter::emit` (`bus.rs:27-41`) forwards the event verbatim — no stamping, no per-plugin source binding, no validation. Consequences within a host: (a) a low-privilege Collector plugin can fabricate `Alert`/`Detection`/`Score` events — the product's core outputs — or impersonate another plugin; (b) spoof `source: "host"` to masquerade as kernel-originated; (c) set a foreign `agent_id`, which the store-sink trusts directly (`sink.rs` `touch_agent(&event.agent_id, ...)`).

The *network* boundary is defended — server ingest overwrites the claimed `agent_id` with the TLS-authenticated identity (`ingest.rs:569`) before emitting onto the server bus — so a forged `agent_id` on raw agent telemetry is corrected. But the in-process bus has no equivalent attribution, so any loaded plugin is fully trusted to speak for any identity, and a malicious *server-side* processor plugin can emit crafted `agent_id`/`source` straight into `StoreSink` (`touch_agent`, `upsert_detection`, `upsert_score`, `append_alert`). This is insider-threat-within-the-plugin-ecosystem rather than a remote-unauthenticated bug, hence medium.

**Fix:** Hand each plugin a per-plugin emitter wrapper that stamps `event.source` with the plugin's registered name (rejecting/overwriting attempts to set `"host"` or another plugin) before forwarding, and pins `agent_id` to `config.agent_id`. Reserve a distinct host-only emitter for kernel-originated events, making `source`/`agent_id` kernel-asserted rather than self-declared.

**Status: Fixed.** Exactly the recommended design: each plugin now receives a `ScopedEmitter` (`bus.rs:126-150`, wired at `host.rs:218`) that overwrites `source` with the plugin's registered name and `agent_id` with the host identity before forwarding; the host retains the raw `BusEmitter` for kernel-originated events. A regression test asserts a plugin cannot spoof `"host"` or a foreign `agent_id`. (A per-*kind* producer ACL — e.g. only a `Processor` may emit `Detection` — is a separate, still-open hardening item noted in THREAT_MODEL §4.4 P3.)

---

### M10 — Security events are silently droppable under queue pressure (detection-evasion / no metrics)
**Severity:** Medium · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/bus.rs:31-40`; `crates/aegis-core/src/host.rs:221-226`

Two drop points use `try_send` and discard the event on a full bounded queue with only a `tracing::warn!`: the ingress channel (`bus.rs:31-34`) and the dispatcher per-plugin fan-out (`host.rs:221-225`). All event kinds are treated identically — a high-value `Alert`/`Detection`/`Score` is dropped as readily as a `Heartbeat` or keystroke (no priority field on `Event`, no separate path). With a default queue depth of 4096 (`config.rs`), any holder of a `BusEmitter` (i.e. any plugin — see M9, where a Collector can emit freely) can flood cheap events to saturate the queue *precisely when malicious activity is occurring*, silently evicting the alert/detection that would catch them. The only signal is a log line; there is no counter, rate metric, or guaranteed delivery for security-critical kinds, so operators cannot even reliably tell that detections were lost. (Minor nuance: the `Closed` arm logs at `debug`, but that arm is irrelevant to the saturation attack — see L11.)

**Fix:** At minimum increment a per-kind dropped-events counter/metric so loss is observable and alertable. Better: give `alert`/`detection`/`score` a separate higher-priority or larger/guaranteed path (dedicated channel, or block/spill-to-disk for those kinds while continuing to drop low-value telemetry). Consider emitting a synthetic "events dropped" alert so the loss itself becomes a detection signal.

**Status: Fixed.** Both halves of the recommendation landed: `BusMetrics` (`bus.rs:26-54`) counts every drop by cause (`ingress_dropped_full`/`_closed`, `fanout_dropped_full`), exposed via `RunningHost::bus_metrics()`; and `alert`/`detection`/`score` (`is_critical_kind`, `bus.rs:19-21`) now take a non-droppable back-pressure path (`tx.send().await`, `bus.rs:81-88`), so cheap telemetry can no longer flood-evict them. Regression tests assert both behaviors.

---

### L1 — TLS 1.2 cipher/codepaths compiled in via cargo features (defense-in-depth)
**Severity:** Low · **Area:** Transport & crypto
**Location:** `Cargo.toml:58-59` (`rustls`/`tokio-rustls` features include `"tls12"`); enforcement `crates/aegis-proto/src/tls.rs:52,74`

The workspace enables the `tls12` feature on both `rustls` and `tokio-rustls`. The code **correctly** restricts negotiation to TLS 1.3 only on both ends via `with_protocol_versions(&[&rustls::version::TLS13])` (`tls.rs:52` client, `tls.rs:74` server), so TLS 1.2 cannot be negotiated today — this is **not** an exploitable downgrade. It is flagged purely as defense-in-depth: the feature compiles in the older protocol/cipher implementation, and the verifier also still implements `verify_tls12_signature` (`pin.rs:140`), which would become live if 1.2 were ever negotiated. A future refactor (switching to a default-version builder, or adding a second config path that forgets the explicit pin) would silently re-enable TLS 1.2 because the capability is compiled in.

**Fix:** Drop the `"tls12"` feature from both dependencies so TLS 1.2 cannot be negotiated even if the explicit version pin is lost in a future change. The `TLS13`-only calls then become belt-and-suspenders rather than the sole line of defense.

**Status: Fixed.** The `tls12` feature is gone: `rustls`/`tokio-rustls` are now `default-features = false` with features `["ring", "std"]` / `["ring"]` (root `Cargo.toml` `[workspace.dependencies]`), so TLS 1.2 cannot be negotiated even if the explicit version pin were lost.

---

### L2 — No length limits on enrollment strings (`hostname`, `os`) allow oversized records
**Severity:** Low · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/enroll.rs:107-111`; `crates/aegis-server/src/store.rs:459-462`

`EnrollRequest.hostname` and `.os` are plain `String` with no inline constraint. `ingest` reads the first frame (bounded only by `MAX_FRAME_BYTES` = 16 MiB) and passes them straight to `enroll::enroll()`, which forwards them unchanged to `store.enroll_txn`, which copies them into `AgentRow` via postcard with no length check. The compaction routine explicitly excludes `agents` from pruning, so an attacker holding a valid enrollment token can permanently embed up to ~16 MiB per record. The same applies to the operator-facing `label` in `create_token`. Low severity: requires a valid (single-use) token, impact is bounded storage pollution, no code-exec or data-breach path.

**Fix:** Validate lengths in `enroll.rs` before the store call (e.g. reject `hostname`/`os` over 255 bytes, `label` over 256), returning `EnrollOutcome::Rejected` or an error for out-of-range input.

**Status: Fixed.** `enroll.rs` defines `MAX_ENROLL_FIELD_LEN = 255` (hostname/os) and `MAX_TOKEN_LABEL_LEN = 256`, and rejects (rather than truncates) over-length input before the store call — exactly the recommended bounds.

---

### L3 — Cross-session event replay is not prevented; dedup set is per-connection only
**Severity:** Low · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/ingest.rs:72-76,522`

The `seen: HashSet<uuid::Uuid>` in `read_loop` is created fresh per connection (`ingest.rs:522`); the comment acknowledges *"Replayed-on-reconnect events arrive on a new connection (fresh set)."* `write_event` builds a `(ts_ns, uuid)` composite key — and since the server never overrides agent-supplied `ts_ns` (see M5), an enrolled agent can reconnect and re-send the same `Event.id` with a *different* `ts_ns`, producing a distinct key and a second persisted row. There is no shared dedup guard (no bloom filter, LRU, or conditional insert) across connections. Impact is limited to audit-log duplication and double-counting on the bus — no privilege escalation — so low, but the dedup guarantee is weaker than the comment implies.

**Fix:** Maintain a bounded shared LRU/bloom of recently-seen `Event.id`s (in `Store` or an `Arc<Mutex<…>>`) checked before `write_event`, or make `write_event` a conditional insert so the B-tree itself dedups.

**Status: Fixed.** A bounded **cross-connection** dedup window now exists — a shared `DedupWindow` of `GLOBAL_DEDUP_CAPACITY` (`ingest.rs:89,366`) checked across all connections — so a reconnect-replay of the same `Event.id` is rejected even with a different `ts_ns` (which is itself now clamped, M5).

---

### L4 — Dedup eviction removes a random quarter, not the oldest quarter (in-session replay of arbitrary past IDs)
**Severity:** Low · **Area:** Server ingest & enrollment
**Location:** `crates/aegis-server/src/ingest.rs:548-553`

When `seen` reaches `DEDUP_CAPACITY` (65,536), eviction collects `seen.iter().take(evict_count)` (`ingest.rs:550`). `HashSet::iter` yields hash-bucket order, not insertion order; the comment concedes the removed IDs are only *"effectively the oldest in practice."* A freshly-inserted UUID in a sparse bucket can be iterated before an old one in a dense bucket, so a recently-seen ID can be evicted and then replayed within the same session. The deliberate-collision vector is largely neutralized because Rust's `HashSet` uses SipHash with a per-process random seed (an attacker cannot deterministically place UUIDs), and reaching the cap requires >65 K events in one session — hence low — but the unordered eviction itself is genuine and the "oldest in practice" claim is not guaranteed.

**Fix:** Replace the `HashSet` with a `VecDeque<uuid::Uuid>` (O(1) front eviction) plus a `HashSet` for membership, or an indexed LRU, for true FIFO eviction.

**Status: Fixed.** `DedupWindow` now pairs a `HashSet` for membership with a `VecDeque` recording insertion order and evicts via `pop_front` (`ingest.rs:118-143`) — true FIFO eviction, exactly as recommended.

---

### L5 — Privilege gate checks real uid, not effective uid/capabilities, for the immutable+systemctl operations
**Severity:** Low *(downgraded from medium — D1)* · **Area:** Tamper resistance
**Location:** `plugins/plugin-tamper/src/lib.rs:118-129` (`is_root`, reused by `install.rs:196-198`); enforced at `install.rs:288,378`

`is_root()` parses the **first** field of the `Uid:` line in `/proc/self/status` via `.split_whitespace().next()` — the **real** uid — not the second field (effective uid). Every gated action depends on the *effective* uid / capabilities, not the real uid: clearing the immutable bit needs `CAP_LINUX_IMMUTABLE` (`FS_IOC_SETFLAGS`), `chown_root` needs `CAP_CHOWN`, systemctl needs effective root. No secondary euid/capability check exists in the call chain. Two consequences: (1) a process with `ruid != 0` but `euid == 0`/full caps (a setuid-root wrapper, or a service with `AmbientCapabilities` but non-root real uid) is wrongly *refused* install/uninstall even though it can perform every operation — potentially locking an admin out of the documented escape hatch; (2) a process with `ruid == 0` but dropped effective privileges passes the gate then fails mid-uninstall after immutable bits are already being cleared, leaving a half-torn-down install.

**Downgrade rationale (D1):** both scenarios require exotic invocation configurations that do not arise in normal deployment, and neither enables privilege escalation (you still need real kernel privilege for the ioctls). It is a correctness/robustness defect, not a protection bypass — hence low, not medium.

**Fix:** Gate on the privilege actually required: call `libc::geteuid() == 0` (libc is already a dependency), or compare the second field of the `Uid:` line, or — strongest — test for `CAP_LINUX_IMMUTABLE` specifically. Keep the real-uid check only if you additionally want to require a true root login (then require *both* `euid == 0` and the capability).

**Status: Fixed.** `is_root()` now tests `libc::geteuid() == 0` (`lib.rs:126-129`) — the recommended effective-uid check — instead of parsing the real uid from `/proc/self/status`.

---

### L6 — Installer writes protected files through symlinks (no `O_NOFOLLOW`/`O_EXCL`), enabling arbitrary-file clobber + chown on (re)install
**Severity:** Low *(downgraded from medium — D2)* · **Area:** Tamper resistance
**Location:** `plugins/plugin-tamper/src/install.rs:221-244` (`write_root_owned`) and the binary copy at `install.rs:300-320`

`write_root_owned` opens with `OpenOptions{write,create,truncate}` and no `O_NOFOLLOW`/`O_EXCL`, then calls path-based `chown_root` (`libc::chown`, not `fchown`) — both follow a symlink at the destination. `create_dir_all` silently materializes missing parents. The binary copy uses `std::fs::copy`, which likewise follows a symlink at `install_path`, then path-based `chown_root`. The `set_immutable(path,false)` pre-step only fires if the path exists and operates on the symlink target's inode — it does not block a freshly planted symlink. If an attacker pre-creates a symlink at any destination before a root-run install/reinstall, root truncates the link target, writes attacker-influenced-or-empty content, and `chown`s it to root:root — an arbitrary write/chown primitive.

**Downgrade rationale (D2):** the finding's claim that `unit_dir`/`state_dir` are configurable is overstated — the `Install` subcommand exposes only `--install-path` and `--server`; `unit_dir`/`state_dir` always default to root-owned `/etc/systemd/system` and `/var/lib/aegis`. Default targets are all root-owned, so an unprivileged attacker cannot plant symlinks there. Exploitation requires an operator deliberately redirecting `--install-path` into a user-writable directory, or a TOCTOU race on a writable path — both non-default. The bug is real and worth fixing, but practical default-deployment risk is low.

**Fix:** Open destinations with `O_NOFOLLOW` and prefer `O_EXCL`; if a real prior-install file legitimately exists, `unlink` it explicitly after confirming via `fstat` on an `O_NOFOLLOW` fd that it is a regular root-owned file. For the binary, open `O_NOFOLLOW|O_CREAT|O_TRUNC` and write into the fd instead of `std::fs::copy`. Use `fchown` on the verified fd. Optionally refuse install paths whose parent is not root-owned and 0755/0700.

**Status: Fixed.** Writes now go through `open_nofollow_write` (`OpenOptions` with `custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)`, `install.rs:229-241`), the binary is copied into an `O_NOFOLLOW` destination fd rather than via `std::fs::copy`, and ownership is set with `fchown_root` on the verified fd (`install.rs:208-214`) instead of path-based `chown` — closing the symlink-clobber primitive.

---

### L7 — Runtime tamper loop is alert-only: it never re-arms the immutable bit or restores a drifted file
**Severity:** Low · **Area:** Tamper resistance
**Location:** `plugins/plugin-tamper/src/lib.rs:222-266`

On detecting content drift (`lib.rs:222-234`), a cleared immutable bit (`238-248`), or a missing file (`252-266`), the loop only emits a `Critical` alert (`emit_tamper`); a grep of the file shows no `set_immutable`/write/restore/re-arm in any branch. This is a **defensible, deliberate** design: the module docstring scopes the threat to an *unprivileged* user and declares it is not a rootkit, clearing the immutable bit or replacing a protected file already requires root, and auto-re-arming would race the legitimate root uninstall (which clears the bit on purpose). Detection fires within one check interval (default 15 s). Surfaced as a residual-risk note rather than a defect: a transient-root attacker can clear immutability, do its work, and the agent alerts but the file stays mutable until a human re-installs.

**Fix:** Document this as intended (alert-only, reversible-by-root, explicitly not self-modifying) in `THREAT_MODEL.md`. If self-healing is later desired, gate it behind a config flag, make it cooperate with uninstall (e.g. a sentinel file written at uninstall start that suppresses re-arming), and only re-arm files that still match the manifest digest — never rewrite content.

**Status: Fixed (documentation).** This was a documentation action, not a code change, and it is now done: `docs/THREAT_MODEL.md` §5.2 carries an explicit "On the alert-only tamper loop" design note stating the loop is intentionally alert-only, reversible-by-root, and explicitly not self-modifying (and why auto-re-arming would race the legitimate uninstall). The code behavior (alert-only) is unchanged and remains correct.

---

### L8 — Per-tick integrity check reads each protected file fully into memory with unbounded `std::fs::read`
**Severity:** Low · **Area:** Tamper resistance
**Location:** `plugins/plugin-tamper/src/manifest.rs:147-162` (`verify`) and install-time hashing `manifest.rs:59-68`

`verify()` runs every `check_interval_s` (default 15 s) and does `std::fs::read(&entry.path)` on every manifest entry with no size cap, hashing the whole buffer. `classify()` does compare length before content, but that optimization is wasted because `verify()` has *already* allocated and filled the full buffer before `classify()` is called; the recorded `entry.len` is never used as a pre-read filter via `std::fs::metadata`. A same-path replacement with a multi-gigabyte file is fully read into RAM on every tick before the size mismatch is noticed — a cheap local memory/IO amplification. Bounded by the fact that swapping a root-owned immutable file requires root, hence low.

**Fix:** Use the recorded `len` as a pre-filter: `std::fs::metadata` first, and if `metadata.len() != entry.len`, classify as `SizeChanged` without reading. When sizes match, stream the file through the hasher in fixed-size chunks (`io::copy` into `Sha256`) rather than slurping into a `Vec`, so a hostile same-size-claimed file cannot force an unbounded allocation.

**Status: Fixed.** `verify_entry` now stats first via `symlink_metadata` and returns `SizeChanged` on a length mismatch **without reading** (`manifest.rs:200`); only when sizes match does it stream the file through `hash_reader` (a `Sha256` `io::Write` sink driven by `io::copy`, `manifest.rs:60-74`), so an oversized or same-size-claimed hostile file cannot force an unbounded allocation. A regression test (`verify_uses_size_prefilter_then_streams`) covers it.

---

### L9 — Config parameters `ewma_alpha` and `decay` have no range validation
**Severity:** Low · **Area:** Detection integrity
**Location:** `plugins/plugin-agent-detect/src/lib.rs:124-125`; `plugins/plugin-scoring/src/lib.rs:73-75`

`DetectConfig.ewma_alpha` and `ScoringConfig.decay` are deserialized from operator config via `ctx.config_as()` with no range check (both `init()` functions call it bare). If `ewma_alpha > 1.0`, the EWMA update (`lib.rs:125`) puts a negative weight on the prior, making the running estimate oscillate and the sequential escalation unreliable. If `decay > 1.0`, scores grow on every `bump()` even with no new evidence (`store.rs:75` computes `entry * decay + delta`), falsely escalating subjects whose risk should decay. If `decay < 0.0`, the bump produces a negative intermediate that the clamp resets to 0.0, erasing all accumulated risk every update. Not externally exploitable (requires a malicious/misconfigured config), hence low, but it corrupts detection integrity.

**Fix:** Validate in `init()`: reject `ewma_alpha` outside `(0.0, 1.0]` and `decay` outside `(0.0, 1.0]` with a descriptive error, and document the required ranges on the struct fields.

**Status: Fixed.** Both `init()`s now range-validate: `plugin-scoring` rejects `decay` outside `(0.0, 1.0]` (`scoring/lib.rs:150-152`, regression test `init_rejects_out_of_range_decay`) and `plugin-agent-detect` validates `ewma_alpha`/`decay`; the required ranges are documented on the struct fields.

---

### L10 — `RiskState` scores map grows without bound and is never evicted
**Severity:** Low · **Area:** Detection integrity
**Location:** `plugins/plugin-scoring/src/lib.rs:68-76`

`RiskState.scores` is a `HashMap<String, f64>` that gains an entry for every distinct subject (session_id or `uid:<N>`) that ever triggers a `Detection`/`ProcessExec`, via `or_insert(0.0)` (`lib.rs:74`), and entries are never removed. After a score decays to near-zero it still occupies memory. The plugin's `subscriptions()` lists only `["detection","process.exec","alert"]` — *not* `session.end` — so it cannot clean up on session close, even though `plugin-agent-detect` demonstrates exactly that pattern. `uid:<N>` subjects are not session-scoped and would persist regardless. Per-entry cost is small (~50–100 bytes), so impact is slow unbounded growth in long-running, high-churn deployments — hence low, with no disclosure/escalation path.

**Fix:** Periodically evict entries below a negligible threshold (e.g. < 0.01) or past a TTL; subscribe to `session.end` and remove the corresponding subject on close, mirroring `plugin-agent-detect`.

**Status: Fixed.** Both halves landed: `RiskState::bump` evicts a subject once its score decays at/below `NEGLIGIBLE_SCORE = 0.01` (`scoring/lib.rs:71,88-90`), and the plugin now subscribes to `session.end` and removes the session subject on close (`scoring/lib.rs:140,161`), mirroring `plugin-agent-detect`. Regression tests `negligible_scores_are_evicted` and `session_end_clears_session_subject` cover it.

---

### L11 — Post-shutdown ingress drops are logged at `debug`, hiding event loss
**Severity:** Low · **Area:** Core & plugin loader
**Location:** `crates/aegis-core/src/bus.rs:36-38`

When the ingress channel is closed (`TrySendError::Closed`), `BusEmitter::emit` drops the event and logs only at `tracing::debug!` — while the sibling `Full` arm logs at `warn!` *and* includes the event kind. The shutdown window is real: `dispatcher.await` completes before plugin `shutdown()` calls (`host.rs:285-299`), yet `PluginContext` (holding an `Arc<dyn Emitter>` clone) stays live until the entries are dropped, so any `emit()` during/after dispatcher teardown — including from plugin `shutdown()` callbacks — silently drops at a level invisible by default. Because `emit()` is fire-and-forget (`-> ()`), callers cannot tell. For an audit/telemetry system, losing events at the lowest log level is a gap.

**Fix:** Log the closed-channel drop at `warn!` (or at least `info!`) and include the event kind, mirroring the `Full` branch. Optionally surface a loss signal to callers (a `Result` or a metric) so shutdown-window loss is observable and bounded.

**Status: Fixed.** The closed-channel ingress drop is now logged at `warn!` and carries the event kind (`bus.rs:97-102`), mirroring the `Full` branch; the drop is also counted in `BusMetrics` (`record_ingress_closed`), so shutdown-window loss is both visible at the default level and observable as a metric.

---

## 5. Prioritized remediation backlog

Ordered by *(severity × directness of subversion of the product's purpose × ease of exploitation)*. Items within a tier are independent and can be parallelized.

> **Backlog status:** This was the original work plan. **25 of the 26 items are
> DONE** in code; **1 remains OPEN** (item 1, H5). Item 26 (L7) was a
> documentation decision and is now satisfied in `THREAT_MODEL.md` §5.2. Each item
> below is prefixed with its current status.

**Tier 0 — Subverts the product's core purpose (do first).**
1. **[OPEN] H5 — Verify dynamic `.so` integrity before load** (`loader.rs`). Mandatory hash/signature + path-ownership check; fail closed. **Still unimplemented — the one remaining gap in this report.** The agent loading attacker code is the worst case for an insider-threat tool.
2. **[DONE] H6 — Check `is_enabled` *before* `load_dynamic`** (`host.rs:78`). Disabled entries are never `dlopen`ed; library name is asserted against the declared name.
3. **[DONE] H4 — Strip `NaN` in `to_map()`** (`features.rs:432-438`). `is_finite` guard added.
4. **[DONE] M10 — Make security-event drops observable / prioritized** (`bus.rs`). `BusMetrics` per-cause counters + non-droppable `alert`/`detection`/`score` path. Flood-to-evade primitive closed.

**Tier 1 — High-severity resource & confidentiality.**
5. **[DONE] H1 — Enforce `spill_max_bytes` on the hot path** (centralized inside `Spill::push`, `spill.rs:215`).
6. **[DONE] H3 — Cap per-session `Vec`s + `session.end` removal** (`SAMPLE_CAP=2048`, `features.rs`).
7. **[DONE] H2 — Create `spill.redb` 0600 and its data dir 0700** (`spill.rs:49,58,70`).
8. **[DONE] H7 — Fix cross-allocator `Box::from_raw`** (paired `DYN_FREE_SYMBOL` free, `loader.rs:60-89`).

**Tier 2 — Medium-severity hardening (DoS, auth, integrity).**
9. **[DONE] M2 — Stop trusting the length prefix for allocation** (incremental growth, `aegis-proto/lib.rs:168-177`).
10. **[DONE] M3 + M4 — Add read deadlines** (`FIRST_FRAME_TIMEOUT` on the challenge reply `ingest.rs:572`; `SESSION_IDLE_TIMEOUT` on the read loop `ingest.rs:691`).
11. **[DONE] M5 — Validate `ts_ns` on ingest** (clamped, `ingest.rs:168-172`); `agent_id` overwritten. (`source`/`labels` length caps a minor residual; `source` is host-asserted in-process.)
12. **[DONE] M6 — Prune `events_by_agent` in `compact`** (same write txn, `store.rs:723-755`).
13. **[DONE] M1 — Make the auth-digest pin binding rotation-aware** (`bind_pin` binds the served leaf, `actor.rs:319`).
14. **[DONE] M8 — Add panic isolation** (`catch_unwind` on the FFI entry and both constructor paths).
15. **[DONE] M9 — Per-plugin emitter that stamps `source` and pins `agent_id`** (`ScopedEmitter`, `bus.rs:126-150`). (Per-kind producer ACL still open — separate item.)
16. **[DONE] M7 — Add a minimum-evidence threshold to hard rule #2** (`reaction_floor_hits >= 0.25`, `model.rs:206`).

**Tier 3 — Low-severity cleanups & defense-in-depth.**
17. **[DONE] L1 — Drop the `"tls12"` cargo feature** (root `Cargo.toml`).
18. **[DONE] L9 — Range-validate `ewma_alpha`/`decay`** (both `init`s).
19. **[DONE] L4 / L3 — True FIFO dedup eviction + cross-connection replay guard** (`VecDeque`-backed `DedupWindow` + `GLOBAL_DEDUP`, `ingest.rs`).
20. **[DONE] L5 — Gate on `geteuid()`** (`tamper/lib.rs:126-129`).
21. **[DONE] L6 — `O_NOFOLLOW` + `fchown` in the installer** (`install.rs`).
22. **[DONE] L8 — `metadata()` size pre-filter + streaming hash** in the tamper verify loop (`manifest.rs`).
23. **[DONE] L2 — Length-limit enrollment strings** (`MAX_ENROLL_FIELD_LEN`, `enroll.rs`).
24. **[DONE] L10 — Evict/TTL the scoring `RiskState` map; subscribe to `session.end`** (`scoring/lib.rs`).
25. **[DONE] L11 — Log closed-channel drops at `warn!` with the event kind** (`bus.rs:97-102`).
26. **[DONE-doc] L7 — Document the alert-only tamper design in `THREAT_MODEL.md`** (§5.2 design note; decision, not a code fix).

---

*End of report. 28 findings confirmed at audit time (7 high, 10 medium, 11 low); no false positives; D1/D2 downgraded, U1 upgraded, as noted inline. **Remediation status (verified against code): 26 Fixed, 1 Open (H5 — dynamic-loader integrity gate); the L7 documentation action is satisfied.***
