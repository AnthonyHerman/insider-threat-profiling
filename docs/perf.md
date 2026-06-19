# Hot-path micro-benchmarks

Indicative [criterion](https://crates.io/crates/criterion) micro-benchmarks for
the performance-sensitive paths of Aegis: the agent-vs-human scoring model,
behavioral feature extraction, the wire-protocol framing codec, the kernel event
bus, and the end-to-end detector plugin.

> **Read these as indicative, not authoritative.** They were run on a developer
> laptop with background load, frequency scaling, and hyperthreading enabled —
> **not** a quiesced, pinned benchmarking rig. They establish rough orders of
> magnitude and the *shape* of each cost (how it scales with input size), not
> reproducible absolute figures. Treat a number as meaningful to roughly one
> significant figure.

## Methodology

- **Harness:** `criterion 0.5`, one `[[bench]]` target per crate
  (`harness = false`). The bench sources live at:
  - `plugins/plugin-agent-detect/benches/assess.rs` (Bench 1)
  - `plugins/plugin-agent-detect/benches/features.rs` (Bench 2 + scaling)
  - `plugins/plugin-agent-detect/benches/detect_e2e.rs` (Bench 5)
  - `crates/aegis-proto/benches/framing.rs` (Bench 3)
  - `crates/aegis-core/benches/dispatch.rs` (Bench 4)
- **What is timed:** every input is constructed *outside* the timed closure
  (pre-built data with `b.iter`, or `iter_batched` where a fresh owned input is
  consumed per iteration). We measure the hot path, not setup. The async benches
  (proto framing variant 3b, bus dispatch, detector e2e) drive a real `tokio`
  runtime via criterion's `async_tokio` support.
- **Inputs:** realistic. Synthetic sessions come from the crate's own
  `plugin_agent_detect::synth` generator (seeded, deterministic); proto batches
  use a mixed `Keystroke` + `CommandObserved` + `Detection` payload (~400 bytes
  per event serialized), not a single repeated heartbeat.
- **Statistic:** the **median** of each criterion estimate (the middle value of
  criterion's `[lower median upper]` confidence interval). Throughput figures are
  criterion's, derived from the median.
- **Sampling:** reduced for turnaround — `--sample-size 30 --warm-up-time 0.5
  --measurement-time 2`. This widens the confidence intervals (often ±5–15% run
  to run); do not over-read small differences.

### Machine

| | |
|---|---|
| CPU | 11th Gen Intel Core i7-1165G7 @ 2.80 GHz (4 cores / 8 threads) |
| Memory | 39 GiB |
| Kernel | Linux 6.18 |
| Toolchain | rustc 1.92.0, `bench` profile (opt-level 3, thin LTO) |
| Conditions | local dev box, not quiesced; frequency scaling + HT on |

### Reproducing

```sh
# All hot-path benches (full criterion sampling — slower, tighter intervals):
cargo bench -p plugin-agent-detect -p aegis-proto -p aegis-core

# Fast pass matching the numbers below:
cargo bench -p plugin-agent-detect --bench assess -- \
    --sample-size 30 --warm-up-time 0.5 --measurement-time 2
# ...repeat per --bench {assess,features,detect_e2e,framing,dispatch}
```

---

## Bench 1 — `Model::assess` (scoring a feature vector)

`Model::assess(&FeatureVector) -> Assessment`: the transparent additive model.
Pure CPU; per call it builds a 12-element term vector, a surviving-terms vector,
and a contributions vector. Runs on every re-assessment tick and on session end.

| Input | Median time | Notes |
|---|---:|---|
| `human_like` | 352 ns | clear human; no hard rule fires |
| `agent_like` | 533 ns | hard rules fire + reasons assembled (slowest path) |
| `short_session_nan` | 249 ns | Tier-3 fields `NaN`; survivor renormalization, fewer terms survive (fastest) |

A single verdict costs a few hundred nanoseconds — i.e. the scoring step is
free relative to feature extraction (Bench 2) and dispatch (Bench 4). The
`agent_like` case is ~1.5× the human case because the hard-rule ratchet fires
and the explanation (`reasons`) list is populated.

## Bench 2 — Feature extraction (`SessionAccumulator::features`)

The heavy numeric work: `mean_std`, `lag1_autocorr`, two `percentile()` calls
(each sorts a clone of up to `SAMPLE_CAP = 2048` samples), and `decay_slope`.

**`features()` alone** (over a pre-populated accumulator):

| Session | Median time | Notes |
|---|---:|---|
| human, ≥22 commands | 3.69 µs | robust-gate length, Tier-3 engaged |
| agent, ≥22 commands | 3.31 µs | |
| near `SAMPLE_CAP` (~2048 gaps) | 88.3 µs | the two `percentile` sorts dominate |

**Full ingest + extract** (replay the whole event stream into a fresh
accumulator, then `features()`):

| Session | Median time | Events/session | Notes |
|---|---:|---:|---|
| human | 6.76 µs | ~480 | `iter_batched`, fresh accumulator per iter |
| agent | 6.38 µs | ~400 | |

**Cost vs. session length** (the plan's Bench 6, attributed by difference rather
than exposing the private `percentile`/`lag1_autocorr` kernels). `features()`
timed at increasing command counts:

| Commands (≈ gap samples) | Median time |
|---:|---:|
| 16 | 3.10 µs |
| 64 | 12.2 µs |
| 256 | 21.2 µs |
| 1024 | 50.2 µs |
| 2048 | 92.3 µs |

The cost is dominated by the per-call sorts and linear passes over the bounded
sample window; it grows steeply with session length and is the reason
`SAMPLE_CAP` exists (it caps both memory and this sort cost). In production,
`features()` runs once per `assess_every` events, not per event.

## Bench 3 — Proto `EventBatch` encode + decode round-trip

The agent→server hot path: serialize an `EventBatch`, frame it, deserialize.
Mixed realistic payload (~396 bytes/event serialized).

**3a — serialization-only round-trip** (`serde_json::to_vec` + 4-byte
big-endian length prefix + `serde_json::from_slice`; no runtime, lowest
variance — the headline number):

| Events / batch | Frame body | Median time | Throughput |
|---:|---:|---:|---:|
| 1 | ~0.3 KiB | 2.63 µs | ~126 MiB/s |
| 100 | ~39 KiB | 310 µs | ~122 MiB/s |
| 1 000 | ~387 KiB | 3.28 ms | ~115 MiB/s |
| 4 000 | ~1.5 MiB | 15.1 ms | ~100 MiB/s |

**3b — through the real `write_message` / `read_message`** over
`tokio::io::duplex` (exercises the incremental chunked-read growth loop; writer
on a spawned task):

| Events / batch | Median time | Throughput |
|---:|---:|---:|
| 1 | 3.90 µs | ~85 MiB/s |
| 100 | 379 µs | ~100 MiB/s |
| 1 000 | 3.72 ms | ~102 MiB/s |
| 4 000 | 17.4 ms | ~87 MiB/s |

JSON encode+decode runs at ~100 MiB/s and scales linearly with batch bytes
(~3.3 µs per mixed event). The real framing API (3b) adds a modest fixed
overhead over pure serialization (3a) — the duplex copy + task spawn + the
chunked read loop — most visible on the smallest frame. The 4 000-event /
~1.5 MiB frame crosses ~24 of the 64 KiB read chunks, exercising the buffer-grow
path. JSON is a deliberate protocol choice (the `Custom` payload escape hatch
needs a self-describing format); these numbers quantify what that costs.

## Bench 4 — Event bus dispatch (kernel)

Full ingress → dispatcher → per-plugin queue → handler path through a real
`Host`: `RunningHost::emit`, subscription fan-out, delivery to a minimal
counting sink. The host is built and `run()` once outside the timed loop; only
emit + await-delivery is timed. Asserted zero ingress/fan-out drops.

| Events emitted + awaited | Median time | Per-event (amortized) | Throughput |
|---:|---:|---:|---:|
| 1 | 12.0 µs | 12.0 µs | ~84 K events/s |
| 100 | 159 µs | ~1.6 µs | ~628 K events/s |
| 1 000 | 1.57 ms | ~1.6 µs | ~635 K events/s |

The N=1 case is single-event round-trip latency — dominated by cross-task
wakeup (emit → dispatcher task → handler task → notify), not by the dispatch
logic itself. As N grows, that wakeup cost amortizes and the bus sustains
~0.6 M events/s in this two-worker configuration. The model verdict (Bench 1,
~0.5 µs) and per-event accumulation are cheap relative to one bus hop.

## Bench 5 — Detector end-to-end (telemetry → `Detection`)

The flagship realistic path: events arrive at `AgentDetectPlugin::handle`,
accumulate per session, and periodically trigger `maybe_emit` →
`Model::assess` → emit a `Detection`. Composes Bench 1 + Bench 2 + the plugin's
session bookkeeping (the `Mutex<HashMap>` lock, EWMA update, cadence check).
Driven directly through `Plugin::handle` with a capturing emitter (variant 5a,
lower variance than routing through a full `Host`); a fresh plugin instance per
iteration. One run = `SessionStart` + a seeded synthetic session (≥22 commands)
+ `SessionEnd`.

| Session | Median time (whole session) | Events/session | Per-event |
|---|---:|---:|---:|
| human | 297 µs | ~480 | ~0.6 µs |
| agent | 265 µs | ~400 | ~0.7 µs |

A full interactive session (hundreds of telemetry events plus the periodic
re-assessments) is processed end-to-end in a few hundred microseconds. Per
event this is well under a microsecond, dominated by the periodic `features()`
recomputation (Bench 2) that fires every `assess_every` (default 10) events.
This is comfortably faster than interactive telemetry arrives in practice.

---

## Caveats and honest limits

- **Not a controlled benchmark.** Dev laptop, background load, frequency
  scaling and hyperthreading on, reduced criterion sampling. Run-to-run
  variation is commonly ±5–15%.
- **Microbenchmarks, not system throughput.** These measure isolated functions
  (or one plugin / one bus). They do not capture contention across many
  concurrent sessions, real socket I/O and TLS, disk-backed storage, or GC-like
  pauses. The server-side ingest path (mutual TLS, signature verification,
  persistence) is *not* covered here.
- **Synthetic inputs.** Sessions come from the modelled behavioral
  distributions, not field data; serialized sizes use a representative mixed
  payload. They validate the *shape* of each cost, not field-accurate latencies.
- **Allocation cost is included on purpose.** `assess` and `features` allocate
  small `Vec`s per call; the benches surface that real per-call cost rather than
  optimizing it away.

The takeaways that *are* robust: scoring is cheap (sub-µs); feature extraction
is the dominant per-tick CPU cost and scales with session length (hence the
`SAMPLE_CAP` bound); JSON framing runs at ~100 MiB/s and scales linearly with
batch size; and one bus hop (~1–2 µs amortized) costs more than a model verdict,
so the kernel's task-handoff — not the detection math — is the throughput
ceiling for the in-process pipeline.
