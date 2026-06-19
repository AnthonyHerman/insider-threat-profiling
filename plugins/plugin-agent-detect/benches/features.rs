//! Bench 2 — feature extraction over a full session (+ Bench 6: cost vs length).
//!
//! `SessionAccumulator::features()` does the heavy numeric work: `mean_std`,
//! `lag1_autocorr`, two `percentile()` calls (each sorts a clone of up to
//! `SAMPLE_CAP = 2048` samples), and `decay_slope`. This is the per-tick cost
//! that scales with session length.
//!
//! Two measurements:
//!   1. `features()` alone over a pre-populated accumulator (isolates the
//!      statistics cost) — at a realistic length and near the sample cap.
//!   2. Full ingest + extract: replay a pre-generated `Vec<SynthEvent>` into a
//!      fresh accumulator, then call `features()` (the realistic per-session
//!      fold cost).
//!
//! A third group ("features_by_length") times `features()` at several session
//! lengths so the feature-extraction cost can be attributed by difference — the
//! plan's Bench 6 without changing the visibility of the private kernels.
//!
//! All synthetic event vectors are generated with a seeded RNG outside the
//! timed region, so the measurement is deterministic and excludes setup.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use plugin_agent_detect::features::SessionAccumulator;
use plugin_agent_detect::synth::{synth_events, ProfileParams, Rng, SynthEvent};

/// Build a deterministic synthetic event stream for a profile, forcing at least
/// `min_commands` so the Tier-3 features engage (mirrors the end-to-end test).
fn events(params: &ProfileParams, seed: u64, min_commands: u32) -> Vec<SynthEvent> {
    let mut rng = Rng::new(seed);
    synth_events(params, &mut rng, min_commands)
}

/// Fold a pre-generated event stream into a fresh accumulator.
fn accumulate(evts: &[SynthEvent]) -> SessionAccumulator {
    let mut acc = SessionAccumulator::default();
    for e in evts {
        e.apply(&mut acc);
    }
    acc
}

fn bench_features(c: &mut Criterion) {
    let human = ProfileParams::human();
    let agent = ProfileParams::agent();

    // Realistic robust-length sessions (>= 22 commands so Tier-3 engages).
    let human_evts = events(&human, 1, 22);
    let agent_evts = events(&agent, 2, 22);
    // A session near the SAMPLE_CAP (2048) so the percentile sort cost shows up.
    // Forcing ~2200 commands generates well over 2048 command-gap samples; the
    // rolling window keeps the most recent SAMPLE_CAP.
    let capped_evts = events(&human, 3, 2200);

    let human_acc = accumulate(&human_evts);
    let agent_acc = accumulate(&agent_evts);
    let capped_acc = accumulate(&capped_evts);

    // --- (1) features() alone -------------------------------------------------
    let mut group = c.benchmark_group("features_extract");
    group.throughput(Throughput::Elements(1));
    for (name, acc) in [
        ("human", &human_acc),
        ("agent", &agent_acc),
        ("near_sample_cap", &capped_acc),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), acc, |b, acc| {
            b.iter(|| black_box(acc.features()));
        });
    }
    group.finish();

    // --- (2) full ingest + extract -------------------------------------------
    // Fresh accumulator per iteration (iter_batched), so session state never
    // accumulates across iterations. We measure replay-of-events + features().
    let mut group = c.benchmark_group("features_ingest_extract");
    for (name, evts) in [("human", &human_evts), ("agent", &agent_evts)] {
        group.throughput(Throughput::Elements(evts.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), evts, |b, evts| {
            b.iter_batched(
                SessionAccumulator::default,
                |mut acc| {
                    for e in evts {
                        e.apply(&mut acc);
                    }
                    black_box(acc.features())
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Bench 6 (attribute-by-difference): `features()` cost as session length grows.
/// The dominant terms inside `features()` are the two O(n log n) `percentile`
/// sorts and the O(n) `lag1_autocorr`/`decay_slope` passes; timing `features()`
/// across lengths lets the paper attribute the cost without exposing the private
/// kernels.
fn bench_features_by_length(c: &mut Criterion) {
    let human = ProfileParams::human();
    let mut group = c.benchmark_group("features_by_length");
    for min_cmds in [16u32, 64, 256, 1024, 2048] {
        let evts = events(&human, 100 + min_cmds as u64, min_cmds);
        let acc = accumulate(&evts);
        // Report per actual command-gap sample count so cost/elem is comparable.
        group.throughput(Throughput::Elements(min_cmds as u64));
        group.bench_with_input(BenchmarkId::from_parameter(min_cmds), &acc, |b, acc| {
            b.iter(|| black_box(acc.features()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_features, bench_features_by_length);
criterion_main!(benches);
