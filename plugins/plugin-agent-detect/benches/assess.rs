//! Bench 1 — `Model::assess` throughput.
//!
//! The core scoring step: maps a `FeatureVector` to an `Assessment`. It runs on
//! every re-assessment tick and on session end, is pure CPU (no I/O), and
//! allocates a few small `Vec`s per call (the 12-term vector, the surviving
//! refs, the contributions). This is the cleanest "verdict cost" number.
//!
//! Three inputs exercise distinct code paths:
//!  * `human_like` — a clear human; few terms point agent, no hard rule fires.
//!  * `agent_like` — a clear agent; the floor+paste hard rule ratchets p_agent.
//!  * `short_session_nan` — Tier-3 fields are `NaN`, exercising the survivor
//!    renormalization branch and leaning on the Tier-1 remnants.
//!
//! Inputs are built once, outside the timed closure, so we measure only assess.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use plugin_agent_detect::features::FeatureVector;
use plugin_agent_detect::model::Model;

/// A clear human (the reference literal from `model.rs` tests).
fn human_like() -> FeatureVector {
    FeatureVector {
        keystroke_cv: 0.9,
        paste_ratio: 0.0,
        mean_inter_command_ms: 4000.0,
        backspace_ratio: 0.2,
        entropy_mean: 3.5,
        cadence_regularity: 0.2,
        gap_autocorr: 0.35,
        think_tail_ratio: 5.0,
        throughput_decay: -0.3,
        reaction_floor_hits: 0.0,
        whole_line_paste_ratio: 0.0,
        keystroke_burst_cv: 0.7,
    }
}

/// A clear agent (the reference literal from `model.rs` tests).
fn agent_like() -> FeatureVector {
    FeatureVector {
        keystroke_cv: 0.08,
        paste_ratio: 0.7,
        mean_inter_command_ms: 40.0,
        backspace_ratio: 0.0,
        entropy_mean: 4.8,
        cadence_regularity: 0.95,
        gap_autocorr: 0.0,
        think_tail_ratio: 1.05,
        throughput_decay: 0.1,
        reaction_floor_hits: 0.4,
        whole_line_paste_ratio: 0.7,
        keystroke_burst_cv: 0.1,
    }
}

/// A short session: every Tier-3 temporal feature is `NaN`, so `assess` must
/// drop those terms and renormalize over the survivors.
fn short_session_nan() -> FeatureVector {
    let mut f = human_like();
    f.gap_autocorr = f64::NAN;
    f.think_tail_ratio = f64::NAN;
    f.throughput_decay = f64::NAN;
    f.keystroke_burst_cv = f64::NAN;
    f
}

fn bench_assess(c: &mut Criterion) {
    let model = Model::default();
    let cases: [(&str, FeatureVector); 3] = [
        ("human_like", human_like()),
        ("agent_like", agent_like()),
        ("short_session_nan", short_session_nan()),
    ];

    let mut group = c.benchmark_group("model_assess");
    // One verdict produced per iteration.
    group.throughput(Throughput::Elements(1));
    for (name, fv) in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), fv, |b, fv| {
            b.iter(|| {
                let a = model.assess(black_box(fv));
                black_box(a.p_agent)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_assess);
criterion_main!(benches);
