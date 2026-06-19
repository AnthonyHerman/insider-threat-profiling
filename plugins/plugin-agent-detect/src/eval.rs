//! Reproducible evaluation harness for the agent-vs-human detector.
//!
//! Generates labelled synthetic sessions ([`crate::synth`]), runs them through
//! the real feature pipeline and [`Model`], and reports standard metrics
//! (precision/recall/F1/accuracy and ROC-AUC). It also models an **adaptive
//! evader** via an evasion budget `e ∈ [0,1]` that interpolates the agent's
//! behavioural parameters toward the human's — letting us quantify how detection
//! degrades as an agent spends more effort mimicking a human. These curves are
//! the empirical core of the paper's game-theoretic analysis.

use crate::baseline::{make_dataset, LogisticRegression, TrainConfig};
use crate::features::SessionAccumulator;
use crate::model::Model;
use crate::synth::{synth_session, ProfileParams, Rng};

/// Metrics from one evaluation run (agent = positive class).
#[derive(Debug, Clone, PartialEq)]
pub struct EvalReport {
    pub n_per_class: usize,
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub fn_: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub accuracy: f64,
    /// ROC-AUC over the model's continuous `p_agent`.
    pub auc: f64,
    /// Fraction of all sessions the model declared `Uncertain`.
    pub uncertain_rate: f64,
}

/// Lerp **all** of `from`'s parameters toward `to` by `t` (the joint mimic).
/// `lerp_params(agent, human, t)` is the canonical full-tactic evader; the
/// per-tactic [`evade_tactic`] reuses the same per-field arithmetic on a single
/// family so the joint and ablation paths cannot drift apart.
fn lerp_params(from: &ProfileParams, to: &ProfileParams, t: f64) -> ProfileParams {
    let lerp = |x: f64, y: f64| x + (y - x) * t;
    let lerp2 = |x: (f64, f64), y: (f64, f64)| (lerp(x.0, y.0), lerp(x.1, y.1));
    ProfileParams {
        keystroke_lognormal: lerp2(from.keystroke_lognormal, to.keystroke_lognormal),
        think_lognormal: lerp2(from.think_lognormal, to.think_lognormal),
        backspace_p: lerp(from.backspace_p, to.backspace_p),
        paste_p: lerp(from.paste_p, to.paste_p),
        entropy: lerp2(from.entropy, to.entropy),
        commands: lerp2(from.commands, to.commands),
        keystrokes_per_cmd: lerp2(from.keystrokes_per_cmd, to.keystrokes_per_cmd),
        think_autocorr: lerp(from.think_autocorr, to.think_autocorr),
        think_fatigue: lerp(from.think_fatigue, to.think_fatigue),
    }
}

/// Linear interpolation of agent parameters toward human parameters by `t`.
/// `t = 0` is a naive agent; `t = 1` is a perfect behavioural mimic that has
/// acquired the human's *temporal structure* (serial correlation + fatigue),
/// not just the marginals.
fn evade(t: f64) -> ProfileParams {
    lerp_params(&ProfileParams::agent(), &ProfileParams::human(), t)
}

/// A single, named evasion **tactic family** the adversary can buy in isolation.
///
/// Each variant maps to a disjoint subset of [`ProfileParams`] fields and, in
/// turn, to a known set of [`Model`] terms / hard rules (see [`evade_tactic`]).
/// Moving one family while holding the others at their naive-agent defaults is
/// the per-tactic *ablation* that ranks tactics by evasion efficiency — the
/// empirical test of the design's Tier-1-cheap / Tier-3-costly hypothesis.
///
/// The five tactics enumerate exactly the families that map onto the
/// demoted-Tier-1 vs promoted-Tier-2/3 split the model claims. The remaining
/// `ProfileParams` fields (`entropy`, `commands`, `keystrokes_per_cmd`) back
/// only weak corroborators (`dense-commands` 0.02) or session volume, so they
/// are deliberately *not* exposed as named tactics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tactic {
    /// Keystroke-timing realism: lerp `keystroke_lognormal` (μ, σ).
    /// Moves `metronomic-typing` (0.06) and `burst-metronome` (0.06).
    KeystrokeTiming,
    /// Reaction-time realism: lerp `think_lognormal` (μ, σ).
    /// Moves `instant-reaction` (0.10), `constant-think-time` (0.12), and lifts
    /// gaps off the physiological reaction floor (hard rules).
    ThinkTime,
    /// Stop pasting whole lines: lerp `paste_p`.
    /// Moves `paste-injection` (0.04), `whole-line-injection` (0.12), and
    /// defuses the `physiological-floor+paste` hard rule.
    PasteAvoidance,
    /// Inject corrections: lerp `backspace_p`.
    /// Moves `errorless-input` (0.04) only.
    FakeBackspaces,
    /// Reproduce the human's *joint temporal structure*: lerp **both**
    /// `think_autocorr` and `think_fatigue`. Moves `gap-non-autocorrelation`
    /// (0.22 — the single heaviest term) and `no-throughput-decay` (0.14), and
    /// defuses the `uncorrelated-flat-throughput` hard rule. This is the
    /// promoted Tier-3 cluster the design claims is the load-bearing robustness.
    TemporalStructure,
}

impl Tactic {
    /// All tactics, in a stable order (for harness/table iteration).
    pub const ALL: [Tactic; 5] = [
        Tactic::KeystrokeTiming,
        Tactic::ThinkTime,
        Tactic::PasteAvoidance,
        Tactic::FakeBackspaces,
        Tactic::TemporalStructure,
    ];

    /// Short human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Tactic::KeystrokeTiming => "keystroke-timing",
            Tactic::ThinkTime => "think-time",
            Tactic::PasteAvoidance => "paste-avoidance",
            Tactic::FakeBackspaces => "fake-backspaces",
            Tactic::TemporalStructure => "temporal-structure",
        }
    }
}

/// Build an evader that has spent effort `t ∈ [0,1]` on a **single tactic
/// family**, leaving every other family at the naive-agent default.
///
/// At `t = 0` this is exactly [`ProfileParams::agent()`]; at `t = 1` only the
/// chosen family's fields equal the human's, and all other fields still equal
/// the agent's. This is the per-family analogue of [`evade`] (which lerps every
/// family jointly), and it reuses the identical per-field arithmetic via
/// [`lerp_params`] so the two paths cannot drift.
pub fn evade_tactic(tactic: Tactic, t: f64) -> ProfileParams {
    let a = ProfileParams::agent();
    let h = ProfileParams::human();
    // Start from the naive agent; move only the chosen family toward human.
    let mut p = a.clone();
    let lerp = |x: f64, y: f64| x + (y - x) * t;
    let lerp2 = |x: (f64, f64), y: (f64, f64)| (lerp(x.0, y.0), lerp(x.1, y.1));
    match tactic {
        Tactic::KeystrokeTiming => {
            p.keystroke_lognormal = lerp2(a.keystroke_lognormal, h.keystroke_lognormal);
        }
        Tactic::ThinkTime => {
            p.think_lognormal = lerp2(a.think_lognormal, h.think_lognormal);
        }
        Tactic::PasteAvoidance => {
            p.paste_p = lerp(a.paste_p, h.paste_p);
        }
        Tactic::FakeBackspaces => {
            p.backspace_p = lerp(a.backspace_p, h.backspace_p);
        }
        Tactic::TemporalStructure => {
            p.think_autocorr = lerp(a.think_autocorr, h.think_autocorr);
            p.think_fatigue = lerp(a.think_fatigue, h.think_fatigue);
        }
    }
    p
}

/// Score one accumulator, returning `p_agent` (or `None` if under-evidenced).
fn score(model: &Model, acc: &SessionAccumulator) -> Option<f64> {
    acc.features().map(|f| model.assess(&f).p_agent)
}

/// Evaluate the detector against naive agents (evasion budget 0).
pub fn evaluate(model: &Model, n_per_class: usize, seed: u64) -> EvalReport {
    evaluate_with_evasion(model, n_per_class, seed, 0.0)
}

/// Evaluate with an adaptive evader spending budget `evasion ∈ [0,1]`.
pub fn evaluate_with_evasion(
    model: &Model,
    n_per_class: usize,
    seed: u64,
    evasion: f64,
) -> EvalReport {
    let human = ProfileParams::human();
    let agent = evade(evasion.clamp(0.0, 1.0));

    let mut rng = Rng::new(seed);
    // (p_agent, is_agent_label)
    let mut scored: Vec<(f64, bool)> = Vec::with_capacity(n_per_class * 2);
    let mut uncertain = 0usize;
    let mut total = 0usize;

    for _ in 0..n_per_class {
        for (params, is_agent) in [(&human, false), (&agent, true)] {
            let acc = synth_session(params, &mut rng);
            if let Some(p) = score(model, &acc) {
                scored.push((p, is_agent));
                total += 1;
                let v = model.assess(&acc.features().unwrap()).verdict;
                if matches!(v, aegis_sdk::Verdict::Uncertain) {
                    uncertain += 1;
                }
            }
        }
    }

    // Confusion at the model's production agent threshold (not 0.5). Using the
    // actual classification boundary means precision/recall/accuracy reflect
    // what the plugin truly classifies in production. Sessions below the human
    // threshold are predicted Human; sessions above the agent threshold are
    // predicted Agent; sessions in between are Uncertain — we count Uncertain as
    // "not Agent" for recall and "not Human" for precision, consistent with the
    // plugin's behavior of not emitting an Agent verdict until it crosses the
    // agent_threshold. AUC remains threshold-free.
    let agent_threshold = model.agent_threshold;
    let (mut tp, mut fp, mut tn, mut fn_) = (0usize, 0usize, 0usize, 0usize);
    for &(p, is_agent) in &scored {
        let pred_agent = p >= agent_threshold;
        match (pred_agent, is_agent) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, false) => tn += 1,
            (false, true) => fn_ += 1,
        }
    }

    let precision = safe_div(tp as f64, (tp + fp) as f64);
    let recall = safe_div(tp as f64, (tp + fn_) as f64);
    let f1 = safe_div(2.0 * precision * recall, precision + recall);
    let accuracy = safe_div((tp + tn) as f64, scored.len() as f64);

    EvalReport {
        n_per_class,
        tp,
        fp,
        tn,
        fn_,
        precision,
        recall,
        f1,
        accuracy,
        auc: roc_auc(&scored),
        uncertain_rate: safe_div(uncertain as f64, total as f64),
    }
}

fn safe_div(a: f64, b: f64) -> f64 {
    if b == 0.0 {
        0.0
    } else {
        a / b
    }
}

/// One row of the transparent-vs-learned head-to-head at a given evasion budget.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelComparison {
    /// Evasion budget `e ∈ [0,1]` the agents in the test set spent mimicking a human.
    pub evasion: f64,
    /// ROC-AUC of the transparent [`Model`] on the shared held-out test set.
    pub transparent_auc: f64,
    /// ROC-AUC of the learned [`LogisticRegression`] baseline on the *same* set.
    pub learned_auc: f64,
}

/// Train the learned baseline once on naive synthetic data, then score **both** the
/// transparent model and the learned baseline on a shared, disjoint held-out test
/// set at each evasion budget. Returns one [`ModelComparison`] per budget.
///
/// The procedure is engineered to be a fair, leak-free head-to-head:
///
/// 1. **Train once, on naive data.** The baseline is fit from `human()` vs `agent()`
///    (evasion 0). Training on naive agents — not on the evaded test distribution —
///    is the honest choice: the evader is adaptive and unknown at training time
///    (mirroring [`evaluate_with_evasion`]), and it prevents the LR from trivially
///    memorizing each evasion budget.
/// 2. **Per budget `e`**, derive the evaded agent via the same `evade` lerp used by
///    the rest of the harness, and build **one** held-out test set with a *distinct*
///    seed so train/test draws are disjoint (no leakage from the training RNG stream).
/// 3. **Score both models on that identical test set** with the shared
///    [`roc_auc`] estimator — same rows, same labels, same AUC ⇒ apples-to-apples.
///
/// Both models see the identical evidenced population: under-evidenced sessions
/// (`features() == None`) are dropped inside [`make_dataset`], exactly as
/// [`evaluate_with_evasion`] drops them.
pub fn compare_models_across_evasion(
    n_train_per_class: usize,
    n_test_per_class: usize,
    seed: u64,
    evasion_budgets: &[f64],
) -> Vec<ModelComparison> {
    // 1. Train the learned baseline once on naive (evasion-0) data.
    let mut train_rng = Rng::new(seed);
    let train = make_dataset(
        &ProfileParams::agent(),
        &ProfileParams::human(),
        n_train_per_class,
        &mut train_rng,
    );
    let lr = LogisticRegression::train(&train, &TrainConfig::default());

    let transparent = Model::default();
    let human = ProfileParams::human();

    evasion_budgets
        .iter()
        .enumerate()
        .map(|(i, &e)| {
            let e = e.clamp(0.0, 1.0);
            let agent = evade(e);

            // 2. One held-out test set per budget, with a seed disjoint from train.
            //    The `0x7E57` ("TEST") salt + per-budget index keeps each test
            //    draw disjoint from the training stream and from every other budget.
            let mut test_rng = Rng::new(seed ^ 0x7E57_0000_u64.wrapping_add(i as u64));
            let test = make_dataset(&agent, &human, n_test_per_class, &mut test_rng);

            // 3. Score both models on the identical rows with the shared estimator.
            let mut transparent_scored: Vec<(f64, bool)> = Vec::with_capacity(test.len());
            let mut learned_scored: Vec<(f64, bool)> = Vec::with_capacity(test.len());
            for (f, label) in &test {
                transparent_scored.push((transparent.assess(f).p_agent, *label));
                learned_scored.push((lr.predict_proba(f), *label));
            }

            ModelComparison {
                evasion: e,
                transparent_auc: roc_auc(&transparent_scored),
                learned_auc: roc_auc(&learned_scored),
            }
        })
        .collect()
}

// ===========================================================================
// Measurement A — COST-TO-EVADE
//
// Treat the evasion budget `e ∈ [0,1]` as the adversary's cost (fraction of
// human-mimicry the agent must buy — by design, throughput surrender). The
// defender's *imposed* cost is the minimal `e` at which a genuine agent session
// stops being caught. Two escape thresholds, one per deployed decision layer:
//
//   * `e*_single` — minimal `e` at which the single-shot per-snapshot model no
//     longer emits `Agent` (`p_agent < agent_threshold`).
//   * `e*_seq`    — minimal `e` at which it also escapes the EWMA sequential
//     escalation over a forced-long session. By construction the sequential
//     test only ever *rescues* dead-band campers, so `e*_seq >= e*_single`; the
//     gap is the extra cost the sequential layer imposes (THREAT_MODEL A5).
// ===========================================================================

/// One point on the agent-cohort escape curve: at evasion budget `budget`, what
/// fraction of a genuine-agent cohort is still **caught** by each decision layer.
#[derive(Debug, Clone, PartialEq)]
pub struct EscapeCurve {
    /// Evasion budget `e ∈ [0,1]` the agent cohort spent (full-tactic [`evade`]).
    pub budget: f64,
    /// Fraction caught by the single-shot per-snapshot `Agent` verdict.
    pub caught_single: f64,
    /// Fraction caught by the EWMA sequential escalation (the deployed layer).
    pub caught_seq: f64,
}

/// Cost-to-evade at one operating point (target caught-fraction `tau`),
/// averaged across seeds. Higher `e_*` ⇒ a more robust detector (a naive agent
/// must surrender more throughput to escape).
#[derive(Debug, Clone, PartialEq)]
pub struct CostToEvade {
    /// Target caught-fraction: `e_*` is the minimal budget whose caught-fraction
    /// drops below this (e.g. `0.5` = the median session escapes; `0.05` = the
    /// cohort essentially escapes).
    pub tau: f64,
    /// Minimal budget to push the single-shot caught-fraction below `tau`.
    pub e_single: f64,
    /// Minimal budget to push the sequential caught-fraction below `tau`.
    pub e_seq: f64,
    /// `e_seq - e_single`: the extra cost the sequential test imposes (≥ 0).
    pub seq_premium: f64,
    /// Human cohort's sequential false-positive rate (caught-as-Agent), averaged
    /// across seeds. Must stay ≤ α (~2%) for a high `e_*` to mean *robustness*
    /// rather than a false-positive artifact — reported alongside as a guard.
    pub human_seq_fp: f64,
}

/// Run an agent cohort at one budget through the *real* sequential replay and
/// return `(caught_single, caught_seq)` fractions over the cohort.
fn agent_caught_fractions(
    model: &Model,
    agent: &ProfileParams,
    n: usize,
    rng: &mut Rng,
) -> (f64, f64) {
    let cfg = crate::DetectConfig::default();
    let mut caught_single = 0usize;
    let mut caught_seq = 0usize;
    for _ in 0..n {
        let (single, seq) = run_session_sequential(
            model,
            agent,
            rng,
            cfg.ewma_alpha,
            cfg.escalate_logit,
            cfg.assess_every,
        );
        if single == aegis_sdk::Verdict::Agent {
            caught_single += 1;
        }
        if seq == aegis_sdk::Verdict::Agent {
            caught_seq += 1;
        }
    }
    (
        caught_single as f64 / n as f64,
        caught_seq as f64 / n as f64,
    )
}

/// Sweep the evasion budget over `grid` and return the agent-cohort escape
/// curves (caught-fraction vs budget) for both decision layers, averaged across
/// `seeds`. Drives the genuine `SessionAccumulator` + `Model` + EWMA via
/// [`run_session_sequential`].
pub fn escape_curves(
    model: &Model,
    n_per_class: usize,
    seeds: &[u64],
    grid: &[f64],
) -> Vec<EscapeCurve> {
    grid.iter()
        .map(|&e| {
            let e = e.clamp(0.0, 1.0);
            let agent = evade(e);
            let mut single_acc = 0.0;
            let mut seq_acc = 0.0;
            for &seed in seeds {
                // Salt by budget so each (seed, budget) draw is its own stream
                // (deterministic), matching the disjoint-draw posture elsewhere.
                let mut rng = Rng::new(seed ^ (0xC057_0000u64).wrapping_add((e * 1000.0) as u64));
                let (cs, cq) = agent_caught_fractions(model, &agent, n_per_class, &mut rng);
                single_acc += cs;
                seq_acc += cq;
            }
            let n = seeds.len() as f64;
            EscapeCurve {
                budget: e,
                caught_single: single_acc / n,
                caught_seq: seq_acc / n,
            }
        })
        .collect()
}

/// Human-cohort sequential false-positive rate (fraction caught as `Agent`),
/// averaged across seeds — the honesty guard for cost-to-evade.
fn human_seq_fp_rate(model: &Model, n_per_class: usize, seeds: &[u64]) -> f64 {
    let human = ProfileParams::human();
    let mut acc = 0.0;
    for &seed in seeds {
        let mut rng = Rng::new(seed ^ 0x4055_0000u64); // "FALS" salt
        let (_single, seq) = agent_caught_fractions(model, &human, n_per_class, &mut rng);
        acc += seq;
    }
    acc / seeds.len() as f64
}

/// Minimal budget on `curve` at which `caught` first drops below `tau`, with
/// linear interpolation between the bracketing grid points. Returns `1.0` if the
/// caught-fraction never falls below `tau` within the grid (uncatchable only at
/// perfect mimicry); returns `0.0` if it starts below `tau` (already escaped).
fn crossing(curve: &[(f64, f64)], tau: f64) -> f64 {
    if curve.is_empty() {
        return 1.0;
    }
    if curve[0].1 < tau {
        return curve[0].0;
    }
    for w in curve.windows(2) {
        let (e0, c0) = w[0];
        let (e1, c1) = w[1];
        if c1 < tau {
            // Linear interpolation of the budget where caught == tau.
            let denom = c0 - c1;
            let frac = if denom.abs() > 1e-12 {
                ((c0 - tau) / denom).clamp(0.0, 1.0)
            } else {
                0.0
            };
            return e0 + (e1 - e0) * frac;
        }
    }
    1.0
}

/// Compute the cost-to-evade at each target caught-fraction in `taus`.
///
/// Sweeps the budget `grid` once (via [`escape_curves`]), then for each `tau`
/// finds the single-shot and sequential crossings. Also measures the human
/// sequential false-positive rate as the honesty guard. Deterministic given
/// `seeds`.
pub fn cost_to_evade(
    model: &Model,
    n_per_class: usize,
    seeds: &[u64],
    grid: &[f64],
    taus: &[f64],
) -> Vec<CostToEvade> {
    let curves = escape_curves(model, n_per_class, seeds, grid);
    let single: Vec<(f64, f64)> = curves.iter().map(|c| (c.budget, c.caught_single)).collect();
    let seq: Vec<(f64, f64)> = curves.iter().map(|c| (c.budget, c.caught_seq)).collect();
    let human_seq_fp = human_seq_fp_rate(model, n_per_class, seeds);

    taus.iter()
        .map(|&tau| {
            let e_single = crossing(&single, tau);
            let e_seq = crossing(&seq, tau);
            CostToEvade {
                tau,
                e_single,
                e_seq,
                seq_premium: (e_seq - e_single).max(0.0),
                human_seq_fp,
            }
        })
        .collect()
}

// ===========================================================================
// Measurement B — PER-TACTIC ABLATION
//
// Move ONE tactic family at a time (`evade_tactic`) over effort `t ∈ [0,1]`,
// holding the other four families at agent defaults, and measure how much
// detection drops per unit effort. Ranks tactics by evasion efficiency,
// validating the Tier-1-cheap / Tier-3-costly hypothesis.
// ===========================================================================

/// One effort point on a single tactic's ablation curve, averaged across seeds.
#[derive(Debug, Clone, PartialEq)]
pub struct TacticAblationPoint {
    /// Effort `t ∈ [0,1]` spent on this single tactic family.
    pub effort: f64,
    /// Threshold-free ROC-AUC of `p_agent` on a balanced human-vs-(single-family
    /// evaded agent) cohort. `0.5` = indistinguishable.
    pub auc: f64,
    /// Mean `p_agent` on the *agent* sub-cohort (the §5.5 "p_agent on a true
    /// agent vs budget" curve, per family). Falls as the family is faked.
    pub mean_p_agent_agent: f64,
}

/// Per-tactic ablation summary: the effort curve plus efficiency statistics.
/// Costlier-to-fake tactics show a *smaller* drop and a *larger* area.
#[derive(Debug, Clone, PartialEq)]
pub struct TacticAblation {
    pub tactic: Tactic,
    /// The full effort curve (`effort`, `auc`, `mean_p_agent_agent`).
    pub points: Vec<TacticAblationPoint>,
    /// `AUC(t=0) - AUC(t=1)`: total ranking-power surrendered by this tactic.
    pub auc_drop: f64,
    /// `⟨p_agent⟩(t=0) - ⟨p_agent⟩(t=1)`: total agent-evidence this tactic sheds.
    pub p_agent_drop: f64,
    /// `∫₀¹ ⟨p_agent⟩(t) dt` (trapezoidal): higher ⇒ the family stays
    /// incriminating across all effort ⇒ **costlier to fake**. The per-tactic
    /// analogue of the design's area-under-the-effort-curve headline metric.
    pub area_p_agent: f64,
    /// Local slope of `⟨p_agent⟩` near `t=0` (drop over the first grid step,
    /// per unit effort): a cheap tactic bites immediately (steep), a costly one
    /// barely moves (shallow).
    pub near_zero_slope: f64,
}

/// Ablate a single tactic family over `effort_grid`, balancing human sessions
/// against single-family-evaded agent sessions and scoring through the *real*
/// pipeline. `min_commands` forces a session length so the Tier-3 robust
/// features engage (use `0` for the natural draw).
fn ablate_one(
    model: &Model,
    tactic: Tactic,
    n_per_class: usize,
    seeds: &[u64],
    effort_grid: &[f64],
    min_commands: u32,
) -> TacticAblation {
    let human = ProfileParams::human();

    let points: Vec<TacticAblationPoint> = effort_grid
        .iter()
        .map(|&t| {
            let t = t.clamp(0.0, 1.0);
            let agent = evade_tactic(tactic, t);
            let mut auc_acc = 0.0;
            let mut pmean_acc = 0.0;
            for &seed in seeds {
                // Disjoint stream per (tactic, effort, seed).
                let salt = (tactic as u64)
                    .wrapping_mul(0x9E37_79B9)
                    .wrapping_add((t * 1000.0) as u64);
                let mut rng = Rng::new(seed ^ salt);
                let mut scored: Vec<(f64, bool)> = Vec::with_capacity(n_per_class * 2);
                let mut agent_ps: Vec<f64> = Vec::with_capacity(n_per_class);
                for _ in 0..n_per_class {
                    for (params, is_agent) in [(&human, false), (&agent, true)] {
                        let mut acc = SessionAccumulator::default();
                        for evt in crate::synth::synth_events(params, &mut rng, min_commands) {
                            evt.apply(&mut acc);
                        }
                        if let Some(p) = score(model, &acc) {
                            scored.push((p, is_agent));
                            if is_agent {
                                agent_ps.push(p);
                            }
                        }
                    }
                }
                auc_acc += roc_auc(&scored);
                pmean_acc += if agent_ps.is_empty() {
                    0.0
                } else {
                    agent_ps.iter().sum::<f64>() / agent_ps.len() as f64
                };
            }
            let n = seeds.len() as f64;
            TacticAblationPoint {
                effort: t,
                auc: auc_acc / n,
                mean_p_agent_agent: pmean_acc / n,
            }
        })
        .collect();

    // Trapezoidal area under ⟨p_agent⟩ vs effort over [grid.first, grid.last].
    let area_p_agent = points
        .windows(2)
        .map(|w| {
            let dt = w[1].effort - w[0].effort;
            0.5 * (w[0].mean_p_agent_agent + w[1].mean_p_agent_agent) * dt
        })
        .sum();

    let first = points.first().cloned().unwrap_or(TacticAblationPoint {
        effort: 0.0,
        auc: 0.5,
        mean_p_agent_agent: 0.0,
    });
    let last = points.last().cloned().unwrap_or_else(|| first.clone());
    let near_zero_slope = if points.len() >= 2 {
        let a = &points[0];
        let b = &points[1];
        let dt = b.effort - a.effort;
        if dt.abs() > 1e-12 {
            (a.mean_p_agent_agent - b.mean_p_agent_agent) / dt
        } else {
            0.0
        }
    } else {
        0.0
    };

    TacticAblation {
        tactic,
        auc_drop: first.auc - last.auc,
        p_agent_drop: first.mean_p_agent_agent - last.mean_p_agent_agent,
        area_p_agent,
        near_zero_slope,
        points,
    }
}

/// Per-tactic ablation across all [`Tactic::ALL`] families, with the natural
/// session-length draw (matching [`evaluate_with_evasion`]). Use
/// [`per_tactic_ablation_min_commands`] to force longer sessions so the Tier-3
/// robust features always engage.
pub fn per_tactic_ablation(
    model: &Model,
    n_per_class: usize,
    seeds: &[u64],
    effort_grid: &[f64],
) -> Vec<TacticAblation> {
    per_tactic_ablation_min_commands(model, n_per_class, seeds, effort_grid, 0)
}

/// Per-tactic ablation forcing at least `min_commands` commands per session, so
/// the volume-hungry Tier-3 features ([`crate::features::MIN_COMMANDS_ROBUST`])
/// engage on every session — the robustness cross-check for the headline
/// natural-length run.
pub fn per_tactic_ablation_min_commands(
    model: &Model,
    n_per_class: usize,
    seeds: &[u64],
    effort_grid: &[f64],
    min_commands: u32,
) -> Vec<TacticAblation> {
    Tactic::ALL
        .iter()
        .map(|&tactic| ablate_one(model, tactic, n_per_class, seeds, effort_grid, min_commands))
        .collect()
}

/// ROC-AUC via the Mann–Whitney U statistic (rank method, ties averaged).
pub fn roc_auc(scored: &[(f64, bool)]) -> f64 {
    let n_pos = scored.iter().filter(|(_, l)| *l).count();
    let n_neg = scored.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return 0.5;
    }
    // Sort by score ascending and assign average ranks (1-based).
    let mut idx: Vec<usize> = (0..scored.len()).collect();
    idx.sort_by(|&a, &b| {
        scored[a]
            .0
            .partial_cmp(&scored[b].0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut ranks = vec![0.0f64; scored.len()];
    let mut i = 0;
    while i < idx.len() {
        let mut j = i + 1;
        while j < idx.len() && scored[idx[j]].0 == scored[idx[i]].0 {
            j += 1;
        }
        // Average rank for ties in [i, j).
        let avg = ((i + 1 + j) as f64) / 2.0; // mean of (i+1..=j)
        for &k in &idx[i..j] {
            ranks[k] = avg;
        }
        i = j;
    }

    let sum_ranks_pos: f64 = scored
        .iter()
        .zip(ranks.iter())
        .filter(|((_, l), _)| *l)
        .map(|(_, r)| *r)
        .sum();
    let u = sum_ranks_pos - (n_pos * (n_pos + 1)) as f64 / 2.0;
    u / (n_pos as f64 * n_neg as f64)
}

/// Replay a single synthetic session **snapshot-by-snapshot**, mirroring the
/// sequential test that `plugin-agent-detect`'s `lib.rs` runs live, and return
/// `(single_shot_terminal_verdict, sequential_verdict)`.
///
/// The session is generated by the shared [`synth_events`] (with commands forced
/// ≥22 so the robust Tier-3 features engage and there are several re-assessment
/// snapshots), then fed into the *real* [`SessionAccumulator`] incrementally.
/// Every `assess_every` events we re-assess (exactly as the plugin does) and
/// fold the snapshot's log-likelihood-ratio into an EWMA, applying the identical
/// escalation rule and constants as `maybe_emit`: a sustained `Uncertain`/
/// agent-leaning session is latched to `Agent` once the EWMA crosses
/// `escalate_logit`. The single-shot verdict is the terminal per-snapshot
/// `assess`. Deterministic given `rng`; exercises the genuine feature pipeline.
///
/// Public so the cost-to-evade harness (and examples) can drive the *real*
/// sequential decision layer, not a re-implementation; the production EWMA
/// constants live in [`crate::DetectConfig`].
pub fn run_session_sequential(
    model: &Model,
    params: &ProfileParams,
    rng: &mut Rng,
    ewma_alpha: f64,
    escalate_logit: f64,
    assess_every: u32,
) -> (aegis_sdk::Verdict, aegis_sdk::Verdict) {
    use aegis_sdk::Verdict;

    let events = crate::synth::synth_events(params, rng, 22);

    let mut acc = SessionAccumulator::default();
    let mut since_last_assess: u32 = 0;
    let mut ewma_logit = 0.0f64;
    let mut ewma_inited = false;
    let mut escalated = false;

    // One sequential step on the current accumulator (the live `maybe_emit`
    // body, minus the I/O). Latches `escalated` per the production rule.
    let step = |acc: &SessionAccumulator,
                ewma_logit: &mut f64,
                ewma_inited: &mut bool,
                escalated: &mut bool| {
        let Some(f) = acc.features() else {
            return;
        };
        let a = model.assess(&f);
        let llr = model.log_likelihood_ratio(&a);
        if *ewma_inited {
            *ewma_logit = ewma_alpha * llr + (1.0 - ewma_alpha) * *ewma_logit;
        } else {
            *ewma_logit = llr;
            *ewma_inited = true;
        }
        if *ewma_logit >= escalate_logit && a.verdict == Verdict::Uncertain && !*escalated {
            *escalated = true;
        }
    };

    for evt in &events {
        evt.apply(&mut acc);
        since_last_assess += 1;
        if since_last_assess >= assess_every {
            since_last_assess = 0;
            step(&acc, &mut ewma_logit, &mut ewma_inited, &mut escalated);
        }
    }

    // Final forced assessment (session end) for both the single-shot terminal
    // verdict and the sequential latch.
    let single_shot = acc
        .features()
        .map(|f| model.assess(&f).verdict)
        .unwrap_or(Verdict::Uncertain);
    step(&acc, &mut ewma_logit, &mut ewma_inited, &mut escalated);

    let seq_verdict = if escalated {
        Verdict::Agent
    } else {
        single_shot
    };
    (single_shot, seq_verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_naive_agents_from_humans() {
        let report = evaluate(&Model::default(), 300, 12345);
        // AUC is threshold-free and should be high (well-separated distributions).
        assert!(report.auc > 0.95, "AUC was {}", report.auc);
        // Accuracy and recall are measured at the model's production agent_threshold
        // (0.62), not 0.5. Sessions scoring in the Uncertain band [0.35, 0.62) are
        // correctly not predicted Agent by production — they count as FN for recall.
        // This gives an honest picture of what single-snapshot classification
        // achieves; the sequential EWMA escalation picks up the remaining Uncertain
        // agents over time (see `sequential_testing_catches_partial_mimic`).
        assert!(report.accuracy > 0.75, "accuracy was {}", report.accuracy);
        assert!(report.recall > 0.60, "recall was {}", report.recall);
    }

    #[test]
    fn naive_agent_uncertain_rate_is_meaningful() {
        // A meaningful fraction of naive agents land in the Uncertain band — this
        // is expected and is handled by the sequential EWMA escalation. The point
        // here is to assert that it's not near zero (which would mean the threshold
        // fix had no effect) and not near 1.0 (which would mean the model is too
        // conservative).
        let report = evaluate(&Model::default(), 300, 12345);
        assert!(
            report.uncertain_rate <= 0.70,
            "uncertain rate {:.2}% is implausibly high",
            100.0 * report.uncertain_rate
        );
    }

    #[test]
    fn detection_degrades_with_evasion_effort() {
        let model = Model::default();
        let naive = evaluate_with_evasion(&model, 300, 1, 0.0).auc;
        let mimic = evaluate_with_evasion(&model, 300, 1, 1.0).auc;
        // A perfect behavioural mimic should be much harder to detect than a
        // naive agent — this is the whole point of the evasion analysis.
        assert!(naive > mimic, "naive {naive} should exceed mimic {mimic}");
        assert!(naive > 0.95, "naive AUC {naive}");
    }

    #[test]
    fn roc_auc_basic_properties() {
        // Perfectly separable: all positives score above all negatives.
        let perfect = vec![(0.1, false), (0.2, false), (0.8, true), (0.9, true)];
        assert!((roc_auc(&perfect) - 1.0).abs() < 1e-9);
        // Inverted ⇒ AUC 0.
        let inverted = vec![(0.9, false), (0.8, false), (0.2, true), (0.1, true)];
        assert!(roc_auc(&inverted).abs() < 1e-9);
    }

    #[test]
    fn sequential_testing_catches_partial_mimic() {
        // THREAT_MODEL A5 mitigation in CI: a *partial* mimic (mid evasion
        // budget e=0.5) that single-shot detection often rates `Uncertain` is
        // caught by the sequential EWMA, which escalates the sustained
        // agent-leaner to `Agent`.
        //
        // We assert over a cohort (not a single seed) to be robust to synth
        // noise, using the *production* sequential constants
        // (`DetectConfig::default`): a meaningful share of partial mimics camp
        // `Uncertain` single-shot; the overall sequential `Agent` rate is high;
        // and the dead-band campers are substantially rescued — i.e. sequential
        // testing strictly and materially improves on single-shot.
        let model = Model::default();
        let cfg = crate::DetectConfig::default();
        let partial = evade(0.5);
        let cohort = 200;

        let mut single_uncertain = 0usize;
        let mut seq_agent = 0usize;
        // Of the camped-Uncertain sessions, how many did the sequential test
        // rescue to Agent?
        let mut camped = 0usize;
        let mut camped_escalated = 0usize;

        let mut rng = Rng::new(2024);
        for _ in 0..cohort {
            let (single, seq) = run_session_sequential(
                &model,
                &partial,
                &mut rng,
                cfg.ewma_alpha,
                cfg.escalate_logit,
                cfg.assess_every,
            );
            if single == aegis_sdk::Verdict::Uncertain {
                single_uncertain += 1;
                camped += 1;
                if seq == aegis_sdk::Verdict::Agent {
                    camped_escalated += 1;
                }
            }
            if seq == aegis_sdk::Verdict::Agent {
                seq_agent += 1;
            }
        }

        let frac_single_uncertain = single_uncertain as f64 / cohort as f64;
        let frac_seq_agent = seq_agent as f64 / cohort as f64;
        let rescue_rate = if camped > 0 {
            camped_escalated as f64 / camped as f64
        } else {
            0.0
        };

        // A large share of partial mimics genuinely camp Uncertain single-shot —
        // the dead-band-camping problem is real and prevalent at e=0.5.
        assert!(
            frac_single_uncertain >= 0.45,
            "expected >=45% single-shot Uncertain, got {:.2}% ({} of {})",
            100.0 * frac_single_uncertain,
            single_uncertain,
            cohort
        );
        // The sequential test catches the large majority of partial mimics.
        assert!(
            frac_seq_agent >= 0.65,
            "expected >=65% sequential Agent, got {:.2}%",
            100.0 * frac_seq_agent
        );
        // Crucially, the sequential test rescues most of the dead-band campers
        // (a session that single-shot would otherwise let camp forever).
        assert!(
            rescue_rate >= 0.50,
            "expected >=50% of camped-Uncertain sessions escalated, got {:.2}%",
            100.0 * rescue_rate
        );
    }

    #[test]
    fn sequential_testing_does_not_false_positive_humans() {
        // The safety-critical guard: the sequential EWMA escalation must NOT
        // manufacture `Agent` verdicts on genuine humans. This is the property
        // that makes the dead-band rescue acceptable to deploy.
        let model = Model::default();
        let cfg = crate::DetectConfig::default();
        let human = ProfileParams::human();
        let humans = 500;

        let mut rng = Rng::new(777);
        let mut human_seq_agent = 0usize;
        for _ in 0..humans {
            let (_single, seq) = run_session_sequential(
                &model,
                &human,
                &mut rng,
                cfg.ewma_alpha,
                cfg.escalate_logit,
                cfg.assess_every,
            );
            if seq == aegis_sdk::Verdict::Agent {
                human_seq_agent += 1;
            }
        }
        let fpr = human_seq_agent as f64 / humans as f64;
        assert!(
            fpr <= 0.02,
            "sequential test must keep human false-positive rate low, got {:.2}% ({}/{})",
            100.0 * fpr,
            human_seq_agent,
            humans
        );
    }

    #[test]
    fn transparent_competitive_with_learned_baseline() {
        // Head-to-head on a shared, disjoint held-out set at three evasion budgets.
        // We assert the *honest, demonstrable* properties, NOT that one model beats
        // the other (the learned model can overfit the synthetic generator, so a
        // small edge for it is not evidence of field skill — see
        // docs/model-comparison.md).
        let rows = compare_models_across_evasion(600, 400, 12345, &[0.0, 0.5, 1.0]);
        assert_eq!(rows.len(), 3);

        // (a) Sanity: at zero evasion both models separate the classes well —
        //     the learned baseline genuinely learned the separation, and the
        //     transparent model's priors hold.
        let naive = &rows[0];
        assert!(
            naive.transparent_auc > 0.9,
            "transparent AUC at e=0 was {}",
            naive.transparent_auc
        );
        assert!(
            naive.learned_auc > 0.9,
            "learned AUC at e=0 was {}",
            naive.learned_auc
        );

        // (b) The two models are COMPARABLE at every budget: neither runs away
        //     from the other. A 0.10 AUC band is generous given synth noise and
        //     is symmetric (we do not privilege either model).
        for r in &rows {
            assert!(
                (r.transparent_auc - r.learned_auc).abs() <= 0.10,
                "models not comparable at e={}: transparent {} vs learned {}",
                r.evasion,
                r.transparent_auc,
                r.learned_auc
            );
        }

        // (c) The evasion story holds for BOTH models: a perfect behavioural mimic
        //     (e=1.0) is much harder to detect than a naive agent (e=0.0), and both
        //     collapse toward chance (~0.5). This is the central claim of the
        //     evasion analysis, and it is not an artifact of the transparent model.
        let mimic = &rows[2];
        assert!(
            naive.transparent_auc > mimic.transparent_auc,
            "transparent: naive {} should exceed mimic {}",
            naive.transparent_auc,
            mimic.transparent_auc
        );
        assert!(
            naive.learned_auc > mimic.learned_auc,
            "learned: naive {} should exceed mimic {}",
            naive.learned_auc,
            mimic.learned_auc
        );
        assert!(
            mimic.transparent_auc < 0.65 && mimic.learned_auc < 0.65,
            "both models should approach chance at full mimicry: transparent {}, learned {}",
            mimic.transparent_auc,
            mimic.learned_auc
        );
    }

    // ---- Per-tactic evasion surface (regression + construction) -----------

    #[test]
    fn evade_tactic_at_zero_is_naive_agent() {
        // t = 0 ⇒ exactly the naive agent, for every tactic (no family moved).
        let a = ProfileParams::agent();
        for tac in Tactic::ALL {
            let p = evade_tactic(tac, 0.0);
            assert_eq!(p.keystroke_lognormal, a.keystroke_lognormal, "{tac:?}");
            assert_eq!(p.think_lognormal, a.think_lognormal, "{tac:?}");
            assert_eq!(p.backspace_p, a.backspace_p, "{tac:?}");
            assert_eq!(p.paste_p, a.paste_p, "{tac:?}");
            assert_eq!(p.think_autocorr, a.think_autocorr, "{tac:?}");
            assert_eq!(p.think_fatigue, a.think_fatigue, "{tac:?}");
        }
    }

    #[test]
    fn evade_tactic_at_one_moves_only_its_family() {
        // t = 1 ⇒ the chosen family equals the human's; every other field stays
        // *bit-identical* to the agent's. This pins the disjoint family→field
        // mapping. The moved fields are compared with a tiny epsilon because the
        // lerp `a + (h-a)*1.0` is not bit-exact for floats; the unmoved fields
        // are untouched and so must compare exactly equal.
        let a = ProfileParams::agent();
        let h = ProfileParams::human();
        let close = |x: f64, y: f64| (x - y).abs() < 1e-9;
        let close2 = |x: (f64, f64), y: (f64, f64)| close(x.0, y.0) && close(x.1, y.1);

        let kt = evade_tactic(Tactic::KeystrokeTiming, 1.0);
        assert!(close2(kt.keystroke_lognormal, h.keystroke_lognormal));
        assert_eq!(kt.think_lognormal, a.think_lognormal);
        assert_eq!(kt.paste_p, a.paste_p);
        assert_eq!(kt.think_autocorr, a.think_autocorr);

        let tt = evade_tactic(Tactic::ThinkTime, 1.0);
        assert!(close2(tt.think_lognormal, h.think_lognormal));
        assert_eq!(tt.keystroke_lognormal, a.keystroke_lognormal);

        let pa = evade_tactic(Tactic::PasteAvoidance, 1.0);
        assert!(close(pa.paste_p, h.paste_p));
        assert_eq!(pa.backspace_p, a.backspace_p);

        let fb = evade_tactic(Tactic::FakeBackspaces, 1.0);
        assert!(close(fb.backspace_p, h.backspace_p));
        assert_eq!(fb.paste_p, a.paste_p);

        let ts = evade_tactic(Tactic::TemporalStructure, 1.0);
        assert!(close(ts.think_autocorr, h.think_autocorr));
        assert!(close(ts.think_fatigue, h.think_fatigue));
        assert_eq!(ts.think_lognormal, a.think_lognormal);
    }

    #[test]
    fn evade_joint_equals_lerp_params_refactor() {
        // Regression pin: after refactoring `evade` onto `lerp_params`, the joint
        // sweep must be bit-identical to lerping every field agent→human.
        let a = ProfileParams::agent();
        let h = ProfileParams::human();
        for &t in &[0.0, 0.123, 0.5, 0.777, 1.0] {
            let got = evade(t);
            let expect = lerp_params(&a, &h, t);
            assert_eq!(got.keystroke_lognormal, expect.keystroke_lognormal, "t={t}");
            assert_eq!(got.think_lognormal, expect.think_lognormal, "t={t}");
            assert_eq!(got.backspace_p, expect.backspace_p, "t={t}");
            assert_eq!(got.paste_p, expect.paste_p, "t={t}");
            assert_eq!(got.entropy, expect.entropy, "t={t}");
            assert_eq!(got.commands, expect.commands, "t={t}");
            assert_eq!(got.keystrokes_per_cmd, expect.keystrokes_per_cmd, "t={t}");
            assert_eq!(got.think_autocorr, expect.think_autocorr, "t={t}");
            assert_eq!(got.think_fatigue, expect.think_fatigue, "t={t}");
        }
    }

    // ---- Cost-to-evade ----------------------------------------------------

    fn fine_budget_grid() -> Vec<f64> {
        let mut g = Vec::new();
        let mut e = 0.0f64;
        while e <= 1.0001 {
            g.push((e * 50.0).round() / 50.0);
            e += 0.02;
        }
        g
    }

    #[test]
    fn cost_to_evade_is_positive_and_sequential_costs_more() {
        // The central cost-to-evade properties, asserted over a cohort with
        // generous bands (synth-noise-tolerant, like the sequential_* tests):
        //   (a) a naive agent IS caught ⇒ cost-to-evade > 0;
        //   (b) the sequential layer only ever raises the cost ⇒ e_seq >= e_single
        //       and the premium is materially positive (the value of A5's SPRT);
        //   (c) the human sequential false-positive rate stays ≤ α (~2%) — so a
        //       high cost-to-evade is robustness, not an FP artifact.
        let model = Model::default();
        let grid = fine_budget_grid();
        let rows = cost_to_evade(&model, 200, &[1, 2, 3], &grid, &[0.5, 0.05]);
        assert_eq!(rows.len(), 2);

        for r in &rows {
            assert!(
                r.e_single > 0.05,
                "cost-to-evade must be > 0 (naive agent caught); tau={} e_single={}",
                r.tau,
                r.e_single
            );
            assert!(
                r.e_seq + 1e-9 >= r.e_single,
                "sequential must not lower the cost: tau={} e_seq={} e_single={}",
                r.tau,
                r.e_seq,
                r.e_single
            );
            assert!(
                r.human_seq_fp <= 0.02,
                "human sequential FP must stay ≤ 2%, got {:.3}%",
                100.0 * r.human_seq_fp
            );
        }

        // At the median operating point the sequential premium is sizeable
        // (empirically ≈0.23): the EWMA buys a materially higher cost-to-evade.
        let median = rows.iter().find(|r| r.tau == 0.5).unwrap();
        assert!(
            median.seq_premium >= 0.10,
            "expected a sizeable sequential premium at tau=0.5, got {}",
            median.seq_premium
        );
    }

    #[test]
    fn escape_curves_are_monotone_and_seq_dominates_single() {
        // The agent caught-fraction falls as the budget rises (more mimicry ⇒
        // fewer caught), and the sequential layer catches at least as many as
        // single-shot at every budget (it only rescues, never releases).
        let model = Model::default();
        let grid = fine_budget_grid();
        let curves = escape_curves(&model, 200, &[1, 2, 3], &grid);

        // Sequential dominates single-shot pointwise.
        for c in &curves {
            assert!(
                c.caught_seq + 1e-9 >= c.caught_single,
                "seq must dominate single at e={}: seq={} single={}",
                c.budget,
                c.caught_seq,
                c.caught_single
            );
        }
        // Endpoints: naive agents are essentially all caught; a perfect mimic
        // essentially escapes both layers.
        assert!(curves.first().unwrap().caught_single > 0.95);
        assert!(curves.last().unwrap().caught_seq < 0.10);

        // Broadly decreasing (allow small non-monotone synth wiggles by checking
        // a coarse 0.0 → 0.6 → 1.0 trend on the sequential curve).
        let at = |e: f64| curves.iter().find(|c| (c.budget - e).abs() < 1e-6).unwrap();
        assert!(at(0.0).caught_seq > at(0.6).caught_seq);
        assert!(at(0.6).caught_seq > at(1.0).caught_seq);
    }

    // ---- Per-tactic ablation (the central validation) ---------------------

    #[test]
    fn full_tactic_evasion_beats_any_single_cheap_tactic() {
        // The Stackelberg punchline: spending budget jointly (the full mimic)
        // sheds far more agent-evidence per unit budget than spending it all on
        // any *single* family. At t=1 the joint evader drives mean p_agent near
        // the human floor (~0.11) while the best single tactic stalls (~0.50),
        // because the model's weight sits on joint structure no single marginal
        // can carry. Asserted on the agent sub-cohort mean p_agent.
        let model = Model::default();
        let seeds: &[u64] = &[1, 2, 3];
        let grid = &[0.0, 1.0];

        let mean_p_full = {
            // Full-tactic mean p_agent at t=1 via the evaluate harness' agent draw.
            let agent = evade(1.0);
            let mut ps = Vec::new();
            for &seed in seeds {
                let mut rng = Rng::new(seed ^ 0xF0FF);
                for _ in 0..500 {
                    let acc = synth_session(&agent, &mut rng);
                    if let Some(p) = score(&model, &acc) {
                        ps.push(p);
                    }
                }
            }
            ps.iter().sum::<f64>() / ps.len() as f64
        };

        let abl = per_tactic_ablation(&model, 500, seeds, grid);
        let best_single_p = abl
            .iter()
            .map(|a| a.points.last().unwrap().mean_p_agent_agent)
            .fold(f64::INFINITY, f64::min);

        assert!(
            mean_p_full + 0.15 < best_single_p,
            "full-tactic mimic (mean p_agent {:.3}) must be markedly more evasive than the best \
             single tactic (mean p_agent {:.3})",
            mean_p_full,
            best_single_p
        );
        // And the full mimic should land near the human floor.
        assert!(
            mean_p_full < 0.35,
            "full mimic mean p_agent should approach the human band, got {mean_p_full:.3}"
        );
    }

    #[test]
    fn temporal_structure_is_the_costliest_single_tactic() {
        // Validates the robust-feature design claim: of the five single tactics,
        // TemporalStructure (autocorrelation + throughput) is the COSTLIEST to
        // fake — it sheds the LEAST agent-evidence per unit effort (largest area
        // under the p_agent-vs-effort curve, smallest drop). In isolation this is
        // because moving only the temporal family leaves the other agent signals
        // (and the hard rules) carrying the score — i.e. you must fix the JOINT
        // structure, not one marginal. ThinkTime is the cheapest single tactic
        // (it also defuses a hard-rule condition), so we assert the clear gap
        // against ThinkTime and PasteAvoidance, plus the global max-area property.
        let model = Model::default();
        let grid: Vec<f64> = (0..=10).map(|i| i as f64 / 10.0).collect();
        let abl = per_tactic_ablation(&model, 600, &[1, 2, 3], &grid);

        let get = |t: Tactic| abl.iter().find(|a| a.tactic == t).unwrap();
        let ts = get(Tactic::TemporalStructure);
        let tt = get(Tactic::ThinkTime);
        let pa = get(Tactic::PasteAvoidance);

        // (a) TemporalStructure has the maximum area of all five tactics.
        let max_area = abl
            .iter()
            .map(|a| a.area_p_agent)
            .fold(f64::NEG_INFINITY, f64::max);
        assert!(
            (ts.area_p_agent - max_area).abs() < 1e-9,
            "TemporalStructure must have the max p_agent area (costliest); areas: {:?}",
            abl.iter()
                .map(|a| (a.tactic.label(), a.area_p_agent))
                .collect::<Vec<_>>()
        );

        // (b) TemporalStructure sheds far less evidence than the cheapest tactics.
        assert!(
            ts.p_agent_drop + 0.10 < tt.p_agent_drop,
            "TemporalStructure (drop {:.3}) must be much costlier than ThinkTime (drop {:.3})",
            ts.p_agent_drop,
            tt.p_agent_drop
        );
        assert!(
            ts.p_agent_drop < pa.p_agent_drop,
            "TemporalStructure (drop {:.3}) must be costlier than PasteAvoidance (drop {:.3})",
            ts.p_agent_drop,
            pa.p_agent_drop
        );
    }
}
