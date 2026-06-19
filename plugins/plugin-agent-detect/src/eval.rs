//! Reproducible evaluation harness for the agent-vs-human detector.
//!
//! Generates labelled synthetic sessions ([`crate::synth`]), runs them through
//! the real feature pipeline and [`Model`], and reports standard metrics
//! (precision/recall/F1/accuracy and ROC-AUC). It also models an **adaptive
//! evader** via an evasion budget `e ∈ [0,1]` that interpolates the agent's
//! behavioural parameters toward the human's — letting us quantify how detection
//! degrades as an agent spends more effort mimicking a human. These curves are
//! the empirical core of the paper's game-theoretic analysis.

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

/// Linear interpolation of agent parameters toward human parameters by `t`.
/// `t = 0` is a naive agent; `t = 1` is a perfect behavioural mimic.
fn evade(t: f64) -> ProfileParams {
    let h = ProfileParams::human();
    let a = ProfileParams::agent();
    let lerp = |x: f64, y: f64| x + (y - x) * t;
    let lerp2 = |x: (f64, f64), y: (f64, f64)| (lerp(x.0, y.0), lerp(x.1, y.1));
    ProfileParams {
        keystroke_lognormal: lerp2(a.keystroke_lognormal, h.keystroke_lognormal),
        think_lognormal: lerp2(a.think_lognormal, h.think_lognormal),
        backspace_p: lerp(a.backspace_p, h.backspace_p),
        paste_p: lerp(a.paste_p, h.paste_p),
        entropy: lerp2(a.entropy, h.entropy),
        commands: lerp2(a.commands, h.commands),
        keystrokes_per_cmd: lerp2(a.keystrokes_per_cmd, h.keystrokes_per_cmd),
        // A sophisticated mimic must also reproduce the human's *temporal
        // structure* (serial correlation + fatigue), not just the marginals;
        // the evader acquires it only as it spends budget toward `t = 1`.
        think_autocorr: lerp(a.think_autocorr, h.think_autocorr),
        think_fatigue: lerp(a.think_fatigue, h.think_fatigue),
    }
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

    // Confusion at the 0.5 operating point.
    let (mut tp, mut fp, mut tn, mut fn_) = (0usize, 0usize, 0usize, 0usize);
    for &(p, is_agent) in &scored {
        let pred_agent = p >= 0.5;
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
#[cfg(test)]
pub(crate) fn run_session_sequential(
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
        // The real pipeline should cleanly separate the modelled behaviours.
        assert!(report.auc > 0.95, "AUC was {}", report.auc);
        assert!(report.accuracy > 0.85, "accuracy was {}", report.accuracy);
        assert!(report.recall > 0.8, "recall was {}", report.recall);
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
}
