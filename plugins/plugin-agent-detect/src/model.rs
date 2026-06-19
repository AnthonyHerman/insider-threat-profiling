//! The agent-vs-human scoring model.
//!
//! A deliberately *transparent* additive model: each feature is mapped to an
//! "agent-evidence" value in [0,1] by a logistic transfer with a documented
//! centre and slope, then combined as a weighted average. Transparency matters
//! for an insider-threat tool — every verdict can be explained by which features
//! drove it, which is exactly what [`Detection::reasons`](aegis_sdk::EventPayload)
//! carries. The detection workflow can swap in a learned model behind the same
//! [`Model`] interface; the synthetic-evaluation harness scores either.
//!
//! ## Design: weight the evasion-robust signals
//!
//! The Tier-1 marginals (keystroke CV, paste ratio, mean think time, backspace
//! ratio, entropy, cadence) are cheap to forge — an evader injecting i.i.d.
//! padding delays and jitter matches all of them and historically slipped to a
//! `Human` verdict. We therefore *demote* the Tier-1 terms (combined ≈0.24) and
//! put the bulk of the weight (≈0.66) on Tier-2/3 joint-structure terms
//! (gap autocorrelation, constant-think-time, throughput decay, whole-line
//! injection, burst metronome) that an i.i.d.-delay evader cannot reproduce.
//!
//! ## NaN handling
//!
//! Short sessions emit `NaN` for the volume-hungry Tier-3 features (see
//! [`crate::features::MIN_COMMANDS_ROBUST`]). [`Model::assess`] drops any term
//! whose evidence is `NaN` and renormalizes the weighted average over the
//! surviving terms, so a short session leans on the hard-rule inputs and the
//! Tier-1 remnants → more `Uncertain`, by design (FPR-protecting).
//!
//! ## Hard rules (asymmetric ratchet)
//!
//! After the weighted average, a small set of *explainable* hard rules can only
//! ever **raise** the agent evidence (noisy-OR / max-pooling). They encode
//! physiological impossibilities (sub-150 ms non-paste reaction) and decisive
//! agent signatures (uncorrelated + flat throughput). Pure *absence* of these
//! signals never pushes a subject toward `Human`.

use crate::features::FeatureVector;
use aegis_sdk::Verdict;

/// Logistic squashing function.
#[inline]
pub fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// A single feature's contribution to the agent-evidence score.
struct Term {
    name: &'static str,
    weight: f64,
    /// Agent-evidence in [0,1]. `NaN` ⇒ "no evidence" (term is skipped and the
    /// weighted average renormalizes over the surviving terms).
    evidence: f64,
}

/// Output of the model: probability the subject is an automated agent, plus the
/// per-feature evidence that produced it (for explanation).
#[derive(Debug, Clone)]
pub struct Assessment {
    pub p_agent: f64,
    pub verdict: Verdict,
    pub confidence: f64,
    pub reasons: Vec<String>,
}

/// The transparent additive model with hand-calibrated coefficients.
///
/// The thresholds are **FPR-budgeted**: they should be set to the (1−α) quantile
/// of the *human-only* `p_agent` distribution (α ≈ 1%), so that at most ~1% of
/// genuine humans are ever called `Agent`. The defaults here are calibrated
/// against the synthetic human distribution; **a field deployment must re-derive
/// them from its own human population** before trusting the `Agent` verdict.
#[derive(Debug, Clone)]
pub struct Model {
    /// p_agent above this ⇒ Agent. Tightened from 0.65 → 0.62 so the re-weighted
    /// robust evidence on evaded agents crosses, while the human distribution
    /// (≈0.03) stays far below.
    pub agent_threshold: f64,
    /// p_agent below this ⇒ Human. Between the two ⇒ Uncertain.
    pub human_threshold: f64,
}

impl Default for Model {
    fn default() -> Self {
        Model {
            agent_threshold: 0.62,
            human_threshold: 0.35,
        }
    }
}

impl Model {
    fn terms(&self, f: &FeatureVector) -> Vec<Term> {
        vec![
            // --- Tier 1 (demoted): cheap first-moment marginals ---------------
            // Low keystroke CV ⇒ metronomic ⇒ agent. Cheap jitter beats this.
            Term {
                name: "metronomic-typing",
                weight: 0.06,
                evidence: sigmoid(8.0 * (0.45 - f.keystroke_cv)),
            },
            // High paste ratio ⇒ commands injected wholesale ⇒ agent. Superseded
            // by the whole-line-injection term below.
            Term {
                name: "paste-injection",
                weight: 0.04,
                evidence: f.paste_ratio.clamp(0.0, 1.0),
            },
            // Short mean think time ⇒ reacting fast ⇒ agent. Kept modest; the
            // physiological *floor* lives in a hard rule, not here.
            Term {
                name: "instant-reaction",
                weight: 0.10,
                evidence: sigmoid(0.004 * (1000.0 - f.mean_inter_command_ms)),
            },
            // No corrections ⇒ never mistypes ⇒ agent. A free bool to fake.
            Term {
                name: "errorless-input",
                weight: 0.04,
                evidence: sigmoid(40.0 * (0.06 - f.backspace_ratio)),
            },
            // Dense, high-entropy one-liners ⇒ weak agent corroborator.
            Term {
                name: "dense-commands",
                weight: 0.02,
                evidence: sigmoid(3.0 * (f.entropy_mean - 4.2)),
            },
            // Clockwork command cadence ⇒ agent. Redundant with autocorr.
            Term {
                name: "regular-cadence",
                weight: 0.04,
                evidence: f.cadence_regularity.clamp(0.0, 1.0),
            },
            // --- Tier 2/3 (promoted): joint structure & distribution shape ----
            // Lag-1 autocorrelation of think times. i.i.d. injected delays (≈0)
            // score high-agent; the genuine human band (0.1–0.6) scores low.
            // This traps the cheapest evasion. NaN below the robust gate.
            Term {
                name: "gap-non-autocorrelation",
                weight: 0.22,
                evidence: nan_or(f.gap_autocorr, |x| sigmoid(6.0 * (0.18 - x))),
            },
            // Constant/uniform think-time padding ⇒ tail ratio ≈1 ⇒ high-agent;
            // genuine heavy tails (>4) ⇒ low. Defeats reaction padding.
            Term {
                name: "constant-think-time",
                weight: 0.12,
                evidence: nan_or(f.think_tail_ratio, |x| sigmoid(2.2 * (2.0 - x))),
            },
            // No throughput decay ⇒ agent. Negative slope (human fatigue) ⇒ low;
            // flat/positive ⇒ high. Forces an evader to surrender throughput.
            Term {
                name: "no-throughput-decay",
                weight: 0.14,
                evidence: nan_or(f.throughput_decay, |x| sigmoid(4.0 * (x + 0.05))),
            },
            // Atomic whole-line delivery is agent-shaped.
            Term {
                name: "whole-line-injection",
                weight: 0.12,
                evidence: f.whole_line_paste_ratio.clamp(0.0, 1.0),
            },
            // Within-burst metronome corroborates char-by-char fakes. NaN if too
            // few burst gaps to estimate.
            Term {
                name: "burst-metronome",
                weight: 0.06,
                evidence: nan_or(f.keystroke_burst_cv, |x| sigmoid(8.0 * (0.30 - x))),
            },
        ]
    }

    /// Assess a feature vector.
    pub fn assess(&self, f: &FeatureVector) -> Assessment {
        let terms = self.terms(f);

        // Weighted average over terms with finite evidence (NaN ⇒ "no evidence",
        // renormalize). If every robust term dropped out and nothing is left, we
        // fall back to a neutral 0.5 (maximally Uncertain).
        let surviving: Vec<&Term> = terms.iter().filter(|t| t.evidence.is_finite()).collect();
        let total_w: f64 = surviving.iter().map(|t| t.weight).sum();
        let mut p_agent: f64 = if total_w > 0.0 {
            surviving.iter().map(|t| t.weight * t.evidence).sum::<f64>() / total_w
        } else {
            0.5
        };

        // --- Hard rules: asymmetric ratchet (can only raise p_agent) ----------
        // Each appends an explanation so every escalation is auditable.
        let mut rule_reasons: Vec<&'static str> = Vec::new();

        // (1) Sustained sub-floor reaction co-occurring with whole-line delivery
        //     is a decisive agent signature.
        if f.reaction_floor_hits >= 0.25 && f.whole_line_paste_ratio >= 0.5 {
            if 0.92 > p_agent {
                p_agent = 0.92;
            }
            rule_reasons.push("physiological-floor+paste");
        }
        // (2) Any sub-floor non-paste slip — a "perfection tax". One slip in a
        //     long session incriminates; pure absence contributes nothing.
        if f.reaction_floor_hits > 0.0 {
            if 0.80 > p_agent {
                p_agent = 0.80;
            }
            rule_reasons.push("reaction-time-floor");
        }
        // (3) Zero-autocorrelation + flat throughput + constant think-time: the
        //     i.i.d.-delay evader that beats the marginals. We require all three
        //     robust temporal signals to point to automation simultaneously,
        //     including a *narrow* think-time distribution (tail ≈1, i.e.
        //     constant/uniform padding). A genuine operator who momentarily
        //     shows low sampled autocorrelation still has a heavy think-time tail
        //     (ratio ≫1) and so does NOT trip this rule — that joint condition
        //     is what keeps the human false-positive rate low. Only fires when
        //     the features are present (finite).
        if f.gap_autocorr.is_finite()
            && f.throughput_decay.is_finite()
            && f.think_tail_ratio.is_finite()
            && f.gap_autocorr < 0.05
            && f.throughput_decay > -0.05
            && f.think_tail_ratio < 1.6
        {
            if 0.72 > p_agent {
                p_agent = 0.72;
            }
            rule_reasons.push("uncorrelated-flat-throughput");
        }

        let verdict = if p_agent >= self.agent_threshold {
            Verdict::Agent
        } else if p_agent <= self.human_threshold {
            Verdict::Human
        } else {
            Verdict::Uncertain
        };
        let confidence = match verdict {
            Verdict::Agent => p_agent,
            Verdict::Human => 1.0 - p_agent,
            Verdict::Uncertain => 1.0 - (p_agent - 0.5).abs() * 2.0,
        };

        // Explain: the strongest contributors toward the chosen direction. Hard
        // rules (if any fired) lead the list — they are the decisive evidence.
        let mut contribs: Vec<(&'static str, f64)> = surviving
            .iter()
            .map(|t| {
                let signed = if matches!(verdict, Verdict::Human) {
                    t.weight * (1.0 - t.evidence)
                } else {
                    t.weight * t.evidence
                };
                (t.name, signed)
            })
            .collect();
        contribs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut reasons: Vec<String> = Vec::new();
        // Hard-rule reasons only make sense when the verdict is not Human (they
        // are agent-raising); include them first when relevant.
        if !matches!(verdict, Verdict::Human) {
            reasons.extend(rule_reasons.iter().map(|s| s.to_string()));
        }
        reasons.extend(
            contribs
                .into_iter()
                .take(3)
                .filter(|(_, c)| *c > 0.0)
                .map(|(name, _)| name.to_string()),
        );

        Assessment {
            p_agent,
            verdict,
            confidence,
            reasons,
        }
    }

    /// Per-snapshot agent-evidence in log-odds, for sequential accumulation.
    ///
    /// Returns `logit(p_agent)`; `> 0` leans agent, `< 0` leans human. lib.rs
    /// accumulates this across re-assessments (an EWMA / sequential test) so a
    /// session that *consistently* leans agent can be escalated even if no single
    /// snapshot crosses the per-snapshot `agent_threshold`.
    pub fn log_likelihood_ratio(&self, a: &Assessment) -> f64 {
        let p = a.p_agent.clamp(1e-4, 1.0 - 1e-4);
        (p / (1.0 - p)).ln()
    }
}

/// Apply `f` to `x` if `x` is finite, else propagate `NaN` (so the term is
/// skipped by [`Model::assess`]).
#[inline]
fn nan_or(x: f64, f: impl Fn(f64) -> f64) -> f64 {
    if x.is_finite() {
        f(x)
    } else {
        f64::NAN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn classifies_human() {
        let a = Model::default().assess(&human_like());
        assert_eq!(a.verdict, Verdict::Human, "p_agent={}", a.p_agent);
        assert!(a.p_agent < 0.35);
        assert!(a.confidence > 0.6);
    }

    #[test]
    fn classifies_agent() {
        let a = Model::default().assess(&agent_like());
        assert_eq!(a.verdict, Verdict::Agent, "p_agent={}", a.p_agent);
        assert!(a.p_agent > 0.62);
        assert!(!a.reasons.is_empty());
    }

    #[test]
    fn monotonic_in_paste_ratio() {
        let model = Model::default();
        let mut f = human_like();
        let low = model.assess(&f).p_agent;
        f.paste_ratio = 1.0;
        f.whole_line_paste_ratio = 1.0;
        let high = model.assess(&f).p_agent;
        assert!(high > low);
    }

    #[test]
    fn nan_terms_are_skipped_and_renormalized() {
        // A short-session vector: all Tier-3 temporal terms are NaN. The model
        // must still produce a finite p_agent from the surviving terms.
        let mut f = human_like();
        f.gap_autocorr = f64::NAN;
        f.think_tail_ratio = f64::NAN;
        f.throughput_decay = f64::NAN;
        f.keystroke_burst_cv = f64::NAN;
        let a = Model::default().assess(&f);
        assert!(a.p_agent.is_finite(), "p_agent {}", a.p_agent);
        // With strong human Tier-1 remnants it should not be called Agent.
        assert_ne!(a.verdict, Verdict::Agent);
    }

    #[test]
    fn reaction_floor_hard_rule_ratchets_up() {
        // A vector that the weighted average alone would rate low-agent, but with
        // a single physiological-floor slip the hard rule lifts it.
        let mut f = human_like();
        f.reaction_floor_hits = 0.1; // one slip in a long session
        let a = Model::default().assess(&f);
        assert!(a.p_agent >= 0.80, "p_agent {}", a.p_agent);
        assert!(a.reasons.iter().any(|r| r == "reaction-time-floor"));
    }

    #[test]
    fn floor_plus_paste_hard_rule_is_decisive() {
        let mut f = human_like();
        f.reaction_floor_hits = 0.3;
        f.whole_line_paste_ratio = 0.6;
        let a = Model::default().assess(&f);
        assert!(a.p_agent >= 0.92, "p_agent {}", a.p_agent);
        assert_eq!(a.verdict, Verdict::Agent);
        assert!(a.reasons.iter().any(|r| r == "physiological-floor+paste"));
    }

    #[test]
    fn uncorrelated_flat_throughput_rule_fires() {
        // No paste, no floor slip, but the full i.i.d.-evader signature: ≈0
        // autocorrelation, flat throughput, AND a narrow (constant-padding)
        // think-time distribution. All three are required so a genuine human
        // with a heavy tail never trips it.
        let mut f = human_like();
        f.gap_autocorr = 0.0;
        f.throughput_decay = 0.0;
        f.think_tail_ratio = 1.2; // narrow ⇒ constant padding
        let a = Model::default().assess(&f);
        assert!(a.p_agent >= 0.72, "p_agent {}", a.p_agent);
        assert!(a
            .reasons
            .iter()
            .any(|r| r == "uncorrelated-flat-throughput"));
    }

    #[test]
    fn heavy_tail_human_does_not_trip_uncorrelated_rule() {
        // A human who momentarily shows low sampled autocorrelation but keeps a
        // heavy think-time tail must NOT be condemned by rule #3.
        let mut f = human_like();
        f.gap_autocorr = 0.0;
        f.throughput_decay = 0.0;
        f.think_tail_ratio = 5.0; // heavy tail ⇒ genuine human
        let a = Model::default().assess(&f);
        assert!(
            !a.reasons
                .iter()
                .any(|r| r == "uncorrelated-flat-throughput"),
            "rule #3 must not fire on a heavy-tailed human"
        );
    }

    #[test]
    fn hard_rules_never_lower_toward_human() {
        // Absence of all hard-rule triggers must not change a genuine human.
        let f = human_like();
        let a = Model::default().assess(&f);
        assert_eq!(a.verdict, Verdict::Human);
    }

    #[test]
    fn log_likelihood_ratio_sign() {
        let model = Model::default();
        let agent = model.assess(&agent_like());
        let human = model.assess(&human_like());
        assert!(model.log_likelihood_ratio(&agent) > 0.0);
        assert!(model.log_likelihood_ratio(&human) < 0.0);
    }
}
