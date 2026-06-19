//! The agent-vs-human scoring model.
//!
//! A deliberately *transparent* additive model: each feature is mapped to an
//! "agent-evidence" value in [0,1] by a logistic transfer with a documented
//! centre and slope, then combined as a weighted average. Transparency matters
//! for an insider-threat tool — every verdict can be explained by which features
//! drove it, which is exactly what [`Detection::reasons`](aegis_sdk::EventPayload)
//! carries. The detection workflow can swap in a learned model behind the same
//! [`Model`] interface; the synthetic-evaluation harness scores either.

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
#[derive(Debug, Clone)]
pub struct Model {
    /// p_agent above this ⇒ Agent.
    pub agent_threshold: f64,
    /// p_agent below this ⇒ Human. Between the two ⇒ Uncertain.
    pub human_threshold: f64,
}

impl Default for Model {
    fn default() -> Self {
        Model {
            agent_threshold: 0.65,
            human_threshold: 0.35,
        }
    }
}

impl Model {
    fn terms(&self, f: &FeatureVector) -> Vec<Term> {
        vec![
            // Low keystroke CV ⇒ metronomic ⇒ agent.
            Term {
                name: "metronomic-typing",
                weight: 0.25,
                evidence: sigmoid(8.0 * (0.45 - f.keystroke_cv)),
            },
            // High paste ratio ⇒ commands injected wholesale ⇒ agent.
            Term {
                name: "paste-injection",
                weight: 0.20,
                evidence: f.paste_ratio.clamp(0.0, 1.0),
            },
            // Short think time ⇒ reacting faster than a human reads ⇒ agent.
            Term {
                name: "instant-reaction",
                weight: 0.25,
                evidence: sigmoid(0.004 * (1000.0 - f.mean_inter_command_ms)),
            },
            // No corrections ⇒ never mistypes ⇒ agent.
            Term {
                name: "errorless-input",
                weight: 0.15,
                evidence: sigmoid(40.0 * (0.06 - f.backspace_ratio)),
            },
            // Dense, high-entropy one-liners ⇒ weak agent signal.
            Term {
                name: "dense-commands",
                weight: 0.05,
                evidence: sigmoid(3.0 * (f.entropy_mean - 4.2)),
            },
            // Clockwork command cadence ⇒ agent.
            Term {
                name: "regular-cadence",
                weight: 0.10,
                evidence: f.cadence_regularity.clamp(0.0, 1.0),
            },
        ]
    }

    /// Assess a feature vector.
    pub fn assess(&self, f: &FeatureVector) -> Assessment {
        let terms = self.terms(f);
        let total_w: f64 = terms.iter().map(|t| t.weight).sum();
        let p_agent: f64 = terms.iter().map(|t| t.weight * t.evidence).sum::<f64>() / total_w;

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

        // Explain: the strongest contributors toward the chosen direction.
        let mut contribs: Vec<(&'static str, f64)> = terms
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
        let reasons = contribs
            .into_iter()
            .take(3)
            .filter(|(_, c)| *c > 0.0)
            .map(|(name, _)| name.to_string())
            .collect();

        Assessment {
            p_agent,
            verdict,
            confidence,
            reasons,
        }
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
        assert!(a.p_agent > 0.65);
        assert!(!a.reasons.is_empty());
    }

    #[test]
    fn monotonic_in_paste_ratio() {
        let model = Model::default();
        let mut f = human_like();
        let low = model.assess(&f).p_agent;
        f.paste_ratio = 1.0;
        let high = model.assess(&f).p_agent;
        assert!(high > low);
    }
}
