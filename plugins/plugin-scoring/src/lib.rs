//! # plugin-scoring
//!
//! Aggregates heterogeneous signals (agent-vs-human detections, suspicious
//! process executions, upstream alerts) into a single, decaying per-subject
//! **risk score**, and raises an [`Alert`](aegis_sdk::EventPayload::Alert) when a
//! subject crosses a configurable threshold. Keeping scoring in its own plugin
//! means the risk policy can evolve (or be replaced per deployment) without
//! touching detection or collection.

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Severity, Subscriptions, Verdict,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

fn default_uncertain_weight() -> f64 {
    6.0
}
fn default_uncertain_min_conf() -> f64 {
    0.5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Risk added when a subject is classified as an agent (scaled by confidence).
    pub agent_detection_weight: f64,
    /// Risk added per suspicious process exec.
    pub process_weight: f64,
    /// Multiplicative decay applied to a subject's score on each update.
    pub decay: f64,
    /// Score at/above which an alert fires.
    pub alert_threshold: f64,
    /// Small risk added per *sustained* `Uncertain` detection (scaled by
    /// confidence). An isolated `Uncertain` adds little and decays away; a
    /// session that keeps re-emitting `Uncertain` (the dead-band-camping
    /// evasion) accumulates faster than it decays and climbs toward an alert.
    /// Chosen ≪ `agent_detection_weight` so a single `Uncertain` never alerts.
    #[serde(default = "default_uncertain_weight")]
    pub uncertain_detection_weight: f64,
    /// Minimum confidence for an `Uncertain` detection to contribute any risk.
    /// `Uncertain` confidence is `1 − |p−0.5|·2`, i.e. it *peaks* in the middle
    /// of the dead band — exactly where a camper sits — so this threshold
    /// naturally concentrates the incremental risk on genuine dead-band campers.
    #[serde(default = "default_uncertain_min_conf")]
    pub uncertain_min_confidence: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        ScoringConfig {
            agent_detection_weight: 60.0,
            process_weight: 5.0,
            decay: 0.98,
            alert_threshold: 75.0,
            uncertain_detection_weight: default_uncertain_weight(),
            uncertain_min_confidence: default_uncertain_min_conf(),
        }
    }
}

/// Pure risk-accumulation state, separated from I/O for testability.
#[derive(Debug, Default, Clone)]
pub struct RiskState {
    scores: HashMap<String, f64>,
}

impl RiskState {
    /// Apply decay then add `delta`, clamping to [0, 100]. Returns the new score.
    pub fn bump(&mut self, subject: &str, delta: f64, decay: f64) -> f64 {
        let entry = self.scores.entry(subject.to_string()).or_insert(0.0);
        *entry = (*entry * decay + delta).clamp(0.0, 100.0);
        *entry
    }

    pub fn get(&self, subject: &str) -> f64 {
        self.scores.get(subject).copied().unwrap_or(0.0)
    }
}

pub struct ScoringPlugin {
    config: ScoringConfig,
    state: Arc<Mutex<RiskState>>,
}

impl Default for ScoringPlugin {
    fn default() -> Self {
        ScoringPlugin {
            config: ScoringConfig::default(),
            state: Arc::new(Mutex::new(RiskState::default())),
        }
    }
}

#[async_trait]
impl Plugin for ScoringPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-scoring",
            env!("CARGO_PKG_VERSION"),
            "Per-subject risk aggregation and alerting",
            PluginKind::Processor,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::kinds(["detection", "process.exec", "alert"])
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        self.config = ctx.config_as()?;
        Ok(())
    }

    async fn handle(&self, event: &Event, ctx: &PluginContext) -> anyhow::Result<()> {
        // (subject, risk delta, optional [confidence, agentness] for the Score
        // feature decomposition — present only for Detection-sourced bumps).
        let (subject, delta, source): (String, f64, Option<(f64, f64)>) = match &event.payload {
            EventPayload::Detection {
                subject,
                verdict: Verdict::Agent,
                confidence,
                ..
            } => (
                subject.clone(),
                self.config.agent_detection_weight * confidence,
                Some((*confidence, 1.0)),
            ),
            // Sustained `Uncertain` is *actionable*: it adds a small, decaying
            // increment so a session camping in the dead band climbs toward an
            // alert, while an isolated `Uncertain` decays away harmlessly.
            EventPayload::Detection {
                subject,
                verdict: Verdict::Uncertain,
                confidence,
                ..
            } if *confidence >= self.config.uncertain_min_confidence => (
                subject.clone(),
                self.config.uncertain_detection_weight * confidence,
                Some((*confidence, 0.5)),
            ),
            EventPayload::ProcessExec { uid, exe, .. } => {
                // Interactive-user processes contribute a small amount of risk.
                let subject = format!("uid:{uid}");
                let weight = if is_suspicious_exe(exe) {
                    self.config.process_weight * 3.0
                } else {
                    self.config.process_weight
                };
                (subject, weight, None)
            }
            _ => return Ok(()),
        };

        let new_score = {
            let mut state = self.state.lock().await;
            state.bump(&subject, delta, self.config.decay)
        };

        // Populate `Score.features` with the risk decomposition so the dashboard
        // can explain a score (what was just added, the decay applied, and — for
        // detection-sourced bumps — the upstream verdict signal).
        let mut features = BTreeMap::from([
            ("risk_score".to_string(), new_score),
            ("delta".to_string(), delta),
            ("decay".to_string(), self.config.decay),
        ]);
        if let Some((confidence, agentness)) = source {
            features.insert("source_confidence".to_string(), confidence);
            features.insert("verdict_agentness".to_string(), agentness);
        }

        ctx.emit(Event::new(
            &ctx.agent_id,
            "plugin-scoring",
            EventPayload::Score {
                subject: subject.clone(),
                model: "risk-aggregator/v1".into(),
                score: new_score,
                features,
            },
        ))
        .await;

        if new_score >= self.config.alert_threshold {
            ctx.emit(Event::new(
                &ctx.agent_id,
                "plugin-scoring",
                EventPayload::Alert {
                    severity: severity_for(new_score),
                    title: "Elevated insider-threat risk".into(),
                    detail: format!("subject {subject} reached risk score {new_score:.1}"),
                    subject: Some(subject),
                },
            ))
            .await;
        }
        Ok(())
    }
}

fn severity_for(score: f64) -> Severity {
    if score >= 90.0 {
        Severity::Critical
    } else if score >= 75.0 {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Heuristic list of executables that warrant extra scrutiny in context.
fn is_suspicious_exe(exe: &str) -> bool {
    const WATCH: &[&str] = &[
        "nc", "ncat", "socat", "nmap", "tcpdump", "scp", "rsync", "curl", "wget", "base64",
        "openssl", "gpg",
    ];
    let base = exe.rsplit('/').next().unwrap_or(exe);
    WATCH.contains(&base)
}

register_plugin!("plugin-scoring", || Box::new(ScoringPlugin::default()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_decays_and_clamps() {
        let mut s = RiskState::default();
        assert_eq!(s.bump("u", 60.0, 0.98), 60.0);
        let after = s.bump("u", 60.0, 0.98); // 60*0.98 + 60 = 118.8 -> clamp 100
        assert_eq!(after, 100.0);
        // pure decay step toward zero
        let decayed = s.bump("u", 0.0, 0.5);
        assert!((decayed - 50.0).abs() < 1e-9);
    }

    #[test]
    fn suspicious_exe_detection() {
        assert!(is_suspicious_exe("/usr/bin/nc"));
        assert!(is_suspicious_exe("socat"));
        assert!(!is_suspicious_exe("/usr/bin/ls"));
    }

    #[test]
    fn sustained_uncertain_becomes_actionable() {
        // Pin the A5 mitigation without the async bus: feeding many *sustained*
        // Uncertain detections (high mid-band confidence) through the same
        // `bump` weight must climb the score, while a single Uncertain stays low.
        let cfg = ScoringConfig::default();
        let conf = 0.9; // high mid-band confidence (dead-band camper)
        let delta = cfg.uncertain_detection_weight * conf;

        // A single Uncertain is harmless and well below the alert threshold.
        let mut s = RiskState::default();
        let one = s.bump("camper", delta, cfg.decay);
        assert!(one < 10.0, "single Uncertain should stay low, got {one}");
        assert!(one < cfg.alert_threshold);

        // Sustained camping accumulates faster than it decays and climbs to a
        // material risk over a couple dozen re-assessments.
        let mut s = RiskState::default();
        let mut last = 0.0;
        for _ in 0..30 {
            last = s.bump("camper", delta, cfg.decay);
        }
        assert!(
            last > 25.0,
            "sustained Uncertain should climb to a material risk, got {last}"
        );
        // Monotone-ish growth check: 30 sustained pushes exceed 12 sustained.
        let mut s12 = RiskState::default();
        let mut at12 = 0.0;
        for _ in 0..12 {
            at12 = s12.bump("camper", delta, cfg.decay);
        }
        assert!(last > at12, "more sustained camping ⇒ higher risk");
    }

    #[test]
    fn isolated_uncertain_never_alerts_but_sustained_eventually_does() {
        // A single (or few) Uncertain stays well below the alert threshold, but
        // *sustained* camping eventually crosses it — the A5 mitigation. With the
        // default weights this takes ~17 sustained re-assessments at conf 0.9, so
        // a fleeting blip cannot trip an alert while persistent camping does.
        let cfg = ScoringConfig::default();
        let delta = cfg.uncertain_detection_weight * 0.9;

        let mut s = RiskState::default();
        let mut crossed_at: Option<usize> = None;
        for i in 1..=40 {
            let score = s.bump("camper", delta, cfg.decay);
            if i <= 3 {
                assert!(
                    score < cfg.alert_threshold,
                    "a few Uncertains must not alert (i={i}, score={score})"
                );
            }
            if score >= cfg.alert_threshold && crossed_at.is_none() {
                crossed_at = Some(i);
            }
        }
        let crossed = crossed_at.expect("sustained Uncertain should eventually alert");
        assert!(
            (5..=40).contains(&crossed),
            "expected sustained camping to alert after a sustained run, crossed at {crossed}"
        );
    }

    #[test]
    fn agent_verdict_still_alerts_fast() {
        // The Agent path is unchanged: two Agent detections at high confidence
        // clear the alert threshold quickly.
        let cfg = ScoringConfig::default();
        let mut s = RiskState::default();
        let d = cfg.agent_detection_weight * 0.95;
        s.bump("agent", d, cfg.decay);
        let after = s.bump("agent", d, cfg.decay);
        assert!(
            after >= cfg.alert_threshold,
            "agent should alert, got {after}"
        );
    }
}
