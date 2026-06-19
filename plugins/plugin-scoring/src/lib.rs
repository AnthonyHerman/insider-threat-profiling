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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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
}

impl Default for ScoringConfig {
    fn default() -> Self {
        ScoringConfig {
            agent_detection_weight: 60.0,
            process_weight: 5.0,
            decay: 0.98,
            alert_threshold: 75.0,
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
        let (subject, delta) = match &event.payload {
            EventPayload::Detection {
                subject,
                verdict: Verdict::Agent,
                confidence,
                ..
            } => (
                subject.clone(),
                self.config.agent_detection_weight * confidence,
            ),
            EventPayload::ProcessExec { uid, exe, .. } => {
                // Interactive-user processes contribute a small amount of risk.
                let subject = format!("uid:{uid}");
                let weight = if is_suspicious_exe(exe) {
                    self.config.process_weight * 3.0
                } else {
                    self.config.process_weight
                };
                (subject, weight)
            }
            _ => return Ok(()),
        };

        let new_score = {
            let mut state = self.state.lock().await;
            state.bump(&subject, delta, self.config.decay)
        };

        ctx.emit(Event::new(
            &ctx.agent_id,
            "plugin-scoring",
            EventPayload::Score {
                subject: subject.clone(),
                model: "risk-aggregator/v1".into(),
                score: new_score,
                features: Default::default(),
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
}
