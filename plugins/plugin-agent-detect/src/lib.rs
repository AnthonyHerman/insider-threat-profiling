//! # plugin-agent-detect
//!
//! The platform's flagship capability: deciding whether the entity driving an
//! interactive session is a **human operator** or an **automated agent**. It
//! consumes timing/structure telemetry ([`input.keystroke`](aegis_sdk::EventPayload::Keystroke)
//! and [`command.observed`](aegis_sdk::EventPayload::CommandObserved)) emitted by
//! collector plugins, accumulates per-session [features](features), and emits a
//! [`Detection`](aegis_sdk::EventPayload::Detection) verdict via the
//! [transparent model](model).

pub mod eval;
pub mod features;
pub mod model;
pub mod synth;

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Subscriptions, Verdict,
};
use async_trait::async_trait;
use features::SessionAccumulator;
use model::{sigmoid, Model};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

fn default_ewma_alpha() -> f64 {
    0.3
}
fn default_escalate_logit() -> f64 {
    // A sustained EWMA of logit(p_agent) ≥ 0.25 ⇒ a steady p_agent ≈ 0.56:
    // squarely in the dead band (below the 0.62 Agent threshold) but
    // *consistently* agent-leaning. This is the dead-band-camping (A5)
    // signature. Calibrated against the synthetic human distribution so the
    // marginal human false-positive cost of escalation is < 1%; a field
    // deployment should re-derive it from its own human population.
    0.25
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectConfig {
    /// Re-assess after every N new events for a session (live verdicts).
    pub assess_every: u32,
    /// Also assess (final verdict) when a session ends.
    pub assess_on_session_end: bool,
    /// EWMA smoothing factor for the per-session sequential test. Each
    /// re-assessment folds its log-likelihood-ratio in with this weight; larger
    /// ⇒ more reactive, smaller ⇒ steadier. Defaults to 0.3.
    #[serde(default = "default_ewma_alpha")]
    pub ewma_alpha: f64,
    /// Escalation threshold for the smoothed log-odds. When the EWMA of
    /// `logit(p_agent)` across re-assessments reaches this, a session that is
    /// merely `Uncertain` per-snapshot is escalated to `Agent` (deletes the
    /// dead-band camping strategy). Defaults to 0.25 (≈ a sustained p_agent of
    /// ~0.56 — below the per-snapshot Agent threshold, so it genuinely catches
    /// consistent sub-threshold leaners while keeping the human cost < 1%).
    #[serde(default = "default_escalate_logit")]
    pub escalate_logit: f64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            assess_every: 10,
            assess_on_session_end: true,
            ewma_alpha: default_ewma_alpha(),
            escalate_logit: default_escalate_logit(),
        }
    }
}

#[derive(Default)]
struct SessionState {
    acc: SessionAccumulator,
    since_last_assess: u32,
    /// EWMA of the per-snapshot log-likelihood ratio across re-assessments.
    ewma_logit: f64,
    /// Whether `ewma_logit` has been seeded yet.
    ewma_inited: bool,
    /// Latch: we have already emitted the sequential escalation once (avoids
    /// alert spam on every subsequent tick).
    escalated: bool,
}

pub struct AgentDetectPlugin {
    model: Model,
    config: DetectConfig,
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
}

impl Default for AgentDetectPlugin {
    fn default() -> Self {
        AgentDetectPlugin {
            model: Model::default(),
            config: DetectConfig::default(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AgentDetectPlugin {
    async fn maybe_emit(&self, session_id: &str, ctx: &PluginContext, force: bool) {
        let mut guard = self.sessions.lock().await;
        let Some(state) = guard.get_mut(session_id) else {
            return;
        };
        if !force && state.since_last_assess < self.config.assess_every {
            return;
        }
        state.since_last_assess = 0;
        let Some(features) = state.acc.features() else {
            return;
        };
        let assessment = self.model.assess(&features);

        // --- Sequential test: accumulate evidence across re-assessments -------
        // A session that camps in `Uncertain` but is *consistently* agent-leaning
        // drives the EWMA of logit(p_agent) above `escalate_logit` and trips to
        // `Agent`. This deletes the cheapest pure evasion strategy: sitting in the
        // dead band (p_agent ≈ 0.5–0.6) across re-assessments.
        let llr = self.model.log_likelihood_ratio(&assessment);
        if state.ewma_inited {
            state.ewma_logit =
                self.config.ewma_alpha * llr + (1.0 - self.config.ewma_alpha) * state.ewma_logit;
        } else {
            state.ewma_logit = llr;
            state.ewma_inited = true;
        }
        let sustained_agent = state.ewma_logit >= self.config.escalate_logit;

        let mut verdict = assessment.verdict;
        let mut confidence = assessment.confidence;
        let mut reasons = assessment.reasons.clone();

        if sustained_agent && verdict == Verdict::Uncertain && !state.escalated {
            verdict = Verdict::Agent;
            // Calibrated-ish confidence from the sustained log-odds.
            confidence = sigmoid(state.ewma_logit).max(confidence);
            reasons.insert(0, "sequential-escalation".into());
            state.escalated = true;
        }

        // Drop the lock before awaiting the emit.
        drop(guard);

        ctx.emit(Event::new(
            &ctx.agent_id,
            "plugin-agent-detect",
            EventPayload::Detection {
                subject: session_id.to_string(),
                verdict,
                confidence,
                model: "transparent-additive/v1".into(),
                reasons,
                features: features.to_map(),
            },
        ))
        .await;
    }
}

#[async_trait]
impl Plugin for AgentDetectPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-agent-detect",
            env!("CARGO_PKG_VERSION"),
            "Agent-vs-human operator distinction from behavioral telemetry",
            PluginKind::Processor,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::kinds([
            "input.keystroke",
            "command.observed",
            "session.start",
            "session.end",
        ])
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        self.config = ctx.config_as()?;
        Ok(())
    }

    async fn handle(&self, event: &Event, ctx: &PluginContext) -> anyhow::Result<()> {
        match &event.payload {
            EventPayload::SessionStart { session_id, .. } => {
                self.sessions
                    .lock()
                    .await
                    .entry(session_id.clone())
                    .or_default();
            }
            EventPayload::Keystroke {
                session_id,
                inter_arrival_ns,
                is_paste,
                burst_len,
            } => {
                {
                    let mut guard = self.sessions.lock().await;
                    let state = guard.entry(session_id.clone()).or_default();
                    state
                        .acc
                        .record_keystroke(*inter_arrival_ns, *is_paste, *burst_len);
                    state.since_last_assess += 1;
                }
                self.maybe_emit(session_id, ctx, false).await;
            }
            EventPayload::CommandObserved {
                session_id,
                inter_command_ns,
                had_backspace,
                shannon_entropy,
                ..
            } => {
                {
                    let mut guard = self.sessions.lock().await;
                    let state = guard.entry(session_id.clone()).or_default();
                    state
                        .acc
                        .record_command(*inter_command_ns, *had_backspace, *shannon_entropy);
                    state.since_last_assess += 1;
                }
                self.maybe_emit(session_id, ctx, false).await;
            }
            EventPayload::SessionEnd { session_id } => {
                if self.config.assess_on_session_end {
                    self.maybe_emit(session_id, ctx, true).await;
                }
                self.sessions.lock().await.remove(session_id);
            }
            _ => {}
        }
        Ok(())
    }
}

register_plugin!("plugin-agent-detect", || Box::new(
    AgentDetectPlugin::default()
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_processor() {
        let p = AgentDetectPlugin::default();
        assert_eq!(p.metadata().kind, PluginKind::Processor);
        assert_eq!(p.metadata().name, "plugin-agent-detect");
    }
}
