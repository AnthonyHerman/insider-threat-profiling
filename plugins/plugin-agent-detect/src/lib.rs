//! # plugin-agent-detect
//!
//! The platform's flagship capability: deciding whether the entity driving an
//! interactive session is a **human operator** or an **automated agent**. It
//! consumes timing/structure telemetry ([`input.keystroke`](aegis_sdk::EventPayload::Keystroke)
//! and [`command.observed`](aegis_sdk::EventPayload::CommandObserved)) emitted by
//! collector plugins, accumulates per-session [features](features), and emits a
//! [`Detection`](aegis_sdk::EventPayload::Detection) verdict via the
//! [transparent model](model).

pub mod features;
pub mod model;

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Subscriptions,
};
use async_trait::async_trait;
use features::SessionAccumulator;
use model::Model;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectConfig {
    /// Re-assess after every N new events for a session (live verdicts).
    pub assess_every: u32,
    /// Also assess (final verdict) when a session ends.
    pub assess_on_session_end: bool,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            assess_every: 10,
            assess_on_session_end: true,
        }
    }
}

#[derive(Default)]
struct SessionState {
    acc: SessionAccumulator,
    since_last_assess: u32,
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
        // Drop the lock before awaiting the emit.
        drop(guard);

        ctx.emit(Event::new(
            &ctx.agent_id,
            "plugin-agent-detect",
            EventPayload::Detection {
                subject: session_id.to_string(),
                verdict: assessment.verdict,
                confidence: assessment.confidence,
                model: "transparent-additive/v1".into(),
                reasons: assessment.reasons,
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
