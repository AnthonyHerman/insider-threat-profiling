//! # plugin-agent-detect
//!
//! The platform's flagship capability: deciding whether the entity driving an
//! interactive session is a **human operator** or an **automated agent**. It
//! consumes timing/structure telemetry ([`input.keystroke`](aegis_sdk::EventPayload::Keystroke)
//! and [`command.observed`](aegis_sdk::EventPayload::CommandObserved)) emitted by
//! collector plugins, accumulates per-session [features](features), and emits a
//! [`Detection`](aegis_sdk::EventPayload::Detection) verdict via the
//! [transparent model](model).

pub mod baseline;
pub mod eval;
pub mod features;
pub mod model;
pub mod synth;

use aegis_sdk::{
    now_ns, register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind,
    PluginMetadata, Subscriptions, Verdict,
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
fn default_session_ttl_s() -> u64 {
    // Evict sessions idle beyond this many seconds. Bounds memory when a
    // `SessionEnd` is lost (the only explicit removal today), so a missing end
    // event cannot pin a session's accumulator forever. 1 hour is generous for
    // an interactive session's idle gap while still reclaiming abandoned ones.
    3600
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
    /// ⇒ more reactive, smaller ⇒ steadier. Must be in `(0.0, 1.0]` (validated
    /// in `init`); `> 1.0` would put negative weight on the prior. Defaults to 0.3.
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
    /// Idle TTL (seconds) after which a session with no further events is
    /// evicted, so a missing `SessionEnd` cannot pin its accumulator forever.
    #[serde(default = "default_session_ttl_s")]
    pub session_ttl_s: u64,
    /// If `false` (default), keystroke/command events for a session that never
    /// had a `SessionStart` are dropped rather than implicitly creating an
    /// accumulator — this prevents an unbounded number of unknown sessions from
    /// being minted by a hostile or buggy event stream. Set `true` only when
    /// upstream is trusted to not emit pre-`SessionStart` telemetry.
    #[serde(default)]
    pub assess_on_missing_session: bool,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            assess_every: 10,
            assess_on_session_end: true,
            ewma_alpha: default_ewma_alpha(),
            escalate_logit: default_escalate_logit(),
            session_ttl_s: default_session_ttl_s(),
            assess_on_missing_session: false,
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
    /// Wall-clock (ns) of the last event for this session, for idle-TTL eviction.
    last_activity_ns: u64,
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

/// Evict sessions whose last activity is older than `ttl_ns` relative to `now`.
/// Called opportunistically while the session map is locked, so a missing
/// `SessionEnd` cannot pin a session's accumulator forever. A `ttl_ns` of 0
/// disables eviction.
fn evict_idle(sessions: &mut HashMap<String, SessionState>, now: u64, ttl_ns: u64) {
    if ttl_ns == 0 {
        return;
    }
    sessions.retain(|_, s| now.saturating_sub(s.last_activity_ns) <= ttl_ns);
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
        // `ewma_alpha` is a smoothing weight in (0, 1]; alpha > 1 puts negative
        // weight on the prior (see the EWMA update in `maybe_emit`), and alpha
        // <= 0 freezes the estimate. Reject out-of-range values up front.
        let alpha = self.config.ewma_alpha;
        if !(alpha > 0.0 && alpha <= 1.0) {
            anyhow::bail!("ewma_alpha must be in (0.0, 1.0], got {alpha}");
        }
        Ok(())
    }

    async fn handle(&self, event: &Event, ctx: &PluginContext) -> anyhow::Result<()> {
        let now = now_ns();
        let ttl_ns = self.config.session_ttl_s.saturating_mul(1_000_000_000);
        match &event.payload {
            EventPayload::SessionStart { session_id, .. } => {
                let mut guard = self.sessions.lock().await;
                evict_idle(&mut guard, now, ttl_ns);
                let state = guard.entry(session_id.clone()).or_default();
                state.last_activity_ns = now;
            }
            EventPayload::Keystroke {
                session_id,
                inter_arrival_ns,
                is_paste,
                burst_len,
            } => {
                {
                    let mut guard = self.sessions.lock().await;
                    evict_idle(&mut guard, now, ttl_ns);
                    // Only `SessionStart` creates a session unless explicitly
                    // configured otherwise; drop telemetry for unknown sessions
                    // so a hostile stream cannot mint unbounded accumulators.
                    let state = match guard.get_mut(session_id) {
                        Some(state) => state,
                        None if self.config.assess_on_missing_session => {
                            guard.entry(session_id.clone()).or_default()
                        }
                        None => return Ok(()),
                    };
                    state
                        .acc
                        .record_keystroke(*inter_arrival_ns, *is_paste, *burst_len);
                    state.since_last_assess += 1;
                    state.last_activity_ns = now;
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
                    evict_idle(&mut guard, now, ttl_ns);
                    let state = match guard.get_mut(session_id) {
                        Some(state) => state,
                        None if self.config.assess_on_missing_session => {
                            guard.entry(session_id.clone()).or_default()
                        }
                        None => return Ok(()),
                    };
                    state
                        .acc
                        .record_command(*inter_command_ns, *had_backspace, *shannon_entropy);
                    state.since_last_assess += 1;
                    state.last_activity_ns = now;
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
    use aegis_sdk::{Emitter, SessionId};
    use std::sync::Mutex as StdMutex;

    #[test]
    fn metadata_is_processor() {
        let p = AgentDetectPlugin::default();
        assert_eq!(p.metadata().kind, PluginKind::Processor);
        assert_eq!(p.metadata().name, "plugin-agent-detect");
    }

    #[test]
    fn detect_config_defaults_are_sane() {
        let c = DetectConfig::default();
        assert_eq!(c.assess_every, 10);
        assert!(c.assess_on_session_end);
        assert!((c.ewma_alpha - 0.3).abs() < 1e-9);
        assert!((c.escalate_logit - 0.25).abs() < 1e-9);
        assert_eq!(c.session_ttl_s, 3600);
        assert!(!c.assess_on_missing_session);
    }

    /// H3 regression (unknown-session guard): telemetry for a session that never
    /// had a `SessionStart` is dropped by default and does NOT mint an
    /// accumulator, so a hostile/buggy stream cannot grow the session map.
    #[tokio::test]
    async fn unknown_session_telemetry_is_dropped() {
        let emitter = Arc::new(CapturingEmitter::default());
        let ctx = test_ctx(emitter.clone());
        let plugin = AgentDetectPlugin::default();
        // 5000 keystrokes for 5000 distinct unknown sessions — none started.
        for i in 0..5000u32 {
            plugin
                .handle(
                    &Event::new(
                        "test-agent",
                        "test",
                        EventPayload::Keystroke {
                            session_id: format!("ghost-{i}"),
                            inter_arrival_ns: 150_000_000,
                            is_paste: false,
                            burst_len: 1,
                        },
                    ),
                    &ctx,
                )
                .await
                .unwrap();
        }
        // No session was created, and nothing was emitted.
        assert_eq!(plugin.sessions.lock().await.len(), 0);
        assert!(emitter.events.lock().unwrap().is_empty());
    }

    /// H3 regression (TTL eviction): `evict_idle` reclaims sessions idle beyond
    /// the TTL so a missing `SessionEnd` cannot pin memory forever.
    #[test]
    fn idle_sessions_are_evicted_by_ttl() {
        let mut sessions: HashMap<String, SessionState> = HashMap::new();
        // One fresh, one stale relative to `now`.
        let now = 10_000_000_000u64; // 10s
        let ttl_ns = 1_000_000_000u64; // 1s
        sessions.insert(
            "fresh".into(),
            SessionState {
                last_activity_ns: now,
                ..Default::default()
            },
        );
        sessions.insert(
            "stale".into(),
            SessionState {
                last_activity_ns: now - 5_000_000_000, // 5s ago, > TTL
                ..Default::default()
            },
        );
        evict_idle(&mut sessions, now, ttl_ns);
        assert!(sessions.contains_key("fresh"));
        assert!(!sessions.contains_key("stale"));

        // ttl_ns == 0 disables eviction even for a long-idle session.
        let mut s2: HashMap<String, SessionState> = HashMap::new();
        s2.insert(
            "ancient".into(),
            SessionState {
                last_activity_ns: 0,
                ..Default::default()
            },
        );
        evict_idle(&mut s2, now + 1_000_000_000_000, 0);
        assert_eq!(s2.len(), 1);
    }

    #[test]
    fn detect_config_parses_without_new_keys() {
        // Wire-compat: a config written before the sequential keys existed must
        // still deserialize, picking up the serde defaults.
        let json = serde_json::json!({
            "assess_every": 5,
            "assess_on_session_end": false
        });
        let c: DetectConfig = serde_json::from_value(json).unwrap();
        assert_eq!(c.assess_every, 5);
        assert!(!c.assess_on_session_end);
        assert!((c.ewma_alpha - 0.3).abs() < 1e-9);
        assert!((c.escalate_logit - 0.25).abs() < 1e-9);
    }

    /// L9: `init` rejects an out-of-range `ewma_alpha` (alpha > 1.0 puts
    /// negative weight on the prior); a valid alpha is accepted.
    #[tokio::test]
    async fn init_rejects_out_of_range_ewma_alpha() {
        let mut plugin = AgentDetectPlugin::default();
        let bad = PluginContext {
            agent_id: "a".into(),
            data_dir: std::env::temp_dir(),
            config: serde_json::json!({ "assess_every": 10, "assess_on_session_end": true, "ewma_alpha": 2.0 }),
            emitter: Arc::new(CapturingEmitter::default()),
        };
        assert!(plugin.init(&bad).await.is_err());

        let mut plugin_ok = AgentDetectPlugin::default();
        let good = PluginContext {
            agent_id: "a".into(),
            data_dir: std::env::temp_dir(),
            config: serde_json::json!({ "assess_every": 10, "assess_on_session_end": true, "ewma_alpha": 0.3 }),
            emitter: Arc::new(CapturingEmitter::default()),
        };
        assert!(plugin_ok.init(&good).await.is_ok());
    }

    /// Test emitter that captures every emitted event.
    #[derive(Default)]
    struct CapturingEmitter {
        events: Arc<StdMutex<Vec<Event>>>,
    }

    #[async_trait]
    impl Emitter for CapturingEmitter {
        async fn emit(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn test_ctx(emitter: Arc<CapturingEmitter>) -> PluginContext {
        PluginContext {
            agent_id: "test-agent".into(),
            data_dir: std::env::temp_dir(),
            config: serde_json::Value::Null,
            emitter,
        }
    }

    /// Drive the *real* plugin end-to-end over a long, mid-evasion (e=0.5)
    /// session and assert the wired-up sequential escalation fires: at least one
    /// emitted Detection carries the `sequential-escalation` reason and the
    /// `Agent` verdict, proving `maybe_emit`'s SPRT/EWMA path works in
    /// production (not just the eval replica).
    #[tokio::test]
    async fn sequential_escalation_emits_agent_detection_end_to_end() {
        use crate::synth::{synth_events, ProfileParams, Rng, SynthEvent};

        // e=0.5 partial mimic params (mirrors eval::evade(0.5)).
        let h = ProfileParams::human();
        let a = ProfileParams::agent();
        let lerp = |x: f64, y: f64| x + (y - x) * 0.5;
        let l2 = |x: (f64, f64), y: (f64, f64)| (lerp(x.0, y.0), lerp(x.1, y.1));
        let partial = ProfileParams {
            keystroke_lognormal: l2(a.keystroke_lognormal, h.keystroke_lognormal),
            think_lognormal: l2(a.think_lognormal, h.think_lognormal),
            backspace_p: lerp(a.backspace_p, h.backspace_p),
            paste_p: lerp(a.paste_p, h.paste_p),
            entropy: l2(a.entropy, h.entropy),
            commands: l2(a.commands, h.commands),
            keystrokes_per_cmd: l2(a.keystrokes_per_cmd, h.keystrokes_per_cmd),
            think_autocorr: lerp(a.think_autocorr, h.think_autocorr),
            think_fatigue: lerp(a.think_fatigue, h.think_fatigue),
        };

        // Search a handful of seeds for a session that escalates (the cohort
        // escalation rate is high but not 100%, so a single fixed seed could be
        // one of the ~30% that legitimately stays Uncertain). This stays
        // deterministic and asserts the production path *can* and *does*
        // escalate a sustained agent-leaner.
        let mut escalated_once = false;
        for seed in 0u64..12 {
            let emitter = Arc::new(CapturingEmitter::default());
            let ctx = test_ctx(emitter.clone());
            let plugin = AgentDetectPlugin::default();
            let sid: SessionId = format!("sess-{seed}");

            plugin
                .handle(
                    &Event::new(
                        "test-agent",
                        "test",
                        EventPayload::SessionStart {
                            session_id: sid.clone(),
                            tty: None,
                            user: "u".into(),
                            remote: None,
                        },
                    ),
                    &ctx,
                )
                .await
                .unwrap();

            let mut rng = Rng::new(seed);
            for evt in synth_events(&partial, &mut rng, 22) {
                let payload = match evt {
                    SynthEvent::Keystroke {
                        inter_arrival_ns,
                        is_paste,
                        burst_len,
                    } => EventPayload::Keystroke {
                        session_id: sid.clone(),
                        inter_arrival_ns,
                        is_paste,
                        burst_len,
                    },
                    SynthEvent::Command {
                        inter_command_ns,
                        had_backspace,
                        entropy,
                    } => EventPayload::CommandObserved {
                        session_id: sid.clone(),
                        command_len: 20,
                        token_count: 3,
                        shannon_entropy: entropy,
                        had_backspace,
                        edit_distance_prev: 5,
                        inter_command_ns,
                        command_hash: "h".into(),
                    },
                };
                plugin
                    .handle(&Event::new("test-agent", "test", payload), &ctx)
                    .await
                    .unwrap();
            }
            // Session end → final forced assessment.
            plugin
                .handle(
                    &Event::new(
                        "test-agent",
                        "test",
                        EventPayload::SessionEnd {
                            session_id: sid.clone(),
                        },
                    ),
                    &ctx,
                )
                .await
                .unwrap();

            let events = emitter.events.lock().unwrap();
            // Detections were emitted at the assess cadence.
            let detections: Vec<&Event> = events
                .iter()
                .filter(|e| matches!(e.payload, EventPayload::Detection { .. }))
                .collect();
            assert!(
                !detections.is_empty(),
                "expected the plugin to emit Detections"
            );
            // Look for a sequential escalation.
            for e in &detections {
                if let EventPayload::Detection {
                    verdict, reasons, ..
                } = &e.payload
                {
                    if *verdict == Verdict::Agent
                        && reasons.iter().any(|r| r == "sequential-escalation")
                    {
                        escalated_once = true;
                    }
                }
            }
            if escalated_once {
                break;
            }
        }
        assert!(
            escalated_once,
            "sequential escalation never fired across seeds — the wired-up SPRT/EWMA path is not escalating sustained agent-leaners"
        );
    }

    /// A genuine, sustained Human session must NOT be escalated to Agent by the
    /// sequential path (escalation is one-directional and gated on Uncertain).
    #[tokio::test]
    async fn sequential_does_not_escalate_clear_human_end_to_end() {
        use crate::synth::{synth_events, ProfileParams, Rng, SynthEvent};

        let mut any_detection = false;
        for seed in 0u64..6 {
            let emitter = Arc::new(CapturingEmitter::default());
            let ctx = test_ctx(emitter.clone());
            let plugin = AgentDetectPlugin::default();
            let sid: SessionId = format!("h-{seed}");
            // Production contract: a session is created by SessionStart before
            // any telemetry; unknown-session telemetry is dropped by default.
            plugin
                .handle(
                    &Event::new(
                        "test-agent",
                        "test",
                        EventPayload::SessionStart {
                            session_id: sid.clone(),
                            tty: None,
                            user: "u".into(),
                            remote: None,
                        },
                    ),
                    &ctx,
                )
                .await
                .unwrap();
            let mut rng = Rng::new(seed);
            for evt in synth_events(&ProfileParams::human(), &mut rng, 22) {
                let payload = match evt {
                    SynthEvent::Keystroke {
                        inter_arrival_ns,
                        is_paste,
                        burst_len,
                    } => EventPayload::Keystroke {
                        session_id: sid.clone(),
                        inter_arrival_ns,
                        is_paste,
                        burst_len,
                    },
                    SynthEvent::Command {
                        inter_command_ns,
                        had_backspace,
                        entropy,
                    } => EventPayload::CommandObserved {
                        session_id: sid.clone(),
                        command_len: 20,
                        token_count: 3,
                        shannon_entropy: entropy,
                        had_backspace,
                        edit_distance_prev: 5,
                        inter_command_ns,
                        command_hash: "h".into(),
                    },
                };
                plugin
                    .handle(&Event::new("test-agent", "test", payload), &ctx)
                    .await
                    .unwrap();
            }
            let events = emitter.events.lock().unwrap();
            for e in events.iter() {
                if let EventPayload::Detection {
                    verdict, reasons, ..
                } = &e.payload
                {
                    any_detection = true;
                    assert!(
                        !reasons.iter().any(|r| r == "sequential-escalation"),
                        "a clear human session was sequentially escalated (verdict {verdict:?})"
                    );
                }
            }
        }
        assert!(
            any_detection,
            "expected at least one human Detection emitted"
        );
    }
}
