//! End-to-end pipeline tests over the **real** Aegis event bus.
//!
//! These are not unit tests of a plugin in isolation: they construct a genuine
//! [`aegis_core`] plugin host, load the two central processors
//! (`plugin-agent-detect` and `plugin-scoring`) exactly as the server does, add a
//! `CapturingSink` subscribed to everything, and feed synthetic behavioral
//! telemetry in through [`RunningHost::emit`]. Every event then travels the full
//! production path:
//!
//! ```text
//!   emit(Keystroke/CommandObserved)            (test → ingress channel)
//!        → dispatcher fan-out                   (aegis-core bus)
//!          → plugin-agent-detect.handle         (accumulates per-session features)
//!            → emit(Detection)                  (its own task, re-enters ingress)
//!              → dispatcher fan-out
//!                → plugin-scoring.handle        (risk aggregation)
//!                  → emit(Score [, Alert])      (re-enters ingress)
//!                    → dispatcher fan-out
//!                      → CapturingSink.handle   (records every event)
//! ```
//!
//! The tests assert on what the sink captured, so they exercise the dispatcher,
//! the per-plugin queues, the critical-event back-pressure path (Detection /
//! Score / Alert are non-droppable), and the multi-hop async re-ingress — not a
//! direct in-process call into a plugin.
//!
//! The synthetic telemetry is produced by the plugin's own public generator
//! ([`plugin_agent_detect::synth`]), which samples the documented human/agent
//! behavioral distributions. We do **not** hand-tune magic numbers or weaken the
//! model: we feed the same distributions the model was calibrated against and
//! assert the verdicts the real model produces (empirically: agent sessions of
//! at least 24 commands cross the 0.62 Agent threshold every time, while human
//! sessions never reach Agent).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::{HostBuilder, HostConfig, RunningHost};
use aegis_sdk::{
    Event, EventPayload, Plugin, PluginKind, PluginMetadata, Severity, Subscriptions, Verdict,
};
use async_trait::async_trait;
use plugin_agent_detect::synth::{synth_events, ProfileParams, Rng, SynthEvent};
use plugin_agent_detect::AgentDetectPlugin;
use plugin_scoring::ScoringPlugin;

/// The risk score at/above which `plugin-scoring` raises an alert (its default).
/// Mirrored here so the human test can assert "stayed below the alert line"
/// without reaching into the plugin's private config.
const ALERT_THRESHOLD: f64 = 75.0;

// --------------------------------------------------------------------------
// CapturingSink: a real Plugin that records every event the bus delivers.
// --------------------------------------------------------------------------

/// A sink plugin subscribed to **all** event kinds. Each delivered event is
/// cloned into a shared buffer the test can inspect. Because it rides the real
/// bus (rather than being a bare `Emitter` the plugin calls directly), capturing
/// an event here proves it actually traversed the dispatcher fan-out.
struct CapturingSink {
    captured: Arc<Mutex<Vec<Event>>>,
}

impl CapturingSink {
    /// Build a sink and return it alongside the shared handle the test reads.
    fn new() -> (Self, Arc<Mutex<Vec<Event>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        (
            CapturingSink {
                captured: captured.clone(),
            },
            captured,
        )
    }
}

#[async_trait]
impl Plugin for CapturingSink {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "itest-capturing-sink",
            "0",
            "captures every bus event for assertions",
            PluginKind::Sink,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::All
    }

    async fn handle(&self, event: &Event, _ctx: &aegis_sdk::PluginContext) -> anyhow::Result<()> {
        self.captured.lock().unwrap().push(event.clone());
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

/// Build and start a host wired exactly like the server's processing core: the
/// two central processors plus a capturing sink, discovery of other static
/// plugins disabled for hermeticity, and a generous queue so droppable telemetry
/// (`input.keystroke` / `command.observed`) is not lost mid-session. Returns the
/// running host and the shared capture buffer.
async fn build_running_host() -> (RunningHost, Arc<Mutex<Vec<Event>>>) {
    let (sink, captured) = CapturingSink::new();

    let mut config = HostConfig::new("itest-agent");
    // Unique temp dir per host so neither concurrent test binaries nor the
    // sequential hosts in one test collide on the per-plugin `data_dir/<plugin>`
    // the host creates. PID separates processes; a process-wide counter
    // separates every host built within this process.
    static HOST_SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "aegis-itest-{}-{}",
        std::process::id(),
        HOST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    config.data_dir = std::env::temp_dir().join(unique);
    // Telemetry (keystrokes/commands) is droppable on a full ingress/fan-out
    // queue; size it to comfortably absorb a whole multi-hundred-event session.
    // The critical kinds (detection/score/alert) are non-droppable regardless.
    config.queue_depth = 1 << 16; // 65536

    let host = HostBuilder::new(config)
        .discover_static(false)
        .with_plugin(Box::new(AgentDetectPlugin::default()))
        .with_plugin(Box::new(ScoringPlugin::default()))
        .with_plugin(Box::new(sink))
        .build()
        .expect("host builds");

    let running = host.run().await.expect("host runs");
    (running, captured)
}

/// Emit a full synthetic session through the bus: `SessionStart`, then every
/// generated [`SynthEvent`] mapped to its matching telemetry payload, then
/// `SessionEnd`. The non-behavioral structural fields of `CommandObserved`
/// (`command_len`, `token_count`, `edit_distance_prev`, `command_hash`) are
/// fixed placeholders — the model keys only on timing/entropy/backspace — exactly
/// as the plugin's own end-to-end tests do.
async fn emit_session(
    host: &RunningHost,
    session_id: &str,
    params: &ProfileParams,
    seed: u64,
    min_commands: u32,
) {
    let agent_id = "itest-agent";

    host.emit(Event::new(
        agent_id,
        "test-collector",
        EventPayload::SessionStart {
            session_id: session_id.to_string(),
            tty: Some("pts/0".into()),
            user: "operator".into(),
            remote: None,
        },
    ))
    .await;

    let mut rng = Rng::new(seed);
    for evt in synth_events(params, &mut rng, min_commands) {
        let payload = match evt {
            SynthEvent::Keystroke {
                inter_arrival_ns,
                is_paste,
                burst_len,
            } => EventPayload::Keystroke {
                session_id: session_id.to_string(),
                inter_arrival_ns,
                is_paste,
                burst_len,
            },
            SynthEvent::Command {
                inter_command_ns,
                had_backspace,
                entropy,
            } => EventPayload::CommandObserved {
                session_id: session_id.to_string(),
                command_len: 20,
                token_count: 3,
                shannon_entropy: entropy,
                had_backspace,
                edit_distance_prev: 5,
                inter_command_ns,
                command_hash: "placeholder".into(),
            },
        };
        host.emit(Event::new(agent_id, "test-collector", payload))
            .await;
    }

    host.emit(Event::new(
        agent_id,
        "test-collector",
        EventPayload::SessionEnd {
            session_id: session_id.to_string(),
        },
    ))
    .await;
}

/// Poll the captured buffer every 10 ms until `pred` holds over the snapshot or
/// `timeout` elapses. Returns whether the predicate was satisfied. Polling (vs a
/// fixed sleep) keeps the multi-hop async pipeline robust under load.
async fn wait_for<F>(captured: &Arc<Mutex<Vec<Event>>>, timeout: Duration, pred: F) -> bool
where
    F: Fn(&[Event]) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        {
            let guard = captured.lock().unwrap();
            if pred(&guard) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --- Filter helpers over a captured snapshot ------------------------------

/// All `Detection` events for `subject`, as `(verdict, confidence, source)`.
fn detections_for(events: &[Event], subject: &str) -> Vec<(Verdict, f64, String)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Detection {
                subject: s,
                verdict,
                confidence,
                ..
            } if s == subject => Some((*verdict, *confidence, e.source.clone())),
            _ => None,
        })
        .collect()
}

/// All `Score` events for `subject`, as `(score, source)`.
fn scores_for(events: &[Event], subject: &str) -> Vec<(f64, String)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Score {
                subject: s, score, ..
            } if s == subject => Some((*score, e.source.clone())),
            _ => None,
        })
        .collect()
}

/// Whether any captured `Score` for `subject` was sourced from an **Agent**
/// detection. `plugin-scoring` records the upstream verdict signal in
/// `features["verdict_agentness"]` (1.0 for Agent, 0.5 for Uncertain), so this
/// distinguishes "risk because the detector said Agent" from "risk because the
/// detector camped Uncertain" without re-deriving any scoring math.
fn has_agent_sourced_score(events: &[Event], subject: &str) -> bool {
    events.iter().any(|e| matches!(
        &e.payload,
        EventPayload::Score { subject: s, features, .. }
            if s == subject
                && (features.get("verdict_agentness").copied().unwrap_or(0.0) - 1.0).abs() < 1e-9
    ))
}

/// All `Alert` events naming `subject`, as `(severity, source)`.
fn alerts_for(events: &[Event], subject: &str) -> Vec<(Severity, String)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Alert {
                severity,
                subject: Some(s),
                ..
            } if s == subject => Some((*severity, e.source.clone())),
            _ => None,
        })
        .collect()
}

/// Count captured events of a given routing kind.
fn count_kind(events: &[Event], kind: &str) -> usize {
    events.iter().filter(|e| e.kind == kind).count()
}

// --------------------------------------------------------------------------
// Test (1): an agent session drives Detection(Agent) → Score → Alert.
// --------------------------------------------------------------------------

/// A synthetic **agent** session (metronomic typing, whole-line pastes,
/// millisecond reactions, no fatigue) is classified `Agent` by the real model,
/// which `plugin-scoring` turns into accumulating risk and ultimately an alert —
/// all over the live bus.
///
/// `min_commands = 24` clears `MIN_COMMANDS_ROBUST` (16) so the Tier-3 temporal
/// terms and the physiological hard rules engage; empirically every agent seed
/// then crosses the 0.62 Agent threshold (p_agent ~0.80–0.92). A long session
/// also produces detections at the assess cadence (`assess_every = 10`) plus a
/// forced one on `SessionEnd`, so the per-Agent-detection risk
/// (`60 * confidence`) accumulates well past the 75 alert threshold within the
/// first couple of Agent detections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_session_yields_detection_score_and_alert() {
    let (running, captured) = build_running_host().await;
    let session = "agent-sess";

    emit_session(&running, session, &ProfileParams::agent(), 0, 24).await;

    // Wait for the pipeline to reach the end: an Alert for this subject is the
    // last hop (telemetry → Detection → Score → Alert). Generous budget for a
    // loaded CI machine; the poll returns as soon as it appears.
    let reached_alert = wait_for(&captured, Duration::from_secs(15), |evs| {
        !alerts_for(evs, session).is_empty()
    })
    .await;

    // Drain every task so all in-flight hops are flushed before final asserts.
    running.shutdown().await.expect("clean shutdown");
    let events = captured.lock().unwrap().clone();

    assert!(
        reached_alert,
        "expected an Alert for {session} within the timeout; captured kinds: \
         detections={}, scores={}, alerts={}",
        count_kind(&events, "detection"),
        count_kind(&events, "score"),
        count_kind(&events, "alert"),
    );

    // (a) The detector emitted at least one Agent verdict for this session, with
    //     host-asserted provenance and a sane confidence.
    let dets = detections_for(&events, session);
    assert!(!dets.is_empty(), "no Detection captured for {session}");
    let agent_dets: Vec<_> = dets
        .iter()
        .filter(|(v, _, _)| *v == Verdict::Agent)
        .collect();
    assert!(
        !agent_dets.is_empty(),
        "expected >=1 Agent detection for {session}, got verdicts {:?}",
        dets.iter().map(|(v, _, _)| *v).collect::<Vec<_>>()
    );
    for (_, conf, source) in &agent_dets {
        assert_eq!(
            source, "plugin-agent-detect",
            "Detection.source must be host-stamped to the detector"
        );
        assert!(
            *conf > 0.5 && *conf <= 1.0,
            "Agent confidence out of range: {conf}"
        );
    }

    // (b) Scoring turned the detection(s) into risk for the same subject, with
    //     host-asserted provenance and a positive risk_score feature.
    let scores = scores_for(&events, session);
    assert!(!scores.is_empty(), "no Score captured for {session}");
    let max_score = scores.iter().map(|(s, _)| *s).fold(0.0_f64, f64::max);
    assert!(
        max_score > 0.0,
        "expected a positive risk score, max was {max_score}"
    );
    for (_, source) in &scores {
        assert_eq!(source, "plugin-scoring", "Score.source must be the scorer");
    }
    // The risk_score feature decomposition must be present and match the score.
    let score_feature_present = events.iter().any(|e| {
        matches!(
            &e.payload,
            EventPayload::Score { subject: s, features, .. }
                if s == session && features.get("risk_score").copied().unwrap_or(0.0) > 0.0
        )
    });
    assert!(
        score_feature_present,
        "Score.features should carry a positive risk_score"
    );

    // (c) Risk crossed the alert threshold and an Alert was raised for the
    //     subject by the scorer.
    assert!(
        max_score >= ALERT_THRESHOLD,
        "expected risk to reach the alert threshold {ALERT_THRESHOLD}, max was {max_score}"
    );
    let alerts = alerts_for(&events, session);
    assert!(!alerts.is_empty(), "no Alert captured for {session}");
    for (severity, source) in &alerts {
        assert_eq!(source, "plugin-scoring", "Alert.source must be the scorer");
        assert!(
            *severity >= Severity::Medium,
            "an elevated-risk alert should be at least Medium, got {severity:?}"
        );
    }

    // (d) Sanity: the upstream telemetry genuinely flowed through the bus to the
    //     capturing sink (not just the derived events), proving the full path.
    assert!(
        count_kind(&events, "input.keystroke") > 0,
        "no keystroke telemetry reached the sink over the bus"
    );
    assert!(
        count_kind(&events, "command.observed") > 0,
        "no command telemetry reached the sink over the bus"
    );
    assert_eq!(
        count_kind(&events, "session.start"),
        1,
        "exactly one SessionStart should have flowed through the bus"
    );
}

// --------------------------------------------------------------------------
// Test (2): a human session is never classified Agent, and a clear human is
// silent (no risk, no alert).
// --------------------------------------------------------------------------

/// A synthetic **human** session (bursty heavy-tailed typing, seconds-long
/// serially-correlated think times, frequent backspaces, fatigue drift) is never
/// classified `Agent` by the real model. We sweep several seeds and require the
/// invariant on every one, so the test exercises the human distribution rather
/// than a single lucky draw.
///
/// Two faithful, deterministic assertions per seed:
///
/// * **Universal (every seed):** no Detection is `Agent`, and no Score is
///   Agent-sourced (`features["verdict_agentness"] == 1.0`). This is the
///   safety-critical contract — a human is never condemned as an automated
///   agent, so no Agent-driven risk is ever attributed.
/// * **Clear-human seeds:** when the model rates the whole session `Human` (the
///   common case — empirically a strong majority of seeds), the pipeline is
///   silent: no risk `Score` and no `Alert` for the subject at all.
///
/// We deliberately do **not** assert "a human never alerts" unconditionally: the
/// system's A5 mitigation in `plugin-scoring` treats a session that *persistently*
/// camps `Uncertain` (high mid-band confidence) as actionable and lets its risk
/// climb toward an alert. A borderline human that the model leaves `Uncertain`
/// across re-assessments can therefore legitimately alert — that is designed
/// behavior, not a model failure, and weakening either the model or the scorer to
/// suppress it would defeat the very mitigation. The invariant that holds for
/// *all* humans is "never Agent / no Agent-sourced risk", which is what we assert
/// universally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn human_session_is_never_agent_and_clear_human_is_silent() {
    let mut clear_human_seeds = 0usize;

    for seed in 0u64..8 {
        let (running, captured) = build_running_host().await;
        let session = format!("human-sess-{seed}");

        emit_session(&running, &session, &ProfileParams::human(), seed, 24).await;

        // Wait until the detector has spoken for this session (>=1 Detection),
        // so we are asserting on a settled pipeline rather than an empty one.
        let saw_detection = wait_for(&captured, Duration::from_secs(15), |evs| {
            !detections_for(evs, &session).is_empty()
        })
        .await;

        running.shutdown().await.expect("clean shutdown");
        let events = captured.lock().unwrap().clone();

        assert!(
            saw_detection,
            "seed {seed}: expected at least one Detection for {session}"
        );

        // (a) UNIVERSAL: no Detection for this session is ever Agent.
        let dets = detections_for(&events, &session);
        for (verdict, _, _) in &dets {
            assert_ne!(
                *verdict,
                Verdict::Agent,
                "seed {seed}: a human session was classified Agent (verdicts {:?})",
                dets.iter().map(|(v, _, _)| *v).collect::<Vec<_>>()
            );
        }

        // (b) UNIVERSAL: no Agent-sourced risk was ever attributed to a human.
        assert!(
            !has_agent_sourced_score(&events, &session),
            "seed {seed}: a human session accrued Agent-sourced risk"
        );

        // (c) CLEAR HUMAN: a session the model rates `Human` throughout must be
        //     completely silent on the risk pipeline — no Score, no Alert.
        let all_human = !dets.is_empty() && dets.iter().all(|(v, _, _)| *v == Verdict::Human);
        if all_human {
            clear_human_seeds += 1;
            assert!(
                scores_for(&events, &session).is_empty(),
                "seed {seed}: a clear-Human session produced a risk Score \
                 (scores {:?})",
                scores_for(&events, &session)
            );
            assert!(
                alerts_for(&events, &session).is_empty(),
                "seed {seed}: a clear-Human session raised an Alert"
            );
        }

        // (d) Sanity: telemetry still flowed through the bus to the sink.
        assert!(
            count_kind(&events, "input.keystroke") > 0,
            "seed {seed}: no keystroke telemetry reached the sink"
        );
        assert!(
            count_kind(&events, "command.observed") > 0,
            "seed {seed}: no command telemetry reached the sink"
        );
        assert_eq!(
            count_kind(&events, "session.start"),
            1,
            "seed {seed}: expected exactly one SessionStart through the bus"
        );
        // Provenance: every Detection for this session must be sourced from the detector.
        for (_, _, source) in detections_for(&events, &session) {
            assert_eq!(
                source, "plugin-agent-detect",
                "seed {seed}: Detection.source must be host-stamped to the detector"
            );
        }
    }

    // The sweep must actually contain clear-human sessions, otherwise the
    // clear-human silence assertion never ran.
    assert!(
        clear_human_seeds > 0,
        "expected at least one clear-Human session across the seed sweep"
    );
}
