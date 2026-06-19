//! # Store sink (`sink.rs`)
//!
//! The [`StoreSink`] plugin: the in-host write path for *derived* telemetry. It
//! is a [`PluginKind::Sink`] plugin added to the host via
//! [`HostBuilder::with_plugin`](aegis_core::HostBuilder::with_plugin), and it is
//! the **only** thing inside the host that persists events the central processors
//! produce — the human-vs-agent detections, the risk scores, the alerts — plus
//! agent `heartbeat`s.
//!
//! ## Why a plugin (and what it does *not* write)
//!
//! Derived kinds (`score`, `detection`, `alert`) never travel the wire; they are
//! created on the internal bus by the scoring/detection processors, so the only
//! way to observe them is to subscribe as a plugin. Raw collector kinds
//! (`input.keystroke`, `command.observed`, `session.*`, `process.exec`) arrive
//! off the network and are written straight to `events` by [`crate::ingest`]
//! *before* they are emitted onto the bus. To avoid double-writing, this sink
//! deliberately does **not** subscribe to those raw kinds. The single rule:
//! *ingest persists what it receives off the wire; the sink persists what the
//! processors produce* (plus `heartbeat`, which the sink uses to refresh agent
//! liveness in addition to logging it).
//!
//! ## What `handle` writes, per kind
//!
//! Every subscribed event is appended to the raw audit log (`events` +
//! `events_by_agent`) via [`Store::write_event`], and then, by kind:
//!
//! * `detection` → upsert the latest detection cell ([`Store::upsert_detection`]).
//! * `score` → upsert the latest score cell ([`Store::upsert_score`]).
//! * `alert` → append to the alert log ([`Store::append_alert`]).
//! * `heartbeat` → refresh the agent's `last_seen_ns` ([`Store::touch_agent`]).
//!
//! The host invokes `handle` one event at a time on the sink's own task, so the
//! writes are naturally serialized; no locking is needed beyond the
//! `Arc<Mutex<Database>>` already inside [`Store`].
//!
//! ## Retention
//!
//! [`init`](StoreSink::init) spawns an hourly Tokio `interval` task that calls
//! [`Store::compact`] with the default [`RETENTION_NS`], pruning expired
//! `events`/`alerts` and defragmenting the file in place.

use std::sync::Arc;
use std::time::Duration;

use aegis_sdk::{Event, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions};
use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::api::LiveEvent;
use crate::store::{AlertRow, DetectionRow, ScoreRow, Store, RETENTION_NS};

/// How often the retention/compaction task runs. Telemetry retention is coarse
/// (30 days by default), so an hourly sweep is ample and keeps the file from
/// growing without bound between restarts.
const COMPACT_INTERVAL: Duration = Duration::from_secs(3600);

/// The plugin that persists derived events (and `heartbeat`s) to the embedded
/// [`Store`] *and* publishes each one onto the live event bus for the HTTP SSE
/// stream. Holds a shared [`Store`] handle (cheap to clone — it shares one
/// `Arc<Mutex<Database>>` and file lock with ingest and the read path) and a
/// [`broadcast::Sender`] whose receivers are the connected `/api/v1/live`
/// clients.
pub struct StoreSink {
    store: Arc<Store>,
    /// Fan-out for the SSE live feed. Cloned from the same channel the HTTP
    /// `AppState` subscribes to; a publish with zero subscribers is not an
    /// error (the `send` result is deliberately discarded).
    live_tx: broadcast::Sender<LiveEvent>,
}

impl StoreSink {
    /// Build a sink over a shared store handle and the live-event fan-out
    /// channel shared with the HTTP layer.
    pub fn new(store: Arc<Store>, live_tx: broadcast::Sender<LiveEvent>) -> Self {
        StoreSink { store, live_tx }
    }
}

#[async_trait]
impl Plugin for StoreSink {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "store-sink",
            env!("CARGO_PKG_VERSION"),
            "Persists derived events (detections, scores, alerts) and heartbeats to the embedded store",
            PluginKind::Sink,
        )
    }

    /// Subscribe only to the derived kinds plus `heartbeat`. The raw collector
    /// kinds are persisted by [`crate::ingest`] before emit, so subscribing to
    /// them here would double-write them.
    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::kinds(["score", "detection", "alert", "heartbeat"])
    }

    /// Spawn the hourly retention/compaction task. The task owns its own clone of
    /// the store handle and runs for the life of the process; it logs (but does
    /// not propagate) compaction errors so a transient failure never tears the
    /// host down.
    async fn init(&mut self, _ctx: &PluginContext) -> anyhow::Result<()> {
        let store = self.store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(COMPACT_INTERVAL);
            // The first tick fires immediately; skip it so we do not compact a
            // just-opened store, and so the first real sweep is one interval in.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match store.compact(RETENTION_NS) {
                    Ok(reclaimed) => {
                        tracing::debug!(reclaimed, "store-sink: retention sweep complete")
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "store-sink: retention sweep failed")
                    }
                }
            }
        });
        Ok(())
    }

    /// Persist one subscribed event. Always logs it to the raw audit log, then
    /// performs the kind-specific write. Each helper opens and commits its own
    /// redb write transaction synchronously.
    async fn handle(&self, event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        // Every subscribed event is part of the audit log.
        self.store.write_event(event)?;

        match event.kind.as_str() {
            "detection" => {
                if let Some(row) = DetectionRow::from_event(event) {
                    self.store.upsert_detection(&row)?;
                    // Publish onto the live feed only after the durable write.
                    self.live_tx
                        .send(LiveEvent::Detection {
                            agent_id: row.agent_id,
                            subject: row.subject,
                            verdict: row.verdict,
                            confidence: row.confidence,
                            ts_ns: row.ts_ns,
                        })
                        .ok();
                } else {
                    tracing::warn!(
                        kind = %event.kind,
                        "store-sink: detection event missing Detection payload"
                    );
                }
            }
            "score" => {
                if let Some(row) = ScoreRow::from_event(event) {
                    self.store.upsert_score(&row)?;
                    self.live_tx
                        .send(LiveEvent::Score {
                            agent_id: row.agent_id,
                            subject: row.subject,
                            score: row.score,
                            ts_ns: row.ts_ns,
                        })
                        .ok();
                } else {
                    tracing::warn!(
                        kind = %event.kind,
                        "store-sink: score event missing Score payload"
                    );
                }
            }
            "alert" => {
                if let Some(row) = AlertRow::from_event(event) {
                    self.store.append_alert(&row)?;
                    self.live_tx
                        .send(LiveEvent::Alert {
                            agent_id: row.agent_id,
                            severity: row.severity,
                            title: row.title,
                            subject: row.subject,
                            ts_ns: row.ts_ns,
                        })
                        .ok();
                } else {
                    tracing::warn!(
                        kind = %event.kind,
                        "store-sink: alert event missing Alert payload"
                    );
                }
            }
            "heartbeat" => {
                self.store.touch_agent(&event.agent_id, event.ts_ns)?;
                // Carry the hostname onto the live feed if the agent is
                // enrolled; a heartbeat from an unknown agent yields None and is
                // still published (the dashboard treats it as a liveness ping).
                let hostname = self
                    .store
                    .agent(&event.agent_id)
                    .ok()
                    .flatten()
                    .map(|a| a.hostname);
                self.live_tx
                    .send(LiveEvent::AgentSeen {
                        agent_id: event.agent_id.clone(),
                        hostname,
                        ts_ns: event.ts_ns,
                    })
                    .ok();
            }
            // We only subscribe to the four kinds above; anything else here is a
            // routing surprise. Log it (it was already written to the audit log).
            other => {
                tracing::debug!(kind = %other, "store-sink: unexpected subscribed kind");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{Event, EventPayload, PluginKind, Severity, Verdict};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Build a minimal `PluginContext` for driving `handle` directly in tests.
    fn ctx(dir: &std::path::Path) -> PluginContext {
        use aegis_sdk::Emitter;
        use async_trait::async_trait;

        /// A no-op emitter; the sink never emits, so this is never exercised.
        struct NullEmitter;
        #[async_trait]
        impl Emitter for NullEmitter {
            async fn emit(&self, _event: Event) {}
        }

        PluginContext {
            agent_id: "server".into(),
            data_dir: PathBuf::from(dir),
            config: serde_json::Value::Null,
            emitter: Arc::new(NullEmitter),
        }
    }

    fn sink_with_store() -> (TempDir, Arc<Store>, StoreSink) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        // A throwaway live-event channel; the receiver is dropped, so publishes
        // are no-ops (zero subscribers is not an error).
        let (live_tx, _) = broadcast::channel(16);
        let sink = StoreSink::new(store.clone(), live_tx);
        (dir, store, sink)
    }

    #[test]
    fn metadata_and_subscriptions_are_correct() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (live_tx, _) = broadcast::channel(16);
        let sink = StoreSink::new(store, live_tx);

        let md = sink.metadata();
        assert_eq!(md.name, "store-sink");
        assert_eq!(md.kind, PluginKind::Sink);

        // Subscribes to exactly the derived kinds + heartbeat; not raw kinds.
        let subs = sink.subscriptions();
        for k in ["score", "detection", "alert", "heartbeat"] {
            assert!(subs.matches(k), "{k} should be subscribed");
        }
        for k in [
            "input.keystroke",
            "command.observed",
            "session.start",
            "session.end",
            "process.exec",
            "custom",
        ] {
            assert!(
                !subs.matches(k),
                "{k} must NOT be subscribed (ingest writes raw)"
            );
        }
    }

    #[tokio::test]
    async fn handle_detection_writes_event_and_cell() {
        let (dir, store, sink) = sink_with_store();
        let ctx = ctx(dir.path());

        let mut ev = Event::new(
            "agent-1",
            "plugin-agent-detect",
            EventPayload::Detection {
                subject: "tty-7".into(),
                verdict: Verdict::Agent,
                confidence: 0.92,
                model: "detect/v1".into(),
                reasons: vec!["regular cadence".into()],
                features: BTreeMap::new(),
            },
        );
        ev.ts_ns = 10_000;
        sink.handle(&ev, &ctx).await.unwrap();

        // The detection cell is populated, keyed by (agent_id, subject).
        let det = store.detection("agent-1", "tty-7").unwrap().unwrap();
        assert_eq!(det.verdict, "agent");
        assert_eq!(det.confidence, 0.92);

        // And the event is in the raw audit log too.
        let evs = store.events_for_agent("agent-1", 0, 10).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "detection");
    }

    #[tokio::test]
    async fn handle_score_writes_event_and_cell() {
        let (dir, store, sink) = sink_with_store();
        let ctx = ctx(dir.path());

        let ev = Event::new(
            "agent-1",
            "plugin-scoring",
            EventPayload::Score {
                subject: "tty-7".into(),
                model: "risk/v1".into(),
                score: 73.5,
                features: BTreeMap::new(),
            },
        );
        sink.handle(&ev, &ctx).await.unwrap();

        let score = store.score("agent-1", "tty-7").unwrap().unwrap();
        assert_eq!(score.score, 73.5);
        assert_eq!(store.events_for_agent("agent-1", 0, 10).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn handle_alert_appends_to_log() {
        let (dir, store, sink) = sink_with_store();
        let ctx = ctx(dir.path());

        let ev = Event::new(
            "agent-1",
            "plugin-scoring",
            EventPayload::Alert {
                severity: Severity::Critical,
                title: "automation detected".into(),
                detail: "subject tty-7 looks scripted".into(),
                subject: Some("tty-7".into()),
            },
        );
        sink.handle(&ev, &ctx).await.unwrap();

        let alerts = store.alerts_recent(10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[0].title, "automation detected");
        assert!(!alerts[0].acknowledged);
    }

    #[tokio::test]
    async fn handle_publishes_live_event_to_subscriber() {
        // A subscriber on the live channel must receive the matching LiveEvent
        // after the durable write.
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (live_tx, mut live_rx) = broadcast::channel(16);
        let sink = StoreSink::new(store.clone(), live_tx);
        let ctx = ctx(dir.path());

        let ev = Event::new(
            "agent-1",
            "plugin-scoring",
            EventPayload::Score {
                subject: "tty-7".into(),
                model: "risk/v1".into(),
                score: 73.5,
                features: BTreeMap::new(),
            },
        );
        sink.handle(&ev, &ctx).await.unwrap();

        match live_rx.try_recv().expect("a live event was published") {
            LiveEvent::Score {
                agent_id,
                subject,
                score,
                ..
            } => {
                assert_eq!(agent_id, "agent-1");
                assert_eq!(subject, "tty-7");
                assert_eq!(score, 73.5);
            }
            other => panic!("unexpected live event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_heartbeat_touches_agent_and_logs() {
        let (dir, store, sink) = sink_with_store();
        let ctx = ctx(dir.path());

        // Seed an enrolled agent so `touch` has a row to update (touch is a no-op
        // on an absent agent).
        let (token, _) = crate::enroll::create_token(&store, "host").unwrap();
        let agent_id =
            match crate::enroll::enroll(&store, &token, "host", "Linux", [9u8; 32]).unwrap() {
                crate::enroll::EnrollOutcome::Accepted { agent_id } => agent_id,
                other => panic!("enroll failed: {other:?}"),
            };

        let mut ev = Event::new(
            agent_id.clone(),
            "agent",
            EventPayload::Heartbeat { uptime_s: 42 },
        );
        ev.ts_ns = 555_000;
        sink.handle(&ev, &ctx).await.unwrap();

        assert_eq!(
            store.agent(&agent_id).unwrap().unwrap().last_seen_ns,
            555_000,
            "heartbeat should refresh last_seen_ns"
        );
        // Heartbeat is also part of the audit log.
        assert_eq!(store.events_for_agent(&agent_id, 0, 10).unwrap().len(), 1);
    }
}
