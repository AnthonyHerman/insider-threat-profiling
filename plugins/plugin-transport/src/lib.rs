//! # plugin-transport
//!
//! The agent's **forwarder**: a [`PluginKind::Sink`] subscribed to every event
//! that relays telemetry to the Aegis server over a mutual-auth TLS session.
//!
//! ## Design
//! [`Plugin::handle`] is on the hot path of the event bus, so it never touches
//! the network — it does exactly one non-blocking thing: push the event into a
//! bounded in-memory [`ring`](crate::ring). A single **connection actor**,
//! spawned in [`Plugin::init`] (the spawn-in-init pattern from `plugin-tamper`),
//! owns everything async: it connects, completes a pinned TLS handshake plus an
//! Ed25519 challenge-response over RFC-5705 channel binding, builds size/time
//! triggered [`EventBatch`](aegis_proto::Message::EventBatch)es, awaits a
//! [`BatchAck`](aegis_proto::Message::BatchAck) (one batch in flight by default,
//! giving strict FIFO), and reconnects with full-jitter exponential backoff on
//! any failure.
//!
//! Durability is two-tiered: the in-memory ring is the front buffer; a redb
//! [`spill`](crate::spill) (postcard-encoded, drop-oldest, with counters) is the
//! disk tier so telemetry survives a restart and is delivered once the server is
//! reachable again.
//!
//! Identity (the per-agent Ed25519 key, assigned `agent_id`, and the server cert
//! pin set) is written by `aegis-agent enroll` and loaded from the plugin's data
//! dir; see [`identity`]. The running forwarder never self-enrolls — if no
//! identity is present it logs a clear instruction and idles, buffering to disk
//! so nothing is lost before enrollment completes.

pub mod actor;
pub mod auth;
pub mod config;
pub mod identity;
pub mod ring;
pub mod spill;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aegis_sdk::{
    register_plugin, Event, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions,
};
use async_trait::async_trait;

use crate::actor::{ActorState, Shutdown};
use crate::config::TransportConfig;
use crate::ring::Ring;

/// The forwarder sink plugin.
pub struct TransportPlugin {
    /// In-memory front buffer. Created in `init` once we know the configured
    /// capacity; `handle` offers into it.
    ring: std::sync::OnceLock<Arc<Ring>>,
    /// Stop signal handed to the actor; fired by `shutdown`.
    shutdown: Shutdown,
    /// Guards against double-init.
    started: AtomicBool,
}

impl Default for TransportPlugin {
    fn default() -> Self {
        TransportPlugin {
            ring: std::sync::OnceLock::new(),
            shutdown: Shutdown::new(),
            started: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl Plugin for TransportPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-transport",
            env!("CARGO_PKG_VERSION"),
            "Forwards telemetry to the Aegis server over mutual-auth TLS",
            PluginKind::Sink,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        // A forwarder relays everything on the bus.
        Subscriptions::All
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let cfg: TransportConfig = ctx.config_as()?;

        let ring = Arc::new(Ring::new(cfg.ring_capacity));
        // Ignore the (impossible) second set; init runs once.
        let _ = self.ring.set(ring.clone());

        if cfg.server.trim().is_empty() {
            tracing::warn!(
                "transport: no server configured; events will buffer in memory only \
                 (set [plugins.plugin-transport].server or the agent --server flag)"
            );
        }

        // Load the enrollment identity written by `aegis-agent enroll`.
        let identity = match identity::load(&ctx.data_dir) {
            Ok(Some(id)) => {
                tracing::info!(agent_id = %id.agent_id, ?id, "transport: loaded enrollment identity");
                id
            }
            Ok(None) => {
                tracing::warn!(
                    data_dir = %ctx.data_dir.display(),
                    "transport: not enrolled; run `aegis-agent enroll`. \
                     Telemetry will buffer to disk until then."
                );
                // Spawn a disk-buffering drain so the ring still flows to spill
                // (so nothing is lost before enrollment); no network actor.
                spawn_buffer_only(ring, ctx.data_dir.clone(), self.shutdown.clone());
                return Ok(());
            }
            Err(e) => {
                tracing::error!(error = %e, "transport: failed to load identity; buffering to disk");
                spawn_buffer_only(ring, ctx.data_dir.clone(), self.shutdown.clone());
                return Ok(());
            }
        };

        let state = ActorState {
            agent_id: ctx.agent_id.clone(),
            data_dir: ctx.data_dir.clone(),
            cfg,
            identity,
            ring,
            emitter: ctx.emitter.clone(),
            shutdown: self.shutdown.clone(),
        };
        tokio::spawn(actor::run(state));
        Ok(())
    }

    async fn handle(&self, event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        // Hot path: never block, never await the network. Just enqueue.
        if let Some(ring) = self.ring.get() {
            ring.offer(event.clone());
        }
        Ok(())
    }

    async fn shutdown(&self) -> anyhow::Result<()> {
        self.shutdown.trigger();
        Ok(())
    }
}

/// When not yet enrolled, still drain the ring to the disk spill so telemetry is
/// not lost before `aegis-agent enroll` runs. Enforces the default spill cap.
fn spawn_buffer_only(ring: Arc<Ring>, data_dir: std::path::PathBuf, shutdown: Shutdown) {
    tokio::spawn(async move {
        let path = data_dir.join("spill.redb");
        let mut spill = match spill::Spill::open(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "transport: cannot open spill for pre-enroll buffering");
                return;
            }
        };
        let cap = TransportConfig::default().spill_max_bytes;
        loop {
            tokio::select! {
                _ = ring.notified() => {
                    let evs = ring.drain(usize::MAX);
                    if !evs.is_empty() {
                        if let Err(e) = spill.push(&evs) {
                            tracing::warn!(error = %e, "transport: pre-enroll spill push failed");
                        }
                        let _ = spill.enforce_cap(cap);
                    }
                }
                _ = shutdown.wait() => {
                    let evs = ring.drain(usize::MAX);
                    let _ = spill.push(&evs);
                    break;
                }
            }
        }
    });
}

register_plugin!("plugin-transport", || Box::new(TransportPlugin::default()));

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{Emitter, EventPayload};

    struct NullEmitter;
    #[async_trait]
    impl Emitter for NullEmitter {
        async fn emit(&self, _e: Event) {}
    }

    fn ctx(dir: std::path::PathBuf, cfg: serde_json::Value) -> PluginContext {
        PluginContext {
            agent_id: "agent-test".into(),
            data_dir: dir,
            config: cfg,
            emitter: Arc::new(NullEmitter),
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-tp-test-{tag}-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn metadata_is_sink_and_subscribes_all() {
        let p = TransportPlugin::default();
        assert_eq!(p.metadata().name, "plugin-transport");
        assert_eq!(p.metadata().kind, PluginKind::Sink);
        assert!(p.subscriptions().matches("anything.at.all"));
    }

    #[tokio::test]
    async fn handle_before_init_is_noop() {
        // No ring yet => handle must not panic and simply drop.
        let p = TransportPlugin::default();
        let c = ctx(tmp("preinit"), serde_json::Value::Null);
        let ev = Event::new("a", "t", EventPayload::Heartbeat { uptime_s: 1 });
        p.handle(&ev, &c).await.unwrap();
    }

    #[tokio::test]
    async fn unenrolled_init_buffers_to_spill_without_crashing() {
        // No identity.json present => init must succeed, ring must accept events,
        // and they must end up on the disk spill (pre-enroll buffering).
        let dir = tmp("unenrolled");
        let mut p = TransportPlugin::default();
        let c = ctx(dir.clone(), serde_json::json!({ "server": "" }));
        p.init(&c)
            .await
            .expect("init must not fail when unenrolled");

        // Offer some events through handle.
        for i in 0..5 {
            let ev = Event::new("a", "t", EventPayload::Heartbeat { uptime_s: i });
            p.handle(&ev, &c).await.unwrap();
        }
        // Let the buffer-only task drain the ring to spill.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        p.shutdown().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let spill = spill::Spill::open(&dir.join("spill.redb")).unwrap();
        assert!(
            spill.len().unwrap() >= 1,
            "events should be buffered to disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
