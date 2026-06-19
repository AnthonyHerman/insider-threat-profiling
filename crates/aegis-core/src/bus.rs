//! The event bus.
//!
//! All events enter through a single bounded ingress channel. A dispatcher task
//! drains it and fans each event out to the private queue of every plugin whose
//! [`Subscriptions`](aegis_sdk::Subscriptions) match the event's `kind`. Each
//! plugin runs its own handler task, so a slow plugin applies back-pressure to
//! itself without head-of-line-blocking the rest of the system.

use aegis_sdk::{Emitter, Event};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Security-critical event kinds that must not be silently dropped on a full
/// queue. Flooding cheap telemetry (e.g. keystrokes/heartbeats) to evict the
/// very alert that would catch the flood is a real "flood-to-evict" primitive;
/// for these kinds we apply back-pressure (await a slot) instead of dropping.
pub(crate) fn is_critical_kind(kind: &str) -> bool {
    matches!(kind, "alert" | "detection" | "score")
}

/// Observable bus-loss counters. Every dropped event increments a counter so
/// loss is alertable rather than merely a log line. Cheap, lock-free, shared.
#[derive(Debug, Default)]
pub struct BusMetrics {
    /// Events dropped at the ingress channel because it was full.
    ingress_dropped_full: AtomicU64,
    /// Events dropped at the ingress channel because it was closed (shutdown).
    ingress_dropped_closed: AtomicU64,
    /// Events dropped while fanning out to a (full) per-plugin queue.
    fanout_dropped_full: AtomicU64,
}

impl BusMetrics {
    pub(crate) fn record_ingress_full(&self) {
        self.ingress_dropped_full.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn record_ingress_closed(&self) {
        self.ingress_dropped_closed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_fanout_full(&self) {
        self.fanout_dropped_full.fetch_add(1, Ordering::Relaxed);
    }
    /// Total events dropped at ingress (full + closed).
    pub fn ingress_dropped(&self) -> u64 {
        self.ingress_dropped_full.load(Ordering::Relaxed)
            + self.ingress_dropped_closed.load(Ordering::Relaxed)
    }
    /// Total events dropped fanning out to per-plugin queues.
    pub fn fanout_dropped(&self) -> u64 {
        self.fanout_dropped_full.load(Ordering::Relaxed)
    }
}

/// Cloneable handle plugins use to publish events back onto the bus.
#[derive(Clone)]
pub struct BusEmitter {
    tx: mpsc::Sender<Event>,
    metrics: Arc<BusMetrics>,
}

impl BusEmitter {
    pub(crate) fn new(tx: mpsc::Sender<Event>, metrics: Arc<BusMetrics>) -> Self {
        BusEmitter { tx, metrics }
    }

    /// Shared drop counters for this bus.
    pub fn metrics(&self) -> Arc<BusMetrics> {
        self.metrics.clone()
    }
}

#[async_trait]
impl Emitter for BusEmitter {
    async fn emit(&self, event: Event) {
        // Security-critical kinds get a non-droppable path: await a slot
        // (back-pressure) rather than dropping, so a flood of cheap telemetry
        // cannot evict the alert/detection/score that would catch it. Closed
        // means shutdown — nothing more we can do.
        if is_critical_kind(&event.kind) {
            let kind = event.kind.clone();
            if let Err(err) = self.tx.send(event).await {
                self.metrics.record_ingress_closed();
                tracing::warn!(kind = %kind, error = %err, "event bus closed; dropping critical event");
            }
            return;
        }
        // Low-value telemetry stays non-blocking on the hot path: prefer to drop
        // (counted) on a full queue rather than risk unbounded memory growth.
        if let Err(err) = self.tx.try_send(event) {
            match err {
                mpsc::error::TrySendError::Full(ev) => {
                    self.metrics.record_ingress_full();
                    tracing::warn!(kind = %ev.kind, "event bus ingress full; dropping event");
                }
                mpsc::error::TrySendError::Closed(ev) => {
                    self.metrics.record_ingress_closed();
                    // Raised from debug→warn and now carries the kind, so loss in
                    // the shutdown window is visible at the default log level.
                    tracing::warn!(kind = %ev.kind, "event bus closed; dropping event");
                }
            }
        }
    }
}

/// Create the ingress channel: an emitter handle and the receiver the
/// dispatcher will drain.
pub(crate) fn ingress(depth: usize) -> (BusEmitter, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(depth);
    (BusEmitter::new(tx, Arc::new(BusMetrics::default())), rx)
}

/// A per-plugin [`Emitter`] that **host-asserts** provenance: it overwrites the
/// `source` of every emitted event with the plugin's registered name and the
/// `agent_id` with the host's configured identity before forwarding to the
/// shared bus.
///
/// Plugins receive one of these (instead of the raw [`BusEmitter`]) in their
/// [`PluginContext`](aegis_sdk::PluginContext), so a plugin cannot spoof another
/// plugin's name or claim `"host"`, and cannot forge an `agent_id`. This closes
/// the in-process attribution gap (the network ingest boundary is defended
/// separately on the server). The host keeps the raw [`BusEmitter`] for
/// genuinely kernel-originated events.
pub struct ScopedEmitter {
    inner: Arc<dyn Emitter>,
    source: String,
    agent_id: String,
}

impl ScopedEmitter {
    pub(crate) fn new(inner: Arc<dyn Emitter>, source: String, agent_id: String) -> Self {
        ScopedEmitter {
            inner,
            source,
            agent_id,
        }
    }
}

#[async_trait]
impl Emitter for ScopedEmitter {
    async fn emit(&self, mut event: Event) {
        // Host-asserted provenance: overwrite whatever the plugin set.
        event.source = self.source.clone();
        event.agent_id = self.agent_id.clone();
        self.inner.emit(event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{EventPayload, Severity};
    use std::sync::Mutex as StdMutex;

    fn heartbeat() -> Event {
        Event::new("a", "test", EventPayload::Heartbeat { uptime_s: 1 })
    }
    fn alert() -> Event {
        Event::new(
            "a",
            "test",
            EventPayload::Alert {
                severity: Severity::High,
                title: "x".into(),
                detail: "y".into(),
                subject: None,
            },
        )
    }

    /// M10: dropping a non-critical event on a full ingress queue increments the
    /// observable drop counter (loss is alertable, not silent).
    #[tokio::test]
    async fn non_critical_drop_is_counted_when_full() {
        let (emitter, _rx) = ingress(1);
        let metrics = emitter.metrics();
        // Fill the single slot, then the next non-critical emit must drop+count.
        emitter.emit(heartbeat()).await;
        emitter.emit(heartbeat()).await;
        assert_eq!(
            metrics.ingress_dropped(),
            1,
            "one heartbeat should be dropped"
        );
        assert_eq!(metrics.fanout_dropped(), 0);
    }

    /// M10: a security-critical event is *not* dropped on a full queue — it
    /// applies back-pressure and is delivered once a slot frees, so it cannot be
    /// flood-evicted by cheap telemetry.
    #[tokio::test]
    async fn critical_event_is_not_dropped_on_full_queue() {
        let (emitter, mut rx) = ingress(1);
        let metrics = emitter.metrics();
        // Prime the single slot so the queue is full.
        emitter.emit(heartbeat()).await;

        // Emit a critical alert concurrently; it must block until the reader
        // drains a slot rather than being dropped.
        let producer = {
            let emitter = emitter.clone();
            tokio::spawn(async move {
                emitter.emit(alert()).await;
            })
        };

        // Drain the priming heartbeat, freeing a slot for the alert.
        let first = rx.recv().await.expect("first event");
        assert_eq!(first.kind, "heartbeat");
        // The alert must arrive (was not dropped).
        let second = rx.recv().await.expect("critical event delivered");
        assert_eq!(second.kind, "alert");
        producer.await.unwrap();
        assert_eq!(
            metrics.ingress_dropped(),
            0,
            "critical event must not be dropped"
        );
    }

    /// M9: the scoped emitter overwrites `source` and `agent_id` so a plugin
    /// cannot spoof another plugin's name or forge an agent identity.
    #[tokio::test]
    async fn scoped_emitter_overwrites_source_and_agent_id() {
        #[derive(Default)]
        struct Capture {
            events: Arc<StdMutex<Vec<Event>>>,
        }
        #[async_trait]
        impl Emitter for Capture {
            async fn emit(&self, event: Event) {
                self.events.lock().unwrap().push(event);
            }
        }
        let captured = Arc::new(StdMutex::new(Vec::new()));
        let inner: Arc<dyn Emitter> = Arc::new(Capture {
            events: captured.clone(),
        });
        let scoped = ScopedEmitter::new(inner, "plugin-real".into(), "host-id".into());

        // A malicious plugin tries to claim it is "host" with another agent_id.
        let mut spoofed = heartbeat();
        spoofed.source = "host".into();
        spoofed.agent_id = "someone-else".into();
        scoped.emit(spoofed).await;

        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "plugin-real");
        assert_eq!(events[0].agent_id, "host-id");
    }
}
