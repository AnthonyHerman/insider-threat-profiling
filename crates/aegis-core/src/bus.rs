//! The event bus.
//!
//! All events enter through a single bounded ingress channel. A dispatcher task
//! drains it and fans each event out to the private queue of every plugin whose
//! [`Subscriptions`](aegis_sdk::Subscriptions) match the event's `kind`. Each
//! plugin runs its own handler task, so a slow plugin applies back-pressure to
//! itself without head-of-line-blocking the rest of the system.

use aegis_sdk::{Emitter, Event};
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Cloneable handle plugins use to publish events back onto the bus.
#[derive(Clone)]
pub struct BusEmitter {
    tx: mpsc::Sender<Event>,
}

impl BusEmitter {
    pub(crate) fn new(tx: mpsc::Sender<Event>) -> Self {
        BusEmitter { tx }
    }
}

#[async_trait]
impl Emitter for BusEmitter {
    async fn emit(&self, event: Event) {
        // A full queue means the system is saturated; we prefer to drop with a
        // warning rather than unbounded memory growth. `try_send` keeps emit
        // non-blocking for collectors on hot paths.
        if let Err(err) = self.tx.try_send(event) {
            match err {
                mpsc::error::TrySendError::Full(ev) => {
                    tracing::warn!(kind = %ev.kind, "event bus ingress full; dropping event");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::debug!("event bus closed; dropping event");
                }
            }
        }
    }
}

/// Create the ingress channel: an emitter handle and the receiver the
/// dispatcher will drain.
pub(crate) fn ingress(depth: usize) -> (BusEmitter, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(depth);
    (BusEmitter::new(tx), rx)
}
