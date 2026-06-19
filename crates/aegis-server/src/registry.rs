//! # Live command router (`registry.rs`)
//!
//! The in-memory table mapping a connected `agent_id` to the command channel of
//! its current ingest session. It is the bridge between the (future) HTTP layer
//! — `POST /agents/:id/command` — and the long-lived TLS connection task in
//! [`crate::ingest`]: the connection handler registers a sender when a session
//! authenticates and removes it on disconnect; the HTTP handler (or any other
//! caller) looks the agent up and pushes a [`ServerCommand`] into that channel,
//! which the connection task drains and writes to the agent.
//!
//! This holds no persistent state — it is purely the *live* connection table.
//! The durable agent registry lives in [`crate::store`] (`agents`); a row there
//! means "enrolled", an entry here means "connected right now".
//!
//! ## Concurrency
//!
//! The router is read-mostly (every queued command is one lookup) and written
//! only on connect/disconnect, so a `tokio::sync::RwLock<HashMap<..>>` behind an
//! `Arc` is sufficient and keeps the server crate free of an extra dependency.
//! (The design notes a `DashMap` as an equally valid alternative; the method
//! surface here is identical, so swapping the backing map later is mechanical.)
//! [`Router`] is `Clone` — every connection handler and the HTTP `AppState`
//! share one instance.

use std::collections::HashMap;
use std::sync::Arc;

use aegis_proto::ServerCommand;
use tokio::sync::{mpsc, RwLock};

/// Why a command could not be delivered to an agent. The HTTP layer maps these
/// to status codes: [`RouterError::NotConnected`] → `404`,
/// [`RouterError::ChannelFull`] → `503`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouterError {
    /// No live session is registered for this `agent_id` (it may be enrolled but
    /// offline). Maps to HTTP 404.
    #[error("agent is not connected")]
    NotConnected,
    /// A session exists but its command queue is full (the connection task is
    /// not draining fast enough). Maps to HTTP 503.
    #[error("agent command channel is full")]
    ChannelFull,
}

/// Live `agent_id` → command-channel map. Cheap to [`clone`](Clone::clone):
/// every clone shares one `Arc<RwLock<..>>`.
#[derive(Clone, Default)]
pub struct Router {
    inner: Arc<RwLock<HashMap<String, mpsc::Sender<ServerCommand>>>>,
}

impl Router {
    /// Create an empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the command sender for a connected agent.
    ///
    /// Last-writer-wins: if the same `agent_id` reconnects while a stale session
    /// is still mapped, the new sender replaces the old one. The old session's
    /// connection task will notice its own read error / channel drop and tear
    /// itself down; we do not want a defunct session to keep receiving commands.
    pub async fn register(&self, agent_id: String, tx: mpsc::Sender<ServerCommand>) {
        self.inner.write().await.insert(agent_id, tx);
    }

    /// Remove an agent's session (on disconnect).
    ///
    /// Guards against clobbering a *newer* session: if a reconnect already
    /// replaced this agent's sender (so the mapped channel differs from the one
    /// closing), the entry is left in place. The closing task's sender half is
    /// dropped either way once its `mpsc::Receiver` is gone.
    pub async fn unregister(&self, agent_id: &str, tx: &mpsc::Sender<ServerCommand>) {
        let mut map = self.inner.write().await;
        if let Some(current) = map.get(agent_id) {
            if current.same_channel(tx) {
                map.remove(agent_id);
            }
        }
    }

    /// Queue a command for delivery to a connected agent.
    ///
    /// Uses `try_send` so a slow/blocked connection cannot stall the caller (the
    /// HTTP request thread): a full queue is reported as [`RouterError::ChannelFull`]
    /// rather than awaited. An unknown/offline agent is [`RouterError::NotConnected`].
    pub async fn send(&self, agent_id: &str, cmd: ServerCommand) -> Result<(), RouterError> {
        // Clone the sender out under the read lock, then release the lock before
        // `try_send` so the map is never held across the (cheap) enqueue.
        let tx = {
            let map = self.inner.read().await;
            map.get(agent_id).cloned()
        };
        match tx {
            Some(tx) => tx.try_send(cmd).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => RouterError::ChannelFull,
                // The receiver is gone (session ended between lookup and send):
                // treat exactly like "not connected".
                mpsc::error::TrySendError::Closed(_) => RouterError::NotConnected,
            }),
            None => Err(RouterError::NotConnected),
        }
    }

    /// Whether a live session is registered for this agent.
    pub async fn is_connected(&self, agent_id: &str) -> bool {
        self.inner.read().await.contains_key(agent_id)
    }

    /// Number of currently-connected agents (diagnostics / dashboard).
    pub async fn connected_count(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_send_and_receive() {
        let router = Router::new();
        let (tx, mut rx) = mpsc::channel::<ServerCommand>(4);
        router.register("agent-1".into(), tx).await;

        assert!(router.is_connected("agent-1").await);
        assert_eq!(router.connected_count().await, 1);

        router
            .send(
                "agent-1",
                ServerCommand::Rescore {
                    subject: "s1".into(),
                },
            )
            .await
            .expect("send to connected agent");

        match rx.recv().await {
            Some(ServerCommand::Rescore { subject }) => assert_eq!(subject, "s1"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_to_unknown_agent_is_not_connected() {
        let router = Router::new();
        assert_eq!(
            router.send("ghost", ServerCommand::Noop).await,
            Err(RouterError::NotConnected)
        );
        assert!(!router.is_connected("ghost").await);
    }

    #[tokio::test]
    async fn full_channel_reports_channel_full() {
        let router = Router::new();
        // Capacity 1, and we never drain it.
        let (tx, _rx) = mpsc::channel::<ServerCommand>(1);
        router.register("a".into(), tx).await;
        // First fills the single slot.
        router.send("a", ServerCommand::Noop).await.unwrap();
        // Second overflows.
        assert_eq!(
            router.send("a", ServerCommand::Noop).await,
            Err(RouterError::ChannelFull)
        );
    }

    #[tokio::test]
    async fn dropped_receiver_reports_not_connected() {
        let router = Router::new();
        let (tx, rx) = mpsc::channel::<ServerCommand>(1);
        router.register("a".into(), tx).await;
        drop(rx); // session ended; receiver gone
        assert_eq!(
            router.send("a", ServerCommand::Noop).await,
            Err(RouterError::NotConnected)
        );
    }

    #[tokio::test]
    async fn reconnect_replaces_sender_last_writer_wins() {
        let router = Router::new();
        let (tx_old, mut rx_old) = mpsc::channel::<ServerCommand>(4);
        let (tx_new, mut rx_new) = mpsc::channel::<ServerCommand>(4);
        router.register("a".into(), tx_old).await;
        router.register("a".into(), tx_new).await;

        router.send("a", ServerCommand::Noop).await.unwrap();
        // The new channel receives it; the old one does not.
        assert!(rx_new.recv().await.is_some());
        assert!(rx_old.try_recv().is_err());
    }

    #[tokio::test]
    async fn unregister_only_removes_matching_session() {
        let router = Router::new();
        let (tx_old, _rx_old) = mpsc::channel::<ServerCommand>(4);
        let (tx_new, _rx_new) = mpsc::channel::<ServerCommand>(4);
        router.register("a".into(), tx_old.clone()).await;
        // A reconnect replaces the sender.
        router.register("a".into(), tx_new.clone()).await;

        // The OLD session disconnecting must not evict the NEW session.
        router.unregister("a", &tx_old).await;
        assert!(router.is_connected("a").await, "newer session must survive");

        // The current session disconnecting does evict it.
        router.unregister("a", &tx_new).await;
        assert!(!router.is_connected("a").await);
    }
}
