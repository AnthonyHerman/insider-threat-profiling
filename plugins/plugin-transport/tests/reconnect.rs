//! Integration test: the connection actor reconnects with backoff after a
//! failed session, and stops promptly on shutdown.
//!
//! We stand up a bare `TcpListener` that accepts a connection and immediately
//! drops it. The actor's TLS handshake therefore fails every time, driving the
//! state machine into its `Retry` → backoff → reconnect loop. By counting
//! accepts we prove the actor really does reconnect (more than once) rather than
//! giving up after the first failure; then we trigger shutdown and assert the
//! actor task finishes quickly.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_sdk::{Emitter, Event};
use plugin_transport::actor::{self, ActorState, Shutdown};
use plugin_transport::config::TransportConfig;
use plugin_transport::identity::{self, Enrolled};
use plugin_transport::ring::Ring;
use tokio::net::TcpListener;

struct NullEmitter;
#[async_trait::async_trait]
impl Emitter for NullEmitter {
    async fn emit(&self, _e: Event) {}
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "aegis-tp-it-{tag}-{}-{}",
        std::process::id(),
        aegis_sdk::now_ns()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn actor_reconnects_with_backoff_then_stops_on_shutdown() {
    // A listener that accepts then drops, counting each accept.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_srv = accepts.clone();
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepts_srv.fetch_add(1, Ordering::SeqCst);
            // Drop the connection immediately to fail the TLS handshake.
            drop(stream);
        }
    });

    let data_dir = tmp("reconnect");
    let identity = Enrolled {
        agent_id: "agent-it".into(),
        signing_key: identity::generate_key(),
        // Any pin: the handshake dies before pinning matters (server drops TCP).
        server_pins: vec![[0xABu8; 32]],
    };
    // Tight backoff so several attempts happen within the test window.
    let cfg = TransportConfig {
        server: format!("https://127.0.0.1:{}", addr.port()),
        backoff_min_ms: 20,
        backoff_max_ms: 60,
        ..Default::default()
    };

    let shutdown = Shutdown::new();
    let state = ActorState {
        agent_id: "agent-it".into(),
        data_dir: data_dir.clone(),
        cfg,
        identity,
        ring: Arc::new(Ring::new(1000)),
        emitter: Arc::new(NullEmitter),
        shutdown: shutdown.clone(),
    };
    let handle = tokio::spawn(actor::run(state));

    // Let the actor cycle through several connect→fail→backoff iterations.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = accepts.load(Ordering::SeqCst);
    assert!(
        seen >= 2,
        "actor should reconnect repeatedly (saw {seen} accepts)"
    );

    // Shutdown must stop the actor promptly (within a backoff ceiling or two).
    shutdown.trigger();
    let stopped = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(stopped.is_ok(), "actor did not stop after shutdown");

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[tokio::test]
async fn actor_backs_off_when_server_unreachable() {
    // Point at a port nobody is listening on: every connect fails fast. The
    // actor must keep looping (not crash) and still honor shutdown.
    let data_dir = tmp("unreachable");
    let identity = Enrolled {
        agent_id: "agent-it2".into(),
        signing_key: identity::generate_key(),
        server_pins: vec![[0x01u8; 32]],
    };
    let cfg = TransportConfig {
        // Port 1 is reserved/unbindable; connect refuses quickly.
        server: "https://127.0.0.1:1".into(),
        backoff_min_ms: 10,
        backoff_max_ms: 40,
        ..Default::default()
    };
    let shutdown = Shutdown::new();
    let state = ActorState {
        agent_id: "agent-it2".into(),
        data_dir: data_dir.clone(),
        cfg,
        identity,
        ring: Arc::new(Ring::new(100)),
        emitter: Arc::new(NullEmitter),
        shutdown: shutdown.clone(),
    };
    let handle = tokio::spawn(actor::run(state));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!handle.is_finished(), "actor must keep retrying, not exit");

    shutdown.trigger();
    let stopped = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(stopped.is_ok(), "actor did not stop after shutdown");
    let _ = std::fs::remove_dir_all(&data_dir);
}
