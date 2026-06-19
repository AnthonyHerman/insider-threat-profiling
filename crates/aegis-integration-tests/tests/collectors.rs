//! End-to-end smoke tests for the **collector** plugins over the real bus.
//!
//! [`pipeline.rs`] exercises the two central *processors* (agent-detect +
//! scoring) by feeding synthetic telemetry straight onto the bus. It deliberately
//! does not load any collector. These tests close that gap: they build a genuine
//! [`aegis_core`] host that loads a real collector plugin (`plugin-process` /
//! `plugin-session`) and assert that the event the collector produces on its own
//! actually traverses the dispatcher fan-out to a `CapturingSink`. That proves
//! the collector → host → sink wiring is intact with real plugin objects, not
//! just that each collector unit-tests its own `/proc` parsing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::{HostBuilder, HostConfig, RunningHost};
use aegis_sdk::{Event, EventPayload, Plugin, PluginKind, PluginMetadata, Subscriptions};
use async_trait::async_trait;

/// A sink subscribed to everything; records each delivered event for assertions.
struct CapturingSink {
    captured: Arc<Mutex<Vec<Event>>>,
}

#[async_trait]
impl Plugin for CapturingSink {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "itest-collector-sink",
            "0",
            "captures every bus event for collector assertions",
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

/// Unique per-host data dir so concurrent test binaries / sequential hosts do not
/// collide on the per-plugin `data_dir/<plugin>` the host creates.
fn unique_config(id: &str) -> HostConfig {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut config = HostConfig::new("itest-collector-agent");
    config.data_dir = std::env::temp_dir().join(format!(
        "aegis-itest-collectors-{id}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    config
}

/// Poll the captured buffer until `pred` holds or `timeout` elapses.
async fn wait_for<F>(captured: &Arc<Mutex<Vec<Event>>>, timeout: Duration, pred: F) -> bool
where
    F: Fn(&[Event]) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if pred(&captured.lock().unwrap()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Build and start a host that loads exactly `plugin` (the collector under test)
/// plus a capturing sink; discovery of the statically-linked set is off for
/// hermeticity. Returns the running host and the shared capture buffer.
async fn start(
    config: HostConfig,
    plugin: Box<dyn Plugin>,
) -> (RunningHost, Arc<Mutex<Vec<Event>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let host = HostBuilder::new(config)
        .discover_static(false)
        .with_plugin(plugin)
        .with_plugin(Box::new(CapturingSink {
            captured: captured.clone(),
        }))
        .build()
        .expect("host builds");
    let running = host.run().await.expect("host runs");
    (running, captured)
}

/// `plugin-process` is a self-driving collector: once started it samples `/proc`
/// and emits a `ProcessExec` for every newly-seen process. The test's own
/// process is always present, so at least one `process.exec` event must reach the
/// sink over the bus within the timeout — proving the collector → host → sink
/// path is wired. `/proc` is Linux-only, so the assertion is gated there; on
/// other platforms `scan()` returns empty by design and we only assert the host
/// runs cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_collector_emits_to_sink() {
    use plugin_process::ProcessPlugin;

    let mut config = unique_config("proc");
    // Fast sampling so the first scan lands quickly (floored at 200 ms internally).
    config.plugins.insert(
        "plugin-process".to_string(),
        serde_json::json!({ "interval_ms": 200, "interactive_uids_only": false }),
    );

    let (running, captured) = start(config, Box::new(ProcessPlugin::default())).await;

    let saw_exec = wait_for(&captured, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| e.kind == "process.exec")
    })
    .await;

    running.shutdown().await.expect("clean shutdown");

    if cfg!(target_os = "linux") {
        assert!(
            saw_exec,
            "expected at least one process.exec from plugin-process to reach the sink"
        );
        // Spot-check the payload shape: a real ProcessExec with a pid.
        let events = captured.lock().unwrap();
        let any_proc = events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::ProcessExec { pid, .. } if *pid > 0));
        assert!(any_proc, "a captured process.exec should carry a real pid");
    }
}

/// `plugin-session` emits a single `SessionStart` from its `init()` when
/// `emit_current_login` is set. The test asserts that lifecycle event reaches the
/// sink over the bus, closing the "no collector smoke test" gap for the session
/// collector too. This is platform-independent (it reads env vars, not `/proc`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_collector_emits_session_start_to_sink() {
    use plugin_session::SessionPlugin;

    let mut config = unique_config("sess");
    config.plugins.insert(
        "plugin-session".to_string(),
        serde_json::json!({ "emit_current_login": true, "hash_salt": "itest-salt" }),
    );

    let (running, captured) = start(config, Box::new(SessionPlugin)).await;

    let saw_start = wait_for(&captured, Duration::from_secs(10), |evs| {
        evs.iter()
            .any(|e| matches!(&e.payload, EventPayload::SessionStart { .. }))
    })
    .await;

    running.shutdown().await.expect("clean shutdown");
    assert!(
        saw_start,
        "expected a SessionStart from plugin-session to reach the sink"
    );
}
