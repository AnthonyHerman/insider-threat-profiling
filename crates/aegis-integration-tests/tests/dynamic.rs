//! End-to-end proof that the Aegis kernel loads a **third-party `cdylib` plugin
//! at runtime** and runs it — the positive counterpart to the negative dynamic
//! loader tests in `aegis-core` (`disabled_dynamic_plugin_is_not_opened`,
//! `enabled_missing_dynamic_plugin_errors`).
//!
//! The plugin under test is the `example-plugin` crate, a standalone shared
//! object that is **not** linked into this test and does **not** use
//! `inventory`/`register_plugin!`. It reaches the host only through the C-ABI
//! contract resolved at runtime. This test:
//!
//! 1. Builds `libexample_plugin.so` by shelling out to cargo (so the artifact
//!    exists even though it is not a Rust dependency of this crate), locating it
//!    robustly from cargo's JSON artifact stream so it honors `CARGO_TARGET_DIR`.
//! 2. Constructs a real [`aegis_core`] host with a [`DynamicPluginSpec`] pointing
//!    at that `.so`, plus a `CapturingSink` subscribed to everything. Building
//!    the host invokes `aegis_core::load_dynamic`, which `dlopen`s the library,
//!    resolves **both** `aegis_plugin_entry` and `aegis_plugin_free_registration`
//!    (failing if either is missing), calls the entrypoint inside `catch_unwind`,
//!    copies the registration's `Copy` fields out, frees the pointer in the
//!    plugin's own allocator, checks the ABI version, and adopts the constructor.
//! 3. Runs the host. `run` awaits the dynamically-constructed plugin's `init`,
//!    which emits one distinctive `Custom` marker event onto the real bus; the
//!    dispatcher fans it out to the `CapturingSink`.
//! 4. Asserts the marker event was captured with the host-stamped `source` and
//!    the expected payload — proving the runtime-loaded plugin's code actually
//!    executed end to end, not merely that the library was opened.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::{DynamicPluginSpec, HostBuilder, HostConfig};
use aegis_sdk::{
    Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions,
};
use async_trait::async_trait;

/// Must match `ExamplePlugin`'s metadata name and the `LOADED_MARKER` it emits.
/// Hardcoded here (rather than depending on the crate) because this test links
/// nothing from `example-plugin`; it only loads the `.so`.
const PLUGIN_NAME: &str = "example-plugin";
const LOADED_MARKER: &str = "example-plugin-loaded-dynamically";

// --------------------------------------------------------------------------
// CapturingSink: a real Plugin that records every event the bus delivers.
// (Same pattern as tests/pipeline.rs — capturing here proves an event actually
// traversed the dispatcher fan-out, not a direct in-process call.)
// --------------------------------------------------------------------------

struct CapturingSink {
    captured: Arc<Mutex<Vec<Event>>>,
}

impl CapturingSink {
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
            "dyn-itest-capturing-sink",
            "0",
            "captures every bus event for assertions",
            PluginKind::Sink,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::All
    }

    async fn handle(&self, event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        self.captured.lock().unwrap().push(event.clone());
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Build + locate the cdylib artifact.
// --------------------------------------------------------------------------

/// Platform shared-object suffix the cdylib artifact ends with.
#[cfg(target_os = "linux")]
const DYLIB_SUFFIX: &str = ".so";
#[cfg(target_os = "macos")]
const DYLIB_SUFFIX: &str = ".dylib";
#[cfg(target_os = "windows")]
const DYLIB_SUFFIX: &str = ".dll";

/// Build the `example-plugin` cdylib and return the path to its shared object.
///
/// Shelling out to cargo is required because `example-plugin` is intentionally
/// not a Rust dependency of this test crate (it is loaded as a `.so`, not
/// linked). We pass `--message-format=json` and parse the `compiler-artifact`
/// record for target `example_plugin`, taking the produced filename that ends in
/// the platform dylib suffix. Parsing the artifact stream (rather than guessing
/// `target/debug/...`) makes this transparently honor `CARGO_TARGET_DIR`.
fn build_example_plugin_so() -> PathBuf {
    // `CARGO` is set by cargo for test/build processes; fall back to "cargo".
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let output = Command::new(cargo)
        .args([
            "build",
            "-p",
            "example-plugin",
            "--message-format=json-render-diagnostics",
        ])
        // Inherit the environment so a CI-set CARGO_TARGET_DIR is honored.
        .output()
        .expect("failed to spawn `cargo build -p example-plugin`");

    assert!(
        output.status.success(),
        "building example-plugin failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Each line of stdout is a JSON message. Find the compiler-artifact for the
    // `example_plugin` target and pull the dylib out of its `filenames`.
    let stdout = String::from_utf8(output.stdout).expect("cargo JSON output is valid UTF-8");
    let mut found: Option<PathBuf> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // non-JSON render lines, if any
        };
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        // cdylib target name uses the crate name with hyphens -> underscores.
        let target_name = msg
            .get("target")
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str());
        if target_name != Some("example_plugin") {
            continue;
        }
        if let Some(filenames) = msg.get("filenames").and_then(|f| f.as_array()) {
            for fname in filenames {
                if let Some(s) = fname.as_str() {
                    if s.ends_with(DYLIB_SUFFIX) {
                        found = Some(PathBuf::from(s));
                        break;
                    }
                }
            }
        }
        if found.is_some() {
            break;
        }
    }

    let path = found.unwrap_or_else(|| {
        panic!(
            "could not locate the example-plugin {DYLIB_SUFFIX} in cargo's artifact output:\n{stdout}"
        )
    });
    assert!(
        path.exists(),
        "cargo reported a plugin artifact that does not exist on disk: {}",
        path.display()
    );
    path
}

/// Locate an already-built `libexample_plugin` shared object next to this test
/// binary, without invoking cargo. Under `cargo test --workspace` (what CI runs)
/// the `example-plugin` cdylib is already built as a workspace member, so we can
/// just point at it — avoiding a NESTED `cargo build` during `cargo test`, which
/// contends on the target-directory build lock and is fragile/hangs in CI.
///
/// The test binary lives at `<target>/<profile>/deps/<bin>`, so the sibling
/// dylib is at `<target>/<profile>/libexample_plugin<suffix>`. This naturally
/// honors `CARGO_TARGET_DIR` because `current_exe()` already reflects it.
fn locate_prebuilt_so() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?; // <target>/<profile>
    let candidate = profile_dir.join(format!("libexample_plugin{DYLIB_SUFFIX}"));
    candidate.exists().then_some(candidate)
}

/// Poll the captured buffer until `pred` holds or `timeout` elapses.
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

/// Is `e` the marker event emitted by the dynamically-loaded example plugin?
fn is_marker_event(e: &Event) -> bool {
    e.kind == "custom"
        && e.source == PLUGIN_NAME
        && matches!(
            &e.payload,
            EventPayload::Custom(v)
                if v.get("marker").and_then(|m| m.as_str()) == Some(LOADED_MARKER)
        )
}

// --------------------------------------------------------------------------
// The test.
// --------------------------------------------------------------------------

/// Load `example-plugin` purely at runtime through `aegis_core`'s real loader and
/// host, then prove it ran by observing its emitted marker event on the bus.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_cdylib_plugin_loads_and_runs() {
    // 1. Build + locate the third-party shared object.
    // Prefer the artifact the workspace build already produced (no nested cargo,
    // so CI's `cargo test --workspace` does not deadlock on the build lock);
    // fall back to building it for a standalone `cargo test -p ...` run.
    let so_path = locate_prebuilt_so().unwrap_or_else(build_example_plugin_so);

    // 2. Build a host whose only sources are the dynamic plugin + a sink.
    let (sink, captured) = CapturingSink::new();

    let mut config = HostConfig::new("dyn-itest-agent");
    // Unique per-process+sequence data dir so concurrent test binaries do not
    // collide on the per-plugin `data_dir/<plugin>` the host creates.
    static HOST_SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "aegis-dyn-itest-{}-{}",
        std::process::id(),
        HOST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    config.data_dir = std::env::temp_dir().join(unique);
    config.dynamic_plugins = vec![DynamicPluginSpec {
        // Must match the library's metadata name or the host rejects it.
        name: PLUGIN_NAME.to_string(),
        path: so_path.clone(),
    }];

    let host = HostBuilder::new(config)
        .discover_static(false) // hermetic: only the dynamic plugin + sink
        .with_plugin(Box::new(sink))
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "host failed to build / dlopen example-plugin at {}: {e:#}",
                so_path.display()
            )
        });

    // 3. Loading succeeded: both C-ABI symbols resolved, the ABI version matched,
    //    the constructor was adopted, and the metadata name matched the spec.
    assert!(
        host.plugin_names().contains(&PLUGIN_NAME),
        "dynamically-loaded plugin {PLUGIN_NAME:?} not present; loaded = {:?}",
        host.plugin_names()
    );

    // 4. Run the host: `run` awaits the plugin's `init`, which emits the marker
    //    event onto the real bus; the dispatcher fans it to the CapturingSink.
    let running = host.run().await.expect("host runs");

    let saw_marker = wait_for(&captured, Duration::from_secs(10), |evs| {
        evs.iter().any(is_marker_event)
    })
    .await;

    // Drain all tasks so in-flight hops are flushed before the final asserts.
    running.shutdown().await.expect("clean shutdown");
    let events = captured.lock().unwrap().clone();

    assert!(
        saw_marker,
        "the dynamically-loaded plugin's marker event never reached the sink; \
         captured {} event(s): kinds={:?}",
        events.len(),
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
    );

    // Precise check on the captured marker event: it is a Custom payload carrying
    // both the marker string and the api_version the plugin stamped, and the host
    // stamped `source`/`agent_id` (proving it flowed through the host, not a raw
    // emitter call).
    let marker = events
        .iter()
        .find(|e| is_marker_event(e))
        .expect("marker event present");
    assert_eq!(marker.source, PLUGIN_NAME, "source must be host-stamped");
    assert_eq!(
        marker.agent_id, "dyn-itest-agent",
        "agent_id must be host-pinned"
    );
    match &marker.payload {
        EventPayload::Custom(v) => {
            assert_eq!(
                v.get("api_version").and_then(|x| x.as_u64()),
                Some(u64::from(aegis_sdk::PLUGIN_API_VERSION)),
                "plugin should report the host ABI version it was built against"
            );
        }
        other => panic!("marker payload should be Custom, got {other:?}"),
    }
}
