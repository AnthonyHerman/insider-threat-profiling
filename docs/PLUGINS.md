# Writing Aegis plugins

Aegis has a deliberately tiny core. The kernel (`aegis-core`) only loads
plugins, routes [`Event`](../crates/aegis-sdk/src/event.rs)s between them, and
manages their lifecycle. **Every feature** — telemetry collection,
agent-vs-human detection, risk scoring, persistence, transport, even endpoint
self-protection — is a [`Plugin`](../crates/aegis-sdk/src/plugin.rs). Adding a
capability never requires touching the core.

This guide explains the event model, the plugin contract, the two ways a plugin
is discovered (static and dynamic), how configuration and provenance work, and
ends with a worked walkthrough for a new collector and a new processor. Every
type and function named here is real; follow the source links to confirm.

All the plugin-facing types live in the `aegis-sdk` crate. Add it as a
dependency and import what you need:

```toml
[dependencies]
aegis-sdk = { workspace = true }
async-trait = { workspace = true }
anyhow = { workspace = true }
```

## The event model

Everything on the bus is an [`Event`](../crates/aegis-sdk/src/event.rs):

```rust
pub struct Event {
    pub id: Uuid,
    pub ts_ns: u64,                       // producer time, ns since Unix epoch
    pub agent_id: AgentId,                // = String; the enrolled endpoint
    pub source: String,                   // producing plugin name (or "host")
    pub kind: String,                     // routing topic, e.g. "command.observed"
    pub payload: EventPayload,
    pub labels: BTreeMap<String, String>, // optional free-form tags
}
```

You rarely build one field-by-field. Use the constructor, which derives `kind`
from the payload and stamps `ts_ns` and a fresh `id`:

```rust
let ev = Event::new(&ctx.agent_id, "my-plugin", payload)
    .with_label("zone", "lab");   // builder-style; also `.with_kind(..)`
```

> **Provenance note:** the `agent_id` and `source` you pass to `Event::new` are
> *advisory*. When a plugin emits through its `PluginContext`, the host
> overwrites both — see [ScopedEmitter](#provenance-the-scopedemitter-guarantee).
> Pass your real plugin name anyway for clarity and for direct unit tests.

### `EventPayload` kinds

[`EventPayload`](../crates/aegis-sdk/src/event.rs) is a tagged enum
(`#[serde(tag = "type")]`). Each variant has a canonical routing `kind` returned
by `EventPayload::default_kind()`; that string is what subscriptions match on.

| Variant            | `kind` (topic)      | Carries                                                                                          |
| ------------------ | ------------------- | ------------------------------------------------------------------------------------------------ |
| `ProcessExec`      | `process.exec`      | `pid`, `ppid`, `uid`, `exe`, `cmdline`, `cwd`                                                     |
| `SessionStart`     | `session.start`     | `session_id`, `tty`, `user`, `remote`                                                            |
| `SessionEnd`       | `session.end`       | `session_id`                                                                                      |
| `Keystroke`        | `input.keystroke`   | `session_id`, `inter_arrival_ns`, `is_paste`, `burst_len` — **timing only, no content**          |
| `CommandObserved`  | `command.observed`  | `session_id`, `command_len`, `token_count`, `shannon_entropy`, `had_backspace`, `edit_distance_prev`, `inter_command_ns`, `command_hash` — **structural summary + salted hash, no text** |
| `Score`            | `score`             | `subject`, `model`, `score`, `features: BTreeMap<String, f64>`                                   |
| `Detection`        | `detection`         | `subject`, `verdict: Verdict`, `confidence`, `model`, `reasons`, `features`                      |
| `Alert`            | `alert`             | `severity: Severity`, `title`, `detail`, `subject`                                               |
| `Heartbeat`        | `heartbeat`         | `uptime_s`                                                                                        |
| `Custom(Value)`    | `custom`            | arbitrary `serde_json::Value` — the escape hatch for new event types                             |

Supporting enums: [`Verdict`](../crates/aegis-sdk/src/event.rs) is
`Human`/`Agent`/`Uncertain` (the core human-vs-agent question), and
[`Severity`](../crates/aegis-sdk/src/event.rs) is the ordered ladder
`Info < Low < Medium < High < Critical`.

**Privacy is a hard constraint, not a default.** Content-free telemetry is a
design invariant of this project (see `CONTRIBUTING.md`): never put typed
characters, raw command text, file contents, etc. into a payload, label, or log.
`Keystroke` is timing-only; `CommandObserved` is statistics plus a salted hash.
If you need a new event shape, prefer extending the typed enum in `aegis-sdk`
(and bumping `PLUGIN_API_VERSION` if it is breaking) over smuggling content
through `Custom`.

## The `Plugin` trait

A plugin is anything implementing [`Plugin`](../crates/aegis-sdk/src/plugin.rs).
It is `Send + Sync`, and `handle` is invoked concurrently, so keep mutable state
behind interior mutability (`tokio::sync::Mutex`, `DashMap`, atomics, …). `init`
is the one `&mut self` call, made once before the plugin is shared.

```rust
#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;                 // required
    fn subscriptions(&self) -> Subscriptions { Subscriptions::None }
    async fn init(&mut self, _ctx: &PluginContext) -> anyhow::Result<()> { Ok(()) }
    async fn handle(&self, _event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> { Ok(()) }
    async fn shutdown(&self) -> anyhow::Result<()> { Ok(()) }
}
```

- **`metadata`** — cheap, side-effect-free identity via
  [`PluginMetadata::new(name, version, description, kind)`](../crates/aegis-sdk/src/plugin.rs).
  It stamps the current `PLUGIN_API_VERSION` for you. The `name` is significant:
  it is the enable/disable key, the per-plugin data-dir and config-subtree key,
  and (for dynamic plugins) is asserted against the declared name at load. Use a
  stable, unique string and `env!("CARGO_PKG_VERSION")` for the version.
- **`subscriptions`** — which event kinds get delivered to `handle`. See below.
- **`init`** — one-time setup. Collectors typically spawn a long-running
  producer task here using `ctx.emitter`. Returning `Err` (or panicking) makes
  the host log and **skip** this one plugin; it does not abort the others.
- **`handle`** — called for each subscribed event. Returning `Err` is logged and
  does not tear anything down.
- **`shutdown`** — graceful teardown on host stop.

### `PluginKind`

[`PluginKind`](../crates/aegis-sdk/src/plugin.rs) declares a plugin's broad role
(used for ordering and operator display):

- `Collector` — produces raw telemetry (process exec, keystroke timing,
  sessions). Usually subscribes to nothing and only emits.
- `Processor` — consumes events and derives higher-level signals (detection,
  scoring).
- `Sink` — persists, forwards, or alerts (storage, transport, notify).
- `Control` — controls the endpoint/host itself (self-protection, lifecycle).

### Subscriptions

[`Subscriptions`](../crates/aegis-sdk/src/plugin.rs) controls routing:

```rust
fn subscriptions(&self) -> Subscriptions {
    Subscriptions::None                                   // pure emitter
    // Subscriptions::All                                 // every event
    // Subscriptions::kinds(["detection", "process.exec", "session.end"])
}
```

`Subscriptions::kinds(..)` takes any iterator of `Into<String>` and builds the
match set; `Subscriptions::matches(kind)` is what the dispatcher calls. Match on
the `kind` strings from the table above (`"detection"`, `"process.exec"`, …),
**not** on Rust variant names.

## `PluginContext` and typed config

Every `init`/`handle` call receives a
[`PluginContext`](../crates/aegis-sdk/src/plugin.rs):

```rust
pub struct PluginContext {
    pub agent_id: String,          // the enrolled endpoint identity
    pub data_dir: PathBuf,         // private, persistent dir: <root>/<plugin-name>
    pub config: serde_json::Value, // this plugin's config subtree (JSON null if unset)
    pub emitter: Arc<dyn Emitter>, // publish events back onto the bus
}
```

The host creates `data_dir` for you before `init` (a per-plugin subdirectory of
the configured root). Use it for any on-disk state.

**Typed config via `config_as`.** Define a `serde` config struct with a `Default`
impl, then deserialize the subtree. `config_as` returns `T::default()` when no
config was provided (the subtree is JSON `null`), and otherwise parses
`self.config`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyConfig { pub interval_ms: u64 }
impl Default for MyConfig { fn default() -> Self { Self { interval_ms: 2000 } } }

async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
    let cfg: MyConfig = ctx.config_as()?;   // T::default() if no [plugins."..."] block
    // validate eagerly and bail! on bad values — see plugin-scoring's decay check
    Ok(())
}
```

Operators populate the subtree in the host config file under
`plugins.<plugin-name>` (the per-plugin map keyed by name in
[`HostConfig`](../crates/aegis-core/src/config.rs)). Validate aggressively in
`init`: `plugin-scoring` rejects an out-of-range `decay` with `anyhow::bail!`,
which cleanly skips just that plugin.

### Emitting events

Emit through the context, from `handle` or from a task you spawned in `init`:

```rust
ctx.emit(Event::new(&ctx.agent_id, "my-plugin", payload)).await;  // convenience
// or hold the handle for a background task:
let emitter = ctx.emitter.clone();
emitter.emit(Event::new(&agent_id, "my-plugin", payload)).await;
```

[`Emitter`](../crates/aegis-sdk/src/plugin.rs) is a cloneable
`async fn emit(&self, Event)` handle. The bus is bounded: low-value telemetry is
dropped (and *counted*) under back-pressure, while security-critical kinds —
`alert`, `detection`, `score` — get a non-droppable path so a flood of cheap
telemetry cannot evict them. You do not opt into this; it is keyed off the
event's `kind`.

## Provenance: the `ScopedEmitter` guarantee

The `emitter` in your `PluginContext` is **not** the raw bus handle. The host
wraps it in a [`ScopedEmitter`](../crates/aegis-core/src/bus.rs) that, on every
`emit`, **overwrites** the event's `source` with your registered plugin name and
its `agent_id` with the host's configured identity, before forwarding to the
shared bus:

```rust
// aegis-core/src/bus.rs
async fn emit(&self, mut event: Event) {
    event.source = self.source.clone();      // host-asserted plugin name
    event.agent_id = self.agent_id.clone();  // host-asserted endpoint id
    self.inner.emit(event).await;
}
```

So a plugin **cannot** spoof another plugin's `source`, claim to be `"host"`, or
forge an `agent_id` — whatever you set on the event is replaced. This is a
deliberate in-process attribution guarantee. Two practical consequences:

- Downstream processors/sinks can trust `event.source` to identify the producer.
- In unit tests you construct `PluginContext` directly with your own `Emitter`,
  so there the values you pass *do* stick — that is expected and is how the
  `plugin-scoring` and `bus` tests assert provenance.

## How plugins are discovered

The two registration paths converge on the same `Plugin` trait; the host
([`HostBuilder`](../crates/aegis-core/src/host.rs)) resolves all sources, applies
the config enable/disable policy, and de-duplicates by name. Precedence is:
**explicit** (`HostBuilder::with_plugin`, e.g. tests/embedding) > **dynamic**
(shared objects) > **static** (`inventory`). A name already loaded by a
higher-precedence source is skipped.

### Path 1 — STATIC (built-in, via `inventory`)

A built-in plugin crate calls the
[`register_plugin!`](../crates/aegis-sdk/src/plugin.rs) macro at module scope.
That submits a `PluginRegistration` (stamped with `PLUGIN_API_VERSION`) into the
`inventory` registry, and the host enumerates them at startup
(`inventory::iter::<PluginRegistration>`).

```rust
register_plugin!("plugin-scoring", || Box::new(ScoringPlugin::default()));
```

The macro takes the registered `name` and a `PluginConstructor`
(`fn() -> Box<dyn Plugin>`). The plugin becomes discoverable **simply by being
linked into the binary** — typically as a path dependency of `aegis-agent`/
`aegis-server`. At startup the host:

1. skips any registration whose `api_version != PLUGIN_API_VERSION` (logged),
2. skips disabled or already-loaded names, and
3. calls the constructor inside `catch_unwind` so a panicking constructor skips
   just that plugin.

`plugin-scoring`, `plugin-process`, `plugin-session`, etc. all use this path.

### Path 2 — DYNAMIC (third-party, via the C-ABI `cdylib`)

A dynamic plugin is a standalone shared object (`cdylib`) loaded at runtime — it
is **not** linked into any host binary and does **not** use `register_plugin!`.
The reference implementation is
[`crates/example-plugin/src/lib.rs`](../crates/example-plugin/src/lib.rs).

**Crate setup.** Build a C-ABI shared object:

```toml
# example-plugin/Cargo.toml
[lib]
crate-type = ["cdylib"]
```

**The two exported symbols.** The loader resolves exactly two C symbols. Their
names must equal `aegis_sdk::DYN_ENTRY_SYMBOL` (`b"aegis_plugin_entry"`) and
`aegis_sdk::DYN_FREE_SYMBOL` (`b"aegis_plugin_free_registration"`). From the
worked example:

```rust
#[no_mangle]
pub extern "C" fn aegis_plugin_entry() -> *mut aegis_sdk::DynPluginRegistration {
    Box::into_raw(Box::new(aegis_sdk::DynPluginRegistration {
        api_version: aegis_sdk::PLUGIN_API_VERSION,   // stamp the host-expected version
        constructor: || Box::new(ExamplePlugin),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn aegis_plugin_free_registration(
    reg: *mut aegis_sdk::DynPluginRegistration,
) {
    if !reg.is_null() {
        drop(Box::from_raw(reg));   // freed in *this* cdylib's allocator
    }
}
```

**Why the paired free function exists (the allocator boundary).**
[`DynPluginRegistration`](../crates/aegis-sdk/src/plugin.rs) is `#[repr(C)]` with
two `Copy` fields (`api_version`, `constructor`). The entrypoint heap-allocates
it with `Box::into_raw`. A `cdylib` may be linked against a different global
allocator than the host, so the host must **not** free that box itself. Instead
[`load_dynamic`](../crates/aegis-core/src/loader.rs) copies the `Copy` fields out
through the raw pointer and hands the pointer back to your
`aegis_plugin_free_registration`, so the allocation is released by the allocator
that produced it. Your free function must tolerate a null pointer (it is called
exactly once with the entrypoint's return value).

**The `api_version` handshake.** The exported entrypoint stamps
`PLUGIN_API_VERSION`; after copying it out, the loader compares it to the host's
`PLUGIN_API_VERSION` and **rejects** a mismatch with an error. This is the only
ABI compatibility gate. It catches gross mismatches but cannot make loading
untrusted native code safe — your `.so` must be built against a compatible
`aegis-sdk` with the same Rust toolchain, and operators should load only from
trusted, integrity-checked paths.

**Is-enabled-before-load.** Operators declare a dynamic plugin in the host
config as a [`DynamicPluginSpec`](../crates/aegis-core/src/config.rs) — a `name`
plus a filesystem `path`:

```toml
[[dynamic_plugins]]
name = "example-plugin"
path = "/opt/aegis/plugins/libexample_plugin.so"
```

Loading a shared object *executes code* (its entrypoint runs), so the host
evaluates enablement from the **declared `name` before the library is ever
opened**: a disabled-but-listed path is never `dlopen`ed. (The
`disabled_dynamic_plugin_is_not_opened` test in `host.rs` pins this by pointing a
*disabled* spec at a nonexistent path and asserting `build` still succeeds.)
After load, the host asserts the library-reported
`metadata().name` equals the declared `name` and **rejects a mismatch** — so a
swapped `.so` cannot impersonate an enabled plugin name. The matched
`PLUGIN_NAME` constant in the example exists for exactly this reason. The
`libloading::Library` handle is kept mapped for the program's lifetime (the
plugin's code and vtable live inside it).

Build it with `cargo build -p example-plugin`; the artifact is
`target/<profile>/libexample_plugin.so`.

## What the host does at runtime

[`Host::run`](../crates/aegis-core/src/host.rs) turns the loaded set into a
[`RunningHost`](../crates/aegis-core/src/host.rs). For each plugin it: creates
the per-plugin `data_dir`; builds a `PluginContext` whose `emitter` is the
provenance-stamping `ScopedEmitter` and whose `config` is `plugin_config(name)`;
calls `init` (isolated by `catch_unwind` — a failing/panicking `init` skips that
plugin only); reads its `subscriptions`; and spawns a dedicated task draining a
**bounded per-plugin queue** into `handle`. A central dispatcher fans each
ingress event out to every plugin whose subscriptions match, so a slow plugin
back-pressures only itself. `RunningHost::shutdown` signals the tasks, awaits
them, then calls each plugin's `shutdown`.

## Worked walkthrough

### A new collector

A `Collector` subscribes to nothing and emits on its own schedule from a task
spawned in `init` — the pattern used by `plugin-process`:

```rust
use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind,
    PluginMetadata, Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig { pub interval_ms: u64 }
impl Default for HeartbeatConfig { fn default() -> Self { Self { interval_ms: 5000 } } }

#[derive(Default)]
pub struct HeartbeatCollector;

#[async_trait]
impl Plugin for HeartbeatCollector {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-heartbeat",
            env!("CARGO_PKG_VERSION"),
            "Periodic endpoint liveness collector",
            PluginKind::Collector,
        )
    }

    fn subscriptions(&self) -> Subscriptions { Subscriptions::None }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        let cfg: HeartbeatConfig = ctx.config_as()?;
        // Clone what the task needs out of the (borrowed) context.
        let emitter = ctx.emitter.clone();
        let agent_id = ctx.agent_id.clone();
        let started = std::time::Instant::now();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                Duration::from_millis(cfg.interval_ms.max(200)),
            );
            loop {
                ticker.tick().await;
                emitter.emit(Event::new(
                    &agent_id,
                    "plugin-heartbeat",
                    EventPayload::Heartbeat { uptime_s: started.elapsed().as_secs() },
                )).await;
            }
        });
        Ok(())
    }
}

register_plugin!("plugin-heartbeat", || Box::new(HeartbeatCollector::default()));
```

Notes: `init` takes `&PluginContext` by reference, so clone `emitter`/`agent_id`
into the `'static` task; the `ScopedEmitter` still stamps `source`/`agent_id` on
every emit. To ship this as a built-in, add the crate as a path dependency of
the host binary. To ship it as a third-party `.so` instead, drop the
`register_plugin!` line, set `crate-type = ["cdylib"]`, and add the two C-ABI
exports from the dynamic section above.

### A new processor

A `Processor` subscribes to upstream kinds and emits derived events from
`handle` (the `plugin-scoring` shape). Hold state behind a `Mutex` because
`handle` runs concurrently:

```rust
use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind,
    PluginMetadata, Severity, Subscriptions, Verdict,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct AgentAlerter { agent_hits: Arc<Mutex<u32>> }

#[async_trait]
impl Plugin for AgentAlerter {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-agent-alerter",
            env!("CARGO_PKG_VERSION"),
            "Raises an alert after repeated high-confidence agent verdicts",
            PluginKind::Processor,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::kinds(["detection"])   // match on the kind string
    }

    async fn handle(&self, event: &Event, ctx: &PluginContext) -> anyhow::Result<()> {
        if let EventPayload::Detection { subject, verdict: Verdict::Agent, confidence, .. }
            = &event.payload
        {
            if *confidence < 0.9 { return Ok(()); }
            let mut hits = self.agent_hits.lock().await;
            *hits += 1;
            if *hits >= 3 {
                ctx.emit(Event::new(
                    &ctx.agent_id,
                    "plugin-agent-alerter",
                    EventPayload::Alert {
                        severity: Severity::High,
                        title: "Repeated agent detections".into(),
                        detail: format!("{subject} flagged as agent {} times", *hits),
                        subject: Some(subject.clone()),
                    },
                )).await;
            }
        }
        Ok(())
    }
}

register_plugin!("plugin-agent-alerter", || Box::new(AgentAlerter::default()));
```

The emitted `alert` (and any `detection`/`score` you produce) rides the bus's
non-droppable critical path automatically.

### Testing

Construct `PluginContext` directly with a capturing `Emitter` and call
`handle`/`init` — no host required. The `plugin-scoring` tests are a complete
template: a small `CapturingEmitter` collecting emitted events, a `test_ctx`
helper, and deterministic assertions over pure state. For end-to-end coverage
(especially dynamic loading), add an integration test under
`crates/aegis-integration-tests`; the existing one boots a real host and asserts
the dynamically loaded `example-plugin`'s marker event traverses the real
dispatcher to a sink.

## Reference

- Event model: [`crates/aegis-sdk/src/event.rs`](../crates/aegis-sdk/src/event.rs)
- Plugin contract + dynamic ABI types:
  [`crates/aegis-sdk/src/plugin.rs`](../crates/aegis-sdk/src/plugin.rs)
- Dynamic loader (handshake, allocator boundary):
  [`crates/aegis-core/src/loader.rs`](../crates/aegis-core/src/loader.rs)
- Host lifecycle + discovery precedence:
  [`crates/aegis-core/src/host.rs`](../crates/aegis-core/src/host.rs)
- Bus, critical kinds, `ScopedEmitter`:
  [`crates/aegis-core/src/bus.rs`](../crates/aegis-core/src/bus.rs)
- Config (`HostConfig`, `DynamicPluginSpec`, enable/disable):
  [`crates/aegis-core/src/config.rs`](../crates/aegis-core/src/config.rs)
- Worked dynamic plugin:
  [`crates/example-plugin/src/lib.rs`](../crates/example-plugin/src/lib.rs)
- Worked static processor:
  [`plugins/plugin-scoring/src/lib.rs`](../plugins/plugin-scoring/src/lib.rs)
