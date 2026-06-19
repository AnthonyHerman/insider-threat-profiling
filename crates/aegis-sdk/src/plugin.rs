//! The plugin contract.
//!
//! Aegis has a deliberately tiny core: the kernel knows how to load plugins,
//! route [`Event`]s between them, and manage their lifecycle. **Every feature**
//! — telemetry collection, agent-vs-human detection, risk scoring, persistence,
//! transport, and even endpoint self-protection — is a [`Plugin`]. Adding a
//! capability never requires touching the core.
//!
//! Plugins are discovered two ways:
//!
//! 1. **Statically**, via [`inventory`]: a built-in plugin crate calls
//!    [`register_plugin!`] and is auto-discovered simply by being linked in.
//! 2. **Dynamically**, via a C-ABI entrypoint loaded at runtime (see the
//!    `aegis-core` dynamic loader). Both paths converge on the same trait.

use crate::event::Event;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

/// The ABI/contract version. Dynamic plugins must match the host's value or be
/// rejected at load time. Bump on any breaking change to this module.
pub const PLUGIN_API_VERSION: u32 = 1;

/// Broad role of a plugin, used for ordering and operator display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginKind {
    /// Produces raw telemetry (process exec, keystroke timing, sessions).
    Collector,
    /// Consumes events and derives higher-level signals (detection, scoring).
    Processor,
    /// Persists, forwards, or alerts on events (storage, transport, notify).
    Sink,
    /// Controls the endpoint/host itself (self-protection, lifecycle).
    Control,
}

/// Static description of a plugin instance.
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub kind: PluginKind,
    pub api_version: u32,
}

impl PluginMetadata {
    pub fn new(
        name: &'static str,
        version: &'static str,
        description: &'static str,
        kind: PluginKind,
    ) -> Self {
        PluginMetadata {
            name,
            version,
            description,
            kind,
            api_version: PLUGIN_API_VERSION,
        }
    }
}

/// Which event topics a plugin wants delivered to [`Plugin::handle`].
#[derive(Debug, Clone)]
pub enum Subscriptions {
    /// Receive every event on the bus.
    All,
    /// Receive nothing (pure collector that only emits).
    None,
    /// Receive only events whose `kind` is in this set.
    Kinds(HashSet<String>),
}

impl Subscriptions {
    /// Subscribe to an explicit list of kinds.
    pub fn kinds<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Subscriptions::Kinds(iter.into_iter().map(Into::into).collect())
    }

    /// Does this subscription want an event of the given `kind`?
    pub fn matches(&self, kind: &str) -> bool {
        match self {
            Subscriptions::All => true,
            Subscriptions::None => false,
            Subscriptions::Kinds(set) => set.contains(kind),
        }
    }
}

/// A cloneable handle a plugin uses to publish events back onto the bus.
/// Collectors typically hold one (from [`PluginContext`]) and emit on their own
/// schedule from a spawned task.
#[async_trait]
pub trait Emitter: Send + Sync {
    async fn emit(&self, event: Event);
}

/// Per-plugin runtime context handed to [`Plugin::init`] and [`Plugin::handle`].
pub struct PluginContext {
    /// The enrolled identity of this endpoint/host.
    pub agent_id: String,
    /// A private, persistent directory this plugin may use for state.
    pub data_dir: PathBuf,
    /// This plugin's configuration subtree (from the host config file).
    pub config: serde_json::Value,
    /// Handle for publishing events.
    pub emitter: Arc<dyn Emitter>,
}

impl PluginContext {
    /// Deserialize this plugin's config subtree into a typed struct, falling
    /// back to `T::default()` when no config was provided.
    pub fn config_as<T: DeserializeOwned + Default>(&self) -> anyhow::Result<T> {
        if self.config.is_null() {
            return Ok(T::default());
        }
        Ok(serde_json::from_value(self.config.clone())?)
    }

    /// Convenience for emitting from inside `handle`.
    pub async fn emit(&self, event: Event) {
        self.emitter.emit(event).await;
    }
}

/// The unit of functionality in Aegis.
///
/// Implementors are `Send + Sync`; `handle` is invoked concurrently, so plugins
/// hold mutable state behind interior mutability (e.g. `Mutex`/`DashMap`).
/// `init` receives `&mut self` once, before the plugin is shared.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Static identity/description. Must be cheap and side-effect free.
    fn metadata(&self) -> PluginMetadata;

    /// Which event kinds should be delivered to [`Plugin::handle`].
    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::None
    }

    /// One-time setup. Collectors usually spawn their producer task here using
    /// `ctx.emitter`. Default: no-op.
    async fn init(&mut self, _ctx: &PluginContext) -> anyhow::Result<()> {
        Ok(())
    }

    /// Handle a subscribed event. Default: no-op.
    async fn handle(&self, _event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        Ok(())
    }

    /// Graceful teardown. Default: no-op.
    async fn shutdown(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Constructor function for a plugin (used by both static and dynamic loaders).
pub type PluginConstructor = fn() -> Box<dyn Plugin>;

/// A registration record collected at link time via [`inventory`]. Built-in
/// plugins submit one of these; the host enumerates them at startup.
pub struct PluginRegistration {
    pub api_version: u32,
    pub name: &'static str,
    pub constructor: PluginConstructor,
}

inventory::collect!(PluginRegistration);

/// Register a built-in plugin so the host auto-discovers it when linked.
///
/// ```ignore
/// aegis_sdk::register_plugin!("plugin-process", || Box::new(ProcessPlugin::default()));
/// ```
#[macro_export]
macro_rules! register_plugin {
    ($name:expr, $ctor:expr) => {
        $crate::inventory::submit! {
            $crate::PluginRegistration {
                api_version: $crate::PLUGIN_API_VERSION,
                name: $name,
                constructor: $ctor,
            }
        }
    };
}

/// Signature of the C-ABI entrypoint a dynamic plugin `cdylib` must export as
/// `aegis_plugin_entry`. It returns a heap registration the host adopts. The
/// host checks `api_version` before calling the constructor.
///
/// A plugin **must export a matching free function** (see [`DynFree`]) so the
/// registration it heap-allocates is freed *in the plugin's own allocator*. The
/// host never calls `Box::from_raw` on this pointer: a `cdylib` may be linked
/// against a different global allocator than the host, and freeing host-side
/// memory the plugin allocated (or vice-versa) is undefined behavior. The host
/// copies the (`Copy`) fields out through the raw pointer and then hands the
/// pointer back to the plugin's free function.
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn aegis_plugin_entry() -> *mut aegis_sdk::DynPluginRegistration {
///     Box::into_raw(Box::new(aegis_sdk::DynPluginRegistration {
///         api_version: aegis_sdk::PLUGIN_API_VERSION,
///         constructor: || Box::new(MyPlugin::default()),
///     }))
/// }
///
/// #[no_mangle]
/// pub unsafe extern "C" fn aegis_plugin_free_registration(
///     reg: *mut aegis_sdk::DynPluginRegistration,
/// ) {
///     if !reg.is_null() {
///         drop(Box::from_raw(reg)); // freed in the plugin's allocator
///     }
/// }
/// ```
pub type DynEntry = unsafe extern "C" fn() -> *mut DynPluginRegistration;

/// Name of the exported symbol the dynamic loader looks up.
pub const DYN_ENTRY_SYMBOL: &[u8] = b"aegis_plugin_entry";

/// Signature of the paired C-ABI free function a dynamic plugin `cdylib` must
/// export as `aegis_plugin_free_registration`. The host calls it to release the
/// [`DynPluginRegistration`] the plugin returned from [`DynEntry`], so the
/// allocation is freed by the same allocator that produced it. The pointer is
/// the exact value returned by the entrypoint (possibly null, which the free
/// function must tolerate).
pub type DynFree = unsafe extern "C" fn(*mut DynPluginRegistration);

/// Name of the exported free-function symbol the dynamic loader looks up to
/// release a [`DynPluginRegistration`] in the plugin's own allocator.
pub const DYN_FREE_SYMBOL: &[u8] = b"aegis_plugin_free_registration";

/// Heap-allocated registration returned across the C ABI by dynamic plugins.
///
/// Both fields are `Copy`, so the host reads them out through the raw pointer
/// and then returns the pointer to the plugin's [`DynFree`] for deallocation —
/// it must never be dropped via `Box::from_raw` on the host side.
#[repr(C)]
pub struct DynPluginRegistration {
    pub api_version: u32,
    pub constructor: PluginConstructor,
}
