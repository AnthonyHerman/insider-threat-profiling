//! Example third-party Aegis plugin, shipped as a runtime-loaded `cdylib`.
//!
//! This crate demonstrates the *dynamic* plugin path end to end. Unlike the
//! built-in plugins, it is **not** linked into any host binary and does **not**
//! register itself via [`aegis_sdk::register_plugin!`]/`inventory`. It is a
//! standalone shared object (`libexample_plugin.so`) that a host discovers
//! purely at runtime by `dlopen`-ing it and resolving a stable C-ABI entrypoint
//! (`aegis_plugin_entry`) plus the paired free function
//! (`aegis_plugin_free_registration`).
//!
//! The contract is documented on [`aegis_sdk::DynEntry`] / [`aegis_sdk::DynFree`]
//! and consumed by `aegis_core::load_dynamic`:
//!
//! * `aegis_plugin_entry` heap-allocates a [`aegis_sdk::DynPluginRegistration`]
//!   (stamping the host-expected [`aegis_sdk::PLUGIN_API_VERSION`]) and hands the
//!   host a raw pointer via `Box::into_raw`.
//! * The host copies the `Copy` fields (`api_version`, `constructor`) out through
//!   that pointer and then returns the pointer to `aegis_plugin_free_registration`
//!   so the allocation is released **in this plugin's own allocator** — never via
//!   `Box::from_raw` on the host side, which could free across mismatched
//!   allocators.

use aegis_sdk::{
    Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions,
};
use async_trait::async_trait;

/// The plugin's registered name. Must match the `name` in the host's
/// [`DynamicPluginSpec`](aegis_sdk) declaration: the host asserts the
/// library-reported metadata name equals the declared name and rejects a
/// mismatch (so a swapped `.so` cannot impersonate an enabled plugin name).
const PLUGIN_NAME: &str = "example-plugin";

/// The distinctive marker the integration test matches on to prove that *this*
/// dynamically-loaded plugin's code actually ran (its event traversed the real
/// dispatcher to the capturing sink), not merely that the library was opened.
pub const LOADED_MARKER: &str = "example-plugin-loaded-dynamically";

/// A trivial collector plugin: it emits a single distinctive [`EventPayload::Custom`]
/// event during [`Plugin::init`] and subscribes to nothing.
#[derive(Default)]
pub struct ExamplePlugin;

#[async_trait]
impl Plugin for ExamplePlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            PLUGIN_NAME,
            env!("CARGO_PKG_VERSION"),
            "Example third-party plugin loaded at runtime from a cdylib.",
            PluginKind::Collector,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        // A pure collector: it only emits, it consumes nothing.
        Subscriptions::None
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        // Emit synchronously here rather than from a spawned task: the host
        // awaits `init` before it starts dispatching, so emitting inline makes
        // the marker event deterministically observable without relying on task
        // scheduling. The host's per-plugin `ScopedEmitter` stamps `source` with
        // this plugin's name and pins `agent_id`, so the test can assert both.
        ctx.emit(Event::new(
            &ctx.agent_id,
            PLUGIN_NAME,
            EventPayload::Custom(serde_json::json!({
                "marker": LOADED_MARKER,
                "api_version": aegis_sdk::PLUGIN_API_VERSION,
            })),
        ))
        .await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// C-ABI exports: the only surface a host uses to discover this plugin at runtime.
// Symbol names must equal `aegis_sdk::DYN_ENTRY_SYMBOL` / `DYN_FREE_SYMBOL`.
// ---------------------------------------------------------------------------

/// Runtime entrypoint resolved by `aegis_core::load_dynamic` under the symbol
/// `aegis_plugin_entry`. Returns a heap [`aegis_sdk::DynPluginRegistration`] the
/// host adopts. The host copies the `Copy` fields out and then frees the pointer
/// via [`aegis_plugin_free_registration`].
///
/// # Safety
/// This is an `extern "C"` boundary. It must not unwind across it (it does not:
/// `Box::new`/`Box::into_raw` do not panic here), and the returned pointer is
/// only ever passed back to [`aegis_plugin_free_registration`].
#[no_mangle]
pub extern "C" fn aegis_plugin_entry() -> *mut aegis_sdk::DynPluginRegistration {
    Box::into_raw(Box::new(aegis_sdk::DynPluginRegistration {
        api_version: aegis_sdk::PLUGIN_API_VERSION,
        constructor: || Box::new(ExamplePlugin),
    }))
}

/// Paired free function resolved by `aegis_core::load_dynamic` under the symbol
/// `aegis_plugin_free_registration`. The host hands back the exact pointer
/// returned by [`aegis_plugin_entry`] so the [`aegis_sdk::DynPluginRegistration`]
/// is released by the allocator that produced it.
///
/// # Safety
/// `reg` must be either null or a pointer previously returned by
/// [`aegis_plugin_entry`] and not yet freed. Both conditions hold for the host
/// loader, which calls this exactly once with that pointer.
#[no_mangle]
pub unsafe extern "C" fn aegis_plugin_free_registration(
    reg: *mut aegis_sdk::DynPluginRegistration,
) {
    if !reg.is_null() {
        // Reclaim the Box in this cdylib's own allocator and drop it.
        drop(Box::from_raw(reg));
    }
}
