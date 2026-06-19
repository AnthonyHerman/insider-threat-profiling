//! Dynamic plugin loading via a stable C-ABI entrypoint.
//!
//! Built-in plugins are discovered statically through [`inventory`]; this module
//! adds *runtime* loading of `cdylib` plugins so the platform genuinely supports
//! third-party plugins shipped as separate shared objects. The host looks up the
//! [`aegis_sdk::DYN_ENTRY_SYMBOL`] symbol, validates the ABI version, and adopts
//! the returned constructor. The [`libloading::Library`] handle is kept alive by
//! the host for the program's lifetime (the plugin's vtable lives inside it).

use aegis_sdk::{
    DynEntry, DynFree, PluginConstructor, DYN_ENTRY_SYMBOL, DYN_FREE_SYMBOL, PLUGIN_API_VERSION,
};
use anyhow::{anyhow, bail, Context};
use std::path::Path;

/// A dynamically loaded plugin: the live library plus its constructor.
pub struct DynamicPlugin {
    /// Kept alive so the constructed plugin's code/vtable stays mapped.
    pub library: libloading::Library,
    pub constructor: PluginConstructor,
}

/// Load a dynamic plugin shared object.
///
/// # Safety
/// Loading arbitrary native code is inherently unsafe: the `.so` runs in-process
/// with full host privileges and must have been built against a compatible
/// `aegis-sdk` with the same Rust toolchain. The ABI-version handshake catches
/// gross mismatches but cannot make loading untrusted code safe. Operators
/// should only load plugins from trusted, integrity-checked paths.
///
/// ## Allocator boundary
/// The plugin heap-allocates the [`DynPluginRegistration`](aegis_sdk::DynPluginRegistration)
/// it returns. Because a `cdylib` may be linked against a different global
/// allocator than the host, the host must **not** free that allocation itself
/// (e.g. via `Box::from_raw`). Instead it copies the `Copy` fields out through
/// the raw pointer and hands the pointer back to the plugin's exported
/// [`aegis_sdk::DYN_FREE_SYMBOL`] function so the memory is released by its
/// owning allocator. The same-toolchain/same-ABI invariant still applies until
/// the boundary becomes fully opaque-handle-based.
pub fn load_dynamic(path: impl AsRef<Path>) -> anyhow::Result<DynamicPlugin> {
    let path = path.as_ref();
    // SAFETY: see the function-level contract above.
    unsafe {
        let library = libloading::Library::new(path)
            .with_context(|| format!("opening dynamic plugin {}", path.display()))?;

        let entry: libloading::Symbol<DynEntry> =
            library.get(DYN_ENTRY_SYMBOL).with_context(|| {
                format!(
                    "missing `{}` symbol in {}",
                    String::from_utf8_lossy(DYN_ENTRY_SYMBOL),
                    path.display()
                )
            })?;

        // The plugin must also export a paired free function so we can release
        // the registration in *its* allocator. Resolve it up front so we never
        // call the entrypoint without a way to free what it returns.
        let free: libloading::Symbol<DynFree> =
            library.get(DYN_FREE_SYMBOL).with_context(|| {
                format!(
                    "missing `{}` symbol in {}",
                    String::from_utf8_lossy(DYN_FREE_SYMBOL),
                    path.display()
                )
            })?;

        // An unwind across the `extern "C"` boundary is undefined behavior;
        // contain a panicking entrypoint and turn it into an error instead.
        let reg_ptr = std::panic::catch_unwind(|| entry()).map_err(|_| {
            anyhow!(
                "dynamic plugin {} panicked in its entrypoint",
                path.display()
            )
        })?;
        if reg_ptr.is_null() {
            bail!(
                "dynamic plugin {} returned a null registration",
                path.display()
            );
        }

        // Copy the `Copy` fields out through the raw pointer (do NOT take
        // ownership via Box::from_raw — that would free with the host
        // allocator). Then return the pointer to the plugin to free.
        let api_version = (*reg_ptr).api_version;
        let constructor: PluginConstructor = (*reg_ptr).constructor;
        free(reg_ptr);

        if api_version != PLUGIN_API_VERSION {
            bail!(
                "dynamic plugin {} has API version {} but host expects {}",
                path.display(),
                api_version,
                PLUGIN_API_VERSION
            );
        }

        Ok(DynamicPlugin {
            library,
            constructor,
        })
    }
}
