//! Dynamic plugin loading via a stable C-ABI entrypoint.
//!
//! Built-in plugins are discovered statically through [`inventory`]; this module
//! adds *runtime* loading of `cdylib` plugins so the platform genuinely supports
//! third-party plugins shipped as separate shared objects. The host looks up the
//! [`aegis_sdk::DYN_ENTRY_SYMBOL`] symbol, validates the ABI version, and adopts
//! the returned constructor. The [`libloading::Library`] handle is kept alive by
//! the host for the program's lifetime (the plugin's vtable lives inside it).

use aegis_sdk::{
    DynEntry, DynPluginRegistration, PluginConstructor, DYN_ENTRY_SYMBOL, PLUGIN_API_VERSION,
};
use anyhow::{bail, Context};
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

        let reg_ptr = entry();
        if reg_ptr.is_null() {
            bail!(
                "dynamic plugin {} returned a null registration",
                path.display()
            );
        }
        let reg: Box<DynPluginRegistration> = Box::from_raw(reg_ptr);

        if reg.api_version != PLUGIN_API_VERSION {
            bail!(
                "dynamic plugin {} has API version {} but host expects {}",
                path.display(),
                reg.api_version,
                PLUGIN_API_VERSION
            );
        }

        Ok(DynamicPlugin {
            library,
            constructor: reg.constructor,
        })
    }
}
