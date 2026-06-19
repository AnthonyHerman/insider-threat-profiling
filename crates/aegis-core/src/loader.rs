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

    // Pre-open integrity gate. A full cryptographic check (Ed25519/SHA-256 against
    // a pin in the immutable config) is the tracked hardening item (ADR #15 /
    // security-audit H5) and is *not* yet implemented. Until it lands we apply the
    // cheap, no-config defence the threat model calls for: refuse to `dlopen` a
    // shared object (or one in a directory) that is world-writable, and — when the
    // host runs as root — that is not owned by root. This blocks the
    // "drop a malicious `.so` in a writable path" escalation without weakening the
    // same-toolchain/same-ABI contract. Best-effort: a path we cannot stat falls
    // through to the open below so the canonical open error is preserved.
    check_load_path_safety(path)?;

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

/// Reject a dynamic-plugin path that an unprivileged or untrusted writer could
/// have controlled, *before* the library is opened (opening runs its code).
///
/// On Unix: the `.so` itself, and the directory containing it, must not be
/// world-writable; and when the host runs as root, both must be owned by root
/// (uid 0). A path that cannot be `stat`ed is left to the subsequent open so its
/// error is reported verbatim (this also keeps a "missing file" an open error,
/// not a permission error). On non-Unix this is a no-op.
fn check_load_path_safety(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `geteuid()` is always-safe (no args, no pointers, cannot fail).
        // We test the *effective* uid because that is the privilege the dlopen
        // would actually run with (matches plugin-tamper's `is_root`).
        let running_as_root = unsafe { libc::geteuid() } == 0;

        let check = |label: &str, p: &Path| -> anyhow::Result<()> {
            let meta = match std::fs::metadata(p) {
                Ok(m) => m,
                // Leave a missing/unreadable path to the open below.
                Err(_) => return Ok(()),
            };
            // World-writable is never acceptable: anyone could swap the code.
            if meta.mode() & 0o002 != 0 {
                bail!(
                    "refusing to load dynamic plugin: {label} {} is world-writable",
                    p.display()
                );
            }
            // Under root, a non-root owner means a less-privileged user could
            // have planted the code that root would then execute.
            if running_as_root && meta.uid() != 0 {
                bail!(
                    "refusing to load dynamic plugin: {label} {} is not owned by root (uid {})",
                    p.display(),
                    meta.uid()
                );
            }
            Ok(())
        };

        check("shared object", path)?;
        if let Some(parent) = path.parent() {
            // An empty parent ("" for a bare filename) means the current dir; skip
            // — relative loads are a dev convenience and `.` ownership is noisy.
            if !parent.as_os_str().is_empty() {
                check("containing directory", parent)?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A world-writable `.so` is rejected before any open is attempted.
    #[test]
    fn world_writable_so_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-loader-ww-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let so = dir.join("evil.so");
        std::fs::write(&so, b"not a real library").unwrap();
        // Make the file world-writable (but keep the dir tight).
        std::fs::set_permissions(&so, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = check_load_path_safety(&so)
            .expect_err("a world-writable .so must be refused before dlopen");
        assert!(
            err.to_string().contains("world-writable"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A non-world-writable `.so` in a tight directory passes the gate (the open
    /// then fails for an unrelated reason — it is not a real library — which is
    /// fine; the gate's job is only to *permit* a safe path).
    #[test]
    fn tight_perms_pass_the_gate() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-loader-ok-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let so = dir.join("plugin.so");
        std::fs::write(&so, b"stub").unwrap();
        std::fs::set_permissions(&so, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            check_load_path_safety(&so).is_ok(),
            "a 0644 file in a 0755 dir must pass the safety gate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing path is *not* a gate failure — it is deferred to the open so the
    /// canonical "opening dynamic plugin" error is what surfaces.
    #[test]
    fn missing_path_defers_to_open() {
        let p = Path::new("/nonexistent/aegis-loader-missing.so");
        assert!(
            check_load_path_safety(p).is_ok(),
            "a missing path must defer to the open, not fail the gate"
        );
    }
}
