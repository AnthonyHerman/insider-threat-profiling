//! Installer/uninstaller for the tamper-resistant deployment.
//!
//! This module *generates* the artifacts of a hardened install and exposes them
//! for the agent's `install`/`uninstall` subcommands. The strategy:
//!
//! 1. Copy the agent binary to a **root-owned** location.
//! 2. Install a **systemd service** with `Restart=always` plus a lightweight
//!    **guardian** unit; if either is killed, systemd (and the guardian) bring
//!    the pair back. Stopping the service requires root.
//! 3. Set the **immutable attribute** (`chattr +i`) on the binary and unit files
//!    so an unprivileged user cannot modify or delete them.
//! 4. Provide an **authenticated, root-only uninstall** so administrators retain
//!    control (clears the immutable bit, stops/*removes* units, deletes files).
//!
//! The unit-text generation and the path/decision logic are kept *pure* and
//! unit-tested; the privileged filesystem and `systemctl` mutations live in
//! [`install`]/[`uninstall`]/[`guard`], which return `Result` so a non-root
//! caller is handled gracefully and which are never executed at import/build or
//! by any test.

use crate::{immutable, manifest::Manifest};
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Parameters that shape the generated systemd units and the on-disk layout.
#[derive(Debug, Clone)]
pub struct InstallSpec {
    pub service_name: String,
    pub guardian_name: String,
    /// Absolute path the hardened binary will live at.
    pub install_path: String,
    /// Server URL the agent should report to.
    pub server_url: String,
    /// System user to run as (kept as root for stop-protection by default).
    pub run_as: String,
    /// Directory the systemd unit files are written to.
    pub unit_dir: String,
    /// Directory for agent state (the baseline manifest and uninstall token).
    pub state_dir: String,
}

impl Default for InstallSpec {
    fn default() -> Self {
        InstallSpec {
            service_name: "aegis-agent".into(),
            guardian_name: "aegis-guardian".into(),
            install_path: "/usr/local/sbin/aegis-agent".into(),
            server_url: "https://127.0.0.1:8443".into(),
            run_as: "root".into(),
            unit_dir: "/etc/systemd/system".into(),
            state_dir: "/var/lib/aegis".into(),
        }
    }
}

/// Render the primary agent service unit.
///
/// `Restart=always` with a short `RestartSec` makes a single `kill` ineffective;
/// the hardening notes in the unit document the additional protections applied at
/// install time (immutable files, guardian pairing).
pub fn render_service_unit(spec: &InstallSpec) -> String {
    format!(
        "[Unit]\n\
         Description=Aegis behavioral threat-monitoring agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         # The guardian restarts us if we are stopped; we bind to it.\n\
         Requires={guardian}.service\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={path} run --server {server}\n\
         Restart=always\n\
         RestartSec=1\n\
         User={user}\n\
         # Self-protection hardening:\n\
         OOMScoreAdjust=-900\n\
         # No privilege transition (defeats setuid/LD_PRELOAD escalation paths);\n\
         # root can still uninstall via the authenticated systemctl/chattr path.\n\
         NoNewPrivileges=yes\n\
         # Resist casual signals/kills via cgroup; root can still override.\n\
         KillMode=process\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        guardian = spec.guardian_name,
        path = spec.install_path,
        server = spec.server_url,
        user = spec.run_as,
    )
}

/// Render the guardian unit, which re-enables and restarts the agent if it is
/// disabled or stopped. The pair mutually depend, so killing one triggers
/// recovery of both.
pub fn render_guardian_unit(spec: &InstallSpec) -> String {
    format!(
        "[Unit]\n\
         Description=Aegis agent guardian (anti-tamper watchdog)\n\
         BindsTo={service}.service\n\
         After={service}.service\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={path} guard --service {service}\n\
         Restart=always\n\
         RestartSec=1\n\
         User=root\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        service = spec.service_name,
        path = spec.install_path,
    )
}

// ---------------------------------------------------------------------------
// Pure path / decision helpers (unit-tested in CI; no privilege, no I/O).
// ---------------------------------------------------------------------------

impl InstallSpec {
    /// Absolute path of the primary service unit file.
    #[must_use]
    pub fn service_unit_path(&self) -> PathBuf {
        Path::new(&self.unit_dir).join(format!("{}.service", self.service_name))
    }

    /// Absolute path of the guardian unit file.
    #[must_use]
    pub fn guardian_unit_path(&self) -> PathBuf {
        Path::new(&self.unit_dir).join(format!("{}.service", self.guardian_name))
    }

    /// Absolute path of the SHA-256 baseline manifest.
    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        Path::new(&self.state_dir).join("manifest.json")
    }

    /// Absolute path of the uninstall token/marker.
    #[must_use]
    pub fn token_path(&self) -> PathBuf {
        Path::new(&self.state_dir).join("uninstall.token")
    }

    /// The set of files that the manifest, the immutable bit, and the tamper loop
    /// all share: the installed binary plus both unit files.
    #[must_use]
    pub fn protected_paths(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from(&self.install_path),
            self.service_unit_path(),
            self.guardian_unit_path(),
        ]
    }
}

/// Pure: given the trimmed stdout of `systemctl is-active <svc>`, decide whether
/// the guardian should restart the service. Anything other than exactly
/// `"active"` (e.g. `"inactive"`, `"failed"`, `""` when the unit is unknown)
/// means revive.
#[must_use]
pub fn should_restart(is_active_stdout: &str) -> bool {
    is_active_stdout.trim() != "active"
}

/// A small marker written at install recording how/where the agent was installed.
///
/// Its presence marks a deliberate, administrator-performed install; [`uninstall`]
/// reads it (when present) to target the exact installed paths. It carries **no
/// protective value** and is intentionally *not* made immutable, so root can
/// always consume it during teardown. Authority to uninstall is gated on uid 0,
/// never on this token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallToken {
    /// Install time, nanoseconds since the Unix epoch.
    pub installed_ns: u64,
    /// Where the hardened binary was placed.
    pub install_path: String,
    /// Agent crate version that performed the install.
    pub version: String,
    /// The unit directory used (so uninstall targets the same files).
    pub unit_dir: String,
    /// The service/guardian unit base names.
    pub service_name: String,
    pub guardian_name: String,
}

// ---------------------------------------------------------------------------
// Privileged lifecycle (runtime-only; returns Result; NOT run in tests).
// ---------------------------------------------------------------------------

/// `true` iff the current process has real uid 0. Reuses the crate's
/// `/proc`-based check so we add no dependency.
fn is_root() -> bool {
    crate::is_root()
}

/// `fchown(fd, 0, 0)` — make the file behind an *already-open, verified* fd
/// explicitly root-owned.
///
/// Operating on the fd (not a path) closes the symlink/TOCTOU window that a
/// path-based `chown` has: we chown exactly the inode we opened and wrote, never
/// whatever a path resolves to at chown time. The installer runs as root, so
/// created files are already root-owned; this corrects ownership on a reinstall
/// over a file some other user might have created.
fn fchown_root(f: &std::fs::File) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `f` owns a valid fd for the duration of the call; fchown takes
    // (fd, uid, gid). Return value checked; errno surfaced on failure.
    let rc = unsafe { libc::fchown(f.as_raw_fd(), 0, 0) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error()).context("fchown root:root");
    }
    Ok(())
}

/// Open `path` for writing such that a symlink planted at the final path
/// component cannot redirect the write (or a later chown) elsewhere.
///
/// Uses `O_NOFOLLOW`: if the final component is a symlink the open fails with
/// `ELOOP` rather than following it, which defeats the "plant a symlink at the
/// install destination" arbitrary-write/chown-to-root primitive. `O_CREAT`
/// creates the file if absent (with `mode`); `O_TRUNC` truncates a legitimate
/// pre-existing *regular* file for an idempotent reinstall (a symlink would have
/// already failed the `O_NOFOLLOW` check, so truncation only ever hits a real
/// file). `O_CLOEXEC` avoids leaking the fd across the `systemctl` execs.
fn open_nofollow_write(path: &Path, mode: u32) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| {
            format!(
                "opening {} for write (O_NOFOLLOW; a symlink at the destination is refused)",
                path.display()
            )
        })
}

/// Write `bytes` to `path` with `mode`, truncating any prior regular file, then
/// `fchown` root:root — all through one symlink-safe fd. Creates parent
/// directories as needed.
fn write_root_owned(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut f = open_nofollow_write(path, mode)?;
    // create+mode only sets perms on creation; tighten the OPEN fd's inode
    // unconditionally (covers a pre-existing file opened with looser perms).
    f.set_permissions(PermissionsExt::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    f.flush().ok();
    // chown the fd we wrote, not a re-resolved path.
    fchown_root(&f).with_context(|| format!("chowning {} root:root", path.display()))?;
    Ok(())
}

/// Copy `src` to `dst` with `mode`, root-owned, through a symlink-safe
/// (`O_NOFOLLOW`) destination fd. Streams the source rather than slurping it, and
/// `fchown`s the destination fd. Used for the agent binary, replacing
/// `std::fs::copy` (which follows a symlink planted at `dst`).
fn copy_root_owned(src: &Path, dst: &Path, mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let mut input =
        std::fs::File::open(src).with_context(|| format!("opening source {}", src.display()))?;
    let mut out = open_nofollow_write(dst, mode)?;
    out.set_permissions(PermissionsExt::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", dst.display()))?;
    std::io::copy(&mut input, &mut out)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    out.flush().ok();
    fchown_root(&out).with_context(|| format!("chowning {} root:root", dst.display()))?;
    Ok(())
}

/// Run `systemctl <args>` and fail if it exits non-zero.
///
/// This is the only `systemctl` invocation in the repo; it is reached only via
/// the agent's privileged subcommands at runtime.
fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("spawning `systemctl {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`systemctl {}` failed with {}", args.join(" "), status);
    }
    Ok(())
}

/// Best-effort `systemctl <args>`: log a warning on failure but do not abort.
/// Used during teardown where a unit may already be gone/unloaded.
fn systemctl_best_effort(args: &[&str]) {
    match std::process::Command::new("systemctl").args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            tracing::warn!(args = ?args, status = %s, "systemctl returned non-zero (continuing)")
        }
        Err(e) => {
            tracing::warn!(args = ?args, error = %e, "systemctl failed to spawn (continuing)")
        }
    }
}

/// Install the agent as a tamper-resistant service. **Requires root.**
///
/// Ordered so the state is never unremovable: immutability is applied *last*, and
/// [`uninstall`] clears it *first*. Steps:
///
/// 1. Copy the running binary to `install_path` (0755, root:root). If a prior
///    immutable copy exists, clear its immutable bit first (idempotent reinstall).
/// 2. Write both systemd unit files (0644, root:root).
/// 3. Write the SHA-256 baseline manifest over the binary + units (0644).
/// 4. Write the uninstall token/marker (0600) — *not* made immutable.
/// 5. `systemctl daemon-reload`, then `enable --now` both units.
/// 6. Set the immutable bit on the binary + both unit files + the manifest.
pub fn install(spec: &InstallSpec) -> anyhow::Result<()> {
    if !is_root() {
        bail!("install requires root (uid 0): run via sudo");
    }

    let install_path = PathBuf::from(&spec.install_path);
    let service_unit = spec.service_unit_path();
    let guardian_unit = spec.guardian_unit_path();
    let manifest_path = spec.manifest_path();
    let token_path = spec.token_path();

    // Step 1: copy the running binary into place.
    // If a previous install left it immutable, clear the bit so we can overwrite.
    if install_path.exists() {
        let _ = immutable::set_immutable(&install_path, false);
    }
    let current = std::env::current_exe().context("resolving current executable path")?;
    if let Some(parent) = install_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    // Symlink-safe copy: open the destination O_NOFOLLOW so a symlink planted at
    // `install_path` cannot redirect the write, stream the bytes, then fchown the
    // fd (not the path). Replaces `std::fs::copy` (which follows a dest symlink).
    copy_root_owned(&current, &install_path, 0o755)?;

    // Step 2: write the unit files (reuse the already-tested rendered text).
    // Clear any pre-existing immutable bit so a reinstall can overwrite.
    let _ = immutable::set_immutable(&service_unit, false);
    let _ = immutable::set_immutable(&guardian_unit, false);
    write_root_owned(&service_unit, render_service_unit(spec).as_bytes(), 0o644)?;
    write_root_owned(&guardian_unit, render_guardian_unit(spec).as_bytes(), 0o644)?;

    // Step 3: write the baseline manifest AFTER the protected files are in place.
    let _ = immutable::set_immutable(&manifest_path, false);
    let baseline = Manifest::from_paths(&spec.protected_paths())
        .context("hashing protected files for the baseline manifest")?;
    let manifest_json = baseline
        .to_json()
        .context("serializing the baseline manifest")?;
    write_root_owned(&manifest_path, manifest_json.as_bytes(), 0o644)?;

    // Step 4: write the uninstall token/marker (escape-hatch marker, mode 0600).
    let token = InstallToken {
        installed_ns: aegis_sdk::now_ns(),
        install_path: spec.install_path.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        unit_dir: spec.unit_dir.clone(),
        service_name: spec.service_name.clone(),
        guardian_name: spec.guardian_name.clone(),
    };
    let token_json = serde_json::to_string_pretty(&token).context("serializing install token")?;
    write_root_owned(&token_path, token_json.as_bytes(), 0o600)?;

    // Step 5: register and start the units.
    systemctl(&["daemon-reload"])?;
    let service_name = format!("{}.service", spec.service_name);
    let guardian_name = format!("{}.service", spec.guardian_name);
    systemctl(&["enable", "--now", &service_name, &guardian_name])?;

    // Step 6: lock the protected files immutable (LAST, so steps 1-5 could write).
    for path in [&install_path, &service_unit, &guardian_unit, &manifest_path] {
        immutable::set_immutable(path, true)
            .with_context(|| format!("setting immutable bit on {}", path.display()))?;
    }

    tracing::info!(
        install_path = %spec.install_path,
        "aegis-agent installed (units enabled, protected files immutable)"
    );
    Ok(())
}

/// Remove the agent — the **authenticated, root-only** uninstall path.
///
/// The single hard precondition is uid 0: root holds the one privileged primitive
/// (`CAP_LINUX_IMMUTABLE` + systemd control + file ownership) that every
/// protection layer is keyed on, so requiring root is both necessary and
/// sufficient. A missing token does **not** block uninstall (the token marks
/// *intent*; root is *authority*), so a partial/corrupt install is still fully
/// removable. Clears immutability *first*, then disables and removes everything.
pub fn uninstall(spec: &InstallSpec) -> anyhow::Result<()> {
    if !is_root() {
        bail!(
            "uninstall requires root (uid 0): this is the authenticated administrator escape hatch"
        );
    }

    // Prefer the exact paths recorded at install time, if the token is present.
    let effective = load_spec_from_token(spec).unwrap_or_else(|| spec.clone());

    let install_path = PathBuf::from(&effective.install_path);
    let service_unit = effective.service_unit_path();
    let guardian_unit = effective.guardian_unit_path();
    let manifest_path = effective.manifest_path();
    let token_path = effective.token_path();

    // Step 1 (informational): note the token if present; never fail on its absence.
    if !token_path.exists() {
        tracing::warn!(
            token = %token_path.display(),
            "no install token found; proceeding with root authority anyway"
        );
    }

    // Step 2: clear immutable bits first so the files become modifiable/removable.
    // Best-effort per path: a missing file (ENOENT) or unsupported fs is fine.
    for path in [&install_path, &service_unit, &guardian_unit, &manifest_path] {
        if let Err(e) = immutable::set_immutable(path, false) {
            tracing::warn!(path = %path.display(), error = %e, "clearing immutable bit (continuing)");
        }
    }

    // Step 3: disable and stop both units (best-effort; they may be unloaded).
    let service_name = format!("{}.service", effective.service_name);
    let guardian_name = format!("{}.service", effective.guardian_name);
    systemctl_best_effort(&["disable", "--now", &service_name, &guardian_name]);
    systemctl_best_effort(&["daemon-reload"]);

    // Step 4: remove the files (idempotent — already-gone is success).
    for path in [
        &service_unit,
        &guardian_unit,
        &install_path,
        &manifest_path,
        &token_path,
    ] {
        remove_if_present(path)?;
    }

    // Step 4b: remove the agent's persisted state so an uninstall does not leave
    // the enrolled cryptographic identity, the Ed25519 private key, server pins,
    // or buffered behavioral telemetry behind. Without this, sensitive residue
    // (the spill DB + plugin-transport/ identity) survives "uninstall", which is
    // both a privacy leak about monitored users and a contradiction of the
    // "removes all artifacts" contract. Best-effort/idempotent: a missing tree is
    // success, and we never fail the uninstall on a leftover-data error.
    let state_dir = PathBuf::from(&effective.state_dir);
    // The forwarder writes its identity/key/pins under <state_dir>/plugin-transport/.
    remove_dir_best_effort(&state_dir.join("plugin-transport"));
    // The on-disk spill buffer (durable telemetry queue).
    remove_if_present_best_effort(&state_dir.join("spill.redb"));
    // Finally, drop the state dir itself if it is now empty (leaves it in place if
    // an operator stored unrelated files there).
    if let Err(e) = std::fs::remove_dir(&state_dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(dir = %state_dir.display(), error = %e, "state dir not removed (non-empty or in use)");
        }
    }

    // Step 5: reload so systemd forgets the removed units.
    systemctl_best_effort(&["daemon-reload"]);

    tracing::info!(
        state_dir = %effective.state_dir,
        "aegis-agent uninstalled (immutable cleared, units disabled, files + agent state removed)"
    );
    Ok(())
}

/// Recursively remove a directory tree, treating "not found" as success and never
/// returning an error (uninstall must not fail because leftover data could not be
/// cleared). Other errors are logged at warn so the operator can clean up.
fn remove_dir_best_effort(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(dir = %path.display(), error = %e, "could not remove agent state dir (continuing)")
        }
    }
}

/// Like [`remove_if_present`] but never propagates an error (best-effort cleanup).
fn remove_if_present_best_effort(path: &Path) {
    if let Err(e) = remove_if_present(path) {
        tracing::warn!(path = %path.display(), error = %e, "could not remove agent state file (continuing)");
    }
}

/// Read back the install token and reconstruct the spec's installed paths, so
/// uninstall targets exactly what was installed. Returns `None` if the token is
/// absent or unparsable (uninstall then falls back to `spec`).
fn load_spec_from_token(spec: &InstallSpec) -> Option<InstallSpec> {
    let token_path = spec.token_path();
    let raw = std::fs::read_to_string(&token_path).ok()?;
    let token: InstallToken = serde_json::from_str(&raw).ok()?;
    Some(InstallSpec {
        install_path: token.install_path,
        unit_dir: token.unit_dir,
        service_name: token.service_name,
        guardian_name: token.guardian_name,
        ..spec.clone()
    })
}

/// Remove a file, treating "not found" as success (idempotent teardown).
fn remove_if_present(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Guardian watchdog loop (invoked by the guardian unit's `ExecStart ... guard`).
///
/// Belt-and-suspenders to systemd's own `BindsTo`/`Restart`: every
/// `guard_interval` it asks `systemctl is-active <service>` and, if the service
/// is not active, tries to start it (logging the event so a kill is observable).
/// The loop is intentionally dependency-free; the decision is factored into the
/// pure [`should_restart`] for testing. This function blocks forever and is run
/// only by the guardian unit at runtime.
pub fn guard(service: &str, interval: std::time::Duration) -> ! {
    let unit = format!("{service}.service");
    loop {
        std::thread::sleep(interval);
        let active = std::process::Command::new("systemctl")
            .args(["is-active", &unit])
            .output();
        let stdout = match active {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => {
                tracing::warn!(error = %e, "guardian: `systemctl is-active` failed");
                continue;
            }
        };
        if should_restart(&stdout) {
            tracing::warn!(
                service,
                state = stdout.trim(),
                "guardian: service not active, attempting restart"
            );
            systemctl_best_effort(&["start", &unit]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_unit_has_restart_and_guardian_dependency() {
        let spec = InstallSpec::default();
        let unit = render_service_unit(&spec);
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("Requires=aegis-guardian.service"));
        assert!(unit.contains("ExecStart=/usr/local/sbin/aegis-agent run"));
    }

    #[test]
    fn service_unit_blocks_privilege_escalation() {
        // NoNewPrivileges defeats setuid/LD_PRELOAD-style escalation (U5/U7) and
        // does not impede the root-only authenticated uninstall path.
        let unit = render_service_unit(&InstallSpec::default());
        assert!(unit.contains("NoNewPrivileges=yes"));
    }

    #[test]
    fn guardian_binds_to_service() {
        let spec = InstallSpec::default();
        let unit = render_guardian_unit(&spec);
        assert!(unit.contains("BindsTo=aegis-agent.service"));
        assert!(unit.contains("Restart=always"));
    }

    #[test]
    fn path_helpers_produce_expected_absolute_paths() {
        let spec = InstallSpec::default();
        assert_eq!(
            spec.service_unit_path(),
            PathBuf::from("/etc/systemd/system/aegis-agent.service")
        );
        assert_eq!(
            spec.guardian_unit_path(),
            PathBuf::from("/etc/systemd/system/aegis-guardian.service")
        );
        assert_eq!(
            spec.manifest_path(),
            PathBuf::from("/var/lib/aegis/manifest.json")
        );
        assert_eq!(
            spec.token_path(),
            PathBuf::from("/var/lib/aegis/uninstall.token")
        );
    }

    #[test]
    fn protected_paths_are_binary_and_both_units() {
        let spec = InstallSpec::default();
        let paths = spec.protected_paths();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&PathBuf::from("/usr/local/sbin/aegis-agent")));
        assert!(paths.contains(&spec.service_unit_path()));
        assert!(paths.contains(&spec.guardian_unit_path()));
        // The token is the escape-hatch marker and is deliberately NOT protected.
        assert!(!paths.contains(&spec.token_path()));
    }

    #[test]
    fn should_restart_truth_table() {
        assert!(!should_restart("active"));
        assert!(!should_restart("active\n")); // systemctl appends a newline
        assert!(should_restart("inactive"));
        assert!(should_restart("failed"));
        assert!(should_restart("activating"));
        assert!(should_restart("")); // unknown unit -> empty stdout
    }

    #[test]
    fn install_token_json_roundtrips() {
        let token = InstallToken {
            installed_ns: 42,
            install_path: "/usr/local/sbin/aegis-agent".into(),
            version: "0.1.0".into(),
            unit_dir: "/etc/systemd/system".into(),
            service_name: "aegis-agent".into(),
            guardian_name: "aegis-guardian".into(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: InstallToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.installed_ns, 42);
        assert_eq!(back.install_path, "/usr/local/sbin/aegis-agent");
        assert_eq!(back.guardian_name, "aegis-guardian");
    }

    #[test]
    fn default_spec_unchanged_for_existing_fields() {
        // Guards the additive nature of the new fields.
        let spec = InstallSpec::default();
        assert_eq!(spec.service_name, "aegis-agent");
        assert_eq!(spec.guardian_name, "aegis-guardian");
        assert_eq!(spec.install_path, "/usr/local/sbin/aegis-agent");
        assert_eq!(spec.run_as, "root");
        assert_eq!(spec.unit_dir, "/etc/systemd/system");
        assert_eq!(spec.state_dir, "/var/lib/aegis");
    }

    /// The state-cleanup helpers used by `uninstall` actually delete the agent's
    /// persisted identity/key/spill, and are idempotent (a missing tree/file is
    /// success, not an error). This pins the privacy-residue fix without requiring
    /// root (the full `uninstall` path is root-gated).
    #[test]
    fn state_cleanup_removes_identity_and_spill_idempotently() {
        let base = std::env::temp_dir().join(format!(
            "aegis-uninstall-state-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        let transport = base.join("plugin-transport");
        std::fs::create_dir_all(&transport).unwrap();
        // Simulate the sensitive residue an enrolled agent leaves behind.
        std::fs::write(transport.join("identity.json"), b"{}").unwrap();
        std::fs::write(transport.join("agent_ed25519.key"), b"secret-key").unwrap();
        std::fs::write(base.join("spill.redb"), b"telemetry").unwrap();

        // First pass removes everything.
        remove_dir_best_effort(&base.join("plugin-transport"));
        remove_if_present_best_effort(&base.join("spill.redb"));
        assert!(!transport.exists(), "identity dir must be gone");
        assert!(!base.join("spill.redb").exists(), "spill db must be gone");

        // Second pass is a no-op (idempotent — no panic, no error surfaced).
        remove_dir_best_effort(&base.join("plugin-transport"));
        remove_if_present_best_effort(&base.join("spill.redb"));

        let _ = std::fs::remove_dir_all(&base);
    }
}
