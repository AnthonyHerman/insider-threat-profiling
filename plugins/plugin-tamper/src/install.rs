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
//! The actual privileged filesystem mutations are performed by the agent binary
//! at install time; here we keep the unit-text generation pure and unit-tested.

/// Parameters that shape the generated systemd units.
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
}

impl Default for InstallSpec {
    fn default() -> Self {
        InstallSpec {
            service_name: "aegis-agent".into(),
            guardian_name: "aegis-guardian".into(),
            install_path: "/usr/local/sbin/aegis-agent".into(),
            server_url: "https://127.0.0.1:8443".into(),
            run_as: "root".into(),
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
    fn guardian_binds_to_service() {
        let spec = InstallSpec::default();
        let unit = render_guardian_unit(&spec);
        assert!(unit.contains("BindsTo=aegis-agent.service"));
        assert!(unit.contains("Restart=always"));
    }
}
