//! # plugin-tamper
//!
//! Endpoint self-protection, expressed as a plugin so that "the agent defends
//! itself" is just another capability on the bus rather than core behaviour.
//!
//! ## Threat model & ethics
//! The protected asset is *visibility*: in an insider-threat deployment the
//! monitored, unprivileged user must not be able to silently disable monitoring
//! on their workstation — exactly as commercial EDR/DLP agents behave. The
//! design therefore resists the **unprivileged user**, while remaining fully
//! removable by **root/administrator** through an authenticated uninstall path.
//! It is explicitly *not* a rootkit and uses only supported OS mechanisms
//! (root-owned files, the immutable attribute, and a systemd watchdog pair).
//! See `THREAT_MODEL.md` and the paper's ethics section.
//!
//! The foundation build ships posture detection and the tamper-watch loop
//! (which raises an alert if the agent's protected files are altered or removed);
//! the systemd unit generation and immutable-attribute installer are completed by
//! the hardening workflow in [`install`].

pub mod immutable;
pub mod install;
pub mod manifest;

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Severity, Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TamperConfig {
    /// How often to verify protective posture, in seconds.
    pub check_interval_s: u64,
    /// Files whose disappearance/alteration constitutes tampering.
    pub protected_paths: Vec<PathBuf>,
    /// Path to the SHA-256 baseline manifest written at install. When present,
    /// the loop verifies *content* (not just existence) of the protected files.
    pub manifest_path: Option<PathBuf>,
}

impl Default for TamperConfig {
    fn default() -> Self {
        TamperConfig {
            check_interval_s: 15,
            protected_paths: Vec::new(),
            manifest_path: Some(PathBuf::from("/var/lib/aegis/manifest.json")),
        }
    }
}

/// A snapshot of the agent's self-protection posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperPosture {
    /// Whether the agent process runs with uid 0.
    pub is_root: bool,
    /// Whether the init system is systemd (enables the watchdog strategy).
    pub systemd_present: bool,
    /// Whether this process shares PID 1's PID namespace. If false, the agent is
    /// running inside a PID namespace (e.g. a container/sandbox) where its view
    /// of the host is incomplete — a likely mis-deployment for endpoint monitoring.
    pub pid_ns_matches_init: bool,
}

impl TamperPosture {
    /// Whether the posture is strong enough to actually protect visibility:
    /// running as root on a systemd host in the host PID namespace.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.is_root && self.systemd_present && self.pid_ns_matches_init
    }

    /// Human-readable reasons the posture is weak (empty when healthy).
    #[must_use]
    pub fn weaknesses(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.is_root {
            out.push("not running as root (uid 0)");
        }
        if !self.systemd_present {
            out.push("init system is not systemd (no watchdog)");
        }
        if !self.pid_ns_matches_init {
            out.push("running in a non-init PID namespace (sandboxed/containerized)");
        }
        out
    }
}

/// Detect current self-protection posture.
pub fn posture() -> TamperPosture {
    TamperPosture {
        is_root: is_root(),
        systemd_present: systemd_present(),
        pid_ns_matches_init: pid_ns_matches_init(),
    }
}

/// Compare this process's PID namespace to PID 1's via `/proc/*/ns/pid`.
///
/// The kernel renders these symlinks as `pid:[<inode>]`; equal targets mean the
/// same namespace. If either link is unreadable (no procfs), assume a match so we
/// don't false-alarm on exotic but legitimate hosts.
fn pid_ns_matches_init() -> bool {
    match (
        std::fs::read_link("/proc/self/ns/pid"),
        std::fs::read_link("/proc/1/ns/pid"),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => true,
    }
}

fn is_root() -> bool {
    // Avoid an extra dependency: read the real uid from /proc/self/status.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|r| r.split_whitespace().next().map(|s| s.to_string()))
        })
        .map(|uid| uid == "0")
        .unwrap_or(false)
}

/// Is PID 1 systemd? Read its `comm` to decide.
pub fn systemd_present() -> bool {
    std::fs::read_to_string("/proc/1/comm")
        .map(|c| c.trim() == "systemd")
        .unwrap_or(false)
}

#[derive(Default)]
pub struct TamperPlugin;

#[async_trait]
impl Plugin for TamperPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-tamper",
            env!("CARGO_PKG_VERSION"),
            "Endpoint self-protection: posture monitoring and tamper alerting",
            PluginKind::Control,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::None
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        let cfg: TamperConfig = ctx.config_as()?;
        let emitter = ctx.emitter.clone();
        let agent_id = ctx.agent_id.clone();

        let p = posture();
        tracing::info!(
            is_root = p.is_root,
            systemd = p.systemd_present,
            pid_ns_init = p.pid_ns_matches_init,
            "tamper posture"
        );

        // Posture self-check: a mis-deployed (sandboxed / non-root) agent is
        // silently weak, so we *report* it (Critical) rather than fail closed.
        // We intentionally do NOT exit — exiting would aid an attacker who induced
        // the condition; an administrator deciding to run unprivileged still can.
        let protected_immutable = !cfg.protected_paths.is_empty()
            && cfg
                .protected_paths
                .iter()
                .all(|path| !path.exists() || immutable::check_immutable(path));
        let mut weak = p.weaknesses();
        if !cfg.protected_paths.is_empty() && !protected_immutable {
            weak.push("protected files are not immutable");
        }
        if !weak.is_empty() {
            emitter
                .emit(Event::new(
                    &agent_id,
                    "plugin-tamper",
                    EventPayload::Alert {
                        severity: Severity::Critical,
                        title: "Agent mis-deployed (weak self-protection)".into(),
                        detail: format!("self-protection is degraded: {}", weak.join("; ")),
                        subject: Some(agent_id.clone()),
                    },
                ))
                .await;
        }

        // SIGTERM/SIGINT tripwire: report disappearance even if a guardian revives
        // us quickly. A cross-UID signal from the monitored user is denied by the
        // kernel, so this fires for legitimate/root stops and acts as a tripwire.
        spawn_signal_tripwire(emitter.clone(), agent_id.clone());

        // Load the baseline manifest once (root-owned). Content drift is checked
        // against it each tick; paths not covered fall back to an existence check.
        let manifest = cfg
            .manifest_path
            .as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|raw| manifest::Manifest::from_json(&raw).ok());
        if cfg.manifest_path.is_some() && manifest.is_none() {
            tracing::debug!("no readable baseline manifest; using existence-only checks");
        }

        let started = std::time::Instant::now();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(cfg.check_interval_s.max(1)));
            loop {
                ticker.tick().await;

                // 1. Content integrity against the baseline manifest (catches an
                //    in-place replacement that a bare existence check misses).
                if let Some(manifest) = &manifest {
                    for (path, kind) in manifest::verify(manifest) {
                        if kind.is_drift() {
                            emit_tamper(
                                &emitter,
                                &agent_id,
                                "Tamper detected (integrity)",
                                format!("protected file {}: {}", path.display(), kind.label()),
                            )
                            .await;
                        }
                    }
                }

                // 2. Immutable-bit watch: losing the bit required root and is
                //    itself auditable tampering.
                for path in &cfg.protected_paths {
                    if path.exists() && !immutable::check_immutable(path) {
                        emit_tamper(
                            &emitter,
                            &agent_id,
                            "Tamper detected (immutable bit cleared)",
                            format!("protected file no longer immutable: {}", path.display()),
                        )
                        .await;
                    }
                }

                // 3. Existence fallback for any path NOT covered by the manifest,
                //    preserving the original behavior for unmanifested paths.
                for path in &cfg.protected_paths {
                    let covered = manifest
                        .as_ref()
                        .map(|m| m.entries.iter().any(|e| &e.path == path))
                        .unwrap_or(false);
                    if !covered && !path.exists() {
                        emit_tamper(
                            &emitter,
                            &agent_id,
                            "Tamper detected",
                            format!("protected path missing: {}", path.display()),
                        )
                        .await;
                    }
                }

                // 4. Cheap liveness so the server can distinguish a kill/restart
                //    from a network drop.
                emitter
                    .emit(Event::new(
                        &agent_id,
                        "plugin-tamper",
                        EventPayload::Heartbeat {
                            uptime_s: started.elapsed().as_secs(),
                        },
                    ))
                    .await;
            }
        });
        Ok(())
    }
}

/// Emit a Critical tamper Alert with the given title/detail.
async fn emit_tamper(
    emitter: &std::sync::Arc<dyn aegis_sdk::Emitter>,
    agent_id: &str,
    title: &str,
    detail: String,
) {
    emitter
        .emit(Event::new(
            agent_id,
            "plugin-tamper",
            EventPayload::Alert {
                severity: Severity::Critical,
                title: title.to_string(),
                detail,
                subject: Some(agent_id.to_string()),
            },
        ))
        .await;
}

/// Spawn a task that emits a Critical Alert on SIGTERM/SIGINT before the process
/// exits, so an externally induced stop is reported even when recovery is fast.
///
/// Linux-only (the agent's target). The alert is awaited before exiting so it has
/// a chance to reach the bus; `process::exit(0)` then ends the process cleanly.
#[cfg(unix)]
fn spawn_signal_tripwire(emitter: std::sync::Arc<dyn aegis_sdk::Emitter>, agent_id: String) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let (mut term, mut intr) = match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(t), Ok(i)) => (t, i),
            _ => {
                tracing::warn!("could not install SIGTERM/SIGINT tripwire");
                return;
            }
        };
        let which = tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = intr.recv() => "SIGINT",
        };
        emit_tamper(
            &emitter,
            &agent_id,
            "Agent stopping (possible tamper)",
            format!("agent received {which} (possible tamper/stop)"),
        )
        .await;
        // Best-effort flush window for async emitters/forwarders, then exit.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::process::exit(0);
    });
}

#[cfg(not(unix))]
fn spawn_signal_tripwire(_emitter: std::sync::Arc<dyn aegis_sdk::Emitter>, _agent_id: String) {}

register_plugin!("plugin-tamper", || Box::new(TamperPlugin));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_is_observable() {
        // Just assert it runs and returns a consistent struct on this platform.
        let p = posture();
        assert_eq!(p.is_root, is_root());
    }

    fn posture_with(is_root: bool, systemd: bool, pid_ns: bool) -> TamperPosture {
        TamperPosture {
            is_root,
            systemd_present: systemd,
            pid_ns_matches_init: pid_ns,
        }
    }

    #[test]
    fn is_healthy_requires_all_three_conditions() {
        assert!(posture_with(true, true, true).is_healthy());
        assert!(!posture_with(false, true, true).is_healthy());
        assert!(!posture_with(true, false, true).is_healthy());
        assert!(!posture_with(true, true, false).is_healthy());
        assert!(!posture_with(false, false, false).is_healthy());
    }

    #[test]
    fn weaknesses_enumerates_each_failing_condition() {
        assert!(posture_with(true, true, true).weaknesses().is_empty());
        let w = posture_with(false, false, false).weaknesses();
        assert_eq!(w.len(), 3);
        assert!(posture_with(false, true, true)
            .weaknesses()
            .iter()
            .any(|s| s.contains("root")));
        assert!(posture_with(true, false, true)
            .weaknesses()
            .iter()
            .any(|s| s.contains("systemd")));
        assert!(posture_with(true, true, false)
            .weaknesses()
            .iter()
            .any(|s| s.contains("PID namespace")));
    }

    #[test]
    fn default_config_enables_manifest_checking() {
        let cfg = TamperConfig::default();
        assert_eq!(
            cfg.manifest_path,
            Some(PathBuf::from("/var/lib/aegis/manifest.json"))
        );
    }

    #[test]
    fn partial_config_subtree_deserializes_with_defaults() {
        // The agent injects `protected_paths`/`manifest_path` without
        // `check_interval_s`; a non-null partial subtree must still load (it is
        // fed straight into `config_as`), defaulting the omitted interval rather
        // than failing plugin init and silently disabling self-protection.
        let cfg: TamperConfig = serde_json::from_value(serde_json::json!({
            "protected_paths": ["/usr/local/sbin/aegis-agent"],
        }))
        .expect("partial subtree must deserialize");
        assert_eq!(cfg.check_interval_s, 15);
        assert_eq!(
            cfg.protected_paths,
            vec![PathBuf::from("/usr/local/sbin/aegis-agent")]
        );
        // Container-level default also restores the manifest path.
        assert_eq!(
            cfg.manifest_path,
            Some(PathBuf::from("/var/lib/aegis/manifest.json"))
        );
    }

    // Smoke-test the re-exported pure primitives so they are in this crate's test
    // graph regardless of which module's tests run.
    #[test]
    fn reexported_pure_primitives_work() {
        assert_eq!(immutable::FS_IMMUTABLE_FL, 0x10);
        assert!(immutable::is_immutable(immutable::apply_immutable(0, true)));
        assert_eq!(
            manifest::hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
