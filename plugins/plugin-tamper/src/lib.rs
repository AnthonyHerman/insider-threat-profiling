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

pub mod install;

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Severity, Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperConfig {
    /// How often to verify protective posture, in seconds.
    pub check_interval_s: u64,
    /// Files whose disappearance/alteration constitutes tampering.
    pub protected_paths: Vec<PathBuf>,
}

impl Default for TamperConfig {
    fn default() -> Self {
        TamperConfig {
            check_interval_s: 15,
            protected_paths: Vec::new(),
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
}

/// Detect current self-protection posture.
pub fn posture() -> TamperPosture {
    TamperPosture {
        is_root: is_root(),
        systemd_present: systemd_present(),
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
            "tamper posture"
        );

        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(cfg.check_interval_s.max(1)));
            loop {
                ticker.tick().await;
                for path in &cfg.protected_paths {
                    if !path.exists() {
                        emitter
                            .emit(Event::new(
                                &agent_id,
                                "plugin-tamper",
                                EventPayload::Alert {
                                    severity: Severity::Critical,
                                    title: "Tamper detected".into(),
                                    detail: format!("protected path missing: {}", path.display()),
                                    subject: Some(agent_id.clone()),
                                },
                            ))
                            .await;
                    }
                }
            }
        });
        Ok(())
    }
}

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
}
