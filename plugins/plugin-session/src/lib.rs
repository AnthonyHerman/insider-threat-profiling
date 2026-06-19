//! # plugin-session
//!
//! Collects interactive-session lifecycle and the *timing/structure* of input
//! within sessions. It is the primary source of the behavioral substrate the
//! agent-vs-human detector consumes.
//!
//! ## Privacy
//! This collector never captures keystroke *content*. It records inter-arrival
//! timing, paste/burst shape, and per-command structural statistics (length,
//! token count, Shannon entropy, whether corrections occurred) plus a salted
//! hash for correlation. See [`command_stats`].
//!
//! The foundation build emits a [`SessionStart`](aegis_sdk::EventPayload::SessionStart)
//! for the current login (derived from the environment) and ships the
//! unit-tested command-statistics helpers. Live tty/pty interception is added by
//! the telemetry workflow behind the same event contract.

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Emit a SessionStart for the current login at startup (best-effort).
    pub emit_current_login: bool,
    /// Per-deployment salt for hashing commands (never store content).
    pub hash_salt: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            emit_current_login: true,
            hash_salt: "aegis-default-salt".to_string(),
        }
    }
}

#[derive(Default)]
pub struct SessionPlugin;

#[async_trait]
impl Plugin for SessionPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-session",
            env!("CARGO_PKG_VERSION"),
            "Interactive session + input-timing collector (privacy-preserving)",
            PluginKind::Collector,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::None
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        let cfg: SessionConfig = ctx.config_as()?;
        if cfg.emit_current_login {
            let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
            let tty = std::env::var("SSH_TTY")
                .or_else(|_| std::env::var("TTY"))
                .ok();
            let remote = std::env::var("SSH_CONNECTION")
                .ok()
                .and_then(|c| c.split_whitespace().next().map(String::from));
            let session_id = format!("{}:{}", user, std::process::id());
            ctx.emit(Event::new(
                &ctx.agent_id,
                "plugin-session",
                EventPayload::SessionStart {
                    session_id,
                    tty,
                    user,
                    remote,
                },
            ))
            .await;
        }
        Ok(())
    }
}

/// Structural statistics for a single command line — derived without storing the
/// command itself. `salt` keeps the correlation hash unlinkable across deploys.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandStats {
    pub command_len: u32,
    pub token_count: u32,
    pub shannon_entropy: f64,
    pub command_hash: String,
}

/// Compute privacy-preserving statistics for a command line.
pub fn command_stats(command: &str, salt: &str) -> CommandStats {
    let command_len = command.chars().count() as u32;
    let token_count = command.split_whitespace().count() as u32;
    let shannon_entropy = shannon_entropy(command);
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"\0");
    hasher.update(command.as_bytes());
    let command_hash = hex::encode(hasher.finalize());
    CommandStats {
        command_len,
        token_count,
        shannon_entropy,
        command_hash,
    }
}

/// Shannon entropy in bits per character over the byte distribution.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

register_plugin!("plugin-session", || Box::new(SessionPlugin));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_is_high_repeated_is_low() {
        assert!(shannon_entropy("aaaaaaaa") < 0.01);
        let h = shannon_entropy("abcdefghijklmnop");
        assert!(h > 3.9, "entropy was {h}");
    }

    #[test]
    fn command_stats_are_content_free_but_correlatable() {
        let a = command_stats("ls -la /etc", "salt");
        let b = command_stats("ls -la /etc", "salt");
        let c = command_stats("ls -la /etc", "other-salt");
        assert_eq!(a, b); // same command + salt → same hash
        assert_ne!(a.command_hash, c.command_hash); // salt changes the hash
        assert_eq!(a.token_count, 3);
        assert_eq!(a.command_len, 11);
    }
}
