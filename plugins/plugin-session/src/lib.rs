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

/// Shannon entropy in bits per character, over the distribution of Unicode
/// scalar values (`char`s) in `s`.
///
/// Counted per-`char` (not per-byte) so the unit matches `command_len`
/// ([`CommandStats`] counts `chars`), the `bits/char` contract on
/// [`EventPayload::CommandObserved`](aegis_sdk::EventPayload::CommandObserved),
/// and the model's `dense-commands` term, which centres the transfer at 4.2
/// bits/char. For pure-ASCII input byte- and char-entropy coincide; for
/// multibyte UTF-8 they diverge, and the per-char measure is the one every
/// consumer assumes.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    let mut n: u64 = 0;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    // Sum in a deterministic order. `HashMap` iteration order is randomized per
    // map, and floating-point addition is not associative, so summing the
    // per-symbol terms in iteration order makes the result vary by a few ULPs
    // between calls on identical input. Entropy depends only on the multiset of
    // counts, so sorting the counts yields a canonical, reproducible order
    // (which `command_stats`' `PartialEq` and its callers rely on).
    let mut counts: Vec<u32> = counts.into_values().collect();
    counts.sort_unstable();
    counts
        .iter()
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

    /// Entropy is measured per *character*, not per byte: four distinct chars,
    /// each appearing once, must give exactly log2(4) = 2 bits/char regardless of
    /// how many UTF-8 bytes those chars occupy. (A per-byte measure over the same
    /// multibyte string would report a different value — the bug this guards.)
    #[test]
    fn entropy_is_per_char_not_per_byte() {
        // Four distinct multibyte chars, equiprobable -> 2.0 bits/char exactly.
        let s = "αβγδ"; // each is 2 bytes in UTF-8 (8 bytes, 4 chars)
        assert_eq!(s.len(), 8);
        assert_eq!(s.chars().count(), 4);
        let h = shannon_entropy(s);
        assert!((h - 2.0).abs() < 1e-12, "per-char entropy was {h}");

        // A single repeated multibyte char has zero entropy (one symbol).
        assert!(shannon_entropy("日日日") < 1e-12);
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
