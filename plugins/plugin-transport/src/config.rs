//! Forwarder configuration.
//!
//! Every field is `#[serde(default = "...")]`-backed so a partial `[plugins.plugin-transport]`
//! TOML subtree still deserializes (via [`PluginContext::config_as`]), with the
//! documented operational defaults filled in for anything omitted.
//!
//! This module also hosts the shared host-fact and server-URL helpers used by
//! *both* the connection actor's handshake and `aegis-agent enroll`, so the
//! `ClientHello` and `EnrollRequest` sent to the same server cannot drift apart.

use serde::{Deserialize, Serialize};

/// Parse a `https://host:port` server URL (scheme optional, port defaults to
/// `8443`) into the `(host, port)` TCP connect + TLS-SNI need.
///
/// Only `https://` and a bare host (no scheme) are accepted. An `http://` prefix
/// is **rejected**: the transport is always TLS regardless of scheme, so silently
/// accepting `http://` would mislead operators and could mask a misconfiguration.
/// Shared by the forwarder actor and `aegis-agent enroll` so the same input is
/// accepted (or rejected) identically by both.
///
/// Bracketed IPv6 is not supported (deployments use a hostname); the split is on
/// the last `:` to tolerate rare bracketless usage.
pub fn parse_server_url(server: &str) -> anyhow::Result<(String, u16)> {
    let trimmed = server.trim();
    if trimmed.starts_with("http://") {
        anyhow::bail!(
            "server URL `{server}` uses http://; the transport is always TLS — \
             use https:// or omit the scheme"
        );
    }
    let s = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        anyhow::bail!("empty server address");
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port in server `{server}`"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((s.to_string(), 8443)),
    }
}

/// Best-effort `(hostname, os)` for the handshake/enroll messages.
///
/// `hostname` is read from `/proc/sys/kernel/hostname` (trimmed; `"unknown"` if
/// unreadable); `os` is [`std::env::consts::OS`] plus the kernel release from
/// `/proc/sys/kernel/osrelease` when available. Shared so the `ClientHello`
/// (actor) and `EnrollRequest` (agent) always report identical host facts.
pub fn host_facts() -> (String, String) {
    (hostname(), os_string())
}

/// Best-effort hostname from `/proc/sys/kernel/hostname`.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// OS descriptor: [`std::env::consts::OS`] plus the kernel release if available.
fn os_string() -> String {
    let base = std::env::consts::OS;
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if release.is_empty() {
        base.to_string()
    } else {
        format!("{base} {release}")
    }
}

/// Tunables for the transport sink and its connection actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Server URL (`https://host:port`). Empty means "fall back to the value the
    /// agent injected" — the agent's `run()` populates this subtree from its
    /// `--server` flag, so an operator config rarely needs to set it directly.
    #[serde(default)]
    pub server: String,

    /// Flush a batch once this many events are queued.
    #[serde(default = "d_batch_max_events")]
    pub batch_max_events: usize,
    /// Flush a batch once its estimated serialized size reaches this many bytes.
    #[serde(default = "d_batch_max_bytes")]
    pub batch_max_bytes: usize,
    /// Flush a partially-full batch after this long even if neither size trigger
    /// has fired (bounds end-to-end latency at low event rates).
    #[serde(default = "d_flush_interval_ms")]
    pub flush_interval_ms: u64,

    /// Capacity of the in-memory ring (events). Overflow spills to disk; if the
    /// disk tier is also full, the oldest in-memory event is dropped.
    #[serde(default = "d_ring_capacity")]
    pub ring_capacity: usize,
    /// Hard cap on the on-disk spill, in bytes. Drop-oldest beyond this.
    #[serde(default = "d_spill_max_bytes")]
    pub spill_max_bytes: u64,

    /// How long to wait for a `BatchAck` before tearing the connection down and
    /// backing off (the un-acked batch is retained and retried).
    #[serde(default = "d_ack_timeout_ms")]
    pub ack_timeout_ms: u64,

    /// Reconnect backoff floor / ceiling (full-jitter exponential).
    #[serde(default = "d_backoff_min_ms")]
    pub backoff_min_ms: u64,
    #[serde(default = "d_backoff_max_ms")]
    pub backoff_max_ms: u64,

    /// Send a `Ping` after this much idle time.
    #[serde(default = "d_keepalive_ms")]
    pub keepalive_ms: u64,
    /// Drop the connection if nothing is received from the server for this long.
    #[serde(default = "d_keepalive_timeout_ms")]
    pub keepalive_timeout_ms: u64,

    /// Maximum number of batches awaiting acknowledgement at once. `1` (the
    /// default) yields strict FIFO delivery.
    #[serde(default = "d_max_in_flight")]
    pub max_in_flight: usize,
}

fn d_batch_max_events() -> usize {
    512
}
fn d_batch_max_bytes() -> usize {
    1_048_576
}
fn d_flush_interval_ms() -> u64 {
    1000
}
fn d_ring_capacity() -> usize {
    50_000
}
fn d_spill_max_bytes() -> u64 {
    67_108_864
}
fn d_ack_timeout_ms() -> u64 {
    30_000
}
fn d_backoff_min_ms() -> u64 {
    500
}
fn d_backoff_max_ms() -> u64 {
    30_000
}
fn d_keepalive_ms() -> u64 {
    15_000
}
fn d_keepalive_timeout_ms() -> u64 {
    45_000
}
fn d_max_in_flight() -> usize {
    1
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            server: String::new(),
            batch_max_events: d_batch_max_events(),
            batch_max_bytes: d_batch_max_bytes(),
            flush_interval_ms: d_flush_interval_ms(),
            ring_capacity: d_ring_capacity(),
            spill_max_bytes: d_spill_max_bytes(),
            ack_timeout_ms: d_ack_timeout_ms(),
            backoff_min_ms: d_backoff_min_ms(),
            backoff_max_ms: d_backoff_max_ms(),
            keepalive_ms: d_keepalive_ms(),
            keepalive_timeout_ms: d_keepalive_timeout_ms(),
            max_in_flight: d_max_in_flight(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_applied_to_partial_toml() {
        // Only `server` is provided; everything else must take its default.
        let v: TransportConfig =
            serde_json::from_value(serde_json::json!({ "server": "https://h:1" })).unwrap();
        assert_eq!(v.server, "https://h:1");
        assert_eq!(v.batch_max_events, 512);
        assert_eq!(v.max_in_flight, 1);
        assert_eq!(v.keepalive_timeout_ms, 45_000);
    }

    #[test]
    fn null_config_yields_default() {
        // Mirrors PluginContext::config_as on an absent subtree.
        let v = TransportConfig::default();
        assert!(v.server.is_empty());
        assert_eq!(v.ring_capacity, 50_000);
    }

    #[test]
    fn parse_server_url_variants() {
        assert_eq!(
            parse_server_url("https://host:9000").unwrap(),
            ("host".into(), 9000)
        );
        assert_eq!(
            parse_server_url("host:1234").unwrap(),
            ("host".into(), 1234)
        );
        assert_eq!(
            parse_server_url("https://only-host").unwrap(),
            ("only-host".into(), 8443)
        );
        assert_eq!(
            parse_server_url("only-host").unwrap(),
            ("only-host".into(), 8443)
        );
        // http:// is always rejected (TLS-only transport); shared by actor + enroll.
        assert!(
            parse_server_url("http://h:443/").is_err(),
            "http:// must be rejected"
        );
        assert!(parse_server_url("").is_err());
        assert!(parse_server_url("https://host:notaport").is_err());
    }

    #[test]
    fn host_facts_are_nonempty_and_stable() {
        let (h1, o1) = host_facts();
        let (h2, o2) = host_facts();
        assert!(!h1.is_empty() && !o1.is_empty());
        // Pure reads of /proc: identical across calls within a run.
        assert_eq!((h1, o1), (h2, o2));
    }
}
