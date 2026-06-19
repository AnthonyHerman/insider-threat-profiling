//! # aegisctl — Aegis management CLI
//!
//! Operator-facing control plane. Two families of subcommands:
//!
//! * **Offline introspection** — [`Command::Plugins`] and [`Command::Version`]
//!   load the in-process plugin set and print build facts; they need no running
//!   server.
//! * **Server control** — [`Command::EnrollToken`], [`Command::Status`],
//!   [`Command::Agents`], and [`Command::Alerts`] talk to a running `aegisd`'s
//!   loopback operator API (default `http://127.0.0.1:8080`). They speak plain
//!   HTTP/1.1 over a [`tokio::net::TcpStream`] via the tiny in-crate [`http`]
//!   client — no `reqwest`/TLS dependency, matching the project's self-contained
//!   ethos and the API's loopback-only posture.
//!
//! Every server subcommand accepts `--server <URL>` (or its host:port) and
//! `--json` to pass the raw API response through verbatim (pretty-printed),
//! mirroring the existing `plugins --json` convention.

use aegis_core::{Host, HostConfig};
use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};

// Link all plugins so discovery enumerates the complete set.
use plugin_agent_detect as _;
use plugin_process as _;
use plugin_scoring as _;
use plugin_session as _;
use plugin_tamper as _;

mod http;

#[derive(Parser)]
#[command(name = "aegisctl", version, about = "Aegis management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all discovered plugins and their roles.
    Plugins {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show platform version information.
    Version,
    /// Manage one-time agent enrollment tokens.
    #[command(subcommand)]
    EnrollToken(EnrollTokenCommand),
    /// Show the server's identity (cert fingerprint, protocol version, agent count).
    Status(ServerArgs),
    /// List enrolled agents.
    Agents(ServerArgs),
    /// List recent alerts.
    Alerts(AlertsArgs),
}

/// Enrollment-token lifecycle, all against `GET/POST/DELETE /api/v1/tokens`.
#[derive(Subcommand)]
enum EnrollTokenCommand {
    /// Mint a new one-time enrollment token and print it with the server's
    /// certificate fingerprint (pin this on the agent).
    Create {
        /// Human-readable label for the token (e.g. the target hostname).
        #[arg(long, default_value = "")]
        label: String,
        #[command(flatten)]
        server: ServerArgs,
    },
    /// List all enrollment tokens and whether each has been consumed.
    List(ServerArgs),
    /// Revoke an unused enrollment token.
    Revoke {
        /// The token to revoke (the 64-char hex string from `create`).
        token: String,
        #[command(flatten)]
        server: ServerArgs,
    },
}

/// Shared connection flags for every server-facing subcommand.
#[derive(Args, Clone)]
struct ServerArgs {
    /// Server operator API base URL or host:port (default loopback).
    #[arg(long, default_value = "http://127.0.0.1:8080", global = true)]
    server: String,
    /// Emit the raw API JSON (pretty-printed) instead of a table.
    #[arg(long, global = true)]
    json: bool,
}

/// `alerts` adds server-side filter flags on top of [`ServerArgs`].
#[derive(Args, Clone)]
struct AlertsArgs {
    /// Maximum number of alerts to return.
    #[arg(long)]
    limit: Option<usize>,
    /// Only alerts with this severity (e.g. `critical`, `high`).
    #[arg(long)]
    severity: Option<String>,
    /// Only alerts that have not been acknowledged.
    #[arg(long)]
    unacknowledged: bool,
    #[command(flatten)]
    server: ServerArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Plugins { json } => cmd_plugins(json),
        Command::Version => cmd_version(),
        Command::EnrollToken(sub) => cmd_enroll_token(sub).await,
        Command::Status(args) => cmd_status(args).await,
        Command::Agents(args) => cmd_agents(args).await,
        Command::Alerts(args) => cmd_alerts(args).await,
    }
}

// --- Offline subcommands --------------------------------------------------

fn cmd_plugins(json: bool) -> anyhow::Result<()> {
    let host = Host::discover(HostConfig::new("aegisctl"))?;
    let meta = host.metadata();
    if json {
        let arr: Vec<_> = meta
            .iter()
            .map(|m| {
                serde_json::json!({
                    "name": m.name,
                    "version": m.version,
                    "kind": format!("{:?}", m.kind),
                    "api_version": m.api_version,
                    "description": m.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        println!("{:24} {:10} {:8} DESCRIPTION", "NAME", "KIND", "VERSION");
        for m in meta {
            println!(
                "{:24} {:10} {:8} {}",
                m.name,
                format!("{:?}", m.kind),
                m.version,
                m.description
            );
        }
    }
    Ok(())
}

fn cmd_version() -> anyhow::Result<()> {
    println!("aegisctl {}", env!("CARGO_PKG_VERSION"));
    println!("plugin API version {}", aegis_sdk::PLUGIN_API_VERSION);
    println!("wire protocol version {}", aegis_proto::PROTO_VERSION);
    Ok(())
}

// --- Server subcommands ---------------------------------------------------

async fn cmd_enroll_token(sub: EnrollTokenCommand) -> anyhow::Result<()> {
    match sub {
        EnrollTokenCommand::Create { label, server } => {
            let body = serde_json::json!({ "label": label });
            let resp = http::post_json(&server.server, "/api/v1/tokens", &body).await?;
            let v = resp.json_ok()?;
            if server.json {
                print_json(&v);
            } else {
                let token = v["token"].as_str().unwrap_or("");
                let fingerprint = v["fingerprint"].as_str().unwrap_or("");
                println!("token:       {token}");
                println!("fingerprint: {fingerprint}");
                println!();
                println!("Pin the fingerprint on the agent, then enroll with the token above.");
            }
            Ok(())
        }
        EnrollTokenCommand::List(server) => {
            let resp = http::get(&server.server, "/api/v1/tokens").await?;
            let v = resp.json_ok()?;
            if server.json {
                print_json(&v);
            } else {
                let rows = v.as_array().cloned().unwrap_or_default();
                println!(
                    "{:64}  {:6}  {:20}  CREATED_AT_NS",
                    "TOKEN", "USED", "LABEL"
                );
                for r in rows {
                    println!(
                        "{:64}  {:6}  {:20}  {}",
                        r["token"].as_str().unwrap_or(""),
                        r["used"].as_bool().unwrap_or(false),
                        truncate(r["label"].as_str().unwrap_or(""), 20),
                        r["created_at_ns"].as_u64().unwrap_or(0),
                    );
                }
            }
            Ok(())
        }
        EnrollTokenCommand::Revoke { token, server } => {
            let path = format!("/api/v1/tokens/{token}");
            let resp = http::delete(&server.server, &path).await?;
            if server.json {
                // No body on 204; synthesize a small status object for scripts.
                print_json(&serde_json::json!({
                    "status": resp.status,
                    "revoked": resp.status == 204,
                }));
                return Ok(());
            }
            match resp.status {
                204 => {
                    println!("revoked");
                    Ok(())
                }
                409 => {
                    println!("already used or unknown");
                    Ok(())
                }
                _ => bail!("{}", resp.error_detail()),
            }
        }
    }
}

async fn cmd_status(args: ServerArgs) -> anyhow::Result<()> {
    let resp = http::get(&args.server, "/api/v1/server-info").await?;
    let info = resp.json_ok()?;
    // Best-effort agent count; a server-info call succeeding implies the API is
    // up, so a failure here is unexpected, but we keep status resilient.
    let agent_count = match http::get(&args.server, "/api/v1/agents").await {
        Ok(r) if r.status == 200 => r.json().ok().and_then(|v| v.as_array().map(|a| a.len())),
        _ => None,
    };

    if args.json {
        let mut out = info.clone();
        if let (Some(obj), Some(n)) = (out.as_object_mut(), agent_count) {
            obj.insert("agent_count".into(), serde_json::json!(n));
        }
        print_json(&out);
    } else {
        println!(
            "fingerprint:    {}",
            info["fingerprint"].as_str().unwrap_or("")
        );
        println!(
            "proto version:  {}",
            info["proto_version"].as_u64().unwrap_or(0)
        );
        match agent_count {
            Some(n) => println!("agents:         {n}"),
            None => println!("agents:         (unavailable)"),
        }
    }
    Ok(())
}

async fn cmd_agents(args: ServerArgs) -> anyhow::Result<()> {
    let resp = http::get(&args.server, "/api/v1/agents").await?;
    let v = resp.json_ok()?;
    if args.json {
        print_json(&v);
    } else {
        let rows = v.as_array().cloned().unwrap_or_default();
        println!(
            "{:36}  {:24}  {:10}  LAST_SEEN_NS",
            "AGENT_ID", "HOSTNAME", "OS"
        );
        for r in rows {
            println!(
                "{:36}  {:24}  {:10}  {}",
                r["agent_id"].as_str().unwrap_or(""),
                truncate(r["hostname"].as_str().unwrap_or(""), 24),
                truncate(r["os"].as_str().unwrap_or(""), 10),
                r["last_seen_ns"].as_u64().unwrap_or(0),
            );
        }
    }
    Ok(())
}

async fn cmd_alerts(args: AlertsArgs) -> anyhow::Result<()> {
    let mut query: Vec<(String, String)> = Vec::new();
    if let Some(limit) = args.limit {
        query.push(("limit".into(), limit.to_string()));
    }
    if let Some(sev) = &args.severity {
        query.push(("severity".into(), sev.clone()));
    }
    if args.unacknowledged {
        query.push(("acknowledged".into(), "false".into()));
    }
    let path = with_query("/api/v1/alerts", &query);

    let resp = http::get(&args.server.server, &path).await?;
    let v = resp.json_ok()?;
    if args.server.json {
        print_json(&v);
    } else {
        let rows = v.as_array().cloned().unwrap_or_default();
        println!(
            "{:10}  {:30}  {:36}  {:5}  TS_NS",
            "SEVERITY", "TITLE", "AGENT_ID", "ACK"
        );
        for r in rows {
            println!(
                "{:10}  {:30}  {:36}  {:5}  {}",
                truncate(r["severity"].as_str().unwrap_or(""), 10),
                truncate(r["title"].as_str().unwrap_or(""), 30),
                r["agent_id"].as_str().unwrap_or(""),
                r["acknowledged"].as_bool().unwrap_or(false),
                r["ts_ns"].as_u64().unwrap_or(0),
            );
        }
    }
    Ok(())
}

// --- Small helpers --------------------------------------------------------

/// Pretty-print a JSON value to stdout (used by every `--json` path).
fn print_json(v: &serde_json::Value) {
    // Serialization of an already-parsed `Value` cannot fail; fall back to the
    // compact form defensively rather than panicking.
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{v}"),
    }
}

/// Truncate a string to `max` columns, appending `…` when it overflows, so the
/// fixed-width tables stay aligned regardless of field length.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Append a `?k=v&...` query string to `path`, percent-encoding values. Returns
/// `path` unchanged when there are no pairs.
fn with_query(path: &str, pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return path.to_string();
    }
    let mut out = String::from(path);
    out.push('?');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}

/// Minimal percent-encoding for query components: keep the RFC 3986 unreserved
/// set verbatim, hex-escape everything else. Enough for severities, limits, and
/// the booleans we send — we never put untrusted bytes here, but encode anyway
/// so a label with spaces/`&` cannot break the query.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl http::Response {
    /// Parse the body as JSON, requiring a 2xx status first. On a non-2xx status
    /// this surfaces the server's `{"error":...}` detail (or the raw body) as the
    /// error, so CLI failures are actionable.
    fn json_ok(&self) -> anyhow::Result<serde_json::Value> {
        if !(200..300).contains(&self.status) {
            bail!("{}", self.error_detail());
        }
        self.json()
    }

    /// Parse the body as JSON without status checking.
    fn json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::from_slice(&self.body).context("server returned invalid JSON")
    }

    /// A human-readable error line for a non-2xx response: prefer the API's
    /// `{"error":"..."}` message, falling back to a status + raw-body summary.
    fn error_detail(&self) -> String {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&self.body) {
            if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
                return format!("server error ({}): {msg}", self.status);
            }
        }
        let body = String::from_utf8_lossy(&self.body);
        let body = body.trim();
        if body.is_empty() {
            format!("server returned HTTP {}", self.status)
        } else {
            format!(
                "server returned HTTP {}: {}",
                self.status,
                truncate(body, 200)
            )
        }
    }
}
