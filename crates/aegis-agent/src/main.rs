//! # aegis-agent
//!
//! The endpoint agent. It runs the plugin host with the collector and
//! self-protection plugins, producing behavioral telemetry that the forwarder
//! relays to the server. It also provides the tamper-resistant install lifecycle
//! (`install` / `uninstall` / `guard`).
//!
//! Built-in plugins are linked via `use plugin_x as _;` so their
//! `inventory`-based registrations are present for static discovery.

use aegis_core::{HostBuilder, HostConfig};
use aegis_sdk::{Emitter, Event, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions};
use anyhow::Context;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use std::sync::Arc;

// Force-link the built-in plugins so their registrations are included.
use plugin_process as _;
use plugin_session as _;
use plugin_tamper as _;
use plugin_transport as _;
use plugin_tty as _;

#[derive(Parser)]
#[command(name = "aegis-agent", version, about = "Aegis endpoint agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent (default operational mode).
    Run(RunArgs),
    /// Install the agent as a tamper-resistant service (requires root).
    Install(InstallArgs),
    /// Remove the agent (requires root; the authenticated uninstall path).
    Uninstall,
    /// Guardian mode: keep the agent service alive (invoked by the watchdog unit).
    Guard {
        #[arg(long, default_value = "aegis-agent")]
        service: String,
    },
    /// Enroll this endpoint with the server: generate a per-agent key, present a
    /// one-time token, and persist the assigned identity + server cert pin.
    Enroll(EnrollArgs),
    /// Run an instrumented interactive shell: your $SHELL inside a PTY,
    /// emitting content-free behavioral telemetry (timing/structure only).
    Shell(ShellArgs),
}

#[derive(Parser)]
struct RunArgs {
    /// Path to a TOML host configuration file (optional).
    #[arg(long)]
    config: Option<String>,
    /// Stable identity for this endpoint.
    #[arg(long, env = "AEGIS_AGENT_ID", default_value = "agent-local")]
    agent_id: String,
    /// Directory for plugin state.
    #[arg(long, default_value = "./data/agent")]
    data_dir: String,
    /// Server URL to report to (used once the forwarder is enabled).
    #[arg(long, env = "AEGIS_SERVER", default_value = "https://127.0.0.1:8443")]
    server: String,
    /// Print every event to stdout (development aid).
    #[arg(long)]
    print_events: bool,
}

#[derive(Parser)]
struct EnrollArgs {
    /// Server URL to enroll with.
    #[arg(long, env = "AEGIS_SERVER", default_value = "https://127.0.0.1:8443")]
    server: String,
    /// Directory for plugin state (the identity is written under
    /// `<data_dir>/plugin-transport/`, where the forwarder reads it).
    #[arg(long, default_value = "./data/agent")]
    data_dir: String,
    /// One-time enrollment token. WARNING: a token on argv is visible to other
    /// local users via `/proc/<pid>/cmdline`; prefer `--token-file`/`--enroll-blob`.
    #[arg(long)]
    token: Option<String>,
    /// Read the one-time token from a file (mode 0600) instead of argv.
    #[arg(long)]
    token_file: Option<String>,
    /// Server certificate pin as 64-char lowercase hex (required with `--token`).
    #[arg(long)]
    pin: Option<String>,
    /// Read an `AEGIS-ENROLL <base64(token||pin32)>` blob from this file, or `-`
    /// for stdin. Carries both the token and the pin; the secure intake path.
    #[arg(long)]
    enroll_blob: Option<String>,
}

#[derive(Parser)]
struct InstallArgs {
    #[arg(long, default_value = "/usr/local/sbin/aegis-agent")]
    install_path: String,
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    server: String,
}

#[derive(Parser)]
struct ShellArgs {
    /// Stable identity for this endpoint.
    #[arg(long, env = "AEGIS_AGENT_ID", default_value = "agent-local")]
    agent_id: String,
    /// Per-deployment salt for the command-correlation hash.
    #[arg(long, default_value = "aegis-default-salt")]
    hash_salt: String,
    /// Print emitted telemetry events (as JSON) to stderr.
    #[arg(long)]
    print_events: bool,
}

/// A small inline sink that prints events — demonstrates host embedding via
/// `HostBuilder::with_plugin` and is handy when running interactively.
struct ConsoleSink;

#[async_trait]
impl Plugin for ConsoleSink {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "console-sink",
            "1",
            "prints events to stdout",
            PluginKind::Sink,
        )
    }
    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::All
    }
    async fn handle(&self, event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        println!(
            "[{}] {} <- {}",
            event.kind,
            serde_json::to_string(&event.payload).unwrap_or_default(),
            event.source
        );
        Ok(())
    }
}

/// A minimal [`Emitter`] used by the `shell` subcommand. The PTY passthrough
/// owns stdout, so telemetry is written to **stderr** (or dropped) to avoid
/// corrupting the interactive terminal stream.
struct StderrEmitter {
    print: bool,
}

#[async_trait]
impl Emitter for StderrEmitter {
    async fn emit(&self, event: Event) {
        if self.print {
            eprintln!(
                "[{}] {}",
                event.kind,
                serde_json::to_string(&event.payload).unwrap_or_default()
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run(args).await,
        Command::Install(args) => {
            // The privileged installer is completed by the hardening workflow.
            let spec = plugin_tamper::install::InstallSpec {
                install_path: args.install_path,
                server_url: args.server,
                ..Default::default()
            };
            println!(
                "--- aegis-agent.service ---\n{}",
                plugin_tamper::install::render_service_unit(&spec)
            );
            println!(
                "--- aegis-guardian.service ---\n{}",
                plugin_tamper::install::render_guardian_unit(&spec)
            );
            println!(
                "\nGenerated unit files above. Privileged installation (copy, chattr +i, \
                 systemctl enable) is performed by the hardening workflow."
            );
            Ok(())
        }
        Command::Uninstall => {
            println!("Authenticated uninstall is implemented by the hardening workflow.");
            Ok(())
        }
        Command::Guard { service } => {
            tracing::info!(
                service,
                "guardian mode: watchdog implemented by hardening workflow"
            );
            Ok(())
        }
        Command::Enroll(args) => enroll(args).await,
        Command::Shell(args) => shell(args).await,
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let mut config = match &args.config {
        Some(path) => HostConfig::from_toml_file(path)?,
        None => HostConfig::new(&args.agent_id),
    };
    config.data_dir = args.data_dir.clone().into();

    // Inject the agent's --server into the forwarder's config subtree unless the
    // operator already pinned one in the TOML. `plugins` is a name->JSON map;
    // plugin-transport reads `server` from it via config_as.
    let entry = config
        .plugins
        .entry("plugin-transport".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = entry.as_object_mut() {
        if !obj.contains_key("server") {
            obj.insert(
                "server".to_string(),
                serde_json::Value::String(args.server.clone()),
            );
        }
    }

    tracing::info!(agent_id = %config.agent_id, server = %args.server, "starting aegis-agent");

    let mut builder = HostBuilder::new(config).discover_static(true);
    if args.print_events {
        builder = builder.with_plugin(Box::new(ConsoleSink));
    }
    let host = builder.build()?;
    tracing::info!(plugins = ?host.plugin_names(), "loaded plugins");

    let running = host.run().await?;
    tracing::info!("agent running; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    running.shutdown().await?;
    Ok(())
}

/// Run an instrumented interactive shell: spawns `$SHELL` inside a PTY and emits
/// content-free behavioral telemetry. The terminal is put in raw mode for the
/// duration and restored on exit. Telemetry goes to stderr (with
/// `--print-events`) so it does not corrupt the PTY-owned stdout stream.
async fn shell(args: ShellArgs) -> anyhow::Result<()> {
    let emitter: Arc<dyn Emitter> = Arc::new(StderrEmitter {
        print: args.print_events,
    });
    let session_id = plugin_tty::current_session_id();
    let cfg = plugin_tty::AnalyzerConfig {
        hash_salt: args.hash_salt,
    };
    let agent_id = args.agent_id;

    // The PTY pump is blocking; run it off the async runtime and await it.
    tokio::task::spawn_blocking(move || {
        plugin_tty::run_instrumented_shell(emitter, agent_id, session_id, cfg)
    })
    .await??;
    Ok(())
}

/// Resolve the one-time token and server cert pin from the enroll arguments.
///
/// Precedence: an `--enroll-blob` (stdin or file) carries both; otherwise
/// `--token`/`--token-file` supplies the token and `--pin` the hex pin. The
/// secure paths (blob / token-file / stdin) keep the secret off argv.
fn resolve_enroll_secret(args: &EnrollArgs) -> anyhow::Result<(String, [u8; 32])> {
    use std::io::Read;

    if let Some(src) = &args.enroll_blob {
        let mut buf = String::new();
        if src == "-" {
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading enroll blob from stdin")?;
        } else {
            buf = std::fs::read_to_string(src)
                .with_context(|| format!("reading enroll blob file {src}"))?;
        }
        return plugin_transport::identity::parse_enroll_blob(&buf);
    }

    let token = if let Some(path) = &args.token_file {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading token file {path}"))?
            .trim()
            .to_string()
    } else if let Some(t) = &args.token {
        tracing::warn!(
            "a token passed via --token is visible to local users in /proc; \
             prefer --token-file or --enroll-blob"
        );
        t.clone()
    } else {
        anyhow::bail!("provide --enroll-blob, --token-file, or --token");
    };

    let pin_hex = args
        .pin
        .as_deref()
        .context("--pin <hex64> is required when enrolling with --token/--token-file")?;
    let pin = aegis_proto::pin::parse_pin_hex(pin_hex)
        .context("--pin must be 64-char lowercase hex (SHA-256 of the server leaf cert)")?;
    Ok((token, pin))
}

/// Enroll this endpoint: generate an Ed25519 key, connect to the server over a
/// pinned TLS channel, exchange `EnrollRequest`/`EnrollResponse`, and on success
/// persist the assigned identity so the forwarder can use it.
async fn enroll(args: EnrollArgs) -> anyhow::Result<()> {
    use aegis_proto::{read_message, tls, write_message, Message, PROTO_VERSION};
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::pki_types::ServerName;

    let _ = PROTO_VERSION; // documented; EnrollRequest carries no version field.

    let (token, pin) = resolve_enroll_secret(&args)?;

    // Fresh per-agent identity.
    let signing_key = plugin_transport::identity::generate_key();
    let agent_pubkey = signing_key.verifying_key().to_bytes().to_vec();

    // Parse host:port from the server URL (scheme optional, default port 8443).
    let (host, port) = parse_server_url(&args.server)?;

    // Pinned TLS connect.
    let client_cfg = tls::client_config(vec![pin]);
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let server_name =
        ServerName::try_from(host.clone()).unwrap_or_else(|_| ServerName::try_from("server.aegis.local").unwrap());
    let mut tls = tls::connect(client_cfg, server_name, tcp)
        .await
        .context("TLS handshake failed (server cert pin mismatch?)")?;

    // Enroll exchange.
    let req = Message::EnrollRequest {
        token,
        hostname: read_hostname(),
        os: os_descriptor(),
        agent_pubkey,
    };
    write_message(&mut tls, &req)
        .await
        .context("sending EnrollRequest")?;
    let resp = read_message(&mut tls)
        .await
        .context("reading EnrollResponse")?;

    match resp {
        Message::EnrollResponse {
            accepted: true,
            agent_id,
            ..
        } => {
            // The forwarder reads identity from <data_dir>/plugin-transport/.
            let dir = std::path::Path::new(&args.data_dir).join("plugin-transport");
            plugin_transport::identity::persist(&dir, &agent_id, &signing_key, &[pin])
                .context("persisting enrolled identity")?;
            println!("enrolled: agent_id={agent_id}");
            println!("identity written to {}", dir.display());
            Ok(())
        }
        Message::EnrollResponse {
            accepted: false,
            reason,
            ..
        } => {
            anyhow::bail!(
                "enrollment rejected by server: {}",
                reason.unwrap_or_else(|| "no reason given".into())
            );
        }
        other => anyhow::bail!("unexpected response to EnrollRequest: {other:?}"),
    }
}

/// Parse `https://host:port` (scheme optional, port defaults to 8443).
fn parse_server_url(server: &str) -> anyhow::Result<(String, u16)> {
    let s = server
        .trim()
        .strip_prefix("https://")
        .or_else(|| server.trim().strip_prefix("http://"))
        .unwrap_or_else(|| server.trim())
        .trim_end_matches('/');
    if s.is_empty() {
        anyhow::bail!("empty server address");
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port: u16 = p
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port in `{server}`"))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((s.to_string(), 8443)),
    }
}

/// Best-effort hostname for the enroll request.
fn read_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// OS descriptor: platform plus kernel release if available.
fn os_descriptor() -> String {
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
