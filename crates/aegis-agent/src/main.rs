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
            let spec = plugin_tamper::install::InstallSpec {
                install_path: args.install_path,
                server_url: args.server,
                ..Default::default()
            };
            // Show the units that are being installed (useful for the operator).
            println!(
                "--- aegis-agent.service ---\n{}",
                plugin_tamper::install::render_service_unit(&spec)
            );
            println!(
                "--- aegis-guardian.service ---\n{}",
                plugin_tamper::install::render_guardian_unit(&spec)
            );
            // Perform the privileged install (copy, write units, daemon-reload,
            // enable --now, set immutable). Requires root; errors are surfaced.
            plugin_tamper::install::install(&spec)?;
            println!(
                "Installed {}; units enabled and protected files made immutable.",
                spec.install_path
            );
            Ok(())
        }
        Command::Uninstall => {
            // Paths default to the install layout; uninstall reads the install
            // token to target the exact installed paths. Requires root (uid 0):
            // the authenticated administrator escape hatch.
            let spec = plugin_tamper::install::InstallSpec::default();
            plugin_tamper::install::uninstall(&spec)?;
            println!("Uninstalled aegis-agent (immutable cleared, units disabled, files removed).");
            Ok(())
        }
        Command::Guard { service } => {
            tracing::info!(service, "guardian mode: watching service liveness");
            // Blocks forever, reviving the service if systemd reports it inactive.
            plugin_tamper::install::guard(&service, std::time::Duration::from_secs(2));
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

    // Wire the tamper plugin to the standard hardened-install layout so the
    // immutable-bit watch, the missing-file fallback, and the startup
    // "files not immutable" posture check are all live in the deployed service.
    // Without this, `run` (the unit's ExecStart) leaves `protected_paths` empty,
    // so only the manifest content-check runs and the immutable bit is never
    // verified at runtime. The operator can still override either field via a
    // `--config` TOML: we only fill keys that are absent.
    //
    // Gated on running as root (the deployed posture): an unprivileged dev `run`
    // has no hardened files on disk, and asserting that layout would only emit
    // spurious "protected path missing" alerts — the posture self-check already
    // reports the weak non-root deployment on its own.
    if plugin_tamper::posture().is_root {
        inject_tamper_defaults(&mut config);
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

/// Populate `plugin-tamper`'s `protected_paths` / `manifest_path` from the
/// canonical hardened-install layout, without clobbering anything the operator
/// already set in a `--config` TOML.
///
/// The installer ([`plugin_tamper::install::install`]) hashes and locks exactly
/// the binary plus both unit files and writes the manifest to the state dir; the
/// runtime tamper loop only watches the immutable bit and the existence of paths
/// listed in `protected_paths`. Deriving both from the same [`InstallSpec`] the
/// installer uses keeps the install-time and run-time views in lockstep, so the
/// loop's immutable-bit and missing-file checks (and the startup immutability
/// posture check) actually cover the deployed files.
fn inject_tamper_defaults(config: &mut HostConfig) {
    use plugin_tamper::install::InstallSpec;

    let spec = InstallSpec::default();
    let entry = config
        .plugins
        .entry("plugin-tamper".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(obj) = entry.as_object_mut() else {
        return;
    };
    if !obj.contains_key("protected_paths") {
        let paths: Vec<String> = spec
            .protected_paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        obj.insert("protected_paths".to_string(), serde_json::json!(paths));
    }
    if !obj.contains_key("manifest_path") {
        obj.insert(
            "manifest_path".to_string(),
            serde_json::Value::String(spec.manifest_path().display().to_string()),
        );
    }
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
    // Shared with the forwarder actor so enroll and the running forwarder accept
    // exactly the same inputs (notably both reject an http:// URL).
    let (host, port) = plugin_transport::config::parse_server_url(&args.server)?;

    // Pinned TLS connect.
    let client_cfg = tls::client_config(vec![pin]);
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let server_name = ServerName::try_from(host.clone())
        .unwrap_or_else(|_| ServerName::try_from("server.aegis.local").unwrap());
    let mut tls = tls::connect(client_cfg, server_name, tcp)
        .await
        .context("TLS handshake failed (server cert pin mismatch?)")?;

    // Enroll exchange. Host facts come from the shared helper so the
    // `EnrollRequest` reports identical hostname/os to the later `ClientHello`.
    let (hostname, os) = plugin_transport::config::host_facts();
    let req = Message::EnrollRequest {
        token,
        hostname,
        os,
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

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_tamper::install::InstallSpec;
    use plugin_tamper::TamperConfig;

    #[test]
    fn inject_tamper_defaults_wires_the_install_layout() {
        let mut config = HostConfig::new("agent-test");
        inject_tamper_defaults(&mut config);

        // The injected subtree must deserialize into the plugin's own config type
        // and cover exactly the hardened-install paths (binary + both units) plus
        // the standard manifest path the installer writes.
        let subtree = config.plugin_config("plugin-tamper");
        let cfg: TamperConfig = serde_json::from_value(subtree).expect("tamper subtree");
        let spec = InstallSpec::default();
        assert_eq!(cfg.protected_paths, spec.protected_paths());
        assert_eq!(cfg.protected_paths.len(), 3);
        assert_eq!(cfg.manifest_path, Some(spec.manifest_path()));
    }

    #[test]
    fn inject_tamper_defaults_does_not_override_operator_config() {
        // An operator who pins paths/manifest in a --config TOML must win.
        let mut config = HostConfig::new("agent-test");
        config.plugins.insert(
            "plugin-tamper".to_string(),
            serde_json::json!({
                "protected_paths": ["/custom/agent"],
                "manifest_path": "/custom/manifest.json",
            }),
        );
        inject_tamper_defaults(&mut config);

        let cfg: TamperConfig =
            serde_json::from_value(config.plugin_config("plugin-tamper")).expect("tamper subtree");
        assert_eq!(
            cfg.protected_paths,
            vec![std::path::PathBuf::from("/custom/agent")]
        );
        assert_eq!(
            cfg.manifest_path,
            Some(std::path::PathBuf::from("/custom/manifest.json"))
        );
    }

    #[test]
    fn inject_tamper_defaults_fills_only_missing_keys() {
        // A partial operator config (paths only) still gets the manifest filled in.
        let mut config = HostConfig::new("agent-test");
        config.plugins.insert(
            "plugin-tamper".to_string(),
            serde_json::json!({ "protected_paths": ["/only/this"] }),
        );
        inject_tamper_defaults(&mut config);

        let cfg: TamperConfig =
            serde_json::from_value(config.plugin_config("plugin-tamper")).expect("tamper subtree");
        assert_eq!(
            cfg.protected_paths,
            vec![std::path::PathBuf::from("/only/this")]
        );
        assert_eq!(
            cfg.manifest_path,
            Some(InstallSpec::default().manifest_path())
        );
    }
}
