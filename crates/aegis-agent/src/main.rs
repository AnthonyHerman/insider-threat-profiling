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
use aegis_sdk::{Event, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions};
use async_trait::async_trait;
use clap::{Parser, Subcommand};

// Force-link the built-in plugins so their registrations are included.
use plugin_process as _;
use plugin_session as _;
use plugin_tamper as _;

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
struct InstallArgs {
    #[arg(long, default_value = "/usr/local/sbin/aegis-agent")]
    install_path: String,
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    server: String,
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
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let mut config = match &args.config {
        Some(path) => HostConfig::from_toml_file(path)?,
        None => HostConfig::new(&args.agent_id),
    };
    config.data_dir = args.data_dir.clone().into();
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
