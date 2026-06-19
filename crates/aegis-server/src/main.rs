//! # aegisd — the Aegis server
//!
//! A single, self-contained binary. It runs the plugin host with the central
//! processors (agent-vs-human detection, risk scoring), ingests telemetry from
//! enrolled agents, persists it to an embedded store, and serves an operator
//! dashboard. Storage, the TLS ingest listener, and the dashboard are layered in
//! by the server workflow as additional plugins/modules; this foundation wires
//! the host and central processing.
//!
//! "Self-contained" is a hard design constraint: no external database, no
//! runtime asset directory — the embedded store and dashboard assets are
//! compiled in, and the binary targets static linking (musl). See `BUILD.md`.

use aegis_core::{Host, HostConfig};
use clap::{Parser, Subcommand};

// Central processors linked into the server.
use plugin_agent_detect as _;
use plugin_scoring as _;

#[derive(Parser)]
#[command(name = "aegisd", version, about = "Aegis server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Run(RunArgs),
    /// Print the list of central processors that would run.
    Plugins,
}

#[derive(Parser)]
struct RunArgs {
    /// Address for the TLS ingest listener (agents connect here).
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,
    /// Address for the operator dashboard / HTTP API.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http: String,
    /// Directory for the embedded store and TLS material.
    #[arg(long, default_value = "./data/server")]
    data_dir: String,
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
        Command::Plugins => {
            let host = Host::discover(HostConfig::new("aegisd"))?;
            for m in host.metadata() {
                println!(
                    "{:22} {:10?} v{}  {}",
                    m.name, m.kind, m.version, m.description
                );
            }
            Ok(())
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let mut config = HostConfig::new("aegisd");
    config.data_dir = args.data_dir.clone().into();
    // The server does not collect local telemetry; it processes ingested events.
    let host = Host::discover(config)?;
    tracing::info!(
        plugins = ?host.plugin_names(),
        listen = %args.listen,
        http = %args.http,
        "starting aegisd (ingest listener + dashboard added by server workflow)"
    );

    let running = host.run().await?;
    tracing::info!("aegisd running; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    running.shutdown().await?;
    Ok(())
}
