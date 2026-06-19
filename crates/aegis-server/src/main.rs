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

use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::{Host, HostBuilder, HostConfig};
use clap::{Parser, Subcommand};

// Server data-path modules. The embedded store, TLS ingest listener,
// enrollment, the store sink, and the live command router land here; the HTTP
// API is layered in by its own workflow. `run()` does not yet reference every
// item (e.g. token CRUD and the read path are consumed by the future HTTP API),
// so allow dead code until those callers land.
#[allow(dead_code)]
mod enroll;
#[allow(dead_code)]
mod ingest;
#[allow(dead_code)]
mod registry;
mod sink;
#[allow(dead_code)]
mod store;

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
    let data_dir = PathBuf::from(&args.data_dir);

    // Open the embedded datastore before the host so the store sink can hold a
    // shared handle; ingest and the (future) HTTP read path share the same one.
    let store = Arc::new(store::Store::open(&data_dir)?);

    // The in-memory live-connection table: connected agent_id -> command channel.
    // Cloned into each ingest connection task (and, later, the HTTP AppState).
    let router = registry::Router::new();

    let mut config = HostConfig::new("aegisd");
    config.data_dir = data_dir.clone();
    // The server does not collect local telemetry; it processes ingested events.
    // Build the host with the store sink as an explicit plugin (highest
    // precedence), while keeping discovery of the statically-linked central
    // processors (agent-vs-human detection, risk scoring) on by default.
    let host = HostBuilder::new(config)
        .with_plugin(Box::new(sink::StoreSink::new(store.clone())))
        .build()?;
    tracing::info!(
        plugins = ?host.plugin_names(),
        listen = %args.listen,
        http = %args.http,
        "starting aegisd (ingest listener up; dashboard added by HTTP workflow)"
    );

    // Start the host: spawns the dispatcher + per-plugin tasks (including the
    // sink's retention task) and exposes the bus emitter.
    let running = host.run().await?;

    // Spawn the TLS ingest listener. It writes raw telemetry to the store and
    // feeds it onto the host bus via the emitter; derived events the processors
    // produce are persisted by the store sink above.
    let ingest_handle = ingest::serve(
        args.listen.clone(),
        data_dir,
        running.emitter(),
        store,
        router.clone(),
    )?;

    // NOTE: the HTTP API + dashboard are wired by a separate workflow:
    //   let http_handle = api::serve(args.http, AppState { store, router, .. })?;
    // Until then, the --http flag is accepted but unused; surface that.
    tracing::warn!(
        http = %args.http,
        "HTTP API/dashboard not yet wired; --http is currently unused"
    );

    tracing::info!("aegisd running; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down aegisd");

    // Stop the network listener and its in-flight connection tasks first so no
    // new events arrive on the bus, then drain and shut down the host (which
    // also stops the sink's retention task via the shutdown signal). The store's
    // file lock is released when the last `Arc<Store>` clone drops at end of run.
    ingest_handle.abort();
    let _ = ingest_handle.await;
    running.shutdown().await?;
    Ok(())
}
