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

// Server data-path modules: the embedded store, the TLS ingest listener,
// enrollment, the store sink, the live command router, the HTTP/JSON operator
// API, and the embedded dashboard assets. `run()` does not exercise every item
// directly (some read-path/CRUD methods are reached only over HTTP, and the
// session-auth helpers only from the ingest state machine), so a few `dead_code`
// allows remain on the modules whose surface is wider than `run()` touches.
#[allow(dead_code)]
mod api;
mod dashboard;
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
    // Cloned into each ingest connection task and the HTTP AppState.
    let router = registry::Router::new();

    // Live-event fan-out for the SSE feed: the store sink publishes derived
    // events onto it; the HTTP `/api/v1/live` handler subscribes. The retained
    // sender lives in `AppState`; the initial receiver is dropped (subscribers
    // are created per connection).
    let (live_tx, _) =
        tokio::sync::broadcast::channel::<api::LiveEvent>(api::LIVE_CHANNEL_CAPACITY);

    // Bootstrap (or load) the server TLS cert once here so its SHA-256 pin — the
    // value agents pin and `/api/v1/server-info` exposes — is available for
    // `AppState`. `ingest::serve` loads the same (now-existing) PEM idempotently.
    let (_chain, _key, pin) = ingest::load_or_create_server_cert(&data_dir)?;
    let server_info = api::ServerInfo {
        fingerprint: hex::encode(pin),
        proto_version: aegis_proto::PROTO_VERSION,
    };

    let mut config = HostConfig::new("aegisd");
    config.data_dir = data_dir.clone();
    // The server does not collect local telemetry; it processes ingested events.
    // Build the host with the store sink as an explicit plugin (highest
    // precedence), while keeping discovery of the statically-linked central
    // processors (agent-vs-human detection, risk scoring) on by default. The
    // sink also publishes each derived event onto the live SSE channel.
    let host = HostBuilder::new(config)
        .with_plugin(Box::new(sink::StoreSink::new(
            store.clone(),
            live_tx.clone(),
        )))
        .build()?;
    tracing::info!(
        plugins = ?host.plugin_names(),
        listen = %args.listen,
        http = %args.http,
        "starting aegisd (ingest listener + HTTP API/dashboard)"
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
        store.clone(),
        router.clone(),
    )?;

    // Spawn the operator HTTP API + embedded dashboard on the loopback address.
    // It is read-mostly over the shared store, dispatches commands via the live
    // router, and serves the SSE feed off `live_tx`.
    let state = api::AppState {
        store,
        router,
        live_tx,
        server_info,
    };
    let http_handle = api::serve(args.http.clone(), state).await?;
    tracing::info!(http = %args.http, "HTTP API/dashboard listening");

    tracing::info!("aegisd running; press Ctrl-C to stop");
    // While running, periodically surface bus-loss counters so event loss is
    // observable (the counters exist precisely so loss is "alertable rather than
    // merely a log line"). Logged as a delta against the last sweep to avoid spam;
    // the loop ends as soon as Ctrl-C fires, after which we shut down.
    {
        let metrics = running.bus_metrics();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.tick().await; // consume the immediate first tick
        let mut last_ingress = metrics.ingress_dropped();
        let mut last_fanout = metrics.fanout_dropped();
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = ticker.tick() => {
                    let ingress = metrics.ingress_dropped();
                    let fanout = metrics.fanout_dropped();
                    if ingress > last_ingress || fanout > last_fanout {
                        tracing::warn!(
                            ingress_dropped = ingress,
                            fanout_dropped = fanout,
                            ingress_delta = ingress - last_ingress,
                            fanout_delta = fanout - last_fanout,
                            "aegisd: bus dropped events since last report"
                        );
                        last_ingress = ingress;
                        last_fanout = fanout;
                    }
                }
            }
        }
    }
    tracing::info!("shutting down aegisd");

    // Stop the network ingress (TLS ingest) and the HTTP server first so no new
    // events arrive on the bus and no new HTTP requests are served, then drain
    // and shut down the host (which also stops the sink's retention task via the
    // shutdown signal). The store's file lock is released when the last
    // `Arc<Store>` clone drops at end of run.
    ingest_handle.abort();
    let _ = ingest_handle.await;
    http_handle.abort();
    let _ = http_handle.await;
    running.shutdown().await?;
    Ok(())
}
