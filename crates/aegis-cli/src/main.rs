//! # aegisctl — Aegis management CLI
//!
//! Operator-facing control plane. The foundation ships plugin introspection
//! (which proves static discovery works end-to-end); enrollment, status, and
//! query subcommands are completed by the transport/server workflows.

use aegis_core::{Host, HostConfig};
use clap::{Parser, Subcommand};

// Link all plugins so discovery enumerates the complete set.
use plugin_agent_detect as _;
use plugin_process as _;
use plugin_scoring as _;
use plugin_session as _;
use plugin_tamper as _;

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Plugins { json } => {
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
        Command::Version => {
            println!("aegisctl {}", env!("CARGO_PKG_VERSION"));
            println!("plugin API version {}", aegis_sdk::PLUGIN_API_VERSION);
            println!("wire protocol version {}", aegis_proto::PROTO_VERSION);
            Ok(())
        }
    }
}
