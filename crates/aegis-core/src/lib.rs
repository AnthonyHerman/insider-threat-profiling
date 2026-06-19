//! # aegis-core
//!
//! The Aegis kernel. It is intentionally feature-free: it knows how to discover
//! plugins (statically via [`inventory`] and dynamically via shared objects),
//! wire them onto a single [event bus](bus), manage their lifecycle, and route
//! events according to each plugin's subscriptions. Detection, scoring,
//! telemetry, transport, storage, and self-protection all live in plugins.
//!
//! ```no_run
//! use aegis_core::{Host, HostConfig};
//! # async fn run() -> anyhow::Result<()> {
//! let config = HostConfig::new("endpoint-42");
//! let host = Host::discover(config)?;       // pull in all built-in plugins
//! let running = host.run().await?;          // init + start the runtime
//! // ... feed events via running.emit(...) or let collector plugins produce ...
//! running.shutdown().await?;
//! # Ok(()) }
//! ```

pub mod bus;
pub mod config;
pub mod host;
pub mod loader;

pub use bus::BusEmitter;
pub use config::{DynamicPluginSpec, HostConfig};
pub use host::{Host, HostBuilder, RunningHost};
pub use loader::{load_dynamic, DynamicPlugin};

// Re-export the SDK so downstream binaries can depend on a single crate.
pub use aegis_sdk;
