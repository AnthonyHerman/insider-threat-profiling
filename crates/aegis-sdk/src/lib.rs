//! # aegis-sdk
//!
//! Stable contracts shared across the entire Aegis platform: the [`event`]
//! model and the [`plugin`] trait/registration machinery. Both the kernel
//! (`aegis-core`), every feature plugin, and the binaries depend only on these
//! contracts, which keeps the core free of any feature-specific knowledge.
//!
//! See the crate-level docs of each module for detail. The two ideas to hold in
//! mind:
//!
//! * **Everything is an [`Event`].** Telemetry, derived signals, scores,
//!   detections, and alerts all share one envelope and travel one bus.
//! * **Everything is a [`Plugin`].** The core orchestrates plugins; it
//!   implements no features itself.

pub mod event;
pub mod plugin;

// Re-export inventory so the `register_plugin!` macro works in downstream crates
// without them needing a direct dependency on `inventory`.
pub use inventory;

pub use event::{now_ns, AgentId, Event, EventPayload, SessionId, Severity, Verdict};
pub use plugin::{
    DynEntry, DynPluginRegistration, Emitter, Plugin, PluginConstructor, PluginContext, PluginKind,
    PluginMetadata, PluginRegistration, Subscriptions, DYN_ENTRY_SYMBOL, PLUGIN_API_VERSION,
};
