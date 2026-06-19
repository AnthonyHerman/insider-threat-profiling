//! # plugin-tty
//!
//! Collector plugin for interactive-shell behavioral telemetry, captured via a
//! PTY. It produces the same content-free substrate the agent-vs-human detector
//! consumes: keystroke timing ([`EventPayload::Keystroke`](aegis_sdk::EventPayload::Keystroke))
//! and per-command structural statistics
//! ([`EventPayload::CommandObserved`](aegis_sdk::EventPayload::CommandObserved)).
//!
//! ## Content-free invariant
//!
//! No raw keystrokes or command text are ever stored or emitted. The plugin
//! reconstructs each command line in a transient in-memory buffer purely to
//! compute structural statistics (length, token count, Shannon entropy), an edit
//! distance from the previous line, and a salted hash for correlation — then
//! discards the buffer. Only those derived quantities and timing gaps leave the
//! process. See [`analyzer`] for the (heavily unit-tested) details.
//!
//! ## Structure
//!
//! * [`analyzer`] — the pure, async/IO/FFI-free core (the test surface).
//! * [`levenshtein`] — hand-written edit distance used for `edit_distance_prev`.
//! * `runtime` — the impure I/O drivers (pipe mode for CI; PTY/shell mode for
//!   real interactive use). Exposed only via [`run_instrumented_shell`] so the
//!   FFI stays encapsulated.
//!
//! ## Activation
//!
//! Because shell mode seizes the controlling terminal, the plugin defaults to
//! [`TtyMode::Off`] and is **inert unless explicitly configured**. Enable it via
//! `[plugins."plugin-tty"]` in the host config (`mode = "pipe"` or
//! `mode = "shell"`), or use the dedicated `aegis-agent shell` subcommand which
//! calls the runtime directly.

pub mod analyzer;
pub mod levenshtein;
mod runtime;

pub use analyzer::{Analyzer, AnalyzerConfig};
pub use levenshtein::levenshtein;

use std::path::PathBuf;
use std::sync::Arc;

use aegis_sdk::{
    register_plugin, Emitter, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Operating mode for the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TtyMode {
    /// Inert: collect nothing. The safe default.
    #[default]
    Off,
    /// Read timestamped input chunks from a fifo/file (CI / testing).
    Pipe,
    /// Run `$SHELL` inside a PTY and instrument it (real interactive use).
    Shell,
}

/// Configuration subtree for `[plugins."plugin-tty"]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtyConfig {
    /// Which runtime to start. Defaults to [`TtyMode::Off`] so the plugin does
    /// nothing unless explicitly enabled.
    #[serde(default)]
    pub mode: TtyMode,
    /// Path to the input fifo/file. Required when `mode = "pipe"`.
    #[serde(default)]
    pub pipe_path: Option<PathBuf>,
    /// Per-deployment salt for the command-correlation hash. Matches
    /// plugin-session's default so hashes correlate across collectors.
    #[serde(default = "default_salt")]
    pub hash_salt: String,
}

fn default_salt() -> String {
    "aegis-default-salt".to_string()
}

impl Default for TtyConfig {
    fn default() -> Self {
        TtyConfig {
            mode: TtyMode::Off,
            pipe_path: None,
            hash_salt: default_salt(),
        }
    }
}

/// The interactive-shell behavioral telemetry collector.
#[derive(Default)]
pub struct TtyPlugin;

#[async_trait]
impl Plugin for TtyPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-tty",
            env!("CARGO_PKG_VERSION"),
            "Interactive shell behavioral telemetry via PTY (timing/structure only, no content)",
            PluginKind::Collector,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::None
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        let cfg: TtyConfig = ctx.config_as()?;
        let session_id = current_session_id();
        let acfg = AnalyzerConfig {
            hash_salt: cfg.hash_salt,
        };
        let emitter = ctx.emitter.clone();
        let agent_id = ctx.agent_id.clone();

        match cfg.mode {
            TtyMode::Off => {
                tracing::debug!("plugin-tty disabled (mode=off)");
            }
            TtyMode::Pipe => {
                let Some(path) = cfg.pipe_path else {
                    tracing::error!("plugin-tty mode=pipe requires `pipe_path`; not starting");
                    return Ok(());
                };
                tracing::info!(?path, "plugin-tty starting in pipe mode");
                // Collector pattern: spawn the producer, don't block init.
                tokio::spawn(async move {
                    if let Err(err) =
                        runtime::run_pipe(path, emitter, agent_id, session_id, acfg).await
                    {
                        tracing::warn!(error = %err, "plugin-tty pipe runtime exited");
                    }
                });
            }
            TtyMode::Shell => {
                tracing::info!("plugin-tty starting in shell (PTY) mode");
                // The PTY pump is blocking; keep it off the tokio worker pool.
                std::thread::spawn(move || {
                    if let Err(err) = runtime::run_shell(emitter, agent_id, session_id, acfg) {
                        tracing::warn!(error = %err, "plugin-tty shell runtime exited");
                    }
                });
            }
        }

        Ok(())
    }
}

/// Session id following the platform convention `"{user}:{pid}"` (matches
/// plugin-session).
pub fn current_session_id() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    format!("{}:{}", user, std::process::id())
}

/// Run an instrumented interactive shell directly, bypassing the host.
///
/// This is the entry point the `aegis-agent shell` subcommand uses. It puts the
/// controlling terminal in raw mode, runs `$SHELL` inside a PTY, and emits
/// content-free behavioral telemetry through `emitter`. Blocking; run it on a
/// dedicated thread or via `spawn_blocking`.
pub fn run_instrumented_shell(
    emitter: Arc<dyn Emitter>,
    agent_id: String,
    session_id: String,
    cfg: AnalyzerConfig,
) -> anyhow::Result<()> {
    runtime::run_shell(emitter, agent_id, session_id, cfg)
}

/// Drive the pipe-mode collector to completion: read timestamped input chunks
/// from `path`, feed the content-free analyzer, and emit the resulting events.
///
/// This is the FFI-free runtime, exposed so the full pipeline can be exercised
/// in integration tests and CI without a real terminal. See the module docs for
/// the accepted line formats.
pub async fn run_pipe_collector(
    path: PathBuf,
    emitter: Arc<dyn Emitter>,
    agent_id: String,
    session_id: String,
    cfg: AnalyzerConfig,
) -> anyhow::Result<()> {
    runtime::run_pipe(path, emitter, agent_id, session_id, cfg).await
}

register_plugin!("plugin-tty", || Box::new(TtyPlugin));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_off() {
        let cfg = TtyConfig::default();
        assert_eq!(cfg.mode, TtyMode::Off);
        assert!(cfg.pipe_path.is_none());
        assert_eq!(cfg.hash_salt, "aegis-default-salt");
    }

    #[test]
    fn config_deserializes_from_partial_toml_like_json() {
        // Only `mode` provided; salt falls back to the default, path stays None.
        let v = serde_json::json!({ "mode": "pipe" });
        let cfg: TtyConfig = serde_json::from_value(v).unwrap();
        assert_eq!(cfg.mode, TtyMode::Pipe);
        assert_eq!(cfg.hash_salt, "aegis-default-salt");
        assert!(cfg.pipe_path.is_none());
    }

    #[test]
    fn mode_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&TtyMode::Shell).unwrap(), "\"shell\"");
        let m: TtyMode = serde_json::from_str("\"off\"").unwrap();
        assert_eq!(m, TtyMode::Off);
    }

    #[test]
    fn metadata_is_a_collector() {
        let p = TtyPlugin;
        let md = p.metadata();
        assert_eq!(md.name, "plugin-tty");
        assert_eq!(md.kind, PluginKind::Collector);
    }

    #[test]
    fn session_id_has_user_pid_shape() {
        let id = current_session_id();
        assert!(id.contains(':'), "session id should be user:pid, got {id}");
    }
}
