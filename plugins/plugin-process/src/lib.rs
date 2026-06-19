//! Process-execution collector.
//!
//! Periodically samples `/proc` and emits [`EventPayload::ProcessExec`] for
//! processes it has not seen before. Process lineage (ppid) and the executing
//! uid are part of the behavioral picture: automated agents tend to spawn
//! characteristic process trees (e.g. shells invoking long non-interactive
//! pipelines) that differ from human interactive use.
//!
//! The full sampling loop is implemented in [`scan`]; the foundation build wires
//! the plugin into the host and ships unit-tested `/proc` parsing. Richer
//! signals (cgroup, session leader, exec via inotify/eBPF) are layered on by the
//! telemetry workflow.

use aegis_sdk::{
    register_plugin, Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata,
    Subscriptions,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Sampling interval in milliseconds.
    pub interval_ms: u64,
    /// If true, only report processes owned by non-system uids (>= 1000).
    pub interactive_uids_only: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        ProcessConfig {
            interval_ms: 2000,
            interactive_uids_only: false,
        }
    }
}

#[derive(Default)]
pub struct ProcessPlugin {
    seen: Arc<Mutex<HashSet<u32>>>,
}

#[async_trait]
impl Plugin for ProcessPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "plugin-process",
            env!("CARGO_PKG_VERSION"),
            "Process execution telemetry collector (/proc sampler)",
            PluginKind::Collector,
        )
    }

    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::None
    }

    async fn init(&mut self, ctx: &PluginContext) -> anyhow::Result<()> {
        let cfg: ProcessConfig = ctx.config_as()?;
        let emitter = ctx.emitter.clone();
        let agent_id = ctx.agent_id.clone();
        let seen = self.seen.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(cfg.interval_ms.max(200)));
            loop {
                ticker.tick().await;
                let snapshot = match scan() {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::debug!(error = %err, "process scan failed");
                        continue;
                    }
                };
                let mut guard = seen.lock().await;
                for proc in snapshot {
                    if cfg.interactive_uids_only && proc.uid < 1000 {
                        continue;
                    }
                    if guard.insert(proc.pid) {
                        emitter
                            .emit(Event::new(
                                &agent_id,
                                "plugin-process",
                                EventPayload::ProcessExec {
                                    pid: proc.pid,
                                    ppid: proc.ppid,
                                    uid: proc.uid,
                                    exe: proc.comm.clone(),
                                    cmdline: proc.cmdline.clone(),
                                    cwd: None,
                                },
                            ))
                            .await;
                    }
                }
                // Bound memory: forget pids beyond a generous cap.
                if guard.len() > 65_536 {
                    guard.clear();
                }
            }
        });
        Ok(())
    }
}

/// A minimal `/proc` process record.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub cmdline: Vec<String>,
}

/// Scan `/proc` for current processes. Returns an empty list on non-Linux.
pub fn scan() -> anyhow::Result<Vec<ProcInfo>> {
    let mut out = Vec::new();
    let proc = std::path::Path::new("/proc");
    if !proc.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(proc)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let dir = entry.path();
        let status = match std::fs::read_to_string(dir.join("status")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (ppid, uid) = parse_status(&status);
        let comm = std::fs::read_to_string(dir.join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let cmdline = std::fs::read(dir.join("cmdline"))
            .map(|b| {
                b.split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        out.push(ProcInfo {
            pid,
            ppid,
            uid,
            comm,
            cmdline,
        });
    }
    Ok(out)
}

/// Extract (PPid, real uid) from the contents of `/proc/<pid>/status`.
fn parse_status(status: &str) -> (u32, u32) {
    let mut ppid = 0;
    let mut uid = 0;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            // "Uid:\t<real>\t<eff>\t<saved>\t<fs>"
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    (ppid, uid)
}

register_plugin!("plugin-process", || Box::new(ProcessPlugin::default()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_block() {
        let status = "Name:\tbash\nPPid:\t1234\nUid:\t1000\t1000\t1000\t1000\n";
        let (ppid, uid) = parse_status(status);
        assert_eq!(ppid, 1234);
        assert_eq!(uid, 1000);
    }

    #[test]
    fn scan_runs_without_panicking() {
        // On Linux CI this returns real processes; elsewhere an empty vec.
        let _ = scan().unwrap();
    }
}
