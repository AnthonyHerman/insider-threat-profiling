//! Host configuration: which plugins to load and how to configure each.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}
fn default_queue_depth() -> usize {
    4096
}

/// Top-level configuration consumed by [`crate::Host`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Stable identity of this endpoint/host.
    pub agent_id: String,

    /// Root directory for plugin state. Each plugin gets `data_dir/<plugin>`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// If `Some`, only these plugins (by name) are loaded. If `None`, every
    /// discovered plugin is loaded except those in `disabled_plugins`.
    #[serde(default)]
    pub enabled_plugins: Option<Vec<String>>,

    /// Plugins to skip even if discovered/enabled.
    #[serde(default)]
    pub disabled_plugins: Vec<String>,

    /// Dynamic plugin shared objects to load at runtime. Each entry carries the
    /// plugin's expected `name` alongside its `path` so the host can evaluate
    /// enablement *before* opening the library — loading a `.so` executes its
    /// entrypoint, so a disabled-but-listed path must never be `dlopen`ed.
    #[serde(default)]
    pub dynamic_plugins: Vec<DynamicPluginSpec>,

    /// Per-plugin configuration subtrees, keyed by plugin name.
    #[serde(default)]
    pub plugins: BTreeMap<String, serde_json::Value>,

    /// Bounded per-plugin queue depth (back-pressure point).
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
}

/// A dynamic (runtime-loaded `cdylib`) plugin declaration.
///
/// The `name` is the plugin's registered name and is used to evaluate the
/// host's enable/disable policy *before* the shared object is opened (opening
/// it runs native code). After load, the host asserts the library-reported
/// metadata name matches this `name` and rejects a mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPluginSpec {
    /// Registered name of the plugin (must match the library's metadata name).
    pub name: String,
    /// Filesystem path to the plugin shared object.
    pub path: PathBuf,
}

impl HostConfig {
    /// A minimal config that loads all discovered plugins.
    pub fn new(agent_id: impl Into<String>) -> Self {
        HostConfig {
            agent_id: agent_id.into(),
            data_dir: default_data_dir(),
            enabled_plugins: None,
            disabled_plugins: Vec::new(),
            dynamic_plugins: Vec::new(),
            plugins: BTreeMap::new(),
            queue_depth: default_queue_depth(),
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Ok(toml::from_str(&text)?)
    }

    /// Whether a plugin name should be loaded under this config.
    pub fn is_enabled(&self, name: &str) -> bool {
        if self.disabled_plugins.iter().any(|p| p == name) {
            return false;
        }
        match &self.enabled_plugins {
            Some(list) => list.iter().any(|p| p == name),
            None => true,
        }
    }

    /// The config subtree for a plugin (JSON `null` if unset).
    pub fn plugin_config(&self, name: &str) -> serde_json::Value {
        self.plugins
            .get(name)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }
}
