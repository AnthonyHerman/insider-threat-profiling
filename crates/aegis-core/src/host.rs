//! The plugin host: discovery, lifecycle, and the dispatch runtime.

use crate::bus::ingress;
use crate::config::HostConfig;
use crate::loader;
use aegis_sdk::{
    Emitter, Event, Plugin, PluginContext, PluginRegistration, Subscriptions, PLUGIN_API_VERSION,
};
use anyhow::Context;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Builds a [`Host`] from explicit plugins, statically-discovered plugins, and
/// dynamically-loaded shared objects, applying the config's enable/disable list.
pub struct HostBuilder {
    config: HostConfig,
    explicit: Vec<Box<dyn Plugin>>,
    discover: bool,
}

impl HostBuilder {
    pub fn new(config: HostConfig) -> Self {
        HostBuilder {
            config,
            explicit: Vec::new(),
            discover: true,
        }
    }

    /// Toggle discovery of statically-registered (`inventory`) plugins.
    pub fn discover_static(mut self, yes: bool) -> Self {
        self.discover = yes;
        self
    }

    /// Add a plugin instance directly (highest precedence, e.g. for embedding
    /// or tests). Wins over a static/dynamic plugin of the same name.
    pub fn with_plugin(mut self, plugin: Box<dyn Plugin>) -> Self {
        self.explicit.push(plugin);
        self
    }

    /// Resolve all plugin sources into a ready-to-run [`Host`].
    pub fn build(self) -> anyhow::Result<Host> {
        let HostBuilder {
            config,
            explicit,
            discover,
        } = self;

        let mut seen: HashSet<String> = HashSet::new();
        let mut loaded: Vec<LoadedPlugin> = Vec::new();
        let mut libs: Vec<libloading::Library> = Vec::new();

        // 1. Explicit plugins (highest precedence).
        for plugin in explicit {
            let name = plugin.metadata().name.to_string();
            if !config.is_enabled(&name) {
                continue;
            }
            if seen.insert(name.clone()) {
                loaded.push(LoadedPlugin { name, plugin });
            }
        }

        // 2. Dynamic plugins from configured shared-object paths.
        for path in &config.dynamic_plugins {
            let dynamic = loader::load_dynamic(path)
                .with_context(|| format!("loading dynamic plugin {}", path.display()))?;
            let plugin = (dynamic.constructor)();
            let name = plugin.metadata().name.to_string();
            // Keep the library mapped regardless; the host owns its lifetime.
            libs.push(dynamic.library);
            if config.is_enabled(&name) && seen.insert(name.clone()) {
                tracing::info!(plugin = %name, path = %path.display(), "loaded dynamic plugin");
                loaded.push(LoadedPlugin { name, plugin });
            }
        }

        // 3. Statically-registered built-in plugins (via inventory).
        if discover {
            for reg in inventory::iter::<PluginRegistration> {
                if reg.api_version != PLUGIN_API_VERSION {
                    tracing::warn!(
                        plugin = reg.name,
                        found = reg.api_version,
                        expected = PLUGIN_API_VERSION,
                        "skipping statically-registered plugin with mismatched API version"
                    );
                    continue;
                }
                let name = reg.name.to_string();
                if config.is_enabled(&name) && !seen.contains(&name) {
                    seen.insert(name.clone());
                    loaded.push(LoadedPlugin {
                        name,
                        plugin: (reg.constructor)(),
                    });
                }
            }
        }

        Ok(Host {
            config,
            loaded,
            libs,
        })
    }
}

struct LoadedPlugin {
    name: String,
    plugin: Box<dyn Plugin>,
}

/// A constructed-but-not-yet-running set of plugins plus their config.
pub struct Host {
    config: HostConfig,
    loaded: Vec<LoadedPlugin>,
    libs: Vec<libloading::Library>,
}

impl Host {
    /// Convenience constructor: discover all statically-registered plugins.
    pub fn discover(config: HostConfig) -> anyhow::Result<Host> {
        HostBuilder::new(config).build()
    }

    /// Names of the plugins that will run, in load order.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.loaded.iter().map(|p| p.name.as_str()).collect()
    }

    /// Metadata for every loaded plugin, in load order.
    pub fn metadata(&self) -> Vec<aegis_sdk::PluginMetadata> {
        self.loaded.iter().map(|p| p.plugin.metadata()).collect()
    }

    /// Initialize every plugin and spawn the dispatch runtime.
    pub async fn run(self) -> anyhow::Result<RunningHost> {
        let Host {
            config,
            loaded,
            libs,
        } = self;

        let (emitter, mut ingress_rx) = ingress(config.queue_depth);
        let emitter_arc: Arc<dyn Emitter> = Arc::new(emitter);
        let (shutdown_tx, _) = watch::channel(false);

        let mut handlers: Vec<JoinHandle<()>> = Vec::new();
        let mut routes: Vec<(Subscriptions, mpsc::Sender<Event>)> = Vec::new();
        let mut entries: Vec<PluginEntry> = Vec::new();

        for LoadedPlugin { name, mut plugin } in loaded {
            let data_dir = config.data_dir.join(&name);
            if let Err(err) = std::fs::create_dir_all(&data_dir) {
                tracing::warn!(plugin = %name, error = %err, "could not create plugin data dir");
            }
            let ctx = Arc::new(PluginContext {
                agent_id: config.agent_id.clone(),
                data_dir,
                config: config.plugin_config(&name),
                emitter: emitter_arc.clone(),
            });

            plugin
                .init(&ctx)
                .await
                .with_context(|| format!("initializing plugin `{name}`"))?;

            let subscriptions = plugin.subscriptions();
            let plugin: Arc<dyn Plugin> = Arc::from(plugin);

            // Each plugin drains its own bounded queue on its own task.
            let (q_tx, mut q_rx) = mpsc::channel::<Event>(config.queue_depth);
            let task_plugin = plugin.clone();
            let task_ctx = ctx.clone();
            let task_name = name.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        maybe_event = q_rx.recv() => {
                            match maybe_event {
                                Some(event) => {
                                    if let Err(err) = task_plugin.handle(&event, &task_ctx).await {
                                        tracing::warn!(plugin = %task_name, error = %err, "plugin handle error");
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                    }
                }
            });
            handlers.push(handle);
            routes.push((subscriptions, q_tx));
            entries.push(PluginEntry {
                name,
                plugin,
                _ctx: ctx,
            });
        }

        // The dispatcher fans ingress events out to subscribed plugin queues.
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dispatcher = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_event = ingress_rx.recv() => {
                        match maybe_event {
                            Some(event) => {
                                for (subs, tx) in &routes {
                                    if subs.matches(&event.kind) {
                                        if let Err(mpsc::error::TrySendError::Full(ev)) =
                                            tx.try_send(event.clone())
                                        {
                                            tracing::warn!(kind = %ev.kind, "plugin queue full; dropping event");
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                }
            }
        });

        Ok(RunningHost {
            emitter: emitter_arc,
            shutdown_tx,
            dispatcher: Some(dispatcher),
            handlers,
            entries,
            _libs: libs,
        })
    }
}

struct PluginEntry {
    name: String,
    plugin: Arc<dyn Plugin>,
    _ctx: Arc<PluginContext>,
}

/// A live host. Hold it for the program's lifetime; emit events into it and call
/// [`RunningHost::shutdown`] for a graceful stop.
pub struct RunningHost {
    emitter: Arc<dyn Emitter>,
    shutdown_tx: watch::Sender<bool>,
    dispatcher: Option<JoinHandle<()>>,
    handlers: Vec<JoinHandle<()>>,
    entries: Vec<PluginEntry>,
    // Declared last so loaded plugin code stays mapped until everything drops.
    _libs: Vec<libloading::Library>,
}

impl RunningHost {
    /// A cloneable emitter for feeding external events (e.g. network ingest).
    pub fn emitter(&self) -> Arc<dyn Emitter> {
        self.emitter.clone()
    }

    /// Publish an event onto the bus.
    pub async fn emit(&self, event: Event) {
        self.emitter.emit(event).await;
    }

    /// Names of the running plugins.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Signal all tasks to stop, await them, then call each plugin's `shutdown`.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(true);
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.await;
        }
        for handle in self.handlers.drain(..) {
            let _ = handle.await;
        }
        for entry in &self.entries {
            if let Err(err) = entry.plugin.shutdown().await {
                tracing::warn!(plugin = %entry.name, error = %err, "plugin shutdown error");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{EventPayload, PluginKind, PluginMetadata, Subscriptions};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A test sink that counts heartbeat events it receives.
    struct Counter {
        seen: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for Counter {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata::new("test-counter", "0", "counts heartbeats", PluginKind::Sink)
        }
        fn subscriptions(&self) -> Subscriptions {
            Subscriptions::kinds(["heartbeat"])
        }
        async fn handle(&self, _event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
            self.seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn routes_subscribed_events_only() {
        let seen = Arc::new(AtomicUsize::new(0));
        let plugin = Box::new(Counter { seen: seen.clone() });

        let mut config = HostConfig::new("test-agent");
        config.data_dir = std::env::temp_dir().join("aegis-test-data");
        let host = HostBuilder::new(config)
            .discover_static(false)
            .with_plugin(plugin)
            .build()
            .unwrap();
        assert_eq!(host.plugin_names(), vec!["test-counter"]);

        let running = host.run().await.unwrap();

        // Two heartbeats (subscribed) and one alert (not subscribed).
        running
            .emit(Event::new(
                "a",
                "test",
                EventPayload::Heartbeat { uptime_s: 1 },
            ))
            .await;
        running
            .emit(Event::new(
                "a",
                "test",
                EventPayload::Heartbeat { uptime_s: 2 },
            ))
            .await;
        running
            .emit(Event::new(
                "a",
                "test",
                EventPayload::Alert {
                    severity: aegis_sdk::Severity::Low,
                    title: "x".into(),
                    detail: "y".into(),
                    subject: None,
                },
            ))
            .await;

        // Give the async dispatch a moment to deliver.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(seen.load(Ordering::SeqCst), 2);

        running.shutdown().await.unwrap();
    }
}
