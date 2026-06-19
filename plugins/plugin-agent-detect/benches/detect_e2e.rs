//! Bench 5 — end-to-end detector path: telemetry events -> `Detection`.
//!
//! The flagship realistic path. Events arrive at `AgentDetectPlugin::handle`,
//! accumulate per session, and periodically trigger `maybe_emit` ->
//! `Model::assess` -> emit a `Detection`. It composes feature extraction (Bench
//! 2), scoring (Bench 1), and the plugin's session bookkeeping (the
//! `Mutex<HashMap>` lock, EWMA update, the cadence check).
//!
//! Variant 5a (direct `Plugin::handle` driving, no full Host) for lower
//! variance: a `PluginContext` with a capturing `Emitter` receives the emitted
//! `Detection`s. We replay a `SessionStart`, a seeded synthetic session
//! (>= 22 commands so Tier-3 engages), then a `SessionEnd` (forced final
//! assessment). A fresh plugin instance per iteration keeps session state from
//! accumulating across iterations.
//!
//! Reported for both a human and an agent session, so the paper has the cost
//! for both verdict directions. Event vectors are built once, outside the timed
//! region.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use aegis_sdk::{Emitter, Event, EventPayload, Plugin};
use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use plugin_agent_detect::synth::{synth_events, ProfileParams, Rng, SynthEvent};
use plugin_agent_detect::AgentDetectPlugin;

/// Captures emitted events (the `Detection`s the plugin produces).
#[derive(Default)]
struct CapturingEmitter {
    events: Arc<StdMutex<Vec<Event>>>,
}

#[async_trait]
impl Emitter for CapturingEmitter {
    async fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn ctx(emitter: Arc<dyn Emitter>) -> aegis_sdk::PluginContext {
    aegis_sdk::PluginContext {
        agent_id: "bench-agent".to_string(),
        data_dir: std::env::temp_dir(),
        // Default DetectConfig (assess_every = 10) via a null config subtree.
        config: serde_json::Value::Null,
        emitter,
    }
}

/// The full event stream for one session: SessionStart, telemetry, SessionEnd.
fn session_events(params: &ProfileParams, seed: u64, min_commands: u32) -> Vec<Event> {
    let sid = "bench-sess";
    let mut out = Vec::new();
    out.push(Event::new(
        "bench-agent",
        "bench",
        EventPayload::SessionStart {
            session_id: sid.to_string(),
            tty: None,
            user: "u".to_string(),
            remote: None,
        },
    ));
    let mut rng = Rng::new(seed);
    for evt in synth_events(params, &mut rng, min_commands) {
        let payload = match evt {
            SynthEvent::Keystroke {
                inter_arrival_ns,
                is_paste,
                burst_len,
            } => EventPayload::Keystroke {
                session_id: sid.to_string(),
                inter_arrival_ns,
                is_paste,
                burst_len,
            },
            SynthEvent::Command {
                inter_command_ns,
                had_backspace,
                entropy,
            } => EventPayload::CommandObserved {
                session_id: sid.to_string(),
                command_len: 20,
                token_count: 3,
                shannon_entropy: entropy,
                had_backspace,
                edit_distance_prev: 5,
                inter_command_ns,
                command_hash: "h".to_string(),
            },
        };
        out.push(Event::new("bench-agent", "bench", payload));
    }
    out.push(Event::new(
        "bench-agent",
        "bench",
        EventPayload::SessionEnd {
            session_id: sid.to_string(),
        },
    ));
    out
}

fn bench_detect_e2e(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");

    let human = session_events(&ProfileParams::human(), 1, 22);
    let agent = session_events(&ProfileParams::agent(), 2, 22);

    let mut group = c.benchmark_group("detector_e2e");
    for (name, evts) in [("human", &human), ("agent", &agent)] {
        // Throughput in events handled per session run.
        group.throughput(Throughput::Elements(evts.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), evts, |b, evts| {
            b.to_async(&rt).iter(|| async {
                // Fresh plugin + emitter per iteration: session state must not
                // carry across iterations. Construction is a HashMap + Model +
                // Config, negligible against the per-event handle cost.
                let emitter = Arc::new(CapturingEmitter::default());
                let ctx = ctx(emitter.clone());
                let plugin = AgentDetectPlugin::default();
                for e in evts {
                    plugin.handle(e, &ctx).await.expect("handle");
                }
                let emitted = emitter.events.lock().unwrap().len();
                black_box(emitted)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_detect_e2e);
criterion_main!(benches);
