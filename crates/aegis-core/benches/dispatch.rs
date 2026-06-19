//! Bench 4 — end-to-end bus dispatch latency/throughput.
//!
//! Measures the full ingress -> dispatcher -> per-plugin-queue -> handler path:
//! the `Emitter::emit` enqueue, the dispatcher's subscription fan-out, and
//! delivery to a subscribed plugin's task. This is the kernel's throughput
//! story, independent of any feature plugin.
//!
//! A minimal counting sink subscribes to `input.keystroke`; an `AtomicUsize` +
//! `Notify` let the bench await delivery of the events it emitted.
//!
//! Caveats (from the source, surfaced here for honesty):
//!  * `emit` for non-critical kinds (`input.keystroke`) is best-effort
//!    (`try_send`, may drop on a full queue). We size `queue_depth` generously
//!    and assert zero ingress/fan-out drops after each run.
//!  * The host (and its dispatcher + handler tasks) is built and `run()` once,
//!    outside the timed loop; only `emit` + await-delivery is timed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aegis_core::{HostBuilder, HostConfig};
use aegis_sdk::{
    Event, EventPayload, Plugin, PluginContext, PluginKind, PluginMetadata, Subscriptions,
};
use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::sync::Notify;

/// A sink that counts the events delivered to it and notifies a single waiter
/// after each delivery, so the bench can await "all N emitted so far handled".
struct CountingSink {
    seen: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

#[async_trait]
impl Plugin for CountingSink {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "bench-counting-sink",
            "0",
            "counts dispatched keystroke events",
            PluginKind::Sink,
        )
    }
    fn subscriptions(&self) -> Subscriptions {
        Subscriptions::kinds(["input.keystroke"])
    }
    async fn handle(&self, _event: &Event, _ctx: &PluginContext) -> anyhow::Result<()> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
        Ok(())
    }
}

fn keystroke(i: u64) -> Event {
    Event::new(
        "bench-agent",
        "bench",
        EventPayload::Keystroke {
            session_id: "s1".to_string(),
            inter_arrival_ns: 150_000_000 + i % 50,
            is_paste: false,
            burst_len: 1,
        },
    )
}

fn bench_dispatch(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let seen = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());

    // Build + run the host once: this spawns the dispatcher and handler tasks.
    let running = rt.block_on(async {
        let mut config = HostConfig::new("bench-agent");
        config.data_dir = std::env::temp_dir().join("aegis-bench-dispatch");
        // Generous depth so the bench measures dispatch, not back-pressure drops.
        config.queue_depth = 1 << 16;
        let sink = Box::new(CountingSink {
            seen: seen.clone(),
            notify: notify.clone(),
        });
        HostBuilder::new(config)
            .discover_static(false)
            .with_plugin(sink)
            .build()
            .expect("build host")
            .run()
            .await
            .expect("run host")
    });

    let mut group = c.benchmark_group("bus_dispatch");
    // Throughput: emit N events, await all N delivered. Reports events/sec.
    for &n in &[1usize, 100, 1000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.to_async(&rt).iter(|| {
                let running = &running;
                let seen = &seen;
                let notify = &notify;
                async move {
                    let target = seen.load(Ordering::SeqCst) + n;
                    for i in 0..n {
                        running.emit(keystroke(i as u64)).await;
                    }
                    // Await delivery of all N (re-check the atomic on each wake;
                    // notify_one stores one permit so a wake between check and
                    // wait is not lost).
                    while seen.load(Ordering::SeqCst) < target {
                        notify.notified().await;
                    }
                    black_box(seen.load(Ordering::SeqCst))
                }
            });
        });
    }
    group.finish();

    // Confirm we measured clean dispatch, not silent drops.
    let metrics = running.bus_metrics();
    assert_eq!(
        metrics.ingress_dropped(),
        0,
        "bench dispatched with ingress drops; raise queue_depth"
    );
    assert_eq!(
        metrics.fanout_dropped(),
        0,
        "bench dispatched with fan-out drops; raise queue_depth"
    );

    rt.block_on(async {
        running.shutdown().await.expect("shutdown");
    });
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
