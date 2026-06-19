//! The in-memory front tier of the forwarder's two-level buffer.
//!
//! [`Plugin::handle`](aegis_sdk::Plugin::handle) must never block on the network,
//! so it does exactly one thing: [`Ring::offer`] an event. The ring is a bounded
//! `VecDeque` behind a `Mutex`; when full it drops the *oldest* event (telemetry
//! recency beats completeness under sustained overload) and bumps a counter. A
//! [`Notify`] wakes the connection actor so it can move events on to the disk
//! spill and the wire.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aegis_sdk::Event;
use tokio::sync::Notify;

/// A bounded, drop-oldest, multi-producer in-memory event buffer.
pub struct Ring {
    inner: Mutex<VecDeque<Event>>,
    capacity: usize,
    /// Lifetime count of events dropped because the ring was full.
    dropped: AtomicU64,
    /// Signalled whenever an event is offered, so the actor can drain promptly.
    notify: Notify,
}

impl Ring {
    /// Create a ring holding at most `capacity` events (minimum 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Ring {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity,
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    /// Offer an event. Non-blocking. If the ring is at capacity the oldest event
    /// is evicted (and counted) to make room. Always wakes the drainer.
    pub fn offer(&self, event: Event) {
        {
            let mut q = self.inner.lock().unwrap();
            if q.len() >= self.capacity {
                q.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(event);
        }
        self.notify.notify_one();
    }

    /// Pop up to `max` events from the front (oldest first).
    pub fn drain(&self, max: usize) -> Vec<Event> {
        let mut q = self.inner.lock().unwrap();
        let n = max.min(q.len());
        q.drain(..n).collect()
    }

    /// Current number of buffered events.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Whether the ring is currently empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Lifetime count of dropped (evicted) events.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Await the next offer notification (used by the actor's `select!`).
    pub async fn notified(&self) {
        self.notify.notified().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::EventPayload;

    fn ev(u: u64) -> Event {
        Event::new("a", "t", EventPayload::Heartbeat { uptime_s: u })
    }

    #[test]
    fn offer_and_drain_fifo() {
        let r = Ring::new(10);
        r.offer(ev(1));
        r.offer(ev(2));
        assert_eq!(r.len(), 2);
        let got = r.drain(10);
        assert_eq!(got.len(), 2);
        match got[0].payload {
            EventPayload::Heartbeat { uptime_s } => assert_eq!(uptime_s, 1),
            _ => panic!(),
        }
        assert!(r.is_empty());
    }

    #[test]
    fn drops_oldest_when_full_and_counts() {
        let r = Ring::new(3);
        for i in 0..5 {
            r.offer(ev(i));
        }
        // Capacity 3: events 0 and 1 were evicted.
        assert_eq!(r.len(), 3);
        assert_eq!(r.dropped(), 2);
        let got = r.drain(10);
        let uptimes: Vec<u64> = got
            .iter()
            .map(|e| match e.payload {
                EventPayload::Heartbeat { uptime_s } => uptime_s,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(uptimes, vec![2, 3, 4]);
    }

    #[test]
    fn capacity_minimum_one() {
        let r = Ring::new(0);
        r.offer(ev(1));
        r.offer(ev(2));
        assert_eq!(r.len(), 1);
        assert_eq!(r.dropped(), 1);
    }

    #[tokio::test]
    async fn notify_wakes_waiter() {
        use std::sync::Arc;
        let r = Arc::new(Ring::new(10));
        let r2 = r.clone();
        let waiter = tokio::spawn(async move {
            r2.notified().await;
            r2.len()
        });
        // Give the waiter a moment to park on notified().
        tokio::task::yield_now().await;
        r.offer(ev(1));
        let len = waiter.await.unwrap();
        assert!(len >= 1);
    }
}
