//! Durable disk spill for telemetry that does not fit (or has not yet been
//! acknowledged from) the in-memory ring.
//!
//! Events are appended under a monotonically increasing `u64` sequence key into
//! a single redb table. This gives us:
//!
//! * **Restart durability** — on reopen the read/write cursors are recovered
//!   from the table's first/last keys, so buffered telemetry survives an agent
//!   restart and is delivered once the server is reachable again.
//! * **FIFO drain** — [`Spill::drain_batch`] reads from the low end.
//! * **Drop-oldest under pressure** — [`Spill::enforce_cap`] advances the read
//!   cursor past the oldest rows when the on-disk size exceeds the configured
//!   cap, incrementing a dropped-events counter for observability.
//!
//! Sequence numbers never repeat for the life of the DB (the write cursor only
//! ever increases), so a batch can be acknowledged by "delete everything with
//! seq <= N" via [`Spill::ack_through`].
//!
//! ## Encoding: JSON, not postcard
//! Rows are JSON, the same encoding [`aegis_proto`](aegis_proto) uses on the
//! wire. [`Event`]'s payload is an internally-tagged enum with a self-describing
//! [`Custom`](aegis_sdk::EventPayload::Custom) escape hatch, which a
//! non-self-describing binary format (postcard) cannot round-trip — postcard
//! rejects `deserialize_any`. Using JSON for the spill keeps the on-disk form
//! identical to the wire form and guarantees every event that can be sent can
//! also be buffered.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_sdk::Event;
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

/// Create `path`'s parent directory `0700` and pre-create the (empty) DB file
/// `0600` so redb opens an already-restricted file rather than creating one under
/// the process umask (which is typically world-readable). The spill holds
/// plaintext telemetry about the monitored user, so it must not be readable by
/// other local unprivileged users.
fn secure_db_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        // An empty parent (relative bare filename) needs no dir creation.
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating spill dir {}", parent.display()))?;
            // Tighten even if the dir pre-existed with looser perms.
            std::fs::set_permissions(parent, PermissionsExt::from_mode(0o700)).ok();
        }
    }
    // Pre-create the backing file 0600 if it does not already exist. `create_new`
    // is a no-op-with-error when the file exists (a recovered spill); in that case
    // we still tighten its mode below.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e).with_context(|| format!("pre-creating spill file {}", path.display()))
        }
    }
    // Enforce 0600 on the data file unconditionally (covers a recovered file that
    // pre-existed with looser perms). redb sidecar/lock files live in the same
    // 0700 directory, so directory protection covers them.
    std::fs::set_permissions(path, PermissionsExt::from_mode(0o600)).ok();
    Ok(())
}

/// `seq (u64) -> json(Event)`.
const SPILL: TableDefinition<u64, &[u8]> = TableDefinition::new("spill");

/// Serialize an event to its on-disk (JSON) form.
fn encode(ev: &Event) -> Result<Vec<u8>> {
    serde_json::to_vec(ev).context("encoding spilled event")
}

/// Deserialize an event from its on-disk (JSON) form.
fn decode(bytes: &[u8]) -> Result<Event> {
    serde_json::from_slice(bytes).context("decoding spilled event")
}

/// A redb-backed FIFO event buffer.
pub struct Spill {
    db: Database,
    /// Next sequence number to assign on push.
    write_cursor: u64,
    /// Total encoded payload bytes currently retained (approximate on-disk
    /// footprint; excludes redb's own per-row overhead).
    bytes: u64,
    /// Hard cap on retained payload bytes. [`push`](Self::push) enforces this
    /// automatically (drop-oldest) so no call site can forget the cap and let the
    /// spill grow without bound while the server is unreachable. `u64::MAX`
    /// effectively disables the cap.
    max_bytes: u64,
    /// Lifetime count of events dropped by [`enforce_cap`].
    dropped: AtomicU64,
}

/// One drained, sequence-tagged event awaiting acknowledgement.
#[derive(Debug, Clone)]
pub struct SpilledEvent {
    pub seq: u64,
    pub event: Event,
}

impl Spill {
    /// Open (creating if absent) the spill database at `path`, recovering cursors
    /// and the retained-byte total from any existing contents.
    ///
    /// `max_bytes` is the hard on-disk retention cap enforced automatically by
    /// [`push`](Self::push) (drop-oldest). Pass `u64::MAX` to disable the cap.
    /// The backing file and its parent directory are created with restrictive
    /// permissions (file `0600`, dir `0700`) so buffered plaintext telemetry
    /// about other users is not world-readable.
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self> {
        // Create the parent directory 0700 and pre-create the DB file 0600 BEFORE
        // redb opens it, so the spill (and its sidecar/lock files, which inherit
        // the dir's protection) are never momentarily world-readable under the
        // umask. Mirrors the identity-file discipline in `identity.rs`.
        secure_db_path(path).with_context(|| format!("securing spill path {}", path.display()))?;

        let db = Database::create(path)
            .with_context(|| format!("opening spill db {}", path.display()))?;

        // Ensure the table exists, and compute the recovery state in one read txn.
        let (write_cursor, bytes) = {
            let wtxn = db.begin_write()?;
            {
                // open_table in a write txn creates the table if missing.
                let _ = wtxn.open_table(SPILL)?;
            }
            wtxn.commit()?;

            let rtxn = db.begin_read()?;
            let table = rtxn.open_table(SPILL)?;
            // Next write seq is one past the current max key (0 if empty).
            let next = match table.last()? {
                Some((k, _)) => k.value() + 1,
                None => 0,
            };
            let mut total: u64 = 0;
            for row in table.iter()? {
                let (_k, v) = row?;
                total += v.value().len() as u64;
            }
            (next, total)
        };

        Ok(Spill {
            db,
            write_cursor,
            bytes,
            max_bytes,
            dropped: AtomicU64::new(0),
        })
    }

    /// Number of events currently buffered on disk.
    pub fn len(&self) -> Result<u64> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(SPILL)?;
        Ok(table.len()?)
    }

    /// Whether the spill is empty.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Approximate retained payload size in bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The sequence number the next pushed event will receive.
    pub fn next_seq(&self) -> u64 {
        self.write_cursor
    }

    /// Lifetime count of events discarded by [`enforce_cap`].
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Append events to the tail of the spill. Each gets the next sequence number.
    ///
    /// The configured byte cap is enforced here (drop-oldest) after the append, so
    /// every producer — the hot flush path, the shutdown drain, and the pre-enroll
    /// buffer — honors `max_bytes` without remembering to call [`enforce_cap`]
    /// itself. This is what bounds on-disk growth when the server is unreachable.
    pub fn push(&mut self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let wtxn = self.db.begin_write()?;
        let mut added_bytes: u64 = 0;
        {
            let mut table = wtxn.open_table(SPILL)?;
            for ev in events {
                let encoded = encode(ev)?;
                added_bytes += encoded.len() as u64;
                table.insert(self.write_cursor, encoded.as_slice())?;
                self.write_cursor += 1;
            }
        }
        wtxn.commit()?;
        self.bytes += added_bytes;
        // Enforce the retention cap centrally so it can never be forgotten at a
        // call site (the original bug: the ring drained into the spill forever).
        self.enforce_cap(self.max_bytes)?;
        Ok(())
    }

    /// Read (without removing) up to `max_events` events from the low end,
    /// stopping early once the accumulated encoded size would exceed `max_bytes`.
    /// At least one event is returned if any are present, even if it alone
    /// exceeds `max_bytes` (so an oversized row can still make progress).
    pub fn drain_batch(&self, max_events: usize, max_bytes: u64) -> Result<Vec<SpilledEvent>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(SPILL)?;
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        for row in table.iter()? {
            let (k, v) = row?;
            let bytes = v.value();
            if !out.is_empty() && (out.len() >= max_events || acc + bytes.len() as u64 > max_bytes)
            {
                break;
            }
            let event: Event = decode(bytes)?;
            acc += bytes.len() as u64;
            out.push(SpilledEvent {
                seq: k.value(),
                event,
            });
            if out.len() >= max_events {
                break;
            }
        }
        Ok(out)
    }

    /// Delete every row with `seq <= through` (an acknowledged prefix). Returns
    /// the number of rows removed.
    pub fn ack_through(&mut self, through: u64) -> Result<u64> {
        let wtxn = self.db.begin_write()?;
        let mut removed: u64 = 0;
        let mut freed: u64 = 0;
        {
            let mut table = wtxn.open_table(SPILL)?;
            // Collect the keys to remove first (can't mutate while iterating).
            let keys: Vec<u64> = table
                .range(0..=through)?
                .map(|r| r.map(|(k, v)| (k.value(), v.value().len() as u64)))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .map(|(k, len)| {
                    freed += len;
                    k
                })
                .collect();
            for k in keys {
                if table.remove(k)?.is_some() {
                    removed += 1;
                }
            }
        }
        wtxn.commit()?;
        self.bytes = self.bytes.saturating_sub(freed);
        Ok(removed)
    }

    /// Drop oldest rows until the retained byte total is at or below
    /// `spill_max_bytes`. Returns the number of events dropped (also folded into
    /// the lifetime [`dropped`](Self::dropped) counter).
    pub fn enforce_cap(&mut self, spill_max_bytes: u64) -> Result<u64> {
        if self.bytes <= spill_max_bytes {
            return Ok(0);
        }
        let wtxn = self.db.begin_write()?;
        let mut dropped: u64 = 0;
        let mut freed: u64 = 0;
        {
            let mut table = wtxn.open_table(SPILL)?;
            // Walk from the oldest key, deleting until under budget.
            let mut to_remove: Vec<u64> = Vec::new();
            let mut running = self.bytes;
            for row in table.iter()? {
                if running <= spill_max_bytes {
                    break;
                }
                let (k, v) = row?;
                let len = v.value().len() as u64;
                to_remove.push(k.value());
                running -= len.min(running);
                freed += len;
            }
            for k in to_remove {
                if table.remove(k)?.is_some() {
                    dropped += 1;
                }
            }
        }
        wtxn.commit()?;
        self.bytes = self.bytes.saturating_sub(freed);
        self.dropped.fetch_add(dropped, Ordering::Relaxed);
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::EventPayload;
    use std::path::PathBuf;

    fn tmp_db(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-spill-test-{tag}-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d.join("spill.redb")
    }

    fn ev(uptime: u64) -> Event {
        Event::new(
            "agent-t",
            "test",
            EventPayload::Heartbeat { uptime_s: uptime },
        )
    }

    #[test]
    fn push_then_drain_is_fifo() {
        let path = tmp_db("fifo");
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        s.push(&[ev(1), ev(2), ev(3)]).unwrap();
        assert_eq!(s.len().unwrap(), 3);

        let batch = s.drain_batch(10, u64::MAX).unwrap();
        assert_eq!(batch.len(), 3);
        // Sequence is monotonically increasing from the low end.
        assert_eq!(batch[0].seq, 0);
        assert_eq!(batch[2].seq, 2);
        match &batch[0].event.payload {
            EventPayload::Heartbeat { uptime_s } => assert_eq!(*uptime_s, 1),
            _ => panic!("wrong payload"),
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn ack_through_removes_prefix() {
        let path = tmp_db("ack");
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        s.push(&[ev(1), ev(2), ev(3), ev(4)]).unwrap();
        // Ack the first two (seq 0,1).
        let removed = s.ack_through(1).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(s.len().unwrap(), 2);
        let remaining = s.drain_batch(10, u64::MAX).unwrap();
        assert_eq!(remaining[0].seq, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn restart_recovers_cursor_and_appends_after() {
        let path = tmp_db("restart");
        {
            let mut s = Spill::open(&path, u64::MAX).unwrap();
            s.push(&[ev(1), ev(2), ev(3)]).unwrap();
            // drop closes the db
        }
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        assert_eq!(s.len().unwrap(), 3, "data survived restart");
        // New push must continue the sequence, not collide with seq 0..=2.
        s.push(&[ev(4)]).unwrap();
        let all = s.drain_batch(10, u64::MAX).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all.last().unwrap().seq, 3);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn restart_recovers_after_ack() {
        // Cursor recovery must be based on max key, so acked-prefix gaps don't
        // cause the next run to reuse a sequence number.
        let path = tmp_db("restart-ack");
        {
            let mut s = Spill::open(&path, u64::MAX).unwrap();
            s.push(&[ev(1), ev(2), ev(3)]).unwrap();
            s.ack_through(1).unwrap(); // remove seq 0,1; max key now 2
        }
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        s.push(&[ev(9)]).unwrap();
        let all = s.drain_batch(10, u64::MAX).unwrap();
        // Remaining seq 2, then the new one at seq 3.
        assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn enforce_cap_drops_oldest_and_counts() {
        let path = tmp_db("cap");
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        // Encode one event to learn its size, then size a cap that holds ~2.
        let one = encode(&ev(0)).unwrap().len() as u64;
        s.push(&[ev(1), ev(2), ev(3), ev(4)]).unwrap();
        let before = s.len().unwrap();
        assert_eq!(before, 4);

        let dropped = s.enforce_cap(one * 2).unwrap();
        assert!(dropped >= 1, "must drop at least one to get under cap");
        assert_eq!(s.dropped(), dropped);
        assert!(s.bytes() <= one * 2, "retained bytes within cap");

        // The survivors are the newest events (drop-oldest), so the lowest
        // remaining seq is > 0.
        let remaining = s.drain_batch(10, u64::MAX).unwrap();
        assert!(remaining.first().unwrap().seq >= dropped);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn drain_batch_respects_byte_budget() {
        let path = tmp_db("budget");
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        let one = encode(&ev(0)).unwrap().len() as u64;
        s.push(&[ev(1), ev(2), ev(3), ev(4), ev(5)]).unwrap();
        // Budget for ~2 events.
        let batch = s.drain_batch(100, one * 2 + 1).unwrap();
        assert!(batch.len() <= 3 && !batch.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn drain_returns_at_least_one_even_if_oversized() {
        let path = tmp_db("oversized");
        let mut s = Spill::open(&path, u64::MAX).unwrap();
        s.push(&[ev(1)]).unwrap();
        // Byte budget of 0 still yields the single present event.
        let batch = s.drain_batch(100, 0).unwrap();
        assert_eq!(batch.len(), 1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// H1 regression: `push` must enforce the configured cap automatically, so a
    /// caller that only ever calls `push` (never `enforce_cap`) still cannot grow
    /// the spill without bound. Opening with a 2-event cap and pushing many events
    /// must leave the retained bytes within the cap and survivors as the newest.
    #[test]
    fn push_enforces_cap_automatically() {
        let one = encode(&ev(0)).unwrap().len() as u64;
        let cap = one * 2;
        let path = tmp_db("auto-cap");
        let mut s = Spill::open(&path, cap).unwrap();

        // Push well past the cap, in several separate pushes (each must re-cap).
        for i in 1..=10u64 {
            s.push(&[ev(i)]).unwrap();
        }
        assert!(
            s.bytes() <= cap,
            "push must hold retained bytes within the cap: {} > {cap}",
            s.bytes()
        );
        assert!(s.dropped() >= 1, "old events must have been dropped");

        // Survivors are the newest events (drop-oldest): the last pushed (uptime
        // 10) must still be present.
        let remaining = s.drain_batch(100, u64::MAX).unwrap();
        let last_uptime = match remaining.last().unwrap().event.payload {
            EventPayload::Heartbeat { uptime_s } => uptime_s,
            _ => panic!("wrong payload"),
        };
        assert_eq!(last_uptime, 10, "newest event must survive drop-oldest");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A batch larger than the cap in a single `push` is still capped afterward
    /// (the cap is enforced post-append, so the transaction stays atomic).
    #[test]
    fn push_caps_even_a_single_oversized_batch() {
        let one = encode(&ev(0)).unwrap().len() as u64;
        let cap = one * 2;
        let path = tmp_db("auto-cap-batch");
        let mut s = Spill::open(&path, cap).unwrap();
        s.push(&[ev(1), ev(2), ev(3), ev(4), ev(5)]).unwrap();
        assert!(s.bytes() <= cap, "single oversized batch must be capped");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// H2 regression: the spill DB file is created mode 0600 and its parent
    /// directory 0700, so buffered plaintext telemetry is not world-readable.
    #[test]
    fn spill_file_and_dir_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_db("perms");
        let _s = Spill::open(&path, u64::MAX).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "spill.redb must be 0600");

        let dir = path.parent().unwrap();
        let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "spill dir must be 0700");
        let _ = std::fs::remove_dir_all(dir);
    }
}
