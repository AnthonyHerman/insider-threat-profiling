//! # Embedded datastore (`store.rs`)
//!
//! The single embedded [`redb`] key/value store backing `aegisd`. Everything the
//! server persists — the raw telemetry audit log, derived detections and scores,
//! the alert feed, the enrolled-agent registry, and one-time enrollment tokens —
//! lives in one file (`{data_dir}/aegis.redb`). This is the self-containment
//! constraint from the server design: no external database, one file to back up.
//!
//! ## Concurrency model
//!
//! [`Store`] wraps `Arc<Mutex<redb::Database>>`. redb's `Database` is `Send +
//! Sync` and its `begin_read`/`begin_write` take `&self`, but in-place
//! [`compact`](Store::compact) requires `&mut Database`, which forces the
//! `Mutex`. The mutex is held only for the (synchronous) duration of a single
//! transaction; no `.await` ever happens between `begin_write()` and `commit()`.
//! Cloning a `Store` clones the `Arc`, so the write path (the store sink), the
//! enrollment logic, and the read path (the HTTP layer) share one handle and one
//! file lock. redb takes an exclusive OS file lock for the handle's lifetime, so
//! a second `aegisd` against the same `--data-dir` simply fails to open — the
//! correct single-node behaviour.
//!
//! ## Value encoding
//!
//! redb only provides built-in `Value`/`Key` impls for `&[u8]`, `&str`,
//! `String`, the scalar types, `bool`, `char`, and `()` — notably **not**
//! `Vec<u8>` or arbitrary structs. Rows are therefore stored as `&[u8]` carrying
//! [`postcard`] bytes of the small `serde` row structs below; keys use the
//! built-in `&[u8]` (24-byte composite) and `&str` impls directly. The raw event
//! payload is held inside [`EventRow::payload_json`] as JSON bytes so the future
//! HTTP layer can serve it without re-encoding.
//!
//! ## Key encoding
//!
//! Append-only logs (events, alerts) use a 24-byte composite key:
//! `ts_ns.to_be_bytes()` (8, big-endian) `||` `uuid.as_bytes()` (16). Big-endian
//! time-first means redb's B-tree (which compares `&[u8]` keys lexicographically)
//! orders rows by time for free, so "most recent N" is `range(..).rev().take(n)`.
//! Latest-per-subject cells (detections, scores) are keyed by the string
//! `"{agent_id}:{subject}"` to avoid cross-agent collisions, since the central
//! processors use bare, per-agent-unique `subject` strings.

use std::path::Path;
use std::sync::{Arc, Mutex};

use aegis_sdk::{Event, EventPayload};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Table definitions ----------------------------------------------------
//
// `TableDefinition::new` is a `const fn`, so these are `const`. Stored values
// are always `&[u8]` (postcard bytes); see the module docs for why structs and
// `Vec<u8>` cannot be redb value types directly.

/// Full raw audit log, time-ordered. Key = 24-byte composite, value =
/// postcard([`EventRow`]).
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");
/// Secondary index: composite keys for one agent, newest last, capped at
/// [`AGENT_EVENT_INDEX_LIMIT`]. Key = `agent_id`, value = postcard(`Vec<[u8;24]>`).
const EVENTS_BY_AGENT: TableDefinition<&str, &[u8]> = TableDefinition::new("events_by_agent");
/// Latest detection per subject. Key = `"{agent_id}:{subject}"`, value =
/// postcard([`DetectionRow`]).
const DETECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("detections");
/// Latest risk score per subject. Key = `"{agent_id}:{subject}"`, value =
/// postcard([`ScoreRow`]).
const SCORES: TableDefinition<&str, &[u8]> = TableDefinition::new("scores");
/// Append-only alert log, time-ordered. Key = 24-byte composite, value =
/// postcard([`AlertRow`]).
const ALERTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("alerts");
/// Enrolled-agent registry. Key = `agent_id`, value = postcard([`AgentRow`]).
const AGENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("agents");
/// One-time enrollment tokens. Key = token hex, value = postcard([`TokenRow`]).
const ENROLL_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("enroll_tokens");

/// Maximum number of composite keys retained in a single agent's
/// `events_by_agent` index vector. The oldest is evicted on insert once full, so
/// per-agent event pagination stays bounded regardless of total event volume.
pub const AGENT_EVENT_INDEX_LIMIT: usize = 10_000;

/// Default telemetry retention window: 30 days, in nanoseconds. `events` and
/// `alerts` older than this are pruned by [`Store::compact`].
pub const RETENTION_NS: u64 = 30 * 24 * 60 * 60 * 1_000_000_000;

// --- Row structs ----------------------------------------------------------

/// One persisted event in the raw audit log. `payload_json` holds the verbatim
/// JSON of the originating [`Event::payload`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRow {
    pub id: [u8; 16],
    pub ts_ns: u64,
    pub agent_id: String,
    pub source: String,
    pub kind: String,
    pub payload_json: Vec<u8>,
}

/// Latest human-vs-agent classification for a subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionRow {
    pub agent_id: String,
    pub subject: String,
    pub verdict: String,
    pub confidence: f64,
    pub model: String,
    pub reasons: Vec<String>,
    pub ts_ns: u64,
}

/// Latest risk score for a subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreRow {
    pub agent_id: String,
    pub subject: String,
    pub model: String,
    pub score: f64,
    pub ts_ns: u64,
}

/// One actionable alert in the append-only alert log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRow {
    pub id: String,
    pub agent_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub subject: Option<String>,
    pub ts_ns: u64,
    pub acknowledged: bool,
}

/// One enrolled agent's identity and liveness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRow {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub pubkey: [u8; 32],
    pub enrolled_at_ns: u64,
    pub last_seen_ns: u64,
}

/// One one-time enrollment token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenRow {
    pub created_at_ns: u64,
    pub label: String,
    pub used: bool,
}

/// Why an [`Store::enroll_txn`] attempt was rejected (no agent was created and
/// no token was burned). [`crate::enroll`] turns these into the `reason` string
/// of an `EnrollResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollReject {
    /// The presented token is not in `enroll_tokens`.
    #[error("unknown or invalid enrollment token")]
    UnknownToken,
    /// The token exists but was already consumed by a prior enrollment.
    #[error("enrollment token already used")]
    TokenUsed,
    /// The token is older than the configured validity window.
    #[error("enrollment token expired")]
    TokenExpired,
}

// --- Key helpers ----------------------------------------------------------

/// Build the 24-byte composite key for an append-only row:
/// big-endian `ts_ns` (8 bytes) followed by the event UUID (16 bytes). The
/// big-endian-time-first layout gives free time ordering under redb's
/// lexicographic `&[u8]` key comparison.
fn composite_key(ts_ns: u64, id: Uuid) -> [u8; 24] {
    let mut k = [0u8; 24];
    k[..8].copy_from_slice(&ts_ns.to_be_bytes());
    k[8..].copy_from_slice(id.as_bytes());
    k
}

/// Build the latest-per-subject cell key `"{agent_id}:{subject}"`. Centralised so
/// every reader/writer agrees on the composite; agent IDs are server-assigned
/// UUIDv4 (no `':'`), so the separator is unambiguous.
fn subject_key(agent_id: &str, subject: &str) -> String {
    format!("{agent_id}:{subject}")
}

// --- Store ----------------------------------------------------------------

/// Handle to the embedded redb datastore. Cheap to [`clone`](Clone::clone): it
/// shares one `Arc<Mutex<Database>>` (and thus one file lock) across the write,
/// enrollment, and read paths.
#[derive(Clone)]
pub struct Store {
    db: Arc<Mutex<Database>>,
}

impl Store {
    /// Open (creating if absent) the embedded datastore under `data_dir`,
    /// returning a handle. Creates `data_dir` if needed, opens
    /// `data_dir/aegis.redb`, and materialises every table once inside an initial
    /// write transaction so later read transactions never hit a never-created
    /// table (which redb treats as an error).
    pub fn open(data_dir: &Path) -> anyhow::Result<Store> {
        std::fs::create_dir_all(data_dir)?;
        let db = Database::create(data_dir.join("aegis.redb"))?;

        // Create all tables up front so read txns always find them.
        let wtxn = db.begin_write()?;
        {
            wtxn.open_table(EVENTS)?;
            wtxn.open_table(EVENTS_BY_AGENT)?;
            wtxn.open_table(DETECTIONS)?;
            wtxn.open_table(SCORES)?;
            wtxn.open_table(ALERTS)?;
            wtxn.open_table(AGENTS)?;
            wtxn.open_table(ENROLL_TOKENS)?;
        }
        wtxn.commit()?;

        Ok(Store {
            db: Arc::new(Mutex::new(db)),
        })
    }

    /// Lock the database mutex, recovering from poisoning (a poisoned lock only
    /// means some other thread panicked mid-operation; the redb file itself is
    /// transactional and consistent, so continuing is safe).
    fn lock(&self) -> std::sync::MutexGuard<'_, Database> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    // --- Write path -------------------------------------------------------
    //
    // Each write opens one write transaction and commits it synchronously, with
    // no `.await` in between. The store sink delivers events one at a time, so
    // writes are naturally serialized.

    /// Persist a raw event into the audit log (`events`) and update the agent's
    /// secondary index (`events_by_agent`) in the same transaction. The event's
    /// payload is stored as verbatim JSON in [`EventRow::payload_json`].
    pub fn write_event(&self, ev: &Event) -> anyhow::Result<()> {
        let row = EventRow {
            id: *ev.id.as_bytes(),
            ts_ns: ev.ts_ns,
            agent_id: ev.agent_id.clone(),
            source: ev.source.clone(),
            kind: ev.kind.clone(),
            payload_json: serde_json::to_vec(&ev.payload)?,
        };
        let bytes = postcard::to_allocvec(&row)?;
        let key = composite_key(ev.ts_ns, ev.id);

        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut events = wtxn.open_table(EVENTS)?;
            events.insert(&key[..], &bytes[..])?;

            let mut index = wtxn.open_table(EVENTS_BY_AGENT)?;
            let mut keys: Vec<[u8; 24]> = match index.get(ev.agent_id.as_str())? {
                Some(guard) => postcard::from_bytes(guard.value())?,
                None => Vec::new(),
            };
            keys.push(key);
            // Evict oldest entries (front) once the cap is exceeded.
            if keys.len() > AGENT_EVENT_INDEX_LIMIT {
                let overflow = keys.len() - AGENT_EVENT_INDEX_LIMIT;
                keys.drain(..overflow);
            }
            let index_bytes = postcard::to_allocvec(&keys)?;
            index.insert(ev.agent_id.as_str(), &index_bytes[..])?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Upsert the latest detection for a subject (mutable cell keyed by
    /// `"{agent_id}:{subject}"`).
    pub fn upsert_detection(&self, row: &DetectionRow) -> anyhow::Result<()> {
        let key = subject_key(&row.agent_id, &row.subject);
        let bytes = postcard::to_allocvec(row)?;
        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut t = wtxn.open_table(DETECTIONS)?;
            t.insert(key.as_str(), &bytes[..])?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Upsert the latest risk score for a subject (mutable cell keyed by
    /// `"{agent_id}:{subject}"`).
    pub fn upsert_score(&self, row: &ScoreRow) -> anyhow::Result<()> {
        let key = subject_key(&row.agent_id, &row.subject);
        let bytes = postcard::to_allocvec(row)?;
        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut t = wtxn.open_table(SCORES)?;
            t.insert(key.as_str(), &bytes[..])?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Append an alert to the append-only alert log. The composite key is built
    /// from the alert's `ts_ns` and its UUID `id` (a non-UUID `id` falls back to
    /// a fresh UUID so the row is still stored time-ordered).
    pub fn append_alert(&self, row: &AlertRow) -> anyhow::Result<()> {
        let id = Uuid::parse_str(&row.id).unwrap_or_else(|_| Uuid::new_v4());
        let key = composite_key(row.ts_ns, id);
        let bytes = postcard::to_allocvec(row)?;
        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut t = wtxn.open_table(ALERTS)?;
            t.insert(&key[..], &bytes[..])?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Update an agent's `last_seen_ns`. No-op if the agent is not enrolled.
    pub fn touch_agent(&self, agent_id: &str, ts_ns: u64) -> anyhow::Result<()> {
        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut t = wtxn.open_table(AGENTS)?;
            // Read the row into an owned value and drop the guard before the
            // mutable insert (the guard borrows the table immutably).
            let existing: Option<AgentRow> = match t.get(agent_id)? {
                Some(guard) => Some(postcard::from_bytes(guard.value())?),
                None => None,
            };
            if let Some(mut row) = existing {
                row.last_seen_ns = ts_ns;
                let bytes = postcard::to_allocvec(&row)?;
                t.insert(agent_id, &bytes[..])?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    // --- Enrollment (token CRUD + atomic burn-and-enroll) -----------------
    //
    // The enrollment *policy* (token generation, validity window, rejection
    // reasons) lives in `enroll.rs`; these methods own only the redb mechanics
    // so every `open_table` call stays inside `store.rs`. The burn-and-enroll
    // step ([`enroll_txn`]) is a single write transaction over both the
    // `enroll_tokens` and `agents` tables, so a crash mid-enrollment can never
    // leave a token consumed without its agent (or vice versa).

    /// Insert (or overwrite) an enrollment token row, keyed by the token string.
    pub fn insert_token(&self, token: &str, row: &TokenRow) -> anyhow::Result<()> {
        let bytes = postcard::to_allocvec(row)?;
        let db = self.lock();
        let wtxn = db.begin_write()?;
        {
            let mut t = wtxn.open_table(ENROLL_TOKENS)?;
            t.insert(token, &bytes[..])?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// All enrollment tokens as `(token, row)` pairs, in key order.
    pub fn list_tokens(&self) -> anyhow::Result<Vec<(String, TokenRow)>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(ENROLL_TOKENS)?;
        let mut out = Vec::new();
        for entry in t.range::<&str>(..)? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), postcard::from_bytes(v.value())?));
        }
        Ok(out)
    }

    /// Revoke (delete) a token unless it has already been consumed.
    ///
    /// Returns `Ok(true)` if a still-unused token was removed, `Ok(false)` if
    /// the token does not exist or was already `used` (so the caller can map an
    /// already-consumed token to HTTP 409 rather than a silent success).
    pub fn revoke_token_if_unused(&self, token: &str) -> anyhow::Result<bool> {
        let db = self.lock();
        let wtxn = db.begin_write()?;
        let removed;
        {
            let mut t = wtxn.open_table(ENROLL_TOKENS)?;
            let existing: Option<TokenRow> = match t.get(token)? {
                Some(guard) => Some(postcard::from_bytes(guard.value())?),
                None => None,
            };
            removed = match existing {
                Some(row) if !row.used => {
                    t.remove(token)?;
                    true
                }
                _ => false,
            };
        }
        wtxn.commit()?;
        Ok(removed)
    }

    /// Atomically validate-and-burn a token, then enrol a new agent — both in
    /// one write transaction.
    ///
    /// `now_ns` is the current timestamp and `validity_ns` the soft validity
    /// window; a token older than `now_ns - validity_ns` is rejected as expired.
    /// On success the token is marked `used`, a fresh `Uuid::new_v4()` `agent_id`
    /// is assigned, and the corresponding [`AgentRow`] (carrying `pubkey`) is
    /// written; the assigned id and the row are returned. On any failure the
    /// transaction makes no change and a [`EnrollReject`] reason is returned.
    pub fn enroll_txn(
        &self,
        token: &str,
        now_ns: u64,
        validity_ns: u64,
        hostname: &str,
        os: &str,
        pubkey: [u8; 32],
    ) -> anyhow::Result<Result<(String, AgentRow), EnrollReject>> {
        let db = self.lock();
        let wtxn = db.begin_write()?;

        // Decide the outcome inside the txn; only commit on success so a reject
        // leaves both tables untouched.
        let outcome: Result<(String, AgentRow), EnrollReject> = {
            let mut tokens = wtxn.open_table(ENROLL_TOKENS)?;
            let token_row: Option<TokenRow> = match tokens.get(token)? {
                Some(guard) => Some(postcard::from_bytes(guard.value())?),
                None => None,
            };
            match token_row {
                None => Err(EnrollReject::UnknownToken),
                Some(row) if row.used => Err(EnrollReject::TokenUsed),
                Some(row) if now_ns.saturating_sub(row.created_at_ns) > validity_ns => {
                    Err(EnrollReject::TokenExpired)
                }
                Some(mut row) => {
                    // Burn the token.
                    row.used = true;
                    let token_bytes = postcard::to_allocvec(&row)?;
                    tokens.insert(token, &token_bytes[..])?;

                    // Mint the identity and write the agent in the SAME txn.
                    let agent_id = Uuid::new_v4().to_string();
                    // Server-assigned UUIDv4 never contains ':' — but the
                    // subject-key composite depends on that, so assert it.
                    debug_assert!(
                        !agent_id.contains(':'),
                        "assigned agent_id must not contain ':'"
                    );
                    let agent = AgentRow {
                        agent_id: agent_id.clone(),
                        hostname: hostname.to_string(),
                        os: os.to_string(),
                        pubkey,
                        enrolled_at_ns: now_ns,
                        last_seen_ns: now_ns,
                    };
                    let agent_bytes = postcard::to_allocvec(&agent)?;
                    let mut agents = wtxn.open_table(AGENTS)?;
                    agents.insert(agent_id.as_str(), &agent_bytes[..])?;
                    Ok((agent_id, agent))
                }
            }
        };

        // Commit only when an agent was actually enrolled; otherwise drop the
        // (no-op) write transaction so nothing changes.
        match outcome {
            Ok(pair) => {
                wtxn.commit()?;
                Ok(Ok(pair))
            }
            Err(reason) => {
                drop(wtxn);
                Ok(Err(reason))
            }
        }
    }

    // --- Read path --------------------------------------------------------
    //
    // Owned-return reads: each opens and drops its own read transaction so no
    // redb lifetimes leak to callers (the future HTTP handlers).

    /// All enrolled agents, in arbitrary (key) order.
    pub fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(AGENTS)?;
        let mut out = Vec::new();
        for entry in t.range::<&str>(..)? {
            let (_k, v) = entry?;
            out.push(postcard::from_bytes(v.value())?);
        }
        Ok(out)
    }

    /// Look up a single enrolled agent by id.
    pub fn agent(&self, agent_id: &str) -> anyhow::Result<Option<AgentRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(AGENTS)?;
        match t.get(agent_id)? {
            Some(guard) => Ok(Some(postcard::from_bytes(guard.value())?)),
            None => Ok(None),
        }
    }

    /// The `limit` most recent alerts, newest first.
    pub fn alerts_recent(&self, limit: usize) -> anyhow::Result<Vec<AlertRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(ALERTS)?;
        let mut out = Vec::new();
        for entry in t.range::<&[u8]>(..)?.rev().take(limit) {
            let (_k, v) = entry?;
            out.push(postcard::from_bytes(v.value())?);
        }
        Ok(out)
    }

    /// The latest risk score for a subject, if any.
    pub fn score(&self, agent_id: &str, subject: &str) -> anyhow::Result<Option<ScoreRow>> {
        let key = subject_key(agent_id, subject);
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(SCORES)?;
        match t.get(key.as_str())? {
            Some(guard) => Ok(Some(postcard::from_bytes(guard.value())?)),
            None => Ok(None),
        }
    }

    /// The latest detection for a subject, if any.
    pub fn detection(&self, agent_id: &str, subject: &str) -> anyhow::Result<Option<DetectionRow>> {
        let key = subject_key(agent_id, subject);
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(DETECTIONS)?;
        match t.get(key.as_str())? {
            Some(guard) => Ok(Some(postcard::from_bytes(guard.value())?)),
            None => Ok(None),
        }
    }

    /// One page of an agent's events, newest first. Reads the `events_by_agent`
    /// index once, slices the requested page from the tail (newest), then does a
    /// point lookup per composite key in `events`.
    pub fn events_for_agent(
        &self,
        agent_id: &str,
        page: usize,
        page_size: usize,
    ) -> anyhow::Result<Vec<EventRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let index_table = rtxn.open_table(EVENTS_BY_AGENT)?;
        let keys: Vec<[u8; 24]> = match index_table.get(agent_id)? {
            Some(guard) => postcard::from_bytes(guard.value())?,
            None => return Ok(Vec::new()),
        };

        // Page from the tail so page 0 is the newest `page_size` events.
        let total = keys.len();
        let skip = page.saturating_mul(page_size);
        if skip >= total {
            return Ok(Vec::new());
        }
        let end = total - skip; // exclusive, walking backwards from the newest
        let start = end.saturating_sub(page_size);

        let events = rtxn.open_table(EVENTS)?;
        let mut out = Vec::with_capacity(end - start);
        // Iterate newest-first within the page.
        for key in keys[start..end].iter().rev() {
            if let Some(guard) = events.get(&key[..])? {
                out.push(postcard::from_bytes(guard.value())?);
            }
        }
        Ok(out)
    }

    /// All latest-per-subject risk scores, in arbitrary (key) order.
    ///
    /// Iterates the whole `scores` table; the HTTP layer filters/limits the
    /// returned `Vec` in the handler. The number of rows is bounded by the count
    /// of distinct `(agent_id, subject)` cells, not by event volume.
    pub fn scores(&self) -> anyhow::Result<Vec<ScoreRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(SCORES)?;
        let mut out = Vec::new();
        for entry in t.range::<&str>(..)? {
            let (_k, v) = entry?;
            out.push(postcard::from_bytes(v.value())?);
        }
        Ok(out)
    }

    /// All latest-per-subject risk scores for one agent.
    ///
    /// Filters [`scores`](Self::scores) on `row.agent_id`. The keys are
    /// `"{agent_id}:{subject}"`, so a prefix range (`format!("{agent_id}:")..`)
    /// would be a cheap post-MVP optimisation; the linear filter is fine while
    /// the per-agent subject count is small.
    pub fn scores_for_agent(&self, agent_id: &str) -> anyhow::Result<Vec<ScoreRow>> {
        Ok(self
            .scores()?
            .into_iter()
            .filter(|r| r.agent_id == agent_id)
            .collect())
    }

    /// All latest-per-subject detections, in arbitrary (key) order.
    pub fn detections(&self) -> anyhow::Result<Vec<DetectionRow>> {
        let db = self.lock();
        let rtxn = db.begin_read()?;
        let t = rtxn.open_table(DETECTIONS)?;
        let mut out = Vec::new();
        for entry in t.range::<&str>(..)? {
            let (_k, v) = entry?;
            out.push(postcard::from_bytes(v.value())?);
        }
        Ok(out)
    }

    /// All latest-per-subject detections for one agent (see
    /// [`scores_for_agent`](Self::scores_for_agent) for the filtering note).
    pub fn detections_for_agent(&self, agent_id: &str) -> anyhow::Result<Vec<DetectionRow>> {
        Ok(self
            .detections()?
            .into_iter()
            .filter(|r| r.agent_id == agent_id)
            .collect())
    }

    /// Mark an alert acknowledged by its `id`, returning whether it was found.
    ///
    /// [`AlertRow::id`] is a *field*, not the row key (the key is the 24-byte
    /// `composite_key(ts_ns, uuid)`), so this scans the `alerts` table for the
    /// matching `id`, flips `acknowledged`, and re-inserts the row under its
    /// original composite key (rebuilt from `row.ts_ns` and the parsed `id`).
    /// Returns `Ok(true)` if an alert was acknowledged, `Ok(false)` if no alert
    /// has that `id` (the HTTP layer maps `false` to 404).
    ///
    /// This is an O(n) scan over the alert log; the post-MVP fix is a secondary
    /// `alert_id → composite_key` index table so ack is a single point lookup.
    pub fn acknowledge_alert(&self, id: &str) -> anyhow::Result<bool> {
        let db = self.lock();
        let wtxn = db.begin_write()?;
        let acked;
        {
            let mut t = wtxn.open_table(ALERTS)?;
            // Find the matching row (owned) and its composite key before any
            // mutable insert; the read guard borrows the table immutably.
            let mut found: Option<AlertRow> = None;
            for entry in t.range::<&[u8]>(..)? {
                let (_k, v) = entry?;
                let row: AlertRow = postcard::from_bytes(v.value())?;
                if row.id == id {
                    found = Some(row);
                    break;
                }
            }
            acked = match found {
                Some(mut row) => {
                    row.acknowledged = true;
                    let uuid = Uuid::parse_str(&row.id).unwrap_or_else(|_| Uuid::new_v4());
                    let key = composite_key(row.ts_ns, uuid);
                    let bytes = postcard::to_allocvec(&row)?;
                    t.insert(&key[..], &bytes[..])?;
                    true
                }
                None => false,
            };
        }
        wtxn.commit()?;
        Ok(acked)
    }

    // --- Retention / compaction ------------------------------------------

    /// Prune append-only logs older than `retention_ns` and defragment the file.
    ///
    /// Only `events` and `alerts` are time-expired; `detections`, `scores`,
    /// `agents`, and `enroll_tokens` are authoritative current-state and are
    /// never pruned here. Returns whether [`Database::compact`] reclaimed space.
    ///
    /// Two steps, as required by redb: the retention write transaction commits
    /// first, then `compact()` (which needs `&mut Database`, hence the held lock)
    /// defragments in place. `now_ns < retention_ns` (clock near the epoch) is a
    /// no-op for retention.
    pub fn compact(&self, retention_ns: u64) -> anyhow::Result<bool> {
        let now = aegis_sdk::now_ns();
        let mut db = self.lock();

        if let Some(cutoff_ts) = now.checked_sub(retention_ns) {
            // Prefix range key: everything strictly before this 24-byte key is
            // older than the cutoff timestamp.
            let mut cutoff = [0u8; 24];
            cutoff[..8].copy_from_slice(&cutoff_ts.to_be_bytes());
            // Typed range so redb infers `KR = &[u8]` (turbofish can't pin just
            // one of `retain_in`'s two generic params).
            let cutoff_ref: &[u8] = &cutoff[..];
            let range = ..cutoff_ref;

            let wtxn = db.begin_write()?;
            {
                let mut events = wtxn.open_table(EVENTS)?;
                events.retain_in(range, |_, _| false)?;
                let mut alerts = wtxn.open_table(ALERTS)?;
                alerts.retain_in(range, |_, _| false)?;
            }
            wtxn.commit()?;
        }

        Ok(db.compact()?)
    }
}

// --- Conversion helpers (used by the sink; defined here with the rows) -----

impl DetectionRow {
    /// Build a [`DetectionRow`] from a `detection` [`Event`], pulling the typed
    /// fields out of [`EventPayload::Detection`]. Returns `None` for any other
    /// payload kind.
    pub fn from_event(ev: &Event) -> Option<DetectionRow> {
        match &ev.payload {
            EventPayload::Detection {
                subject,
                verdict,
                confidence,
                model,
                reasons,
                ..
            } => Some(DetectionRow {
                agent_id: ev.agent_id.clone(),
                subject: subject.clone(),
                verdict: verdict.to_string(),
                confidence: *confidence,
                model: model.clone(),
                reasons: reasons.clone(),
                ts_ns: ev.ts_ns,
            }),
            _ => None,
        }
    }
}

impl ScoreRow {
    /// Build a [`ScoreRow`] from a `score` [`Event`]. Returns `None` for any
    /// other payload kind.
    pub fn from_event(ev: &Event) -> Option<ScoreRow> {
        match &ev.payload {
            EventPayload::Score {
                subject,
                model,
                score,
                ..
            } => Some(ScoreRow {
                agent_id: ev.agent_id.clone(),
                subject: subject.clone(),
                model: model.clone(),
                score: *score,
                ts_ns: ev.ts_ns,
            }),
            _ => None,
        }
    }
}

impl AlertRow {
    /// Build an [`AlertRow`] (with a fresh UUID `id`, unacknowledged) from an
    /// `alert` [`Event`]. Returns `None` for any other payload kind.
    pub fn from_event(ev: &Event) -> Option<AlertRow> {
        match &ev.payload {
            EventPayload::Alert {
                severity,
                title,
                detail,
                subject,
            } => Some(AlertRow {
                id: Uuid::new_v4().to_string(),
                agent_id: ev.agent_id.clone(),
                severity: format!("{severity:?}").to_lowercase(),
                title: title.clone(),
                detail: detail.clone(),
                subject: subject.clone(),
                ts_ns: ev.ts_ns,
                acknowledged: false,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{now_ns, Event, EventPayload, Severity, Verdict};
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn open_tmp() -> (TempDir, Store) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).expect("open store");
        (dir, store)
    }

    /// Build a raw keystroke event with a specific timestamp and agent.
    fn keystroke_event(agent: &str, ts_ns: u64) -> Event {
        let mut ev = Event::new(
            agent,
            "plugin-tty",
            EventPayload::Keystroke {
                session_id: "s1".into(),
                inter_arrival_ns: 100_000_000,
                is_paste: false,
                burst_len: 1,
            },
        );
        ev.ts_ns = ts_ns;
        ev
    }

    #[test]
    fn open_is_idempotent_and_takes_file_lock() {
        let dir = TempDir::new().unwrap();
        {
            let _s = Store::open(dir.path()).unwrap();
            // The redb file should exist now.
            assert!(dir.path().join("aegis.redb").exists());
        }
        // Reopening the same directory after the first handle dropped works
        // (file lock released on drop).
        let _s2 = Store::open(dir.path()).unwrap();
    }

    #[test]
    fn write_event_roundtrips_and_indexes_by_agent() {
        let (_dir, store) = open_tmp();
        let ev = keystroke_event("agent-a", 1_000);
        store.write_event(&ev).unwrap();

        let page = store.events_for_agent("agent-a", 0, 10).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, *ev.id.as_bytes());
        assert_eq!(page[0].ts_ns, 1_000);
        assert_eq!(page[0].kind, "input.keystroke");
        assert_eq!(page[0].agent_id, "agent-a");

        // payload_json is the verbatim JSON of the payload.
        let parsed: EventPayload = serde_json::from_slice(&page[0].payload_json).unwrap();
        assert_eq!(parsed.default_kind(), "input.keystroke");

        // A different agent has no events.
        assert!(store.events_for_agent("agent-b", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn events_for_agent_is_newest_first_and_paginates() {
        let (_dir, store) = open_tmp();
        // Insert 5 events with increasing timestamps.
        for ts in 1..=5u64 {
            store.write_event(&keystroke_event("a", ts)).unwrap();
        }
        // Page 0, size 2 => newest two (ts 5, 4).
        let p0 = store.events_for_agent("a", 0, 2).unwrap();
        assert_eq!(
            p0.iter().map(|r| r.ts_ns).collect::<Vec<_>>(),
            vec![5, 4],
            "page 0 should be the newest two, newest first"
        );
        // Page 1, size 2 => ts 3, 2.
        let p1 = store.events_for_agent("a", 1, 2).unwrap();
        assert_eq!(p1.iter().map(|r| r.ts_ns).collect::<Vec<_>>(), vec![3, 2]);
        // Page 2, size 2 => ts 1 only.
        let p2 = store.events_for_agent("a", 2, 2).unwrap();
        assert_eq!(p2.iter().map(|r| r.ts_ns).collect::<Vec<_>>(), vec![1]);
        // Page 3 is past the end.
        assert!(store.events_for_agent("a", 3, 2).unwrap().is_empty());
    }

    #[test]
    fn detection_and_score_upsert_overwrites_same_subject() {
        let (_dir, store) = open_tmp();
        let d1 = DetectionRow {
            agent_id: "a".into(),
            subject: "s1".into(),
            verdict: Verdict::Uncertain.to_string(),
            confidence: 0.4,
            model: "m".into(),
            reasons: vec![],
            ts_ns: 10,
        };
        store.upsert_detection(&d1).unwrap();
        let d2 = DetectionRow {
            confidence: 0.95,
            verdict: Verdict::Agent.to_string(),
            ts_ns: 20,
            ..d1.clone()
        };
        store.upsert_detection(&d2).unwrap();

        let got = store.detection("a", "s1").unwrap().unwrap();
        assert_eq!(got.verdict, "agent");
        assert_eq!(got.confidence, 0.95);
        assert_eq!(got.ts_ns, 20);

        let s1 = ScoreRow {
            agent_id: "a".into(),
            subject: "s1".into(),
            model: "risk/v1".into(),
            score: 12.0,
            ts_ns: 10,
        };
        store.upsert_score(&s1).unwrap();
        store
            .upsert_score(&ScoreRow {
                score: 88.5,
                ts_ns: 30,
                ..s1.clone()
            })
            .unwrap();
        let gs = store.score("a", "s1").unwrap().unwrap();
        assert_eq!(gs.score, 88.5);
        assert_eq!(gs.ts_ns, 30);

        // No collision across agents using the same bare subject.
        assert!(store.score("b", "s1").unwrap().is_none());
        assert!(store.detection("b", "s1").unwrap().is_none());
    }

    #[test]
    fn alerts_recent_returns_newest_first() {
        let (_dir, store) = open_tmp();
        for ts in [100u64, 300, 200] {
            store
                .append_alert(&AlertRow {
                    id: Uuid::new_v4().to_string(),
                    agent_id: "a".into(),
                    severity: "high".into(),
                    title: format!("alert-{ts}"),
                    detail: "d".into(),
                    subject: Some("s1".into()),
                    ts_ns: ts,
                    acknowledged: false,
                })
                .unwrap();
        }
        let recent = store.alerts_recent(2).unwrap();
        assert_eq!(
            recent.iter().map(|a| a.ts_ns).collect::<Vec<_>>(),
            vec![300, 200],
            "newest first, limited to 2"
        );
        let all = store.alerts_recent(100).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn agents_list_touch_and_lookup() {
        let (_dir, store) = open_tmp();
        // touch on an absent agent is a no-op (does not create it).
        store.touch_agent("ghost", 999).unwrap();
        assert!(store.agents().unwrap().is_empty());
        assert!(store.agent("ghost").unwrap().is_none());

        // Insert an agent via a raw write transaction (enrollment lives in
        // enroll.rs; here we just need a row to read back).
        let row = AgentRow {
            agent_id: "agent-x".into(),
            hostname: "host".into(),
            os: "Linux".into(),
            pubkey: [7u8; 32],
            enrolled_at_ns: 1,
            last_seen_ns: 1,
        };
        {
            let db = store.lock();
            let wtxn = db.begin_write().unwrap();
            {
                let mut t = wtxn.open_table(AGENTS).unwrap();
                let bytes = postcard::to_allocvec(&row).unwrap();
                t.insert("agent-x", &bytes[..]).unwrap();
            }
            wtxn.commit().unwrap();
        }

        let listed = store.agents().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent_id, "agent-x");
        assert_eq!(listed[0].pubkey, [7u8; 32]);

        // touch updates last_seen_ns.
        store.touch_agent("agent-x", 42).unwrap();
        assert_eq!(store.agent("agent-x").unwrap().unwrap().last_seen_ns, 42);
    }

    #[test]
    fn from_event_helpers_extract_typed_payloads() {
        let det = Event::new(
            "a",
            "plugin-agent-detect",
            EventPayload::Detection {
                subject: "s1".into(),
                verdict: Verdict::Agent,
                confidence: 0.9,
                model: "m".into(),
                reasons: vec!["fast".into()],
                features: BTreeMap::new(),
            },
        );
        let dr = DetectionRow::from_event(&det).unwrap();
        assert_eq!(dr.verdict, "agent");
        assert_eq!(dr.reasons, vec!["fast".to_string()]);

        let sc = Event::new(
            "a",
            "plugin-scoring",
            EventPayload::Score {
                subject: "s1".into(),
                model: "risk/v1".into(),
                score: 50.0,
                features: BTreeMap::new(),
            },
        );
        assert_eq!(ScoreRow::from_event(&sc).unwrap().score, 50.0);

        let al = Event::new(
            "a",
            "plugin-scoring",
            EventPayload::Alert {
                severity: Severity::High,
                title: "t".into(),
                detail: "d".into(),
                subject: Some("s1".into()),
            },
        );
        let ar = AlertRow::from_event(&al).unwrap();
        assert_eq!(ar.severity, "high");
        assert!(!ar.acknowledged);

        // Wrong payload kind yields None.
        let hb = Event::new("a", "agent", EventPayload::Heartbeat { uptime_s: 1 });
        assert!(DetectionRow::from_event(&hb).is_none());
        assert!(ScoreRow::from_event(&hb).is_none());
        assert!(AlertRow::from_event(&hb).is_none());
    }

    #[test]
    fn compact_prunes_old_events_and_alerts() {
        let (_dir, store) = open_tmp();
        let now = now_ns();
        // One recent event/alert and one ancient one (well past a 1s retention).
        let recent_ev = keystroke_event("a", now);
        let old_ev = keystroke_event("a", 1_000); // ~epoch, definitely expired
        store.write_event(&recent_ev).unwrap();
        store.write_event(&old_ev).unwrap();

        store
            .append_alert(&AlertRow {
                id: Uuid::new_v4().to_string(),
                agent_id: "a".into(),
                severity: "low".into(),
                title: "recent".into(),
                detail: "d".into(),
                subject: None,
                ts_ns: now,
                acknowledged: false,
            })
            .unwrap();
        store
            .append_alert(&AlertRow {
                id: Uuid::new_v4().to_string(),
                agent_id: "a".into(),
                severity: "low".into(),
                title: "old".into(),
                detail: "d".into(),
                subject: None,
                ts_ns: 1_000,
                acknowledged: false,
            })
            .unwrap();

        // Retain only the last second of data.
        store.compact(1_000_000_000).unwrap();

        // Only the recent alert survives.
        let alerts = store.alerts_recent(100).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "recent");

        // events_by_agent still references both keys, but the pruned event row
        // is gone from `events`, so only the recent one comes back.
        let evs = store.events_for_agent("a", 0, 100).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].ts_ns, now);
    }

    #[test]
    fn retention_no_op_when_clock_below_window() {
        // If now_ns() < retention_ns the cutoff underflows; compact must not
        // delete anything (and must not panic).
        let (_dir, store) = open_tmp();
        store.write_event(&keystroke_event("a", 5)).unwrap();
        // u64::MAX retention => now - retention underflows => skip pruning.
        store.compact(u64::MAX).unwrap();
        assert_eq!(store.events_for_agent("a", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn scores_and_detections_list_all_and_filter_by_agent() {
        let (_dir, store) = open_tmp();
        // Two agents, one shared bare subject; the composite key prevents
        // collisions, so each agent has its own cell.
        for (agent, score) in [("a", 10.0), ("b", 20.0)] {
            store
                .upsert_score(&ScoreRow {
                    agent_id: agent.into(),
                    subject: "s1".into(),
                    model: "risk/v1".into(),
                    score,
                    ts_ns: 1,
                })
                .unwrap();
            store
                .upsert_detection(&DetectionRow {
                    agent_id: agent.into(),
                    subject: "s1".into(),
                    verdict: Verdict::Uncertain.to_string(),
                    confidence: 0.5,
                    model: "m".into(),
                    reasons: vec![],
                    ts_ns: 1,
                })
                .unwrap();
        }

        // Collection reads see both agents' cells.
        assert_eq!(store.scores().unwrap().len(), 2);
        assert_eq!(store.detections().unwrap().len(), 2);

        // Per-agent reads filter on agent_id.
        let a_scores = store.scores_for_agent("a").unwrap();
        assert_eq!(a_scores.len(), 1);
        assert_eq!(a_scores[0].score, 10.0);
        let b_dets = store.detections_for_agent("b").unwrap();
        assert_eq!(b_dets.len(), 1);
        assert_eq!(b_dets[0].agent_id, "b");

        // An agent with no cells yields empty vectors, not an error.
        assert!(store.scores_for_agent("ghost").unwrap().is_empty());
        assert!(store.detections_for_agent("ghost").unwrap().is_empty());
    }

    #[test]
    fn acknowledge_alert_flips_and_returns_false_on_unknown() {
        let (_dir, store) = open_tmp();
        let id = Uuid::new_v4().to_string();
        store
            .append_alert(&AlertRow {
                id: id.clone(),
                agent_id: "a".into(),
                severity: "high".into(),
                title: "t".into(),
                detail: "d".into(),
                subject: Some("s1".into()),
                ts_ns: 500,
                acknowledged: false,
            })
            .unwrap();

        // Acking a known id flips the flag and reports success.
        assert!(store.acknowledge_alert(&id).unwrap());
        let after = store.alerts_recent(10).unwrap();
        assert_eq!(after.len(), 1, "ack must not duplicate the row");
        assert!(after[0].acknowledged);
        assert_eq!(after[0].id, id, "re-inserted under the same logical row");

        // Acking it again is still Ok(true) (idempotent flip).
        assert!(store.acknowledge_alert(&id).unwrap());

        // An unknown id reports false (mapped to 404 by the API).
        assert!(!store.acknowledge_alert("does-not-exist").unwrap());
    }

    #[test]
    fn index_eviction_keeps_newest_when_over_limit() {
        // Exercise the front-eviction path without inserting 10k rows: prove the
        // cap math via a small local check on the same drain logic.
        let mut keys: Vec<[u8; 24]> = (0..(AGENT_EVENT_INDEX_LIMIT as u64 + 3))
            .map(|i| composite_key(i, Uuid::nil()))
            .collect();
        if keys.len() > AGENT_EVENT_INDEX_LIMIT {
            let overflow = keys.len() - AGENT_EVENT_INDEX_LIMIT;
            keys.drain(..overflow);
        }
        assert_eq!(keys.len(), AGENT_EVENT_INDEX_LIMIT);
        // The first surviving key corresponds to ts=3 (0,1,2 evicted).
        assert_eq!(&keys[0][..8], &3u64.to_be_bytes());
    }
}
