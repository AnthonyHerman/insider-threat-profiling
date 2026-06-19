//! The connection actor: a single-task state machine that owns the TLS session
//! and moves buffered telemetry to the server.
//!
//! ```text
//!   Disconnected ──connect ok──▶ Connecting ──hello+auth ok──▶ Online
//!        ▲                            │ accepted=false              │
//!        │                            ▼                             │ io error /
//!        └────── Backoff ◀── (any failure, full-jitter) ◀──────────┘ ack timeout
//!                                     │
//!                                  Fatal (auth rejected; stop retrying)
//! ```
//!
//! Buffer tiers, drained in this precedence on each flush so ordering is
//! preserved across reconnects: **un-acked `pending` → disk spill → live ring**.
//! With `max_in_flight == 1` (the default) delivery is strict FIFO.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_proto::pin::{self, PIN_LEN};
use aegis_proto::tls::{self, AUTH_LABEL};
use aegis_proto::{read_message, write_message, Message, ServerCommand, PROTO_VERSION};
use aegis_sdk::{Emitter, Event, EventPayload, Severity};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{interval, Instant};
use tokio_rustls::rustls::pki_types::ServerName;
use uuid::Uuid;

use crate::auth;
use crate::config::TransportConfig;
use crate::identity::Enrolled;
use crate::ring::Ring;
use crate::spill::Spill;

/// A cooperative shutdown signal shared between the plugin and its actor: a flag
/// that can be *checked* synchronously plus a [`Notify`] to *wake* a parked
/// actor. Using both avoids `Notify`'s edge-triggered "lost wakeup if not
/// currently awaiting" pitfall.
#[derive(Clone, Default)]
pub struct Shutdown {
    flag: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request shutdown: set the flag and wake the actor.
    pub fn trigger(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether shutdown has been requested.
    pub fn is_set(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Await a shutdown signal (returns immediately if already set).
    pub async fn wait(&self) {
        if self.is_set() {
            return;
        }
        self.notify.notified().await;
    }
}

/// Inputs the actor owns for its lifetime.
pub struct ActorState {
    pub agent_id: String,
    pub data_dir: std::path::PathBuf,
    pub cfg: TransportConfig,
    pub identity: Enrolled,
    pub ring: Arc<Ring>,
    pub emitter: Arc<dyn Emitter>,
    /// Cooperative stop signal from the plugin's `shutdown`.
    pub shutdown: Shutdown,
}

/// A batch awaiting `BatchAck`. We keep the spill sequence numbers it covers so
/// an ack can delete exactly the acknowledged disk rows; live-ring events in the
/// batch have no spill row yet and are re-spilled on failure.
struct PendingBatch {
    events: Vec<Event>,
    /// Highest spill sequence covered by this batch, if any rows came from disk.
    spill_high: Option<u64>,
    sent_at: Instant,
}

/// Reasons a connection attempt or session ended.
enum SessionEnd {
    /// Recoverable: back off and retry.
    Retry,
    /// Unrecoverable (auth rejected): stop the actor.
    Fatal,
    /// Clean shutdown requested.
    Shutdown,
}

/// Run the actor until shutdown. Owns the reconnect/backoff outer loop.
pub async fn run(mut state: ActorState) {
    // The spill lives for the whole actor; open it once with the configured
    // retention cap so `push` enforces it on every tier (hot path + shutdown drain).
    let spill_path = state.data_dir.join("spill.redb");
    let spill = match Spill::open(&spill_path, state.cfg.spill_max_bytes) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            tracing::error!(error = %e, path = %spill_path.display(),
                "transport: cannot open spill db; events will buffer in memory only");
            // Without a spill we still run, but drain only the ring. Use a
            // null-ish spill by pointing at a temp path is risky; instead bail
            // the disk tier by keeping it None-equivalent. For simplicity we
            // retry opening on each connect; here, abort the actor cleanly.
            return;
        }
    };

    let mut backoff_exp: u32 = 0;
    loop {
        // Honor a shutdown requested while between connections.
        if state.shutdown.is_set() {
            break;
        }

        let online_at = Instant::now();
        let outcome = connect_and_serve(&mut state, &spill).await;
        match outcome {
            SessionEnd::Shutdown => break,
            SessionEnd::Fatal => {
                tracing::error!(
                    "transport: authentication rejected by server; not retrying. \
                     Re-run `aegis-agent enroll` if the agent was de-provisioned."
                );
                break;
            }
            SessionEnd::Retry => {
                if state.shutdown.is_set() {
                    break;
                }
                // Reset backoff if the last session stayed up long enough to be
                // considered healthy (grace = backoff_min); otherwise escalate.
                let stayed = online_at.elapsed();
                if stayed >= Duration::from_millis(state.cfg.backoff_min_ms) && backoff_exp > 0 {
                    backoff_exp = 0;
                }
                let delay = backoff_delay(&state.cfg, backoff_exp);
                backoff_exp = backoff_exp.saturating_add(1);
                tracing::warn!(
                    delay_ms = delay.as_millis() as u64,
                    "transport: backing off"
                );
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = state.shutdown.wait() => break,
                }
            }
        }
    }

    // Best-effort: persist whatever is still in the ring to disk on the way out.
    let leftover = state.ring.drain(usize::MAX);
    if !leftover.is_empty() {
        let mut s = spill.lock().await;
        if let Err(e) = s.push(&leftover) {
            tracing::warn!(error = %e, count = leftover.len(),
                "transport: failed to persist ring on shutdown");
        } else {
            tracing::info!(
                count = leftover.len(),
                "transport: persisted ring to spill on shutdown"
            );
        }
    }
    tracing::info!("transport: actor stopped");
}

/// Full-jitter exponential backoff: sleep a uniformly random duration in
/// `[0, min(max, base * 2^exp))`, clamped to at least 1ms when nonzero.
fn backoff_delay(cfg: &TransportConfig, exp: u32) -> Duration {
    let base = cfg.backoff_min_ms.max(1);
    let ceil = cfg.backoff_max_ms.max(base);
    let scaled = base.saturating_mul(1u64 << exp.min(20));
    let bound = scaled.min(ceil);
    let jittered = rand::thread_rng().gen_range(0..=bound);
    Duration::from_millis(jittered.max(1))
}

/// One full connect → handshake → serve cycle. Returns how the session ended.
async fn connect_and_serve(state: &mut ActorState, spill: &Arc<Mutex<Spill>>) -> SessionEnd {
    let (host, port) = match crate::config::parse_server_url(&state.cfg.server) {
        Ok(hp) => hp,
        Err(e) => {
            tracing::error!(error = %e, server = %state.cfg.server, "transport: bad server URL");
            return SessionEnd::Retry;
        }
    };

    // --- TCP ---
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, host, port, "transport: tcp connect failed");
            return SessionEnd::Retry;
        }
    };
    let _ = tcp.set_nodelay(true);

    // --- TLS (pinned) ---
    let client_cfg = tls::client_config(state.identity.server_pins.clone());
    let server_name = match ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(_) => {
            // Pinning does not validate the SNI name, but rustls needs a
            // syntactically valid one; fall back to a fixed placeholder.
            ServerName::try_from("server.aegis.local").unwrap()
        }
    };
    let tls_stream = match tls::connect(client_cfg, server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "transport: TLS handshake failed (pin mismatch?)");
            return SessionEnd::Retry;
        }
    };

    // --- RFC-5705 exporter + served-cert pin: read on the typed stream BEFORE
    // split (both reach the rustls connection handle, lost after `split`). ---
    let mut exporter = [0u8; 32];
    let bound_pin: [u8; PIN_LEN] = {
        let (_io, conn) = tls_stream.get_ref();
        if let Err(e) = conn.export_keying_material(&mut exporter, AUTH_LABEL, None) {
            tracing::warn!(error = %e, "transport: failed to export TLS keying material");
            return SessionEnd::Retry;
        }
        // Bind the auth digest to the pin of the cert the server ACTUALLY served
        // this handshake, computed from the verified peer leaf — not blindly to
        // `server_pins[0]`. During a rotation where the agent holds {old, new}
        // pins but the server already serves the new cert, the pinned-TLS
        // handshake still succeeds (pin-set match) yet the old `server_pins[0]`
        // would mismatch the server's digest and wedge the agent in `Fatal`.
        // Signing the served leaf's fingerprint makes both ends hash the same pin.
        bind_pin(conn.peer_certificates(), &state.identity.server_pins[0])
    };

    let (mut rd, wr) = tokio::io::split(tls_stream);
    let wr = Arc::new(Mutex::new(wr));

    // --- Handshake: ClientHello → Noop challenge → CommandResult(sig) → ServerHello ---
    // The handshake borrows the read half by &mut and returns it to us on
    // success, so the serve loop takes clean ownership (no Mutex/swap dance).
    match handshake(state, &mut rd, &wr, &exporter, &bound_pin).await {
        Ok(()) => {
            tracing::info!(agent_id = %state.agent_id, host, port, "transport: online");
            serve_online(state, spill, rd, wr).await
        }
        Err(HandshakeErr::Fatal(reason)) => {
            tracing::error!(reason, "transport: server rejected session");
            SessionEnd::Fatal
        }
        Err(HandshakeErr::Retry(reason)) => {
            tracing::warn!(reason, "transport: handshake failed");
            SessionEnd::Retry
        }
    }
}

/// Choose the pin to bind the session-auth digest to: the SHA-256 of the leaf
/// certificate the server actually served this handshake, or `fallback` (the
/// first configured pin) if no peer certificate is somehow available.
///
/// Factored out of [`connect_and_serve`] so the rotation-binding choice is
/// unit-testable without a live TLS handshake. `peer_certs` is what
/// `rustls::ClientConnection::peer_certificates()` returns after a completed
/// handshake (the leaf is the first element).
fn bind_pin(
    peer_certs: Option<&[tokio_rustls::rustls::pki_types::CertificateDer<'_>]>,
    fallback: &[u8; PIN_LEN],
) -> [u8; PIN_LEN] {
    match peer_certs.and_then(|c| c.first()) {
        Some(leaf) => pin::fingerprint(leaf.as_ref()),
        None => {
            tracing::warn!(
                "transport: no peer certificate after handshake; \
                 falling back to server_pins[0] for auth binding"
            );
            *fallback
        }
    }
}

enum HandshakeErr {
    Fatal(String),
    Retry(String),
}

/// Perform the already-enrolled session handshake and challenge-response auth.
///
/// Borrows the read half by `&mut` (so ownership returns to the caller) and the
/// shared write half. On `Ok(())` the session is authenticated and the caller
/// may hand `rd` to the serve loop.
async fn handshake<R, W>(
    state: &ActorState,
    rd: &mut R,
    wr: &Arc<Mutex<W>>,
    exporter: &[u8],
    bound_pin: &[u8; PIN_LEN],
) -> Result<(), HandshakeErr>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (hostname, os) = crate::config::host_facts();
    let hello = Message::ClientHello {
        proto_version: PROTO_VERSION,
        agent_id: state.agent_id.clone(),
        hostname,
        os,
        agent_pubkey: state
            .identity
            .signing_key
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    send(wr, &hello)
        .await
        .map_err(|e| HandshakeErr::Retry(format!("send ClientHello: {e}")))?;

    // Expect a Command{Noop} challenge.
    let challenge = read_message(rd)
        .await
        .map_err(|e| HandshakeErr::Retry(format!("read challenge: {e}")))?;
    let (challenge_id, command) = match challenge {
        Message::Command { id, command } => (id, command),
        other => {
            return Err(HandshakeErr::Retry(format!(
                "expected Command challenge, got {other:?}"
            )))
        }
    };
    // Only a Noop is a valid auth challenge; anything else in this slot is a
    // protocol error (keeps the auth path distinct from the command handler).
    if !matches!(command, ServerCommand::Noop) {
        return Err(HandshakeErr::Retry(format!(
            "expected Noop challenge, got {command:?}"
        )));
    }

    // Bind the auth digest to `bound_pin` — the fingerprint of the cert the
    // server actually served this handshake (see `connect_and_serve`). The server
    // verifies against the SHA-256 of its own leaf, so signing the served leaf's
    // pin makes both ends hash identical bytes even mid-rotation.
    let nonce = auth::nonce_from_challenge(&challenge_id);
    let sig_b64 = auth::sign_auth(
        &state.identity.signing_key,
        bound_pin,
        &state.agent_id,
        &nonce,
        exporter,
    );
    let reply = Message::CommandResult {
        id: challenge_id,
        ok: true,
        detail: Some(sig_b64),
    };
    send(wr, &reply)
        .await
        .map_err(|e| HandshakeErr::Retry(format!("send auth: {e}")))?;

    // Expect ServerHello.
    let resp = read_message(rd)
        .await
        .map_err(|e| HandshakeErr::Retry(format!("read ServerHello: {e}")))?;
    match resp {
        Message::ServerHello { accepted: true, .. } => Ok(()),
        // A protocol-version mismatch is genuinely unrecoverable (retrying with
        // the same binary cannot help): keep it Fatal so the actor stops.
        Message::ServerHello {
            accepted: false,
            proto_version,
            ..
        } if proto_version != PROTO_VERSION => Err(HandshakeErr::Fatal(format!(
            "server speaks proto_version {proto_version}, agent speaks {PROTO_VERSION}"
        ))),
        Message::ServerHello {
            accepted: false,
            reason,
            ..
        } => {
            // Retry (with backoff), not Fatal: an auth rejection can be a
            // transient rotation window (server mid-roll) rather than genuine
            // de-provisioning. Backing off and retrying lets a rotation self-heal;
            // a truly de-provisioned agent simply keeps backing off (no tight
            // loop) until an operator re-enrolls it. Binding the digest to the
            // served cert (above) already removes the common rotation mismatch;
            // this is defense in depth for the residual window.
            Err(HandshakeErr::Retry(format!(
                "server rejected session: {}",
                reason.unwrap_or_else(|| "no reason given".into())
            )))
        }
        other => Err(HandshakeErr::Retry(format!(
            "expected ServerHello, got {other:?}"
        ))),
    }
}

/// The Online phase: batch builder + reader, racing flush/keepalive/shutdown.
async fn serve_online<R, W>(
    state: &ActorState,
    spill: &Arc<Mutex<Spill>>,
    reader: R,
    wr: Arc<Mutex<W>>,
) -> SessionEnd
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Channel from reader task → serve loop: (acked batch id, accepted count).
    let (ack_tx, mut ack_rx) = mpsc::channel::<(Uuid, u32)>(64);
    let (rderr_tx, mut rderr_rx) = mpsc::channel::<()>(1);

    // Spawn the reader: routes BatchAck → ack_tx, dispatches Commands, refreshes
    // the watchdog via `last_rx`.
    let last_rx = Arc::new(Mutex::new(Instant::now()));
    let reader_handle = spawn_reader(
        reader,
        wr.clone(),
        ack_tx,
        rderr_tx,
        last_rx.clone(),
        state.agent_id.clone(),
        state.emitter.clone(),
    );

    let mut pending: BTreeMap<Uuid, PendingBatch> = BTreeMap::new();
    let mut flush = interval(Duration::from_millis(state.cfg.flush_interval_ms.max(1)));
    let mut keepalive = interval(Duration::from_millis(state.cfg.keepalive_ms.max(1)));
    let mut watchdog = interval(Duration::from_millis(
        (state.cfg.keepalive_timeout_ms / 4).max(1),
    ));

    // Last observed ring drop count, so the watchdog can surface *new* ring loss
    // (the only quantitative loss signal the front buffer exposes) rather than the
    // counter sitting unread. Reported as a delta to avoid log spam.
    let mut last_ring_dropped = state.ring.dropped();

    let end = loop {
        tokio::select! {
            // Reader hit an error/EOF → reconnect.
            _ = rderr_rx.recv() => break SessionEnd::Retry,

            _ = state.shutdown.wait() => break SessionEnd::Shutdown,

            // Ack arrived.
            Some((batch_id, accepted)) = ack_rx.recv() => {
                if let Some(p) = pending.remove(&batch_id) {
                    if (accepted as usize) < p.events.len() {
                        tracing::warn!(
                            batch = %batch_id,
                            accepted,
                            sent = p.events.len(),
                            "transport: server accepted fewer events than sent"
                        );
                    }
                    if let Some(high) = p.spill_high {
                        let mut s = spill.lock().await;
                        if let Err(e) = s.ack_through(high) {
                            tracing::warn!(error = %e, "transport: spill ack_through failed");
                        }
                    }
                    tracing::debug!(batch = %batch_id, events = p.events.len(), "transport: batch acked");
                }
            }

            // Time-based flush.
            _ = flush.tick() => {
                match try_flush(state, spill, &wr, &mut pending).await {
                    Ok(()) => {}
                    Err(()) => break SessionEnd::Retry,
                }
            }

            // Ring activity → opportunistic flush.
            _ = state.ring.notified() => {
                match try_flush(state, spill, &wr, &mut pending).await {
                    Ok(()) => {}
                    Err(()) => break SessionEnd::Retry,
                }
            }

            // Keepalive.
            _ = keepalive.tick() => {
                if let Err(e) = send(&wr, &Message::Ping).await {
                    tracing::warn!(error = %e, "transport: keepalive send failed");
                    break SessionEnd::Retry;
                }
            }

            // Watchdog + ack-timeout sweep.
            _ = watchdog.tick() => {
                // Surface front-buffer loss: if the ring dropped events since the
                // last sweep, log the delta and the lifetime total so loss is
                // visible rather than a silent counter.
                let dropped = state.ring.dropped();
                if dropped > last_ring_dropped {
                    tracing::warn!(
                        newly_dropped = dropped - last_ring_dropped,
                        total_dropped = dropped,
                        "transport: ring dropped events (front buffer overflow)"
                    );
                    last_ring_dropped = dropped;
                }

                let silent = last_rx.lock().await.elapsed();
                if silent > Duration::from_millis(state.cfg.keepalive_timeout_ms) {
                    tracing::warn!(silent_ms = silent.as_millis() as u64,
                        "transport: server silent past timeout; reconnecting");
                    break SessionEnd::Retry;
                }
                // Ack timeout: if the oldest in-flight batch is too old, tear down.
                let now = Instant::now();
                let stale = pending.values().any(|p| {
                    now.duration_since(p.sent_at) > Duration::from_millis(state.cfg.ack_timeout_ms)
                });
                if stale {
                    tracing::warn!("transport: ack timeout; reconnecting (batch retained)");
                    break SessionEnd::Retry;
                }
            }
        }
    };

    // Tear down the reader task.
    reader_handle.abort();
    let _ = reader_handle.await;

    // On retry/shutdown, un-acked batches must not be lost. Every event in a
    // pending batch was written to the spill BEFORE it was sent (see try_flush)
    // and its rows are never deleted until a matching BatchAck, so the spill
    // already holds them and the next session will re-drain them in order. The
    // block below is a defensive fallback for the (currently unreachable) case
    // of a batch with no backing spill rows; sort by send time to keep FIFO.
    if !pending.is_empty() {
        let mut batches: Vec<PendingBatch> = pending.into_values().collect();
        batches.sort_by_key(|p| p.sent_at);
        let mut s = spill.lock().await;
        for b in batches {
            if b.spill_high.is_none() {
                if let Err(e) = s.push(&b.events) {
                    tracing::warn!(error = %e, "transport: failed to re-spill pending batch");
                }
            }
        }
    }

    end
}

/// Build and send one batch if there is anything to send and we are under the
/// in-flight limit. `Ok(())` = nothing wrong (sent or nothing to do);
/// `Err(())` = write failed, caller should reconnect.
async fn try_flush<W>(
    state: &ActorState,
    spill: &Arc<Mutex<Spill>>,
    wr: &Arc<Mutex<W>>,
    pending: &mut BTreeMap<Uuid, PendingBatch>,
) -> Result<(), ()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if pending.len() >= state.cfg.max_in_flight {
        return Ok(());
    }

    // Precedence: spill (disk, oldest) first, then the live ring. Un-acked
    // `pending` batches are already "in flight" and are not re-collected here;
    // they are retried by being retained until ack or re-spilled on teardown.
    let mut events: Vec<Event> = Vec::new();
    let mut spill_high: Option<u64> = None;
    let mut est_bytes: usize = 0;

    {
        let s = spill.lock().await;
        match s.drain_batch(state.cfg.batch_max_events, state.cfg.batch_max_bytes as u64) {
            Ok(spilled) => {
                for se in spilled {
                    let sz = estimate_size(&se.event);
                    // Share the single tested budgeting predicate with the live-ring
                    // path (`plan_batch`) instead of re-deriving the cap arithmetic.
                    if !batch_has_room(
                        events.len(),
                        est_bytes,
                        sz,
                        state.cfg.batch_max_events,
                        state.cfg.batch_max_bytes,
                    ) {
                        break;
                    }
                    spill_high = Some(se.seq);
                    est_bytes += sz;
                    events.push(se.event);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "transport: spill drain failed");
            }
        }
    }

    // Top up from the live ring if there is room in the batch.
    if events.len() < state.cfg.batch_max_events && est_bytes < state.cfg.batch_max_bytes {
        let room = state.cfg.batch_max_events - events.len();
        let ring_events = state.ring.drain(room);
        if !ring_events.is_empty() {
            // Decide what fits this batch vs. what overflows (pure planner).
            let candidates: Vec<(Event, usize)> = ring_events
                .into_iter()
                .map(|e| {
                    let sz = estimate_size(&e);
                    (e, sz)
                })
                .collect();
            let (keep, overflow) = plan_batch(
                candidates,
                events.len(),
                est_bytes,
                state.cfg.batch_max_events,
                state.cfg.batch_max_bytes,
            );

            // Everything pulled from the ring must be durable before we rely on
            // an ack to delete it: persist `keep` (tracked by seq so the ack
            // cleans it up) and re-spill `overflow` (cannot be returned to a
            // VecDeque ring) so it is not lost.
            let mut s = spill.lock().await;
            if !keep.is_empty() {
                let before_seq = s.next_seq();
                if let Err(e) = s.push(&keep) {
                    tracing::warn!(error = %e, "transport: failed to spill ring batch");
                } else {
                    let high = before_seq + keep.len() as u64 - 1;
                    spill_high = Some(spill_high.map_or(high, |h| h.max(high)));
                    events.extend(keep);
                }
            }
            if !overflow.is_empty() {
                if let Err(e) = s.push(&overflow) {
                    tracing::warn!(error = %e, "transport: failed to spill ring overflow");
                }
            }
        }
    }

    if events.is_empty() {
        return Ok(());
    }

    // Drop any single event that cannot fit a frame even alone.
    let batch_id = Uuid::new_v4();
    let msg = Message::EventBatch {
        batch_id,
        events: events.clone(),
    };
    // Frame-size guard against MAX_FRAME_BYTES.
    match serde_json::to_vec(&msg) {
        Ok(bytes) if bytes.len() > aegis_proto::MAX_FRAME_BYTES => {
            tracing::warn!(
                bytes = bytes.len(),
                "transport: batch exceeds MAX_FRAME_BYTES; dropping (acking spill rows)"
            );
            // These events are already in the spill; ack them away to avoid a
            // poison batch looping forever.
            if let Some(high) = spill_high {
                let mut s = spill.lock().await;
                let _ = s.ack_through(high);
            }
            return Ok(());
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "transport: batch serialize failed");
            return Ok(());
        }
    }

    // Record as pending BEFORE awaiting send so a concurrent ack can match it.
    pending.insert(
        batch_id,
        PendingBatch {
            events,
            spill_high,
            sent_at: Instant::now(),
        },
    );

    if let Err(e) = send(wr, &msg).await {
        tracing::warn!(error = %e, batch = %batch_id, "transport: batch send failed");
        // Keep it in pending; the teardown path re-spills if needed. The rows
        // are still in the spill (spill_high), so they are not lost.
        return Err(());
    }
    Ok(())
}

/// Estimate an event's on-wire JSON size (cheap upper-ish bound used for budgeting).
fn estimate_size(ev: &Event) -> usize {
    serde_json::to_vec(ev).map(|v| v.len()).unwrap_or(256)
}

/// Decide whether a candidate of size `sz` may be added to a batch that already
/// holds `cur_events` events totalling `cur_bytes`. The first event is always
/// allowed (so a lone oversized event can still make progress); subsequent
/// events must respect both the event-count and byte-size caps.
fn batch_has_room(
    cur_events: usize,
    cur_bytes: usize,
    sz: usize,
    max_events: usize,
    max_bytes: usize,
) -> bool {
    if cur_events == 0 {
        return true;
    }
    cur_events < max_events && cur_bytes + sz <= max_bytes
}

/// Pure batch planner: greedily split `candidates` (in order) into the events
/// that fit one batch under the caps and the overflow that does not. Each
/// candidate is `(event, estimated_size)`. Used by the live-ring top-up so the
/// size/time budgeting is unit-testable without a TLS stream.
fn plan_batch(
    candidates: Vec<(Event, usize)>,
    start_events: usize,
    start_bytes: usize,
    max_events: usize,
    max_bytes: usize,
) -> (Vec<Event>, Vec<Event>) {
    let mut taken = Vec::new();
    let mut overflow = Vec::new();
    let mut n = start_events;
    let mut bytes = start_bytes;
    for (ev, sz) in candidates {
        if !overflow.is_empty() || !batch_has_room(n, bytes, sz, max_events, max_bytes) {
            overflow.push(ev);
            continue;
        }
        n += 1;
        bytes += sz;
        taken.push(ev);
    }
    (taken, overflow)
}

/// Maximum number of server-`Command` dispatch tasks allowed in flight at once.
/// A compromised (or buggy) server that streams commands faster than they can be
/// handled would otherwise spawn unbounded tasks, each holding allocations and
/// awaiting a (back-pressured) bus slot. Beyond this cap a command's reply is
/// dropped rather than queued — the server retries idempotent commands.
const MAX_INFLIGHT_COMMANDS: usize = 16;

/// Spawn the reader task. It loops `read_message`, routes acks, dispatches each
/// `Command` on its own task (so a slow handler never blocks reads) under a
/// bounded [`Semaphore`], replies to `Ping` inline, and updates `last_rx` on
/// every inbound frame for the watchdog.
fn spawn_reader<R, W>(
    mut rd: R,
    wr: Arc<Mutex<W>>,
    ack_tx: mpsc::Sender<(Uuid, u32)>,
    rderr_tx: mpsc::Sender<()>,
    last_rx: Arc<Mutex<Instant>>,
    agent_id: String,
    emitter: Arc<dyn Emitter>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Cap concurrent command-dispatch tasks so a command flood cannot spawn an
    // unbounded number of tasks all parked on bus back-pressure.
    let cmd_sem = Arc::new(Semaphore::new(MAX_INFLIGHT_COMMANDS));
    tokio::spawn(async move {
        loop {
            match read_message(&mut rd).await {
                Ok(msg) => {
                    *last_rx.lock().await = Instant::now();
                    match msg {
                        Message::BatchAck { batch_id, accepted } => {
                            // Forward id + count; the serve loop compares against
                            // the pending batch size and warns on partial accept.
                            if ack_tx.send((batch_id, accepted)).await.is_err() {
                                break;
                            }
                        }
                        Message::Command { id, command } => {
                            // Acquire a permit BEFORE spawning; move it into the
                            // task so it is released on completion. If the cap is
                            // reached, drop the command (do not queue unboundedly).
                            match Arc::clone(&cmd_sem).try_acquire_owned() {
                                Ok(permit) => {
                                    let wr = wr.clone();
                                    let agent_id = agent_id.clone();
                                    let emitter = emitter.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        let result =
                                            dispatch_command(id, command, &agent_id, &emitter)
                                                .await;
                                        if let Err(e) = send(&wr, &result).await {
                                            tracing::warn!(error = %e, "transport: command result send failed");
                                        }
                                    });
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        %id,
                                        cap = MAX_INFLIGHT_COMMANDS,
                                        "transport: command dispatch at capacity; dropping command"
                                    );
                                }
                            }
                        }
                        Message::Pong => { /* watchdog already refreshed */ }
                        Message::Ping => {
                            // Server pinged us; pong back inline (no spawn) — a
                            // single short write that cannot fan out into a flood.
                            if let Err(e) = send(&wr, &Message::Pong).await {
                                tracing::warn!(error = %e, "transport: pong send failed");
                            }
                        }
                        other => {
                            tracing::debug!(
                                ?other,
                                "transport: ignoring unexpected inbound message"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "transport: read error; ending session");
                    let _ = rderr_tx.send(()).await;
                    break;
                }
            }
        }
    })
}

/// Handle one server command and produce its `CommandResult`.
///
/// The server contract for `Rescore`/`SetConfig` is deferred (separate
/// workflow), so those are acked with an explanatory detail. `Isolate` raises a
/// local critical alert; `Noop` is a plain ack.
async fn dispatch_command(
    id: Uuid,
    command: ServerCommand,
    agent_id: &str,
    emitter: &Arc<dyn Emitter>,
) -> Message {
    match command {
        ServerCommand::Noop => Message::CommandResult {
            id,
            ok: true,
            detail: None,
        },
        ServerCommand::Rescore { subject } => {
            // Surface the request as a local trigger event for processors; full
            // re-scoring orchestration lands with the server workflow.
            emitter
                .emit(
                    Event::new(
                        agent_id,
                        "plugin-transport",
                        EventPayload::Custom(serde_json::json!({
                            "type": "rescore_request",
                            "subject": subject,
                        })),
                    )
                    .with_kind("transport.rescore"),
                )
                .await;
            Message::CommandResult {
                id,
                ok: true,
                detail: Some("rescore request emitted locally".into()),
            }
        }
        ServerCommand::SetConfig { plugin, .. } => Message::CommandResult {
            id,
            ok: false,
            detail: Some(format!(
                "live reconfigure of `{}` unsupported (no Plugin::reconfigure yet)",
                sanitize(&plugin)
            )),
        },
        ServerCommand::Isolate { reason } => {
            let reason = sanitize(&reason);
            emitter
                .emit(Event::new(
                    agent_id,
                    "plugin-transport",
                    EventPayload::Alert {
                        severity: Severity::Critical,
                        title: "Isolation requested by server".into(),
                        detail: format!("reason: {reason}"),
                        subject: Some(agent_id.to_string()),
                    },
                ))
                .await;
            Message::CommandResult {
                id,
                ok: true,
                detail: Some("isolation alert raised".into()),
            }
        }
    }
}

/// Bound and strip control characters from server-supplied strings before they
/// land in logs/alerts (defense against log injection / unbounded growth).
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

async fn send<W>(wr: &Arc<Mutex<W>>, msg: &Message) -> Result<(), aegis_proto::ProtoError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut guard = wr.lock().await;
    write_message(&mut *guard, msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::EventPayload;

    fn ev(u: u64) -> Event {
        Event::new("a", "t", EventPayload::Heartbeat { uptime_s: u })
    }

    // ---- batch builder ----

    #[test]
    fn batch_room_first_event_always_fits() {
        // Even a single event larger than the byte cap is allowed when the batch
        // is empty, so an oversized event can still make progress.
        assert!(batch_has_room(0, 0, 10_000, 100, 50));
    }

    #[test]
    fn batch_room_respects_event_and_byte_caps() {
        // Under the event cap and within bytes: room.
        assert!(batch_has_room(2, 100, 50, 10, 1000));
        // At the event cap: no room.
        assert!(!batch_has_room(10, 100, 1, 10, 1000));
        // Byte cap would be exceeded: no room.
        assert!(!batch_has_room(2, 990, 20, 10, 1000));
        // Exactly hitting the byte cap is allowed (<=).
        assert!(batch_has_room(2, 980, 20, 10, 1000));
    }

    #[test]
    fn plan_batch_splits_on_event_cap() {
        let cands: Vec<(Event, usize)> = (0..5).map(|i| (ev(i), 10)).collect();
        let (taken, overflow) = plan_batch(cands, 0, 0, 3, 10_000);
        assert_eq!(taken.len(), 3, "event cap of 3");
        assert_eq!(overflow.len(), 2);
    }

    #[test]
    fn plan_batch_splits_on_byte_cap() {
        // Each event "costs" 100 bytes; cap 250 fits 2 (first always fits, then
        // one more keeps us at 200 <= 250, a third would be 300 > 250).
        let cands: Vec<(Event, usize)> = (0..5).map(|i| (ev(i), 100)).collect();
        let (taken, overflow) = plan_batch(cands, 0, 0, 100, 250);
        assert_eq!(taken.len(), 2);
        assert_eq!(overflow.len(), 3);
    }

    #[test]
    fn plan_batch_accounts_for_starting_fill() {
        // Batch already has 2 events / 80 bytes; only 1 more 100-byte event fits
        // under a 200-byte cap (80+100=180 <= 200; a second would be 280 > 200).
        let cands: Vec<(Event, usize)> = (0..4).map(|i| (ev(i), 100)).collect();
        let (taken, overflow) = plan_batch(cands, 2, 80, 100, 200);
        assert_eq!(taken.len(), 1);
        assert_eq!(overflow.len(), 3);
    }

    #[test]
    fn plan_batch_preserves_order_once_overflowing() {
        // After the first overflow, every remaining candidate overflows too
        // (FIFO is preserved; we never reorder to pack a later small event).
        let cands = vec![(ev(0), 100), (ev(1), 100), (ev(2), 1)];
        let (taken, overflow) = plan_batch(cands, 0, 0, 100, 150);
        assert_eq!(taken.len(), 1, "only the first fits the 150-byte cap");
        // The tiny third event still goes to overflow, not packed ahead.
        assert_eq!(overflow.len(), 2);
        match overflow[1].payload {
            EventPayload::Heartbeat { uptime_s } => assert_eq!(uptime_s, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn estimate_size_is_positive() {
        assert!(estimate_size(&ev(1)) > 0);
    }

    /// M1 regression: `bind_pin` must bind to the pin of the SERVED leaf cert, not
    /// the configured fallback (`server_pins[0]`). This is what lets a rotation
    /// window self-heal — the agent signs whatever cert the server is currently
    /// serving (which TLS already verified is in the agent's pin set), so the
    /// server's digest (computed over its own leaf) matches.
    #[test]
    fn bind_pin_uses_served_leaf_not_fallback() {
        use tokio_rustls::rustls::pki_types::CertificateDer;
        // Mint a "served" cert; its pin is what the server would verify against.
        let ck = rcgen::generate_simple_self_signed(vec!["aegisd".to_string()]).unwrap();
        let served_der = ck.cert.der().to_vec();
        let served_pin = aegis_proto::pin::fingerprint(&served_der);

        // A different (stale rotation) fallback pin the agent happens to hold first.
        let stale_fallback = [0xABu8; PIN_LEN];
        assert_ne!(served_pin, stale_fallback);

        let leaf = CertificateDer::from(served_der);
        let certs = [leaf];
        let bound = bind_pin(Some(&certs), &stale_fallback);
        assert_eq!(bound, served_pin, "must bind to the served leaf's pin");

        // With no peer cert (degenerate), fall back to the configured pin.
        assert_eq!(bind_pin(None, &stale_fallback), stale_fallback);
        let empty: [CertificateDer; 0] = [];
        assert_eq!(bind_pin(Some(&empty), &stale_fallback), stale_fallback);
    }

    #[test]
    fn backoff_is_bounded_and_jittered() {
        let cfg = TransportConfig {
            backoff_min_ms: 100,
            backoff_max_ms: 1000,
            ..Default::default()
        };
        // exp grows; delay never exceeds the ceiling and is >= 1ms.
        for exp in 0..10 {
            let d = backoff_delay(&cfg, exp).as_millis() as u64;
            assert!(d >= 1, "delay must be at least 1ms");
            assert!(d <= 1000, "delay {d} exceeded ceiling at exp={exp}");
        }
    }

    #[test]
    fn backoff_distribution_uses_full_range() {
        // Full jitter: across many draws at a high exp the max observed should
        // approach the ceiling and the min should be well below it.
        let cfg = TransportConfig {
            backoff_min_ms: 100,
            backoff_max_ms: 1000,
            ..Default::default()
        };
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        for _ in 0..2000 {
            let d = backoff_delay(&cfg, 8).as_millis() as u64;
            lo = lo.min(d);
            hi = hi.max(d);
        }
        assert!(
            hi > 700,
            "expected some large draws near the ceiling, got hi={hi}"
        );
        assert!(
            lo < 300,
            "expected some small draws (full jitter), got lo={lo}"
        );
    }

    #[test]
    fn sanitize_strips_control_and_bounds_length() {
        let dirty = format!("a\nb\r\t{}", "x".repeat(1000));
        let clean = sanitize(&dirty);
        assert!(!clean.contains('\n') && !clean.contains('\r') && !clean.contains('\t'));
        assert!(clean.len() <= 256);
    }

    #[tokio::test]
    async fn dispatch_isolate_acks_and_alerts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl Emitter for Counter {
            async fn emit(&self, _e: Event) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let n = Arc::new(AtomicUsize::new(0));
        let em: Arc<dyn Emitter> = Arc::new(Counter(n.clone()));
        let id = Uuid::new_v4();
        let res = dispatch_command(
            id,
            ServerCommand::Isolate {
                reason: "suspicious\nactivity".into(),
            },
            "agent-x",
            &em,
        )
        .await;
        match res {
            Message::CommandResult { ok, id: rid, .. } => {
                assert!(ok);
                assert_eq!(rid, id);
            }
            _ => panic!("expected CommandResult"),
        }
        assert_eq!(n.load(Ordering::SeqCst), 1, "isolate must emit one alert");
    }

    #[tokio::test]
    async fn dispatch_setconfig_is_acked_unsupported() {
        // SetConfig has no live implementation (no Plugin::reconfigure); the
        // dispatcher must reject it AND emit nothing, so a future partial wiring
        // cannot silently half-apply. We assert both the negative ack and that no
        // event was emitted.
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl Emitter for Counter {
            async fn emit(&self, _e: Event) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let n = Arc::new(AtomicUsize::new(0));
        let em: Arc<dyn Emitter> = Arc::new(Counter(n.clone()));
        let res = dispatch_command(
            Uuid::new_v4(),
            ServerCommand::SetConfig {
                plugin: "plugin-x".into(),
                config: serde_json::json!({}),
            },
            "agent-x",
            &em,
        )
        .await;
        match res {
            Message::CommandResult { ok, detail, .. } => {
                assert!(!ok);
                assert!(detail.unwrap().contains("unsupported"));
            }
            _ => panic!("expected CommandResult"),
        }
        assert_eq!(
            n.load(Ordering::SeqCst),
            0,
            "SetConfig must not emit any event while it is unimplemented"
        );
    }

    #[tokio::test]
    async fn dispatch_rescore_acks_and_emits_one_custom_trigger() {
        // `Rescore` is a fire-and-forget local trigger: it acks ok:true and emits
        // exactly one Custom event tagged `transport.rescore`. No processor in the
        // workspace subscribes to that kind yet (the full re-scoring orchestration
        // is deferred), so this pins the emitted shape that a future consumer will
        // key on and guards against the path silently breaking.
        struct Capture(Arc<std::sync::Mutex<Vec<Event>>>);
        #[async_trait::async_trait]
        impl Emitter for Capture {
            async fn emit(&self, e: Event) {
                self.0.lock().unwrap().push(e);
            }
        }
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let em: Arc<dyn Emitter> = Arc::new(Capture(seen.clone()));
        let id = Uuid::new_v4();
        let res = dispatch_command(
            id,
            ServerCommand::Rescore {
                subject: "uid:1000".into(),
            },
            "agent-x",
            &em,
        )
        .await;
        match res {
            Message::CommandResult { ok, id: rid, .. } => {
                assert!(ok, "rescore should ack ok:true");
                assert_eq!(rid, id);
            }
            _ => panic!("expected CommandResult"),
        }
        let events = seen.lock().unwrap();
        assert_eq!(events.len(), 1, "rescore must emit exactly one event");
        assert_eq!(
            events[0].kind, "transport.rescore",
            "the emitted trigger must be tagged transport.rescore"
        );
        // The payload carries the requested subject so a future consumer can act.
        match &events[0].payload {
            EventPayload::Custom(v) => {
                assert_eq!(v["type"], "rescore_request");
                assert_eq!(v["subject"], "uid:1000");
            }
            other => panic!("expected a Custom rescore payload, got {other:?}"),
        }
    }

    // ---- Online round-trip over an in-memory duplex (no TLS) ----

    struct NullEmitter;
    #[async_trait::async_trait]
    impl Emitter for NullEmitter {
        async fn emit(&self, _e: Event) {}
    }

    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-actor-test-{tag}-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn test_state(dir: std::path::PathBuf, ring: Arc<Ring>, cfg: TransportConfig) -> ActorState {
        ActorState {
            agent_id: "agent-rt".into(),
            data_dir: dir,
            cfg,
            identity: crate::identity::Enrolled {
                agent_id: "agent-rt".into(),
                signing_key: crate::identity::generate_key(),
                server_pins: vec![[0u8; 32]],
            },
            ring,
            emitter: Arc::new(NullEmitter),
            shutdown: Shutdown::new(),
        }
    }

    /// The batch builder, driven through `serve_online` over a plaintext duplex:
    /// events offered into the ring must arrive as an `EventBatch`; after we send
    /// a `BatchAck`, the corresponding spill rows must be deleted (so they are
    /// not re-sent). This exercises ring→spill→batch→pending→ack end to end.
    #[tokio::test]
    async fn online_sends_batch_and_acks_clear_spill() {
        let dir = tmp_db("online-ack");
        let spill = Arc::new(Mutex::new(
            Spill::open(&dir.join("spill.redb"), u64::MAX).unwrap(),
        ));
        let ring = Arc::new(Ring::new(1000));
        for i in 0..3 {
            ring.offer(ev(i));
        }
        let cfg = TransportConfig {
            flush_interval_ms: 10,
            keepalive_ms: 10_000,
            keepalive_timeout_ms: 60_000,
            ack_timeout_ms: 60_000,
            ..Default::default()
        };
        let state = test_state(dir.clone(), ring.clone(), cfg);
        let shutdown = state.shutdown.clone();

        // client_io is what the actor writes/reads; server_io is our test peer.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (crd, cwr) = tokio::io::split(client_io);
        let spill_for_actor = spill.clone();
        let actor = tokio::spawn(async move {
            serve_online(&state, &spill_for_actor, crd, Arc::new(Mutex::new(cwr))).await
        });

        // Server peer: read the batch, send an ack for it.
        let (mut srd, mut swr) = tokio::io::split(server_io);
        let batch_id = match read_message(&mut srd).await.unwrap() {
            Message::EventBatch { batch_id, events } => {
                assert_eq!(events.len(), 3, "all three ring events in one batch");
                batch_id
            }
            other => panic!("expected EventBatch, got {other:?}"),
        };
        write_message(
            &mut swr,
            &Message::BatchAck {
                batch_id,
                accepted: 3,
            },
        )
        .await
        .unwrap();

        // Give the actor a moment to process the ack, then stop it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.trigger();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor).await;

        // After ack, the spill must be empty (rows were acked, not retained).
        let s = spill.lock().await;
        assert_eq!(s.len().unwrap(), 0, "acked batch must clear the spill");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With `max_in_flight == 1`, a second batch must not be sent until the first
    /// is acked — strict FIFO. We offer events, read the first batch, withhold
    /// the ack, offer more, and assert no second batch arrives until we ack.
    #[tokio::test]
    async fn fifo_single_in_flight_blocks_second_batch() {
        let dir = tmp_db("fifo");
        let spill = Arc::new(Mutex::new(
            Spill::open(&dir.join("spill.redb"), u64::MAX).unwrap(),
        ));
        let ring = Arc::new(Ring::new(1000));
        ring.offer(ev(1));
        let cfg = TransportConfig {
            flush_interval_ms: 10,
            keepalive_ms: 10_000,
            keepalive_timeout_ms: 60_000,
            ack_timeout_ms: 60_000,
            max_in_flight: 1,
            ..Default::default()
        };
        let state = test_state(dir.clone(), ring.clone(), cfg);
        let shutdown = state.shutdown.clone();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (crd, cwr) = tokio::io::split(client_io);
        let spill_for_actor = spill.clone();
        let actor = tokio::spawn(async move {
            serve_online(&state, &spill_for_actor, crd, Arc::new(Mutex::new(cwr))).await
        });

        let (mut srd, mut swr) = tokio::io::split(server_io);
        // First batch arrives.
        let first_id = match read_message(&mut srd).await.unwrap() {
            Message::EventBatch { batch_id, .. } => batch_id,
            other => panic!("expected first EventBatch, got {other:?}"),
        };

        // Offer more events while the first batch is unacked.
        ring.offer(ev(2));
        ring.offer(ev(3));

        // No second batch should arrive within a few flush intervals (we may see
        // Pings, but never an EventBatch) because we are at the in-flight limit.
        let blocked = tokio::time::timeout(Duration::from_millis(150), async {
            loop {
                match read_message(&mut srd).await.unwrap() {
                    Message::EventBatch { .. } => break true,
                    _ => continue, // ignore keepalives etc.
                }
            }
        })
        .await;
        assert!(
            blocked.is_err(),
            "no second batch may be sent before the first is acked"
        );

        // Ack the first; now the second batch (events 2,3) must be delivered.
        write_message(
            &mut swr,
            &Message::BatchAck {
                batch_id: first_id,
                accepted: 1,
            },
        )
        .await
        .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Message::EventBatch { events, .. } = read_message(&mut srd).await.unwrap() {
                    break events;
                }
            }
        })
        .await
        .expect("second batch must arrive after ack");
        assert_eq!(second.len(), 2, "the two queued events form the next batch");

        shutdown.trigger();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
