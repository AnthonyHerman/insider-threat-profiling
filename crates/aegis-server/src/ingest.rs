//! # TLS ingest listener (`ingest.rs`)
//!
//! The network data path: a self-signed-TLS listener that accepts enrolled
//! agents, runs the [`aegis_proto`] handshake + session state machine, persists
//! raw telemetry to the [`Store`], and feeds it onto the host event bus via the
//! [`Emitter`]. It is a plain Tokio task tree (not a plugin): the host owns
//! processing; this module owns the wire.
//!
//! ## What it is responsible for
//!
//! * **Certificate bootstrap** ([`load_or_create_server_cert`]): on first start
//!   self-sign a leaf with `rcgen`, persist `tls.crt` / `tls.key` (the key
//!   atomically and mode `0600`); on later starts load them back. The SHA-256 of
//!   the leaf DER is the *pin* — both the value agents pin out-of-band and the
//!   `pin` mixed into the session-auth digest.
//! * **Accept loop** ([`serve`]): bind a `TcpListener`, build a TLS-1.3 acceptor
//!   via [`aegis_proto::tls::server_config`], and per connection enforce a global
//!   connection cap (a [`Semaphore`]) and a first-frame deadline before handing
//!   off to [`handle_conn`].
//! * **Session state machine**: enroll, or authenticate (`ClientHello` → Noop
//!   challenge → signature → `ServerHello`) then stream `EventBatch`es. Ingested
//!   events have their `agent_id` overwritten with the authenticated identity and
//!   their `kind` validated against the raw-telemetry allowlist (so an agent can
//!   neither forge identity nor inject derived `score`/`alert` rows). Each
//!   accepted event is written to the store *then* emitted; the batch is acked.
//!
//! ## Trust boundary
//!
//! Nothing the agent sends is trusted for identity or routing: `event.agent_id`
//! is replaced server-side, and only the [`INGESTIBLE_KINDS`] raw kinds are
//! accepted into the store and the bus. Derived kinds (`score`, `detection`,
//! `alert`) exist only on the internal bus, produced by the central processors;
//! the [`crate::sink`] persists those.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aegis_proto::pin::{self, PIN_LEN};
use aegis_proto::{read_message, write_message, Message, ServerCommand};
use aegis_sdk::{now_ns, Emitter, Event};
use anyhow::Context;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::enroll;
use crate::registry::Router;
use crate::store::Store;

/// Maximum simultaneously-accepted TLS connections. Each held connection costs a
/// task and a `redb` handle clone; the cap bounds resource use against a flood of
/// half-open or idle connections. Permits are released when a connection ends.
pub const MAX_CONNECTIONS: usize = 1024;

/// How long a freshly-accepted connection has to send its first protocol frame
/// (`EnrollRequest` or `ClientHello`) before it is dropped. Stops a peer that
/// completes the TLS handshake but never speaks from pinning a slot/task.
pub const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum idle time in the authenticated session read loop before the server
/// tears the connection down. A healthy agent sends a keepalive `Ping` well
/// within this window (default agent keepalive is 15s); the timeout backstops a
/// silently-stalled authenticated peer that would otherwise pin a connection
/// permit, task, and `redb` handle indefinitely (Tokio `TcpStream` keepalives are
/// off by default).
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Capacity of a session's command queue (server → agent). Commands beyond this
/// are reported to the enqueuer as [`crate::registry::RouterError::ChannelFull`].
const COMMAND_QUEUE_DEPTH: usize = 64;

/// Upper bound on per-session de-duplication memory: the set of recently-seen
/// `Event.id`s. Replayed-on-reconnect events arrive on a *new* connection (fresh
/// set); this guards only against in-session retransmits, so a modest cap is
/// ample and prevents unbounded growth on a very long-lived session.
const DEDUP_CAPACITY: usize = 65_536;

/// Capacity of the cross-connection (global) replay-dedup window. Larger than the
/// per-session window because it spans every agent; still O(1)-bounded memory
/// (~16 bytes/id). FIFO eviction means only genuinely old ids age out.
const GLOBAL_DEDUP_CAPACITY: usize = 262_144;

/// A de-dup window shared across all connections (see [`accept_loop`]). Wrapped in
/// an async [`Mutex`] because connection tasks run concurrently; the lock is held
/// only for the O(1) `insert` and never across an `.await`.
type SharedDedup = Arc<Mutex<DedupWindow>>;

/// How far an agent-supplied `ts_ns` may lead/lag the server clock before it is
/// clamped to `now`. The timestamp is the audit-log sort key
/// ([`composite_key`](crate::store)), so an out-of-range value from a compromised
/// endpoint would corrupt ordering and pagination. One hour of skew tolerance
/// covers legitimate clock drift and brief spill replay; anything beyond is reset
/// to the server's `now_ns()`.
const MAX_TS_SKEW_NS: u64 = 60 * 60 * 1_000_000_000;

/// Maximum accepted length (bytes) of an agent-supplied `event.source`. Truncated
/// past this to bound per-row storage and keep logs/UI sane.
const MAX_SOURCE_LEN: usize = 128;

/// Maximum number of `labels` entries retained on an ingested event.
const MAX_LABELS: usize = 32;
/// Maximum length (bytes) of a single label key or value (truncated past this).
const MAX_LABEL_KV_LEN: usize = 256;

/// A bounded, insertion-ordered de-duplication window over `Event.id`s.
///
/// Backs the in-session retransmit guard. A `HashSet` gives O(1) membership but
/// has no ordered eviction, so the prior implementation evicted in hash-bucket
/// order and could drop a *recently* seen id (re-opening a replay window). Pairing
/// the set with a `VecDeque` recording insertion order makes eviction true FIFO:
/// at capacity the genuine oldest id is removed.
struct DedupWindow {
    set: HashSet<uuid::Uuid>,
    order: std::collections::VecDeque<uuid::Uuid>,
    capacity: usize,
}

impl DedupWindow {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        DedupWindow {
            set: HashSet::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record `id` as seen. Returns `true` if it was newly inserted, `false` if it
    /// was already present (a duplicate). Evicts the oldest id first when full.
    fn insert(&mut self, id: uuid::Uuid) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.order.push_back(id);
        self.set.insert(id);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// Clamp/validate agent-supplied event fields on ingest (M5). `agent_id` is
/// already overwritten with the authenticated identity and `kind` allowlisted by
/// the caller; this hardens the *remaining* trusted-by-default fields:
///
/// * `ts_ns` — clamped to a sane window around the server clock (it is the audit
///   B-tree sort key, so a wild value corrupts ordering/pagination);
/// * `source` — truncated to [`MAX_SOURCE_LEN`] (attribution/log-bloat guard);
/// * `labels` — capped to [`MAX_LABELS`] entries with each key/value truncated to
///   [`MAX_LABEL_KV_LEN`] (per-write DB bloat guard).
fn sanitize_ingest_fields(event: &mut Event) {
    let now = now_ns();
    let lo = now.saturating_sub(MAX_TS_SKEW_NS);
    let hi = now.saturating_add(MAX_TS_SKEW_NS);
    if event.ts_ns < lo || event.ts_ns > hi {
        event.ts_ns = now;
    }

    truncate_to(&mut event.source, MAX_SOURCE_LEN);

    if event.labels.len() > MAX_LABELS
        || event
            .labels
            .iter()
            .any(|(k, v)| k.len() > MAX_LABEL_KV_LEN || v.len() > MAX_LABEL_KV_LEN)
    {
        let trimmed: std::collections::BTreeMap<String, String> = event
            .labels
            .iter()
            .take(MAX_LABELS)
            .map(|(k, v)| {
                let mut k = k.clone();
                let mut v = v.clone();
                truncate_to(&mut k, MAX_LABEL_KV_LEN);
                truncate_to(&mut v, MAX_LABEL_KV_LEN);
                (k, v)
            })
            .collect();
        event.labels = trimmed;
    }
}

/// Truncate `s` in place to at most `max` bytes, respecting UTF-8 char
/// boundaries (never splits a multi-byte char).
fn truncate_to(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

/// Raw telemetry kinds an agent is allowed to push. Derived kinds
/// (`score`/`detection`/`alert`) and the `custom` escape hatch are rejected: the
/// processors produce derived kinds internally and the [`crate::sink`] persists
/// them, so accepting them off the wire would let an agent forge findings.
pub const INGESTIBLE_KINDS: &[&str] = &[
    "input.keystroke",
    "command.observed",
    "session.start",
    "session.end",
    "process.exec",
    "heartbeat",
];

/// Whether `kind` is an ingestible raw-telemetry kind (see [`INGESTIBLE_KINDS`]).
fn is_ingestible(kind: &str) -> bool {
    INGESTIBLE_KINDS.contains(&kind)
}

// --- Certificate bootstrap ------------------------------------------------

/// Load the server's TLS material, generating and persisting a self-signed leaf
/// on first start.
///
/// Files live under `{data_dir}/server/`: `tls.crt` (PEM chain) and `tls.key`
/// (PEM private key, mode `0600`). When absent, a leaf is minted with
/// `rcgen::generate_simple_self_signed(["aegisd"])` and both files are written —
/// the key via a temp-file + `rename` so it is never momentarily world-readable.
/// Returns the cert chain, the private key, and the SHA-256 pin of the leaf DER.
pub fn load_or_create_server_cert(
    data_dir: &Path,
) -> anyhow::Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    [u8; PIN_LEN],
)> {
    let server_dir = data_dir.join("server");
    std::fs::create_dir_all(&server_dir)
        .with_context(|| format!("creating {}", server_dir.display()))?;
    let crt_path = server_dir.join("tls.crt");
    let key_path = server_dir.join("tls.key");

    if !crt_path.exists() || !key_path.exists() {
        let ck = rcgen::generate_simple_self_signed(vec!["aegisd".to_string()])
            .context("generating self-signed server certificate")?;
        // Cert PEM is public; write it directly (atomic for consistency).
        write_atomic(&crt_path, ck.cert.pem().as_bytes(), 0o644)
            .with_context(|| format!("writing {}", crt_path.display()))?;
        // Key PEM is secret: 0600, atomic temp+rename so there is no window in
        // which a partially-written or default-perm key is readable.
        write_atomic(&key_path, ck.key_pair.serialize_pem().as_bytes(), 0o600)
            .with_context(|| format!("writing {}", key_path.display()))?;
        tracing::info!(dir = %server_dir.display(), "generated self-signed server certificate");
    }

    // Load (the just-written, or pre-existing) PEM material.
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&crt_path)
        .with_context(|| format!("opening {}", crt_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {}", crt_path.display()))?;
    if chain.is_empty() {
        anyhow::bail!("no certificates found in {}", crt_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .with_context(|| format!("parsing private key in {}", key_path.display()))?;

    // Pin = SHA-256 of the LEAF (first) cert's DER.
    let leaf_pin = pin::fingerprint(chain[0].as_ref());
    Ok((chain, key, leaf_pin))
}

/// Write `bytes` to `path` atomically (temp file in the same dir + `rename`) with
/// the given Unix `mode`, applied to the temp file *before* the rename.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        // Enforce mode even if the file pre-existed with looser perms.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

// --- Accept loop ----------------------------------------------------------

/// Bind the ingest listener on `addr` and spawn the accept loop.
///
/// Builds the TLS-1.3 acceptor from the (loaded-or-generated) server cert and
/// returns the [`JoinHandle`] of the accept-loop task. Each accepted connection
/// is handled on its own spawned task with cloned `emitter` / `store` / `router`
/// handles; accept errors are logged and non-fatal. Abort the returned handle to
/// stop listening (in-flight connection tasks observe their own read errors and
/// exit).
pub fn serve(
    addr: String,
    data_dir: PathBuf,
    emitter: Arc<dyn Emitter>,
    store: Arc<Store>,
    router: Router,
) -> anyhow::Result<JoinHandle<()>> {
    let (chain, key, pin) = load_or_create_server_cert(&data_dir)?;
    let server_config =
        aegis_proto::tls::server_config(chain, key).context("building rustls server config")?;
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(addr = %addr, error = %e, "ingest: failed to bind listener");
                return;
            }
        };
        tracing::info!(addr = %addr, "ingest: TLS listener bound");
        accept_loop(listener, acceptor, emitter, store, router, pin).await;
    });

    Ok(handle)
}

/// Drive the accept loop over an already-bound listener.
///
/// Split out from [`serve`] so the binding step (which can fail) is separate from
/// the never-returning loop, and so tests can bind an ephemeral-port listener and
/// learn its address before driving connections. Each connection runs on its own
/// task under a [`Semaphore`] permit ([`MAX_CONNECTIONS`]); accept errors are
/// logged and non-fatal.
async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    emitter: Arc<dyn Emitter>,
    store: Arc<Store>,
    router: Router,
    pin: [u8; PIN_LEN],
) {
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Bounded de-dup window of recently-seen `Event.id`s shared across ALL
    // connections (L3): a replay of the same id on a fresh connection — which has
    // its own per-session window and could land a distinct B-tree key once its
    // stale `ts_ns` is clamped — is still rejected here. FIFO eviction keeps it
    // bounded regardless of total traffic.
    let global_dedup: SharedDedup = Arc::new(Mutex::new(DedupWindow::new(GLOBAL_DEDUP_CAPACITY)));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Transient accept errors (e.g. fd exhaustion) are logged and
                // the loop continues rather than tearing the listener down.
                tracing::warn!(error = %e, "ingest: accept error");
                continue;
            }
        };

        // Acquire a connection permit; if the cap is reached, drop the
        // connection immediately rather than queueing unboundedly.
        let permit = match Arc::clone(&limiter).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(peer = %peer, "ingest: connection cap reached; dropping");
                drop(tcp);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let emitter = emitter.clone();
        let store = store.clone();
        let router = router.clone();
        let global_dedup = global_dedup.clone();
        tokio::spawn(async move {
            // Hold the permit for the whole connection lifetime.
            let _permit = permit;
            if let Err(e) = handle_conn(
                tcp,
                peer,
                acceptor,
                emitter,
                store,
                router,
                pin,
                global_dedup,
            )
            .await
            {
                tracing::debug!(peer = %peer, error = %e, "ingest: connection ended");
            }
        });
    }
}

/// A small protocol error type for the connection handler, so the accept loop can
/// log a single reason string. Most "errors" here are benign (peer closed).
#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("tls handshake failed: {0}")]
    Tls(std::io::Error),
    #[error("tls keying-material export failed: {0}")]
    Export(rustls::Error),
    #[error("first frame not received within timeout")]
    FirstFrameTimeout,
    #[error(transparent)]
    Proto(#[from] aegis_proto::ProtoError),
}

/// Run one accepted connection through the protocol state machine.
#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    emitter: Arc<dyn Emitter>,
    store: Arc<Store>,
    router: Router,
    pin: [u8; PIN_LEN],
    global_dedup: SharedDedup,
) -> Result<(), ConnError> {
    let mut tls = acceptor.accept(tcp).await.map_err(ConnError::Tls)?;

    // RFC-5705 exporter for channel binding. Read it on the typed server stream
    // before any framing (and before any split); this matches the agent, which
    // exports the same label before splitting its stream.
    let exporter: [u8; 32] = {
        let (_io, conn) = tls.get_ref();
        conn.export_keying_material([0u8; 32], aegis_proto::tls::AUTH_LABEL, None)
            .map_err(ConnError::Export)?
    };

    // First frame must arrive promptly; it selects enroll vs. session.
    let first = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_message(&mut tls)).await {
        Ok(r) => r?,
        Err(_) => return Err(ConnError::FirstFrameTimeout),
    };

    match first {
        // --- First contact: enrollment. ---------------------------------
        Message::EnrollRequest {
            token,
            hostname,
            os,
            agent_pubkey,
        } => {
            let response = match coerce_pubkey(&agent_pubkey) {
                Some(pk) => match enroll::enroll(&store, &token, &hostname, &os, pk) {
                    Ok(enroll::EnrollOutcome::Accepted { agent_id }) => {
                        tracing::info!(peer = %peer, agent_id = %agent_id, "ingest: agent enrolled");
                        Message::EnrollResponse {
                            accepted: true,
                            agent_id,
                            reason: None,
                        }
                    }
                    Ok(enroll::EnrollOutcome::Rejected { reason }) => {
                        tracing::warn!(peer = %peer, reason = %reason, "ingest: enrollment rejected");
                        Message::EnrollResponse {
                            accepted: false,
                            agent_id: String::new(),
                            reason: Some(reason),
                        }
                    }
                    Err(e) => {
                        tracing::error!(peer = %peer, error = %e, "ingest: enrollment store error");
                        Message::EnrollResponse {
                            accepted: false,
                            agent_id: String::new(),
                            reason: Some("internal error".to_string()),
                        }
                    }
                },
                None => Message::EnrollResponse {
                    accepted: false,
                    agent_id: String::new(),
                    reason: Some("agent_pubkey must be 32 bytes".to_string()),
                },
            };
            write_message(&mut tls, &response).await?;
            // The agent closes after enrollment and opens a fresh connection for
            // the session, so we are done here.
            Ok(())
        }

        // --- Subsequent session: authenticate then stream events. -------
        Message::ClientHello {
            proto_version,
            agent_id,
            agent_pubkey,
            ..
        } => {
            // Protocol-version gate.
            if proto_version != aegis_proto::PROTO_VERSION {
                write_message(
                    &mut tls,
                    &server_hello(
                        false,
                        Some(format!("unsupported proto_version {proto_version}")),
                    ),
                )
                .await?;
                return Ok(());
            }

            // The agent must be enrolled, and the pubkey it presents must match
            // the one stored at enrollment (binds the session to the identity).
            let agent_row = match store.agent(&agent_id) {
                Ok(Some(row)) => row,
                Ok(None) => {
                    write_message(&mut tls, &server_hello(false, Some("unknown agent".into())))
                        .await?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!(error = %e, "ingest: agent lookup failed");
                    write_message(
                        &mut tls,
                        &server_hello(false, Some("internal error".into())),
                    )
                    .await?;
                    return Ok(());
                }
            };
            match coerce_pubkey(&agent_pubkey) {
                Some(pk) if pk == agent_row.pubkey => {}
                _ => {
                    write_message(
                        &mut tls,
                        &server_hello(false, Some("pubkey mismatch".into())),
                    )
                    .await?;
                    return Ok(());
                }
            }

            // Challenge: send Noop{id}, expect CommandResult{id, detail=sig}.
            let challenge_id = enroll::make_challenge();
            write_message(
                &mut tls,
                &Message::Command {
                    id: challenge_id,
                    command: ServerCommand::Noop,
                },
            )
            .await?;

            // Bound the challenge reply: an enrolled (or key-theft) peer can
            // receive the Noop and then stall forever while holding a connection
            // permit. Reuse the first-frame deadline; an elapse maps to the same
            // timeout error as the first frame.
            let reply =
                match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_message(&mut tls)).await {
                    Ok(r) => r?,
                    Err(_) => return Err(ConnError::FirstFrameTimeout),
                };
            let sig_b64 = match reply {
                Message::CommandResult {
                    id,
                    ok: true,
                    detail: Some(sig),
                } if id == challenge_id => sig,
                _ => {
                    write_message(
                        &mut tls,
                        &server_hello(false, Some("malformed challenge response".into())),
                    )
                    .await?;
                    return Ok(());
                }
            };

            if !enroll::verify_challenge(
                &agent_row.pubkey,
                &pin,
                &agent_id,
                &challenge_id,
                &exporter,
                &sig_b64,
            ) {
                tracing::warn!(agent_id = %agent_id, "ingest: challenge verification failed");
                write_message(
                    &mut tls,
                    &server_hello(false, Some("authentication failed".into())),
                )
                .await?;
                return Ok(());
            }

            // Authenticated. Accept the session.
            write_message(&mut tls, &server_hello(true, None)).await?;
            let _ = store.touch_agent(&agent_id, now_ns());
            tracing::info!(peer = %peer, agent_id = %agent_id, "ingest: session authenticated");

            run_session(tls, agent_id, emitter, store, router, global_dedup).await
        }

        // Any other first frame is a protocol violation; close.
        other => {
            tracing::warn!(peer = %peer, ?other, "ingest: unexpected first frame");
            Ok(())
        }
    }
}

/// The authenticated online phase: register a command channel, then run a reader
/// task (events / ping / command-results) alongside a writer that drains queued
/// [`ServerCommand`]s — both over the split TLS stream, sharing one write half.
async fn run_session<S>(
    tls: S,
    agent_id: String,
    emitter: Arc<dyn Emitter>,
    store: Arc<Store>,
    router: Router,
    global_dedup: SharedDedup,
) -> Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(tls);
    let wr = Arc::new(Mutex::new(wr));

    // Register this session so the HTTP layer can push commands to it.
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ServerCommand>(COMMAND_QUEUE_DEPTH);
    router.register(agent_id.clone(), cmd_tx.clone()).await;

    // Writer: drain queued commands → Command frames. Ends when the channel
    // closes (session torn down) or a write fails.
    let writer_wr = wr.clone();
    let writer = tokio::spawn(async move {
        while let Some(command) = cmd_rx.recv().await {
            let msg = Message::Command {
                id: uuid::Uuid::new_v4(),
                command,
            };
            if send(&writer_wr, &msg).await.is_err() {
                break;
            }
        }
    });

    // Reader: events / ping / command-results, on this task.
    let read_result = read_loop(&mut rd, &wr, &agent_id, &emitter, &store, &global_dedup).await;

    // Teardown: unregister (only if still ours), stop the writer.
    router.unregister(&agent_id, &cmd_tx).await;
    writer.abort();
    let _ = writer.await;

    read_result
}

/// The session read loop. Returns `Ok(())` on a clean peer close, or the proto
/// error that ended the session.
async fn read_loop<R, W>(
    rd: &mut R,
    wr: &Arc<Mutex<W>>,
    agent_id: &str,
    emitter: &Arc<dyn Emitter>,
    store: &Arc<Store>,
    global_dedup: &SharedDedup,
) -> Result<(), ConnError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut seen: DedupWindow = DedupWindow::new(DEDUP_CAPACITY);

    loop {
        // Idle deadline: a silent authenticated peer must not pin the session
        // forever. On elapse we tear the session down cleanly (no error).
        let msg = match tokio::time::timeout(SESSION_IDLE_TIMEOUT, read_message(rd)).await {
            Ok(Ok(m)) => m,
            // A clean close (EOF) is the normal end of a session.
            Ok(Err(aegis_proto::ProtoError::Closed)) => return Ok(()),
            Ok(Err(e)) => return Err(ConnError::Proto(e)),
            Err(_) => {
                tracing::debug!(
                    agent_id = %agent_id,
                    timeout_s = SESSION_IDLE_TIMEOUT.as_secs(),
                    "ingest: session idle past timeout; closing"
                );
                return Ok(());
            }
        };

        match msg {
            Message::EventBatch { batch_id, events } => {
                let mut accepted: u32 = 0;
                for mut event in events {
                    // De-dup in-session retransmits by Event.id. `DedupWindow` is a
                    // true FIFO (insertion-ordered): at capacity it evicts the
                    // genuine oldest id, so a recently-seen id can never be evicted
                    // and replayed within the session (the prior `HashSet` evicted
                    // in hash-bucket order, which could drop a recent id).
                    if !seen.insert(event.id) {
                        continue;
                    }
                    // Cross-connection replay guard (L3): reject an id already seen
                    // on any recent connection. Lock held only for the O(1) insert.
                    if !global_dedup.lock().await.insert(event.id) {
                        tracing::debug!(
                            agent_id = %agent_id,
                            "ingest: dropping cross-session replayed event id"
                        );
                        continue;
                    }

                    // Trust boundary: force the authenticated identity and only
                    // accept raw-telemetry kinds.
                    if !is_ingestible(&event.kind) {
                        tracing::debug!(
                            agent_id = %agent_id,
                            kind = %event.kind,
                            "ingest: rejecting non-ingestible event kind"
                        );
                        continue;
                    }
                    event.agent_id = agent_id.to_string();

                    // Clamp/validate the remaining agent-supplied fields before
                    // they reach the store and the bus (M5): a compromised endpoint
                    // must not corrupt audit ordering, spoof attribution, or bloat
                    // the DB via oversized `source`/`labels`.
                    sanitize_ingest_fields(&mut event);

                    // Persist to the raw audit log first (so the log is complete
                    // even if the bus drops on a full queue), then emit.
                    if let Err(e) = store.write_event(&event) {
                        tracing::warn!(agent_id = %agent_id, error = %e, "ingest: write_event failed");
                        continue;
                    }
                    emit_to_bus(emitter, event).await;
                    accepted += 1;
                }

                let _ = store.touch_agent(agent_id, now_ns());
                send(wr, &Message::BatchAck { batch_id, accepted }).await?;
            }

            Message::Ping => {
                send(wr, &Message::Pong).await?;
            }

            // The agent reports command outcomes here (outside the challenge);
            // log and continue.
            Message::CommandResult { id, ok, detail } => {
                tracing::debug!(agent_id = %agent_id, %id, ok, ?detail, "ingest: command result");
            }

            Message::Pong => { /* keepalive ack; nothing to do */ }

            // Server-only or unexpected variants in the online phase: ignore.
            other => {
                tracing::debug!(agent_id = %agent_id, ?other, "ingest: ignoring unexpected frame");
            }
        }
    }
}

/// Emit an event onto the host bus. Split out so the `.await` boundary is
/// obvious and never sits inside a `redb` transaction.
async fn emit_to_bus(emitter: &Arc<dyn Emitter>, event: Event) {
    emitter.emit(event).await;
}

/// Build a `ServerHello` with the current proto version.
fn server_hello(accepted: bool, reason: Option<String>) -> Message {
    Message::ServerHello {
        proto_version: aegis_proto::PROTO_VERSION,
        accepted,
        reason,
    }
}

/// Coerce a wire `agent_pubkey: Vec<u8>` into a fixed 32-byte array, or `None` if
/// the length is wrong.
fn coerce_pubkey(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Write one framed message through the shared write half.
async fn send<W>(wr: &Arc<Mutex<W>>, msg: &Message) -> Result<(), aegis_proto::ProtoError>
where
    W: AsyncWrite + Unpin,
{
    let mut guard = wr.lock().await;
    write_message(&mut *guard, msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::{EventPayload, Severity};
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn ingestible_kinds_allow_raw_reject_derived() {
        for k in INGESTIBLE_KINDS {
            assert!(is_ingestible(k), "{k} should be ingestible");
        }
        for k in ["score", "detection", "alert", "custom"] {
            assert!(!is_ingestible(k), "{k} must not be ingestible");
        }
        // The typed payloads map to the expected allow/deny outcome.
        assert!(is_ingestible(
            EventPayload::Heartbeat { uptime_s: 1 }.default_kind()
        ));
        assert!(!is_ingestible(
            EventPayload::Alert {
                severity: Severity::High,
                title: "t".into(),
                detail: "d".into(),
                subject: None,
            }
            .default_kind()
        ));
    }

    #[test]
    fn coerce_pubkey_checks_length() {
        assert_eq!(coerce_pubkey(&[7u8; 32]), Some([7u8; 32]));
        assert_eq!(coerce_pubkey(&[7u8; 31]), None);
        assert_eq!(coerce_pubkey(&[7u8; 33]), None);
        assert_eq!(coerce_pubkey(&[]), None);
    }

    #[test]
    fn cert_bootstrap_is_persistent_and_0600_key() {
        let dir = TempDir::new().unwrap();
        let (chain1, _key1, pin1) = load_or_create_server_cert(dir.path()).unwrap();
        assert!(!chain1.is_empty());

        // The key file must be mode 0600.
        let key_path = dir.path().join("server").join("tls.key");
        let meta = std::fs::metadata(&key_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "key must be 0600");
        assert!(dir.path().join("server").join("tls.crt").exists());

        // A second load returns the SAME pin (cert persisted, not regenerated).
        let (_chain2, _key2, pin2) = load_or_create_server_cert(dir.path()).unwrap();
        assert_eq!(pin1, pin2, "pin must be stable across restarts");
    }

    #[test]
    fn server_config_builds_from_bootstrapped_cert() {
        // The bootstrapped chain + key must satisfy aegis_proto's server_config
        // (key matches leaf, TLS 1.3 available).
        let dir = TempDir::new().unwrap();
        let (chain, key, _pin) = load_or_create_server_cert(dir.path()).unwrap();
        assert!(aegis_proto::tls::server_config(chain, key).is_ok());
    }

    #[test]
    fn write_atomic_sets_mode_and_contents() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("secret");
        write_atomic(&p, b"hello", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // No leftover temp file in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp file must be renamed away");
    }

    /// The dedup set is keyed by Event.id: the same id twice is one accept.
    #[test]
    fn dedup_set_collapses_repeat_ids() {
        let mut seen: HashSet<Uuid> = HashSet::new();
        let id = Uuid::new_v4();
        assert!(seen.insert(id));
        assert!(!seen.insert(id), "second insert of same id is a dup");
    }

    /// L4 regression: `DedupWindow` is a true FIFO. The first id inserted must be
    /// the first evicted at capacity, and a recently-seen id must NOT be evicted
    /// (the old `HashSet` eviction could drop a recent id, re-opening a replay).
    #[test]
    fn dedup_window_evicts_oldest_first_and_dedups() {
        let mut w = DedupWindow::new(3);
        let ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();

        // Fill to capacity (3).
        assert!(w.insert(ids[0]));
        assert!(w.insert(ids[1]));
        assert!(w.insert(ids[2]));
        assert_eq!(w.len(), 3);
        // A repeat of any held id is a dup.
        assert!(!w.insert(ids[1]), "held id is a duplicate");

        // Inserting a 4th evicts the OLDEST (ids[0]) only.
        assert!(w.insert(ids[3]));
        assert_eq!(w.len(), 3);
        // ids[0] aged out -> it is now "new" again...
        assert!(w.insert(ids[0]), "oldest was evicted, so it re-inserts");
        // ...but the more-recent ids[2]/ids[3] are still remembered.
        assert!(!w.insert(ids[2]), "recent id must still be remembered");
        assert!(!w.insert(ids[3]), "recent id must still be remembered");
    }

    /// M5 regression: out-of-window `ts_ns` is reset to ~now; a far-past or
    /// far-future timestamp from a compromised endpoint cannot corrupt the audit
    /// sort key. A timestamp within the skew window is preserved.
    #[test]
    fn sanitize_clamps_ts_ns() {
        let mk = |ts: u64| {
            let mut e = Event::new("a", "plugin-tty", EventPayload::Heartbeat { uptime_s: 1 });
            e.ts_ns = ts;
            e
        };
        let now = now_ns();

        // Far future -> reset to ~now.
        let mut future = mk(now + 10 * MAX_TS_SKEW_NS);
        sanitize_ingest_fields(&mut future);
        assert!(future.ts_ns <= now_ns() && future.ts_ns + MAX_TS_SKEW_NS >= now);

        // Far past (epoch) -> reset to ~now.
        let mut past = mk(1_000);
        sanitize_ingest_fields(&mut past);
        assert!(past.ts_ns + MAX_TS_SKEW_NS >= now);

        // Within the window -> preserved exactly.
        let in_window = now.saturating_sub(MAX_TS_SKEW_NS / 2);
        let mut ok = mk(in_window);
        sanitize_ingest_fields(&mut ok);
        assert_eq!(ok.ts_ns, in_window, "in-window ts must be preserved");
    }

    /// M5 regression: an over-long `source` is truncated and oversized `labels`
    /// (too many entries, or over-long key/value) are bounded.
    #[test]
    fn sanitize_bounds_source_and_labels() {
        let mut e = Event::new(
            "a",
            "x".repeat(10_000), // oversized source
            EventPayload::Heartbeat { uptime_s: 1 },
        );
        e.ts_ns = now_ns();
        for i in 0..1000 {
            e.labels.insert(format!("k{i}"), "v".repeat(10_000));
        }
        sanitize_ingest_fields(&mut e);

        assert!(e.source.len() <= MAX_SOURCE_LEN, "source must be truncated");
        assert!(e.labels.len() <= MAX_LABELS, "labels count must be bounded");
        assert!(
            e.labels.values().all(|v| v.len() <= MAX_LABEL_KV_LEN),
            "label values must be truncated"
        );
        assert!(
            e.labels.keys().all(|k| k.len() <= MAX_LABEL_KV_LEN),
            "label keys must be bounded"
        );
    }

    /// `truncate_to` never splits a multibyte UTF-8 char.
    #[test]
    fn truncate_to_respects_char_boundaries() {
        let mut s = "é".repeat(10); // each 'é' is 2 bytes
        truncate_to(&mut s, 5); // 5 is mid-char; must back off to 4
        assert!(s.is_char_boundary(s.len()));
        assert!(s.len() <= 5);
    }

    // --- End-to-end session over real TLS on an ephemeral port -----------

    use aegis_proto::pin::PIN_LEN as TEST_PIN_LEN;
    use aegis_sdk::Event;
    use async_trait::async_trait;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts events pushed onto the bus, so the test can assert ingest emitted.
    struct CountingEmitter(Arc<AtomicUsize>);
    #[async_trait]
    impl Emitter for CountingEmitter {
        async fn emit(&self, _event: Event) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Sign a Noop challenge exactly as `plugin_transport::auth::sign_auth` does:
    /// nonce = SHA-256(challenge_id), sign the shared digest, base64-encode.
    fn agent_sign(
        key: &SigningKey,
        pin: &[u8; TEST_PIN_LEN],
        agent_id: &str,
        challenge_id: &Uuid,
        exporter: &[u8],
    ) -> String {
        let nonce = enroll::nonce_from_challenge(challenge_id);
        let digest = aegis_proto::tls::auth_challenge_digest(pin, agent_id, &nonce, exporter);
        base64::engine::general_purpose::STANDARD.encode(key.sign(&digest).to_bytes())
    }

    /// Full happy path: enroll, connect over pinned TLS, pass the Ed25519
    /// challenge, push a batch with one valid + one derived event, and confirm
    /// the valid one was persisted (with the authenticated agent_id) and emitted
    /// while the derived one was rejected.
    #[tokio::test]
    async fn end_to_end_session_persists_and_emits() {
        use tokio::net::TcpStream;
        use tokio_rustls::rustls::pki_types::ServerName;

        // Server-side: store + cert + acceptor.
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (chain, key, pin) = load_or_create_server_cert(dir.path()).unwrap();
        let acceptor = TlsAcceptor::from(aegis_proto::tls::server_config(chain, key).unwrap());

        // Enroll an agent in-process with a known signing key.
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let (token, _) = enroll::create_token(&store, "test-host").unwrap();
        let agent_id = match enroll::enroll(&store, &token, "host", "Linux", pubkey).unwrap() {
            enroll::EnrollOutcome::Accepted { agent_id } => agent_id,
            other => panic!("enroll failed: {other:?}"),
        };

        // Bind an ephemeral port and drive the accept loop.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let emitter: Arc<dyn Emitter> = Arc::new(CountingEmitter(counter.clone()));
        let router = Router::new();
        let server_task = tokio::spawn(accept_loop(
            listener,
            acceptor,
            emitter,
            store.clone(),
            router.clone(),
            pin,
        ));

        // Client-side: pinned TLS connect.
        let client_cfg = aegis_proto::tls::client_config(vec![pin]);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("aegisd").unwrap();
        let mut tls = aegis_proto::tls::connect(client_cfg, name, tcp)
            .await
            .unwrap();

        // Export keying material BEFORE any framing (matches the agent).
        let mut exporter = [0u8; 32];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, aegis_proto::tls::AUTH_LABEL, None)
            .unwrap();

        // ClientHello.
        write_message(
            &mut tls,
            &Message::ClientHello {
                proto_version: aegis_proto::PROTO_VERSION,
                agent_id: agent_id.clone(),
                hostname: "host".into(),
                os: "Linux".into(),
                agent_pubkey: pubkey.to_vec(),
            },
        )
        .await
        .unwrap();

        // Expect a Noop challenge; sign and reply.
        let challenge_id = match read_message(&mut tls).await.unwrap() {
            Message::Command {
                id,
                command: ServerCommand::Noop,
            } => id,
            other => panic!("expected Noop challenge, got {other:?}"),
        };
        let sig = agent_sign(&signing_key, &pin, &agent_id, &challenge_id, &exporter);
        write_message(
            &mut tls,
            &Message::CommandResult {
                id: challenge_id,
                ok: true,
                detail: Some(sig),
            },
        )
        .await
        .unwrap();

        // Expect ServerHello accepted.
        match read_message(&mut tls).await.unwrap() {
            Message::ServerHello { accepted: true, .. } => {}
            other => panic!("expected ServerHello accepted, got {other:?}"),
        }

        // Send a batch: one valid keystroke (lying about agent_id) + one derived
        // alert (must be rejected).
        let valid = {
            let mut e = Event::new(
                "SPOOFED-AGENT", // server must overwrite this
                "plugin-tty",
                EventPayload::Keystroke {
                    session_id: "s1".into(),
                    inter_arrival_ns: 1_000_000,
                    is_paste: false,
                    burst_len: 1,
                },
            );
            e.ts_ns = 5_000;
            e
        };
        let derived = Event::new(
            "SPOOFED-AGENT",
            "plugin-x",
            EventPayload::Alert {
                severity: Severity::Critical,
                title: "forged".into(),
                detail: "should be rejected".into(),
                subject: None,
            },
        );
        let batch_id = Uuid::new_v4();
        write_message(
            &mut tls,
            &Message::EventBatch {
                batch_id,
                events: vec![valid.clone(), derived],
            },
        )
        .await
        .unwrap();

        // BatchAck: exactly one accepted (the derived alert was rejected).
        match read_message(&mut tls).await.unwrap() {
            Message::BatchAck {
                batch_id: got,
                accepted,
            } => {
                assert_eq!(got, batch_id);
                assert_eq!(accepted, 1, "only the raw keystroke should be accepted");
            }
            other => panic!("expected BatchAck, got {other:?}"),
        }

        // The store persisted exactly the keystroke, with the AUTHENTICATED
        // agent_id (not the spoofed one), and the emitter saw exactly one event.
        let events = store.events_for_agent(&agent_id, 0, 10).unwrap();
        assert_eq!(
            events.len(),
            1,
            "one raw event persisted under real agent_id"
        );
        assert_eq!(events[0].kind, "input.keystroke");
        assert_eq!(events[0].agent_id, agent_id);
        assert!(
            store
                .events_for_agent("SPOOFED-AGENT", 0, 10)
                .unwrap()
                .is_empty(),
            "nothing stored under the spoofed agent_id"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one event emitted"
        );

        // The session is registered while open.
        assert!(router.is_connected(&agent_id).await);

        // Close the client; the session unregisters on disconnect.
        drop(tls);
        // Give the server task a moment to observe EOF and unregister.
        for _ in 0..50 {
            if !router.is_connected(&agent_id).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !router.is_connected(&agent_id).await,
            "unregistered on disconnect"
        );

        server_task.abort();
    }

    /// A connection that presents a `ClientHello` for an unknown agent is
    /// rejected with `ServerHello{accepted:false}` and no challenge is issued.
    #[tokio::test]
    async fn unknown_agent_is_rejected() {
        use tokio::net::TcpStream;
        use tokio_rustls::rustls::pki_types::ServerName;

        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (chain, key, pin) = load_or_create_server_cert(dir.path()).unwrap();
        let acceptor = TlsAcceptor::from(aegis_proto::tls::server_config(chain, key).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let emitter: Arc<dyn Emitter> = Arc::new(CountingEmitter(counter));
        let server_task = tokio::spawn(accept_loop(
            listener,
            acceptor,
            emitter,
            store,
            Router::new(),
            pin,
        ));

        let client_cfg = aegis_proto::tls::client_config(vec![pin]);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("aegisd").unwrap();
        let mut tls = aegis_proto::tls::connect(client_cfg, name, tcp)
            .await
            .unwrap();

        write_message(
            &mut tls,
            &Message::ClientHello {
                proto_version: aegis_proto::PROTO_VERSION,
                agent_id: "never-enrolled".into(),
                hostname: "h".into(),
                os: "o".into(),
                agent_pubkey: vec![0u8; 32],
            },
        )
        .await
        .unwrap();

        match read_message(&mut tls).await.unwrap() {
            Message::ServerHello {
                accepted: false,
                reason,
                ..
            } => assert!(reason.unwrap_or_default().contains("unknown")),
            other => panic!("expected rejection, got {other:?}"),
        }

        server_task.abort();
    }

    /// A correct enrollment over the wire returns an `EnrollResponse{accepted}`
    /// with a UUID agent_id, and burns the token.
    #[tokio::test]
    async fn wire_enrollment_round_trip() {
        use tokio::net::TcpStream;
        use tokio_rustls::rustls::pki_types::ServerName;

        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (chain, key, pin) = load_or_create_server_cert(dir.path()).unwrap();
        let acceptor = TlsAcceptor::from(aegis_proto::tls::server_config(chain, key).unwrap());
        let (token, _) = enroll::create_token(&store, "laptop").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let emitter: Arc<dyn Emitter> = Arc::new(CountingEmitter(counter));
        let server_task = tokio::spawn(accept_loop(
            listener,
            acceptor,
            emitter,
            store.clone(),
            Router::new(),
            pin,
        ));

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();

        let client_cfg = aegis_proto::tls::client_config(vec![pin]);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("aegisd").unwrap();
        let mut tls = aegis_proto::tls::connect(client_cfg, name, tcp)
            .await
            .unwrap();

        write_message(
            &mut tls,
            &Message::EnrollRequest {
                token: token.clone(),
                hostname: "laptop".into(),
                os: "Linux".into(),
                agent_pubkey: pubkey.to_vec(),
            },
        )
        .await
        .unwrap();

        let agent_id = match read_message(&mut tls).await.unwrap() {
            Message::EnrollResponse {
                accepted: true,
                agent_id,
                ..
            } => agent_id,
            other => panic!("expected acceptance, got {other:?}"),
        };
        assert!(Uuid::parse_str(&agent_id).is_ok());
        // The agent row now exists; the token is burned.
        assert!(store.agent(&agent_id).unwrap().is_some());
        assert!(
            store
                .list_tokens()
                .unwrap()
                .iter()
                .find(|(t, _)| *t == token)
                .map(|(_, r)| r.used)
                .unwrap(),
            "token must be marked used"
        );

        server_task.abort();
    }
}
