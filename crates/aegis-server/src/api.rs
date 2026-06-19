//! # Operator HTTP/JSON API + live feed (`api.rs`)
//!
//! The loopback operator surface for `aegisd`: a small axum 0.7 application that
//! serves a read-mostly JSON API over the embedded [`Store`](crate::store), a
//! command-dispatch endpoint backed by the live [`Router`](crate::registry), a
//! Server-Sent-Events live feed, and (as the catch-all fallback) the embedded
//! [`dashboard`](crate::dashboard) assets. It binds to a loopback address by
//! default and is the only thing in the process that talks plain HTTP.
//!
//! ## Shape
//!
//! * [`AppState`] is the cheap-to-clone shared context: the [`Store`] handle, the
//!   command [`Router`], the SSE fan-out [`broadcast::Sender`], and a small
//!   [`ServerInfo`] (cert fingerprint + protocol version). axum clones it per
//!   request, so every field is itself an `Arc`/`Clone`.
//! * [`router`] builds the full route table (see the module-level route doc in
//!   the design) and layers in [`security_headers`] on every response and the
//!   dashboard fallback for non-API paths.
//! * Handlers are thin: they read owned `Vec`s/`Option`s from the [`Store`],
//!   optionally filter/limit in-handler (keeping the store API small), and map
//!   the result to a serialisable DTO. Mutating routes are the alert ack, the
//!   enrollment-token CRUD, and the fire-and-forget command POST.
//!
//! ## Errors
//!
//! Every fallible handler returns `Result<_, ApiError>`. [`ApiError`] renders a
//! `{ "error": "..." }` body with the right status: storage failures are `500`
//! (logged before returning), and the domain cases map to `404` / `409` / `503`.
//!
//! ## Security posture
//!
//! This API is unauthenticated and intended for loopback only; [`serve`] warns
//! if asked to bind a non-`127.` address. [`security_headers`] sets
//! `X-Content-Type-Options`, `X-Frame-Options`, and a restrictive
//! `Content-Security-Policy` on every response so the embedded dashboard cannot
//! load third-party origins.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router as AxumRouter};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use aegis_proto::ServerCommand;

use crate::dashboard;
use crate::enroll;
use crate::registry::{Router, RouterError};
use crate::store::{AgentRow, AlertRow, DetectionRow, EventRow, ScoreRow, Store, TokenRow};

/// Capacity of the SSE fan-out channel. Slow `/api/v1/live` subscribers that
/// fall this far behind are dropped (broadcast lag semantics) rather than
/// back-pressuring the write path; the dashboard re-syncs from the REST API on
/// reconnect.
pub const LIVE_CHANNEL_CAPACITY: usize = 1024;

/// Static facts about this server, surfaced at `/api/v1/server-info` and folded
/// into token-creation responses. Cheap to clone (one owned `String` + a `u16`).
#[derive(Clone, Debug, Serialize)]
pub struct ServerInfo {
    /// Hex SHA-256 of the server's leaf TLS certificate DER — the pin operators
    /// distribute to agents (see [`enroll::cert_fingerprint`]).
    pub fingerprint: String,
    /// The wire protocol version agents must speak ([`aegis_proto::PROTO_VERSION`]).
    pub proto_version: u16,
}

/// Shared, cheaply-cloneable context for every HTTP handler.
///
/// axum clones this once per request, so each field is an `Arc`/`Clone` handle
/// rather than owned data. The command [`Router`] is reused directly (it already
/// wraps `Arc<RwLock<..>>`) so the HTTP layer and the ingest connection tasks
/// share one live-connection table.
#[derive(Clone)]
pub struct AppState {
    /// The embedded datastore (shared with ingest and the store sink).
    pub store: Arc<Store>,
    /// The live `agent_id` → command-channel table, for command dispatch.
    pub router: Router,
    /// Fan-out for the SSE live feed; the store sink publishes onto it.
    pub live_tx: broadcast::Sender<LiveEvent>,
    /// Static server identity / protocol facts.
    pub server_info: ServerInfo,
}

/// One event on the `/api/v1/live` SSE feed.
///
/// Tagged by `kind` so a dashboard can attach a per-name `EventSource` listener
/// (the SSE `event:` field is set to the `kind` value). Constructed by the store
/// sink ([`crate::sink`]) after each durable write.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiveEvent {
    /// A risk score was (re)computed for a subject.
    Score {
        agent_id: String,
        subject: String,
        score: f64,
        ts_ns: u64,
    },
    /// A human-vs-agent detection landed for a subject.
    Detection {
        agent_id: String,
        subject: String,
        verdict: String,
        confidence: f64,
        ts_ns: u64,
    },
    /// An alert was raised.
    Alert {
        agent_id: String,
        severity: String,
        title: String,
        subject: Option<String>,
        ts_ns: u64,
    },
    /// An agent was seen (heartbeat); `hostname` is present if the agent is
    /// enrolled.
    AgentSeen {
        agent_id: String,
        hostname: Option<String>,
        ts_ns: u64,
    },
}

impl LiveEvent {
    /// The SSE event name for this variant (matches the serde `kind` tag), used
    /// to set the `event:` field so per-name dashboard listeners fire.
    fn name(&self) -> &'static str {
        match self {
            LiveEvent::Score { .. } => "score",
            LiveEvent::Detection { .. } => "detection",
            LiveEvent::Alert { .. } => "alert",
            LiveEvent::AgentSeen { .. } => "agent_seen",
        }
    }
}

// --- Response DTOs --------------------------------------------------------
//
// The store rows mostly serialise straight to the API shapes (their field names
// already match). Two need a transform: agents expose the pubkey as hex, and
// events expose the stored JSON payload bytes as parsed JSON rather than a byte
// array.

/// An agent as returned by the API: the [`AgentRow`] fields with the raw
/// `pubkey` bytes rendered as a hex string.
#[derive(Debug, Serialize)]
struct AgentRecord {
    agent_id: String,
    hostname: String,
    os: String,
    pubkey_hex: String,
    enrolled_at_ns: u64,
    last_seen_ns: u64,
}

impl From<AgentRow> for AgentRecord {
    fn from(r: AgentRow) -> Self {
        AgentRecord {
            agent_id: r.agent_id,
            hostname: r.hostname,
            os: r.os,
            pubkey_hex: hex::encode(r.pubkey),
            enrolled_at_ns: r.enrolled_at_ns,
            last_seen_ns: r.last_seen_ns,
        }
    }
}

/// An audit-log event as returned by the API: the [`EventRow`] fields with the
/// stored `payload_json` bytes parsed back into JSON for embedding.
#[derive(Debug, Serialize)]
struct EventRecord {
    id: String,
    ts_ns: u64,
    agent_id: String,
    source: String,
    kind: String,
    payload: serde_json::Value,
}

impl From<EventRow> for EventRecord {
    fn from(r: EventRow) -> Self {
        // The payload is verbatim JSON written by the producer; if it somehow
        // fails to parse, surface null rather than failing the whole request.
        let payload = serde_json::from_slice(&r.payload_json).unwrap_or(serde_json::Value::Null);
        EventRecord {
            id: uuid::Uuid::from_bytes(r.id).to_string(),
            ts_ns: r.ts_ns,
            agent_id: r.agent_id,
            source: r.source,
            kind: r.kind,
            payload,
        }
    }
}

/// An enrollment token as returned by the API (the store yields `(token, row)`
/// pairs; this flattens them).
#[derive(Debug, Serialize)]
struct TokenRecord {
    token: String,
    label: String,
    created_at_ns: u64,
    used: bool,
}

impl From<(String, TokenRow)> for TokenRecord {
    fn from((token, row): (String, TokenRow)) -> Self {
        TokenRecord {
            token,
            label: row.label,
            created_at_ns: row.created_at_ns,
            used: row.used,
        }
    }
}

// --- Query / body parameter structs --------------------------------------

/// Filters for `GET /api/v1/scores`.
#[derive(Debug, Deserialize)]
struct ScoreQuery {
    subject: Option<String>,
    min_score: Option<f64>,
    limit: Option<usize>,
}

/// Filters for `GET /api/v1/detections`.
#[derive(Debug, Deserialize)]
struct DetectionQuery {
    verdict: Option<String>,
    min_confidence: Option<f64>,
    limit: Option<usize>,
}

/// Filters for `GET /api/v1/alerts`.
#[derive(Debug, Deserialize)]
struct AlertQuery {
    severity: Option<String>,
    acknowledged: Option<bool>,
    agent_id: Option<String>,
    since_ns: Option<u64>,
    limit: Option<usize>,
}

/// Pagination for `GET /api/v1/events/:agent_id`.
#[derive(Debug, Deserialize)]
struct EventQuery {
    page: Option<usize>,
    page_size: Option<usize>,
}

/// Body for `POST /api/v1/tokens`.
#[derive(Debug, Deserialize)]
struct CreateToken {
    label: String,
}

/// Default alert page size when no `limit` is supplied. Alerts are the busiest
/// feed; a bounded default keeps the dashboard's first paint cheap.
const DEFAULT_ALERT_LIMIT: usize = 200;
/// Default events page size for `GET /api/v1/events/:agent_id`.
const DEFAULT_EVENT_PAGE_SIZE: usize = 50;
/// Hard cap on the events page size so a client cannot request an unbounded page.
const MAX_EVENT_PAGE_SIZE: usize = 500;

// --- Router ---------------------------------------------------------------

/// Build the operator [`AxumRouter`] over `state`.
///
/// Wires the full `/api/v1` route table, attaches the embedded dashboard as the
/// fallback (so any non-API path serves a dashboard asset / the SPA shell), and
/// layers [`security_headers`] onto every response.
pub fn router(state: AppState) -> AxumRouter {
    AxumRouter::new()
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/:agent_id", get(get_agent))
        .route("/api/v1/agents/:agent_id/command", post(post_command))
        .route("/api/v1/scores", get(list_scores))
        .route("/api/v1/scores/:agent_id", get(scores_for_agent))
        .route("/api/v1/detections", get(list_detections))
        .route("/api/v1/detections/:agent_id", get(detections_for_agent))
        .route("/api/v1/alerts", get(list_alerts))
        .route("/api/v1/alerts/:id/ack", axum::routing::patch(ack_alert))
        .route("/api/v1/events/:agent_id", get(events_for_agent))
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/:token", axum::routing::delete(revoke_token))
        .route("/api/v1/server-info", get(server_info))
        .route("/api/v1/live", get(sse_live))
        .fallback(dashboard::static_handler)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// --- Error type -----------------------------------------------------------

/// The single error type returned by every fallible handler.
///
/// Renders `{ "error": "<message>" }` with an appropriate status. A storage
/// (`anyhow`) failure becomes `500` and is logged via `tracing::error!` before
/// the response is built (so the operator sees the underlying cause that the
/// client does not).
#[derive(Debug)]
enum ApiError {
    /// 400 — the request body failed validation (e.g. an over-long token label).
    BadRequest(String),
    /// 404 — the addressed resource (agent, alert) does not exist, or the target
    /// agent is not connected.
    NotFound(String),
    /// 409 — the request conflicts with current state (token already used /
    /// unknown on revoke).
    Conflict(String),
    /// 503 — the agent's command channel is full; retry later.
    ServiceUnavailable(String),
    /// 500 — an internal (storage) error; the detail is logged, not exposed.
    Internal(anyhow::Error),
}

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError::NotFound(msg.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}

impl From<RouterError> for ApiError {
    fn from(e: RouterError) -> Self {
        match e {
            RouterError::NotConnected => ApiError::NotFound("agent is not connected".into()),
            RouterError::ChannelFull => {
                ApiError::ServiceUnavailable("agent command channel is full".into())
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::Internal(e) => {
                // Log the underlying cause; return an opaque message.
                tracing::error!(error = %e, "api: internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

// --- Handlers: agents -----------------------------------------------------

/// `GET /api/v1/agents` — all enrolled agents.
async fn list_agents(State(st): State<AppState>) -> Result<Json<Vec<AgentRecord>>, ApiError> {
    let agents = st.store.agents()?;
    Ok(Json(agents.into_iter().map(AgentRecord::from).collect()))
}

/// `GET /api/v1/agents/:agent_id` — one agent, or 404.
async fn get_agent(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, ApiError> {
    match st.store.agent(&agent_id)? {
        Some(row) => Ok(Json(AgentRecord::from(row))),
        None => Err(ApiError::not_found("agent not found")),
    }
}

/// `POST /api/v1/agents/:agent_id/command` — fire-and-forget a [`ServerCommand`]
/// to a connected agent. Returns `202 Accepted` once queued; `404` if the agent
/// is not connected, `503` if its command channel is full.
async fn post_command(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
    Json(command): Json<ServerCommand>,
) -> Result<StatusCode, ApiError> {
    st.router.send(&agent_id, command).await?;
    Ok(StatusCode::ACCEPTED)
}

// --- Handlers: scores -----------------------------------------------------

/// `GET /api/v1/scores` — latest scores across all subjects, with optional
/// `subject` / `min_score` filters and a `limit`.
async fn list_scores(
    State(st): State<AppState>,
    Query(q): Query<ScoreQuery>,
) -> Result<Json<Vec<ScoreRow>>, ApiError> {
    let mut rows = st.store.scores()?;
    if let Some(subject) = &q.subject {
        rows.retain(|r| &r.subject == subject);
    }
    if let Some(min) = q.min_score {
        rows.retain(|r| r.score >= min);
    }
    if let Some(limit) = q.limit {
        rows.truncate(limit);
    }
    Ok(Json(rows))
}

/// `GET /api/v1/scores/:agent_id` — latest scores for one agent.
async fn scores_for_agent(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<ScoreRow>>, ApiError> {
    Ok(Json(st.store.scores_for_agent(&agent_id)?))
}

// --- Handlers: detections -------------------------------------------------

/// `GET /api/v1/detections` — latest detections across all subjects, with
/// optional `verdict` / `min_confidence` filters and a `limit`.
async fn list_detections(
    State(st): State<AppState>,
    Query(q): Query<DetectionQuery>,
) -> Result<Json<Vec<DetectionRow>>, ApiError> {
    let mut rows = st.store.detections()?;
    if let Some(verdict) = &q.verdict {
        rows.retain(|r| &r.verdict == verdict);
    }
    if let Some(min) = q.min_confidence {
        rows.retain(|r| r.confidence >= min);
    }
    if let Some(limit) = q.limit {
        rows.truncate(limit);
    }
    Ok(Json(rows))
}

/// `GET /api/v1/detections/:agent_id` — latest detections for one agent.
async fn detections_for_agent(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<DetectionRow>>, ApiError> {
    Ok(Json(st.store.detections_for_agent(&agent_id)?))
}

// --- Handlers: alerts -----------------------------------------------------

/// `GET /api/v1/alerts` — recent alerts (newest first), filtered in-handler by
/// `severity` / `acknowledged` / `agent_id` / `since_ns`, limited by `limit`.
async fn list_alerts(
    State(st): State<AppState>,
    Query(q): Query<AlertQuery>,
) -> Result<Json<Vec<AlertRow>>, ApiError> {
    let limit = q.limit.unwrap_or(DEFAULT_ALERT_LIMIT);
    // Read at least a default-sized newest-first window so a small explicit
    // `limit` still has a reasonable candidate pool to filter against, apply the
    // predicates in-handler, then re-cap to `limit`. Filtering is therefore over
    // the newest `max(limit, DEFAULT_ALERT_LIMIT)` alerts; `since_ns` is the
    // natural bound for older windows (a post-MVP ranged store read could serve
    // it directly). The store read is itself bounded by `alerts_recent`.
    let mut rows = st.store.alerts_recent(limit.max(DEFAULT_ALERT_LIMIT))?;
    if let Some(sev) = &q.severity {
        rows.retain(|r| &r.severity == sev);
    }
    if let Some(ack) = q.acknowledged {
        rows.retain(|r| r.acknowledged == ack);
    }
    if let Some(agent_id) = &q.agent_id {
        rows.retain(|r| &r.agent_id == agent_id);
    }
    if let Some(since) = q.since_ns {
        rows.retain(|r| r.ts_ns >= since);
    }
    rows.truncate(limit);
    Ok(Json(rows))
}

/// `PATCH /api/v1/alerts/:id/ack` — acknowledge an alert by id. `200` if found,
/// `404` if no alert has that id.
async fn ack_alert(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if st.store.acknowledge_alert(&id)? {
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::not_found("alert not found"))
    }
}

// --- Handlers: events -----------------------------------------------------

/// `GET /api/v1/events/:agent_id` — one page of an agent's audit-log events
/// (newest first). `page` defaults to 0; `page_size` defaults to
/// [`DEFAULT_EVENT_PAGE_SIZE`] and is capped at [`MAX_EVENT_PAGE_SIZE`].
async fn events_for_agent(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
    Query(q): Query<EventQuery>,
) -> Result<Json<Vec<EventRecord>>, ApiError> {
    let page = q.page.unwrap_or(0);
    let page_size = q
        .page_size
        .unwrap_or(DEFAULT_EVENT_PAGE_SIZE)
        .min(MAX_EVENT_PAGE_SIZE);
    let rows = st.store.events_for_agent(&agent_id, page, page_size)?;
    Ok(Json(rows.into_iter().map(EventRecord::from).collect()))
}

// --- Handlers: tokens -----------------------------------------------------

/// `POST /api/v1/tokens` — mint a one-time enrollment token. Returns `201` with
/// the token, the server's cert fingerprint (for pinning), and the creation time.
async fn create_token(
    State(st): State<AppState>,
    Json(body): Json<CreateToken>,
) -> Result<Response, ApiError> {
    // Bound the operator-facing label (L2) and surface a clean 400 rather than a
    // 500 from the store layer.
    if body.label.len() > enroll::MAX_TOKEN_LABEL_LEN {
        return Err(ApiError::BadRequest(format!(
            "label too long (max {} bytes)",
            enroll::MAX_TOKEN_LABEL_LEN
        )));
    }
    let (token, row) = enroll::create_token(&st.store, &body.label)?;
    let payload = json!({
        "token": token,
        "fingerprint": st.server_info.fingerprint,
        "created_at_ns": row.created_at_ns,
    });
    Ok((StatusCode::CREATED, Json(payload)).into_response())
}

/// `GET /api/v1/tokens` — all enrollment tokens (including consumed ones, so the
/// dashboard can show `used` state).
async fn list_tokens(State(st): State<AppState>) -> Result<Json<Vec<TokenRecord>>, ApiError> {
    let tokens = enroll::list_tokens(&st.store)?;
    Ok(Json(tokens.into_iter().map(TokenRecord::from).collect()))
}

/// `DELETE /api/v1/tokens/:token` — revoke an unused token. `204` on success;
/// `409` if the token is unknown or already consumed.
async fn revoke_token(
    State(st): State<AppState>,
    Path(token): Path<String>,
) -> Result<StatusCode, ApiError> {
    if enroll::revoke_token(&st.store, &token)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict(
            "token is unknown or already used".into(),
        ))
    }
}

// --- Handlers: server-info + live ----------------------------------------

/// `GET /api/v1/server-info` — the server's cert fingerprint and proto version.
async fn server_info(State(st): State<AppState>) -> Json<ServerInfo> {
    Json(st.server_info.clone())
}

/// `GET /api/v1/live` — the SSE live feed.
///
/// Subscribes a fresh [`broadcast::Receiver`] and adapts it into an SSE event
/// stream: each [`LiveEvent`] becomes an `event:`-named, JSON-`data:` SSE frame.
/// Lagging subscribers (broadcast `Lagged`) are skipped rather than terminating
/// the stream; a closed channel ends it.
async fn sse_live(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = st.live_tx.subscribe();
    // `unfold` carries the receiver as state; each step awaits the next event.
    // We avoid `tokio_stream::BroadcastStream` deliberately so this stays an
    // in-crate change (no new root dependency); `futures` is already a dep.
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    // Serialise with serde_json + `.data(...)` rather than the
                    // gated SSE `json_data` helper; name the event by its kind so
                    // per-name dashboard `EventSource` listeners fire.
                    let data = serde_json::to_string(&ev)
                        .unwrap_or_else(|_| "{\"kind\":\"error\"}".to_string());
                    let sse = SseEvent::default().event(ev.name()).data(data);
                    return Some((Ok(sse), rx));
                }
                // Slow consumer fell behind: skip the gap and keep going.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                // Sender dropped (server shutting down): end the stream.
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// --- Middleware -----------------------------------------------------------

/// Add hardening headers to every response: block MIME sniffing and framing, and
/// constrain the dashboard to same-origin resources/connections.
async fn security_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'self'; connect-src 'self'"),
    );
    response
}

// --- Serve ----------------------------------------------------------------

/// Bind the operator HTTP server on `addr` and spawn its accept loop, returning
/// the task [`JoinHandle`] so the caller can abort it on shutdown.
///
/// Binding happens synchronously (before the spawn) so a bind failure surfaces to
/// the caller immediately — matching [`crate::ingest::serve`]'s shape. A
/// non-loopback `addr` is logged as a warning, since this API is unauthenticated
/// and meant for loopback only.
pub async fn serve(addr: String, state: AppState) -> anyhow::Result<JoinHandle<()>> {
    if !addr.starts_with("127.") {
        tracing::warn!(
            addr = %addr,
            "api: binding the operator HTTP API to a non-loopback address; it is unauthenticated"
        );
    }
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "api: HTTP/dashboard listener bound");
    let app = router(state);
    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            tracing::error!(error = %e, "api: HTTP server exited with error");
        }
    });
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt; // for `oneshot`

    /// Build an `AppState` over a fresh temp store, an empty command router, and
    /// a live channel. Returns the tempdir guard (keeps the store dir alive), the
    /// store handle, and the live sender for tests that publish.
    fn test_state() -> (TempDir, Arc<Store>, broadcast::Sender<LiveEvent>, AppState) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (live_tx, _) = broadcast::channel(LIVE_CHANNEL_CAPACITY);
        let state = AppState {
            store: store.clone(),
            router: Router::new(),
            live_tx: live_tx.clone(),
            server_info: ServerInfo {
                fingerprint: "deadbeef".into(),
                proto_version: aegis_proto::PROTO_VERSION,
            },
        };
        (dir, store, live_tx, state)
    }

    /// Run one request through the router and return (status, body bytes).
    async fn call(state: AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = router(state).oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, body)
    }

    /// JSON GET request helper.
    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn list_agents_empty_is_ok_and_empty_array() {
        let (_d, _store, _tx, state) = test_state();
        let (status, body) = call(state, get("/api/v1/agents")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!([]), "empty agent list");
    }

    #[tokio::test]
    async fn agents_list_exposes_pubkey_hex() {
        let (_d, store, _tx, state) = test_state();
        // Enroll an agent so there is a row to read back.
        let (token, _) = enroll::create_token(&store, "host").unwrap();
        let agent_id = match enroll::enroll(&store, &token, "h", "Linux", [0xABu8; 32]).unwrap() {
            enroll::EnrollOutcome::Accepted { agent_id } => agent_id,
            other => panic!("enroll failed: {other:?}"),
        };

        let (status, body) = call(state, get("/api/v1/agents")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["agent_id"], agent_id);
        // pubkey is rendered as hex, not a byte array.
        assert_eq!(arr[0]["pubkey_hex"], "ab".repeat(32));
        assert!(arr[0].get("pubkey").is_none(), "raw bytes must not leak");
    }

    #[tokio::test]
    async fn get_unknown_agent_is_404() {
        let (_d, _store, _tx, state) = test_state();
        let (status, body) = call(state, get("/api/v1/agents/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].is_string(), "error body shape");
    }

    #[tokio::test]
    async fn create_then_list_then_revoke_token() {
        let (_d, _store, _tx, state) = test_state();

        // Create.
        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/tokens")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"label":"laptop-7"}"#))
            .unwrap();
        let (status, body) = call(state.clone(), create_req).await;
        assert_eq!(status, StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = created["token"].as_str().unwrap().to_string();
        assert_eq!(token.len(), 64, "32-byte hex token");
        assert_eq!(created["fingerprint"], "deadbeef");
        assert!(created["created_at_ns"].is_u64());

        // List shows it, unused.
        let (status, body) = call(state.clone(), get("/api/v1/tokens")).await;
        assert_eq!(status, StatusCode::OK);
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = listed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["token"], token);
        assert_eq!(arr[0]["label"], "laptop-7");
        assert_eq!(arr[0]["used"], false);

        // Revoke (unused) -> 204.
        let del = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/tokens/{token}"))
            .body(Body::empty())
            .unwrap();
        let (status, _body) = call(state.clone(), del).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Revoking again (now unknown) -> 409.
        let del2 = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/tokens/{token}"))
            .body(Body::empty())
            .unwrap();
        let (status, _body) = call(state, del2).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn command_to_unknown_agent_is_404() {
        let (_d, _store, _tx, state) = test_state();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/agents/ghost/command")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"cmd":"noop"}"#))
            .unwrap();
        let (status, _body) = call(state, req).await;
        // No live session registered for "ghost" -> NotConnected -> 404.
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ack_unknown_alert_is_404() {
        let (_d, _store, _tx, state) = test_state();
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/alerts/does-not-exist/ack")
            .body(Body::empty())
            .unwrap();
        let (status, _body) = call(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn server_info_reports_fingerprint_and_proto() {
        let (_d, _store, _tx, state) = test_state();
        let (status, body) = call(state, get("/api/v1/server-info")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["fingerprint"], "deadbeef");
        assert_eq!(v["proto_version"], aegis_proto::PROTO_VERSION);
    }

    #[tokio::test]
    async fn fallback_serves_dashboard_index() {
        let (_d, _store, _tx, state) = test_state();
        // An unknown, non-API path hits the dashboard fallback (SPA shell).
        let (status, body) = call(state, get("/some/spa/route")).await;
        assert_eq!(status, StatusCode::OK);
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("<h1>Aegis</h1>"), "served placeholder index");
    }

    #[tokio::test]
    async fn security_headers_present_on_responses() {
        let (_d, _store, _tx, state) = test_state();
        let resp = router(state).oneshot(get("/api/v1/agents")).await.unwrap();
        let h = resp.headers();
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert!(h
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'self'"));
    }

    #[tokio::test]
    async fn scores_filter_by_min_score_and_subject() {
        let (_d, store, _tx, state) = test_state();
        for (subject, score) in [("s1", 10.0), ("s2", 90.0)] {
            store
                .upsert_score(&ScoreRow {
                    agent_id: "a".into(),
                    subject: subject.into(),
                    model: "risk/v1".into(),
                    score,
                    ts_ns: 1,
                })
                .unwrap();
        }
        // min_score filters out s1.
        let (status, body) = call(state.clone(), get("/api/v1/scores?min_score=50")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["subject"], "s2");

        // subject filter selects exactly one.
        let (_s, body) = call(state, get("/api/v1/scores?subject=s1")).await;
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["subject"], "s1");
    }

    #[tokio::test]
    async fn alerts_filter_by_acknowledged() {
        let (_d, store, _tx, state) = test_state();
        let acked_id = uuid::Uuid::new_v4().to_string();
        for (id, ack, ts) in [
            (uuid::Uuid::new_v4().to_string(), false, 100u64),
            (acked_id.clone(), true, 200u64),
        ] {
            store
                .append_alert(&AlertRow {
                    id,
                    agent_id: "a".into(),
                    severity: "high".into(),
                    title: "t".into(),
                    detail: "d".into(),
                    subject: None,
                    ts_ns: ts,
                    acknowledged: ack,
                })
                .unwrap();
        }
        let (status, body) = call(state, get("/api/v1/alerts?acknowledged=false")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only the unacknowledged alert");
        assert_eq!(arr[0]["acknowledged"], false);
    }

    #[tokio::test]
    async fn events_record_parses_payload_as_json() {
        let (_d, store, _tx, state) = test_state();
        let mut ev = aegis_sdk::Event::new(
            "agent-z",
            "plugin-tty",
            aegis_sdk::EventPayload::Keystroke {
                session_id: "s1".into(),
                inter_arrival_ns: 1_000_000,
                is_paste: false,
                burst_len: 1,
            },
        );
        ev.ts_ns = 7;
        store.write_event(&ev).unwrap();

        let (status, body) = call(state, get("/api/v1/events/agent-z")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["kind"], "input.keystroke");
        // payload is embedded JSON (an object), not a byte array.
        assert!(arr[0]["payload"].is_object(), "payload parsed to JSON");
    }

    #[tokio::test]
    async fn sse_live_emits_named_event_after_publish() {
        use tokio::time::{timeout, Duration};

        let (_d, _store, live_tx, state) = test_state();

        // Open the SSE stream as a streaming response and read the first frame
        // after publishing one event.
        let resp = router(state).oneshot(get("/api/v1/live")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));

        // Publish after the subscriber exists.
        live_tx
            .send(LiveEvent::Alert {
                agent_id: "a".into(),
                severity: "critical".into(),
                title: "boom".into(),
                subject: Some("s1".into()),
                ts_ns: 42,
            })
            .unwrap();

        // Read frames until we see the data line (skip any keep-alive comments).
        let mut body = resp.into_body().into_data_stream();
        use futures::StreamExt;
        let mut seen = String::new();
        let read = timeout(Duration::from_secs(5), async {
            while let Some(chunk) = body.next().await {
                let chunk = chunk.unwrap();
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if seen.contains("\"title\":\"boom\"") {
                    return;
                }
            }
        })
        .await;
        assert!(read.is_ok(), "did not receive SSE frame in time: {seen:?}");
        // The SSE wire format puts a space after the field name's colon.
        assert!(seen.contains("event: alert"), "named event: {seen:?}");
        assert!(
            seen.contains("\"severity\":\"critical\""),
            "payload: {seen:?}"
        );
    }
}
