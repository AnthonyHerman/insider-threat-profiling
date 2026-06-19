//! Integration tests for the server-facing `aegisctl` subcommands.
//!
//! These exercise the whole client path end-to-end: the compiled `aegisctl`
//! binary (via `CARGO_BIN_EXE_aegisctl`) runs against a *fake* operator API — a
//! bare loopback [`TcpListener`] that speaks just enough HTTP/1.1 to answer the
//! handful of routes the CLI calls. That proves the in-crate `http` client
//! builds correct requests (method, path, `Host`, body, `Connection: close`)
//! and parses real responses (status + body), and that each subcommand renders
//! both its table and `--json` form and maps error statuses sensibly.
//!
//! We do not depend on `aegis-server` here: a tiny canned server keeps the test
//! hermetic and fast, and the request/response wire is identical to what axum
//! emits for these endpoints (plain JSON bodies, no chunked encoding).

use std::collections::HashMap;
use std::io::Write as _;
use std::process::Command;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A single canned reply keyed by `"METHOD PATH"` (path without query string).
#[derive(Clone)]
struct Reply {
    status: u16,
    reason: &'static str,
    body: String,
}

/// Spawn a one-shot-ish fake API server bound to `127.0.0.1:0`.
///
/// Returns the bound `host:port` and a sender that, when fired (or dropped),
/// stops the accept loop. The server answers `routes["METHOD /path"]`; anything
/// unmatched gets a 404 with a JSON error body, mirroring the real API's shape.
/// The request line's query string is stripped before lookup so callers can key
/// on the bare path.
async fn spawn_fake_api(routes: HashMap<String, Reply>) -> (String, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut sock, _)) = accepted else { break };
                    let routes = routes.clone();
                    tokio::spawn(async move {
                        // Read the request head (up to the blank line); the CLI
                        // sends small bodies, so a bounded read is plenty.
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 1024];
                        loop {
                            match sock.read(&mut tmp).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    if find(&buf, b"\r\n\r\n").is_some() {
                                        break;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                        let head = String::from_utf8_lossy(&buf);
                        let request_line = head.lines().next().unwrap_or("");
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let raw_path = parts.next().unwrap_or("");
                        let path = raw_path.split('?').next().unwrap_or(raw_path);
                        let key = format!("{method} {path}");

                        let reply = routes.get(&key).cloned().unwrap_or(Reply {
                            status: 404,
                            reason: "Not Found",
                            body: r#"{"error":"no such route"}"#.to_string(),
                        });

                        let mut out = format!(
                            "HTTP/1.1 {} {}\r\nConnection: close\r\n",
                            reply.status, reply.reason
                        );
                        if reply.status == 204 {
                            out.push_str("\r\n");
                        } else {
                            out.push_str("Content-Type: application/json\r\n");
                            out.push_str(&format!("Content-Length: {}\r\n\r\n", reply.body.len()));
                            out.push_str(&reply.body);
                        }
                        let _ = sock.write_all(out.as_bytes()).await;
                        let _ = sock.flush().await;
                    });
                }
            }
        }
    });

    (format!("http://{addr}"), stop_tx)
}

/// Naive subslice search (no external deps in the test crate).
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Run `aegisctl <args...>` and return (success, stdout, stderr).
fn run_cli(args: &[&str]) -> (bool, String, String) {
    let exe = env!("CARGO_BIN_EXE_aegisctl");
    let out = Command::new(exe).args(args).output().unwrap();
    // Help debugging on failure.
    std::io::stdout().flush().ok();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn reply(status: u16, reason: &'static str, body: &str) -> Reply {
    Reply {
        status,
        reason,
        body: body.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_prints_fingerprint_and_agent_count() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/server-info".into(),
        reply(200, "OK", r#"{"fingerprint":"abc123","proto_version":1}"#),
    );
    routes.insert(
        "GET /api/v1/agents".into(),
        reply(200, "OK", r#"[{"agent_id":"a1"},{"agent_id":"a2"}]"#),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    let (ok, stdout, stderr) = run_cli(&["status", "--server", &base]);
    assert!(ok, "status failed: {stderr}");
    assert!(stdout.contains("abc123"), "fingerprint missing: {stdout}");
    assert!(
        stdout.contains("proto version:  1"),
        "proto missing: {stdout}"
    );
    assert!(
        stdout.contains("agents:         2"),
        "agent count missing: {stdout}"
    );

    // --json passthrough includes the merged agent_count.
    let (ok, stdout, _e) = run_cli(&["status", "--server", &base, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["fingerprint"], "abc123");
    assert_eq!(v["agent_count"], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_table_and_json() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/agents".into(),
        reply(
            200,
            "OK",
            r#"[{"agent_id":"agent-1","hostname":"box","os":"Linux","pubkey_hex":"ab","enrolled_at_ns":1,"last_seen_ns":99}]"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    let (ok, stdout, stderr) = run_cli(&["agents", "--server", &base]);
    assert!(ok, "agents failed: {stderr}");
    assert!(stdout.contains("AGENT_ID"), "header missing: {stdout}");
    assert!(stdout.contains("agent-1"));
    assert!(stdout.contains("box"));
    assert!(stdout.contains("Linux"));

    let (ok, stdout, _e) = run_cli(&["agents", "--server", &base, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v[0]["agent_id"], "agent-1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_table_and_filters() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/alerts".into(),
        reply(
            200,
            "OK",
            r#"[{"id":"x","agent_id":"a1","severity":"critical","title":"boom","detail":"d","subject":null,"ts_ns":7,"acknowledged":false}]"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    // Filters are accepted (they go into the query string the fake server ignores).
    let (ok, stdout, stderr) = run_cli(&[
        "alerts",
        "--server",
        &base,
        "--severity",
        "critical",
        "--unacknowledged",
        "--limit",
        "10",
    ]);
    assert!(ok, "alerts failed: {stderr}");
    assert!(stdout.contains("SEVERITY"), "header missing: {stdout}");
    assert!(stdout.contains("critical"));
    assert!(stdout.contains("boom"));

    let (ok, stdout, _e) = run_cli(&["alerts", "--server", &base, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v[0]["title"], "boom");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scores_table_json_and_per_agent() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/scores".into(),
        reply(
            200,
            "OK",
            r#"[{"agent_id":"a1","subject":"uid:1000","model":"risk-aggregator/v1","score":82.5,"ts_ns":7}]"#,
        ),
    );
    routes.insert(
        "GET /api/v1/scores/a1".into(),
        reply(
            200,
            "OK",
            r#"[{"agent_id":"a1","subject":"sess-1","model":"risk-aggregator/v1","score":12.0,"ts_ns":9}]"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    // Global listing renders a table (filters go into the ignored query string).
    let (ok, stdout, stderr) = run_cli(&["scores", "--server", &base, "--min-score", "50"]);
    assert!(ok, "scores failed: {stderr}");
    assert!(stdout.contains("SUBJECT"), "header missing: {stdout}");
    assert!(stdout.contains("uid:1000"));
    assert!(stdout.contains("82.5"));

    // --json passthrough.
    let (ok, stdout, _e) = run_cli(&["scores", "--server", &base, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v[0]["subject"], "uid:1000");

    // --agent hits the per-agent route.
    let (ok, stdout, stderr) = run_cli(&["scores", "--server", &base, "--agent", "a1"]);
    assert!(ok, "scores --agent failed: {stderr}");
    assert!(stdout.contains("sess-1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_table_json_and_per_agent_filter() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/detections".into(),
        reply(
            200,
            "OK",
            r#"[{"agent_id":"a1","subject":"sess-1","verdict":"agent","confidence":0.91,"model":"m","reasons":["r"],"ts_ns":7}]"#,
        ),
    );
    routes.insert(
        "GET /api/v1/detections/a1".into(),
        reply(
            200,
            "OK",
            r#"[{"agent_id":"a1","subject":"sess-1","verdict":"agent","confidence":0.91,"model":"m","reasons":["r"],"ts_ns":7},
                {"agent_id":"a1","subject":"sess-2","verdict":"human","confidence":0.80,"model":"m","reasons":[],"ts_ns":8}]"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    let (ok, stdout, stderr) = run_cli(&[
        "detections",
        "--server",
        &base,
        "--verdict",
        "agent",
        "--min-confidence",
        "0.5",
    ]);
    assert!(ok, "detections failed: {stderr}");
    assert!(stdout.contains("VERDICT"), "header missing: {stdout}");
    assert!(stdout.contains("agent"));
    assert!(stdout.contains("0.91"));

    let (ok, stdout, _e) = run_cli(&["detections", "--server", &base, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v[0]["verdict"], "agent");

    // --agent uses the per-agent route; the client-side --verdict filter then
    // keeps only the matching row (the per-agent endpoint returns both).
    let (ok, stdout, stderr) = run_cli(&[
        "detections",
        "--server",
        &base,
        "--agent",
        "a1",
        "--verdict",
        "agent",
    ]);
    assert!(ok, "detections --agent failed: {stderr}");
    assert!(stdout.contains("sess-1"));
    assert!(
        !stdout.contains("sess-2"),
        "client-side verdict filter should drop the human row: {stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enroll_token_create_list_revoke() {
    let mut routes = HashMap::new();
    routes.insert(
        "POST /api/v1/tokens".into(),
        reply(
            201,
            "Created",
            r#"{"token":"deadbeef","fingerprint":"fp-xyz","created_at_ns":123}"#,
        ),
    );
    routes.insert(
        "GET /api/v1/tokens".into(),
        reply(
            200,
            "OK",
            r#"[{"token":"deadbeef","label":"laptop","created_at_ns":123,"used":false}]"#,
        ),
    );
    routes.insert(
        "DELETE /api/v1/tokens/deadbeef".into(),
        reply(204, "No Content", ""),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    // create
    let (ok, stdout, stderr) = run_cli(&[
        "enroll-token",
        "create",
        "--label",
        "laptop",
        "--server",
        &base,
    ]);
    assert!(ok, "create failed: {stderr}");
    assert!(stdout.contains("deadbeef"), "token missing: {stdout}");
    assert!(stdout.contains("fp-xyz"), "fingerprint missing: {stdout}");

    // list
    let (ok, stdout, stderr) = run_cli(&["enroll-token", "list", "--server", &base]);
    assert!(ok, "list failed: {stderr}");
    assert!(stdout.contains("TOKEN"), "header missing: {stdout}");
    assert!(stdout.contains("deadbeef"));
    assert!(stdout.contains("laptop"));

    // revoke -> 204 -> "revoked"
    let (ok, stdout, stderr) = run_cli(&["enroll-token", "revoke", "deadbeef", "--server", &base]);
    assert!(ok, "revoke failed: {stderr}");
    assert!(
        stdout.trim() == "revoked",
        "unexpected revoke output: {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_conflict_reports_already_used() {
    let mut routes = HashMap::new();
    routes.insert(
        "DELETE /api/v1/tokens/spent".into(),
        reply(
            409,
            "Conflict",
            r#"{"error":"token is unknown or already used"}"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    let (ok, stdout, stderr) = run_cli(&["enroll-token", "revoke", "spent", "--server", &base]);
    // 409 is a handled outcome, not a hard failure -> exit 0 with a message.
    assert!(ok, "revoke (409) should not be a hard error: {stderr}");
    assert!(
        stdout.contains("already used or unknown"),
        "unexpected output: {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_error_surfaces_message_and_fails() {
    let mut routes = HashMap::new();
    routes.insert(
        "GET /api/v1/agents".into(),
        reply(
            500,
            "Internal Server Error",
            r#"{"error":"internal server error"}"#,
        ),
    );
    let (base, _stop) = spawn_fake_api(routes).await;

    let (ok, _stdout, stderr) = run_cli(&["agents", "--server", &base]);
    assert!(!ok, "a 500 should fail the command");
    assert!(
        stderr.contains("internal server error"),
        "error detail missing: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_server_fails_with_connect_error() {
    // Nothing is listening on this port; the connect must fail with a clear message.
    let (ok, _stdout, stderr) = run_cli(&["status", "--server", "http://127.0.0.1:1"]);
    assert!(!ok, "unreachable server should fail");
    assert!(
        stderr.contains("could not connect"),
        "connect error missing: {stderr}"
    );
}
