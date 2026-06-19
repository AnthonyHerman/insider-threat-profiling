//! # Minimal loopback HTTP/1.1 client (`http.rs`)
//!
//! A dependency-free HTTP/1.1 client used by the server-facing subcommands to
//! talk to `aegisd`'s loopback operator API. It deliberately does **not** pull
//! in `reqwest`/`hyper`/TLS: the operator API is plain HTTP on loopback, the
//! requests are tiny JSON bodies, and a hand-built request keeps the CLI
//! self-contained.
//!
//! ## How it works
//!
//! Each call opens a fresh [`tokio::net::TcpStream`] to the server's host:port,
//! writes a request with `Connection: close`, then reads the whole response to
//! EOF. Because we always send `Connection: close` and read until the peer
//! closes, we never need chunked-transfer or keep-alive handling: the body is
//! simply "everything after the blank line". axum/hyper honours `Connection:
//! close`, so this is correct for our server.
//!
//! ## Scope / non-goals
//!
//! * Only `http://` (or a bare `host:port`) is accepted; `https://` is rejected
//!   with a clear error (the API is loopback HTTP).
//! * No redirects, no compression, no chunked decoding — none are emitted by the
//!   server for these endpoints.
//! * Status line + headers are parsed just enough to extract the numeric status;
//!   the caller interprets the body as JSON.

use anyhow::{anyhow, bail, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A parsed HTTP response: the numeric status code and the raw body bytes.
pub struct Response {
    /// The HTTP status code from the response line (e.g. `200`, `404`).
    pub status: u16,
    /// The response body (everything after the blank line), verbatim.
    pub body: Vec<u8>,
}

/// The `host:port` parsed out of a `--server` value, plus the `Host:` header
/// value to send. `port` defaults to 80 when the URL omits one.
struct Target {
    /// `host:port` to connect to (always includes an explicit port).
    authority: String,
    /// The value for the `Host:` request header (host plus non-default port).
    host_header: String,
}

/// Parse a `--server` argument into a connect target.
///
/// Accepts `http://host`, `http://host:port`, `http://host:port/ignored-path`,
/// or a bare `host:port` / `host`. Rejects `https://` since the operator API is
/// plain HTTP on loopback.
fn parse_target(server: &str) -> anyhow::Result<Target> {
    let s = server.trim();
    if let Some(rest) = s.strip_prefix("https://") {
        let _ = rest;
        bail!(
            "https is not supported: the operator API is plain HTTP on loopback (use http://...)"
        );
    }
    // Strip the scheme if present, then drop any path/query the user pasted in.
    let without_scheme = s.strip_prefix("http://").unwrap_or(s);
    let authority_str = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    if authority_str.is_empty() {
        bail!("empty server address");
    }

    // Split host and optional port. Bracketed IPv6 (`[::1]:8080`) is handled so
    // a loopback IPv6 literal works; otherwise split on the last colon.
    let (host, port): (String, u16) = if let Some(end) = authority_str.strip_prefix('[') {
        // IPv6 literal in brackets.
        let close = end
            .find(']')
            .ok_or_else(|| anyhow!("malformed IPv6 address: {authority_str}"))?;
        let host = &end[..close];
        let after = &end[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().with_context(|| format!("invalid port: {p}"))?,
            None => 80,
        };
        (format!("[{host}]"), port)
    } else {
        match authority_str.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() => (
                h.to_string(),
                p.parse().with_context(|| format!("invalid port: {p}"))?,
            ),
            _ => (authority_str.to_string(), 80),
        }
    };

    // Host header includes the port unless it is the HTTP default.
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    Ok(Target {
        authority: format!("{host}:{port}"),
        host_header,
    })
}

/// Send one request and read the full response.
///
/// `method` is the HTTP verb, `path` the request target (`/api/v1/...` including
/// any query string), and `body` an optional JSON payload (sets `Content-Type`
/// and `Content-Length`).
async fn request(
    server: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> anyhow::Result<Response> {
    let target = parse_target(server)?;
    let mut stream = TcpStream::connect(&target.authority)
        .await
        .with_context(|| {
            format!(
                "could not connect to {} (is aegisd running?)",
                target.authority
            )
        })?;

    // Build the request head. `Connection: close` lets us read to EOF.
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: aegisctl\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n",
        method = method,
        path = path,
        host = target.host_header,
    );
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .context("failed writing request head")?;
    if let Some(b) = body {
        stream
            .write_all(b)
            .await
            .context("failed writing request body")?;
    }
    stream.flush().await.ok();

    // Read the entire response (server closes the connection when done).
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .context("failed reading response")?;

    parse_response(&raw)
}

/// Split a raw HTTP response into its status code and body.
///
/// Finds the CRLF that ends the status line for the code, then the `\r\n\r\n`
/// that ends the headers; everything after is the body. Tolerates a bare `\n\n`
/// header terminator defensively.
fn parse_response(raw: &[u8]) -> anyhow::Result<Response> {
    if raw.is_empty() {
        bail!("server closed the connection without a response");
    }
    // Locate end of header block.
    let header_end = find_subslice(raw, b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| find_subslice(raw, b"\n\n").map(|i| (i, i + 2)));
    let (head_end, body_start) =
        header_end.ok_or_else(|| anyhow!("malformed HTTP response: no header terminator"))?;

    let head = &raw[..head_end];
    let status_line_end = find_subslice(head, b"\r\n").unwrap_or(head.len());
    let status_line =
        std::str::from_utf8(&head[..status_line_end]).context("non-UTF-8 status line")?;

    // "HTTP/1.1 200 OK" -> the second whitespace-separated token is the code.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().ok_or_else(|| anyhow!("empty status line"))?;
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code in: {status_line:?}"))?;
    let status: u16 = code
        .parse()
        .with_context(|| format!("invalid status code: {code:?}"))?;

    Ok(Response {
        status,
        body: raw[body_start..].to_vec(),
    })
}

/// Find the first index of `needle` within `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- Verb helpers ---------------------------------------------------------

/// `GET path`.
pub async fn get(server: &str, path: &str) -> anyhow::Result<Response> {
    request(server, "GET", path, None).await
}

/// `POST path` with a JSON body.
pub async fn post_json(
    server: &str,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<Response> {
    let bytes = serde_json::to_vec(body).context("failed to serialize request body")?;
    request(server, "POST", path, Some(&bytes)).await
}

/// `DELETE path`.
pub async fn delete(server: &str, path: &str) -> anyhow::Result<Response> {
    request(server, "DELETE", path, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_defaults_and_scheme() {
        let t = parse_target("http://127.0.0.1:8080").unwrap();
        assert_eq!(t.authority, "127.0.0.1:8080");
        assert_eq!(t.host_header, "127.0.0.1:8080");

        // Bare host:port (no scheme).
        let t = parse_target("127.0.0.1:9000").unwrap();
        assert_eq!(t.authority, "127.0.0.1:9000");

        // Default port when omitted; Host header drops the default port.
        let t = parse_target("http://example.test").unwrap();
        assert_eq!(t.authority, "example.test:80");
        assert_eq!(t.host_header, "example.test");

        // A pasted trailing path is ignored for connection purposes.
        let t = parse_target("http://127.0.0.1:8080/api/v1/agents").unwrap();
        assert_eq!(t.authority, "127.0.0.1:8080");
    }

    #[test]
    fn parse_target_ipv6() {
        let t = parse_target("http://[::1]:8080").unwrap();
        assert_eq!(t.authority, "[::1]:8080");
        assert_eq!(t.host_header, "[::1]:8080");
    }

    #[test]
    fn parse_target_rejects_https_and_empty() {
        assert!(parse_target("https://127.0.0.1:8080").is_err());
        assert!(parse_target("http://").is_err());
    }

    #[test]
    fn parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 201);
        assert_eq!(r.body, b"{}");
    }

    #[test]
    fn parse_response_handles_no_content() {
        let raw = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[test]
    fn parse_response_rejects_garbage() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"not http at all").is_err());
    }

    #[test]
    fn find_subslice_basic() {
        assert_eq!(find_subslice(b"abcde", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcde", b"xy"), None);
        assert_eq!(find_subslice(b"ab", b"abc"), None);
    }
}
