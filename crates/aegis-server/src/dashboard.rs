//! # Embedded dashboard assets (`dashboard.rs`)
//!
//! Serves the operator dashboard's static files, which are compiled *into* the
//! `aegisd` binary via [`rust_embed`] — the self-containment constraint from the
//! server design: no runtime asset directory, the dashboard ships inside the
//! single binary. The assets live under `assets/dashboard/` in this crate and
//! are embedded at compile time; [`static_handler`] is wired as the
//! [`axum::Router`] fallback by [`crate::api::router`], so any request that does
//! not match an `/api/v1/...` route is treated as a request for a dashboard
//! asset.
//!
//! ## SPA fallback
//!
//! The dashboard is a single-page app: client-side routes (e.g. `/agents/123`)
//! have no corresponding file. On a miss, [`static_handler`] therefore serves
//! `index.html` with a `200` status (not a `404`) so the SPA router can take
//! over. A genuine missing-asset case (no `index.html` embedded at all) is the
//! only `404` this handler produces.
//!
//! ## Content type
//!
//! The `Content-Type` is inferred from the request path with [`mime_guess`]
//! (falling back to `application/octet-stream`), so CSS, JS, fonts, and images
//! are all served with a sensible type without hand-maintaining a table.
//!
//! ## Build-time invariant
//!
//! `rust_embed`'s derive requires a non-empty folder at compile time. A minimal,
//! CSP-compatible `index.html` placeholder is committed under
//! `assets/dashboard/` so the crate compiles before the real dashboard workflow
//! lands; that workflow replaces the placeholder with the built SPA assets.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

/// The embedded dashboard asset bundle: every file under
/// `assets/dashboard/` is compiled into the binary. `interpolate-folder-path`
/// expands `$CARGO_MANIFEST_DIR` so the path resolves from the crate root
/// regardless of the build's working directory.
#[derive(rust_embed::RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/assets/dashboard"]
struct Assets;

/// The SPA entry point served for `/` and for any client-side route that does
/// not correspond to an embedded file.
const INDEX_HTML: &str = "index.html";

/// Serve an embedded dashboard asset for `uri`, with an SPA fallback to
/// `index.html`.
///
/// Resolution:
/// * `/` (or empty path) → `index.html`.
/// * an exact embedded file → that file, typed via [`mime_guess`].
/// * any other path → `index.html` with status `200` (SPA client routing).
/// * `index.html` itself absent → `404` with a short plain-text body.
pub async fn static_handler(uri: Uri) -> Response {
    // Trim the leading '/'; an empty path is the index.
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { INDEX_HTML } else { path };

    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_ref().to_string())],
            file.data.into_owned(),
        )
            .into_response();
    }

    // Miss: fall back to the SPA shell so client-side routing works. Serve it
    // with 200 (not 404) and an explicit HTML content type.
    match Assets::get(INDEX_HTML) {
        Some(index) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
            index.data.into_owned(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            )],
            "dashboard assets not bundled in this build"
                .as_bytes()
                .to_vec(),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// Collect a response body to bytes (test helper).
    async fn body_bytes(resp: Response) -> Vec<u8> {
        to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body")
            .to_vec()
    }

    #[tokio::test]
    async fn root_serves_placeholder_index() {
        let resp = static_handler("/".parse().unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.starts_with("text/html"),
            "index served as html, got {ct}"
        );
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains("<h1>Aegis</h1>"), "placeholder index body");
    }

    #[tokio::test]
    async fn unknown_spa_path_falls_back_to_index_with_200() {
        let resp = static_handler("/agents/some-uuid".parse().unwrap()).await;
        // SPA fallback: 200 + index.html, so client-side routing can take over.
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/html"));
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains("<h1>Aegis</h1>"));
    }

    #[tokio::test]
    async fn known_asset_gets_correct_mime() {
        let resp = static_handler("/app.css".parse().unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/css"), "css mime, got {ct}");
    }
}
