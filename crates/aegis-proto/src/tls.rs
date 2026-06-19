//! Shared TLS configuration and session-auth digest construction for the Aegis
//! transport.
//!
//! Both ends of the connection are built here so the agent and the server agree
//! on every security parameter:
//!
//! * [`client_config`] produces a TLS-1.3-only [`rustls::ClientConfig`] whose
//!   server-cert verifier is the SHA-256 [`PinnedVerifier`](crate::pin::PinnedVerifier).
//! * [`server_config`] produces the matching TLS-1.3-only
//!   [`rustls::ServerConfig`] from a cert chain and key. (Server certificate
//!   *generation* lives in the server crate; this helper is the consumer-side
//!   counterpart and is exercised by the loopback handshake test.)
//! * [`connect`] performs the client handshake and returns the *typed*
//!   [`tokio_rustls::client::TlsStream`] (not the unified `TlsStream` enum) so
//!   the caller can reach [`rustls::ClientConnection::export_keying_material`]
//!   for RFC-5705 channel binding before splitting the stream.
//! * [`auth_challenge_digest`] is the single, shared construction of the bytes
//!   the agent signs and the server verifies during session authentication.
//!
//! Both configs use the *ring* crypto provider and pin TLS 1.3 explicitly via
//! `builder_with_provider` + `with_protocol_versions`, rather than relying on a
//! process-wide default provider.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::pin::{PinnedVerifier, PIN_LEN};

/// Domain-separation / RFC-5705 exporter label for session authentication.
///
/// Used both as the TLS keying-material exporter label (the `label` argument to
/// `export_keying_material`) and as the leading domain-separation tag inside
/// [`auth_challenge_digest`], so a signature can never be replayed in another
/// protocol context.
pub const AUTH_LABEL: &[u8] = b"aegis-session-auth-v1";

/// Build a TLS-1.3-only client config that authenticates the server by
/// SHA-256 certificate pinning.
///
/// `pins` is the set of accepted leaf-certificate fingerprints (see
/// [`crate::pin`]); a handshake succeeds only if the server's leaf matches one
/// of them. Signature verification within the handshake is still performed by
/// the ring provider — only trust-anchor / identity is overridden.
pub fn client_config(pins: Vec<[u8; PIN_LEN]>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Safe to expect: the ring provider always has a TLS 1.3 cipher suite
        // and a key-exchange group, so version selection cannot fail here.
        .expect("ring provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(pins)))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Build a TLS-1.3-only server config from a certificate chain and private key.
///
/// The agent does not present a client certificate (it authenticates at the
/// application layer via Ed25519; see [`auth_challenge_digest`]), so the server
/// uses `with_no_client_auth`. Returns an error if the key does not match the
/// leaf certificate or the key encoding is invalid.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(Arc::new(cfg))
}

/// Perform the client side of the TLS handshake over `stream`.
///
/// Returns the *typed* [`tokio_rustls::client::TlsStream`], whose
/// [`get_ref`](tokio_rustls::client::TlsStream::get_ref) yields a
/// `&`[`rustls::ClientConnection`]. This matters: the unified
/// `tokio_rustls::TlsStream` enum exposes only a `&CommonState`, which cannot
/// produce RFC-5705 exporter material. Callers that need channel binding MUST
/// call `tls.get_ref().1.export_keying_material(&mut buf, AUTH_LABEL, None)`
/// **before** `tokio::io::split(tls)` — splitting consumes the connection
/// handle and the exporter becomes unreachable afterwards.
pub async fn connect<IO>(
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    stream: IO,
) -> std::io::Result<tokio_rustls::client::TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    TlsConnector::from(config)
        .connect(server_name, stream)
        .await
}

/// Construct the 32-byte digest the agent signs (and the server verifies) to
/// prove possession of its enrolled Ed25519 key for this specific session.
///
/// The digest binds together:
/// * [`AUTH_LABEL`] — domain separation, so a signature is meaningless outside
///   this protocol/version;
/// * `pin` — the server pin the agent actually connected through, binding the
///   auth to the intended server identity;
/// * `agent_id` — the claimed identity;
/// * `nonce32` — server-chosen freshness, preventing replay;
/// * `tls_exporter` — RFC-5705 keying material from *this* TLS session, binding
///   the signature to the channel and defeating MITM relay.
///
/// Keeping this in one place guarantees the signer and verifier hash exactly
/// the same bytes in the same order.
pub fn auth_challenge_digest(
    pin: &[u8; PIN_LEN],
    agent_id: &str,
    nonce32: &[u8; 32],
    tls_exporter: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AUTH_LABEL);
    h.update(pin);
    h.update(agent_id.as_bytes());
    h.update(nonce32);
    h.update(tls_exporter);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::fingerprint;
    use crate::{read_message, write_message, Message};
    use rcgen::generate_simple_self_signed;
    use tokio_rustls::TlsAcceptor;

    /// Mint a self-signed leaf and return (config-ready chain, key, pin).
    fn server_material() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        [u8; PIN_LEN],
    ) {
        let ck = generate_simple_self_signed(vec!["server.aegis.local".to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let pin = fingerprint(&cert_der);
        let chain = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
        (chain, key, pin)
    }

    #[test]
    fn auth_digest_is_deterministic_and_input_sensitive() {
        let pin = [9u8; PIN_LEN];
        let nonce = [3u8; 32];
        let exporter = [1u8; 32];
        let base = auth_challenge_digest(&pin, "agent-1", &nonce, &exporter);
        assert_eq!(
            base,
            auth_challenge_digest(&pin, "agent-1", &nonce, &exporter),
            "same inputs => same digest"
        );
        // Each input must change the digest.
        let mut pin2 = pin;
        pin2[0] ^= 1;
        assert_ne!(
            base,
            auth_challenge_digest(&pin2, "agent-1", &nonce, &exporter)
        );
        assert_ne!(
            base,
            auth_challenge_digest(&pin, "agent-2", &nonce, &exporter)
        );
        let mut nonce2 = nonce;
        nonce2[0] ^= 1;
        assert_ne!(
            base,
            auth_challenge_digest(&pin, "agent-1", &nonce2, &exporter)
        );
        assert_ne!(
            base,
            auth_challenge_digest(&pin, "agent-1", &nonce, &[2u8; 32])
        );
    }

    #[test]
    fn client_config_builds_with_pins() {
        // Building a client config with pins must not panic, and the resulting
        // config must be wrapped in an Arc that is independently cloneable
        // (rustls configs are cheap to share across connections).
        let pin = [4u8; PIN_LEN];
        let cfg = client_config(vec![pin]);
        let _clone = Arc::clone(&cfg);
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    /// Full TLS 1.3 loopback: a pinned client and the matching server complete a
    /// handshake over an in-memory duplex, exchange a `Ping`/`Pong`, and the
    /// client can extract RFC-5705 exporter material before splitting.
    #[tokio::test]
    async fn loopback_handshake_and_ping_pong() {
        let (chain, key, pin) = server_material();
        let server_cfg = server_config(chain, key).expect("server config");
        let client_cfg = client_config(vec![pin]);

        // In-memory bidirectional pipe standing in for a TCP connection.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let acceptor = TlsAcceptor::from(server_cfg);
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.expect("server accept");
            // Read the client's Ping, reply Pong.
            let msg = read_message(&mut tls).await.expect("server read");
            assert!(matches!(msg, Message::Ping));
            write_message(&mut tls, &Message::Pong)
                .await
                .expect("server write");
        });

        let name = ServerName::try_from("server.aegis.local").unwrap();
        let mut tls = connect(client_cfg, name, client_io)
            .await
            .expect("client handshake");

        // Exporter material must be reachable on the typed stream BEFORE split.
        let (_io, conn) = tls.get_ref();
        let mut exporter = [0u8; 32];
        conn.export_keying_material(&mut exporter, AUTH_LABEL, None)
            .expect("export keying material");
        assert_ne!(exporter, [0u8; 32], "exporter must be filled");

        write_message(&mut tls, &Message::Ping)
            .await
            .expect("client write");
        let reply = read_message(&mut tls).await.expect("client read");
        assert!(matches!(reply, Message::Pong));

        server.await.unwrap();
    }

    /// A client pinned to the WRONG fingerprint must fail the handshake.
    #[tokio::test]
    async fn loopback_handshake_rejects_wrong_pin() {
        let (chain, key, _pin) = server_material();
        let server_cfg = server_config(chain, key).expect("server config");
        let mut wrong = [0u8; PIN_LEN];
        wrong[0] = 0xAA;
        let client_cfg = client_config(vec![wrong]);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(server_cfg);
        // Server may error or just see the connection torn down; don't assert
        // on its result, only that the client refuses to complete.
        let server = tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });

        let name = ServerName::try_from("server.aegis.local").unwrap();
        let res = connect(client_cfg, name, client_io).await;
        assert!(res.is_err(), "pin mismatch must fail the client handshake");
        let _ = server.await;
    }
}
