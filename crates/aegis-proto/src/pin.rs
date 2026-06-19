//! Server-certificate pinning for the Aegis transport.
//!
//! Agents do not trust a public certificate authority. Instead, enrollment
//! hands the agent the SHA-256 fingerprint(s) of the server's leaf certificate,
//! and every subsequent TLS handshake is checked against that pin set. This
//! removes the public-PKI trust root entirely: a mis-issued or rogue CA cert is
//! irrelevant because only an exact fingerprint match is accepted.
//!
//! [`PinnedVerifier`] plugs into rustls as a
//! [`ServerCertVerifier`](rustls::client::danger::ServerCertVerifier). It
//! overrides *only* trust-anchor / identity verification (the pin comparison);
//! handshake-signature verification is delegated back to the ring crypto
//! provider so the cryptographic guarantees of the TLS handshake itself are
//! unchanged.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// Length, in bytes, of a SHA-256 certificate pin.
pub const PIN_LEN: usize = 32;

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
///
/// This is the raw digest of the certificate's DER bytes (the same bytes
/// rustls hands a verifier as the end-entity certificate), returned as a fixed
/// 32-byte array. The server publishes this value at enrollment time and the
/// agent stores it as a pin.
pub fn fingerprint(cert_der: &[u8]) -> [u8; PIN_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().into()
}

/// Constant-time equality for two 32-byte pins.
///
/// The comparison time depends only on the (fixed) length, never on where the
/// first differing byte is, so it does not leak match-prefix information to a
/// timing attacker. We fold every byte into an accumulator and only inspect the
/// accumulator at the end; the loop body is branch-free.
pub fn ct_eq(a: &[u8; PIN_LEN], b: &[u8; PIN_LEN]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..PIN_LEN {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Decode a 64-character hex string into a 32-byte pin.
///
/// Pins are stored in `identity.json` as lowercase hex; this is the inverse of
/// rendering a [`fingerprint`] with [`hex::encode`]. Returns `None` if the
/// string is not valid hex or does not decode to exactly [`PIN_LEN`] bytes.
pub fn parse_pin_hex(s: &str) -> Option<[u8; PIN_LEN]> {
    let bytes = hex::decode(s.trim()).ok()?;
    let arr: [u8; PIN_LEN] = bytes.try_into().ok()?;
    Some(arr)
}

/// A rustls server-certificate verifier that accepts a connection iff the
/// server's leaf certificate fingerprint matches one of a set of pinned
/// SHA-256 digests.
///
/// The pin *set* (rather than a single pin) exists to support rotation: during
/// a key roll the agent can hold both the outgoing and incoming pins so neither
/// the old nor the new server cert is rejected mid-rotation.
#[derive(Clone)]
pub struct PinnedVerifier {
    pins: Vec<[u8; PIN_LEN]>,
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    /// Build a verifier accepting any of `pins`, delegating signature
    /// verification to the ring crypto provider.
    pub fn new(pins: Vec<[u8; PIN_LEN]>) -> Self {
        Self {
            pins,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Build a verifier reusing an existing crypto provider handle (avoids
    /// constructing a second provider when the caller already has one).
    pub fn with_provider(pins: Vec<[u8; PIN_LEN]>, provider: Arc<CryptoProvider>) -> Self {
        Self { pins, provider }
    }

    /// The pins this verifier currently accepts.
    pub fn pins(&self) -> &[[u8; PIN_LEN]] {
        &self.pins
    }
}

impl std::fmt::Debug for PinnedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render pins as hex for legibility; never log key material (there is
        // none here — a cert fingerprint is public, but hex is still clearer).
        f.debug_struct("PinnedVerifier")
            .field(
                "pins",
                &self.pins.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Pin only the end-entity leaf. Intermediates and the server name are
        // intentionally ignored: trust is established solely by the leaf
        // fingerprint matching a pin, so there is no chain to build and no DNS
        // name to validate. Do the comparison BEFORE returning anything so
        // there is no `goto fail`-style elision of the check.
        let presented = fingerprint(end_entity.as_ref());
        let mut matched = false;
        for pin in &self.pins {
            // ct_eq is constant-time per comparison; OR-accumulate so we always
            // scan the whole pin set rather than short-circuiting on first hit.
            matched |= ct_eq(&presented, pin);
        }
        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("server certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Delegate to ring: we override identity, not the handshake signature.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    /// Mint a fresh self-signed cert and return its DER bytes.
    fn mint_cert(san: &str) -> Vec<u8> {
        let ck = generate_simple_self_signed(vec![san.to_string()]).unwrap();
        ck.cert.der().to_vec()
    }

    #[test]
    fn fingerprint_is_stable_and_32_bytes() {
        let der = mint_cert("a.example");
        let fp1 = fingerprint(&der);
        let fp2 = fingerprint(&der);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
        assert_eq!(fp1.len(), 32);
    }

    #[test]
    fn fingerprint_differs_across_certs() {
        let a = fingerprint(&mint_cert("a.example"));
        let b = fingerprint(&mint_cert("b.example"));
        assert_ne!(a, b, "distinct certs must have distinct fingerprints");
    }

    #[test]
    fn ct_eq_matches_and_mismatches() {
        let a = [7u8; 32];
        let b = [7u8; 32];
        let mut c = [7u8; 32];
        c[31] ^= 1;
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }

    #[test]
    fn parse_pin_hex_roundtrip() {
        let der = mint_cert("a.example");
        let fp = fingerprint(&der);
        let s = hex::encode(fp);
        assert_eq!(parse_pin_hex(&s), Some(fp));
        // trims surrounding whitespace (identity.json may include a newline)
        assert_eq!(parse_pin_hex(&format!("  {s}\n")), Some(fp));
    }

    #[test]
    fn parse_pin_hex_rejects_bad_input() {
        assert_eq!(parse_pin_hex("zz"), None); // not hex
        assert_eq!(parse_pin_hex("abcd"), None); // wrong length
        assert_eq!(parse_pin_hex(&"00".repeat(33)), None); // too long
    }

    // --- ServerCertVerifier (RT-6) matrix, driven directly through the trait ---

    fn server_name() -> ServerName<'static> {
        ServerName::try_from("server.aegis.local").unwrap()
    }

    fn verify(verifier: &PinnedVerifier, cert_der: &[u8]) -> Result<(), Error> {
        let leaf = CertificateDer::from(cert_der.to_vec());
        verifier
            .verify_server_cert(&leaf, &[], &server_name(), &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn pin_match_accepts() {
        let der = mint_cert("a.example");
        let v = PinnedVerifier::new(vec![fingerprint(&der)]);
        assert!(verify(&v, &der).is_ok(), "exact pin must accept");
    }

    #[test]
    fn flipped_pin_byte_rejects() {
        let der = mint_cert("a.example");
        let mut pin = fingerprint(&der);
        pin[0] ^= 0x01;
        let v = PinnedVerifier::new(vec![pin]);
        assert!(verify(&v, &der).is_err(), "single-bit pin diff must reject");
    }

    #[test]
    fn pin_of_a_rejects_cert_b() {
        let a = mint_cert("a.example");
        let b = mint_cert("b.example");
        let v = PinnedVerifier::new(vec![fingerprint(&a)]);
        assert!(verify(&v, &b).is_err(), "wrong cert must reject");
    }

    #[test]
    fn empty_or_short_cert_bytes_reject() {
        let der = mint_cert("a.example");
        let v = PinnedVerifier::new(vec![fingerprint(&der)]);
        assert!(verify(&v, &[]).is_err(), "empty cert must reject");
        assert!(verify(&v, &[0u8; 8]).is_err(), "garbage cert must reject");
    }

    #[test]
    fn empty_pin_set_rejects_everything() {
        let der = mint_cert("a.example");
        let v = PinnedVerifier::new(vec![]);
        assert!(verify(&v, &der).is_err(), "no pins => reject");
    }

    #[test]
    fn rotation_pin_set_accepts_either_cert() {
        // Two valid pins (e.g. mid-rotation): both certs must verify.
        let a = mint_cert("a.example");
        let b = mint_cert("b.example");
        let v = PinnedVerifier::new(vec![fingerprint(&a), fingerprint(&b)]);
        assert!(verify(&v, &a).is_ok());
        assert!(verify(&v, &b).is_ok());
    }

    #[test]
    fn supported_schemes_nonempty() {
        let v = PinnedVerifier::new(vec![]);
        assert!(
            !v.supported_verify_schemes().is_empty(),
            "ring provider advertises signature schemes"
        );
    }
}
