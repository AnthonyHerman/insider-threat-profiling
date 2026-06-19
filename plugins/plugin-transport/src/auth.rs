//! Ed25519 session-authentication signing, agent side.
//!
//! The shared digest construction lives in [`aegis_proto::tls::auth_challenge_digest`]
//! so signer (here) and verifier (the server) hash identical bytes. This module
//! only holds the key-bearing half — producing a base64 signature over that
//! digest — and the nonce-derivation convention both ends must agree on.

use aegis_proto::pin::PIN_LEN;
use aegis_proto::tls::auth_challenge_digest;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Derive the 32-byte session nonce from the server's challenge.
///
/// The server carries freshness in the `Command.id` UUID of its `Noop`
/// challenge; both ends expand those 16 bytes to 32 via SHA-256 so the value fed
/// into [`auth_challenge_digest`] is a fixed width. This is the agreed
/// convention until/unless the server is changed to send explicit nonce
/// material; the server-side verifier must derive the nonce the same way.
pub fn nonce_from_challenge(challenge_id: &Uuid) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge_id.as_bytes());
    h.finalize().into()
}

/// Sign the channel-bound auth digest and return the signature as base64.
///
/// `tls_exporter` is RFC-5705 keying material from the live TLS session (see
/// [`aegis_proto::tls`]); `pin` is the server pin actually connected through.
pub fn sign_auth(
    signing_key: &SigningKey,
    pin: &[u8; PIN_LEN],
    agent_id: &str,
    nonce32: &[u8; 32],
    tls_exporter: &[u8],
) -> String {
    let digest = auth_challenge_digest(pin, agent_id, nonce32, tls_exporter);
    let sig = signing_key.sign(&digest);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn nonce_is_deterministic_per_id() {
        let id = Uuid::new_v4();
        assert_eq!(nonce_from_challenge(&id), nonce_from_challenge(&id));
        assert_ne!(
            nonce_from_challenge(&id),
            nonce_from_challenge(&Uuid::new_v4())
        );
    }

    #[test]
    fn signature_verifies_against_shared_digest() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk: VerifyingKey = key.verifying_key();
        let pin = [3u8; PIN_LEN];
        let id = Uuid::new_v4();
        let nonce = nonce_from_challenge(&id);
        let exporter = [9u8; 32];

        let sig_b64 = sign_auth(&key, &pin, "agent-1", &nonce, &exporter);

        // Reconstruct exactly what the server would: same digest, verify_strict.
        let digest = auth_challenge_digest(&pin, "agent-1", &nonce, &exporter);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let sig = Signature::from_bytes(&raw.try_into().unwrap());
        assert!(vk.verify_strict(&digest, &sig).is_ok());
        // A different agent_id must not verify under this signature.
        let other = auth_challenge_digest(&pin, "agent-2", &nonce, &exporter);
        assert!(vk.verify(&other, &sig).is_err());
    }
}
