//! # Enrollment and session authentication (`enroll.rs`)
//!
//! The enrollment *policy* layer over [`crate::store`]: one-time token CRUD, the
//! atomic burn-and-enroll entry point, and the Ed25519 session-challenge
//! verification. These are pure functions over a `&Store` (plus crypto);
//! [`crate::ingest`] calls them from the per-connection protocol state machine.
//!
//! ## Two-phase identity
//!
//! 1. **Enroll** (first contact): the agent presents a one-time token and its
//!    Ed25519 *public* key. [`enroll`] atomically burns the token and writes an
//!    [`AgentRow`](crate::store::AgentRow) carrying that pubkey, returning a
//!    freshly-minted UUIDv4 `agent_id`. The token is single-use with a soft
//!    validity window ([`TOKEN_VALIDITY_NS`]).
//! 2. **Authenticate** (every subsequent session): the agent proves possession
//!    of the matching *private* key by signing a channel-bound challenge. The
//!    server reuses the existing `Message::Command{ServerCommand::Noop}` variant
//!    as the challenge carrier rather than adding a protocol message.
//!
//! ## Challenge construction — interop with the agent signer
//!
//! The bytes signed are produced by [`aegis_proto::tls::auth_challenge_digest`],
//! the single shared construction used by both ends. Two conventions the agent
//! (`plugin-transport`) fixes, which the verifier here must match exactly:
//!
//! * **The nonce is derived from the challenge UUID**, not sent separately: both
//!   ends compute `SHA-256(challenge_id.as_bytes())` (see
//!   [`nonce_from_challenge`]). Freshness therefore comes from the random
//!   `Command.id` the server picks per session.
//! * **The signature is standard base64** in `CommandResult.detail` (the agent
//!   encodes with `base64::STANDARD`); [`verify_challenge`] decodes the same way.
//! * The `pin` mixed into the digest is the SHA-256 of the server's own leaf
//!   certificate DER — the exact pin the agent connected through — and the
//!   `tls_exporter` is this session's RFC-5705 keying material.

use aegis_proto::pin::{self, PIN_LEN};
use aegis_proto::tls::auth_challenge_digest;
use aegis_sdk::now_ns;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::store::{EnrollReject, Store, TokenRow};

/// Soft validity window for an enrollment token: 24 hours, in nanoseconds.
/// A token older than this is rejected even if never used (explicit revocation
/// via [`revoke_token`] is the other removal path).
pub const TOKEN_VALIDITY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Number of random bytes in a token (rendered as 64 lowercase hex chars).
const TOKEN_BYTES: usize = 32;

/// Maximum accepted length (bytes) of the agent-supplied `hostname` / `os`
/// strings at enrollment. They are stored permanently in the `agents` table
/// (excluded from compaction), so an unbounded value from a peer would be a
/// permanent per-record bloat. 255 covers any real hostname (RFC 1035 limit) and
/// OS descriptor.
pub const MAX_ENROLL_FIELD_LEN: usize = 255;

/// Maximum accepted length (bytes) of the operator-facing token `label`.
pub const MAX_TOKEN_LABEL_LEN: usize = 256;

// --- Token CRUD -----------------------------------------------------------

/// Mint a new one-time enrollment token with an operator-facing `label`.
///
/// Returns the token string (64-char lowercase hex) and the stored
/// [`TokenRow`]. The 32 random bytes come from the OS CSPRNG.
pub fn create_token(store: &Store, label: &str) -> anyhow::Result<(String, TokenRow)> {
    if label.len() > MAX_TOKEN_LABEL_LEN {
        anyhow::bail!(
            "token label too long ({} bytes; max {MAX_TOKEN_LABEL_LEN})",
            label.len()
        );
    }
    let mut raw = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let row = TokenRow {
        created_at_ns: now_ns(),
        label: label.to_string(),
        used: false,
    };
    store.insert_token(&token, &row)?;
    Ok((token, row))
}

/// List all enrollment tokens as `(token, row)` pairs (including consumed ones,
/// so the dashboard can show `used` state).
pub fn list_tokens(store: &Store) -> anyhow::Result<Vec<(String, TokenRow)>> {
    store.list_tokens()
}

/// Revoke an unused token. Returns `Ok(true)` if a still-unused token was
/// removed; `Ok(false)` if it was unknown or already consumed (the caller maps
/// the already-consumed case to HTTP 409).
pub fn revoke_token(store: &Store, token: &str) -> anyhow::Result<bool> {
    store.revoke_token_if_unused(token)
}

// --- Atomic burn-and-enroll ----------------------------------------------

/// Outcome of an [`enroll`] attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// The token was valid; it has been burned and the agent enrolled.
    Accepted { agent_id: String },
    /// The token was missing, used, or expired; nothing was changed.
    Rejected { reason: String },
}

/// Atomically validate-and-burn a one-time token and enrol a new agent.
///
/// Delegates the single write transaction (over both `enroll_tokens` and
/// `agents`) to [`Store::enroll_txn`] and maps a [`EnrollReject`] to a
/// human-readable `reason`. On success the assigned `agent_id` is a fresh
/// UUIDv4 (never containing `':'`, which the subject-key composite relies on).
pub fn enroll(
    store: &Store,
    token: &str,
    hostname: &str,
    os: &str,
    pubkey: [u8; 32],
) -> anyhow::Result<EnrollOutcome> {
    // Bound the agent-supplied descriptor strings before they are persisted
    // permanently in the `agents` table (L2). Reject (rather than truncate) so a
    // misbehaving/compromised endpoint gets a clear signal and the token is not
    // burned on a malformed request.
    if hostname.len() > MAX_ENROLL_FIELD_LEN || os.len() > MAX_ENROLL_FIELD_LEN {
        return Ok(EnrollOutcome::Rejected {
            reason: format!("hostname/os too long (max {MAX_ENROLL_FIELD_LEN} bytes each)"),
        });
    }
    let result = store.enroll_txn(token, now_ns(), TOKEN_VALIDITY_NS, hostname, os, pubkey)?;
    Ok(match result {
        Ok((agent_id, _row)) => EnrollOutcome::Accepted { agent_id },
        Err(reject) => EnrollOutcome::Rejected {
            reason: reject_reason(reject),
        },
    })
}

/// Render a [`EnrollReject`] as the `reason` returned to the agent.
fn reject_reason(reject: EnrollReject) -> String {
    reject.to_string()
}

// --- Session challenge / verify ------------------------------------------

/// Derive the 32-byte session nonce from the server's challenge UUID.
///
/// Must match the agent's `auth::nonce_from_challenge`: both expand the 16-byte
/// `Command.id` to a fixed-width 32-byte nonce via SHA-256 before feeding it
/// into [`auth_challenge_digest`].
pub fn nonce_from_challenge(challenge_id: &Uuid) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge_id.as_bytes());
    h.finalize().into()
}

/// Mint a fresh challenge: the random UUID carried as the `Command.id` of the
/// `ServerCommand::Noop` auth challenge. Freshness (replay resistance) comes
/// from this per-session random id; the nonce is derived from it via
/// [`nonce_from_challenge`].
pub fn make_challenge() -> Uuid {
    Uuid::new_v4()
}

/// Verify an agent's challenge signature against its enrolled public key.
///
/// Rebuilds the exact digest the agent signed — `auth_challenge_digest(pin,
/// agent_id, nonce, tls_exporter)` where `nonce = nonce_from_challenge(id)` — and
/// checks the base64-decoded signature with `verify_strict`. Returns `false` on
/// any malformed input (bad key, bad base64, wrong signature length) as well as
/// a genuine signature mismatch; the caller treats all of these identically
/// (reject the session).
///
/// * `stored_pubkey` is the agent's enrolled `AgentRow.pubkey`.
/// * `pin` is the SHA-256 of the server's own leaf certificate DER (see
///   [`cert_fingerprint`] / [`pin::fingerprint`]).
/// * `challenge_id` is the UUID the server sent in its `Noop` challenge.
/// * `tls_exporter` is this session's RFC-5705 keying material.
/// * `sig_b64` is the agent's `CommandResult.detail` (standard base64).
pub fn verify_challenge(
    stored_pubkey: &[u8; 32],
    pin: &[u8; PIN_LEN],
    agent_id: &str,
    challenge_id: &Uuid,
    tls_exporter: &[u8],
    sig_b64: &str,
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(stored_pubkey) else {
        return false;
    };
    // An Ed25519 signature is exactly 64 bytes; base64-encoded that is 88 chars
    // (no padding variation since 64 % 3 == 1). Reject anything grossly oversized
    // before touching the allocator, so a malicious agent cannot force a large
    // heap allocation via a padded or garbage detail string.
    let trimmed = sig_b64.trim();
    if trimmed.len() > 128 {
        return false;
    }
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    let nonce = nonce_from_challenge(challenge_id);
    let digest = auth_challenge_digest(pin, agent_id, &nonce, tls_exporter);
    vk.verify_strict(&digest, &sig).is_ok()
}

/// Hex-encode the SHA-256 fingerprint of the server's leaf certificate DER.
///
/// This is the value the operator distributes to agents as the pin (and that the
/// future `GET /server-info` route exposes); it is also the raw input — via
/// [`pin::fingerprint`] — to the [`verify_challenge`] digest.
pub fn cert_fingerprint(server_cert_der: &[u8]) -> String {
    hex::encode(pin::fingerprint(server_cert_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use ed25519_dalek::{Signer, SigningKey};
    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, Store) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).expect("open store");
        (dir, store)
    }

    #[test]
    fn create_token_is_hex64_and_unused() {
        let (_d, store) = open_tmp();
        let (token, row) = create_token(&store, "laptop-3").unwrap();
        assert_eq!(token.len(), 64, "token is 32 bytes hex");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(row.label, "laptop-3");
        assert!(!row.used);

        // It shows up in the listing, still unused.
        let listed = list_tokens(&store).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, token);
        assert!(!listed[0].1.used);
    }

    #[test]
    fn enroll_burns_token_and_assigns_uuid() {
        let (_d, store) = open_tmp();
        let (token, _) = create_token(&store, "host").unwrap();
        let pubkey = [9u8; 32];

        let outcome = enroll(&store, &token, "host-a", "Linux", pubkey).unwrap();
        let agent_id = match outcome {
            EnrollOutcome::Accepted { agent_id } => agent_id,
            other => panic!("expected acceptance, got {other:?}"),
        };
        // UUIDv4: parseable and contains no ':' (subject-key invariant).
        assert!(Uuid::parse_str(&agent_id).is_ok());
        assert!(!agent_id.contains(':'));

        // The agent row exists with the stored pubkey.
        let row = store.agent(&agent_id).unwrap().expect("agent row");
        assert_eq!(row.pubkey, pubkey);
        assert_eq!(row.hostname, "host-a");
    }

    #[test]
    fn enroll_token_is_single_use() {
        let (_d, store) = open_tmp();
        let (token, _) = create_token(&store, "host").unwrap();

        // First enroll succeeds.
        let first = enroll(&store, &token, "h", "os", [1u8; 32]).unwrap();
        assert!(matches!(first, EnrollOutcome::Accepted { .. }));

        // Second enroll with the SAME token is rejected (burned), and creates no
        // second agent.
        let before = store.agents().unwrap().len();
        let second = enroll(&store, &token, "h", "os", [2u8; 32]).unwrap();
        match second {
            EnrollOutcome::Rejected { reason } => {
                assert!(reason.to_lowercase().contains("used"), "reason: {reason}");
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        assert_eq!(store.agents().unwrap().len(), before, "no second agent");
    }

    #[test]
    fn create_token_rejects_overlong_label() {
        let (_d, store) = open_tmp();
        let long = "x".repeat(MAX_TOKEN_LABEL_LEN + 1);
        assert!(
            create_token(&store, &long).is_err(),
            "over-long label must be rejected"
        );
        // A label at the limit is accepted.
        let ok = "y".repeat(MAX_TOKEN_LABEL_LEN);
        assert!(create_token(&store, &ok).is_ok());
    }

    #[test]
    fn enroll_rejects_overlong_hostname_or_os_without_burning_token() {
        let (_d, store) = open_tmp();
        let (token, _) = create_token(&store, "host").unwrap();
        let long = "h".repeat(MAX_ENROLL_FIELD_LEN + 1);

        // Over-long hostname is rejected...
        let outcome = enroll(&store, &token, &long, "Linux", [1u8; 32]).unwrap();
        assert!(matches!(outcome, EnrollOutcome::Rejected { .. }));
        // ...and the token is NOT burned (the request was malformed, not used).
        assert!(store.agents().unwrap().is_empty(), "no agent created");
        let still_unused = list_tokens(&store)
            .unwrap()
            .into_iter()
            .find(|(t, _)| *t == token)
            .map(|(_, r)| !r.used)
            .unwrap_or(false);
        assert!(still_unused, "token must remain reusable after a rejection");

        // The same token then enrolls fine with sane fields.
        let ok = enroll(&store, &token, "host-a", "Linux", [1u8; 32]).unwrap();
        assert!(matches!(ok, EnrollOutcome::Accepted { .. }));
    }

    #[test]
    fn enroll_unknown_token_rejected() {
        let (_d, store) = open_tmp();
        let outcome = enroll(&store, "deadbeef", "h", "os", [0u8; 32]).unwrap();
        assert!(matches!(outcome, EnrollOutcome::Rejected { .. }));
        assert!(store.agents().unwrap().is_empty());
    }

    #[test]
    fn revoke_unused_then_already_used() {
        let (_d, store) = open_tmp();
        let (t1, _) = create_token(&store, "a").unwrap();
        // Revoking an unused token succeeds and removes it.
        assert!(revoke_token(&store, &t1).unwrap());
        assert!(enroll(&store, &t1, "h", "o", [0u8; 32])
            .unwrap()
            .eq(&EnrollOutcome::Rejected {
                reason: EnrollReject::UnknownToken.to_string()
            }));

        // A consumed token cannot be revoked (maps to 409 in the API).
        let (t2, _) = create_token(&store, "b").unwrap();
        enroll(&store, &t2, "h", "o", [0u8; 32]).unwrap();
        assert!(
            !revoke_token(&store, &t2).unwrap(),
            "used token not revocable"
        );
        // An unknown token also returns false.
        assert!(!revoke_token(&store, "nope").unwrap());
    }

    #[test]
    fn cert_fingerprint_matches_pin_of_der() {
        // The hex fingerprint must equal hex(pin::fingerprint(der)) so an agent
        // pinning the printed value computes the same digest pin.
        let ck = generate_simple_self_signed(vec!["aegisd".to_string()]).unwrap();
        let der = ck.cert.der().to_vec();
        let fp = cert_fingerprint(&der);
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, hex::encode(pin::fingerprint(&der)));
        // Deterministic.
        assert_eq!(fp, cert_fingerprint(&der));
    }

    /// End-to-end: a signature produced exactly the way the agent's `sign_auth`
    /// produces it must verify, and tampering with any bound input must fail.
    #[test]
    fn verify_challenge_accepts_agent_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = key.verifying_key().to_bytes();
        let pin = [3u8; PIN_LEN];
        let agent_id = "agent-1";
        let challenge_id = make_challenge();
        let exporter = [9u8; 32];

        // Reproduce the agent side: nonce = SHA256(id), sign the shared digest,
        // base64-encode (matches `plugin_transport::auth::sign_auth`).
        let nonce = nonce_from_challenge(&challenge_id);
        let digest = auth_challenge_digest(&pin, agent_id, &nonce, &exporter);
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.sign(&digest).to_bytes());

        assert!(verify_challenge(
            &vk,
            &pin,
            agent_id,
            &challenge_id,
            &exporter,
            &sig_b64
        ));

        // Wrong agent_id -> reject.
        assert!(!verify_challenge(
            &vk,
            &pin,
            "agent-2",
            &challenge_id,
            &exporter,
            &sig_b64
        ));
        // Wrong pin -> reject.
        let mut pin2 = pin;
        pin2[0] ^= 1;
        assert!(!verify_challenge(
            &vk,
            &pin2,
            agent_id,
            &challenge_id,
            &exporter,
            &sig_b64
        ));
        // Wrong challenge id (different nonce) -> reject.
        assert!(!verify_challenge(
            &vk,
            &pin,
            agent_id,
            &make_challenge(),
            &exporter,
            &sig_b64
        ));
        // Wrong exporter -> reject.
        assert!(!verify_challenge(
            &vk,
            &pin,
            agent_id,
            &challenge_id,
            &[0u8; 32],
            &sig_b64
        ));
    }

    #[test]
    fn verify_challenge_rejects_malformed_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = key.verifying_key().to_bytes();
        let pin = [1u8; PIN_LEN];
        let id = make_challenge();
        // Not base64.
        assert!(!verify_challenge(
            &vk,
            &pin,
            "a",
            &id,
            &[0u8; 32],
            "!!!not-base64!!!"
        ));
        // Valid base64 but wrong length for an Ed25519 signature.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 8]);
        assert!(!verify_challenge(&vk, &pin, "a", &id, &[0u8; 32], &short));
    }
}
