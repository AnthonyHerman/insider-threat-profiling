//! Agent enrollment identity: the per-agent Ed25519 key, assigned `agent_id`,
//! and the server certificate pin(s) — all written by `aegis-agent enroll` and
//! read back by the running forwarder.
//!
//! Layout under the plugin's data dir (`<data_dir>/plugin-transport/`):
//!
//! * `identity.json` — `{ agent_id, server_pins: [hex32, ...], enrolled_at_ns }`
//! * `agent_ed25519.key` — the raw 32-byte Ed25519 seed, mode `0600`
//!
//! The forwarder never self-enrolls: if `identity.json` is absent it logs a
//! clear "run `aegis-agent enroll`" warning and idles. Secret intake (the
//! one-time token + pin) is the `enroll` subcommand's responsibility and is read
//! from stdin or a `0600` file — never from argv/env — via [`read_enroll_blob`].

use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aegis_proto::pin::{self, PIN_LEN};
use anyhow::{anyhow, Context};
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const IDENTITY_FILE: &str = "identity.json";
const KEY_FILE: &str = "agent_ed25519.key";

/// The on-disk `identity.json` schema. Pins are stored as lowercase hex so the
/// file is human-inspectable; the key seed lives in a separate `0600` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityFile {
    agent_id: String,
    server_pins: Vec<String>,
    enrolled_at_ns: u64,
}

/// A fully-loaded enrollment identity ready for the connection actor.
pub struct Enrolled {
    pub agent_id: String,
    pub signing_key: SigningKey,
    pub server_pins: Vec<[u8; PIN_LEN]>,
}

impl std::fmt::Debug for Enrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the signing key.
        f.debug_struct("Enrolled")
            .field("agent_id", &self.agent_id)
            .field(
                "server_pins",
                &self.server_pins.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Load the enrollment identity from `data_dir`, or `None` if not enrolled yet
/// (i.e. `identity.json` is absent). Returns an error only on a malformed or
/// unreadable file once it does exist.
pub fn load(data_dir: &Path) -> anyhow::Result<Option<Enrolled>> {
    let id_path = data_dir.join(IDENTITY_FILE);
    if !id_path.exists() {
        return Ok(None);
    }
    let text =
        fs::read_to_string(&id_path).with_context(|| format!("reading {}", id_path.display()))?;
    let parsed: IdentityFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", id_path.display()))?;

    let key_path = data_dir.join(KEY_FILE);
    let seed = fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{} is not a 32-byte Ed25519 seed", key_path.display()))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let mut server_pins = Vec::with_capacity(parsed.server_pins.len());
    for (i, p) in parsed.server_pins.iter().enumerate() {
        let pin =
            pin::parse_pin_hex(p).ok_or_else(|| anyhow!("server_pins[{i}] is not 64-char hex"))?;
        server_pins.push(pin);
    }
    if server_pins.is_empty() {
        return Err(anyhow!("identity.json has no server pins"));
    }

    Ok(Some(Enrolled {
        agent_id: parsed.agent_id,
        signing_key,
        server_pins,
    }))
}

/// Persist a freshly-enrolled identity. Creates `data_dir` if needed and writes
/// both files mode `0600` (the seed must never be world-readable; the JSON is
/// non-secret but kept consistent). Owned by whatever uid runs `enroll`.
pub fn persist(
    data_dir: &Path,
    agent_id: &str,
    signing_key: &SigningKey,
    pins: &[[u8; PIN_LEN]],
) -> anyhow::Result<()> {
    fs::create_dir_all(data_dir).with_context(|| format!("creating {}", data_dir.display()))?;

    let file = IdentityFile {
        agent_id: agent_id.to_string(),
        server_pins: pins.iter().map(hex::encode).collect(),
        enrolled_at_ns: aegis_sdk::now_ns(),
    };
    let json = serde_json::to_vec_pretty(&file)?;
    write_private(&data_dir.join(IDENTITY_FILE), &json)?;
    write_private(&data_dir.join(KEY_FILE), signing_key.to_bytes().as_slice())?;
    Ok(())
}

/// Write `bytes` to `path` with mode `0600`, truncating any prior file.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    // Tighten mode even if the file pre-existed with looser perms (create+mode
    // only sets perms on creation).
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o600);
    fs::set_permissions(path, perms).ok();
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    f.flush().ok();
    Ok(())
}

/// Decode an `AEGIS-ENROLL <base64(token || pin32)>` blob into its parts.
///
/// The trailing 32 bytes are the server cert pin; everything before is the
/// UTF-8 enrollment token. The blob is read from `source` (stdin or a file the
/// `enroll` subcommand opened) — never from argv/env, so the secret token does
/// not appear in `/proc/<pid>/cmdline` or the environment.
pub fn parse_enroll_blob(line: &str) -> anyhow::Result<(String, [u8; PIN_LEN])> {
    let b64 = line
        .trim()
        .strip_prefix("AEGIS-ENROLL")
        .map(str::trim)
        .ok_or_else(|| anyhow!("enroll blob must start with `AEGIS-ENROLL`"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("enroll blob is not valid base64")?;
    if raw.len() <= PIN_LEN {
        return Err(anyhow!(
            "enroll blob too short: need token bytes plus a {PIN_LEN}-byte pin"
        ));
    }
    let split = raw.len() - PIN_LEN;
    let token =
        String::from_utf8(raw[..split].to_vec()).context("enroll token is not valid UTF-8")?;
    let pin: [u8; PIN_LEN] = raw[split..].try_into().expect("checked length");
    Ok((token, pin))
}

/// Read and parse an enroll blob from an open reader (stdin or a file).
pub fn read_enroll_blob<R: Read>(mut reader: R) -> anyhow::Result<(String, [u8; PIN_LEN])> {
    let mut buf = String::new();
    reader
        .read_to_string(&mut buf)
        .context("reading enroll blob")?;
    parse_enroll_blob(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A unique temp dir without pulling in the `tempfile` crate (musl-safe).
    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis-id-test-{tag}-{}-{}",
            std::process::id(),
            aegis_sdk::now_ns()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn load_absent_is_none() {
        let d = tmp_dir("absent");
        assert!(load(&d).unwrap().is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn persist_then_load_roundtrips() {
        let d = tmp_dir("roundtrip");
        let key = generate_key();
        let vk = key.verifying_key().to_bytes();
        let pin_a = [0x11u8; PIN_LEN];
        let pin_b = [0x22u8; PIN_LEN];

        persist(&d, "agent-xyz", &key, &[pin_a, pin_b]).unwrap();

        let loaded = load(&d).unwrap().expect("identity present");
        assert_eq!(loaded.agent_id, "agent-xyz");
        assert_eq!(loaded.signing_key.verifying_key().to_bytes(), vk);
        assert_eq!(loaded.server_pins, vec![pin_a, pin_b]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn key_file_is_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp_dir("perms");
        persist(&d, "a", &generate_key(), &[[7u8; PIN_LEN]]).unwrap();
        let meta = fs::metadata(d.join(KEY_FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn enroll_blob_roundtrips() {
        let token = "one-time-token-abc";
        let pin = [0x5au8; PIN_LEN];
        let mut raw = token.as_bytes().to_vec();
        raw.extend_from_slice(&pin);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let line = format!("AEGIS-ENROLL {b64}\n");

        let (got_token, got_pin) = parse_enroll_blob(&line).unwrap();
        assert_eq!(got_token, token);
        assert_eq!(got_pin, pin);
    }

    #[test]
    fn enroll_blob_rejects_bad_input() {
        assert!(parse_enroll_blob("no prefix here").is_err());
        assert!(parse_enroll_blob("AEGIS-ENROLL not-base64!!").is_err());
        // Valid base64 but too short to contain a pin.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        assert!(parse_enroll_blob(&format!("AEGIS-ENROLL {short}")).is_err());
    }
}
