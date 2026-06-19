//! A SHA-256 *baseline manifest* of the agent's protected files.
//!
//! The tamper-watch loop originally only checked that protected paths still
//! *exist* (`path.exists()`), which an attacker defeats by replacing a file
//! in-place with a decoy of any content. This module records, at install time,
//! the exact SHA-256 digest and length of each protected file, so the runtime can
//! detect *content* drift (silent replacement), not merely deletion.
//!
//! The manifest is itself written root-owned and made immutable at install (see
//! [`super::install`]), so tampering with the baseline is the same privileged
//! operation as tampering with the files it protects.
//!
//! ## Pure core
//!
//! [`hash_bytes`] and [`classify`] are pure and unit-tested in CI; only
//! [`Manifest::from_paths`] and [`verify`] touch the filesystem.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::PathBuf;

/// One protected file's recorded baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Absolute path of the protected file.
    pub path: PathBuf,
    /// Lowercase-hex SHA-256 of the file's bytes at install time.
    pub sha256: String,
    /// File length in bytes at install time (a cheap pre-check before hashing).
    pub len: u64,
}

/// The full baseline: a set of [`ManifestEntry`] plus when it was created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Creation time, nanoseconds since the Unix epoch.
    pub created_ns: u64,
    pub entries: Vec<ManifestEntry>,
}

/// Pure: SHA-256 of `bytes` as lowercase hex.
///
/// Uses the same convention as the rest of the codebase
/// (`sha2::{Digest, Sha256}` + [`hex::encode`]); see `aegis-proto::pin` and
/// `plugin-session`.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// SHA-256 (lowercase hex) of everything `reader` yields, hashed in fixed-size
/// chunks so an arbitrarily large file is never buffered into memory at once.
///
/// `Sha256` implements [`io::Write`], so [`io::copy`] streams the file straight
/// through the hasher. This is what lets [`verify`] hash a protected file without
/// a hostile same-size replacement forcing an unbounded allocation.
fn hash_reader<R: io::Read>(reader: &mut R) -> io::Result<String> {
    struct HashSink(Sha256);
    impl io::Write for HashSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut sink = HashSink(Sha256::new());
    io::copy(reader, &mut sink)?;
    Ok(hex::encode(sink.0.finalize()))
}

impl Manifest {
    /// Build a manifest by hashing each path (install time).
    ///
    /// Each file is streamed through [`hash_reader`] in fixed-size chunks rather
    /// than slurped whole with `std::fs::read`: the protected set includes the
    /// agent binary, which can be tens or hundreds of MB, so buffering it entirely
    /// would cause a transient allocation spike at install. `len` comes from the
    /// open file's metadata. Returns the first I/O error encountered, so a manifest
    /// is never written over a file the installer could not read.
    pub fn from_paths(paths: &[PathBuf]) -> io::Result<Self> {
        let mut entries = Vec::with_capacity(paths.len());
        for path in paths {
            let mut file = std::fs::File::open(path)?;
            let len = file.metadata()?.len();
            let sha256 = hash_reader(&mut file)?;
            entries.push(ManifestEntry {
                path: path.clone(),
                sha256,
                len,
            });
        }
        Ok(Manifest {
            created_ns: aegis_sdk::now_ns(),
            entries,
        })
    }

    /// Serialize to pretty JSON (written to disk at install).
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Parse from JSON (read back by the runtime tamper loop).
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// The integrity verdict for a single protected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftKind {
    /// The file matches its recorded length and digest.
    Ok,
    /// The file is gone (deleted/renamed).
    Missing,
    /// The file exists but its length differs from the baseline.
    SizeChanged,
    /// The file's length matches but its content (digest) differs.
    ContentChanged,
}

impl DriftKind {
    /// Whether this verdict represents tampering (anything but [`DriftKind::Ok`]).
    #[must_use]
    pub fn is_drift(self) -> bool {
        !matches!(self, DriftKind::Ok)
    }

    /// A short, stable label for alert text.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            DriftKind::Ok => "ok",
            DriftKind::Missing => "missing",
            DriftKind::SizeChanged => "size changed",
            DriftKind::ContentChanged => "content changed",
        }
    }
}

/// Pure: classify an observed file state against its recorded baseline.
///
/// `observed` is `None` if the file is absent, or `Some((bytes, len))` for a
/// present file. Length is compared before content so a truncation/extension is
/// reported as [`DriftKind::SizeChanged`] even if (degenerately) a same-length
/// replacement would be [`DriftKind::ContentChanged`]. Kept pure so the full
/// truth table is unit-testable without touching the filesystem.
#[must_use]
pub fn classify(expected: &ManifestEntry, observed: Option<(&[u8], u64)>) -> DriftKind {
    match observed {
        None => DriftKind::Missing,
        Some((bytes, len)) => {
            if len != expected.len {
                DriftKind::SizeChanged
            } else if hash_bytes(bytes) != expected.sha256 {
                DriftKind::ContentChanged
            } else {
                DriftKind::Ok
            }
        }
    }
}

/// Runtime: stat each manifest path, then classify it against the baseline.
///
/// Hardened against a hostile multi-GB same-path replacement (this runs every
/// `check_interval_s`):
///
/// 1. **`metadata` size pre-filter** — if the file's length differs from the
///    recorded [`ManifestEntry::len`], it is [`DriftKind::SizeChanged`]
///    immediately, with **no read** (so an oversized decoy is never slurped).
/// 2. **streaming hash** — only when the size matches is the file hashed, and
///    then in fixed-size chunks via [`hash_reader`] (never buffered whole), so a
///    same-size-claimed hostile file cannot force an unbounded allocation either.
///
/// A path that cannot be stat'd/opened is reported as [`DriftKind::Missing`].
/// Returns one `(path, verdict)` per entry, in manifest order.
#[must_use]
pub fn verify(manifest: &Manifest) -> Vec<(PathBuf, DriftKind)> {
    manifest
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), verify_entry(entry)))
        .collect()
}

/// Classify a single entry against the on-disk file using the stat-then-stream
/// strategy described on [`verify`].
fn verify_entry(entry: &ManifestEntry) -> DriftKind {
    // `symlink_metadata` does not traverse a final symlink: if the protected file
    // was swapped for a symlink, that is itself drift (the link's own length will
    // not match) rather than a read of whatever it points at.
    let meta = match std::fs::symlink_metadata(&entry.path) {
        Ok(m) => m,
        Err(_) => return DriftKind::Missing,
    };
    if !meta.is_file() {
        // A directory/symlink/socket where a regular file was recorded is drift.
        return DriftKind::SizeChanged;
    }
    if meta.len() != entry.len {
        return DriftKind::SizeChanged;
    }
    // Sizes match: stream-hash to detect a same-length content swap.
    match std::fs::File::open(&entry.path) {
        Ok(mut f) => match hash_reader(&mut f) {
            Ok(digest) if digest == entry.sha256 => DriftKind::Ok,
            Ok(_) => DriftKind::ContentChanged,
            Err(_) => DriftKind::Missing,
        },
        Err(_) => DriftKind::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bytes_matches_known_vector() {
        // SHA-256("") and SHA-256("abc") are well-known test vectors.
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn entry(sha: &str, len: u64) -> ManifestEntry {
        ManifestEntry {
            path: PathBuf::from("/x"),
            sha256: sha.to_string(),
            len,
        }
    }

    #[test]
    fn classify_reports_ok_for_matching_content() {
        let bytes = b"hello world";
        let e = entry(&hash_bytes(bytes), bytes.len() as u64);
        assert_eq!(
            classify(&e, Some((bytes, bytes.len() as u64))),
            DriftKind::Ok
        );
    }

    #[test]
    fn classify_reports_missing_when_absent() {
        let e = entry(&hash_bytes(b"hello"), 5);
        assert_eq!(classify(&e, None), DriftKind::Missing);
    }

    #[test]
    fn classify_reports_size_changed_on_length_diff() {
        let e = entry(&hash_bytes(b"hello"), 5);
        let now = b"hello!!";
        assert_eq!(
            classify(&e, Some((now, now.len() as u64))),
            DriftKind::SizeChanged
        );
    }

    #[test]
    fn classify_reports_content_changed_on_same_length_diff() {
        let e = entry(&hash_bytes(b"hello"), 5);
        let now = b"world"; // same length, different bytes
        assert_eq!(
            classify(&e, Some((now, now.len() as u64))),
            DriftKind::ContentChanged
        );
    }

    #[test]
    fn manifest_json_roundtrips() {
        let m = Manifest {
            created_ns: 123,
            entries: vec![
                entry("aa", 1),
                ManifestEntry {
                    path: PathBuf::from("/etc/systemd/system/aegis-agent.service"),
                    sha256: hash_bytes(b"unit text"),
                    len: 9,
                },
            ],
        };
        let json = m.to_json().unwrap();
        let back = Manifest::from_json(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn from_paths_hashes_real_files() {
        let dir = std::env::temp_dir().join(format!("aegis-manifest-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"alpha").unwrap();
        std::fs::write(&b, b"bravo!").unwrap();

        let m = Manifest::from_paths(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.entries[0].sha256, hash_bytes(b"alpha"));
        assert_eq!(m.entries[0].len, 5);
        assert_eq!(m.entries[1].sha256, hash_bytes(b"bravo!"));
        assert_eq!(m.entries[1].len, 6);

        // verify() over the unmodified files is all-Ok.
        let v = verify(&m);
        assert!(v.iter().all(|(_, k)| *k == DriftKind::Ok));

        // Mutate one file and confirm drift is detected.
        std::fs::write(&b, b"BRAVO!").unwrap(); // same length, new content
        let v2 = verify(&m);
        let kind_b = v2.iter().find(|(p, _)| p == &b).map(|(_, k)| *k);
        assert_eq!(kind_b, Some(DriftKind::ContentChanged));

        // Remove one file and confirm Missing.
        std::fs::remove_file(&a).unwrap();
        let v3 = verify(&m);
        let kind_a = v3.iter().find(|(p, _)| p == &a).map(|(_, k)| *k);
        assert_eq!(kind_a, Some(DriftKind::Missing));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_paths_errors_on_missing_file() {
        let missing = PathBuf::from("/nonexistent/aegis/does-not-exist");
        assert!(Manifest::from_paths(&[missing]).is_err());
    }

    #[test]
    fn hash_reader_matches_hash_bytes() {
        // The streaming hasher must produce the identical digest to the in-memory
        // one for the same input (so verify() agrees with from_paths()).
        let data = b"the quick brown fox jumps over the lazy dog";
        let mut cur = std::io::Cursor::new(&data[..]);
        assert_eq!(hash_reader(&mut cur).unwrap(), hash_bytes(data));
        // Empty input -> SHA-256("").
        let mut empty = std::io::Cursor::new(&b""[..]);
        assert_eq!(hash_reader(&mut empty).unwrap(), hash_bytes(b""));
    }

    /// L8 regression: `verify` classifies a size mismatch via the metadata
    /// pre-filter (SizeChanged) and a same-size content swap via the streaming
    /// hash (ContentChanged), and reports a swapped-in symlink/dir as drift.
    #[test]
    fn verify_uses_size_prefilter_then_streams() {
        let dir = std::env::temp_dir().join(format!("aegis-manifest-l8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("bin");
        std::fs::write(&f, b"hello").unwrap();
        let m = Manifest::from_paths(std::slice::from_ref(&f)).unwrap();
        assert_eq!(verify(&m)[0].1, DriftKind::Ok);

        // Grow the file: different length -> SizeChanged (no content read needed).
        std::fs::write(&f, b"hello world, this is much longer").unwrap();
        assert_eq!(verify(&m)[0].1, DriftKind::SizeChanged);

        // Same length, different bytes -> ContentChanged via streaming hash.
        std::fs::write(&f, b"world").unwrap(); // 5 bytes, matches baseline len
        assert_eq!(verify(&m)[0].1, DriftKind::ContentChanged);

        // Replace the regular file with a directory -> drift, not a panic/read.
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
        assert_eq!(verify(&m)[0].1, DriftKind::SizeChanged);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
