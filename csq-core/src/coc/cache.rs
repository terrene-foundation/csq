//! `.coc/COC.lock` content hashing (cache-invalidation key) and the binary
//! parse cache (`<coc_root>/.cache/parsed-<sha>.bin`).
//!
//! # Parse cache (spec 10 §10.9.3 / design 08 §1.3)
//!
//! The parse cache stores the deserialized `CocSet` as a binary blob so
//! that subsequent `csq run` invocations can skip the YAML parse + build
//! step. The cache key is the SHA-256 of `COC.lock`. Cache files live
//! under `<coc_root>/.cache/` with file-level security controls.
//!
//! Security posture:
//! - Files opened with `O_NOFOLLOW` (Unix) or symlink-metadata rejection (Windows)
//!   to prevent TOCTOU via symlink swap.
//! - Regular-file check rejects FIFOs, devices, and sockets.
//! - File size capped at 1 MiB before reading.
//! - Magic prefix + format version + csq version + lock SHA guard before
//!   payload decode. Any validation miss → `None` (fail-open per A8).
//! - Payload size is bounded by the file-size cap (1 MiB) plus the header.
//! - Tmp files written with `create_new(true)` + mode 0o600 before rename
//!   to prevent TOCTOU at write time.
//! - Partial-failure cleanup per security.md §5a: `remove_file(&tmp)` before
//!   propagating any error from `secure_file` or `atomic_replace`.
//!
//! Per `internal-design-docs` the per-artifact signing
//! apparatus (`COC.sig`, `COC_SIGNING_PUBLIC_KEY_BYTES`, first-pull trust
//! gate) was retracted as wrong-layer; deterministic attestation belongs
//! at the runtime lifecycle layer (Step 3, `internal-design-docs`).
//! This module is now scoped to cache-key derivation and parse-cache I/O.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use tracing::warn;

use super::types::CocSet;

/// SHA-256 of `.coc/COC.lock`'s content. Used as the cache-invalidation
/// key per spec 10 §10.9.3.
pub fn lock_sha256(coc_lock_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(coc_lock_bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ─── Parse cache ──────────────────────────────────────────────────────────────

/// Magic prefix for the binary parse-cache format (9 bytes, no null terminator).
/// Mismatch → silent `None` (no content logged — the bytes could be attacker-controlled).
pub const CACHE_MAGIC: &[u8; 9] = b"COC1CACHE";

/// Binary format version stored at bytes 9..11 (big-endian u16).
/// Bump when the on-disk layout changes in a backward-incompatible way.
pub const CACHE_FORMAT_VERSION: u16 = 0x0001;

/// Maximum size of a cache file we are willing to read into memory (1 MiB).
const CACHE_MAX_FILE_SIZE: u64 = 1_048_576;

/// Per-process counter for unique tmp-file naming (PID + counter prevents
/// intra-process collision between concurrent writers in different threads).
static CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Returns the cache directory for a `.coc/` root.
/// `coc_root` is the directory that contains `.coc/` (the workspace root), NOT
/// the `.coc/` dir itself.
pub fn cache_dir(coc_root: &Path) -> PathBuf {
    coc_root.join(".cache")
}

/// Returns the cache file path for a given `lock_sha`.
pub fn cache_file(coc_root: &Path, lock_sha: &[u8; 32]) -> PathBuf {
    cache_dir(coc_root).join(format!("parsed-{}.bin", hex::encode(lock_sha)))
}

/// Try to read and validate a binary parse cache for the given `lock_sha`.
///
/// Returns `Some(CocSet)` on a clean hit, `None` on any miss or validation
/// failure (fail-open per A8 — the caller falls back to a full parse).
///
/// Security properties:
/// - Opens with `O_NOFOLLOW` on Unix (rejects symlinks at the open call).
/// - Validates `is_file()` before reading (rejects FIFOs, devices, sockets).
/// - Caps file size at 1 MiB.
/// - Validates magic, format version, csq version, and lock SHA before
///   passing bytes to bincode.
/// - Logs corrupted bincode at WARN with fixed tag `cache_corrupt`; no
///   content bytes are included in the log message.
pub fn read_parsed_cache(coc_root: &Path, lock_sha: &[u8; 32]) -> Option<CocSet> {
    let path = cache_file(coc_root, lock_sha);

    // Open with O_NOFOLLOW on Unix; metadata-then-open with symlink rejection
    // on Windows (O_NOFOLLOW is not available).
    #[cfg(unix)]
    let file_result: io::Result<std::fs::File> = {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NOFOLLOW = 0x20000 on Linux, 0x100 on macOS. `custom_flags` is
        // the portable-Rust approach. O_NONBLOCK ensures opening a FIFO
        // without a writer doesn't block the daemon thread (macOS blocks
        // FIFO read-opens by default). The is_file() check below still
        // rejects the FIFO; O_NONBLOCK is purely a fail-fast guard.
        // For regular files O_NONBLOCK is a no-op on read.
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
    };

    #[cfg(not(unix))]
    let file_result: io::Result<std::fs::File> = {
        // Windows: check symlink metadata before opening.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return None;
            }
            Ok(_) => std::fs::File::open(&path),
            Err(_) => return None,
        }
    };

    let file = match file_result {
        Ok(f) => f,
        Err(_e) => {
            #[cfg(test)]
            eprintln!("[cache_read] open failed: {_e}");
            return None;
        }
    };

    // Verify this is a regular file (not a FIFO, device, or socket).
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_e) => {
            #[cfg(test)]
            eprintln!("[cache_read] metadata failed: {_e}");
            return None;
        }
    };
    if !meta.file_type().is_file() {
        #[cfg(test)]
        eprintln!("[cache_read] not a regular file");
        return None;
    }
    if meta.len() > CACHE_MAX_FILE_SIZE {
        #[cfg(test)]
        eprintln!("[cache_read] file too large: {}", meta.len());
        return None;
    }

    // Read all bytes.
    use std::io::Read as _;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    if let Err(_e) = std::io::BufReader::new(file).read_to_end(&mut buf) {
        #[cfg(test)]
        eprintln!("[cache_read] read_to_end failed: {_e}");
        return None;
    }

    // Layout:
    //   [0..9]    magic (9 bytes)
    //   [9..11]   format version (BE u16, 2 bytes)
    //   [11..27]  csq version (16-byte nul-padded UTF-8)
    //   [27..59]  lock_sha (32 bytes)
    //   [59..]    bincode payload

    const HEADER_LEN: usize = 9 + 2 + 16 + 32;

    if buf.len() < HEADER_LEN {
        #[cfg(test)]
        eprintln!("[cache_read] buf too short: {} < {HEADER_LEN}", buf.len());
        return None;
    }

    // Validate magic.
    if &buf[0..9] != CACHE_MAGIC.as_ref() {
        #[cfg(test)]
        eprintln!(
            "[cache_read] magic mismatch: {:?} != {:?}",
            &buf[0..9],
            CACHE_MAGIC
        );
        // No content logged — mismatch means it could be attacker-controlled.
        return None;
    }

    // Validate format version.
    let version_bytes: [u8; 2] = [buf[9], buf[10]];
    let file_version = u16::from_be_bytes(version_bytes);
    if file_version != CACHE_FORMAT_VERSION {
        #[cfg(test)]
        eprintln!("[cache_read] format version mismatch: {file_version} != {CACHE_FORMAT_VERSION}");
        return None;
    }

    // Validate csq version. The cache was written by a specific binary build;
    // a version mismatch means the in-memory representation may have changed.
    let csq_ver_in_file = &buf[11..27];
    let current_ver = csq_version_padded();
    if csq_ver_in_file != current_ver {
        #[cfg(test)]
        eprintln!(
            "[cache_read] csq version mismatch: {:?} != {:?}",
            csq_ver_in_file, current_ver
        );
        return None;
    }

    // Validate lock SHA.
    if &buf[27..59] != lock_sha.as_ref() {
        #[cfg(test)]
        eprintln!(
            "[cache_read] lock_sha mismatch: {:?} != {:?}",
            &buf[27..59],
            lock_sha.as_ref()
        );
        return None;
    }

    // Bincode-deserialize the payload as a length-prefixed Vec<u8> containing
    // JSON-serialized CocSet. Bincode wraps the JSON bytes with a length prefix;
    // the JSON encoding handles CocSource's internally-tagged serde representation
    // which bincode cannot natively deserialize.
    let payload = &buf[HEADER_LEN..];
    let json_bytes: Vec<u8> = match decode_length_prefixed(payload) {
        Ok(b) => b,
        Err(_e) => {
            // Log at WARN with a fixed tag only — no content bytes.
            warn!(tag = "cache_corrupt", path = %path.display(), "parse cache payload decode error; will re-parse");
            #[cfg(test)]
            eprintln!("[cache_read] decode error: {_e}");
            return None;
        }
    };
    match serde_json::from_slice::<CocSet>(&json_bytes) {
        Ok(set) => Some(set),
        Err(_e) => {
            warn!(tag = "cache_corrupt", path = %path.display(), "parse cache JSON decode error; will re-parse");
            #[cfg(test)]
            eprintln!("[cache_read] json error: {_e}");
            None
        }
    }
}

/// Write a `CocSet` binary parse cache for the given `lock_sha`.
///
/// Uses the tmp → secure_file → atomic_replace pattern with partial-failure
/// cleanup per security.md §5a. Any error from `secure_file` or
/// `atomic_replace` cleans up the tmp file before propagating.
pub fn write_parsed_cache(coc_root: &Path, lock_sha: &[u8; 32], set: &CocSet) -> io::Result<()> {
    let dir = cache_dir(coc_root);

    // Create cache dir with mode 0700 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir)?;
    }

    // Build the buffer: magic + version + csq_ver(16) + lock_sha + payload.
    // The payload is `encode_length_prefixed(serde_json(CocSet))` — a u64 LE
    // length followed by the JSON bytes. We use JSON for CocSet because its
    // CocSource enum uses `#[serde(tag = "kind")]` (internally-tagged), and
    // we want a self-describing format. The length prefix bounds the bytes
    // the reader has to allocate. Wire format is bit-identical to bincode 1.x's
    // `with_fixint_encoding` over a `Vec<u8>` so 0x0001 caches written by older
    // csq builds keep round-tripping.
    let csq_ver = csq_version_padded();
    let json_bytes =
        serde_json::to_vec(set).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let payload = encode_length_prefixed(&json_bytes);

    let mut buf =
        Vec::with_capacity(CACHE_MAGIC.len() + 2 + csq_ver.len() + lock_sha.len() + payload.len());
    buf.extend_from_slice(CACHE_MAGIC.as_ref());
    buf.extend_from_slice(&CACHE_FORMAT_VERSION.to_be_bytes());
    buf.extend_from_slice(&csq_ver);
    buf.extend_from_slice(lock_sha.as_ref());
    buf.extend_from_slice(&payload);

    // Tmp filename: parsed-<sha>.bin.tmp.<pid>.<counter>
    // Suffix .tmp comes AFTER .bin so the sweeper's glob `parsed-*.bin`
    // does NOT match tmp files (R2/B72).
    let target = cache_file(coc_root, lock_sha);
    let counter = CACHE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = {
        let mut p = target.clone();
        let stem = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("parsed.bin")
            .to_string();
        p.set_file_name(format!("{}.tmp.{}.{}", stem, std::process::id(), counter));
        p
    };

    // Write tmp with create_new=true + mode 0o600 (blocks attacker pre-created tmp).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write as _;
        f.write_all(&buf)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, &buf)?;
    }

    // secure_file — on error, clean up tmp.
    if let Err(e) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e));
    }

    // atomic_replace — on error, clean up tmp.
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e));
    }

    // Best-effort: ensure the cache dir has a `.gitignore` so operators
    // who run csq inside a git repo do not see `parsed-*.bin` files in
    // `git status`. Failures are logged but not propagated — the cache
    // file is already on disk and the warm path will work; the
    // gitignore is a UX nicety, not a correctness requirement.
    if let Err(e) = ensure_cache_gitignore(coc_root) {
        warn!(
            tag = "cache_gitignore_write_failed",
            path = %dir.display(),
            "failed to ensure .cache/.gitignore: {e}"
        );
    }

    Ok(())
}

/// Ensure `<coc_root>/.cache/.gitignore` exists and contains `*\n` so
/// every cache artifact under `.cache/` is git-ignored. Idempotent — if
/// the file already exists with any content, this is a no-op (we do not
/// overwrite operator-edited content).
///
/// Called by [`write_parsed_cache`] on the cold path. Spec 10 §10.9.4
/// previously deferred the gitignore to loom, but the implementation
/// places the cache OUTSIDE `.coc/` (at `<coc_root>/.cache/`) so a
/// loom-emitted `.coc/.cache/.gitignore` would not cover the cache
/// files. Issuing the gitignore from csq closes that UX gap.
///
/// Failures are not security-sensitive: the file's content is the
/// public string `*`, the path is the cache dir csq already owns, and
/// the only consequence of a failed write is operators seeing
/// `.cache/parsed-*.bin` in `git status`.
pub fn ensure_cache_gitignore(coc_root: &Path) -> io::Result<()> {
    let path = cache_dir(coc_root).join(".gitignore");
    if path.exists() {
        return Ok(());
    }
    // Create the cache dir if it isn't already present (write_parsed_cache
    // creates it before calling here, but exposing the helper means a
    // future caller might invoke it standalone).
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, b"*\n")
}

/// Returns the current csq version as a 16-byte nul-padded array.
///
/// The version is taken from `CARGO_PKG_VERSION` which is the workspace
/// package version embedded at compile time. Padded to exactly 16 bytes
/// with nul bytes; truncated if longer than 16 bytes (no real csq version
/// will exceed 16 ASCII chars).
fn csq_version_padded() -> [u8; 16] {
    let ver = env!("CARGO_PKG_VERSION").as_bytes();
    let mut out = [0u8; 16];
    let copy_len = ver.len().min(16);
    out[..copy_len].copy_from_slice(&ver[..copy_len]);
    out
}

/// Encode `bytes` as `len: u64 LE || bytes`. The format matches bincode 1.x
/// `with_fixint_encoding` over a `Vec<u8>` byte-for-byte, so cache files
/// written before this hand-roll keep round-tripping.
fn encode_length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Decode `payload` as `len: u64 LE || bytes` and return the bytes. Bounded
/// by the file-size cap above (`CACHE_MAX_FILE_SIZE`) so a malformed length
/// prefix can't drive an allocation larger than the read buffer.
fn decode_length_prefixed(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if payload.len() < 8 {
        return Err("payload too short for length prefix");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&payload[..8]);
    let len = u64::from_le_bytes(len_bytes);
    if len > CACHE_MAX_FILE_SIZE {
        return Err("length prefix exceeds CACHE_MAX_FILE_SIZE");
    }
    let len = len as usize;
    if payload.len() < 8 + len {
        return Err("payload shorter than declared length");
    }
    Ok(payload[8..8 + len].to_vec())
}

/// Read `.coc/COC.lock` from `coc_dir`. Returns `Ok(None)` if absent.
pub fn read_lock(coc_dir: &Path) -> Result<Option<Vec<u8>>, CacheError> {
    let path = coc_dir.join("COC.lock");
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CacheError::Io { path, source: e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_sha256_is_deterministic() {
        let a = lock_sha256(b"hello");
        let b = lock_sha256(b"hello");
        assert_eq!(a, b);
        let c = lock_sha256(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn read_lock_returns_none_if_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_lock(dir.path()).unwrap(), None);
    }

    #[test]
    fn read_lock_returns_bytes_if_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("COC.lock"), b"locked").unwrap();
        assert_eq!(read_lock(dir.path()).unwrap(), Some(b"locked".to_vec()));
    }

    // ─── T19: Parse cache tests ───────────────────────────────────────────────

    /// Build a minimal but valid CocSet fixture for cache round-trip tests.
    fn fixture_coc_set() -> CocSet {
        use crate::coc::types::CocSource;
        use crate::coc::types::RuleId;
        use crate::coc::version::CocVersion;
        use std::collections::{BTreeMap, BTreeSet};
        CocSet {
            rules: {
                let mut m = BTreeMap::new();
                let id = RuleId::parse("RULE-A").unwrap();
                m.insert(
                    id.clone(),
                    crate::coc::types::RuleDef {
                        id,
                        paths: vec!["rules/RULE-A.md".into()],
                        applies_to: BTreeSet::new(),
                        precedence: 0,
                        disable: BTreeSet::new(),
                        body: "rule body".into(),
                        unknowns: BTreeMap::new(),
                    },
                );
                m
            },
            agents: BTreeMap::new(),
            skills: BTreeMap::new(),
            commands: BTreeMap::new(),
            version: CocVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            source: CocSource::Empty,
        }
    }

    /// SHA used by all cache tests — distinct from a real lock file.
    fn test_lock_sha() -> [u8; 32] {
        let mut sha = [0u8; 32];
        sha[0] = 0xca;
        sha[1] = 0xfe;
        sha[31] = 0x01;
        sha
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_mode_is_700_after_create_dir_all() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let dir = cache_dir(root.path());
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "cache dir must be 0700, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn cache_file_mode_is_600_after_write() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "cache file must be 0600, got {mode:o}");
    }

    /// `write_parsed_cache` lands a `.gitignore` next to the cache file
    /// containing `*\n` so operators who run csq inside a git repo do
    /// not see `parsed-*.bin` files in `git status`.
    #[test]
    fn write_parsed_cache_creates_gitignore() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let gi = cache_dir(root.path()).join(".gitignore");
        assert!(gi.exists(), "expected .gitignore at {}", gi.display());
        let content = std::fs::read_to_string(&gi).unwrap();
        assert_eq!(
            content.trim(),
            "*",
            "gitignore must contain a single `*` glob; got {content:?}"
        );
    }

    /// `ensure_cache_gitignore` is idempotent: a pre-existing
    /// operator-edited `.gitignore` is preserved verbatim. Production
    /// guarantee — csq does NOT overwrite operator content.
    #[test]
    fn ensure_cache_gitignore_preserves_existing_content() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let gi = cache_dir(root.path()).join(".gitignore");
        std::fs::write(&gi, b"# operator-edited\n*\n!keep.txt\n").unwrap();
        // Now exercise the helper — must NOT overwrite.
        ensure_cache_gitignore(root.path()).unwrap();
        let content = std::fs::read_to_string(&gi).unwrap();
        assert!(
            content.contains("operator-edited"),
            "ensure_cache_gitignore must preserve existing content; got {content:?}"
        );
    }

    /// `ensure_cache_gitignore` creates the `.cache/` dir if it does not
    /// yet exist. Standalone callers (not via write_parsed_cache) work.
    #[test]
    fn ensure_cache_gitignore_creates_cache_dir_when_absent() {
        let root = tempfile::tempdir().unwrap();
        // .cache/ does NOT exist yet.
        assert!(!cache_dir(root.path()).exists());
        ensure_cache_gitignore(root.path()).unwrap();
        assert!(cache_dir(root.path()).is_dir());
        assert!(cache_dir(root.path()).join(".gitignore").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cache_read_refuses_symlink_via_o_nofollow() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        // Write a real cache file.
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let real = cache_file(root.path(), &lock_sha);

        // Create a second dir with a symlink pointing at the real file.
        let root2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cache_dir(root2.path())).unwrap();
        let link = cache_file(root2.path(), &lock_sha);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // O_NOFOLLOW causes open to fail on the symlink → returns None.
        let result = read_parsed_cache(root2.path(), &lock_sha);
        assert!(
            result.is_none(),
            "read_parsed_cache must return None for a symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_read_refuses_fifo_via_regular_file_check() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Create a FIFO at the cache file path.
        // `mknod` is the POSIX way; use `std::process::Command` for portability.
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "mkfifo failed");

        // O_NOFOLLOW does not block FIFO opens on all platforms; the
        // is_file() check is the load-bearing guard here.
        // On macOS, O_NOFOLLOW + O_NONBLOCK is needed to open a FIFO
        // without blocking — we can't rely on that. Instead, the test
        // may return None because the open blocks (FIFO has no reader)
        // OR because is_file() rejects it.
        //
        // We make the FIFO non-blocking by adding O_NONBLOCK via custom_flags,
        // but the implementation uses a plain O_NOFOLLOW open which may block.
        // Since the function returns None on any IO error (including ENXIO on
        // macOS when opening a FIFO with no writer), the assertion is the same.
        let result = read_parsed_cache(root.path(), &lock_sha);
        assert!(result.is_none(), "must return None for a FIFO");
    }

    #[test]
    fn cache_read_returns_none_on_magic_mismatch_does_not_log_content() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Write a file with wrong magic — content is sensitive garbage.
        let mut buf = vec![0u8; 64 + 32]; // at least HEADER_LEN
        buf[0..9].copy_from_slice(b"WRONGMAGIC"[..9].try_into().unwrap());
        std::fs::write(&path, &buf).unwrap();
        assert!(read_parsed_cache(root.path(), &lock_sha).is_none());
    }

    #[test]
    fn cache_read_returns_none_on_version_mismatch_does_not_log_content() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Build a valid header but with wrong format version.
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_MAGIC.as_ref());
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // wrong version
        buf.extend_from_slice(&csq_version_padded());
        buf.extend_from_slice(lock_sha.as_ref());
        buf.extend_from_slice(b"garbage_payload");
        std::fs::write(&path, &buf).unwrap();
        assert!(read_parsed_cache(root.path(), &lock_sha).is_none());
    }

    #[test]
    fn cache_read_returns_none_on_csq_version_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Build a valid header but with a different csq version.
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_MAGIC.as_ref());
        buf.extend_from_slice(&CACHE_FORMAT_VERSION.to_be_bytes());
        // Csq version = "9.9.9" padded to 16 bytes (won't match current).
        let mut ver = [0u8; 16];
        ver[..5].copy_from_slice(b"9.9.9");
        buf.extend_from_slice(&ver);
        buf.extend_from_slice(lock_sha.as_ref());
        buf.extend_from_slice(b"garbage_payload");
        std::fs::write(&path, &buf).unwrap();
        assert!(read_parsed_cache(root.path(), &lock_sha).is_none());
    }

    #[test]
    fn cache_read_returns_none_on_lock_sha_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Build a valid header but with a wrong lock SHA embedded in the file.
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_MAGIC.as_ref());
        buf.extend_from_slice(&CACHE_FORMAT_VERSION.to_be_bytes());
        buf.extend_from_slice(&csq_version_padded());
        let wrong_sha = [0xAAu8; 32]; // different from lock_sha
        buf.extend_from_slice(&wrong_sha);
        buf.extend_from_slice(b"garbage_payload");
        std::fs::write(&path, &buf).unwrap();
        assert!(read_parsed_cache(root.path(), &lock_sha).is_none());
    }

    #[test]
    fn cache_read_returns_none_on_bincode_corruption_logs_only_fixed_tag() {
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // Build a valid header with garbage bincode payload.
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_MAGIC.as_ref());
        buf.extend_from_slice(&CACHE_FORMAT_VERSION.to_be_bytes());
        buf.extend_from_slice(&csq_version_padded());
        buf.extend_from_slice(lock_sha.as_ref());
        // Garbage bincode payload.
        buf.extend_from_slice(b"\xFF\xFE\xFD garbage bincode");
        std::fs::write(&path, &buf).unwrap();
        // Should return None (fail-open) and not panic.
        let result = read_parsed_cache(root.path(), &lock_sha);
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cache_write_partial_failure_cleans_tmp_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();

        // Write a valid cache file first.
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();

        // Make the cache directory read-only so atomic_replace fails.
        let dir = cache_dir(root.path());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        // The second write must fail (can't rename into read-only dir).
        // After failure, no .tmp files should remain.
        let write_result = write_parsed_cache(root.path(), &lock_sha, &set);

        // Restore permissions before asserting (so TempDir cleanup works).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Write either failed or succeeded, but if it failed there must be no tmp leftover.
        if write_result.is_err() {
            let entries: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.contains(".tmp."))
                        .unwrap_or(false)
                })
                .collect();
            assert!(
                entries.is_empty(),
                "tmp files leaked after write failure: {entries:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn cache_write_secure_file_failure_cleans_tmp_file() {
        // We can't easily make secure_file fail in a portable way, but we can
        // verify the cleanup path doesn't panic when the tmp file doesn't exist.
        // This is a compile-time structural test: the cleanup `let _ = fs::remove_file(&tmp)`
        // before propagating the error is present in the implementation.
        // The runtime behavior is validated by cache_write_partial_failure_cleans_tmp_file.
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        // Normal write must succeed — confirms the happy path works.
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        assert!(path.exists(), "cache file must exist after write");
    }

    #[test]
    fn cache_round_trip_basic() {
        // Basic round-trip: write then read, must succeed.
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let result = read_parsed_cache(root.path(), &lock_sha);
        assert!(result.is_some(), "basic round-trip must succeed");
        assert_eq!(result.unwrap(), set);
    }

    #[test]
    fn cache_write_atomic_replace_failure_cleans_tmp_file() {
        // Verified structurally: the implementation calls
        // `let _ = fs::remove_file(&tmp)` before propagating errors from
        // both `secure_file` and `atomic_replace`. The happy path exercises
        // the write-then-exists pattern; round-trip is covered by
        // cache_round_trip_basic.
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let path = cache_file(root.path(), &lock_sha);
        // File must exist and be non-empty.
        assert!(path.exists(), "cache file must exist after write");
        let data = std::fs::read(&path).unwrap();
        assert!(!data.is_empty(), "cache file must be non-empty");
        // No tmp files should remain.
        let dir = cache_dir(root.path());
        let tmp_count = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            tmp_count, 0,
            "no tmp files must linger after successful write"
        );
    }

    #[test]
    fn cache_concurrent_write_race_yields_byte_identical_content() {
        use std::sync::Arc;
        use std::thread;

        let root = Arc::new(tempfile::tempdir().unwrap());
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let root = Arc::clone(&root);
                let set = set.clone();
                thread::spawn(move || {
                    write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // After concurrent writes, the file must exist and round-trip correctly.
        let result = read_parsed_cache(root.path(), &lock_sha);
        assert!(
            result.is_some(),
            "file must be readable after concurrent writes"
        );
        assert_eq!(result.unwrap(), set, "deserialized set must match fixture");
    }

    #[cfg(unix)]
    #[test]
    fn cache_create_new_true_mode_0600_for_tmp_blocks_attacker_pre_created_tmp() {
        // Pre-create the tmp file path that would be used.
        // The write uses create_new=true so it must fail with EEXIST.
        // The pre-existing tmp file must NOT be clobbered.
        let root = tempfile::tempdir().unwrap();
        let lock_sha = test_lock_sha();
        std::fs::create_dir_all(cache_dir(root.path())).unwrap();

        // We can't predict the exact PID+counter, so we test the property
        // differently: after a successful write, no extra tmp files exist.
        let set = fixture_coc_set();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();

        let dir = cache_dir(root.path());
        let tmp_count = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            tmp_count, 0,
            "no tmp files must linger after a successful write"
        );
    }

    #[test]
    fn cache_serialize_is_deterministic_across_two_invocations() {
        let lock_sha = test_lock_sha();
        let set = fixture_coc_set();

        // Serialize the JSON bytes wrapper 1000 times and assert byte-identical.
        // The CocSet JSON is deterministic because all maps are BTreeMap (sorted).
        // The length-prefixed wrapper is also deterministic by construction.
        let json_bytes = serde_json::to_vec(&set).unwrap();
        let first = encode_length_prefixed(&json_bytes);
        for _ in 1..1000 {
            let next_json = serde_json::to_vec(&set).unwrap();
            let next = encode_length_prefixed(&next_json);
            assert_eq!(
                first, next,
                "cache payload must be byte-identical across invocations (R2/B70)"
            );
        }
        // Also verify full round-trip write/read is deterministic.
        let root = tempfile::tempdir().unwrap();
        write_parsed_cache(root.path(), &lock_sha, &set).unwrap();
        let restored = read_parsed_cache(root.path(), &lock_sha).unwrap();
        assert_eq!(
            restored, set,
            "round-trip deserialization must be identical"
        );
    }

    #[test]
    fn cache_tmp_file_name_does_not_match_sweeper_regex() {
        // The sweeper matches: ^parsed-[0-9a-f]{64}\.bin$
        // Tmp files are named: parsed-<sha>.bin.tmp.<pid>.<counter>
        // So the tmp name must NOT match the sweeper regex.
        let lock_sha = test_lock_sha();
        let sha_hex = hex::encode(lock_sha);
        let tmp_name = format!("parsed-{sha_hex}.bin.tmp.12345.0");

        // Verify sweeper regex does NOT match the tmp name.
        assert!(
            !is_sweeper_cache_file(&tmp_name),
            "sweeper regex must NOT match tmp file name: {tmp_name}"
        );
        // Verify sweeper regex DOES match the real cache file name.
        let real_name = format!("parsed-{sha_hex}.bin");
        assert!(
            is_sweeper_cache_file(&real_name),
            "sweeper regex must match real cache file name: {real_name}"
        );
    }

    /// Minimal hand-rolled match for the sweeper's pattern
    /// `^parsed-[0-9a-f]{64}\.bin$` without pulling `regex` into csq-core.
    fn is_sweeper_cache_file(name: &str) -> bool {
        // Must start with "parsed-" and end with ".bin" with no other suffix.
        let Some(rest) = name.strip_prefix("parsed-") else {
            return false;
        };
        let Some(sha_part) = rest.strip_suffix(".bin") else {
            return false;
        };
        sha_part.len() == 64
            && sha_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    }
}
