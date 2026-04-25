//! Gemini slot provisioning — `csq setkey gemini` writes a binding
//! marker file that csq-cli's `run` and the daemon's IPC handler use
//! to authoritatively detect a Gemini-bound slot.
//!
//! # Why a separate marker file
//!
//! Three other surfaces use the same shape:
//!
//! - ClaudeCode → `credentials/<N>.json`
//! - Codex → `credentials/codex-<N>.json`
//! - Gemini → `credentials/gemini-<N>.json` (this file)
//!
//! `canonical_path_for(base_dir, slot, Surface::Gemini)` (PR-G1)
//! already returns this path; PR-G4a finally writes content there.
//!
//! Unlike Anthropic and Codex, the Gemini binding marker carries
//! **no secret material** — the API key lives in the `platform::secret`
//! vault, the Vertex SA JSON lives at the path the operator points
//! us at. The marker is metadata: how to authenticate (API key vs
//! Vertex SA), where to find the Vertex SA file (if applicable), and
//! the model the slot was provisioned with.
//!
//! # Why not the Vault as the dispatch signal
//!
//! [`csq run`] dispatches on a filesystem stat — exactly one
//! `symlink_metadata` syscall per launch. Routing dispatch through
//! the vault would add a Keychain prompt latency budget on every
//! `csq run`, and would force the daemon's IPC slot-existence check
//! (PR-G3 H2 resolution) to read the vault on every event POST.
//! Cheap stat-only dispatch is the right cost shape.
//!
//! # Atomicity
//!
//! The marker is written via `unique_tmp_path → secure_file →
//! atomic_replace` — same pipeline as every other credential write
//! per `rules/security.md` §4 + §5a. Partial failures clean up the
//! tmp file before propagating the error so the umask-default tmp
//! does not linger on disk (PR-G3 redteam B2 pattern).
//!
//! [`csq run`]: https://github.com/terrene-foundation/csq/blob/main/csq-cli/src/commands/run.rs

use crate::credentials::file::canonical_path_for;
use crate::error::PlatformError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::platform::secret::SecretError;
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version for the binding marker file. Bump on any
/// non-backward-compatible field change so the reader can refuse
/// older clients gracefully.
pub const BINDING_SCHEMA_VERSION: u32 = 1;

/// How a Gemini slot authenticates. The two modes are mutually
/// exclusive — a slot is either AI Studio API key (cleartext kept in
/// the vault) or Vertex AI service account (JSON file at a path the
/// operator owns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AuthMode {
    /// AI Studio API key. The key itself is in the platform-native
    /// secret vault under `SlotKey { surface: Gemini, account: N }`;
    /// the marker carries no key material.
    ApiKey,
    /// Vertex AI service account JSON. The marker carries the
    /// absolute path the operator pointed `--vertex-sa-json` at;
    /// `spawn_gemini` sets `GOOGLE_APPLICATION_CREDENTIALS` to this
    /// path on exec.
    VertexSa {
        /// Absolute path to the Vertex SA JSON. Caller validates
        /// `is_file()` + `0o400`-or-stricter at provisioning time.
        path: PathBuf,
    },
}

/// Persisted contents of `credentials/gemini-<N>.json`. JSON shape:
///
/// ```json
/// {
///   "v": 1,
///   "auth": { "mode": "api_key" },
///   "model_name": "auto",
///   "created_unix_secs": 1714000000
/// }
/// ```
///
/// or, for Vertex SA:
///
/// ```json
/// {
///   "v": 1,
///   "auth": { "mode": "vertex_sa", "path": "/abs/path/sa.json" },
///   "model_name": "auto",
///   "created_unix_secs": 1714000000
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeminiBinding {
    /// Schema version. Reader refuses unknown values.
    pub v: u32,
    /// API-key vs Vertex SA mode + Vertex path when applicable.
    #[serde(rename = "auth")]
    pub auth: AuthMode,
    /// Operator-selected model alias or concrete id (`auto`,
    /// `gemini-2.5-pro`, etc). `csq models switch` rewrites this
    /// field. The seed `settings.json` mirrors the same value so
    /// gemini-cli sees it.
    pub model_name: String,
    /// Provisioning timestamp — unix seconds. Diagnostic only;
    /// nothing in csq compares against it.
    pub created_unix_secs: u64,
}

impl GeminiBinding {
    /// Builds a fresh binding with `created_unix_secs` set to the
    /// current wall clock. Used by both provisioning paths.
    pub fn new(auth: AuthMode, model_name: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            v: BINDING_SCHEMA_VERSION,
            auth,
            model_name: model_name.into(),
            created_unix_secs: now,
        }
    }
}

/// Errors raised by provisioning operations. Distinct from
/// [`SecretError`] so callers can map provisioning-IO failures
/// (e.g. credentials dir missing) separately from vault failures.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Filesystem error writing or reading the marker.
    #[error("provisioning I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Atomic-replace primitive failed.
    #[error("atomic replace at {path}: {reason}")]
    AtomicReplace { path: PathBuf, reason: String },
    /// Vault operation failed during API-key provisioning.
    #[error(transparent)]
    Vault(#[from] SecretError),
    /// Marker JSON is malformed or refers to an unknown schema
    /// version. Caller treats the slot as unbound.
    #[error("malformed marker at {path}: {reason}")]
    Malformed { path: PathBuf, reason: String },
    /// Vertex SA JSON path is missing or not a regular file.
    #[error("vertex SA file invalid at {path}: {reason}")]
    VertexSaInvalid { path: PathBuf, reason: String },
}

impl ProvisionError {
    /// Fixed-vocabulary tag for structured logging. Mirrors
    /// [`SecretError::error_kind_tag`] discipline.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            ProvisionError::Io { .. } => "gemini_provision_io",
            ProvisionError::AtomicReplace { .. } => "gemini_provision_atomic_replace",
            ProvisionError::Vault(e) => e.error_kind_tag(),
            ProvisionError::Malformed { .. } => "gemini_provision_malformed",
            ProvisionError::VertexSaInvalid { .. } => "gemini_provision_vertex_sa_invalid",
        }
    }
}

impl From<PlatformError> for ProvisionError {
    fn from(value: PlatformError) -> Self {
        ProvisionError::AtomicReplace {
            path: PathBuf::new(),
            reason: value.to_string(),
        }
    }
}

/// Returns the marker path for a given slot. Thin wrapper over
/// [`canonical_path_for`] that pins the `Surface::Gemini` argument
/// so callers do not have to import the enum.
pub fn binding_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    canonical_path_for(base_dir, slot, Surface::Gemini)
}

/// Whether `slot` has a Gemini binding marker. Single
/// `symlink_metadata` syscall — no JSON parse, no vault touch.
/// Treats a dangling symlink at the marker path as "bound" (same
/// posture as `is_codex_bound_slot` per FR-CLI-05 / journal 0013).
pub fn is_gemini_bound_slot(base_dir: &Path, slot: AccountNum) -> bool {
    std::fs::symlink_metadata(binding_path(base_dir, slot)).is_ok()
}

/// Reads and parses the binding marker. Returns
/// [`ProvisionError::Io`] with `NotFound` when the marker is absent
/// (caller should match on the source kind to distinguish unbound
/// from corrupted).
pub fn read_binding(base_dir: &Path, slot: AccountNum) -> Result<GeminiBinding, ProvisionError> {
    let path = binding_path(base_dir, slot);
    let raw = std::fs::read_to_string(&path).map_err(|source| ProvisionError::Io {
        path: path.clone(),
        source,
    })?;
    let binding: GeminiBinding =
        serde_json::from_str(&raw).map_err(|e| ProvisionError::Malformed {
            path: path.clone(),
            reason: format!("json parse: {e}"),
        })?;
    if binding.v != BINDING_SCHEMA_VERSION {
        return Err(ProvisionError::Malformed {
            path,
            reason: format!(
                "unknown schema version {} (expected {})",
                binding.v, BINDING_SCHEMA_VERSION
            ),
        });
    }
    Ok(binding)
}

/// Writes the binding marker atomically with 0o600 permissions.
/// Caller is responsible for vault writes (API-key mode) or path
/// validation (Vertex SA mode); this helper is purely the marker
/// write.
pub fn write_binding(
    base_dir: &Path,
    slot: AccountNum,
    binding: &GeminiBinding,
) -> Result<(), ProvisionError> {
    let path = binding_path(base_dir, slot);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ProvisionError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let json =
        serde_json::to_string_pretty(binding).map_err(|e| ProvisionError::AtomicReplace {
            path: path.clone(),
            reason: format!("serialize: {e}"),
        })?;

    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::AtomicReplace {
            path: path.clone(),
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::AtomicReplace {
            path,
            reason: format!("atomic replace: {e}"),
        });
    }
    Ok(())
}

/// Validates a Vertex SA JSON path before provisioning. Refuses
/// non-existent paths, non-regular files, and files larger than 64
/// KiB (real Vertex SA JSON is ~2 KiB; anything larger is suspect).
/// Does NOT parse the JSON — gemini-cli does that on first call.
pub fn validate_vertex_sa_path(path: &Path) -> Result<PathBuf, ProvisionError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|source| ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: format!("stat: {source}"),
        })?;
    if !meta.file_type().is_file() {
        return Err(ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: "not a regular file (symlinks rejected to prevent confused-deputy)".into(),
        });
    }
    if meta.len() > 64 * 1024 {
        return Err(ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: format!("file too large ({} bytes; expected <= 64 KiB)", meta.len()),
        });
    }
    // Canonicalise to an absolute path so a future relative-path
    // CWD change cannot reroute the resolution.
    let abs = std::fs::canonicalize(path).map_err(|source| ProvisionError::VertexSaInvalid {
        path: path.to_path_buf(),
        reason: format!("canonicalize: {source}"),
    })?;
    Ok(abs)
}

/// Removes the binding marker. Does NOT touch the vault entry —
/// callers that want a full unbind invoke `Vault::delete` separately
/// so the audit log emits both events distinctly.
pub fn unbind(base_dir: &Path, slot: AccountNum) -> Result<(), ProvisionError> {
    let path = binding_path(base_dir, slot);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProvisionError::Io { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn binding_path_is_credentials_gemini_n_json() {
        let dir = TempDir::new().unwrap();
        let path = binding_path(dir.path(), slot(3));
        assert_eq!(path, dir.path().join("credentials/gemini-3.json"));
    }

    #[test]
    fn write_then_read_round_trip_api_key_mode() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-pro");
        write_binding(dir.path(), slot(7), &binding).unwrap();

        let read = read_binding(dir.path(), slot(7)).unwrap();
        assert_eq!(read.v, BINDING_SCHEMA_VERSION);
        assert_eq!(read.auth, AuthMode::ApiKey);
        assert_eq!(read.model_name, "gemini-2.5-pro");
        assert_eq!(read.created_unix_secs, binding.created_unix_secs);
    }

    #[test]
    fn write_then_read_round_trip_vertex_mode() {
        let dir = TempDir::new().unwrap();
        let sa_path = PathBuf::from("/abs/path/sa.json");
        let binding = GeminiBinding::new(
            AuthMode::VertexSa {
                path: sa_path.clone(),
            },
            "auto",
        );
        write_binding(dir.path(), slot(2), &binding).unwrap();

        let read = read_binding(dir.path(), slot(2)).unwrap();
        match read.auth {
            AuthMode::VertexSa { path } => assert_eq!(path, sa_path),
            other => panic!("expected VertexSa, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn marker_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(4), &binding).unwrap();
        let perms = std::fs::metadata(binding_path(dir.path(), slot(4)))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "marker must be 0o600");
    }

    #[test]
    fn is_gemini_bound_slot_returns_false_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!is_gemini_bound_slot(dir.path(), slot(5)));
    }

    #[test]
    fn is_gemini_bound_slot_returns_true_after_write() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(5), &binding).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(5)));
    }

    #[cfg(unix)]
    #[test]
    fn is_gemini_bound_slot_treats_dangling_symlink_as_bound() {
        // Same posture as `is_codex_bound_slot` (FR-CLI-05): a
        // dangling symlink at the canonical path is still "bound" —
        // refuse to silently re-provision over what may be a
        // user-recoverable broken link.
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        symlink(dir.path().join("nowhere.json"), creds.join("gemini-9.json")).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(9)));
    }

    #[test]
    fn read_binding_returns_io_not_found_when_absent() {
        let dir = TempDir::new().unwrap();
        let err = read_binding(dir.path(), slot(6)).unwrap_err();
        match err {
            ProvisionError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io NotFound, got {other:?}"),
        }
    }

    #[test]
    fn read_binding_rejects_unknown_schema_version() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let raw = serde_json::json!({
            "v": 999,
            "auth": { "mode": "api_key" },
            "model_name": "auto",
            "created_unix_secs": 0_u64,
        });
        std::fs::write(creds.join("gemini-1.json"), raw.to_string()).unwrap();

        let err = read_binding(dir.path(), slot(1)).unwrap_err();
        assert!(matches!(err, ProvisionError::Malformed { .. }));
        assert_eq!(err.error_kind_tag(), "gemini_provision_malformed");
    }

    #[test]
    fn read_binding_rejects_garbage_json() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-1.json"), "{ this is not json").unwrap();
        let err = read_binding(dir.path(), slot(1)).unwrap_err();
        assert!(matches!(err, ProvisionError::Malformed { .. }));
    }

    #[test]
    fn unbind_is_idempotent_when_absent() {
        let dir = TempDir::new().unwrap();
        unbind(dir.path(), slot(8)).unwrap();
        unbind(dir.path(), slot(8)).unwrap();
    }

    #[test]
    fn unbind_removes_marker_when_present() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(8), &binding).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(8)));
        unbind(dir.path(), slot(8)).unwrap();
        assert!(!is_gemini_bound_slot(dir.path(), slot(8)));
    }

    #[test]
    fn validate_vertex_sa_rejects_missing_path() {
        let err = validate_vertex_sa_path(Path::new("/this/does/not/exist.json")).unwrap_err();
        assert!(matches!(err, ProvisionError::VertexSaInvalid { .. }));
    }

    #[test]
    fn validate_vertex_sa_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let err = validate_vertex_sa_path(dir.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::VertexSaInvalid { .. }));
    }

    #[test]
    fn validate_vertex_sa_rejects_oversized_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("sa.json");
        // Just over 64 KiB.
        std::fs::write(&p, vec![b'{'; 64 * 1024 + 1]).unwrap();
        let err = validate_vertex_sa_path(&p).unwrap_err();
        match err {
            ProvisionError::VertexSaInvalid { reason, .. } => {
                assert!(reason.contains("too large"), "got: {reason}");
            }
            other => panic!("expected VertexSaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_vertex_sa_returns_canonical_path() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("sa.json");
        std::fs::write(&p, br#"{"type":"service_account"}"#).unwrap();
        let canon = validate_vertex_sa_path(&p).unwrap();
        assert!(canon.is_absolute());
        // canonicalize resolves via the platform — assert that the
        // result points back at the same file rather than asserting
        // a literal path (TempDir on macOS goes via `/private/var`).
        assert_eq!(
            std::fs::canonicalize(&p).unwrap(),
            std::fs::canonicalize(&canon).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_vertex_sa_rejects_symlink_to_real_file() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, br#"{"type":"service_account"}"#).unwrap();
        let link = dir.path().join("link.json");
        symlink(&real, &link).unwrap();
        let err = validate_vertex_sa_path(&link).unwrap_err();
        match err {
            ProvisionError::VertexSaInvalid { reason, .. } => {
                assert!(reason.contains("symlink") || reason.contains("regular file"));
            }
            other => panic!("expected VertexSaInvalid, got {other:?}"),
        }
    }
}
