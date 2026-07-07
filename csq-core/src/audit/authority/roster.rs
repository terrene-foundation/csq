//! M12 — Signed authority roster on-disk representation + `RosterFileRegistry`.
//!
//! # On-disk formats
//!
//! ## Embedded form (primary)
//!
//! `<base>/audit/authority-roster.json`:
//!
//! ```json
//! {
//!   "roster": {
//!     "format_version": 1,
//!     "roster_version": 42,
//!     "generated_at": "2026-06-02T12:00:00+00:00",
//!     "entries": {
//!       "alice@example.com": {
//!         "keys": [...],
//!         "op_classes": ["key_rotate", "release_auth"]
//!       }
//!     }
//!   },
//!   "roster_pubkey": "<hex 32B org-root pubkey>",
//!   "signature": "<hex 64B Ed25519 sig over canonical roster bytes>"
//! }
//! ```
//!
//! ## Detached form (alternative for cross-language signers; §12.16.6)
//!
//! Roster file (`<base>/audit/authority-roster.json`) — no `signature` field:
//!
//! ```json
//! {
//!   "roster": { ... },
//!   "roster_pubkey": "<hex 32B org-root pubkey>"
//! }
//! ```
//!
//! Sidecar (`<base>/audit/authority-roster.json.sig`): 128 hex chars (64 bytes)
//! — Ed25519 signature over the RAW stored bytes of the roster file.
//!
//! # Resolution order (in `RosterFileRegistry::load`)
//!
//! 1. Embedded `signature` field present → embedded path (primary). Sidecar
//!    is IGNORED and a fixed-tag `tracing::warn!` is emitted.
//! 2. No embedded signature AND sidecar exists → detached verification over
//!    raw file bytes.
//! 3. Neither → `RosterCorrupt` (fixed-vocabulary message).
//!
//! # Root-of-trust resolution
//!
//! Priority (highest to lowest):
//! 1. `CSQ_AUDIT_ROSTER_ROOT_PUBKEY` env var — hex-encoded 32 bytes.
//! 2. `<base>/audit/roster-root.pub` — binary 32-byte file at mode 0o600.
//!
//! Missing both → `AuthorityError::RootPubkeyMissing` (fail closed).
//!
//! # Rollback defense
//!
//! `roster.roster_version` MUST be >= `chain.json::roster_version_floor`.
//! The floor is set when the roster is installed (`csq audit roster install`).
//! Below-floor → `AuthorityError::RosterRollback` (fail closed).
//!
//! # §5a write path
//!
//! `save_roster` uses `unique_tmp_path → write → secure_file → atomic_replace`
//! with `remove_file(&tmp)` on every failure branch (per `rules/security.md §5a`).
//! `save_detached_roster` uses the same pattern for BOTH files (roster + sidecar),
//! with byte-preserving writes (no re-serialization — the sidecar covers raw bytes).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::audit::types::{Ed25519PublicKey, Ed25519Signature};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

use super::error::AuthorityError;
use super::grant::{AuthorityGrant, EnrolledKey, PactDefinition};
use super::op_class::OpClass;
use super::registry::AuthorityRegistry;

// ---------------------------------------------------------------------------
// On-disk types
// ---------------------------------------------------------------------------

/// A single roster entry: one principal's keys and op-class grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterEntry {
    /// The enrolled keys for this principal (validity windows).
    pub keys: Vec<EnrolledKey>,
    /// The op classes this principal is enrolled for.
    pub op_classes: Vec<OpClass>,
}

/// The inner (unsigned) roster.
///
/// `#[serde(deny_unknown_fields)]` — the roster is a tamper-evident
/// signed artifact. Unknown fields → parse failure → `RosterCorrupt`.
/// Mirrors `SeedEntryPayload`'s deny_unknown_fields precedent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    /// Schema version for future migrations. Currently 1.
    pub format_version: u32,
    /// Monotonically increasing roster version (rollback defense).
    pub roster_version: u64,
    /// ISO-8601 timestamp of roster generation.
    pub generated_at: String,
    /// Principal → entry map. `BTreeMap` for deterministic serialization
    /// (canonical bytes for Ed25519 signature verification).
    pub entries: BTreeMap<String, RosterEntry>,
}

/// The signed roster: roster bytes + org-root pubkey + signature.
///
/// `signature` is an Ed25519 signature over the **canonical bytes** of `roster`
/// (i.e. `serde_json::to_vec(&roster)` — deterministic because `Roster` uses
/// `BTreeMap` for `entries` and derives `Serialize` with fixed field order).
///
/// `#[serde(deny_unknown_fields)]` — same tamper-evidence policy as `Roster`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRoster {
    /// The signed roster payload.
    pub roster: Roster,
    /// The 32-byte org-root Ed25519 public key (hex-encoded).
    #[serde(serialize_with = "ser_pubkey", deserialize_with = "de_pubkey")]
    pub roster_pubkey: Ed25519PublicKey,
    /// The 64-byte Ed25519 signature over the canonical roster bytes.
    #[serde(serialize_with = "ser_signature", deserialize_with = "de_signature")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// The unsigned roster file — used by the detached-signature path.
///
/// Contains `roster` and `roster_pubkey` but NO `signature` field.
/// `deny_unknown_fields` ensures a stale `signature` field in the JSON (if a
/// caller accidentally tries to parse an embedded roster as unsigned) causes a
/// parse failure rather than silent success with an ignored `signature`.
///
/// The detached sidecar (`<roster-file>.sig`) covers the RAW bytes of the
/// serialized form of this struct as stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedRosterFile {
    /// The signed roster payload (format gate, version, entries).
    pub roster: Roster,
    /// The 32-byte org-root Ed25519 public key (hex-encoded).
    #[serde(serialize_with = "ser_pubkey", deserialize_with = "de_pubkey")]
    pub roster_pubkey: Ed25519PublicKey,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Path to `authority-roster.json`.
pub fn roster_path(base: &Path) -> PathBuf {
    base.join("audit").join("authority-roster.json")
}

/// Path to `authority-roster.json.sig` (detached-signature sidecar).
pub fn roster_sig_path(base: &Path) -> PathBuf {
    base.join("audit").join("authority-roster.json.sig")
}

/// Path to `roster-root.pub` (fallback root pubkey file).
pub fn root_pub_path(base: &Path) -> PathBuf {
    base.join("audit").join("roster-root.pub")
}

/// The highest `format_version` this version of csq can interpret.
///
/// Rosters with `format_version > SUPPORTED_ROSTER_FORMAT_VERSION` are
/// rejected with `AuthorityError::RosterFormatTooNew` BEFORE signature
/// verification, so an unrecognized format schema never silently passes.
pub const SUPPORTED_ROSTER_FORMAT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Root-of-trust resolution
// ---------------------------------------------------------------------------

/// Resolve the org-root Ed25519 public key.
///
/// Priority (highest first):
/// 1. `CSQ_AUDIT_ROSTER_ROOT_PUBKEY` env var — 64 lowercase hex chars.
///    This is the **recommended production source** — it avoids the
///    on-disk-mode dependency and works in containerized / CI environments.
/// 2. `<base>/audit/roster-root.pub` — 32 raw bytes.
///    The file MUST be mode 0o600 (owner read/write only) on Unix.
///    If the file has group- or world-readable/writable bits set,
///    `Err(AuthorityError::RootPubkeyInsecurePermissions)` is returned.
///
/// Returns `Err(AuthorityError::RootPubkeyMissing)` if neither is available.
/// Returns `Err(AuthorityError::Io(...))` if the file cannot be read.
/// Returns `Err(AuthorityError::RosterCorrupt)` if the env/file value is malformed.
/// Returns `Err(AuthorityError::RootPubkeyInsecurePermissions)` if the file has
///   insecure permissions on Unix (mode bits other than 0o600 for the owner).
pub(crate) fn resolve_root_pubkey(base: &Path) -> Result<Ed25519PublicKey, AuthorityError> {
    // Priority 1: environment variable (recommended production source).
    if let Ok(hex_str) = std::env::var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY") {
        let bytes = hex::decode(hex_str.trim()).map_err(|_| AuthorityError::RosterCorrupt)?;
        if bytes.len() != 32 {
            return Err(AuthorityError::RosterCorrupt);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Ed25519PublicKey(arr));
    }

    // Priority 2: roster-root.pub file (32 raw bytes).
    let pub_path = root_pub_path(base);
    if pub_path.exists() {
        // HIGH-1: enforce 0o600 permissions on Unix before reading.
        // The roster-root.pub file is the on-disk root-of-trust anchor;
        // group/other read or write bits indicate misconfiguration that
        // could allow an attacker to substitute a different root pubkey.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&pub_path)
                .map_err(|_| AuthorityError::Io("stat roster-root.pub"))?;
            let mode = meta.mode() & 0o777;
            // Allow only 0o600 (owner rw, no group/other bits).
            // 0o400 (owner read-only) is also acceptable.
            if mode & 0o077 != 0 {
                tracing::warn!(
                    error_kind = "roster_root_pub_insecure_permissions",
                    mode = format!("{mode:04o}"),
                    "roster-root.pub has insecure permissions; expected 0o600 or stricter"
                );
                return Err(AuthorityError::RootPubkeyInsecurePermissions);
            }
        }
        let raw =
            std::fs::read(&pub_path).map_err(|_| AuthorityError::Io("read roster-root.pub"))?;
        if raw.len() != 32 {
            return Err(AuthorityError::RosterCorrupt);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        return Ok(Ed25519PublicKey(arr));
    }

    Err(AuthorityError::RootPubkeyMissing)
}

// ---------------------------------------------------------------------------
// In-memory roster verification (used by install path — CRIT-2)
// ---------------------------------------------------------------------------

/// Verify a `SignedRoster` that has already been parsed into memory — without
/// reading from disk. Used by the install path to verify BEFORE writing the
/// live roster file.
///
/// This is the same verification logic as `RosterFileRegistry::load` but
/// operates on an already-parsed in-memory `SignedRoster`, allowing the
/// install command to validate before overwriting the live path (CRIT-2).
///
/// # Checks (in order)
///
/// 1. `format_version <= SUPPORTED_ROSTER_FORMAT_VERSION` — unknown schema gate.
/// 2. Root pubkey resolution (env or file, with 0o600 check on Unix).
/// 3. `roster_pubkey` field matches resolved root pubkey.
/// 4. Ed25519 signature over canonical roster bytes.
/// 5. `roster_version >= version_floor`.
pub fn verify_signed_roster(
    base: &Path,
    signed: &SignedRoster,
    version_floor: u64,
) -> Result<(), AuthorityError> {
    // 1. format_version gate.
    if signed.roster.format_version > SUPPORTED_ROSTER_FORMAT_VERSION {
        tracing::warn!(
            error_kind = "roster_format_too_new",
            roster_format_version = signed.roster.format_version,
            supported_format_version = SUPPORTED_ROSTER_FORMAT_VERSION,
            "verify_signed_roster: roster format_version too new"
        );
        return Err(AuthorityError::RosterFormatTooNew(
            signed.roster.format_version,
            SUPPORTED_ROSTER_FORMAT_VERSION,
        ));
    }

    // 2. Resolve root pubkey.
    let root_pk = resolve_root_pubkey(base)?;

    // 3. Match pubkey field.
    if signed.roster_pubkey.0 != root_pk.0 {
        tracing::warn!(
            error_kind = "roster_pubkey_mismatch",
            "verify_signed_roster: roster_pubkey does not match resolved root pubkey"
        );
        return Err(AuthorityError::RosterSignatureInvalid);
    }

    // 4. Signature verification (canonicalization contract per §12.16.6).
    let roster_bytes =
        serde_json::to_vec(&signed.roster).map_err(|_| AuthorityError::RosterCorrupt)?;

    let verifying =
        VerifyingKey::from_bytes(&root_pk.0).map_err(|_| AuthorityError::RosterCorrupt)?;

    let dalek_sig = ed25519_dalek::Signature::from_bytes(&signed.signature.0);

    if verifying.verify_strict(&roster_bytes, &dalek_sig).is_err() {
        tracing::warn!(
            error_kind = "roster_signature_invalid",
            "verify_signed_roster: signature verification failed"
        );
        return Err(AuthorityError::RosterSignatureInvalid);
    }

    // 5. Rollback defense.
    if signed.roster.roster_version < version_floor {
        tracing::warn!(
            error_kind = "roster_rollback_detected",
            roster_version = signed.roster.roster_version,
            version_floor = version_floor,
            "verify_signed_roster: roster_version below installed floor"
        );
        return Err(AuthorityError::RosterRollback);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Detached-signature verification (§12.16.6 — cross-language signer path)
// ---------------------------------------------------------------------------

/// Verify a detached-signature roster: the `unsigned` form has already been
/// parsed in memory, and `raw_file_bytes` are the EXACT bytes of the roster
/// file as stored on disk. The sidecar hex string `sidecar_hex` is a 128-char
/// lowercase hex encoding of the 64-byte Ed25519 signature.
///
/// # Checks (in order, matching the embedded path per §12.16.6)
///
/// 1. `format_version <= SUPPORTED_ROSTER_FORMAT_VERSION` — unknown schema gate
///    (BEFORE signature — same ordering as the embedded path).
/// 2. Root pubkey resolution (env or file, with 0o600 check on Unix).
/// 3. `roster_pubkey` field matches resolved root pubkey.
/// 4. Ed25519 signature over `raw_file_bytes` (the stored bytes, not canonical JSON).
/// 5. `roster_version >= version_floor` (rollback defense).
///
/// Never called directly by user code — called by `RosterFileRegistry::load`
/// when the detached form is detected.
pub fn verify_detached_roster(
    base: &Path,
    unsigned: &UnsignedRosterFile,
    raw_file_bytes: &[u8],
    sidecar_hex: &str,
    version_floor: u64,
) -> Result<(), AuthorityError> {
    // 1. format_version gate (BEFORE signature — mirrors embedded path).
    if unsigned.roster.format_version > SUPPORTED_ROSTER_FORMAT_VERSION {
        tracing::warn!(
            error_kind = "roster_format_too_new",
            roster_format_version = unsigned.roster.format_version,
            supported_format_version = SUPPORTED_ROSTER_FORMAT_VERSION,
            "verify_detached_roster: roster format_version too new"
        );
        return Err(AuthorityError::RosterFormatTooNew(
            unsigned.roster.format_version,
            SUPPORTED_ROSTER_FORMAT_VERSION,
        ));
    }

    // 2. Resolve root pubkey.
    let root_pk = resolve_root_pubkey(base)?;

    // 3. Match pubkey field.
    if unsigned.roster_pubkey.0 != root_pk.0 {
        tracing::warn!(
            error_kind = "roster_pubkey_mismatch",
            "verify_detached_roster: roster_pubkey does not match resolved root pubkey"
        );
        return Err(AuthorityError::RosterSignatureInvalid);
    }

    // 4. Decode the sidecar hex and verify signature over raw file bytes.
    let sig_bytes = hex::decode(sidecar_hex.trim()).map_err(|_| {
        tracing::warn!(
            error_kind = "roster_sidecar_corrupt",
            "verify_detached_roster: sidecar is not valid hex"
        );
        AuthorityError::RosterCorrupt
    })?;
    if sig_bytes.len() != 64 {
        tracing::warn!(
            error_kind = "roster_sidecar_wrong_length",
            len = sig_bytes.len(),
            "verify_detached_roster: sidecar must be 64 bytes"
        );
        return Err(AuthorityError::RosterCorrupt);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let verifying =
        VerifyingKey::from_bytes(&root_pk.0).map_err(|_| AuthorityError::RosterCorrupt)?;

    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    if verifying.verify_strict(raw_file_bytes, &dalek_sig).is_err() {
        tracing::warn!(
            error_kind = "roster_detached_signature_invalid",
            "verify_detached_roster: signature verification failed"
        );
        return Err(AuthorityError::RosterSignatureInvalid);
    }

    // 5. Rollback defense.
    if unsigned.roster.roster_version < version_floor {
        tracing::warn!(
            error_kind = "roster_rollback_detected",
            roster_version = unsigned.roster.roster_version,
            version_floor = version_floor,
            "verify_detached_roster: roster_version below installed floor"
        );
        return Err(AuthorityError::RosterRollback);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Roster save (§5a compliant)
// ---------------------------------------------------------------------------

/// Save a `SignedRoster` to `<base>/audit/authority-roster.json`.
///
/// Uses `unique_tmp_path → write → secure_file → atomic_replace` with
/// `remove_file(&tmp)` on every failure branch (§5a).
///
/// Creates `<base>/audit/` if it does not exist.
pub fn save_roster(base: &Path, signed: &SignedRoster) -> Result<(), AuthorityError> {
    let path = roster_path(base);
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|_| AuthorityError::Io("create audit dir"))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent).map_err(|_| AuthorityError::Io("create audit dir"))?;
        }
    }

    let json =
        serde_json::to_string_pretty(signed).map_err(|_| AuthorityError::Io("serialize roster"))?;

    // §5a: unique_tmp_path → write → secure_file → atomic_replace
    // with remove_file(&tmp) on every failure branch.
    let tmp = unique_tmp_path(&path);

    if std::fs::write(&tmp, json.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuthorityError::Io("write roster tmp"));
    }

    if secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuthorityError::Io("secure_file roster tmp"));
    }

    if atomic_replace(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuthorityError::Io("atomic_replace roster"));
    }

    Ok(())
}

/// Save a detached-form roster: write `raw_roster_bytes` byte-for-byte to
/// `<base>/audit/authority-roster.json` and the hex-encoded sidecar to
/// `<base>/audit/authority-roster.json.sig`.
///
/// The sidecar covers the raw bytes; we MUST NOT re-serialize — any difference
/// in whitespace or field ordering would break the signature. Both files are
/// written via `unique_tmp_path → write → secure_file → atomic_replace` with
/// `remove_file(&tmp)` on every failure branch (§5a, per `rules/security.md`).
///
/// Creates `<base>/audit/` if it does not exist.
pub fn save_detached_roster(
    base: &Path,
    raw_roster_bytes: &[u8],
    sidecar_hex: &str,
) -> Result<(), AuthorityError> {
    let roster_p = roster_path(base);
    let sig_p = roster_sig_path(base);

    // Create the audit dir (mode 0o700 on Unix).
    if let Some(parent) = roster_p.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|_| AuthorityError::Io("create audit dir"))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent).map_err(|_| AuthorityError::Io("create audit dir"))?;
        }
    }

    // --- Write sidecar FIRST, roster file SECOND (an internal ticket review LOW-1) ---
    // A crash between the two renames must fail closed AND, where possible,
    // preserve availability. Sidecar-first means the crash window leaves the
    // OLD roster + NEW sidecar: if the old roster is embedded-form the sidecar
    // is ignored (embedded wins) and the install simply did not happen; if the
    // old roster is detached-form the stale pair fails verification (fail-
    // closed). Roster-first would instead always leave a new-roster/old-
    // sidecar pair that fails verification and bricks startup until re-install.
    // --- Write sidecar file ---
    let tmp_sig = unique_tmp_path(&sig_p);

    if std::fs::write(&tmp_sig, sidecar_hex.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp_sig);
        return Err(AuthorityError::Io("write sidecar tmp"));
    }
    if secure_file(&tmp_sig).is_err() {
        let _ = std::fs::remove_file(&tmp_sig);
        return Err(AuthorityError::Io("secure_file sidecar tmp"));
    }
    if atomic_replace(&tmp_sig, &sig_p).is_err() {
        let _ = std::fs::remove_file(&tmp_sig);
        return Err(AuthorityError::Io("atomic_replace sidecar"));
    }

    // --- Write roster file (byte-preserving — no re-serialize) ---
    let tmp_roster = unique_tmp_path(&roster_p);

    if std::fs::write(&tmp_roster, raw_roster_bytes).is_err() {
        let _ = std::fs::remove_file(&tmp_roster);
        return Err(AuthorityError::Io("write detached roster tmp"));
    }
    if secure_file(&tmp_roster).is_err() {
        let _ = std::fs::remove_file(&tmp_roster);
        return Err(AuthorityError::Io("secure_file detached roster tmp"));
    }
    if atomic_replace(&tmp_roster, &roster_p).is_err() {
        let _ = std::fs::remove_file(&tmp_roster);
        return Err(AuthorityError::Io("atomic_replace detached roster"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RosterFileRegistry
// ---------------------------------------------------------------------------

/// Registry implementation backed by a signed on-disk roster file.
///
/// Used by the enterprise edition. `load` verifies the signature, checks
/// rollback defense, and builds an internal pubkey index.
///
/// # HIGH-3 WARNING — activation_seq trap
///
/// A bare `RosterFileRegistry` used as `AuthorityRegistry` returns
/// `activation_seq() = None`, which silently disables membership enforcement
/// for ALL records. This is intentional: `RosterFileRegistry` does not
/// own the activation seq — that lives in `chain.json` and is injected
/// by `resolve_registry` which wraps this in `EnterpriseRegistry`.
///
/// **MUST NOT** use a bare `RosterFileRegistry` as an `AuthorityRegistry`
/// in production paths. Use `EnterpriseRegistry` (wrapping this) instead.
/// In tests, use a `WithActivation` wrapper or `EnterpriseRegistry` when
/// testing activation semantics.
#[derive(Debug)]
pub struct RosterFileRegistry {
    roster: Roster,
}

impl RosterFileRegistry {
    /// Load the signed (or detached-signed) roster from disk, verify it, and
    /// check rollback defense.
    ///
    /// # Resolution order
    ///
    /// 1. **Embedded** (`signature` field present in the file): parse as
    ///    `SignedRoster`, delegate all 5 checks to `verify_signed_roster`.
    ///    Any sidecar (`<file>.sig`) is IGNORED and a fixed-tag warn is emitted.
    /// 2. **Detached** (parse as `UnsignedRosterFile` succeeds AND sidecar
    ///    `<file>.sig` exists): delegate all 5 checks to
    ///    `verify_detached_roster` over the raw file bytes.
    /// 3. **Neither**: `Err(RosterCorrupt)` with fixed-vocabulary message.
    ///
    /// # Fail-closed behavior (in order of checks)
    ///
    /// - Missing file → `Err(RosterMissing)`
    /// - Parse failure (both forms fail) → `Err(RosterCorrupt)`
    /// - `format_version > SUPPORTED_ROSTER_FORMAT_VERSION` → `Err(RosterFormatTooNew)`
    ///   (BEFORE signature — same ordering on BOTH paths)
    /// - Missing root pubkey → `Err(RootPubkeyMissing)` / `Err(RootPubkeyInsecurePermissions)`
    /// - `roster_pubkey` mismatch → `Err(RosterSignatureInvalid)`
    /// - Invalid signature → `Err(RosterSignatureInvalid)`
    /// - `roster_version < roster_version_floor` → `Err(RosterRollback)`
    ///
    /// Never falls back to community edition — enterprise misconfiguration
    /// must be resolved explicitly.
    pub fn load(base: &Path, version_floor: u64) -> Result<Self, AuthorityError> {
        let path = roster_path(base);
        if !path.exists() {
            return Err(AuthorityError::RosterMissing);
        }

        // Read the raw bytes — needed for both embedded (string parse) and
        // detached (byte-exact verification over stored bytes) paths.
        let raw_bytes = std::fs::read(&path).map_err(|_| AuthorityError::Io("read roster file"))?;
        let raw_str = std::str::from_utf8(&raw_bytes).map_err(|_| AuthorityError::RosterCorrupt)?;

        // --- Path 1: try to parse as the embedded (signed) form ---
        if let Ok(signed) = serde_json::from_str::<SignedRoster>(raw_str) {
            // Embedded form detected.  Warn if a sidecar also exists.
            let sig_path = roster_sig_path(base);
            if sig_path.exists() {
                tracing::warn!(
                    error_kind = "sidecar_shadowed_by_embedded",
                    "RosterFileRegistry::load: roster has an embedded signature; \
                     sidecar (.sig) is present but IGNORED — embedded takes precedence"
                );
            }

            // Delegate all 5 checks to the single verification authority.
            verify_signed_roster(base, &signed, version_floor)?;

            return Ok(Self {
                roster: signed.roster,
            });
        }

        // --- Path 2: try to parse as the unsigned (detached) form ---
        if let Ok(unsigned) = serde_json::from_str::<UnsignedRosterFile>(raw_str) {
            let sig_path = roster_sig_path(base);
            if !sig_path.exists() {
                // No embedded signature AND no sidecar — fail closed.
                tracing::warn!(
                    error_kind = "roster_no_signature",
                    "RosterFileRegistry::load: roster has no embedded signature \
                     and no .sig sidecar — cannot verify"
                );
                return Err(AuthorityError::RosterCorrupt);
            }

            let sidecar_hex = std::fs::read_to_string(&sig_path)
                .map_err(|_| AuthorityError::Io("read roster sidecar"))?;

            verify_detached_roster(base, &unsigned, &raw_bytes, &sidecar_hex, version_floor)?;

            return Ok(Self {
                roster: unsigned.roster,
            });
        }

        // --- Path 3: both parse forms failed ---
        tracing::warn!(
            error_kind = "roster_parse_failed",
            "RosterFileRegistry::load: roster file could not be parsed as either \
             embedded or unsigned form"
        );
        Err(AuthorityError::RosterCorrupt)
    }

    /// Return a reference to the underlying `Roster` for inspection.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }
}

impl AuthorityRegistry for RosterFileRegistry {
    fn resolve(&self, op_class: OpClass) -> Option<AuthorityGrant> {
        // Collect all keys enrolled for this op_class across all principals.
        let mut enrolled_keys: Vec<EnrolledKey> = Vec::new();
        for entry in self.roster.entries.values() {
            if entry.op_classes.contains(&op_class) {
                enrolled_keys.extend(entry.keys.iter().cloned());
            }
        }
        if enrolled_keys.is_empty() {
            return None;
        }
        Some(AuthorityGrant {
            keys: enrolled_keys,
            envelope: PactDefinition {
                op_classes: vec![op_class],
                definition: format!(
                    "roster v{} — op_class: {op_class:?}",
                    self.roster.roster_version
                ),
            },
        })
    }

    fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
        for entry in self.roster.entries.values() {
            if !entry.op_classes.contains(&op_class) {
                continue;
            }
            for key in &entry.keys {
                if key.pubkey.0 == pubkey.0 && key.is_active_at(seq) {
                    return true;
                }
            }
        }
        false
    }

    fn activation_seq(&self) -> Option<u64> {
        // RosterFileRegistry's activation_seq is supplied externally via
        // chain.json::roster_activation_seq. The registry itself does not store
        // it — the caller (verify_chain) resolves it from chain state.
        // We return None here; resolve_registry passes the value from chain.json
        // when threading into verify_record_multi_sig via EnterpriseRegistry.
        //
        // HIGH-3: Returning None here silently DISABLES membership enforcement
        // for all records. A bare RosterFileRegistry used as an AuthorityRegistry
        // in production code is a structural trap. EnterpriseRegistry (from
        // resolve_registry) is the correct wrapper for production paths.
        //
        // If you see this in a production code path, you have a bug: wrap this
        // in EnterpriseRegistry and supply roster_activation_seq from chain.json.
        //
        // debug_assert ensures this is caught in debug builds if a bare registry
        // reaches verify_record_multi_sig with a guarded op-class record.
        // (Cannot assert unconditionally here — callers like RosterFileRegistry::load
        // + is_enrolled in tests legitimately call activation_seq() on a bare registry.)
        None
    }
}

// ---------------------------------------------------------------------------
// Custom (de)serialisers for Ed25519PublicKey and Ed25519Signature ↔ hex
// ---------------------------------------------------------------------------

fn ser_pubkey<S>(val: &Ed25519PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(val.0))
}

fn de_pubkey<'de, D>(d: D) -> Result<Ed25519PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str = String::deserialize(d)?;
    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(format!(
            "pubkey hex must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Ed25519PublicKey(arr))
}

fn ser_signature<S>(val: &Ed25519Signature, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(val.0))
}

fn de_signature<'de, D>(d: D) -> Result<Ed25519Signature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str = String::deserialize(d)?;
    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
    if bytes.len() != 64 {
        return Err(serde::de::Error::custom(format!(
            "signature hex must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Ed25519Signature::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_env;
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Generate a fresh Ed25519 keypair for testing using getrandom.
    fn gen_keypair() -> (DalekSigningKey, Ed25519PublicKey) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom");
        let sk = DalekSigningKey::from_bytes(&seed);
        let pk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn sign_roster(
        sk: &DalekSigningKey,
        roster: &Roster,
        root_pk: Ed25519PublicKey,
    ) -> SignedRoster {
        use ed25519_dalek::Signer;
        let bytes = serde_json::to_vec(roster).expect("serialize");
        let sig = sk.sign(&bytes);
        SignedRoster {
            roster: roster.clone(),
            roster_pubkey: root_pk,
            signature: Ed25519Signature::new(sig.to_bytes()),
        }
    }

    fn minimal_roster(version: u64) -> Roster {
        Roster {
            format_version: 1,
            roster_version: version,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries: BTreeMap::new(),
        }
    }

    /// A roster with one principal enrolled for KeyRotate with a single active key.
    fn roster_with_principal(
        version: u64,
        pk: Ed25519PublicKey,
        op_classes: Vec<OpClass>,
    ) -> Roster {
        let mut entries = BTreeMap::new();
        entries.insert(
            "alice@example.com".to_string(),
            RosterEntry {
                keys: vec![EnrolledKey {
                    pubkey: pk,
                    active_from_seq: 0,
                    retired_at_seq: None,
                }],
                op_classes,
            },
        );
        Roster {
            format_version: 1,
            roster_version: version,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries,
        }
    }

    #[test]
    fn roster_roundtrip_signed() {
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(1);
        let signed = sign_roster(&sk, &roster, root_pk);

        // Save via §5a write path.
        save_roster(tmp.path(), &signed).expect("save_roster");

        // Check the file exists.
        assert!(
            roster_path(tmp.path()).exists(),
            "roster file must exist after save"
        );

        // Re-parse to verify roundtrip.
        let raw = std::fs::read_to_string(roster_path(tmp.path())).expect("read");
        let parsed: SignedRoster = serde_json::from_str(&raw).expect("parse");
        assert_eq!(parsed.roster.roster_version, 1);
    }

    #[test]
    fn roster_file_registry_valid_loads() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let (member_sk, member_pk) = gen_keypair();
        let _ = member_sk; // member private key is unused in this test

        let roster = roster_with_principal(5, member_pk, vec![OpClass::KeyRotate]);
        let signed = sign_roster(&sk, &roster, root_pk);
        save_roster(tmp.path(), &signed).expect("save_roster");

        // Set env so resolve_root_pubkey finds the key.
        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            result.is_ok(),
            "valid signed roster must load: {:?}",
            result.err()
        );
    }

    #[test]
    fn roster_file_registry_missing_roster_fails_closed() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let root_hex = hex::encode(root_pk.0);
        let _ = sk;

        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterMissing)),
            "missing roster must return RosterMissing"
        );
    }

    #[test]
    fn roster_file_registry_tampered_signature_fails_closed() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let (_, other_pk) = gen_keypair(); // different pubkey

        // Sign with sk but embed a DIFFERENT pubkey in the envelope → mismatch.
        let roster = minimal_roster(1);
        let signed = sign_roster(&sk, &roster, other_pk);
        save_roster(tmp.path(), &signed).expect("save");

        // The env key is the real root, but the file has other_pk — mismatch.
        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterSignatureInvalid)),
            "mismatched roster_pubkey must fail: {result:?}"
        );
    }

    #[test]
    fn roster_file_registry_rollback_rejected() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();

        let roster = minimal_roster(5); // version 5
        let signed = sign_roster(&sk, &roster, root_pk);
        save_roster(tmp.path(), &signed).expect("save");

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        // version_floor = 10 > roster_version 5 → rollback.
        let result = RosterFileRegistry::load(tmp.path(), 10);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterRollback)),
            "below-floor version must return RosterRollback: {result:?}"
        );
    }

    #[test]
    fn roster_deny_unknown_fields_corrupt() {
        let _g = test_env::lock();
        let tmp = tmp();
        // Write a JSON with an unknown field at the Roster level.
        let audit_dir = tmp.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(
            audit_dir.join("authority-roster.json"),
            br#"{"roster":{"format_version":1,"roster_version":1,"generated_at":"x","entries":{},"unknown_field":"x"},"roster_pubkey":"aabb","signature":"00"}"#,
        ).unwrap();

        let root_hex = "aa".repeat(32);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterCorrupt)),
            "unknown fields in Roster must produce RosterCorrupt: {result:?}"
        );
    }

    #[test]
    fn is_enrolled_checks_op_class() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let (_, member_pk) = gen_keypair();

        // Enroll alice for KeyRotate only, NOT ReleaseAuth.
        let roster = roster_with_principal(1, member_pk, vec![OpClass::KeyRotate]);
        let signed = sign_roster(&sk, &roster, root_pk);
        save_roster(tmp.path(), &signed).expect("save");

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let reg = RosterFileRegistry::load(tmp.path(), 0).expect("load");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Enrolled for KeyRotate at seq 0.
        assert!(reg.is_enrolled(&member_pk, OpClass::KeyRotate, 0));
        // NOT enrolled for ReleaseAuth.
        assert!(!reg.is_enrolled(&member_pk, OpClass::ReleaseAuth, 0));
        // NOT enrolled for IdentityMint.
        assert!(!reg.is_enrolled(&member_pk, OpClass::IdentityMint, 0));
    }

    // -----------------------------------------------------------------------
    // Detached-signature tests (§12.16.6 — an internal ticket item 3)
    // -----------------------------------------------------------------------

    /// Helper: sign `raw_bytes` with `sk`, return lowercase hex of the sig.
    fn sign_raw(sk: &DalekSigningKey, raw_bytes: &[u8]) -> String {
        use ed25519_dalek::Signer;
        let sig = sk.sign(raw_bytes);
        hex::encode(sig.to_bytes())
    }

    /// Helper: build an `UnsignedRosterFile` and serialize it to bytes.
    fn make_unsigned_file(roster: &Roster, root_pk: Ed25519PublicKey) -> Vec<u8> {
        let unsigned = UnsignedRosterFile {
            roster: roster.clone(),
            roster_pubkey: root_pk,
        };
        serde_json::to_vec(&unsigned).expect("serialize unsigned")
    }

    /// Detached roundtrip: sign raw bytes in-test → verify passes.
    #[test]
    fn detached_roundtrip_passes() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(1);

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        // Save via save_detached_roster (byte-preserving).
        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save_detached_roster");

        // Verify both files exist.
        assert!(
            roster_path(tmp.path()).exists(),
            "roster file must exist after save_detached_roster"
        );
        assert!(
            roster_sig_path(tmp.path()).exists(),
            "sidecar must exist after save_detached_roster"
        );

        // Load via RosterFileRegistry — must take the detached path.
        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            result.is_ok(),
            "detached roundtrip must load successfully: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().roster().roster_version, 1);
    }

    /// Detached install preserves bytes exactly (read back == written).
    #[test]
    fn detached_install_preserves_bytes_exactly() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(7);

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save");

        // Read back the roster file — must be byte-identical.
        let on_disk = std::fs::read(roster_path(tmp.path())).expect("read back roster");
        assert_eq!(
            on_disk, raw_bytes,
            "saved bytes must be identical to original (no re-serialization)"
        );
    }

    /// Tampered roster file (bytes differ from what was signed) → signature invalid.
    ///
    /// The tamper strategy modifies the first byte of the JSON so the file remains
    /// UTF-8 parseable but has different raw bytes than what the sidecar covers.
    /// We produce a fresh sidecar over the NEW bytes then flip one byte — this ensures
    /// the sidecar was signed with the right key but covers different content.
    ///
    /// Actually simpler: sign, save, then append a trailing space to the roster file.
    /// `UnsignedRosterFile` will still parse (serde_json ignores trailing whitespace),
    /// but the raw bytes (including the space) differ from the signed slice.
    #[test]
    fn detached_tampered_roster_fails() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(1);

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save");

        // Append a space — the JSON still parses but the raw bytes differ from what
        // the sidecar signature covers → RosterSignatureInvalid.
        let roster_p = roster_path(tmp.path());
        let mut contents = std::fs::read(&roster_p).unwrap();
        contents.push(b' ');
        std::fs::write(&roster_p, &contents).unwrap();

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterSignatureInvalid)),
            "tampered roster (extra byte) must fail with RosterSignatureInvalid: {result:?}"
        );
    }

    /// Tampered sidecar (wrong sig) → fail.
    #[test]
    fn detached_tampered_sidecar_fails() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(1);

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save");

        // Overwrite sidecar with a different (wrong) signature.
        let (sk2, _) = gen_keypair();
        let wrong_sig = sign_raw(&sk2, &raw_bytes);
        std::fs::write(roster_sig_path(tmp.path()), wrong_sig.as_bytes()).unwrap();

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterSignatureInvalid)),
            "tampered sidecar must fail: {result:?}"
        );
    }

    /// Orphaned sidecar (no roster file) → RosterMissing (roster file absent).
    #[test]
    fn detached_orphaned_sidecar_no_roster_file_fails() {
        let _g = test_env::lock();
        let tmp = tmp();
        let audit = tmp.path().join("audit");
        std::fs::create_dir_all(&audit).unwrap();
        // Only write the sidecar — no roster file.
        std::fs::write(audit.join("authority-roster.json.sig"), b"deadbeef").unwrap();

        let result = RosterFileRegistry::load(tmp.path(), 0);

        assert!(
            matches!(result, Err(AuthorityError::RosterMissing)),
            "missing roster file (only sidecar) must return RosterMissing: {result:?}"
        );
    }

    /// Embedded signature + sidecar present → embedded wins, sidecar ignored.
    #[test]
    fn embedded_wins_over_sidecar_when_both_present() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(2);

        // Write the embedded-form roster (valid).
        let signed = sign_roster(&sk, &roster, root_pk);
        save_roster(tmp.path(), &signed).expect("save embedded");

        // Also write a sidecar with garbage — it must be ignored.
        std::fs::write(roster_sig_path(tmp.path()), b"not_a_real_signature").unwrap();

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            result.is_ok(),
            "embedded form must win over sidecar — sidecar garbage is irrelevant: {:?}",
            result.err()
        );
    }

    /// Neither embedded nor detached form → RosterCorrupt.
    #[test]
    fn detached_neither_form_returns_roster_corrupt() {
        let _g = test_env::lock();
        let tmp = tmp();
        // Write a roster file with no signature field AND no sidecar.
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(1);
        let raw_bytes = make_unsigned_file(&roster, root_pk);
        // Save just the unsigned file, no sidecar.
        let audit = tmp.path().join("audit");
        std::fs::create_dir_all(&audit).unwrap();
        std::fs::write(audit.join("authority-roster.json"), &raw_bytes).unwrap();
        let _ = sk;

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterCorrupt)),
            "unsigned roster with no sidecar must return RosterCorrupt: {result:?}"
        );
    }

    /// format_version too new → RosterFormatTooNew BEFORE signature on detached path.
    #[test]
    fn detached_format_version_too_new_rejected_before_sig() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = Roster {
            format_version: SUPPORTED_ROSTER_FORMAT_VERSION + 1,
            roster_version: 1,
            generated_at: "2026-06-11T00:00:00+00:00".to_string(),
            entries: BTreeMap::new(),
        };

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save");

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        let result = RosterFileRegistry::load(tmp.path(), 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterFormatTooNew(_, _))),
            "too-new format_version on detached path must return RosterFormatTooNew: {result:?}"
        );
    }

    /// Floor check enforced on detached path: roster_version < floor → RosterRollback.
    #[test]
    fn detached_floor_check_enforced() {
        let _g = test_env::lock();
        let tmp = tmp();
        let (sk, root_pk) = gen_keypair();
        let roster = minimal_roster(3); // version 3

        let raw_bytes = make_unsigned_file(&roster, root_pk);
        let sig_hex = sign_raw(&sk, &raw_bytes);

        save_detached_roster(tmp.path(), &raw_bytes, &sig_hex).expect("save");

        let root_hex = hex::encode(root_pk.0);
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
        // floor = 10 > roster_version 3 → rollback rejected.
        let result = RosterFileRegistry::load(tmp.path(), 10);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            matches!(result, Err(AuthorityError::RosterRollback)),
            "below-floor roster on detached path must return RosterRollback: {result:?}"
        );
    }
}
