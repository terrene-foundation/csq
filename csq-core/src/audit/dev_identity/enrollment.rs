//! M17 — Per-developer enrollment table.
//!
//! Stores a principal → public-key mapping in `<base>/audit/dev-enrollment.json`.
//! The private key lives in the OS keychain under service
//! `csq-dev-signing-<principal>` — never on disk.
//!
//! # Attribution granularity
//!
//! Two granularities are supported (per M17 PRIMARY METHODOLOGICAL DIRECTIVE):
//!
//! - `AccountablePrincipal` (default): the enrolled principal is a role or team
//!   token (e.g. `"backend-team@rrps.example"`). Multiple individuals may share
//!   one enrollment entry. Works-council-safe default for BetrVG §87(1)6
//!   deployments.
//! - `PerIndividual`: the enrolled principal identifies a specific person
//!   (e.g. `"alice@rrps.example"`). Requires explicit works-council opt-in
//!   for monitoring-regulated deployments.
//!
//! # §5a tmp-cleanup
//!
//! Every write of `dev-enrollment.json` uses `unique_tmp_path → write →
//! secure_file → atomic_replace` with `remove_file(&tmp)` on every failure
//! branch (per `rules/security.md §5a`).
//!
//! # Human-present gate (CRITICAL-2 mitigation)
//!
//! `enroll_developer` accepts a `confirm` closure so tests can inject a
//! non-interactive gate. In production, callers pass a closure that
//! requests TTY confirmation (per `rules/redteam-discipline.md` Rule 5 —
//! closure injection makes the gate testable without a real TTY).

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::SigningKey as DalekSigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit::types::Ed25519PublicKey;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

use super::error::DevIdentityError;

/// Principal service name prefix for per-developer keychain entries.
/// Full service name: `csq-dev-signing-<principal>`.
pub const DEV_SIGNING_SERVICE_PREFIX: &str = "csq-dev-signing-";

/// Attribution granularity for per-developer provenance.
///
/// Default is `AccountablePrincipal` (works-council-safe; no per-person
/// monitoring without explicit opt-in).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    /// The principal identifies an accountable role or team, not a specific
    /// individual. Multiple developers may share one enrollment entry.
    /// This is the default — safe under BetrVG §87(1)6 (RRPS / works-council).
    #[default]
    AccountablePrincipal,
    /// The principal identifies a specific individual developer. Requires
    /// explicit works-council opt-in for deployments where BetrVG §87(1)6
    /// or equivalent monitoring-regulation law applies.
    PerIndividual,
}

/// A validated principal string.
///
/// Accepted characters: `[A-Za-z0-9._@-]`, length 1..=128.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(transparent)]
pub struct Principal(String);

impl Principal {
    /// Validate and construct a `Principal`.
    pub fn new(s: impl Into<String>) -> Result<Self, DevIdentityError> {
        let s = s.into();
        if s.is_empty() || s.len() > 128 {
            return Err(DevIdentityError::InvalidPrincipal(
                "principal must be 1..=128 characters".into(),
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
        {
            return Err(DevIdentityError::InvalidPrincipal(
                "principal contains disallowed characters; allowed: [A-Za-z0-9._@-]".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Return the principal as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single enrollment entry: principal → enrolled public key + granularity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevEnrollment {
    /// The enrolled principal (role/team token or individual identifier).
    pub principal: Principal,
    /// Attribution granularity.
    pub granularity: Granularity,
    /// The Ed25519 public key whose private counterpart is in the OS keychain.
    /// Only the public key is stored on disk.
    pub enrolled_pubkey: Ed25519PublicKey,
}

/// The on-disk enrollment table: `principal → DevEnrollment`.
///
/// Stored at `<base>/audit/dev-enrollment.json`.
/// Private keys are NEVER in this file — they live in the OS keychain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentTable {
    /// Map from principal string to enrollment entry.
    #[serde(default)]
    pub entries: BTreeMap<String, DevEnrollment>,
}

impl EnrollmentTable {
    /// Load the enrollment table from `<base>/audit/dev-enrollment.json`.
    ///
    /// Returns an empty table when the file does not exist (first use).
    pub fn load(base: &Path) -> Result<Self, DevIdentityError> {
        let path = enrollment_path(base);
        // try-read-or-default: open directly and treat NotFound as an empty
        // table (first use). This avoids the exists()→read() TOCTOU window in
        // which a concurrent enrollment could create the file between the two
        // calls (review finding LOW — enrollment-table load TOCTOU).
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(_) => return Err(DevIdentityError::Io("read dev-enrollment.json")),
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| DevIdentityError::Io("parse dev-enrollment.json"))
    }

    /// Save the enrollment table to `<base>/audit/dev-enrollment.json`.
    ///
    /// Uses `unique_tmp_path → write → secure_file → atomic_replace` with
    /// §5a tmp-cleanup on every failure branch.
    pub fn save(&self, base: &Path) -> Result<(), DevIdentityError> {
        let path = enrollment_path(base);
        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| DevIdentityError::Io("create audit dir"))?;
        }

        let json = serde_json::to_vec_pretty(self)
            .map_err(|_| DevIdentityError::Io("serialize enrollment table"))?;

        let tmp = unique_tmp_path(&path);

        // §5a: write → secure_file → atomic_replace, with remove_file on every failure.
        if std::fs::write(&tmp, &json).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(DevIdentityError::Io("write enrollment tmp"));
        }
        if secure_file(&tmp).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(DevIdentityError::Io("secure enrollment tmp"));
        }
        if atomic_replace(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(DevIdentityError::Io("atomic replace enrollment"));
        }
        Ok(())
    }
}

/// Returns the canonical path for the enrollment table.
pub fn enrollment_path(base: &Path) -> std::path::PathBuf {
    base.join("audit").join("dev-enrollment.json")
}

/// Returns the keychain service name for the given principal.
///
/// Service format: `csq-dev-signing-<principal>`.
pub fn dev_signing_service(principal: &Principal) -> String {
    format!("{}{}", DEV_SIGNING_SERVICE_PREFIX, principal.as_str())
}

/// Enroll a developer: generate an Ed25519 keypair, store the private key in
/// the OS keychain, and add the public key to the enrollment table.
///
/// # Human-present gate (CRITICAL-2)
///
/// The `confirm` closure receives a description of the enrollment action and
/// returns `true` if the operator confirms. This gate MUST require human
/// presence — a background process MUST NOT confirm silently. In production,
/// pass a closure that reads a TTY `[y/N]` prompt. In tests, inject a closure
/// that returns the desired answer.
///
/// # Idempotent behaviour
///
/// If `principal` is already enrolled, this function returns
/// `Err(DevIdentityError::AlreadyEnrolled)`. Use `unenroll_developer` first.
///
/// # §5a compliance
///
/// The private key bytes are Zeroized inside the keychain-store path
/// (same pattern as `LocalSigningKey::generate_and_store`).
pub fn enroll_developer(
    base: &Path,
    principal: Principal,
    granularity: Granularity,
    confirm: impl Fn(&str) -> bool,
) -> Result<DevEnrollment, DevIdentityError> {
    // Human-present gate.
    let description = format!(
        "Enroll developer principal '{}' (granularity: {:?}) — a new signing key will be \
generated and stored in the OS keychain. This cannot be undone without unenrolling.",
        principal.as_str(),
        granularity
    );
    if !confirm(&description) {
        return Err(DevIdentityError::EnrollmentRefused(
            "operator did not confirm enrollment".into(),
        ));
    }

    let mut table = EnrollmentTable::load(base)?;
    if table.entries.contains_key(principal.as_str()) {
        return Err(DevIdentityError::AlreadyEnrolled(
            principal.as_str().to_string(),
        ));
    }

    // Generate Ed25519 keypair.
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|_| DevIdentityError::KeyGen("getrandom"))?;

    let inner = DalekSigningKey::from_bytes(&seed);
    let verifying = inner.verifying_key();
    let pubkey_bytes = verifying.to_bytes();

    // Serialize seed as hex for keychain storage.
    let seed_hex: Zeroizing<String> = Zeroizing::new(hex::encode(*seed));

    // Store private key in OS keychain.
    let service = dev_signing_service(&principal);
    let entry = crate::audit::key_custody::keyring_entry(&service, principal.as_str())
        .map_err(|_| DevIdentityError::Keychain("keyring entry"))?;
    entry
        .set_password(seed_hex.as_str())
        .map_err(|_| DevIdentityError::Keychain("store dev key"))?;
    // seed_hex (Zeroizing<String>) is zeroed on drop here.

    let enrollment = DevEnrollment {
        principal: principal.clone(),
        granularity,
        enrolled_pubkey: Ed25519PublicKey(pubkey_bytes),
    };

    // Update the on-disk enrollment table. On failure, ROLL BACK the keychain
    // write — otherwise a partial enrollment orphans a live private key under
    // `csq-dev-signing-<principal>` with no on-disk record, and the next
    // enroll attempt (seeing an empty table) silently overwrites it with a
    // second keypair. This is the inverse of the §5a tmp-cleanup invariant and
    // mirrors the M04 `audit_init` rollback in `key_custody/init.rs` (review
    // finding MED — keychain/disk inconsistency).
    table
        .entries
        .insert(principal.as_str().to_string(), enrollment.clone());
    if let Err(e) = table.save(base) {
        let _ = entry.delete_credential();
        return Err(e);
    }

    Ok(enrollment)
}

/// Remove a developer from the enrollment table and delete the keychain entry.
///
/// Returns `Err(DevIdentityError::NotEnrolled)` when the principal is not
/// present in the table.
pub fn unenroll_developer(base: &Path, principal: &Principal) -> Result<(), DevIdentityError> {
    let mut table = EnrollmentTable::load(base)?;
    if table.entries.remove(principal.as_str()).is_none() {
        return Err(DevIdentityError::NotEnrolled(
            principal.as_str().to_string(),
        ));
    }
    table.save(base)?;

    // Best-effort: delete keychain entry (not fatal if already absent).
    let service = dev_signing_service(principal);
    if let Ok(entry) = crate::audit::key_custody::keyring_entry(&service, principal.as_str()) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn confirm_yes(_: &str) -> bool {
        true
    }
    fn confirm_no(_: &str) -> bool {
        false
    }

    #[test]
    fn test_principal_valid() {
        assert!(Principal::new("alice@example.com").is_ok());
        assert!(Principal::new("backend-team").is_ok());
        assert!(Principal::new("user_123").is_ok());
    }

    #[test]
    fn test_principal_invalid_chars() {
        assert!(Principal::new("alice space").is_err());
        assert!(Principal::new("alice/dir").is_err());
        assert!(Principal::new("alice;cmd").is_err());
    }

    #[test]
    fn test_principal_empty_rejected() {
        assert!(Principal::new("").is_err());
    }

    #[test]
    fn test_principal_too_long_rejected() {
        let long = "a".repeat(129);
        assert!(Principal::new(long).is_err());
    }

    #[test]
    fn test_granularity_default_is_accountable_principal() {
        let g = Granularity::default();
        assert_eq!(g, Granularity::AccountablePrincipal);
    }

    /// Returns a process-unique principal to avoid keychain key collisions between
    /// concurrent tests that share the process-global mock keyring.
    fn unique_principal(tag: &str) -> Principal {
        let pid = std::process::id();
        let s = format!("enroll-{tag}-{pid}@example.com");
        Principal::new(s).unwrap()
    }

    #[test]
    fn test_enrollment_human_present_gate_requires_confirmation() {
        init_mock_keyring();
        let dir = tmp();
        let p = unique_principal("gate");
        // Non-interactive confirm_no → refuses (gate fires before keychain write).
        let result = enroll_developer(dir.path(), p, Granularity::default(), confirm_no);
        assert!(
            result.is_err(),
            "enrollment must be refused when confirmation returns false"
        );
        match result.unwrap_err() {
            DevIdentityError::EnrollmentRefused(_) => {}
            other => panic!("expected EnrollmentRefused, got {other:?}"),
        }
    }

    #[test]
    fn test_enroll_and_load_round_trip() {
        init_mock_keyring();
        let dir = tmp();
        let p = unique_principal("roundtrip");

        let enrollment = enroll_developer(
            dir.path(),
            p.clone(),
            Granularity::AccountablePrincipal,
            confirm_yes,
        )
        .expect("enroll must succeed");

        // Public key on disk must be 32 bytes.
        assert_eq!(enrollment.enrolled_pubkey.0.len(), 32);
        assert_eq!(enrollment.granularity, Granularity::AccountablePrincipal);

        // Re-load and verify persistence.
        let table = EnrollmentTable::load(dir.path()).expect("load");
        let entry = table.entries.get(p.as_str()).expect("entry present");
        assert_eq!(entry.enrolled_pubkey.0, enrollment.enrolled_pubkey.0);
    }

    #[test]
    fn test_enroll_duplicate_rejected() {
        init_mock_keyring();
        let dir = tmp();
        let p = unique_principal("dup");

        enroll_developer(dir.path(), p.clone(), Granularity::default(), confirm_yes)
            .expect("first enroll ok");
        let result = enroll_developer(dir.path(), p.clone(), Granularity::default(), confirm_yes);
        assert!(
            matches!(result, Err(DevIdentityError::AlreadyEnrolled(_))),
            "duplicate enroll must fail"
        );
    }
}
