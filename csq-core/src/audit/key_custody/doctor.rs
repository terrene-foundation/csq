//! `csq doctor` integration for M04 signing-key presence check.
//!
//! Returns `SigningKeyStatus::Present { key_id }` when the active signing key
//! is present in the OS keychain, or `SigningKeyStatus::Absent` when it is
//! not (e.g., fresh install, keychain reset, different machine).
//!
//! No private-key bytes are returned or logged — per `rules/security.md §2`.

use std::path::Path;

use crate::audit::key_custody::{
    chain_state::ChainState, try_load_signing_key, KeyLoadOutcome, KeySlot,
};
use crate::audit::types::KeyId;

/// Status of the M04 signing key from the perspective of `csq doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKeyStatus {
    /// Signing key is present and readable (file store or keychain).
    Present {
        /// The stable identifier of the active signing key.
        key_id: KeyId,
    },
    /// No signing key found in EITHER the file store or the keychain.
    /// Remediation: run `csq audit init`.
    Absent,
    /// The signing key is PRESENT but not readable right now — the OS keychain
    /// is locked / ACL-blocked (a non-interactive process cannot answer the
    /// prompt) and there is no file-store copy, OR a present copy is corrupt.
    /// This is distinct from `Absent`: `csq audit init` would mint a SECOND key
    /// and is the WRONG remediation. Remediation: run `csq audit migrate-keys`
    /// interactively (grants the one-time keychain prompt, copies the key into
    /// the daemon-readable file store).
    Inaccessible,
}

/// Check whether the M04 signing key is present in the OS keychain.
///
/// # Arguments
///
/// - `base_dir` — csq accounts base directory.
/// - `service`  — keychain service name (production: `csq-audit-signing`).
///
/// # Note on privacy
///
/// This function does NOT log key material. It logs the `key_id` (a public
/// fingerprint) at the `debug` level only when the key is present.
pub fn check_signing_key(base_dir: &Path, service: &str) -> SigningKeyStatus {
    let state = match ChainState::load(base_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error_kind = "chain_load_failed", "check_signing_key: {e}");
            return SigningKeyStatus::Absent;
        }
    };

    // H-1: If chain_id is empty, the key has never been initialised — report Absent
    // rather than falling back to a "default" sentinel that may alias another
    // installation's keychain entry.
    if state.chain_id.is_empty() {
        tracing::debug!("check_signing_key: chain_id empty — reporting Absent");
        return SigningKeyStatus::Absent;
    }
    let account = state.chain_id.clone();

    // Classify accessibility via the file-first facade (file store, then
    // keychain fallback). Distinguishes a present-but-inaccessible key (locked /
    // ACL-blocked keychain, no file copy) from a genuinely-absent one — so
    // `csq doctor` recommends `migrate-keys` (correct) rather than `audit init`
    // (which would mint a second key over a present-but-blocked one).
    match try_load_signing_key(base_dir, service, &account, KeySlot::Active) {
        KeyLoadOutcome::Loaded(_) => {
            // Report the key_id from chain.json (the recorded identity). The
            // file/keychain cross-check that this matches is the verifier's job.
            match state.signing_key_id {
                Some(kid) => {
                    tracing::debug!(key_id = kid.as_str(), "audit signing key present");
                    SigningKeyStatus::Present { key_id: kid }
                }
                None => SigningKeyStatus::Absent,
            }
        }
        KeyLoadOutcome::Inaccessible | KeyLoadOutcome::Corrupt(_) => SigningKeyStatus::Inaccessible,
        KeyLoadOutcome::Absent => SigningKeyStatus::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::keyring_backend::LocalSigningKey;
    use crate::audit::key_custody::{chain_state::ChainState, init::audit_init};
    use tempfile::TempDir;

    fn tmp_base() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn svc() -> String {
        format!("csq-audit-signing-test-{}", std::process::id())
    }

    /// Named test — doctor reports FAIL when key not initialized.
    #[test]
    fn test_doctor_reports_signing_key_absent_when_not_initialized() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = svc();
        // Don't initialize — key should be absent.
        let status = check_signing_key(tmp.path(), &svc);
        assert_eq!(
            status,
            SigningKeyStatus::Absent,
            "expected Absent on fresh base_dir"
        );
    }

    #[test]
    fn test_doctor_reports_present_after_init() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = svc();
        let chain_id = "doctor_present_test";
        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);

        audit_init(tmp.path(), &svc).expect("init");

        match check_signing_key(tmp.path(), &svc) {
            SigningKeyStatus::Present { key_id } => {
                assert!(key_id.as_str().starts_with("ed25519:"));
            }
            other => panic!("expected Present after init, got {other:?}"),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }
}
