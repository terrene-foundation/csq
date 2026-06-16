//! M11 — Multi-sig authorization gate.
//!
//! `authorize_op` is the single collection call-site. It:
//!
//! 1. Computes the intent hash from `(kind, payload)`.
//! 2. Asks each signer to sign the intent hash.
//! 3. Self-checks each produced signature against the signer's own pubkey via
//!    `VerifyingKey::verify_strict` (corrupt-key guard — no silent swallow per
//!    `rules/zero-tolerance.md` Rule 3).
//! 4. If valid count < policy threshold → `Err(MultiSigError::InsufficientSignatures)`.
//!    FAIL CLOSED.
//! 5. Else returns the `EatpAuthority` blob for `SignedRecord.authority`.
//!
//! # Signer roster trait seam for M12
//!
//! `SignerSet` is the minimal trait the gate consumes. M12 will add an
//! `AuthorityRegistry`-backed impl. M11 ships `InMemorySignerSet` for
//! tests and the community/enterprise default path.
//!
//! # Community 1-of-1
//!
//! `authorize_op` with `signers = [outgoing_key]` and `policy.threshold = 1`
//! is the community single-operator path: the operator's own key self-authorizes
//! with no additional ceremony.

use ed25519_dalek::VerifyingKey;
use serde_json::json;

use crate::audit::traits::SigningKey;
use crate::audit::types::{EatpAuthority, EventKind, EventPayload};

use super::edition::MultiSigPolicy;
use super::error::MultiSigError;
use super::intent::intent_hash;

/// Minimal trait the authorization gate consumes.
///
/// M12 will supply an `AuthorityRegistry`-backed impl. M11 ships
/// [`InMemorySignerSet`] for tests and the community/enterprise default path.
pub trait SignerSet {
    /// The signers available to authorize this operation.
    fn signers(&self) -> Vec<&dyn SigningKey>;
}

/// An in-memory signer set backed by a `Vec<Box<dyn SigningKey>>`.
///
/// Used by tests and the M11 community/enterprise default paths (where the
/// signer set is built from the in-memory outgoing key).
pub struct InMemorySignerSet {
    keys: Vec<Box<dyn SigningKey>>,
}

impl InMemorySignerSet {
    /// Create a new `InMemorySignerSet` from a vector of boxed signing keys.
    pub fn new(keys: Vec<Box<dyn SigningKey>>) -> Self {
        Self { keys }
    }
}

impl SignerSet for InMemorySignerSet {
    fn signers(&self) -> Vec<&dyn SigningKey> {
        self.keys.iter().map(|k| k.as_ref()).collect()
    }
}

/// Authorize a high-impact operation by collecting N-of-M signatures over the
/// canonical intent.
///
/// # Arguments
///
/// - `chain_id` — the chain identifier for the record being authorized. Bound
///   into the intent hash to prevent cross-chain replay (SEC-3).
/// - `kind` — the `EventKind` of the operation being authorized.
/// - `payload` — the `EventPayload` of the operation.
/// - `signers` — slice of available signing keys (`M` signers offered). MUST
///   contain distinct pubkeys — duplicate pubkeys are rejected with
///   `MalformedAuthorityBlob` as a defense-in-depth guard (SEC-1).
/// - `policy` — the resolved multi-sig policy (`N` signatures required).
///
/// # Returns
///
/// On success, returns an `EatpAuthority` blob suitable for
/// `SignedRecord.authority`. The blob has the shape:
///
/// ```json
/// {
///   "multi_sig": {
///     "threshold": N,
///     "roster_size": M,
///     "authorizations": [
///       { "signer_pubkey": "<hex 32B>", "signature": "<hex 64B>" },
///       ...
///     ]
///   }
/// }
/// ```
///
/// # Errors
///
/// - [`MultiSigError::InsufficientSignatures`] if fewer than `policy.threshold`
///   valid signatures were collected (FAIL CLOSED).
/// - [`MultiSigError::SigningFailed`] if a signer's `sign()` call returns an
///   error (the signer is dropped from the count; if the remaining count falls
///   below threshold, `InsufficientSignatures` is returned).
/// - [`MultiSigError::MalformedAuthorityBlob`] if the signer slice contains
///   duplicate pubkeys (defense-in-depth: ensures the blob that would be
///   produced cannot later trick the verifier's dedup guard).
pub fn authorize_op(
    chain_id: &str,
    kind: &EventKind,
    payload: &EventPayload,
    signers: &[&dyn SigningKey],
    policy: &MultiSigPolicy,
) -> Result<EatpAuthority, MultiSigError> {
    use std::collections::HashSet;

    // SEC-1 defense-in-depth: reject duplicate pubkeys at build time so the
    // produced blob cannot carry them. A duplicate pubkey slipped in here would
    // later be caught and rejected by verify_record_multi_sig, but refusing
    // early prevents the invalid blob from ever being written.
    let mut seen_pubkeys: HashSet<[u8; 32]> = HashSet::new();
    for signer in signers {
        let pk = signer.public_key().0;
        if !seen_pubkeys.insert(pk) {
            return Err(MultiSigError::MalformedAuthorityBlob(
                "duplicate signer pubkey in multi_sig authorizations",
            ));
        }
    }

    let hash = intent_hash(chain_id, kind, payload);

    let mut authorizations: Vec<serde_json::Value> = Vec::with_capacity(signers.len());
    let mut valid_count: usize = 0;

    for signer in signers {
        // Sign the 32-byte intent hash.
        let sig = match signer.sign(&hash) {
            Ok(s) => s,
            Err(_e) => {
                // Signing failed — log with fixed-vocab tag (no raw error body
                // — security.md §2) and skip this signer.
                tracing::warn!(
                    error_kind = "multi_sig_signing_failed",
                    "authorize_op: signer sign() failed — dropping from count"
                );
                continue;
            }
        };

        let pubkey = signer.public_key();

        // Self-check: verify the produced signature against the signer's own
        // pubkey. A failed self-check indicates a corrupt key
        // (zero-tolerance.md Rule 3 — no silent swallow; warn + drop).
        let verifying = match VerifyingKey::from_bytes(&pubkey.0) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    error_kind = "multi_sig_corrupt_pubkey",
                    "authorize_op: signer pubkey bytes are not a valid Ed25519 point; \
                     dropping from count"
                );
                continue;
            }
        };
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        if verifying.verify_strict(&hash, &dalek_sig).is_err() {
            tracing::warn!(
                error_kind = "multi_sig_self_check_failed",
                "authorize_op: produced signature failed self-check — corrupt key, \
                 dropping from count"
            );
            continue;
        }

        // Valid signature — append to the authorizations array.
        authorizations.push(json!({
            "signer_pubkey": hex::encode(pubkey.0),
            "signature":     hex::encode(sig.0),
        }));
        valid_count += 1;
    }

    if valid_count < policy.threshold {
        return Err(MultiSigError::InsufficientSignatures {
            needed: policy.threshold,
            got: valid_count,
        });
    }

    Ok(EatpAuthority(json!({
        "multi_sig": {
            "threshold":      policy.threshold as u64,
            "roster_size":    signers.len() as u64,
            "authorizations": authorizations,
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::chain_state::ChainState;
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use crate::audit::key_custody::{audit_init, LocalSigningKey};
    use crate::audit::types::{
        Ed25519PublicKey, EventPayload, IdentityMintPayload, KeyId, KeyRotatePayload,
        ReleaseAuthPayload, RotationReason, Sha256Hex,
    };
    use crate::types::AccountNum;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn svc(tag: &str) -> String {
        format!("csq-m11-gate-test-{}-{}", std::process::id(), tag)
    }

    /// Load the active signing key from chain state.
    /// chain_id is the keychain account used by audit_init.
    fn load_key_from_chain(dir: &std::path::Path, svc_name: &str) -> LocalSigningKey {
        let state = ChainState::load(dir).expect("load chain state");
        let chain_id = state.chain_id;
        LocalSigningKey::load_from_keychain(svc_name, &chain_id).expect("load signing key")
    }

    /// Bootstrap: set up chain.json, init key, return the signing key.
    fn bootstrap_key(dir: &std::path::Path, chain_id: &str, svc_name: &str) -> LocalSigningKey {
        ChainState::new(chain_id)
            .save(dir)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(svc_name, chain_id);
        audit_init(dir, svc_name).expect("audit_init");
        load_key_from_chain(dir, svc_name)
    }

    fn key_rotate_payload() -> EventPayload {
        EventPayload::KeyRotate(KeyRotatePayload {
            previous_key_id: KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).unwrap(),
            new_key_id: KeyId::try_new(format!("ed25519:{}", "b".repeat(64))).unwrap(),
            incoming_pubkey: Ed25519PublicKey([1u8; 32]),
            rotation_reason: RotationReason::Operator,
        })
    }

    fn release_auth_payload() -> EventPayload {
        EventPayload::ReleaseAuth(ReleaseAuthPayload {
            release_tag: "v2.0.0".to_string(),
            artifact_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
        })
    }

    fn identity_mint_payload() -> EventPayload {
        EventPayload::IdentityMint(IdentityMintPayload {
            identity_uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            slot: AccountNum::try_from(1u16).unwrap(),
        })
    }

    const CHAIN_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";

    /// AC-1: N-of-M signatures collected over the canonical intent before op proceeds.
    /// AC-2 (community 1-of-1): a single signer authorizes the KeyRotate op.
    #[test]
    fn test_community_1_of_1_key_rotate_succeeds() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("ckr");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA0";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKey] = &[&key];

        let result = authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy);
        assert!(
            result.is_ok(),
            "community 1-of-1 must succeed: {:?}",
            result.err()
        );

        let authority = result.unwrap();
        let ms = authority.0["multi_sig"].as_object().expect("multi_sig");
        assert_eq!(ms["threshold"].as_u64(), Some(1));
        assert_eq!(ms["roster_size"].as_u64(), Some(1));
        let auths = ms["authorizations"].as_array().expect("authorizations");
        assert_eq!(auths.len(), 1, "exactly one authorization expected");

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// AC-3: threshold configurable; enterprise default N=2 with 2 signers succeeds.
    /// AC-6 (2-of-2 success): two valid signers, threshold 2.
    #[test]
    fn test_enterprise_2_of_2_key_rotate_succeeds() {
        init_mock_keyring();
        let dir1 = tmp();
        let dir2 = tmp();
        let svc1 = svc("e2k1");
        let svc2 = svc("e2k2");
        let chain1 = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
        let chain2 = "01ARZ3NDEKTSV4RRFFQ69G5FA2";

        let key1 = bootstrap_key(dir1.path(), chain1, &svc1);
        let key2 = bootstrap_key(dir2.path(), chain2, &svc2);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 2 };
        let signers: &[&dyn SigningKey] = &[&key1, &key2];

        let result = authorize_op(CHAIN_ID, &EventKind::KeyRotate, &payload, signers, &policy);
        assert!(result.is_ok(), "2-of-2 must succeed: {:?}", result.err());

        let ms = result.unwrap().0["multi_sig"]
            .as_object()
            .expect("multi_sig")
            .clone();
        assert_eq!(ms["threshold"].as_u64(), Some(2));
        assert_eq!(ms["roster_size"].as_u64(), Some(2));
        let auths = ms["authorizations"].as_array().expect("authorizations");
        assert_eq!(auths.len(), 2);

        let _ = LocalSigningKey::delete_from_keychain(&svc1, chain1);
        let _ = LocalSigningKey::delete_from_keychain(&svc2, chain2);
    }

    /// AC-5 / AC-6 (1-of-3 reject): threshold 2 with 1 valid signer fails closed
    /// with a descriptive error naming threshold and count.
    #[test]
    fn test_insufficient_signatures_fails_closed_descriptive() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("ins");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA3";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        // threshold 2 but only 1 signer → must fail
        let policy = MultiSigPolicy { threshold: 2 };
        let signers: &[&dyn SigningKey] = &[&key];

        let result = authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy);
        assert!(
            result.is_err(),
            "1 signer with threshold 2 must fail closed"
        );
        match result.unwrap_err() {
            MultiSigError::InsufficientSignatures { needed, got } => {
                assert_eq!(needed, 2, "needed must be threshold");
                assert_eq!(got, 1, "got must be actual valid count");
            }
            other => panic!("expected InsufficientSignatures, got {:?}", other),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// AC-2 (release-auth): authorize_op accepts ReleaseAuth kind + payload.
    #[test]
    fn test_gate_accepts_release_auth_kind() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("rea");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA4";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = release_auth_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKey] = &[&key];

        let result = authorize_op(
            chain_id,
            &EventKind::ReleaseAuth,
            &payload,
            signers,
            &policy,
        );
        assert!(
            result.is_ok(),
            "ReleaseAuth gate must succeed: {:?}",
            result.err()
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// AC-2 (identity-mint): authorize_op accepts IdentityMint kind + payload.
    #[test]
    fn test_gate_accepts_identity_mint_kind() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("idm");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA5";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = identity_mint_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKey] = &[&key];

        let result = authorize_op(
            chain_id,
            &EventKind::IdentityMint,
            &payload,
            signers,
            &policy,
        );
        assert!(
            result.is_ok(),
            "IdentityMint gate must succeed: {:?}",
            result.err()
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// AC-6 (2-of-3 success): 3 signers available, threshold 2 → 2 valid sigs suffice.
    #[test]
    fn test_2_of_3_succeeds() {
        init_mock_keyring();
        let dirs: Vec<TempDir> = (0..3).map(|_| tmp()).collect();
        let svcs: Vec<String> = (0..3).map(|i| svc(&format!("2o3_{i}"))).collect();
        let chains = [
            "01ARZ3NDEKTSV4RRFFQ69G5FA6",
            "01ARZ3NDEKTSV4RRFFQ69G5FA7",
            "01ARZ3NDEKTSV4RRFFQ69G5FA8",
        ];

        let keys: Vec<LocalSigningKey> = (0..3)
            .map(|i| bootstrap_key(dirs[i].path(), chains[i], &svcs[i]))
            .collect();

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 2 };
        // Offer all 3 signers; expect ≥2 valid sigs collected.
        let signers: &[&dyn SigningKey] = &[&keys[0], &keys[1], &keys[2]];

        let result = authorize_op(CHAIN_ID, &EventKind::KeyRotate, &payload, signers, &policy);
        assert!(result.is_ok(), "2-of-3 must succeed: {:?}", result.err());
        let ms = result.unwrap().0["multi_sig"].clone();
        assert_eq!(ms["roster_size"].as_u64(), Some(3));
        assert_eq!(ms["threshold"].as_u64(), Some(2));
        let auths = ms["authorizations"].as_array().expect("authorizations");
        assert!(auths.len() >= 2, "at least 2 authorizations expected");

        for i in 0..3 {
            let _ = LocalSigningKey::delete_from_keychain(&svcs[i], chains[i]);
        }
    }

    /// SEC-1: authorize_op MUST reject a signer slice with duplicate pubkeys.
    /// Defense-in-depth: ensures the produced blob cannot carry duplicates.
    #[test]
    fn test_authorize_op_rejects_duplicate_pubkeys() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("dup_pk");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA9";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 2 };
        // Both entries are the same key → duplicate pubkey.
        let signers: &[&dyn SigningKey] = &[&key, &key];

        let result = authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy);
        assert!(
            result.is_err(),
            "authorize_op MUST reject duplicate pubkeys — got Ok instead"
        );
        match result.unwrap_err() {
            MultiSigError::MalformedAuthorityBlob(msg) => {
                assert!(
                    msg.contains("duplicate"),
                    "error message must mention duplicate: got {msg}"
                );
            }
            other => panic!(
                "expected MalformedAuthorityBlob(duplicate), got {:?}",
                other
            ),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }
}
