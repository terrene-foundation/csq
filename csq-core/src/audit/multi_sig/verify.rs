//! M11 + M12 — Multi-sig verification hook for `verify_chain`.
//!
//! `verify_record_multi_sig` is inserted into `verify_chain`'s per-record loop
//! immediately AFTER the outer Ed25519 signature check and BEFORE the 'Advance
//! state' block. It is ADDITIVE: records with `authority: None` or whose
//! authority blob does not contain a `multi_sig` key return `Ok(())` immediately
//! — backward compatibility with ALL existing records is preserved.
//!
//! # Behavior for multi-sig records
//!
//! A record whose `authority` blob carries a `multi_sig` object MUST pass:
//!
//! 1. Parse `threshold` (u64 ≥ 1) and `authorizations` array.
//! 2. Validate `roster_size >= authorizations.len()` (internal consistency).
//! 3. Re-derive `intent_hash(record.chain_id, record.kind, record.payload)`.
//! 4. For each authorization, parse `signer_pubkey` (32B hex) and `signature`
//!    (64B hex). Verify via `VerifyingKey::verify_strict`.
//! 5. Count valid verifications, tracking seen pubkeys in a `HashSet<[u8;32]>`.
//!    Duplicate pubkeys cause immediate rejection (SEC-1).
//! 6. If `valid_count < threshold` → `Err(MultiSigError::VerificationUnderThreshold)`.
//!
//! Malformed blobs (missing fields, bad hex, wrong lengths) → `Err(
//! MultiSigError::MalformedAuthorityBlob)` — fail closed. A record CLAIMING
//! multi-sig with a broken blob is NEVER silently accepted.
//!
//! # M12 roster membership check (NEW)
//!
//! When `registry` is `Some` AND the registry's `activation_seq` is `Some(a)`
//! AND `record.seq >= a` AND `record.kind` maps to a guarded `OpClass`:
//!
//! A pubkey that verifies cryptographically BUT is NOT enrolled (for that
//! op-class, at that seq's window) contributes **0** to `valid_count`.
//! The threshold is then checked over the ENROLLED-AND-VALID count.
//!
//! This is the load-bearing change that closes the M11 Sybil-resistance gap:
//! an actor who self-mints N distinct keypairs cannot satisfy the threshold
//! post-activation because unenrolled pubkeys are filtered out.
//!
//! For community / pre-activation / unguarded kind / no registry: exact M11
//! behavior (backward compat — inner-sig validity only).

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;

use crate::audit::authority::op_class::OpClass;
use crate::audit::authority::registry::AuthorityRegistry;
use crate::audit::types::{Ed25519PublicKey, SignedRecord};

use super::error::MultiSigError;
use super::intent::{intent_hash, intent_hash_raw};

/// Verify the multi-sig authorization on a `SignedRecord`.
///
/// # Arguments
///
/// - `record` — the record to verify.
/// - `registry` — optional authority registry. When `Some`, the M12 membership
///   check is applied for guarded op-classes post-activation. When `None`,
///   pure M11 behavior (inner-sig validity only). Community edition passes `None`.
///
/// # Fast path
///
/// If `record.authority` is `None`, or the authority JSON value does not
/// contain a `"multi_sig"` key, returns `Ok(())` immediately. This is the
/// fast path for all pre-M11 records and for records that use the authority
/// slot for non-multi-sig purposes.
///
/// **M13 exception:** if membership enforcement is active for this record
/// (registry `Some`, `record.seq >= activation_seq`, and `record.kind` maps to
/// a guarded `OpClass`), a record carrying NO `multi_sig` blob is REJECTED with
/// `MultiSigError::MissingAuthorizationForGuardedOp` instead of taking the fast
/// path — otherwise an outgoing-key-only attacker could bypass the roster
/// threshold by simply omitting the authority blob.
///
/// # Error path
///
/// Returns `Err(MultiSigError::MalformedAuthorityBlob)` for structurally
/// broken multi-sig blobs (fail-closed — a record claiming multi-sig with a
/// broken blob MUST be rejected).
///
/// Returns `Err(MultiSigError::VerificationUnderThreshold)` when the number
/// of valid (and enrolled, if membership is enforced) inner authorizations is
/// less than the blob's own `threshold`.
pub fn verify_record_multi_sig(
    record: &SignedRecord,
    registry: Option<&dyn AuthorityRegistry>,
) -> Result<(), MultiSigError> {
    // M13 (closes the M11/M12 authority-presence gap): determine whether roster
    // membership enforcement is active for THIS record before the fast path.
    // Enforced IFF registry is Some, has an activation_seq `a`, `record.seq >= a`,
    // and `record.kind` maps to a guarded OpClass.
    let enforced_op_class: Option<OpClass> = registry.and_then(|reg| {
        let op_class = OpClass::from_event_kind(&record.kind)?;
        let activation = reg.activation_seq()?;
        (record.seq >= activation).then_some(op_class)
    });

    // Fast path: no authority, or authority has no multi_sig key.
    let ms_blob = match record
        .authority
        .as_ref()
        .and_then(|auth| auth.0.get("multi_sig"))
    {
        Some(v) => v,
        None => {
            // A guarded op-class record, when roster membership is being
            // enforced (`enforced_op_class` is Some), MUST carry a multi_sig
            // blob. Omitting it would otherwise bypass the roster threshold (an
            // outgoing-key-only attacker could forge an authority-less guarded
            // record that passes the fast path).
            if enforced_op_class.is_some() {
                return Err(MultiSigError::MissingAuthorizationForGuardedOp);
            }
            return Ok(());
        }
    };

    // Re-derive the intent hash from this record's (chain_id, kind, payload).
    // SEC-3: chain_id binds the intent to this chain, closing cross-chain replay.
    let hash = intent_hash(record.chain_id.as_str(), &record.kind, &record.payload);

    // M12: roster membership enforcement is active under the same condition as
    // `enforced_op_class`. When active, only enrolled pubkeys count toward the
    // threshold (the `record.seq` validity window); otherwise pure M11 behavior.
    let membership: Option<(OpClass, &dyn AuthorityRegistry, u64)> =
        match (enforced_op_class, registry) {
            (Some(op_class), Some(reg)) => Some((op_class, reg, record.seq)),
            _ => None,
        };

    verify_multi_sig_authorizations(ms_blob, &hash, membership)
}

/// Forward-compat (GH an internal ticket): verify the multi-sig authorization on a record
/// whose `EventKind` is UNKNOWN to this binary.
///
/// An unknown kind cannot be mapped to an [`OpClass`], so M12 roster-membership
/// enforcement cannot run — the reader does not know whether this future
/// op-class is guarded. The check degrades to pure-M11 inner-threshold
/// verification (every valid inner signature over the [`intent_hash_raw`]
/// pre-image counts; no membership filter). The one INHERENT forward-compat
/// limitation: a FUTURE guarded op-class shipped with NO `multi_sig` blob cannot
/// be rejected as `MissingAuthorizationForGuardedOp` here — a kind-aware (newer)
/// reader enforces that on its own verify. The outer Ed25519 signature (verified
/// separately by the caller) already commits to the entire authority blob, so a
/// present blob is tamper-evident regardless. See spec 25 §25.12.2.
///
/// `authority` is the record's authority slot parsed as a [`serde_json::Value`]
/// (`None` when the record carries no authority — the fast path returns `Ok`).
pub(crate) fn verify_opaque_multi_sig(
    chain_id: &str,
    kind: &str,
    payload: &serde_json::value::RawValue,
    authority: Option<&serde_json::Value>,
) -> Result<(), MultiSigError> {
    let ms_blob = match authority.and_then(|a| a.get("multi_sig")) {
        Some(v) => v,
        // No multi_sig blob: fast path. Unlike the typed path there is no
        // `MissingAuthorizationForGuardedOp` branch — op-class is unknowable.
        None => return Ok(()),
    };
    let hash = intent_hash_raw(chain_id, kind, payload);
    verify_multi_sig_authorizations(ms_blob, &hash, None)
}

/// Verify the inner authorizations of a `multi_sig` blob against a precomputed
/// `intent_hash`. Shared by [`verify_record_multi_sig`] (typed records) and
/// [`verify_opaque_multi_sig`] (unknown-kind forward-compat records, GH an internal ticket).
///
/// `membership` is `Some((op_class, registry, record_seq))` when M12 roster
/// enforcement applies — then only pubkeys enrolled for `op_class` at
/// `record_seq` count toward the threshold. `None` is pure-M11 (inner-sig
/// validity only), the mode used for opaque records whose op-class cannot be
/// determined.
fn verify_multi_sig_authorizations(
    ms_blob: &serde_json::Value,
    intent_hash: &[u8; 32],
    membership: Option<(OpClass, &dyn AuthorityRegistry, u64)>,
) -> Result<(), MultiSigError> {
    let ms = ms_blob
        .as_object()
        .ok_or(MultiSigError::MalformedAuthorityBlob(
            "multi_sig is not an object",
        ))?;

    let threshold = ms.get("threshold").and_then(|v| v.as_u64()).ok_or(
        MultiSigError::MalformedAuthorityBlob("multi_sig.threshold is missing or not a u64"),
    )?;

    if threshold == 0 {
        return Err(MultiSigError::MalformedAuthorityBlob(
            "multi_sig.threshold must be ≥ 1",
        ));
    }

    let authorizations = ms.get("authorizations").and_then(|v| v.as_array()).ok_or(
        MultiSigError::MalformedAuthorityBlob(
            "multi_sig.authorizations is missing or not an array",
        ),
    )?;

    // SEC-5: validate roster_size internal consistency.
    // roster_size is an M-claim for M12's roster; here we verify it is ≥
    // the number of authorization entries (a smaller roster_size than the
    // number of signatures the blob actually carries is nonsensical).
    if let Some(roster_size) = ms.get("roster_size").and_then(|v| v.as_u64()) {
        if (authorizations.len() as u64) > roster_size {
            return Err(MultiSigError::MalformedAuthorityBlob(
                "multi_sig.roster_size is smaller than the number of authorizations — malformed blob",
            ));
        }
    }

    // SEC-1: track seen pubkeys to detect duplicates. A duplicate pubkey in
    // a claimed-multi-sig blob is rejected as malformed (fail-closed). Ed25519
    // signatures are deterministic, so a single signer repeating their entry
    // N times would otherwise satisfy a threshold-N record, collapsing N-of-M
    // to effectively 1-of-1.
    let mut seen_pubkeys: HashSet<[u8; 32]> = HashSet::new();
    let mut valid_count: u64 = 0;

    for (idx, auth_entry) in authorizations.iter().enumerate() {
        let entry = auth_entry
            .as_object()
            .ok_or(MultiSigError::MalformedAuthorityBlob(
                "authorization entry is not an object",
            ))?;

        // Parse signer_pubkey (32 bytes, hex-encoded = 64 hex chars).
        let pubkey_hex = entry.get("signer_pubkey").and_then(|v| v.as_str()).ok_or(
            MultiSigError::MalformedAuthorityBlob(
                "authorization.signer_pubkey is missing or not a string",
            ),
        )?;

        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| {
            MultiSigError::MalformedAuthorityBlob("authorization.signer_pubkey is not valid hex")
        })?;
        if pubkey_bytes.len() != 32 {
            return Err(MultiSigError::MalformedAuthorityBlob(
                "authorization.signer_pubkey must decode to exactly 32 bytes",
            ));
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);

        // SEC-1: reject duplicate pubkeys — fail closed.
        if !seen_pubkeys.insert(pk_arr) {
            return Err(MultiSigError::MalformedAuthorityBlob(
                "duplicate signer pubkey in multi_sig authorizations",
            ));
        }

        // Parse signature (64 bytes, hex-encoded = 128 hex chars).
        let sig_hex = entry.get("signature").and_then(|v| v.as_str()).ok_or(
            MultiSigError::MalformedAuthorityBlob(
                "authorization.signature is missing or not a string",
            ),
        )?;

        let sig_bytes = hex::decode(sig_hex).map_err(|_| {
            MultiSigError::MalformedAuthorityBlob("authorization.signature is not valid hex")
        })?;
        if sig_bytes.len() != 64 {
            return Err(MultiSigError::MalformedAuthorityBlob(
                "authorization.signature must decode to exactly 64 bytes",
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        // Verify the inner authorization signature over the intent hash.
        let verifying = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(v) => v,
            Err(_) => {
                // Malformed pubkey in a claimed-multi-sig blob: fail closed.
                tracing::warn!(
                    error_kind = "multi_sig_verify_invalid_pubkey",
                    auth_index = idx,
                    "verify_multi_sig_authorizations: authorization pubkey is not a valid Ed25519 point"
                );
                return Err(MultiSigError::MalformedAuthorityBlob(
                    "authorization.signer_pubkey is not a valid Ed25519 point",
                ));
            }
        };

        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let sig_valid = verifying.verify_strict(intent_hash, &dalek_sig).is_ok();

        if sig_valid {
            // M12: if membership check is active, verify enrollment.
            match &membership {
                None => {
                    // Pure M11 behavior: sig valid → count it.
                    valid_count += 1;
                }
                Some((op_class, reg, seq)) => {
                    // Membership enforced: pubkey must be enrolled for this
                    // op-class at this seq (validity window check).
                    let pk = Ed25519PublicKey(pk_arr);
                    if reg.is_enrolled(&pk, *op_class, *seq) {
                        valid_count += 1;
                    } else {
                        // Sig-valid but unenrolled: contributes 0.
                        tracing::warn!(
                            error_kind = "multi_sig_non_member_signer",
                            auth_index = idx,
                            seq = *seq,
                            op_class = ?op_class,
                            "verify_multi_sig_authorizations: sig-valid pubkey is not enrolled \
                             in roster for this op-class — not counted toward threshold"
                        );
                    }
                }
            }
        }
        // A single invalid sig is NOT fatal: we count valid (+ enrolled) sigs
        // and check threshold. However a structurally malformed entry (above)
        // IS fatal — fail closed.
    }

    if valid_count < threshold {
        return Err(MultiSigError::VerificationUnderThreshold {
            threshold,
            valid: valid_count,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::chain_state::ChainState;
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use crate::audit::key_custody::{audit_init, LocalSigningKey};
    use crate::audit::multi_sig::edition::MultiSigPolicy;
    use crate::audit::multi_sig::gate::authorize_op;
    use crate::audit::traits::SigningKey as SigningKeyTrait;
    use crate::audit::types::{
        Ed25519PublicKey, Ed25519Signature, EventKind, EventPayload, KeyId, KeyRotatePayload,
        RecordId, RotationReason, Sha256Hex, SignedRecord,
    };
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn svc(tag: &str) -> String {
        format!("csq-m11-verify-test-{}-{}", std::process::id(), tag)
    }

    fn bootstrap_key(dir: &std::path::Path, chain_id: &str, svc_name: &str) -> LocalSigningKey {
        ChainState::new(chain_id)
            .save(dir)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(svc_name, chain_id);
        audit_init(dir, svc_name).expect("audit_init");
        LocalSigningKey::load_from_keychain(svc_name, chain_id).expect("load key")
    }

    fn key_rotate_payload() -> EventPayload {
        EventPayload::KeyRotate(KeyRotatePayload {
            previous_key_id: KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).unwrap(),
            new_key_id: KeyId::try_new(format!("ed25519:{}", "b".repeat(64))).unwrap(),
            incoming_pubkey: Ed25519PublicKey([1u8; 32]),
            rotation_reason: RotationReason::Operator,
        })
    }

    /// Build a minimal SignedRecord for testing with the given authority.
    ///
    /// `chain_id` MUST match the chain_id passed to `authorize_op` when
    /// constructing the authority blob (SEC-3: intent hash binds to chain_id).
    fn make_record(
        chain_id: &str,
        kind: EventKind,
        payload: EventPayload,
        authority: Option<crate::audit::types::EatpAuthority>,
    ) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind,
            payload,
            ts: "2026-06-02T12:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        }
    }

    const TEST_CHAIN_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";

    /// AC-7: backward compat — record with authority: None passes the hook.
    #[test]
    fn test_verify_no_authority_passes() {
        let record = make_record(
            TEST_CHAIN_ID,
            EventKind::KeyRotate,
            key_rotate_payload(),
            None,
        );
        assert!(
            verify_record_multi_sig(&record, None).is_ok(),
            "record with authority: None must pass the multi-sig hook"
        );
    }

    /// AC-7: record with authority JSON that has no multi_sig key passes.
    #[test]
    fn test_verify_non_multi_sig_authority_passes() {
        use crate::audit::types::EatpAuthority;
        use serde_json::json;
        let authority = Some(EatpAuthority(json!({ "other_field": "value" })));
        let record = make_record(
            TEST_CHAIN_ID,
            EventKind::KeyRotate,
            key_rotate_payload(),
            authority,
        );
        assert!(
            verify_record_multi_sig(&record, None).is_ok(),
            "authority without multi_sig key must pass (backward compat)"
        );
    }

    /// AC-6 (community 1-of-1 success, verify path): a valid multi-sig authority
    /// from authorize_op verifies successfully.
    #[test]
    fn test_verify_valid_multi_sig_authority_passes() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("valid_ms");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB0";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKeyTrait] = &[&key];

        let authority = authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy)
            .expect("authorize_op must succeed");

        let record = make_record(chain_id, EventKind::KeyRotate, payload, Some(authority));
        assert!(
            verify_record_multi_sig(&record, None).is_ok(),
            "valid multi-sig authority must verify successfully"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// AC-6 (tamper — forged inner signature): a record whose inner authorization
    /// signature is forged (random bytes) is REJECTED by verify_record_multi_sig.
    ///
    /// F-02: positive control — assert the UNTAMPERED authority passes first,
    /// then tamper and assert Err. This ensures the negative result is not a
    /// false positive from a pre-existing broken state.
    #[test]
    fn test_verify_tampered_inner_signature_rejected() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("tamper_sig");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB1";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKeyTrait] = &[&key];

        // Collect a valid authority.
        let mut authority =
            authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy)
                .expect("authorize_op must succeed");

        // F-02: positive control — untampered authority MUST pass.
        {
            let record_clean = make_record(
                chain_id,
                EventKind::KeyRotate,
                payload.clone(),
                Some(authority.clone()),
            );
            assert!(
                verify_record_multi_sig(&record_clean, None).is_ok(),
                "F-02: untampered authority must pass verify_record_multi_sig before tampering"
            );
        }

        // Tamper: replace the signature in the first authorization with all-zero hex.
        let tampered_sig = "00".repeat(64);
        if let Some(ms) = authority.0.get_mut("multi_sig") {
            if let Some(auths) = ms.get_mut("authorizations") {
                if let Some(first) = auths.as_array_mut().and_then(|a| a.first_mut()) {
                    first["signature"] = serde_json::Value::String(tampered_sig);
                }
            }
        }

        let record = make_record(chain_id, EventKind::KeyRotate, payload, Some(authority));
        let result = verify_record_multi_sig(&record, None);
        assert!(
            result.is_err(),
            "tampered inner signature MUST be rejected by verify_record_multi_sig"
        );
        // Should be VerificationUnderThreshold (0 valid < threshold 1).
        match result.unwrap_err() {
            MultiSigError::VerificationUnderThreshold { threshold, valid } => {
                assert_eq!(threshold, 1);
                assert_eq!(valid, 0);
            }
            other => panic!("expected VerificationUnderThreshold, got {:?}", other),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// SEC-1: verify_record_multi_sig MUST reject a blob where the same
    /// signer pubkey appears twice. Even with threshold=2, one signer listing
    /// their key twice MUST NOT satisfy the check — that would collapse N-of-M
    /// to 1-of-1.
    #[test]
    fn test_verify_rejects_duplicate_signer_pubkey() {
        init_mock_keyring();
        let dir = tmp();
        let svc_name = svc("dedup_verify");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB4";

        let key = bootstrap_key(dir.path(), chain_id, &svc_name);

        let payload = key_rotate_payload();
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn SigningKeyTrait] = &[&key];

        // Collect a valid 1-of-1 authority.
        let authority_single =
            authorize_op(chain_id, &EventKind::KeyRotate, &payload, signers, &policy)
                .expect("authorize_op must succeed for single signer");

        // Build a blob manually with threshold=2 and the same authorization duplicated.
        // This simulates an attacker trying to satisfy threshold=2 with one key.
        let first_auth = authority_single.0["multi_sig"]["authorizations"]
            .as_array()
            .expect("authorizations")
            .first()
            .expect("at least one auth")
            .clone();

        let authority_dup = crate::audit::types::EatpAuthority(serde_json::json!({
            "multi_sig": {
                "threshold": 2u64,
                "roster_size": 2u64,
                "authorizations": [first_auth.clone(), first_auth],
            }
        }));

        let record = make_record(chain_id, EventKind::KeyRotate, payload, Some(authority_dup));
        let result = verify_record_multi_sig(&record, None);
        assert!(
            result.is_err(),
            "duplicate signer pubkey in multi_sig MUST be rejected"
        );
        match result.unwrap_err() {
            MultiSigError::MalformedAuthorityBlob(msg) => {
                assert!(
                    msg.contains("duplicate"),
                    "error must mention duplicate: got {msg}"
                );
            }
            other => panic!(
                "expected MalformedAuthorityBlob(duplicate), got {:?}",
                other
            ),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc_name, chain_id);
    }

    /// OBS-1 / SEC-5: a blob whose `roster_size` is SMALLER than the number of
    /// authorizations it carries is nonsensical and MUST be rejected as malformed.
    /// This exercises the reject side of the SEC-5 consistency guard (the existing
    /// blob tests only cover the pass side, where roster_size >= authorizations.len()).
    #[test]
    fn test_verify_rejects_roster_size_smaller_than_authorizations() {
        use crate::audit::types::EatpAuthority;
        use serde_json::json;
        // roster_size: 1, but two authorization entries → 2 > 1 → reject.
        // (The roster_size guard runs BEFORE per-entry parsing, so the entry
        // contents only need to form a 2-element array.)
        let authority = Some(EatpAuthority(json!({
            "multi_sig": {
                "threshold": 1u64,
                "roster_size": 1u64,
                "authorizations": [
                    { "signer_pubkey": "aa".repeat(32), "signature": "bb".repeat(64) },
                    { "signer_pubkey": "cc".repeat(32), "signature": "dd".repeat(64) }
                ]
            }
        })));
        let record = make_record(
            TEST_CHAIN_ID,
            EventKind::KeyRotate,
            key_rotate_payload(),
            authority,
        );
        let result = verify_record_multi_sig(&record, None);
        assert!(
            result.is_err(),
            "roster_size smaller than authorizations.len() must be rejected"
        );
        match result.unwrap_err() {
            MultiSigError::MalformedAuthorityBlob(msg) => assert!(
                msg.contains("roster_size"),
                "error must mention roster_size: got {msg}"
            ),
            other => panic!("expected MalformedAuthorityBlob(roster_size), got {other:?}"),
        }
    }

    /// AC-7: malformed authority blob (missing threshold field) is REJECTED.
    #[test]
    fn test_verify_malformed_blob_missing_threshold_rejected() {
        use crate::audit::types::EatpAuthority;
        use serde_json::json;
        let authority = Some(EatpAuthority(json!({
            "multi_sig": {
                "roster_size": 1,
                "authorizations": []
            }
        })));
        let record = make_record(
            TEST_CHAIN_ID,
            EventKind::KeyRotate,
            key_rotate_payload(),
            authority,
        );
        let result = verify_record_multi_sig(&record, None);
        assert!(result.is_err(), "missing threshold must be rejected");
        assert!(
            matches!(
                result.unwrap_err(),
                MultiSigError::MalformedAuthorityBlob(_)
            ),
            "should be MalformedAuthorityBlob"
        );
    }

    /// AC-7: malformed authority blob (bad pubkey hex) is REJECTED.
    #[test]
    fn test_verify_malformed_blob_bad_pubkey_hex_rejected() {
        use crate::audit::types::EatpAuthority;
        use serde_json::json;
        let authority = Some(EatpAuthority(json!({
            "multi_sig": {
                "threshold": 1,
                "roster_size": 1,
                "authorizations": [
                    { "signer_pubkey": "not-hex", "signature": "a".repeat(128) }
                ]
            }
        })));
        let record = make_record(
            TEST_CHAIN_ID,
            EventKind::KeyRotate,
            key_rotate_payload(),
            authority,
        );
        let result = verify_record_multi_sig(&record, None);
        assert!(result.is_err(), "bad pubkey hex must be rejected");
    }
}
