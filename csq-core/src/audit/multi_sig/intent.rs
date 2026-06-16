//! M11 — Intent-hash derivation for multi-sig authorization.
//!
//! Each multi-sig authorization signs an **intent hash**: the SHA-256 of the
//! canonical serialization of `(chain_id, EventKind, EventPayload)`. This is
//! the "canonical intent record" the milestone names.
//!
//! # Why intent hash, not the record's canonical_hash
//!
//! The record's `canonical_hash` covers the `authority` slot — which
//! CONTAINS the multi-sig signatures. Signing `canonical_hash` would be
//! circular (the authority blob must be known to compute canonical_hash, but
//! the authority blob contains the signatures which in turn require the hash).
//!
//! The intent hash binds to `(chain_id, kind, payload)` — exactly what signers
//! are authorizing: "I authorize this KeyRotate on chain X with these
//! previous/new key ids" or "I authorize this ReleaseAuth on chain X for
//! this release tag and artifact SHA-256".
//!
//! Binding `chain_id` closes cross-chain replay: a valid multi-sig
//! authorization for chain A cannot satisfy a threshold check on chain B,
//! even if both chains contain records with identical (kind, payload).
//!
//! `seq`, `record_id`, and `ts` are EXCLUDED from the pre-image because they
//! are assigned by the writer at commit time — after the authorization is
//! collected. Excluding them allows the same authorization to be collected
//! before the writer assigns those fields. Same-(chain_id, kind, payload)
//! authorizations therefore remain interchangeable, which is acceptable because
//! the OUTER record signature (over canonical_hash) commits to seq, prev_hash,
//! record_id, and ts — uniquely binding the authorization to one physical
//! record on disk.
//!
//! The outer record signature (over canonical_hash) then covers the authority
//! blob as a whole, providing cryptographic commitment to the full multi-sig
//! blob on-chain.
//!
//! # Determinism
//!
//! `serde_json::to_vec` on a fixed-field `#[derive(Serialize)]` struct with
//! no `HashMap` fields is deterministic (field order follows declaration order
//! per serde derive). Both `EventKind` and all `EventPayload` variants satisfy
//! this property.

use serde::Serialize;

use crate::audit::types::{EventKind, EventPayload};

/// The view serialized to produce the intent hash pre-image.
///
/// Binds to `(chain_id, kind, payload)`. `seq`, `record_id`, and `ts` are
/// excluded because they are assigned after authorization is collected.
///
/// # Note on `kind` redundancy
///
/// `EventPayload` uses `#[serde(tag="kind")]`, so `kind` also appears inside
/// the serialized payload. The outer `kind` field is kept here for
/// explicitness — signers authorizing a `KeyRotate` can see the discriminant
/// in the pre-image without parsing the inner payload.
#[derive(Serialize)]
struct IntentView<'a> {
    chain_id: &'a str,
    kind: &'a EventKind,
    payload: &'a EventPayload,
}

/// Compute the intent hash pre-image bytes for `(chain_id, kind, payload)`.
///
/// Returns the raw JSON bytes that, when SHA-256'd, produce the intent hash.
/// Exposed for tests that want to inspect the pre-image.
#[cfg(any(test, feature = "test-utils"))]
pub fn intent_bytes_test(chain_id: &str, kind: &EventKind, payload: &EventPayload) -> Vec<u8> {
    intent_bytes(chain_id, kind, payload)
}

/// Compute the intent pre-image bytes (private, used internally).
pub(super) fn intent_bytes(chain_id: &str, kind: &EventKind, payload: &EventPayload) -> Vec<u8> {
    let view = IntentView {
        chain_id,
        kind,
        payload,
    };
    // Serialization of a fixed-field struct over serde_json::Value variants
    // (EventPayload is a typed enum) cannot fail under normal allocator
    // conditions. A failure here would indicate OOM, at which point the audit
    // pipeline cannot continue — same reasoning as persist.rs canonical_bytes_for.
    serde_json::to_vec(&view)
        .expect("IntentView serialization must not fail on valid chain_id/EventKind/EventPayload")
}

/// Compute the 32-byte SHA-256 intent hash for `(chain_id, kind, payload)`.
///
/// This is the value each authorizing signer signs. The verifier independently
/// re-derives it from `record.chain_id` + `record.kind` + `record.payload`
/// to verify inner authorization signatures.
/// Public under `test-utils` feature (or within the crate) so cross-crate
/// tests can compute the intent hash for constructing test authority blobs
/// without needing a real `LocalSigningKey`. Production code calls `authorize_op`.
#[cfg(any(test, feature = "test-utils"))]
pub fn intent_hash(chain_id: &str, kind: &EventKind, payload: &EventPayload) -> [u8; 32] {
    let bytes = intent_bytes(chain_id, kind, payload);
    sha256_32(&bytes)
}

/// Crate-private version used by `verify.rs` and `gate.rs` in production paths.
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) fn intent_hash(chain_id: &str, kind: &EventKind, payload: &EventPayload) -> [u8; 32] {
    let bytes = intent_bytes(chain_id, kind, payload);
    sha256_32(&bytes)
}

/// SHA-256 producing 32 raw bytes.
///
/// Uses the `sha2` crate (already a csq-core dependency via persist.rs).
/// Exposed as `pub(crate)` so `gate.rs` and `verify.rs` can call it without
/// re-importing sha2 directly.
pub(crate) fn sha256_32(input: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{
        Ed25519PublicKey, EventPayload, KeyId, KeyRotatePayload, ReleaseAuthPayload,
        RotationReason, Sha256Hex,
    };

    fn sample_key_rotate_payload() -> EventPayload {
        EventPayload::KeyRotate(KeyRotatePayload {
            previous_key_id: KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).unwrap(),
            new_key_id: KeyId::try_new(format!("ed25519:{}", "b".repeat(64))).unwrap(),
            incoming_pubkey: Ed25519PublicKey([1u8; 32]),
            rotation_reason: RotationReason::Operator,
        })
    }

    fn sample_release_auth_payload() -> EventPayload {
        EventPayload::ReleaseAuth(ReleaseAuthPayload {
            release_tag: "v2.0.0".to_string(),
            artifact_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
        })
    }

    const CHAIN_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";
    const CHAIN_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA1";

    /// intent_hash is deterministic: same inputs produce same bytes.
    #[test]
    fn test_intent_hash_deterministic() {
        let payload = sample_key_rotate_payload();
        let h1 = intent_hash(CHAIN_A, &EventKind::KeyRotate, &payload);
        let h2 = intent_hash(CHAIN_A, &EventKind::KeyRotate, &payload);
        assert_eq!(h1, h2, "intent_hash must be deterministic");
    }

    /// intent_hash differs across EventKind values (kind is part of the pre-image).
    #[test]
    fn test_intent_hash_differs_by_kind() {
        // ReleaseAuth vs IdentityMint carry different payload types, but we can
        // compare KeyRotate vs ReleaseAuth trivially.
        let kp = sample_key_rotate_payload();
        let rp = sample_release_auth_payload();

        let h_kp = intent_hash(CHAIN_A, &EventKind::KeyRotate, &kp);
        let h_rp = intent_hash(CHAIN_A, &EventKind::ReleaseAuth, &rp);
        assert_ne!(
            h_kp, h_rp,
            "different (kind, payload) must produce different hashes"
        );
    }

    /// intent_hash differs when payload fields differ.
    #[test]
    fn test_intent_hash_differs_by_payload() {
        let p1 = EventPayload::ReleaseAuth(ReleaseAuthPayload {
            release_tag: "v1.0.0".to_string(),
            artifact_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
        });
        let p2 = EventPayload::ReleaseAuth(ReleaseAuthPayload {
            release_tag: "v2.0.0".to_string(),
            artifact_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
        });
        let h1 = intent_hash(CHAIN_A, &EventKind::ReleaseAuth, &p1);
        let h2 = intent_hash(CHAIN_A, &EventKind::ReleaseAuth, &p2);
        assert_ne!(
            h1, h2,
            "different release tags must produce different hashes"
        );
    }

    /// intent_hash differs across chain_ids (SEC-3: cross-chain replay prevention).
    #[test]
    fn test_intent_hash_differs_by_chain_id() {
        let payload = sample_key_rotate_payload();
        let h_a = intent_hash(CHAIN_A, &EventKind::KeyRotate, &payload);
        let h_b = intent_hash(CHAIN_B, &EventKind::KeyRotate, &payload);
        assert_ne!(
            h_a, h_b,
            "identical (kind, payload) on different chain_ids MUST produce different intent hashes"
        );
    }

    /// sha256_32 produces 32 bytes and is consistent with hex encoding.
    #[test]
    fn test_sha256_32_len() {
        let result = sha256_32(b"test input");
        assert_eq!(result.len(), 32, "sha256_32 must produce 32 bytes");
    }
}
