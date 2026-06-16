//! M17 — Challenge-response proof of key control.
//!
//! Implements:
//! - `prove_control`: signs `[nonce || event_hash]` with the developer's
//!   enrolled Ed25519 private key. Nonce-bound — each proof is unique.
//! - `verify_control`: verifies the proof against the enrolled public key
//!   using `VerifyingKey::verify_strict`. Returns `true` iff valid.
//!
//! # Replay defense (HIGH-2 mitigation)
//!
//! The proof signs over `[nonce || event_hash]` where the nonce is
//! CSPRNG-generated and single-use (issued by `attest_authorship`).
//! A captured proof cannot be replayed because it is bound to a specific
//! nonce. Callers MUST use a fresh 32-byte nonce for every attestation.
//!
//! # Why `verify_strict`
//!
//! `VerifyingKey::verify_strict` runs cofactor-check and rejects
//! non-canonical encodings. It is the correct primitive for signature
//! verification in a security-critical context (per ed25519-dalek docs).

use ed25519_dalek::{Signer, VerifyingKey};

use crate::audit::types::{Ed25519PublicKey, Ed25519Signature};

use super::error::DevIdentityError;

/// Prove control of an enrolled Ed25519 key by signing `[nonce || event_hash]`.
///
/// `dev_key` is the Ed25519 signing key for the enrolled developer (obtained
/// via `DevResolution::Enrolled { key, .. }`).
///
/// Returns the signature over `[nonce || event_hash]`.
pub fn prove_control(
    dev_key: &ed25519_dalek::SigningKey,
    nonce: &[u8; 32],
    event_hash: &[u8],
) -> Ed25519Signature {
    let mut message = Vec::with_capacity(32 + event_hash.len());
    message.extend_from_slice(nonce);
    message.extend_from_slice(event_hash);
    let sig = dev_key.sign(&message);
    Ed25519Signature(sig.to_bytes())
}

/// Verify a challenge-response proof.
///
/// Returns `true` iff `proof` is a valid Ed25519 signature over
/// `[nonce || event_hash]` by the key whose public bytes are `pubkey`.
///
/// Returns `false` (not `Err`) for invalid signatures — the caller
/// (`attest_authorship`) interprets `false` as `backing: unbacked`.
///
/// # Errors
///
/// Returns `Err(DevIdentityError::ProofInvalid)` only when `pubkey` bytes
/// are not a valid Ed25519 point (corrupt enrollment table). A bad signature
/// over a valid key returns `Ok(false)`.
pub fn verify_control(
    pubkey: &Ed25519PublicKey,
    nonce: &[u8; 32],
    event_hash: &[u8],
    proof: &Ed25519Signature,
) -> Result<bool, DevIdentityError> {
    let verifying =
        VerifyingKey::from_bytes(&pubkey.0).map_err(|_| DevIdentityError::ProofInvalid)?;
    let mut message = Vec::with_capacity(32 + event_hash.len());
    message.extend_from_slice(nonce);
    message.extend_from_slice(event_hash);
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&proof.0);
    Ok(verifying.verify_strict(&message, &dalek_sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::dev_identity::enrollment::{enroll_developer, Granularity, Principal};
    use crate::audit::dev_identity::resolution::{resolve_developer, DevResolution};
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn fresh_nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        getrandom::getrandom(&mut n).unwrap();
        n
    }

    /// Returns a process-unique principal to avoid keychain key collisions between
    /// concurrent tests that share the process-global mock keyring.
    fn unique_principal(tag: &str) -> Principal {
        let pid = std::process::id();
        let p = format!("challenge-test-{tag}-{pid}@example.com");
        Principal::new(p).unwrap()
    }

    #[test]
    fn test_challenge_response_binds_nonce() {
        init_mock_keyring();
        let dir = tmp();
        let p = unique_principal("nonce");
        enroll_developer(dir.path(), p.clone(), Granularity::default(), |_| true)
            .expect("enroll ok");

        let DevResolution::Enrolled { key, pubkey } = resolve_developer(dir.path(), &p) else {
            panic!("expected Enrolled");
        };
        let key = *key;

        let nonce_a = fresh_nonce();
        let nonce_b = fresh_nonce();
        let event_hash = b"test-event-hash-32-bytes-exactly";

        let proof_a = prove_control(&key, &nonce_a, event_hash);

        // Verify with matching nonce → true.
        assert!(
            verify_control(&pubkey, &nonce_a, event_hash, &proof_a).unwrap(),
            "proof signed with nonce_a must verify with nonce_a"
        );

        // Verify with different nonce → false (replay defense).
        let different = verify_control(&pubkey, &nonce_b, event_hash, &proof_a).unwrap();
        assert!(
            !different,
            "proof signed with nonce_a MUST NOT verify with nonce_b (nonce-binding)"
        );
    }

    #[test]
    fn test_spoofed_payload_identity_without_key_control_rejected() {
        init_mock_keyring();
        let dir = tmp();

        // Use unique principals per test to avoid keychain state collisions.
        let p_alice = unique_principal("spoof-alice");
        let p_bob = unique_principal("spoof-bob");

        // Enroll alice.
        enroll_developer(dir.path(), p_alice.clone(), Granularity::default(), |_| {
            true
        })
        .expect("enroll alice");

        let DevResolution::Enrolled {
            key: alice_key_boxed,
            pubkey: alice_pubkey,
        } = resolve_developer(dir.path(), &p_alice)
        else {
            panic!("expected Enrolled for alice");
        };
        let alice_key = *alice_key_boxed;

        // Enroll bob.
        enroll_developer(dir.path(), p_bob.clone(), Granularity::default(), |_| true)
            .expect("enroll bob");

        let DevResolution::Enrolled {
            pubkey: bob_pubkey, ..
        } = resolve_developer(dir.path(), &p_bob)
        else {
            panic!("expected Enrolled for bob");
        };

        // Alice signs a proof — then attempts to verify it against bob's pubkey.
        let nonce = fresh_nonce();
        let event_hash = b"approve-release";
        let alice_proof = prove_control(&alice_key, &nonce, event_hash);

        // alice_proof is NOT valid for bob's key (identity spoofing rejected).
        let valid_for_bob = verify_control(&bob_pubkey, &nonce, event_hash, &alice_proof).unwrap();
        assert!(
            !valid_for_bob,
            "alice's proof MUST NOT verify with bob's public key (spoofed identity rejected)"
        );

        // But alice_proof IS valid for alice's key.
        let valid_for_alice =
            verify_control(&alice_pubkey, &nonce, event_hash, &alice_proof).unwrap();
        assert!(
            valid_for_alice,
            "alice's proof MUST verify with alice's own public key"
        );
    }
}
