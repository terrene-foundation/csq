//! an internal ticket — shared Ed25519 signing seam for roster authoring.
//!
//! This is the single production home for "sign raw bytes with an Ed25519
//! secret key, return lowercase hex". Both the roster-signing CLI verb
//! (`csq audit roster-sign`) and the roster test helpers route through it, so
//! the sign side and the verify side (`roster::verify_signed_roster` /
//! `roster::verify_detached_roster`) never drift.
//!
//! The output is a 128-char lowercase hex encoding of the 64-byte Ed25519
//! signature over `data`, verifiable with `VerifyingKey::verify_strict`.
//!
//! # Secret custody
//!
//! This function consumes a `SigningKey` reference — it never reads, writes,
//! logs, or prints the secret seed. The caller owns key material lifetime and
//! is responsible for zeroization / 0o600 file custody (see the CLI layer).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::audit::types::Ed25519PublicKey;

/// Sign `data` with `sk` and return the lowercase-hex Ed25519 signature.
///
/// The returned string is 128 hex chars (64 signature bytes). It verifies with
/// `VerifyingKey::from_bytes(&sk.verifying_key().to_bytes()).verify_strict(data, &sig)`.
///
/// This seam is byte-compatible with both roster verification paths:
/// - Embedded (`SignedRoster`): `data` is the canonical `serde_json::to_vec(&roster)`.
/// - Detached (`UnsignedRosterFile` + `.sig`): `data` is the RAW stored file bytes.
pub fn sign_raw_bytes(sk: &SigningKey, data: &[u8]) -> String {
    hex::encode(sk.sign(data).to_bytes())
}

/// Construct an Ed25519 signing key from a raw 32-byte seed.
///
/// Centralizes `ed25519_dalek::SigningKey` construction so the CLI layer never
/// depends on `ed25519-dalek` directly (the crypto seam lives here).
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Return the 32-byte public key for a signing key, as `Ed25519PublicKey`.
pub fn public_key_of(sk: &SigningKey) -> Ed25519PublicKey {
    Ed25519PublicKey(sk.verifying_key().to_bytes())
}

/// Generate a fresh Ed25519 keypair using the OS CSPRNG (`getrandom`).
///
/// Returns `(seed, public_key)`. The 32-byte seed is the SECRET — the caller is
/// responsible for its custody (0o600 file, offline backup) and MUST NOT print
/// or log it. Returns `Err(())` if entropy could not be gathered.
#[allow(clippy::result_unit_err)]
pub fn generate_keypair() -> Result<([u8; 32], Ed25519PublicKey), ()> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| ())?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = Ed25519PublicKey(sk.verifying_key().to_bytes());
    Ok((seed, pk))
}

/// Sign `data` with a raw 32-byte seed, returning the lowercase-hex signature.
///
/// Convenience over `signing_key_from_seed` + `sign_raw_bytes` so callers that
/// hold only a seed (e.g. the CLI, which reads a 0o600 secret file) never need
/// to name the `ed25519_dalek::SigningKey` type.
pub fn sign_raw_bytes_with_seed(seed: &[u8; 32], data: &[u8]) -> String {
    sign_raw_bytes(&SigningKey::from_bytes(seed), data)
}

/// Return the `Ed25519PublicKey` for a raw 32-byte seed.
pub fn public_key_of_seed(seed: &[u8; 32]) -> Ed25519PublicKey {
    Ed25519PublicKey(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Verify a hex-encoded Ed25519 signature over `data` with a 32-byte public key.
///
/// Uses `verify_strict` (matches the roster verification paths). Returns
/// `Ok(true)` on a valid signature, `Ok(false)` on a valid-length-but-failing
/// signature, and `Err(())` if `pubkey`/`sig_hex` are malformed.
#[allow(clippy::result_unit_err)]
pub fn verify_hex_signature(pubkey: &[u8; 32], data: &[u8], sig_hex: &str) -> Result<bool, ()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| ())?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|_| ())?;
    if sig_bytes.len() != 64 {
        return Err(());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    Ok(vk.verify_strict(data, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    fn gen_sk() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom");
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn sign_raw_bytes_output_verifies_with_verify_strict() {
        let sk = gen_sk();
        let vk: VerifyingKey = sk.verifying_key();
        let data = b"issue-790 roster authoring seam";

        let hex_sig = sign_raw_bytes(&sk, data);
        assert_eq!(hex_sig.len(), 128, "64-byte sig hex is 128 chars");

        let sig_bytes = hex::decode(&hex_sig).expect("valid hex");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&arr);

        assert!(
            vk.verify_strict(data, &sig).is_ok(),
            "sign_raw_bytes output must verify with verify_strict"
        );
    }

    #[test]
    fn tampered_data_fails_verify() {
        let sk = gen_sk();
        let vk: VerifyingKey = sk.verifying_key();
        let hex_sig = sign_raw_bytes(&sk, b"original");

        let sig_bytes = hex::decode(&hex_sig).expect("valid hex");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&arr);

        assert!(
            vk.verify_strict(b"tampered", &sig).is_err(),
            "signature over 'original' must not verify 'tampered'"
        );
    }

    #[test]
    fn deterministic_for_same_key_and_data() {
        // Ed25519 (RFC 8032) is deterministic: same key + data → same signature.
        let sk = gen_sk();
        let a = sign_raw_bytes(&sk, b"same-input");
        let b = sign_raw_bytes(&sk, b"same-input");
        assert_eq!(a, b, "Ed25519 signatures are deterministic");
    }
}
