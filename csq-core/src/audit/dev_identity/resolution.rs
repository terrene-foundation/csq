//! M17 — Per-developer identity resolution.
//!
//! Resolves a claimed principal to an `Enrolled{key, pubkey}` variant
//! when the principal is in the enrollment table AND the private key can be
//! loaded from the OS keychain. Any other case resolves to `Unbacked`.
//!
//! # CRITICAL-2 invariant
//!
//! `resolve_developer` NEVER returns or uses the chain/model credential.
//! An unenrolled principal OR a principal whose keychain entry is missing
//! resolves to `Unbacked` — NOT to any fallback key.

use std::path::Path;

use ed25519_dalek::SigningKey as DalekSigningKey;
use zeroize::Zeroizing;

use crate::audit::types::Ed25519PublicKey;

use super::enrollment::{dev_signing_service, EnrollmentTable, Principal};
use super::error::DevIdentityError;

/// The result of resolving a claimed developer principal.
#[derive(Debug)]
pub enum DevResolution {
    /// The principal is enrolled and the private key is accessible in the
    /// OS keychain. Carries the loaded signing key and the enrolled pubkey.
    ///
    /// The key is boxed to reduce the enum variant size difference (the
    /// `DalekSigningKey` expanded scalar is large; `Unbacked` is zero-sized).
    Enrolled {
        /// The loaded Ed25519 signing key (in-memory; never returned to disk).
        key: Box<DalekSigningKey>,
        /// The enrolled public key (from the enrollment table on disk).
        pubkey: Ed25519PublicKey,
    },
    /// The principal is not enrolled, or the keychain entry is missing.
    ///
    /// Callers MUST treat this as fail-closed — do NOT fall back to any
    /// model credential or default identity.
    Unbacked,
}

/// Resolve a claimed principal to an enrolled key or `Unbacked`.
///
/// Resolution logic:
/// 1. Load the enrollment table from `<base>/audit/dev-enrollment.json`.
/// 2. Look up `claimed_principal` in the table.
/// 3. If found: attempt to load the private key from the OS keychain.
/// 4. If the key loads successfully: `Enrolled`.
/// 5. Any other case (not enrolled, keychain miss, key corrupt): `Unbacked`.
///
/// # CRITICAL-2 invariant
///
/// This function MUST NEVER return the chain/model signing key as a fallback.
/// The model credential is org-level model access, not developer identity.
/// Unenrolled or unresolvable principals MUST produce `Unbacked`.
pub fn resolve_developer(base: &Path, claimed_principal: &Principal) -> DevResolution {
    // Load enrollment table; any error → Unbacked (fail-closed).
    let table = match EnrollmentTable::load(base) {
        Ok(t) => t,
        Err(_) => return DevResolution::Unbacked,
    };

    // Look up the claimed principal.
    let entry = match table.entries.get(claimed_principal.as_str()) {
        Some(e) => e,
        None => return DevResolution::Unbacked,
    };

    let pubkey = entry.enrolled_pubkey;

    // Attempt to load the private key from the OS keychain.
    let service = dev_signing_service(claimed_principal);
    let key = match load_dev_signing_key(&service, claimed_principal.as_str()) {
        Ok(k) => k,
        Err(_) => return DevResolution::Unbacked,
    };

    DevResolution::Enrolled {
        key: Box::new(key),
        pubkey,
    }
}

/// Load an Ed25519 signing key from the OS keychain.
///
/// Returns the `DalekSigningKey` loaded from the stored 32-byte hex seed.
/// The seed hex is wrapped in `Zeroizing<String>` to ensure it is zeroed
/// immediately after the key is constructed.
fn load_dev_signing_key(service: &str, account: &str) -> Result<DalekSigningKey, DevIdentityError> {
    let entry = crate::audit::key_custody::keyring_entry(service, account)
        .map_err(|_| DevIdentityError::Keychain("entry"))?;
    let raw: Zeroizing<String> = Zeroizing::new(
        entry
            .get_password()
            .map_err(|_| DevIdentityError::Keychain("get"))?,
    );

    let seed_bytes = Zeroizing::new(
        hex::decode(raw.as_str())
            .map_err(|_| DevIdentityError::KeyGen("seed hex decode failed"))?,
    );

    if seed_bytes.len() != 32 {
        return Err(DevIdentityError::KeyGen("seed wrong length"));
    }

    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seed_bytes);
    Ok(DalekSigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::dev_identity::enrollment::{enroll_developer, Granularity};
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn unique_principal(tag: &str) -> Principal {
        let pid = std::process::id();
        let s = format!("resolution-{tag}-{pid}@example.com");
        Principal::new(s).unwrap()
    }

    /// Resolution-layer test: unenrolled principal → Unbacked (never model-key).
    #[test]
    fn test_resolve_unenrolled_yields_unbacked() {
        init_mock_keyring();
        let dir = tmp();
        // Use a principal that is guaranteed not enrolled in this test's tempdir.
        let p = unique_principal("ghost");
        let result = resolve_developer(dir.path(), &p);
        assert!(
            matches!(result, DevResolution::Unbacked),
            "unenrolled principal MUST resolve to Unbacked (CRITICAL-2)"
        );
    }

    /// Resolution-layer test: enrolled principal → Enrolled variant with key + pubkey.
    #[test]
    fn test_resolve_enrolled_returns_key_and_pubkey() {
        init_mock_keyring();
        let dir = tmp();
        let p = unique_principal("alice");

        enroll_developer(dir.path(), p.clone(), Granularity::default(), |_| true)
            .expect("enroll ok");

        let result = resolve_developer(dir.path(), &p);
        assert!(
            matches!(result, DevResolution::Enrolled { .. }),
            "enrolled principal MUST resolve to Enrolled"
        );
    }
}
