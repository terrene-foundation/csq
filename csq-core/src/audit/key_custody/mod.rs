//! M04 — local Ed25519 signing-key generation and OS keychain custody.
//!
//! This module provides the complete M04 surface:
//!
//! - [`LocalSigningKey`] — concrete `SigningKey` impl wrapping a
//!   `Zeroizing<ed25519_dalek::SigningKey>` loaded from / stored to the OS
//!   keychain via the `keyring` crate.
//! - [`ChainState`] — extends `chain.json` with `signing_key_id` and `pubkey`
//!   fields; writes use the `unique_tmp_path → write → secure_file →
//!   atomic_replace` pipeline with §5a tmp cleanup on every failure branch.
//! - [`audit_init`] — idempotent key initialisation; no-op when the key is
//!   already present in the keychain.
//! - [`rotate_key`] — generates a fresh keypair, writes a `KeyRotate` audit
//!   record signed by the outgoing key, and updates `chain.json`.
//! - [`check_signing_key`] / [`SigningKeyStatus`] — `csq doctor` integration;
//!   returns `Present` or `Absent` without leaking key material.
//!
//! # PRIMARY METHODOLOGICAL DIRECTIVE (M04, amended for file-based custody)
//!
//! **Primary custody is the 0o600 file store at `csq-runs/keys/`** (see
//! [`file_store`]). The OS keychain is retained as a **migration source +
//! read fallback + integrity anchor**, NOT the primary store — the daemon
//! cannot read the keychain non-interactively (the brick root cause), so the
//! file store is the daemon-readable channel.
//!
//! WHEN the OS keychain IS accessed (fallback read, migration read, anchor
//! cross-check, init/rotate anchor write), ALL keychain I/O MUST go through the
//! `keyring` crate. `security-framework`, `secret-service`, and `windows-rs`
//! remain BLOCKED in this module — hand-rolled native keychain FFI is never
//! permitted. File I/O via `platform::fs` is NOT keychain access and is the
//! primary path. The audit primitive (the anti-native-FFI intent is unchanged):
//!
//! ```bash
//! grep -rn 'security-framework\|secret-service\|windows.*credential' \
//!     csq-core/src/audit/key_custody/ --include='*.rs' | grep -v test
//! # Expected: 0 matches
//! ```
//!
//! # PRIMARY METHODOLOGICAL DIRECTIVE (Zeroize)
//!
//! The private key MUST live inside `Zeroizing<ed25519_dalek::SigningKey>`.
//! A raw `Vec<u8>` or `[u8; 32]` for private-key bytes is BLOCKED.
//!
//! # PRIMARY METHODOLOGICAL DIRECTIVE (§5a)
//!
//! Every `chain.json` write that carries `signing_key_id` or `pubkey` is a
//! `rules/security.md §5a` site. Use `unique_tmp_path → write → secure_file →
//! atomic_replace` with `remove_file(&tmp)` on every failure branch.

pub(crate) mod chain_state;
pub(crate) mod doctor;
pub(crate) mod file_store;
pub(crate) mod init;
pub(crate) mod keyring_backend;
pub(crate) mod migrate;
pub(crate) mod rotate;

pub use chain_state::ChainState;
pub use doctor::{check_signing_key, SigningKeyStatus};
pub use file_store::KeySlot;
pub use init::audit_init;
pub use keyring_backend::{
    delete_dual, exists_any, generate_and_store_dual, is_keychain_access_error,
    load_embedded_cutoff, load_embedded_cutoff_file_first, preserve_dual, store_dual,
    try_load_signing_key, write_roster_floor_to_keychain, EmbeddedCutoff, KeyLoadOutcome,
    LocalSigningKey, SERVICE_NAME,
};
pub use migrate::{migrate_keys_to_file_store, repair_audit_chain, MigrateOutcome, RepairOutcome};
pub use rotate::rotate_key;

use thiserror::Error;

/// Sole constructor for OS-keyring entries across the workspace (production
/// AND tests) — pinned by `csq-core/tests/keyring_isolation.rs`.
///
/// Under `cfg(test)` or the `test-utils` feature the process-global in-memory
/// mock store is installed before the first entry is created, so no test
/// binary can ever reach the operator's real OS keychain. Unsigned cargo test
/// binaries triggering real-keychain access produce a macOS authorization
/// prompt per rebuild per access ("unknown" binary) — the 2026-06-11
/// prompt-spam incident. Production builds compile the mock branch out.
pub(crate) fn keyring_entry(
    service: &str,
    account: &str,
) -> Result<keyring::Entry, keyring::Error> {
    #[cfg(any(test, feature = "test-utils"))]
    test_helpers::init_mock_keyring();
    keyring::Entry::new(service, account)
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) mod test_helpers {
    //! Process-global test setup for keyring-backed key-custody tests.
    //!
    //! # Why a custom backend
    //!
    //! `keyring` v3 on Linux without `linux-native-*` features attempts the
    //! `secret-service` D-Bus backend; headless CI runners (GitHub Actions
    //! ubuntu-latest) have no D-Bus session, so `Entry::get_password` returns
    //! `Keychain("No matching entry found in secure storage")` even after a
    //! successful `set_password` — the writes go to nothing.
    //!
    //! `keyring::mock::default_credential_builder()` does NOT solve this
    //! either: keyring v3's stock mock stores the password inside the
    //! `MockCredential` instance, so two `Entry::new(svc, acct)` calls
    //! produce two separate credentials and the second never sees the first's
    //! `set_password`. Our production code calls `Entry::new` once per
    //! operation (set, get, delete) — fundamentally incompatible with
    //! per-entry mock state.
    //!
    //! # Solution
    //!
    //! `InMemoryStoreBuilder` is a custom `CredentialBuilderApi` that hands
    //! out lightweight `InMemoryCredential` handles. All handles read from /
    //! write to a process-global `HashMap<(service, user), Vec<u8>>` behind
    //! a `Mutex` — `Entry::new("svc", "acct").set_password(p)` followed by
    //! `Entry::new("svc", "acct").get_password()` returns `p` because both
    //! handles resolve the same `(svc, acct)` key in the shared map.
    //!
    //! `keyring::set_default_credential_builder` is process-global; wrap in
    //! `Once` so concurrent test threads cooperate.
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::{Mutex, Once, OnceLock};

    use keyring::credential::{
        Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialPersistence,
    };
    use keyring::Error as KeyringError;

    type Store = Mutex<HashMap<(String, String), Vec<u8>>>;

    fn shared_store() -> &'static Store {
        static STORE: OnceLock<Store> = OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    #[derive(Debug)]
    struct InMemoryCredential {
        service: String,
        user: String,
    }

    impl CredentialApi for InMemoryCredential {
        fn set_secret(&self, secret: &[u8]) -> Result<(), KeyringError> {
            shared_store()
                .lock()
                .unwrap()
                .insert((self.service.clone(), self.user.clone()), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> Result<Vec<u8>, KeyringError> {
            shared_store()
                .lock()
                .unwrap()
                .get(&(self.service.clone(), self.user.clone()))
                .cloned()
                .ok_or(KeyringError::NoEntry)
        }

        fn delete_credential(&self) -> Result<(), KeyringError> {
            let mut map = shared_store().lock().unwrap();
            if map
                .remove(&(self.service.clone(), self.user.clone()))
                .is_some()
            {
                Ok(())
            } else {
                Err(KeyringError::NoEntry)
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Debug)]
    struct InMemoryStoreBuilder;

    impl CredentialBuilderApi for InMemoryStoreBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            service: &str,
            user: &str,
        ) -> Result<Box<Credential>, KeyringError> {
            Ok(Box::new(InMemoryCredential {
                service: service.to_string(),
                user: user.to_string(),
            }))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::ProcessOnly
        }
    }

    /// Install the in-memory shared-store keyring backend for the lifetime
    /// of the test binary. Idempotent; safe to call from every `#[test]`
    /// that exercises [`crate::audit::key_custody`].
    pub fn init_mock_keyring() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let builder: Box<CredentialBuilder> = Box::new(InMemoryStoreBuilder);
            keyring::set_default_credential_builder(builder);
        });
    }
}

/// Errors that can arise from M04 key-custody operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeyCustodyError {
    /// The OS keychain backend returned an error.
    ///
    /// H-13: typed `#[from] keyring::Error` instead of `String` so the
    /// compiler catches missing `?`-conversions on new keyring callsites and
    /// the full structured error is preserved for diagnostics.
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring::Error),

    /// The stored key bytes could not be parsed as a valid Ed25519 signing key.
    #[error("key bytes corrupt or invalid: {0}")]
    KeyCorrupt(String),

    /// A `chain.json` read or write failed.
    #[error("chain.json I/O error: {0}")]
    ChainIo(String),

    /// `chain.json` content could not be parsed.
    #[error("chain.json parse error: {0}")]
    ChainParse(String),

    /// The signing operation itself failed.
    #[error("signing error: {0}")]
    Signing(String),

    /// Rotation failed because there is no existing key to rotate from.
    #[error("no existing key to rotate — run `csq audit init` first")]
    NoKeyToRotate,

    /// The `base_dir` path does not exist or is not a directory.
    #[error("base directory does not exist or is not a directory: {0}")]
    BaseDirMissing(String),
}
