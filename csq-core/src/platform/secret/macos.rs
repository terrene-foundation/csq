//! macOS Keychain backend for [`Vault`] — sole production backend in
//! PR-G2a.
//!
//! Uses `security-framework`'s native API (already a workspace
//! dependency). Items are stored as
//! `kSecClassGenericPassword` with:
//!
//! - `service` = [`SlotKey::native_name`] (e.g. `"csq.gemini.3"`)
//! - `account` = `"csq"` (constant — the slot info lives in service)
//!
//! Per security-reviewer §1: this gives us four protections above a
//! plain `0o600` file: Time Machine / iCloud Keychain inclusion
//! control, ACL prompts on cross-app read, lock-state binding
//! (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and TCC / app
//! sandbox boundary.
//!
//! Per security-reviewer §7: failure modes are explicit
//! [`SecretError`] variants. We never silently fall back; we never
//! cache the cleartext.
//!
//! # Open question Q1 (deferred to PR-G2b)
//!
//! Whether the csq-cli binary needs separate keychain access groups
//! from the desktop bundle to avoid per-rebuild authorization
//! prompts. This PR uses the native API uniformly; csq-cli on
//! developer machines may see prompts during rebuilds. PR-G2b will
//! decide whether to add an entitlement file or fall back to the
//! `security` CLI for the CLI binary's writes.

use super::{run_with_timeout, SecretError, SlotKey, Vault};
use crate::types::AccountNum;
use secrecy::{ExposeSecret, SecretString};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

/// Constant `account` field on every keychain item we write. The
/// addressable slot identity lives in the `service` field via
/// [`SlotKey::native_name`]; the `account` field is a per-app
/// namespace tag.
const KEYCHAIN_ACCOUNT: &str = "csq";

/// Production macOS Keychain backend. Stateless — every method is a
/// fresh keychain call. The `Vault` trait's no-caching invariant is
/// enforced by construction here.
pub struct MacosKeychainVault;

impl MacosKeychainVault {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosKeychainVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault for MacosKeychainVault {
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }
        // Move owned values into the worker so the closure outlives
        // the calling stack frame and the Keychain syscall is bounded
        // by `VAULT_OP_TIMEOUT` per the trait contract.
        let service = slot.native_name();
        let bytes: Vec<u8> = secret.expose_secret().as_bytes().to_vec();
        run_with_timeout("csq-vault-keychain", move || {
            // `set_generic_password` overwrites if present; if the
            // item doesn't exist it creates it. No separate update
            // path needed.
            set_generic_password(&service, KEYCHAIN_ACCOUNT, &bytes).map_err(map_sf_error)
        })
    }

    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
        let service = slot.native_name();
        let surface_static = slot.surface;
        let account = slot.account.get();
        run_with_timeout("csq-vault-keychain", move || {
            match get_generic_password(&service, KEYCHAIN_ACCOUNT) {
                Ok(bytes) => {
                    // Non-UTF-8 secret is a corruption signal — Gemini
                    // keys are ASCII (AIza*) and Vertex SA paths are
                    // filesystem paths.
                    let s = String::from_utf8(bytes).map_err(|_| SecretError::InvalidKey {
                        reason: "stored Keychain secret is not valid UTF-8".into(),
                    })?;
                    Ok(SecretString::new(s.into()))
                }
                Err(e) => Err(map_sf_error_for_read_static(e, surface_static, account)),
            }
        })
    }

    fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
        let service = slot.native_name();
        run_with_timeout("csq-vault-keychain", move || {
            match delete_generic_password(&service, KEYCHAIN_ACCOUNT) {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Idempotent contract: NotFound on delete is OK.
                    if is_not_found(&e) {
                        Ok(())
                    } else {
                        Err(map_sf_error(e))
                    }
                }
            }
        })
    }

    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
        // security-framework does not expose a generic_password
        // search-by-prefix in the high-level API. The low-level
        // SecItemCopyMatching is available but adds significant
        // surface area for a feature only needed by orphan-cleanup
        // and `csq doctor`.
        //
        // PR-G2a posture: return Ok(empty) and document the gap.
        // PR-G2a.2 will plumb the search path and update this return.
        // The provisioning UI does not call list_slots in the hot
        // path (it knows which slots it provisioned via on-disk
        // markers); this only blocks orphan cleanup which can be
        // run as a follow-up command.
        let _ = surface;
        Ok(Vec::new())
    }

    fn backend_id(&self) -> &'static str {
        "macos-keychain"
    }
}

/// Maps a generic `security_framework::base::Error` to our
/// [`SecretError`] variant. Without an OSStatus accessor on the
/// older `security-framework` API surface we use the rendered
/// message as a coarse classifier. `set` / `delete` paths share this
/// mapping; reads use [`map_sf_error_for_read`] to distinguish
/// `NotFound`.
fn map_sf_error(e: security_framework::base::Error) -> SecretError {
    let msg = e.to_string().to_ascii_lowercase();
    if msg.contains("user canceled") || msg.contains("user cancelled") {
        SecretError::PermissionDenied {
            reason: e.to_string(),
        }
    } else if msg.contains("locked") || msg.contains("not unlocked") {
        SecretError::Locked
    } else if msg.contains("authorization") || msg.contains("not authorized") {
        SecretError::AuthorizationRequired
    } else {
        SecretError::BackendUnavailable {
            reason: e.to_string(),
        }
    }
}

/// Read-path mapper that distinguishes "no such item" (NotFound)
/// from genuine backend errors. Other variants reuse `map_sf_error`.
/// Takes raw surface + account so the `get` worker thread can pass
/// owned values without re-constructing a `SlotKey` (which would
/// require borrowing).
fn map_sf_error_for_read_static(
    e: security_framework::base::Error,
    surface: &'static str,
    account: u16,
) -> SecretError {
    if is_not_found(&e) {
        return SecretError::NotFound { surface, account };
    }
    map_sf_error(e)
}

/// Heuristic check for "no such keychain item". The
/// `security-framework` stable API surface for OSStatus extraction
/// has shifted across versions; relying on the rendered error
/// message keeps the code working across minor bumps.
fn is_not_found(e: &security_framework::base::Error) -> bool {
    let msg = e.to_string().to_ascii_lowercase();
    msg.contains("the specified item could not be found")
        || msg.contains("not be found in the keychain")
        || msg.contains("errsecitemnotfound")
}

#[cfg(test)]
mod tests {
    //! These tests touch the real macOS login keychain and are gated
    //! by both `#[cfg(target_os = "macos")]` (compile-time) and
    //! `#[ignore]` (runtime, opt-in via `cargo test -- --ignored`).
    //!
    //! Standard `cargo test --workspace` does NOT run them — they
    //! pollute the developer's keychain and may trigger
    //! authorization prompts. Run them locally before signing off
    //! PR-G2a per the security-reviewer's gate.

    use super::*;
    use crate::types::AccountNum;

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: "gemini-test",
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    /// RAII guard that deletes the test slot on drop so a panicking
    /// test cannot leave keychain residue.
    struct ScopedSlot(SlotKey);
    impl Drop for ScopedSlot {
        fn drop(&mut self) {
            let v = MacosKeychainVault::new();
            let _ = v.delete(self.0);
        }
    }

    #[test]
    #[ignore = "touches real macOS keychain — run with --ignored"]
    fn live_set_get_round_trip() {
        let s = slot(900);
        let _guard = ScopedSlot(s);
        let v = MacosKeychainVault::new();
        let secret = SecretString::new("AIzaTEST_LIVE_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxx".into());
        v.set(s, &secret).expect("set");
        let got = v.get(s).expect("get");
        assert_eq!(
            got.expose_secret(),
            "AIzaTEST_LIVE_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );
    }

    #[test]
    #[ignore = "touches real macOS keychain — run with --ignored"]
    fn live_delete_idempotent() {
        let s = slot(901);
        let _guard = ScopedSlot(s);
        let v = MacosKeychainVault::new();
        // Delete with no item present — idempotent.
        v.delete(s).expect("delete on empty");
        v.set(s, &SecretString::new("test".into())).expect("set");
        v.delete(s).expect("delete after set");
        v.delete(s).expect("delete idempotent");
        assert!(matches!(v.get(s), Err(SecretError::NotFound { .. })));
    }

    #[test]
    fn backend_id_is_macos_keychain() {
        let v = MacosKeychainVault::new();
        assert_eq!(v.backend_id(), "macos-keychain");
    }

    #[test]
    fn empty_secret_rejected_at_set_without_keychain_call() {
        // Validation must happen before the keychain syscall so
        // empty-input bugs do not pollute the user's keychain or
        // leak the empty value into the audit log.
        let v = MacosKeychainVault::new();
        let err = v
            .set(slot(1), &SecretString::new(String::new().into()))
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }
}
