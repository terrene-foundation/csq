//! In-memory [`Vault`] implementation for tests and the explicit
//! `secret-in-memory` feature flag.
//!
//! This backend exists so the Gemini provisioning path can be tested
//! end-to-end without polluting the developer's real keychain or
//! triggering OS authorization prompts in CI. It is compiled
//! unconditionally under `#[cfg(test)]` and behind the
//! `secret-in-memory` Cargo feature for integration test harnesses.
//!
//! It MUST NOT be reachable in production binaries unless the feature
//! is explicitly enabled — and the feature is NOT in `default`. The
//! `open_default_vault` factory only routes here when both
//! `CSQ_SECRET_BACKEND=in-memory` is set AND the feature is on, so a
//! production build refuses the env var.
//!
//! Despite being in-memory, this implementation honours the same
//! contract as the native backends: `set` overwrites, `delete` is
//! idempotent, `list_slots` returns only account numbers (never any
//! function of the secret), `get` returns a fresh
//! [`SecretString`].

use super::{SecretError, SlotKey, Vault};
use crate::types::AccountNum;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Mutex;

/// Test-grade vault. Holds bytes in a `Mutex<HashMap>`. The bytes
/// are zeroized on drop via the `secrecy` wrapper around the stored
/// value — but ultimately memory protection is not the point of
/// this backend; explicit-test-isolation is.
pub struct InMemoryVault {
    store: Mutex<HashMap<(String, u16), SecretString>>,
}

impl InMemoryVault {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot of the slot count for diagnostics. Test-only — not
    /// part of the [`Vault`] trait so production code cannot depend
    /// on it.
    #[cfg(test)]
    pub fn slot_count(&self) -> usize {
        self.store.lock().unwrap().len()
    }
}

impl Default for InMemoryVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault for InMemoryVault {
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }
        let mut guard = self.store.lock().unwrap();
        // Clone via SecretString construction so the caller's value
        // can drop without affecting our stored copy. The new
        // SecretString owns its allocation.
        guard.insert(
            (slot.surface.to_string(), slot.account.get()),
            SecretString::new(secret.expose_secret().to_string().into()),
        );
        Ok(())
    }

    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
        let guard = self.store.lock().unwrap();
        match guard.get(&(slot.surface.to_string(), slot.account.get())) {
            Some(stored) => Ok(SecretString::new(stored.expose_secret().to_string().into())),
            None => Err(SecretError::NotFound {
                surface: slot.surface,
                account: slot.account.get(),
            }),
        }
    }

    fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
        let mut guard = self.store.lock().unwrap();
        // Idempotent — drop is fine if the key wasn't there.
        guard.remove(&(slot.surface.to_string(), slot.account.get()));
        Ok(())
    }

    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
        let guard = self.store.lock().unwrap();
        let mut out: Vec<AccountNum> = guard
            .keys()
            .filter(|(s, _)| s == surface)
            .filter_map(|(_, n)| AccountNum::try_from(*n).ok())
            .collect();
        out.sort_by_key(|a| a.get());
        Ok(out)
    }

    fn backend_id(&self) -> &'static str {
        "in-memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: "gemini",
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    #[test]
    fn set_and_get_round_trip() {
        let v = InMemoryVault::new();
        let s = SecretString::new("AIzaSyTEST_KEY_1234567890_ROUNDTRIPxx".into());
        v.set(slot(1), &s).unwrap();
        let got = v.get(slot(1)).unwrap();
        assert_eq!(got.expose_secret(), "AIzaSyTEST_KEY_1234567890_ROUNDTRIPxx");
    }

    #[test]
    fn set_overwrites_existing() {
        let v = InMemoryVault::new();
        v.set(slot(2), &SecretString::new("first".into())).unwrap();
        v.set(slot(2), &SecretString::new("second".into())).unwrap();
        let got = v.get(slot(2)).unwrap();
        assert_eq!(got.expose_secret(), "second");
        assert_eq!(v.slot_count(), 1);
    }

    #[test]
    fn get_missing_returns_not_found() {
        let v = InMemoryVault::new();
        let err = v.get(slot(7)).unwrap_err();
        assert!(matches!(
            err,
            SecretError::NotFound {
                surface: "gemini",
                account: 7
            }
        ));
    }

    #[test]
    fn delete_is_idempotent() {
        let v = InMemoryVault::new();
        // Delete on empty vault is OK.
        v.delete(slot(5)).unwrap();
        v.set(slot(5), &SecretString::new("x".into())).unwrap();
        v.delete(slot(5)).unwrap();
        // Second delete still OK.
        v.delete(slot(5)).unwrap();
        assert!(matches!(v.get(slot(5)), Err(SecretError::NotFound { .. })));
    }

    #[test]
    fn list_slots_returns_sorted_account_numbers_only() {
        let v = InMemoryVault::new();
        v.set(slot(10), &SecretString::new("x".into())).unwrap();
        v.set(slot(2), &SecretString::new("y".into())).unwrap();
        v.set(slot(7), &SecretString::new("z".into())).unwrap();

        let slots = v.list_slots("gemini").unwrap();
        let nums: Vec<u16> = slots.iter().map(|a| a.get()).collect();
        assert_eq!(nums, vec![2, 7, 10], "must be sorted ascending");
    }

    #[test]
    fn list_slots_filters_by_surface() {
        // Cross-surface namespacing — a future surface using the
        // same vault must not see Gemini's slots.
        let v = InMemoryVault::new();
        v.set(slot(1), &SecretString::new("g".into())).unwrap();
        v.set(
            SlotKey {
                surface: "future-surface",
                account: AccountNum::try_from(1u16).unwrap(),
            },
            &SecretString::new("f".into()),
        )
        .unwrap();
        let g = v.list_slots("gemini").unwrap();
        let f = v.list_slots("future-surface").unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn empty_secret_rejected_at_set() {
        // Defence in depth — backends MUST validate even though the
        // provisioning UI also validates. Empty secrets indicate a
        // logic bug or hostile caller.
        let v = InMemoryVault::new();
        let err = v
            .set(slot(1), &SecretString::new(String::new().into()))
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn backend_id_is_in_memory() {
        let v = InMemoryVault::new();
        assert_eq!(v.backend_id(), "in-memory");
    }

    /// Concurrent set/get from multiple threads must not deadlock or
    /// drop writes. Simple smoke test against the Mutex.
    #[test]
    fn concurrent_set_get_smoke() {
        let v = std::sync::Arc::new(InMemoryVault::new());
        let mut handles = Vec::new();
        for i in 1..=8u16 {
            let v = v.clone();
            handles.push(std::thread::spawn(move || {
                v.set(slot(i), &SecretString::new(format!("key-{i}").into()))
                    .unwrap();
                let got = v.get(slot(i)).unwrap();
                assert_eq!(got.expose_secret(), &format!("key-{i}"));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(v.slot_count(), 8);
    }
}
