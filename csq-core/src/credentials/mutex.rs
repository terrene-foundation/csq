//! Per-account credential-write mutex table.
//!
//! Serialises concurrent writers of a single canonical credential file
//! within one process. Cross-process serialisation is a separate concern
//! handled by the `flock` refresh-lock in [`crate::broker::check`] and
//! the daemon's file-locked refresh path.
//!
//! Keyed by `(Surface, AccountNum)` so slot-N-ClaudeCode and slot-N-Codex
//! are independent — see spec 07 INV-P09.
//!
//! # Mutex primitive
//!
//! The inner guard is a [`std::sync::Mutex`] rather than
//! [`tokio::sync::Mutex`]. Spec 07 §7.5 names `tokio::sync::Mutex` as the
//! INV-P09 primitive, but every current consumer of [`AccountMutexTable`]
//! ([`crate::credentials::file::save_canonical_for`]) is synchronous —
//! it holds the guard across a bounded atomic rename, never across an
//! `await`. A sync mutex is sufficient and avoids forcing every caller
//! into tokio. PR-C4 (async Codex refresher, spec 07 §7.5 INV-P01) may
//! extend this table with an async variant if refresh paths grow
//! `.await` points inside the critical section.

use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

static GLOBAL_TABLE: OnceLock<AccountMutexTable> = OnceLock::new();

/// Map from slot key to the `Arc<Mutex<()>>` that serialises writers of
/// that slot. Factored out as a `type` alias so the `Mutex`-of-`HashMap`-of-
/// `Arc`-of-`Mutex` stack does not trip the `clippy::type_complexity` lint
/// on [`AccountMutexTable::inner`].
type SlotMutexMap = Mutex<HashMap<(Surface, AccountNum), Arc<Mutex<()>>>>;

/// Process-local table of per-(surface, account) write mutexes.
///
/// Use [`AccountMutexTable::global`] from production code — a fresh
/// [`AccountMutexTable::new`] instance is intended only for tests that
/// need isolation from the process-global table.
pub struct AccountMutexTable {
    inner: SlotMutexMap,
}

impl Default for AccountMutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountMutexTable {
    /// Fresh, empty table. Production code should use
    /// [`AccountMutexTable::global`] to share state across writers.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the process-global table, allocating on first use.
    pub fn global() -> &'static Self {
        GLOBAL_TABLE.get_or_init(Self::new)
    }

    /// Returns an `Arc<Mutex<()>>` for this slot. Allocates on first
    /// touch; subsequent calls for the same key return the same `Arc`.
    pub fn get_or_insert(&self, surface: Surface, account: AccountNum) -> Arc<Mutex<()>> {
        let mut map = self
            .inner
            .lock()
            .expect("AccountMutexTable inner map poisoned");
        map.entry((surface, account))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Drops the mutex entry for this slot. Called on logout per
    /// spec 07 INV-P09 so the table does not leak entries across
    /// login/logout cycles. Any outstanding `Arc` holders continue to
    /// serialise against one another; subsequent calls to
    /// [`Self::get_or_insert`] allocate a fresh mutex (acceptable
    /// because there should be no live writer for a logged-out slot).
    pub fn remove(&self, surface: Surface, account: AccountNum) {
        let mut map = self
            .inner
            .lock()
            .expect("AccountMutexTable inner map poisoned");
        map.remove(&(surface, account));
    }

    /// Number of live entries. Test-only — production callers do not
    /// need to introspect table size.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("AccountMutexTable inner map poisoned")
            .len()
    }

    /// Whether the table has any live entries. Test-only — required to
    /// satisfy the `len_without_is_empty` lint on the test-only `len`.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("AccountMutexTable inner map poisoned")
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn get_or_insert_returns_same_arc_for_same_key() {
        let table = AccountMutexTable::new();
        let m1 = table.get_or_insert(Surface::ClaudeCode, acc(1));
        let m2 = table.get_or_insert(Surface::ClaudeCode, acc(1));
        assert!(Arc::ptr_eq(&m1, &m2), "same key must return same Arc");
    }

    #[test]
    fn different_surfaces_get_different_mutexes() {
        let table = AccountMutexTable::new();
        let anth = table.get_or_insert(Surface::ClaudeCode, acc(3));
        let codex = table.get_or_insert(Surface::Codex, acc(3));
        assert!(
            !Arc::ptr_eq(&anth, &codex),
            "same account number across surfaces must not share a mutex (INV-P09)"
        );
    }

    #[test]
    fn different_accounts_get_different_mutexes() {
        let table = AccountMutexTable::new();
        let a1 = table.get_or_insert(Surface::ClaudeCode, acc(1));
        let a2 = table.get_or_insert(Surface::ClaudeCode, acc(2));
        assert!(!Arc::ptr_eq(&a1, &a2));
    }

    #[test]
    fn remove_drops_entry_from_table() {
        let table = AccountMutexTable::new();
        table.get_or_insert(Surface::Codex, acc(4));
        assert_eq!(table.len(), 1);
        table.remove(Surface::Codex, acc(4));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn remove_is_idempotent() {
        let table = AccountMutexTable::new();
        // Removing a missing entry must not panic.
        table.remove(Surface::Codex, acc(9));
        table.remove(Surface::Codex, acc(9));
    }

    #[test]
    fn get_or_insert_after_remove_allocates_new_mutex() {
        let table = AccountMutexTable::new();
        let first = table.get_or_insert(Surface::Codex, acc(5));
        table.remove(Surface::Codex, acc(5));
        let second = table.get_or_insert(Surface::Codex, acc(5));
        assert!(
            !Arc::ptr_eq(&first, &second),
            "remove then re-insert must yield a fresh mutex"
        );
    }

    #[test]
    fn concurrent_get_or_insert_returns_same_arc() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let table = StdArc::new(AccountMutexTable::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let t = StdArc::clone(&table);
                thread::spawn(move || t.get_or_insert(Surface::ClaudeCode, acc(7)))
            })
            .collect();

        let mutexes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = &mutexes[0];
        for m in &mutexes[1..] {
            assert!(
                Arc::ptr_eq(first, m),
                "concurrent get_or_insert for same key must share one Arc"
            );
        }
    }

    #[test]
    fn global_table_is_singleton() {
        let a = AccountMutexTable::global();
        let b = AccountMutexTable::global();
        assert!(
            std::ptr::eq(a, b),
            "AccountMutexTable::global must return the same &'static reference"
        );
    }
}
