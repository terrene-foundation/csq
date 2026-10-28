//! Thread-safe TTL cache for daemon subsystems.
//!
//! Used by the refresher, usage poller, and HTTP API routes to
//! avoid hammering the same code paths on every request. Entries
//! expire after a configurable max age — reads past the expiry
//! return `None` as if the entry were never inserted.
//!
//! # Concurrency
//!
//! Backed by `std::sync::RwLock` so concurrent readers do not block
//! each other. Writers take exclusive access briefly during
//! `set`/`delete`/`clear`. No `Send`/`Sync` gymnastics required at
//! the call site — `Arc<TtlCache<K, V>>` can be cloned and sent to
//! any tokio task.
//!
//! # Expiry policy
//!
//! Entries are soft-expired: they remain in the map until either
//! (a) the next `set` for the same key overwrites them, (b) a
//! `delete` or `clear` is called, or (c) a future `sweep_expired`
//! implementation runs. A `get` that finds an expired entry returns
//! `None` but does NOT remove the entry in the current design —
//! removing under an upgraded lock is straightforward but adds
//! contention and we prefer the simpler read path.
//!
//! # What lives here
//!
//! M8.4 uses the cache for broker status (per-account refresh
//! outcome + timestamp) so the HTTP API can return current state
//! without re-running `broker_check` on every poll. M8.5 will add
//! usage window data and provider quota info. The cache is
//! deliberately generic over `K: Eq + Hash` and `V: Clone` so
//! each subsystem can instantiate its own typed cache rather than
//! sharing a stringly-typed one.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Default maximum age for cached entries: 10 minutes.
///
/// Matches the statusline render budget (stale quota for up to 10
/// minutes is acceptable; beyond that the daemon should refresh
/// from source).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(600);

/// A single cache entry tracking the value and its insertion time.
#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    inserted_at: Instant,
}

/// Thread-safe TTL cache.
///
/// Entries are cloned on `get` because returning a reference would
/// require holding the read lock across the caller's work, which is
/// fine for primitive types but awkward for the nested structs we
/// cache. The clone cost is negligible for the types we store.
#[derive(Debug)]
pub struct TtlCache<K, V> {
    entries: RwLock<HashMap<K, Entry<V>>>,
    max_age: Duration,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    /// Creates a new cache with the given entry lifetime.
    pub fn new(max_age: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_age,
        }
    }

    /// Creates a cache with [`DEFAULT_MAX_AGE`].
    pub fn with_default_age() -> Self {
        Self::new(DEFAULT_MAX_AGE)
    }

    /// Returns the configured max entry age.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Inserts or updates an entry. The insertion time is reset to
    /// `now` regardless of whether the key already existed.
    pub fn set(&self, key: K, value: V) {
        let mut guard = self.entries.write().expect("cache lock poisoned");
        guard.insert(
            key,
            Entry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Returns a clone of the cached value if present and not
    /// expired. Entries older than `max_age` are treated as missing
    /// (but not removed — see the module docstring).
    pub fn get(&self, key: &K) -> Option<V> {
        let guard = self.entries.read().expect("cache lock poisoned");
        let entry = guard.get(key)?;
        if entry.inserted_at.elapsed() > self.max_age {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Removes an entry from the cache if present. Returns whether
    /// an entry was removed.
    pub fn delete(&self, key: &K) -> bool {
        let mut guard = self.entries.write().expect("cache lock poisoned");
        guard.remove(key).is_some()
    }

    /// Removes all entries from the cache.
    pub fn clear(&self) {
        let mut guard = self.entries.write().expect("cache lock poisoned");
        guard.clear();
    }

    /// Returns the number of entries currently stored (including
    /// expired-but-not-yet-swept entries).
    pub fn len(&self) -> usize {
        self.entries.read().expect("cache lock poisoned").len()
    }

    /// Returns whether the cache contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes all expired entries. Called periodically by the
    /// daemon to bound memory usage — M8.4 does not schedule a
    /// sweeper yet; M8.5 will add it to the refresher tick.
    pub fn sweep_expired(&self) -> usize {
        let mut guard = self.entries.write().expect("cache lock poisoned");
        let before = guard.len();
        let cutoff = self.max_age;
        guard.retain(|_, entry| entry.inserted_at.elapsed() <= cutoff);
        before - guard.len()
    }

    /// Test-only: ages an existing entry by `by`, as if it had been inserted
    /// that much earlier. Returns false if the key is absent.
    ///
    /// Expiry tests are ABOUT the expiry predicate, not about the wall clock,
    /// but with `Instant::now()` fixed inside `set` the only way to reach an
    /// expired state was to sleep — which makes every such test a race between
    /// the TTL and the scheduler. Back-dating removes the clock from the test
    /// entirely: the assertions become deterministic at any host load.
    ///
    /// `#[cfg(test)]`, so it is not part of the shipped API and cannot be
    /// reached from production code.
    #[cfg(test)]
    fn backdate(&self, key: &K, by: Duration) -> bool {
        let mut guard = self.entries.write().expect("cache lock poisoned");
        match guard.get_mut(key) {
            Some(entry) => {
                entry.inserted_at = entry
                    .inserted_at
                    .checked_sub(by)
                    .expect("backdate underflowed the monotonic clock");
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn set_then_get_returns_value() {
        let cache: TtlCache<String, u32> = TtlCache::with_default_age();
        cache.set("foo".into(), 42);
        assert_eq!(cache.get(&"foo".to_string()), Some(42));
    }

    #[test]
    fn missing_key_returns_none() {
        let cache: TtlCache<String, u32> = TtlCache::with_default_age();
        assert_eq!(cache.get(&"missing".to_string()), None);
    }

    #[test]
    fn expired_entry_returns_none() {
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_secs(60));
        cache.set("foo".into(), 1);
        // Aged well past the TTL, deterministically — no sleep, no race.
        assert!(cache.backdate(&"foo".to_string(), Duration::from_secs(120)));
        assert_eq!(cache.get(&"foo".to_string()), None);
    }

    #[test]
    fn set_overwrites_and_resets_timestamp() {
        // Previously TTL 2000ms with two sleeps, widened from 200ms/50ms after
        // it flaked on macOS CI under load. Widening a margin does not remove a
        // race, it only lengthens the odds — so the clock is gone instead: the
        // first entry is aged past the TTL, and the overwrite must reset it.
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_secs(60));
        cache.set("foo".into(), 1);
        assert!(cache.backdate(&"foo".to_string(), Duration::from_secs(120)));
        cache.set("foo".into(), 2);
        assert_eq!(cache.get(&"foo".to_string()), Some(2));
    }

    #[test]
    fn delete_removes_entry() {
        let cache: TtlCache<String, u32> = TtlCache::with_default_age();
        cache.set("foo".into(), 1);
        assert!(cache.delete(&"foo".to_string()));
        assert_eq!(cache.get(&"foo".to_string()), None);
    }

    #[test]
    fn delete_missing_returns_false() {
        let cache: TtlCache<String, u32> = TtlCache::with_default_age();
        assert!(!cache.delete(&"missing".to_string()));
    }

    #[test]
    fn clear_removes_all() {
        let cache: TtlCache<String, u32> = TtlCache::with_default_age();
        cache.set("a".into(), 1);
        cache.set("b".into(), 2);
        cache.set("c".into(), 3);
        assert_eq!(cache.len(), 3);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn sweep_removes_only_expired() {
        // Failed on CI 2026-09-01 (`left: None, right: Some(2)`) with TTL 20ms
        // and a 30ms sleep: the assertion required "new" to be READ within 20ms
        // of being written, so under host load the sweep evicted both entries
        // and the test reported a bug in code that was fine. The margin was the
        // defect. Now: a 60s TTL that nothing in this test can outrun, with
        // "old" aged past it explicitly.
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_secs(60));
        cache.set("old".into(), 1);
        cache.set("new".into(), 2);
        assert!(cache.backdate(&"old".to_string(), Duration::from_secs(120)));

        let removed = cache.sweep_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.get(&"new".to_string()), Some(2));
        assert_eq!(cache.get(&"old".to_string()), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn concurrent_readers_do_not_block_each_other() {
        let cache: Arc<TtlCache<u32, u32>> = Arc::new(TtlCache::with_default_age());
        cache.set(1, 100);
        cache.set(2, 200);
        cache.set(3, 300);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(cache.get(&1), Some(100));
                    assert_eq!(cache.get(&2), Some(200));
                    assert_eq!(cache.get(&3), Some(300));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn concurrent_writes_serialize_correctly() {
        let cache: Arc<TtlCache<u32, u32>> = Arc::new(TtlCache::with_default_age());
        let mut handles = Vec::new();
        for i in 0..16 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                cache.set(i, i * 10);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        for i in 0..16 {
            assert_eq!(cache.get(&i), Some(i * 10));
        }
    }
}
