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
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_millis(5));
        cache.set("foo".into(), 1);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get(&"foo".to_string()), None);
    }

    #[test]
    fn set_overwrites_and_resets_timestamp() {
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_millis(50));
        cache.set("foo".into(), 1);
        thread::sleep(Duration::from_millis(40));
        // Overwrite — timestamp resets.
        cache.set("foo".into(), 2);
        thread::sleep(Duration::from_millis(20));
        // Original TTL would have expired; the second write's TTL
        // is still live.
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
        let cache: TtlCache<String, u32> = TtlCache::new(Duration::from_millis(20));
        cache.set("old".into(), 1);
        thread::sleep(Duration::from_millis(30));
        cache.set("new".into(), 2);

        let removed = cache.sweep_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.get(&"new".to_string()), Some(2));
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
