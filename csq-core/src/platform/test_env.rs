//! Test-only env-var mutation serialization.
//!
//! Unit tests that need to set or clear process-global environment
//! variables (e.g. `XDG_RUNTIME_DIR`, `LOCALAPPDATA`, `USERNAME`) race
//! when cargo test runs modules in parallel. Each module previously
//! owned a module-local mutex (e.g. `WINDOWS_ENV_TEST_MUTEX` in
//! `daemon::detect`) which did not protect against cross-module races
//! — a second test in `daemon::paths` calling `set_var` on the same
//! variable would still race.
//!
//! This module exposes a SHARED cross-module mutex keyed by env-var
//! name. Every test that mutates `std::env::set_var` or
//! `std::env::remove_var` MUST acquire the guard for that name. The
//! guard is held for the test's lifetime and auto-released on drop.
//!
//! # Why not a per-variable mutex?
//!
//! A per-variable map adds complexity (lazy init + entry acquisition
//! under a meta-lock) that is not yet justified by the use case. The
//! csq test suite mutates a small fixed set of variables:
//!
//! - `XDG_RUNTIME_DIR` (Linux daemon path resolution)
//! - `LOCALAPPDATA` (Windows daemon path resolution)
//! - `USERNAME` (Windows named-pipe name derivation)
//! - `CLAUDE_CONFIG_DIR` (statusline tests, has its own `ENV_MUTEX`)
//! - `OLLAMA_BIN` (provider tests, single test with save+restore)
//! - `PATH`, `HOME` (accounts::login tests, save+restore)
//!
//! A single coarse mutex across all env-mutating tests serializes the
//! handful of tests that touch process-global env without contention
//! becoming a problem (all env-mutating tests together take < 1s in
//! a normal run).
//!
//! # Usage
//!
//! ```ignore
//! #[cfg(target_os = "linux")]
//! #[test]
//! fn my_test() {
//!     let _guard = csq_core::platform::test_env::lock();
//!     let saved = std::env::var("XDG_RUNTIME_DIR").ok();
//!     std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
//!     // ... do work that reads XDG_RUNTIME_DIR ...
//!     match saved {
//!         Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
//!         None => std::env::remove_var("XDG_RUNTIME_DIR"),
//!     }
//! }
//! ```
//!
//! The guard must remain alive for the entire duration the test
//! depends on the mutated env — hold it past the point where the
//! code-under-test reads the variable.
//!
//! Origin: journal 0021 finding 11 (round-1 redteam of PR-C8).

use std::sync::{Mutex, MutexGuard};

static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Acquires the shared env-test mutex. Blocks until any other test
/// mutating process-global env releases it. Returns a guard that
/// auto-releases on drop — hold it for the entire test body.
///
/// Poisoning is recovered silently: if a previous test panicked
/// while holding the guard, we clear the poison and proceed. The
/// env mutations the panicked test made might still be present,
/// but the next test will save+restore its own variables anyway.
pub fn lock() -> MutexGuard<'static, ()> {
    match ENV_TEST_MUTEX.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            ENV_TEST_MUTEX.clear_poison();
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// Two threads each acquiring the guard MUST serialize — no
    /// parallel execution inside the guarded block. We prove this
    /// by incrementing a counter before and after a small sleep:
    /// if the mutex serializes correctly, the counter is always
    /// observed as 0 at entry and 1 after release.
    #[test]
    fn lock_serializes_concurrent_acquirers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();

        let t1 = thread::spawn(move || {
            let _g = lock();
            let seen_before = c1.load(Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            c1.store(seen_before + 1, Ordering::SeqCst);
        });
        let t2 = thread::spawn(move || {
            let _g = lock();
            let seen_before = c2.load(Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            c2.store(seen_before + 1, Ordering::SeqCst);
        });
        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "both threads must have observed and incremented under the lock"
        );
    }

    /// A panic inside the guarded block must not permanently poison
    /// the mutex — a second acquirer must proceed.
    #[test]
    fn lock_recovers_from_poisoning() {
        let t = thread::spawn(|| {
            let _g = lock();
            panic!("intentional panic");
        });
        let _ = t.join(); // panic propagates here; mutex is poisoned

        // Second acquirer should not block / fail.
        let _g = lock();
    }
}
