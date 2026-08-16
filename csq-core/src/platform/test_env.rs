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
//! csq test suite mutates a small fixed set of variables; every test
//! that touches one MUST acquire `lock()` first:
//!
//! | Variable                    | Mutator                                                     | In-module lock          |
//! | --------------------------- | ----------------------------------------------------------- | ----------------------- |
//! | `XDG_RUNTIME_DIR`           | `daemon::paths::tests::linux_prefers_xdg_runtime_dir`       | (none)                  |
//! | `XDG_RUNTIME_DIR` (read)    | `daemon::detect::tests::detect_live_*` (Linux)              | `SOCKET_TEST_MUTEX`     |
//! | `LOCALAPPDATA`, `USERNAME`  | `daemon::detect::tests::detect_windows_*`                   | `WINDOWS_ENV_TEST_MUTEX`|
//! | `LOCALAPPDATA` (read)       | `daemon::paths::tests::windows_*`                           | (none)                  |
//! | `CLAUDE_CONFIG_DIR`         | `csq-cli` statusline tests                                  | `ENV_MUTEX`             |
//! | `OLLAMA_BIN`                | `providers::ollama::tests::find_ollama_bin_*`               | (none)                  |
//! | `PATH`, `HOME`              | `accounts::login::tests::find_claude_binary_*`              | (none)                  |
//! | `CSQ_SECRET_BACKEND`        | `platform::secret::tests::*`                                | `ENV_LOCK`              |
//! | `CSQ_SECRET_PASSPHRASE*`    | `platform::secret::file::tests::*`                          | `ENV_LOCK`              |
//!
//! A single coarse mutex across all env-mutating tests serializes the
//! handful of tests that touch process-global env without contention
//! becoming a problem (all env-mutating tests together take < 1s in
//! a normal run).
//!
//! Lock ordering: when a test holds both this shared mutex AND an
//! in-module mutex, the shared mutex MUST be acquired FIRST. Otherwise
//! pairs of tests that consistently choose opposite orders deadlock.
//! All current call sites follow this order — `detect.rs:573, 613` is
//! the canonical example.
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
//! Origin: an internal journal entry finding 11 (round-1 redteam of PR-C8).

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

/// Runs `f` with `CSQ_SECRET_BACKEND=in-memory`, holding [`lock`] for the
/// whole call and restoring the previous value on the way out — including
/// on unwind, so a failing assertion inside `f` cannot leak the override
/// into the rest of the suite.
///
/// # Why every test that drives a login path needs this
///
/// [`crate::platform::secret::open_default_vault`] resolves the backend
/// from AMBIENT state: `CSQ_SECRET_BACKEND`, and — when that is unset —
/// the platform. On macOS it hands back the Keychain vault
/// unconditionally; on Linux it first probes the D-Bus Secret Service and
/// returns `BackendUnavailable` when there is no session bus, which is
/// exactly the case on a headless CI runner. Any test whose
/// code-under-test reaches `open_default_vault` therefore takes a
/// DIFFERENT branch per platform unless it pins the backend.
///
/// That is not hypothetical: `binding_guard::clear_detected_marker_binding`
/// deletes a stale Gemini slot's vault entry BEFORE its marker and is
/// fail-closed on any vault-step failure (it leaves the marker in place so
/// the secret stays findable). On a bus-less Linux runner the vault never
/// opens, the marker survives, and every test asserting the marker is gone
/// fails — while passing on macOS and Windows, whose vaults always open.
/// Pinning `in-memory` makes the branch identical everywhere AND keeps the
/// suite off the developer's real Keychain (`feedback_no_security_w_on_cc_keychain`).
#[cfg(test)]
pub(crate) fn with_in_memory_secret_backend<R>(f: impl FnOnce() -> R) -> R {
    let guard = lock();
    with_in_memory_secret_backend_locked(&guard, f)
}

/// The body of [`with_in_memory_secret_backend`], taking the shared lock by
/// REFERENCE rather than acquiring it.
///
/// The split exists so this module's own self-tests can observe the
/// before/after value of `CSQ_SECRET_BACKEND` inside the SAME lock
/// acquisition that brackets the call. Reading it outside the lock is a
/// race against `platform::secret`'s tests, which mutate the same variable
/// — and `lock()` is a plain `std::sync::Mutex`, so a self-test cannot hold
/// the lock and then call the acquiring wrapper without deadlocking. This
/// is not hypothetical either: the first version of those self-tests read
/// the ambient value outside the lock and went RED on the full-suite run
/// while passing under a module filter.
#[cfg(test)]
fn with_in_memory_secret_backend_locked<R>(
    _lock: &MutexGuard<'static, ()>,
    f: impl FnOnce() -> R,
) -> R {
    /// Restores `CSQ_SECRET_BACKEND` in `Drop` — i.e. on the panicking
    /// path too, so a failing assertion inside `f` cannot leak the
    /// override into the rest of the suite.
    struct Restore {
        prev: Option<std::ffi::OsString>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => unsafe { std::env::set_var("CSQ_SECRET_BACKEND", v) },
                None => unsafe { std::env::remove_var("CSQ_SECRET_BACKEND") },
            }
        }
    }

    // Read under the caller's lock, so a concurrent env-mutating test
    // cannot change the value between this read and the overwrite below.
    let _restore = Restore {
        prev: std::env::var_os("CSQ_SECRET_BACKEND"),
    };
    unsafe { std::env::set_var("CSQ_SECRET_BACKEND", "in-memory") };
    f()
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

    /// The override must be VISIBLE inside the closure and GONE after —
    /// the second half is what stops one test's backend pin from
    /// silently becoming every later test's backend.
    #[test]
    fn with_in_memory_secret_backend_sets_and_restores() {
        // One acquisition brackets the before-read, the call, and the
        // after-read: reading the ambient value outside the lock races
        // `platform::secret`'s tests, which mutate the same variable.
        let guard = lock();
        let before = std::env::var_os("CSQ_SECRET_BACKEND");
        let seen = with_in_memory_secret_backend_locked(&guard, || {
            std::env::var("CSQ_SECRET_BACKEND").ok()
        });
        assert_eq!(
            seen.as_deref(),
            Some("in-memory"),
            "the override must be visible to code running inside the closure"
        );
        assert_eq!(
            std::env::var_os("CSQ_SECRET_BACKEND"),
            before,
            "the previous value must be restored on the success path"
        );
    }

    /// The wrapper must acquire the lock itself — that is the property
    /// every caller relies on, and it is not exercised by the `_locked`
    /// tests above.
    #[test]
    fn with_in_memory_secret_backend_pins_the_backend_for_callers() {
        let seen = with_in_memory_secret_backend(|| std::env::var("CSQ_SECRET_BACKEND").ok());
        assert_eq!(seen.as_deref(), Some("in-memory"));
    }

    /// Restoration happens in `Drop`, so it must survive an unwind. A
    /// failing assertion inside the closure is the common case, and a
    /// leaked `in-memory` pin would silently make later tests hermetic
    /// for the wrong reason.
    #[test]
    fn with_in_memory_secret_backend_restores_on_panic() {
        let guard = lock();
        let before = std::env::var_os("CSQ_SECRET_BACKEND");
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_in_memory_secret_backend_locked(&guard, || panic!("assertion inside the closure"));
        }));
        assert!(caught.is_err(), "the panic must propagate to the caller");
        assert_eq!(
            std::env::var_os("CSQ_SECRET_BACKEND"),
            before,
            "the previous value must be restored even when the closure panics"
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
