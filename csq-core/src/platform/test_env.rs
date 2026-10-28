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
//! The same mutex also serializes tests that temporarily repoint the
//! process-global stdin (fd 0). Readers such as the login drivability guard
//! sample `stdin().is_terminal()` process-wide, so a concurrent fd-0 swap can
//! flip a sibling test's verdict mid-body (the darwin preflight's login-TTY
//! flake). A test that swaps fd 0 takes this lock TOO, but AFTER the shared
//! signal mutex: between these two SHARED mutexes the established order is
//! signal-first, then env (the opposite order is an ABBA deadlock of the
//! test process — see `codex_supervise`'s documented lock order).
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

/// Item 4 (D-F3, signal-test harness hazards): serializes every test in
/// this WORKSPACE (not just this crate) that mutates PROCESS-WIDE signal
/// disposition — raw `libc::signal(SIGINT/SIGTERM/SIGHUP/SIGUSR1, ..)`
/// calls in `cli_deps::auto_update::InterruptSignalGuard`,
/// `csq::cli::commands::codex_supervise::drive_child`'s
/// `SIGTERM_FLAG`/`SIGHUP_FLAG`/`SIGUSR1_FLAG` machinery, and the desktop
/// `daemon_supervisor` SIGTERM bridge (which additionally registers via
/// `tokio`'s `signal-hook-registry` — a mechanism a raw `libc::signal()`
/// call elsewhere in this workspace silently OVERWRITES for the remainder
/// of the process, since both ultimately contend for the same kernel
/// per-process disposition table).
///
/// Signal disposition is process-wide, not per-thread, so `cargo test`'s
/// default parallel runner would otherwise let any two of the above race
/// on the SAME underlying kernel state — including across the CRATE
/// boundary this function exists to cross (`auto_update.rs`'s own
/// `SIGNAL_TEST_LOCK` doc, before this function existed, recorded that its
/// module-local mutex could not be shared with `codex_supervise`'s for
/// exactly this reason). A single shared mutex, callable from any crate in
/// the workspace, is what closes that gap.
static SIGNAL_TEST_MUTEX: Mutex<()> = Mutex::new(());

thread_local! {
    /// True while THIS thread holds the shared env-test mutex. [`signal_lock`]
    /// consults it to refuse the one order that ABBA-deadlocks the whole test
    /// binary: taking the signal lock while the env lock is already held.
    /// The established order between these two SHARED mutexes is SIGNAL
    /// first, then ENV (`codex_supervise`'s dual-lock tests document it).
    static ENV_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn mark_env_held() {
    ENV_HELD.with(|held| held.set(true));
}

/// Acquires the shared signal-test mutex. See `SIGNAL_TEST_MUTEX`'s doc
/// for the full set of call sites this MUST serialize against. Poisoning
/// is recovered silently, same rationale as [`lock`].
///
/// PANICS on the one forbidden acquisition order: the signal lock taken
/// while THIS thread already holds the shared env-test lock. Two tests
/// choosing opposite orders deadlock the whole bin under the default
/// parallel harness, and the deadlock is silent — every later test piles up
/// behind whichever lock the two are holding. This check turns that into an
/// immediate, named failure at the offending site. Taking the signal lock
/// FIRST and the env lock second is the established, allowed order.
pub fn signal_lock() -> MutexGuard<'static, ()> {
    ENV_HELD.with(|held| {
        assert!(
            !held.get(),
            "test lock-order violation: the signal lock was acquired while this \
             thread holds the shared env-test lock. The established order between \
             these two shared mutexes is SIGNAL first, then ENV; the reverse is an \
             ABBA deadlock of the whole test binary (see codex_supervise's \
             documented lock order). Swap the acquisitions."
        );
    });
    match SIGNAL_TEST_MUTEX.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            SIGNAL_TEST_MUTEX.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// The `ThreadId` of the thread holding the shared env-test mutex, as of the
/// most recent acquisition that has not yet been released. Written by the
/// acquiring thread while it holds the mutex ([`record_holder`]), cleared by
/// [`EnvTestGuard`]'s drop BEFORE the mutex is released — so a reader never
/// sees a stale holder.
///
/// Why the record exists: `try_lock()==None` cannot say WHO holds the shared
/// lock. Under a full `cargo test` run a SIBLING holding it makes that
/// observation true as well, so the `BaseDirEnvGuard` serialization proof
/// (fixcheck2 LOW 2) could only discriminate against a private-lock guard
/// under a single-test filter. `current_holder() == thread::current().id()` is
/// the discriminating form: it is true only when THIS thread holds it, in the
/// sign-off run as much as when run alone.
static ENV_TEST_HOLDER: Mutex<Option<Holder>> = Mutex::new(None);

/// One acquisition of the shared env-test mutex, as recorded by its holder.
/// `name` is the acquiring thread's name — under libtest, the test's path —
/// and `acquired_at` when it took the lock, so a long-waiting acquirer can
/// say WHICH test is holding it and for how long. Diagnostic only: nothing
/// gates on it.
struct Holder {
    id: std::thread::ThreadId,
    name: String,
    acquired_at: std::time::Instant,
}

/// How long [`lock`] waits before it reports, ONCE, which test holds the lock
/// (`CSQ_TEST_ENV_LOCK_WAIT holder=<name> held_ms=<n>`, written straight to
/// the process's stderr by [`report_to_stderr`], so libtest's output capture
/// cannot swallow it in a captured run). It never
/// gives up: a slow but healthy holder (e.g. a test spanning two cold `cargo
/// build`s) must not turn its waiters red. A genuine wedge is still bounded
/// by the test watchdog (`scripts/ci/test-watchdog.mjs`, 360 s with no test
/// completing), whose log now carries the holder's name.
const LOCK_WAIT_REPORT: std::time::Duration = std::time::Duration::from_secs(60);
/// Poll interval while waiting for [`LOCK_WAIT_REPORT`]; after the report the
/// waiter blocks on the mutex instead of polling.
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// The shared env-test mutex's guard: a [`MutexGuard`] that records its
/// holder's `ThreadId` on acquire and clears the record on drop.
///
/// The record is written under the env-test mutex (the acquirer holds it) and
/// cleared by the releaser BEFORE its inner guard unlocks (struct fields drop
/// after the `Drop` body), so the two mutexes are only ever taken in the order
/// env-test → holder and the record never names a thread that has released.
pub struct EnvTestGuard {
    _inner: MutexGuard<'static, ()>,
}

impl Drop for EnvTestGuard {
    fn drop(&mut self) {
        clear_holder_if_mine();
        ENV_HELD.with(|held| held.set(false));
    }
}

/// The `ThreadId` recorded as the shared env-test mutex's current holder, or
/// `None` when it is free (see `ENV_TEST_HOLDER`). `Some(id)` names a thread
/// that holds the mutex at the moment of the read, so
/// `current_holder() == Some(thread::current().id())` proves the CALLER holds
/// it — unlike `try_lock()==None`, which a sibling holder satisfies too.
pub fn current_holder() -> Option<std::thread::ThreadId> {
    holder_record().as_ref().map(|h| h.id)
}

fn holder_record() -> MutexGuard<'static, Option<Holder>> {
    record_of(&ENV_TEST_HOLDER)
}

fn record_of(record: &Mutex<Option<Holder>>) -> MutexGuard<'_, Option<Holder>> {
    match record.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            record.clear_poison();
            poisoned.into_inner()
        }
    }
}

fn record_holder() {
    record_holder_in(&ENV_TEST_HOLDER);
}

fn record_holder_in(record: &Mutex<Option<Holder>>) {
    let me = std::thread::current();
    let name = me
        .name()
        .map_or_else(|| format!("<unnamed thread {:?}>", me.id()), str::to_owned);
    *record_of(record) = Some(Holder {
        id: me.id(),
        name,
        acquired_at: std::time::Instant::now(),
    });
}

/// Clears the record only when it is this thread's. While this thread holds
/// the env-test mutex no other thread can have recorded (recording requires
/// the mutex), so the condition holds on every real release path; it is a
/// guard against a future recording path that does not hold the mutex.
fn clear_holder_if_mine() {
    let mut record = holder_record();
    if record.as_ref().map(|h| h.id) == Some(std::thread::current().id()) {
        *record = None;
    }
}

/// Acquires the shared env-test mutex. Blocks until any other test
/// mutating process-global env releases it. Returns a guard that
/// auto-releases on drop — hold it for the entire test body. The guard
/// records its holder for [`current_holder`].
///
/// Poisoning is recovered silently: if a previous test panicked
/// while holding the guard, we clear the poison and proceed. The
/// env mutations the panicked test made might still be present,
/// but the next test will save+restore its own variables anyway.
///
/// Never gives up. Once this caller has waited `LOCK_WAIT_REPORT` (60 s)
/// it writes ONE line to the process's stderr (fd 2, bypassing libtest's
/// capture — see `report_to_stderr`) naming the current holder's test and
/// how long it has held the lock, then keeps waiting — so a convoy behind a wedged test
/// (the 48-test stall behind a fixture whose workers never left a barrier)
/// names its culprit in the watchdog's log instead of failing healthy tests.
pub fn lock() -> EnvTestGuard {
    let inner = acquire_reporting(
        &ENV_TEST_MUTEX,
        &ENV_TEST_HOLDER,
        LOCK_WAIT_REPORT,
        &mut report_to_stderr,
    );
    record_holder();
    mark_env_held();
    EnvTestGuard { _inner: inner }
}

/// [`lock`]'s report sink. Writes to the `std::io::stderr()` handle rather
/// than through `eprintln!`: the print macros route into libtest's
/// per-test capture buffer, which is discarded when the watchdog kills a
/// captured run — exactly when this line matters. The handle is fd 2.
fn report_to_stderr(line: &str) {
    let mut err = std::io::stderr().lock();
    // A diagnostic line that fails to write changes nothing about the lock
    // acquisition it describes, so the error is deliberately ignored.
    let _ = std::io::Write::write_all(&mut err, format!("{line}\n").as_bytes());
}

/// Acquires `mutex`, emitting one holder report through `emit` if the wait
/// reaches `report_after`. Poisoning is recovered exactly as [`lock`] always
/// has. Parameterised over the mutex, its holder record, the threshold and
/// the sink so a self-test can drive it without the shared lock.
fn acquire_reporting<'m>(
    mutex: &'m Mutex<()>,
    record: &Mutex<Option<Holder>>,
    report_after: std::time::Duration,
    emit: &mut dyn FnMut(&str),
) -> MutexGuard<'m, ()> {
    let started = std::time::Instant::now();
    while started.elapsed() < report_after {
        match mutex.try_lock() {
            Ok(g) => return g,
            Err(std::sync::TryLockError::Poisoned(p)) => {
                mutex.clear_poison();
                return p.into_inner();
            }
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(LOCK_POLL),
        }
    }
    let (name, held_ms) = record_of(record).as_ref().map_or_else(
        || ("<holder not yet recorded>".to_owned(), 0),
        |h| (h.name.clone(), h.acquired_at.elapsed().as_millis()),
    );
    emit(&format!(
        "CSQ_TEST_ENV_LOCK_WAIT holder={name} held_ms={held_ms}"
    ));
    match mutex.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// Non-blocking variant of [`lock`]: `Some` when the shared env-test mutex
/// was free, `None` when it is currently held. A successful acquisition
/// records its holder exactly as [`lock`] does.
pub fn try_lock() -> Option<EnvTestGuard> {
    match ENV_TEST_MUTEX.try_lock() {
        Ok(g) => {
            record_holder();
            mark_env_held();
            Some(EnvTestGuard { _inner: g })
        }
        Err(std::sync::TryLockError::Poisoned(p)) => {
            ENV_TEST_MUTEX.clear_poison();
            record_holder();
            mark_env_held();
            Some(EnvTestGuard {
                _inner: p.into_inner(),
            })
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// Pins the process-global umask for a test and restores the previous mask
/// on `Drop` — including on panic — while holding [`lock`] for the guard's
/// whole lifetime.
///
/// `libc::umask` is process-global (the same hazard class as signal
/// disposition), so every test that exercises a umask window serializes on
/// the shared env-test mutex. The Drop restore is what the manual
/// save/restore pairs it replaces offered only on the success path: a
/// failing assertion inside the window would otherwise leak the temporary
/// mask into every test that runs afterwards (review round 1 LOW: umask
/// restore was not panic-safe).
#[cfg(unix)]
#[cfg(any(test, feature = "test-utils"))]
pub struct UmaskGuard {
    previous: libc::mode_t,
    _lock: EnvTestGuard,
}

#[cfg(unix)]
#[cfg(any(test, feature = "test-utils"))]
impl UmaskGuard {
    /// Sets the process umask to `mask` until the guard is dropped. Holds
    /// the shared lock for the whole window, so no other umask test can run
    /// concurrently.
    pub fn pin(mask: libc::mode_t) -> Self {
        let lock = lock();
        // SAFETY: libc::umask is always safe to call; the previous value is
        // restored in Drop.
        let previous = unsafe { libc::umask(mask) };
        Self {
            previous,
            _lock: lock,
        }
    }
}

#[cfg(unix)]
#[cfg(any(test, feature = "test-utils"))]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: same as pin — restoring the saved mask.
        unsafe {
            libc::umask(self.previous);
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
#[cfg(any(test, feature = "test-utils"))]
pub fn with_in_memory_secret_backend<R>(f: impl FnOnce() -> R) -> R {
    with_secret_backend("in-memory", || {
        // Fail closed: if the pin did not select the in-memory vault (the
        // `secret-in-memory` feature is off), `open_default_vault` would fall
        // through to the platform vault, e.g. the real macOS Keychain.
        let vault = crate::platform::secret::open_default_vault()
            .expect("in-memory secret backend must open under the in-memory pin");
        assert_eq!(
            vault.backend_id(),
            "in-memory",
            "with_in_memory_secret_backend must never run against a real vault"
        );
        f()
    })
}

/// Runs `f` with `CSQ_SECRET_BACKEND` set to `value`, holding [`lock`] for
/// the whole call and restoring the previous value on the way out (including
/// on unwind) — the general form of [`with_in_memory_secret_backend`],
/// sharing its lock and its restore guarantee.
///
/// `in-memory` is not the only backend state a test needs to pin.
/// [`crate::platform::secret::open_default_vault`] also has a FAILURE branch:
/// an unrecognised value is rejected outright by `is_known_override`, on
/// EVERY platform. That is the only pin that reproduces the
/// vault-cannot-open arm of `binding_guard::clear_detected_marker_binding`
/// deterministically off Linux, whose native vaults (macOS Keychain, Windows
/// credential manager) always open — a `file` pin does not: it is Linux-only
/// and errors on macOS, while SUCCEEDING on the very Linux hosts the arm is
/// about. an internal ticket.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn with_secret_backend<R>(value: &str, f: impl FnOnce() -> R) -> R {
    let guard = lock();
    with_secret_backend_locked(&guard, value, f)
}

/// [`with_in_memory_secret_backend`]'s locked body — the `in-memory` special
/// case of [`with_secret_backend_locked`], kept as a named wrapper because
/// this module's own self-tests call it directly.
#[cfg(test)]
fn with_in_memory_secret_backend_locked<R>(lock: &EnvTestGuard, f: impl FnOnce() -> R) -> R {
    with_secret_backend_locked(lock, "in-memory", f)
}

/// The body of [`with_secret_backend`], taking the shared lock by
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
#[cfg(any(test, feature = "test-utils"))]
fn with_secret_backend_locked<R>(_lock: &EnvTestGuard, value: &str, f: impl FnOnce() -> R) -> R {
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
    unsafe { std::env::set_var("CSQ_SECRET_BACKEND", value) };
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// The helper's whole promise is that `f` runs against the in-memory vault,
    /// never a platform one; assert the vault the code under test would open.
    #[test]
    fn with_in_memory_secret_backend_opens_the_in_memory_vault() {
        let id = with_in_memory_secret_backend(|| {
            crate::platform::secret::open_default_vault()
                .unwrap()
                .backend_id()
        });
        assert_eq!(id, "in-memory");
    }

    /// The holder record's RELEASE half: after a guard drops, the record must
    /// never name that thread again. Asserted as `ne` (not `None`) so a
    /// sibling holding the shared lock concurrently cannot make it flake —
    /// `None` would be true only when the lock is free, which a full-set run
    /// does not guarantee, while "not this thread" is true in both cases.
    #[test]
    fn holder_record_never_names_a_releaser() {
        {
            let g = lock();
            assert_eq!(
                current_holder(),
                Some(std::thread::current().id()),
                "a held guard's acquirer is the recorded holder"
            );
            drop(g);
        }
        assert_ne!(
            current_holder(),
            Some(std::thread::current().id()),
            "the record must be cleared when the guard drops"
        );
    }

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

    const REPORT_CHILD_ENV: &str = "CSQ_TEST_ENV_LOCK_REPORT_CHILD";

    /// Child half of `the_wait_report_survives_libtest_output_capture`; a
    /// no-op unless that parent sets `CSQ_TEST_ENV_LOCK_REPORT_CHILD=1`. Drives
    /// [`lock`]'s REAL sink through `acquire_reporting` on a private mutex; the
    /// holder releases only after the sink has written, so no clock decides it.
    #[test]
    fn wait_report_capture_child_fixture() {
        if std::env::var_os(REPORT_CHILD_ENV).is_none() {
            return;
        }
        use std::sync::mpsc;
        static MUTEX: Mutex<()> = Mutex::new(());
        static RECORD: Mutex<Option<Holder>> = Mutex::new(None);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = thread::Builder::new()
            .name("report-capture-holder-fixture".to_owned())
            .spawn(move || {
                let _g = MUTEX.lock().unwrap();
                record_holder_in(&RECORD);
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
                *record_of(&RECORD) = None;
            })
            .unwrap();
        held_rx.recv().unwrap();
        let mut sink = |line: &str| {
            report_to_stderr(line);
            let _ = release_tx.send(());
        };
        drop(acquire_reporting(
            &MUTEX,
            &RECORD,
            std::time::Duration::from_millis(50),
            &mut sink,
        ));
        holder.join().unwrap();
    }

    /// The report must reach the process's stderr in a CAPTURED libtest run
    /// (no `--nocapture`), the mode of the sign-off legs the watchdog kills.
    /// RED: an `eprintln!` sink writes into the passing child test's capture
    /// buffer, which libtest discards, so the parent never sees the line.
    #[test]
    fn the_wait_report_survives_libtest_output_capture() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let child_test = format!("{module}::wait_report_capture_child_fixture");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([child_test.as_str(), "--exact", "--test-threads=1"])
            .env(REPORT_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let reader = thread::spawn(move || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
            text
        });
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let text = reader.join().unwrap();
        let status = status.expect("the capture child must finish within 120 s (killed)");
        assert!(status.success(), "capture child failed: {status:?}\n{text}");
        assert!(
            text.contains("CSQ_TEST_ENV_LOCK_WAIT holder=report-capture-holder-fixture"),
            "the wait report must survive libtest capture; child stderr:\n{text}"
        );
    }

    /// A waiter that outlasts the report threshold must print ONE line naming
    /// the holder, then still acquire once the holder releases. Runs on a
    /// private mutex and record, never the shared lock. RED: without the
    /// report no line arrives within the bound (200x the threshold).
    #[test]
    fn a_long_wait_reports_the_holder_once_then_acquires() {
        use std::sync::mpsc;
        use std::time::Duration;
        static MUTEX: Mutex<()> = Mutex::new(());
        static RECORD: Mutex<Option<Holder>> = Mutex::new(None);
        const THRESHOLD: Duration = Duration::from_millis(50);
        const BOUND: Duration = Duration::from_millis(50 * 200);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = thread::Builder::new()
            .name("wait-report-holder-fixture".to_owned())
            .spawn(move || {
                let _g = MUTEX.lock().unwrap();
                record_holder_in(&RECORD);
                held_tx.send(()).unwrap();
                // Dropped sender (test failure) also releases.
                let _ = release_rx.recv();
                *record_of(&RECORD) = None;
            })
            .unwrap();
        held_rx
            .recv()
            .expect("the fixture holder takes the private lock");
        let (line_tx, line_rx) = mpsc::channel::<String>();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let _g = acquire_reporting(&MUTEX, &RECORD, THRESHOLD, &mut |l| {
                line_tx.send(l.to_owned()).unwrap()
            });
            acquired_tx.send(()).unwrap();
        });
        let first = line_rx.recv_timeout(BOUND);
        drop(release_tx);
        holder.join().unwrap();
        let line = first.expect("a waiter past the threshold must report the holder");
        acquired_rx
            .recv()
            .expect("the waiter acquires once the holder releases");
        waiter.join().unwrap();
        let extra: Vec<String> = line_rx.try_iter().collect();
        assert!(extra.is_empty(), "the report is emitted once: {extra:?}");
        assert!(
            line.starts_with("CSQ_TEST_ENV_LOCK_WAIT holder=wait-report-holder-fixture held_ms="),
            "{line}"
        );
        let held: u128 = line.rsplit('=').next().unwrap().parse().unwrap();
        assert!(held >= THRESHOLD.as_millis(), "{line}");
    }

    /// RED row for the structural order guard: env-then-signal is the ONLY
    /// forbidden order, and it must fail immediately with the rule named.
    /// (RED-first: removing the check in `signal_lock` makes this test fail —
    /// no panic is raised, and the production outcome is a silent deadlock.)
    #[test]
    fn signal_lock_after_env_lock_panics_with_the_order_rule() {
        let env = lock();
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = signal_lock();
        }))
        .expect_err("signal_lock must refuse env-then-signal");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("lock-order violation"),
            "message must name the rule, got: {msg:?}"
        );
        drop(env);
    }

    /// The allowed order: signal first, env second.
    #[test]
    fn signal_then_env_is_the_allowed_order() {
        let signal = signal_lock();
        let env = lock();
        drop(env);
        drop(signal);
    }
}
