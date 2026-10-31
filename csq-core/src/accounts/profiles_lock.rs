//! Cross-process file lock for `accounts/profiles.json`.
//!
//! # Why this exists
//!
//! `accounts/profiles.json` is written by two independent OS processes:
//!
//! - **`csqd`** (daemon) — Pass 0 walks every `config-N/` directory and calls
//!   `profiles::add_identity_mapping` for each slot.
//! - **`csq login N`** (CLI or desktop) — `accounts::anthropic_identity::commit_anthropic_login`
//!   publishes the verified slot binding under this lock, then
//!   `accounts::login::finalize_verified_login` consumes its receipt.
//!
//! Both paths perform a **read-modify-write** cycle (load JSON, mutate,
//! `atomic_replace`). Without serialization, the second writer's `atomic_replace`
//! clobbers the first writer's modifications, producing a silent lost-update.
//!
//! The lock file `<base_dir>/.profiles.lock` serializes cross-process writers
//! via `platform::lock::try_lock_file_bounded` (non-blocking `flock` retried
//! within [`PROFILES_LOCK_BUDGET`] on Unix, one total `LockFileEx` deadline on
//! Windows). A waiter that cannot acquire within the budget fails closed with
//! the fixed-vocabulary `profiles_lock_busy` error — it never writes custody
//! metadata without the lock and never blocks a refresher or login forever.
//! The lock is advisory for **readers** — `profiles::load` and pure
//! accessors (`resolve_slot_to_uuid`) skip the lock
//! because `atomic_replace` guarantees a reader never observes a torn write.
//!
//! # Re-entrancy contract
//!
//! `flock` IS re-entrant for duplicated fds within the same process (dup/dup2
//! share the open file description), but TWO `open()` calls to the same path
//! from the same process produce independent open file descriptions, and
//! `flock(LOCK_EX)` on the second contends with the first holder's lock. It
//! used to self-deadlock on the same thread; with the bounded acquire it now
//! fails closed at [`PROFILES_LOCK_BUDGET`] with `profiles_lock_busy`. Within
//! a single-threaded flow (e.g. a Codex login holds the lock and calls
//! `mint_for_codex_login` which calls `add_identity_mapping`), we avoid
//! re-acquisition by **passing the lock by reference** to `add_identity_mapping`.
//! The type-witness pattern — requiring a `&ProfilesFileLock` parameter on
//! `profiles::add_identity_mapping` — makes lock-held callsites statically
//! visible and structurally prevents the self-deadlock.
//!
//! # Lock file lifecycle
//!
//! The lock file itself is empty (it exists only as a kernel lock target). It
//! is created if missing. It is NOT deleted on release — keeping the inode
//! stable prevents a race between `unlink` and re-`open` on concurrent
//! processes. The lock file carries no secrets, so a `secure_file` call is
//! made for consistency with other lock artefacts in csq, but failure is
//! best-effort (non-fatal on FAT or network mounts).

use crate::error::ConfigError;
use crate::platform::{fs::secure_file, lock};
use std::path::{Path, PathBuf};

/// Delay between attempts in [`PROFILES_LOCK_ATTEMPTS`]'s budget — the same
/// cadence the nested credential locks use.
pub const PROFILES_LOCK_DELAY: std::time::Duration = crate::platform::lock::CREDENTIAL_LOCK_DELAY;

/// POLICY allowance, in the COMMIT-IO class, for the holder's own
/// `profiles.json` read-modify-write around its nested canonical wait.
///
/// Local file I/O has no enforceable cap, so this is a stated policy
/// choice, never a measurement.
pub const PROFILES_HOLDER_LOCAL_IO_ALLOWANCE: std::time::Duration =
    crate::credentials::rescue::CREDENTIAL_COMMIT_IO_ALLOWANCE;

/// Worst-case wait for `<base_dir>/.profiles.lock`.
///
/// CLASS: custody lock whose LONGEST holder section is a POST-COMMIT login
/// publication. Under this lock `publish_login_locked_with` calls
/// `save_anthropic_login_target_locked`, which waits up to
/// [`crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET`] (30 s) for
/// the canonical lock. A waiter budget derived from the 500 ms PRE-COMMIT
/// credential class therefore INVERTED the real bound: a legitimate holder
/// could outlast it, and a second concurrent login lost its
/// already-consumed grant to a `profiles_lock_busy` refusal (D237 round-2
/// correctness N4 / security M4).
///
/// DERIVATION: the COMMIT-class canonical budget plus
/// [`PROFILES_HOLDER_LOCAL_IO_ALLOWANCE`] for the holder's own profiles
/// read-modify-write and the publication's local steps. The `const`
/// assertions below make the old inversion a BUILD FAILURE: if the budget
/// ever stops exceeding the nested commit-class wait, the build breaks
/// rather than silently reopening the grant-loss window.
///
/// At the current constants that is 35 s. Every profiles waiter that can
/// afford to fail closed (custody re-checks, the refresher's failure
/// classification) still returns promptly when the lock is free; only a
/// genuinely long holder makes it wait.
pub const PROFILES_LOCK_BUDGET: std::time::Duration =
    crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET
        .saturating_add(PROFILES_HOLDER_LOCAL_IO_ALLOWANCE);

/// Attempts covering [`PROFILES_LOCK_BUDGET`] at [`PROFILES_LOCK_DELAY`],
/// derived from the two Durations — never a bare literal.
pub const PROFILES_LOCK_ATTEMPTS: u32 =
    (PROFILES_LOCK_BUDGET.as_millis() / PROFILES_LOCK_DELAY.as_millis()) as u32;

/// [`PROFILES_LOCK_BUDGET`] in whole milliseconds, for fixed-vocabulary error
/// text.
pub const PROFILES_LOCK_BUDGET_MS: u64 = PROFILES_LOCK_BUDGET.as_millis() as u64;

// Structural derivation checks (see [`PROFILES_LOCK_BUDGET`]). The old
// derivation compared against the PRE-COMMIT class and produced 2 s — less
// than the 30 s nested commit wait. These assertions make that inversion a
// build failure.
const _: () = assert!(
    PROFILES_LOCK_BUDGET.as_millis()
        > crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET.as_millis(),
    "PROFILES_LOCK_BUDGET must exceed the long post-commit holder's canonical wait"
);
const _: () = assert!(
    PROFILES_LOCK_BUDGET.as_millis()
        >= crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET.as_millis()
            + crate::credentials::rescue::CREDENTIAL_COMMIT_IO_ALLOWANCE.as_millis(),
    "PROFILES_LOCK_BUDGET must include the holder's local-I/O allowance on top of its nested wait"
);

/// Test-only override of [`PROFILES_LOCK_ATTEMPTS`], so rows can exercise
/// the expiry branch without a 35-second wall-clock wait.
///
/// Thread-local, mirroring `credentials::rescue`'s commit-budget override:
/// the holder runs on another thread, the waiter under test on this one.
/// Only the ATTEMPT COUNT is overridable; the delay and every production
/// constant stay the shape a release build uses.
#[cfg(test)]
mod budget_override {
    use std::cell::Cell;

    thread_local! {
        static ATTEMPTS: Cell<Option<u32>> = const { Cell::new(None) };
    }

    pub(super) fn get() -> Option<u32> {
        ATTEMPTS.with(Cell::get)
    }

    pub(super) fn set(attempts: Option<u32>) {
        ATTEMPTS.with(|slot| slot.set(attempts));
    }
}

/// RAII override of the profiles-lock attempts for the CURRENT thread.
#[cfg(test)]
pub(crate) struct ProfilesBudgetOverrideGuard;

#[cfg(test)]
impl ProfilesBudgetOverrideGuard {
    #[must_use]
    pub(crate) fn install(attempts: u32) -> Self {
        budget_override::set(Some(attempts));
        ProfilesBudgetOverrideGuard
    }
}

#[cfg(test)]
impl Drop for ProfilesBudgetOverrideGuard {
    fn drop(&mut self) {
        budget_override::set(None);
    }
}

fn profiles_lock_attempts() -> u32 {
    #[cfg(test)]
    if let Some(attempts) = budget_override::get() {
        return attempts;
    }
    PROFILES_LOCK_ATTEMPTS
}

/// RAII guard holding the exclusive file lock for `accounts/profiles.json`.
///
/// Acquire via [`ProfilesFileLock::acquire`]; the lock is released on `Drop`.
///
/// Pass a reference to any function that performs a `load + mutate + save`
/// cycle on `profiles.json` to enforce the "lock must be held" precondition
/// at the type level.
pub struct ProfilesFileLock {
    /// The underlying platform file-lock guard.
    _guard: lock::FileLockGuard,
    /// Path to the lock file (for diagnostics and tests).
    path: PathBuf,
}

impl ProfilesFileLock {
    /// Returns the path to `.profiles.lock` within `base_dir`.
    pub fn lock_path(base_dir: &Path) -> PathBuf {
        base_dir.join(".profiles.lock")
    }

    /// Acquires the exclusive lock on `<base_dir>/.profiles.lock`.
    ///
    /// Waits within [`PROFILES_LOCK_BUDGET`] (see the class and derivation on
    /// [`PROFILES_LOCK_ATTEMPTS`]) — never indefinitely. A live holder
    /// (a `profiles.json` read-modify-write whose LONGEST nested section is a
    /// post-commit canonical wait under the COMMIT-class budget, plus local
    /// file I/O) finishes inside the budget; a WEDGED holder exceeds it.
    ///
    /// On expiry returns `ConfigError::InvalidJson` with the fixed-vocabulary
    /// reason prefix `profiles_lock_busy`. Callers MUST fail closed: the lock
    /// witness is what permits a custody-metadata write, and no caller may
    /// write without one. Locking I/O failures carry `profiles_lock_refused`.
    ///
    /// The lock file is created if it does not exist. `secure_file` is
    /// called best-effort AFTER the lock is taken (non-fatal on filesystems
    /// that cannot honour 0o600).
    pub fn acquire(base_dir: &Path) -> Result<Self, ConfigError> {
        Self::acquire_bounded(base_dir)?.ok_or_else(|| ConfigError::InvalidJson {
            path: Self::lock_path(base_dir),
            // Fixed vocabulary: no `{e}`, no holder identity, no path.
            reason: format!(
                "profiles_lock_busy: lock not acquired within the {PROFILES_LOCK_BUDGET_MS} ms budget"
            ),
        })
    }

    /// Waits within the same budget as [`Self::acquire`], preserving the
    /// distinction between expiry (`Ok(None)`) and local I/O refusal (`Err`).
    /// Callers can classify contention without inspecting diagnostic text.
    pub(crate) fn acquire_bounded(base_dir: &Path) -> Result<Option<Self>, ConfigError> {
        let path = Self::lock_path(base_dir);

        // SEC-2.15 (unified, R1 M1): the lock lives directly in the
        // accounts root — create AND secure it fail-closed via the shared
        // helper (was a silent `.ok()` best-effort).
        if let Some(parent) = path.parent() {
            crate::platform::fs::ensure_private_dir_root(parent).map_err(|e| {
                ConfigError::InvalidJson {
                    path: path.clone(),
                    // Fixed vocabulary: the io kind, never an arbitrary message.
                    reason: format!(
                        "profiles_lock_parent_refused: {:?}",
                        crate::credentials::rescue::platform_error_kind(&e)
                    ),
                }
            })?;
        }

        // Create (or open) the lock file and take the exclusive lock within
        // the derived budget. Opening happens ONCE; only the lock attempts
        // are retried (`try_lock_file_bounded`).
        let Some(guard) =
            lock::try_lock_file_bounded(&path, profiles_lock_attempts(), PROFILES_LOCK_DELAY)
                .map_err(|e| ConfigError::InvalidJson {
                    path: path.clone(),
                    // R3 corr L-1: the io kind is part of the durable failure text so
                    // a non-contention fault is never mistaken for busy.
                    reason: format!(
                        "profiles_lock_refused: {:?}",
                        crate::credentials::rescue::platform_error_kind(&e)
                    ),
                })?
        else {
            return Ok(None);
        };

        // Best-effort secure_file AFTER the lock is taken — on a fresh
        // install the file does not exist before the lock call creates it, so
        // calling secure_file before would be a silent no-op.  The lock file
        // carries no secrets; failure is non-fatal on FAT/network mounts.
        secure_file(&path).ok();

        Ok(Some(Self {
            _guard: guard,
            path,
        }))
    }

    /// A nonblocking authority witness for bounded keychain operations.
    pub fn try_acquire(base_dir: &Path) -> Result<Option<Self>, ConfigError> {
        let path = Self::lock_path(base_dir);
        if let Some(parent) = path.parent() {
            crate::platform::fs::ensure_private_dir_root(parent).map_err(|e| {
                ConfigError::InvalidJson {
                    path: path.clone(),
                    reason: format!(
                        "profiles_lock_parent_refused: {:?}",
                        crate::credentials::rescue::platform_error_kind(&e)
                    ),
                }
            })?;
        }
        let guard = lock::try_lock_file_bounded_nofollow(&path, 1, std::time::Duration::ZERO)
            .map_err(|e| ConfigError::InvalidJson {
                path: path.clone(),
                // A single attempt never waits, so ANY error here is a
                // non-contention lock fault. Carry the io kind (R3 corr L-1).
                reason: format!(
                    "profiles_lock_refused: {:?}",
                    crate::credentials::rescue::platform_error_kind(&e)
                ),
            })?;
        Ok(guard.map(|guard| Self {
            _guard: guard,
            path,
        }))
    }

    /// Returns the lock file path. Useful for tests and diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A lock witness must protect the same namespace as the operation.
    pub fn protects(&self, base: &Path) -> bool {
        self.path
            .parent()
            .and_then(|p| std::fs::canonicalize(p).ok())
            == std::fs::canonicalize(base).ok()
            && std::fs::canonicalize(base).is_ok()
    }
}

/// R3 corr L-1: a [`ProfilesFileLock`] failure is CONTENTION only when the
/// derived budget ([`PROFILES_LOCK_BUDGET`]) expired. A lock-file or
/// parent-directory I/O failure (EACCES, EROFS, ENOSPC, a path that is a
/// directory, …) is a permanent local fault — callers MUST NOT report it as
/// "busy; retried next tick", because no later tick clears it.
pub fn failure_is_contention(error: &ConfigError) -> bool {
    matches!(
        error,
        ConfigError::InvalidJson { reason, .. } if reason.starts_with("profiles_lock_busy")
    )
}

/// Fixed-vocabulary tag for a NON-contention [`ProfilesFileLock`] failure:
/// `profiles_lock_parent_refused` (the accounts root could not be secured) or
/// `profiles_lock_refused` (the lock file could not be opened/locked). The
/// reason string also carries the [`std::io::ErrorKind`] (`{kind:?}`), never
/// an arbitrary OS message.
pub fn failure_reason(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::InvalidJson { reason, .. }
            if reason.starts_with("profiles_lock_parent_refused") =>
        {
            "profiles_lock_parent_refused"
        }
        _ => "profiles_lock_refused",
    }
}

impl std::fmt::Debug for ProfilesFileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfilesFileLock")
            .field("path", &self.path)
            .finish()
    }
}

/// Test-only holder that owns a lock on a DIFFERENT thread for its lifetime.
///
/// Windows named mutexes (the `platform::lock` implementation there) are
/// re-entrant per thread: a second acquire on the holding thread returns
/// immediately, so a same-thread holder never produces contention on
/// Windows. POSIX `flock` contends per open file description, so a
/// cross-thread holder contends on every platform and is the portable
/// fixture for "another writer holds the lock". The guard is acquired AND
/// released on the holder thread (a Windows mutex must be released by its
/// owning thread).
#[cfg(test)]
pub(crate) struct HeldOnOtherThread {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
#[cfg(test)]
impl HeldOnOtherThread {
    /// Runs `acquire` on a new thread and returns once it holds the guard.
    pub(crate) fn hold<G: 'static>(acquire: impl FnOnce() -> G + Send + 'static) -> Self {
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let guard = acquire();
            let _ = held_tx.send(());
            let _ = release_rx.recv();
            drop(guard);
        });
        // Constructed before the readiness check so a failed acquisition
        // still joins the holder thread through Drop.
        let held = Self {
            release: Some(release_tx),
            thread: Some(thread),
        };
        held_rx
            .recv()
            .expect("lock holder thread must acquire before the test proceeds");
        held
    }
    /// Holds `<base_dir>/.profiles.lock` on another thread.
    pub(crate) fn profiles(base_dir: &Path) -> Self {
        let base = base_dir.to_owned();
        Self::hold(move || ProfilesFileLock::acquire(&base).expect("profiles lock"))
    }
}
#[cfg(test)]
impl Drop for HeldOnOtherThread {
    fn drop(&mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() && !std::thread::panicking() {
                panic!("lock holder thread panicked");
            }
        }
    }
}
/// Test-only: runs `probe` on another thread and returns its result, so a
/// lock the CALLING thread holds is observed as contended on every platform
/// (see [`HeldOnOtherThread`] for the Windows re-entrancy reason).
#[cfg(test)]
pub(crate) fn on_other_thread<R: Send>(probe: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| scope.spawn(probe).join().expect("probe thread"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── basic acquire / release ────────────────────────────────────────────

    #[test]
    fn acquire_succeeds_on_fresh_dir() {
        // Arrange
        let dir = TempDir::new().unwrap();

        // Act
        let result = ProfilesFileLock::acquire(dir.path());

        // Assert
        assert!(
            result.is_ok(),
            "acquire must succeed on a fresh dir: {:?}",
            result.err()
        );
        let guard = result.unwrap();
        assert!(
            guard.path().ends_with(".profiles.lock"),
            "lock path must end with .profiles.lock"
        );
    }

    /// R3 corr L-1: a lock-file I/O failure (here EISDIR from a directory at
    /// the lock path; EACCES/EROFS/ENOSPC behave alike) is NOT contention.
    /// Its reason carries the io kind in fixed vocabulary, and the failure
    /// classifier keeps it out of the "busy; retried next tick" class.
    ///
    /// RED on the pre-fix code: the reason embedded the arbitrary
    /// `PlatformError` Display and no classifier existed — every caller that
    /// collapsed the error into "busy" hid this permanent fault forever.
    #[cfg(unix)]
    #[test]
    fn lock_io_refusal_carries_io_kind_and_is_not_contention() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(ProfilesFileLock::lock_path(dir.path())).unwrap();

        let error = ProfilesFileLock::acquire(dir.path()).unwrap_err();
        assert!(
            matches!(&error, ConfigError::InvalidJson { reason, .. }
                if reason.starts_with("profiles_lock_refused: ")),
            "expected the lock-file refusal class, got {error:?}"
        );
        assert!(
            !failure_is_contention(&error),
            "an io fault must never be classified as contention: {error:?}"
        );
        assert_eq!(failure_reason(&error), "profiles_lock_refused");
    }

    #[test]
    fn lock_creates_lock_file_if_missing() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".profiles.lock");
        assert!(
            !lock_path.exists(),
            "lock file must not exist before acquire"
        );

        // Act
        let _guard = ProfilesFileLock::acquire(dir.path()).unwrap();

        // Assert: the lock file was created (Unix path; on Windows the
        // lock is a named mutex, not a file, so only assert on Unix)
        #[cfg(unix)]
        assert!(
            lock_path.exists(),
            "lock file must exist after acquire on Unix"
        );
    }

    #[test]
    fn lock_released_after_drop() {
        // Arrange
        let dir = TempDir::new().unwrap();

        // Act: acquire and drop
        {
            let _guard = ProfilesFileLock::acquire(dir.path()).unwrap();
        }

        // Assert: can acquire again immediately (lock was released)
        let result = ProfilesFileLock::acquire(dir.path());
        assert!(
            result.is_ok(),
            "second acquire must succeed after drop: {:?}",
            result.err()
        );
    }

    /// Validates that releasing the lock on panic still allows re-acquisition.
    /// Relevant to `lock_released_on_panic` requirement.
    #[test]
    fn lock_released_on_panic() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        // Act: acquire in a thread that panics while holding the lock
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = ProfilesFileLock::acquire(&dir_path).unwrap();
                // Notify main thread that we hold the lock
                tx.send(()).unwrap();
                panic!("simulated panic while holding profiles lock");
            }));
        });

        // Wait for the thread to acquire before we join
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("thread should have acquired lock");
        let _ = handle.join(); // catches the unwind

        // Assert: after panic + unwind, the lock is released
        let result = ProfilesFileLock::acquire(dir.path());
        assert!(
            result.is_ok(),
            "lock must be released after panic-induced drop: {:?}",
            result.err()
        );
    }

    #[test]
    fn lock_path_is_dot_profiles_lock_under_base_dir() {
        let dir = TempDir::new().unwrap();
        let path = ProfilesFileLock::lock_path(dir.path());
        assert_eq!(path, dir.path().join(".profiles.lock"));
    }

    /// R3-LOW-2: `secure_file` must run AFTER `lock_file` creates the file.
    ///
    /// On a fresh install the `.profiles.lock` file does not exist before
    /// `acquire` is called.  If `secure_file` ran first it would either error
    /// silently (the file is absent) or be a no-op.  This test verifies that
    /// after `acquire` the lock file exists AND has 0o600 permissions —
    /// meaning `secure_file` executed on an existing file, not before
    /// `lock_file` created it.
    #[cfg(unix)]
    #[test]
    fn lock_file_exists_at_0o600_after_acquire_on_fresh_dir() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange: fresh dir with no .profiles.lock
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".profiles.lock");
        assert!(
            !lock_path.exists(),
            "lock file must not exist before acquire"
        );

        // Act
        let guard = ProfilesFileLock::acquire(dir.path()).expect("acquire must succeed");

        // Assert: lock file exists
        assert!(
            lock_path.exists(),
            "lock file must exist after acquire (lock_file creates it)"
        );

        // Assert: permissions are 0o600 (secure_file ran after lock_file)
        let mode = std::fs::metadata(&lock_path)
            .expect("lock file metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "lock file must be 0o600 after acquire — secure_file ran after lock_file; mode={mode:o}"
        );

        drop(guard);
    }

    // ── bounded expiry (D237 round 2 — lock class treatment) ───────────────

    /// A holder that OUTLASTS [`PROFILES_LOCK_BUDGET`] makes `acquire` fail
    /// closed with the fixed-vocabulary class error, within a bounded wait,
    /// having written nothing.
    ///
    /// Non-vacuity (RED): the holder sleeps past the budget and then releases.
    /// An unbounded `lock::lock_file` acquire therefore BLOCKS until the
    /// release and returns `Ok` — this test reds by ASSERTION on the
    /// `Ok(_) => panic!` arm (it does not hang, because the holder always
    /// releases). The bounded implementation returns `Err` at the budget.
    #[test]
    fn acquire_expires_within_the_declared_budget_when_a_holder_outlasts_it() {
        let dir = TempDir::new().unwrap();
        let lock_path = ProfilesFileLock::lock_path(dir.path());

        // A pre-existing custody payload that a refused acquire must not touch.
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        let sentinel = br#"{"sentinel":"must-not-be-rewritten"}"#;
        std::fs::write(&profiles_path, sentinel).unwrap();

        // Test-only override: the production budget is 35 s, and the point of
        // this row is the EXPIRY path, not the wall clock. The derivation of
        // the production budget is guarded by the `const` assertions above
        // and by `profiles_budget_outlasts_the_post_commit_holder` below.
        const OVERRIDE_ATTEMPTS: u32 = 5;
        let _budget = ProfilesBudgetOverrideGuard::install(OVERRIDE_ATTEMPTS);
        let effective_budget = PROFILES_LOCK_DELAY * OVERRIDE_ATTEMPTS;

        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let guard =
                crate::platform::lock::lock_file(&lock_path).expect("holder takes the lock");
            held_tx.send(()).expect("signal held");
            // Outlast the waiter's budget, then release so the OLD unbounded
            // implementation would return Ok (a red by assertion, not a hang).
            std::thread::sleep(effective_budget + std::time::Duration::from_millis(500));
            drop(guard);
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("holder must acquire before the waiter runs");

        let started = std::time::Instant::now();
        let result = ProfilesFileLock::acquire(dir.path());
        let elapsed = started.elapsed();
        holder.join().expect("holder thread must exit");

        match result {
            Err(ConfigError::InvalidJson { path, reason }) => {
                assert_eq!(path, ProfilesFileLock::lock_path(dir.path()));
                assert!(
                    reason.starts_with("profiles_lock_busy"),
                    "expiry must use the fixed-vocabulary class error, got {reason:?}"
                );
                assert!(
                    !reason.contains('/') && !reason.contains('\\'),
                    "the expiry reason must not carry a path, got {reason:?}"
                );
            }
            Ok(_) => panic!(
                "acquire must fail closed once the holder outlasts the budget — an \
                 unbounded wait returns Ok here"
            ),
            Err(other) => panic!("expected the profiles_lock_busy class error, got {other:?}"),
        }
        assert!(
            elapsed >= effective_budget - PROFILES_LOCK_DELAY,
            "the waiter must actually use its attempt budget (not skip it): {elapsed:?}"
        );
        assert!(
            elapsed < effective_budget + std::time::Duration::from_secs(2),
            "a wedged holder must not pin the waiter (bounded return): {elapsed:?}"
        );
        assert_eq!(
            std::fs::read(&profiles_path).unwrap(),
            sentinel,
            "a refused acquire must write nothing — no custody metadata without the lock"
        );
    }

    /// D237 round-2 corr N4 / sec M4: the profiles budget MUST outlast the
    /// longest holder section — a post-commit login publication waiting on
    /// the canonical lock under `CREDENTIAL_COMMIT_LOCK_BUDGET`. The old
    /// derivation (4 x 500 ms = 2 s) inverted this; the const assertions in
    /// the module make that inversion a build failure, and this row pins the
    /// runtime relationship operators read.
    #[test]
    fn profiles_budget_outlasts_the_post_commit_holder() {
        assert!(
            PROFILES_LOCK_BUDGET > crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET,
            "the profiles waiter budget must exceed the nested canonical commit wait"
        );
        assert!(
            PROFILES_LOCK_BUDGET
                >= crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET
                    + crate::credentials::rescue::CREDENTIAL_COMMIT_IO_ALLOWANCE,
            "the profiles budget must add the holder's local-I/O allowance"
        );
    }
}
