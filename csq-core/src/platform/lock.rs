//! File locking — POSIX `flock` on Unix, named mutexes on Windows.
//!
//! All locking is exposed through [`lock_file`] (blocking) and
//! [`try_lock_file`] (non-blocking). Both return an RAII guard that
//! releases the lock on drop.

use crate::error::PlatformError;
use std::path::Path;

// ── Public API (platform-dispatched) ──────────────────────────────────

/// Acquires an exclusive lock on `path`, blocking until available.
///
/// Returns a guard that releases the lock on drop. On Unix the lock file is
/// created if it does not exist; on Windows the lock is a named mutex keyed
/// on `path` and NO file is created, so a caller that needs the file on disk
/// (e.g. a liveness sidecar another process probes) creates it explicitly.
///
/// On Windows the lock is re-entrant on the thread that holds it: a second
/// acquisition of the same path from the holding thread succeeds at once
/// instead of contending. A contention test therefore holds the lock on a
/// different thread from the one that probes it. Across threads and
/// processes both platforms contend.
///
/// Refused (`Err`) when taking `path` would break the lock order in
/// [`order`].
pub fn lock_file(path: &Path) -> Result<FileLockGuard, PlatformError> {
    let class = order::admit(path)?;
    imp::lock_file(path).map(|raw| raw.register(class))
}

/// Attempts to acquire an exclusive lock without blocking.
///
/// Returns `Ok(Some(guard))` if acquired, `Ok(None)` if the lock is held
/// elsewhere: by another process, by another thread of this process, or (on
/// Unix only) by another open of the same file on the calling thread.
/// File creation and Windows same-thread re-entrancy are as in
/// [`lock_file`]: on Windows no file is created, and the thread that holds
/// the lock gets `Ok(Some(_))` again rather than `Ok(None)`.
pub fn try_lock_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
    let class = order::admit(path)?;
    imp::try_lock_file(path).map(|raw| raw.map(|raw| raw.register(class)))
}

/// Attempts to acquire an exclusive lock on `path`, retrying up to
/// `attempts` times with `delay` between attempts.
///
/// Unlike calling [`try_lock_file`] in a caller-side loop, the
/// underlying OS handle (file descriptor on Unix, mutex handle on
/// Windows) is obtained EXACTLY ONCE — only the lock-acquisition
/// attempt itself is retried. A caller-side loop around
/// `try_lock_file` re-opens the lock file (a real `open(2)` syscall) on
/// every attempt; on a slow filesystem (network home directory, FUSE
/// mount) that re-open cost stacks on top of every retry's `delay` and
/// makes a documented "`attempts * delay`" bound false — the real worst
/// case becomes `attempts * (open latency + delay)`.
///
/// Returns `Ok(Some(guard))` if acquired within the budget, `Ok(None)`
/// if every attempt failed to acquire (the lock was held by another
/// process for the whole window).
pub fn try_lock_file_bounded(
    path: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<Option<FileLockGuard>, PlatformError> {
    let class = order::admit(path)?;
    imp::try_lock_file_bounded(path, attempts, delay).map(|raw| raw.map(|raw| raw.register(class)))
}

/// [`try_lock_file_bounded`] for a lock file in a directory the current user
/// shares with less-trusted writers (e.g. `~/.local/bin`): on Unix the file is
/// opened `O_NOFOLLOW` with mode `0o600`, so a planted symlink at the lock path
/// is REFUSED (an `Err`) instead of followed; an already-existing lock file is
/// accepted only if it is a regular file owned by the current user with no
/// group/other permission bits (`fstat` on the opened fd), else an `Err`. Elsewhere identical to
/// [`try_lock_file_bounded`].
pub fn try_lock_file_bounded_nofollow(
    path: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<Option<FileLockGuard>, PlatformError> {
    let class = order::admit(path)?;
    #[cfg(unix)]
    let raw = imp::try_lock_file_bounded_nofollow(path, attempts, delay);
    #[cfg(not(unix))]
    let raw = imp::try_lock_file_bounded(path, attempts, delay);
    raw.map(|raw| raw.map(|raw| raw.register(class)))
}

/// Attempts in the bounded budget for a lock taken on a PRE-COMMIT or
/// PRE-HTTP path — a place where a refusal is free because nothing has been
/// consumed yet and the next tick retries.
///
/// This is a TYPICAL-CASE allowance, not a worst-case derivation. A live
/// holder is usually (typical case — not a bound) doing bounded local work:
/// read the record, validate it, serialize, `atomic_replace`. The tree also
/// contains longer holders, and this budget must not be described as
/// outlasting them: `credentials::file::save_anthropic_canonical_guarded_locked`
/// scans sibling canonicals under the canonical lock (O(accounts) file
/// reads), and a canonical section nests a token-history lock wait.
///
/// Network I/O or a subprocess under a credential lock is a DEFECT, never a
/// bound. The tree had one: `credentials::keychain::resolve_pending_clear_at_creation_with`
/// held the pending-clears lock across a `security` subprocess and a Node
/// HTTP adopt call. That path is split (snapshot, release, act, relock) so
/// its locked sections are local-only, and durable records use
/// [`lock_durable_record_file`] instead of this constant.
///
/// What still bounds each section: the at-creation resolve's snapshot section
/// is ONE bounded queue load and its removal section ONE bounded load+save;
/// `sweep_pending_clears_inner`'s removal section is one bounded load, an
/// in-memory retain, and one bounded save (the `security` calls run outside
/// it); `token_history::append_history`/`start_new_segment` are one bounded
/// read, an in-memory edit, and one bounded atomic write. None performs
/// network I/O, spawns a subprocess, or waits on user input, so their
/// duration is bounded by fixed operation counts over byte-capped files —
/// not by a timeout. 50 attempts × 10 ms = 500 ms is a deliberate pre-commit
/// policy: a WEDGED holder (stopped process, stuck filesystem, crashed lock
/// owner) exceeds it and the caller fails closed instead of blocking a
/// refresher forever. Raise this only with a measured critical-section
/// duration, never to "wait longer".
pub const CREDENTIAL_LOCK_ATTEMPTS: u32 = 50;

/// Delay between attempts in [`CREDENTIAL_LOCK_ATTEMPTS`]'s budget.
pub const CREDENTIAL_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// Per-transaction wait for the PRE-COMMIT credential locks — DERIVED from
/// [`CREDENTIAL_LOCK_ATTEMPTS`] × [`CREDENTIAL_LOCK_DELAY`], never a literal
/// or a measured value.
///
/// The Unix backend makes `ATTEMPTS` flock attempts with `DELAY` between them
/// (wall clock `(ATTEMPTS - 1) * DELAY` plus syscall time, under this same
/// bound). The Windows backend turns it into ONE total deadline shared by its
/// three named-mutex waits.
///
/// This is the budget for call sites that may safely REFUSE: a pre-HTTP
/// preflight, a recoverable read-modify-write whose next tick retries.
/// DURABLE-RECORD paths — a write whose loss is not recoverable by a later
/// read — MUST use [`DURABLE_RECORD_LOCK_BUDGET`] instead. A downstream
/// deadline that must outlast every credential transaction composes from
/// BOTH constants.
pub const CREDENTIAL_LOCK_BUDGET: std::time::Duration =
    CREDENTIAL_LOCK_DELAY.saturating_mul(CREDENTIAL_LOCK_ATTEMPTS);

/// [`CREDENTIAL_LOCK_BUDGET`] in whole milliseconds, for fixed-vocabulary
/// error text.
pub const CREDENTIAL_LOCK_BUDGET_MS: u64 = CREDENTIAL_LOCK_BUDGET.as_millis() as u64;

/// Acquires a lock that guards credential material within
/// [`CREDENTIAL_LOCK_BUDGET`].
///
/// `Ok(None)` means the budget expired while another process held the lock.
/// Callers MUST fail closed on it: never write without the lock and never
/// silently skip a credential write (`security.md` MUST-6 / §5a). Errors
/// behave exactly as [`try_lock_file_bounded`]'s.
pub fn lock_credential_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
    try_lock_file_bounded(path, CREDENTIAL_LOCK_ATTEMPTS, CREDENTIAL_LOCK_DELAY)
}

/// Per-holder-section allowance used to derive
/// [`DURABLE_RECORD_LOCK_BUDGET`]. This is a POLICY allowance, not a
/// measurement (see that constant's derivation): the enforced property is the
/// fixed operation/byte count each holder section may perform, stated in the
/// keychain/token-history lock table, not a stopwatch reading.
pub const DURABLE_RECORD_LOCK_SECTION_ALLOWANCE_MS: u64 = 1_000;

/// How many DISTINCT holder sections of a durable-record lock can stand
/// between one acquisition request and the lock becoming free.
///
/// Enumerated from the tree (the pending-clears lock; the token-history lock
/// has two and uses this same conservative count):
/// 1. `credentials::keychain::record_pending_clear_with_identity` — one
///    bounded queue load, an optional bounded spool drain, an in-memory
///    edit, one bounded save.
/// 2. `credentials::keychain::sweep_pending_clears_inner` — one bounded
///    queue load, an in-memory retain/backoff edit, one bounded save.
/// 3. `credentials::keychain::resolve_pending_clear_at_creation_with`'s
///    snapshot section — one bounded queue load.
/// 4. The same function's removal section — one bounded queue load, one
///    entry removal, one bounded save.
///
/// Concurrent waiters are NOT counted: the retry loop interleaves them, and
/// every section above is bounded local work. Expiry is SAFE on these paths
/// — the caller records the intent durably (a spool file / pending append)
/// instead of dropping it — so this constant governs availability, never
/// correctness.
pub const DURABLE_RECORD_LOCK_HOLDER_SECTIONS_AHEAD: u32 = 4;

/// Delay between attempts in the durable-record budget.
pub const DURABLE_RECORD_LOCK_DELAY: std::time::Duration = CREDENTIAL_LOCK_DELAY;

/// Attempts for [`lock_durable_record_file`], DERIVED from
/// [`DURABLE_RECORD_LOCK_SECTION_ALLOWANCE_MS`] ×
/// [`DURABLE_RECORD_LOCK_HOLDER_SECTIONS_AHEAD`] ÷
/// [`DURABLE_RECORD_LOCK_DELAY`] — never a literal chosen to "wait longer".
///
/// `1_000 ms × 4 ÷ 10 ms = 400`, i.e. a 4 s budget, eight times the
/// pre-commit [`CREDENTIAL_LOCK_BUDGET`]. A PRE-COMMIT budget is at or below
/// a live holder's composed worst case (a canonical section nests a
/// token-history wait and scans sibling canonicals), so using it for a
/// durable record loses the record under ordinary contention; see
/// `review-check-discipline.md` D237 round-2 ruling B/H2 and the
/// `CREDENTIAL_LOCK_ATTEMPTS` doc for the sections that still bound each
/// holder.
pub const DURABLE_RECORD_LOCK_ATTEMPTS: u32 =
    (DURABLE_RECORD_LOCK_SECTION_ALLOWANCE_MS * DURABLE_RECORD_LOCK_HOLDER_SECTIONS_AHEAD as u64
        / DURABLE_RECORD_LOCK_DELAY.as_millis() as u64) as u32;

/// The durable-record lock budget — [`DURABLE_RECORD_LOCK_ATTEMPTS`] ×
/// [`DURABLE_RECORD_LOCK_DELAY`].
pub const DURABLE_RECORD_LOCK_BUDGET: std::time::Duration =
    DURABLE_RECORD_LOCK_DELAY.saturating_mul(DURABLE_RECORD_LOCK_ATTEMPTS);

/// [`DURABLE_RECORD_LOCK_BUDGET`] in whole milliseconds, for
/// fixed-vocabulary error text.
pub const DURABLE_RECORD_LOCK_BUDGET_MS: u64 = DURABLE_RECORD_LOCK_BUDGET.as_millis() as u64;

/// Acquires a lock whose protected section IS the persistence of a durable
/// record — a logout's pending keychain clear, a token-history fingerprint,
/// a new-segment intent — within [`DURABLE_RECORD_LOCK_BUDGET`].
///
/// `Ok(None)`/`Err` mean the budget expired (or the lock file was
/// unreadable) while another process held the lock. A caller of a durable
/// record MUST NOT treat that as "drop the record": it MUST persist the
/// intent through its durable fallback (a spool file the sweep merges, a
/// pending-append the next locked read drains) and log a fixed-vocabulary
/// tag. `security.md` MUST-6 / §5a still forbid writing the record WITHOUT
/// the lock; the fallback is a separate, uniquely named file, never an
/// unlocked write of the guarded record.
pub fn lock_durable_record_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
    try_lock_file_bounded(
        path,
        DURABLE_RECORD_LOCK_ATTEMPTS,
        DURABLE_RECORD_LOCK_DELAY,
    )
}

/// Refusal to wait on a Windows lock mutex that already exists but is owned
/// by a different principal than the current user.
///
/// Carried as the source of a `PlatformError::Io` with
/// `ErrorKind::PermissionDenied`; match it with
/// `io_error.get_ref().and_then(|e| e.downcast_ref::<ForeignLockOwner>())`.
/// Only constructed on Windows (Unix `flock` locks have no separate owner).
#[derive(Debug, thiserror::Error)]
#[error("lock mutex for {} exists but is owned by another user; refusing to wait on it", .path.display())]
pub struct ForeignLockOwner {
    /// The lock path whose mutex is foreign-owned.
    pub path: std::path::PathBuf,
}

// ── Guard type ────────────────────────────────────────────────────────

/// RAII guard that releases the lock on drop.
pub struct FileLockGuard {
    // Held for its Drop impl — releasing the lock on scope exit.
    _inner: imp::InnerGuard,
    // Held for its Drop impl — leaving the lock-order registry. Declared AFTER
    // `_inner` so the OS lock is released before the registry forgets it.
    _order: order::Registration,
}

/// What an `imp` acquisition returns, before the lock-order registry has
/// recorded it. Only this module turns it into a [`FileLockGuard`].
struct RawGuard {
    _inner: imp::InnerGuard,
}

impl RawGuard {
    fn register(self, class: order::Class) -> FileLockGuard {
        FileLockGuard {
            _inner: self._inner,
            _order: order::register(class),
        }
    }
}

impl std::fmt::Debug for FileLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLockGuard").finish_non_exhaustive()
    }
}

// ── Lock order: the term mint lock is a LEAF ──────────────────────────

/// The lock-order contract for the one lock that is a LEAF: the term mint lock
/// ([`order::MINT_LOCK_FILENAME`], `<accounts>/.term-mint.lock`).
///
/// * Taken for a `term-<pid>` creation, and by the keychain orphan sweep from
///   its final "dir is gone" check through its `security delete`.
/// * It is NEVER acquired while this thread holds a swap lock (`.swap-lock`,
///   the A4a keychain-desync guard, or `.swap.lock`, the rename lock; they are
///   two files and merging them self-deadlocks) or the keychain pending-clears
///   lock; and NO lock of any kind is acquired while this thread holds it.
///
/// Enforced here, at the one chokepoint every acquisition passes through, not by
/// convention: `admit` refuses with an `Err` (the caller fails closed: a
/// creator refuses the launch, the sweep keeps the item, a swap skips) and logs
/// a fixed tag. Scope: this registry sees only locks taken through
/// `platform::lock` on this thread (a lock opened directly with `std::fs`, such
/// as the mirror-status writer lock, is not tracked).
pub mod order {
    use super::PlatformError;
    use std::path::Path;
    use std::sync::Mutex;
    use std::thread::ThreadId;

    /// File name of the term mint lock, under the accounts dir.
    pub const MINT_LOCK_FILENAME: &str = ".term-mint.lock";

    /// File names of the swap locks and the keychain write lock: the locks the
    /// mint lock must never be taken under.
    const SWAP_AND_KEYCHAIN_WRITE_LOCKS: &[&str] =
        &[".swap-lock", ".swap.lock", "keychain-pending-clears.lock"];

    /// Which side of the contract a lock path is on.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Class {
        Mint,
        SwapOrKeychainWrite,
        Other,
    }

    /// Classify a lock path by its file name.
    pub fn classify(path: &Path) -> Class {
        match path.file_name().and_then(|n| n.to_str()) {
            Some(MINT_LOCK_FILENAME) => Class::Mint,
            Some(name) if SWAP_AND_KEYCHAIN_WRITE_LOCKS.contains(&name) => {
                Class::SwapOrKeychainWrite
            }
            _ => Class::Other,
        }
    }

    struct Held {
        id: u64,
        thread: ThreadId,
        class: Class,
    }

    // A global registry, not a thread-local: a guard dropped on a different
    // thread than the one that took it must still leave the registry.
    static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    fn held() -> std::sync::MutexGuard<'static, Vec<Held>> {
        // The registry holds plain data; a poisoned lock is still consistent.
        HELD.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Refuse an acquisition that would break the contract, else return its class.
    pub(super) fn admit(path: &Path) -> Result<Class, PlatformError> {
        let class = classify(path);
        let me = std::thread::current().id();
        let violated = held().iter().filter(|h| h.thread == me).any(|h| {
            match (class, h.class) {
                // Nothing at all while the leaf is held (including a second
                // take of the leaf itself, which would self-deadlock a blocking
                // acquire through a different file description).
                (_, Class::Mint) => true,
                // The leaf is never taken under a swap or keychain write lock.
                (Class::Mint, Class::SwapOrKeychainWrite) => true,
                _ => false,
            }
        });
        if violated {
            tracing::error!(
                error_kind = "lock_order_violation",
                "refusing a lock acquisition that breaks the term mint lock's leaf order"
            );
            return Err(PlatformError::Io(std::io::Error::other(
                "lock order violation: the term mint lock is a leaf",
            )));
        }
        Ok(class)
    }

    /// RAII entry in the registry; leaves it on drop.
    pub(super) struct Registration {
        id: Option<u64>,
    }

    pub(super) fn register(class: Class) -> Registration {
        // Only the two classes the contract names are tracked; `Other` locks
        // are admitted but need no entry (nothing is ordered against them).
        if class == Class::Other {
            return Registration { id: None };
        }
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        held().push(Held {
            id,
            thread: std::thread::current().id(),
            class,
        });
        Registration { id: Some(id) }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            if let Some(id) = self.id {
                held().retain(|h| h.id != id);
            }
        }
    }
}

/// Test-only holder of a lock on a SECOND thread, released and joined on
/// drop.
///
/// Windows locks are re-entrant on the holding thread (see [`lock_file`]), so
/// a test that holds a lock and calls the code under test on the same thread
/// never reaches the contended branch there. Holding through this type makes
/// the contended branch run on every OS. It holds only the lock: on Windows
/// it creates no file, so a test that needs the file creates it itself.
#[cfg(test)]
pub(crate) struct HeldOnOtherThread {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl HeldOnOtherThread {
    /// Blocks until the holder thread has acquired `path`. Panics if the
    /// acquisition fails; the holder thread is joined on that path too.
    pub(crate) fn hold(path: &Path) -> Self {
        let path = path.to_path_buf();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || match lock_file(&path) {
            Ok(guard) => {
                let _ = ready_tx.send(Ok(()));
                // Returns on an explicit release or when the sender drops.
                let _ = release_rx.recv();
                drop(guard);
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
            }
        });
        // Constructed before the readiness check so an unwind from the panics
        // below still joins the thread through Drop.
        let held = Self {
            release: Some(release),
            thread: Some(thread),
        };
        match ready_rx.recv() {
            Ok(Ok(())) => held,
            Ok(Err(e)) => panic!("holder thread could not take the lock: {e}"),
            Err(_) => panic!("holder thread exited before reporting the lock"),
        }
    }

    /// Releases the lock and joins the holder thread.
    pub(crate) fn release(self) {
        drop(self);
    }
}

#[cfg(test)]
impl Drop for HeldOnOtherThread {
    fn drop(&mut self) {
        // Dropping the sender wakes the holder, which releases the lock.
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            if let Err(payload) = thread.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(payload);
                }
            }
        }
    }
}

// ── Unix implementation (flock) ───────────────────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::unix::io::AsRawFd;

    pub struct InnerGuard {
        file: File,
    }

    impl Drop for InnerGuard {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    pub fn lock_file(path: &Path) -> Result<RawGuard, PlatformError> {
        let file = open_lock_file(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        Ok(RawGuard {
            _inner: InnerGuard { file },
        })
    }

    pub fn try_lock_file(path: &Path) -> Result<Option<RawGuard>, PlatformError> {
        let file = open_lock_file(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(PlatformError::Io(err));
        }
        Ok(Some(RawGuard {
            _inner: InnerGuard { file },
        }))
    }

    fn open_lock_file(path: &Path) -> Result<File, PlatformError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(PlatformError::Io)
    }

    pub fn try_lock_file_bounded_nofollow(
        path: &Path,
        attempts: u32,
        delay: std::time::Duration,
    ) -> Result<Option<RawGuard>, PlatformError> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            // O_NONBLOCK so a FIFO planted at the path can never wedge the open.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(PlatformError::Io)?;
        // A PRE-EXISTING file is only accepted when it is what we would have
        // created: a regular file, owned by us, with no group/other access.
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(PlatformError::Io)?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !m.is_file() || m.uid() != euid || m.mode() & 0o077 != 0 {
            return Err(PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lock file is not a private regular file owned by the current user",
            )));
        }
        lock_bounded_on(file, attempts, delay)
    }

    pub fn try_lock_file_bounded(
        path: &Path,
        attempts: u32,
        delay: std::time::Duration,
    ) -> Result<Option<RawGuard>, PlatformError> {
        // Opened ONCE — every retry below re-attempts flock(2) on this
        // SAME fd, never re-opening the file (see the public doc
        // comment on `try_lock_file_bounded`).
        let file = open_lock_file(path)?;
        lock_bounded_on(file, attempts, delay)
    }

    fn lock_bounded_on(
        file: File,
        attempts: u32,
        delay: std::time::Duration,
    ) -> Result<Option<RawGuard>, PlatformError> {
        for attempt in 0..attempts {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(Some(RawGuard {
                    _inner: InnerGuard { file },
                }));
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(PlatformError::Io(err));
            }
            if attempt + 1 < attempts {
                std::thread::sleep(delay);
            }
        }
        Ok(None)
    }
}

// ── Windows implementation (named mutex) ──────────────────────────────

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use tracing::warn;

    // Win32 constants
    const WAIT_OBJECT_0: u32 = 0x00000000;
    const WAIT_ABANDONED: u32 = 0x00000080;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const INFINITE: u32 = 0xFFFFFFFF;

    extern "system" {
        fn CreateMutexW(
            lpMutexAttributes: *const std::ffi::c_void,
            bInitialOwner: i32,
            lpName: *const u16,
        ) -> *mut std::ffi::c_void;
        fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
        fn ReleaseMutex(hMutex: *mut std::ffi::c_void) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
        fn SetLastError(dwErrCode: u32);
        fn OpenMutexW(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            lpName: *const u16,
        ) -> *mut std::ffi::c_void;
    }

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    // SYNCHRONIZE | MUTEX_MODIFY_STATE: all a waiter needs on a foreign mutex.
    const WAIT_AND_RELEASE_ACCESS: u32 = 0x0010_0000 | 0x0001;

    /// Every mutex this lock holds, in ACQUISITION order (legacy local,
    /// legacy Global if present, canonical). Dropped in REVERSE order.
    pub struct InnerGuard {
        handles: Vec<*mut std::ffi::c_void>,
    }

    // SAFETY: The mutex handles are process-scoped and safe to send across threads.
    unsafe impl Send for InnerGuard {}

    impl Drop for InnerGuard {
        fn drop(&mut self) {
            for handle in self.handles.drain(..).rev() {
                // SAFETY: each handle was acquired by this guard and is
                // released/closed exactly once, last-acquired first.
                unsafe {
                    ReleaseMutex(handle);
                    CloseHandle(handle);
                }
            }
        }
    }

    /// Produces a mutex name hash from a path.
    ///
    /// Hashes the raw wide-char path on Windows (not the lossy
    /// UTF-8 form) so non-UTF-8 sequences and surrogate halves
    /// don't collide on `U+FFFD`. Uses the full path — callers
    /// can pre-canonicalize if case-insensitivity matters.
    fn hash_path(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        // Convert u16 to bytes for hashing (little-endian).
        let mut bytes = Vec::with_capacity(wide.len() * 2);
        for u in &wide {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let digest = Sha256::digest(&bytes);
        // 16 hex chars = 64 bits — sufficient collision resistance
        // for the file-system lock paths on a single machine.
        hex::encode(&digest[..8])
    }

    /// Produces a Windows named mutex name for a path:
    /// `Local\csq-lock-{hash}`, the per-session namespace.
    ///
    /// Every csq process on Windows (CLI, desktop, the daemon they spawn)
    /// runs in the user's interactive session — csq installs no service and
    /// nothing in session 0 — so cross-session visibility is never needed.
    /// Always `Local\` (never `Global\` when elevated, `Local\` otherwise)
    /// keeps an elevated and an unelevated csq process locking the same path
    /// on the SAME name. Opening that one object from both sides additionally
    /// needs its integrity label to admit a Medium opener: the descriptor
    /// (`fs_windows_acl::DescriptorKind::Object`) sets an explicit Medium
    /// no-write-up label, so the label never follows the creator's level.
    ///
    /// NOTE — same-process/same-thread re-entrancy: Windows named
    /// mutexes are re-entrant within the same thread.
    /// `WaitForSingleObject` returns WAIT_OBJECT_0 immediately if
    /// the calling thread already owns the mutex, so same-thread
    /// contention tests are unreliable.  Cross-thread and cross-
    /// process tests work correctly.
    pub(super) fn mutex_name(path: &Path) -> Vec<u16> {
        let hash_hex = hash_path(path);
        format!("Local\\csq-lock-{hash_hex}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    /// The path a lock is named by: the CANONICAL parent directory joined
    /// with the lock file's own name.
    ///
    /// `flock` on Unix contends on the opened file, so every spelling of one
    /// lock path (`/var/…` vs `/private/var/…`, a symlinked accounts root)
    /// contends with every other. A named mutex contends only on an equal
    /// NAME, and the name is a hash of the path string, so without this two
    /// callers spelling one lock file differently (`C:\…` vs the verbatim
    /// `\\?\C:\…` that `canonicalize` returns, an 8.3 short component, a
    /// symlinked root, a different letter case) would each hold the "same"
    /// lock at once. Canonicalizing the parent resolves all of those to the
    /// one on-disk spelling `canonicalize` produces. The leaf is not
    /// resolved, only ASCII-lowercased: Windows file names are
    /// case-insensitive, so case variants of one leaf must map to one mutex
    /// (the lock's own file is not created by the mutex; callers such as
    /// `messaging::request::ensure_windows_lock_file` may create `.lock`
    /// files separately). A parent that cannot be canonicalized
    /// (absent, unreadable) is an error — the same outcome as Unix, whose
    /// `open(O_CREAT)` of a lock file in a missing directory fails.
    pub(super) fn lock_identity(path: &Path) -> Result<std::path::PathBuf, PlatformError> {
        let leaf = path.file_name().ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "lock path has no file name",
            ))
        })?;
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let folded: Vec<u16> = leaf
            .encode_wide()
            .map(|u| match u {
                0x41..=0x5A => u + 0x20,
                other => other,
            })
            .collect();
        Ok(std::fs::canonicalize(parent)?
            .join(<std::ffi::OsString as std::os::windows::ffi::OsStringExt>::from_wide(&folded)))
    }

    /// Creates (or opens) the path's named mutex with an owner-only
    /// protected DACL (`fs_windows_acl::OwnerOnlyObjectSecurity`). The
    /// descriptor applies when this call creates the object; an existing
    /// object created by another principal with a DACL denying this user
    /// fails here (`ERROR_ACCESS_DENIED`) rather than being silently shared.
    /// A descriptor that cannot be built fails closed: no mutex is created.
    ///
    /// When the mutex already EXISTS (`ERROR_ALREADY_EXISTS`) the descriptor
    /// above was not applied, so the existing object's owner is read back:
    /// another csq process of this user (the normal case) proceeds; a
    /// different owner is refused with [`ForeignLockOwner`] instead of being
    /// waited on, and an unreadable owner is refused too (fail closed).
    pub(super) fn create_mutex(path: &Path) -> Result<*mut std::ffi::c_void, PlatformError> {
        open_or_create_mutex(path).map(|(handle, _existed)| handle)
    }

    /// [`create_mutex`] that also reports whether the mutex already existed.
    pub(super) fn open_or_create_mutex(
        path: &Path,
    ) -> Result<(*mut std::ffi::c_void, bool), PlatformError> {
        let security = crate::platform::fs_windows_acl::OwnerOnlyObjectSecurity::current_user()
            .map_err(|e| PlatformError::Io(e.into()))?;
        let attributes = security.attributes();
        let name = mutex_name(&lock_identity(path)?);
        // SAFETY: `attributes` points into `security`, and both it and `name`
        // stay alive until this synchronous call returns.
        // SetLastError(0) first so a stale ERROR_ALREADY_EXISTS from an
        // earlier call can never be read as "this mutex existed".
        let (handle, last_error) = unsafe {
            SetLastError(0);
            let handle = CreateMutexW(
                (&attributes as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
                0,
                name.as_ptr(),
            );
            (handle, GetLastError())
        };
        if !handle.is_null() {
            if last_error != ERROR_ALREADY_EXISTS {
                return Ok((handle, false));
            }
            // The handle carries MUTEX_ALL_ACCESS (includes READ_CONTROL).
            return match crate::platform::fs_windows_acl::object_owned_by_current_user(handle as _)
            {
                Ok(true) => Ok((handle, true)),
                Ok(false) => {
                    unsafe { CloseHandle(handle) };
                    Err(PlatformError::Io(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        ForeignLockOwner {
                            path: path.to_path_buf(),
                        },
                    )))
                }
                Err(e) => {
                    unsafe { CloseHandle(handle) };
                    Err(PlatformError::Io(e.into()))
                }
            };
        }
        Err(PlatformError::Win32 {
            code: unsafe { GetLastError() },
            message: "CreateMutexW failed in Local namespace".into(),
        })
    }

    // ── Legacy-compatibility acquisition ──────────────────────────────
    //
    // REMOVAL TRIGGER (guard-reader-writer-parity MUST-5): delete this whole
    // section (`legacy_*`, `LEGACY_GLOBAL_AVAILABLE`, steps 1-2 of `acquire`)
    // once the first release whose minimum supported RUNNING version
    // already uses the canonical `Local\` scheme has shipped (no released
    // build that names mutexes `csq-lock-<hash(raw)>` /
    // `Global\csq-lock-<hash(raw)>` can still be running), and no earlier
    // than 2027-01-31.
    //
    // Released builds named the mutex by the RAW caller path: `Global\` when
    // the process could create Global objects (elevated), else the implicit
    // per-session name. An old process therefore holds exactly ONE of the
    // two legacy names; taking BOTH excludes every old build. Fixed global
    // order, identical in every new process (so none can deadlock another):
    // (1) legacy local, (2) legacy Global, (3) canonical. Release in reverse.

    /// Legacy per-session name `csq-lock-<hash(raw path)>`, byte-identical
    /// to the released `mutex_name(path, false)`.
    pub(super) fn legacy_local_name(raw: &Path) -> Vec<u16> {
        format!("csq-lock-{}", hash_path(raw))
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Legacy `Global\csq-lock-<hash(raw path)>`, byte-identical to the
    /// released `mutex_name(path, true)`.
    pub(super) fn legacy_global_name(raw: &Path) -> Vec<u16> {
        format!("Global\\csq-lock-{}", hash_path(raw))
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Whether this process can CREATE Global objects (the released probe,
    /// cached per process). Per-PID probe name so an existing object is
    /// never mistaken for a successful create.
    static LEGACY_GLOBAL_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    fn probe_global_create() -> bool {
        let probe: Vec<u16> = format!("Global\\csq-probe-{}", std::process::id())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `probe` is NUL-terminated and outlives the call.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, probe.as_ptr()) };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            warn!(
                error = err,
                "Global\\ create unavailable; legacy Global lock is joined only when it already exists"
            );
            return false;
        }
        // SAFETY: handle is the valid handle just created.
        unsafe { CloseHandle(handle) };
        true
    }

    /// Creates or opens one legacy-named mutex with the SAME owner-only
    /// descriptor as the canonical mutex (`OwnerOnlyObjectSecurity`).
    ///
    /// A NULL descriptor would give a new ELEVATED creator an Administrators
    /// default DACL plus a High label, and a later non-elevated csq process
    /// would get ACCESS_DENIED instead of waiting. Old builds call
    /// `CreateMutexW(NULL)`, which on an EXISTING object only opens it, so
    /// they stay compatible. An existing object this user cannot open (an old
    /// elevated build created it first) fails here: fail closed.
    /// Returns the handle and whether the object already existed.
    fn create_legacy_mutex(
        name: &[u16],
        what: &'static str,
    ) -> Result<(*mut std::ffi::c_void, bool), PlatformError> {
        let security = crate::platform::fs_windows_acl::OwnerOnlyObjectSecurity::current_user()
            .map_err(|e| PlatformError::Io(e.into()))?;
        let attributes = security.attributes();
        // SAFETY: `attributes` points into `security` and `name` is
        // NUL-terminated; both outlive this synchronous call. SetLastError(0)
        // first so a stale ERROR_ALREADY_EXISTS is never read as "existed".
        let (handle, last_error) = unsafe {
            SetLastError(0);
            let handle = CreateMutexW(
                (&attributes as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
                0,
                name.as_ptr(),
            );
            (handle, GetLastError())
        };
        if handle.is_null() {
            return Err(PlatformError::Win32 {
                code: last_error,
                message: what.into(),
            });
        }
        Ok((handle, last_error == ERROR_ALREADY_EXISTS))
    }

    /// Whether the legacy per-session name IS the canonical object. An
    /// unprefixed name lives in the session namespace, exactly like
    /// `Local\`, so `csq-lock-<h>` and `Local\csq-lock-<h>` are one kernel
    /// object when the hashes (raw path vs canonical identity) match. The
    /// full names are compared, never an assumed hash shape.
    pub(super) fn legacy_local_aliases_canonical(raw: &Path) -> Result<bool, PlatformError> {
        let legacy = legacy_local_name(raw);
        let canonical = mutex_name(&lock_identity(raw)?);
        let session_prefixed: Vec<u16> = "Local\\".encode_utf16().chain(legacy).collect();
        Ok(session_prefixed == canonical)
    }

    /// Step 1: the legacy per-session mutex, created with the canonical
    /// owner-only descriptor. When it already EXISTS its owner is read back
    /// exactly as `open_or_create_mutex` does: a foreign owner is refused
    /// with [`ForeignLockOwner`] (a squatter pre-creating the name), an
    /// unreadable owner is refused too.
    pub(super) fn open_legacy_local(raw: &Path) -> Result<*mut std::ffi::c_void, PlatformError> {
        let name = legacy_local_name(raw);
        let (handle, existed) =
            create_legacy_mutex(&name, "CreateMutexW failed for legacy local lock")?;
        if !existed {
            return Ok(handle);
        }
        // The handle carries MUTEX_ALL_ACCESS (includes READ_CONTROL).
        match crate::platform::fs_windows_acl::object_owned_by_current_user(handle as _) {
            Ok(true) => Ok(handle),
            Ok(false) => {
                unsafe { CloseHandle(handle) };
                Err(PlatformError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    ForeignLockOwner {
                        path: raw.to_path_buf(),
                    },
                )))
            }
            Err(e) => {
                unsafe { CloseHandle(handle) };
                Err(PlatformError::Io(e.into()))
            }
        }
    }

    /// Step 2: the legacy Global mutex. A process that can create Global
    /// objects creates it (as released elevated builds did). One that cannot
    /// OPENS an existing one: `Ok(None)` only when it provably does not
    /// exist right now; if it exists but cannot be opened (DACL of an
    /// elevated creator) the lock is REFUSED (fail closed), since an old
    /// elevated holder is then live and cannot be waited on.
    ///
    /// Remaining window (unavoidable without `SeCreateGlobalPrivilege`): an
    /// old ELEVATED process may create the object right after this probe
    /// reports NotFound. Re-probing after step 3 would invert the global
    /// order against a new elevated process and could deadlock, so it is not
    /// done; the window closes once old builds are gone (removal trigger).
    pub(super) fn open_legacy_global(
        raw: &Path,
    ) -> Result<Option<*mut std::ffi::c_void>, PlatformError> {
        let name = legacy_global_name(raw);
        if *LEGACY_GLOBAL_AVAILABLE.get_or_init(probe_global_create) {
            // NO owner check on this name, deliberately: an old ELEVATED
            // build creates it owned by Administrators, so a foreign owner
            // is the normal legacy case here, not a squatter. An existing
            // object we cannot open still fails closed in the create.
            let (handle, _existed) =
                create_legacy_mutex(&name, "CreateMutexW failed for legacy Global lock")?;
            return Ok(Some(handle));
        }
        // SAFETY: `name` is NUL-terminated and outlives the call.
        let handle = unsafe { OpenMutexW(WAIT_AND_RELEASE_ACCESS, 0, name.as_ptr()) };
        if !handle.is_null() {
            return Ok(Some(handle));
        }
        match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(PlatformError::Win32 {
                code,
                message: "legacy Global lock exists but cannot be opened; refusing to proceed"
                    .into(),
            }),
        }
    }

    /// Milliseconds left before `deadline` (`INFINITE` for no deadline).
    fn remaining_ms(deadline: Option<std::time::Instant>) -> u32 {
        match deadline {
            None => INFINITE,
            Some(d) => d
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(u128::from(INFINITE - 1)) as u32,
        }
    }

    /// Waits on `handle`; on success moves it into `guard`. `Ok(false)` =
    /// timed out (handle closed). Any other outcome closes it and errors.
    fn wait_into(
        handle: *mut std::ffi::c_void,
        timeout_ms: u32,
        guard: &mut InnerGuard,
        path: &Path,
    ) -> Result<bool, PlatformError> {
        // SAFETY: `handle` is a valid mutex handle owned by this call.
        let wait_result = unsafe { WaitForSingleObject(handle, timeout_ms) };
        match wait_result {
            WAIT_OBJECT_0 => {
                guard.handles.push(handle);
                Ok(true)
            }
            WAIT_ABANDONED => {
                // GAP-8: treat as acquired but log a warning — the previous
                // holder crashed without releasing.
                warn!(
                    path = %path.display(),
                    "mutex acquired after WAIT_ABANDONED (previous holder crashed)"
                );
                guard.handles.push(handle);
                Ok(true)
            }
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(handle) };
                Ok(false)
            }
            _ => {
                unsafe { CloseHandle(handle) };
                Err(PlatformError::Win32 {
                    code: wait_result,
                    message: format!("WaitForSingleObject returned {wait_result:#x}"),
                })
            }
        }
    }

    /// Acquires (1) legacy local, (2) legacy Global, (3) canonical, in that
    /// fixed order, within `timeout` in total (`None` = wait forever).
    /// `Ok(None)` = ANY of the three is held past the budget; everything
    /// already taken is released (guard drop, reverse order).
    fn acquire(
        path: &Path,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<InnerGuard>, PlatformError> {
        // Fail early on an unresolvable parent, before taking anything.
        lock_identity(path)?;
        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let mut guard = InnerGuard {
            handles: Vec::with_capacity(3),
        };
        // When the legacy local name IS the canonical object, step 1 would
        // take it first without the canonical owner policy; skip it and let
        // step 3 create and owner-check that one object.
        if !legacy_local_aliases_canonical(path)?
            && !wait_into(
                open_legacy_local(path)?,
                remaining_ms(deadline),
                &mut guard,
                path,
            )?
        {
            return Ok(None);
        }
        if let Some(handle) = open_legacy_global(path)? {
            if !wait_into(handle, remaining_ms(deadline), &mut guard, path)? {
                return Ok(None);
            }
        }
        if !wait_into(
            create_mutex(path)?,
            remaining_ms(deadline),
            &mut guard,
            path,
        )? {
            return Ok(None);
        }
        Ok(Some(guard))
    }

    pub fn lock_file(path: &Path) -> Result<RawGuard, PlatformError> {
        match acquire(path, None)? {
            Some(inner) => Ok(RawGuard { _inner: inner }),
            None => Err(PlatformError::Win32 {
                code: WAIT_TIMEOUT,
                message: "infinite lock wait reported timeout".into(),
            }),
        }
    }

    pub fn try_lock_file(path: &Path) -> Result<Option<RawGuard>, PlatformError> {
        Ok(acquire(path, Some(std::time::Duration::ZERO))?.map(|inner| RawGuard { _inner: inner }))
    }

    pub fn try_lock_file_bounded(
        path: &Path,
        attempts: u32,
        delay: std::time::Duration,
    ) -> Result<Option<RawGuard>, PlatformError> {
        // One TOTAL budget shared by all three waits, clamped to u32 ms as
        // before, so the bounded variant stays bounded (security.md MUST-6).
        let total_ms = delay
            .saturating_mul(attempts)
            .as_millis()
            .min(u128::from(INFINITE - 1)) as u64;
        Ok(
            acquire(path, Some(std::time::Duration::from_millis(total_ms)))?
                .map(|inner| RawGuard { _inner: inner }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn nofollow_lock_refuses_wrong_mode_fifo_and_foreign_file_but_accepts_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::time::Duration::ZERO;
        let dir = TempDir::new().unwrap();
        // group/other-accessible pre-existing file -> refused
        let loose = dir.path().join("loose.lock");
        std::fs::write(&loose, b"").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(try_lock_file_bounded_nofollow(&loose, 1, d).is_err());
        // FIFO -> refused, and the call returns (does not block)
        let fifo = dir.path().join("fifo.lock");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = std::time::Instant::now();
        assert!(try_lock_file_bounded_nofollow(&fifo, 1, d).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        // a private pre-existing regular file we own -> accepted
        let ok = dir.path().join("ok.lock");
        std::fs::write(&ok, b"").unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(try_lock_file_bounded_nofollow(&ok, 1, d).unwrap().is_some());
        // a fresh path is created 0o600 and accepted
        let fresh = dir.path().join("fresh.lock");
        assert!(try_lock_file_bounded_nofollow(&fresh, 1, d)
            .unwrap()
            .is_some());
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o077,
            0
        );
    }

    /// The term mint lock is a LEAF, enforced at the chokepoint: refused under a
    /// swap or keychain write lock, and every lock (itself included) refused
    /// under it. RED against an `admit` that always allows.
    #[test]
    fn the_mint_lock_is_a_leaf_in_both_directions() {
        let dir = TempDir::new().unwrap();
        let none = std::time::Duration::ZERO;
        let mint = dir.path().join(order::MINT_LOCK_FILENAME);
        let swap = dir.path().join(".swap-lock");
        let rename = dir.path().join(".swap.lock");
        let pending = dir.path().join("keychain-pending-clears.lock");
        let other = dir.path().join("profiles.lock");

        // (1) the mint lock is never taken under a swap or keychain write lock.
        for held in [&swap, &rename, &pending] {
            let guard = lock_file(held).unwrap();
            assert!(try_lock_file(&mint).is_err(), "under {held:?}");
            assert!(
                try_lock_file_bounded(&mint, 1, none).is_err(),
                "under {held:?}"
            );
            assert!(lock_file(&mint).is_err(), "under {held:?}");
            drop(guard);
            assert!(
                try_lock_file(&mint).unwrap().is_some(),
                "free once {held:?} is released"
            );
        }

        // (2) no lock of any kind is taken under the mint lock.
        let guard = try_lock_file(&mint).unwrap().unwrap();
        for p in [&swap, &rename, &pending, &other, &mint] {
            assert!(try_lock_file(p).is_err(), "{p:?}");
            assert!(try_lock_file_bounded(p, 1, none).is_err(), "{p:?}");
            assert!(lock_file(p).is_err(), "{p:?}");
        }
        drop(guard);

        // (3) an unrelated lock does not constrain the mint lock.
        let o = lock_file(&other).unwrap();
        assert!(try_lock_file(&mint).unwrap().is_some());
        drop(o);
    }

    /// The order is per thread (another thread's swap lock is not this
    /// thread's), and a guard dropped on a different thread than the one that
    /// took it still leaves the registry (no stale "held" entry).
    #[test]
    fn the_lock_order_is_per_thread_and_survives_a_cross_thread_drop() {
        let dir = TempDir::new().unwrap();
        let mint = dir.path().join(order::MINT_LOCK_FILENAME);
        let swap = dir.path().join(".swap-lock");

        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let swap2 = swap.clone();
        let other_thread = std::thread::spawn(move || {
            let _swap = lock_file(&swap2).unwrap();
            held_tx.send(()).unwrap();
            let _ = go_rx.recv();
        });
        held_rx.recv().unwrap();
        assert!(
            try_lock_file(&mint).unwrap().is_some(),
            "another thread's swap lock does not forbid this thread's mint lock"
        );
        go_tx.send(()).unwrap();
        other_thread.join().unwrap();

        let guard = lock_file(&swap).unwrap();
        std::thread::spawn(move || drop(guard)).join().unwrap();
        assert!(
            try_lock_file(&mint).unwrap().is_some(),
            "a swap guard dropped on another thread must leave the registry"
        );
    }

    #[test]
    fn lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let guard = lock_file(&lock_path).unwrap();
        drop(guard);

        // Can re-acquire after drop
        let _guard2 = lock_file(&lock_path).unwrap();
    }

    /// The credential-lock budget is bounded on BOTH platforms and a live
    /// holder cannot extend it. The probe runs on another thread: Windows
    /// named mutexes are re-entrant per thread.
    #[test]
    fn lock_credential_file_expires_against_a_held_lock() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("credential.lock");
        let held = lock_file(&lock_path).unwrap();
        let started = std::time::Instant::now();
        let expired = std::thread::scope(|scope| {
            scope
                .spawn(|| lock_credential_file(&lock_path).unwrap().is_none())
                .join()
                .unwrap()
        });
        let elapsed = started.elapsed();
        assert!(
            expired,
            "the bounded acquisition must expire against a held lock"
        );
        // Unix sleeps only between attempts, so it waits out one delay less
        // than the full Windows deadline. Both must reach that derived floor.
        assert!(
            elapsed >= CREDENTIAL_LOCK_BUDGET - CREDENTIAL_LOCK_DELAY,
            "expiry returned before the budget elapsed: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "expiry did not return promptly: {elapsed:?}"
        );
        drop(held);
        // No leaked guard: the lock is immediately re-acquirable.
        assert!(try_lock_file(&lock_path).unwrap().is_some());
    }

    #[test]
    fn credential_lock_budget_matches_attempts_times_delay() {
        assert_eq!(
            CREDENTIAL_LOCK_BUDGET_MS,
            u64::from(CREDENTIAL_LOCK_ATTEMPTS) * CREDENTIAL_LOCK_DELAY.as_millis() as u64
        );
    }

    /// The durable-record budget is DERIVED from the named per-section
    /// allowance and holder-section count — not a literal — and it is
    /// strictly larger than the pre-commit budget it must outlast.
    #[test]
    fn durable_record_lock_budget_is_derived_and_outlasts_the_pre_commit_budget() {
        assert_eq!(DURABLE_RECORD_LOCK_ATTEMPTS, 400);
        assert_eq!(
            DURABLE_RECORD_LOCK_BUDGET,
            std::time::Duration::from_secs(4)
        );
        assert_eq!(
            DURABLE_RECORD_LOCK_BUDGET_MS,
            DURABLE_RECORD_LOCK_SECTION_ALLOWANCE_MS
                * u64::from(DURABLE_RECORD_LOCK_HOLDER_SECTIONS_AHEAD)
        );
        assert!(
            DURABLE_RECORD_LOCK_BUDGET > CREDENTIAL_LOCK_BUDGET,
            "a durable record must be allowed to outlast every pre-commit section"
        );
    }

    /// Two spellings of ONE lock file contend. The holder locks the raw
    /// temp path; a probe on ANOTHER thread (Windows mutexes are re-entrant
    /// per thread) locks the canonical spelling — `\\?\C:\…` on Windows,
    /// `/private/var/…` on macOS. RED on Windows when the mutex name hashes
    /// the caller's path string: the two names differ and both acquire.
    #[test]
    fn differently_spelled_paths_to_one_lock_contend() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("spelling.lock");
        let canonical = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("spelling.lock");
        let _held = lock_file(&raw).unwrap();
        let probe = std::thread::scope(|scope| {
            scope
                .spawn(|| try_lock_file(&canonical).unwrap().is_none())
                .join()
                .unwrap()
        });
        assert!(probe, "canonical spelling must observe the raw-path holder");
    }

    #[test]
    fn try_lock_returns_none_when_held() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let _guard = lock_file(&lock_path).unwrap();

        // Same process, different fd — flock allows this on some systems,
        // but we test the cross-process case below in integration tests.
        // For the unit test, just verify the API works.
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let guard = try_lock_file(&lock_path).unwrap();
        assert!(guard.is_some());
    }

    /// On Unix, `lock_file` creates an actual `.lock` file via
    /// `OpenOptions::create(true)`. On Windows, the "lock" is a
    /// named kernel mutex — no file is created by the locking
    /// primitive itself, so this assertion is Unix-only.
    #[test]
    #[cfg(unix)]
    fn lock_creates_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("new.lock");
        assert!(!lock_path.exists());

        let _guard = lock_file(&lock_path).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn lock_guard_is_debug() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("debug.lock");
        let guard = lock_file(&lock_path).unwrap();
        let s = format!("{guard:?}");
        assert!(s.contains("FileLockGuard"));
    }

    /// The mutex name is `Local\csq-lock-<16 hex>`: exactly one backslash
    /// (the namespace separator), never anything from the path itself.
    #[test]
    #[cfg(windows)]
    fn mutex_name_is_local_with_only_namespace_separator() {
        use std::path::Path;

        let path = Path::new(r"C:\Users\runner\AppData\Local\Temp\test.lock");
        let wide = imp::mutex_name(path);
        let decoded = String::from_utf16(&wide[..wide.len() - 1]).unwrap();

        assert!(
            decoded.starts_with("Local\\csq-lock-"),
            "unexpected name: {decoded}"
        );
        assert_eq!(
            decoded.chars().filter(|c| *c == '\\').count(),
            1,
            "name must have exactly one backslash (namespace separator): {decoded}"
        );
        let hash_part = &decoded["Local\\csq-lock-".len()..];
        assert_eq!(hash_part.len(), 16);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Native: the created mutex carries a PROTECTED DACL with exactly one
    /// ACE. RED under the previous NULL security descriptor, which gives a
    /// named object the creator's default (unprotected) DACL.
    #[test]
    #[cfg(windows)]
    fn native_windows_lock_mutex_has_protected_single_ace_dacl() {
        use windows_sys::Win32::Security::{
            Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
            GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        };
        let dir = TempDir::new().unwrap();
        let handle = imp::create_mutex(&dir.path().join("acl.lock")).unwrap();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        // SAFETY: live mutex handle; output slots are valid; sd is LocalFree'd.
        let rc = unsafe {
            GetSecurityInfo(
                handle as _,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetSecurityInfo failed: {rc}");
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: sd was returned by GetSecurityInfo above and is still live.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) },
            0
        );
        assert!(!dacl.is_null(), "mutex must carry a DACL");
        // SAFETY: non-null DACL pointer into the live descriptor.
        let ace_count = unsafe { (*dacl).AceCount };
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(sd);
            windows_sys::Win32::Foundation::CloseHandle(handle as _);
        }
        assert_ne!(control & SE_DACL_PROTECTED, 0, "DACL must be protected");
        assert_eq!(ace_count, 1, "owner-only DACL must have exactly one ACE");
    }

    /// Native: the created mutex carries exactly one mandatory label ACE —
    /// Medium (`S-1-16-8192`), no-write-up. RED without the explicit label:
    /// the SACL then has no label ACE (Medium/High creators get none by
    /// default) or one at the creator's own level (`S-1-16-12288` elevated).
    #[test]
    #[cfg(windows)]
    fn native_windows_lock_mutex_has_medium_no_write_up_label() {
        let dir = TempDir::new().unwrap();
        let handle = imp::create_mutex(&dir.path().join("label.lock")).unwrap();
        assert_medium_no_write_up_label(handle);
    }

    /// Asserts `handle` carries exactly one Medium no-write-up label ACE,
    /// then closes it.
    #[cfg(windows)]
    fn assert_medium_no_write_up_label(handle: *mut std::ffi::c_void) {
        use windows_sys::Win32::Security::{
            Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT},
            GetAce, ACE_HEADER, ACL, LABEL_SECURITY_INFORMATION, SYSTEM_MANDATORY_LABEL_ACE,
        };
        // WinNT.h values; windows-sys 0.52 exposes them only under the
        // `Win32_System_SystemServices` feature, which csq-core does not enable.
        const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u32 = 0x11;
        const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x1;
        let mut sacl: *mut ACL = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        // SAFETY: live mutex handle (MUTEX_ALL_ACCESS includes READ_CONTROL,
        // which a label query needs); output slots valid; sd LocalFree'd.
        let rc = unsafe {
            GetSecurityInfo(
                handle as _,
                SE_KERNEL_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sacl,
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetSecurityInfo(label) failed: {rc}");
        let mut ace_count = 0u16;
        let mut ace_type = 0u8;
        let mut mask = 0u32;
        let mut sid_text = String::new();
        if !sacl.is_null() {
            // SAFETY: non-null SACL pointer into the live descriptor; the ACE
            // and its SID are read only after GetAce succeeds and the header
            // names the mandatory-label layout.
            unsafe {
                ace_count = (*sacl).AceCount;
                let mut ace = std::ptr::null_mut();
                if ace_count >= 1 && GetAce(sacl, 0, &mut ace) != 0 && !ace.is_null() {
                    ace_type = (*ace.cast::<ACE_HEADER>()).AceType;
                    if u32::from(ace_type) == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                        let label = &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
                        mask = label.Mask;
                        let sid = std::ptr::addr_of!(label.SidStart) as *mut std::ffi::c_void;
                        let mut text = std::ptr::null_mut();
                        if ConvertSidToStringSidW(sid, &mut text) != 0 {
                            let mut len = 0;
                            while len < 256 && *text.add(len) != 0 {
                                len += 1;
                            }
                            sid_text =
                                String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
                            windows_sys::Win32::Foundation::LocalFree(text.cast());
                        }
                    }
                }
            }
        }
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(sd);
            windows_sys::Win32::Foundation::CloseHandle(handle as _);
        }
        assert_eq!(ace_count, 1, "SACL must carry exactly the label ACE");
        assert_eq!(u32::from(ace_type), SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        assert_eq!(
            mask, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            "policy must be NW"
        );
        assert_eq!(sid_text, "S-1-16-8192", "label must be Medium");
    }

    /// Native: opening an EXISTING same-user mutex takes the owner-check
    /// branch and proceeds. The first assertion proves the branch ran (the
    /// second open reports `existed`); the open then succeeds only if the
    /// owner read back equals the current user — RED if the owner check
    /// misread or refused a same-user mutex. The cross-user refusal cannot be
    /// exercised in CI (it needs a second account to pre-create the mutex);
    /// the predicate's `false` answer is pinned on a system-owned object in
    /// `native_windows_owner_predicate_rejects_system_owned_object`.
    #[test]
    #[cfg(windows)]
    fn native_windows_existing_same_user_mutex_passes_owner_check() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("owner.lock");
        let (first, first_existed) = imp::open_or_create_mutex(&path).unwrap();
        assert!(!first_existed, "first open must create the mutex");
        let (second, second_existed) = imp::open_or_create_mutex(&path)
            .expect("same-user existing mutex must pass the owner check");
        assert!(second_existed, "second open must take the existing branch");
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(first as _);
            windows_sys::Win32::Foundation::CloseHandle(second as _);
        }
        let guard = try_lock_file(&path).unwrap();
        assert!(guard.is_some(), "lock must still be acquirable");
    }

    /// Native: the owner predicate answers `false` for an object owned by
    /// another principal (a system DLL, owned by TrustedInstaller), so the
    /// same-user `true` above discriminates. RED if the predicate always
    /// answered `true`.
    #[test]
    #[cfg(windows)]
    fn native_windows_owner_predicate_rejects_system_owned_object() {
        use std::os::windows::io::AsRawHandle;
        let root = std::env::var_os("SystemRoot").expect("SystemRoot set on Windows");
        let dll = std::path::Path::new(&root)
            .join("System32")
            .join("kernel32.dll");
        let file = std::fs::File::open(&dll).unwrap();
        let owned = crate::platform::fs_windows_acl::object_owned_by_current_user(
            file.as_raw_handle() as _,
        )
        .unwrap();
        assert!(
            !owned,
            "a system-owned object must not read as the current user's"
        );
    }

    /// Two distinct paths must produce distinct mutex names.
    #[test]
    #[cfg(windows)]
    fn mutex_name_distinct_for_distinct_paths() {
        use std::path::Path;

        let a = imp::mutex_name(Path::new(r"C:\Temp\a.lock"));
        let b = imp::mutex_name(Path::new(r"C:\Temp\b.lock"));
        assert_ne!(a, b, "different paths must yield different mutex names");
    }

    /// The same path must always produce the same mutex name.
    #[test]
    #[cfg(windows)]
    fn mutex_name_deterministic() {
        use std::path::Path;

        let path = Path::new(r"C:\Temp\stable.lock");
        let first = imp::mutex_name(path);
        let second = imp::mutex_name(path);
        assert_eq!(first, second);
    }

    /// Holds a named mutex (created with NULL attributes, exactly as
    /// released builds did) on ANOTHER thread — Windows mutexes are
    /// re-entrant per thread — until dropped. `None` if creation is denied.
    #[cfg(windows)]
    struct LegacyHolder {
        release: std::sync::mpsc::Sender<()>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(windows)]
    impl LegacyHolder {
        fn hold(name: Vec<u16>) -> Option<Self> {
            extern "system" {
                fn CreateMutexW(
                    a: *const std::ffi::c_void,
                    o: i32,
                    n: *const u16,
                ) -> *mut std::ffi::c_void;
                fn WaitForSingleObject(h: *mut std::ffi::c_void, ms: u32) -> u32;
                fn ReleaseMutex(h: *mut std::ffi::c_void) -> i32;
                fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
            }
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
            let (release, release_rx) = std::sync::mpsc::channel::<()>();
            let thread = std::thread::spawn(move || {
                // SAFETY: name is NUL-terminated; handle used only on this thread.
                let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
                if h.is_null() || unsafe { WaitForSingleObject(h, 5000) } != 0 {
                    let _ = ready_tx.send(false);
                    return;
                }
                let _ = ready_tx.send(true);
                let _ = release_rx.recv();
                unsafe {
                    ReleaseMutex(h);
                    CloseHandle(h);
                }
            });
            if ready_rx.recv().unwrap_or(false) {
                Some(Self {
                    release,
                    thread: Some(thread),
                })
            } else {
                let _ = thread.join();
                None
            }
        }
    }

    #[cfg(windows)]
    impl Drop for LegacyHolder {
        fn drop(&mut self) {
            let _ = self.release.send(());
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// RED if the shim (step 1) is removed: an old non-elevated build holds
    /// `csq-lock-<hash(raw)>` and the new try-lock would acquire canonical.
    #[test]
    #[cfg(windows)]
    fn try_lock_reports_held_when_legacy_local_mutex_is_held() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("legacy-local.lock");
        let holder = LegacyHolder::hold(imp::legacy_local_name(&raw))
            .expect("legacy local mutex must be creatable");
        assert!(try_lock_file(&raw).unwrap().is_none());
        assert!(
            try_lock_file_bounded(&raw, 2, std::time::Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        drop(holder);
        assert!(
            try_lock_file(&raw).unwrap().is_some(),
            "free again once the legacy holder releases (no leaked handles)"
        );
    }

    /// RED if shim step 2 is removed. Skips VISIBLY if this runner cannot
    /// create a Global object (no SeCreateGlobalPrivilege).
    #[test]
    #[cfg(windows)]
    fn try_lock_reports_held_when_legacy_global_mutex_is_held() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("legacy-global.lock");
        let Some(holder) = LegacyHolder::hold(imp::legacy_global_name(&raw)) else {
            eprintln!(
                "SKIPPED: runner cannot create Global\\ mutexes; legacy-Global shim not exercised"
            );
            return;
        };
        assert!(try_lock_file(&raw).unwrap().is_none());
        assert!(
            try_lock_file_bounded(&raw, 2, std::time::Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        drop(holder);
        assert!(try_lock_file(&raw).unwrap().is_some());
    }

    /// The legacy names are byte-identical to the released scheme.
    #[test]
    #[cfg(windows)]
    fn legacy_names_have_released_shape() {
        let raw = Path::new(r"C:\Temp\x.lock");
        let local = String::from_utf16(&imp::legacy_local_name(raw)).unwrap();
        let global = String::from_utf16(&imp::legacy_global_name(raw)).unwrap();
        assert!(local.starts_with("csq-lock-") && !local.contains('\\'));
        assert_eq!(global, format!("Global\\{local}"));
        // Golden vector computed OUTSIDE this code: python3 -I
        // hashlib.sha256(r"C:\Temp\x.lock".encode("utf-16-le")).digest()[:8].hex()
        // using the released `hash_path` algorithm (origin/main lock.rs).
        assert_eq!(local.trim_end_matches('\0'), "csq-lock-b8ea5e9605ca8912");
        assert_eq!(
            global.trim_end_matches('\0'),
            "Global\\csq-lock-b8ea5e9605ca8912"
        );
    }

    /// RED if step 1 creates the legacy names with NULL attributes: a NULL
    /// descriptor yields no label ACE (Medium creator) or a High label
    /// (elevated creator), never the canonical Medium no-write-up label.
    #[test]
    #[cfg(windows)]
    fn native_windows_legacy_local_mutex_has_canonical_descriptor() {
        let dir = TempDir::new().unwrap();
        let handle = imp::open_legacy_local(&dir.path().join("lg-local.lock")).unwrap();
        assert_medium_no_write_up_label(handle);
    }

    /// Same for the legacy Global name (skips VISIBLY if the runner can
    /// neither create nor find a Global object).
    #[test]
    #[cfg(windows)]
    fn native_windows_legacy_global_mutex_has_canonical_descriptor() {
        let dir = TempDir::new().unwrap();
        match imp::open_legacy_global(&dir.path().join("lg-global.lock")).unwrap() {
            Some(handle) => assert_medium_no_write_up_label(handle),
            None => eprintln!("SKIPPED: runner cannot create Global\\ mutexes"),
        }
    }

    /// The legacy local name aliases the canonical object only when the
    /// raw path IS the canonical identity (hash(raw) == hash(identity)).
    /// RED if the predicate is constant either way.
    #[test]
    #[cfg(windows)]
    fn legacy_local_aliases_canonical_only_for_identity_path() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("Alias.lock");
        let identity = imp::lock_identity(&raw).unwrap();
        assert!(imp::legacy_local_aliases_canonical(&identity).unwrap());
        // Upper-case leaf differs from the folded identity: distinct names.
        assert!(!imp::legacy_local_aliases_canonical(&raw).unwrap());
    }

    /// Locking on the identity path itself (legacy local == canonical object)
    /// succeeds with no ForeignLockOwner and releases cleanly. RED on an
    /// elevated runner if step 1 took that object with a NULL descriptor
    /// (Administrators owner) before the canonical owner check.
    #[test]
    #[cfg(windows)]
    fn lock_on_identity_path_aliasing_canonical_succeeds() {
        let dir = TempDir::new().unwrap();
        let identity = imp::lock_identity(&dir.path().join("alias.lock")).unwrap();
        let guard = try_lock_file(&identity)
            .expect("aliased legacy/canonical name must not be refused as foreign");
        assert!(guard.is_some());
        drop(guard);
        assert!(try_lock_file(&identity).unwrap().is_some());
    }

    /// A legacy local name pre-created by a FOREIGN owner is refused with
    /// ForeignLockOwner. The squatter is made with owner `BA` (settable by an
    /// elevated token, e.g. the CI runner); skips VISIBLY when this token
    /// cannot create a foreign-owned object. RED without the owner check:
    /// `open_legacy_local` would return Ok on the existing object.
    #[test]
    #[cfg(windows)]
    fn native_windows_legacy_local_foreign_owner_is_refused() {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        extern "system" {
            fn CreateMutexW(
                a: *const std::ffi::c_void,
                o: i32,
                n: *const u16,
            ) -> *mut std::ffi::c_void;
            fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        }
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("squat.lock");
        let sddl: Vec<u16> = "O:BAD:(A;;GA;;;WD)\0".encode_utf16().collect();
        let mut sd = std::ptr::null_mut();
        // SAFETY: NUL-terminated SDDL, valid output slot, sd LocalFree'd below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "SDDL must parse");
        let attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let name = imp::legacy_local_name(&raw);
        // SAFETY: attrs/name outlive the call.
        let squatter = unsafe {
            CreateMutexW(
                (&attrs as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
                0,
                name.as_ptr(),
            )
        };
        unsafe { windows_sys::Win32::Foundation::LocalFree(sd) };
        let foreign = !squatter.is_null()
            && !crate::platform::fs_windows_acl::object_owned_by_current_user(squatter as _)
                .unwrap_or(true);
        if !foreign {
            if !squatter.is_null() {
                unsafe { CloseHandle(squatter) };
            }
            eprintln!("SKIPPED: this token cannot create a foreign-owned mutex");
            return;
        }
        let result = imp::open_legacy_local(&raw);
        unsafe { CloseHandle(squatter) };
        let err = result.expect_err("foreign-owned legacy local mutex must be refused");
        let is_foreign = match &err {
            PlatformError::Io(e) => e
                .get_ref()
                .and_then(|i| i.downcast_ref::<ForeignLockOwner>())
                .is_some(),
            _ => false,
        };
        assert!(is_foreign, "expected ForeignLockOwner, got {err:?}");
    }

    /// Case variants of one leaf map to one mutex identity and contend.
    #[test]
    #[cfg(windows)]
    fn case_variants_of_leaf_share_one_identity_and_contend() {
        let dir = TempDir::new().unwrap();
        let lower = dir.path().join("case.lock");
        let upper = dir.path().join("CASE.Lock");
        assert_eq!(
            imp::lock_identity(&lower).unwrap(),
            imp::lock_identity(&upper).unwrap()
        );
        let _held = lock_file(&lower).unwrap();
        let busy = std::thread::scope(|s| {
            s.spawn(|| try_lock_file(&upper).unwrap().is_none())
                .join()
                .unwrap()
        });
        assert!(busy, "case variant must observe the holder");
    }
}
