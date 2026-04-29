//! Per-account exclusive file lock for the `csq login N` flow.
//!
//! # Why this exists
//!
//! Two concurrent `csq login 5` processes can both reach
//! `prepare_race`, both bind a loopback port, both mint PKCE
//! verifiers, and both complete OAuth races. The last one to
//! finish stomps `accounts/credentials/5.json`. The first user's
//! tokens are silently lost; the user has no idea which session
//! "won."
//!
//! Holding an exclusive POSIX flock (Unix) / `LockFileEx` (Windows)
//! for the duration of the login serializes them. The second
//! process gets a clear error pointing at the holder PID so the
//! user knows which terminal already has the flow open.
//!
//! UX-R1-H3.
//!
//! # Lock file naming
//!
//! `<base_dir>/.login-N.lock` — sibling to `accounts/credentials/`
//! and `profiles.json`. The lock file CONTAINS the holder's PID as
//! decimal text so a concurrent attempt can render a useful error
//! ("PID 12345 is already running csq login 5"). On lock release
//! the file is *not* deleted: keeping it around lets the next
//! attempt re-use the same inode and ensures the lock survives
//! filesystem races between unlink and re-open. The PID inside is
//! cleared on release so a stale file never misattributes a fresh
//! lock attempt.

use crate::platform::fs::secure_file;
use crate::types::AccountNum;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Outcome of [`AccountLoginLock::acquire`].
pub enum AcquireOutcome {
    /// Caller now holds the lock; drop the returned guard to
    /// release.
    Acquired(AccountLoginLock),
    /// Another process holds the lock. The PID is the holder
    /// (read from the lock file) when available, `None` if the
    /// lock file is empty or unreadable.
    ///
    /// `pid_alive` is `Some(true)` when the holder PID is verifiably
    /// running, `Some(false)` when the PID is dead (stale lock from a
    /// prior crash), and `None` when no PID was readable or the
    /// liveness probe is unsupported on this platform.
    /// SEC-R2-08 / REV-R2-03 — distinguishes a real contention from a
    /// stale crash artefact so the caller can render a "the lock has
    /// been reclaimed" message instead of pointing at a dead PID.
    Held {
        pid: Option<u32>,
        pid_alive: Option<bool>,
    },
}

impl std::fmt::Debug for AcquireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquireOutcome::Acquired(g) => {
                f.debug_struct("Acquired").field("path", &g.path).finish()
            }
            AcquireOutcome::Held { pid, pid_alive } => f
                .debug_struct("Held")
                .field("pid", pid)
                .field("pid_alive", pid_alive)
                .finish(),
        }
    }
}

/// Exclusive per-account lock around the `csq login N` flow.
///
/// Acquired via [`AccountLoginLock::acquire`]; released on `Drop`.
/// The lock is process-scoped (POSIX flock on Unix, LockFileEx on
/// Windows) so a panic that unwinds past the guard still releases
/// it via the kernel's process-exit cleanup.
pub struct AccountLoginLock {
    file: File,
    path: PathBuf,
}

impl AccountLoginLock {
    /// Lock file path for `account` under `base_dir`. Exposed so
    /// tests can assert on the location without re-deriving it.
    pub fn lock_path(base_dir: &Path, account: AccountNum) -> PathBuf {
        base_dir.join(format!(".login-{}.lock", account.get()))
    }

    /// Tries to acquire the exclusive lock for `account`. Returns
    /// immediately with [`AcquireOutcome::Held`] if another process
    /// is already holding the lock — this is non-blocking by design
    /// so the CLI can render a clear error rather than appearing to
    /// hang.
    ///
    /// On success, the lock file is rewritten with the current
    /// process's PID so a concurrent attempt can identify the
    /// holder.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on filesystem errors (cannot create lock
    /// file, cannot write PID). A held lock is reported via
    /// [`AcquireOutcome::Held`], not as an error.
    pub fn acquire(base_dir: &Path, account: AccountNum) -> std::io::Result<AcquireOutcome> {
        // Make sure base_dir exists before trying to create the
        // lock file — otherwise the OpenOptions open would fail
        // with ENOENT, which would mask the real "your base dir is
        // missing" error.
        if !base_dir.exists() {
            std::fs::create_dir_all(base_dir)?;
        }

        let path = Self::lock_path(base_dir, account);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        // SEC-R2-07 / UX-R2-04: secure the lock file so a same-host
        // attacker cannot read the holder PID through a world-readable
        // file. The PID itself is low-impact, but a per-account stream
        // of "csq is logging in for slot N" timing data is exactly the
        // information a side-channel attack would seek. `secure_file`
        // is best-effort — on Windows it's a no-op (ACL defaults
        // already protect owner-only) and on Unix it sets 0o600. A
        // failure here is non-fatal: the lock still works correctly,
        // the file is just at default umask.
        let _ = secure_file(&path);

        match try_lock_exclusive(&file)? {
            LockResult::Acquired => {
                // We own it. Write our PID so a concurrent waiter
                // can identify us. Truncate first because the file
                // may contain a previous holder's PID.
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                writeln!(file, "{}", std::process::id())?;
                file.flush()?;
                Ok(AcquireOutcome::Acquired(AccountLoginLock { file, path }))
            }
            LockResult::WouldBlock => {
                // Read the PID the holder wrote. Best-effort —
                // file may be empty if the holder hasn't written
                // its PID yet (microsecond window between open and
                // PID write).
                let mut buf = String::new();
                let _ = file.read_to_string(&mut buf);
                let pid = buf.trim().parse::<u32>().ok();
                // SEC-R2-08 / REV-R2-03: confirm the PID is alive. A
                // crashed login holder leaves a `.login-N.lock` file
                // on disk with its (now-dead) PID inside, but the OS
                // released the flock when the process exited — so any
                // FRESH attempt would actually succeed on `flock` and
                // fall through this branch. Reaching `WouldBlock` with
                // a dead PID written inside is the rarer race where
                // ANOTHER concurrent acquire holds the live flock but
                // hasn't yet rewritten the file with its own PID.
                // Either way, the user sees a more accurate message:
                // "stale lock file" when the file contents lie about
                // the holder, "PID N — wait or kill" when the holder
                // is verifiably alive.
                let pid_alive = pid.map(pid_is_alive);
                Ok(AcquireOutcome::Held { pid, pid_alive })
            }
        }
    }

    /// Returns the path to the lock file. Useful for tests and
    /// debugging output.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AccountLoginLock {
    fn drop(&mut self) {
        // Clear the PID before releasing so a stale file never
        // misattributes a future acquire attempt. Best-effort —
        // if truncate fails we still release the lock; the
        // outdated PID just becomes "holder unknown" on the next
        // contended acquire. The lock release itself happens via
        // the OS file-handle close, which the File's Drop impl
        // performs automatically AFTER our truncation here.
        let _ = self.file.set_len(0);
        let _ = self.file.flush();
        // POSIX flock is released when ALL handles to the open
        // file description are closed (the kernel does this on
        // File::drop). On Windows, LockFileEx is released by
        // CloseHandle, also driven by File::drop.
        //
        // REV-R2-02: actively delete the lock file after the kernel
        // releases the flock. Without this, every `csq login N` ever
        // run leaves a `.login-N.lock` artefact on disk that
        // accumulates across the lifetime of the install. The race
        // the original docstring warned about ("re-create vs remove")
        // is bounded by the next acquirer's `OpenOptions::create(true)`
        // which is atomic with respect to deletion: the worst case is
        // the next acquirer creates a fresh file with default umask,
        // and the SECURE_FILE call in `acquire` then sets it back to
        // 0o600 before any meaningful content is written. Best-effort
        // — a failure (filesystem unmounted, perms changed under us)
        // leaves the artefact but does not affect correctness.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LockResult {
    Acquired,
    WouldBlock,
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<LockResult> {
    use std::os::unix::io::AsRawFd;
    // LOCK_EX | LOCK_NB — exclusive, non-blocking.
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(LockResult::Acquired)
    } else {
        let err = std::io::Error::last_os_error();
        // EWOULDBLOCK / EAGAIN means another process holds the
        // lock. Anything else is a real error.
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            Ok(LockResult::WouldBlock)
        } else {
            Err(err)
        }
    }
}

/// Returns true when the given OS process ID corresponds to a process
/// that is currently alive (or for which we cannot tell — fail-open on
/// the "alive" side because reporting "stale lock — reclaimed" for a
/// live holder would mislead the user into killing nothing).
///
/// SEC-R2-08 / REV-R2-03: the lock file content is plain text that
/// outlives the holder process. A crash between flock acquire and
/// flock release leaves the PID inside but the kernel has reclaimed
/// the lock — so a fresh `acquire` would actually pass `flock`. Reaching
/// the contention path means a SECOND concurrent acquirer holds the live
/// flock; we use this probe to disambiguate "the file says PID 12345
/// but that PID is dead" (stale artefact) from "PID 12345 is the active
/// holder" (real contention).
///
/// Implementation notes:
///
/// - Unix: `kill(pid, 0)` returns 0 if the signal could be delivered
///   (process exists), `ESRCH` if no such process. `EPERM` (no
///   permission to signal — different UID) means the PID is alive but
///   we cannot signal it; treat as alive. The pidfile-on-csq always
///   contains same-UID PIDs, so EPERM is unlikely in practice.
/// - Windows: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
///   pid)` returns NULL when the PID does not correspond to any
///   process; on success we call `GetExitCodeProcess` and treat
///   `STILL_ACTIVE (259)` as alive. `ERROR_ACCESS_DENIED` (PID exists
///   but is owned by a higher-privilege account) is treated as ALIVE
///   so the message never tells the user the holder is stale when it
///   may not be — fail-open on the "alive" side, matching the Unix
///   `EPERM` branch above. R3-M1 / round-4 redteam.
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Safe-guard against truncation on platforms where pid_t is
    // narrower than u32. macOS/Linux pid_t is i32; PIDs above i32::MAX
    // are unreachable in practice but we still refuse to misinterpret
    // them as a valid query.
    let pid_signed = match i32::try_from(pid) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // SAFETY: `kill` with signal 0 performs no side-effect; it only
    // checks signal-delivery permission. The pid is a value the
    // kernel will validate.
    let rc = unsafe { libc::kill(pid_signed, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => false,
        // EPERM = process exists but we lack permission to signal it.
        // Treat as alive — the holder is real, we just can't probe it.
        Some(libc::EPERM) => true,
        _ => true,
    }
}

#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    // R3-M1 / round-4 redteam: real Windows liveness probe via
    // `OpenProcess` + `GetExitCodeProcess`. Previously stubbed to
    // `true`, which made the stale-lock-detection UX message lie:
    // a Windows user with a `.login-N.lock` from a crashed prior
    // process saw "PID 12345 is in progress" even when the process
    // was dead, leading them to `taskkill /F /PID 12345` only to
    // get "process not found". The real probe disambiguates so the
    // user sees the accurate "stale lock — reclaiming" message
    // instead.
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        // PID 0 is the system idle process on Windows; never a
        // user-mode login holder.
        return false;
    }

    // SAFETY: `OpenProcess` is a documented Win32 API. A zero/NULL
    // return indicates failure (no such PID, or access denied). We
    // check the handle before any further use, and always
    // `CloseHandle` on the success path.
    //
    // windows-sys 0.52 declares `HANDLE` as `isize` (not a raw
    // pointer), so the NULL check is against the integer value 0
    // — `is_null()` is unavailable on this newtype.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle == 0 {
        // Distinguish "no such process" from "no permission to
        // query". Permission denials on a same-user lock file
        // should be rare (csq writes 0o600 / ACL owner-only) but
        // could happen if an admin process or service account
        // holds the lock. Treat ERROR_ACCESS_DENIED as ALIVE so
        // we never tell the user "stale — reclaiming" for a real
        // holder we just couldn't query — matches the Unix EPERM
        // branch.
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return code == ERROR_ACCESS_DENIED;
    }

    // STILL_ACTIVE = 259 is the canonical "process has not yet
    // exited" sentinel returned by GetExitCodeProcess. There is a
    // 1-in-2^32 false-positive risk if a real process happens to
    // exit with code 259, but every csq subprocess we care about
    // (the prior login holder) exits with 0 on success or a small
    // signal-derived code on crash — so 259 in practice means the
    // process is still running.
    const STILL_ACTIVE: u32 = 259;
    let mut exit_code: u32 = 0;
    // SAFETY: handle is non-null (checked above). exit_code is a
    // valid out-pointer. GetExitCodeProcess does not retain the
    // handle.
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    // SAFETY: handle is non-null and we own it. CloseHandle is
    // idempotent w.r.t. our local pointer; we never use it again
    // after this call.
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        // GetExitCodeProcess failed for a reason we couldn't
        // anticipate. Fail-open as alive so the user-facing message
        // never falsely claims the holder is dead.
        return true;
    }
    exit_code == STILL_ACTIVE
}

#[cfg(windows)]
fn try_lock_exclusive(file: &File) -> std::io::Result<LockResult> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        Ok(LockResult::Acquired)
    } else {
        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING {
            Ok(LockResult::WouldBlock)
        } else {
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn account(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn handle_race_acquires_exclusive_lock_for_account() {
        // Successful acquire returns Acquired with a guard that
        // points at the right path.
        let dir = TempDir::new().unwrap();
        let result = AccountLoginLock::acquire(dir.path(), account(5)).unwrap();
        match result {
            AcquireOutcome::Acquired(guard) => {
                let expected = dir.path().join(".login-5.lock");
                assert_eq!(guard.path(), &expected);
                assert!(guard.path().exists());
            }
            AcquireOutcome::Held { .. } => {
                panic!("first acquire on a fresh dir must succeed")
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn handle_race_returns_clear_error_when_lock_held() {
        // Hold the lock in a separate thread; second acquire must
        // return Held with the holder's PID.
        //
        // POSIX-only: this test exercises BSD `flock` semantics where
        // two opens of the same file from the same process get
        // separate file descriptions and so respect each other's
        // advisory locks. Windows `LockFileEx` returns success for
        // both acquires from the same process — so the second
        // acquire reads back its OWN write rather than the first
        // holder's PID, and `pid` is None at line 454. The Windows
        // path is exercised via the Job-Object integration test
        // tracked under M8-03 (Windows port follow-up).
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let first = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match first {
            AcquireOutcome::Acquired(_) => {}
            _ => panic!("first acquire must succeed"),
        }

        let second = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match second {
            AcquireOutcome::Held { pid, pid_alive } => {
                let pid = pid.expect("holder should have written a PID");
                assert_eq!(
                    pid,
                    std::process::id(),
                    "lock file should contain the holder's PID"
                );
                // SEC-R2-08 / R3-M1: the holder is THIS process, which
                // is by definition alive at this assertion. Both Unix
                // (`kill(pid, 0)`) and Windows (`OpenProcess` +
                // `GetExitCodeProcess` per round-4 redteam) return
                // Some(true) for a live holder.
                assert_eq!(pid_alive, Some(true), "live holder must be reported alive");
            }
            AcquireOutcome::Acquired(_) => {
                panic!("second acquire must report Held while first guard is alive")
            }
        }
    }

    #[test]
    fn lock_released_after_handle_race_returns() {
        // Drop the guard, then acquire again — must succeed.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let first = AccountLoginLock::acquire(&dir_path, account(3)).unwrap();
        match first {
            AcquireOutcome::Acquired(guard) => drop(guard),
            _ => panic!("first acquire must succeed"),
        }

        // After drop, a second acquire must succeed.
        let second = AccountLoginLock::acquire(&dir_path, account(3)).unwrap();
        match second {
            AcquireOutcome::Acquired(_) => {}
            AcquireOutcome::Held { .. } => {
                panic!("lock must be released when the guard drops")
            }
        }
    }

    #[test]
    fn lock_released_after_handle_race_panics() {
        // Even if the holder's thread panics, the OS releases the
        // lock when the process exits — but since we're testing
        // within ONE process here, we use a thread to simulate the
        // panic boundary. The thread's File handles get closed
        // when the thread unwinds and drops local owners, which
        // releases the flock.
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let (tx, rx) = mpsc::channel::<()>();
        let dir_for_thread = dir_path.clone();
        let handle = thread::spawn(move || {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let acquired = AccountLoginLock::acquire(&dir_for_thread, account(9)).unwrap();
                match acquired {
                    AcquireOutcome::Acquired(_guard) => {
                        // Notify the main thread that we're holding the lock.
                        tx.send(()).unwrap();
                        // Panic while holding the lock.
                        panic!("simulated panic while holding lock");
                    }
                    _ => unreachable!(),
                }
            }));
        });

        // Wait for the thread to acquire.
        rx.recv_timeout(Duration::from_secs(2))
            .expect("thread should have acquired the lock");
        // Wait for the panic-and-unwind to complete so the File
        // (and thus the flock) is fully released.
        let _ = handle.join();

        // Now we should be able to acquire.
        let result = AccountLoginLock::acquire(&dir_path, account(9)).unwrap();
        match result {
            AcquireOutcome::Acquired(_) => {}
            AcquireOutcome::Held { .. } => panic!("lock must be released after holder panics"),
        }
    }

    #[test]
    fn distinct_accounts_have_independent_locks() {
        // Holding the lock for account 1 must not block account 2.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let g1 = AccountLoginLock::acquire(&dir_path, account(1)).unwrap();
        let g2 = AccountLoginLock::acquire(&dir_path, account(2)).unwrap();

        assert!(matches!(g1, AcquireOutcome::Acquired(_)));
        assert!(matches!(g2, AcquireOutcome::Acquired(_)));
    }

    #[test]
    fn lock_path_uses_account_number() {
        let dir = TempDir::new().unwrap();
        let path = AccountLoginLock::lock_path(dir.path(), account(42));
        assert_eq!(path, dir.path().join(".login-42.lock"));
    }

    // ── SEC-R2-07 / UX-R2-04: lock file is chmod 0600 on Unix ──────

    #[cfg(unix)]
    #[test]
    fn lock_file_is_chmod_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let _guard = match AccountLoginLock::acquire(dir.path(), account(11)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };

        let path = dir.path().join(".login-11.lock");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "lock file must be chmod 0600 to prevent same-host PID disclosure: got 0o{:o}",
            mode
        );
    }

    // ── REV-R2-02: lock file removed after Drop ────────────────────

    #[test]
    fn lock_file_removed_after_drop() {
        // The lock file is best-effort removed when the guard drops.
        // After the next acquire, a fresh file is created — so we
        // observe the artefact going away between the two windows.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".login-13.lock");

        {
            let _guard = match AccountLoginLock::acquire(dir.path(), account(13)).unwrap() {
                AcquireOutcome::Acquired(g) => g,
                _ => panic!("first acquire must succeed"),
            };
            assert!(path.exists(), "lock file must exist while guard is alive");
        }
        assert!(
            !path.exists(),
            "lock file MUST be removed after guard drops (REV-R2-02): {:?}",
            path
        );
    }

    // ── SEC-R2-08 / REV-R2-03: dead PID in lock file → stale ───────

    #[cfg(unix)]
    #[test]
    fn dead_pid_in_lock_file_produces_stale_lock_message() {
        // Manually pre-populate a lock file with a known-dead PID,
        // then force a contention by holding the lock from a thread.
        // The Held-branch must report `pid_alive: Some(false)` for
        // the stale PID written into the file, even though the
        // ACTUAL holder is the live thread (the file content lies
        // about who's holding because we wrote it manually before
        // the thread acquired). The point: the caller's render path
        // sees the file content as the source of truth for the PID,
        // and SEC-R2-08 lets it disambiguate "stale" from "live".
        //
        // In production this case is reached when a prior crash left
        // the file with a dead PID and a NEW concurrent acquirer
        // holds the live flock but hasn't yet truncated the old PID
        // out. We simulate that ordering by writing the dead PID,
        // acquiring the live lock, then probing.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".login-29.lock");

        // Pick a PID that is guaranteed dead. PID 1 is init, almost
        // certainly alive, so we can't use it as a "dead PID". Use
        // a value well above any PID a sandbox would hand out: u32
        // wrap-around space is huge, and `kill(0xDEAD_BEEF, 0)`
        // will return ESRCH on every supported OS.
        let dead_pid: u32 = 0xDEAD_BEEF;
        // Sanity-check: must actually be reported dead by our probe
        // before we use it as the stale-PID fixture.
        assert!(
            !pid_is_alive(dead_pid),
            "test fixture PID {dead_pid} must be reported dead"
        );

        // Write the stale PID into a fresh lock file. Don't acquire
        // through the public API — just seed the bytes.
        std::fs::write(&path, format!("{dead_pid}\n")).unwrap();

        // Now hold the live lock from a thread so the next acquire
        // hits the contention path. We use a barrier-via-channel so
        // the thread has acquired BEFORE we attempt the second
        // acquire.
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let dir_for_thread = dir.path().to_path_buf();
        let handle = thread::spawn(move || {
            let g = AccountLoginLock::acquire(&dir_for_thread, account(29)).unwrap();
            // We immediately re-write the file with the dead PID so
            // the contender reads "stale" content — production hits
            // this when the live holder hasn't yet rewritten the file.
            // The lock guard write happens after `flock` succeeds
            // (see `acquire`), so we have to clobber it back to the
            // dead PID for the contender to observe a stale read.
            std::fs::write(
                dir_for_thread.join(".login-29.lock"),
                format!("{dead_pid}\n"),
            )
            .unwrap();
            ready_tx.send(()).unwrap();
            // Hold until the main thread says we can release.
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
            drop(g);
        });

        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("holder thread should have signalled ready");

        // Contend.
        let outcome = AccountLoginLock::acquire(dir.path(), account(29)).unwrap();
        match outcome {
            AcquireOutcome::Held { pid, pid_alive } => {
                assert_eq!(pid, Some(dead_pid), "should have read the stale PID");
                assert_eq!(
                    pid_alive,
                    Some(false),
                    "stale PID must be reported as dead so the caller can render \
                     a 'stale lock file' message instead of pointing at a dead PID"
                );
            }
            AcquireOutcome::Acquired(_) => panic!("expected contention, got acquired"),
        }

        // Release the holder so the test cleans up.
        let _ = release_tx.send(());
        let _ = handle.join();
    }

    // ── pid_is_alive sanity: this process is alive ────────────────

    #[cfg(unix)]
    #[test]
    fn pid_is_alive_returns_true_for_self() {
        assert!(
            pid_is_alive(std::process::id()),
            "pid_is_alive(self) MUST return true — defines the predicate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pid_is_alive_returns_false_for_zero_pid() {
        // PID 0 is the kernel scheduler placeholder; `kill(0, 0)`
        // semantics are "send signal 0 to every process in this
        // process group" which is meaningless as a liveness probe.
        // Treat as dead.
        assert!(!pid_is_alive(0));
    }

    // ── R3-M1 / round-4 redteam: Windows liveness probe ──────────

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_true_for_self_windows() {
        // The current process is by definition alive. The Windows
        // `OpenProcess` + `GetExitCodeProcess` path must agree.
        // Pre-R3-M1 this was a `true`-return stub; the assertion is
        // unchanged from the Unix sibling because the contract is
        // platform-uniform.
        assert!(
            pid_is_alive(std::process::id()),
            "pid_is_alive(self) MUST return true on Windows (R3-M1)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_false_for_non_existent_pid_windows() {
        // Pick a PID that is overwhelmingly unlikely to be assigned:
        // `OpenProcess` returns NULL with last-error
        // `ERROR_INVALID_PARAMETER` for a non-existent PID. We must
        // observe `false` (not the legacy `true` stub) so the
        // stale-lock UX message correctly reports "reclaimable" when
        // the prior holder crashed.
        //
        // Production-equivalent: a `.login-N.lock` left behind by a
        // crashed prior holder. The kernel released the flock at
        // process exit, but the file content still names the dead
        // PID — without R3-M1 the user would see "PID 0xDEAD_BEEF
        // is in progress" and run a futile `taskkill`.
        let dead_pid: u32 = 0xDEAD_BEEF;
        assert!(
            !pid_is_alive(dead_pid),
            "pid_is_alive must return false for a non-existent PID on Windows \
             (R3-M1 — pre-fix this was a true-stub)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_false_for_zero_pid_windows() {
        // PID 0 is the system idle process on Windows; the function
        // short-circuits to false so a malformed lock file containing
        // "0\n" cannot be misread as a live holder.
        assert!(!pid_is_alive(0));
    }
}
