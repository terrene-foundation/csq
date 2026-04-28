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
    Held { pid: Option<u32> },
}

impl std::fmt::Debug for AcquireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquireOutcome::Acquired(g) => f
                .debug_struct("Acquired")
                .field("path", &g.path)
                .finish(),
            AcquireOutcome::Held { pid } => {
                f.debug_struct("Held").field("pid", pid).finish()
            }
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
                Ok(AcquireOutcome::Held { pid })
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
        if err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            Ok(LockResult::WouldBlock)
        } else {
            Err(err)
        }
    }
}

#[cfg(windows)]
fn try_lock_exclusive(file: &File) -> std::io::Result<LockResult> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_IO_PENDING};
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
    fn handle_race_returns_clear_error_when_lock_held() {
        // Hold the lock in a separate thread; second acquire must
        // return Held with the holder's PID.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let first = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match first {
            AcquireOutcome::Acquired(_) => {}
            _ => panic!("first acquire must succeed"),
        }

        // POSIX flock is per-OPEN-FILE-DESCRIPTION; opening a new
        // handle in another thread of the SAME process gets a
        // separate description and so respects the existing lock.
        // (BSD flock semantics; Linux matches when not using OFD
        // locks.) We exploit that here to test contention without
        // spawning a child process.
        let second = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match second {
            AcquireOutcome::Held { pid } => {
                let pid = pid.expect("holder should have written a PID");
                assert_eq!(
                    pid,
                    std::process::id(),
                    "lock file should contain the holder's PID"
                );
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
}
