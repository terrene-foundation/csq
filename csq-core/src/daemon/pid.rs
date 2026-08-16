//! PID file primitives with single-instance guard.
//!
//! Single-instance exclusion is **kernel-atomic**: `acquire` holds an
//! exclusive OS lock (`flock` on Unix, a named kernel mutex via
//! `CreateMutexW` on Windows — see `platform::lock`) tied to a sibling
//! `<pidfile>.lock` for the daemon's whole lifetime. Two
//! concurrent `acquire` calls cannot both win — the kernel grants the
//! lock to exactly one; the other gets `AlreadyRunning`. The lock is
//! released automatically on process death, so a crashed daemon never
//! leaves a stuck lock. The PID file itself is written atomically (temp
//! file + rename) for partial-read safety and carries the owner PID for
//! `stop`/`status` and stale-file cleanup.
//!
//! Before the flock (daemon-auth-resilience Wave B), exclusion rested on
//! a write-then-re-read heuristic that admitted a TOCTOU double-win under
//! near-simultaneous starts — two live daemons, two refreshers, an OAuth
//! refresh-token war. The flock closes that class structurally.

use crate::error::DaemonError;
use crate::platform::lock::{try_lock_file, FileLockGuard};
use crate::platform::{fs as platform_fs, process};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// RAII guard around a PID file owned by the current process.
///
/// Created via `acquire`. On drop, removes the PID file — but only
/// if the file on disk still contains *our* PID (prevents removing a
/// successor daemon's PID file if we're killed after a race).
#[derive(Debug)]
pub struct PidFile {
    path: PathBuf,
    owned_pid: u32,
    /// Exclusive advisory lock on `<path>.lock`, held for the daemon's
    /// lifetime. Dropped AFTER the `Drop` body removes the PID file (Rust
    /// drops fields after the enclosing value's `Drop::drop`), so the PID
    /// file is removed while the lock is still held — no window where a
    /// contender sees both the lock free and the PID file gone.
    _lock: FileLockGuard,
}

/// The sibling lock-file path for a PID file: `<path>.lock`. Never
/// renamed (unlike the atomically-replaced PID file), so the flock on it
/// is stable across PID-file rewrites.
fn lock_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

impl PidFile {
    /// Attempts to acquire exclusive ownership of the PID file at
    /// `path`.
    ///
    /// # Single-instance algorithm
    ///
    /// 0. Acquire an exclusive OS lock tied to `<path>.lock` (`flock` on
    ///    Unix, a named kernel mutex on Windows; non-blocking). If another
    ///    process holds it, error [`DaemonError::AlreadyRunning`]. This is
    ///    the kernel-atomic exclusion — steps 1-5 run under it, race-free.
    /// 1. Read existing PID file if any.
    /// 2. If it exists and its PID is alive AND that PID is a csq process,
    ///    error [`DaemonError::AlreadyRunning`] (defers to a daemon started
    ///    by an older binary that predates the flock).
    /// 3. If it exists but the PID is dead — or alive yet positively
    ///    identified as some OTHER program, i.e. the kernel recycled a dead
    ///    daemon's PID ([`process::is_pid_foreign`]) — delete the stale file.
    /// 4. Write our PID atomically (temp file + rename).
    /// 5. Re-read as a cheap sanity check (belt-and-suspenders under the
    ///    lock).
    ///
    /// The flock (step 0) is the primary guarantee: it is granted to
    /// exactly one process and released automatically on death. Steps 1-2
    /// remain for upgrade-transition safety (an old-binary daemon holds
    /// the PID file but not the lock) and PID-reuse rejection.
    pub fn acquire(path: &Path) -> Result<Self, DaemonError> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DaemonError::SocketConnect {
                        path: parent.to_path_buf(),
                    }
                    .with_source(e)
                })?;
            }
        }

        // Step 0: kernel-atomic exclusion. Held for the daemon's whole
        // lifetime; released on drop or process death. If another daemon
        // holds it, we lose here — report its PID from the file if legible.
        let lock_path = lock_path_for(path);
        let lock = match try_lock_file(&lock_path) {
            Ok(Some(guard)) => guard,
            Ok(None) => {
                let pid = read_pid(path).unwrap_or(0);
                return Err(DaemonError::AlreadyRunning { pid });
            }
            Err(e) => {
                return Err(DaemonError::SocketConnect {
                    path: lock_path.clone(),
                }
                .with_source_platform(e));
            }
        };

        // Step 1-3: handle existing file (now race-free under the lock).
        if path.exists() {
            match read_pid(path) {
                // A live PID defers to a possibly-older-binary daemon —
                // but ONLY if the PID is actually csq. A recycled PID
                // (dead daemon whose `Drop` never ran, kernel reissued
                // the number) would otherwise make `acquire` fail
                // `AlreadyRunning` forever: the desktop supervisor backs
                // off, never hosts a daemon, and the Codex spawn gate —
                // which hard-requires a healthy daemon — refuses every
                // run. We already hold the flock here, so no live daemon
                // of a flock-aware build owns this file; the identity
                // check covers the pre-flock-binary case too and fails
                // open, so a real daemon is never displaced.
                Some(existing_pid)
                    if process::is_pid_alive(existing_pid)
                        && !process::is_pid_foreign(existing_pid) =>
                {
                    return Err(DaemonError::AlreadyRunning { pid: existing_pid });
                }
                _ => {
                    // Either dead PID (Some(_) not alive, fell
                    // through) or unreadable file (None) — remove
                    // and proceed. This handles corruption (non-
                    // numeric content) and crash recovery.
                    let _ = fs::remove_file(path);
                }
            }
        }

        // Step 4: atomic write.
        let our_pid = std::process::id();
        write_pid_atomic(path, our_pid)?;

        // Step 5: verify we own it (belt-and-suspenders under the lock).
        match read_pid(path) {
            Some(pid) if pid == our_pid => Ok(PidFile {
                path: path.to_path_buf(),
                owned_pid: our_pid,
                _lock: lock,
            }),
            Some(other) => Err(DaemonError::AlreadyRunning { pid: other }),
            None => Err(DaemonError::SocketConnect {
                path: path.to_path_buf(),
            }),
        }
    }

    /// Returns the PID written to the file (always the current
    /// process's PID).
    pub fn owned_pid(&self) -> u32 {
        self.owned_pid
    }

    /// Returns the PID file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Only remove the file if it still contains our PID. If we
        // were forcibly killed and a successor daemon has already
        // overwritten it, we must not delete the successor's file.
        if let Some(on_disk) = read_pid(&self.path) {
            if on_disk == self.owned_pid {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Reads a PID from a PID file. Returns `None` if the file is
/// missing, unreadable, or does not contain a valid `u32`.
pub fn read_pid(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// Writes a PID atomically via temp file + rename. The temp file is
/// created in the same directory as `path` to guarantee the rename
/// is on the same filesystem.
fn write_pid_atomic(path: &Path, pid: u32) -> Result<(), DaemonError> {
    let tmp = platform_fs::unique_tmp_path(path);

    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
        writeln!(f, "{pid}")
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
        f.sync_all()
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
    }

    // 0o600 on Unix before the rename so the final file always has
    // the restrictive mode. No-op on Windows.
    let _ = platform_fs::secure_file(&tmp);

    platform_fs::atomic_replace(&tmp, path).map_err(|e| {
        // Map platform error to daemon error.
        DaemonError::SocketConnect {
            path: path.to_path_buf(),
        }
        .with_source_platform(e)
    })?;

    Ok(())
}

// Small helper extensions to attach io/platform error context to
// DaemonError. We don't add these as thiserror variants because the
// daemon error messages are surfaced to the user, and including the
// raw io error string is usually fine for operator diagnostics.
trait DaemonErrorContext {
    fn with_source(self, e: std::io::Error) -> DaemonError;
    fn with_source_platform(self, e: crate::error::PlatformError) -> DaemonError;
}

impl DaemonErrorContext for DaemonError {
    fn with_source(self, e: std::io::Error) -> DaemonError {
        // Log the raw io error for operator diagnostics but keep the
        // user-facing variant unchanged. This is intentionally lossy:
        // the DaemonError enum doesn't carry source chains by design,
        // so we dump context via tracing instead.
        tracing::debug!(error = %e, daemon_error = %self, "pid file io error");
        self
    }

    fn with_source_platform(self, e: crate::error::PlatformError) -> DaemonError {
        tracing::debug!(error = %e, daemon_error = %self, "pid file platform error");
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pid_path(dir: &TempDir) -> PathBuf {
        dir.path().join("test.pid")
    }

    #[test]
    fn read_pid_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        assert_eq!(read_pid(&p), None);
    }

    #[test]
    fn read_pid_invalid_content_returns_none() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        fs::write(&p, "not-a-number\n").unwrap();
        assert_eq!(read_pid(&p), None);
    }

    #[test]
    fn read_pid_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        fs::write(&p, "12345\n").unwrap();
        assert_eq!(read_pid(&p), Some(12345));
    }

    #[test]
    fn write_pid_atomic_creates_readable_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        write_pid_atomic(&p, 54321).unwrap();
        assert_eq!(read_pid(&p), Some(54321));
    }

    #[test]
    fn write_pid_atomic_leaves_no_tmp_files() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        write_pid_atomic(&p, 1).unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        // Only the final PID file should remain; no stray tmp files.
        assert_eq!(entries, vec!["test.pid"]);
    }

    #[test]
    fn acquire_writes_our_pid() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
        assert_eq!(read_pid(&p), Some(std::process::id()));
    }

    #[test]
    fn drop_removes_our_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        {
            let _guard = PidFile::acquire(&p).unwrap();
            assert!(p.exists());
        }
        // After drop, file is gone.
        assert!(!p.exists());
    }

    #[test]
    fn acquire_rejects_when_alive_pid_exists() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // Write our own PID — we're alive, so second acquire must
        // fail with AlreadyRunning.
        fs::write(&p, format!("{}\n", std::process::id())).unwrap();

        let result = PidFile::acquire(&p);
        match result {
            Err(DaemonError::AlreadyRunning { pid }) => {
                assert_eq!(pid, std::process::id());
            }
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    /// Regression: a PID file naming a LIVE but FOREIGN process must not
    /// block acquisition.
    ///
    /// This is the defect that made the originating incident unrecoverable
    /// rather than merely noisy. The desktop supervisor's loop detects
    /// daemon state, decides to take over, then calls `acquire`. With a
    /// recycled PID in the file, `acquire` returned `AlreadyRunning`
    /// every iteration, so the supervisor backed off — capped at 60s —
    /// and never hosted a daemon. Because the Codex spawn path hard-gates
    /// on a healthy daemon, `csq run <codex-slot>` was permanently
    /// refused while Anthropic slots (which fall back to direct mode)
    /// kept working. Hence "issues with codex but not the others".
    #[cfg(unix)]
    #[test]
    fn acquire_takes_over_when_pid_file_names_a_live_foreign_process() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        let mut foreign = crate::platform::process::spawn_foreign_test_process();
        fs::write(&p, format!("{}\n", foreign.id())).unwrap();

        let result = PidFile::acquire(&p);

        let _ = foreign.kill();
        let _ = foreign.wait();

        match result {
            Ok(guard) => {
                assert_eq!(
                    guard.owned_pid(),
                    std::process::id(),
                    "the taking-over process must own the file"
                );
                assert_eq!(read_pid(&p), Some(std::process::id()));
            }
            Err(e) => {
                panic!("acquire must take over a recycled PID, not refuse forever; got {e:?}")
            }
        }
    }

    // Unix-only: Windows named mutexes are re-entrant within the same
    // thread (`platform::lock` docs), so a same-thread second `acquire`
    // re-enters the mutex and this same-process test is unreliable there.
    // The production guarantee (cross-PROCESS exclusion) holds on Windows;
    // it is exercised by real two-process contention, not this unit test.
    #[cfg(unix)]
    #[test]
    fn acquire_flock_blocks_second_even_without_live_pidfile() {
        // The flock (Step 0) — not the PID-file heuristic — must be the
        // authority. Hold a PidFile, then remove the PID file so the
        // is-pid-alive check (Steps 1-2) would let a second acquire
        // proceed. The flock alone must still refuse it. This is the F1
        // double-win the write-then-re-read heuristic admitted.
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        let _guard = PidFile::acquire(&p).unwrap();
        // Drop the PID file — without the flock, the next acquire would
        // see NotRunning and happily write a second owner.
        fs::remove_file(&p).unwrap();

        match PidFile::acquire(&p) {
            Err(DaemonError::AlreadyRunning { .. }) => {}
            other => panic!("flock must refuse a second acquire, got {other:?}"),
        }
    }

    // Unix-only: the Unix lock backend creates a `<pidfile>.lock` FILE
    // (flock target); the Windows backend uses a named kernel mutex and
    // writes no such file, so this assertion is Unix-specific.
    #[cfg(unix)]
    #[test]
    fn acquire_creates_sibling_lock_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        let _guard = PidFile::acquire(&p).unwrap();
        assert!(
            lock_path_for(&p).exists(),
            "acquire must create the sibling <pidfile>.lock"
        );
    }

    #[test]
    fn acquire_succeeds_again_after_previous_guard_dropped() {
        // Releasing the guard (Drop) releases the flock, so a fresh acquire
        // on the same path succeeds — no stuck lock.
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        {
            let _g = PidFile::acquire(&p).unwrap();
        }
        let g2 = PidFile::acquire(&p).unwrap();
        assert_eq!(g2.owned_pid(), std::process::id());
    }

    #[test]
    fn acquire_cleans_up_stale_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // PID 99_999_999 is almost certainly not alive on any
        // reasonable system (process::is_pid_alive already tests
        // this assumption in platform::process tests).
        fs::write(&p, "99999999\n").unwrap();

        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
        assert_eq!(read_pid(&p), Some(std::process::id()));
    }

    #[test]
    fn acquire_cleans_up_corrupted_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // Non-numeric content should be treated like a stale file.
        fs::write(&p, "garbage\nnot a pid\n").unwrap();

        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
    }

    #[test]
    fn acquire_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("test.pid");
        assert!(!nested.parent().unwrap().exists());

        let _guard = PidFile::acquire(&nested).unwrap();
        assert!(nested.exists());
    }

    #[cfg(unix)]
    #[test]
    fn acquire_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        let _guard = PidFile::acquire(&p).unwrap();

        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pid file must be owner-only 0o600");
    }
}
