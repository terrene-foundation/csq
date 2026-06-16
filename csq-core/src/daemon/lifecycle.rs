//! Daemon lifecycle: status inspection and graceful stop.
//!
//! The `start` side of the lifecycle (acquire PID, install signal
//! handlers, block until shutdown) is owned by the CLI command
//! handler in `csq-cli/src/commands/daemon.rs` because it requires a
//! tokio runtime and is tied to process lifetime. This module exposes
//! the testable, pure primitives: status inspection and remote stop.

use super::pid::read_pid;
use crate::error::DaemonError;
use crate::platform::process;
use std::path::Path;
use std::time::{Duration, Instant};

/// Status of the csq daemon as observed from outside the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Daemon is running under this PID.
    Running { pid: u32 },
    /// PID file exists but references a dead PID (crash recovery
    /// territory — caller can safely clean up).
    Stale { pid: u32 },
    /// No PID file, no running daemon.
    NotRunning,
}

/// Inspects the daemon status at `pid_path` without taking any
/// action. Safe to call from any CLI command that wants to branch on
/// daemon availability.
pub fn status_of(pid_path: &Path) -> DaemonStatus {
    if !pid_path.exists() {
        return DaemonStatus::NotRunning;
    }

    match read_pid(pid_path) {
        None => {
            // File exists but is unreadable / corrupt. Treat as
            // stale so the caller cleans it up on next start.
            DaemonStatus::Stale { pid: 0 }
        }
        Some(pid) if process::is_pid_alive(pid) => DaemonStatus::Running { pid },
        Some(pid) => DaemonStatus::Stale { pid },
    }
}

/// Stops a running daemon by sending SIGTERM and polling for exit.
///
/// # Behavior
///
/// 1. Reads the PID file. If missing, returns
///    [`DaemonError::NotRunning`].
/// 2. If PID is dead, cleans up stale files and returns
///    [`DaemonError::StalePidFile`].
/// 3. Sends SIGTERM (Unix) or issues a graceful stop signal
///    (Windows — deferred to M8.6; currently returns
///    [`DaemonError::IpcTimeout`] as a placeholder on that platform).
/// 4. Polls [`process::is_pid_alive`] every 100ms until the PID
///    exits or the 5-second deadline passes.
/// 5. On clean exit, attempts to remove the PID file (the daemon's
///    own Drop handler usually does this, but we're defensive in
///    case the daemon crashed mid-shutdown).
/// 6. If the deadline elapses with the PID still alive, returns
///    [`DaemonError::IpcTimeout`]. The caller can retry with
///    SIGKILL if desired (not implemented here — fail loud).
///
/// # Safety
///
/// On Unix, `libc::kill` is unsafe because it can affect other
/// processes. We guard this by only sending to the PID read from
/// our own PID file, which we wrote ourselves. In the worst case
/// where the OS has recycled the PID to an unrelated process, we'd
/// SIGTERM that process — but this window is very narrow (typical
/// kernels don't recycle PIDs for several seconds) and the file
/// would have been cleaned up on daemon exit anyway.
pub fn stop_daemon(pid_path: &Path) -> Result<u32, DaemonError> {
    if !pid_path.exists() {
        return Err(DaemonError::NotRunning {
            pid_path: pid_path.to_path_buf(),
        });
    }

    let pid = read_pid(pid_path).ok_or_else(|| DaemonError::NotRunning {
        pid_path: pid_path.to_path_buf(),
    })?;

    if !process::is_pid_alive(pid) {
        let _ = std::fs::remove_file(pid_path);
        return Err(DaemonError::StalePidFile { pid });
    }

    send_shutdown_signal(pid)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !process::is_pid_alive(pid) {
            // Daemon exited cleanly. Remove the PID file if it's
            // still there (the daemon's Drop handler should have
            // done this).
            let _ = std::fs::remove_file(pid_path);
            return Ok(pid);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(DaemonError::IpcTimeout { timeout_ms: 5000 })
}

#[cfg(unix)]
fn send_shutdown_signal(pid: u32) -> Result<(), DaemonError> {
    // SAFETY: We read this PID from our own PID file. The worst case
    // is a PID-reuse race (daemon crashed, OS recycled PID) which is
    // rare and bounded by the PID file's presence window.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ESRCH) {
            // No such process — the daemon died between our
            // is_pid_alive check and the kill syscall. Treat as
            // already stopped.
            Err(DaemonError::StalePidFile { pid })
        } else {
            tracing::debug!(errno = ?errno, "SIGTERM failed");
            Err(DaemonError::IpcTimeout { timeout_ms: 0 })
        }
    }
}

#[cfg(windows)]
fn send_shutdown_signal(_pid: u32) -> Result<(), DaemonError> {
    // Windows graceful-stop requires either a console control event
    // sent to the daemon's console, or a quit message posted to its
    // main thread via an IPC channel. Both are deferred to M8.6
    // (Windows integration). For now, return a clear error so
    // callers on Windows can surface the limitation.
    Err(DaemonError::IpcTimeout { timeout_ms: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn status_of_missing_file_is_not_running() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        assert_eq!(status_of(&p), DaemonStatus::NotRunning);
    }

    #[test]
    fn status_of_alive_pid_is_running() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        let our_pid = std::process::id();
        fs::write(&p, format!("{our_pid}\n")).unwrap();

        match status_of(&p) {
            DaemonStatus::Running { pid } => assert_eq!(pid, our_pid),
            other => panic!("expected Running, got {other:?}"),
        }
    }

    #[test]
    fn status_of_dead_pid_is_stale() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        fs::write(&p, "99999999\n").unwrap();

        match status_of(&p) {
            DaemonStatus::Stale { pid } => assert_eq!(pid, 99_999_999),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn status_of_corrupt_file_is_stale() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        fs::write(&p, "not-a-pid\n").unwrap();

        assert_eq!(status_of(&p), DaemonStatus::Stale { pid: 0 });
    }

    #[test]
    fn stop_daemon_missing_file_returns_not_running() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");

        match stop_daemon(&p) {
            Err(DaemonError::NotRunning { .. }) => {}
            other => panic!("expected NotRunning, got {other:?}"),
        }
    }

    #[test]
    fn stop_daemon_stale_file_returns_stale_and_cleans_up() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        fs::write(&p, "99999999\n").unwrap();

        match stop_daemon(&p) {
            Err(DaemonError::StalePidFile { pid }) => {
                assert_eq!(pid, 99_999_999);
                // Stale cleanup should have removed the file.
                assert!(!p.exists());
            }
            other => panic!("expected StalePidFile, got {other:?}"),
        }
    }

    // We deliberately do not test the live-PID SIGTERM path here
    // because it requires spawning a real child process that blocks
    // on signal — doable but noisy in unit tests. The integration
    // test suite (M8.6) exercises the full round trip.
}
