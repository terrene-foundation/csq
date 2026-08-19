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
    /// PID file exists and its PID is **alive**, but that process is not
    /// csq — the OS recycled a dead daemon's PID (see
    /// [`process::is_pid_foreign`]). No daemon is running. Distinct from
    /// [`DaemonStatus::Stale`] because the operator-facing wording
    /// differs: "references a dead PID" is a lie here, and the PID MUST
    /// NOT be signalled.
    PidReused { pid: u32 },
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
        // A live PID is only OUR daemon if the process is actually csq.
        // Without the identity check a recycled PID reports `Running`
        // and `csq daemon status` names an unrelated program as the
        // daemon (observed: a Microsoft Teams helper).
        Some(pid) if process::is_pid_alive(pid) => {
            if process::is_pid_foreign(pid) {
                DaemonStatus::PidReused { pid }
            } else {
                DaemonStatus::Running { pid }
            }
        }
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
/// 3. Sends SIGTERM (Unix) or fires the per-user named shutdown event
///    (Windows — see the `shutdown_windows` module, an internal ticket). Both drive the
///    daemon's shared `CancellationToken` so every subsystem drains.
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
/// processes. Reading the PID from our own PID file is NOT sufficient
/// to make the signal safe: when a daemon dies without running its
/// `Drop` (SIGKILL, panic-abort, OOM, a reaped tmpdir) the PID file
/// outlives it, and the kernel is free to reissue that PID to an
/// unrelated program — after which SIGTERM would terminate a stranger.
/// An earlier revision of this doc-comment claimed the window was "very
/// narrow (typical kernels don't recycle PIDs for several seconds)" and
/// that "the file would have been cleaned up on daemon exit anyway";
/// both premises fail in exactly the case that matters. Observed on a
/// maintainer host: a PID file written at 07:54 still named PID 1754 at
/// 13:00, by which point 1754 was a Microsoft Teams helper — a ~5-hour
/// window, and `csq daemon stop` was the remediation csq itself printed.
///
/// So the signal is now gated on process IDENTITY
/// ([`process::is_pid_foreign`]): a positively-foreign PID is reported
/// as [`DaemonError::StalePidFile`] and its PID file removed, WITHOUT
/// signalling. The check fails open, so an unreadable command still
/// takes the signal path — it never refuses to stop a real daemon.
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

    // The PID is alive — but is it OURS? A recycled PID must never be
    // signalled. Remove the stale file so the next `daemon start`
    // acquires cleanly, and report stale rather than stopped.
    if process::is_pid_foreign(pid) {
        let _ = std::fs::remove_file(pid_path);
        return Err(DaemonError::StalePidFile { pid });
    }

    send_shutdown_signal(pid)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon_has_stopped(pid, pid_path) {
            // Remove the PID file if it's still there (the daemon's Drop
            // handler usually does this; a dedicated daemon process that
            // exited without cleanup leaves it behind).
            let _ = std::fs::remove_file(pid_path);
            return Ok(pid);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(DaemonError::IpcTimeout { timeout_ms: 5000 })
}

/// The daemon has stopped once EITHER its process is gone (a dedicated
/// `csq daemon start` process exits) OR it has released its PID file (a
/// desktop-supervised **in-process** daemon: the app process outlives the
/// daemon task, so PID-liveness never flips — the supervisor's `drop(pid_file)`
/// after the drain is the authoritative "daemon stopped" signal).
///
/// Without the PID-file check, `csq daemon stop` against a desktop daemon would
/// poll the still-alive app PID for the full 5s deadline and then falsely report
/// the daemon as "stuck" (an internal ticket redteam HIGH-2).
fn daemon_has_stopped(pid: u32, pid_path: &Path) -> bool {
    !process::is_pid_alive(pid) || !pid_path.exists()
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
fn send_shutdown_signal(pid: u32) -> Result<(), DaemonError> {
    // Windows has no per-process SIGTERM. The daemon creates a per-user
    // named event at startup and blocks on it; firing that event is the
    // graceful equivalent of SIGTERM — the daemon's `CancellationToken`
    // fires and every subsystem drains exactly as on Unix (an internal ticket).
    //
    // `StalePidFile` is returned when the event does not exist: the PID
    // is alive per the caller's pre-check but is not a listening csq
    // daemon (or died in the race window), mirroring the Unix `ESRCH`
    // arm above.
    super::shutdown_windows::signal_shutdown(pid)
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

    /// Regression: `csq daemon status` must not report an unrelated
    /// program as the running daemon. Pre-fix it printed
    /// `running / PID: 1754` where 1754 was a Microsoft Teams helper.
    #[cfg(unix)]
    #[test]
    fn status_of_live_but_foreign_pid_is_pid_reused() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        let mut foreign = crate::platform::process::spawn_foreign_test_process();
        let foreign_pid = foreign.id();
        fs::write(&p, format!("{foreign_pid}\n")).unwrap();

        let status = status_of(&p);

        let _ = foreign.kill();
        let _ = foreign.wait();

        // Specifically NOT `Stale` — that variant's operator string says
        // "references a dead PID", which is false for a live stranger.
        assert_eq!(status, DaemonStatus::PidReused { pid: foreign_pid });
    }

    /// Regression — the safety-critical one: `stop_daemon` MUST NOT
    /// signal a process it did not start.
    ///
    /// Pre-fix, `stop_daemon` read the PID from csq's own PID file,
    /// confirmed only that *something* held it, and called
    /// `libc::kill(pid, SIGTERM)`. On the originating host that PID
    /// belonged to a Microsoft Teams helper — and `csq daemon stop` was
    /// the remediation csq's own error message told the user to run.
    ///
    /// The load-bearing assertion is that the foreign process is STILL
    /// ALIVE after the call. Asserting only the `StalePidFile` return
    /// would pass even if the signal had been delivered.
    #[cfg(unix)]
    #[test]
    fn stop_daemon_refuses_to_signal_a_foreign_pid() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        let mut foreign = crate::platform::process::spawn_foreign_test_process();
        let foreign_pid = foreign.id();
        fs::write(&p, format!("{foreign_pid}\n")).unwrap();

        let result = stop_daemon(&p);

        // Read liveness BEFORE reaping so the observation is meaningful.
        // `try_wait` returning None means the child has not exited: it was
        // not signalled. (`is_pid_alive` would also be true for an
        // unreaped zombie, so it cannot distinguish killed-from-alive
        // here — the exit-status channel can.)
        let still_running = foreign.try_wait().expect("try_wait").is_none();

        let _ = foreign.kill();
        let _ = foreign.wait();

        assert!(
            still_running,
            "stop_daemon signalled a process that is not csq — the recycled-PID \
             bug this guard exists to prevent"
        );
        match result {
            Err(DaemonError::StalePidFile { pid }) => {
                assert_eq!(pid, foreign_pid);
                // The stale file must be gone so the next `daemon start`
                // acquires cleanly instead of wedging on AlreadyRunning.
                assert!(!p.exists(), "stale PID file should have been removed");
            }
            other => panic!("expected StalePidFile, got {other:?}"),
        }
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

    #[test]
    fn daemon_has_stopped_detects_pid_file_release_of_a_live_host() {
        // an internal ticket HIGH-2: a desktop-supervised daemon's PID file holds the app's
        // PID, which stays alive after the daemon task stops. The PID-file
        // release — not PID death — is the "stopped" signal that lets
        // `stop_daemon` return Ok instead of falsely reporting "stuck".
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        let me = std::process::id(); // our own PID: genuinely alive.
        fs::write(&p, format!("{me}\n")).unwrap();

        // Alive PID + present PID file → still running.
        assert!(!daemon_has_stopped(me, &p));

        // Alive PID + released PID file → stopped (the in-process desktop case).
        fs::remove_file(&p).unwrap();
        assert!(daemon_has_stopped(me, &p));
    }

    #[test]
    fn daemon_has_stopped_detects_dead_process() {
        // The dedicated `csq daemon start` process case: PID death is stop,
        // regardless of the PID file (which its Drop usually removes).
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("csq-daemon.pid");
        fs::write(&p, "99999999\n").unwrap();
        assert!(daemon_has_stopped(99_999_999, &p));
    }

    // We deliberately do not test the live-PID SIGTERM path here
    // because it requires spawning a real child process that blocks
    // on signal — doable but noisy in unit tests. The Windows
    // graceful-stop round trip is exercised by the integration test
    // `tests/daemon_windows_graceful_stop.rs` (an internal ticket).
}
