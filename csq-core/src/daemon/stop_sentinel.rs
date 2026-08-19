//! Explicit-stop sentinel — makes `csq daemon stop` honest while a
//! desktop-app in-process supervisor is cohabiting with the daemon
//! (an internal ticket).
//!
//! ### The lie this closes
//!
//! `csq daemon stop` SIGTERMs (Unix) / fires the shutdown event for
//! (Windows) whichever process currently owns the [`crate::daemon::PidFile`]
//! — typically the launchd/systemd-managed standalone daemon
//! (`csq daemon start --supervised`), which drains and exits cleanly. But
//! the desktop app's own in-process supervisor loop
//! (`csq::desktop::daemon_supervisor`) was only ever backing off because
//! the standalone daemon held the lock; once that daemon is gone, the
//! in-process loop's next [`crate::daemon::detect_daemon`] tick (at most
//! [`crate::daemon::supervise::BACKOFF_MAX`] = 60s later) observes
//! `NotRunning` and re-acquires — the refresher resurrects, silently
//! making "csq daemon stopped" false the moment it was printed.
//!
//! ### The fix
//!
//! `csq daemon stop` sets this sentinel BEFORE signalling. The shared
//! [`crate::daemon::supervise::run_forever`] loop — the SAME loop both
//! the standalone `--supervised` daemon and the desktop in-process
//! supervisor drive — checks it before every `PidFile::acquire` attempt
//! and defers instead of taking over, polling at a slow, non-busy
//! cadence. Every daemon-START entry point clears it FIRST, so an
//! explicit start always undoes a prior stop — including after a crash:
//! the sentinel is a plain marker file with no liveness semantics of its
//! own, so a machine that reboots with it still set is unstuck by the
//! very first `csq daemon start` (launchd `RunAtLoad`, or the user
//! reopening the desktop app). It can never leave the daemon
//! permanently un-startable.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use std::path::{Path, PathBuf};

/// Fixed sentinel payload. Not machine-parsed — a human-readable tag in
/// case an operator `cat`s the file while diagnosing "why won't the
/// daemon start."
const STOP_REQUESTED_PAYLOAD: &[u8] = b"stopped_via_csq_daemon_stop";

/// Returns the path of the stop-requested sentinel.
///
/// Lives directly under `base_dir` (not a subsystem-scoped directory)
/// because it is read by every supervisor loop, on every platform,
/// before that loop has decided which subsystem — if any — it is about
/// to spin up.
fn sentinel_path(base_dir: &Path) -> PathBuf {
    base_dir.join(".daemon-stop-requested")
}

/// Sets the stop-requested sentinel.
///
/// MUST be called from:
/// - `csq/src/cli/commands/daemon.rs::handle_stop` — the ONLY current
///   `csq daemon stop` entry point on every platform. Called BEFORE
///   `stop_daemon` signals the PidFile owner, so a supervisor loop
///   racing the signal already sees the sentinel on its next tick.
///
/// Best-effort by design (§5a write pattern: tmp → secure → atomic
/// replace, tmp cleaned up on every failure branch) — a write failure is
/// logged and swallowed rather than propagated, because `csq daemon
/// stop` must still stop the process it CAN reach (the SIGTERM/shutdown
/// event) even if this optimization against resurrection could not be
/// persisted.
pub fn set_stop_requested(base_dir: &Path) {
    let path = sentinel_path(base_dir);
    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, STOP_REQUESTED_PAYLOAD) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "stop_sentinel_write_failed",
            "could not write daemon stop-requested sentinel: {e}"
        );
        return;
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "stop_sentinel_write_failed",
            "could not secure daemon stop-requested sentinel: {e}"
        );
        return;
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "stop_sentinel_write_failed",
            "could not atomically place daemon stop-requested sentinel: {e}"
        );
    }
}

/// Clears the stop-requested sentinel (best-effort; ignores ENOENT).
///
/// MUST be called, FIRST thing, from every daemon-START entry point on
/// every platform — "start always means start", and this is the
/// mechanism that keeps that true even after a crash left the sentinel
/// set:
/// - `csq/src/cli/commands/daemon.rs::handle_start` (foreground —
///   also reached via `handle_start_background`'s re-exec).
/// - `csq/src/cli/commands/daemon.rs::handle_start_supervised`
///   (the launchd/systemd-managed background daemon — this is also the
///   path a reboot takes via `RunAtLoad`/the service manager, which is
///   the crash-recovery boundary: the sentinel cannot outlive a reboot
///   uncleared).
/// - `csq::desktop::daemon_supervisor::start` (desktop app launch —
///   reopening the app is itself an explicit "start" intent).
pub fn clear_stop_requested(base_dir: &Path) {
    let path = sentinel_path(base_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                error_kind = "stop_sentinel_clear_failed",
                "could not remove daemon stop-requested sentinel: {e}"
            );
        }
    }
}

/// Returns `true` if `csq daemon stop` was the most recent daemon
/// lifecycle action observed for this `base_dir` and no start entry
/// point has run since (see [`clear_stop_requested`]).
///
/// Read by [`crate::daemon::supervise::run_forever`] before EVERY
/// `PidFile::acquire` attempt — the loop MUST NOT take ownership of the
/// daemon while this is set, regardless of platform or which of the two
/// supervisor hosts (standalone `--supervised`, or the desktop
/// in-process loop) is asking. A missing or unreadable sentinel reads as
/// `false` (existence-only check — the file has no content the gate
/// depends on; [`STOP_REQUESTED_PAYLOAD`] is diagnostic-only).
pub fn is_stop_requested(base_dir: &Path) -> bool {
    sentinel_path(base_dir).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_is_requested_true() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert!(!is_stop_requested(base));
        set_stop_requested(base);
        assert!(is_stop_requested(base));
    }

    #[test]
    fn clear_resets_to_false() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        set_stop_requested(base);
        assert!(is_stop_requested(base));
        clear_stop_requested(base);
        assert!(!is_stop_requested(base));
    }

    #[test]
    fn clear_on_absent_sentinel_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        // No prior set_stop_requested call — must not panic or error-log
        // in a way a caller would observe as failure.
        clear_stop_requested(base);
        assert!(!is_stop_requested(base));
    }

    #[test]
    fn sentinel_file_is_owner_only_permissioned() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        set_stop_requested(base);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(sentinel_path(base)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    /// A stale sentinel left by a crash MUST be clearable by a fresh
    /// `set_stop_requested` → `clear_stop_requested` cycle exactly like a
    /// clean one — no special "was this a crash" state to get wrong.
    #[test]
    fn repeated_set_clear_cycles_are_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        for _ in 0..3 {
            set_stop_requested(base);
            assert!(is_stop_requested(base));
            clear_stop_requested(base);
            assert!(!is_stop_requested(base));
        }
    }
}
