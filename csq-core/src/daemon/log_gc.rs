//! Daemon rolling-log garbage collector (#1a-2, daemon-auth-resilience Wave A2).
//!
//! Deletes rolling daemon-log files (`csq-daemon.log.<date>`, written by
//! `tracing-appender`'s daily rolling file appender — see the `csq` binary
//! crate's `daemon_log` module, which is the writer half of this pair) older
//! than `RETENTION` (14 days). Mirrors the `coc_cache_sweeper`
//! spawn/tick idiom: a `tokio::task::spawn`-ed background loop driven by
//! `tokio::time::interval`, cancelled via a shared `CancellationToken`.
//!
//! # Why this exists
//!
//! The 2026-07-24 mass-expiry incident (an internal journal entry) found daemon logs
//! going to stderr — discarded by a Finder-launched `.app` and, even when
//! file-redirected, silenced past 10 events by the (now-fixed, an internal ticket) event
//! ceiling. #1a-1 adds a persistent rolling file log so the daemon's history
//! survives process death; this module is the paired GC that keeps that log
//! directory from growing unbounded over a long-lived daemon's lifetime.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Filename prefix for rolling daemon-log files. Shared with the `csq`
/// binary crate's `daemon_log` module, which passes this same prefix to
/// `tracing_appender::rolling::daily` — the writer and this GC MUST agree
/// on what a "daemon log file" looks like on disk, or the GC either misses
/// real log files or (worse) deletes files it doesn't own.
pub const LOG_FILE_PREFIX: &str = "csq-daemon.log";

/// Files older than this are deleted.
pub const RETENTION: Duration = Duration::from_secs(14 * 86_400);

/// Tick cadence — the GC runs once per day.
pub const TICK_INTERVAL: Duration = Duration::from_secs(86_400);

/// Resolves the directory holding rolling daemon-log files, given the csq
/// base directory (`~/.claude/accounts` on a default install).
pub fn daemon_log_dir(base_dir: &Path) -> PathBuf {
    base_dir.join("csq-runs").join(".daemon-log")
}

/// One GC pass. Deletes every REGULAR file in `dir` whose file name starts
/// with [`LOG_FILE_PREFIX`] and whose mtime age exceeds `retention`. Returns
/// the count of files deleted.
///
/// A missing `dir` is not an error — a daemon that has never written a
/// rolling log yet (or whose log dir was already fully cleaned) is the
/// common case, not a fault. Per-entry read/metadata/delete errors are
/// logged at debug and skipped rather than aborting the whole pass,
/// mirroring `coc_cache_sweeper::sweep_root`. A file whose name does NOT
/// start with [`LOG_FILE_PREFIX`] is NEVER deleted, regardless of age —
/// defense against nuking siblings that happen to share the directory.
pub fn run_once(dir: &Path, retention: Duration) -> std::io::Result<u64> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let now = SystemTime::now();
    let mut deleted: u64 = 0;

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!("daemon-log-gc: read_dir entry error: {e}");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with(LOG_FILE_PREFIX) {
            // Never touch files that don't match the prefix.
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %entry.path().display(), "daemon-log-gc: metadata error: {e}");
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = match meta.modified() {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %entry.path().display(), "daemon-log-gc: mtime unavailable: {e}");
                continue;
            }
        };
        let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);
        if age <= retention {
            continue;
        }

        let path = entry.path();
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(
                    event = "daemon_log_gc_deleted",
                    path = %path.display(),
                    "daemon-log-gc: deleted"
                );
                deleted += 1;
            }
            Err(e) => {
                debug!(path = %path.display(), "daemon-log-gc: delete failed: {e}");
            }
        }
    }

    Ok(deleted)
}

/// Spawns the daemon-log GC as a background task.
///
/// Runs on [`TICK_INTERVAL`] cadence until `shutdown` is cancelled. Uses
/// `tokio::time::interval_at` anchored one full interval in the future —
/// NOT a bare `tokio::time::interval`, whose first `.tick()` always
/// resolves immediately regardless of `MissedTickBehavior` (that setting
/// only governs *missed* ticks, not the initial one). A freshly-started
/// daemon should not pay the GC's directory-walk cost during startup, so
/// the first real tick is deliberately deferred by one full
/// `TICK_INTERVAL`.
pub fn spawn(base_dir: PathBuf, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
    let dir = daemon_log_dir(&base_dir);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + TICK_INTERVAL;
        let mut ticker = tokio::time::interval_at(start, TICK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("daemon-log-gc: shutdown signalled, exiting");
                    return;
                }
                _ = ticker.tick() => {
                    match run_once(&dir, RETENTION) {
                        Ok(deleted) if deleted > 0 => {
                            info!(
                                event = "daemon_log_gc_complete",
                                files_deleted = deleted,
                                "daemon-log-gc: tick complete"
                            );
                        }
                        Ok(_) => {
                            debug!(
                                event = "daemon_log_gc_complete",
                                files_deleted = 0u64,
                                "daemon-log-gc: tick complete, nothing to do"
                            );
                        }
                        Err(e) => {
                            debug!(
                                error_kind = "daemon_log_gc_failed",
                                "daemon-log-gc: tick failed: {e}"
                            );
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn run_once_deletes_matching_files_with_zero_retention() {
        let tmp = TempDir::new().unwrap();
        let path = touch(tmp.path(), "csq-daemon.log.2026-01-01", b"old log line\n");

        let deleted = run_once(tmp.path(), Duration::from_secs(0)).unwrap();

        assert_eq!(deleted, 1);
        assert!(
            !path.exists(),
            "file older than zero-retention must be deleted"
        );
    }

    #[test]
    fn run_once_keeps_matching_files_with_large_retention() {
        let tmp = TempDir::new().unwrap();
        let path = touch(
            tmp.path(),
            "csq-daemon.log.2026-01-01",
            b"recent log line\n",
        );

        let deleted = run_once(tmp.path(), Duration::from_secs(365 * 86_400)).unwrap();

        assert_eq!(deleted, 0);
        assert!(path.exists(), "file within retention must survive");
    }

    #[test]
    fn run_once_never_deletes_non_prefix_files() {
        let tmp = TempDir::new().unwrap();
        let sibling = touch(tmp.path(), "other.txt", b"not a daemon log\n");

        // Zero retention would delete EVERYTHING matching the prefix — the
        // sibling file must survive regardless because its name doesn't
        // start with LOG_FILE_PREFIX.
        let deleted = run_once(tmp.path(), Duration::from_secs(0)).unwrap();

        assert_eq!(deleted, 0);
        assert!(sibling.exists(), "non-prefix file must never be deleted");
    }

    #[test]
    fn run_once_missing_dir_is_a_no_op() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");

        let deleted = run_once(&missing, Duration::from_secs(0)).unwrap();

        assert_eq!(deleted, 0);
    }

    #[test]
    fn daemon_log_dir_builds_expected_path() {
        let base = Path::new("/tmp/example/.claude/accounts");
        let dir = daemon_log_dir(base);
        assert_eq!(
            dir,
            Path::new("/tmp/example/.claude/accounts/csq-runs/.daemon-log")
        );
    }
}
