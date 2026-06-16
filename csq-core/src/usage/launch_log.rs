//! csq launch log — append-only NDJSON record of every `csq run` and `csq swap`.
//!
//! Per journal 0050 D2 (post-hoc time correlation attribution strategy). Each
//! line carries enough info for the daemon aggregator to attribute a CC
//! session-meta file to a slot:
//!
//! ```json
//! {"ts":"2026-05-06T11:30:00Z","event":"run","slot":4,"pid":12345,
//!  "project_path":"/Users/me/repos/foo"}
//! ```
//!
//! Path: `<base_dir>/.csq-launch.log` (alongside profiles.json + quota.json).
//! Mode 0o600 — same as credential files (the log includes project paths
//! which can be sensitive).
//!
//! Compaction: append-only with a 90-day rolling tail (entries older than 90
//! days are dropped on next append). The daemon aggregator's startup pass
//! triggers the compaction; CLI append paths just write the new line.
//!
//! **Failure mode policy**: launch log writes are best-effort. A failed
//! append MUST NOT block `csq run` / `csq swap` — billing telemetry is
//! diagnostic, not load-bearing. Failures log at WARN with `error_kind` tag.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Filename relative to `base_dir`.
pub const LAUNCH_LOG_FILENAME: &str = ".csq-launch.log";

/// Compaction window — entries older than this are dropped on next compaction.
pub const COMPACTION_WINDOW_DAYS: i64 = 90;

/// Returns the absolute path to the launch log.
pub fn launch_log_path(base_dir: &Path) -> PathBuf {
    base_dir.join(LAUNCH_LOG_FILENAME)
}

/// One line in the launch log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchEvent {
    /// ISO8601 UTC timestamp, e.g. `"2026-05-06T11:30:00Z"`.
    pub ts: String,
    /// Event type: `"run"` (csq run) or `"swap"` (csq swap).
    pub event: String,
    /// Slot bound after the event.
    pub slot: u16,
    /// PID of the csq process that emitted the event (csq run = pre-exec PID
    /// matching the handle dir's `term-<pid>`; csq swap = csq's own PID at
    /// swap time).
    pub pid: u32,
    /// Working directory at csq run / csq swap time. CC's session-meta
    /// `project_path` matches this exactly (CC inherits cwd).
    pub project_path: String,
}

impl LaunchEvent {
    /// Serializes one event as a single NDJSON line (no trailing newline).
    /// The newline is added by [`append`] so callers don't double-write.
    pub fn to_ndjson_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Appends an event to the launch log. Best-effort: failures are returned but
/// callers MUST treat them as non-fatal per the failure-mode policy above.
pub fn append(base_dir: &Path, event: &LaunchEvent) -> Result<(), AppendError> {
    let path = launch_log_path(base_dir);
    let mut line = event.to_ndjson_line().map_err(AppendError::Serialize)?;
    line.push('\n');

    // Append-with-secure-permissions: read existing → append in memory →
    // atomic-replace. For a 90-day-window log this is fast (< few KB on
    // typical use). If this gets hot we'd switch to O_APPEND + fchmod, but
    // that path requires careful tmp-file accounting per security.md §5a.
    let existing = std::fs::read(&path).unwrap_or_default();
    let mut content = existing;
    content.extend_from_slice(line.as_bytes());

    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, &content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppendError::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppendError::Platform(e));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AppendError::Platform(e));
    }
    Ok(())
}

/// Reads all events. Malformed lines are skipped (with a count returned for
/// diagnostics) rather than failing the read — best-effort read mirrors the
/// best-effort write policy.
pub fn read_all(base_dir: &Path) -> Result<ReadResult, std::io::Error> {
    let path = launch_log_path(base_dir);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReadResult {
                events: Vec::new(),
                skipped_malformed: 0,
            });
        }
        Err(e) => return Err(e),
    };
    let mut events = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<LaunchEvent>(trimmed) {
            Ok(ev) => events.push(ev),
            Err(_) => skipped += 1,
        }
    }
    Ok(ReadResult {
        events,
        skipped_malformed: skipped,
    })
}

/// Result of a launch-log read. `skipped_malformed` is non-fatal but tracked
/// so the daemon can surface "your log has corruption" diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub events: Vec<LaunchEvent>,
    pub skipped_malformed: usize,
}

/// Errors from [`append`].
#[derive(Debug)]
pub enum AppendError {
    Io(std::io::Error),
    Platform(crate::error::PlatformError),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendError::Io(e) => write!(f, "io: {e}"),
            AppendError::Platform(e) => write!(f, "platform: {e}"),
            AppendError::Serialize(e) => write!(f, "serialize: {e}"),
        }
    }
}

impl std::error::Error for AppendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ev(ts: &str, event: &str, slot: u16, pid: u32, project: &str) -> LaunchEvent {
        LaunchEvent {
            ts: ts.into(),
            event: event.into(),
            slot,
            pid,
            project_path: project.into(),
        }
    }

    #[test]
    fn append_then_read_round_trips() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let e1 = ev("2026-05-06T10:00:00Z", "run", 1, 12345, "/repo/a");
        let e2 = ev("2026-05-06T10:05:00Z", "swap", 4, 67890, "/repo/b");

        append(base, &e1).unwrap();
        append(base, &e2).unwrap();

        let result = read_all(base).unwrap();
        assert_eq!(result.events, vec![e1, e2]);
        assert_eq!(result.skipped_malformed, 0);
    }

    #[test]
    fn read_missing_log_returns_empty() {
        let dir = TempDir::new().unwrap();
        let result = read_all(dir.path()).unwrap();
        assert!(result.events.is_empty());
        assert_eq!(result.skipped_malformed, 0);
    }

    #[test]
    fn read_skips_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let path = launch_log_path(dir.path());
        std::fs::write(
            &path,
            r#"{"ts":"2026-05-06T10:00:00Z","event":"run","slot":1,"pid":1,"project_path":"/a"}
not-json-at-all
{"ts":"2026-05-06T10:01:00Z","event":"swap","slot":2,"pid":2,"project_path":"/b"}
"#,
        )
        .unwrap();

        let result = read_all(dir.path()).unwrap();
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.skipped_malformed, 1);
    }

    #[test]
    fn append_creates_file_with_secure_mode() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = TempDir::new().unwrap();
            let e = ev("2026-05-06T10:00:00Z", "run", 1, 1, "/a");
            append(dir.path(), &e).unwrap();
            let mode = std::fs::metadata(launch_log_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "launch log must be 0o600 per security.md"
            );
        }
    }

    #[test]
    fn ndjson_line_no_embedded_newlines() {
        let e = ev(
            "2026-05-06T10:00:00Z",
            "run",
            1,
            1,
            "/path/with spaces/and\nmaybe newline?",
        );
        let line = e.to_ndjson_line().unwrap();
        // serde_json escapes \n as \\n — the line itself MUST be one line.
        assert!(
            !line.contains('\n'),
            "ndjson line must not contain newlines"
        );
    }
}
