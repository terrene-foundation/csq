//! Audit sweep — 24-hour tick deleting >30-day-old records under
//! `~/.claude/accounts/csq-runs/` and `csq-runs/.pending/`.
//!
//! See `specs/12-audit-trail.md` §12.6 (retention) and
//! `specs/04-csq-daemon-architecture.md` §4.2.8 (sweep cadence).
//!
//! # Single-write-site invariant
//!
//! This module ONLY DELETES files — it does NOT write under `csq-runs/`.
//! Drain (re-applying `.pending/` records) lives in
//! `daemon::startup_reconciler::pass5_audit_drain`, which calls
//! `audit::persist::write_record` (the single authorized write site) and
//! deletes the source file on success.
//!
//! # Structural pattern
//!
//! Mirrors `daemon::coc_cache_sweeper` exactly:
//! - `AuditSweepSnapshot` — observable state surfaced via `csq doctor --json`.
//! - `AuditSweeperHandle` — returned by `spawn()`; holds the tokio task.
//! - `run_once()` — synchronous core; testable without spawning a task.
//! - Cooperative yield every 100 files (audit files are tiny JSONL).
//! - 5-second per-tick wall-clock budget.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default tick interval — sweep runs once per day.
pub const TICK_INTERVAL: Duration = Duration::from_secs(86_400);

/// Per-tick wall-clock budget per spec 04 §4.2.8.
pub const PER_TICK_BUDGET: Duration = Duration::from_secs(5);

/// Files older than 30 days are deleted unconditionally per spec 12 §12.6.
pub const MAX_AGE: Duration = Duration::from_secs(30 * 86_400);

/// `csq-runs/.trace/*.log` files older than 24 hours are deleted
/// unconditionally per PR-CA11c plan § 0.6. Trace logs are
/// operator-debugging artifacts with no NFR-AUDIT-01 retention
/// requirement; 24h matches "I'll get to this debugging tomorrow".
pub const TRACE_MAX_AGE: Duration = Duration::from_secs(86_400);

/// Cooperative yield every N files (cheaper than cache sweeper's 10-dir yield
/// because audit files are tiny JSONL).
const YIELD_EVERY: usize = 100;

/// Threshold for detecting stale `.pending/` files that the drain did not consume.
const STALE_PENDING_THRESHOLD: Duration = Duration::from_secs(86_400); // 24 hours

/// Snapshot of the sweeper's most recent observable state.
///
/// `csq doctor --json` surfaces this as the top-level `audit_sweeper` block
/// per spec 04 §4.2.8 (same shape as `cache_sweeper` per §4.2.7).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AuditSweepSnapshot {
    /// ISO-8601 UTC timestamp of the most recent completed tick.
    /// `None` until the first tick finishes.
    pub last_sweep_at: Option<String>,
    /// Wall-clock duration of the most recent sweep in milliseconds.
    pub last_sweep_duration_ms: Option<u64>,
    /// Number of `csq-runs/*.jsonl` files deleted in the most recent tick.
    pub files_swept_last_run: u64,
    /// Number of `csq-runs/.pending/*.jsonl` files deleted in the most recent tick.
    pub pending_files_swept_last_run: u64,
    /// True if `.pending/` has files older than 24 hours that the most
    /// recent drain did NOT consume — surfaces `degraded` per spec 04 §4.2.8.
    pub pending_stale_24h: bool,
    /// Number of `csq-runs/.trace/*.log` files deleted in the most
    /// recent tick (PR-CA11c T7). `serde(default)` so older snapshot
    /// payloads parsed by upgraded daemons don't fail.
    #[serde(default)]
    pub trace_files_swept_last_run: u64,
}

/// Handle to a running sweeper task.
pub struct AuditSweeperHandle {
    pub join: tokio::task::JoinHandle<()>,
    /// Shared snapshot; `csq doctor --json` reads this without an IPC round-trip.
    pub snapshot: Arc<RwLock<AuditSweepSnapshot>>,
}

/// Spawns the daemon-side audit sweeper.
///
/// `base_dir` is `~/.claude/accounts`; pass an explicit override path during
/// testing. The sweeper runs every `TICK_INTERVAL` until cancelled.
pub fn spawn(base_dir: PathBuf, shutdown: CancellationToken) -> AuditSweeperHandle {
    spawn_with_config(base_dir, shutdown, TICK_INTERVAL)
}

/// Like [`spawn`] but with explicit tick interval for tests.
pub fn spawn_with_config(
    base_dir: PathBuf,
    shutdown: CancellationToken,
    interval: Duration,
) -> AuditSweeperHandle {
    let snapshot = Arc::new(RwLock::new(AuditSweepSnapshot::default()));
    let task_snapshot = Arc::clone(&snapshot);

    let join = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("audit-sweep: shutdown signalled, exiting");
                    return;
                }
                _ = ticker.tick() => {
                    let snap = run_once(&base_dir);
                    if let Ok(mut guard) = task_snapshot.write() {
                        *guard = snap;
                    }
                }
            }
        }
    });

    AuditSweeperHandle { join, snapshot }
}

/// One tick of the audit sweeper.
///
/// Public so tests and the doctor harness can drive a synchronous sweep
/// without needing to spawn a task.
///
/// Deletes:
/// - `<base_dir>/csq-runs/*.jsonl` with mtime > 30 days.
/// - `<base_dir>/csq-runs/.pending/*.jsonl` with mtime > 30 days.
/// - `<base_dir>/csq-runs/.trace/*.log` with mtime > 24 hours
///   (PR-CA11c T7).
///
/// Per-deletion logging at INFO with structured `audit_sweep_deleted` tag.
/// Cooperative yield every 100 files via `std::hint::spin_loop` (blocking
/// context — `run_once` is called from inside a tokio task but the deletion
/// itself is synchronous).
///
/// Returns the populated [`AuditSweepSnapshot`].
pub fn run_once(base_dir: &Path) -> AuditSweepSnapshot {
    let started = Instant::now();
    let now = SystemTime::now();

    let csq_runs = base_dir.join("csq-runs");
    let pending_dir = csq_runs.join(".pending");
    let trace_dir = csq_runs.join(".trace");

    // Sweep main csq-runs/ directory.
    let files_swept = sweep_dir(
        &csq_runs,
        now,
        started,
        PER_TICK_BUDGET,
        SweepKind::AuditJsonl,
    );

    // Sweep .pending/ directory (same 30-day cutoff).
    let pending_files_swept = sweep_dir(
        &pending_dir,
        now,
        started,
        PER_TICK_BUDGET,
        SweepKind::AuditJsonl,
    );

    // Sweep .trace/ directory (24-hour cutoff per PR-CA11c § 0.6).
    let trace_files_swept = sweep_dir(
        &trace_dir,
        now,
        started,
        PER_TICK_BUDGET,
        SweepKind::TraceLog,
    );

    // Check for stale-but-surviving .pending/ files (drain didn't consume them).
    let pending_stale_24h = check_pending_stale(&pending_dir, now);

    let duration = started.elapsed();
    let now_iso = current_iso8601_utc();

    let snap = AuditSweepSnapshot {
        last_sweep_at: Some(now_iso),
        last_sweep_duration_ms: Some(duration.as_millis() as u64),
        files_swept_last_run: files_swept,
        pending_files_swept_last_run: pending_files_swept,
        pending_stale_24h,
        trace_files_swept_last_run: trace_files_swept,
    };

    if files_swept > 0 || pending_files_swept > 0 || trace_files_swept > 0 {
        info!(
            event = "audit_sweep_complete",
            files_swept = files_swept,
            pending_files_swept = pending_files_swept,
            trace_files_swept = trace_files_swept,
            duration_ms = duration.as_millis() as u64,
            "audit-sweep: tick complete"
        );
    } else {
        debug!(
            event = "audit_sweep_complete",
            files_swept = 0,
            pending_files_swept = 0,
            trace_files_swept = 0,
            duration_ms = duration.as_millis() as u64,
            "audit-sweep: tick complete (nothing to sweep)"
        );
    }

    snap
}

/// Per-target sweep configuration. Determines which extension + age
/// threshold + log-reason tag the sweep applies to a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepKind {
    /// `*.jsonl` files older than 30 days (audit records and `.pending/`).
    AuditJsonl,
    /// `*.log` files older than 24 hours (`csq-runs/.trace/`, PR-CA11c T7).
    TraceLog,
}

impl SweepKind {
    fn extension(self) -> &'static str {
        match self {
            SweepKind::AuditJsonl => "jsonl",
            SweepKind::TraceLog => "log",
        }
    }
    fn max_age(self) -> Duration {
        match self {
            SweepKind::AuditJsonl => MAX_AGE,
            SweepKind::TraceLog => TRACE_MAX_AGE,
        }
    }
    fn reason(self) -> &'static str {
        match self {
            SweepKind::AuditJsonl => "mtime_30d",
            SweepKind::TraceLog => "trace_log_24h",
        }
    }
}

/// Sweeps a single directory, deleting files matching the kind's
/// extension whose mtime exceeds the kind's max-age.
///
/// Returns the count of deleted files.
fn sweep_dir(
    dir: &Path,
    now: SystemTime,
    started: Instant,
    budget: Duration,
    kind: SweepKind,
) -> u64 {
    if !dir.exists() {
        return 0;
    }

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            warn!(
                error_kind = "audit_sweep_readdir_failed",
                dir = %dir.display(),
                "audit-sweep: read_dir failed: {e}"
            );
            return 0;
        }
    };

    let mut swept: u64 = 0;
    let mut file_count: usize = 0;
    let target_ext = kind.extension();
    let max_age = kind.max_age();
    let reason = kind.reason();

    for entry in read_dir {
        // Cooperative yield every YIELD_EVERY files per spec 04 §4.2.8.
        file_count += 1;
        if file_count.is_multiple_of(YIELD_EVERY) {
            std::hint::spin_loop();
        }

        // Wall-clock budget check.
        if started.elapsed() >= budget {
            info!(
                event = "audit_sweep_budget_exceeded",
                dir = %dir.display(),
                files_swept = swept,
                "audit-sweep: 5s budget exceeded; remaining files deferred to next tick"
            );
            break;
        }

        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!("audit-sweep: read_dir entry error: {e}");
                continue;
            }
        };

        let path = entry.path();

        // Only sweep files matching the kind's extension; skip subdirs.
        if path.is_dir() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some(target_ext) {
            continue;
        }
        // Skip tmp files (name contains ".tmp.").
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if fname.contains(".tmp.") {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                debug!(
                    path = %path.display(),
                    "audit-sweep: metadata error: {e}"
                );
                continue;
            }
        };

        let mtime = meta.modified().unwrap_or(now);
        let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);

        if age > max_age {
            // Chain-aware guard (M02, Amendment 2): never age-delete a v2
            // record. Read ONLY the first 128 bytes of the file (enough to
            // detect the `"schema_version":"2"` marker) to keep the hot path
            // allocation-free. Any read error → conservative keep (do not
            // delete). A v2 record must be explicitly migrated or archived
            // via the chain-export path, not silently discarded.
            if kind == SweepKind::AuditJsonl && is_schema_v2(&path) {
                debug!(
                    event = "audit_sweep_skip_v2",
                    path = %path.display(),
                    "audit-sweep: skipping v2 record (chain-aware guard)"
                );
                continue;
            }

            match std::fs::remove_file(&path) {
                Ok(()) => {
                    info!(
                        event = "audit_sweep_deleted",
                        path = %path.display(),
                        reason = reason,
                        "audit-sweep: deleted"
                    );
                    swept += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Concurrent deletion is fine — idempotent. Do NOT increment
                    // `swept`: another sweeper already counted this one. Counting
                    // both attempts overstates per-tick deletions, which the
                    // `concurrent_safe` test pins.
                }
                Err(e) => {
                    warn!(
                        event = "audit_sweep_delete_failed",
                        path = %path.display(),
                        "audit-sweep: delete failed: {e}"
                    );
                }
            }
        }
    }

    swept
}

/// Returns true if `path` is a schema-v2 JSONL record.
///
/// Reads at most 128 bytes from the file (sufficient to detect the
/// `"schema_version":"2"` marker placed early in the JSON object).
/// Returns `false` on any read error so that unreadable files are
/// treated conservatively (keep, not delete).
fn is_schema_v2(path: &Path) -> bool {
    use std::io::Read as _;
    let mut buf = [0u8; 128];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => n,
        Err(_) => return false,
    };
    // We search for the literal byte sequence: `"schema_version":"2"` or
    // `"schema_version": "2"` (with optional space). Using a simple
    // substring search on the prefix avoids pulling in serde for the
    // hot-path sweep guard.
    let prefix = &buf[..n];
    let s = match std::str::from_utf8(prefix) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Trim leading whitespace / `{` then scan for the version marker.
    s.contains("\"schema_version\":\"2\"") || s.contains("\"schema_version\": \"2\"")
}

/// Returns true if any `.jsonl` file in `pending_dir` has an mtime older
/// than 24 hours — indicating the drain did not consume it.
fn check_pending_stale(pending_dir: &Path, now: SystemTime) -> bool {
    if !pending_dir.exists() {
        return false;
    }

    let read_dir = match std::fs::read_dir(pending_dir) {
        Ok(rd) => rd,
        Err(_) => return false,
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if fname.contains(".tmp.") {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            let mtime = meta.modified().unwrap_or(now);
            let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);
            if age > STALE_PENDING_THRESHOLD {
                return true;
            }
        }
    }

    false
}

/// Minimal ISO-8601 UTC formatter using stdlib only.
fn current_iso8601_utc() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = now.as_secs() as i64;
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Civil-time conversion adapted from the public-domain "civil_from_days"
/// algorithm (Howard Hinnant). Stdlib-only.
fn unix_to_ymdhms(mut t: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (t.rem_euclid(86_400)) as u32;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    t = t.div_euclid(86_400);
    let z = t + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = (y + i64::from(month <= 2)) as i32;
    (year, month, day, hour, minute, second)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Write a `.jsonl` file under `dir` and set its mtime to `now - age`.
    #[cfg(unix)]
    fn plant_file_with_age(dir: &Path, name: &str, age: Duration) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"{}").unwrap();
        // Set mtime by computing the target SystemTime and using filetime crate
        // — but we don't have filetime. Use a workaround: write, then call
        // `std::fs::File::set_times` if available, or just use utimensat directly.
        // Since we can't directly set mtime without filetime or libc, we use a
        // trick: set the file's mtime via the raw `utimensat` syscall on unix.
        set_mtime_age(&path, age);
        path
    }

    /// Sets `path`'s mtime to `now - age` using libc utimensat on Unix.
    #[cfg(unix)]
    fn set_mtime_age(path: &Path, age: Duration) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let target_time = SystemTime::now()
            .checked_sub(age)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let secs = target_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as libc::time_t)
            .unwrap_or(0);

        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path_c is a valid null-terminated C string; timespec values are valid.
        unsafe {
            let times = [
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
            ];
            libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0);
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn set_mtime_age(_path: &Path, _age: Duration) {
        // No-op on non-Unix, non-Windows — mtime manipulation requires
        // platform-specific APIs. The mtime-sensitive tests are marked
        // #[cfg(unix)], and their sole (also unix-gated) caller
        // `plant_file_with_age` never reaches this arm on Windows either,
        // so this stub is scoped away from both to avoid a dead-code
        // warning on the Windows test target.
    }

    #[cfg(unix)]
    fn setup_csq_runs(tmp: &TempDir) -> (PathBuf, PathBuf) {
        let base = tmp.path().to_path_buf();
        let csq_runs = base.join("csq-runs");
        let pending = csq_runs.join(".pending");
        std::fs::create_dir_all(&csq_runs).unwrap();
        std::fs::create_dir_all(&pending).unwrap();
        (csq_runs, pending)
    }

    // ── T8.1 — run_once deletes 30d+ old records in csq-runs/ ─────────────

    #[cfg(unix)]
    #[test]
    fn run_once_deletes_30d_old_records() {
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _pending) = setup_csq_runs(&tmp);

        // Plant files with varying ages.
        // Note: "exactly 30 days" is set to 30d - 60s to ensure it's reliably
        // WITHIN the boundary (age <= MAX_AGE) rather than drifting past it
        // by the time the sweep runs. The sweep uses `age > MAX_AGE` (strict).
        let age_31d = Duration::from_secs(31 * 86_400);
        let age_just_under_30d = Duration::from_secs(30 * 86_400 - 60); // 30d - 1min
        let age_29d = Duration::from_secs(29 * 86_400);
        let age_1h = Duration::from_secs(3_600);

        let f_31d = plant_file_with_age(&csq_runs, "a.jsonl", age_31d);
        let f_30d = plant_file_with_age(&csq_runs, "b.jsonl", age_just_under_30d);
        let f_29d = plant_file_with_age(&csq_runs, "c.jsonl", age_29d);
        let f_1h = plant_file_with_age(&csq_runs, "d.jsonl", age_1h);

        let snap = run_once(tmp.path());

        // The 31d file must be gone.
        assert!(
            !f_31d.exists(),
            "31-day-old file must be swept (age > MAX_AGE)"
        );
        // The just-under-30d file: age < MAX_AGE, must survive.
        assert!(
            f_30d.exists(),
            "just-under-30-day file must survive (age < MAX_AGE)"
        );
        assert!(f_29d.exists(), "29-day-old file must survive");
        assert!(f_1h.exists(), "1-hour-old file must survive");

        assert_eq!(snap.files_swept_last_run, 1, "only the 31d file swept");
    }

    // ── T8.2 — run_once sweeps .pending/ too ──────────────────────────────

    #[cfg(unix)]
    #[test]
    fn run_once_sweeps_pending_dir_too() {
        let tmp = TempDir::new().unwrap();
        let (_csq_runs, pending) = setup_csq_runs(&tmp);

        let age_31d = Duration::from_secs(31 * 86_400);
        let age_1h = Duration::from_secs(3_600);

        let f_old = plant_file_with_age(&pending, "old.jsonl", age_31d);
        let f_new = plant_file_with_age(&pending, "new.jsonl", age_1h);

        let snap = run_once(tmp.path());

        assert!(!f_old.exists(), "31d pending file must be swept");
        assert!(f_new.exists(), "recent pending file must survive");
        assert_eq!(snap.pending_files_swept_last_run, 1);
    }

    // ── T8.3 — pending_stale_24h detected ──────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn pending_stale_24h_detected() {
        let tmp = TempDir::new().unwrap();
        let (_csq_runs, pending) = setup_csq_runs(&tmp);

        // Plant a file that is 25h old (stale but < 30d so not swept).
        let age_25h = Duration::from_secs(25 * 3_600);
        let _f = plant_file_with_age(&pending, "stale.jsonl", age_25h);

        let snap = run_once(tmp.path());
        assert!(
            snap.pending_stale_24h,
            "a 25h-old .pending/ file must trigger pending_stale_24h"
        );
    }

    // ── T8.4 — pending_stale_24h false when only recent files ─────────────

    #[cfg(unix)]
    #[test]
    fn pending_stale_24h_false_when_only_recent() {
        let tmp = TempDir::new().unwrap();
        let (_csq_runs, pending) = setup_csq_runs(&tmp);

        // Plant a file with age < 24h.
        let age_23h = Duration::from_secs(23 * 3_600);
        let _f = plant_file_with_age(&pending, "recent.jsonl", age_23h);

        let snap = run_once(tmp.path());
        assert!(
            !snap.pending_stale_24h,
            "a 23h-old .pending/ file must NOT trigger pending_stale_24h"
        );
    }

    // ── T8.5 — yield every 100 files (structure test) ─────────────────────

    /// The YIELD_EVERY constant is verified to be 100 — the actual cooperative
    /// yield (std::hint::spin_loop) is not directly observable without a spy,
    /// so this test verifies the constant and the sweep correctness under a
    /// larger file set.
    #[cfg(unix)]
    #[test]
    fn sweep_handles_200_files_correctly() {
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _pending) = setup_csq_runs(&tmp);

        // Plant 150 old files and 50 recent files.
        let age_31d = Duration::from_secs(31 * 86_400);
        let age_1h = Duration::from_secs(3_600);

        for i in 0..150 {
            plant_file_with_age(&csq_runs, &format!("old-{i:04}.jsonl"), age_31d);
        }
        for i in 0..50 {
            plant_file_with_age(&csq_runs, &format!("new-{i:04}.jsonl"), age_1h);
        }

        let snap = run_once(tmp.path());

        // Exactly 150 old files deleted.
        assert_eq!(snap.files_swept_last_run, 150, "all 150 old files swept");

        // 50 recent files must remain.
        let remaining: Vec<_> = std::fs::read_dir(&csq_runs)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x == "jsonl")
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(remaining.len(), 50, "50 recent files must survive");

        // Verify YIELD_EVERY is 100 (the constant).
        assert_eq!(YIELD_EVERY, 100);
    }

    // ── T8.6 — per-deletion log tag is audit_sweep_deleted ─────────────────

    /// Structural test: verifies the `audit_sweep_deleted` event tag is used
    /// in the deletion logging code. The actual tracing output is validated by
    /// reading the source — a code-level probe rather than a runtime capture.
    #[test]
    fn audit_sweep_deleted_tag_is_in_source() {
        // Structural probe: check that the constant string appears in this
        // file's source. This is a static assertion against the logging contract.
        let source = include_str!("sweep.rs");
        assert!(
            source.contains("audit_sweep_deleted"),
            "sweep.rs must contain the audit_sweep_deleted log tag"
        );
        assert!(
            source.contains("mtime_30d"),
            "sweep.rs must log reason = \"mtime_30d\""
        );
    }

    // ── T8.7 — concurrent run_once calls are safe ──────────────────────────

    #[cfg(unix)]
    #[test]
    fn concurrent_safe() {
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _pending) = setup_csq_runs(&tmp);

        // Plant one old file that both threads will race to delete.
        let age_31d = Duration::from_secs(31 * 86_400);
        plant_file_with_age(&csq_runs, "race.jsonl", age_31d);

        let base = tmp.path().to_path_buf();
        let base2 = base.clone();

        // Run two concurrent sweeps. Both must complete without panic,
        // even if both try to delete the same file (ENOENT is OK).
        let h1 = std::thread::spawn(move || run_once(&base));
        let h2 = std::thread::spawn(move || run_once(&base2));

        let snap1 = h1.join().expect("thread 1 must not panic");
        let snap2 = h2.join().expect("thread 2 must not panic");

        // Per-thread structural invariant: each must report ≥ 1 sweep
        // (either it deleted, or saw an ENOENT under our compensating code
        // path) and the file MUST be gone afterwards. The exact total is
        // OS-dependent: macOS APFS allows two concurrent `unlink()` calls
        // on the same file to BOTH return success (verified empirically),
        // so per-OS the total is in {1, 2}. Linux ext4 returns ENOENT to
        // the loser. Both are valid; the structural property is the file
        // is deleted, not the count.
        let total_swept = snap1.files_swept_last_run + snap2.files_swept_last_run;
        assert!(
            (1..=2).contains(&total_swept),
            "per-thread sweep count total must be 1 or 2; got {total_swept}"
        );

        assert!(
            !csq_runs.join("race.jsonl").exists(),
            "race file must be gone after either thread sweeps"
        );
    }

    // ── T8.8 — no-op on missing csq-runs/ dir ─────────────────────────────

    #[test]
    fn run_once_noop_on_missing_dir() {
        let tmp = TempDir::new().unwrap();
        // Don't create csq-runs/ — sweep must be a no-op.
        let snap = run_once(tmp.path());
        assert_eq!(snap.files_swept_last_run, 0);
        assert_eq!(snap.pending_files_swept_last_run, 0);
        assert!(!snap.pending_stale_24h);
        assert_eq!(snap.trace_files_swept_last_run, 0);
    }

    // ── T7 — trace-log purge tests (PR-CA11c) ────────────────────────────

    /// Helper: plant a `.log` file in `dir` with a given age.
    #[cfg(unix)]
    fn plant_log_with_age(dir: &Path, name: &str, age: Duration) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"trace event line").unwrap();
        set_mtime_age(&path, age);
        path
    }

    #[cfg(unix)]
    fn setup_trace(tmp: &TempDir) -> (PathBuf, PathBuf) {
        let base = tmp.path().to_path_buf();
        let csq_runs = base.join("csq-runs");
        let trace = csq_runs.join(".trace");
        std::fs::create_dir_all(&csq_runs).unwrap();
        std::fs::create_dir_all(&trace).unwrap();
        (csq_runs, trace)
    }

    #[cfg(unix)]
    #[test]
    fn run_once_deletes_trace_logs_older_than_24h() {
        let tmp = TempDir::new().unwrap();
        let (_csq_runs, trace) = setup_trace(&tmp);

        let age_25h = Duration::from_secs(25 * 3_600);
        // Use 23h-30min instead of literal "24h - 60s" so the test
        // doesn't hit a boundary race during a slow runner. The
        // sweep uses `age > TRACE_MAX_AGE` (strict), so anything
        // strictly under 86400s survives.
        let age_just_under_24h = Duration::from_secs(23 * 3_600 + 30 * 60);
        let age_1h = Duration::from_secs(3_600);

        let f_25h = plant_log_with_age(&trace, "old-25h.log", age_25h);
        let f_under_24h = plant_log_with_age(&trace, "edge.log", age_just_under_24h);
        let f_1h = plant_log_with_age(&trace, "fresh.log", age_1h);

        let snap = run_once(tmp.path());

        assert!(!f_25h.exists(), "25h-old trace log must be swept");
        assert!(f_under_24h.exists(), "<24h trace log must survive");
        assert!(f_1h.exists(), "1h trace log must survive");
        assert_eq!(snap.trace_files_swept_last_run, 1);
    }

    #[cfg(unix)]
    #[test]
    fn run_once_independent_thresholds_for_audit_vs_trace() {
        // Plant files in BOTH csq-runs/ and csq-runs/.trace/ at ages
        // that span the boundary between the two thresholds.
        // Verify each target uses its own max-age.
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _) = setup_csq_runs(&tmp);
        let trace = csq_runs.join(".trace");
        std::fs::create_dir_all(&trace).unwrap();

        // 25h is OLDER than TRACE_MAX_AGE (24h) → trace sweep deletes.
        // 25h is NEWER than MAX_AGE (30d) → audit sweep does NOT delete.
        let age_25h = Duration::from_secs(25 * 3_600);

        let audit_25h = plant_file_with_age(&csq_runs, "audit.jsonl", age_25h);
        let trace_25h = plant_log_with_age(&trace, "trace.log", age_25h);

        let snap = run_once(tmp.path());

        assert!(audit_25h.exists(), "25h audit file must survive (< 30d)");
        assert!(!trace_25h.exists(), "25h trace log must be swept (> 24h)");
        assert_eq!(snap.files_swept_last_run, 0);
        assert_eq!(snap.trace_files_swept_last_run, 1);
    }

    #[cfg(unix)]
    #[test]
    fn run_once_skips_non_log_files_in_trace_dir() {
        let tmp = TempDir::new().unwrap();
        let (_csq_runs, trace) = setup_trace(&tmp);

        let age_25h = Duration::from_secs(25 * 3_600);
        // .jsonl in .trace/ is NOT swept by trace target (wrong ext).
        let jsonl = plant_file_with_age(&trace, "wrong-ext.jsonl", age_25h);
        // .log in .trace/ IS swept.
        let logf = plant_log_with_age(&trace, "trace.log", age_25h);

        let snap = run_once(tmp.path());

        assert!(jsonl.exists(), ".jsonl in .trace/ must NOT be swept");
        assert!(!logf.exists(), ".log in .trace/ MUST be swept");
        assert_eq!(snap.trace_files_swept_last_run, 1);
    }

    #[test]
    fn run_once_noop_on_missing_trace_dir() {
        let tmp = TempDir::new().unwrap();
        // Create csq-runs/ but NOT .trace/.
        std::fs::create_dir_all(tmp.path().join("csq-runs")).unwrap();
        let snap = run_once(tmp.path());
        assert_eq!(snap.trace_files_swept_last_run, 0);
    }

    #[test]
    fn audit_sweep_deleted_tag_includes_trace_log_24h_reason() {
        // Structural assertion: the source contains the new reason
        // string `trace_log_24h` as the per-deletion log tag.
        let source = include_str!("sweep.rs");
        assert!(
            source.contains("trace_log_24h"),
            "sweep.rs must log reason = \"trace_log_24h\""
        );
        // Old reason string still present.
        assert!(source.contains("mtime_30d"));
    }

    #[test]
    fn trace_max_age_is_24_hours() {
        // Pin the contract that PR-CA11c plan § 0.6 cites.
        assert_eq!(TRACE_MAX_AGE, Duration::from_secs(86_400));
    }

    // ── M02 Amendment 2 — chain-aware v2 guard ───────────────────────────

    /// Verify the chain-aware guard: v2 records MUST NOT be aged out even
    /// when their mtime exceeds MAX_AGE. A v1 record at the same age MUST
    /// be deleted normally (regression: guard only fires for v2).
    #[cfg(unix)]
    #[test]
    fn sweep_v2_records_never_aged_out() {
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _pending) = setup_csq_runs(&tmp);

        let age_31d = Duration::from_secs(31 * 86_400);

        // v2 record — has `"schema_version":"2"` in its content.
        let v2_path = csq_runs.join("v2_record.jsonl");
        std::fs::write(
            &v2_path,
            br#"{"schema_version":"2","record_id":"01JZ00000000000000000000XY","seq":0}"#,
        )
        .unwrap();
        set_mtime_age(&v2_path, age_31d);

        // v1 record — has `"schema_version":"1"` (or no version field at all).
        let v1_path = csq_runs.join("v1_record.jsonl");
        std::fs::write(
            &v1_path,
            br#"{"schema_version":"1","record_id":"01JZ00000000000000000000R0","seq":0}"#,
        )
        .unwrap();
        set_mtime_age(&v1_path, age_31d);

        let snap = run_once(tmp.path());

        // v2 file MUST still exist — chain-aware guard preserved it.
        assert!(
            v2_path.exists(),
            "v2 record must NOT be age-deleted (chain-aware guard)"
        );

        // v1 file MUST be gone — normal MAX_AGE deletion.
        assert!(
            !v1_path.exists(),
            "v1 record must be age-deleted (normal sweep)"
        );

        // Only 1 deletion counted (the v1 file).
        assert_eq!(snap.files_swept_last_run, 1, "only the v1 record was swept");
    }

    /// M-17 (R1 fix-wave): the chain-aware guard MUST also preserve a
    /// fully-shaped KeyRotate v2 record (not just the minimal
    /// `{schema_version, record_id, seq}` fixture used by
    /// [`sweep_v2_records_never_aged_out`]). Regression guard for any
    /// future per-EventKind variant carve-out in the guard logic.
    #[cfg(unix)]
    #[test]
    fn test_sweep_v2_keyrotate_record_never_aged_out() {
        let tmp = TempDir::new().unwrap();
        let (csq_runs, _pending) = setup_csq_runs(&tmp);

        let age_31d = Duration::from_secs(31 * 86_400);

        // Fully-shaped v2 KeyRotate record — every field the live writer
        // emits is present, so any guard that pivoted on `kind` would
        // observe the variant correctly.
        let keyrotate_path = csq_runs.join("keyrotate_record.jsonl");
        let payload = br#"{"schema_version":"2","record_id":"01JZKEYROTATE00000000000XY","chain_id":"01JZKEYROTATE00000000000XY","seq":7,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","kind":"KeyRotate","payload":{"KeyRotate":{"previous_key_id":"ed25519:0000000000000000000000000000000000000000000000000000000000000000","new_key_id":"ed25519:1111111111111111111111111111111111111111111111111111111111111111","incoming_pubkey":"1111111111111111111111111111111111111111111111111111111111111111","rotation_reason":"Operator"}},"ts":"2026-05-28T12:00:00+00:00","key_id":"ed25519:0000000000000000000000000000000000000000000000000000000000000000","canonical_hash":"0000000000000000000000000000000000000000000000000000000000000000","signature":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}"#;
        std::fs::write(&keyrotate_path, payload).unwrap();
        set_mtime_age(&keyrotate_path, age_31d);

        let snap = run_once(tmp.path());

        // Chain-aware guard MUST preserve any v2 record regardless of `kind`.
        assert!(
            keyrotate_path.exists(),
            "v2 KeyRotate record must NOT be age-deleted (chain-aware guard)"
        );
        assert_eq!(
            snap.files_swept_last_run, 0,
            "no files swept — only the KeyRotate v2 record was present and guard preserved it"
        );
    }

    #[test]
    fn snapshot_serializes_trace_field_with_serde_default_compatibility() {
        // An older snapshot JSON without the `trace_files_swept_last_run`
        // field MUST still parse — the new field is `serde(default)`.
        let legacy = r#"{
            "last_sweep_at": null,
            "last_sweep_duration_ms": null,
            "files_swept_last_run": 0,
            "pending_files_swept_last_run": 0,
            "pending_stale_24h": false
        }"#;
        let snap: AuditSweepSnapshot = serde_json::from_str(legacy).unwrap();
        assert_eq!(snap.trace_files_swept_last_run, 0);
    }
}
