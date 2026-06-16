//! Daemon-side parse-cache sweeper (PR-CA9b / T20).
//!
//! Sweeps `<.coc/-root>/.cache/parsed-<lock_sha>.bin` files written by
//! [`crate::coc::cache::write_parsed_cache`]. Files are deleted when
//! their mtime exceeds 30 days OR when the embedded `lock_sha` no longer
//! matches the `<root>/.coc/COC.lock` digest of any currently-known root.
//!
//! Runs as a `tokio::task::spawn`-ed background task per R2/B59 — never on
//! the daemon main loop. Each tick is wall-clock-capped at 30 seconds; if
//! the budget is exhausted the sweeper records `sweep_partial: true` plus
//! a cursor and resumes from there on the next tick (per R2/B59 bullet).
//!
//! Bench-results retention is **out of scope** per R2/B57 — that lives in
//! `coc-eval/bench/lib/results_retention.py` (Python, gate-side).
//!
//! Filename validation uses an exact-shape check (`parsed-<64-hex>.bin`)
//! per R2/B72; tmp files (`<base>.bin.tmp.<pid>.<counter>`) MUST NOT
//! match. The check is implemented as a small stdlib function rather
//! than a regex crate to keep `csq-core`'s dep graph minimal.
//!
//! Roots come from `~/.csq/coc-roots-seen.jsonl`, a FIFO (256-line cap)
//! that `csq-cli` writes on every successful `csq run` invocation. PR-CA10
//! transitions authority to per-run-recorded `coc_root` in the audit
//! pipeline; the FIFO is the transitional source per spec 10 §10.9.3.

use crate::coc::cache::{lock_sha256, read_lock};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default tick interval — the sweep runs once per day.
pub const TICK_INTERVAL: Duration = Duration::from_secs(86_400);

/// Per-tick wall-clock budget per R2/B59. Exceeding this records
/// `sweep_partial` + a cursor and yields to the next tick.
pub const PER_TICK_BUDGET: Duration = Duration::from_secs(30);

/// Files older than this are deleted unconditionally per spec 10 §10.9.3.
pub const MAX_AGE: Duration = Duration::from_secs(30 * 86_400);

/// FIFO cap on `coc-roots-seen.jsonl` per spec 10 §10.9.3.
pub const ROOTS_SEEN_CAP: usize = 256;

/// Threshold beyond which a Windows `ERROR_SHARING_VIOLATION` retry counter
/// surfaces in `csq doctor --json::cache_sweeper.cache_sweep_blocked`
/// (R2/B71). We track per-file retries; once any file exceeds this many
/// consecutive blocked ticks we bump the surfaced count.
pub const SHARING_VIOLATION_RETRY_LIMIT: u8 = 7;

/// One row in `~/.csq/coc-roots-seen.jsonl`. JSON-line format:
///
/// ```json
/// {"coc_root": "/abs/path/to/.coc/-rooted/repo", "last_seen": 1234567890}
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RootEntry {
    pub coc_root: String,
    /// Unix epoch seconds at the most recent `csq run` that touched this root.
    pub last_seen: i64,
}

/// Snapshot of the sweeper's most recent observable state. `csq doctor
/// --json` surfaces this as the top-level `cache_sweeper` block per R3/B90.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SweeperSnapshot {
    /// ISO-8601 UTC timestamp of the most recent COMPLETED tick.
    /// `None` until the first tick finishes.
    pub last_sweep_at: Option<String>,
    pub last_sweep_duration_ms: u64,
    pub sweep_partial: bool,
    /// Minutes since `last_sweep_at` exceeds 24h ⇒ `csq doctor` flips
    /// top-level `status: "degraded"`.
    pub sweep_lag_minutes: i64,
    pub files_swept_last_run: u64,
    pub files_skipped_last_run: u64,
    /// Number of files currently blocked by Windows `ERROR_SHARING_VIOLATION`
    /// for `>= SHARING_VIOLATION_RETRY_LIMIT` consecutive ticks.
    pub cache_sweep_blocked: u64,
}

/// Mutable state shared between the spawned tick task and the doctor
/// snapshot accessor. `BTreeMap` (NOT HashMap) for the per-file retry
/// table per R2/B70 — deterministic iteration is required when we surface
/// counts to the doctor JSON (so two doctor invocations agree on order).
#[derive(Debug, Default)]
pub struct SweeperState {
    pub snapshot: SweeperSnapshot,
    pub partial_cursor: Option<usize>,
    pub sharing_violation_retries: BTreeMap<PathBuf, u8>,
}

impl SweeperState {
    pub fn snapshot(&self) -> SweeperSnapshot {
        self.snapshot.clone()
    }
}

/// Handle to a running sweeper task.
pub struct SweeperHandle {
    pub join: tokio::task::JoinHandle<()>,
    pub state: Arc<Mutex<SweeperState>>,
}

/// Spawns the daemon-side parse-cache sweeper.
///
/// `roots_seen_path` points at `~/.csq/coc-roots-seen.jsonl`; pass an
/// explicit override path during testing. The sweeper runs immediately
/// (one tick at startup) and then every `TICK_INTERVAL` until cancelled.
pub fn spawn(roots_seen_path: PathBuf, shutdown: CancellationToken) -> SweeperHandle {
    spawn_with_config(roots_seen_path, shutdown, TICK_INTERVAL, PER_TICK_BUDGET)
}

/// Like [`spawn`] but with explicit timing for tests.
pub fn spawn_with_config(
    roots_seen_path: PathBuf,
    shutdown: CancellationToken,
    interval: Duration,
    per_tick_budget: Duration,
) -> SweeperHandle {
    let state = Arc::new(Mutex::new(SweeperState::default()));
    let task_state = Arc::clone(&state);

    // Persist the snapshot to a sibling file so `csq doctor --json` can
    // read it without an IPC round-trip. The base_dir for the state file
    // is the parent of `roots_seen_path` (typically `~/.csq/`).
    let state_path = roots_seen_path
        .parent()
        .map(state_file_path)
        .unwrap_or_else(|| PathBuf::from("coc-cache-sweeper-state.json"));

    let join = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately by default. Skip the immediate
        // tick and then run on cadence so a freshly-started daemon does
        // not pay the sweep cost during startup-critical operations.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("coc-cache-sweep: shutdown signalled, exiting");
                    return;
                }
                _ = ticker.tick() => {
                    let _ = run_once(&roots_seen_path, &task_state, per_tick_budget);
                    let snap = task_state
                        .lock()
                        .map(|s| s.snapshot())
                        .unwrap_or_default();
                    if let Err(e) = write_state_file(&state_path, &snap) {
                        warn!(error_kind = "coc_cache_sweeper_state_write", "{e}");
                    }
                }
            }
        }
    });

    SweeperHandle { join, state }
}

/// Resolves the sweeper-state JSON file for a given base_dir.
/// `csq doctor --json` reads this file to surface the `cache_sweeper`
/// block per R3/B90.
pub fn state_file_path(base_dir: &Path) -> PathBuf {
    base_dir.join("coc-cache-sweeper-state.json")
}

/// Atomic write of the snapshot to `path`. Mode 0600 on Unix.
pub fn write_state_file(path: &Path, snap: &SweeperSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string(snap)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let pid = std::process::id();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.tmp.{pid}.{n}"));

    if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Read the snapshot from `path`. Returns `None` if the file is missing
/// or unparseable — the doctor surfaces "no recent sweep" via empty
/// fields rather than failing.
pub fn read_state_file(path: &Path) -> Option<SweeperSnapshot> {
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

/// One tick. Public so tests + the doctor harness can drive a synchronous
/// sweep without needing to spawn a task.
pub fn run_once(
    roots_seen_path: &Path,
    state: &Arc<Mutex<SweeperState>>,
    budget: Duration,
) -> std::io::Result<()> {
    let started = Instant::now();
    let resume_from = {
        let s = state.lock().expect("sweeper state poisoned");
        s.partial_cursor.unwrap_or(0)
    };

    let entries = read_roots_seen(roots_seen_path)?;
    let mut swept: u64 = 0;
    let mut skipped: u64 = 0;
    let mut idx = resume_from;
    let mut partial = false;

    while idx < entries.len() {
        if started.elapsed() >= budget {
            partial = true;
            break;
        }
        let coc_root = Path::new(&entries[idx].coc_root);
        match sweep_root(coc_root, state) {
            Ok((s, sk)) => {
                swept += s;
                skipped += sk;
            }
            Err(e) => {
                warn!(
                    error_kind = "coc_cache_sweep_root_failed",
                    coc_root = %coc_root.display(),
                    "coc-cache-sweep: root walk error: {e}"
                );
            }
        }
        idx += 1;
    }

    let blocked = {
        let s = state.lock().expect("sweeper state poisoned");
        s.sharing_violation_retries
            .values()
            .filter(|&&v| v >= SHARING_VIOLATION_RETRY_LIMIT)
            .count() as u64
    };

    let now_iso = current_iso8601_utc();
    let duration = started.elapsed();
    let cursor_after = if partial { Some(idx) } else { None };

    {
        let mut s = state.lock().expect("sweeper state poisoned");
        s.partial_cursor = cursor_after;
        s.snapshot = SweeperSnapshot {
            last_sweep_at: Some(now_iso),
            last_sweep_duration_ms: duration.as_millis() as u64,
            sweep_partial: partial,
            sweep_lag_minutes: 0,
            files_swept_last_run: swept,
            files_skipped_last_run: skipped,
            cache_sweep_blocked: blocked,
        };
    }

    if partial {
        info!(
            event = "coc_cache_sweep_partial",
            cursor = idx,
            files_swept = swept,
            "coc-cache-sweep: 30s budget exceeded; resuming next tick"
        );
    } else {
        debug!(
            event = "coc_cache_sweep_complete",
            files_swept = swept,
            files_skipped = skipped,
            duration_ms = duration.as_millis() as u64,
            "coc-cache-sweep: tick complete"
        );
    }

    Ok(())
}

/// Returns true if `s` matches `parsed-<64-hex-chars>.bin` exactly. Used
/// by the sweeper to filter `.cache/` walks per R2/B72 — tmp files with
/// suffix `.bin.tmp.<pid>.<counter>` MUST NOT match.
pub fn is_parsed_cache_filename(s: &str) -> bool {
    // Shape: "parsed-" (7) + 64 hex chars + ".bin" = 75 chars exactly.
    if s.len() != 75 {
        return false;
    }
    if !s.starts_with("parsed-") {
        return false;
    }
    if !s.ends_with(".bin") {
        return false;
    }
    s[7..71].bytes().all(|b| b.is_ascii_hexdigit())
}

fn sweep_root(coc_root: &Path, state: &Arc<Mutex<SweeperState>>) -> std::io::Result<(u64, u64)> {
    let cache_dir = coc_root.join(".cache");
    if !cache_dir.exists() {
        return Ok((0, 0));
    }
    if !coc_root.is_dir() {
        // Root no longer exists; clear sharing-violation entries that point at it.
        let mut s = state.lock().expect("sweeper state poisoned");
        s.sharing_violation_retries
            .retain(|p, _| !p.starts_with(coc_root));
        return Ok((0, 0));
    }

    let current_lock_sha = current_lock_sha_for_root(coc_root);
    let now = SystemTime::now();
    let mut swept: u64 = 0;
    let mut skipped: u64 = 0;

    let read_dir = match std::fs::read_dir(&cache_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!("coc-cache-sweep: read_dir entry error: {e}");
                skipped += 1;
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            skipped += 1;
            continue;
        };
        if !is_parsed_cache_filename(name_str) {
            // tmp files, foreign files, anything else — leave alone.
            skipped += 1;
            continue;
        }

        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %path.display(), "coc-cache-sweep: metadata error: {e}");
                skipped += 1;
                continue;
            }
        };
        let mtime = meta.modified().unwrap_or(now);
        let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);

        let filename_sha = parse_filename_sha(name_str);

        // Reasons to delete:
        //   - mtime older than 30 days, OR
        //   - filename's lock_sha does not match the current root's lock.
        let mut reason: Option<&'static str> = None;
        if age > MAX_AGE {
            reason = Some("mtime_30d");
        } else if let Some(current) = current_lock_sha {
            if filename_sha.is_some_and(|f| f != current) {
                reason = Some("stale_lock_sha");
            }
        }

        if let Some(r) = reason {
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    info!(
                        event = "coc_cache_sweep_deleted",
                        path = %path.display(),
                        reason = r,
                        "coc-cache-sweep: deleted"
                    );
                    swept += 1;
                    let mut s = state.lock().expect("sweeper state poisoned");
                    s.sharing_violation_retries.remove(&path);
                }
                Err(e) => {
                    if is_sharing_violation(&e) {
                        // Windows: log INFO + retry next tick (R2/B71).
                        let mut s = state.lock().expect("sweeper state poisoned");
                        let count = s.sharing_violation_retries.entry(path.clone()).or_insert(0);
                        *count = count.saturating_add(1);
                        info!(
                            event = "coc_cache_sweep_blocked",
                            path = %path.display(),
                            retries = *count,
                            "coc-cache-sweep: sharing violation; retry next tick"
                        );
                    } else {
                        warn!(
                            event = "coc_cache_sweep_delete_failed",
                            path = %path.display(),
                            "coc-cache-sweep: delete failed: {e}"
                        );
                    }
                    skipped += 1;
                }
            }
        } else {
            skipped += 1;
        }
    }

    Ok((swept, skipped))
}

fn current_lock_sha_for_root(coc_root: &Path) -> Option<[u8; 32]> {
    let coc_dir = coc_root.join(".coc");
    match read_lock(&coc_dir) {
        Ok(Some(lock_bytes)) => Some(lock_sha256(&lock_bytes)),
        _ => None,
    }
}

fn parse_filename_sha(s: &str) -> Option<[u8; 32]> {
    if !is_parsed_cache_filename(s) {
        return None;
    }
    let hex = &s[7..71];
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}

#[cfg(windows)]
fn is_sharing_violation(e: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION = 32
    e.raw_os_error() == Some(32)
}

#[cfg(not(windows))]
fn is_sharing_violation(_e: &std::io::Error) -> bool {
    false
}

/// Append `coc_root` to the roots-seen FIFO at `path`. Maintains the
/// 256-line cap by dropping the oldest entry when the cap is reached.
/// Atomic write per `security.md` §5: temp file → secure_file (mode 0600)
/// → atomic_replace, with cleanup-on-error per §5a.
///
/// Best-effort — `csq run` should call this opportunistically after
/// resolving its `.coc/` root. Failures are logged but never propagated.
pub fn append_root_seen(path: &Path, coc_root: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut entries = read_roots_seen(path).unwrap_or_default();
    let coc_root_str = coc_root.to_string_lossy().to_string();
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Update existing entry's last_seen if root already present.
    if let Some(existing) = entries.iter_mut().find(|e| e.coc_root == coc_root_str) {
        existing.last_seen = now_secs;
    } else {
        entries.push(RootEntry {
            coc_root: coc_root_str,
            last_seen: now_secs,
        });
    }

    // FIFO cap — drop oldest by last_seen until we're under the cap.
    if entries.len() > ROOTS_SEEN_CAP {
        entries.sort_by_key(|e| e.last_seen);
        let drop_n = entries.len() - ROOTS_SEEN_CAP;
        entries.drain(0..drop_n);
    }

    let mut buf = String::new();
    for entry in &entries {
        let line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        buf.push_str(&line);
        buf.push('\n');
    }

    let pid = std::process::id();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("jsonl.tmp.{pid}.{n}"));

    if let Err(e) = std::fs::write(&tmp, buf.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    Ok(())
}

/// Read the FIFO at `path`. Lines that fail to parse as `RootEntry` are
/// skipped with a debug log and counted as `skipped` in the next tick.
pub fn read_roots_seen(path: &Path) -> std::io::Result<Vec<RootEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<RootEntry>(line) {
            Ok(entry) => out.push(entry),
            Err(e) => {
                debug!(
                    error_kind = "coc_roots_seen_parse",
                    "coc-roots-seen: skipping malformed line: {e}"
                );
            }
        }
    }
    Ok(out)
}

fn current_iso8601_utc() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = now.as_secs() as i64;
    // Minimal ISO-8601 formatter — stdlib only. `chrono` is not in csq-core's
    // dep graph and pulling it in for one timestamp is over-rotation.
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn unix_to_ymdhms(mut t: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Civil-time conversion adapted from the public-domain "civil_from_days"
    // algorithm (Howard Hinnant). Stdlib-only.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build an empty `.coc/` directory tree with a COC.lock at the
    /// requested digest. Returns the coc_root absolute path.
    fn fresh_root(tmp: &TempDir, name: &str, lock_bytes: &[u8]) -> PathBuf {
        let root = tmp.path().join(name);
        let coc = root.join(".coc");
        std::fs::create_dir_all(&coc).unwrap();
        std::fs::write(coc.join("COC.lock"), lock_bytes).unwrap();
        std::fs::create_dir_all(root.join(".cache")).unwrap();
        root
    }

    fn write_cache_file_simple(root: &Path, lock_sha: &[u8; 32]) -> PathBuf {
        let hex: String = lock_sha.iter().map(|b| format!("{:02x}", b)).collect();
        let path = root.join(".cache").join(format!("parsed-{hex}.bin"));
        std::fs::write(&path, b"stub-cache-payload").unwrap();
        path
    }

    /// Test helper: write a `coc-roots-seen.jsonl` from a slice of roots,
    /// using the same `serde_json` serialization as production
    /// `append_root_seen` so paths with backslashes (Windows) are
    /// properly escaped instead of producing malformed JSON.
    fn write_roots_seen_jsonl(path: &Path, roots: &[&Path]) {
        let mut body = String::new();
        for root in roots {
            let entry = RootEntry {
                coc_root: root.to_string_lossy().to_string(),
                last_seen: 0,
            };
            body.push_str(&serde_json::to_string(&entry).unwrap());
            body.push('\n');
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn is_parsed_cache_filename_matches_canonical_shape() {
        let valid = format!("parsed-{}.bin", "ab".repeat(32));
        assert!(is_parsed_cache_filename(&valid));
    }

    #[test]
    fn is_parsed_cache_filename_rejects_tmp_suffix() {
        // R2/B72 — sweeper MUST NOT match tmp files.
        let tmp = format!("parsed-{}.bin.tmp.12345.7", "ab".repeat(32));
        assert!(!is_parsed_cache_filename(&tmp));
    }

    #[test]
    fn is_parsed_cache_filename_rejects_short_hex() {
        let short = format!("parsed-{}.bin", "ab".repeat(20));
        assert!(!is_parsed_cache_filename(&short));
    }

    #[test]
    fn is_parsed_cache_filename_rejects_non_hex() {
        let bad = format!("parsed-{}.bin", "zz".repeat(32));
        assert!(!is_parsed_cache_filename(&bad));
    }

    #[test]
    fn sweeper_regex_rejects_tmp_files() {
        // Same as above — explicit name from the R4 acceptance bullet.
        let tmp = format!("parsed-{}.bin.tmp.123.4", "cd".repeat(32));
        assert!(!is_parsed_cache_filename(&tmp));
    }

    #[test]
    fn sweeper_deletes_files_with_lock_sha_not_matching_any_current_root() {
        let tmp = TempDir::new().unwrap();
        // Root has lock with digest A. Cache file is named after digest B.
        let root = fresh_root(&tmp, "repo-a", b"lock-A");
        let stale_sha = [0xcdu8; 32]; // not the lock_sha of "lock-A"
        let stale_path = write_cache_file_simple(&root, &stale_sha);

        let roots_jsonl = tmp.path().join("coc-roots-seen.jsonl");
        write_roots_seen_jsonl(&roots_jsonl, &[&root]);

        let state = Arc::new(Mutex::new(SweeperState::default()));
        run_once(&roots_jsonl, &state, Duration::from_secs(30)).unwrap();

        assert!(
            !stale_path.exists(),
            "stale-lock_sha cache file should be deleted"
        );
        let snap = state.lock().unwrap().snapshot();
        assert_eq!(snap.files_swept_last_run, 1);
    }

    #[test]
    fn sweeper_preserves_current_lock_sha_files() {
        let tmp = TempDir::new().unwrap();
        let lock_bytes = b"lock-current";
        let root = fresh_root(&tmp, "repo-b", lock_bytes);
        let current_sha = lock_sha256(lock_bytes);
        let preserved = write_cache_file_simple(&root, &current_sha);

        let roots_jsonl = tmp.path().join("coc-roots-seen.jsonl");
        write_roots_seen_jsonl(&roots_jsonl, &[&root]);

        let state = Arc::new(Mutex::new(SweeperState::default()));
        run_once(&roots_jsonl, &state, Duration::from_secs(30)).unwrap();

        assert!(preserved.exists(), "current-lock_sha file must survive");
        let snap = state.lock().unwrap().snapshot();
        assert_eq!(snap.files_swept_last_run, 0);
    }

    #[test]
    fn sweeper_handles_missing_root_gracefully() {
        let tmp = TempDir::new().unwrap();
        // The roots-seen file points at a non-existent root.
        let roots_jsonl = tmp.path().join("coc-roots-seen.jsonl");
        std::fs::write(
            &roots_jsonl,
            "{\"coc_root\":\"/nonexistent/repo\",\"last_seen\":0}\n",
        )
        .unwrap();

        let state = Arc::new(Mutex::new(SweeperState::default()));
        // No panic, no error.
        run_once(&roots_jsonl, &state, Duration::from_secs(30)).unwrap();
        let snap = state.lock().unwrap().snapshot();
        assert_eq!(snap.files_swept_last_run, 0);
    }

    #[test]
    fn sweeper_treats_empty_roots_seen_as_no_op() {
        let tmp = TempDir::new().unwrap();
        let roots_jsonl = tmp.path().join("coc-roots-seen.jsonl");
        // File doesn't exist at all — first sweep, nothing to walk.
        let state = Arc::new(Mutex::new(SweeperState::default()));
        run_once(&roots_jsonl, &state, Duration::from_secs(30)).unwrap();
        let snap = state.lock().unwrap().snapshot();
        assert_eq!(snap.files_swept_last_run, 0);
        assert!(!snap.sweep_partial);
    }

    #[test]
    fn sweeper_partial_when_zero_budget() {
        let tmp = TempDir::new().unwrap();
        // Two roots — with a zero budget the sweep should record
        // sweep_partial=true and a non-zero cursor.
        let r1 = fresh_root(&tmp, "r1", b"lock-1");
        let r2 = fresh_root(&tmp, "r2", b"lock-2");
        let roots_jsonl = tmp.path().join("coc-roots-seen.jsonl");
        write_roots_seen_jsonl(&roots_jsonl, &[&r1, &r2]);

        let state = Arc::new(Mutex::new(SweeperState::default()));
        run_once(&roots_jsonl, &state, Duration::from_nanos(1)).unwrap();
        let snap = state.lock().unwrap().snapshot();
        assert!(
            snap.sweep_partial,
            "zero budget should record sweep_partial=true"
        );
    }

    #[test]
    fn read_roots_seen_skips_malformed_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("coc-roots-seen.jsonl");
        std::fs::write(
            &path,
            "{\"coc_root\":\"/a\",\"last_seen\":1}\n\
             not-json-at-all\n\
             {\"coc_root\":\"/b\",\"last_seen\":2}\n",
        )
        .unwrap();
        let entries = read_roots_seen(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].coc_root, "/a");
        assert_eq!(entries[1].coc_root, "/b");
    }

    #[test]
    fn parse_filename_sha_round_trips() {
        let sha = [0x01u8; 32];
        let hex: String = sha.iter().map(|b| format!("{:02x}", b)).collect();
        let name = format!("parsed-{hex}.bin");
        let parsed = parse_filename_sha(&name).expect("valid name");
        assert_eq!(parsed, sha);
    }

    #[test]
    fn parse_filename_sha_rejects_invalid_shape() {
        assert!(parse_filename_sha("not-a-cache-file").is_none());
        let tmp = format!("parsed-{}.bin.tmp.1.2", "ab".repeat(32));
        assert!(parse_filename_sha(&tmp).is_none());
    }

    #[test]
    fn roots_seen_fifo_caps_at_256_lines_drops_oldest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("coc-roots-seen.jsonl");
        // Pre-populate with 256 entries with ascending last_seen so we
        // know which one will be dropped.
        let mut buf = String::new();
        for i in 0..ROOTS_SEEN_CAP {
            buf.push_str(&format!("{{\"coc_root\":\"/r{i}\",\"last_seen\":{i}}}\n"));
        }
        std::fs::write(&path, buf).unwrap();
        // Append one more — total 257; oldest (last_seen=0) drops.
        append_root_seen(&path, Path::new("/r-new")).unwrap();
        let entries = read_roots_seen(&path).unwrap();
        assert_eq!(entries.len(), ROOTS_SEEN_CAP);
        // The /r0 entry is gone; /r-new is the latest.
        assert!(!entries.iter().any(|e| e.coc_root == "/r0"));
        assert!(entries.iter().any(|e| e.coc_root == "/r-new"));
    }

    #[test]
    fn roots_seen_fifo_atomic_write_with_secure_file_mode_0600() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("coc-roots-seen.jsonl");
        // Parent dir doesn't exist yet — append should create it.
        append_root_seen(&path, Path::new("/repo-x")).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "roots-seen.jsonl must be mode 0600");
        }
    }

    #[test]
    fn roots_seen_fifo_updates_last_seen_on_repeat() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("coc-roots-seen.jsonl");
        append_root_seen(&path, Path::new("/repo-y")).unwrap();
        // Sleep one second so the timestamp delta is observable.
        std::thread::sleep(Duration::from_secs(1));
        append_root_seen(&path, Path::new("/repo-y")).unwrap();
        let entries = read_roots_seen(&path).unwrap();
        // Still one entry — the second call updated last_seen rather
        // than appending a duplicate.
        assert_eq!(entries.len(), 1);
        assert!(entries[0].last_seen > 0);
    }
}
