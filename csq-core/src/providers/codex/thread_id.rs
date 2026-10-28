//! Exact thread-id discovery for a running `codex` process.
//!
//! A codex process may hold more than one thread open at once (observed
//! live: a single `codex` process held four distinct
//! `<uuid>.lock` writer locks and four matching `rollout-*.jsonl` files
//! open simultaneously — one process, several concurrently-active
//! threads, e.g. sub-agent spawns). Among SEVERAL candidates a process
//! holds, [`discover_thread_id`] picks the one whose rollout file was
//! modified most recently — but ONLY when that pick is unambiguous: the
//! winner's mtime must beat the runner-up's by more than
//! `MARGIN_SECS`, and the winner's own age must fall within
//! `RECENCY_WINDOW_SECS` of now. Any other shape (a tie inside the
//! margin, or the least-stale candidate still too old to be "moments
//! ago") returns [`ThreadDiscovery::Ambiguous`] rather than guess. A SINGLE exact (lock,
//! rollout) match has no rival to disambiguate against and is returned
//! regardless of its own age (decision: C-F13).
//!
//! A process holding exactly ONE lock and NO rollout (a session with no turn yet) resolves to
//! that lock's id: the lock fd is in the live pid's own table. Several
//! locks and no rollout are ambiguous. Only an observed snapshot with no relevant
//! held lock is [`ThreadDiscovery::NoEvidence`]; unavailable snapshots are ambiguous.
//!
//! # Measured on-disk shape (macOS, 2026-09-26)
//!
//! - `locks_dir` entries are named `<uuid>.lock` — the bare thread id
//!   (a UUIDv7-shaped string) is the file stem, nothing else is
//!   embedded (no pid, no timestamp).
//! - `sessions_dir` entries are rollout files named
//!   `rollout-<RFC3339-ish timestamp with `:` replaced by `-`>-<uuid>.jsonl`
//!   under a `YYYY/MM/DD/` subtree. The trailing 36 characters before
//!   `.jsonl` are the same uuid that names the matching lock file, and
//!   that uuid matches the codex sqlite `threads.id` column verbatim
//!   (verified against a copied `state_*.sqlite`, ids-only, no content
//!   read).
//! - No environment variable identifies the active thread to a codex
//!   child process (`strings` scan of the installed `codex` binary for
//!   `*THREAD*` and `CODEX_*`-shaped identifiers found none).
//!
//! The exact signal this module uses to MATCH a candidate: a thread id
//! is a candidate only when the process holds BOTH the matching
//! `<uuid>.lock` file AND a rollout file whose name ends in
//! `-<uuid>.jsonl` open at the same time. Holding only one of the two
//! (a lock with no matching open rollout, or vice versa) does not
//! count — that pairing is exactly what distinguishes a genuinely
//! active writer from a stale or orphaned lock file. Once matched,
//! candidates are ranked by their rollout file's mtime — read via
//! `stat`/`fs::metadata` only, never by opening or reading the file's
//! content — per `pick_winner_by_recency`.
//!
//! # Measured mtime spread (live pid, 8 snapshots over ~70s, 2026-09-26)
//!
//! This pid ran FOUR concurrently-active threads (a busy multi-agent
//! session, not the single-thread-typing case this exists to serve),
//! so every snapshot is a genuine ambiguity case and `None` was the
//! correct answer throughout. The winner-vs-runner-up gap observed
//! across the 8 snapshots: 0s, 0s, 1s, 1s, 2s, 2s, 4s, 5s (max 5s —
//! this is the noise floor `MARGIN_SECS` must exceed). The winner's
//! own age (how long ago its rollout was touched) was never more than
//! 4s across the same snapshots (aside from one `-1s` reading — clock
//! skew between the `date` and `stat` calls, clamped to 0 by
//! `pick_winner_by_recency`); a lock+rollout pair that had gone quiet
//! showed ages of 11s, 12s, 15s, 18s, 22s in the same snapshots — this
//! is the floor `RECENCY_WINDOW_SECS` must stay under.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Wall-clock budget for the `lsof` / `/proc` fd enumeration. Mirrors
/// the pattern in `cli_deps::probe::run_probe` (spawn + background
/// reader thread + `mpsc::recv_timeout`, kill on timeout) rather than
/// blocking indefinitely on a wedged subprocess.
const FD_ENUM_TIMEOUT: Duration = Duration::from_secs(5);

/// Margin (seconds) the winner's mtime must beat the runner-up's by,
/// before the pick counts as unambiguous.
///
/// **Outcome it separates:** below the margin, two rollout files were
/// BOTH part of a genuinely concurrent multi-thread session and
/// neither is "the" active one (reject, return `None`); at or above
/// it, one candidate stands out and the rest are stale by comparison
/// (accept it as the winner).
///
/// **Derivation:** measured live against pid 50534 (8 snapshots, ~70s,
/// 2026-09-26) — the winner-vs-runner-up gap in a genuinely-ambiguous
/// 4-active-thread session was 0, 0, 1, 1, 2, 2, 4, and 5 seconds; 5s
/// is the largest gap observed between two threads that were BOTH
/// still actively being written. `MARGIN_SECS = 8` leaves 3s of
/// headroom above that noise floor. The real single-active-thread
/// scenario this exists to detect (every other thread on the pid
/// untouched for minutes, not seconds) clears an 8s gap trivially, so
/// the margin costs that case nothing.
const MARGIN_SECS: u64 = 8;

/// Recency window (seconds): the winner's own age (`now - mtime`) must
/// fall within this to count as "written moments ago", rather than
/// merely being the least-stale member of an otherwise-idle set.
///
/// Applied ONLY when disambiguating among SEVERAL candidates — a single
/// exact (lock, rollout) match has no rival to compare against and wins
/// regardless of age (decision: C-F13; see [`pick_winner_by_recency`]).
///
/// **Outcome it separates:** at or under the window, the winner was
/// genuinely touched moments ago (accept); over it, the winner is
/// merely the freshest of a set that is not currently being written to
/// (reject, return `None` — a sole surviving lock file can be an
/// orphaned one left by a session that never released it, not
/// evidence of "right now").
///
/// **Derivation:** same 8 snapshots — ages that were part of an active
/// exchange were never more than 4s (aside from one `-1s` clock-skew
/// reading, clamped to 0); a lock+rollout pair that had gone quiet
/// showed ages of 11s, 12s, 15s, 18s, 22s in the same snapshots.
/// `RECENCY_WINDOW_SECS = 10` leaves 6s of headroom under the largest
/// observed genuinely-active age (4s) and 1s of headroom under the
/// smallest observed genuinely-idle age (11s).
const RECENCY_WINDOW_SECS: u64 = 10;

/// Read-only discovery from a live process's open file paths and rollout mtimes.
/// No rollout content is opened or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadDiscovery {
    /// The held-file evidence identifies one thread unambiguously.
    Found(String),
    /// Held thread evidence cannot identify the active thread safely, or the fd
    /// snapshot could not be read. Both cases prohibit guessing under uncertainty.
    /// Callers must not fall back to a previously captured or launch-time thread.
    Ambiguous,
    /// An observed fd snapshot contained no relevant held thread locks.
    NoEvidence,
}

/// Discovers a thread using only the target process's fd paths and file metadata.
/// Unlike [`discover_thread_id`], this preserves ambiguity so callers can prohibit
/// a stale-thread fallback. Directory arguments have the same canonicalization
/// requirements as [`discover_thread_id`].
pub fn discover_thread_id_outcome(
    codex_pid: u32,
    sessions_dir: &Path,
    locks_dir: &Path,
) -> ThreadDiscovery {
    let open_paths = imp::open_file_paths(codex_pid, FD_ENUM_TIMEOUT);
    discover_outcome_from_snapshot(open_paths.as_deref(), sessions_dir, locks_dir)
}

fn discover_outcome_from_snapshot(
    open_paths: Option<&[PathBuf]>,
    sessions_dir: &Path,
    locks_dir: &Path,
) -> ThreadDiscovery {
    match open_paths {
        Some(paths) => discover_outcome_from_paths(paths, sessions_dir, locks_dir),
        None => ThreadDiscovery::Ambiguous,
    }
}

fn discover_outcome_from_paths(
    open_paths: &[PathBuf],
    sessions_dir: &Path,
    locks_dir: &Path,
) -> ThreadDiscovery {
    discover_outcome_from_paths_with(
        open_paths,
        sessions_dir,
        locks_dir,
        SystemTime::now(),
        |path| std::fs::metadata(path).ok()?.modified().ok(),
    )
}

/// Returns the thread id the codex process `codex_pid` is currently
/// writing, or `None` when it cannot be determined EXACTLY.
///
/// `sessions_dir` is the shared codex sessions dir (the resolved target
/// of `<CODEX_HOME>/sessions`); `locks_dir` is the resolved
/// `<CODEX_HOME>/thread-writer-locks`. Both MUST be canonicalized by
/// the caller (or already absolute, symlink-resolved paths) — this
/// function does not itself resolve symlinks in the *directories*, only
/// in the fd paths it reads back from the OS, so a caller passing a
/// symlinked `sessions_dir` would silently fail to match every rollout
/// path (fail-closed: that reads as "no candidates", never a false
/// positive).
pub fn discover_thread_id(codex_pid: u32, sessions_dir: &Path, locks_dir: &Path) -> Option<String> {
    match discover_thread_id_outcome(codex_pid, sessions_dir, locks_dir) {
        ThreadDiscovery::Found(id) => Some(id),
        ThreadDiscovery::Ambiguous | ThreadDiscovery::NoEvidence => None,
    }
}

/// [`discover_thread_id`] over an already-read fd path list (the fixture tests call this).
#[cfg(test)]
fn discover_from_paths(
    open_paths: &[PathBuf],
    sessions_dir: &Path,
    locks_dir: &Path,
) -> Option<String> {
    match discover_outcome_from_paths(open_paths, sessions_dir, locks_dir) {
        ThreadDiscovery::Found(id) => Some(id),
        ThreadDiscovery::Ambiguous | ThreadDiscovery::NoEvidence => None,
    }
}

fn discover_outcome_from_paths_with(
    open_paths: &[PathBuf],
    sessions_dir: &Path,
    locks_dir: &Path,
    now: SystemTime,
    mut modified: impl FnMut(&Path) -> Option<SystemTime>,
) -> ThreadDiscovery {
    let candidates = matched_candidates(open_paths, sessions_dir, locks_dir);
    // A held lock with NO open rollout beside a (lock, rollout) pair is a thread that has not
    // taken a turn yet. MEASURED 2026-10-06 (codex-cli 0.160.1, `/new` with no further turn):
    // the abandoned thread kept its lock AND rollout fds open and the new thread's lock was
    // taken without a rollout, so the pair names the OLD thread. Ambiguous: fail closed.
    let held = held_lock_ids_in(open_paths, locks_dir);
    if held.is_empty() {
        return ThreadDiscovery::NoEvidence;
    }
    if !candidates.is_empty()
        && held
            .iter()
            .any(|id| !candidates.iter().any(|(c, _)| c == id))
    {
        return ThreadDiscovery::Ambiguous;
    }
    if candidates.is_empty() {
        // No (lock, rollout) pair: a session with no turn yet, or one that closed its rollout
        // while idle. A lock fd held open by THIS live pid is still exact evidence of its
        // current thread when it is the only one held.
        return if held.len() == 1 {
            match held.into_iter().next() {
                Some(id) => ThreadDiscovery::Found(id),
                None => ThreadDiscovery::NoEvidence,
            }
        } else {
            ThreadDiscovery::Ambiguous
        };
    }
    // Read-only: `fs::metadata` is a stat call, never an open/read of
    // the rollout file's content (per the task's read-only mandate).
    // Missing metadata leaves held evidence unresolved. Dropping such a rival
    // would incorrectly promote the remaining pair to an unambiguous singleton.
    let with_mtime: Option<Vec<(String, SystemTime)>> = candidates
        .into_iter()
        .map(|(id, path)| modified(&path).map(|mtime| (id, mtime)))
        .collect();
    match with_mtime.and_then(|pairs| pick_winner_by_recency(&pairs, now)) {
        Some(id) => ThreadDiscovery::Found(id),
        None => ThreadDiscovery::Ambiguous,
    }
}

/// Pure decision core, independent of how `open_paths` was obtained —
/// this is what the fixture-driven tests exercise directly, so the
/// matching logic is tested without spawning `lsof`/reading `/proc`.
/// Returns every uuid the process holds BOTH a lock and a rollout file
/// open for, paired with that rollout file's path (mtime is read by
/// the caller, kept out of this function so it stays a pure path
/// classifier).
fn matched_candidates(
    open_paths: &[PathBuf],
    sessions_dir: &Path,
    locks_dir: &Path,
) -> Vec<(String, PathBuf)> {
    let mut lock_ids: HashSet<String> = HashSet::new();
    let mut rollout_paths: HashMap<String, PathBuf> = HashMap::new();

    for path in open_paths {
        if let Some(parent) = path.parent() {
            if parent == locks_dir {
                if let Some(id) = lock_thread_id(path) {
                    lock_ids.insert(id);
                }
                continue;
            }
        }
        if path.starts_with(sessions_dir) {
            if let Some(id) = rollout_thread_id(path) {
                rollout_paths.insert(id, path.clone());
            }
        }
    }

    let mut candidates: Vec<(String, PathBuf)> = lock_ids
        .into_iter()
        .filter_map(|id| rollout_paths.get(&id).cloned().map(|path| (id, path)))
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates
}

/// Picks the unambiguous winner from a set of (thread id, rollout
/// mtime) pairs, or `None`. Pure and injectable — `now` and every
/// `mtime` are caller-supplied, so tests exercise this without
/// touching the filesystem or the clock.
///
/// A SINGLE exact (lock, rollout) match wins unconditionally, regardless
/// of its own age (decision: C-F13) — there is no rival for the recency
/// window or the margin to disambiguate against, and `matched_candidates`
/// already requires BOTH the lock and the rollout to be open at the same
/// time, so a lone candidate is the process's one currently-held thread,
/// not merely the freshest member of an otherwise-idle set. The recency
/// window (`RECENCY_WINDOW_SECS`) and the margin (`MARGIN_SECS`) apply
/// ONLY when choosing AMONG SEVERAL candidates.
fn pick_winner_by_recency(candidates: &[(String, SystemTime)], now: SystemTime) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates[0].0.clone());
    }

    let mut aged: Vec<(&str, u64)> = candidates
        .iter()
        .map(|(id, mtime)| {
            let age = now
                .duration_since(*mtime)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            (id.as_str(), age)
        })
        .collect();
    aged.sort_by_key(|&(_, age)| age);

    let (winner_id, winner_age) = aged[0];
    if winner_age > RECENCY_WINDOW_SECS {
        return None;
    }
    // `aged.len() >= 2` here (the len()==1 case returned above), so
    // `aged[1]` is always present.
    let (_, runner_up_age) = aged[1];
    // `aged` is sorted ascending, so runner_up_age >= winner_age —
    // the subtraction cannot underflow.
    if runner_up_age - winner_age <= MARGIN_SECS {
        return None;
    }
    Some(winner_id.to_string())
}

/// Extracts the thread id from a `<uuid>.lock` path, or `None` if the
/// file stem is not a UUID.
fn lock_thread_id(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    let ext = path.extension()?.to_str()?;
    if ext != "lock" {
        return None;
    }
    is_uuid(stem).then(|| stem.to_string())
}

/// Extracts the trailing UUID from a `rollout-...-<uuid>.jsonl` path,
/// or `None` if the filename does not match that exact shape.
fn rollout_thread_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stripped = name.strip_prefix("rollout-")?;
    let stripped = stripped.strip_suffix(".jsonl")?;
    // The uuid is exactly the trailing 36 characters ("xxxxxxxx-xxxx-
    // xxxx-xxxx-xxxxxxxxxxxx"), preceded by a `-` that joins it to the
    // timestamp segment.
    if stripped.len() < 37 {
        return None;
    }
    let split_at = stripped.len() - 36;
    if stripped.as_bytes()[split_at - 1] != b'-' {
        return None;
    }
    let candidate = &stripped[split_at..];
    is_uuid(candidate).then(|| candidate.to_string())
}

/// Validates the canonical UUID shape (`8-4-4-4-12` hex groups). Does
/// NOT validate the version/variant nibbles — any RFC 4122-shaped
/// string is accepted, since codex's ids have been observed as UUIDv7
/// but nothing in this module depends on that specific version.
fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let expect_dash = matches!(i, 8 | 13 | 18 | 23);
        if expect_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Role recorded by Codex itself; mtime and lock age cannot establish this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadRole {
    Main,
    Subagent,
    Unknown,
}

/// Cooperative SQLite execution budget. SQLite interruption is observed at VM
/// checkpoints; filesystem calls, scheduling and a single native function are not
/// a hard wall-clock bound. The owned watchdog is cancelled and joined on all exits.
struct RoleReadBudget {
    deadline: std::time::Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancel: Option<std::sync::mpsc::Sender<BudgetSignal>>,
    timer: Option<std::thread::JoinHandle<()>>,
}
/// Control message for the budget watchdog: end it quietly, or (test probe only)
/// spend the budget now without consulting the wall clock.
enum BudgetSignal {
    Cancel,
    // The probe is constructed only by the `capture_tests` module below, which
    // is `cfg(all(test, unix))`. Under a bare `cfg(test)` the variant is dead
    // code on every other platform as soon as that module is compiled out —
    // mingw clippy with `-D warnings` reds on it (`thread_id.rs:415`,
    // windows-cfg cross-lint, 2026-10-22). The probe carries its user's gate.
    #[cfg(all(test, unix))]
    Expire,
}
impl RoleReadBudget {
    fn start(db: &rusqlite::Connection, deadline: std::time::Instant) -> Option<Self> {
        let expired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = expired.clone();
        let interrupt = db.get_interrupt_handle();
        let (cancel, wait) = std::sync::mpsc::channel();
        let timer = std::thread::Builder::new()
            .name("csq-thread-role-budget".into())
            .spawn(move || {
                if match wait
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => true,
                    #[cfg(all(test, unix))]
                    Ok(BudgetSignal::Expire) => true,
                    _ => false,
                } {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    // An idle sqlite3_interrupt does not affect a later sqlite3_step.
                    // Repeat until cancellation so the precheck/step gap is covered.
                    loop {
                        interrupt.interrupt();
                        match wait.recv_timeout(Duration::from_millis(1)) {
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            #[cfg(all(test, unix))]
                            Ok(BudgetSignal::Expire) => {}
                            _ => break,
                        }
                    }
                }
            })
            .ok()?;
        Some(Self {
            deadline,
            expired,
            cancel: Some(cancel),
            timer: Some(timer),
        })
    }
    /// Test probe: spend the budget now and block until the watchdog has raised the
    /// expiry flag. The interrupt itself is then issued and repeated every 1ms by the
    /// watchdog, so the next SQLite step is interrupted because that repeat is far
    /// shorter than the test's 1M-row unindexed scan (a timing margin, not a guarantee).
    /// Gated like its only caller (`capture_tests`, unix) so the mingw lint sees no
    /// dead method where that module is compiled out.
    #[cfg(all(test, unix))]
    fn expire_now(&self) {
        if let Some(tx) = &self.cancel {
            let _ = tx.send(BudgetSignal::Expire);
        }
        while !self.expired.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
    fn elapsed(&self) -> bool {
        self.expired.load(std::sync::atomic::Ordering::SeqCst)
            || std::time::Instant::now() >= self.deadline
    }
}
impl Drop for RoleReadBudget {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(BudgetSignal::Cancel);
        }
        if let Some(timer) = self.timer.take() {
            let _ = timer.join();
        }
    }
}

fn role_from_native_source(source: &str) -> ThreadRole {
    if source == "cli" {
        return ThreadRole::Main;
    }
    let value = serde_json::from_str::<serde_json::Value>(source).ok();
    let spawn = value
        .as_ref()
        .and_then(|v| v.get("subagent"))
        .and_then(|v| v.get("thread_spawn"))
        .and_then(serde_json::Value::as_object);
    if spawn.is_some_and(|s| {
        s.get("parent_thread_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(is_uuid)
            && s.get("depth")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|depth| depth > 0)
    }) {
        ThreadRole::Subagent
    } else {
        ThreadRole::Unknown
    }
}

/// Read only `threads.id/source` from the newest native state database. Missing,
/// unsupported or unreadable metadata is unknown, never evidence of a main thread.
pub fn read_thread_roles(
    sqlite_home: &Path,
    held: &HashSet<String>,
) -> Option<HashMap<String, ThreadRole>> {
    read_thread_roles_with_budget(sqlite_home, held, Duration::from_millis(250))
}

fn read_thread_roles_with_budget(
    sqlite_home: &Path,
    held: &HashSet<String>,
    duration: Duration,
) -> Option<HashMap<String, ThreadRole>> {
    read_thread_roles_with_probe(sqlite_home, held, duration, &|_| {}, &|| {})
}

fn role_query_source(
    stmt: &mut rusqlite::Statement<'_>,
    id: &str,
    budget: &RoleReadBudget,
    before: &dyn Fn(&RoleReadBudget),
    interrupted: &dyn Fn(),
) -> rusqlite::Result<String> {
    before(budget);
    let result = stmt.query_row([id], |r| r.get::<_, String>(0));
    if matches!(&result, Err(rusqlite::Error::SqliteFailure(error,_)) if error.code == rusqlite::ErrorCode::OperationInterrupted)
    {
        interrupted();
    }
    result
}

fn read_thread_roles_with_probe(
    sqlite_home: &Path,
    held: &HashSet<String>,
    duration: Duration,
    before: &dyn Fn(&RoleReadBudget),
    interrupted: &dyn Fn(),
) -> Option<HashMap<String, ThreadRole>> {
    let deadline = std::time::Instant::now() + duration;
    use rusqlite::{Connection, OpenFlags};
    let mut databases = Vec::new();
    for (index, entry) in std::fs::read_dir(sqlite_home).ok()?.take(4097).enumerate() {
        if index == 4096 {
            return None;
        }
        let path = entry.ok()?.path();
        let name = path.file_name()?.to_str()?;
        if let Some(version) = name
            .strip_prefix("state_")
            .and_then(|s| s.strip_suffix(".sqlite"))
            .and_then(|s| s.parse::<u32>().ok())
        {
            databases.push((version, path));
        }
    }
    let (_, path) = databases.into_iter().max_by_key(|(v, _)| *v)?;
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    if std::time::Instant::now() >= deadline {
        return None;
    }
    let budget = RoleReadBudget::start(&db, deadline)?;
    db.busy_timeout(Duration::from_millis(100)).ok()?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN DEFERRED;")
        .ok()?;
    let definition: String = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='threads' AND type='table'",
            [],
            |r| r.get(0),
        )
        .ok()?;
    if !definition
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE TABLE")
        || held.len() > 256
    {
        return None;
    }
    let mut stmt = db
        .prepare("SELECT source FROM threads WHERE id=?1 AND length(source)<=4096 LIMIT 1")
        .ok()?;
    let mut roles = HashMap::new();
    for id in held {
        if budget.elapsed() {
            return None;
        }
        let role = match role_query_source(&mut stmt, id, &budget, before, interrupted) {
            Ok(source) => role_from_native_source(&source),
            Err(rusqlite::Error::QueryReturnedNoRows) => ThreadRole::Unknown,
            Err(_) => return None,
        };
        roles.insert(id.clone(), role);
    }
    if budget.elapsed() {
        return None;
    }
    Some(roles)
}

/// Require one native CLI main and only proven child rivals. A held explicit resume
/// identity must name that main, never a child or a stale different top-level thread.
/// Several top-level threads (including `/new`) and unknown roles remain ambiguous.
pub fn select_main_thread(
    held: Option<&HashSet<String>>,
    from_launch: Option<&str>,
    roles: Option<&HashMap<String, ThreadRole>>,
) -> ThreadDiscovery {
    let Some(held) = held else {
        return ThreadDiscovery::Ambiguous;
    };
    if held.is_empty() {
        return ThreadDiscovery::NoEvidence;
    }
    let Some(roles) = roles else {
        return ThreadDiscovery::Ambiguous;
    };
    let mut main = None;
    for id in held {
        match roles.get(id) {
            Some(ThreadRole::Main) if main.is_none() => main = Some(id.clone()),
            Some(ThreadRole::Subagent) => {}
            _ => return ThreadDiscovery::Ambiguous,
        }
    }
    if let Some(id) = from_launch {
        if !held.contains(id) || main.as_deref() != Some(id) {
            return ThreadDiscovery::Ambiguous;
        }
    }
    main.map_or(ThreadDiscovery::Ambiguous, ThreadDiscovery::Found)
}

/// Capture the top-level thread, including a resumed rollout that predates this launch.
/// Native process-tree boundaries prevent a tool's foreign session from contributing locks.
pub fn capture_main_thread_id(
    root_pid: u32,
    locks_dir: &Path,
    sqlite_home: &Path,
    from_launch: Option<&str>,
) -> Option<String> {
    let rows = process_table()?;
    capture_main_thread_with(
        &|| capture_tree(&rows, root_pid),
        locks_dir,
        sqlite_home,
        from_launch,
        &|pid| imp::open_file_paths(pid, FD_ENUM_TIMEOUT),
    )
}

/// Injectable production capture core: all held locks participate, not only newly-created rollouts.
pub fn capture_main_thread_with(
    tree: &dyn Fn() -> Vec<u32>,
    locks_dir: &Path,
    sqlite_home: &Path,
    from_launch: Option<&str>,
    open_paths: &dyn Fn(u32) -> Option<Vec<PathBuf>>,
) -> Option<String> {
    let mut held = HashSet::new();
    for pid in tree() {
        held.extend(held_lock_ids_in(&open_paths(pid)?, locks_dir));
    }
    let roles = read_thread_roles(sqlite_home, &held);
    match select_main_thread(Some(&held), from_launch, roles.as_ref()) {
        ThreadDiscovery::Found(id) => Some(id),
        _ => None,
    }
}

// ── Launch-time capture (spec 32 §5.1 step 3, MODELLED §9.6) ────────

/// File beside a handle dir's `.live-pid` that records the thread id the supervisor captured.
///
/// The `.csq` prefix is load-bearing: `share_audit::is_expected_per_terminal` treats every
/// `.csq*` entry as csq's own per-handle bookkeeping, so a captured id is not reported as
/// unshared state in every handle dir.
pub const CAPTURED_THREAD_FILE: &str = ".csq-thread-id";

/// Deepest directory level under `sessions_dir` that is scanned: `YYYY/MM/DD`.
const SESSIONS_DEPTH: usize = 3;

/// Every thread id that has a `rollout-*-<uuid>.jsonl` under `sessions_dir` (`YYYY/MM/DD/`).
/// Entries are inspected with `symlink_metadata` and symlinks are never followed, so a link
/// planted in the tree cannot widen the scan. `None` when the root cannot be read.
#[must_use]
pub fn list_rollout_ids(sessions_dir: &Path) -> Option<HashSet<String>> {
    fn walk(dir: &Path, depth: usize, out: &mut HashSet<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if md.file_type().is_dir() {
                if depth < SESSIONS_DEPTH {
                    walk(&path, depth + 1, out);
                }
            } else if md.file_type().is_file() {
                if let Some(id) = rollout_thread_id(&path) {
                    out.insert(id);
                }
            }
        }
    }
    std::fs::read_dir(sessions_dir).ok()?;
    let mut out = HashSet::new();
    walk(sessions_dir, 0, &mut out);
    Some(out)
}

/// Record `id` beside the handle dir's `.live-pid`. The tmp file is renamed over the target, and
/// nothing is created when the handle dir is gone (a vanished dir is `Err`, not re-created).
pub fn write_captured_thread_id(handle_dir: &Path, id: &str) -> std::io::Result<()> {
    if !is_uuid(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a thread id",
        ));
    }
    let tmp = handle_dir.join(format!("{CAPTURED_THREAD_FILE}.tmp-{}", std::process::id()));
    // A leftover from a crashed writer with a recycled pid is removed first; `remove_file`
    // unlinks a planted symlink itself rather than following it. The create is exclusive
    // (`create_new`, which fails on ANY existing entry, symlink included) at mode 0600, so a
    // link planted after the unlink is refused, never written through.
    let _ = std::fs::remove_file(&tmp);
    crate::platform::fs::write_new_private(&tmp, id.as_bytes())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let res = std::fs::rename(&tmp, handle_dir.join(CAPTURED_THREAD_FILE));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// The captured thread id of the handle dir `codex_home`, or `None`. The file is opened
/// `O_NOFOLLOW` and the OPENED DESCRIPTOR is fstat'ed (no check-then-open-by-path, so a swap
/// between check and open cannot redirect the read); it must be a regular file of at most
/// 64 bytes holding exactly a UUID. Anything else is `None`, so the value reaching argv is
/// always UUID-shaped.
#[must_use]
pub fn read_captured_thread_id(codex_home: &Path) -> Option<String> {
    let bytes = crate::platform::fs::read_regular_nofollow_bounded(
        &codex_home.join(CAPTURED_THREAD_FILE),
        64,
    )
    .ok()??;
    let s = std::str::from_utf8(&bytes).ok()?.trim();
    is_uuid(s).then(|| s.to_ascii_lowercase())
}

/// One row of the process table: `pid`, `ppid` and the executable's image as `ps` prints it
/// (`comm`: a full path on macOS, the kernel name cut to 15 characters on Linux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcRow {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
}

/// Whether a `comm` value names a native `codex` image (`codex`, `codex-aarch64-apple-darwin`,
/// the 15-character Linux cut of it): the process that opens the rollout. The `node` wrapper
/// and the tools a session runs are not.
fn is_native_codex_image(image: &str) -> bool {
    let base = image.rsplit(['/', '\\']).next().unwrap_or(image);
    base.to_ascii_lowercase().starts_with("codex") && crate::sessions::is_cli_image_name(base)
}

/// `root` and its descendants in `rows`, `root` first, NOT descending below the first native
/// `codex` image on a path: that process is the one that holds the session's rollout, and
/// everything it spawns (shells, builds, another csq) is a tool, which would otherwise be
/// fd-enumerated on every poll and could hold a foreign rollout open. A cycle in a corrupt
/// table cannot loop: each pid is visited once.
#[must_use]
pub fn capture_tree(rows: &[ProcRow], root: u32) -> Vec<u32> {
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() {
        let parent = out[i];
        let native = rows
            .iter()
            .find(|r| r.pid == parent)
            .is_some_and(|r| is_native_codex_image(&r.image));
        if !native {
            for r in rows {
                if r.ppid == parent && !out.contains(&r.pid) {
                    out.push(r.pid);
                }
            }
        }
        i += 1;
    }
    out
}

/// The process table of this host via `ps`; `None` when it cannot be read. The child's env is
/// cleared (nothing secret reaches it); each line is `pid ppid image`, the image being the rest
/// of the line (a macOS path may contain spaces).
#[must_use]
pub fn process_table() -> Option<Vec<ProcRow>> {
    use std::process::{Command, Stdio};
    let out = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,comm="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.lines().filter_map(parse_ps_row).collect())
}

fn parse_ps_row(line: &str) -> Option<ProcRow> {
    let line = line.trim_start();
    let (pid, rest) = line.split_once(char::is_whitespace)?;
    let (ppid, image) = rest.trim_start().split_once(char::is_whitespace)?;
    Some(ProcRow {
        pid: pid.parse().ok()?,
        ppid: ppid.parse().ok()?,
        image: image.trim().to_owned(),
    })
}

/// Consecutive polls on which an id must be held by no tree process, every fd table read
/// successfully, before it is rejected as another session's. One miss is not enough: the
/// session's own rollout can be unheld for an instant (its fd briefly closed while the file is
/// rewritten), and a rejected id is never inspected again. At the 2 s poll this is ~6 s.
pub const REJECT_AFTER_MISSES: u8 = 3;

/// One capture poll. The rollouts are listed FIRST and the process tree is built (`tree`,
/// which reads the host's process table) only when `after - before` is non-empty, so an idle
/// session costs one directory walk per poll and no subprocess.
///
/// Under npm the supervisor's direct child is the `node` wrapper and the native `codex` that
/// opens the rollout is its descendant, so every pid `tree` returns is tested; and since a
/// second session on the same slot writes its own rollouts into the shared dir, EVERY new id
/// is tested rather than requiring exactly one. Returns the id some tree process holds open.
/// An id that no tree process holds, with every fd table read successfully, on
/// [`REJECT_AFTER_MISSES`] CONSECUTIVE polls (`misses` counts them; a poll that holds it
/// resets it, an unreadable table neither counts nor resets) is another session's and is added
/// to `before` so later polls do not re-inspect it. Two new ids both held by the tree are
/// ambiguous and return `None`.
#[must_use]
pub fn capture_poll_with(
    tree: &dyn Fn() -> Vec<u32>,
    sessions_dir: &Path,
    before: &mut HashSet<String>,
    misses: &mut std::collections::HashMap<String, u8>,
    open_paths: &dyn Fn(u32) -> Option<Vec<PathBuf>>,
) -> Option<String> {
    let after = list_rollout_ids(sessions_dir)?;
    let mut new: Vec<String> = after.difference(before).cloned().collect();
    new.sort();
    if new.is_empty() {
        return None;
    }
    let mut all_read = true;
    let mut held: HashSet<String> = HashSet::new();
    for pid in tree() {
        match open_paths(pid) {
            Some(paths) => {
                for p in paths.iter().filter(|p| p.starts_with(sessions_dir)) {
                    if let Some(id) = rollout_thread_id(p) {
                        if new.contains(&id) {
                            held.insert(id);
                        }
                    }
                }
            }
            None => all_read = false,
        }
    }
    if held.len() == 1 {
        return held.into_iter().next();
    }
    for id in &held {
        misses.remove(id);
    }
    if all_read {
        for id in new.iter().filter(|id| !held.contains(*id)) {
            let n = misses.entry(id.clone()).or_insert(0);
            *n += 1;
            if *n >= REJECT_AFTER_MISSES {
                misses.remove(id);
                before.insert(id.clone());
            }
        }
    }
    None
}

/// [`capture_poll_with`] over the real process table and fd enumeration, rooted at `root_pid`.
#[must_use]
pub fn capture_poll(
    root_pid: u32,
    sessions_dir: &Path,
    before: &mut HashSet<String>,
    misses: &mut std::collections::HashMap<String, u8>,
) -> Option<String> {
    capture_poll_with(
        &|| match process_table() {
            Some(rows) => capture_tree(&rows, root_pid),
            None => vec![root_pid],
        },
        sessions_dir,
        before,
        misses,
        &|pid| imp::open_file_paths(pid, FD_ENUM_TIMEOUT),
    )
}

/// The thread ids whose `<id>.lock` under `locks_dir` process `pid` currently holds open;
/// `None` when the fd table could not be read (never read as "holds nothing").
#[must_use]
pub fn held_lock_ids(pid: u32, locks_dir: &Path) -> Option<HashSet<String>> {
    let paths = imp::open_file_paths(pid, FD_ENUM_TIMEOUT)?;
    Some(held_lock_ids_in(&paths, locks_dir))
}

fn held_lock_ids_in(paths: &[PathBuf], locks_dir: &Path) -> HashSet<String> {
    paths
        .iter()
        .filter(|p| p.parent() == Some(locks_dir))
        .filter_map(|p| lock_thread_id(p))
        .collect()
}

// ── Platform fd enumeration ─────────────────────────────────────────

/// A complete field-mode lsof snapshot, or no snapshot on any read/decoding
/// failure. Partial bytes cannot establish either a sole thread or no locks.
#[cfg(any(target_os = "macos", test))]
fn read_lsof_paths(mut reader: impl std::io::Read) -> Option<Vec<PathBuf>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    Some(
        text.lines()
            .filter_map(|line| line.strip_prefix('n'))
            .map(PathBuf::from)
            .collect(),
    )
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    /// Enumerates the absolute paths of every regular file `pid` has
    /// open, via `lsof -p <pid> -Fn` (field-mode output: `n<path>`
    /// lines only, immune to the column-alignment ambiguity of lsof's
    /// default human-readable output). Returns `None` on timeout,
    /// spawn failure, or a non-zero exit — never a partial/misleading
    /// list. An empty (but successful) result is `Some(vec![])`.
    pub(super) fn open_file_paths(pid: u32, timeout: Duration) -> Option<Vec<PathBuf>> {
        // S-F10: absolute path + env_clear() + a minimal fixed env — the
        // parent's env (which may carry secrets from any of the callers
        // above `discover_thread_id`) is never handed to this child.
        // `PATH` is kept only because `lsof` is invoked by absolute path
        // already and this repo's other minimal-subprocess call sites
        // (`session::shared_state::run_sqlite3_with`) keep the same
        // "/usr/bin:/bin" floor rather than an empty one.
        let mut child = Command::new("/usr/sbin/lsof")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-Fn")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let stdout = child.stdout.take()?;
        let (tx, rx) = mpsc::channel::<Option<Vec<PathBuf>>>();
        let reader_handle = std::thread::spawn(move || {
            let _ = tx.send(read_lsof_paths(stdout));
        });

        let paths = match rx.recv_timeout(timeout) {
            Ok(paths) => paths,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                reader_handle.join().ok();
                return None;
            }
        };

        let status = child.wait().ok()?;
        reader_handle.join().ok();
        // A failed enumeration cannot prove the absence of held locks. This
        // includes lsof's exit 1 for an exited pid: prohibit stale fallback.
        if !status.success() {
            return None;
        }

        paths
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    /// Enumerates open file paths via `/proc/<pid>/fd/*` symlink
    /// readlinks. No subprocess, so `timeout` is unused here but kept
    /// in the signature for platform-uniform callers; a directory read
    /// on `/proc` does not itself block.
    pub(super) fn open_file_paths(pid: u32, _timeout: Duration) -> Option<Vec<PathBuf>> {
        let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
        open_file_paths_in(&fd_dir)
    }

    pub(super) fn open_file_paths_in(fd_dir: &Path) -> Option<Vec<PathBuf>> {
        let entries = std::fs::read_dir(fd_dir).ok()?;
        let mut paths = Vec::new();
        for entry in entries {
            // An unreadable member may be a competing held lock. A partial
            // snapshot must not become evidence for a singleton or no locks.
            paths.push(std::fs::read_link(entry.ok()?.path()).ok()?);
        }
        Some(paths)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;

    /// Windows (and any other unsupported platform) has no equivalent
    /// of `lsof`/`/proc/<pid>/fd` wired here yet — always `None`. This
    /// is a documented gap, not a claim that no such process exists.
    pub(super) fn open_file_paths(_pid: u32, _timeout: Duration) -> Option<Vec<PathBuf>> {
        None
    }
}

#[cfg(all(test, unix))]
mod capture_tests {
    use super::*;
    use std::collections::HashMap as M;
    use tempfile::TempDir;

    const A: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c";
    const B: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5d";

    fn rollout(root: &Path, id: &str) {
        let d = root.join("2026/10/05");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join(format!("rollout-2026-10-05T01-02-03-{id}.jsonl")),
            b"{}",
        )
        .unwrap();
    }

    #[test]
    fn code_red_role_reader_interrupts_unindexed_work_on_execution_budget() {
        let t = TempDir::new().unwrap();
        let db = rusqlite::Connection::open(t.path().join("state_5.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE threads(id TEXT, source TEXT); WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000000) INSERT INTO threads SELECT 'other-'||i,'cli' FROM n;").unwrap();
        let held = (0..2)
            .map(|i| format!("0198f1a2-3b4c-7d5e-8f9a-{i:012x}"))
            .collect();
        let queries = std::cell::Cell::new(0);
        let interrupted = std::cell::Cell::new(0);
        // The budget is spent by this probe, after the pre-query check passed and
        // immediately before the first real SQLite step: no wall-clock race decides
        // whether a step runs. The 1h duration is never reached.
        let before = |budget: &RoleReadBudget| {
            queries.set(queries.get() + 1);
            if queries.get() == 1 {
                budget.expire_now();
            }
        };
        let on_interrupt = || interrupted.set(interrupted.get() + 1);
        let start = std::time::Instant::now();
        let result = read_thread_roles_with_probe(
            t.path(),
            &held,
            Duration::from_secs(3600),
            &before,
            &on_interrupt,
        );
        eprintln!(
            "role-reader actual private SQLite queries={} interrupted={} elapsed_ms={}",
            queries.get(),
            interrupted.get(),
            start.elapsed().as_millis()
        );
        assert!(
            result.is_none(),
            "unindexed query workload must refuse on execution budget"
        );
        assert!(
            queries.get() > 0 && interrupted.get() > 0,
            "actual SQLite step must report OperationInterrupted; prequery expiry is not a probe"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "owned interrupt should stop actual private SQLite workload promptly"
        );
    }

    #[test]
    fn code_red_native_child_source_shape_is_validated() {
        let t = TempDir::new().unwrap();
        let db = rusqlite::Connection::open(t.path().join("state_5.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE threads(id TEXT PRIMARY KEY,source TEXT);")
            .unwrap();
        let held = [B.to_owned()].into_iter().collect();
        for source in ["{\"subagent\":null}","{\"subagent\":\"child\"}","{\"subagent\":{}}","{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"bad\",\"depth\":1}}}","{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c\",\"depth\":0}}}"] {
            db.execute("INSERT OR REPLACE INTO threads VALUES(?1,?2)",[B,source]).unwrap();
            assert_eq!(read_thread_roles(t.path(),&held).unwrap().get(B),Some(&ThreadRole::Unknown));
        }
        let source = format!(
            "{{\"subagent\":{{\"thread_spawn\":{{\"parent_thread_id\":\"{A}\",\"depth\":1}}}}}}"
        );
        db.execute("INSERT OR REPLACE INTO threads VALUES(?1,?2)", [B, &source])
            .unwrap();
        assert_eq!(
            read_thread_roles(t.path(), &held).unwrap().get(B),
            Some(&ThreadRole::Subagent)
        );
    }

    #[test]
    fn code_red_main_source_roles_reject_children_unknown_and_multiple_roots() {
        use ThreadDiscovery::*;
        let held: HashSet<String> = [A, B, C].into_iter().map(str::to_owned).collect();
        let mut roles: HashMap<String, ThreadRole> = [
            (A.into(), ThreadRole::Main),
            (B.into(), ThreadRole::Subagent),
            (C.into(), ThreadRole::Subagent),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            select_main_thread(Some(&held), Some(A), Some(&roles)),
            Found(A.into())
        );
        assert_eq!(
            select_main_thread(Some(&held), None, Some(&roles)),
            Found(A.into())
        );
        assert_eq!(
            select_main_thread(Some(&held), Some("not-held-old-thread"), Some(&roles)),
            Ambiguous,
            "stale explicit argv must not promote another MAIN"
        );
        assert_eq!(
            select_main_thread(Some(&held), Some(B), Some(&roles)),
            Ambiguous
        );
        roles.insert(C.into(), ThreadRole::Main);
        assert_eq!(
            select_main_thread(Some(&held), Some(A), Some(&roles)),
            Ambiguous
        );
        roles.insert(C.into(), ThreadRole::Unknown);
        assert_eq!(
            select_main_thread(Some(&held), Some(A), Some(&roles)),
            Ambiguous
        );
        assert_eq!(select_main_thread(None, Some(A), Some(&roles)), Ambiguous);
        assert_eq!(select_main_thread(Some(&held), Some(A), None), Ambiguous);
    }

    #[test]
    fn code_red_capture_existing_main_before_new_child_corrects_child_record() {
        let t = TempDir::new().unwrap();
        let sessions = t.path().join("sessions");
        let locks = t.path().join("locks");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::create_dir_all(&locks).unwrap();
        rollout(&sessions, A);
        let before = list_rollout_ids(&sessions).unwrap();
        assert!(before.contains(A));
        rollout(&sessions, B);
        let db = rusqlite::Connection::open(t.path().join("state_5.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE threads(id TEXT PRIMARY KEY, source TEXT);")
            .unwrap();
        for (id, source) in [
            (A, "cli"),
            (B, "{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c\",\"depth\":1}}}"),
            (C, "{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c\",\"depth\":1}}}"),
        ] {
            db.execute("INSERT INTO threads VALUES(?1,?2)", [id, source])
                .unwrap();
        }
        write_captured_thread_id(t.path(), B).unwrap();
        let mut paths = [A, B, C]
            .into_iter()
            .map(|id| locks.join(format!("{id}.lock")))
            .collect::<Vec<_>>();
        let child_rollout = sessions
            .join("2026/10/05")
            .join(format!("rollout-2026-10-05T01-02-03-{B}.jsonl"));
        paths.push(child_rollout);
        let id = capture_main_thread_with(&|| vec![100], &locks, t.path(), Some(A), &|_| {
            Some(paths.clone())
        });
        assert_eq!(
            id.as_deref(),
            Some(A),
            "existing resumed MAIN must beat newly-created child rollouts"
        );
        write_captured_thread_id(t.path(), &id.unwrap()).unwrap();
        assert_eq!(read_captured_thread_id(t.path()).as_deref(), Some(A));
        assert_eq!(
            capture_main_thread_with(&|| vec![100], &locks, t.path(), Some(A), &|_| None),
            None
        );
        let fresh = capture_main_thread_with(&|| vec![100], &locks, t.path(), None, &|_| {
            Some(paths.clone())
        });
        assert_eq!(
            fresh.as_deref(),
            Some(A),
            "native CLI source selects fresh MAIN among children"
        );
    }

    #[test]
    fn list_ids() {
        let t = TempDir::new().unwrap();
        rollout(t.path(), A);
        let before = list_rollout_ids(t.path()).unwrap();
        assert_eq!(before.len(), 1);
        rollout(t.path(), B);
        let after = list_rollout_ids(t.path()).unwrap();
        assert_eq!(after.len(), 2);
        assert!(list_rollout_ids(&t.path().join("absent")).is_none());
    }

    #[test]
    fn list_does_not_follow_symlinked_dirs() {
        let t = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        rollout(outside.path(), A);
        std::os::unix::fs::symlink(outside.path(), t.path().join("2026")).unwrap();
        assert!(list_rollout_ids(t.path()).unwrap().is_empty());
    }

    #[test]
    fn captured_file_round_trip_and_refusals() {
        let t = TempDir::new().unwrap();
        assert_eq!(read_captured_thread_id(t.path()), None);
        write_captured_thread_id(t.path(), A).unwrap();
        assert_eq!(read_captured_thread_id(t.path()).as_deref(), Some(A));
        assert!(write_captured_thread_id(t.path(), "../x").is_err());
        assert!(write_captured_thread_id(&t.path().join("gone"), A).is_err());
        // garbage and a symlink are refused
        std::fs::write(t.path().join(CAPTURED_THREAD_FILE), "--no-daemon").unwrap();
        assert_eq!(read_captured_thread_id(t.path()), None);
        std::fs::remove_file(t.path().join(CAPTURED_THREAD_FILE)).unwrap();
        let real = t.path().join("real");
        std::fs::write(&real, A).unwrap();
        std::os::unix::fs::symlink(&real, t.path().join(CAPTURED_THREAD_FILE)).unwrap();
        assert_eq!(read_captured_thread_id(t.path()), None);
    }

    fn paths_holding(sessions: &Path, ids: &[&str]) -> Option<Vec<PathBuf>> {
        Some(
            ids.iter()
                .map(|id| {
                    sessions.join(format!("2026/10/05/rollout-2026-10-05T01-02-03-{id}.jsonl"))
                })
                .collect(),
        )
    }

    const C: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5e";

    /// F3: under npm the spawned child (100) is the `node` wrapper and the rollout is held by
    /// its native descendant (101). Falsifier: testing only the spawned pid never finds B.
    #[test]
    fn capture_finds_the_id_held_by_the_native_descendant() {
        let t = TempDir::new().unwrap();
        rollout(t.path(), A);
        let mut before = list_rollout_ids(t.path()).unwrap();
        rollout(t.path(), B);
        let sessions = t.path().to_path_buf();
        let open = |pid: u32| -> Option<Vec<PathBuf>> {
            match pid {
                101 => paths_holding(&sessions, &[B]),
                _ => Some(vec![]),
            }
        };
        assert_eq!(
            capture_poll_with(
                &|| vec![100],
                t.path(),
                &mut before.clone(),
                &mut M::new(),
                &open
            ),
            None,
            "the wrapper alone holds nothing"
        );
        assert_eq!(
            capture_poll_with(
                &|| vec![100, 101],
                t.path(),
                &mut before,
                &mut M::new(),
                &open
            )
            .as_deref(),
            Some(B)
        );
    }

    /// F3: a second session on the same slot adds its own rollout (C) to the shared dir; the
    /// target's id is still captured, and the foreign id is remembered as not ours. Falsifier:
    /// the old "exactly one new id" rule returns None here.
    #[test]
    fn capture_survives_a_sibling_sessions_rollout() {
        let t = TempDir::new().unwrap();
        let mut before = list_rollout_ids(t.path()).unwrap();
        rollout(t.path(), B);
        rollout(t.path(), C);
        let sessions = t.path().to_path_buf();
        let open = |pid: u32| -> Option<Vec<PathBuf>> {
            if pid == 101 {
                paths_holding(&sessions, &[B])
            } else {
                Some(vec![])
            }
        };
        assert_eq!(
            capture_poll_with(
                &|| vec![100, 101],
                t.path(),
                &mut before,
                &mut M::new(),
                &open
            )
            .as_deref(),
            Some(B)
        );
        // an id no tree process holds is rejected for good (no repeated lsof) only after
        // REJECT_AFTER_MISSES consecutive polls, every fd table read
        let mut before2 = list_rollout_ids(t.path()).unwrap();
        before2.remove(C);
        before2.remove(B);
        let mut misses = M::new();
        let none = |_p: u32| Some(vec![]);
        for poll in 1..=REJECT_AFTER_MISSES {
            assert!(
                !before2.contains(C) && !before2.contains(B),
                "not rejected before miss {poll}"
            );
            assert_eq!(
                capture_poll_with(&|| vec![100], t.path(), &mut before2, &mut misses, &none),
                None
            );
        }
        assert!(before2.contains(C) && before2.contains(B));
        // an unreadable fd table rejects nothing, however many polls
        let mut before3 = HashSet::new();
        let mut misses3 = M::new();
        let unreadable = |_p: u32| None;
        for _ in 0..(REJECT_AFTER_MISSES + 2) {
            assert_eq!(
                capture_poll_with(
                    &|| vec![100],
                    t.path(),
                    &mut before3,
                    &mut misses3,
                    &unreadable
                ),
                None
            );
        }
        assert!(before3.is_empty());
    }

    /// I4: the session's own id, unheld on one successful poll (its fd briefly closed) and held
    /// on the next, is captured. Falsifier: the old reject-on-first-miss `before.extend(new)`
    /// dropped it for good on poll 1, so poll 2 returned `None`. Three consecutive misses still
    /// reject, so a foreign id is not re-inspected forever.
    #[test]
    fn an_id_unheld_on_one_poll_and_held_on_the_next_is_captured() {
        let t = TempDir::new().unwrap();
        let mut before = list_rollout_ids(t.path()).unwrap();
        rollout(t.path(), B);
        let sessions = t.path().to_path_buf();
        let mut misses = M::new();
        let closed = |_p: u32| Some(vec![]);
        assert_eq!(
            capture_poll_with(&|| vec![100], t.path(), &mut before, &mut misses, &closed),
            None
        );
        assert!(!before.contains(B), "one miss must not reject the id");
        let held = |_p: u32| paths_holding(&sessions, &[B]);
        assert_eq!(
            capture_poll_with(&|| vec![100], t.path(), &mut before, &mut misses, &held).as_deref(),
            Some(B)
        );
        // REJECT_AFTER_MISSES - 1 misses keep the id; the next consecutive miss rejects it
        let mut before = list_rollout_ids(t.path()).unwrap();
        before.remove(B);
        let mut misses = M::new();
        for _ in 0..(REJECT_AFTER_MISSES - 1) {
            let _ = capture_poll_with(&|| vec![100], t.path(), &mut before, &mut misses, &closed);
        }
        assert!(!before.contains(B));
        let _ = capture_poll_with(&|| vec![100], t.path(), &mut before, &mut misses, &closed);
        assert!(before.contains(B), "the third consecutive miss rejects");
    }

    /// I1: with no rollout newer than `before`, the process table is never read: the tree
    /// provider is not called. Falsifier: building the tree before listing (the old order)
    /// calls it on every poll, an idle session included.
    #[test]
    fn no_process_table_read_when_nothing_is_new() {
        let t = TempDir::new().unwrap();
        rollout(t.path(), A);
        let mut before = list_rollout_ids(t.path()).unwrap();
        let reads = std::cell::Cell::new(0u32);
        let tree = || {
            reads.set(reads.get() + 1);
            vec![100]
        };
        let open = |_p: u32| Some(vec![]);
        for _ in 0..3 {
            assert_eq!(
                capture_poll_with(&tree, t.path(), &mut before, &mut M::new(), &open),
                None
            );
        }
        assert_eq!(reads.get(), 0, "an idle poll reads no process table");
        rollout(t.path(), B);
        let _ = capture_poll_with(&tree, t.path(), &mut before, &mut M::new(), &open);
        assert_eq!(reads.get(), 1, "a new rollout reads it exactly once");
    }

    fn row(pid: u32, ppid: u32, image: &str) -> ProcRow {
        ProcRow {
            pid,
            ppid,
            image: image.to_owned(),
        }
    }

    #[test]
    fn tree_walk_is_transitive_and_cycle_safe() {
        let rows = [
            row(2, 1, "launchd"),
            row(100, 2, "node"),
            row(101, 100, "sh"),
            row(102, 101, "sh"),
            row(7, 1, "x"),
            row(8, 9, "x"),
            row(9, 8, "x"),
        ];
        assert_eq!(capture_tree(&rows, 100), vec![100, 101, 102]);
        assert_eq!(capture_tree(&rows, 8), vec![8, 9]);
        assert_eq!(capture_tree(&rows, 55), vec![55]);
    }

    /// S1: the walk stops at the first native `codex` image, so the tools a session runs are
    /// never fd-enumerated. Falsifier: the old unconditional descent includes 102 and 103.
    #[test]
    fn tree_walk_stops_at_the_native_codex_image() {
        let rows = [
            row(100, 2, "/usr/local/bin/node"),
            row(101, 100, "/opt/x/codex-aarch64-apple-darwin"),
            row(102, 101, "/bin/zsh"),
            row(103, 102, "/usr/bin/cargo"),
            row(104, 100, "/bin/sibling-of-codex"),
        ];
        assert_eq!(capture_tree(&rows, 100), vec![100, 101, 104]);
        // a native codex as the spawned child itself
        let direct = [row(100, 2, "codex"), row(101, 100, "bash")];
        assert_eq!(capture_tree(&direct, 100), vec![100]);
        // the Linux 15-character comm cut still counts; a lookalike tool does not
        assert!(is_native_codex_image("codex-aarch64-a"));
        assert!(!is_native_codex_image("codex-helper"));
        assert!(!is_native_codex_image("node"));
    }

    #[test]
    fn ps_rows_parse_with_spaces_in_the_image_path() {
        assert_eq!(
            parse_ps_row("  412     1 /Users/a b/bin/codex\n"),
            Some(row(412, 1, "/Users/a b/bin/codex"))
        );
        assert_eq!(parse_ps_row("junk"), None);
    }

    #[test]
    fn held_lock_ids_reads_only_the_locks_dir() {
        let locks = Path::new("/h/thread-writer-locks");
        let paths = vec![
            locks.join(format!("{A}.lock")),
            PathBuf::from(format!("/elsewhere/{B}.lock")),
            PathBuf::from("/h/thread-writer-locks/junk.lock"),
        ];
        let got = held_lock_ids_in(&paths, locks);
        assert_eq!(got.len(), 1);
        assert!(got.contains(A));
    }

    /// L1: a symlink planted at the predictable tmp name is never written through.
    /// Falsifier: `std::fs::write` on the tmp path overwrites `victim` with the id.
    #[test]
    fn write_never_follows_a_planted_tmp_symlink() {
        let t = TempDir::new().unwrap();
        let victim = t.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let tmp = t
            .path()
            .join(format!("{CAPTURED_THREAD_FILE}.tmp-{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        // A stale link is replaced by an exclusive create; either way the victim is intact.
        let _ = write_captured_thread_id(t.path(), A);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        // mode 0600 on the published file
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(t.path().join(CAPTURED_THREAD_FILE)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        assert_eq!(read_captured_thread_id(t.path()).as_deref(), Some(A));
    }

    /// F5: a captured id in a real handle dir is not reported by the share audit.
    /// Falsifier: with the old `.thread-id` name the audit lists it as unshared state.
    #[test]
    fn captured_file_is_not_flagged_by_the_share_audit() {
        let t = TempDir::new().unwrap();
        let h = t.path().join("term-4242");
        std::fs::create_dir(&h).unwrap();
        write_captured_thread_id(&h, A).unwrap();
        assert!(
            crate::session::share_audit::unshared_handle_dir_state(t.path()).is_empty(),
            "captured thread id must not read as unshared state"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u8) -> String {
        format!("01a0db{n:02x}-b7b7-7441-a2fe-81bfeef9916{n:x}")
    }

    #[test]
    fn is_uuid_accepts_measured_shape() {
        assert!(is_uuid("01a0db1d-b7b7-7441-a2fe-81bfeef99161"));
    }

    #[test]
    fn is_uuid_rejects_wrong_length_and_bad_dashes() {
        assert!(!is_uuid("01a0db1d-b7b7-7441-a2fe-81bfeef9916")); // 35 chars
        assert!(!is_uuid("01a0db1db7b7-7441-a2fe-81bfeef99161X")); // dash moved
        assert!(!is_uuid("gggggggg-b7b7-7441-a2fe-81bfeef99161")); // non-hex
    }

    #[test]
    fn lock_thread_id_extracts_stem() {
        let p = PathBuf::from("/locks/01a0db1d-b7b7-7441-a2fe-81bfeef99161.lock");
        assert_eq!(
            lock_thread_id(&p).as_deref(),
            Some("01a0db1d-b7b7-7441-a2fe-81bfeef99161")
        );
    }

    #[test]
    fn lock_thread_id_rejects_non_lock_extension_and_non_uuid_stem() {
        assert!(lock_thread_id(&PathBuf::from("/locks/not-a-uuid.lock")).is_none());
        assert!(lock_thread_id(&PathBuf::from(
            "/locks/01a0db1d-b7b7-7441-a2fe-81bfeef99161.txt"
        ))
        .is_none());
    }

    #[test]
    fn rollout_thread_id_extracts_trailing_uuid() {
        let p = PathBuf::from(
            "/sessions/2026/09/26/rollout-2026-09-26T08-32-13-01a0db20-7797-7ba0-a5aa-3bb2f8a037ac.jsonl",
        );
        assert_eq!(
            rollout_thread_id(&p).as_deref(),
            Some("01a0db20-7797-7ba0-a5aa-3bb2f8a037ac")
        );
    }

    #[test]
    fn rollout_thread_id_rejects_malformed_names() {
        assert!(rollout_thread_id(&PathBuf::from("/sessions/rollout-nouid.jsonl")).is_none());
        assert!(rollout_thread_id(&PathBuf::from(
            "/sessions/not-rollout-01a0db20-7797-7ba0-a5aa-3bb2f8a037ac.jsonl"
        ))
        .is_none());
        assert!(rollout_thread_id(&PathBuf::from(
            "/sessions/rollout-2026-09-26T08-32-13-01a0db20-7797-7ba0-a5aa-3bb2f8a037ac.txt"
        ))
        .is_none());
    }

    fn sessions_and_locks() -> (PathBuf, PathBuf) {
        (PathBuf::from("/sessions"), PathBuf::from("/locks"))
    }

    fn lock_path(locks: &Path, id: &str) -> PathBuf {
        locks.join(format!("{id}.lock"))
    }

    fn rollout_path(sessions: &Path, id: &str) -> PathBuf {
        sessions
            .join("2026/09/26")
            .join(format!("rollout-2026-09-26T08-32-13-{id}.jsonl"))
    }

    #[test]
    fn exact_match_yields_the_single_candidate() {
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let open = vec![lock_path(&locks, &id), rollout_path(&sessions, &id)];
        assert_eq!(
            matched_candidates(&open, &sessions, &locks),
            vec![(id.clone(), rollout_path(&sessions, &id))]
        );
    }

    #[test]
    fn two_open_rollouts_are_both_matched_as_candidates() {
        // Mirrors the MEASURED live process: multiple concurrently-open
        // (lock, rollout) pairs are both legitimate MATCHES — resolving
        // the ambiguity between them is pick_winner_by_recency's job,
        // exercised separately below.
        let (sessions, locks) = sessions_and_locks();
        let id_a = uuid(1);
        let id_b = uuid(2);
        let open = vec![
            lock_path(&locks, &id_a),
            rollout_path(&sessions, &id_a),
            lock_path(&locks, &id_b),
            rollout_path(&sessions, &id_b),
        ];
        assert_eq!(matched_candidates(&open, &sessions, &locks).len(), 2);
    }

    #[test]
    fn no_candidate_gives_empty_list() {
        let (sessions, locks) = sessions_and_locks();
        let open: Vec<PathBuf> = vec![];
        assert!(matched_candidates(&open, &sessions, &locks).is_empty());
    }

    #[test]
    fn lock_without_matching_rollout_gives_empty_list() {
        // A held lock with no matching open rollout is exactly the
        // "stale/orphaned lock" case the pairing requirement exists to
        // reject — not sufficient evidence of an active writer.
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let open = vec![lock_path(&locks, &id)];
        assert!(matched_candidates(&open, &sessions, &locks).is_empty());
    }

    #[test]
    fn rollout_without_matching_lock_gives_empty_list() {
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let open = vec![rollout_path(&sessions, &id)];
        assert!(matched_candidates(&open, &sessions, &locks).is_empty());
    }

    #[test]
    fn malformed_id_in_lock_name_is_rejected() {
        let (sessions, locks) = sessions_and_locks();
        let bad_id = "not-a-valid-uuid-at-all";
        let open = vec![
            locks.join(format!("{bad_id}.lock")),
            sessions
                .join("2026/09/26")
                .join(format!("rollout-2026-09-26T08-32-13-{bad_id}.jsonl")),
        ];
        assert!(matched_candidates(&open, &sessions, &locks).is_empty());
    }

    #[test]
    fn unrelated_open_files_are_ignored() {
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let open = vec![
            PathBuf::from("/dev/null"),
            PathBuf::from("/Users/example/repos/dev/csq"),
            lock_path(&locks, &id),
            rollout_path(&sessions, &id),
        ];
        assert_eq!(
            matched_candidates(&open, &sessions, &locks),
            vec![(id.clone(), rollout_path(&sessions, &id))]
        );
    }

    // ── lsof/proc-shaped text parsing (macOS field-mode output) ─────
    //
    // These exercise the SAME pure matcher against paths that mimic
    // what `lsof -p <pid> -Fn` produces, as a synthetic fixture rather
    // than a captured real invocation (no real paths/pids committed).

    #[test]
    fn synthetic_lsof_fn_style_paths_resolve_to_one_candidate() {
        let sessions =
            PathBuf::from("/Users/redacted/.claude/accounts/shared-state/codex/codex-sessions");
        let locks = PathBuf::from(
            "/Users/redacted/.claude/accounts/shared-state/codex/codex-thread-writer-locks",
        );
        let id = "01a0db20-7797-7ba0-a5aa-3bb2f8a037ac".to_string();
        // Shaped exactly like the `n<path>` lines lsof -Fn emits, minus
        // the leading `n` (already stripped by open_file_paths()).
        let rollout = PathBuf::from(format!(
            "{}/2026/09/26/rollout-2026-09-26T08-32-13-{id}.jsonl",
            sessions.display()
        ));
        let open = vec![rollout.clone(), locks.join(format!("{id}.lock"))];
        assert_eq!(
            matched_candidates(&open, &sessions, &locks),
            vec![(id, rollout)]
        );
    }

    #[test]
    fn partial_lsof_read_cannot_establish_thread_or_no_evidence() {
        struct FailsAfterBytes(std::io::Cursor<Vec<u8>>);
        impl std::io::Read for FailsAfterBytes {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    return Err(std::io::Error::other("injected snapshot read failure"));
                }
                std::io::Read::read(&mut self.0, buf)
            }
        }

        let (sessions, locks) = sessions_and_locks();
        let old = uuid(1);
        let old_pair = format!(
            "p123\nn{}\nn{}\n",
            lock_path(&locks, &old).display(),
            rollout_path(&sessions, &old).display()
        )
        .into_bytes();
        let now = at(4_102_444_800);
        // The complete fixture does identify the old pair. If its later read
        // fails, missing bytes may contain the new thread's lock after /new.
        let complete = read_lsof_paths(std::io::Cursor::new(old_pair.clone())).unwrap();
        assert_eq!(
            discover_outcome_from_paths_with(&complete, &sessions, &locks, now, |_| Some(now)),
            ThreadDiscovery::Found(old)
        );
        for bytes in [old_pair, b"p123\nn/dev/null\n".to_vec(), vec![]] {
            let paths = read_lsof_paths(FailsAfterBytes(std::io::Cursor::new(bytes)));
            assert!(paths.is_none(), "partial enumeration must not be accepted");
            assert_eq!(
                discover_outcome_from_snapshot(paths.as_deref(), &sessions, &locks),
                ThreadDiscovery::Ambiguous
            );
        }
    }

    #[test]
    fn lsof_decoding_failure_is_unavailable_but_complete_empty_snapshot_is_observed() {
        let (sessions, locks) = sessions_and_locks();
        let unreadable = read_lsof_paths(&b"p123\nn/locks/\xff.lock\n"[..]);
        assert_eq!(
            discover_outcome_from_snapshot(unreadable.as_deref(), &sessions, &locks),
            ThreadDiscovery::Ambiguous
        );
        let empty = read_lsof_paths(&b"p123\n"[..]);
        assert_eq!(
            discover_outcome_from_snapshot(empty.as_deref(), &sessions, &locks),
            ThreadDiscovery::NoEvidence
        );
    }

    // ── pick_winner_by_recency — pure, injected `now` + mtimes ──────
    //
    // Every mtime below is expressed as seconds since UNIX_EPOCH so the
    // arithmetic in the test bodies is legible; `at()` is the only
    // place SystemTime is constructed.

    fn at(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn a_clear_newest_wins() {
        // winner age = 2s (well within the 10s window); runner-up age =
        // 30s (28s clear of the 8s margin) — unambiguous on both axes.
        let now = at(1_000_000);
        let winner = uuid(1);
        let runner_up = uuid(2);
        let candidates = vec![
            (runner_up, at(1_000_000 - 30)),
            (winner.clone(), at(1_000_000 - 2)),
        ];
        assert_eq!(pick_winner_by_recency(&candidates, now), Some(winner));
    }

    #[test]
    fn two_within_the_margin_give_none() {
        // winner age = 2s, runner-up age = 9s: gap is 7s, <= the 8s
        // margin (measured live noise floor was 5s between two
        // genuinely-concurrent threads) — reject as ambiguous even
        // though both ages individually sit inside the recency window.
        let now = at(1_000_000);
        let candidates = vec![(uuid(1), at(1_000_000 - 2)), (uuid(2), at(1_000_000 - 9))];
        assert_eq!(pick_winner_by_recency(&candidates, now), None);
    }

    #[test]
    fn a_newest_that_is_too_old_gives_none_among_several_candidates() {
        // TWO candidates (per C-F13, a single-candidate winner is
        // exempted from the recency window — see
        // `a_single_candidate_wins_even_when_old`): the winner is 15s
        // old — past the 10s recency window (measured floor for a
        // genuinely-idle pair was 11s) — and clearly ahead of the
        // runner-up by more than the margin. Proves the recency-window
        // check still rejects a stale winner among several candidates
        // even when the disambiguation itself is unambiguous.
        let now = at(1_000_000);
        let candidates = vec![(uuid(1), at(1_000_000 - 15)), (uuid(2), at(1_000_000 - 40))];
        assert_eq!(pick_winner_by_recency(&candidates, now), None);
    }

    #[test]
    fn a_single_candidate_wins_when_inside_the_recency_window() {
        // A lone candidate wins regardless of age (C-F13); here it is
        // additionally young (3s), which was already unambiguous under
        // the pre-C-F13 rule and remains so — kept as a regression guard
        // distinct from `a_single_candidate_wins_even_when_old`.
        let now = at(1_000_000);
        let id = uuid(1);
        let candidates = vec![(id.clone(), at(1_000_000 - 3))];
        assert_eq!(pick_winner_by_recency(&candidates, now), Some(id));
    }

    #[test]
    fn a_single_candidate_wins_even_when_old() {
        // Same shape as the "inside the window" test above but 15s old:
        // per the accepted decision (C-F13), the recency window and the
        // margin apply only when DISAMBIGUATING among several candidates.
        // A single exact (lock, rollout) match has no rival to compare
        // against, so it wins regardless of its own age.
        let now = at(1_000_000);
        let id = uuid(1);
        let candidates = vec![(id.clone(), at(1_000_000 - 15))];
        assert_eq!(pick_winner_by_recency(&candidates, now), Some(id));
    }

    #[test]
    fn empty_candidate_list_gives_none() {
        assert_eq!(pick_winner_by_recency(&[], at(1_000_000)), None);
    }

    #[test]
    fn future_mtime_clock_skew_is_clamped_not_panicking() {
        // A rollout mtime one second AHEAD of `now` (observed live —
        // clock skew between the sampling `date` call and `stat`) must
        // not panic on the duration_since() subtraction; it clamps to
        // age 0, which is within the window.
        let now = at(1_000_000);
        let id = uuid(1);
        let candidates = vec![(id.clone(), at(1_000_001))];
        assert_eq!(pick_winner_by_recency(&candidates, now), Some(id));
    }

    /// A session with no turn yet: only its lock is open. The id is exact (fd in the live
    /// pid's own table). Red proof: the pre-change `discover` required a rollout fd too.
    #[test]
    fn lone_held_lock_without_rollout_is_the_thread() {
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let open = vec![lock_path(&locks, &id)];
        assert_eq!(
            discover_from_paths(&open, &sessions, &locks).as_deref(),
            Some(id.as_str())
        );
    }

    /// MEASURED after `/new` with no further turn: the old thread's lock + rollout stay open
    /// and the new thread's lock is held without a rollout. Resolving the pair would wake the
    /// abandoned thread, so the answer is `None`.
    #[test]
    fn pair_plus_unpaired_lock_after_new_is_none() {
        let (sessions, locks) = sessions_and_locks();
        let (old, new) = (uuid(1), uuid(2));
        let open = vec![
            lock_path(&locks, &old),
            rollout_path(&sessions, &old),
            lock_path(&locks, &new),
        ];
        assert_eq!(discover_from_paths(&open, &sessions, &locks), None);
    }

    #[test]
    fn pair_plus_unpaired_lock_preserves_ambiguity_for_fallback_callers() {
        let (sessions, locks) = sessions_and_locks();
        let (old, new) = (uuid(1), uuid(2));
        let open = vec![
            lock_path(&locks, &old),
            rollout_path(&sessions, &old),
            lock_path(&locks, &new),
        ];
        assert_eq!(
            discover_outcome_from_paths(&open, &sessions, &locks),
            ThreadDiscovery::Ambiguous
        );
    }

    #[test]
    fn unavailable_snapshot_is_ambiguous_but_observed_empty_snapshot_has_no_evidence() {
        let (sessions, locks) = sessions_and_locks();
        assert_eq!(
            discover_outcome_from_snapshot(None, &sessions, &locks),
            ThreadDiscovery::Ambiguous
        );
        assert_eq!(
            discover_outcome_from_snapshot(Some(&[]), &sessions, &locks),
            ThreadDiscovery::NoEvidence
        );
        let rollout_only = [rollout_path(&sessions, &uuid(1))];
        assert_eq!(
            discover_outcome_from_snapshot(Some(&rollout_only), &sessions, &locks),
            ThreadDiscovery::NoEvidence
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incomplete_fd_enumeration_cannot_become_an_observed_empty_snapshot() {
        let fd_dir = tempfile::TempDir::new().unwrap();
        assert_eq!(imp::open_file_paths_in(fd_dir.path()), Some(vec![]));
        // A regular file cannot be read as an fd symlink; simulate a failed member.
        std::fs::write(fd_dir.path().join("unreadable-fd"), []).unwrap();
        let paths = imp::open_file_paths_in(fd_dir.path());
        assert_eq!(paths, None);
        let (sessions, locks) = sessions_and_locks();
        assert_eq!(
            discover_outcome_from_snapshot(paths.as_deref(), &sessions, &locks),
            ThreadDiscovery::Ambiguous
        );
    }

    #[test]
    fn sole_held_lock_outcome_is_found_but_multiple_unpaired_locks_are_ambiguous() {
        let (sessions, locks) = sessions_and_locks();
        let id = uuid(1);
        let mut open = vec![lock_path(&locks, &id)];
        assert_eq!(
            discover_outcome_from_paths(&open, &sessions, &locks),
            ThreadDiscovery::Found(id)
        );
        open.push(lock_path(&locks, &uuid(2)));
        assert_eq!(
            discover_outcome_from_paths(&open, &sessions, &locks),
            ThreadDiscovery::Ambiguous
        );
    }

    #[test]
    fn competing_pair_outcomes_preserve_ties_staleness_and_clear_winners() {
        let (sessions, locks) = sessions_and_locks();
        let (winner, rival) = (uuid(1), uuid(2));
        let winner_rollout = rollout_path(&sessions, &winner);
        let open = vec![
            lock_path(&locks, &winner),
            winner_rollout.clone(),
            lock_path(&locks, &rival),
            rollout_path(&sessions, &rival),
        ];
        // Fixed injected time in 2100: independent of wall-clock progress.
        let now = at(4_102_444_800);
        for (winner_age, rival_age, expected) in [
            (2, 2, ThreadDiscovery::Ambiguous),
            (2, 9, ThreadDiscovery::Ambiguous),
            (15, 60, ThreadDiscovery::Ambiguous),
            (2, 30, ThreadDiscovery::Found(winner.clone())),
        ] {
            assert_eq!(
                discover_outcome_from_paths_with(&open, &sessions, &locks, now, |path| {
                    let age = if path == winner_rollout {
                        winner_age
                    } else {
                        rival_age
                    };
                    Some(now - Duration::from_secs(age))
                }),
                expected
            );
        }
    }

    #[test]
    fn unreadable_rollout_metadata_cannot_promote_a_remaining_held_pair() {
        let (sessions, locks) = sessions_and_locks();
        let (first, second) = (uuid(1), uuid(2));
        let first_rollout = rollout_path(&sessions, &first);
        let open = vec![
            lock_path(&locks, &first),
            first_rollout.clone(),
            lock_path(&locks, &second),
            rollout_path(&sessions, &second),
        ];
        let now = at(4_102_444_800);
        assert_eq!(
            discover_outcome_from_paths_with(&open, &sessions, &locks, now, |path| {
                (path == first_rollout).then_some(now)
            }),
            ThreadDiscovery::Ambiguous
        );
        assert_eq!(
            discover_outcome_from_paths_with(&open[..2], &sessions, &locks, now, |_| None),
            ThreadDiscovery::Ambiguous
        );
        assert_eq!(
            discover_outcome_from_paths_with(&open[..2], &sessions, &locks, now, |_| {
                Some(now - Duration::from_secs(60))
            }),
            ThreadDiscovery::Found(first)
        );
    }

    #[test]
    fn two_held_locks_without_rollout_stay_none() {
        let (sessions, locks) = sessions_and_locks();
        let open = vec![lock_path(&locks, &uuid(1)), lock_path(&locks, &uuid(2))];
        assert_eq!(discover_from_paths(&open, &sessions, &locks), None);
    }
}
