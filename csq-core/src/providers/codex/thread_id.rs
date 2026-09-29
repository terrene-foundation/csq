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
//! ago") returns `None` rather than guess. A SINGLE exact (lock,
//! rollout) match has no rival to disambiguate against and is returned
//! regardless of its own age (decision: C-F13).
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
    let open_paths = imp::open_file_paths(codex_pid, FD_ENUM_TIMEOUT)?;
    let candidates = matched_candidates(&open_paths, sessions_dir, locks_dir);
    // Read-only: `fs::metadata` is a stat call, never an open/read of
    // the rollout file's content (per the task's read-only mandate).
    // A candidate whose rollout vanished between the fd snapshot and
    // this stat (or whose mtime is unreadable) is dropped rather than
    // aborting the whole discovery — the remaining candidates (if any)
    // are still decided normally.
    let with_mtime: Vec<(String, SystemTime)> = candidates
        .into_iter()
        .filter_map(|(id, path)| {
            std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|mtime| (id, mtime))
        })
        .collect();
    pick_winner_by_recency(&with_mtime, SystemTime::now())
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

// ── Platform fd enumeration ─────────────────────────────────────────

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::io::Read;
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

        let mut stdout = child.stdout.take()?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });

        let buf = match rx.recv_timeout(timeout) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                reader_handle.join().ok();
                return None;
            }
        };

        let status = child.wait().ok()?;
        reader_handle.join().ok();
        // lsof exits 1 when the pid has no open files matching the
        // filter, or has already exited between the caller's liveness
        // check and this call — both read as "no evidence", not
        // "error", so only a genuinely absent/unparseable output
        // returns None from the CALLER's perspective (empty Vec here
        // still yields None overall, since `[only]` can never match).
        if !status.success() {
            return Some(Vec::new());
        }

        let text = String::from_utf8_lossy(&buf);
        Some(
            text.lines()
                .filter_map(|line| line.strip_prefix('n'))
                .map(PathBuf::from)
                .collect(),
        )
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
        let entries = std::fs::read_dir(&fd_dir).ok()?;
        let mut paths = Vec::new();
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                paths.push(target);
            }
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
}
