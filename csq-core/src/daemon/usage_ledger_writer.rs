//! Daemon-side usage-ledger writer (an internal ticket Part 1).
//!
//! Periodically re-derives each account's usage history from CC's transcripts
//! (`~/.claude/projects/<cwd>/<session-id>.jsonl`) via [`crate::usage::aggregator`]
//! and atomically publishes it to the per-slot ledger
//! ([`crate::usage::ledger::write_all`]). The desktop `get_account_usage`
//! command then just [`crate::usage::ledger::read_all`] + `summarize` — a
//! sub-millisecond read that renders instantly, instead of the ~20s live
//! transcript scan that an internal ticket shipped behind a background-refresh cache.
//!
//! This makes the daemon the SOLE producer of the billing ledger and terminals
//! pure readers — the extension of `rules/account-terminal-separation.md`
//! Rule 1 to billing telemetry that the ledger module was designed for (see
//! `crate::usage::ledger` header).
//!
//! Runs as a `tokio::spawn`-ed background task (never on the daemon main loop),
//! mirroring [`crate::daemon::coc_cache_sweeper`]. The FIRST tick fires
//! immediately at startup so a freshly-launched daemon populates the ledger
//! before the user opens the dashboard; subsequent ticks run on cadence. Each
//! tick's scan is best-effort — a per-slot write failure is logged and skipped,
//! never fatal (mirrors the poller / sweeper policy).

use crate::types::AccountNum;
use crate::usage::{aggregator, ledger};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Default tick interval. The read path is instant regardless of cadence (it
/// reads the published ledger), so this only bounds staleness — 10 minutes is
/// imperceptible for a billing view and halves the always-on daemon's
/// background transcript-scan load versus the 5-minute cache TTL that #986
/// shipped.
pub const TICK_INTERVAL: Duration = Duration::from_secs(600);

/// Fallback model used ONLY for transcript sessions whose lines carried no
/// model (rare post-#986; the per-turn model is normally read from the
/// transcript). Matches the desktop command's historical fallback; the writer
/// improves on it per-slot via [`crate::providers::settings::model_id_for_slot`].
const DEFAULT_FALLBACK_MODEL: &str = "claude-sonnet-4-6";

/// Outcome of one writer tick. Returned by [`run_once`] for logging and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Slots whose ledger was rewritten with current events this tick.
    pub slots_written: usize,
    /// Total events published across all slots.
    pub events_written: usize,
    /// Slots whose existing ledger was rolled off to empty this tick because
    /// their transcripts aged out of the scan window (or were deleted).
    pub slots_rolled_off: usize,
    /// Slots whose `write_all` failed (logged, non-fatal).
    pub write_failures: usize,
}

/// Handle to a running usage-ledger writer task.
pub struct WriterHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Runs one aggregation → publish cycle synchronously. This is the testable
/// core the tick loop calls; it holds no timing state.
///
/// `claude_home` is `~/.claude` (parent of `base_dir`'s accounts dir) — the
/// root the aggregator scans for transcripts. `base_dir` is
/// `~/.claude/accounts`, the ledger + launch-log root.
///
/// The per-slot model FALLBACK is resolved from the slot's configured
/// `settings.json` (`model_id_for_slot`) rather than a flat constant, so a 3P
/// slot's rare model-less transcript line is costed at that slot's real model
/// instead of always-Sonnet.
pub fn run_once(
    claude_home: &Path,
    base_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> WriteReport {
    let pairs = aggregator::aggregate(claude_home, base_dir, now, |slot: AccountNum| {
        crate::providers::settings::model_id_for_slot(base_dir, slot.get())
            .unwrap_or_else(|| DEFAULT_FALLBACK_MODEL.to_string())
    });

    // Group by slot, then full-replace each slot's ledger with its current
    // events. Full-replace is idempotent: re-running over the same transcripts
    // produces the same file.
    let mut by_slot: BTreeMap<AccountNum, Vec<ledger::UsageEvent>> = BTreeMap::new();
    for (slot, event) in pairs {
        by_slot.entry(slot).or_default().push(event);
    }

    let mut report = WriteReport::default();
    // Track the ledger FILE each active slot published to, so the roll-off
    // below never empties a file an active slot just wrote (see R3 guard).
    let mut written_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for (slot, events) in &by_slot {
        match ledger::write_all(base_dir, *slot, events) {
            Ok(()) => {
                report.slots_written += 1;
                report.events_written += events.len();
                written_paths.insert(ledger::ledger_path(base_dir, *slot));
            }
            Err(e) => {
                report.write_failures += 1;
                warn!(
                    error_kind = "usage_ledger_write_failed",
                    slot = slot.get(),
                    "usage-ledger write failed: {e}"
                );
            }
        }
    }

    // Roll off slots whose transcripts aged out of the aggregator's 31-day scan
    // window (or were deleted): a slot with an EXISTING ledger but no events
    // this tick must converge to empty. Otherwise its stale Total freezes at the
    // last non-empty tick while a fresh live-scan — which the ledger is a cache
    // of — would attribute it zero events. Skip slots already empty so the
    // roll-off quiesces after one tick instead of rewriting every cycle.
    // (#992 redteam R1 HIGH-1.)
    for slot in existing_ledger_slots(base_dir) {
        if by_slot.contains_key(&slot) {
            continue;
        }
        // Defensive: two slots can (anomalously) share one UUID-keyed ledger
        // file. If an ACTIVE slot just wrote to the file this inactive slot
        // resolves to, rolling it off would wipe the active slot's events. Skip
        // any slot whose ledger path an active slot already published to.
        // (#992 redteam R3 LOW-1.)
        if written_paths.contains(&ledger::ledger_path(base_dir, slot)) {
            continue;
        }
        let already_empty = ledger::read_all(base_dir, slot)
            .map(|r| r.events.is_empty())
            .unwrap_or(false);
        if already_empty {
            continue;
        }
        match ledger::write_all(base_dir, slot, &[]) {
            Ok(()) => report.slots_rolled_off += 1,
            Err(e) => {
                report.write_failures += 1;
                warn!(
                    error_kind = "usage_ledger_rolloff_failed",
                    slot = slot.get(),
                    "usage-ledger roll-off write failed: {e}"
                );
            }
        }
    }
    report
}

/// Enumerates every slot that currently has a ledger file on disk — both the
/// UUID-keyed (`identities/<UUID>/usage.ndjson`) and legacy flat
/// (`usage-{slot}.ndjson`) shapes. Used by [`run_once`] to roll off a slot
/// whose transcripts aged out of the scan window so its published ledger
/// converges to what a fresh live-scan produces (empty). Best-effort: an
/// unreadable directory yields no slots for that shape rather than failing.
fn existing_ledger_slots(base_dir: &Path) -> std::collections::BTreeSet<AccountNum> {
    use std::str::FromStr;
    let mut slots = std::collections::BTreeSet::new();

    // Legacy flat ledgers: <base>/usage-{N}.ndjson
    if let Ok(rd) = std::fs::read_dir(base_dir) {
        for entry in rd.flatten() {
            if let Some(slot) = entry
                .file_name()
                .to_str()
                .and_then(|f| f.strip_prefix("usage-"))
                .and_then(|f| f.strip_suffix(".ndjson"))
                .and_then(|n| n.parse::<u16>().ok())
                .and_then(|n| AccountNum::try_from(n).ok())
            {
                slots.insert(slot);
            }
        }
    }

    // UUID-keyed ledgers: <base>/identities/<UUID>/usage.ndjson. Load profiles
    // ONCE and reverse-map each UUID inline — `resolve_uuid_to_slot` re-reads
    // profiles.json per directory entry, which is O(N²) across identities.
    // (#992 redteam R2 LOW-2.) No profiles → no UUID→slot mapping possible, so
    // the branch is skipped (matching the read path, which also needs profiles
    // to resolve a UUID-keyed ledger).
    let identities = crate::accounts::identity_store::identities_dir(base_dir);
    if let Ok(rd) = std::fs::read_dir(&identities) {
        if let Ok(profiles) =
            crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base_dir))
        {
            for entry in rd.flatten() {
                if !entry.path().join("usage.ndjson").exists() {
                    continue;
                }
                let Some(id) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| crate::accounts::identity_store::IdentityId::from_str(s).ok())
                else {
                    continue;
                };
                if let Some(slot) = profiles
                    .by_slot
                    .iter()
                    .filter(|(_, v)| **v == id)
                    .filter_map(|(k, _)| k.parse::<u16>().ok())
                    .min()
                    .and_then(|n| AccountNum::try_from(n).ok())
                {
                    slots.insert(slot);
                }
            }
        }
    }
    slots
}

/// Spawns the daemon-side usage-ledger writer.
///
/// `claude_home` is `~/.claude`; pass `None` when it cannot be resolved (no
/// `$HOME`) — the writer then becomes a no-op (it cannot scan transcripts).
/// The task runs one tick immediately and then every [`TICK_INTERVAL`] until
/// `shutdown` is cancelled.
///
/// `now_fn` supplies the current time per tick. csq-core builds chrono WITHOUT
/// the `clock` feature (deliberate — see `crate::usage::aggregator`, so tests
/// stay deterministic), so the CALLER (the `csq` crate, which enables `clock`)
/// passes `chrono::Utc::now`; tests pass a fixed-time closure.
pub fn spawn<N>(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    now_fn: N,
) -> WriterHandle
where
    N: Fn() -> chrono::DateTime<chrono::Utc> + Send + 'static,
{
    spawn_with_config(base_dir, claude_home, shutdown, TICK_INTERVAL, now_fn)
}

/// Like [`spawn`] but with an explicit tick interval for tests.
pub fn spawn_with_config<N>(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    interval: Duration,
    now_fn: N,
) -> WriterHandle
where
    N: Fn() -> chrono::DateTime<chrono::Utc> + Send + 'static,
{
    let join = tokio::spawn(async move {
        let Some(claude_home) = claude_home else {
            debug!("usage-ledger-writer: no claude_home — writer disabled");
            return;
        };
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately (tokio interval default), populating the
        // ledger at daemon startup. Delay (not Burst) on a missed tick so a
        // long scan never stacks catch-up ticks.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("usage-ledger-writer: shutdown signalled, exiting");
                    return;
                }
                _ = ticker.tick() => {
                    let base = base_dir.clone();
                    let home = claude_home.clone();
                    let now = now_fn();
                    // The scan is filesystem-heavy (~20s on a large host); keep
                    // it off the async runtime's worker threads.
                    let scan = tokio::task::spawn_blocking(move || {
                        run_once(&home, &base, now)
                    });
                    // Race the scan against shutdown so cancellation is observed
                    // MID-scan, not only at the top of the loop. spawn_blocking
                    // runs to completion regardless (a blocking task cannot be
                    // cancelled), so the detached task finishes its atomic write
                    // harmlessly — we just stop waiting on it. No ledger is torn
                    // (atomic_replace). (#992 redteam R1 MEDIUM-3.)
                    let report = tokio::select! {
                        _ = shutdown.cancelled() => {
                            debug!("usage-ledger-writer: shutdown during scan, exiting");
                            return;
                        }
                        r = scan => r,
                    };
                    match report {
                        Ok(r) => debug!(
                            slots_written = r.slots_written,
                            events_written = r.events_written,
                            slots_rolled_off = r.slots_rolled_off,
                            write_failures = r.write_failures,
                            "usage-ledger-writer tick complete"
                        ),
                        Err(e) => warn!(
                            error_kind = "usage_ledger_writer_join",
                            "usage-ledger-writer tick task failed: {e}"
                        ),
                    }
                }
            }
        }
    });
    WriterHandle { join }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Builds a `~/.claude` + `~/.claude/accounts` pair under a tempdir and
    /// writes a CC transcript + a matching launch-log entry so the aggregator
    /// attributes the session to `slot`.
    #[allow(clippy::too_many_arguments)] // test fixture builder — explicit params keep call sites readable
    fn fixture(
        claude_home: &Path,
        base_dir: &Path,
        slot: u16,
        project_dir: &str,
        session_id: &str,
        ts: &str,
        input: u64,
        output: u64,
    ) {
        // Launch log: maps the project path → slot (attribution key).
        let project_abs = format!("/work/{project_dir}");
        let launch_line = serde_json::json!({
            "ts": ts, "event": "run", "slot": slot, "pid": 1, "project_path": project_abs,
        });
        std::fs::create_dir_all(base_dir).unwrap();
        std::fs::write(
            base_dir.join(crate::usage::launch_log::LAUNCH_LOG_FILENAME),
            format!("{launch_line}\n"),
        )
        .unwrap();

        // Transcript: CC encodes the cwd into the projects subdir name.
        let encoded = project_abs.replace('/', "-");
        let tdir = claude_home.join("projects").join(encoded);
        std::fs::create_dir_all(&tdir).unwrap();
        // A claude-family transcript: these tests exercise write/roll-off
        // plumbing, not 3P attribution. With no 3P binding planted, the slot's
        // `AccountSource` is unresolved (gate falls through) for the plain
        // tests, and resolves to Anthropic for the tests that plant a
        // `profiles.json` `by_slot` mapping (the shared-UUID case) — a claude
        // model is provider-consistent with BOTH, so the aggregator's gate
        // never spuriously drops the fixture session.
        let line = serde_json::json!({
            "type": "assistant",
            "timestamp": ts,
            "cwd": project_abs,
            "sessionId": session_id,
            "message": {
                "model": "claude-sonnet-4-6",
                "usage": { "input_tokens": input, "output_tokens": output }
            }
        });
        std::fs::write(
            tdir.join(format!("{session_id}.jsonl")),
            format!("{line}\n"),
        )
        .unwrap();
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 0).unwrap()
    }

    #[test]
    fn run_once_publishes_ledger_a_terminal_can_read() {
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        fixture(
            &claude_home,
            &base_dir,
            11,
            "repo",
            "sess-a",
            "2026-07-07T10:00:00Z",
            10_000,
            5_000,
        );

        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(report.slots_written, 1, "one slot had usage");
        assert_eq!(report.events_written, 1);
        assert_eq!(report.write_failures, 0);

        // A terminal reading the published ledger sees the same session.
        let slot = AccountNum::try_from(11u16).unwrap();
        let events = ledger::read_all(&base_dir, slot).unwrap().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].input_tokens, 10_000);
        assert_eq!(events[0].output_tokens, 5_000);
    }

    #[test]
    fn run_once_is_idempotent_across_ticks() {
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        fixture(
            &claude_home,
            &base_dir,
            11,
            "repo",
            "sess-a",
            "2026-07-07T10:00:00Z",
            10_000,
            5_000,
        );

        run_once(&claude_home, &base_dir, now());
        let after_first = ledger::read_all(&base_dir, AccountNum::try_from(11u16).unwrap())
            .unwrap()
            .events;
        // A second tick over the same transcripts must not duplicate rows.
        run_once(&claude_home, &base_dir, now());
        let after_second = ledger::read_all(&base_dir, AccountNum::try_from(11u16).unwrap())
            .unwrap()
            .events;
        assert_eq!(after_first, after_second, "full-replace is idempotent");
        assert_eq!(after_second.len(), 1);
    }

    #[test]
    fn run_once_no_transcripts_writes_nothing() {
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        std::fs::create_dir_all(&base_dir).unwrap();

        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(report, WriteReport::default(), "no usage → nothing written");
    }

    #[test]
    fn run_once_rolls_off_aged_out_slot_to_empty() {
        // A slot whose transcripts aged out of the scan window (here: simply no
        // transcripts) but which has an EXISTING ledger from a prior tick must
        // converge to empty, so the read path matches a fresh live-scan.
        // (#992 redteam R1 HIGH-1.)
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        std::fs::create_dir_all(&base_dir).unwrap();

        // Seed slot 11's ledger as a prior tick would have (legacy flat path —
        // no profiles.json → usage-11.ndjson).
        let slot = AccountNum::try_from(11u16).unwrap();
        let stale = ledger::UsageEvent {
            ts: "2026-05-01T10:00:00Z".into(),
            session_id: "old".into(),
            model: "deepseek-chat".into(),
            input_tokens: 9_999,
            output_tokens: 1_111,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            cost_usd_estimate: Some(0.5),
            source: ledger::UsageSource::ProjectsJsonl,
            project_path: None,
        };
        ledger::write_all(&base_dir, slot, std::slice::from_ref(&stale)).unwrap();
        assert!(!ledger::read_all(&base_dir, slot).unwrap().events.is_empty());

        // A tick with NO current transcripts for that slot rolls it off.
        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(report.slots_rolled_off, 1, "aged-out slot must roll off");
        assert_eq!(report.slots_written, 0);
        assert!(
            ledger::read_all(&base_dir, slot).unwrap().events.is_empty(),
            "rolled-off ledger must be empty"
        );

        // Second tick is idempotent — already empty, so no re-write.
        let report2 = run_once(&claude_home, &base_dir, now());
        assert_eq!(
            report2.slots_rolled_off, 0,
            "already-empty ledger must quiesce (no rewrite every tick)"
        );
    }

    #[test]
    fn run_once_rolls_off_uuid_keyed_aged_out_slot() {
        // The PRIMARY production shape (post-A++): a UUID-keyed ledger at
        // identities/<UUID>/usage.ndjson must be discovered by
        // existing_ledger_slots (via resolve_uuid_to_slot) and rolled off.
        // (#992 redteam R2 GAP-1.)
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        std::fs::create_dir_all(&base_dir).unwrap();

        // profiles.json with by_slot so ledger_path routes slot 11 to the
        // UUID-keyed path.
        let uuid_str = "550e8400-e29b-41d4-a716-446655440099";
        std::fs::write(
            base_dir.join("profiles.json"),
            format!(r#"{{"accounts":{{}},"by_slot":{{"11":"{uuid_str}"}}}}"#),
        )
        .unwrap();

        let slot = AccountNum::try_from(11u16).unwrap();
        // Confirm the write actually landed at the UUID path (not the flat one).
        let uuid_ledger = base_dir
            .join("identities")
            .join(uuid_str)
            .join("usage.ndjson");
        let stale = ledger::UsageEvent {
            ts: "2026-05-01T10:00:00Z".into(),
            session_id: "old-uuid".into(),
            model: "deepseek-chat".into(),
            input_tokens: 9_999,
            output_tokens: 1_111,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            cost_usd_estimate: Some(0.5),
            source: ledger::UsageSource::ProjectsJsonl,
            project_path: None,
        };
        ledger::write_all(&base_dir, slot, std::slice::from_ref(&stale)).unwrap();
        assert!(uuid_ledger.exists(), "ledger must land at the UUID path");
        assert!(!ledger::read_all(&base_dir, slot).unwrap().events.is_empty());

        // No transcripts this tick → the UUID-keyed slot must roll off.
        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(
            report.slots_rolled_off, 1,
            "UUID-keyed aged-out slot must roll off"
        );
        assert!(
            ledger::read_all(&base_dir, slot).unwrap().events.is_empty(),
            "UUID-keyed rolled-off ledger must be empty"
        );

        // Quiesce.
        let report2 = run_once(&claude_home, &base_dir, now());
        assert_eq!(report2.slots_rolled_off, 0);
    }

    #[test]
    fn existing_ledger_slots_ignores_non_ledger_files() {
        // A stray file must not be misidentified as a ledger slot and trigger a
        // spurious roll-off. (#992 redteam R2 GAP-3.)
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        for name in &[
            "usage-0.ndjson",     // slot 0 invalid (AccountNum is 1..=999)
            "usage-abc.ndjson",   // non-numeric
            "usage-1.ndjson.bak", // wrong suffix
            ".usage-1.ndjson.swp",
            "usage-.ndjson", // empty numeric part
            "not-a-ledger.txt",
            "usage-1000.ndjson", // above MAX_ACCOUNTS
        ] {
            std::fs::write(base.join(name), b"").unwrap();
        }
        // One real ledger to confirm the valid case IS found.
        let slot = AccountNum::try_from(3u16).unwrap();
        ledger::write_all(base, slot, &[]).unwrap();

        let slots = existing_ledger_slots(base);
        assert_eq!(slots.len(), 1, "only the real ledger slot must be found");
        assert!(slots.contains(&slot));
    }

    #[test]
    fn run_once_writes_active_slot_and_rolls_off_stale_slot_together() {
        // Mixed tick: an active slot (has transcripts) must be WRITTEN while a
        // stale slot (ledger only) is rolled off — guards the
        // by_slot.contains_key gate against inversion. (#992 redteam R2 GAP-4.)
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        std::fs::create_dir_all(&base_dir).unwrap();

        // Slot 11: live transcripts → written, NOT rolled off.
        fixture(
            &claude_home,
            &base_dir,
            11,
            "active-repo",
            "sess-active",
            "2026-07-07T10:00:00Z",
            1_000,
            500,
        );
        // Slot 12: stale ledger, no transcripts → rolled off.
        let stale_slot = AccountNum::try_from(12u16).unwrap();
        let stale = ledger::UsageEvent {
            ts: "2026-05-01T10:00:00Z".into(),
            session_id: "stale".into(),
            model: "deepseek-chat".into(),
            input_tokens: 42,
            output_tokens: 7,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            cost_usd_estimate: Some(0.01),
            source: ledger::UsageSource::ProjectsJsonl,
            project_path: None,
        };
        ledger::write_all(&base_dir, stale_slot, std::slice::from_ref(&stale)).unwrap();

        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(report.slots_written, 1, "active slot must be written");
        assert_eq!(report.slots_rolled_off, 1, "stale slot must roll off");

        let active = AccountNum::try_from(11u16).unwrap();
        assert!(
            !ledger::read_all(&base_dir, active)
                .unwrap()
                .events
                .is_empty(),
            "active slot keeps its events"
        );
        assert!(
            ledger::read_all(&base_dir, stale_slot)
                .unwrap()
                .events
                .is_empty(),
            "stale slot rolled off to empty"
        );
    }

    #[test]
    fn run_once_shared_uuid_rolloff_does_not_wipe_active_slot() {
        // Anomaly guard (#992 redteam R3 LOW-1): two slots mapped to ONE UUID
        // share one ledger file. When slot 7 is active and slot 5 is not, the
        // roll-off (which resolves the shared UUID to min slot = 5) must NOT
        // wipe the file slot 7 just wrote.
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        std::fs::create_dir_all(&base_dir).unwrap();

        let uuid_str = "550e8400-e29b-41d4-a716-446655440077";
        std::fs::write(
            base_dir.join("profiles.json"),
            format!(r#"{{"accounts":{{}},"by_slot":{{"5":"{uuid_str}","7":"{uuid_str}"}}}}"#),
        )
        .unwrap();

        // Slot 7 active this tick (transcript + launch attribute to 7).
        fixture(
            &claude_home,
            &base_dir,
            7,
            "repo",
            "sess-shared",
            "2026-07-07T10:00:00Z",
            3_000,
            1_500,
        );

        let report = run_once(&claude_home, &base_dir, now());
        assert_eq!(report.slots_written, 1, "active slot 7 written");
        assert_eq!(
            report.slots_rolled_off, 0,
            "inactive slot 5 sharing 7's ledger must NOT be rolled off"
        );

        // The shared ledger retains slot 7's active events (not wiped).
        let slot7 = AccountNum::try_from(7u16).unwrap();
        let events = ledger::read_all(&base_dir, slot7).unwrap().events;
        assert_eq!(events.len(), 1, "active slot's events preserved");
        assert_eq!(events[0].input_tokens, 3_000);
    }

    #[tokio::test]
    async fn spawn_none_claude_home_is_noop_and_exits() {
        let dir = TempDir::new().unwrap();
        let shutdown = CancellationToken::new();
        let handle = spawn_with_config(
            dir.path().to_path_buf(),
            None,
            shutdown.clone(),
            Duration::from_millis(10),
            now,
        );
        // With no claude_home the task returns immediately without ticking.
        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("no-op writer must exit promptly")
            .unwrap();
    }

    #[tokio::test]
    async fn spawn_ticks_immediately_then_honors_shutdown() {
        let home = TempDir::new().unwrap();
        let claude_home = home.path().join(".claude");
        let base_dir = claude_home.join("accounts");
        fixture(
            &claude_home,
            &base_dir,
            11,
            "repo",
            "sess-a",
            "2026-07-07T10:00:00Z",
            10_000,
            5_000,
        );
        let shutdown = CancellationToken::new();
        let handle = spawn_with_config(
            base_dir.clone(),
            Some(claude_home.clone()),
            shutdown.clone(),
            Duration::from_secs(3600), // long: only the immediate first tick fires
            now,
        );

        // Poll for the first (immediate) tick to publish the ledger.
        let slot = AccountNum::try_from(11u16).unwrap();
        let mut wrote = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if ledger::read_all(&base_dir, slot)
                .map(|r| !r.events.is_empty())
                .unwrap_or(false)
            {
                wrote = true;
                break;
            }
        }
        assert!(wrote, "first tick must publish the ledger immediately");

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("writer must exit on shutdown")
            .unwrap();
    }
}
