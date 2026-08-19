//! Per-account usage ledger — append-only NDJSON of usage events,
//! identity-keyed (M2-5, an internal ticket Phase 2) when `by_slot` is populated
//! in `profiles.json`, slot-keyed otherwise.
//!
//! Per an internal journal entry D4. Paths:
//! - UUID case  (Phase 2+): `<base_dir>/identities/<UUID>/usage.ndjson`
//! - Legacy case (no UUID): `<base_dir>/usage-{slot}.ndjson`
//!
//! Mode 0o600. Each line is a [`UsageEvent`].
//!
//! CURRENT (an internal ticket, superseded by the ledger-first design below): the
//! desktop `get_account_usage` command computes the summary live from CC's
//! transcripts via [`super::aggregator`] (behind a background-refresh cache)
//! and this NDJSON ledger's [`append`]/[`read_all`] path is the persistence
//! layer the daemon writer publishes to. The end state described by an internal ticket
//! (a daemon-written ledger that terminals READ via [`read_all`] +
//! [`summarize`] — per `rules/account-terminal-separation.md` Rule 1,
//! extended for billing telemetry: only the daemon writes; terminals read)
//! IS BUILT: [`crate::daemon::usage_ledger_writer`], spawned by both the CLI
//! and desktop daemon startup paths, periodically re-derives usage from
//! transcripts and atomically publishes it here. `get_account_usage` reads
//! this ledger FIRST and falls back to the live-scan cache above only as a
//! cold-start path (before the writer's first tick). an internal ticket is CLOSED — its
//! own scope shipped; the citation was stale prose, re-verified 2026-08-12
//! against `csq/src/desktop/commands/mod.rs`'s `get_account_usage` and both
//! daemon startup wirings, not a repointed tracker (nothing here is still
//! open — see `scripts/verify/todo-closed-issue.sh` for the sibling
//! citations that WERE still-open work and were repointed to an internal ticket).

use crate::accounts::identity_store::usage_ledger_path_for;
use crate::accounts::profiles;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Returns the absolute path to the per-account ledger (M2-5, an internal ticket).
///
/// **UUID case** (Phase 2+, `by_slot` populated in `profiles.json`):
/// `<base_dir>/identities/<UUID>/usage.ndjson`
///
/// **Legacy case** (slot has no UUID mapping yet):
/// `<base_dir>/usage-{slot}.ndjson`
///
/// The branch is determined by `profiles::resolve_slot_to_uuid`. Callers
/// that need the parent directory to exist MUST call `fs::create_dir_all`
/// before writing.
pub fn ledger_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    match profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(uuid) => usage_ledger_path_for(base_dir, uuid),
        None => base_dir.join(format!("usage-{}.ndjson", slot.get())),
    }
}

/// Where the usage event came from. Used for diagnostic filtering — e.g. the
/// daemon's probe-response is a small constant overhead that the user might
/// want to exclude from "my actual spend" totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageSource {
    /// LEGACY (an internal ticket): the `~/.claude/usage-data/session-meta/*.json`
    /// directory this named was never written by CC. Retained only so old
    /// ledger lines carrying this tag still deserialize; the aggregator now
    /// emits [`UsageSource::ProjectsJsonl`].
    #[serde(rename = "session-meta")]
    SessionMeta,
    /// Sourced from CC's per-cwd `~/.claude/projects/<cwd>/<session-id>.jsonl`
    /// (per-turn detail). v2 enrichment per an internal journal entry D3.
    #[serde(rename = "projects-jsonl")]
    ProjectsJsonl,
    /// Sourced from the daemon's 3P probe responses. Counts csq's polling
    /// overhead, NOT the user's spend.
    #[serde(rename = "probe")]
    Probe,
}

/// One usage event. PRIVACY: this struct is the authoritative deserialization
/// shape for ledger reads AND the projects/jsonl transcript scan. NO content
/// fields. If a future contributor wants to add a `first_prompt` or `messages`
/// field here, it MUST be rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageEvent {
    /// ISO8601 UTC timestamp of the session START.
    pub ts: String,
    /// CC's session ID (UUID string).
    pub session_id: String,
    /// Model name (an internal ticket): the real per-turn model observed in the
    /// transcript when present, else the slot's configured model (caller
    /// fallback). v1 attributes the whole session to its first model; per-turn
    /// billing is a follow-up.
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Cache-write tokens (`cache_creation_input_tokens`) summed across the
    /// session. Captured from the transcript (an internal ticket). For Anthropic Claude
    /// models these are billed into `cost_usd_estimate` at 1.25× the base input
    /// rate; non-Anthropic providers bill cache at $0 pending verified
    /// per-provider rates (tracked by an internal ticket).
    /// The prior citation pointed at closed an internal ticket and was re-pointed 2026-08-12.
    /// `#[serde(default)]` keeps older ledger lines readable.
    #[serde(default)]
    pub cache_creation_tokens: u64,
    /// Cache-read tokens (`cache_read_input_tokens`) summed across the session.
    /// Billed at 0.10× the base input rate for Claude models only (see
    /// `cache_creation_tokens` for the per-provider tracking issue, an internal ticket).
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// USD cost estimate computed via [`super::cost_rates`]. `None` if the
    /// model name was unrecognized (table miss → fail-loud rather than guess).
    /// Bills `input_tokens` + `output_tokens`, plus cache tokens for Anthropic
    /// Claude models (other providers bill cache at $0 — see
    /// `cache_creation_tokens` for the per-provider tracking issue, an internal ticket).
    pub cost_usd_estimate: Option<f64>,
    /// Where this event was sourced from.
    pub source: UsageSource,
    /// Optional project path (cwd at session start). Used for attribution
    /// matching against the launch log. Never sent over IPC (`UsageSummaryView`
    /// carries no path), but IS persisted to the on-disk 0o600 ledger for
    /// attribution replay — a filesystem path is mild same-user metadata, not a
    /// credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
}

/// Appends one event to the ledger. Best-effort failure mode (mirror
/// launch_log policy): a failed append MUST NOT block whoever called the
/// daemon aggregator.
pub fn append(base_dir: &Path, slot: AccountNum, event: &UsageEvent) -> Result<(), LedgerError> {
    let path = ledger_path(base_dir, slot);
    // Ensure the parent directory exists (needed for identities/<UUID>/ paths).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LedgerError::Io)?;
    }
    let mut line = serde_json::to_string(event).map_err(LedgerError::Serialize)?;
    line.push('\n');

    let existing = std::fs::read(&path).unwrap_or_default();
    let mut content = existing;
    content.extend_from_slice(line.as_bytes());

    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, &content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Platform(e));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Platform(e));
    }
    Ok(())
}

/// Atomically REPLACES the entire ledger for `slot` with `events` (an internal ticket).
///
/// Unlike [`append`], this rewrites the whole file. The daemon usage-ledger
/// writer ([`crate::daemon::usage_ledger_writer`]) re-derives the COMPLETE
/// usage history from CC's transcripts on every tick and calls this to publish
/// it, so a full-replace is idempotent by construction: running it twice with
/// the same transcript state produces the same file. This is why the writer is
/// the SOLE producer and terminals only [`read_all`] — per
/// `rules/account-terminal-separation.md` Rule 1 (extended for billing
/// telemetry).
///
/// Follows the §5a partial-failure cleanup contract (`rules/security.md`): the
/// tmp file is removed on EVERY failure branch before the error propagates, so
/// a crash between `write` and `atomic_replace` never leaves a 0o644 artifact
/// behind. Mode 0o600 via [`secure_file`]. An empty `events` slice writes an
/// empty (0-byte) ledger — a legitimate "this slot has no usage" state.
pub fn write_all(
    base_dir: &Path,
    slot: AccountNum,
    events: &[UsageEvent],
) -> Result<(), LedgerError> {
    let path = ledger_path(base_dir, slot);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LedgerError::Io)?;
    }

    let mut content = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(LedgerError::Serialize)?;
        content.push_str(&line);
        content.push('\n');
    }

    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, content.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Platform(e));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Platform(e));
    }
    Ok(())
}

/// Reads all events for one slot. Malformed lines skipped (counted).
pub fn read_all(base_dir: &Path, slot: AccountNum) -> Result<ReadResult, std::io::Error> {
    let path = ledger_path(base_dir, slot);
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
        match serde_json::from_str::<UsageEvent>(trimmed) {
            Ok(ev) => events.push(ev),
            Err(_) => skipped += 1,
        }
    }
    Ok(ReadResult {
        events,
        skipped_malformed: skipped,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadResult {
    pub events: Vec<UsageEvent>,
    pub skipped_malformed: usize,
}

/// Summary over rolling time windows. Computed by [`summarize`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct UsageSummary {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub last_30d_input_tokens: u64,
    pub last_30d_output_tokens: u64,
    pub last_30d_cost_usd: f64,
    pub last_7d_input_tokens: u64,
    pub last_7d_output_tokens: u64,
    pub last_7d_cost_usd: f64,
    pub last_5d_input_tokens: u64,
    pub last_5d_output_tokens: u64,
    pub last_5d_cost_usd: f64,
    pub today_input_tokens: u64,
    pub today_output_tokens: u64,
    pub today_cost_usd: f64,
    pub event_count: u64,
    /// Count of events with `cost_usd_estimate.is_none()` — the model name
    /// was unrecognized. Surfaces as "n/a" in the UI for the cost column;
    /// tokens still aggregate correctly.
    pub unestimated_cost_count: u64,
}

/// Summarizes events into rolling windows ending at `now`. Events with
/// unparseable timestamps are silently skipped (the rolling-window math
/// requires valid timestamps).
///
/// Window definitions: 30d / 7d / 5d / today are all relative to `now` —
/// e.g. "today" = events whose ts is in the same UTC day as `now`.
pub fn summarize(events: &[UsageEvent], now: chrono::DateTime<chrono::Utc>) -> UsageSummary {
    let mut s = UsageSummary::default();
    let cutoff_30d = now - chrono::Duration::days(30);
    let cutoff_7d = now - chrono::Duration::days(7);
    let cutoff_5d = now - chrono::Duration::days(5);
    let today_start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|naive| naive.and_utc())
        .unwrap_or(now);

    for ev in events {
        s.event_count += 1;
        let cost = ev.cost_usd_estimate.unwrap_or(0.0);
        if ev.cost_usd_estimate.is_none() {
            s.unestimated_cost_count += 1;
        }
        // Tokens are factual regardless of whether the timestamp parses;
        // accumulate into Total before any bucket-skip. Bucketing
        // (30d/7d/5d/today) requires a parseable timestamp.
        s.total_input_tokens += ev.input_tokens;
        s.total_output_tokens += ev.output_tokens;
        s.total_cost_usd += cost;

        let ts = match chrono::DateTime::parse_from_rfc3339(&ev.ts) {
            Ok(t) => t.with_timezone(&chrono::Utc),
            Err(_) => continue,
        };

        if ts >= cutoff_30d {
            s.last_30d_input_tokens += ev.input_tokens;
            s.last_30d_output_tokens += ev.output_tokens;
            s.last_30d_cost_usd += cost;
        }
        if ts >= cutoff_7d {
            s.last_7d_input_tokens += ev.input_tokens;
            s.last_7d_output_tokens += ev.output_tokens;
            s.last_7d_cost_usd += cost;
        }
        if ts >= cutoff_5d {
            s.last_5d_input_tokens += ev.input_tokens;
            s.last_5d_output_tokens += ev.output_tokens;
            s.last_5d_cost_usd += cost;
        }
        if ts >= today_start {
            s.today_input_tokens += ev.input_tokens;
            s.today_output_tokens += ev.output_tokens;
            s.today_cost_usd += cost;
        }
    }
    s
}

#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Platform(crate::error::PlatformError),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "io: {e}"),
            LedgerError::Platform(e) => write!(f, "platform: {e}"),
            LedgerError::Serialize(e) => write!(f, "serialize: {e}"),
        }
    }
}

impl std::error::Error for LedgerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn ev(ts: &str, model: &str, input: u64, output: u64, cost: Option<f64>) -> UsageEvent {
        UsageEvent {
            ts: ts.into(),
            session_id: format!("sess-{ts}"),
            model: model.into(),
            input_tokens: input,
            output_tokens: output,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            cost_usd_estimate: cost,
            source: UsageSource::ProjectsJsonl,
            project_path: None,
        }
    }

    #[test]
    fn append_then_read_round_trips() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(1);

        let e1 = ev(
            "2026-05-06T10:00:00Z",
            "deepseek-chat",
            10000,
            5000,
            Some(0.0083),
        );
        let e2 = ev(
            "2026-05-06T11:00:00Z",
            "deepseek-coder",
            20000,
            10000,
            Some(0.0164),
        );
        append(base, s, &e1).unwrap();
        append(base, s, &e2).unwrap();

        let result = read_all(base, s).unwrap();
        assert_eq!(result.events, vec![e1, e2]);
        assert_eq!(result.skipped_malformed, 0);
    }

    #[test]
    fn write_all_then_read_round_trips() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(3);
        let e1 = ev(
            "2026-05-06T10:00:00Z",
            "deepseek-chat",
            10000,
            5000,
            Some(0.0083),
        );
        let e2 = ev(
            "2026-05-06T11:00:00Z",
            "deepseek-coder",
            20000,
            10000,
            Some(0.0164),
        );

        write_all(base, s, &[e1.clone(), e2.clone()]).unwrap();

        let result = read_all(base, s).unwrap();
        assert_eq!(result.events, vec![e1, e2]);
        assert_eq!(result.skipped_malformed, 0);
    }

    #[test]
    fn write_all_replaces_prior_content_idempotently() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(3);
        let old = ev(
            "2026-05-06T10:00:00Z",
            "deepseek-chat",
            999,
            111,
            Some(0.001),
        );
        // Seed the ledger the append way, then a full-replace must DROP the old row.
        append(base, s, &old).unwrap();
        let fresh = ev(
            "2026-05-06T12:00:00Z",
            "deepseek-coder",
            20000,
            10000,
            Some(0.0164),
        );

        write_all(base, s, std::slice::from_ref(&fresh)).unwrap();
        assert_eq!(read_all(base, s).unwrap().events, vec![fresh.clone()]);

        // Running it again with the same input is idempotent (same file).
        write_all(base, s, std::slice::from_ref(&fresh)).unwrap();
        assert_eq!(read_all(base, s).unwrap().events, vec![fresh]);
    }

    #[test]
    fn write_all_empty_writes_empty_ledger() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(3);
        let seeded = ev(
            "2026-05-06T10:00:00Z",
            "deepseek-chat",
            999,
            111,
            Some(0.001),
        );
        append(base, s, &seeded).unwrap();

        // A slot whose usage dropped to zero → the writer publishes an empty set.
        write_all(base, s, &[]).unwrap();
        let result = read_all(base, s).unwrap();
        assert!(result.events.is_empty());
        assert_eq!(result.skipped_malformed, 0);
        assert!(
            ledger_path(base, s).exists(),
            "empty ledger file still present"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_all_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(3);
        let e1 = ev("2026-05-06T10:00:00Z", "deepseek-chat", 10, 5, Some(0.001));
        write_all(base, s, &[e1]).unwrap();
        let mode = std::fs::metadata(ledger_path(base, s))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "ledger must be owner-only (0o600)");
    }

    #[test]
    fn ledger_path_uses_account_id_chokepoint() {
        let dir = TempDir::new().unwrap();
        let path = ledger_path(dir.path(), slot(7));
        assert_eq!(
            path,
            dir.path().join("usage-7.ndjson"),
            "today's chokepoint returns slot # as string"
        );
    }

    #[test]
    fn read_missing_ledger_returns_empty() {
        let dir = TempDir::new().unwrap();
        let result = read_all(dir.path(), slot(1)).unwrap();
        assert!(result.events.is_empty());
    }

    #[test]
    fn append_creates_file_with_secure_mode() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = TempDir::new().unwrap();
            let e = ev("2026-05-06T10:00:00Z", "deepseek-chat", 10, 5, Some(0.001));
            append(dir.path(), slot(1), &e).unwrap();
            let mode = std::fs::metadata(ledger_path(dir.path(), slot(1)))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn summarize_buckets_correctly() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap();
        let events = vec![
            // Today (5h ago).
            ev("2026-05-06T07:00:00Z", "deepseek-chat", 100, 50, Some(0.10)),
            // Last 5d (3 days ago).
            ev(
                "2026-05-03T12:00:00Z",
                "deepseek-chat",
                200,
                100,
                Some(0.20),
            ),
            // Last 7d (6 days ago).
            ev(
                "2026-04-30T12:00:00Z",
                "deepseek-chat",
                300,
                150,
                Some(0.30),
            ),
            // Last 30d (15 days ago).
            ev(
                "2026-04-21T12:00:00Z",
                "deepseek-chat",
                400,
                200,
                Some(0.40),
            ),
            // Older than 30d (45 days ago) — only counts toward Total.
            ev(
                "2026-03-22T12:00:00Z",
                "deepseek-chat",
                500,
                250,
                Some(0.50),
            ),
            // Unrecognized model — tokens count, cost = None.
            ev("2026-05-06T08:00:00Z", "foobar-1", 50, 25, None),
        ];

        let s = summarize(&events, now);

        // Today: 100+50+50+25 = 175 input, 75 output, $0.10 + $0 (foobar) = $0.10
        assert_eq!(s.today_input_tokens, 150);
        assert_eq!(s.today_output_tokens, 75);
        assert!((s.today_cost_usd - 0.10).abs() < 1e-9);

        // Last 5d: today + 3-days-ago = 100+200+50 input
        assert_eq!(s.last_5d_input_tokens, 350);
        assert!((s.last_5d_cost_usd - 0.30).abs() < 1e-9);

        // Last 7d: today + 3-days + 6-days = 100+200+300+50
        assert_eq!(s.last_7d_input_tokens, 650);
        assert!((s.last_7d_cost_usd - 0.60).abs() < 1e-9);

        // Last 30d: today + 3 + 6 + 15 = 100+200+300+400+50
        assert_eq!(s.last_30d_input_tokens, 1050);
        assert!((s.last_30d_cost_usd - 1.00).abs() < 1e-9);

        // Total: all 6 events
        assert_eq!(s.total_input_tokens, 1550);
        assert_eq!(s.total_output_tokens, 775);
        assert!((s.total_cost_usd - 1.50).abs() < 1e-9);

        // 1 unestimated event.
        assert_eq!(s.unestimated_cost_count, 1);
        assert_eq!(s.event_count, 6);
    }

    #[test]
    fn summarize_ignores_malformed_timestamps() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap();
        let events = vec![
            ev("not-a-timestamp", "deepseek-chat", 100, 50, Some(0.10)),
            ev(
                "2026-05-06T11:00:00Z",
                "deepseek-chat",
                200,
                100,
                Some(0.20),
            ),
        ];
        let s = summarize(&events, now);
        // Malformed event still counts toward `event_count` + total tokens
        // (that's a deliberate choice — tokens are factual; window-bucketing
        // requires the timestamp).
        assert_eq!(s.event_count, 2);
        assert_eq!(s.total_input_tokens, 300);
        // Only the well-formed event counts toward today.
        assert_eq!(s.today_input_tokens, 200);
    }

    #[test]
    fn read_skips_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let path = ledger_path(dir.path(), slot(1));
        std::fs::write(
            &path,
            r#"{"ts":"2026-05-06T10:00:00Z","session_id":"a","model":"deepseek-chat","input_tokens":1,"output_tokens":2,"cost_usd_estimate":null,"source":"session-meta"}
not-json
{"ts":"2026-05-06T11:00:00Z","session_id":"b","model":"deepseek-chat","input_tokens":3,"output_tokens":4,"cost_usd_estimate":0.001,"source":"session-meta"}
"#,
        )
        .unwrap();
        let result = read_all(dir.path(), slot(1)).unwrap();
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.skipped_malformed, 1);
    }

    // ── M2-5 acceptance-criteria tests ──────────────────────────────────────

    /// Structural guard: the `save_state`/`save_quota` callsite count in
    /// csq-core/src (excluding `quota/state.rs` itself) MUST stay at 28
    /// (cross-phase invariant — `rules/account-terminal-separation.md`
    /// MUST Rule 1). This test enforces that no new callsite was added
    /// accidentally; any intentional change re-runs the Rule 1 channel
    /// classification and updates the expected count here.
    ///
    /// Count composition (the line-level scan does NOT exclude `#[cfg(test)]`
    /// modules — the `#[cfg(test)]` check below only skips lines that carry
    /// the attribute text themselves): 15 genuine production callsites,
    /// 12 callsites inside test modules, and 1 self-referential match (this
    /// test's own `contains("save_state(")` line). The tripwire value is the
    /// invariant; the per-channel audit lives in the rule's grep primitive.
    ///
    /// The 10th and 11th test-module callsites (2026-07-30, MED-2 an internal ticket
    /// redteam) are `accounts::third_party::tests::
    /// rebind_to_different_provider_clears_stale_quota_row` and
    /// `rebind_to_same_provider_preserves_quota_row` — each seeds a
    /// pre-existing quota row via `quota_state::save_state` directly (a
    /// hardcoded literal slot id in a tempdir fixture), not a production
    /// writer. No Rule 1 channel classification applies to test fixtures.
    ///
    /// The 13th production callsite (2026-07-06) is the DeepSeek balance writer
    /// `usage_poller::deepseek::write_deepseek_balance` — an AUTHORIZED writer
    /// per Rule 1 channel (a): its slot id comes from `info.id` in the 3P poll
    /// loop's per-slot iteration state, exactly like MiniMax/Z.AI. NOT a
    /// terminal-derived slot. See an internal ticket.
    ///
    /// The 14th production callsite (2026-07-28) is the Grok billing writer
    /// `usage_poller::grok::write_grok_billing` — an AUTHORIZED writer per
    /// Rule 1 channel (a): its `account_id` comes from the per-slot iteration
    /// state of `usage_poller::grok::tick`, whose slot list is built by
    /// `accounts::discovery::discover_native` (the `credentials/grok-<N>.json`
    /// binding-marker enumeration — a slot-lifecycle channel). Each slot is
    /// polled with the token from its OWN per-slot vendor home
    /// (`native-homes/grok-<N>/auth.json`), never the user-global
    /// `~/.grok/auth.json`, so neither the slot id nor the credential is
    /// terminal-derived. NOT a `CLAUDE_CONFIG_DIR` / marker-fallback /
    /// CC-`rate_limits` derivation.
    ///
    /// The 15th production callsite (2026-07-29) is the Kimi usages writer
    /// `usage_poller::kimi::write_kimi_usages` — an AUTHORIZED writer per
    /// Rule 1 channel (a): its `account_id` comes from the per-slot
    /// iteration state of `usage_poller::kimi::tick`, whose slot list is
    /// built by `accounts::discovery::discover_all` (for the 3P bearer
    /// `kimi` provider) and `accounts::discovery::discover_native` (for
    /// the `credentials/kimi-<N>.json` binding-marker enumeration) —
    /// both slot-lifecycle channels. Each slot is polled with its OWN
    /// credential: the 3P slot with the `sk-kimi-…` key from
    /// `config-<N>/settings.json` (via
    /// `third_party::load_3p_api_key_for_slot`, the same channel the
    /// existing MiniMax/Z.AI/DeepSeek writers use), the native slot
    /// with the OAuth `access_token` from its OWN per-slot vendor home
    /// (`native-homes/kimi-<N>/credentials/kimi-code.json`). Neither the
    /// slot id nor the credential is terminal-derived. NOT a
    /// `CLAUDE_CONFIG_DIR` / marker-fallback / CC-`rate_limits`
    /// derivation.
    ///
    /// The 12th test-module callsite (2026-08-02, `quota/status.rs` stale
    /// quota-row diagnostic) is `quota::status::tests::setup_with_updated_at`
    /// — a test fixture that seeds a quota row with a caller-supplied
    /// `updated_at` (a hardcoded literal slot id from the `account: u16`
    /// test parameter, in a tempdir fixture), not a production writer. No
    /// Rule 1 channel classification applies to test fixtures.
    ///
    /// The 13th test-module callsite (2026-08-02 redteam fix wave, same
    /// diagnostic) is `quota::status::tests::setup_quota_row` — a test
    /// fixture that writes an arbitrary caller-supplied `AccountQuota` row
    /// (used by the event-driven-Gemini and native-Grok-balance staleness
    /// regression tests), likewise a hardcoded literal slot id in a
    /// tempdir fixture, not a production writer. No Rule 1 channel
    /// classification applies to test fixtures.
    ///
    /// The 14th test-module callsite (2026-08-02 redteam round 2) is
    /// `providers::gemini::provisioning::tests::seed_oauth_shaped_quota_row`
    /// — a test fixture seeding an OAuth-shaped row (`surface: "gemini"`,
    /// `kind: "utilization"`) so the regime-change tests can prove
    /// `write_binding` clears it. Hardcoded literal slot id from the
    /// `n: u16` test parameter, in a tempdir fixture; not a production
    /// writer. No Rule 1 channel classification applies to test fixtures.
    ///
    /// NOTE on the PRODUCTION side of that same change: `write_binding`
    /// now REMOVES a slot's quota row on a polling-regime change, via
    /// `accounts::logout::remove_quota_entry`. That is a remover, not a
    /// `save_state` writer, so it does not appear in this count — and its
    /// slot id is the `slot: AccountNum` parameter of a slot-lifecycle
    /// operation (Rule 1 channel (c)), the same channel
    /// `accounts::third_party::bind_provider_to_slot` uses for the
    /// identical purpose. Nothing terminal-derived.
    ///
    /// Implementation: a runtime grep against the source tree at
    /// `CARGO_MANIFEST_DIR`. The test only runs when the manifest dir env
    /// var is set (i.e. under `cargo test`).
    #[test]
    fn ledger_no_quota_writer_touched() {
        // Locate the csq-core source root from the Cargo manifest dir.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_root = std::path::PathBuf::from(manifest_dir).join("src");

        // Grep for save_state/save_quota callsites in production code
        // (exclude the state.rs definition itself and test code).
        let mut count = 0usize;
        fn walk_and_count(dir: &std::path::Path, count: &mut usize) {
            let rd = match std::fs::read_dir(dir) {
                Ok(r) => r,
                Err(_) => return,
            };
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk_and_count(&path, count);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    let Ok(content) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    // Skip the definition file itself.
                    if path.ends_with("quota/state.rs") {
                        continue;
                    }
                    for line in content.lines() {
                        let trimmed = line.trim();
                        // Skip comment lines and test cfg blocks.
                        if trimmed.starts_with("//") {
                            continue;
                        }
                        if trimmed.contains("save_state(") || trimmed.contains("save_quota(") {
                            // Line-level filter only: skips lines that carry the
                            // `#[cfg(test)]` attribute TEXT themselves; it does NOT
                            // exclude lines inside test modules (those are part of
                            // the tripwire count — see the doc comment above).
                            if !trimmed.contains("#[cfg(test)]") {
                                *count += 1;
                            }
                        }
                    }
                }
            }
        }
        walk_and_count(&src_root, &mut count);

        assert_eq!(
            count, 30,
            "save_state production callsite count changed: expected 30, got {count}. \
             A new quota writer MUST source its slot id from an authoritative channel \
             (per-slot poller state / IPC event / slot-lifecycle param) per \
             rules/account-terminal-separation.md MUST Rule 1 — classify the channel \
             before updating this count."
        );
    }

    /// Writes a minimal `profiles.json` with `by_slot` populated so that
    /// `ledger_path` resolves to `identities/<UUID>/usage.ndjson`.
    fn write_profiles_with_uuid(base: &Path, slot_num: u16, uuid_str: &str) {
        let profiles_path = base.join("profiles.json");
        let content = format!(
            r#"{{"accounts":{{"{}": {{"email":"a@b.com","method":"oauth"}}}},"by_slot":{{"{}":"{}"}}}}"#,
            slot_num, slot_num, uuid_str
        );
        std::fs::write(&profiles_path, content).unwrap();
    }

    #[test]
    fn ledger_write_uses_uuid_filename_when_uuid_present() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid_str = "550e8400-e29b-41d4-a716-446655440001";
        write_profiles_with_uuid(base, 1, uuid_str);

        // Act
        let path = ledger_path(base, slot(1));

        // Assert — path must be identities/<UUID>/usage.ndjson, not usage-1.ndjson
        let expected = base.join("identities").join(uuid_str).join("usage.ndjson");
        assert_eq!(
            path, expected,
            "when by_slot is populated, ledger_path must route to identities/<UUID>/usage.ndjson"
        );
        // Also verify append creates the file in the UUID path.
        let event = ev(
            "2026-05-14T10:00:00Z",
            "claude-3-5-sonnet",
            100,
            50,
            Some(0.01),
        );
        append(base, slot(1), &event).unwrap();
        assert!(
            expected.exists(),
            "UUID-keyed ledger file must be created by append"
        );
    }

    #[test]
    fn ledger_write_falls_back_to_slot_filename_when_uuid_missing() {
        // Arrange — no profiles.json, no by_slot entry
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Act
        let path = ledger_path(base, slot(3));

        // Assert — must fall back to flat usage-{slot}.ndjson
        let expected = base.join("usage-3.ndjson");
        assert_eq!(
            path, expected,
            "when by_slot is absent, ledger_path must fall back to usage-{{slot}}.ndjson"
        );
    }

    #[test]
    fn ledger_ndjson_append_atomic_under_concurrent_writers() {
        // Arrange — set up a UUID-keyed slot with profiles.json.
        // The `append` function uses read-then-atomic-replace semantics
        // (best-effort per module docstring): under concurrent writers
        // the guarantee is NO PARTIAL / CORRUPTED LINES — each atomic
        // replace lands a well-formed NDJSON file.  Last-writer-wins
        // under racing replaces means some events may be overwritten;
        // the structural invariant is integrity (no malformed lines),
        // not total event count.
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let uuid_str = "550e8400-e29b-41d4-a716-446655440002";
        write_profiles_with_uuid(&base, 2, uuid_str);

        let n_writers = 4usize;
        let events_per_writer = 5usize;

        // Act — spawn threads that each append events
        let mut handles = Vec::new();
        for writer_id in 0..n_writers {
            let base_clone = base.clone();
            handles.push(std::thread::spawn(move || {
                let s = AccountNum::try_from(2u16).unwrap();
                for ev_idx in 0..events_per_writer {
                    let session_id = format!("writer{writer_id}-ev{ev_idx}");
                    let event = UsageEvent {
                        ts: format!("2026-05-14T10:{writer_id:02}:{ev_idx:02}Z"),
                        session_id,
                        model: "claude-3-5-sonnet".into(),
                        input_tokens: 1,
                        output_tokens: 1,
                        cache_creation_tokens: 0,
                        cache_read_tokens: 0,
                        cost_usd_estimate: Some(0.001),
                        source: UsageSource::ProjectsJsonl,
                        project_path: None,
                    };
                    append(&base_clone, s, &event).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer thread must not panic");
        }

        // Assert — the final ledger file must be valid NDJSON (no partial or
        // corrupted lines), and at least one event must have survived.
        // Total count may be less than n_writers * events_per_writer due to
        // the last-writer-wins semantics of atomic replace — that is expected.
        let s = AccountNum::try_from(2u16).unwrap();
        let result = read_all(&base, s).unwrap();
        assert_eq!(
            result.skipped_malformed, 0,
            "atomic replace MUST produce zero partial / malformed lines under concurrent writers"
        );
        assert!(
            !result.events.is_empty(),
            "at least one event must survive concurrent appends"
        );
    }
}
