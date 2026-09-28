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

/// Serde helper: omit a `false` diagnostic flag from the written line, so the
/// an internal ticket fields cost zero bytes on the overwhelmingly common clean request.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Serde helper: omit a zero diagnostic counter for the same reason.
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One usage event. PRIVACY: this struct is the authoritative deserialization
/// shape for ledger reads AND the projects/jsonl transcript scan. NO content
/// fields. If a future contributor wants to add a `first_prompt` or `messages`
/// field here, it MUST be rejected.
///
/// GRANULARITY (an internal ticket): one event is one NORMALIZED REQUEST, not one
/// session. A session's transcript contributes as many events as it made
/// distinct API calls, each priced and bucketed at its own model and its own
/// timestamp. Before an internal ticket a session produced exactly one event carrying the
/// session's summed tokens, its FIRST model and its START time; a ledger
/// written by such a binary still deserializes here unchanged, because every
/// field added by an internal ticket is `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageEvent {
    /// ISO8601 UTC timestamp. Since an internal ticket this is the REQUEST's own earliest
    /// observed timestamp; on lines written before an internal ticket it is the session
    /// start.
    pub ts: String,
    /// CC's session ID (UUID string). Several events share one `session_id`
    /// when a session made several requests.
    pub session_id: String,
    /// Model name (an internal ticket): the real model observed on this REQUEST's own
    /// transcript records when present, else the slot's configured model
    /// (caller fallback). Since an internal ticket a session that switched models mid-run
    /// therefore produces events carrying each model it actually used, rather
    /// than attributing the whole session to its first.
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Cache-write tokens (`cache_creation_input_tokens`) summed across the
    /// session. Captured from the transcript (an internal ticket). For Anthropic Claude
    /// models these are billed into `cost_usd_estimate` at 1.25× the base input
    /// rate. Each rate row owns its cache prices; DeepSeek has a verified
    /// cache-read price but no separate cache-write price, so writes bill $0.
    /// `#[serde(default)]` keeps older ledger lines readable.
    #[serde(default)]
    pub cache_creation_tokens: u64,
    /// Cache-read tokens (`cache_read_input_tokens`) summed across the session.
    /// Billed at the rate row's own cache-read price: 0.10× base input for
    /// Claude, or DeepSeek's published cache-hit price. Unpriced dimensions
    /// contribute $0 rather than borrowing another provider's cache economics.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// USD cost estimate computed via [`super::cost_rates`]. `None` if the
    /// model name was unrecognized (table miss → fail-loud rather than guess).
    /// Bills `input_tokens` + `output_tokens`, plus cache tokens at each
    /// matched rate row's verified prices (see `cache_creation_tokens` and
    /// `cache_read_tokens`).
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
    /// How many streaming usage snapshots of this request were discarded by
    /// finalization (an internal ticket). A DIAGNOSTIC of how much double counting the
    /// pre-an internal ticket blind sum was doing on this request — never a billable
    /// quantity, and never added into any token or cost total.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub snapshots_collapsed: u64,
    /// True when this request's billed (last) snapshot differs from the
    /// per-field maximum across its snapshots — the residual where the
    /// finalization rule and a per-field max disagree. Surfaced rather than
    /// resolved; see [`crate::usage::request::RequestCollector::finish`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub finalization_divergent: bool,
    /// True when this request was read from a `<session>/subagents/*.jsonl`
    /// file rather than the parent-level transcript.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_subagent: bool,
    /// True when neither `requestId` nor `message.id` was present, so this
    /// record was billed on its own instead of being merged with its siblings.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unidentified: bool,
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
///
/// ## Token dimensions are DISJOINT (an internal ticket)
///
/// The four token dimensions — input, output, cache-creation, cache-read —
/// come from four separate `message.usage` fields that CC reports side by side,
/// so a cache-INCLUSIVE total for a window is the sum of that window's four
/// fields and counts nothing twice. `*_input_tokens` is NOT cache-inclusive: it
/// is the non-cached input alone. Before an internal ticket only two of the four reached
/// this struct, which is why the displayed totals omitted cached input even
/// though [`UsageEvent`] had carried both cache fields since an internal ticket.
///
/// Every field added by an internal ticket is additive and `#[serde(default)]`, so an
/// envelope produced by an older binary still deserializes.
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

    // ── an internal ticket: cache dimensions, per window ────────────────────────────────
    /// Cache-WRITE tokens (`cache_creation_input_tokens`), all time.
    #[serde(default)]
    pub total_cache_creation_tokens: u64,
    /// Cache-READ tokens (`cache_read_input_tokens`), all time.
    #[serde(default)]
    pub total_cache_read_tokens: u64,
    #[serde(default)]
    pub last_30d_cache_creation_tokens: u64,
    #[serde(default)]
    pub last_30d_cache_read_tokens: u64,
    #[serde(default)]
    pub last_7d_cache_creation_tokens: u64,
    #[serde(default)]
    pub last_7d_cache_read_tokens: u64,
    #[serde(default)]
    pub last_5d_cache_creation_tokens: u64,
    #[serde(default)]
    pub last_5d_cache_read_tokens: u64,
    #[serde(default)]
    pub today_cache_creation_tokens: u64,
    #[serde(default)]
    pub today_cache_read_tokens: u64,

    // ── an internal ticket: coverage diagnostics. NONE of these is a billable quantity. ──
    /// Number of normalized requests in the ledger. Equal to `event_count` for
    /// any ledger published after an internal ticket, because one event IS one request
    /// there; it is named separately so a consumer can label the figure without
    /// relying on that equality holding for a ledger an older binary wrote.
    #[serde(default)]
    pub request_count: u64,
    /// Total streaming snapshots discarded by finalization across all requests
    /// — how much repeated counting the pre-an internal ticket blind sum was doing.
    #[serde(default)]
    pub duplicate_snapshots_collapsed: u64,
    /// Requests whose billed (last) snapshot differs from the per-field maximum
    /// across their snapshots. The measured residual of the finalization rule,
    /// reported instead of resolved.
    #[serde(default)]
    pub finalization_divergent_requests: u64,
    /// Requests read from `<session>/subagents/*.jsonl` rather than the
    /// parent-level transcript. Before an internal ticket the scanner never opened those
    /// files, so this was structurally zero and the usage was simply missing.
    #[serde(default)]
    pub subagent_request_count: u64,
    /// Requests that carried neither `requestId` nor `message.id` and were
    /// therefore billed per record rather than per request.
    #[serde(default)]
    pub unidentified_request_count: u64,
}

/// Summarizes events into rolling windows ending at `now`. An event whose
/// timestamp does not parse still contributes its tokens and cost to the
/// all-time totals — tokens are factual — but is excluded from every rolling
/// window, which needs a timestamp to place it.
///
/// Window definitions: 30d / 7d / 5d are rolling cutoffs relative to `now`;
/// "today" is the UTC calendar day containing `now`. None of these is a
/// provider billing period: a vendor portal that reports GMT+8 calendar days
/// is answering a different question and will not equal these figures.
///
/// Since an internal ticket the unit is a normalized REQUEST, so each event lands in the
/// window containing its OWN timestamp rather than its session's start — a
/// long session that straddles a cutoff now splits across the two windows
/// instead of landing wholly in the earlier one.
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
        s.request_count += 1;
        let cost = ev.cost_usd_estimate.unwrap_or(0.0);
        if ev.cost_usd_estimate.is_none() {
            s.unestimated_cost_count += 1;
        }
        // Coverage diagnostics (an internal ticket). These describe how the figures were
        // derived; none of them is added into a token or cost total.
        s.duplicate_snapshots_collapsed += ev.snapshots_collapsed;
        s.finalization_divergent_requests += u64::from(ev.finalization_divergent);
        s.subagent_request_count += u64::from(ev.from_subagent);
        s.unidentified_request_count += u64::from(ev.unidentified);

        // Tokens are factual regardless of whether the timestamp parses;
        // accumulate into Total before any bucket-skip. Bucketing
        // (30d/7d/5d/today) requires a parseable timestamp.
        s.total_input_tokens += ev.input_tokens;
        s.total_output_tokens += ev.output_tokens;
        s.total_cache_creation_tokens += ev.cache_creation_tokens;
        s.total_cache_read_tokens += ev.cache_read_tokens;
        s.total_cost_usd += cost;

        let ts = match chrono::DateTime::parse_from_rfc3339(&ev.ts) {
            Ok(t) => t.with_timezone(&chrono::Utc),
            Err(_) => continue,
        };

        if ts >= cutoff_30d {
            s.last_30d_input_tokens += ev.input_tokens;
            s.last_30d_output_tokens += ev.output_tokens;
            s.last_30d_cache_creation_tokens += ev.cache_creation_tokens;
            s.last_30d_cache_read_tokens += ev.cache_read_tokens;
            s.last_30d_cost_usd += cost;
        }
        if ts >= cutoff_7d {
            s.last_7d_input_tokens += ev.input_tokens;
            s.last_7d_output_tokens += ev.output_tokens;
            s.last_7d_cache_creation_tokens += ev.cache_creation_tokens;
            s.last_7d_cache_read_tokens += ev.cache_read_tokens;
            s.last_7d_cost_usd += cost;
        }
        if ts >= cutoff_5d {
            s.last_5d_input_tokens += ev.input_tokens;
            s.last_5d_output_tokens += ev.output_tokens;
            s.last_5d_cache_creation_tokens += ev.cache_creation_tokens;
            s.last_5d_cache_read_tokens += ev.cache_read_tokens;
            s.last_5d_cost_usd += cost;
        }
        if ts >= today_start {
            s.today_input_tokens += ev.input_tokens;
            s.today_output_tokens += ev.output_tokens;
            s.today_cache_creation_tokens += ev.cache_creation_tokens;
            s.today_cache_read_tokens += ev.cache_read_tokens;
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
            snapshots_collapsed: 0,
            finalization_divergent: false,
            from_subagent: false,
            unidentified: false,
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

    /// an internal ticket: cache dimensions reach every window exactly once, and the four
    /// dimensions stay disjoint. Falsifying result: any cache field at 0 (the
    /// pre-an internal ticket omission), or `total_input_tokens` inflated by the cache
    /// counts (double counting in the other direction).
    #[test]
    fn summarize_buckets_cache_dimensions_into_every_window_exactly_once() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap();
        let mut today = ev(
            "2026-05-06T07:00:00Z",
            "claude-opus-4-8",
            100,
            50,
            Some(0.10),
        );
        today.cache_creation_tokens = 7_000;
        today.cache_read_tokens = 90_000;
        let mut older = ev(
            "2026-03-22T12:00:00Z",
            "claude-opus-4-8",
            200,
            60,
            Some(0.20),
        );
        older.cache_creation_tokens = 3_000;
        older.cache_read_tokens = 10_000;

        let s = summarize(&[today, older], now);

        // Today's window carries only today's cache tokens.
        assert_eq!(s.today_cache_creation_tokens, 7_000);
        assert_eq!(s.today_cache_read_tokens, 90_000);
        // 5d / 7d / 30d all contain today's event and not the 45-day-old one.
        for (created, read, label) in [
            (
                s.last_5d_cache_creation_tokens,
                s.last_5d_cache_read_tokens,
                "5d",
            ),
            (
                s.last_7d_cache_creation_tokens,
                s.last_7d_cache_read_tokens,
                "7d",
            ),
            (
                s.last_30d_cache_creation_tokens,
                s.last_30d_cache_read_tokens,
                "30d",
            ),
        ] {
            assert_eq!(created, 7_000, "{label} cache-creation counted once");
            assert_eq!(read, 90_000, "{label} cache-read counted once");
        }
        // Totals span both events.
        assert_eq!(s.total_cache_creation_tokens, 10_000);
        assert_eq!(s.total_cache_read_tokens, 100_000);
        // Dimensions stay disjoint: input is non-cached input alone.
        assert_eq!(s.total_input_tokens, 300);
        assert_eq!(s.total_output_tokens, 110);
    }

    /// The coverage diagnostics total across events and never enter any token
    /// or cost figure. Falsifying result: `total_input_tokens` moving when only
    /// a diagnostic flag changes.
    #[test]
    fn summarize_totals_coverage_diagnostics_without_touching_tokens_or_cost() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap();
        let plain = ev(
            "2026-05-06T07:00:00Z",
            "claude-opus-4-8",
            100,
            50,
            Some(0.10),
        );

        let mut flagged = plain.clone();
        flagged.snapshots_collapsed = 4;
        flagged.finalization_divergent = true;
        flagged.from_subagent = true;
        flagged.unidentified = true;

        let baseline = summarize(std::slice::from_ref(&plain), now);
        let s = summarize(&[plain, flagged], now);

        assert_eq!(s.duplicate_snapshots_collapsed, 4);
        assert_eq!(s.finalization_divergent_requests, 1);
        assert_eq!(s.subagent_request_count, 1);
        assert_eq!(s.unidentified_request_count, 1);
        assert_eq!(s.request_count, 2);
        assert_eq!(s.event_count, s.request_count);
        // Exactly two events' worth of tokens and cost — the flags added none.
        assert_eq!(s.total_input_tokens, baseline.total_input_tokens * 2);
        assert_eq!(s.total_output_tokens, baseline.total_output_tokens * 2);
        assert!((s.total_cost_usd - baseline.total_cost_usd * 2.0).abs() < 1e-9);
    }

    /// A ledger line written before an internal ticket carries none of the new keys and MUST
    /// still deserialize, with the diagnostics defaulting to "nothing to
    /// report". Falsifying result: a deserialization error, which would make
    /// the whole pre-existing ledger read as malformed and drop the user's
    /// history.
    #[test]
    fn pre_1573_ledger_lines_still_deserialize_with_defaulted_diagnostics() {
        let dir = TempDir::new().unwrap();
        let path = ledger_path(dir.path(), slot(1));
        std::fs::write(
            &path,
            r#"{"ts":"2026-05-06T10:00:00Z","session_id":"a","model":"claude-opus-4-8","input_tokens":10,"output_tokens":2,"cost_usd_estimate":0.5,"source":"projects-jsonl"}
"#,
        )
        .unwrap();
        let result = read_all(dir.path(), slot(1)).unwrap();
        assert_eq!(result.skipped_malformed, 0);
        assert_eq!(result.events.len(), 1);
        let e = &result.events[0];
        assert_eq!(e.input_tokens, 10);
        assert_eq!(e.snapshots_collapsed, 0);
        assert!(!e.finalization_divergent);
        assert!(!e.from_subagent);
        assert!(!e.unidentified);
    }

    /// A clean request costs zero extra ledger bytes: the four diagnostic keys
    /// are skipped when they carry nothing. Falsifying result: any of the four
    /// key names appearing in the written line.
    #[test]
    fn clean_events_omit_the_diagnostic_keys_from_the_written_line() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let s = slot(5);
        write_all(base, s, &[ev("2026-05-06T10:00:00Z", "m", 1, 2, Some(0.1))]).unwrap();
        let written = std::fs::read_to_string(ledger_path(base, s)).unwrap();
        for key in [
            "snapshots_collapsed",
            "finalization_divergent",
            "from_subagent",
            "unidentified",
        ] {
            assert!(
                !written.contains(key),
                "clean line must omit {key}, got: {written}"
            );
        }
        // And a flagged one DOES carry them, so the omission is conditional on
        // the value and not on the field being unserialized entirely.
        let mut flagged = ev("2026-05-06T10:00:00Z", "m", 1, 2, Some(0.1));
        flagged.from_subagent = true;
        write_all(base, s, &[flagged]).unwrap();
        assert!(std::fs::read_to_string(ledger_path(base, s))
            .unwrap()
            .contains("from_subagent"));
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
    /// csq-core/src (excluding `quota/state.rs` itself) MUST stay at 32
    /// (cross-phase invariant — `rules/account-terminal-separation.md`
    /// MUST Rule 1). This test enforces that no new callsite was added
    /// accidentally; any intentional change re-runs the Rule 1 channel
    /// classification and updates the expected count here.
    ///
    /// COUNT COMPOSITION, re-enumerated 2026-09-16 (the line-level scan does
    /// NOT exclude `#[cfg(test)]` modules — the `#[cfg(test)]` check below only
    /// skips lines carrying the attribute text themselves):
    ///
    /// - **16 production callsites**, every one on an authorized slot-id
    ///   channel. Channel (a), per-slot poller iteration state — thirteen:
    ///   `usage_poller::{zai,minimax,grok,deepseek,gemini_oauth,kimi}` one
    ///   each, `usage_poller::third_party` one, `usage_poller::anthropic` two
    ///   (the quota write and `record_poll_failure`), `usage_poller::codex`
    ///   two, and `usage_poller::gemini` two (its drain and its event write).
    ///   Channel (b), an IPC event payload validated at the daemon boundary —
    ///   one: `daemon::server`'s Gemini event handler. Channel (c), an explicit
    ///   slot argument to a slot-lifecycle operation — two:
    ///   `accounts::logout` and `accounts::move_slot`. None derives its slot id
    ///   from a marker read, a `CLAUDE_CONFIG_DIR` parse, or CC's per-terminal
    ///   `rate_limits` JSON, so none is terminal-attribution.
    /// - **15 test-module callsites** — fixtures in
    ///   `providers::gemini::provisioning`, `daemon::startup_reconciler`,
    ///   `daemon::auto_rotate`, `usage_poller::{third_party,codex,gemini}`,
    ///   `accounts::{logout,third_party}` (two), `quota::status` (three),
    ///   `quota` (two) and `rotation::picker`. Each seeds a quota row with a
    ///   hardcoded literal slot id in a tempdir; no Rule 1 channel
    ///   classification applies to test fixtures.
    /// - **1 self-referential match** — this test's own
    ///   `contains("save_state(")` line.
    ///
    /// 16 + 15 + 1 = 32. The tripwire value is the invariant; the per-channel
    /// audit lives in the rule's grep primitive, which is what produced the
    /// enumeration above rather than a reading of this comment.
    ///
    /// HISTORY: this constant read 31 while the tree held 32, so the test was
    /// RED at `7b6b222c` — before the first tool call of the session that fixed
    /// it — and its prose still described a 15-production / 12-test split that
    /// had not matched the tree for some time. Both were corrected together by
    /// re-running the enumeration rather than by moving the number: the point
    /// of the guard is the classification, and a count updated without one is
    /// a rubber stamp. Spec 04 §4.2.2 independently records 16 production
    /// callsites as of 2026-09-13, which the enumeration above agrees with.
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
            count, 32,
            "save_state production callsite count changed: expected 32, got {count}. \
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
                        snapshots_collapsed: 0,
                        finalization_divergent: false,
                        from_subagent: false,
                        unidentified: false,
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
