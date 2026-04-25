//! Gemini event-driven quota consumer.
//!
//! Unlike the Anthropic / Codex / 3P pollers in sibling modules, this
//! consumer never makes an HTTP request — Google exposes no public
//! quota endpoint for AI Studio API keys. Instead, csq-cli emits
//! [`EventEnvelope`]s on every spawn, response, 429, and ToS-guard
//! event; the daemon receives them via two paths:
//!
//! - **Live IPC:** csq-cli `POST /api/gemini/event` to the daemon
//!   socket. Same-session latency path.
//! - **NDJSON drain:** csq-cli writes every event to
//!   `~/.claude/accounts/gemini-events-<slot>.ndjson` (durability
//!   floor) BEFORE attempting IPC. The daemon drains the log on
//!   startup + every poll tick. Survives daemon-down windows.
//!
//! Per spec 05 §5.8.1, the same `id` arriving via both paths applies
//! at most once — the [`AppliedSet`] is the dedup ledger.
//!
//! # Drain discipline (spec 05 §5.8.1)
//!
//! On each tick, for every `gemini-events-<N>.ndjson`:
//!
//! 1. Acquire the per-slot advisory lock ([`platform::lock`]). If
//!    contended, skip — never block.
//! 2. Read the file to EOF. Parse each line as an [`EventEnvelope`].
//! 3. For each event with `v == EVENT_SCHEMA_VERSION` and `id` not
//!    already in [`AppliedSet`], apply to `quota.json` (under the
//!    per-slot mutex shared with the IPC handler) and insert `id`.
//! 4. After successful apply of ALL lines, truncate the file. On any
//!    parse error, quarantine the file as
//!    `gemini-events-<N>.corrupt.<unix_ms>` and start fresh.
//!
//! [`platform::lock`]: crate::platform::lock

use crate::providers::gemini::capture::{
    EventEnvelope, EventKind, EVENT_SCHEMA_VERSION, EVENT_SURFACE_GEMINI,
};
use crate::quota::state as quota_state;
use crate::quota::{AccountQuota, CounterState, QuotaFile, RateLimitState};
use crate::types::AccountNum;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Maximum entries in the dedup [`AppliedSet`] before LRU-style
/// eviction kicks in. UUIDv7 ordering makes dedup a sliding window —
/// older IDs cannot reappear because file order matches generation
/// order. Bound chosen so 16 k events of recent history is enough to
/// dedup across any realistic IPC + drain ordering window.
pub const APPLIED_SET_CAPACITY: usize = 16_384;

/// Number of consecutive `quota_schema_drift` events that flips the
/// slot's `kind` to `"unknown"` per the spec 05 §5.8 circuit breaker.
pub const SCHEMA_DRIFT_BREAKER_THRESHOLD: u32 = 5;

/// Number of mismatched-effective-model observations within
/// [`DOWNGRADE_DEBOUNCE_WINDOW`] that latches `is_downgrade = true`
/// per ADR-G06.
pub const DOWNGRADE_DEBOUNCE_THRESHOLD: u32 = 3;

/// Bounded ledger of applied event IDs. UUIDv7 IDs are monotonic by
/// emission time, so a FIFO eviction at capacity is correct: an
/// evicted ID is older than every ID still present, and older IDs
/// cannot reappear (file-order dedup).
#[derive(Debug, Default)]
pub struct AppliedSet {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl AppliedSet {
    /// Returns true if `id` was newly inserted; false if it was
    /// already present (duplicate event).
    pub fn insert(&mut self, id: String) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.order.len() >= APPLIED_SET_CAPACITY {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        self.order.push_back(id.clone());
        self.set.insert(id);
        true
    }

    /// Returns true if `id` is in the dedup ledger.
    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Per-slot circuit-breaker state for schema-drift detection.
/// `consecutive_drifts` resets to 0 on any successful (non-drift)
/// event apply.
#[derive(Debug, Default, Clone)]
pub struct BreakerState {
    pub consecutive_drifts: u32,
}

/// Where the envelope arrived from. Drives the schema-drift breaker
/// gate per PR-G3 redteam M3 — only NDJSON events trip the breaker
/// because they represent csq-cli observations of real malformed
/// responses; live IPC events from a same-UID caller cannot be
/// trusted to drive a structural state-flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    /// Envelope was drained from a `gemini-events-<slot>.ndjson`
    /// file. csq-cli emitted it after observing a real response.
    Drain,
    /// Envelope arrived via the live `POST /api/gemini/event` route.
    /// Same-UID isolation only — not trusted for breaker mutation.
    Ipc,
}

/// Daemon-wide consumer state. Cloned cheaply (every field is an
/// `Arc`) for sharing between the drain task, the live IPC route
/// handler, and the midnight-LA reset task.
#[derive(Clone, Default)]
pub struct GeminiConsumerState {
    /// Dedup ledger spanning live IPC + NDJSON drain.
    pub applied: Arc<Mutex<AppliedSet>>,
    /// Per-slot drift breaker.
    pub breakers: Arc<Mutex<std::collections::HashMap<u16, BreakerState>>>,
    /// Process-wide quota.json mutex. Held across read-modify-write so
    /// the IPC + drain paths can never lose updates to each other. Per
    /// spec 05 §5.8.1: "single-writer-to-quota.json invariant
    /// preserved across IPC path AND NDJSON drain path".
    pub quota_lock: Arc<Mutex<()>>,
}

/// Outcome of a single drain pass over one slot's NDJSON file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    pub applied: usize,
    pub deduped: usize,
    pub quarantined: bool,
}

/// Errors raised by drain operations. Fixed-vocabulary so log queries
/// can disambiguate failure modes.
#[derive(Debug, thiserror::Error)]
pub enum DrainError {
    #[error("io error draining gemini events at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Per-slot lock contended — drain will be retried next tick.
    #[error("gemini event log lock contended for slot {slot}; will retry")]
    LockContended { slot: u16 },
    /// Filename slot encoded in the path could not be parsed back to
    /// an [`AccountNum`]. Indicates corruption of the directory entry,
    /// not the log file content.
    #[error("invalid gemini event filename: {filename}")]
    InvalidFilename { filename: String },
}

/// Returns the canonical directory entry pattern: every file matching
/// `gemini-events-*.ndjson` under `base_dir`.
pub fn enumerate_event_logs(base_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if name.starts_with("gemini-events-")
            && name.ends_with(".ndjson")
            && !name.contains(".corrupt.")
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Extracts `<slot>` from a `gemini-events-<slot>.ndjson` filename.
/// Returns `None` if the format does not match.
pub fn slot_from_filename(filename: &str) -> Option<AccountNum> {
    let stripped = filename
        .strip_prefix("gemini-events-")
        .and_then(|s| s.strip_suffix(".ndjson"))?;
    let n: u16 = stripped.parse().ok()?;
    AccountNum::try_from(n).ok()
}

/// Drains all gemini-event NDJSON logs under `base_dir`. Returns the
/// summed [`DrainOutcome`]. Errors per slot are logged and skipped
/// (other slots continue to drain).
pub fn drain_all(base_dir: &Path, state: &GeminiConsumerState) -> DrainOutcome {
    let mut total = DrainOutcome::default();
    for path in enumerate_event_logs(base_dir) {
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let slot = match slot_from_filename(&filename) {
            Some(s) => s,
            None => {
                warn!(
                    error_kind = "gemini_event_invalid_filename",
                    file = %filename,
                    "skipping malformed gemini event log filename"
                );
                continue;
            }
        };
        match drain_slot(base_dir, slot, state) {
            Ok(out) => {
                total.applied += out.applied;
                total.deduped += out.deduped;
                total.quarantined |= out.quarantined;
                if out.applied > 0 || out.quarantined {
                    info!(
                        slot = slot.get(),
                        applied = out.applied,
                        deduped = out.deduped,
                        quarantined = out.quarantined,
                        "gemini event drain"
                    );
                }
            }
            Err(DrainError::LockContended { .. }) => {
                debug!(
                    slot = slot.get(),
                    "gemini event log lock contended; will retry next tick"
                );
            }
            Err(e) => {
                warn!(
                    error_kind = "gemini_event_drain_failed",
                    slot = slot.get(),
                    error = %e,
                    "gemini event drain error"
                );
            }
        }
    }
    total
}

/// Drains the per-slot NDJSON log into `quota.json`, then truncates
/// the log on success. Acquires the per-slot lock-file
/// non-blockingly; returns [`DrainError::LockContended`] if another
/// process holds it.
pub fn drain_slot(
    base_dir: &Path,
    slot: AccountNum,
    state: &GeminiConsumerState,
) -> Result<DrainOutcome, DrainError> {
    let log_path = ndjson_log_path(base_dir, slot);
    let lock_path = ndjson_lock_path(base_dir, slot);

    let _file_lock =
        match crate::platform::lock::try_lock_file(&lock_path).map_err(|e| DrainError::Io {
            path: lock_path.clone(),
            source: std::io::Error::other(format!("lock open: {e:?}")),
        })? {
            Some(g) => g,
            None => return Err(DrainError::LockContended { slot: slot.get() }),
        };

    let content = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DrainOutcome::default()),
        Err(e) => {
            return Err(DrainError::Io {
                path: log_path,
                source: e,
            })
        }
    };

    if content.is_empty() {
        return Ok(DrainOutcome::default());
    }

    let mut envelopes = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<EventEnvelope>(line) {
            Ok(env) => envelopes.push(env),
            Err(_) => {
                let outcome = quarantine_log(&log_path)?;
                return Ok(outcome);
            }
        }
    }

    let mut outcome = DrainOutcome::default();
    {
        let _q_guard = state.quota_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut quota = quota_state::load_state(base_dir).map_err(|e| DrainError::Io {
            path: base_dir.to_path_buf(),
            source: std::io::Error::other(format!("quota load: {e}")),
        })?;
        let mut applied = state.applied.lock().unwrap_or_else(|p| p.into_inner());
        let mut breakers = state.breakers.lock().unwrap_or_else(|p| p.into_inner());

        for env in &envelopes {
            if env.v != EVENT_SCHEMA_VERSION {
                debug!(
                    error_kind = "gemini_event_unsupported_version",
                    slot = env.slot,
                    v = env.v,
                    "skipping NDJSON event with unsupported schema version"
                );
                continue;
            }
            if env.slot != slot.get() {
                debug!(
                    error_kind = "gemini_event_slot_mismatch",
                    expected = slot.get(),
                    found = env.slot,
                    "envelope slot does not match filename; skipping"
                );
                continue;
            }
            if !applied.insert(env.id.clone()) {
                outcome.deduped += 1;
                continue;
            }
            let breaker = breakers.entry(env.slot).or_default();
            apply_event(&mut quota, env, breaker);
            outcome.applied += 1;
        }
        if outcome.applied > 0 {
            quota_state::save_state(base_dir, &quota).map_err(|e| DrainError::Io {
                path: base_dir.to_path_buf(),
                source: std::io::Error::other(format!("quota save: {e}")),
            })?;
        }
    }

    truncate_log(&log_path)?;
    Ok(outcome)
}

/// Applies a single envelope's effect to its slot in `quota`. Mutates
/// `breaker` for schema-drift events when the source is the NDJSON
/// drainer. Caller is responsible for holding the dedup ledger +
/// quota mutex.
///
/// Convenience wrapper that defaults `source` to
/// [`EventSource::Drain`] — the historical contract before PR-G3
/// redteam M3 introduced source-aware breaker gating. Existing
/// drain call sites keep using this entry point.
pub fn apply_event(quota: &mut QuotaFile, env: &EventEnvelope, breaker: &mut BreakerState) {
    apply_event_with_source(quota, env, breaker, EventSource::Drain);
}

/// Same as [`apply_event`] but takes an explicit [`EventSource`].
/// The IPC handler MUST pass [`EventSource::Ipc`]; the drainer MUST
/// pass [`EventSource::Drain`]. Schema-drift events received via IPC
/// are recorded structurally but DO NOT increment the breaker —
/// closes the same-UID drift-spam vector flagged by PR-G3 redteam M3.
pub fn apply_event_with_source(
    quota: &mut QuotaFile,
    env: &EventEnvelope,
    breaker: &mut BreakerState,
    source: EventSource,
) {
    let now = epoch_now_secs() as f64;
    let entry = quota
        .accounts
        .entry(env.slot.to_string())
        .or_insert_with(|| AccountQuota {
            surface: EVENT_SURFACE_GEMINI.to_string(),
            kind: "counter".into(),
            updated_at: now,
            ..Default::default()
        });
    entry.surface = EVENT_SURFACE_GEMINI.to_string();
    entry.updated_at = now;

    match &env.kind {
        EventKind::CounterIncrement(_) => {
            breaker.consecutive_drifts = 0;
            // Outside of a drift breaker trip, kind reverts to counter
            // — covers both `"unknown"` (post-breaker recovery) and
            // any other previous value (e.g. a default-constructed
            // entry).
            if entry.kind != "counter" {
                entry.kind = "counter".into();
            }
            let counter = entry.counter.get_or_insert_with(default_counter_state);
            counter.requests_today = counter.requests_today.saturating_add(1);
        }
        EventKind::RateLimited(payload) => {
            breaker.consecutive_drifts = 0;
            let rl = entry.rate_limit.get_or_insert_with(RateLimitState::default);
            rl.active = true;
            rl.last_retry_delay_s = Some(payload.retry_delay_s as u64);
            rl.last_quota_metric = Some(payload.quota_metric.clone());
            if let Some(cap) = payload.cap {
                rl.cap = Some(cap);
            }
            // reset_at = ts + retry_delay_s. Best-effort string add;
            // if `ts` parsing is not strict the daemon UI reads
            // last_retry_delay_s for countdown anyway.
            rl.reset_at = compute_reset_at(&env.ts, payload.retry_delay_s);
        }
        EventKind::EffectiveModelObserved(payload) => {
            breaker.consecutive_drifts = 0;
            entry.selected_model = Some(payload.selected.clone());
            let prev_effective = entry.effective_model.clone();
            entry.effective_model = Some(payload.effective.clone());
            if prev_effective.as_deref() != Some(payload.effective.as_str()) {
                entry.effective_model_first_seen_at = Some(env.ts.clone());
            }
            if payload.selected != payload.effective {
                let count = entry.mismatch_count_today.unwrap_or(0).saturating_add(1);
                entry.mismatch_count_today = Some(count);
                entry.is_downgrade = Some(count >= DOWNGRADE_DEBOUNCE_THRESHOLD);
            } else {
                // Reset on observed match — clears latched downgrade.
                entry.mismatch_count_today = Some(0);
                entry.is_downgrade = Some(false);
            }
        }
        EventKind::TosGuardTripped(_) => {
            // Tripping the ToS guard does not change quota numbers
            // — surfaced via separate UI banner. Recorded in the
            // event log + structured-log only.
            warn!(
                error_kind = "gemini_tos_guard_tripped",
                slot = env.slot,
                "EP4 ToS-guard tripped — child terminated by csq-cli"
            );
            breaker.consecutive_drifts = 0;
        }
        EventKind::QuotaSchemaDrift(_) => match source {
            EventSource::Drain => {
                breaker.consecutive_drifts = breaker.consecutive_drifts.saturating_add(1);
                if breaker.consecutive_drifts >= SCHEMA_DRIFT_BREAKER_THRESHOLD {
                    warn!(
                        error_kind = "gemini_quota_schema_drift_breaker_open",
                        slot = env.slot,
                        consecutive = breaker.consecutive_drifts,
                        "5-strike schema-drift breaker open; flipping kind=unknown"
                    );
                    entry.kind = "unknown".into();
                }
            }
            EventSource::Ipc => {
                // PR-G3 redteam M3: IPC drift events are observed but
                // do NOT mutate the breaker. Logged for visibility.
                debug!(
                    error_kind = "gemini_quota_schema_drift_via_ipc_ignored",
                    slot = env.slot,
                    "drift event via IPC does not count toward breaker"
                );
            }
        },
    }
}

/// Resets per-slot counters at midnight America/Los_Angeles. Called
/// by [`run_midnight_reset`]; exposed for unit-testable apply.
pub fn apply_midnight_reset(quota: &mut QuotaFile, now_ts_iso: String) {
    let now = epoch_now_secs() as f64;
    for (_, entry) in quota.accounts.iter_mut() {
        if entry.surface != EVENT_SURFACE_GEMINI {
            continue;
        }
        if let Some(counter) = entry.counter.as_mut() {
            counter.requests_today = 0;
            counter.last_reset = Some(now_ts_iso.clone());
        }
        // Daily mismatch counter is also a "today" quantity — reset
        // alongside the request counter.
        entry.mismatch_count_today = Some(0);
        entry.is_downgrade = Some(false);
        entry.updated_at = now;
    }
}

/// Spawns the midnight-America/Los_Angeles reset task. Sleeps until
/// the next midnight LA, fires reset, repeats. Cancellation-aware via
/// the supplied token.
pub async fn run_midnight_reset(
    base_dir: PathBuf,
    state: GeminiConsumerState,
    shutdown: tokio_util::sync::CancellationToken,
) {
    info!("gemini midnight-LA reset task started");
    loop {
        let now_ms = epoch_now_ms();
        let sleep_ms = millis_until_next_midnight_la(now_ms);
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("gemini midnight reset task cancelled");
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)) => {}
        }
        // Reset under the quota mutex so the active drainer cannot
        // race the reset.
        let _q_guard = state.quota_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut quota = match quota_state::load_state(&base_dir) {
            Ok(q) => q,
            Err(e) => {
                warn!(error = %e, "midnight reset: quota load failed");
                continue;
            }
        };
        let now_iso = format_rfc3339_la(epoch_now_secs());
        apply_midnight_reset(&mut quota, now_iso);
        if let Err(e) = quota_state::save_state(&base_dir, &quota) {
            warn!(error = %e, "midnight reset: quota save failed");
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────

fn ndjson_log_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    base_dir.join(format!("gemini-events-{}.ndjson", slot.get()))
}

fn ndjson_lock_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    base_dir.join(format!("gemini-events-{}.lock", slot.get()))
}

fn quarantine_log(log_path: &Path) -> Result<DrainOutcome, DrainError> {
    let ts_ms = epoch_now_ms();
    let mut quarantine_path = log_path.to_path_buf();
    let mut filename = log_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("gemini-events-unknown.ndjson")
        .to_string();
    if let Some(stem) = filename.strip_suffix(".ndjson") {
        filename = format!("{stem}.corrupt.{ts_ms}.ndjson");
    } else {
        filename = format!("{filename}.corrupt.{ts_ms}");
    }
    quarantine_path.set_file_name(filename);
    std::fs::rename(log_path, &quarantine_path).map_err(|e| DrainError::Io {
        path: log_path.to_path_buf(),
        source: e,
    })?;
    // PR-G3 redteam M2: defence in depth — quarantine sibling
    // inherits source permissions via rename, but if the user dropped
    // a manually-crafted NDJSON file at umask-default (0o644), the
    // quarantine would stay world-readable. Re-assert 0o600. No-op
    // on Windows.
    if let Err(e) = crate::platform::fs::secure_file(&quarantine_path) {
        warn!(
            error_kind = "gemini_event_quarantine_secure_file_failed",
            path = %quarantine_path.display(),
            error = %e,
            "secure_file on quarantine path failed"
        );
    }
    warn!(
        error_kind = "gemini_event_log_quarantined",
        original = %log_path.display(),
        quarantine = %quarantine_path.display(),
        "parse error in NDJSON log; file moved aside"
    );
    Ok(DrainOutcome {
        applied: 0,
        deduped: 0,
        quarantined: true,
    })
}

fn truncate_log(log_path: &Path) -> Result<(), DrainError> {
    use std::fs::OpenOptions;
    let opts = OpenOptions::new().write(true).truncate(true).open(log_path);
    match opts {
        Ok(f) => {
            f.sync_all().map_err(|e| DrainError::Io {
                path: log_path.to_path_buf(),
                source: e,
            })?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DrainError::Io {
            path: log_path.to_path_buf(),
            source: e,
        }),
    }
}

fn default_counter_state() -> CounterState {
    CounterState {
        requests_today: 0,
        resets_at_tz: "America/Los_Angeles".into(),
        last_reset: None,
    }
}

fn compute_reset_at(emitted_ts: &str, retry_delay_s: u32) -> Option<String> {
    // Parse the RFC 3339 ts to seconds-since-epoch; add retry_delay_s;
    // re-format. Best-effort — caller falls back to last_retry_delay_s
    // for countdowns when this returns None.
    let secs = parse_rfc3339_to_unix_secs(emitted_ts)?;
    let reset = secs + retry_delay_s as u64;
    Some(format_rfc3339_utc(reset))
}

fn parse_rfc3339_to_unix_secs(ts: &str) -> Option<u64> {
    // RFC 3339: YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)
    // PR-G3 redteam H3: accept both `Z` and ±HH:MM offsets so values
    // produced by `format_rfc3339_la` round-trip. The offset is
    // normalised to UTC by adjusting `secs`.
    if ts.len() < 20 {
        return None;
    }
    let y: i64 = ts[0..4].parse().ok()?;
    let mo: u32 = ts[5..7].parse().ok()?;
    let d: u32 = ts[8..10].parse().ok()?;
    let h: u32 = ts[11..13].parse().ok()?;
    let mi: u32 = ts[14..16].parse().ok()?;
    let s: u32 = ts[17..19].parse().ok()?;

    // Locate the suffix (Z or ±HH:MM), skipping any optional
    // fractional-seconds component (`.fff...`) at position 19.
    let mut idx = 19;
    if ts.as_bytes().get(idx) == Some(&b'.') {
        idx += 1;
        let bytes = ts.as_bytes();
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    let suffix = ts.get(idx..)?;

    let offset_secs: i64 = match suffix.chars().next()? {
        'Z' => {
            if suffix.len() != 1 {
                return None;
            }
            0
        }
        sign @ ('+' | '-') => {
            // Expect "+HH:MM" or "-HH:MM" — exactly 6 chars.
            if suffix.len() != 6 || suffix.as_bytes()[3] != b':' {
                return None;
            }
            let oh: i64 = suffix[1..3].parse().ok()?;
            let om: i64 = suffix[4..6].parse().ok()?;
            let mag = oh * 3600 + om * 60;
            if sign == '-' {
                -mag
            } else {
                mag
            }
        }
        _ => return None,
    };

    let days = days_from_civil(y, mo, d)?;
    let local_secs = days * 86_400 + (h as i64) * 3600 + (mi as i64) * 60 + s as i64;
    // RFC 3339: a `+08:00` offset means wall-clock runs 8 hours
    // AHEAD of UTC, so to normalise to UTC we SUBTRACT the offset
    // (subtracting a negative offset for `-08:00` adds).
    let utc_secs = local_secs - offset_secs;
    if utc_secs < 0 {
        return None;
    }
    Some(utc_secs as u64)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if m == 0 || m > 12 || d == 0 || d > 31 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

fn format_rfc3339_utc(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_civil(unix_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn format_rfc3339_la(unix_secs: u64) -> String {
    // Best-effort fixed -08:00 (PST). DST adjustment is handled by
    // the schedule (next-midnight calc), not this label — the
    // `last_reset` field is informational.
    let (y, mo, d, h, mi, s) = unix_to_civil(unix_secs - 8 * 3600);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}-08:00")
}

fn unix_to_civil(unix_secs: u64) -> (i64, u8, u8, u8, u8, u8) {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let h = (secs_of_day / 3600) as u8;
    let mi = ((secs_of_day % 3600) / 60) as u8;
    let s = (secs_of_day % 60) as u8;
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, s)
}

fn epoch_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn epoch_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Milliseconds from `now_ms` to the next midnight in
/// America/Los_Angeles. Uses fixed -08:00 offset (PST). DST
/// adjustment is acceptable approximation here: the reset task fires
/// daily, so a DST event drifts the reset by 60min on two days per
/// year — well within the spec's "best-effort daily reset" tolerance.
fn millis_until_next_midnight_la(now_ms: u64) -> u64 {
    let la_offset_ms: u64 = 8 * 3600 * 1000;
    // "Now in LA" measured in ms since LA epoch.
    let la_now_ms = now_ms.saturating_sub(la_offset_ms);
    let day_ms = 86_400_000_u64;
    let into_today = la_now_ms % day_ms;
    let to_midnight = day_ms - into_today;
    if to_midnight == 0 {
        day_ms
    } else {
        to_midnight
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::gemini::capture::{
        append_event, EmptyPayload, EventKind, RateLimitedPayload,
    };
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn fresh_state() -> GeminiConsumerState {
        GeminiConsumerState::default()
    }

    fn fresh_envelope(slot_num: u16, kind: EventKind) -> EventEnvelope {
        EventEnvelope::new(slot(slot_num), kind)
    }

    #[test]
    fn applied_set_inserts_unique_and_dedups() {
        let mut s = AppliedSet::default();
        assert!(s.insert("a".into()));
        assert!(!s.insert("a".into()));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn applied_set_evicts_oldest_at_capacity() {
        // Bound-respecting LRU semantics — older IDs get evicted so
        // the set never grows unboundedly.
        let mut s = AppliedSet::default();
        for i in 0..APPLIED_SET_CAPACITY {
            assert!(s.insert(format!("id-{i}")));
        }
        assert_eq!(s.len(), APPLIED_SET_CAPACITY);
        // One more insertion evicts "id-0".
        assert!(s.insert("id-new".into()));
        assert_eq!(s.len(), APPLIED_SET_CAPACITY);
        assert!(!s.contains("id-0"));
        assert!(s.contains("id-new"));
    }

    #[test]
    fn slot_from_filename_parses_well_formed() {
        assert_eq!(slot_from_filename("gemini-events-7.ndjson"), Some(slot(7)));
        assert_eq!(
            slot_from_filename("gemini-events-999.ndjson"),
            Some(slot(999))
        );
    }

    #[test]
    fn slot_from_filename_rejects_corrupt_or_other() {
        assert_eq!(
            slot_from_filename("gemini-events-7.corrupt.123.ndjson"),
            None
        );
        assert_eq!(slot_from_filename("not-events.ndjson"), None);
        assert_eq!(slot_from_filename("gemini-events-abc.ndjson"), None);
    }

    #[test]
    fn drain_slot_no_log_returns_empty_outcome() {
        let dir = TempDir::new().unwrap();
        let state = fresh_state();
        let outcome = drain_slot(dir.path(), slot(3), &state).unwrap();
        assert_eq!(outcome, DrainOutcome::default());
    }

    #[test]
    fn drain_slot_applies_counter_increment_and_truncates() {
        let dir = TempDir::new().unwrap();
        let env = fresh_envelope(2, EventKind::CounterIncrement(EmptyPayload {}));
        append_event(dir.path(), &env).unwrap();

        let state = fresh_state();
        let outcome = drain_slot(dir.path(), slot(2), &state).unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.deduped, 0);

        // Quota updated.
        let qf = quota_state::load_state(dir.path()).unwrap();
        let acct = qf.get(2).expect("slot 2 quota present");
        assert_eq!(acct.surface, "gemini");
        assert_eq!(acct.kind, "counter");
        assert_eq!(acct.counter.as_ref().unwrap().requests_today, 1);

        // Log truncated.
        let log_path = ndjson_log_path(dir.path(), slot(2));
        let after = std::fs::metadata(&log_path).unwrap();
        assert_eq!(
            after.len(),
            0,
            "log must be truncated after successful drain"
        );
    }

    #[test]
    fn drain_slot_dedups_duplicate_id() {
        let dir = TempDir::new().unwrap();
        let env = fresh_envelope(4, EventKind::CounterIncrement(EmptyPayload {}));

        // Pre-seed the dedup ledger as if the live IPC already applied.
        let state = fresh_state();
        state.applied.lock().unwrap().insert(env.id.clone());
        // Pre-seed the quota as if the live IPC already updated it.
        {
            let _q = state.quota_lock.lock().unwrap();
            let mut qf = quota_state::load_state(dir.path()).unwrap();
            let mut acct = AccountQuota {
                surface: "gemini".into(),
                kind: "counter".into(),
                ..Default::default()
            };
            acct.counter = Some(default_counter_state());
            acct.counter.as_mut().unwrap().requests_today = 1;
            qf.set(4, acct);
            quota_state::save_state(dir.path(), &qf).unwrap();
        }
        // Now write the same event to NDJSON.
        append_event(dir.path(), &env).unwrap();

        let outcome = drain_slot(dir.path(), slot(4), &state).unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.deduped, 1);

        // Quota counter remains 1 (no double-count).
        let qf = quota_state::load_state(dir.path()).unwrap();
        let acct = qf.get(4).unwrap();
        assert_eq!(acct.counter.as_ref().unwrap().requests_today, 1);
    }

    #[test]
    fn drain_slot_quarantines_on_corrupt_line() {
        let dir = TempDir::new().unwrap();
        let log_path = ndjson_log_path(dir.path(), slot(8));
        std::fs::write(&log_path, "{not valid json}\n").unwrap();

        let state = fresh_state();
        let outcome = drain_slot(dir.path(), slot(8), &state).unwrap();
        assert!(outcome.quarantined);

        // Original removed; quarantine sibling exists.
        assert!(!log_path.exists(), "corrupt log must be moved aside");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.contains("gemini-events-8.corrupt."))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "expected one quarantine file, got {entries:?}"
        );
    }

    #[test]
    fn apply_event_rate_limited_sets_active_and_metric() {
        let mut qf = QuotaFile::empty();
        let env = fresh_envelope(
            5,
            EventKind::RateLimited(RateLimitedPayload {
                retry_delay_s: 60,
                quota_metric: "rpm".into(),
                cap: Some(250),
            }),
        );
        let mut breaker = BreakerState::default();
        apply_event(&mut qf, &env, &mut breaker);

        let acct = qf.get(5).unwrap();
        let rl = acct.rate_limit.as_ref().unwrap();
        assert!(rl.active);
        assert_eq!(rl.last_quota_metric.as_deref(), Some("rpm"));
        assert_eq!(rl.last_retry_delay_s, Some(60));
        assert_eq!(rl.cap, Some(250));
    }

    #[test]
    fn apply_event_effective_model_latches_downgrade_after_three() {
        let mut qf = QuotaFile::empty();
        let mut breaker = BreakerState::default();
        let mismatch_payload = || {
            EventKind::EffectiveModelObserved(
                crate::providers::gemini::capture::EffectiveModelPayload {
                    selected: "gemini-2.5-pro".into(),
                    effective: "gemini-2.0-flash".into(),
                },
            )
        };

        // 1 + 2 mismatches: downgrade NOT yet latched (debounce
        // threshold is 3 per ADR-G06).
        apply_event(
            &mut qf,
            &fresh_envelope(6, mismatch_payload()),
            &mut breaker,
        );
        apply_event(
            &mut qf,
            &fresh_envelope(6, mismatch_payload()),
            &mut breaker,
        );
        let acct = qf.get(6).unwrap();
        assert_eq!(acct.is_downgrade, Some(false));

        // 3rd mismatch latches.
        apply_event(
            &mut qf,
            &fresh_envelope(6, mismatch_payload()),
            &mut breaker,
        );
        let acct = qf.get(6).unwrap();
        assert_eq!(acct.mismatch_count_today, Some(3));
        assert_eq!(acct.is_downgrade, Some(true));
    }

    #[test]
    fn apply_event_schema_drift_breaker_flips_kind_at_five() {
        let mut qf = QuotaFile::empty();
        let mut breaker = BreakerState::default();
        for _ in 0..4 {
            apply_event(
                &mut qf,
                &fresh_envelope(9, EventKind::QuotaSchemaDrift(EmptyPayload {})),
                &mut breaker,
            );
        }
        // 4 strikes: kind still default counter.
        let acct = qf.get(9).unwrap();
        assert_eq!(acct.kind, "counter");

        // 5th strike trips the breaker.
        apply_event(
            &mut qf,
            &fresh_envelope(9, EventKind::QuotaSchemaDrift(EmptyPayload {})),
            &mut breaker,
        );
        let acct = qf.get(9).unwrap();
        assert_eq!(acct.kind, "unknown");
        assert_eq!(breaker.consecutive_drifts, 5);
    }

    #[test]
    fn apply_midnight_reset_zeroes_counter_and_mismatch() {
        let mut qf = QuotaFile::empty();
        let mut acct = AccountQuota {
            surface: "gemini".into(),
            kind: "counter".into(),
            ..Default::default()
        };
        acct.counter = Some(CounterState {
            requests_today: 237,
            resets_at_tz: "America/Los_Angeles".into(),
            last_reset: None,
        });
        acct.mismatch_count_today = Some(3);
        acct.is_downgrade = Some(true);
        qf.set(11, acct);

        apply_midnight_reset(&mut qf, "2026-04-26T00:00:00-08:00".into());

        let acct = qf.get(11).unwrap();
        assert_eq!(acct.counter.as_ref().unwrap().requests_today, 0);
        assert_eq!(
            acct.counter.as_ref().unwrap().last_reset.as_deref(),
            Some("2026-04-26T00:00:00-08:00")
        );
        assert_eq!(acct.mismatch_count_today, Some(0));
        assert_eq!(acct.is_downgrade, Some(false));
    }

    #[cfg(unix)]
    #[test]
    fn drain_slot_lock_contention_returns_specific_error() {
        // Two concurrent drains on the same slot — the second must
        // surface LockContended, not block forever. Unix-only because
        // Windows named mutexes are re-entrant WITHIN the same
        // thread, which makes a single-thread same-process contention
        // test unreliable on that platform (see platform::lock::imp
        // doc-comment). Cross-process Windows behaviour is exercised
        // by the integration tests that spawn a real daemon.
        let dir = TempDir::new().unwrap();
        let env = fresh_envelope(12, EventKind::CounterIncrement(EmptyPayload {}));
        append_event(dir.path(), &env).unwrap();

        let state = fresh_state();
        let lock_guard =
            crate::platform::lock::lock_file(&ndjson_lock_path(dir.path(), slot(12))).unwrap();
        let result = drain_slot(dir.path(), slot(12), &state);
        match result {
            Err(DrainError::LockContended { slot: 12 }) => {}
            other => panic!("expected LockContended, got {other:?}"),
        }
        drop(lock_guard);
    }

    #[test]
    fn drain_all_processes_multiple_slot_files() {
        let dir = TempDir::new().unwrap();
        for slot_num in [1u16, 2, 3] {
            let env = fresh_envelope(slot_num, EventKind::CounterIncrement(EmptyPayload {}));
            append_event(dir.path(), &env).unwrap();
        }

        let state = fresh_state();
        let outcome = drain_all(dir.path(), &state);
        assert_eq!(outcome.applied, 3);

        let qf = quota_state::load_state(dir.path()).unwrap();
        for slot_num in [1u16, 2, 3] {
            let acct = qf
                .get(slot_num)
                .unwrap_or_else(|| panic!("slot {slot_num} quota present"));
            assert_eq!(acct.counter.as_ref().unwrap().requests_today, 1);
        }
    }

    #[test]
    fn ipc_source_drift_does_not_trip_breaker() {
        // PR-G3 redteam M3 regression — same-UID caller posting drift
        // events via IPC must NOT flip kind=unknown.
        let mut qf = QuotaFile::empty();
        let mut breaker = BreakerState::default();
        for _ in 0..10 {
            apply_event_with_source(
                &mut qf,
                &fresh_envelope(13, EventKind::QuotaSchemaDrift(EmptyPayload {})),
                &mut breaker,
                EventSource::Ipc,
            );
        }
        let acct = qf.get(13).unwrap();
        // Counter is the default kind because we created this entry
        // with a default-constructed AccountQuota; whatever it is, it
        // MUST NOT have flipped to "unknown" via IPC.
        assert_ne!(
            acct.kind, "unknown",
            "IPC drift events must not flip kind to unknown"
        );
        assert_eq!(
            breaker.consecutive_drifts, 0,
            "IPC events must not increment the drift breaker"
        );
    }

    #[test]
    fn drain_source_drift_still_trips_breaker() {
        // PR-G3 redteam M3 regression — drain-path drift events MUST
        // continue to trip the breaker. Pairs with the test above.
        let mut qf = QuotaFile::empty();
        let mut breaker = BreakerState::default();
        for _ in 0..SCHEMA_DRIFT_BREAKER_THRESHOLD {
            apply_event_with_source(
                &mut qf,
                &fresh_envelope(14, EventKind::QuotaSchemaDrift(EmptyPayload {})),
                &mut breaker,
                EventSource::Drain,
            );
        }
        let acct = qf.get(14).unwrap();
        assert_eq!(acct.kind, "unknown");
    }

    #[test]
    fn parse_rfc3339_accepts_z_and_offsets() {
        // PR-G3 redteam H3 regression — the parser must accept both
        // `Z` and ±HH:MM offsets so values produced by
        // `format_rfc3339_la` round-trip.
        let z = parse_rfc3339_to_unix_secs("2026-04-26T00:00:00Z").unwrap();
        let pst = parse_rfc3339_to_unix_secs("2026-04-25T16:00:00-08:00").unwrap();
        assert_eq!(z, pst, "PST and Z forms must converge to the same epoch");

        let with_ms = parse_rfc3339_to_unix_secs("2026-04-25T22:30:00.123Z").unwrap();
        let no_ms = parse_rfc3339_to_unix_secs("2026-04-25T22:30:00Z").unwrap();
        assert_eq!(with_ms, no_ms, "fractional seconds rounded to second");

        // Reject malformed offsets.
        assert!(parse_rfc3339_to_unix_secs("2026-04-25T22:30:00+0800").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-04-25T22:30:00X").is_none());
    }

    #[test]
    fn millis_until_next_midnight_la_is_under_24h() {
        let now_ms = epoch_now_ms();
        let until = millis_until_next_midnight_la(now_ms);
        assert!(until > 0);
        assert!(until <= 86_400_000);
    }
}
