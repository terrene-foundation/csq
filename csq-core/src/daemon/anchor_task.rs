//! M14 — Daemon tokio task for periodic external anchoring.
//!
//! Mirrors the `refresher.rs` pattern: a cancellable tokio loop that fires on
//! a configurable cadence and calls [`anchor_head`] to commit the chain HEAD
//! to the active [`LedgerSink`].
//!
//! # Cadence
//!
//! - Regular: `AuditSinkConfig.cadence_for(sink).cadence` (default `"1d"`).
//! - High-impact detection (AC2 mechanism): on every poll the loop reads the
//!   current chain HEAD. When `head.kind ∈ {KeyRotate, IdentityMint, ReleaseAuth}`
//!   AND `head.seq > last_anchored_seq`, the loop anchors immediately regardless
//!   of the regular cadence. This works uniformly for CLI `rotate-key` (a
//!   separate process that can never signal the daemon directly) AND in-daemon
//!   identity-mint. The daemon OBSERVES the chain — it does not need to be
//!   signalled by the writer.
//!
//! # `request_immediate_anchor()` (latency-reduction only)
//!
//! The `AnchorTaskHandle::request_immediate_anchor()` API is a latency-reduction
//! hint for in-daemon ops: calling it causes the next poll to happen within 30
//! seconds instead of up to `POLL_INTERVAL_SECS`. It is NOT the AC2 correctness
//! mechanism — head-kind detection covers correctness.
//!
//! # `last_anchored_seq` gate (no double-anchor)
//!
//! `AnchorState::last_anchored_seq` is updated on every successful anchor.
//! The high-impact gate checks `head.seq > last_anchored_seq` before submitting,
//! so an unchanged high-impact head does NOT re-submit on consecutive polls.
//!
//! # Non-fatal failure
//!
//! Anchor failures update `replication_drift_count` in `anchor-state-<sink>.json`
//! and log at WARN. The local chain and csq operation continue normally.
//!
//! # Layering
//!
//! This module only drives the tokio loop. The pure anchoring logic (read HEAD,
//! call sink, record outcome, update state) lives in
//! [`crate::audit::anchor::anchor_head`] so it can be tested without a running
//! daemon or network.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::audit::anchor::{
    anchor_head, default_cadence, default_cadence_high_impact, is_high_impact_kind, parse_cadence,
    read_anchor_state_for, read_chain_head, scan_tail_for_high_impact, write_anchor_state,
    AnchorOutcome,
};
use crate::audit::sink_config::AuditSinkConfig;
use crate::audit::traits::LedgerSink;

/// Default startup delay before the first anchor tick.
///
/// Matches [`crate::daemon::refresher::STARTUP_DELAY`] so all daemon
/// subsystems are initialised before any outbound network calls are made.
pub const ANCHOR_STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Interval between loop polls.
///
/// 30 seconds balances two requirements:
/// 1. High-impact head detection (KeyRotate / IdentityMint / ReleaseAuth) fires
///    within 30 seconds of the op completing — fast enough for practical compliance
///    without hammering the filesystem or the sink.
/// 2. `request_immediate_anchor()` hint is serviced within 30 seconds, which is
///    the latency-reduction upper bound for in-daemon callers.
///
/// This is intentionally NOT sub-second: a 1-second poll on every daemon instance
/// across N operator installs would be noisy filesystem I/O even before any Rekor
/// submission. High-impact ops (key rotation, release auth) are rare; 30s latency
/// is acceptable.
pub(crate) const POLL_INTERVAL_SECS: u64 = 30;
const POLL_INTERVAL: Duration = Duration::from_secs(POLL_INTERVAL_SECS);

/// Handle to the running anchor task.
///
/// The `notify` is also available so callers can request immediate anchors
/// from M11 high-impact op callsites.
pub struct AnchorTaskHandle {
    /// Background tokio task join handle. Await to ensure clean shutdown.
    pub join: tokio::task::JoinHandle<()>,
    /// Shared notify: call `.notify_one()` to request an immediate anchor.
    pub notify: Arc<Notify>,
}

impl AnchorTaskHandle {
    /// Requests an immediate anchor.
    ///
    /// Returns immediately — the anchor is processed when the loop's
    /// `immediate_notify` `select!` arm fires (sub-second; NOT bounded by the
    /// 30s [`POLL_INTERVAL`], which only paces the head-detection poll).
    /// Non-blocking so M11 high-impact ops are not delayed by any in-progress
    /// anchor call.
    ///
    /// Rationale for a `Notify` signal instead of a direct call:
    /// - A direct async call from an M11 op would require `await`-ing from
    ///   inside the op handler, which may hold state-layer locks. The signal
    ///   pattern avoids any lock-across-await risk.
    /// - The anchor task already runs continuously; a `Notify` is the
    ///   lowest-coupling trigger that the loop already polls.
    pub fn request_immediate_anchor(&self) {
        self.notify.notify_one();
    }
}

/// Spawns the anchor task on the current tokio runtime.
///
/// Returns `None` when `sink_config.sink == "none"` (no external anchoring
/// configured). The daemon startup code calls this only when a sink is active.
///
/// # Arguments
///
/// - `base_dir` — csq state directory (`~/.claude/accounts`).
/// - `sink_config` — the current operator sink configuration.
/// - `sink` — the compiled-in `LedgerSink` implementation (behind `Arc`).
/// - `shutdown` — shared cancellation token; task exits when cancelled.
#[must_use]
pub fn spawn(
    base_dir: PathBuf,
    sink_config: AuditSinkConfig,
    sink: Arc<dyn LedgerSink>,
    shutdown: CancellationToken,
) -> Option<AnchorTaskHandle> {
    if sink_config.sink == "none" {
        debug!("anchor_task: sink=none, anchor task not started");
        return None;
    }

    spawn_with_config(base_dir, sink_config, sink, shutdown, ANCHOR_STARTUP_DELAY)
}

/// Like [`spawn`] but with explicit startup delay (for testing).
#[must_use]
pub fn spawn_with_config(
    base_dir: PathBuf,
    sink_config: AuditSinkConfig,
    sink: Arc<dyn LedgerSink>,
    shutdown: CancellationToken,
    startup_delay: Duration,
) -> Option<AnchorTaskHandle> {
    if sink_config.sink == "none" {
        return None;
    }

    let notify = Arc::new(Notify::new());
    let notify_for_task = Arc::clone(&notify);
    let sink_name = sink_config.sink.clone();

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            sink_config,
            sink_name,
            sink,
            notify_for_task,
            shutdown,
            startup_delay,
        )
        .await;
    });

    Some(AnchorTaskHandle { join, notify })
}

/// The main anchor task loop.
///
/// On every [`POLL_INTERVAL`] (30s) tick:
///
/// 1. M1: Tail-scans the chain for any unanchored high-impact record in
///    `(last_anchored_seq, head_seq]` — not just the HEAD. A KeyRotate buried
///    under a later CsqRun is still detected and anchored immediately.
/// 2. H4: `cadence_high_impact` is honored: `"immediate"` = fire on detection;
///    a duration value = minimum interval gate before firing high-impact anchor.
/// 3. M2: After each anchor (high-impact OR regular), re-derives `next_regular`
///    from the persisted `last_anchor_ts` (wall-clock), not from `last_tick`
///    (monotonic). This correctly reconciles after suspend/resume drift.
/// 4. `immediate_notify` fires within 30s as a latency-reduction hint.
async fn run_loop(
    base_dir: PathBuf,
    sink_config: AuditSinkConfig,
    sink_name: String,
    sink: Arc<dyn LedgerSink>,
    immediate_notify: Arc<Notify>,
    shutdown: CancellationToken,
    startup_delay: Duration,
) {
    // Resolve regular cadence (default: 1d).
    let cadence_str = sink_config
        .cadence_for(&sink_name)
        .and_then(|c| c.cadence.as_deref().map(str::to_string))
        .unwrap_or_else(|| default_cadence(&sink_name).to_string());
    let regular_cadence =
        parse_cadence(&cadence_str).unwrap_or_else(|| Duration::from_secs(86_400));

    // H4: resolve high-impact cadence (default per sink: "immediate" for rekor).
    let hi_cadence_str = sink_config
        .cadence_for(&sink_name)
        .and_then(|c| c.cadence_high_impact.as_deref().map(str::to_string))
        .unwrap_or_else(|| default_cadence_high_impact(&sink_name).to_string());
    // `"immediate"` → Duration::ZERO (always fire on detection).
    // A duration value → minimum interval between high-impact fires.
    let hi_cadence = parse_cadence(&hi_cadence_str).unwrap_or(Duration::ZERO);

    // M2: always derive `next_regular` from the persisted `last_anchor_ts`.
    let derive_next_regular = |base: &Path, sname: &str| -> Duration {
        let state = read_anchor_state_for(base, sname);
        compute_next_regular(state.last_anchor_ts.as_deref(), regular_cadence)
    };

    let mut next_regular = derive_next_regular(&base_dir, &sink_name);

    // Startup delay (lets daemon bind sockets before first outbound call).
    tokio::select! {
        _ = tokio::time::sleep(startup_delay) => {},
        _ = shutdown.cancelled() => {
            debug!("anchor_task: cancelled during startup delay");
            return;
        },
        _ = immediate_notify.notified() => {
            debug!("anchor_task: immediate hint during startup delay");
            do_anchor(Arc::as_ref(&sink), &base_dir, &sink_name).await;
            // M2: re-derive after fire.
            next_regular = derive_next_regular(&base_dir, &sink_name);
        }
    }

    loop {
        // Sleep up to POLL_INTERVAL (or less if the regular cadence is due sooner).
        let sleep = next_regular.min(POLL_INTERVAL);

        tokio::select! {
            _ = tokio::time::sleep(sleep) => {
                // ── Step A: high-impact tail scan (M1) ────────────────────
                let fired_high_impact = check_and_anchor_high_impact(
                    Arc::as_ref(&sink),
                    &base_dir,
                    &sink_name,
                    hi_cadence,
                )
                .await;

                // ── Step B: regular cadence ────────────────────────────────
                // M2: re-derive from persisted ts (handles suspend/resume).
                next_regular = derive_next_regular(&base_dir, &sink_name);

                if next_regular == Duration::ZERO && !fired_high_impact {
                    debug!(sink = %sink_name, "anchor_task: regular cadence tick");
                    do_anchor(Arc::as_ref(&sink), &base_dir, &sink_name).await;
                    // M2: re-derive after fire.
                    next_regular = derive_next_regular(&base_dir, &sink_name);
                }
            }
            _ = immediate_notify.notified() => {
                info!(sink = %sink_name, "anchor_task: immediate anchor hint received");
                do_anchor(Arc::as_ref(&sink), &base_dir, &sink_name).await;
                // M2: re-derive after fire.
                next_regular = derive_next_regular(&base_dir, &sink_name);
            }
            _ = shutdown.cancelled() => {
                debug!(sink = %sink_name, "anchor_task: shutdown signal received");
                break;
            }
        }
    }

    info!(sink = %sink_name, "anchor_task: exited");
}

/// Checks the chain tail for high-impact records not yet anchored.
///
/// M1 fix: scans backward from HEAD to `last_anchored_seq` (not just HEAD).
/// A KeyRotate buried under a later CsqRun is still detected.
///
/// H2 fix: `last_anchored_seq` is `Option<u64>`. An impossible value
/// (`Some(N)` where `N > head.seq`) is treated as tamper + logged as a
/// doctor-visible warning; effectively treated as `None` (re-anchor).
///
/// H4 fix: `hi_cadence` gates the fire — `Duration::ZERO` = always fire on
/// detection; a non-zero duration = minimum interval between high-impact fires
/// (checked against `last_anchor_ts`).
///
/// Returns `true` when an anchor was fired.
async fn check_and_anchor_high_impact(
    sink: &dyn LedgerSink,
    base_dir: &Path,
    sink_name: &str,
    hi_cadence: Duration,
) -> bool {
    let state = read_anchor_state_for(base_dir, sink_name);

    // H2: detect impossible last_anchored_seq.
    // Read HEAD once to validate the state file's seq claim.
    let head_seq_opt = match read_chain_head(base_dir) {
        Ok(Some(h)) => Some(h.seq),
        Ok(None) => return false,
        Err(e) => {
            debug!(sink = sink_name, error = %e, "anchor_task: chain head read error");
            return false;
        }
    };
    let head_seq = head_seq_opt.unwrap_or(0);

    let effective_last_anchored: Option<u64> = if let Some(las) = state.last_anchored_seq {
        if las > head_seq {
            warn!(
                event = "anchor_state_tamper_suspected",
                sink = sink_name,
                last_anchored_seq = las,
                head_seq,
                "anchor_task: last_anchored_seq ({las}) > head.seq ({head_seq}) — \
                 state file may be tampered; re-anchoring"
            );
            let mut patched = read_anchor_state_for(base_dir, sink_name);
            patched.tamper_suspected = true;
            patched.last_anchored_seq = None;
            let _ = write_anchor_state(base_dir, sink_name, &patched);
            None
        } else {
            Some(las)
        }
    } else {
        None
    };

    // H4: check high-impact cadence minimum interval.
    if hi_cadence > Duration::ZERO {
        let fresh = read_anchor_state_for(base_dir, sink_name);
        if let Some(ref last_ts) = fresh.last_anchor_ts {
            let elapsed =
                now_unix_secs().saturating_sub(parse_utc_iso8601_secs(last_ts).unwrap_or(0));
            if Duration::from_secs(elapsed) < hi_cadence {
                return false; // Within minimum interval.
            }
        }
    }

    // M1: scan the chain tail for any unanchored high-impact record.
    //
    // `scan_tail_for_high_impact(base, after)` returns records with seq > after.
    // When never anchored (None), we want to scan ALL records including seq=0.
    // Since we can't pass seq < 0, we handle the None case by checking the HEAD
    // directly and also scanning from seq=0 via after=0 (which gives seq > 0,
    // so seq=0 high-impact is covered by the HEAD check in the None branch).
    let unanchored = match effective_last_anchored {
        None => {
            // Never anchored — check HEAD for high-impact (covers seq=0).
            // For buried high-impact at seq=0 specifically, the HEAD check suffices
            // because seq=0 is always the first record (nothing buries it until anchored).
            match read_chain_head(base_dir) {
                Ok(Some(h)) if is_high_impact_kind(&h.kind) => Some(h),
                Ok(Some(_)) => {
                    // HEAD is low-impact; check if there's a buried high-impact
                    // anywhere in the chain via scan starting from 0 (seq > 0).
                    // seq=0 itself can't be buried under seq=0, so after=0 is correct.
                    scan_tail_for_high_impact(base_dir, 0).unwrap_or(None)
                }
                _ => return false,
            }
        }
        Some(las) => match scan_tail_for_high_impact(base_dir, las) {
            Ok(r) => r,
            Err(e) => {
                debug!(sink = sink_name, error = %e, "anchor_task: tail scan error");
                return false;
            }
        },
    };

    match unanchored {
        Some(rec) => {
            info!(
                sink = sink_name,
                kind = ?rec.kind,
                seq = rec.seq,
                "anchor_task: high-impact record detected, anchoring immediately"
            );
            do_anchor(sink, base_dir, sink_name).await;
            true
        }
        None => false,
    }
}

/// Computes the `Duration` until the next regular anchor.
///
/// If there has been no prior anchor (`last_anchor_ts` is `None`), fires
/// immediately (returns `Duration::ZERO`) so the first anchor happens on
/// startup.
///
/// If the last anchor was MORE than `cadence` ago, also fires immediately.
fn compute_next_regular(last_anchor_ts: Option<&str>, cadence: Duration) -> Duration {
    let last_secs = last_anchor_ts.and_then(parse_utc_iso8601_secs);
    let now_secs = now_unix_secs();
    match last_secs {
        None => Duration::ZERO, // No prior anchor — fire immediately.
        Some(last) => {
            let elapsed = now_secs.saturating_sub(last);
            let elapsed_dur = Duration::from_secs(elapsed);
            if elapsed_dur >= cadence {
                Duration::ZERO // Overdue — fire immediately.
            } else {
                cadence - elapsed_dur
            }
        }
    }
}

/// Calls [`anchor_head`] and updates `anchor-state-<sink>.json` based on the
/// outcome. Non-fatal: logs at WARN on failure.
///
/// On success, updates BOTH `last_anchor_ts` AND `last_anchored_seq` so the
/// high-impact-head-detection gate can prevent re-submission of an unchanged head.
async fn do_anchor(sink: &dyn LedgerSink, base_dir: &Path, sink_name: &str) {
    let now_ts = now_iso8601();
    let outcome = anchor_head(sink, &now_ts, base_dir).await;

    let mut state = read_anchor_state_for(base_dir, sink_name);

    match &outcome {
        AnchorOutcome::Succeeded {
            receipt_sink_id,
            anchored_seq,
        } => {
            state.last_anchor_ts = Some(now_ts.clone());
            state.last_anchored_seq = Some(*anchored_seq);
            state.tamper_suspected = false; // reset on successful anchor
            info!(
                event = "anchor_completed",
                sink = sink_name,
                sink_id = receipt_sink_id,
                seq = anchored_seq,
                ts = now_ts,
                "anchor_task: anchor succeeded"
            );
        }
        AnchorOutcome::Failed { reason } => {
            state.replication_drift_count = state.replication_drift_count.saturating_add(1);
            warn!(
                event = "anchor_failed",
                sink = sink_name,
                drift_count = state.replication_drift_count,
                reason = reason,
                "anchor_task: anchor failed — drift count incremented"
            );
        }
        AnchorOutcome::EmptyChain => {
            debug!(sink = sink_name, "anchor_task: chain empty, skip");
        }
    }

    if !matches!(outcome, AnchorOutcome::EmptyChain) {
        if let Err(e) = write_anchor_state(base_dir, sink_name, &state) {
            // State write failure is logged but not fatal. csq continues.
            // This means `csq doctor` may show stale data until the next
            // successful write, but that is acceptable under the non-fatal
            // contract.
            warn!(
                event = "anchor_state_write_failed",
                sink = sink_name,
                error = %e,
                "anchor_task: could not write anchor-state file"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_iso8601() -> String {
    format_utc_seconds(now_unix_secs())
}

fn format_utc_seconds(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = sod / 3600;
    let mm = (sod / 60) % 60;
    let ss = sod % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Converts a civil date from a days-since-Unix-epoch count.
/// Algorithm: Euclidean affine from Howard Hinnant's date lib.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parses an ISO-8601 UTC timestamp string into Unix seconds.
///
/// Accepts the subset used by csq: `YYYY-MM-DDTHH:MM:SSZ` and
/// `YYYY-MM-DDTHH:MM:SS+00:00`. Returns `None` for any other format.
fn parse_utc_iso8601_secs(ts: &str) -> Option<u64> {
    // Strip trailing +00:00 or Z.
    let ts = ts.trim_end_matches("+00:00").trim_end_matches('Z');
    if ts.len() < 19 {
        return None;
    }
    let year: u64 = ts[0..4].parse().ok()?;
    let month: u64 = ts[5..7].parse().ok()?;
    let day: u64 = ts[8..10].parse().ok()?;
    let hour: u64 = ts[11..13].parse().ok()?;
    let minute: u64 = ts[14..16].parse().ok()?;
    let second: u64 = ts[17..19].parse().ok()?;

    // Days since Unix epoch.
    let days = days_from_civil(year as i64, month as i64, day as i64);
    let secs = (days as u64)
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?;
    Some(secs)
}

/// Civil date to days-since-Unix-epoch (inverse of `civil_from_days`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use async_trait::async_trait;
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    use crate::audit::anchor::test_helpers::sample_signed_record;
    use crate::audit::impls::noop::NoopSink;
    use crate::audit::persist::write_record_v2;
    use crate::audit::types::{RecordId, SignedRecord, SinkError, SinkName, SinkReceipt};

    // ── Counting sink ──

    struct CountingSink {
        name: SinkName,
        count: Arc<AtomicU32>,
    }

    impl CountingSink {
        fn new(count: Arc<AtomicU32>) -> Self {
            Self {
                name: SinkName::try_new("counting-sink").unwrap(),
                count,
            }
        }
    }

    #[async_trait]
    impl LedgerSink for CountingSink {
        fn name(&self) -> &str {
            self.name.as_str()
        }

        async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            let sink_id = crate::audit::types::SinkId::try_new(format!("cnt-{}", record.seq))
                .map_err(|e| SinkError::Internal {
                    message: crate::audit::types::RedactedString::from_trusted(e.to_string()),
                })?;
            Ok(SinkReceipt {
                sink: self.name.clone(),
                sink_id,
                anchored_at: record.ts.clone(),
                inclusion_proof: None,
            })
        }

        async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
            Err(SinkError::NotFound {
                record_id: id.clone(),
            })
        }
    }

    fn seed_chain(base_dir: &std::path::Path) {
        let rec = sample_signed_record(0, "01JZ00000000000000000000R0");
        write_record_v2(rec, Some(base_dir)).unwrap();
    }

    /// AC: `compute_next_regular` returns ZERO when no prior anchor.
    #[test]
    fn compute_next_regular_no_prior_anchor_fires_immediately() {
        let duration = compute_next_regular(None, Duration::from_secs(86_400));
        assert_eq!(
            duration,
            Duration::ZERO,
            "first anchor must fire immediately"
        );
    }

    /// AC: `compute_next_regular` returns a non-zero duration when
    /// the last anchor was recent.
    #[test]
    fn compute_next_regular_recent_anchor_defers() {
        // Pin now to a known time, produce a ts ~10 seconds ago.
        let now = now_unix_secs();
        let ts_str = format_utc_seconds(now.saturating_sub(10));
        let cadence = Duration::from_secs(3600);
        let remaining = compute_next_regular(Some(&ts_str), cadence);
        assert!(
            remaining > Duration::ZERO,
            "recent anchor must defer the next tick"
        );
        assert!(remaining <= cadence, "remaining must not exceed cadence");
    }

    /// AC: `compute_next_regular` fires immediately when overdue.
    #[test]
    fn compute_next_regular_overdue_fires_immediately() {
        // Last anchor was 2 days ago, cadence is 1 day.
        let two_days_ago = now_unix_secs().saturating_sub(2 * 86_400);
        let ts_str = format_utc_seconds(two_days_ago);
        let duration = compute_next_regular(Some(&ts_str), Duration::from_secs(86_400));
        assert_eq!(
            duration,
            Duration::ZERO,
            "overdue anchor must fire immediately"
        );
    }

    /// AC: `parse_utc_iso8601_secs` round-trips through `format_utc_seconds`.
    #[test]
    fn parse_utc_iso8601_round_trips_with_format_utc_seconds() {
        let secs_in = 1_748_908_800u64; // 2026-06-03T00:00:00Z
        let ts = format_utc_seconds(secs_in);
        let parsed = parse_utc_iso8601_secs(&ts).expect("must parse");
        assert_eq!(parsed, secs_in, "round-trip must be exact");
    }

    /// AC: anchor-on-high-impact — the `AnchorTaskHandle::request_immediate_anchor`
    /// method triggers an anchor via the `Notify` within 2s.
    #[tokio::test]
    async fn anchor_on_high_impact_fires_via_notify() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        seed_chain(&base);

        let count = Arc::new(AtomicU32::new(0));
        let count_for_sink = Arc::clone(&count);
        let sink = Arc::new(CountingSink::new(count_for_sink));

        // Use counting-sink; cadence=1d so the regular tick does NOT fire during test.
        let mut cfg = crate::audit::sink_config::AuditSinkConfig {
            sink: "counting-sink".to_string(),
            ..Default::default()
        };
        cfg.set_sink_cadence("counting-sink", "cadence", "1d").ok();

        // Suppress the regular tick by using a custom AuditSinkConfig with a
        // long cadence and a recent-enough last_anchor_ts.
        let now_ts = now_iso8601();
        // Write a recent last_anchor_ts so the regular cadence does NOT fire
        // during the test (we only want to observe the immediate-anchor path).
        crate::audit::anchor::write_anchor_state(
            &base,
            "counting-sink",
            &crate::audit::anchor::AnchorState {
                last_anchor_ts: Some(now_ts),
                replication_drift_count: 0,
                last_anchored_seq: Some(0),
                tamper_suspected: false,
            },
        )
        .unwrap();

        let shutdown = CancellationToken::new();
        let handle = spawn_with_config(
            base.clone(),
            cfg,
            sink as Arc<dyn LedgerSink>,
            shutdown.clone(),
            Duration::ZERO, // no startup delay in test
        )
        .expect("spawn must return Some when sink != none");

        // Wait a moment for the task to start.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Request an immediate anchor.
        handle.request_immediate_anchor();

        // Give the task time to process the Notify (up to 2s).
        let deadline = Instant::now() + Duration::from_secs(2);
        while count.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let calls = count.load(Ordering::SeqCst);
        shutdown.cancel();
        let _ = handle.join.await;

        assert!(
            calls >= 1,
            "immediate anchor must have fired at least once (got {calls} calls)"
        );
    }

    /// AC: spawn returns None when sink is "none".
    #[test]
    fn spawn_returns_none_when_sink_is_none() {
        let dir = TempDir::new().unwrap();
        let cfg = crate::audit::sink_config::AuditSinkConfig::default(); // sink = "none"
        let sink = Arc::new(NoopSink::new("noop").unwrap());
        let shutdown = CancellationToken::new();
        let handle = spawn(
            dir.path().to_path_buf(),
            cfg,
            sink as Arc<dyn LedgerSink>,
            shutdown,
        );
        assert!(handle.is_none(), "spawn must return None when sink=none");
    }

    /// AC: `AnchorState` Serde round-trip including `last_anchored_seq`.
    #[test]
    fn anchor_state_serde_round_trip() {
        let state = crate::audit::anchor::AnchorState {
            last_anchor_ts: Some("2026-06-03T12:00:00Z".to_string()),
            replication_drift_count: 3,
            last_anchored_seq: Some(42),
            tamper_suspected: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        let loaded: crate::audit::anchor::AnchorState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            loaded.last_anchor_ts.as_deref(),
            Some("2026-06-03T12:00:00Z")
        );
        assert_eq!(loaded.replication_drift_count, 3);
        assert_eq!(loaded.last_anchored_seq, Some(42));
    }

    /// H2/backward-compat: `last_anchored_seq` defaults to `None` when
    /// deserialising a pre-M14 state file (backward-compat).
    #[test]
    fn anchor_state_last_anchored_seq_defaults_zero_for_old_files() {
        let old_json = r#"{"last_anchor_ts":"2026-06-01T00:00:00Z","replication_drift_count":0}"#;
        let loaded: crate::audit::anchor::AnchorState =
            serde_json::from_str(old_json).expect("must deserialise pre-M14 state");
        assert_eq!(
            loaded.last_anchored_seq, None,
            "missing last_anchored_seq must default to None"
        );
        assert_eq!(
            loaded.last_anchor_ts.as_deref(),
            Some("2026-06-01T00:00:00Z")
        );
    }

    // ── High-impact-kind fixture helpers ────────────────────────────────────

    /// Builds a `SignedRecord` with `kind = KeyRotate` and the supplied seq.
    /// Uses `write_record_v2` so the chain is properly linked.
    fn write_high_impact_record_key_rotate(base_dir: &std::path::Path, id: &str) {
        use crate::audit::types::{
            Ed25519PublicKey, Ed25519Signature, EventKind, EventPayload, KeyId, KeyRotatePayload,
            RecordId, RotationReason, Sha256Hex, SignedRecord,
        };
        let record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::KeyRotate,
            payload: EventPayload::KeyRotate(KeyRotatePayload {
                previous_key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
                new_key_id: KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap(),
                incoming_pubkey: Ed25519PublicKey::new([0u8; 32]),
                rotation_reason: RotationReason::Operator,
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };
        write_record_v2(record, Some(base_dir)).unwrap();
    }

    fn write_high_impact_record_identity_mint(base_dir: &std::path::Path, id: &str) {
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, IdentityMintPayload, KeyId, RecordId,
            Sha256Hex, SignedRecord,
        };
        use crate::types::AccountNum;
        let record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::IdentityMint,
            payload: EventPayload::IdentityMint(IdentityMintPayload {
                identity_uuid: "test-uuid-0001".to_string(),
                slot: AccountNum::try_from(1u16).unwrap(),
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };
        write_record_v2(record, Some(base_dir)).unwrap();
    }

    fn write_high_impact_record_release_auth(base_dir: &std::path::Path, id: &str) {
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, ReleaseAuthPayload,
            Sha256Hex, SignedRecord,
        };
        let record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::ReleaseAuth,
            payload: EventPayload::ReleaseAuth(ReleaseAuthPayload {
                release_tag: "v2.14.0".to_string(),
                artifact_sha256: Sha256Hex::genesis(),
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };
        write_record_v2(record, Some(base_dir)).unwrap();
    }

    // ── Head-kind detection tests ────────────────────────────────────────────

    /// AC2: A high-impact HEAD (KeyRotate) triggers `check_and_anchor_high_impact`
    /// WITHOUT any direct signal — detection is by observation, not by notify.
    ///
    /// This proves that `rotate-key` (a CLI-context op that cannot reach the
    /// daemon's `AnchorTaskHandle`) is covered by head-kind detection.
    #[tokio::test]
    async fn high_impact_head_key_rotate_triggers_anchor_by_detection() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();

        // Write a CsqRun baseline, then a KeyRotate head.
        seed_chain(base.as_path());
        write_high_impact_record_key_rotate(base.as_path(), "01JZ00000000000000000000K1");

        // Use a CountingSink to observe submissions.
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        // No prior anchor state → last_anchored_seq = 0 < head.seq.
        // check_and_anchor_high_impact must fire.
        let fired = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;

        assert!(
            fired,
            "KeyRotate head must trigger immediate anchor by detection"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "sink must have received exactly one submission"
        );

        // State file must now have last_anchor_ts set (last_anchored_seq = head.seq,
        // which may validly be 0 if the high-impact record is the first chain record).
        let state = crate::audit::anchor::read_anchor_state_for(&base, "counting-sink");
        assert!(
            state.last_anchor_ts.is_some(),
            "last_anchor_ts must be set after anchor"
        );
    }

    /// AC2: A high-impact HEAD (IdentityMint) triggers detection.
    #[tokio::test]
    async fn high_impact_head_identity_mint_triggers_anchor_by_detection() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        write_high_impact_record_identity_mint(base.as_path(), "01JZ0000000000000000000001");

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        let fired = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;

        assert!(fired, "IdentityMint head must trigger immediate anchor");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// AC2: A high-impact HEAD (ReleaseAuth) triggers detection.
    #[tokio::test]
    async fn high_impact_head_release_auth_triggers_anchor_by_detection() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        write_high_impact_record_release_auth(base.as_path(), "01JZ00000000000000000000A1");

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        let fired = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;

        assert!(fired, "ReleaseAuth head must trigger immediate anchor");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// AC2: A `CsqRun` HEAD does NOT trigger high-impact detection.
    ///
    /// A CsqRun record at the chain head must NOT cause a Rekor submission
    /// outside the regular daily cadence (directive 3 — conservative submission).
    #[tokio::test]
    async fn csq_run_head_does_not_trigger_high_impact_detection() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        seed_chain(base.as_path()); // CsqRun head

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        let fired = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;

        assert!(!fired, "CsqRun head must NOT trigger high-impact detection");
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "no sink submission for CsqRun head"
        );
    }

    /// AC: No double-anchor — two consecutive polls with an unchanged
    /// high-impact HEAD → exactly ONE submission.
    ///
    /// After the first anchor succeeds, `last_anchored_seq` is updated to the
    /// head's seq. The second poll finds `head.seq <= last_anchored_seq` and
    /// skips the submission.
    #[tokio::test]
    async fn no_double_anchor_on_unchanged_high_impact_head() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        write_high_impact_record_key_rotate(base.as_path(), "01JZ00000000000000000000K2");

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        // First poll — head is new, fires anchor.
        let fired1 = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;
        assert!(fired1, "first poll must fire anchor");
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second poll — head is unchanged (same seq), must NOT re-submit.
        let fired2 = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;
        assert!(!fired2, "second poll must NOT re-anchor unchanged head");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "sink must still have exactly one submission after two polls"
        );
    }

    /// AC: `last_anchored_seq` persists across simulated restarts.
    ///
    /// After writing a high-impact head and anchoring it, the state file holds
    /// `last_anchored_seq = head.seq`. A subsequent poll (simulating daemon
    /// restart reading from disk) finds `head.seq <= last_anchored_seq` and
    /// skips re-anchoring.
    #[tokio::test]
    async fn last_anchored_seq_persists_prevents_reanchor_after_restart() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        write_high_impact_record_key_rotate(base.as_path(), "01JZ00000000000000000000K3");

        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        // Initial anchor.
        check_and_anchor_high_impact(Arc::as_ref(&sink), &base, "counting-sink", Duration::ZERO)
            .await;
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Read back the persisted state (simulating what a restarted daemon reads).
        let state = crate::audit::anchor::read_anchor_state_for(&base, "counting-sink");
        assert!(
            state.last_anchor_ts.is_some(),
            "last_anchor_ts must be set after successful anchor (last_anchored_seq={:?})",
            state.last_anchored_seq
        );

        // Simulate restart: fresh CountingSink but reads state from disk.
        let count2 = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink2: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count2)));

        // Head unchanged (same seq) — must NOT re-anchor.
        let fired_after_restart = check_and_anchor_high_impact(
            Arc::as_ref(&sink2),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;
        assert!(
            !fired_after_restart,
            "restart must not re-anchor an already-anchored high-impact head"
        );
        assert_eq!(
            count2.load(Ordering::SeqCst),
            0,
            "no submission after simulated restart with unchanged head"
        );
    }

    // ── H2: forged last_anchored_seq does not suppress anchoring ─────────────

    /// H2 regression: a forged `anchor-state-<sink>.json` with
    /// `last_anchored_seq = u64::MAX` MUST NOT suppress anchoring of a
    /// genuine unanchored high-impact record.
    ///
    /// The H2 fix cross-checks `last_anchored_seq` against the chain's actual
    /// HEAD seq. When `last_anchored_seq > head.seq`, the gate treats the
    /// state file as tampered (logs a warning, sets `tamper_suspected = true`,
    /// resets to `None`) and re-anchors the high-impact head.
    ///
    /// Non-tautological: reverting the H2 fix (removing the `las > head_seq`
    /// tamper-detection branch so the gate trusts `last_anchored_seq` from
    /// the state file directly) causes the function to compute
    /// `effective_last_anchored = Some(u64::MAX)`, find no record with
    /// `seq > u64::MAX` (impossible), return `None` from `scan_tail_for_high_impact`,
    /// and return `false` — anchor is suppressed. The `assert!(fired)` then
    /// fails.
    #[tokio::test]
    async fn forged_last_anchored_seq_does_not_suppress_high_impact_anchor() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();

        // Write one high-impact record (KeyRotate). write_record_v2 assigns seq = 0.
        write_high_impact_record_key_rotate(base.as_path(), "01JZ00000000000000000000H2");

        // Write a FORGED anchor-state with last_anchored_seq = u64::MAX.
        // An attacker hoping to suppress anchoring would write this file.
        let forged_state = crate::audit::anchor::AnchorState {
            last_anchor_ts: Some("2099-01-01T00:00:00Z".to_string()),
            replication_drift_count: 0,
            last_anchored_seq: Some(u64::MAX),
            tamper_suspected: false,
        };
        crate::audit::anchor::write_anchor_state(&base, "counting-sink", &forged_state)
            .expect("write forged state");

        // Run the high-impact detection gate.
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sink: Arc<dyn LedgerSink> = Arc::new(CountingSink::new(Arc::clone(&count)));

        let fired = check_and_anchor_high_impact(
            Arc::as_ref(&sink),
            &base,
            "counting-sink",
            Duration::ZERO,
        )
        .await;

        // Gate must have detected the tamper and anchored anyway.
        assert!(
            fired,
            "forged last_anchored_seq=MAX must not suppress high-impact anchor"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "sink must receive exactly one submission despite forged state"
        );

        // State file must now reflect tamper_suspected was set (then cleared on success).
        // After a successful anchor, tamper_suspected is reset to false by do_anchor.
        let post_state = crate::audit::anchor::read_anchor_state_for(&base, "counting-sink");
        assert!(
            post_state.last_anchor_ts.is_some(),
            "last_anchor_ts must be written after anchor"
        );
        // tamper_suspected is cleared on successful anchor (see do_anchor → AnchorOutcome::Succeeded branch).
        assert!(
            !post_state.tamper_suspected,
            "tamper_suspected must be cleared after successful anchor"
        );
    }
}
