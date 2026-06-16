//! M20 degraded-reconcile — prev_link hash-chain ordering + held-pending store.
//!
//! M18-bind rewrites the ordering model from per-surface integer counters
//! (`source_counter`) to per-operator `prev_link` hash-chains. Each v1 event
//! carries `prev_link: Option<sha256hex>` where `None` = genesis and
//! `Some(h)` = the prior event's `decision_id`.
//!
//! Gap-detection uses the EXISTING `.seam-dedup-index` (`seam_dedup_index_contains`)
//! — no new sidecar. The held store is re-keyed to
//! `.pending/provenance-ordered/<person_id>/<decision_id>.json`.
//!
//! ## Deleted machinery (M18-bind)
//!
//! - `decide_gap` (counter-based)
//! - `MAX_FORWARD_GAP` / `TooFarAhead`
//! - `COUNTER_PAD`
//! - `.seam-source-counters` read/write paths
//! - `read_source_counter` / `advance_source_counter` (deleted from persist.rs)
//! - `chain_max_source_counter` (deleted from persist.rs)
//!
//! ## Preserved machinery
//!
//! - `ordering_basis_for` / `WALLCLOCK_SKEW_BOUNDED` / `RECONNECT_GAP_THRESHOLD_SECS`
//! - `PREDECESSOR_WAIT_SECS` (timeout bound)
//! - `HELD_HARD_CAP` / custody cap
//! - `sweep_timed_out` (all held events past PREDECESSOR_WAIT_SECS)
//! - `OrderingContext` (epistemic annotation)

use std::path::{Path, PathBuf};

use crate::audit::seam::SeamError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// Bounded wait for a missing intra-operator prev_link predecessor. A held event
/// whose file age exceeds this links with `predecessor_missing: Some(true)`
/// rather than waiting forever.
pub const PREDECESSOR_WAIT_SECS: i64 = 300;

/// Epistemic ordering annotation carried onto a `ProvenanceAnchored` record.
///
/// `live()` is the normal in-order path (no annotation). The gap/wallclock
/// constructors mark the honest epistemic status of a span linked across a
/// degraded-reconnect window.
#[derive(Debug, Clone, Default)]
pub struct OrderingContext {
    /// `Some("wallclock_skew_bounded")` for cross-source gap spans.
    pub ordering_basis: Option<String>,
    /// `Some(true)` when linked past an unfilled prev_link gap on bounded
    /// timeout.
    pub predecessor_missing: Option<bool>,
    /// `true` when this is a sweep-forced link (gap_timeout constructor).
    ///
    /// MEDIUM-3: explicit predicate for the sweep-forced path so `ingest_anchored`
    /// can skip the gap-check without inferring from the payload annotation field.
    /// A future refactor that constructs `OrderingContext` differently cannot
    /// silently revert to a gap-check re-hold.
    forced: bool,
}

impl OrderingContext {
    /// Normal live-ingest path: csq-assigned `seq` is authoritative, no
    /// annotation.
    pub fn live() -> Self {
        Self::default()
    }

    /// Linked past an unfilled prev_link gap on bounded timeout (F-SEAM-09):
    /// the predecessor never arrived within `PREDECESSOR_WAIT_SECS`.
    pub fn gap_timeout() -> Self {
        Self {
            ordering_basis: None,
            predecessor_missing: Some(true),
            forced: true,
        }
    }

    /// Returns `true` when this context represents a sweep-forced link (i.e.
    /// the event is being linked past an unfilled prev_link gap on bounded
    /// timeout). Used by `ingest_anchored` to decide whether to skip the
    /// gap-check — an explicit predicate rather than inferring from the payload
    /// annotation field (MEDIUM-3 fix).
    #[inline]
    pub fn is_forced(&self) -> bool {
        self.forced
    }
}

/// The fixed `ordering_basis` tag for spans ordered by skew-bounded wall-clock.
pub const WALLCLOCK_SKEW_BOUNDED: &str = "wallclock_skew_bounded";

/// An event whose `claimed_decision_ts` precedes its arrival (`now`) by more
/// than this was BUFFERED — it was decided during a window csq could not
/// live-link it (a daemon-down/hook-retry gap), so its cross-source ordering
/// relative to csq's own lifecycle records is wall-clock-derived, not causal
/// (F-SEAM-03(b)). Such an event is annotated `ordering_basis:
/// "wallclock_skew_bounded"`. 60s is deliberately conservative.
pub const RECONNECT_GAP_THRESHOLD_SECS: i64 = 60;

/// Compute the `ordering_basis` for an event whose claimed decision time is
/// `claimed_unix`, arriving at `now_unix`. Returns
/// `Some("wallclock_skew_bounded")` when the arrival lag exceeds
/// [`RECONNECT_GAP_THRESHOLD_SECS`] (a buffered/backfilled event), else `None`
/// (a live event whose csq-assigned `seq` is authoritative).
pub fn ordering_basis_for(now_unix: i64, claimed_unix: i64) -> Option<String> {
    if now_unix.saturating_sub(claimed_unix) > RECONNECT_GAP_THRESHOLD_SECS {
        Some(WALLCLOCK_SKEW_BOUNDED.to_string())
    } else {
        None
    }
}

/// Decision for an inbound event's prev_link relative to the dedup index.
#[derive(Debug, PartialEq, Eq)]
pub enum GapDecision {
    /// Link now — genesis (`prev_link == None`) or predecessor already anchored
    /// (`seam_dedup_index_contains(prev_link)`).
    Proceed,
    /// Predecessor not yet anchored — hold until predecessor arrives or timeout.
    /// Carries the missing predecessor decision_id.
    Hold { missing: String },
}

/// Decide whether an event with `prev_link` links now or holds.
///
/// Uses `seam_dedup_index_contains_or_rebuild` (MEDIUM-1 fix) — rebuilds the
/// index from the active chain when the sidecar is absent. This is the
/// rebuild-aware reader, symmetric with the IN-LOCK writer's
/// `load_or_rebuild_dedup_index`. Without rebuild, a Step-9 sidecar-drop would
/// cause the gap-checker to false-Hold events whose predecessors are durably
/// anchored.
///
/// No `TooFarAhead` variant: hash-chains have no forward-gap concept (a hash
/// is either present or absent).
///
/// `person_id` is the operator identity key (for held-dir path).
pub fn decide_gap_prev_link(csq_runs: &Path, prev_link: Option<&str>) -> GapDecision {
    match prev_link {
        None => GapDecision::Proceed, // genesis event
        Some(pl) => {
            if crate::audit::persist::seam_dedup_index_contains_or_rebuild(csq_runs, pl) {
                GapDecision::Proceed
            } else {
                GapDecision::Hold {
                    missing: pl.to_string(),
                }
            }
        }
    }
}

/// Sanitize a person_id / decision_id for use as a path component.
/// Rejects anything with path separators or `..`.
fn is_path_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.contains('/')
        && !s.contains('\\')
        && s != ".."
        && s != "."
        && !s.contains("..")
}

/// `.pending/provenance-ordered/<person_id>/` for the held intra-operator buffer.
fn operator_held_dir(csq_runs: &Path, person_id: &str) -> PathBuf {
    csq_runs
        .join(".pending")
        .join("provenance-ordered")
        .join(person_id)
}

/// The held-event path for `(person_id, decision_id)`.
pub fn held_path(csq_runs: &Path, person_id: &str, decision_id: &str) -> PathBuf {
    operator_held_dir(csq_runs, person_id).join(format!("{decision_id}.json"))
}

/// Hard ceiling on TOTAL files in the held store. At the cap,
/// `hold_for_predecessor` refuses with `SeamError::CustodyFull`.
pub const HELD_HARD_CAP: usize = 10_000;

/// Outcome of [`hold_for_predecessor`].
#[derive(Debug, PartialEq, Eq)]
pub enum HoldOutcome {
    /// The event was buffered in the held store.
    Held,
    /// A DIFFERENT event already occupies this `(person_id, decision_id)` slot
    /// (a collision — the first is preserved; the caller quarantines the loser).
    Collision,
}

/// Count total files across the held store (all operators).
fn held_total_count(csq_runs: &Path) -> usize {
    let root = csq_runs.join(".pending").join("provenance-ordered");
    let Ok(operators) = std::fs::read_dir(&root) else {
        return 0;
    };
    let mut n = 0usize;
    for op in operators.flatten() {
        if let Ok(files) = std::fs::read_dir(op.path()) {
            for _ in files.flatten() {
                n += 1;
                if n >= HELD_HARD_CAP {
                    return n;
                }
            }
        }
    }
    n
}

/// Hold raw event bytes in `.pending/provenance-ordered/<person_id>/<decision_id>.json`
/// pending its prev_link predecessor.
pub fn hold_for_predecessor(
    csq_runs: &Path,
    person_id: &str,
    decision_id: &str,
    raw: &[u8],
) -> Result<HoldOutcome, SeamError> {
    if !is_path_safe(person_id) || !is_path_safe(decision_id) {
        return Err(SeamError::Internal);
    }
    let path = held_path(csq_runs, person_id, decision_id);

    // Collision guard: a different event already held at this (person_id, decision_id).
    if let Ok(existing) = std::fs::read(&path) {
        if existing == raw {
            return Ok(HoldOutcome::Held); // idempotent re-hold
        }
        tracing::warn!(
            error_kind = "seam_held_decision_id_collision",
            "seam: distinct event collides with a held event at the same (person_id, decision_id)"
        );
        return Ok(HoldOutcome::Collision);
    }

    // Custody cap.
    if held_total_count(csq_runs) >= HELD_HARD_CAP {
        tracing::error!(
            error_kind = "seam_held_custody_full",
            "seam: held store at hard cap; refusing hold"
        );
        return Err(SeamError::CustodyFull);
    }

    let dir = operator_held_dir(csq_runs, person_id);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    write_held_file(&path, raw)?;
    tracing::info!(
        error_kind = "seam_held_predecessor_gap",
        "seam: event held pending prev_link predecessor"
    );
    Ok(HoldOutcome::Held)
}

/// Read held raw bytes for `(person_id, decision_id)`, if present.
pub fn read_held(csq_runs: &Path, person_id: &str, decision_id: &str) -> Option<Vec<u8>> {
    std::fs::read(held_path(csq_runs, person_id, decision_id)).ok()
}

/// Remove a held file after it has been drained/linked.
pub fn remove_held(csq_runs: &Path, person_id: &str, decision_id: &str) {
    let _ = std::fs::remove_file(held_path(csq_runs, person_id, decision_id));
}

/// One held event awaiting its predecessor.
#[derive(Debug, Clone)]
pub struct HeldEvent {
    /// Operator person_id (directory component).
    pub person_id: String,
    /// The held event's `decision_id` (filename stem, without `.json`).
    pub decision_id: String,
    /// Age in seconds relative to the caller-supplied `now_unix` (from mtime).
    /// `None` when mtime is unreadable (treated as not-yet-timed-out).
    pub age_secs: Option<i64>,
}

/// Enumerate every held event across all operators, with each event's age
/// relative to `now_unix`. Used by the timeout sweep + the doctor surface.
pub fn list_held(csq_runs: &Path, now_unix: i64) -> Vec<HeldEvent> {
    let root = csq_runs.join(".pending").join("provenance-ordered");
    let mut out = Vec::new();
    let Ok(operators) = std::fs::read_dir(&root) else {
        return out;
    };
    for op_entry in operators.flatten() {
        if !op_entry.path().is_dir() {
            continue;
        }
        let person_id = op_entry.file_name().to_string_lossy().to_string();
        if !is_path_safe(&person_id) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(op_entry.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let decision_id = stem.to_string();
            if !is_path_safe(&decision_id) {
                continue;
            }
            let age_secs = file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|mtime| {
                    mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| now_unix.saturating_sub(d.as_secs() as i64))
                });
            out.push(HeldEvent {
                person_id: person_id.clone(),
                decision_id,
                age_secs,
            });
        }
    }
    out
}

/// Write a held custody file via the §5a tmp-cleanup pipeline.
fn write_held_file(path: &Path, raw: &[u8]) -> Result<(), SeamError> {
    let tmp = unique_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, raw) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SeamError::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SeamError::Io(std::io::Error::other(e.to_string())));
    }
    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SeamError::Io(std::io::Error::other(e.to_string())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn ordering_basis_flags_backfill_only() {
        // Live: arrival ≈ claimed → no annotation.
        assert_eq!(ordering_basis_for(1_000, 1_000), None);
        assert_eq!(
            ordering_basis_for(1_000, 1_000 - RECONNECT_GAP_THRESHOLD_SECS),
            None
        );
        // Backfill: arrival materially after claimed → wall-clock annotation.
        assert_eq!(
            ordering_basis_for(1_000, 1_000 - RECONNECT_GAP_THRESHOLD_SECS - 1).as_deref(),
            Some(WALLCLOCK_SKEW_BOUNDED)
        );
        // A future-claimed event (negative lag) is never a backfill.
        assert_eq!(ordering_basis_for(1_000, 5_000), None);
    }

    #[test]
    fn decide_gap_genesis_proceeds() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        assert_eq!(
            decide_gap_prev_link(&csq_runs, None),
            GapDecision::Proceed,
            "genesis event (prev_link=None) must Proceed"
        );
    }

    #[test]
    fn decide_gap_present_predecessor_proceeds() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        // Seed the dedup index with a fake predecessor.
        let pred_id = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        std::fs::write(
            csq_runs.join(crate::audit::persist::SEAM_DEDUP_INDEX),
            format!("{pred_id}\n"),
        )
        .unwrap();
        assert_eq!(
            decide_gap_prev_link(&csq_runs, Some(pred_id)),
            GapDecision::Proceed,
            "present predecessor must Proceed"
        );
    }

    #[test]
    fn decide_gap_absent_predecessor_holds() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let pred_id = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        // No dedup index → predecessor absent → Hold.
        let result = decide_gap_prev_link(&csq_runs, Some(pred_id));
        assert_eq!(
            result,
            GapDecision::Hold {
                missing: pred_id.to_string()
            },
            "absent predecessor must produce Hold"
        );
    }

    // ── MEDIUM-1: decide_gap_prev_link rebuilds-on-index-absence (regression) ──

    #[test]
    fn decide_gap_prev_link_rebuilds_on_absent_index() {
        // Setup: write a chain.json + chain JSONL that contains a ProvenanceAnchored
        // record with a known decision_id (simulating a durably-anchored predecessor),
        // but NO .seam-dedup-index sidecar (simulating a Step-9 append failure that
        // deleted it). The gap-check must Proceed (not false-Hold) by rebuilding
        // the index from the chain.
        use crate::audit::persist::SEAM_DEDUP_INDEX;
        use serde_json::json;

        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();

        // Crockford Base32 IDs (26 chars, no I/L/O/U).
        let chain_id = "01JZTEST0000000000TESTCHN0";
        let record_id = "01JZTEST0000000000000REC00";
        let pred_id = "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a";

        // Write a minimal chain.json.
        let genesis = json!({
            "chain_id": chain_id,
            "genesis_seq": 0,
            "genesis_ts": "2026-06-10T00:00:00+00:00"
        });
        std::fs::write(csq_runs.join("chain.json"), genesis.to_string()).unwrap();

        // Write a minimal JSONL with one ProvenanceAnchored record containing pred_id.
        // EventPayload uses #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
        // so the payload object must be {"kind": "provenance_anchored", "data": {...}}.
        // RecordId / chain_id must be valid Crockford Base32 (26 chars, no I/L/O/U).
        let record = json!({
            "schema_version": "2",
            "record_id": record_id,
            "chain_id": chain_id,
            "seq": 1,
            "prev_hash": "0".repeat(64),
            "kind": "provenance_anchored",
            "payload": {
                "kind": "provenance_anchored",
                "data": {
                    "decision_id": pred_id,
                    "surface": "journal/test.md",
                    "claimed_decision_ts": "2026-06-10T00:00:00+00:00",
                    "f101_schema_version": "1",
                    "received_bytes_hash": pred_id
                }
            },
            "ts": "2026-06-10T00:00:00+00:00",
            "key_id": format!("ed25519:{}", "0".repeat(64)),
            "canonical_hash": "0".repeat(64),
            "signature": "0".repeat(128)
        });
        let jsonl_path = csq_runs.join(format!("{chain_id}.jsonl"));
        std::fs::write(&jsonl_path, format!("{}\n", record)).unwrap();

        // Confirm no index exists yet.
        assert!(
            !csq_runs.join(SEAM_DEDUP_INDEX).exists(),
            "pre-condition: no dedup index"
        );

        // Gap-check MUST Proceed (rebuild finds pred_id in the chain).
        let result = decide_gap_prev_link(&csq_runs, Some(pred_id));
        assert_eq!(
            result,
            GapDecision::Proceed,
            "MEDIUM-1: decide_gap_prev_link must Proceed after rebuilding index from chain"
        );

        // The rebuilt index should now exist on disk (side-effect of rebuild).
        assert!(
            csq_runs.join(SEAM_DEDUP_INDEX).exists(),
            "MEDIUM-1: rebuild must persist the index for subsequent O(1) reads"
        );
    }

    #[test]
    fn hold_rejects_unsafe_person_id() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let result = hold_for_predecessor(&csq_runs, "../escape", "decision-id", b"{}");
        assert!(matches!(result, Err(SeamError::Internal)));
    }

    #[test]
    fn hold_collision_preserves_first() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let pid = "pid-alice";
        let did = "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a";
        assert_eq!(
            hold_for_predecessor(&csq_runs, pid, did, b"AAAA").unwrap(),
            HoldOutcome::Held
        );
        // Identical re-hold is idempotent.
        assert_eq!(
            hold_for_predecessor(&csq_runs, pid, did, b"AAAA").unwrap(),
            HoldOutcome::Held
        );
        // Different bytes at same slot → Collision.
        assert_eq!(
            hold_for_predecessor(&csq_runs, pid, did, b"BBBB").unwrap(),
            HoldOutcome::Collision
        );
        assert_eq!(read_held(&csq_runs, pid, did).unwrap(), b"AAAA");
    }

    #[test]
    fn list_held_reports_entries() {
        let dir = tmp();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let pid = "pid-bob";
        let did = "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a";
        hold_for_predecessor(&csq_runs, pid, did, b"{\"x\":1}").unwrap();
        let held = list_held(&csq_runs, 32_503_680_000); // year ~3000
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].person_id, pid);
        assert_eq!(held[0].decision_id, did);
        assert!(held[0].age_secs.is_some_and(|a| a > 0));
    }
}
