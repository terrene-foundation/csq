//! Version-grace state — the soft-grace window for unknown `coc.version`
//! values. Per M6 PR-CA13 + spec 09 §9.5.3 (drift posture, R6 mitigation).
//!
//! When csq encounters a `coc.version` whose major exceeds
//! [`crate::coc::version::MAX_KNOWN_COC_MAJOR`], it would normally
//! refuse to load (spec 09 §9.5.1 third row). For the first
//! [`SOFT_GRACE_DAYS`] after first observation, csq instead degrades
//! to "unknown shape, load in passthrough mode" and surfaces a
//! `csq update needed` banner. After the grace expires the original
//! hard-refuse posture returns.
//!
//! # File location and shape
//!
//! Stored at `<base_dir>/coc-version-grace.json`:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "records": [
//!     {
//!       "observed_version": "2.0.0",
//!       "first_seen_unix": 1775722800
//!     }
//!   ]
//! }
//! ```
//!
//! Records are keyed by `observed_version` string so two unknown
//! versions seen in quick succession (e.g. a project hops from 2.0.0
//! to 2.1.0 mid-grace) each get their own grace clock. This is the
//! conservative posture: the user MUST upgrade csq to consume EITHER,
//! so each unknown version's grace runs independently.
//!
//! # Why this is in csq-core, not csq-cli
//!
//! Both the CLI (`csq run` ↔ `csq-cli/src/commands/run.rs`) and the
//! desktop tray (future banner consumer) need this state. Putting
//! the load/save in csq-core keeps both consumers on the same code
//! path and the grace clock honest across surfaces.

use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Soft-grace window in days. During this period an unknown
/// `coc.version` major loads in degraded mode + surfaces a `csq
/// update needed` banner. After this window the original hard-refuse
/// returns. Per spec 09 §9.5.3 (M6 PR-CA13).
pub const SOFT_GRACE_DAYS: u64 = 30;

/// Filename for the persisted grace records, relative to `base_dir`.
pub const VERSION_GRACE_FILE: &str = "coc-version-grace.json";

/// One grace record: an unknown `coc.version` was first observed at
/// `first_seen_unix`. Subsequent observations of the SAME version
/// reuse this record (the clock does not restart on every load); a
/// DIFFERENT unknown version gets its own record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceRecord {
    /// Verbatim `coc.version` string (e.g. `"2.0.0"`). Stored as a
    /// string rather than a parsed [`crate::coc::version::CocVersion`]
    /// so a future shape change to the version type does not
    /// invalidate every existing grace record.
    pub observed_version: String,
    /// Unix seconds at first observation. The grace expires at
    /// `first_seen_unix + SOFT_GRACE_DAYS * 86400`.
    pub first_seen_unix: i64,
}

/// Top-level grace state. `schema_version=1` is the M6 PR-CA13 shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub records: Vec<GraceRecord>,
}

fn default_schema_version() -> u32 {
    1
}

impl Default for GraceState {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            records: Vec::new(),
        }
    }
}

impl GraceState {
    /// Find the grace record for a given observed version, or insert
    /// a new one stamped at `now_unix`. Returns the record's
    /// `first_seen_unix` AFTER any insertion (so the caller can
    /// compute remaining days against the same baseline regardless
    /// of insert vs find).
    pub fn upsert(&mut self, observed: &str, now_unix: i64) -> i64 {
        if let Some(rec) = self.records.iter().find(|r| r.observed_version == observed) {
            return rec.first_seen_unix;
        }
        self.records.push(GraceRecord {
            observed_version: observed.to_string(),
            first_seen_unix: now_unix,
        });
        now_unix
    }

    /// Days remaining in the grace window for a given record's
    /// `first_seen_unix`. Negative means the grace has expired
    /// (caller MUST hard-refuse). Returns `i64` so callers can
    /// distinguish "expired N days ago" (audit signal) from
    /// "expires in M days".
    ///
    /// # Clock-jump defense (R-HIGH-2 + R-LOW-2)
    ///
    /// Two failure modes addressed structurally:
    ///
    /// 1. **Clock leaping forward** (suspended laptop wakes up, NTP
    ///    re-syncs, virtualized clock skew). `elapsed_secs` would
    ///    grow huge in one step and silently expire an unrelated
    ///    project's grace clock mid-session. Defense: cap at
    ///    `SOFT_GRACE_DAYS * 2` (60 days). Beyond that, log a
    ///    `coc.version_grace_clock_jump` warn and return 0
    ///    (treat as expired, fail-closed). The user-visible result
    ///    is the same hard-refuse they'd get if the grace had
    ///    legitimately run out, plus a structured log signal an
    ///    operator can grep for. We choose fail-closed because the
    ///    alternative (extending the grace silently) lets a clock
    ///    desync mask a genuine "user has been ignoring the
    ///    upgrade banner for 60+ days" condition.
    ///
    /// 2. **Clock leaping backward** (`now < first_seen`). The
    ///    `saturating_sub` returns 0 and the caller sees a fresh
    ///    grace window, but we log `coc.version_grace_clock_before_epoch`
    ///    so an operator can correlate a sudden "grace reset" with
    ///    a clock anomaly rather than a real first observation.
    pub fn days_remaining_at(first_seen_unix: i64, now_unix: i64) -> i64 {
        if now_unix < first_seen_unix {
            // Backwards clock: pretend no time has passed but emit
            // a structural warn so the anomaly is auditable.
            tracing::warn!(
                error_kind = "coc.version_grace_clock_before_epoch",
                first_seen_unix,
                now_unix,
                "now_unix is before first_seen_unix — clock skew or VM rollback; treating elapsed as 0"
            );
            return SOFT_GRACE_DAYS as i64;
        }
        let elapsed_secs = now_unix - first_seen_unix;
        let elapsed_days = elapsed_secs / 86400;
        let grace_cap_days = (SOFT_GRACE_DAYS as i64) * 2;
        if elapsed_days > grace_cap_days {
            // Leap forward beyond 2x the soft grace — assume the clock
            // jumped, fail closed (treat as expired) rather than let
            // a bogus elapsed value mask the genuine expiry condition.
            tracing::warn!(
                error_kind = "coc.version_grace_clock_jump",
                first_seen_unix,
                now_unix,
                elapsed_days,
                grace_cap_days,
                "elapsed_days exceeds 2x SOFT_GRACE_DAYS cap — treating grace as expired"
            );
            return 0_i64.saturating_sub(elapsed_days - SOFT_GRACE_DAYS as i64);
        }
        SOFT_GRACE_DAYS as i64 - elapsed_days
    }
}

/// Loads the grace state. Returns the default (empty records) when
/// the file is missing, empty, or fails to parse — read errors are
/// logged at WARN with `error_kind` tags. Shape mirrors
/// [`crate::capability_layer::settings::load_capability_layer_toggles`]
/// for consistency.
pub fn load_grace_state(base_dir: &Path) -> GraceState {
    let path = base_dir.join(VERSION_GRACE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            match serde_json::from_str::<GraceState>(&content) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        error_kind = "coc_version_grace_parse",
                        error = %e,
                        "coc-version-grace.json failed to parse, using defaults"
                    );
                    GraceState::default()
                }
            }
        }
        Ok(_) => GraceState::default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => GraceState::default(),
        Err(e) => {
            tracing::warn!(
                error_kind = "coc_version_grace_read",
                error = %e,
                "coc-version-grace.json read failed, using defaults"
            );
            GraceState::default()
        }
    }
}

/// Persists the grace state via the same atomic-write contract as
/// [`crate::providers::settings::save_settings`]. The file holds no
/// secrets but the cleanup-on-failure pattern mirrors security.md
/// §5a so a future change that adds a per-record metadata field
/// (e.g. project realpath) does not introduce a tmp-file leak path.
///
/// # Concurrent-writer convergence (R-MEDIUM-1)
///
/// Two concurrent `csq run` invocations may both observe the same
/// unknown major and race the load-mutate-save cycle. Spec 09 §9.5.3
/// says "the grace clock does not restart on subsequent observations
/// of the same version" — naive last-write-wins violates this when
/// process B observes the version a millisecond AFTER process A
/// already wrote a record with `first_seen_unix=A.now`, then process B
/// does its own upsert and writes back a record with
/// `first_seen_unix=B.now > A.now`, advancing the clock.
///
/// Defense (two-layer):
///
/// 1. **flock-serialized writes.** A process-wide advisory lock on
///    `<base_dir>/coc-version-grace.lock` serializes the
///    load-mutate-save sequence within `save_grace_state`. Concurrent
///    callers block on the lock; sequential ones merge correctly.
///
/// 2. **MIN merge-on-save.** Even with the lock, a caller that read
///    the file before another process wrote it can have a stale view.
///    `save_grace_state` re-reads the on-disk state under the lock
///    and merges record-by-record: for any `observed_version` present
///    in BOTH the in-memory state and the on-disk state, the persisted
///    `first_seen_unix` is `min(in_memory, on_disk)`. Records present
///    in only one side are preserved verbatim. This guarantees the
///    grace clock never advances backwards (toward "now") on save.
pub fn save_grace_state(base_dir: &Path, state: &GraceState) -> Result<(), ConfigError> {
    let path = base_dir.join(VERSION_GRACE_FILE);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Acquire the per-base-dir lock BEFORE the merge re-read so that
    // (a) the on-disk state we merge against is stable, and (b) two
    // concurrent writers don't both observe each other's pre-merge
    // file content. The lock file is in the same directory as the
    // grace state file; same-base-dir callers serialize.
    let lock_path = base_dir.join(VERSION_GRACE_LOCK_FILE);
    let _guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| ConfigError::InvalidJson {
            path: lock_path.clone(),
            reason: format!("lock: {e}"),
        })?;

    // Merge-on-save: re-read the persisted state under the lock and
    // pick `MIN(first_seen_unix)` per `observed_version`. Records the
    // in-memory state has not seen are preserved from disk.
    let merged = merge_grace_states(load_grace_state(base_dir), state);

    let json = serde_json::to_string_pretty(&merged).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialize: {e}"),
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("write: {e}"),
        });
    }
    if secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: "secure_file: chmod failed".into(),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }
    Ok(())
}

/// Filename for the per-base-dir advisory lock (R-MEDIUM-1).
pub const VERSION_GRACE_LOCK_FILE: &str = "coc-version-grace.lock";

/// Merge two grace states by `observed_version`. For shared records
/// the surviving `first_seen_unix` is the MINIMUM of the two —
/// upholding spec 09 §9.5.3 ("the clock does not restart on
/// subsequent observations") even when load-mutate-save races
/// produce divergent in-memory views.
///
/// Visible for testing — used by the merge-on-save path inside
/// [`save_grace_state`] AND by the concurrent-writer regression test.
pub(crate) fn merge_grace_states(on_disk: GraceState, in_memory: &GraceState) -> GraceState {
    use std::collections::HashMap;
    let mut merged: HashMap<String, GraceRecord> = HashMap::new();
    for r in on_disk.records.into_iter() {
        merged.insert(r.observed_version.clone(), r);
    }
    for r in &in_memory.records {
        merged
            .entry(r.observed_version.clone())
            .and_modify(|existing| {
                if r.first_seen_unix < existing.first_seen_unix {
                    existing.first_seen_unix = r.first_seen_unix;
                }
            })
            .or_insert_with(|| r.clone());
    }
    let mut records: Vec<GraceRecord> = merged.into_values().collect();
    // Stable sort so the on-disk file is byte-deterministic for a
    // given content, simplifying drift detection by external tools.
    records.sort_by(|a, b| a.observed_version.cmp(&b.observed_version));
    GraceState {
        schema_version: in_memory.schema_version,
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_file_returns_default() {
        let dir = TempDir::new().unwrap();
        let s = load_grace_state(dir.path());
        assert_eq!(s, GraceState::default());
        assert_eq!(s.schema_version, 1);
        assert!(s.records.is_empty());
    }

    #[test]
    fn upsert_inserts_new_record() {
        let mut state = GraceState::default();
        let inserted_at = state.upsert("2.0.0", 1_700_000_000);
        assert_eq!(inserted_at, 1_700_000_000);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0].observed_version, "2.0.0");
        assert_eq!(state.records[0].first_seen_unix, 1_700_000_000);
    }

    #[test]
    fn upsert_returns_existing_first_seen_for_same_version() {
        let mut state = GraceState::default();
        state.upsert("2.0.0", 1_700_000_000);
        // Subsequent observation 1 day later does NOT reset the clock.
        let returned = state.upsert("2.0.0", 1_700_086_400);
        assert_eq!(returned, 1_700_000_000);
        assert_eq!(state.records.len(), 1);
    }

    #[test]
    fn upsert_creates_separate_records_for_different_versions() {
        let mut state = GraceState::default();
        state.upsert("2.0.0", 1_700_000_000);
        state.upsert("2.1.0", 1_700_086_400);
        assert_eq!(state.records.len(), 2);
    }

    #[test]
    fn days_remaining_starts_at_30_for_fresh_observation() {
        let now = 1_700_000_000;
        let remaining = GraceState::days_remaining_at(now, now);
        assert_eq!(remaining, SOFT_GRACE_DAYS as i64);
    }

    #[test]
    fn days_remaining_30_day_soft_grace_holds_at_29_days() {
        // 29 days elapsed → 1 day left in grace.
        let first_seen = 1_700_000_000;
        let now = first_seen + 29 * 86400;
        assert_eq!(GraceState::days_remaining_at(first_seen, now), 1);
    }

    #[test]
    fn days_remaining_31_day_old_observation_is_negative() {
        // 31 days elapsed → grace expired by 1 day. Caller MUST
        // hard-refuse rather than load in degraded mode.
        let first_seen = 1_700_000_000;
        let now = first_seen + 31 * 86400;
        assert_eq!(GraceState::days_remaining_at(first_seen, now), -1);
    }

    #[test]
    fn round_trip_persists_records() {
        let dir = TempDir::new().unwrap();
        let mut original = GraceState::default();
        original.upsert("2.0.0", 1_700_000_000);
        original.upsert("3.5.1", 1_700_500_000);
        save_grace_state(dir.path(), &original).unwrap();
        let reloaded = load_grace_state(dir.path());
        assert_eq!(reloaded, original);
    }

    #[test]
    fn corrupt_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(VERSION_GRACE_FILE), "{ not valid json").unwrap();
        let s = load_grace_state(dir.path());
        assert_eq!(s, GraceState::default());
    }

    #[test]
    fn missing_schema_version_field_loads_with_default() {
        // Forward-compat: an older csq writer may not include
        // schema_version. The reader assigns the default so the file
        // is still useful.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(VERSION_GRACE_FILE),
            r#"{"records": [{"observed_version": "2.0.0", "first_seen_unix": 1700000000}]}"#,
        )
        .unwrap();
        let s = load_grace_state(dir.path());
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.records.len(), 1);
    }

    // ── R-HIGH-2 / R-LOW-2: clock-jump defenses ─────────────────

    /// R-HIGH-2: a forward NTP/clock jump beyond `2 * SOFT_GRACE_DAYS`
    /// (60 days) is treated as expired (fail-closed) rather than
    /// silently absorbed by `saturating_sub` returning a huge
    /// `elapsed_days` that just expires the grace anyway.
    #[test]
    fn days_remaining_clock_leap_forward_caps_at_2x_grace_window() {
        let first_seen = 1_700_000_000;
        // 1 year forward leap: well past the 2x cap (60 days).
        let now = first_seen + 365 * 86400;
        let remaining = GraceState::days_remaining_at(first_seen, now);
        // Returns a strongly-negative value (well past expiry) so
        // `remaining < 0` keeps the caller on the hard-refuse path.
        assert!(
            remaining < 0,
            "clock leap forward must be treated as expired: got remaining={remaining}"
        );
    }

    /// R-LOW-2: backwards-clock returns the full grace window AND
    /// emits a structured warn (visible in test logs). The important
    /// behavior is that the function does not panic on `now < first_seen`
    /// AND does not silently extend a stale grace.
    #[test]
    fn days_remaining_clock_before_epoch_returns_full_window() {
        let first_seen = 1_700_000_000;
        // Backwards clock: 100 days before first_seen.
        let now = first_seen - 100 * 86400;
        let remaining = GraceState::days_remaining_at(first_seen, now);
        // Returns SOFT_GRACE_DAYS — caller treats as fresh grace,
        // but the warn log is the audit signal.
        assert_eq!(remaining, SOFT_GRACE_DAYS as i64);
    }

    /// R-LOW-3: independent grace clocks for distinct unknown
    /// versions — observing 3.0.0 a month after 2.0.0 does NOT
    /// reset 2.0.0's clock; each version's grace runs from its own
    /// `first_seen_unix`.
    #[test]
    fn independent_clocks_for_different_versions() {
        let dir = TempDir::new().unwrap();
        let mut state = GraceState::default();
        state.upsert("2.0.0", 1_700_000_000);
        save_grace_state(dir.path(), &state).unwrap();

        // 31 days later, observe 3.0.0 for the first time.
        let later = 1_700_000_000 + 31 * 86400;
        let mut state2 = load_grace_state(dir.path());
        state2.upsert("3.0.0", later);
        save_grace_state(dir.path(), &state2).unwrap();

        // 2.0.0 grace has expired (31 days elapsed); 3.0.0 grace
        // is fresh (just observed).
        let final_state = load_grace_state(dir.path());
        let v2 = final_state
            .records
            .iter()
            .find(|r| r.observed_version == "2.0.0")
            .expect("2.0.0 record preserved across separate observations");
        let v3 = final_state
            .records
            .iter()
            .find(|r| r.observed_version == "3.0.0")
            .expect("3.0.0 record was created");
        assert_eq!(v2.first_seen_unix, 1_700_000_000);
        assert_eq!(v3.first_seen_unix, later);
        assert_eq!(GraceState::days_remaining_at(v2.first_seen_unix, later), -1);
        assert_eq!(
            GraceState::days_remaining_at(v3.first_seen_unix, later),
            SOFT_GRACE_DAYS as i64
        );
    }

    // ── R-MEDIUM-1: concurrent-writer convergence ───────────────

    /// R-MEDIUM-1: under racing load-mutate-save, the surviving
    /// `first_seen_unix` per `observed_version` is the MIN of the
    /// two writers' views. The clock cannot advance forward via
    /// merge.
    #[test]
    fn merge_grace_states_keeps_min_first_seen_per_version() {
        let on_disk = GraceState {
            schema_version: 1,
            records: vec![GraceRecord {
                observed_version: "2.0.0".into(),
                first_seen_unix: 1_700_000_000,
            }],
        };
        let in_memory = GraceState {
            schema_version: 1,
            records: vec![GraceRecord {
                observed_version: "2.0.0".into(),
                // Later observation: must NOT win the merge.
                first_seen_unix: 1_700_086_400,
            }],
        };
        let merged = merge_grace_states(on_disk, &in_memory);
        assert_eq!(merged.records.len(), 1);
        assert_eq!(merged.records[0].first_seen_unix, 1_700_000_000);
    }

    /// R-MEDIUM-1: records present on only one side are preserved.
    #[test]
    fn merge_grace_states_preserves_unique_records_from_each_side() {
        let on_disk = GraceState {
            schema_version: 1,
            records: vec![GraceRecord {
                observed_version: "2.0.0".into(),
                first_seen_unix: 1_700_000_000,
            }],
        };
        let in_memory = GraceState {
            schema_version: 1,
            records: vec![GraceRecord {
                observed_version: "3.0.0".into(),
                first_seen_unix: 1_700_500_000,
            }],
        };
        let merged = merge_grace_states(on_disk, &in_memory);
        assert_eq!(merged.records.len(), 2);
        // Sorted by observed_version for determinism.
        assert_eq!(merged.records[0].observed_version, "2.0.0");
        assert_eq!(merged.records[1].observed_version, "3.0.0");
    }

    /// R-MEDIUM-1: `std::thread::scope`-based concurrent-writer test.
    /// Two threads both observe the same unknown version with
    /// different `first_seen_unix` values and race save_grace_state.
    /// After both complete, the persisted file MUST contain the
    /// MIN(first_seen_unix) per spec 09 §9.5.3.
    #[test]
    fn concurrent_save_grace_state_keeps_min_first_seen() {
        let dir = TempDir::new().unwrap();
        // Pre-populate with the LATER timestamp so a naive
        // last-write-wins implementation would leave the later
        // value on disk after the race.
        let later = 1_700_086_400_i64;
        let earlier = 1_700_000_000_i64;
        std::thread::scope(|s| {
            let path = dir.path();
            let h1 = s.spawn(move || {
                let mut st = GraceState::default();
                st.upsert("2.0.0", later);
                save_grace_state(path, &st).unwrap();
            });
            let h2 = s.spawn(move || {
                let mut st = GraceState::default();
                st.upsert("2.0.0", earlier);
                save_grace_state(path, &st).unwrap();
            });
            h1.join().unwrap();
            h2.join().unwrap();
        });
        let final_state = load_grace_state(dir.path());
        assert_eq!(final_state.records.len(), 1);
        assert_eq!(
            final_state.records[0].first_seen_unix, earlier,
            "merge-on-save must keep the earlier first_seen_unix even under race"
        );
    }

    /// R-MEDIUM-3: a read-only `base_dir` causes save_grace_state to
    /// fail, but load_grace_state still proceeds with WARN; the
    /// caller (check_version_envelope) still produces a verdict from
    /// the in-memory state. We test the load side here — the save
    /// side's error path is exercised by the merge tests above.
    #[test]
    fn load_grace_state_proceeds_when_base_dir_is_read_only() {
        let dir = TempDir::new().unwrap();
        // Write a valid state, then make the directory read-only.
        let mut state = GraceState::default();
        state.upsert("2.0.0", 1_700_000_000);
        save_grace_state(dir.path(), &state).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
            perms.set_mode(0o555); // r-x for everyone
            std::fs::set_permissions(dir.path(), perms).unwrap();
        }

        // Load still works (read-only is fine for reading).
        let loaded = load_grace_state(dir.path());
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].observed_version, "2.0.0");

        #[cfg(unix)]
        {
            // Restore so TempDir's drop can clean up.
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dir.path(), perms).unwrap();
        }
    }
}
