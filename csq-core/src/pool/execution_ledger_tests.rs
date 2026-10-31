//! an internal ticket R1 accounting regressions; all clocks, processes and storage are isolated.

use super::execution_ledger::{BudgetError, BudgetLedger, Reservation, ReserveResult};
use super::store::ExecutionCandidate;
use super::types::{KeySource, PoolEntry, PoolName, Reset};
use super::{LedgerIdentity, LedgerState};
use rusqlite::params;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

const DOLLAR: u64 = 1_000_000_000;
const GENERATION: &str = "00000000-0000-4000-8000-000000000001";
const REPLACEMENT: &str = "00000000-0000-4000-8000-000000000002";
// Far-future, injected dates: no assertion depends on the host's current clock.
const START: &str = "2100-01-01T00:00:00Z";

fn at(value: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .timestamp()
}

fn candidate(cap: f64) -> ExecutionCandidate {
    ExecutionCandidate {
        entry: PoolEntry {
            name: PoolName::new("synthetic-ledger-key").unwrap(),
            provider: "anthropic".into(),
            source: KeySource::SecretStore,
            reset: None,
            monthly_cap_usd: Some(cap),
            added_at: START.into(),
        },
        generation: GENERATION.into(),
        fingerprint: "a".repeat(64),
    }
}

fn held(result: Result<ReserveResult, BudgetError>) -> Reservation {
    match result.unwrap() {
        ReserveResult::Held(reservation) => reservation,
        ReserveResult::CapBlocked => panic!("expected a hold, got settled cap exhaustion"),
        ReserveResult::InFlightBlocked => panic!("expected a hold, got in-flight exhaustion"),
        ReserveResult::Cooling => panic!("expected a hold, got cooldown"),
        other => panic!("expected a hold, got {other:?}"),
    }
}

fn database(base: &Path) -> PathBuf {
    base.join("pool/execution-ledger.sqlite3")
}

fn assert_unknown(result: Result<ReserveResult, BudgetError>) {
    assert!(matches!(result, Ok(ReserveResult::Unresolved)));
}

#[test]
fn execution_ledger_restart_preserves_holds_then_settles_actual_at_exact_cap() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let first = held(ledger.reserve(&key, 8 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    assert_eq!(first.generation, GENERATION);
    assert_eq!(first.held_nanos, 8 * DOLLAR);
    assert!(!first.id.is_empty());
    assert!(!first.period.is_empty());
    drop(ledger);

    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert!(matches!(
        ledger.reserve(&key, 3 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.settle(&first, 3 * DOLLAR).unwrap();
    drop(ledger);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let rest = held(ledger.reserve(&key, 7 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    ledger.settle(&rest, 7 * DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::CapBlocked)
    ));
}

#[test]
fn execution_ledger_sums_settled_and_every_hold_using_integer_nanodollars() {
    let base = TempDir::new().unwrap();
    let key = candidate(0.000_000_010_5); // floor to ten nanodollars, not eleven.
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let first = held(ledger.reserve(&key, 6, at(START), at("2199-01-01T00:00:00Z")));
    ledger.settle(&first, 3).unwrap();
    let second = held(ledger.reserve(&key, 4, at(START), at("2199-01-01T00:00:00Z")));
    let third = held(ledger.reserve(&key, 3, at(START), at("2199-01-01T00:00:00Z")));
    assert_ne!(second.id, third.id);
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.release(&second).unwrap();
    ledger.release(&third).unwrap();
    let remaining = held(ledger.reserve(&key, 7, at(START), at("2199-01-01T00:00:00Z")));
    ledger.settle(&remaining, 7).unwrap();
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::CapBlocked)
    ));
}

#[test]
fn execution_ledger_cap_scaling_does_not_round_binary_value_upward() {
    let base = TempDir::new().unwrap();
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    // Binary f64 0.3 is strictly less than 3/10. Its exact scaled floor is
    // 299_999_999; multiplying as f64 first rounds it up to 300_000_000.
    let key = candidate(0.3);
    assert!(matches!(
        ledger.reserve(&key, 300_000_000, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::BelowHold)
    ));
    held(ledger.reserve(&key, 299_999_999, at(START), at("2199-01-01T00:00:00Z")));
}

#[test]
fn execution_ledger_cap_edits_do_not_resize_or_cancel_existing_holds() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(10.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let old = held(ledger.reserve(&key, 8 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    key.entry.monthly_cap_usd = Some(5.0);
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.settle(&old, 6 * DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::CapBlocked)
    ));
    key.entry.monthly_cap_usd = Some(10.0);
    held(ledger.reserve(&key, 4 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
}

#[test]
fn execution_ledger_settles_into_original_utc_calendar_period_after_reset() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let old = held(ledger.reserve(
        &key,
        9 * DOLLAR,
        at("2100-01-31T23:59:59Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    let new = held(ledger.reserve(
        &key,
        5 * DOLLAR,
        at("2100-02-01T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    assert_ne!(old.period, new.period);
    ledger.settle(&old, 9 * DOLLAR).unwrap();
    drop(ledger);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    held(ledger.reserve(
        &key,
        5 * DOLLAR,
        at("2100-02-01T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    assert!(matches!(
        ledger.reserve(
            &key,
            1,
            at("2100-02-01T00:00:00Z"),
            at("2199-01-01T00:00:00Z")
        ),
        Ok(ReserveResult::InFlightBlocked)
    ));
}

#[test]
fn execution_ledger_monthly_day_boundary_is_utc_and_repeats() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(1.0);
    key.entry.reset = Some(Reset::Day { day_of_month: 28 });
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let first = held(ledger.reserve(
        &key,
        DOLLAR,
        at("2100-01-27T23:59:59Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    ledger.settle(&first, DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(
            &key,
            1,
            at("2100-01-27T23:59:59Z"),
            at("2199-01-01T00:00:00Z")
        ),
        Ok(ReserveResult::CapBlocked)
    ));
    let second = held(ledger.reserve(
        &key,
        DOLLAR,
        at("2100-01-28T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    ledger.settle(&second, DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(
            &key,
            1,
            at("2100-02-27T23:59:59Z"),
            at("2199-01-01T00:00:00Z")
        ),
        Ok(ReserveResult::CapBlocked)
    ));
    held(ledger.reserve(
        &key,
        DOLLAR,
        at("2100-02-28T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
}

#[test]
fn execution_ledger_iso_reset_is_one_time_with_added_at_as_initial_window() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(1.0);
    key.entry.added_at = "2099-11-01T00:00:00Z".into();
    key.entry.reset = Some(Reset::Date {
        date: "2100-01-15".into(),
    });
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let before = held(ledger.reserve(
        &key,
        DOLLAR,
        at("2099-11-30T23:59:59Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    ledger.settle(&before, DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(
            &key,
            1,
            at("2100-01-14T23:59:59Z"),
            at("2199-01-01T00:00:00Z")
        ),
        Ok(ReserveResult::CapBlocked)
    ));
    let after = held(ledger.reserve(
        &key,
        DOLLAR,
        at("2100-01-15T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    assert_ne!(before.period, after.period);
    ledger.settle(&after, DOLLAR).unwrap();
    assert!(matches!(
        ledger.reserve(
            &key,
            1,
            at("2101-02-01T00:00:00Z"),
            at("2199-01-01T00:00:00Z")
        ),
        Ok(ReserveResult::CapBlocked)
    ));
}

#[test]
fn execution_ledger_quota_rejection_releases_and_persists_cooldown_atomically() {
    let base = TempDir::new().unwrap();
    let key = candidate(1.0);
    let now = at(START);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, DOLLAR, now, at("2199-01-01T00:00:00Z")));
    ledger.reject_quota(&reservation, now + 60).unwrap();
    drop(ledger);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert!(matches!(
        ledger.reserve(&key, DOLLAR, now + 59, at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::Cooling)
    ));
    held(ledger.reserve(&key, DOLLAR, now + 60, at("2199-01-01T00:00:00Z")));
}

#[test]
fn execution_ledger_unknown_hold_survives_restart_reset_and_release_attempt() {
    let base = TempDir::new().unwrap();
    let key = candidate(1.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    ledger.retain_unknown(&reservation).unwrap();
    assert!(matches!(
        ledger.release(&reservation),
        Err(BudgetError::DefiniteDispositionAlreadyRecorded)
    ));
    drop(ledger);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert_unknown(ledger.reserve(
        &key,
        1,
        at("2101-02-01T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
}

#[test]
fn execution_ledger_crash_without_settlement_retains_original_period_hold() {
    let base = TempDir::new().unwrap();
    let key = candidate(1.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, DOLLAR, at(START), at(START) + 60));
    drop(ledger); // Simulate losing the request owner, without a release or settlement.
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::InFlightBlocked)
    ));
    assert_unknown(ledger.reserve(&key, 1, at(START) + 60, at(START) + 120));
    ledger.retain_unknown(&reservation).unwrap();
    assert_unknown(ledger.reserve(
        &key,
        1,
        at("2102-01-01T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
}

#[test]
fn execution_ledger_readded_and_renamed_secret_retains_old_fingerprint_spend() {
    let base = TempDir::new().unwrap();
    let old_key = candidate(1.0);
    let mut new_key = candidate(1.0);
    new_key.generation = REPLACEMENT.into();
    new_key.entry.name = PoolName::new("renamed-synthetic-key").unwrap();
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let old = held(ledger.reserve(&old_key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    ledger.retain_unknown(&old).unwrap();
    assert!(matches!(
        ledger.reserve(&new_key, DOLLAR, at(START), at(START) + 60),
        Ok(ReserveResult::InFlightBlocked)
    ));
    assert_unknown(ledger.reserve(&old_key, 1, at(START), at("2199-01-01T00:00:00Z")));
    ledger
        .resolve(&old_key.fingerprint, &old_key.generation, at(START))
        .unwrap();
    assert!(matches!(
        ledger.reserve(&new_key, 1, at(START), at(START) + 60),
        Ok(ReserveResult::CapBlocked)
    ));
    new_key.fingerprint = "b".repeat(64);
    new_key.generation = "00000000-0000-4000-8000-000000000003".into();
    held(ledger.reserve(&new_key, DOLLAR, at(START), at(START) + 60));
}

#[test]
fn execution_ledger_reset_edits_count_every_overlapping_stored_window() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(10.0);
    let now = at("2100-01-20T00:00:00Z");
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let old = held(ledger.reserve(&key, 6 * DOLLAR, now, now + 60));
    ledger.settle(&old, 6 * DOLLAR).unwrap();
    key.entry.reset = Some(Reset::Day { day_of_month: 20 });
    let current = held(ledger.reserve(&key, 4 * DOLLAR, now, now + 60));
    assert!(matches!(
        ledger.reserve(&key, 1, now, now + 60),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.settle(&current, 4 * DOLLAR).unwrap();
    key.entry.reset = Some(Reset::Date {
        date: "2100-01-20".into(),
    });
    assert!(matches!(
        ledger.reserve(&key, 1, now, now + 60),
        Ok(ReserveResult::CapBlocked)
    ));
    // An ended stored window still overlaps the edited one-time window.
    let february = at("2100-02-01T00:00:00Z");
    assert!(matches!(
        ledger.reserve(&key, 6 * DOLLAR, february, february + 60),
        Ok(ReserveResult::CapBlocked)
    ));
    key.entry.reset = None;
    let march = at("2100-03-01T00:00:00Z");
    held(ledger.reserve(&key, 10 * DOLLAR, march, march + 60));
}

#[test]
fn execution_ledger_daily_reset_shortening_cannot_re_admit_spent_cap() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(1.0);
    key.entry.reset = Some(Reset::Day { day_of_month: 3 });
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let jan2 = at("2100-01-02T00:00:00Z");
    let spent = held(ledger.reserve(&key, DOLLAR, jan2, jan2 + 60));
    ledger.settle(&spent, DOLLAR).unwrap();
    for (day, now) in [(4, "2100-01-03T00:00:00Z"), (5, "2100-01-04T00:00:00Z")] {
        key.entry.reset = Some(Reset::Day { day_of_month: day });
        assert!(
            matches!(
                ledger.reserve(&key, 1, at(now), at(now) + 60),
                Ok(ReserveResult::CapBlocked)
            ),
            "overlapping reset windows must retain prior spend across days"
        );
    }
}

#[test]
fn execution_ledger_uncapped_and_below_one_hold_are_distinct_ineligible_results() {
    let base = TempDir::new().unwrap();
    let mut key = candidate(1.0);
    let now = at(START);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    key.entry.monthly_cap_usd = None;
    assert!(matches!(
        ledger.reserve(&key, DOLLAR, now, now + 60),
        Ok(ReserveResult::NoCap)
    ));
    key.entry.monthly_cap_usd = Some(1.0);
    assert!(matches!(
        ledger.reserve(&key, 2 * DOLLAR, now, now + 60),
        Ok(ReserveResult::BelowHold)
    ));
    held(ledger.reserve(&key, DOLLAR, now, now + 60));
}

#[test]
fn execution_ledger_resolve_conservatively_settles_only_uncertain_or_overdue_holds() {
    let base = TempDir::new().unwrap();
    let now = at(START);
    let first = candidate(10.0);
    let mut second = candidate(10.0);
    second.generation = REPLACEMENT.into();
    second.entry.name = PoolName::new("renamed-synthetic-key").unwrap();
    let mut third = candidate(10.0);
    third.generation = "00000000-0000-4000-8000-000000000003".into();
    third.entry.name = PoolName::new("third-synthetic-key").unwrap();
    let mut other = candidate(10.0);
    other.generation = "00000000-0000-4000-8000-000000000004".into();
    other.fingerprint = "b".repeat(64);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let unknown = held(ledger.reserve(&first, 2 * DOLLAR, now, now + 60));
    let overdue = held(ledger.reserve(&second, 3 * DOLLAR, now, now + 60));
    let active = held(ledger.reserve(&third, DOLLAR, now, now + 600));
    let unrelated = held(ledger.reserve(&other, 4 * DOLLAR, now, now + 60));
    ledger.retain_unknown(&unknown).unwrap();
    ledger.retain_unknown(&unrelated).unwrap();
    assert_eq!(
        ledger
            .resolve(&first.fingerprint, &first.generation, now + 100)
            .unwrap(),
        2
    );
    assert_eq!(
        ledger
            .resolve(&first.fingerprint, &first.generation, now + 100)
            .unwrap(),
        0
    );
    assert!(matches!(
        ledger.settle(&unknown, 1),
        Err(BudgetError::Undetermined)
    ));
    assert!(matches!(
        ledger.release(&overdue),
        Err(BudgetError::DefiniteDispositionAlreadyRecorded)
    ));
    held(ledger.reserve(&first, 4 * DOLLAR, now + 100, now + 200));
    assert!(matches!(
        ledger.reserve(&first, 1, now + 100, now + 200),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.release(&active).unwrap();
    drop(ledger);
    let accounting = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let unrelated_flag: i64 = accounting
        .query_row(
            "SELECT uncertain FROM generations WHERE generation=?1",
            [&other.generation],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        unrelated_flag, 1,
        "resolve must preserve other fingerprints' flags"
    );
}

const SALT_ID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn bound<T>(
    base: &Path,
    anchor: &mut Option<LedgerIdentity>,
    f: impl FnOnce(&mut BudgetLedger) -> Result<T, BudgetError>,
) -> Result<T, BudgetError> {
    // Model custody's durable PendingInit publication before the ledger callback.
    if anchor.is_none() {
        *anchor = Some(pending_identity());
    }
    BudgetLedger::with_bound(base, anchor, SALT_ID, f)
}

fn pending_identity() -> LedgerIdentity {
    LedgerIdentity {
        id: uuid::Uuid::new_v4().simple().to_string(),
        sequence: 0,
        salt_id: SALT_ID.into(),
        state: LedgerState::PendingInit,
    }
}

#[test]
fn execution_ledger_initialization_requires_prepublished_pending_identity() {
    let base = TempDir::new().unwrap();
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut None, SALT_ID, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    assert!(
        !database(base.path()).exists(),
        "no database may precede custody publication"
    );
    let mut pending = Some(pending_identity());
    let published_id = pending.as_ref().unwrap().id.clone();
    BudgetLedger::with_bound(base.path(), &mut pending, SALT_ID, |_| Ok(())).unwrap();
    assert_eq!(
        pending.as_ref().unwrap().id,
        published_id,
        "creation must use the prepublished ledger id"
    );
    assert_eq!(pending.as_ref().unwrap().state, LedgerState::Active);
}

#[test]
fn execution_ledger_crash_after_initial_commit_finalizes_pending_anchor_without_refund() {
    let base = TempDir::new().unwrap();
    let published = Some(pending_identity());
    let mut unpublished = published.clone();
    BudgetLedger::with_bound(base.path(), &mut unpublished, SALT_ID, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Ok(())
    })
    .unwrap();
    let mut recovered = published; // Crash discarded callback's final Active mirror.
    BudgetLedger::with_bound(base.path(), &mut recovered, SALT_ID, |ledger| {
        assert!(
            matches!(
                ledger.reserve(&candidate(1.0), 1, at(START), at(START) + 60),
                Ok(ReserveResult::InFlightBlocked)
            ),
            "pending initialization recovery must preserve committed holds"
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(recovered.as_ref().unwrap().state, LedgerState::Active);
    assert!(recovered.unwrap().sequence >= unpublished.unwrap().sequence);
}

#[test]
fn execution_ledger_crash_after_active_commit_rolls_stale_mirror_forward_without_refund() {
    let base = TempDir::new().unwrap();
    let mut published = None;
    bound(base.path(), &mut published, |_| Ok(())).unwrap();
    let mut unpublished = published.clone();
    bound(base.path(), &mut unpublished, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Ok(())
    })
    .unwrap();
    let committed = unpublished.unwrap().sequence;
    bound(base.path(), &mut published, |ledger| {
        assert!(
            matches!(
                ledger.reserve(&candidate(1.0), 1, at(START), at(START) + 60),
                Ok(ReserveResult::InFlightBlocked)
            ),
            "active mirror recovery must preserve committed holds"
        );
        Ok(())
    })
    .unwrap();
    assert!(published.unwrap().sequence >= committed);
}

#[test]
fn execution_ledger_pending_initialization_never_adopts_a_different_database() {
    let base = TempDir::new().unwrap();
    let mut first = Some(pending_identity());
    BudgetLedger::with_bound(base.path(), &mut first, SALT_ID, |_| Ok(())).unwrap();
    let bytes = std::fs::read(database(base.path())).unwrap();
    let mut different = Some(pending_identity());
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut different, SALT_ID, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    assert_eq!(std::fs::read(database(base.path())).unwrap(), bytes);
}

#[test]
fn execution_ledger_pending_initialization_resumes_after_empty_file_creation() {
    let base = TempDir::new().unwrap();
    // The leaf in the shape production creates. `ensure_private_dir` is a plain
    // `create_dir_all` on Windows (the default DACL), which pool mode accepts
    // only through the F5 adoption path — and this test is about the resume,
    // not adoption (native run 41155302330: the fixture leaf made the ledger
    // return Unavailable). Unix keeps the 0o700 creator.
    #[cfg(windows)]
    crate::platform::fs_windows_acl::create_private_directory_inheriting(&base.path().join("pool"))
        .unwrap();
    #[cfg(not(windows))]
    crate::platform::fs::ensure_private_dir(&base.path().join("pool")).unwrap();
    crate::platform::fs::write_new_private(&database(base.path()), &[]).unwrap();
    let mut pending = Some(pending_identity());
    let published = pending.as_ref().unwrap().id.clone();
    BudgetLedger::with_bound(base.path(), &mut pending, SALT_ID, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        pending.as_ref().unwrap().id,
        published,
        "empty-file recovery must use the published identity"
    );
    assert_eq!(pending.as_ref().unwrap().state, LedgerState::Active);
    BudgetLedger::with_bound(base.path(), &mut pending, SALT_ID, |ledger| {
        assert!(
            matches!(
                ledger.reserve(&candidate(1.0), 1, at(START), at(START) + 60),
                Ok(ReserveResult::InFlightBlocked)
            ),
            "empty-file recovery must not initialize twice and refund its first hold"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn execution_ledger_active_empty_database_and_foreign_pending_schema_fail_closed() {
    for active in [true, false] {
        let base = TempDir::new().unwrap();
        crate::platform::fs::ensure_private_dir(&base.path().join("pool")).unwrap();
        crate::platform::fs::write_new_private(&database(base.path()), &[]).unwrap();
        let mut anchor = Some(pending_identity());
        if active {
            anchor.as_mut().unwrap().state = LedgerState::Active;
        } else {
            let db = rusqlite::Connection::open(database(base.path())).unwrap();
            db.execute_batch(
                "CREATE TABLE unexpected(payload TEXT); INSERT INTO unexpected VALUES('preserve');",
            )
            .unwrap();
        }
        let before = anchor.clone();
        assert!(matches!(
            BudgetLedger::with_bound::<()>(base.path(), &mut anchor, SALT_ID, |_| panic!(
                "active-empty or foreign-schema database must never initialize"
            )),
            Err(BudgetError::Unavailable)
        ));
        assert_eq!(anchor, before);
        let db = rusqlite::Connection::open_with_flags(
            database(base.path()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let meta: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!meta, "refused initialization must leave schema untouched");
    }
}

#[test]
fn execution_ledger_pending_initialization_refuses_sqlite_prefix_lookalike_table() {
    let base = TempDir::new().unwrap();
    crate::platform::fs::ensure_private_dir(&base.path().join("pool")).unwrap();
    crate::platform::fs::write_new_private(&database(base.path()), &[]).unwrap();
    let db = rusqlite::Connection::open(database(base.path())).unwrap();
    db.execute_batch("CREATE TABLE sqliteX(payload TEXT); INSERT INTO sqliteX VALUES('preserve');")
        .unwrap();
    drop(db);
    let mut anchor = Some(pending_identity());
    let before = anchor.clone();
    let result = BudgetLedger::with_bound(base.path(), &mut anchor, SALT_ID, |_| Ok(()));
    assert!(
        matches!(result, Err(BudgetError::Unavailable)),
        "pending initialization must refuse a sqlite-prefix lookalike table"
    );
    assert_eq!(anchor, before);
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let objects: i64 = db
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        objects, 1,
        "refused initialization must not add ledger schema"
    );
    let payload: String = db
        .query_row("SELECT payload FROM sqliteX", [], |row| row.get(0))
        .unwrap();
    assert_eq!(payload, "preserve");
}

#[test]
fn execution_ledger_version_two_upgrade_preserves_existing_holds() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    bound(base.path(), &mut anchor, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Ok(())
    })
    .unwrap();
    let before = stored_rows(base.path());
    let db = rusqlite::Connection::open(database(base.path())).unwrap();
    db.execute_batch(
        "DROP TABLE settled_totals; DROP INDEX reservations_generation; ALTER TABLE meta DROP COLUMN admission_high_water; PRAGMA user_version=2;",
    )
    .unwrap();
    drop(db);
    bound(base.path(), &mut anchor, |_| Ok(())).unwrap();
    assert_eq!(
        stored_rows(base.path()),
        before,
        "schema upgrade must preserve every accounting row"
    );
    bound(base.path(), &mut anchor, |ledger| {
        assert!(matches!(
            ledger.reserve(&candidate(1.0), 1, at(START), at(START) + 60),
            Ok(ReserveResult::InFlightBlocked)
        ));
        Ok(())
    })
    .unwrap();
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, 4,
        "existing ledgers must acquire the high-water and compaction schema"
    );
}

fn stored_rows(base: &Path) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open_with_flags(
        database(base),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut statement = db.prepare("SELECT reservations.*,generations.uncertain,generations.cooldown FROM reservations JOIN generations USING(generation) ORDER BY id").unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn stored_totals(base: &Path) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open_with_flags(
        database(base),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut query = db
        .prepare("SELECT * FROM settled_totals ORDER BY fingerprint,window_start,window_end")
        .unwrap();
    let columns = query.column_count();
    query
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn assert_rebaseline_counts_future_spend(compacted: bool) {
    let base = TempDir::new().unwrap();
    let key = candidate(1.0);
    let february = at("2100-02-15T00:00:00Z");
    let january = at("2100-01-15T00:00:00Z");
    let mut anchor = None;
    bound(base.path(), &mut anchor, |ledger| {
        let spent = held(ledger.reserve(&key, DOLLAR, february, february + 60));
        ledger.settle(&spent, DOLLAR)?;
        if compacted {
            assert_eq!(ledger.compact_for_test(at("2100-04-05T00:00:00Z"))?, 1);
        }
        ledger.rebaseline_clock(january)
    })
    .unwrap();
    bound(base.path(), &mut anchor, |ledger| {
        assert!(
            matches!(
                ledger.reserve(&key, 1, january, january + 60),
                Ok(ReserveResult::CapBlocked)
            ),
            "clock recovery must count future-window spend"
        );
        Ok(())
    })
    .unwrap();
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let clocks: (i64, i64) = db
        .query_row(
            "SELECT max_admission,admission_high_water FROM meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        clocks,
        (january, february),
        "only admissions may change the high-water mark"
    );
}

#[test]
fn execution_ledger_rebaseline_cannot_borrow_future_reservation_spend() {
    assert_rebaseline_counts_future_spend(false);
}

#[test]
fn execution_ledger_rebaseline_cannot_borrow_future_compacted_spend() {
    assert_rebaseline_counts_future_spend(true);
}

#[test]
fn execution_ledger_version_three_migration_protects_already_rebaselined_future_spend() {
    for compacted in [false, true] {
        let base = TempDir::new().unwrap();
        let key = candidate(1.0);
        let february = at("2100-02-15T00:00:00Z");
        let january = at("2100-01-15T00:00:00Z");
        let mut anchor = None;
        bound(base.path(), &mut anchor, |ledger| {
            let spent = held(ledger.reserve(&key, DOLLAR, february, february + 60));
            ledger.settle(&spent, DOLLAR)?;
            if compacted {
                ledger.compact_for_test(at("2100-04-05T00:00:00Z"))?;
            }
            ledger.rebaseline_clock(january)
        })
        .unwrap();
        let rows = stored_rows(base.path());
        let totals = stored_totals(base.path());
        let before = anchor.as_ref().unwrap().sequence;
        let db = rusqlite::Connection::open(database(base.path())).unwrap();
        db.execute_batch(
            "ALTER TABLE meta DROP COLUMN admission_high_water; PRAGMA user_version=3;",
        )
        .unwrap();
        drop(db);
        bound(base.path(), &mut anchor, |_| Ok(())).unwrap();
        assert_eq!(
            stored_rows(base.path()),
            rows,
            "v3 upgrade must preserve reservation state"
        );
        assert_eq!(
            stored_totals(base.path()),
            totals,
            "v3 upgrade must preserve compacted spend"
        );
        assert!(anchor.as_ref().unwrap().sequence > before);
        bound(base.path(), &mut anchor, |ledger| {
            assert!(
                matches!(
                    ledger.reserve(&key, 1, january, january + 60),
                    Ok(ReserveResult::CapBlocked)
                ),
                "legacy migration must protect future recorded spend"
            );
            Ok(())
        })
        .unwrap();
        let db = rusqlite::Connection::open_with_flags(
            database(base.path()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mark: i64 = db
            .query_row("SELECT admission_high_water FROM meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(mark >= at("2100-02-01T00:00:00Z"));
        let index: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='reservations_generation'", [], |row| row.get(0)).unwrap();
        assert_eq!(index, 1);
    }
}

#[test]
fn execution_ledger_rebaseline_only_lowers_clock_preserving_spend_holds_and_cooldown() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let future = at(START) + 100;
    let mut anchor = None;
    bound(base.path(), &mut anchor, |ledger| {
        let spent = held(ledger.reserve(&key, 3 * DOLLAR, future, future + 1000));
        ledger.settle(&spent, 3 * DOLLAR)?;
        let rejected = held(ledger.reserve(&key, DOLLAR, future, future + 1000));
        let pending = held(ledger.reserve(&key, 4 * DOLLAR, future, future + 1000));
        let unknown = held(ledger.reserve(&key, DOLLAR, future, future + 1000));
        ledger.reject_quota(&rejected, future + 1000)?;
        ledger.retain_unknown(&unknown)?;
        assert!(!pending.id.is_empty());
        Ok(())
    })
    .unwrap();
    let before = stored_rows(base.path());
    let now = at(START) + 10;
    bound(base.path(), &mut anchor, |ledger| {
        ledger.rebaseline_clock(now)
    })
    .unwrap();
    assert_eq!(
        stored_rows(base.path()),
        before,
        "clock recovery must not refund or clear any accounting state"
    );
    let mut replacement = key.clone();
    replacement.generation = REPLACEMENT.into();
    bound(base.path(), &mut anchor, |ledger| {
        assert!(matches!(
            ledger.reserve(&replacement, 3 * DOLLAR, now + 1, future + 1000),
            Ok(ReserveResult::InFlightBlocked)
        ));
        held(ledger.reserve(&replacement, 2 * DOLLAR, now + 1, future + 1000));
        ledger.rebaseline_clock(future + 2000)
    })
    .unwrap();
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let maximum: i64 = db
        .query_row("SELECT max_admission FROM meta", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        maximum,
        now + 1,
        "rebaseline must never raise the admission clock"
    );
}

#[test]
fn execution_ledger_candidate_fault_is_local_but_sql_fault_is_global() {
    let base = TempDir::new().unwrap();
    let now = at(START);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let first = candidate(1.0);
    let reservation = held(ledger.reserve(&first, DOLLAR, now, now + 60));
    ledger.release(&reservation).unwrap();
    let mut stale = first.clone();
    stale.fingerprint = "d".repeat(64);
    assert!(
        matches!(
            ledger.reserve(&stale, 1, now, now + 60),
            Err(BudgetError::CandidateUnavailable)
        ),
        "one stale generation must not be reported as a global ledger outage"
    );
    stale.entry.monthly_cap_usd = Some(f64::NAN);
    assert!(matches!(
        ledger.reserve(&stale, 1, now, now + 60),
        Err(BudgetError::CandidateUnavailable)
    ));
    let mut healthy = first.clone();
    healthy.generation = REPLACEMENT.into();
    healthy.fingerprint = "b".repeat(64);
    held(ledger.reserve(&healthy, DOLLAR, now, now + 60));
    drop(ledger);
    let db = rusqlite::Connection::open(database(base.path())).unwrap();
    db.execute_batch("DROP TABLE reservations").unwrap();
    drop(db);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert!(
        matches!(
            ledger.reserve(&healthy, 1, now, now + 60),
            Err(BudgetError::Unavailable)
        ),
        "SQL failures must remain ledger-wide"
    );
}

#[test]
fn execution_ledger_nonpending_release_preserves_definite_recorded_disposition() {
    for disposition in 0..3 {
        let base = TempDir::new().unwrap();
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        let reservation = held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        match disposition {
            0 => ledger.settle(&reservation, DOLLAR).unwrap(),
            1 => ledger.release(&reservation).unwrap(),
            _ => ledger.retain_unknown(&reservation).unwrap(),
        }
        drop(ledger);
        let before = stored_rows(base.path());
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        assert!(matches!(
            ledger.release(&reservation),
            Err(BudgetError::DefiniteDispositionAlreadyRecorded)
        ));
        assert_eq!(
            stored_rows(base.path()),
            before,
            "release must preserve recorded disposition"
        );
        assert!(matches!(
            ledger.reject_quota(&reservation, at(START) + 600),
            Err(BudgetError::DefiniteDispositionAlreadyRecorded)
        ));
        drop(ledger);
        let mut expected = before;
        for row in &mut expected {
            *row.last_mut().unwrap() = rusqlite::types::Value::Integer(at(START) + 600);
        }
        assert_eq!(
            stored_rows(base.path()),
            expected,
            "quota cleanup may update cooldown but must preserve recorded disposition"
        );
    }
}

#[test]
fn execution_ledger_quota_after_resolve_commits_cooldown_without_refunding() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let now = at(START);
    let until = now + 120;
    let mut anchor = None;
    let reservation = bound(base.path(), &mut anchor, |ledger| {
        let reservation = held(ledger.reserve(&key, DOLLAR, now, now + 1));
        assert_eq!(
            ledger.resolve(&key.fingerprint, &key.generation, now + 2)?,
            1
        );
        Ok(reservation)
    })
    .unwrap();
    let previous = anchor.as_ref().unwrap().sequence;
    assert!(matches!(
        bound(base.path(), &mut anchor, |ledger| ledger
            .reject_quota(&reservation, until)),
        Err(BudgetError::DefiniteDispositionAlreadyRecorded)
    ));
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let row: (i64,i64,i64) = db.query_row(
        "SELECT state,actual,cooldown FROM reservations JOIN generations USING(generation) WHERE id=?1",
        [&reservation.id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(
        row,
        (1, DOLLAR as i64, until),
        "definite quota cooldown must survive an already-recorded disposition without a refund"
    );
    drop(db);
    assert!(
        anchor.as_ref().unwrap().sequence > previous,
        "cooldown commit must advance the mirrored sequence"
    );
    bound(base.path(), &mut anchor, |ledger| {
        assert!(
            matches!(
                ledger.reserve(&key, DOLLAR, now + 3, until + 60),
                Ok(ReserveResult::Cooling)
            ),
            "recorded quota cooldown must block selection after reopening"
        );
        held(ledger.reserve(&key, DOLLAR, until, until + 60));
        Ok(())
    })
    .unwrap();
}

#[test]
fn execution_ledger_resolve_safe_current_holds_despite_historical_oversized_rows() {
    for actual in [2 * DOLLAR, u64::MAX] {
        let base = TempDir::new().unwrap();
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        let old = candidate(10.0);
        let bad = held(ledger.reserve(&old, DOLLAR, at(START), at(START) + 60));
        assert!(matches!(
            ledger.settle(&bad, actual),
            Err(BudgetError::Undetermined)
        ));
        let mut current = old.clone();
        current.generation = REPLACEMENT.into();
        let next = at("2100-02-01T00:00:00Z");
        let pending = held(ledger.reserve(&current, DOLLAR, next, next + 60));
        ledger.retain_unknown(&pending).unwrap();
        let resolved = ledger
            .resolve(&current.fingerprint, &current.generation, next + 100)
            .unwrap();
        drop(ledger);
        let db = rusqlite::Connection::open_with_flags(
            database(base.path()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let row: (i64, Option<i64>, Option<String>) = db
            .query_row(
                "SELECT state,actual,overflow_actual FROM reservations WHERE id=?1",
                [&bad.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            if actual == u64::MAX {
                (3, None, Some(actual.to_string()))
            } else {
                (3, Some(actual as i64), None)
            },
            "historical oversized accounting must remain untouched"
        );
        assert_eq!(
            resolved, 1,
            "an older generation's invariant violation must not prevent safe recovery"
        );
        drop(db);
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        assert_unknown(ledger.reserve(&old, 1, next + 100, next + 200));
    }
}

#[test]
fn execution_ledger_identity_is_persisted_even_when_operation_returns_nested_error() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    let result: Result<(), BudgetError> = bound(base.path(), &mut anchor, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Err(BudgetError::Undetermined)
    });
    assert!(matches!(result, Err(BudgetError::Undetermined)));
    let identity = anchor.clone().unwrap();
    assert!(!identity.id.is_empty());
    assert!(identity.sequence > 0);
    assert_eq!(identity.salt_id, SALT_ID);
    bound(base.path(), &mut anchor, |ledger| {
        assert!(matches!(
            ledger.reserve(&candidate(1.0), 1, at(START), at(START) + 60),
            Ok(ReserveResult::InFlightBlocked)
        ));
        Ok(())
    })
    .unwrap();
    assert!(anchor.unwrap().sequence > identity.sequence);
}

#[test]
fn execution_ledger_missing_database_with_manifest_anchor_is_never_recreated() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    bound(base.path(), &mut anchor, |_| Ok(())).unwrap();
    std::fs::remove_file(database(base.path())).unwrap();
    assert!(matches!(
        bound(base.path(), &mut anchor, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    assert!(!database(base.path()).exists());
}

#[test]
fn execution_ledger_initialized_database_with_missing_manifest_anchor_is_refused() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    bound(base.path(), &mut anchor, |_| Ok(())).unwrap();
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut None, SALT_ID, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
}

#[test]
fn execution_ledger_orphaned_sidecar_is_not_pristine_first_initialization() {
    let base = TempDir::new().unwrap();
    let pool = base.path().join("pool");
    crate::platform::fs::ensure_private_dir(&pool).unwrap();
    crate::platform::fs::write_new_private(
        &pool.join("execution-ledger.sqlite3-journal"),
        &[0; 512],
    )
    .unwrap();
    let mut pending = Some(pending_identity());
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut pending, SALT_ID, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    assert!(!database(base.path()).exists());
}

#[test]
fn execution_ledger_anchor_id_mismatch_and_salt_change_fail_closed() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    bound(base.path(), &mut anchor, |_| Ok(())).unwrap();
    let original = anchor.clone();
    bound(base.path(), &mut anchor, |ledger| {
        held(ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60));
        Ok(())
    })
    .unwrap();
    let mut lagging = original.clone();
    bound(base.path(), &mut lagging, |_| Ok(())).unwrap();
    assert_eq!(
        lagging, anchor,
        "newer committed database must roll its mirror forward"
    );
    let mut wrong = anchor.clone();
    wrong.as_mut().unwrap().id = REPLACEMENT.into();
    assert!(matches!(
        bound(base.path(), &mut wrong, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    let wrong_salt = "d".repeat(64);
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut anchor, &wrong_salt, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
    anchor.as_mut().unwrap().salt_id = wrong_salt.clone();
    assert!(matches!(
        BudgetLedger::with_bound(base.path(), &mut anchor, &wrong_salt, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
}

#[test]
fn execution_ledger_rollback_to_older_valid_database_is_refused() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    let reservation = bound(base.path(), &mut anchor, |ledger| {
        ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60)
    })
    .map(|r| held(Ok(r)))
    .unwrap();
    let earlier = std::fs::read(database(base.path())).unwrap();
    bound(base.path(), &mut anchor, |ledger| {
        ledger.settle(&reservation, DOLLAR)
    })
    .unwrap();
    std::fs::write(database(base.path()), earlier).unwrap();
    assert!(matches!(
        bound(base.path(), &mut anchor, |_| Ok(())),
        Err(BudgetError::IdentityMismatch)
    ));
}

#[test]
fn execution_ledger_regressed_admission_clock_is_refused_after_reopen() {
    let base = TempDir::new().unwrap();
    let mut anchor = None;
    let now = at(START) + 100;
    bound(base.path(), &mut anchor, |ledger| {
        let reservation = held(ledger.reserve(&candidate(1.0), DOLLAR, now, now + 60));
        ledger.release(&reservation)
    })
    .unwrap();
    assert!(matches!(
        bound(base.path(), &mut anchor, |ledger| ledger.reserve(
            &candidate(1.0),
            DOLLAR,
            now - 1,
            now + 60
        )),
        Err(BudgetError::ClockRegressed)
    ));
}

#[test]
fn execution_ledger_actual_above_hold_is_durable_undetermined() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    assert!(matches!(
        ledger.settle(&reservation, 2 * DOLLAR),
        Err(BudgetError::Undetermined)
    ));
    drop(ledger);
    let accounting = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let persisted: (i64, i64, i64) = accounting
        .query_row(
            "SELECT held,actual,state FROM reservations WHERE id=?1",
            [&reservation.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(persisted, (DOLLAR as i64, (2 * DOLLAR) as i64, 3));
    drop(accounting);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    assert_unknown(ledger.reserve(
        &key,
        1,
        at("2101-02-01T00:00:00Z"),
        at("2199-01-01T00:00:00Z"),
    ));
    assert!(matches!(
        ledger.release(&reservation),
        Err(BudgetError::DefiniteDispositionAlreadyRecorded)
    ));
}

#[test]
fn execution_ledger_readded_fingerprint_counts_known_actual_above_original_hold() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let now = at(START);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, DOLLAR, now, now + 60));
    assert!(matches!(
        ledger.settle(&reservation, 2 * DOLLAR),
        Err(BudgetError::Undetermined)
    ));
    let mut replacement = key.clone();
    replacement.generation = REPLACEMENT.into();
    replacement.entry.name = PoolName::new("renamed-synthetic-key").unwrap();
    assert!(matches!(
        ledger.reserve(&replacement, 9 * DOLLAR, now, now + 60),
        Ok(ReserveResult::InFlightBlocked)
    ));
    held(ledger.reserve(&replacement, 8 * DOLLAR, now, now + 60));
}

#[test]
fn execution_ledger_resolve_invariant_violation_preserves_actual_and_overflow_rows() {
    fn snapshot(base: &Path, id: &str) -> Vec<rusqlite::types::Value> {
        let db = rusqlite::Connection::open_with_flags(
            database(base),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut statement = db.prepare("SELECT reservations.*,generations.uncertain FROM reservations JOIN generations USING(generation) WHERE id=?1").unwrap();
        let columns = statement.column_count();
        statement
            .query_row([id], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap()
    }
    for actual in [2 * DOLLAR, u64::MAX] {
        let base = TempDir::new().unwrap();
        let mut anchor = None;
        let reservation = bound(base.path(), &mut anchor, |ledger| {
            ledger.reserve(&candidate(10.0), DOLLAR, at(START), at(START) + 60)
        })
        .map(|result| held(Ok(result)))
        .unwrap();
        assert!(matches!(
            bound(base.path(), &mut anchor, |ledger| ledger
                .settle(&reservation, actual)),
            Err(BudgetError::Undetermined)
        ));
        let before = snapshot(base.path(), &reservation.id);
        let before_identity = anchor.clone();
        let result = bound(base.path(), &mut anchor, |ledger| {
            ledger.resolve(
                &candidate(10.0).fingerprint,
                &candidate(10.0).generation,
                at(START) + 100,
            )
        });
        assert_eq!(
            snapshot(base.path(), &reservation.id),
            before,
            "resolution must not alter recorded invariant-violation rows"
        );
        assert_eq!(
            anchor, before_identity,
            "refused resolution must not advance the identity"
        );
        assert!(matches!(
            result,
            Err(BudgetError::ResolveInvariantViolation)
        ));
    }
    assert_eq!(
        BudgetError::ResolveInvariantViolation.to_string(),
        "pool_resolve_invariant_violation"
    );
}

#[test]
fn execution_ledger_completion_replay_neither_double_charges_nor_refunds_settlement() {
    let base = TempDir::new().unwrap();
    let key = candidate(10.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let reservation = held(ledger.reserve(&key, 9 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    ledger.settle(&reservation, 9 * DOLLAR).unwrap();
    // Exact replay may be idempotent or refused, but may not mutate accounting.
    assert!(matches!(
        ledger.settle(&reservation, 9 * DOLLAR),
        Ok(()) | Err(BudgetError::Undetermined)
    ));
    assert!(matches!(
        ledger.settle(&reservation, 1),
        Err(BudgetError::Undetermined)
    ));
    assert!(matches!(
        ledger.release(&reservation),
        Err(BudgetError::DefiniteDispositionAlreadyRecorded)
    ));
    assert!(matches!(
        ledger.reserve(&key, 2 * DOLLAR, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::CapBlocked)
    ));
    held(ledger.reserve(&key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
}

#[test]
fn execution_ledger_reservation_identity_fields_are_bound_to_durable_hold() {
    let base = TempDir::new().unwrap();
    let key = candidate(1.0);
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let original = held(ledger.reserve(&key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
    for field in 0..4 {
        let mut forged = Reservation {
            id: original.id.clone(),
            generation: original.generation.clone(),
            period: original.period.clone(),
            held_nanos: original.held_nanos,
        };
        match field {
            0 => forged.id.push('x'),
            1 => forged.generation = REPLACEMENT.into(),
            2 => forged.period.push('x'),
            _ => forged.held_nanos -= 1,
        }
        assert!(matches!(
            ledger.release(&forged),
            Err(BudgetError::Undetermined)
        ));
    }
    assert!(matches!(
        ledger.reserve(&key, 1, at(START), at("2199-01-01T00:00:00Z")),
        Ok(ReserveResult::InFlightBlocked)
    ));
    ledger.release(&original).unwrap();
    held(ledger.reserve(&key, DOLLAR, at(START), at("2199-01-01T00:00:00Z")));
}

#[test]
fn execution_ledger_nonfinite_caps_and_integer_overflow_fail_closed() {
    let base = TempDir::new().unwrap();
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    for cap in [f64::NAN, f64::INFINITY, -1.0, 0.0, f64::MAX] {
        assert!(ledger
            .reserve(&candidate(cap), 1, at(START), at("2199-01-01T00:00:00Z"))
            .is_err());
    }
    assert!(ledger
        .reserve(
            &candidate(1.0),
            u64::MAX,
            at(START),
            at("2199-01-01T00:00:00Z")
        )
        .is_err());
    // A refused overflowing transaction cannot consume an otherwise valid cap.
    let reservation = held(ledger.reserve(
        &candidate(1.0),
        DOLLAR,
        at(START),
        at("2199-01-01T00:00:00Z"),
    ));
    assert!(matches!(
        ledger.settle(&reservation, u64::MAX),
        Err(BudgetError::Undetermined)
    ));
    assert_unknown(ledger.reserve(&candidate(1.0), 1, at(START), at("2199-01-01T00:00:00Z")));
    drop(ledger);
    let accounting = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let persisted: (Option<i64>, String) = accounting
        .query_row(
            "SELECT actual,overflow_actual FROM reservations WHERE id=?1",
            [&reservation.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(persisted, (None, u64::MAX.to_string()));
}

#[test]
fn execution_ledger_corrupt_database_is_unavailable_with_fixed_error() {
    let base = TempDir::new().unwrap();
    drop(BudgetLedger::open(base.path()).unwrap());
    std::fs::write(
        database(base.path()),
        b"synthetic corruption: private path marker",
    )
    .unwrap();
    match BudgetLedger::open(base.path()) {
        Err(error) => {
            assert!(matches!(error, BudgetError::Unavailable));
            assert_eq!(format!("{error:?}"), "Unavailable");
            assert_eq!(error.to_string(), BudgetError::Unavailable.to_string());
        }
        Ok(_) => panic!("corrupt accounting must not become a fresh empty ledger"),
    }
}

#[cfg(unix)]
#[test]
fn execution_ledger_storage_is_private_and_refuses_unsafe_existing_modes() {
    use std::os::unix::fs::PermissionsExt;
    let base = TempDir::new().unwrap();
    drop(BudgetLedger::open(base.path()).unwrap());
    let pool = base.path().join("pool");
    let db = database(base.path());
    assert_eq!(
        std::fs::metadata(&pool).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        BudgetLedger::open(base.path()),
        Err(BudgetError::Unavailable)
    ));
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&pool, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        BudgetLedger::open(base.path()),
        Err(BudgetError::Unavailable)
    ));
}

#[cfg(unix)]
#[test]
fn execution_ledger_refuses_symlinked_pool_and_leaf_without_touching_target() {
    use std::os::unix::fs::symlink;
    let base = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    symlink(outside.path(), base.path().join("pool")).unwrap();
    assert!(matches!(
        BudgetLedger::open(base.path()),
        Err(BudgetError::Unavailable)
    ));
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    std::fs::remove_file(base.path().join("pool")).unwrap();
    drop(BudgetLedger::open(base.path()).unwrap());
    let target = outside.path().join("victim");
    std::fs::write(&target, b"do not modify").unwrap();
    std::fs::remove_file(database(base.path())).unwrap();
    symlink(&target, database(base.path())).unwrap();
    assert!(matches!(
        BudgetLedger::open(base.path()),
        Err(BudgetError::Unavailable)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"do not modify");
}

#[cfg(unix)]
#[test]
fn execution_ledger_refuses_hardlinked_database_without_modifying_shared_inode() {
    let base = TempDir::new().unwrap();
    drop(BudgetLedger::open(base.path()).unwrap());
    let alias = base.path().join("shared-ledger");
    std::fs::hard_link(database(base.path()), &alias).unwrap();
    let before = std::fs::read(&alias).unwrap();
    assert!(matches!(
        BudgetLedger::open(base.path()),
        Err(BudgetError::Unavailable)
    ));
    assert_eq!(std::fs::read(&alias).unwrap(), before);
}

pub(super) fn admission_read_probe() {
    #[cfg(unix)]
    process_race::after_read();
}

pub(super) fn compaction_checkpoint() {
    #[cfg(unix)]
    process_race::after_compaction();
}

#[test]
fn execution_ledger_compaction_keeps_spend_for_retroactive_windows_and_retains_unresolved() {
    let base = TempDir::new().unwrap();
    let old = candidate(10.0);
    let jan15 = at("2100-01-15T00:00:00Z");
    let end = at("2100-02-01T00:00:00Z");
    let threshold = end + 31 * 86_400;
    let mut ledger = BudgetLedger::open(base.path()).unwrap();
    let spent = held(ledger.reserve(&old, 6 * DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    ledger.settle(&spent, 6 * DOLLAR).unwrap();
    let free = held(ledger.reserve(&old, DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    ledger.settle(&free, 0).unwrap();
    let released = held(ledger.reserve(&old, DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    ledger.release(&released).unwrap();
    let pending = held(ledger.reserve(&old, DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    let unknown = held(ledger.reserve(&old, DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    ledger.retain_unknown(&unknown).unwrap();
    let mut forever = old.clone();
    forever.fingerprint = "b".repeat(64);
    forever.generation = "00000000-0000-4000-8000-000000000003".into();
    forever.entry.reset = Some(Reset::Date {
        date: "2100-01-01".into(),
    });
    let infinite = held(ledger.reserve(&forever, DOLLAR, jan15, at("2199-01-01T00:00:00Z")));
    ledger.settle(&infinite, DOLLAR).unwrap();
    assert_eq!(
        ledger.compact_for_test(i64::MIN).unwrap(),
        0,
        "retention subtraction must not overflow"
    );
    assert_eq!(
        ledger.compact_for_test(threshold - 1).unwrap(),
        0,
        "retain a full 31 days after the stored window end"
    );
    let mut current = old.clone();
    current.generation = REPLACEMENT.into();
    current.entry.reset = Some(Reset::Date {
        date: "2100-04-01".into(),
    });
    assert!(matches!(
        ledger.reserve(&current, 3 * DOLLAR, threshold - 1, threshold + 60),
        Ok(ReserveResult::InFlightBlocked)
    ));
    assert_eq!(ledger.compact_for_test(threshold).unwrap(), 3);
    assert!(
        matches!(
            ledger.reserve(&current, 3 * DOLLAR, threshold, threshold + 60),
            Ok(ReserveResult::InFlightBlocked)
        ),
        "compacted totals must retain identical budget under a later retroactive reset"
    );
    drop(ledger);
    let db = rusqlite::Connection::open_with_flags(
        database(base.path()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let total: i64 = db
        .query_row("SELECT actual FROM settled_totals", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total, (6 * DOLLAR) as i64);
    let retained: i64 = db
        .query_row(
            "SELECT count(*) FROM reservations WHERE id IN(?1,?2,?3)",
            params![pending.id, unknown.id, infinite.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        retained, 3,
        "pending, uncertain and unbounded windows must never compact"
    );
    let details: i64 = db
        .query_row(
            "SELECT count(*) FROM reservations WHERE id IN(?1,?2,?3)",
            params![spent.id, released.id, free.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        details, 0,
        "aged settled and released request details should compact"
    );
    let index: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='reservations_generation'", [], |row| row.get(0)).unwrap();
    assert_eq!(
        index, 1,
        "unresolved generation checks need their own index"
    );
}

#[cfg(unix)]
mod process_race {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    thread_local! {
        static PROBE: RefCell<Option<UnixStream>> = const { RefCell::new(None) };
        static COMPACTION_PROBE: RefCell<Option<UnixStream>> = const { RefCell::new(None) };
    }

    pub(super) fn after_compaction() {
        COMPACTION_PROBE.with_borrow_mut(|slot| {
            if let Some(stream) = slot {
                stream.write_all(b"C").unwrap();
                assert_eq!(byte(stream), b'G');
            }
        });
    }

    pub(super) fn after_read() {
        PROBE.with_borrow_mut(|slot| {
            if let Some(stream) = slot {
                stream.write_all(b"R").unwrap();
                assert_eq!(byte(stream), b'G');
            }
        });
    }

    fn busy(_: i32) -> bool {
        PROBE.with_borrow_mut(|slot| {
            let stream = slot.as_mut().unwrap();
            stream.write_all(b"B").unwrap();
            byte(stream) == b'G'
        })
    }

    fn byte(stream: &mut UnixStream) -> u8 {
        let mut value = [0];
        stream.read_exact(&mut value).unwrap();
        value[0]
    }

    fn accept(listener: &UnixListener) -> UnixStream {
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll references one live descriptor and a valid pollfd for this call.
        assert_eq!(
            unsafe { libc::poll(&mut poll, 1, 10_000) },
            1,
            "child did not connect"
        );
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
    }

    fn child(base: &Path, socket: &Path, home: &Path, role: &str) -> std::process::Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env_clear();
        for name in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TERM",
            "USER",
            "TMPDIR",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let entry = if role == "C" {
            "pool::execution_ledger_tests::process_race::execution_ledger_compaction_contender"
        } else {
            "pool::execution_ledger_tests::process_race::execution_ledger_process_contender"
        };
        command
            .env("HOME", home)
            .env("CSQ_BASE_DIR", base)
            .env("CSQ_LEDGER_RACE_SOCKET", socket)
            .env("CSQ_LEDGER_RACE_ROLE", role)
            .args(["--exact", entry, "--ignored", "--nocapture"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    #[ignore = "child protocol requires parent IPC; invoked with --ignored by execution_ledger_cross_process_immediate_locks_before_admission_snapshot"]
    fn execution_ledger_process_contender() {
        let _env = crate::platform::test_env::lock();
        let Some(socket) = std::env::var_os("CSQ_LEDGER_RACE_SOCKET") else {
            return;
        };
        let role = std::env::var("CSQ_LEDGER_RACE_ROLE").unwrap();
        let base = PathBuf::from(std::env::var_os("CSQ_BASE_DIR").unwrap());
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut ledger = BudgetLedger::open(&base).unwrap();
        if role == "B" {
            ledger.install_busy_probe(busy).unwrap();
        }
        PROBE.with_borrow_mut(|slot| *slot = Some(stream.try_clone().unwrap()));
        stream.write_all(b"Y").unwrap();
        assert_eq!(byte(&mut stream), b'G');
        let result = ledger.reserve(&candidate(1.0), DOLLAR, at(START), at(START) + 60);
        PROBE.with_borrow_mut(|slot| *slot = None);
        let result = match result {
            Ok(ReserveResult::Held(_)) => b'H',
            Ok(ReserveResult::InFlightBlocked) => b'I',
            Err(_) => b'E',
            _ => b'X',
        };
        stream.write_all(&[result]).unwrap();
    }

    #[test]
    #[ignore = "requires parent crash IPC; invoked with --ignored by execution_ledger_compaction_process_crash_preserves_exact_accounting"]
    fn execution_ledger_compaction_contender() {
        let _env = crate::platform::test_env::lock();
        let socket = std::env::var_os("CSQ_LEDGER_RACE_SOCKET").expect("child requires parent IPC");
        let base = PathBuf::from(std::env::var_os("CSQ_BASE_DIR").unwrap());
        let stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut ledger = BudgetLedger::open(&base).unwrap();
        COMPACTION_PROBE.with_borrow_mut(|slot| *slot = Some(stream));
        ledger.compact_for_test(at("2100-03-05T00:00:00Z")).unwrap();
    }

    #[test]
    fn execution_ledger_compaction_process_crash_preserves_exact_accounting() {
        let _env = crate::platform::test_env::lock();
        let base = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let key = candidate(10.0);
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        let old = at("2100-01-15T00:00:00Z");
        let spent = held(ledger.reserve(&key, 6 * DOLLAR, old, old + 60));
        ledger.settle(&spent, 6 * DOLLAR).unwrap();
        drop(ledger);
        // The socket gets a SHORT kernel path: `base` lives under TMPDIR, which is
        // arbitrarily deep on a CI runner, and `sun_path` is 104 bytes on macOS /
        // 108 on Linux. `short_root` is the repository's one source of truth for
        // that bound (csq-core/src/testing/socket_fixture.rs).
        let socket_root = crate::testing::socket_fixture::short_root("csq-lr-").unwrap();
        let socket = socket_root.path().join("compact.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut process = child(base.path(), &socket, home.path(), "C");
        let mut stream = accept(&listener);
        let mut stage = [0];
        let observed = stream.read_exact(&mut stage);
        let killed = process.kill();
        let output = process.wait_with_output().unwrap();
        assert!(
            observed.is_ok(),
            "child must reach the aggregate-write checkpoint before termination"
        );
        assert_eq!(stage, *b"C");
        killed.unwrap();
        assert!(
            !output.status.success(),
            "child must be terminated without Rust cleanup"
        );
        drop(BudgetLedger::open(base.path()).unwrap()); // SQLite recovers its transaction.
        let db = rusqlite::Connection::open_with_flags(
            database(base.path()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let rows: i64 = db
            .query_row("SELECT count(*) FROM reservations", [], |r| r.get(0))
            .unwrap();
        let totals: i64 = db
            .query_row(
                "SELECT coalesce(sum(actual),0) FROM settled_totals",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (rows == 1 && totals == 0) || (rows == 0 && totals == (6 * DOLLAR) as i64),
            "crash must preserve exactly one complete representation of settled spend"
        );
        drop(db);
        let mut current = key;
        current.generation = REPLACEMENT.into();
        current.entry.reset = Some(Reset::Date {
            date: "2100-04-01".into(),
        });
        let now = at("2100-03-05T00:00:00Z");
        let mut ledger = BudgetLedger::open(base.path()).unwrap();
        held(ledger.reserve(&current, 4 * DOLLAR, now, now + 60));
        assert!(matches!(
            ledger.reserve(&current, 1, now, now + 60),
            Ok(ReserveResult::InFlightBlocked)
        ));
    }

    #[test]
    fn execution_ledger_cross_process_immediate_locks_before_admission_snapshot() {
        let _env = crate::platform::test_env::lock();
        let base = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        drop(BudgetLedger::open(base.path()).unwrap());
        // Same bound as the compaction test above: the socket, not the state,
        // needs the short root.
        let socket_root = crate::testing::socket_fixture::short_root("csq-lr-").unwrap();
        let socket = socket_root.path().join("race.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let first = child(base.path(), &socket, home.path(), "A");
        let mut a = accept(&listener);
        assert_eq!(byte(&mut a), b'Y');
        // Open BOTH connections before A reserves, keeping initialization out of the race.
        let second = child(base.path(), &socket, home.path(), "B");
        let mut b = accept(&listener);
        assert_eq!(byte(&mut b), b'Y');
        a.write_all(b"G").unwrap();
        assert_eq!(byte(&mut a), b'R'); // A owns its admission snapshot, before any write.
        b.write_all(b"G").unwrap();
        let first_b_event = byte(&mut b);
        let (first_result, second_result) = if first_b_event == b'B' {
            a.write_all(b"G").unwrap();
            let first_result = byte(&mut a);
            b.write_all(b"G").unwrap(); // Retry BEGIN only after A's durable commit.
            assert_eq!(byte(&mut b), b'R');
            b.write_all(b"G").unwrap();
            (first_result, byte(&mut b))
        } else {
            // Deferred mutation: B already read while A owns the write reservation.
            // Let B fail its snapshot upgrade, then release A; no child is left blocked.
            b.write_all(b"G").unwrap();
            let mut second_result = byte(&mut b);
            while second_result == b'B' {
                b.write_all(b"F").unwrap();
                second_result = byte(&mut b);
            }
            a.write_all(b"G").unwrap();
            (byte(&mut a), second_result)
        };
        for process in [first, second] {
            let output = process.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            first_b_event, b'B',
            "contender read a snapshot before acquiring the write reservation"
        );
        assert_eq!((first_result, second_result), (b'H', b'I'));
    }
}
