//! Explicit admission samples; no filesystem, process, or ambient UTC dependency.
use super::*;
use std::cell::Cell;

#[test]
fn rollback_survives_recreated_admission_contexts_without_further_raw_reads() {
    let reads = Cell::new(0);
    let raw = || {
        let samples = [110, 115, 114, 120];
        let n = reads.get();
        reads.set(n + 1);
        Ok(samples[n.min(samples.len() - 1)])
    };
    let provider = AdmissionProvider::new(&raw);
    let admitted = || provider.observe();
    assert_eq!(
        AdmissionClock::new(100.into(), &admitted)
            .observe()
            .unwrap(),
        110
    );
    assert_eq!(
        AdmissionClock::new(100.into(), &admitted)
            .observe()
            .unwrap(),
        115
    );
    let rollback = AdmissionClock::new(100.into(), &admitted)
        .observe()
        .unwrap_err();
    assert_eq!(rollback.cause, Some(Cause::Clock));
    let retry = AdmissionClock::new(100.into(), &admitted)
        .observe()
        .unwrap_err();
    assert_eq!(retry.cause, Some(Cause::Clock));
    assert_eq!(
        reads.get(),
        3,
        "latched rollback must not re-read raw UTC on retry"
    );
}

#[test]
fn transient_provider_error_remains_retryable_without_latching() {
    let reads = Cell::new(0);
    let raw = || {
        reads.set(reads.get() + 1);
        match reads.get() {
            1 => Ok(110),
            2 => Err(DirectiveError::undet(
                "fixture temporary clock read failure",
            )),
            _ => Ok(111),
        }
    };
    let provider = AdmissionProvider::new(&raw);
    assert_eq!(provider.observe().unwrap(), 110);
    assert_eq!(provider.observe().unwrap_err().cause, Some(Cause::Clock));
    assert_eq!(
        provider.observe().unwrap(),
        111,
        "transient clock errors retain ordinary retry policy"
    );
}

#[test]
fn rollback_latch_is_local_to_one_logical_invocation() {
    let reads = Cell::new(0);
    let raw = || {
        reads.set(reads.get() + 1);
        Ok(if reads.get() == 1 { 115 } else { 114 })
    };
    let first = AdmissionProvider::new(&raw);
    assert_eq!(first.observe().unwrap(), 115);
    assert_eq!(first.observe().unwrap_err().cause, Some(Cause::Clock));
    let next = AdmissionProvider::new(&raw);
    assert_eq!(
        next.observe().unwrap(),
        114,
        "new logical invocation may independently admit honest UTC"
    );
}

#[test]
fn first_admission_below_preflight_floor_latches_across_recreated_contexts() {
    let reads = Cell::new(0);
    let raw = || {
        let samples = [110, 109, 100, 110];
        let n = reads.get();
        reads.set(n + 1);
        Ok(samples[n.min(samples.len() - 1)])
    };
    let provider = AdmissionProvider::new(&raw);
    let admitted = || provider.observe();
    let first = clock(100, std::time::Instant::now(), provider.capture()).unwrap();
    assert_eq!(
        AdmissionClock::new(first, &admitted)
            .observe()
            .unwrap_err()
            .cause,
        Some(Cause::Clock)
    );
    let retry = clock(100, std::time::Instant::now(), provider.capture()).unwrap();
    assert_eq!(
        AdmissionClock::new(retry, &admitted)
            .observe()
            .unwrap_err()
            .cause,
        Some(Cause::Clock)
    );
    assert_eq!(
        reads.get(),
        3,
        "first-admission rollback must stay latched after a lower raw capture"
    );
}

#[test]
fn lower_raw_capture_preserves_admitted_floor_without_latching_healthy_admission() {
    let reads = Cell::new(0);
    let raw = || {
        let samples = [100, 110, 100, 110];
        let n = reads.get();
        reads.set(n + 1);
        Ok(samples[n.min(samples.len() - 1)])
    };
    let provider = AdmissionProvider::new(&raw);
    let admitted = || provider.observe();
    let first = clock(100, std::time::Instant::now(), provider.capture()).unwrap();
    assert_eq!(
        AdmissionClock::new(first, &admitted).observe().unwrap(),
        110
    );
    let next = clock(100, std::time::Instant::now(), provider.capture()).unwrap();
    assert_eq!(
        next.observed(),
        100,
        "capture must return raw UTC, never synthesize the shared floor"
    );
    assert_eq!(
        AdmissionClock::new(next, &admitted).observe().unwrap(),
        110,
        "lower raw captures must not poison healthy later admitted samples"
    );
    assert_eq!(reads.get(), 4, "capture registration must add no raw reads");
}

#[test]
fn raw_capture_below_original_epoch_is_refused_without_disabling_honest_retry() {
    let reads = Cell::new(0);
    let raw = || {
        reads.set(reads.get() + 1);
        Ok(if reads.get() == 1 { 90 } else { 100 })
    };
    let provider = AdmissionProvider::new(&raw);
    let initial = clock(100, std::time::Instant::now(), provider.capture());
    assert_eq!(initial.err().unwrap().cause, Some(Cause::Clock));
    let retry = clock(100, std::time::Instant::now(), provider.capture()).unwrap();
    let admitted = || provider.observe();
    assert_eq!(
        AdmissionClock::new(retry, &admitted).observe().unwrap(),
        100,
        "lower raw preflight is refused locally but honest retry remains permitted"
    );
    assert_eq!(reads.get(), 3);
}

#[test]
fn transient_capture_error_keeps_floor_and_allows_honest_admitted_retry() {
    let reads = Cell::new(0);
    let raw = || {
        reads.set(reads.get() + 1);
        match reads.get() {
            1 => Ok(110),
            2 => Err(DirectiveError::undet("fixture temporary capture failure")),
            _ => Ok(111),
        }
    };
    let provider = AdmissionProvider::new(&raw);
    assert_eq!(provider.capture().unwrap(), 110);
    assert_eq!(provider.capture().unwrap_err().cause, Some(Cause::Clock));
    assert_eq!(
        provider.observe().unwrap(),
        111,
        "capture read errors must retain ordinary retry policy"
    );
    assert_eq!(reads.get(), 3);

    // A separate provider proves a transient capture failure preserves the prior floor.
    let floor_reads = Cell::new(0);
    let floor_raw = || {
        floor_reads.set(floor_reads.get() + 1);
        match floor_reads.get() {
            1 => Ok(110),
            2 => Err(DirectiveError::undet(
                "fixture retained-floor capture failure",
            )),
            3 => Ok(109),
            _ => Ok(111),
        }
    };
    let floor_provider = AdmissionProvider::new(&floor_raw);
    assert_eq!(floor_provider.capture().unwrap(), 110);
    assert_eq!(
        floor_provider.capture().unwrap_err().cause,
        Some(Cause::Clock)
    );
    assert_eq!(
        floor_provider.observe().unwrap_err().cause,
        Some(Cause::Clock),
        "capture failure must retain the successful capture floor against admitted rollback"
    );
    assert_eq!(floor_reads.get(), 3);
    for _ in 0..2 {
        assert_eq!(
            floor_provider.observe().unwrap_err().cause,
            Some(Cause::Clock)
        );
    }
    assert_eq!(
        floor_reads.get(),
        3,
        "latched rollback after a transient capture failure must not re-read raw UTC"
    );
}
