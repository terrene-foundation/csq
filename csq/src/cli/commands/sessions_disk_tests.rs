use super::*;
use csq_core::sessions::lifecycle_report::LifecycleRow;

/// `report` returns `complete: false` for a store it cannot lock or verify —
/// correct production behaviour whose causes (a contended writer lock, fd
/// exhaustion while the full suite's tests run in parallel, an unreadable or
/// replaced receipt) leave the observation UNKNOWN rather than wrong. A
/// one-shot `report` therefore reds on its PREMISE instead of its property —
/// exactly how this test failed the macOS CI leg while passing in isolation.
/// Retry while the observation is UNKNOWN: every iteration is a real `report`
/// against the same store, the budget keeps a persistent incompleteness LOUD
/// (with the reasons named), and the completeness/row assertions stay the
/// property under test. Mirrors the sibling
/// `csq_core::sessions::lifecycle_report_tests::report_until_complete`.
#[cfg(unix)]
fn report_until_complete(base: &Path) -> LifecycleReport {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let report = lifecycle_report::report(base);
        if report.complete {
            return report;
        }
        // Measured, not discarded: the reasons of EVERY incomplete attempt are
        // printed, so a retry that eventually succeeds still leaves the cause
        // of the original refusal in the captured test output.
        eprintln!(
            "lifecycle report incomplete (attempt {attempts}) — retrying: {:?}",
            report.reasons
        );
        assert!(
            start.elapsed() <= BUDGET,
            "report stayed incomplete within {BUDGET:?} ({attempts} attempts): {:?}",
            report.reasons
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The same discipline for `handle()`, whose `5` (UNDETERMINED) maps 1:1 onto
/// an incomplete `report`. A persistent `5` exhausts the budget loudly.
#[cfg(unix)]
fn handle_until_determined(base: &Path, json: bool) -> i32 {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let code = handle(base, json).unwrap();
        if code != 5 {
            return code;
        }
        // `handle()` exposes only the exit code; re-read the report so every
        // UNDETERMINED attempt's reasons are measured rather than discarded.
        let reasons = lifecycle_report::report(base).reasons;
        eprintln!(
            "session-disk exit UNDETERMINED (5) (attempt {attempts}) — retrying: {reasons:?}"
        );
        assert!(
            start.elapsed() <= BUDGET,
            "session-disk exit stayed UNDETERMINED (5) within {BUDGET:?} ({attempts} attempts): \
             {reasons:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn incomplete_lifecycle_evidence_keeps_payload_and_omits_unknown_fields() {
    let value = payload(LifecycleReport {
        schema: SCHEMA_SESSION_DISK_V1,
        complete: false,
        rows: vec![LifecycleRow {
            generation: "01234567-89ab-4def-8123-0123456789ab".into(),
            pid: 123,
            session_id: None,
            scratch_dir: None,
            state: "launched".into(),
            decision: "KEEP",
            reasons: vec!["scratch_binding_unproved"],
        }],
        reasons: vec!["lifecycle_store_unknown"],
    });
    let line = Envelope::verdict(SCHEMA_SESSION_DISK_V1, None, value.complete, value)
        .to_line()
        .unwrap();
    let wire: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(wire["schema"], "csq.session-disk.v1");
    assert_eq!(wire["ok"], false);
    assert_eq!(wire["complete"], false);
    assert_eq!(wire["rows"][0]["decision"], "KEEP");
    assert_eq!(wire["rows"][0]["reasons"][0], "scratch_binding_unproved");
    assert_eq!(wire["reasons"][0], "lifecycle_store_unknown");
    for absent in ["session_id", "scratch_dir"] {
        assert!(wire["rows"][0].get(absent).is_none());
    }
    assert!(wire.get("error").is_none());
    assert!(wire.get("payload").is_none());
}

#[test]
fn missing_lifecycle_store_uses_distinct_undetermined_exit() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("accounts");
    for json in [false, true] {
        assert_eq!(
            handle(&base, json).unwrap(),
            5,
            "incomplete evidence must differ from command error 1"
        );
        assert!(!base.exists(), "report must not create missing state");
    }
}

#[cfg(unix)]
#[test]
fn complete_lifecycle_store_uses_success_exit_without_retirement_proof() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(temp.path()).unwrap().join("accounts");
    let handle_dir = base.join("term-fixture");
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&handle_dir).unwrap();
    std::fs::set_permissions(&handle_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ticket = csq_core::sessions::lifecycle::prepare_exec(&handle_dir).unwrap();
    let report = report_until_complete(&base);
    assert!(report.rows.iter().all(|row| row.decision == "KEEP"));
    for json in [false, true] {
        assert_eq!(handle_until_determined(&base, json), 0);
    }
}
