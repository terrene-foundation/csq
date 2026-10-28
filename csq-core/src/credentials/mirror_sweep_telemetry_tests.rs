//! Synthetic actual sweep fixtures; fake elapsed time describes admission only.
use super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
struct Fields(BTreeMap<String, String>);
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.insert(f.name().into(), v.into());
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.insert(f.name().into(), format!("{v:?}"));
    }
}
struct Capture(Arc<Mutex<Vec<Fields>>>);
impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::WARN)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut f = Fields::default();
        event.record(&mut f);
        assert_eq!(*event.metadata().level(), tracing::Level::WARN);
        self.0.lock().unwrap().push(f);
    }
}
fn capture(run: impl FnOnce()) -> Vec<Fields> {
    let _guard = crate::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let rows = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(rows.clone()), run);
    let result = rows.lock().unwrap().clone();
    result
}
fn dirs(base: &Path, pids: &[u32]) {
    for pid in pids {
        std::fs::create_dir_all(base.join(format!("term-{pid}"))).unwrap();
    }
}
fn sweep(
    base: &Path,
    sync: &dyn Fn(&Path) -> Result<bool, PlatformError>,
    elapsed: &Cell<u64>,
) -> MirrorSyncStatus {
    sync_all_handle_dirs_with_budget(
        base,
        sync,
        &|_| BoundedLockOutcome::NotNeeded,
        &|_| true,
        &|delay| elapsed.set(elapsed.get() + delay.as_millis() as u64),
        &save_mirror_sync_status,
        &|| Duration::from_millis(elapsed.get()),
    )
}
fn has_reason(rows: &[Fields], reason: &str) -> bool {
    let key = match reason {
        "Budget" => "deferred",
        "SyncFailed" => "sync_failed",
        "ScanUnknown" => "scan_unknown",
        "ObservationUnknown" => "observation_unknown",
        _ => panic!("fixture reason must be fixed vocabulary"),
    };
    rows.iter().any(|f| {
        f.0.get(key)
            .is_some_and(|value| value.parse::<usize>().unwrap() > 0)
    })
}
fn completed(rows: &[Fields]) -> &Fields {
    rows.iter()
        .find(|f| {
            f.0.get("event_kind")
                .is_some_and(|v| v == "cc_keychain_mirror_sweep_completed")
        })
        .unwrap()
}

#[test]
fn slow_head_rotates_and_healthy_sinks_converge_in_two_sweeps() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10, 20, 30]);
    let elapsed = Cell::new(0);
    let delivered = RefCell::new(Vec::new());
    let sync = |path: &Path| {
        let pid = mirror_sweep_pid(path).unwrap();
        if pid == 10 {
            elapsed.set(11_000);
            Err(PlatformError::Keychain("synthetic failure".into()))
        } else {
            delivered.borrow_mut().push(pid);
            Ok(true)
        }
    };
    let mut first = None;
    let rows = capture(|| first = Some(sweep(base.path(), &sync, &elapsed)));
    let first = first.unwrap();
    assert_eq!((first.failed, first.deferred, first.pending), (1, 2, 3));
    assert!(delivered.borrow().is_empty());
    assert!(has_reason(&rows, "Budget"));
    assert!(has_reason(&rows, "SyncFailed"));
    assert!(completed(&rows).0["elapsed_ms"].parse::<u64>().is_ok());
    assert_eq!(
        elapsed.get(),
        11_000,
        "fake policy clock is separate from observed elapsed time"
    );
    assert_eq!(completed(&rows).0["budget_ms"], "10000");
    assert_eq!(completed(&rows).0["admitted_position"], "1");
    let completion = completed(&rows);
    for row in &rows {
        assert_eq!(row.0["run_epoch_ms"], completion.0["run_epoch_ms"]);
        assert_eq!(row.0["sweep_sequence"], completion.0["sweep_sequence"]);
    }
    elapsed.set(0);
    let mut second = None;
    let second_rows = capture(|| second = Some(sweep(base.path(), &sync, &elapsed)));
    let second = second.unwrap();
    assert_eq!(*delivered.borrow(), vec![20, 30]);
    assert_eq!(second.synced, 2);
    assert_eq!(second.last_admitted_pid, Some(10));
    assert_eq!(
        completed(&second_rows).0["run_epoch_ms"],
        completion.0["run_epoch_ms"]
    );
    assert!(
        completed(&second_rows).0["sweep_sequence"]
            .parse::<u64>()
            .unwrap()
            > completion.0["sweep_sequence"].parse::<u64>().unwrap()
    );
}

#[test]
fn fast_failing_head_does_not_stop_healthy_sinks_in_one_sweep() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10, 20, 30]);
    let elapsed = Cell::new(0);
    let calls = RefCell::new(Vec::new());
    let rows = capture(|| {
        let status = sweep(
            base.path(),
            &|path| {
                let pid = mirror_sweep_pid(path).unwrap();
                calls.borrow_mut().push(pid);
                if pid == 10 {
                    Err(PlatformError::Keychain("synthetic failure".into()))
                } else {
                    Ok(true)
                }
            },
            &elapsed,
        );
        assert_eq!((status.synced, status.failed, status.pending), (2, 1, 1));
    });
    assert_eq!(*calls.borrow(), vec![10, 10, 20, 30]);
    assert_eq!(elapsed.get(), 100);
    assert!(has_reason(&rows, "SyncFailed"));
    assert!(!has_reason(&rows, "Budget"));
}

#[test]
fn unknown_scan_is_not_drain_and_recovers_in_one_available_sweep() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("missing");
    let elapsed = Cell::new(0);
    let rows = capture(|| {
        let status = sweep(
            &base,
            &|_| panic!("missing scan cannot admit a sink"),
            &elapsed,
        );
        assert!(status.sessions_undetermined);
        assert_eq!((status.failed, status.pending), (1, 1));
    });
    assert!(has_reason(&rows, "ScanUnknown"));
    assert_eq!(completed(&rows).0["sessions_undetermined"], "true");
    dirs(&base, &[10]);
    let recovered = sweep(&base, &|_| Ok(true), &elapsed);
    assert_eq!((recovered.synced, recovered.pending), (1, 0));
    assert!(
        recovered.sessions_undetermined,
        "delivery drain is independent of unknown Login evidence"
    );
}

#[test]
fn budget_exhausted_after_lock_defers_without_write_and_next_sweep_converges() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let elapsed = Cell::new(0);
    let calls = Cell::new(0);
    let rows = capture(|| {
        let status = sync_all_handle_dirs_with_budget(
            base.path(),
            &|_| {
                calls.set(calls.get() + 1);
                Ok(true)
            },
            &|_| {
                elapsed.set(10_000);
                BoundedLockOutcome::NotNeeded
            },
            &|_| true,
            &|_| {},
            &save_mirror_sync_status,
            &|| Duration::from_millis(elapsed.get()),
        );
        assert_eq!((status.deferred, status.pending), (1, 1));
    });
    assert_eq!(calls.get(), 0);
    assert!(has_reason(&rows, "Budget"));
    elapsed.set(0);
    let recovered = sweep(
        base.path(),
        &|_| {
            calls.set(calls.get() + 1);
            Ok(true)
        },
        &elapsed,
    );
    assert_eq!(
        (calls.get(), recovered.synced, recovered.pending),
        (1, 1, 0)
    );
}

#[test]
fn telemetry_contains_only_fixed_categories_and_numeric_boolean_fields() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let rows = capture(|| {
        sweep(
            base.path(),
            &|_| {
                Err(PlatformError::Keychain(
                    "synthetic-secret /private/credential".into(),
                ))
            },
            &Cell::new(0),
        );
    });
    assert!(has_reason(&rows, "SyncFailed"));
    assert!(has_reason(&rows, "ObservationUnknown"));
    for row in &rows {
        let allowed = vec![
            "admitted_position",
            "budget_ms",
            "coverage_unknown",
            "cursor_present",
            "deferred",
            "elapsed_ms",
            "event_kind",
            "failed",
            "lock_failed",
            "lock_timed_out",
            "malformed",
            "observation_unknown",
            "owner_unknown",
            "pending",
            "process_id",
            "publication_ok",
            "run_epoch_ms",
            "scan_unknown",
            "sessions_undetermined",
            "skipped",
            "sweep_sequence",
            "sync_failed",
            "synced",
        ];
        assert_eq!(
            row.0.keys().map(String::as_str).collect::<Vec<_>>(),
            allowed
        );
        let all = format!("{row:?}");
        assert!(!all.contains("synthetic-secret") && !all.contains("/private/credential"));
        assert!(!all.contains(&base.path().display().to_string()));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn explicit_sweep_executor_reaches_policy_and_failure_never_falls_back() {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            clear_test_keychain_executor();
        }
    }
    let _env = crate::platform::test_env::lock();
    let _clear = Clear;
    let (base, _handle) = crate::credentials::session_login::mirror_applicability_fixture("claude");
    let rec = std::rc::Rc::new(super::tests::RecordingExecutor::scripted(
        RawContentClassification::Absent,
    ));
    set_test_keychain_executor(rec.clone());
    let result = sync_all_handle_dirs_status(base.path(), &HashMap::new());
    assert_eq!(
        (result.synced, result.pending),
        (1, 0),
        "explicit executor must pass the disabled test guard"
    );
    assert!(rec.calls().iter().any(|(op, _, _)| *op == "find"));
    assert!(rec.last_add_payload().unwrap().contains("synthetic-at"));
    rec.add_ok.set(false);
    let failed = sync_all_handle_dirs_status(base.path(), &HashMap::new());
    assert_eq!(
        (failed.failed, failed.pending),
        (1, 1),
        "injected write failure must remain failure without SecurityCLI fallback"
    );
}

#[test]
fn telemetry_preserves_exact_stateful_policy_clock_invocation_count() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let calls = Cell::new(0);
    let rows = capture(|| {
        let status = sync_all_handle_dirs_with_budget(
            base.path(),
            &|_| Ok(true),
            &|_| BoundedLockOutcome::NotNeeded,
            &|_| true,
            &|_| {},
            &save_mirror_sync_status,
            &|| {
                calls.set(calls.get() + 1);
                Duration::ZERO
            },
        );
        assert_eq!((status.synced, status.pending), (1, 0));
    });
    assert_eq!(
        calls.get(),
        3,
        "only the original pre-attempt/start/post-lock admission checks sample this clock"
    );
    assert_eq!(completed(&rows).0["synced"], "1");
    assert_eq!(completed(&rows).0["publication_ok"], "true");
}

#[test]
fn publication_failure_is_not_drain_even_when_fresh_pending_is_zero() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let rows = capture(|| {
        let status = sync_all_handle_dirs_with_budget(
            base.path(),
            &|_| Ok(true),
            &|_| BoundedLockOutcome::NotNeeded,
            &|_| true,
            &|_| {},
            &|_, _| false,
            &|| Duration::ZERO,
        );
        assert_eq!((status.synced, status.pending), (1, 0));
        assert!(mirror_sync_retry_requested(base.path()));
    });
    assert_eq!(completed(&rows).0["publication_ok"], "false");
    assert_eq!(completed(&rows).0["pending"], "0");
    let recovered = capture(|| {
        let status = sweep(base.path(), &|_| Ok(true), &Cell::new(0));
        assert_eq!((status.synced, status.pending), (1, 0));
        assert!(!mirror_sync_retry_requested(base.path()));
    });
    assert_eq!(completed(&recovered).0["publication_ok"], "true");
}

#[test]
fn default_warn_sink_has_one_nonhealthy_summary_and_healthy_sweep_is_quiet() {
    use crate::credentials::session_login::{LoginEvidence, LoginReason, LoginState, SessionLogin};
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let healthy = capture(|| {
        let status = sync_all_handle_dirs_with_observations(
            base.path(),
            &|_| MirrorHandleObservation {
                result: Ok(true),
                session: SessionLogin::from_evidence(
                    10,
                    Some(AccountNum::try_from(1u16).unwrap()),
                    LoginEvidence {
                        state: LoginState::Current,
                        reason: LoginReason::Current,
                        remedy: None,
                    },
                ),
                malformed: false,
            },
            &|_| BoundedLockOutcome::NotNeeded,
            &|_| true,
            &|_| {},
            &save_mirror_sync_status,
            &|| Duration::ZERO,
        );
        assert_eq!(
            (status.synced, status.pending, status.sessions_undetermined),
            (1, 0, false)
        );
    });
    assert!(
        healthy.is_empty(),
        "a determinate healthy sweep emits no summary"
    );
    let unknown = capture(|| {
        let status = sweep(base.path(), &|_| Ok(true), &Cell::new(0));
        assert_eq!(
            (status.synced, status.pending, status.sessions_undetermined),
            (1, 0, true)
        );
    });
    assert_eq!(
        unknown.len(),
        1,
        "default WARN sink must receive exactly one nonhealthy sweep summary"
    );
    assert_eq!(completed(&unknown).0["observation_unknown"], "1");
    assert_eq!(completed(&unknown).0["sessions_undetermined"], "true");
}

#[test]
fn actual_publication_failure_has_only_one_default_warn_summary() {
    let base = tempfile::tempdir().unwrap();
    dirs(base.path(), &[10]);
    let obstruction = base.path().join(MIRROR_SYNC_STATUS_FILE);
    std::fs::create_dir(&obstruction).unwrap();
    let sentinel = obstruction.join("unrelated-sentinel");
    std::fs::write(&sentinel, b"unchanged").unwrap();
    let rows = capture(|| {
        let status = sweep(base.path(), &|_| Ok(true), &Cell::new(0));
        assert_eq!((status.synced, status.pending), (1, 0));
        assert!(mirror_sync_retry_requested(base.path()));
    });
    assert_eq!(
        rows.len(),
        1,
        "failed actual status publication must not add a second per-item WARN"
    );
    assert_eq!(completed(&rows).0["publication_ok"], "false");
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
    std::fs::remove_file(&sentinel).unwrap();
    std::fs::remove_dir(&obstruction).unwrap();
    let restored = capture(|| {
        let status = sweep(base.path(), &|_| Ok(true), &Cell::new(0));
        assert_eq!((status.synced, status.pending), (1, 0));
        assert!(!mirror_sync_retry_requested(base.path()));
    });
    assert_eq!(restored.len(), 1);
    assert_eq!(completed(&restored).0["publication_ok"], "true");
}
