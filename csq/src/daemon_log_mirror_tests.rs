//! Actual rolling writer/default filter bytes; no daemon launch or global subscriber.
use tracing_subscriber::prelude::*;

#[test]
fn default_daemon_writer_persists_unknown_sweep_summary_at_warn() {
    let _env = csq_core::platform::test_env::lock();
    let _capture = csq_core::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        std::env::var_os("CSQ_LOG").is_none(),
        "wrapper must preserve default filter without changing host configuration"
    );
    let root = tempfile::tempdir().unwrap();
    let unknown_accounts = root.path().join("synthetic-unknown-accounts");
    std::fs::write(&unknown_accounts, b"unrelated-sentinel").unwrap();
    let (writer, guard) = super::make_writer(root.path()).expect("owned rolling writer");
    let filter = tracing_subscriber::EnvFilter::try_from_env("CSQ_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(writer);
    let subscriber = tracing_subscriber::registry().with(filter).with(file_layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::debug!(event_kind = "la_sink_debug_control");
        let (synced, skipped, pending) = csq_core::credentials::keychain::sync_all_handle_dirs(
            &unknown_accounts,
            &std::collections::HashMap::new(),
        );
        assert_eq!((synced, skipped, pending), (0, 0, 1));
    });
    // The scoped subscriber has dropped its writer; guard drop flushes the real worker.
    drop(guard);
    let dir = csq_core::daemon::log_gc::daemon_log_dir(root.path());
    let mut entries = std::fs::read_dir(&dir)
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    let mut text = String::new();
    for entry in entries {
        assert!(entry.file_type().unwrap().is_file());
        assert!(entry
            .file_name()
            .to_string_lossy()
            .starts_with(csq_core::daemon::log_gc::LOG_FILE_PREFIX));
        text.push_str(&std::fs::read_to_string(entry.path()).unwrap());
    }
    assert!(
        !text.contains("la_sink_debug_control"),
        "default rolling sink filters DEBUG"
    );
    let rows = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        1,
        "real default rolling sink must receive one unknown sweep summary"
    );
    let summary = rows[0].replace('"', "");
    for field in [
        "event_kind=cc_keychain_mirror_sweep_completed",
        "pending=1",
        "failed=1",
        "scan_unknown=1",
        "sync_failed=0",
        "sessions_undetermined=true",
        "publication_ok=false",
        "budget_ms=10000",
        "run_epoch_ms=",
        "process_id=",
        "sweep_sequence=",
    ] {
        assert!(
            summary.contains(field),
            "closed rolling log must contain fixed field {field}"
        );
    }
    assert!(!text.contains(&unknown_accounts.display().to_string()));
    assert!(!text.contains("unrelated-sentinel"));
    assert_eq!(
        std::fs::read(&unknown_accounts).unwrap(),
        b"unrelated-sentinel"
    );
}
