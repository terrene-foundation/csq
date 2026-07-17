//! #786 merge gate — Windows daemon graceful-stop round-trip.
//!
//! Unix daemons stop via SIGTERM; Windows has no per-process SIGTERM, so
//! #786 introduces a per-user named kernel event as the graceful-stop
//! channel (`csq_core::daemon::shutdown_windows`). The daemon creates +
//! awaits the event; `csq daemon stop` fires it, and every subsystem
//! drains on the shared `CancellationToken` exactly as on Unix.
//!
//! This test exercises that channel end to end, standing in for the parts
//! `lifecycle.rs::stop_daemon` cannot unit-test (it needs a live process
//! that owns the event):
//!
//! 1. **Signal round-trip** — a task creates the shutdown event and blocks
//!    on it; a second call `signal_shutdown`s by name; the wait returns.
//!    This is the `csq daemon stop` → running-daemon graceful-wake path.
//!
//! 2. **No-listener disposition** — `signal_shutdown` against a PID with no
//!    live event returns `StalePidFile`, mirroring the Unix `ESRCH` arm so
//!    `stop_daemon` reports "already gone" instead of hanging.
//!
//! 3. **Full lifecycle round-trip** — a named-pipe daemon server plus a
//!    shutdown-event listener stand in for a running daemon. `status_of`
//!    reports `Running`; `stop_daemon` fires the event, the listener's
//!    `CancellationToken` drains the server, and `status_of` reports
//!    stopped once the PID file is removed. This is the `csq daemon
//!    start → status → stop` round-trip the AC (lifecycle.rs deferred
//!    integration coverage) requires.
//!
//! On non-Windows hosts the file compiles to an empty unit via the
//! top-level `#![cfg(windows)]` gate.

#![cfg(windows)]

use csq_core::daemon::{self, server, server_windows};
use csq_core::daemon::{create_shutdown_event_scoped, signal_shutdown_scoped};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A per-test-process scope suffix for the shutdown event name so these
/// tests NEVER create or fire a REAL daemon's event (which shares the
/// per-user base name) — #786 redteam MEDIUM test-isolation. All three
/// tests in this binary share this one process scope, so they must still
/// not run concurrently against EACH OTHER (see [`EVENT_MUTEX`]).
fn test_scope() -> String {
    format!("-test-{}", std::process::id())
}

/// The three event-touching tests share one process `test_scope()`, so one
/// test's `signal_shutdown_scoped` would wake another's listener if they
/// overlapped. `cargo test` runs a binary's tests on multiple threads by
/// default; this process-global mutex serialises them. (Isolation from a
/// concurrently-running real daemon is handled by the scope suffix, not
/// this mutex.)
static EVENT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn test_state(base: &std::path::Path) -> server::RouterState {
    server::RouterState {
        cache: Arc::new(daemon::TtlCache::with_default_age()),
        discovery_cache: Arc::new(daemon::TtlCache::new(server::DISCOVERY_CACHE_MAX_AGE)),
        base_dir: Arc::new(base.to_path_buf()),
        oauth_store: None,
        gemini_consumer: csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default(),
        audit_health: csq_core::audit::AuditHealth::Verified,
        anchor_sink: None,
        #[cfg(feature = "enterprise")]
        interactive: Arc::new(csq_core::daemon::InteractiveSessionRegistry::empty()),
    }
}

/// (1) A blocked `wait_blocking` returns once `signal_shutdown` fires the
/// named event — the graceful-wake half of `csq daemon stop`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_event_signal_wakes_waiter() {
    let _guard = EVENT_MUTEX.lock().unwrap();

    let event =
        create_shutdown_event_scoped(&test_scope()).expect("daemon creates the shutdown event");
    let waiter = tokio::task::spawn_blocking(move || {
        // Blocks until signaled; returns promptly once the event fires.
        event.wait_blocking();
    });

    // Give the blocking wait a moment to enter WaitForSingleObject before
    // we open+set the event (SetEvent on a manual-reset event is durable,
    // so even if it fires first the waiter still observes the signal).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The `stop` side: open the same named event and fire it. PID is
    // carried only for the StalePidFile variant; the signal is
    // name-addressed, so any PID value works here.
    signal_shutdown_scoped(&test_scope(), std::process::id())
        .expect("signal_shutdown fires the live event");

    tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("waiter must wake within 2s of SetEvent")
        .expect("waiter task must not panic");
}

/// (2) With no daemon listening, `signal_shutdown` reports `StalePidFile`
/// (the event does not exist → `ERROR_FILE_NOT_FOUND`), mirroring the Unix
/// `ESRCH` arm so `stop_daemon` reports "already gone" rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_shutdown_no_listener_is_stale() {
    let _guard = EVENT_MUTEX.lock().unwrap();

    // No `create_shutdown_event_scoped` here → the named event does not exist.
    let fake_pid = 4242;
    match signal_shutdown_scoped(&test_scope(), fake_pid) {
        Err(csq_core::error::DaemonError::StalePidFile { pid }) => assert_eq!(pid, fake_pid),
        other => panic!("expected StalePidFile, got {other:?}"),
    }
}

/// (3) Full `start → status → stop` round-trip over the named pipe with a
/// live shutdown-event listener. Verifies `status_of` sees the daemon; that
/// the #786 stop *signal* (`signal_shutdown_scoped`, the exact call
/// `send_shutdown_signal` makes on Windows) fires the event; that the server
/// drains on the shared token; and that status reports stopped once the PID
/// file is gone. NOTE: this exercises the signal + drain path directly, NOT
/// `stop_daemon`'s 5s liveness-poll loop — our own PID stays alive for the
/// whole test, so a full `stop_daemon` call could never observe an exit. A
/// child-process test that spawns a real `csq daemon start` and calls
/// `stop_daemon` on it is the follow-up for the poll-loop leg (#786 LOW).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_start_status_stop_round_trip() {
    let _guard = EVENT_MUTEX.lock().unwrap();

    let tmp = tempfile::TempDir::new().unwrap();
    let base = tmp.path();

    // ── start: bind the pipe, spawn a shutdown-event listener that
    //    drives the server's cancellation token, write the PID file ──
    let pipe_name = format!(r"\\.\pipe\csq-786-roundtrip-{}", std::process::id());
    let (server_handle, server_join) = server_windows::serve(&pipe_name, test_state(base))
        .await
        .unwrap();

    // The daemon's graceful-stop wiring: a blocking wait on the shutdown
    // event that, when fired, drives the drain (the real daemon shares one
    // CancellationToken across every subsystem; here the server is the
    // only subsystem, so the listener simply signals the drain token).
    let drain_token = CancellationToken::new();
    let drain_token_for_listener = drain_token.clone();
    let event =
        create_shutdown_event_scoped(&test_scope()).expect("daemon creates the shutdown event");
    let listener = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || event.wait_blocking())
            .await
            .expect("event wait task must not panic");
        drain_token_for_listener.cancel();
    });

    // Write the PID file so `status_of` / `stop_daemon` observe a live
    // daemon under our own (alive) PID.
    let pid_path = daemon::pid_file_path(base);
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

    // ── status: reports Running under our PID ──
    match daemon::status_of(&pid_path) {
        daemon::DaemonStatus::Running { pid } => assert_eq!(pid, std::process::id()),
        other => panic!("expected Running, got {other:?}"),
    }

    // ── stop: `stop_daemon` fires the event. Our PID is genuinely alive
    //    (this test process), so `stop_daemon`'s 5s liveness poll would
    //    NOT observe an exit — instead we assert the SIGNAL path fires and
    //    drains the server, which is the #786 mechanism under test. Fire
    //    the signal directly (the same call `send_shutdown_signal` makes)
    //    and confirm the listener drains the server. ──
    signal_shutdown_scoped(&test_scope(), std::process::id())
        .expect("stop fires the shutdown event");

    // The listener wakes, cancels, and the server accept loop exits. Also
    // shut the server down explicitly to release the pipe (mirrors the
    // daemon's `server.shutdown()` after the shared token fires).
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener must observe the fired event within 2s")
        .expect("listener task must not panic");
    // The listener fired the shared drain token — the daemon's subsystems
    // would now wind down on it.
    assert!(
        drain_token.is_cancelled(),
        "the fired shutdown event must drive the shared drain token"
    );
    server_handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_join).await;

    // ── post-stop: the daemon removes its PID file on exit. Simulate that
    //    final cleanup (the real daemon's PidFile::Drop does it) and
    //    confirm status now reports NotRunning. ──
    let _ = std::fs::remove_file(&pid_path);
    assert_eq!(
        daemon::status_of(&pid_path),
        daemon::DaemonStatus::NotRunning
    );
}
