//! an internal ticket merge gate — Windows daemon graceful-stop round-trip.
//!
//! Unix daemons stop via SIGTERM; Windows has no per-process SIGTERM, so
//! an internal ticket introduces a per-user named kernel event as the graceful-stop
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
//! Two follow-up fixes (2026-07-31), both tracing back to this being an
//! INTEGRATION test binary rather than csq-core's own lib-test binary:
//! `daemon::lifecycle::status_of`'s PID-reuse identity check (landed
//! 2026-07-30) correctly disowns `std::process::id()` here, since this
//! binary's own name never reads as csq — so (3) now stages a genuine
//! `csq`-prefixed child process instead
//! ([`csq_core::platform::process::spawn_csq_named_test_process`]). And
//! [`test_scope`] now takes a per-test tag, so each of the three tests owns
//! a shutdown-event name no sibling test can create or observe.
//!
//! On non-Windows hosts the file compiles to an empty unit via the
//! top-level `#![cfg(windows)]` gate.

#![cfg(windows)]

use csq_core::daemon::{self, server, server_windows};
use csq_core::daemon::{create_shutdown_event_scoped, signal_shutdown_scoped};
use csq_core::platform::process::spawn_csq_named_test_process;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A per-test scope suffix for the shutdown event name, so these tests
/// NEVER create or fire a REAL daemon's event (which shares the per-user
/// base name) — an internal ticket redteam MEDIUM test-isolation. `tag` MUST be a
/// distinct literal per test function (`"signal"` / `"stale"` /
/// `"roundtrip"`, one per test in this file).
///
/// An earlier revision used a single process-wide scope shared by all
/// three tests (`EVENT_MUTEX` alone was relied on for isolation). CI
/// observed `signal_shutdown_no_listener_is_stale` — which asserts NO
/// event exists — finding one anyway: `Ok(())` where `StalePidFile` was
/// expected. Every reachable close/drop path for the shared name traced
/// correctly (each creator's `ShutdownEvent` is moved into a
/// `spawn_blocking` closure whose completion is `.await`ed, synchronously
/// before `EVENT_MUTEX`'s guard drops), so the exact timing mechanism
/// wasn't pinned down — but the shared name is the ONE precondition that
/// makes the observed symptom possible at all: no OTHER code creates this
/// named object. Giving each test an unshareable name removes that
/// precondition outright, independent of the exact mechanism.
/// [`EVENT_MUTEX`] still serialises the event-touching test bodies as
/// defense-in-depth.
fn test_scope(tag: &str) -> String {
    format!("-test-{}-{tag}", std::process::id())
}

/// Serialises the event-touching test bodies on this process. Each test now
/// owns its own [`test_scope`] name (see that function's doc comment), so
/// this is defense-in-depth rather than the sole isolation mechanism —
/// `cargo test` runs a binary's tests on multiple threads by default, and
/// nothing in these tests needs a THIRD test's unrelated work interleaved
/// with a `wait_blocking` / `SetEvent` pair mid-flight.
///
/// An async-aware `tokio::sync::Mutex` — each test intentionally holds the
/// guard across its `.await` points (spawn_blocking / sleep / timeout) for
/// the whole test body, so a `std::sync::Mutex` guard would trip
/// `clippy::await_holding_lock`. Every `#[tokio::test]` runs on its own
/// runtime, so a contending sibling only ever awaits (never blocks a worker
/// that must resume the guard holder); the async mutex is the correct
/// primitive for that.
static EVENT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let _guard = EVENT_MUTEX.lock().await;

    let scope = test_scope("signal");
    let event = create_shutdown_event_scoped(&scope).expect("daemon creates the shutdown event");
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
    signal_shutdown_scoped(&scope, std::process::id())
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
    let _guard = EVENT_MUTEX.lock().await;

    // No `create_shutdown_event_scoped` here → the named event does not exist.
    let fake_pid = 4242;
    match signal_shutdown_scoped(&test_scope("stale"), fake_pid) {
        Err(csq_core::error::DaemonError::StalePidFile { pid }) => assert_eq!(pid, fake_pid),
        other => panic!("expected StalePidFile, got {other:?}"),
    }
}

/// Long-sleep target for [`spawn_csq_named_test_process`] to run as a
/// genuine child process — NOT a real test in its own right. `#[ignore]`d
/// so ordinary `cargo test` runs never execute it directly;
/// `daemon_start_status_stop_round_trip` spawns it explicitly, on a COPY of
/// this very binary renamed to a `csq`-prefixed path, via
/// `--ignored --exact windows_long_sleep_child` — so the child's
/// self-reported executable name reads as csq.
#[test]
#[ignore]
fn windows_long_sleep_child() {
    std::thread::sleep(Duration::from_secs(60));
}

/// (3) Full `start → status → stop` round-trip over the named pipe with a
/// live shutdown-event listener. Verifies `status_of` sees the daemon; that
/// the an internal ticket stop *signal* (`signal_shutdown_scoped`, the exact call
/// `send_shutdown_signal` makes on Windows) fires the event; that the server
/// drains on the shared token; and that status reports stopped once the PID
/// file is gone. NOTE: this exercises the signal + drain path directly, NOT
/// `stop_daemon`'s 5s liveness-poll loop — the staged daemon PID stays alive
/// for the whole test, so a full `stop_daemon` call could never observe an
/// exit. A child-process test that spawns a real `csq daemon start` and
/// calls `stop_daemon` on it is the follow-up for the poll-loop leg (an internal ticket
/// LOW).
///
/// The "live daemon" PID staged here MUST positively resolve as csq —
/// `status_of` disowns any live PID whose reported command isn't ours (see
/// `daemon::lifecycle::status_of`'s identity check, closing the PID-reuse
/// gap the recycled-Teams-helper incident surfaced). This test binary's own
/// PID does not (it reads as `daemon_windows_graceful_stop-<hash>.exe`), so
/// `std::process::id()` can no longer stand in for the daemon's PID the way
/// an earlier revision of this test assumed — [`spawn_csq_named_test_process`]
/// stages a genuine child process whose self-reported name DOES resolve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_start_status_stop_round_trip() {
    let _guard = EVENT_MUTEX.lock().await;
    let scope = test_scope("roundtrip");

    let tmp = tempfile::TempDir::new().unwrap();
    let base = tmp.path();

    // ── start: bind the pipe, spawn a shutdown-event listener that
    //    drives the server's cancellation token, write the PID file ──
    let pipe_name = format!(r"\\.\pipe\csq-786-roundtrip-{}", std::process::id());
    let (server_handle, server_join) = server_windows::serve(&pipe_name, test_state(base))
        .await
        .unwrap();

    // Stage the "live daemon" PID: a genuine child process whose
    // self-reported executable name resolves as csq (see doc comment
    // above). `_daemon_child_dir` must outlive `daemon_child` — it holds
    // the renamed binary's TempDir, and a still-running Windows process
    // keeps its image file locked.
    let (mut daemon_child, _daemon_child_dir) =
        spawn_csq_named_test_process("windows_long_sleep_child");
    let daemon_pid = daemon_child.id();

    // The daemon's graceful-stop wiring: a blocking wait on the shutdown
    // event that, when fired, drives the drain (the real daemon shares one
    // CancellationToken across every subsystem; here the server is the
    // only subsystem, so the listener simply signals the drain token).
    let drain_token = CancellationToken::new();
    let drain_token_for_listener = drain_token.clone();
    let event = create_shutdown_event_scoped(&scope).expect("daemon creates the shutdown event");
    let listener = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || event.wait_blocking())
            .await
            .expect("event wait task must not panic");
        drain_token_for_listener.cancel();
    });

    // Write the PID file so `status_of` / `stop_daemon` observe a live
    // daemon under the staged child's (alive, positively-csq) PID.
    let pid_path = daemon::pid_file_path(base);
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&pid_path, format!("{daemon_pid}\n")).unwrap();

    // ── status: reports Running under the staged child's PID ──
    match daemon::status_of(&pid_path) {
        daemon::DaemonStatus::Running { pid } => assert_eq!(pid, daemon_pid),
        other => panic!("expected Running, got {other:?}"),
    }

    // ── stop: `stop_daemon` fires the event. The staged PID is genuinely
    //    alive (a real child process), so `stop_daemon`'s 5s liveness poll
    //    would NOT observe an exit — instead we assert the SIGNAL path
    //    fires and drains the server, which is the an internal ticket mechanism under
    //    test. Fire the signal directly (the same call
    //    `send_shutdown_signal` makes) and confirm the listener drains the
    //    server. ──
    signal_shutdown_scoped(&scope, daemon_pid).expect("stop fires the shutdown event");

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

    // The staged child has served its purpose — kill + wait it before
    // `_daemon_child_dir` drops (a still-running process holds its exe
    // file locked on Windows, which would make the TempDir cleanup fail).
    let _ = daemon_child.kill();
    let _ = daemon_child.wait();

    // ── post-stop: the daemon removes its PID file on exit. Simulate that
    //    final cleanup (the real daemon's PidFile::Drop does it) and
    //    confirm status now reports NotRunning. ──
    let _ = std::fs::remove_file(&pid_path);
    assert_eq!(
        daemon::status_of(&pid_path),
        daemon::DaemonStatus::NotRunning
    );
}
