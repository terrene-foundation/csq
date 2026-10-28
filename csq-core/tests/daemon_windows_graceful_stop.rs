//! Windows graceful-stop regression coverage.
//!
//! The original scoped-event/server round trips below retain coverage of the
//! legacy compatibility utilities. The r1_production_* tests call the current
//! production signal_shutdown path and own a PID/birth-bound DaemonStopEvent.
//! Scoped legacy fixtures cover verified graceful exit, non-csq refusal and
//! a retained process that outlasts its observation deadline. Every spawned
//! fixture clears its environment and uses temporary home and base paths.

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
        audit_health: csq_core::audit::new_shared(csq_core::audit::AuditHealth::Verified),
        audit_records_unverified: 0,
        anchor_sink: None,
        usage_poller_wake: std::sync::Arc::new(csq_core::daemon::usage_poller::WakeChannel::new()),
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

/// Production path: retain the current process and signal its PID/birth endpoint.
#[tokio::test]
async fn r1_production_bound_stop_signals_owner_event() {
    let _guard = EVENT_MUTEX.lock().await;
    let event =
        csq_core::update::upgrade_guard::quit_event::DaemonStopEvent::create_current().unwrap();
    csq_core::daemon::shutdown_windows::signal_shutdown(std::process::id()).unwrap();
    assert!(event.wait_for_quit(Duration::from_millis(250)).unwrap());
}

#[test]
fn r1_production_missing_pid_is_stale() {
    let pid = u32::MAX;
    assert!(matches!(
        csq_core::daemon::shutdown_windows::signal_shutdown(pid),
        Err(csq_core::error::DaemonError::StalePidFile { pid: stale }) if stale == pid
    ));
}

#[test]
#[ignore = "native subprocess fixture selected explicitly"]
fn r1_pre_upgrade_daemon_child() {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenEventW, WaitForSingleObject},
    };
    let base = std::path::PathBuf::from(std::env::var_os("CSQ_TEST_R1_STOP_BASE").unwrap());
    let scope = std::env::var("CSQ_TEST_R1_SCOPE").unwrap();
    let mode = std::env::var("CSQ_TEST_R1_MODE").unwrap();
    let _event = create_shutdown_event_scoped(&scope).unwrap();
    let mut user = vec![0u16; 257];
    let mut len = user.len() as u32;
    // SAFETY: writable username buffer matches its supplied capacity.
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::WindowsProgramming::GetUserNameW(
                user.as_mut_ptr(),
                &mut len,
            )
        },
        0
    );
    let user = String::from_utf16(&user[..len as usize - 1]).unwrap();
    let name: Vec<u16> = format!(r"Local\csq-daemon-shutdown-{user}{scope}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: scoped existing event and NUL-terminated name; synchronize only.
    let event = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
    assert_ne!(event, 0);
    std::fs::write(base.join("ready"), b"1").unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while !base.join("stop").exists() && std::time::Instant::now() < until {
        // SAFETY: valid retained event; zero-duration observation.
        if unsafe { WaitForSingleObject(event, 0) } == 0 {
            std::fs::write(base.join("signalled"), b"1").unwrap();
            if mode == "exit" {
                // Discriminates request-only success from retained-handle exit.
                std::thread::sleep(Duration::from_millis(250));
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // SAFETY: sole ownership of this secondary observation handle.
    unsafe {
        CloseHandle(event);
    }
}

struct S2LegacyChild {
    child: std::process::Child,
    base: std::path::PathBuf,
    image: std::path::PathBuf,
}
impl Drop for S2LegacyChild {
    fn drop(&mut self) {
        let _ = std::fs::write(self.base.join("stop"), b"1");
        let deadline = std::time::Instant::now() + Duration::from_secs(12);
        let mut reaped = false;
        while std::time::Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if !reaped {
            eprintln!("fixture_reap_unverified pid={}", self.child.id());
            if !std::thread::panicking() {
                panic!("fixture exit unverified");
            }
        }
    }
}

fn s2_spawn_legacy_child(
    root: &std::path::Path,
    tag: &str,
    scope: &str,
    mode: &str,
    daemon: bool,
    foreign: bool,
) -> S2LegacyChild {
    let base = root.join(tag);
    std::fs::create_dir(&base).unwrap();
    let home = base.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        base.join(".csq-stop-fixture"),
        b"csq-private-native-fixture-v1",
    )
    .unwrap();
    let image = base.join(if foreign {
        "unrelated-stop-test.exe"
    } else {
        "csq-stop-test.exe"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_windows-daemon-stop-fixture"), &image).unwrap();
    let mut command = std::process::Command::new(&image);
    command.env_clear();
    for key in [
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    ] {
        command.env(key, &home);
    }
    command.env("CSQ_BASE_DIR", &base);
    if daemon {
        command.args(["daemon", "start"]);
    } else {
        command.arg("status");
    }
    command
        .arg("--fixture-scope")
        .arg(scope)
        .arg("--fixture-base")
        .arg(&base)
        .arg("--fixture-mode")
        .arg(mode)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = S2LegacyChild {
        child: command.spawn().unwrap(),
        base,
        image,
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !child.base.join("ready").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        child.base.join("ready").exists(),
        "fixture readiness unverified"
    );
    child
}

fn assert_legacy_signal_observed(child: &S2LegacyChild) {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while !child.base.join("signalled").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        std::fs::read(child.base.join("signalled")).expect(
            "timeout must follow the native signal; pre-signal refusal is not WAIT_TIMEOUT coverage",
        ),
        b"1",
    );
}

fn r1_legacy_fixture(mode: &str) {
    let _env_guard = csq_core::platform::test_env::lock();
    let _event_guard = EVENT_MUTEX.blocking_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let scope = format!("-test-{}-{mode}", std::process::id());
    let mut child = s2_spawn_legacy_child(
        dir.path(),
        "target",
        &scope,
        if mode == "exit" { "exit" } else { "never" },
        true,
        mode == "foreign",
    );
    // This daemon has a DIFFERENT isolated event and is deliberately outside
    // the supplied fixture census. It models a developer's live host csq and
    // makes a regression to a whole-host test census fail deterministically.
    let mut outside_census = if mode == "exit" {
        Some(s2_spawn_legacy_child(
            dir.path(),
            "outside-census",
            &format!("{scope}-other"),
            "never",
            true,
            false,
        ))
    } else {
        None
    };
    let selected = if mode == "foreign" {
        std::env::current_exe().unwrap()
    } else {
        child.image.clone()
    };
    // Identity and census must finish before signalling. A positive fixture
    // receipt below proves timeout cases reached the post-signal native wait.
    let budget = Duration::from_secs(2);
    let result = csq_core::daemon::shutdown_windows::signal_shutdown_scoped_for_test(
        child.child.id(),
        &[selected],
        &scope,
        budget,
        &[child.child.id()],
    );
    match mode {
        "exit" => {
            result.unwrap();
            assert!(
                child.child.try_wait().unwrap().is_some(),
                "success must prove retained process exit"
            );
            assert!(child.base.join("signalled").exists());
            let outside = outside_census.as_mut().unwrap();
            assert!(outside.child.try_wait().unwrap().is_none());
            assert!(!outside.base.join("signalled").exists());
        }
        "foreign" => {
            assert!(result.is_err());
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                !child.base.join("signalled").exists(),
                "non-csq target was signalled"
            );
            assert!(child.child.try_wait().unwrap().is_none());
        }
        "never" => {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("legacy daemon retained handle did not exit"),
                "{error}"
            );
            assert!(child.child.try_wait().unwrap().is_none());
            assert_legacy_signal_observed(&child);
        }
        _ => panic!("unknown fixture mode"),
    }
}

#[test]
fn r1_legacy_only_daemon_proves_retained_handle_exit() {
    r1_legacy_fixture("exit");
}
#[test]
fn r1_non_csq_pid_file_target_gets_zero_legacy_signals() {
    r1_legacy_fixture("foreign");
}
#[test]
fn r1_legacy_never_exit_names_deadline_without_kill() {
    r1_legacy_fixture("never");
}

#[test]
fn s2_two_legacy_daemons_refuse_with_zero_collateral_signals() {
    let _env_guard = csq_core::platform::test_env::lock();
    let _event_guard = EVENT_MUTEX.blocking_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let scope = format!("-test-{}-two-daemons", std::process::id());
    // Different base directories, SAME isolated event: frozen production sends
    // to both listeners, while the CLI-only sole-daemon census must send none.
    let mut target = s2_spawn_legacy_child(dir.path(), "target", &scope, "exit", true, false);
    let mut bystander =
        s2_spawn_legacy_child(dir.path(), "bystander", &scope, "never", true, false);
    let result = csq_core::daemon::shutdown_windows::signal_shutdown_scoped_for_test(
        target.child.id(),
        &[target.image.clone()],
        &scope,
        Duration::from_secs(2),
        &[target.child.id(), bystander.child.id()],
    );
    assert!(
        result.is_err(),
        "ordinary stop must refuse ambiguous event listeners"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !target.base.join("signalled").exists(),
        "target received collateral-prone signal"
    );
    assert!(
        !bystander.base.join("signalled").exists(),
        "bystander received a legacy signal"
    );
    assert!(target.child.try_wait().unwrap().is_none());
    assert!(bystander.child.try_wait().unwrap().is_none());
}

#[test]
fn s2_same_image_non_daemon_is_stale_without_signal() {
    let _env_guard = csq_core::platform::test_env::lock();
    let _event_guard = EVENT_MUTEX.blocking_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let scope = format!("-test-{}-non-daemon", std::process::id());
    let mut child = s2_spawn_legacy_child(dir.path(), "target", &scope, "never", false, false);
    let result = csq_core::daemon::shutdown_windows::signal_shutdown_scoped_for_test(
        child.child.id(),
        std::slice::from_ref(&child.image),
        &scope,
        Duration::from_millis(10),
        &[child.child.id()],
    );
    assert!(matches!(
        result,
        Err(csq_core::error::DaemonError::StalePidFile { .. })
    ));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!child.base.join("signalled").exists());
    assert!(child.child.try_wait().unwrap().is_none());
}

#[test]
fn s2_legacy_timeout_reports_full_policy_budget() {
    let _env_guard = csq_core::platform::test_env::lock();
    let _event_guard = EVENT_MUTEX.blocking_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let scope = format!("-test-{}-policy-timeout", std::process::id());
    let child = s2_spawn_legacy_child(dir.path(), "target", &scope, "never", true, false);
    let budget = Duration::from_secs(2);
    let result = csq_core::daemon::shutdown_windows::signal_shutdown_scoped_for_test(
        child.child.id(),
        std::slice::from_ref(&child.image),
        &scope,
        budget,
        &[child.child.id()],
    );
    match result {
        Err(csq_core::error::DaemonError::LegacyShutdownTimeout { timeout_ms, .. }) => {
            assert_eq!(timeout_ms, budget.as_millis() as u64);
            assert_legacy_signal_observed(&child);
        }
        other => panic!("expected policy timeout, got {other:?}"),
    }
}
