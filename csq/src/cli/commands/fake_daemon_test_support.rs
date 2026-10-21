//! Shared `#[cfg(test)]` fixture: a fake, minimally-responsive csq daemon
//! for tests that exercise a code path gated on `daemon::detect_daemon`
//! reporting `Healthy` (C-R4-3's up-front daemon-health checks in both
//! `codex_supervise::validate_codex_relaunch_target`'s callers and
//! `swap::handoff_to_supervisor`).
//!
//! Governing task item 4 (test-helper hoist): this was previously defined
//! twice — `codex_supervise::tests::{FakeHealthyDaemon, spawn_fake_healthy_daemon}`
//! and an identical `swap::tests::{SwapFakeHealthyDaemon, spawn_swap_fake_healthy_daemon}`
//! — because at the time `swap.rs`'s C-R4-3 fix landed, hoisting the two into
//! one shared helper would have touched a sibling shard's file. Both call
//! sites now use this single definition.
//!
//! Writes THIS test process's own pid into the fake daemon's PID file (a
//! genuinely alive process whose OS-reported command starts with `csq-` —
//! this crate's cargo test binary naming — which `process::is_pid_foreign`
//! accepts as "ours", mirroring `daemon::detect::tests::detect_live_daemon_
//! returns_healthy`'s precedent) and answers exactly one `/api/health` GET
//! with this CLI's own [`csq_core::daemon::CLI_VERSION`], so
//! `version_drift_reason` sees no drift.
//!
//! SAFETY note (environment-safety, not memory-safety): on Linux,
//! `pid_file_path`/`socket_path` resolve through `$XDG_RUNTIME_DIR` rather
//! than `base_dir` whenever that env var is set (common on systemd-managed
//! CI runners) — overriding it to a fixture-local dir for the guard's
//! lifetime is load-bearing, not just isolation: without it this fixture
//! could silently write into (or read from) a REAL daemon's runtime dir on
//! such a host. The override is guarded by the shared cross-module
//! `csq_core::platform::test_env::lock()` mutex so two tests overriding the
//! same process-global env var never race.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
pub(crate) struct FakeHealthyDaemon {
    pid_path: PathBuf,
    // F-flaky: signals the accept loop to stop. Set in `Drop`, BEFORE the
    // pid file is removed — see this struct's `Drop` impl doc.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _listener_thread: std::thread::JoinHandle<()>,
    #[cfg(target_os = "linux")]
    _env_guard: csq_core::platform::test_env::EnvTestGuard,
    #[cfg(target_os = "linux")]
    saved_xdg: Option<String>,
    #[cfg(target_os = "linux")]
    _runtime_dir: tempfile::TempDir,
}

#[cfg(unix)]
impl Drop for FakeHealthyDaemon {
    fn drop(&mut self) {
        // F-flaky: stop the accept loop before anything else — the thread
        // is NOT joined (a blocking `cargo test` teardown for every one of
        // this fixture's callers is not worth the latency), so this is a
        // best-effort signal; the loop's own `Duration::from_millis(5)`
        // poll means it notices within one tick and exits on its own.
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.pid_path);
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `_env_guard` (dropped after this fn returns, per
            // field-drop order) still holds the shared env-test mutex for
            // the duration of this restore.
            unsafe {
                match &self.saved_xdg {
                    Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
    }
}

#[cfg(unix)]
pub(crate) fn spawn_fake_healthy_daemon(base_dir: &Path) -> FakeHealthyDaemon {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Keep the Linux socket in an owned short directory, independent of a
    // runner's arbitrarily deep TMPDIR. State fixtures remain in base_dir.
    #[cfg(target_os = "linux")]
    let runtime_dir = tempfile::Builder::new()
        .prefix("csq-fd-")
        .tempdir_in("/tmp")
        .expect("private short fake daemon runtime dir");

    #[cfg(target_os = "linux")]
    let env_state = {
        let guard = csq_core::platform::test_env::lock();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        // SAFETY: guarded by the shared cross-module env-test mutex above,
        // per `csq_core::platform::test_env`'s documented contract.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", runtime_dir.path());
        }
        (guard, saved)
    };

    let pid_path = csq_core::daemon::pid_file_path(base_dir);
    let sock_path = csq_core::daemon::socket_path(base_dir);
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent).expect("pid file parent dir");
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).expect("socket parent dir");
    }
    // Defensive unlink — a stale socket left by an unrelated prior run (or,
    // off macOS, shared via `$XDG_RUNTIME_DIR`) must not collide with our
    // bind.
    let _ = std::fs::remove_file(&sock_path);

    std::fs::write(&pid_path, std::process::id().to_string()).expect("write fake pid file");

    let listener = UnixListener::bind(&sock_path).expect("bind fake daemon socket");
    // F-flaky (root cause of `handoff_refuses_and_withdraws_request_when_
    // recorded_supervisor_is_dead` intermittently reporting "csq daemon is
    // stale" under full-suite concurrency): the PRIOR version of this
    // thread called `listener.accept()` exactly ONCE and then returned,
    // which DROPS `listener` (moved into the closure) the instant that one
    // connection is handled — closing the socket to any FURTHER connect
    // attempt with `ECONNREFUSED`, which `unix_health_check` reports as
    // `Stale`. Any caller whose flow reaches `detect_daemon` more than
    // once against this fixture (directly, via a retry, or via a second
    // code path this fixture's callers evolve to add later) loses the
    // race the instant the first connection completes — under a
    // uncontended run the ONE health-check this test needs usually lands
    // before that happens; under heavy concurrent subprocess load (this
    // file spawns real child processes in nearly every test) the accept
    // thread can be scheduled late enough that a caller's OWN retry (or a
    // sibling call this function's callers did not anticipate) is the one
    // that hits the already-closed listener. Looping `accept()` for the
    // fixture's entire lifetime removes the one-shot fragility rather than
    // trying to prove which caller path is the second connection.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    listener
        .set_nonblocking(true)
        .expect("set fake daemon listener nonblocking");
    let thread = std::thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);
                    let body = format!("{{\"version\":\"{}\"}}", csq_core::daemon::CLI_VERSION);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    FakeHealthyDaemon {
        pid_path,
        stop,
        _listener_thread: thread,
        #[cfg(target_os = "linux")]
        _env_guard: env_state.0,
        #[cfg(target_os = "linux")]
        saved_xdg: env_state.1,
        #[cfg(target_os = "linux")]
        _runtime_dir: runtime_dir,
    }
}

/// The "no daemon at all" counterpart to [`spawn_fake_healthy_daemon`]: a
/// test that needs `daemon::detect_daemon` to report `NotRunning` against a
/// FRESH tempdir (rather than a genuinely healthy fixture) still needs the
/// SAME `$XDG_RUNTIME_DIR` override, for the SAME reason — on Linux,
/// `pid_file_path`/`socket_path` prefer the process-global env var over
/// `base_dir` whenever it is set, so an un-guarded test is not actually
/// checking `base_dir` at all: it is checking whatever real (or
/// concurrently fixture-mutated) `$XDG_RUNTIME_DIR` happens to hold at that
/// moment. Guarded by the same cross-module mutex, so it never races a
/// sibling test's `spawn_fake_healthy_daemon`/`spawn_no_daemon_env_guard`
/// call on the same process-global var.
#[cfg(unix)]
pub(crate) struct NoDaemonEnvGuard {
    #[cfg(target_os = "linux")]
    _env_guard: csq_core::platform::test_env::EnvTestGuard,
    #[cfg(target_os = "linux")]
    saved_xdg: Option<String>,
}

#[cfg(unix)]
impl Drop for NoDaemonEnvGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `_env_guard` (dropped after this fn returns, per
            // field-drop order) still holds the shared env-test mutex for
            // the duration of this restore.
            unsafe {
                match &self.saved_xdg {
                    Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
    }
}

#[cfg(unix)]
pub(crate) fn spawn_no_daemon_env_guard(base_dir: &Path) -> NoDaemonEnvGuard {
    #[cfg(target_os = "linux")]
    {
        let guard = csq_core::platform::test_env::lock();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        // SAFETY: guarded by the shared cross-module env-test mutex above,
        // per `csq_core::platform::test_env`'s documented contract.
        // `base_dir` is a fresh tempdir with no pid/socket file, so
        // pointing XDG_RUNTIME_DIR at it makes `detect_daemon` genuinely
        // observe `NotRunning`, not whatever the real/ambient runtime dir
        // (or a concurrently-running fixture's) holds.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", base_dir);
        }
        NoDaemonEnvGuard {
            _env_guard: guard,
            saved_xdg: saved,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = base_dir;
        NoDaemonEnvGuard {}
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[test]
    fn fake_daemon_socket_is_healthy_beneath_an_overlong_state_root() {
        let root = tempfile::TempDir::new_in("/tmp").unwrap();
        let state = root.path().join("x".repeat(160));
        std::fs::create_dir(&state).unwrap();
        // macOS resolves its socket through the base path rather than XDG.
        // An owned short alias keeps the kernel address bounded while the
        // physical state still resides beneath the overlong directory.
        #[cfg(target_os = "macos")]
        let base = {
            let alias = root.path().join("s");
            std::os::unix::fs::symlink(&state, &alias).unwrap();
            assert_eq!(
                std::fs::canonicalize(&alias).unwrap(),
                std::fs::canonicalize(&state).unwrap(),
            );
            alias
        };
        #[cfg(not(target_os = "macos"))]
        let base = state.clone();
        let fixture = super::spawn_fake_healthy_daemon(&base);
        let socket = csq_core::daemon::socket_path(&base);
        assert!(!socket.starts_with(&state));
        assert!(socket.as_os_str().len() < 104);
        assert!(matches!(
            csq_core::daemon::detect_daemon(&base),
            csq_core::daemon::DetectResult::Healthy { .. },
        ));
        let runtime = socket.parent().unwrap().to_owned();
        drop(fixture);
        // Linux's fixture owns the short runtime; macOS's root owns the alias.
        #[cfg(target_os = "macos")]
        drop(root);
        assert!(!runtime.exists(), "owned runtime dir is removed on drop");
    }
}
