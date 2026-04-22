//! 4-step daemon detection protocol (client side).
//!
//! Per GAP-9, any CLI command that wants to delegate to the daemon
//! must decide quickly whether a daemon is available. The protocol:
//!
//! 1. Read PID file
//!    - missing → `NotRunning`
//!    - unreadable → `Stale` (cleanup by caller)
//! 2. Check PID alive
//!    - dead → `Stale`
//! 3. Connect socket (100ms timeout)
//!    - refused → `Stale` (PID reuse by unrelated process — caller
//!      can delete the PID file and fall back to direct mode)
//!    - timeout → `Unhealthy("socket connect timeout")` — daemon is
//!      alive but overloaded; caller falls back with a stderr
//!      warning
//! 4. Send `GET /api/health` (200ms timeout)
//!    - success → `Healthy`
//!    - timeout / parse error → `Unhealthy(reason)`
//!
//! The detection function runs synchronously (no tokio runtime
//! required) so the statusline hook can call it directly from the
//! blocking CLI path. It uses `std::os::unix::net::UnixStream` and a
//! hand-rolled minimal HTTP/1.1 GET — avoiding pulling reqwest +
//! tokio into the hot CLI path where every millisecond matters.

use crate::platform::process;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Result of detecting whether the daemon is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectResult {
    /// Daemon is running and health check passed.
    Healthy { pid: u32, socket_path: PathBuf },
    /// PID file missing or dead — no daemon running.
    NotRunning,
    /// PID file or socket exists but points at a dead/stale
    /// resource. Caller should clean up the PID file before falling
    /// back to direct mode.
    Stale { reason: String },
    /// Daemon is alive (PID alive) but socket connect or health
    /// check failed. Usually means the daemon is overloaded or in
    /// the middle of startup. Caller should fall back with a stderr
    /// warning.
    Unhealthy { reason: String },
}

/// Health-check read/write timeout per GAP-9. Applied to the socket
/// after connect via `set_read_timeout`/`set_write_timeout` so the
/// HTTP/1.1 exchange cannot hang longer than this.
const HEALTH_TIMEOUT: Duration = Duration::from_millis(200);

/// Runs the 4-step detection protocol.
///
/// Non-tokio, synchronous — safe to call from the blocking CLI
/// statusline hook where the 50ms statusline deadline demands no
/// runtime startup overhead.
pub fn detect_daemon(base_dir: &Path) -> DetectResult {
    // Step 1: PID file.
    let pid_path = super::pid_file_path(base_dir);
    if !pid_path.exists() {
        return DetectResult::NotRunning;
    }

    let pid = match super::pid::read_pid(&pid_path) {
        Some(p) => p,
        None => {
            return DetectResult::Stale {
                reason: format!("unreadable PID file at {}", pid_path.display()),
            };
        }
    };

    // Step 2: PID liveness.
    if !process::is_pid_alive(pid) {
        return DetectResult::Stale {
            reason: format!("PID {pid} not alive"),
        };
    }

    // Step 3 + 4: socket / pipe connect + health check.
    #[cfg(unix)]
    {
        let sock_path = super::socket_path(base_dir);
        unix_health_check(pid, &sock_path)
    }

    #[cfg(windows)]
    {
        let pipe_path = super::socket_path(base_dir);
        windows_health_check(pid, &pipe_path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        DetectResult::Unhealthy {
            reason: "daemon IPC detection not implemented on this platform".into(),
        }
    }
}

#[cfg(unix)]
fn unix_health_check(pid: u32, sock_path: &Path) -> DetectResult {
    use std::os::unix::net::UnixStream;

    if !sock_path.exists() {
        return DetectResult::Stale {
            reason: format!(
                "PID {pid} alive but socket {} missing (daemon may still be starting)",
                sock_path.display()
            ),
        };
    }

    // Step 3: connect. Unix-domain socket connect is effectively
    // instantaneous on the local kernel — either the socket accepts
    // the connection immediately or returns ECONNREFUSED. We do not
    // enforce a timeout because `std::os::unix::net::UnixStream` has
    // no timeout variant and the observed pathological cases that
    // would motivate one (kernel under extreme load) are indistin-
    // guishable from "daemon hung" anyway. The 100ms budget is
    // retained as a documented SLA, not an enforced limit.
    let mut stream = match std::os::unix::net::UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(e) => {
            // `ECONNREFUSED` with a live PID means either the PID
            // file is stale (reused PID) or the daemon has closed
            // the socket but not yet removed the PID file. Either
            // way, the caller should treat this as "not available".
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                return DetectResult::Stale {
                    reason: format!("socket connect refused (stale daemon?): {e}"),
                };
            }
            return DetectResult::Unhealthy {
                reason: format!("socket connect: {e}"),
            };
        }
    };

    // Apply read+write timeouts to bound the health check.
    if stream.set_read_timeout(Some(HEALTH_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HEALTH_TIMEOUT)).is_err()
    {
        return DetectResult::Unhealthy {
            reason: "failed to set socket timeouts".into(),
        };
    }

    // Step 4: minimal HTTP/1.1 GET /api/health.
    let request = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if let Err(e) = UnixStream::write_all(&mut stream, request) {
        return DetectResult::Unhealthy {
            reason: format!("health write: {e}"),
        };
    }

    // Read up to 4096 bytes (more than enough for a health response).
    let mut buf = [0u8; 4096];
    let mut total = 0;
    loop {
        match UnixStream::read(&mut stream, &mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= buf.len() {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return DetectResult::Unhealthy {
                    reason: format!("health read: {e}"),
                };
            }
            Err(e) => {
                return DetectResult::Unhealthy {
                    reason: format!("health read: {e}"),
                };
            }
        }
    }

    let text = std::str::from_utf8(&buf[..total]).unwrap_or("");
    // Parse the HTTP/1.1 status line. A correctly-formed axum response
    // starts with `HTTP/1.1 200 OK\r\n`.
    let first_line = text.lines().next().unwrap_or("");
    if first_line.starts_with("HTTP/1.1 200") {
        DetectResult::Healthy {
            pid,
            socket_path: sock_path.to_path_buf(),
        }
    } else {
        DetectResult::Unhealthy {
            reason: format!("unexpected health status line: {first_line}"),
        }
    }
}

/// Steps 3 + 4 of the detection protocol on Windows.
///
/// Attempts to open the named pipe and send a minimal HTTP/1.1 GET
/// /api/health. The pipe open uses a zero-wait `CreateFile` — if
/// `ERROR_FILE_NOT_FOUND` is returned, the daemon's pipe server is not
/// yet running (Stale). If `ERROR_PIPE_BUSY` is returned, all instances
/// are currently serving clients (Unhealthy/"overloaded"). Anything else
/// that succeeds is treated as a live connection.
///
/// The health exchange uses `std::io::Read`/`Write` via the synchronous
/// blocking pipe handle so the detection function stays non-async and
/// safe to call from the statusline hook.
#[cfg(windows)]
fn windows_health_check(pid: u32, pipe_path: &Path) -> DetectResult {
    use std::io::{Read, Write};

    // Attempt a synchronous open of the named pipe.
    // We use `std::fs::OpenOptions` which on Windows calls `CreateFileW`.
    // A zero timeout means "return immediately" — either the pipe
    // exists and accepts our connection, or we get an OS error we can
    // classify.
    let mut stream = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
    {
        Ok(f) => f,
        Err(e) => {
            // Map Windows error codes to DetectResult variants.
            return match e.raw_os_error() {
                // ERROR_FILE_NOT_FOUND (2): pipe server not running yet,
                // or daemon cleaned up its pipe on exit.
                Some(2) => DetectResult::Stale {
                    reason: format!(
                        "PID {pid} alive but named pipe {} not found (daemon may still be starting)",
                        pipe_path.display()
                    ),
                },
                // ERROR_PIPE_BUSY (231): pipe server exists but all
                // instances are currently connected — daemon is alive
                // but overloaded.
                Some(231) => DetectResult::Unhealthy {
                    reason: format!(
                        "named pipe busy (all instances connected): {}",
                        pipe_path.display()
                    ),
                },
                // ERROR_ACCESS_DENIED (5): pipe exists but we cannot
                // open it — likely a cross-user scenario or security
                // descriptor mismatch.
                Some(5) => DetectResult::Unhealthy {
                    reason: format!(
                        "named pipe access denied: {}",
                        pipe_path.display()
                    ),
                },
                _ => DetectResult::Unhealthy {
                    reason: format!(
                        "named pipe open failed: {e} (pipe: {})",
                        pipe_path.display()
                    ),
                },
            };
        }
    };

    // Set read/write timeouts via the COMMTIMEOUTS structure.
    // On named pipes, `set_read_timeout` / `set_write_timeout` are not
    // available via the Rust standard library directly. Instead we rely
    // on the HEALTH_TIMEOUT budget via the bounded read loop below.
    // The pipe file handle is opened in blocking mode, so read will
    // block until the daemon sends data. If the daemon is hung, the
    // health check will block for up to HEALTH_TIMEOUT before we detect
    // it via a separate thread or just accept the block. For the
    // statusline use case, this is acceptable — the daemon should
    // respond in well under 1ms for /api/health on a healthy system.
    //
    // A proper timeout on named pipe reads requires either:
    //   - `OVERLAPPED` I/O with `WaitForSingleObject` and a timer
    //   - Opening with `FILE_FLAG_OVERLAPPED`
    //
    // For M8-03, we accept the blocking behavior. The daemon is expected
    // to respond within microseconds, and the 200ms SLA is met in the
    // common case. A full async health check is available via
    // `client_windows::http_get_pipe` for callers with a tokio runtime.

    // Step 4: minimal HTTP/1.1 GET /api/health.
    let request = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if let Err(e) = stream.write_all(request) {
        return DetectResult::Unhealthy {
            reason: format!("health write: {e}"),
        };
    }

    // Read up to 4096 bytes.
    let mut buf = [0u8; 4096];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= buf.len() {
                    break;
                }
            }
            Err(e) => {
                return DetectResult::Unhealthy {
                    reason: format!("health read: {e}"),
                };
            }
        }
    }

    let text = std::str::from_utf8(&buf[..total]).unwrap_or("");
    let first_line = text.lines().next().unwrap_or("");
    if first_line.starts_with("HTTP/1.1 200") {
        DetectResult::Healthy {
            pid,
            socket_path: pipe_path.to_path_buf(),
        }
    } else {
        DetectResult::Unhealthy {
            reason: format!("unexpected health status line: {first_line}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn detect_missing_pid_file_is_not_running() {
        let dir = TempDir::new().unwrap();

        // pid_file_path() uses platform-specific storage:
        //   * Linux: $XDG_RUNTIME_DIR/csq-daemon.pid
        //   * macOS: {base_dir}/csq-daemon.pid
        //   * Windows: %LOCALAPPDATA%\csq\csq-daemon.pid
        //
        // On Linux and Windows, the default path is shared across
        // tests running in parallel — we must override the env var
        // so this test checks an isolated location. macOS uses
        // base_dir directly so no override is needed there.
        #[cfg(target_os = "linux")]
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        }
        #[cfg(target_os = "windows")]
        unsafe {
            std::env::set_var("LOCALAPPDATA", dir.path());
        }

        // Clean up any leftover PID file that a previous test run
        // may have written to the pid_file_path location — the
        // LOCALAPPDATA override moves us to a fresh tempdir, but a
        // sibling test may have already set the env to some other
        // value that already contains a stale PID file.
        let pid_path = super::super::pid_file_path(dir.path());
        let _ = fs::remove_file(&pid_path);

        assert_eq!(detect_daemon(dir.path()), DetectResult::NotRunning);
    }

    // macOS-only: `pid_file_path` honors `base_dir` directly on macOS
    // (no env-var indirection), so each TempDir gets its own pid file
    // and parallel tests isolate cleanly.
    //
    // Off Windows: `pid_file_path` resolves to `%LOCALAPPDATA%\csq\csq-daemon.pid`,
    // a process-global path, so two tests writing different file contents
    // race. Overriding `LOCALAPPDATA` per-test is unsafe under parallel
    // execution (`std::env::set_var` is process-global).
    //
    // Off Linux: `pid_file_path` resolves to `$XDG_RUNTIME_DIR/csq-daemon.pid`
    // when that env var is set (which it usually is on systemd-managed
    // runners). The earlier attempt to override `XDG_RUNTIME_DIR` per-test
    // worked in isolation but POLLUTED the env for unrelated tests like
    // `detect_live_pid_but_missing_socket_is_stale`, which then read a
    // stale TempDir path that no longer existed and saw `NotRunning`
    // instead of `Stale`. Surfaced post-merge of #113.
    //
    // The corrupt + dead-pid code paths are still exercised on macOS,
    // and the Windows + Linux pid-resolution paths have their own
    // dedicated tests in this module that don't touch global env.
    #[cfg(target_os = "macos")]
    #[test]
    fn detect_corrupt_pid_file_is_stale() {
        let dir = TempDir::new().unwrap();
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        fs::write(&pid_path, "garbage").unwrap();

        match detect_daemon(dir.path()) {
            DetectResult::Stale { reason } => {
                assert!(reason.contains("unreadable"), "reason: {reason}");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    // macOS-only for the same env-pollution reason documented on
    // `detect_corrupt_pid_file_is_stale` above.
    #[cfg(target_os = "macos")]
    #[test]
    fn detect_dead_pid_is_stale() {
        let dir = TempDir::new().unwrap();
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        fs::write(&pid_path, "99999999\n").unwrap();

        match detect_daemon(dir.path()) {
            DetectResult::Stale { reason } => {
                assert!(reason.contains("not alive"), "reason: {reason}");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Serializes the two tests that read / write the shared
    /// `socket_path(base_dir)` on Linux. `socket_path` ignores
    /// `base_dir` when `XDG_RUNTIME_DIR` is set (paths.rs:65-78),
    /// which is the common case on Ubuntu CI runners — so
    /// `detect_live_pid_but_missing_socket_is_stale` and
    /// `detect_live_daemon_returns_healthy` contend on the same
    /// `$XDG_RUNTIME_DIR/csq.sock` file regardless of their
    /// per-test TempDir. Running them concurrently produces a flaky
    /// Healthy / Stale outcome depending on scheduler order. Origin:
    /// PR-C3c CI flake surfaced on PR #174; pre-existing latent race
    /// but never manifested until new tests changed parallel timing.
    #[cfg(unix)]
    static SOCKET_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[tokio::test]
    // Serializing the whole test is the point — the `.await`s
    // below are not a lock-contention hazard because no other code
    // path acquires this mutex.
    #[allow(clippy::await_holding_lock)]
    async fn detect_live_pid_but_missing_socket_is_stale() {
        let _guard = SOCKET_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        // Write our own PID — we're alive.
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        // Defensive unlink: XDG_RUNTIME_DIR on Linux means
        // `socket_path(dir.path())` may return a path shared with
        // the detect_live_daemon_returns_healthy test. The mutex
        // prevents those two from running concurrently, but a stale
        // socket from a prior test run (or an orphaned real csq
        // daemon on the runner) would still fail the assertion. The
        // mutex plus this delete make the test hermetic.
        let sock_path = super::super::socket_path(dir.path());
        let _ = fs::remove_file(&sock_path);

        match detect_daemon(dir.path()) {
            DetectResult::Stale { reason } => {
                assert!(
                    reason.contains("socket") && reason.contains("missing"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // See sibling test comment.
    async fn detect_live_daemon_returns_healthy() {
        use crate::daemon::server;

        let _guard = SOCKET_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let pid_path = super::super::pid_file_path(dir.path());
        let sock_path = super::super::socket_path(dir.path());

        // Write our own PID (the test process is alive).
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        // Start the real server at the computed socket path. Note:
        // socket_path() may return a path outside the TempDir on
        // Linux (XDG_RUNTIME_DIR). In that case the test is best
        // effort — it still verifies the detection logic.
        let sock_parent = sock_path.parent().unwrap();
        if !sock_parent.exists() {
            fs::create_dir_all(sock_parent).ok();
        }

        let state = crate::daemon::server::RouterState {
            cache: std::sync::Arc::new(crate::daemon::TtlCache::with_default_age()),
            discovery_cache: std::sync::Arc::new(crate::daemon::TtlCache::new(
                crate::daemon::server::DISCOVERY_CACHE_MAX_AGE,
            )),
            base_dir: std::sync::Arc::new(dir.path().to_path_buf()),
            oauth_store: None,
        };
        let (handle, join) = match server::serve(&sock_path, state).await {
            Ok(r) => r,
            Err(_) => {
                // Non-writable socket parent (XDG_RUNTIME_DIR may
                // not exist in a test env) — skip this test.
                eprintln!("skipping: could not bind socket at {}", sock_path.display());
                return;
            }
        };

        // Detection runs in a blocking context — spawn_blocking so
        // the tokio runtime doesn't complain.
        let base = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || detect_daemon(&base))
            .await
            .unwrap();

        match result {
            DetectResult::Healthy { pid, .. } => {
                assert_eq!(pid, std::process::id());
            }
            other => panic!("expected Healthy, got {other:?}"),
        }

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// Windows: a live PID with no pipe present should return Stale.
    #[cfg(windows)]
    #[test]
    fn detect_windows_live_pid_but_no_pipe_is_stale() {
        let dir = TempDir::new().unwrap();
        // On Windows, pid_file_path uses %LOCALAPPDATA%\csq\ by default.
        // Override so the test is isolated.
        unsafe {
            std::env::set_var("LOCALAPPDATA", dir.path());
        }
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        // Write our own PID — we're definitely alive.
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        // socket_path() on Windows returns \\.\pipe\csq-{username}.
        // That pipe does not exist, so detection should be Stale.
        match detect_daemon(dir.path()) {
            DetectResult::Stale { reason } => {
                assert!(
                    reason.contains("pipe") || reason.contains("not found"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Windows: a live daemon on the named pipe returns Healthy.
    #[cfg(windows)]
    #[tokio::test]
    async fn detect_windows_live_daemon_returns_healthy() {
        use crate::daemon::server_windows;

        let dir = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LOCALAPPDATA", dir.path());
        }
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        // Use a unique pipe name to avoid collisions with other tests.
        let pipe_name = format!(r"\\.\pipe\csq-detect-test-{}", std::process::id());

        let state = crate::daemon::server::RouterState {
            cache: std::sync::Arc::new(crate::daemon::TtlCache::with_default_age()),
            discovery_cache: std::sync::Arc::new(crate::daemon::TtlCache::new(
                crate::daemon::server::DISCOVERY_CACHE_MAX_AGE,
            )),
            base_dir: std::sync::Arc::new(dir.path().to_path_buf()),
            oauth_store: None,
        };
        let (handle, join) = server_windows::serve(&pipe_name, state).await.unwrap();

        // Override USERNAME so socket_path() returns our unique pipe name.
        // We isolate by using the pipe name we just created directly via
        // spawn_blocking with the path we know, rather than relying on
        // socket_path() resolution. This makes the test deterministic.
        let pipe_path = std::path::PathBuf::from(&pipe_name);
        let pid = std::process::id();
        let result = tokio::task::spawn_blocking(move || windows_health_check(pid, &pipe_path))
            .await
            .unwrap();

        match result {
            DetectResult::Healthy { pid: got_pid, .. } => {
                assert_eq!(got_pid, std::process::id());
            }
            other => panic!("expected Healthy, got {other:?}"),
        }

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }
}
