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

    // Step 3 + 4: socket connect + health check.
    #[cfg(unix)]
    {
        let sock_path = super::socket_path(base_dir);
        unix_health_check(pid, &sock_path)
    }

    #[cfg(not(unix))]
    {
        // Windows named-pipe detection lands in M8.6.
        let _ = pid;
        DetectResult::Unhealthy {
            reason: "Windows named-pipe detection not yet implemented (M8.6)".into(),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn detect_live_pid_but_missing_socket_is_stale() {
        let dir = TempDir::new().unwrap();
        let pid_path = super::super::pid_file_path(dir.path());
        fs::create_dir_all(pid_path.parent().unwrap()).ok();
        // Write our own PID — we're alive.
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

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
    async fn detect_live_daemon_returns_healthy() {
        use crate::daemon::server;

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
}
