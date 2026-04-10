//! Unix socket IPC server for the daemon.
//!
//! Serves a minimal axum HTTP/1.1 router over a Unix domain socket.
//! M8.3 only wires the `GET /api/health` route — additional routes
//! (accounts, usage, refresh, OAuth callback) land in M8.4+.
//!
//! # Platform scope
//!
//! This module is Unix-only (`cfg(unix)`). Windows named-pipe
//! support is deferred to M8.6 — see
//! `workspaces/csq-v2/todos/active/M8-daemon-core.md` task M8-03.
//!
//! # Security model
//!
//! Three defensive layers protect the IPC surface. Any single layer
//! breaking should not expose the daemon; together they match the
//! hardening baseline sshd and systemd use for local sockets.
//!
//! ## Layer 1 — socket file permissions (0o600)
//!
//! The socket file is created with `0o600` permissions. To close the
//! microsecond window between `bind(2)` and `chmod(2)` during which
//! the socket would otherwise inherit the process umask (typically
//! 0o644 or 0o755), [`serve`] temporarily sets the thread's umask to
//! `0o077` immediately before bind and restores it immediately after.
//! The explicit `set_permissions(0o600)` call remains as
//! defense-in-depth.
//!
//! ## Layer 2 — `SO_PEERCRED` / `LOCAL_PEERCRED` peer UID check
//!
//! Every accepted connection is checked against `geteuid()` before
//! the HTTP router sees the request. Linux uses `SO_PEERCRED` to
//! read `struct ucred.uid`; macOS uses `LOCAL_PEERCRED` to read
//! `struct xucred.cr_uid`. Connections from other UIDs are closed
//! immediately with no HTTP response. This catches the case where
//! a file-permission bug (incorrect chmod, symlink swap, race) lets
//! a different-UID process connect.
//!
//! ## Layer 3 — per-user socket directory
//!
//! The socket path itself lives under a per-user directory:
//! `$XDG_RUNTIME_DIR` on Linux (tmpfs, 0o700), `~/.claude/accounts`
//! on macOS (0o755 but inside the user's HOME), or
//! `/tmp/csq-{uid}.sock` as the Linux fallback (uid in the name so
//! different-UID collisions are harmless).
//!
//! ## HTTP request authentication
//!
//! There is no application-layer authentication on the HTTP
//! requests because the three layers above establish that any
//! caller is the owning user. Anyone who can open the socket is
//! already the same UID, which is exactly the threat model for a
//! per-user daemon.

#![cfg(unix)]

use crate::error::DaemonError;
use axum::{extract::DefaultBodyLimit, routing::get, Json, Router};
use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

/// Maximum request body size accepted by the daemon HTTP router.
/// M8.3 has no body-accepting routes, but the limit is set now so
/// every future route (M8.5 `/api/login`, `/api/refresh-token/:id`,
/// etc.) inherits it automatically. 1 MiB is generous for JSON
/// command payloads while still bounding worst-case allocation.
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Health endpoint response body. Deliberately minimal — the client
/// only cares that the endpoint responds with 200 and valid JSON.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub pid: u32,
}

/// Builds the axum router for the daemon HTTP API.
///
/// M8.3 only mounts `GET /api/health`. M8.4+ will extend this with
/// `/api/accounts`, `/api/account/:id/usage`, `/api/refresh`, etc.
/// The [`DefaultBodyLimit`] layer is installed here so every future
/// route inherits the 1 MiB cap without having to remember.
pub fn router() -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
    })
}

/// Handle to a running daemon HTTP server. Dropping this handle
/// does NOT stop the server — use [`ServerHandle::shutdown`] to
/// initiate graceful shutdown and await the join handle.
pub struct ServerHandle {
    /// Path to the socket file. Removed on shutdown.
    socket_path: PathBuf,
    /// Triggered to start graceful shutdown.
    shutdown: CancellationToken,
}

impl ServerHandle {
    /// Signals the server to shut down. The accept loop exits on the
    /// next poll, and in-flight connections are allowed to complete.
    /// Removes the socket file.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
        // Best-effort socket file cleanup. If the server loop is
        // already removing it, the error is ignored.
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Returns the socket path the server is bound to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Binds a Unix domain socket at `socket_path` and serves the daemon
/// HTTP router on it until `shutdown` fires.
///
/// # Behavior
///
/// 1. Removes any existing file at `socket_path` (cleanup of stale
///    sockets from previous crashed daemons). If a live daemon is
///    bound there, the `try_lock`/PID file guard in
///    [`super::pid::PidFile::acquire`] should have failed already —
///    we trust that guard and overwrite.
/// 2. Binds a `tokio::net::UnixListener`.
/// 3. `chmod` the socket file to `0o600` so only the owning UID can
///    connect. Done via `std::fs::set_permissions` on the path — the
///    kernel honors this on macOS and modern Linux.
/// 4. Spawns the accept loop, which waits for connections and
///    dispatches each to a tokio task running the axum service.
/// 5. On `shutdown.cancelled()`, the accept loop exits. In-flight
///    connections are allowed to complete on their own tasks.
/// 6. Removes the socket file on exit (best-effort).
///
/// Returns a [`ServerHandle`] the caller can use to trigger
/// shutdown, and an awaitable future that resolves when the accept
/// loop has exited.
pub async fn serve(
    socket_path: &Path,
) -> Result<(ServerHandle, tokio::task::JoinHandle<()>), DaemonError> {
    // Cleanup stale socket file (previous crash).
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|_| DaemonError::SocketConnect {
            path: socket_path.to_path_buf(),
        })?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| DaemonError::SocketConnect {
                path: parent.to_path_buf(),
            })?;
        }
    }

    // Tighten umask to 0o077 so the socket file bind(2) creates has
    // 0o600 mode from the very first syscall — closing the
    // bind→chmod race window where an unprivileged local process
    // could otherwise racy-connect(2) to a world-readable socket.
    // umask(2) is process-global on Unix; we restore the previous
    // value immediately after bind. The window is bounded to a
    // single syscall and no other daemon work races it because
    // `serve()` is called from the single-threaded startup path
    // before any background tokio tasks are spawned.
    //
    // SAFETY: libc::umask is always safe to call; we restore the
    // previous mask on all paths via the explicit guard below.
    let old_umask = unsafe { libc::umask(0o077) };

    let bind_result = UnixListener::bind(socket_path);

    // Restore the original umask before handling errors so a bind
    // failure does not leave the process with a tightened mask.
    unsafe {
        libc::umask(old_umask);
    }

    let listener = bind_result.map_err(|e| {
        tracing::debug!(error = %e, path = ?socket_path, "UnixListener::bind failed");
        DaemonError::SocketConnect {
            path: socket_path.to_path_buf(),
        }
    })?;

    // Defense-in-depth: explicit set_permissions even after the
    // umask-controlled bind. If the filesystem or kernel behaved
    // unexpectedly (NFS, container layer), this catches it.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
        |e| {
            tracing::debug!(error = %e, "chmod socket 0o600 failed");
            DaemonError::SocketConnect {
                path: socket_path.to_path_buf(),
            }
        },
    )?;

    let shutdown = CancellationToken::new();
    let handle = ServerHandle {
        socket_path: socket_path.to_path_buf(),
        shutdown: shutdown.clone(),
    };

    let app = Arc::new(router());
    let sock_for_cleanup = socket_path.to_path_buf();
    let join = tokio::spawn(async move {
        accept_loop(listener, app, shutdown, sock_for_cleanup).await;
    });

    Ok((handle, join))
}

/// The accept loop. Exits when the shutdown token is cancelled.
///
/// Each accepted connection is handed to a fresh tokio task running
/// the hyper connection service. In-flight tasks are NOT awaited on
/// shutdown — the daemon's main loop (in lifecycle.rs) is
/// responsible for the wider graceful-shutdown deadline via
/// `JoinHandle::abort` or a tokio `timeout`.
async fn accept_loop(
    listener: UnixListener,
    app: Arc<Router>,
    shutdown: CancellationToken,
    socket_path: PathBuf,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("daemon server: shutdown signaled, exiting accept loop");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        // Verify the connecting peer runs as our own
                        // UID. Any mismatch is closed immediately —
                        // the HTTP router is never invoked. This is
                        // the second defensive layer after socket
                        // file permissions.
                        if let Err(e) = verify_peer_uid(&stream) {
                            tracing::warn!(error = %e, "rejecting cross-UID connection");
                            drop(stream);
                            continue;
                        }

                        let app = Arc::clone(&app);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let app = Arc::clone(&app);
                                async move {
                                    let router = (*app).clone();
                                    router.oneshot(req).await
                                }
                            });
                            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                            {
                                tracing::debug!(error = %e, "connection service error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed, continuing");
                        // A short pause avoids hot-spinning on
                        // persistent accept errors (e.g., EMFILE).
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    // Best-effort socket cleanup on exit.
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!(path = ?socket_path, "daemon server: accept loop exited");
}

/// Verifies the peer at the other end of a Unix domain socket is
/// running under the same effective UID as this daemon.
///
/// On Linux this uses `getsockopt(SO_PEERCRED)` which returns a
/// `struct ucred` with the peer's PID, UID, and GID. On macOS this
/// uses `getsockopt(LOCAL_PEERCRED)` which returns a `struct xucred`
/// with `cr_uid` (among other fields).
///
/// Any getsockopt failure or UID mismatch returns `Err` — the
/// caller drops the stream without invoking the HTTP router.
#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // `libc::ucred` layout: { pid: pid_t, uid: uid_t, gid: gid_t }
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: fd is a valid Unix-domain socket fd; cred is a valid
    // stack allocation of the right type; len matches its size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let our_uid = unsafe { libc::geteuid() };
    if cred.uid != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("peer UID {} != daemon UID {}", cred.uid, our_uid),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // macOS `struct xucred` from <sys/ucred.h>:
    //   cr_version: u32
    //   cr_uid:     uid_t
    //   cr_ngroups: i16
    //   cr_groups:  [gid_t; NGROUPS]  (NGROUPS = 16)
    #[repr(C)]
    struct XUcred {
        cr_version: u32,
        cr_uid: libc::uid_t,
        cr_ngroups: libc::c_short,
        cr_groups: [libc::gid_t; 16],
    }

    // From <sys/un.h>: SOL_LOCAL = 0, LOCAL_PEERCRED = 1.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERCRED: libc::c_int = 1;

    let fd = stream.as_raw_fd();
    let mut cred: XUcred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<XUcred>() as libc::socklen_t;

    // SAFETY: fd is a valid Unix-domain socket fd; cred is a valid
    // stack allocation matching struct xucred; len reflects size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut XUcred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let our_uid = unsafe { libc::geteuid() };
    if cred.cr_uid != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("peer UID {} != daemon UID {}", cred.cr_uid, our_uid),
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn verify_peer_uid(_stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // Other Unixes: no portable peer-credential API. The 0o600
    // socket permission is the sole boundary; log a warning so
    // operators on BSD/Illumos/etc. are aware.
    tracing::warn!(
        "peer UID verification not implemented on this platform — \
         relying solely on socket file permissions"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn serve_binds_and_sets_permissions() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock).await.unwrap();
        assert!(sock.exists(), "socket file should be created");

        // Verify 0o600 permissions.
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be 0o600 (owner-only)");

        handle.shutdown();
        // Give the accept loop a moment to exit.
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();

        // Socket file should be cleaned up.
        assert!(!sock.exists(), "socket file should be removed on shutdown");
    }

    #[tokio::test]
    async fn serve_cleans_stale_socket_file() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        // Pretend a stale socket file exists (regular file, not a real socket).
        std::fs::write(&sock, "stale").unwrap();
        assert!(sock.exists());

        let (handle, join) = serve(&sock).await.unwrap();
        assert!(sock.exists());

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn health_endpoint_over_real_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock).await.unwrap();

        // Connect and send a minimal HTTP/1.1 GET.
        let mut stream = UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // Read the full response.
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("health response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("200 OK"),
            "expected 200 OK in response, got: {text}"
        );
        assert!(
            text.contains(r#""status":"ok""#),
            "expected JSON body, got: {text}"
        );
        assert!(
            text.contains(r#""version":""#),
            "expected version field, got: {text}"
        );

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock).await.unwrap();

        let mut stream = UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /api/nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("404"),
            "expected 404 for unknown route, got: {text}"
        );

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn health_response_serializes() {
        let r = HealthResponse {
            status: "ok",
            version: "2.0.0-alpha.1",
            pid: 42,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"pid\":42"));
    }
}
