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

use super::cache::TtlCache;
use super::refresher::RefreshStatus;
use crate::accounts::{discovery, AccountInfo};
use crate::error::DaemonError;
use crate::types::AccountNum;
use axum::{
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

/// Shared router state — cache + base_dir paths. Cloned cheaply
/// (both fields are `Arc`/`PathBuf` inside) for each request via
/// axum's `State` extractor.
#[derive(Clone)]
pub struct RouterState {
    /// Refresh-status cache owned by the daemon lifecycle. The
    /// refresher writes; HTTP routes only read.
    pub cache: Arc<TtlCache<u16, RefreshStatus>>,
    /// csq base directory, passed through for account discovery.
    pub base_dir: Arc<PathBuf>,
}

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
/// Routes mounted:
/// - `GET /api/health` — liveness probe (M8.3)
/// - `GET /api/accounts` — discovered accounts (M8.5)
/// - `GET /api/refresh-status` — all refresh statuses from the cache (M8.5)
/// - `GET /api/refresh-status/:id` — one account's refresh status (M8.5)
///
/// The [`DefaultBodyLimit`] layer is installed here so every future
/// route inherits the 1 MiB cap without having to remember. State
/// is shared via `with_state` so each handler gets a cheap clone
/// of the [`RouterState`].
pub fn router(state: RouterState) -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/accounts", get(accounts_handler))
        .route("/api/refresh-status", get(refresh_status_all_handler))
        .route("/api/refresh-status/{id}", get(refresh_status_one_handler))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
    })
}

/// GET /api/accounts — returns the full discovered account list.
///
/// Runs `discovery::discover_anthropic` inside `spawn_blocking`
/// because the discovery code does synchronous file IO. The full
/// list is serialized directly; for realistic account counts
/// (<=100) the response size is well under the 1 MiB body cap.
async fn accounts_handler(
    State(state): State<RouterState>,
) -> Result<Json<AccountsResponse>, (StatusCode, String)> {
    let base_dir = Arc::clone(&state.base_dir);
    let accounts = tokio::task::spawn_blocking(move || discovery::discover_anthropic(&base_dir))
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "accounts discovery task panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "discovery task failed".to_string(),
            )
        })?;

    Ok(Json(AccountsResponse { accounts }))
}

/// GET /api/refresh-status — returns every currently-cached
/// `RefreshStatus` entry as a map keyed by account ID.
async fn refresh_status_all_handler(
    State(state): State<RouterState>,
) -> Json<RefreshStatusListResponse> {
    // Walk known account IDs via discovery and look up each in the
    // cache. We do NOT expose the cache's internal HashMap directly
    // because that couples the IPC schema to the cache's internal
    // layout. A linear lookup over discovered accounts is fine for
    // the realistic account count.
    let base_dir = Arc::clone(&state.base_dir);
    let accounts_future =
        tokio::task::spawn_blocking(move || discovery::discover_anthropic(&base_dir));

    let mut entries = Vec::new();
    if let Ok(accounts) = accounts_future.await {
        for info in accounts {
            if let Some(status) = state.cache.get(&info.id) {
                entries.push(status);
            }
        }
    }

    Json(RefreshStatusListResponse { statuses: entries })
}

/// GET /api/refresh-status/:id — returns one account's cached
/// refresh status, or 404 if no cached entry exists.
///
/// The path parameter `{id}` is validated via
/// `AccountNum::try_from` — values outside 1..=999 are rejected
/// with 400 so path-injection attempts like `/api/refresh-status/
/// ../../etc` fail at deserialization (u16 parse) or the range
/// guard before touching the cache.
async fn refresh_status_one_handler(
    State(state): State<RouterState>,
    AxumPath(id): AxumPath<u16>,
) -> Result<Json<RefreshStatus>, (StatusCode, String)> {
    // Validate account number. This also defends against negative
    // or out-of-range values that slipped past the u16 decode.
    let account = AccountNum::try_from(id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid account id: {e}"),
        )
    })?;

    match state.cache.get(&account.get()) {
        Some(status) => Ok(Json(status)),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no cached refresh status for account {id}"),
        )),
    }
}

/// Response body for `GET /api/accounts`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountsResponse {
    pub accounts: Vec<AccountInfo>,
}

/// Response body for `GET /api/refresh-status`.
#[derive(Debug, Clone, Serialize)]
pub struct RefreshStatusListResponse {
    pub statuses: Vec<RefreshStatus>,
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

    /// Returns a clone of the shutdown token so sibling subsystems
    /// (refresher, poller, future HTTP handlers) can cancel on the
    /// same signal. Cloning a `CancellationToken` is cheap — it's
    /// just an Arc bump.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Returns the socket path the server is bound to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Binds a Unix domain socket at `socket_path` and serves the daemon
/// HTTP router on it until `shutdown` fires.
///
/// `state` is the shared router state: cache + base_dir. The accept
/// loop clones `state` per-connection so handlers get independent
/// axum `State` extractor instances.
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
    state: RouterState,
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

    let app = Arc::new(router(state));
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

    /// Builds a minimal RouterState for tests. Cache starts empty;
    /// base_dir points at the provided temp directory.
    fn test_state(base: &Path) -> RouterState {
        RouterState {
            cache: Arc::new(TtlCache::with_default_age()),
            base_dir: Arc::new(base.to_path_buf()),
        }
    }

    #[tokio::test]
    async fn serve_binds_and_sets_permissions() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();
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

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();
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

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

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

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

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

    /// Sends a minimal HTTP/1.1 GET over a Unix socket and reads
    /// the full response. Returns (status_line, body) where body
    /// is everything after the blank CRLF-CRLF.
    async fn http_get(sock: &std::path::Path, path: &str) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(sock).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf).into_owned();
        let status_line = text.lines().next().unwrap_or("").to_string();
        // Find the blank line separating headers from body.
        let body = text
            .find("\r\n\r\n")
            .map(|i| text[i + 4..].to_string())
            .unwrap_or_default();
        (status_line, body)
    }

    #[tokio::test]
    async fn accounts_route_returns_empty_list_on_empty_base() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/accounts").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(
            body.contains(r#""accounts":[]"#),
            "body should have empty accounts array: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn accounts_route_lists_discovered_accounts() {
        use crate::credentials::{self, CredentialFile, OAuthPayload};
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();

        // Install a valid credentials/1.json so discover_anthropic picks it up.
        let creds = CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        };
        let num = AccountNum::try_from(1u16).unwrap();
        credentials::save(&crate::credentials::file::canonical_path(dir.path(), num), &creds)
            .unwrap();

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/accounts").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""id":1"#), "body: {body}");
        assert!(body.contains(r#""source":"Anthropic""#), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_returns_404_when_absent() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status/1").await;
        assert!(status.contains("404"), "status: {status}");
        assert!(body.contains("no cached refresh status"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_rejects_out_of_range_id() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        // 0 is out of the 1..=999 range so AccountNum::try_from rejects it.
        let (status, body) = http_get(&sock, "/api/refresh-status/0").await;
        assert!(status.contains("400"), "status: {status}");
        assert!(body.contains("invalid account id"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_returns_cached_entry() {
        use crate::daemon::refresher::RefreshStatus;

        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path());

        // Pre-populate the cache with a known status.
        state.cache.set(
            1,
            RefreshStatus {
                account: 1,
                last_result: "refreshed".to_string(),
                expires_at_ms: 1_234_567_890,
                checked_at_secs: 42,
            },
        );

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status/1").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""account":1"#), "body: {body}");
        assert!(
            body.contains(r#""last_result":"refreshed""#),
            "body: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_all_returns_only_accounts_in_cache() {
        use crate::credentials::{self, CredentialFile, OAuthPayload};
        use crate::daemon::refresher::RefreshStatus;
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();

        // Install account 1 and account 2, but only populate the
        // cache for account 1.
        for id in [1u16, 2] {
            let creds = CredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new("at".into()),
                    refresh_token: RefreshToken::new("rt".into()),
                    expires_at: 9_999_999_999_999,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: Default::default(),
                },
                extra: Default::default(),
            };
            let num = AccountNum::try_from(id).unwrap();
            credentials::save(
                &crate::credentials::file::canonical_path(dir.path(), num),
                &creds,
            )
            .unwrap();
        }

        let state = test_state(dir.path());
        state.cache.set(
            1,
            RefreshStatus {
                account: 1,
                last_result: "valid".to_string(),
                expires_at_ms: 9_999_999_999_999,
                checked_at_secs: 99,
            },
        );

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""account":1"#), "body: {body}");
        // Account 2 is not in the cache, so it must not appear.
        assert!(!body.contains(r#""account":2"#), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }
}
