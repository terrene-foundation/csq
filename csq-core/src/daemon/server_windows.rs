//! Windows named-pipe IPC server for the daemon.
//!
//! Serves the same axum HTTP/1.1 router as the Unix socket server
//! (`server.rs`), but over a Windows named pipe instead of a Unix
//! domain socket.
//!
//! # Platform scope
//!
//! This module is Windows-only (`cfg(windows)`). The Unix implementation
//! lives in `server.rs`.
//!
//! # Named pipe path
//!
//! `\\.\pipe\csq-{username}` where `username` is read from the
//! `USERNAME` environment variable (Windows default). Per-user isolation
//! on multi-user boxes is achieved through the username suffix combined
//! with Windows' default pipe DACL (see Security model below).
//!
//! # Security model
//!
//! Named pipes on Windows use two complementary layers:
//!
//! ## Layer 1 — `first_pipe_instance(true)`
//!
//! The first `ServerOptions::new().first_pipe_instance(true).create()`
//! call succeeds only if no other instance of the named pipe exists.
//! This prevents a rogue process from pre-creating the pipe and
//! hijacking connections. If a stale daemon pipe already exists (crashed
//! daemon that did not call `DisconnectNamedPipe`/`CloseHandle` cleanly),
//! the new daemon's bind attempt fails and the caller should clean up
//! the PID file and retry.
//!
//! ## Layer 2 — Windows default pipe DACL
//!
//! When `CreateNamedPipeW` is called without an explicit
//! `SECURITY_ATTRIBUTES`, Windows applies the process token's default
//! DACL to the pipe object. For a standard user account this grants
//! `GENERIC_READ | GENERIC_WRITE` to the owning user's SID and denies
//! everything to other users. The named pipe is therefore accessible
//! only to the user who created the daemon — matching the Unix `0o600`
//! socket permission model.
//!
//! An explicit DACL using `SetSecurityDescriptorDacl` / `windows-sys`
//! is not required for correctness on single-user or standard-user
//! accounts. Should the need arise (e.g., restricting access within a
//! shared Windows service account), a `SECURITY_ATTRIBUTES` can be
//! passed to `ServerOptions::security_attributes()`.
//!
//! ## Layer 3 — per-user pipe name
//!
//! The `csq-{username}` suffix ensures that two users on the same
//! multi-user terminal server cannot confuse each other's daemons even
//! if the DACL were somehow misconfigured.
//!
//! ## HTTP request authentication
//!
//! There is no application-layer authentication because the two layers
//! above establish that any caller is the owning user. Anyone who can
//! open the pipe is already the same user identity, which matches the
//! threat model for a per-user daemon.
//!
//! # Accept loop design
//!
//! Unlike Unix sockets (one `listen` fd, many `accept` calls), Windows
//! named pipes are single-connection per server instance. The accept
//! loop therefore:
//!
//! 1. Calls `server.connect().await?` on the current instance (waits
//!    for a client to connect).
//! 2. Moves the connected instance into a fresh tokio task for the
//!    hyper service.
//! 3. Creates a new pipe instance for the next connection before
//!    moving the old one.
//!
//! This ensures the pipe name is always "listening" while an existing
//! connection is being served.

#![cfg(windows)]

use super::server::{router, RouterState};
use crate::error::DaemonError;
use std::path::{Path, PathBuf};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio_util::sync::CancellationToken;

/// Handle to a running daemon HTTP server on Windows.
///
/// Drop does NOT stop the server — call [`WindowsServerHandle::shutdown`]
/// to signal shutdown and then await the join handle.
pub struct WindowsServerHandle {
    /// Pipe path string (e.g., `\\.\pipe\csq-alice`).
    pipe_name: String,
    /// Triggered to start graceful shutdown.
    shutdown: CancellationToken,
}

impl WindowsServerHandle {
    /// Signals the server to shut down.
    ///
    /// The accept loop exits on the next poll after the token fires.
    /// In-flight connections are allowed to complete on their own
    /// tasks.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Returns a clone of the shutdown token so sibling subsystems
    /// can cancel on the same signal.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Returns the pipe name the server is bound to.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Returns a `PathBuf` wrapping the pipe name for callers that
    /// expect a path (e.g., the `ServerHandle` abstraction in the
    /// daemon lifecycle).
    pub fn socket_path(&self) -> &Path {
        Path::new(&self.pipe_name)
    }
}

/// Binds a Windows named pipe at `pipe_name` and serves the daemon
/// HTTP router on it until `shutdown` fires.
///
/// # Behavior
///
/// 1. Creates the first pipe instance with `first_pipe_instance(true)`
///    so a stale pipe from a crashed daemon causes an immediate error
///    rather than silently serving a second daemon on the same name.
/// 2. Spawns the accept loop, which waits for connections via
///    `NamedPipeServer::connect()` and dispatches each to a tokio task
///    running the hyper/axum service.
/// 3. Before moving the connected instance to a task, creates the next
///    pipe instance so the pipe name is always accepting new connections.
/// 4. On `shutdown.cancelled()`, the accept loop exits. In-flight
///    connections are allowed to complete on their own tasks.
///
/// # Errors
///
/// Returns [`DaemonError::SocketConnect`] if the pipe cannot be created
/// (e.g., a live daemon already holds `first_pipe_instance`).
pub async fn serve(
    pipe_name: &str,
    state: RouterState,
) -> Result<(WindowsServerHandle, tokio::task::JoinHandle<()>), DaemonError> {
    // `first_pipe_instance(true)` ensures we are the only daemon
    // bound to this name. If another process (or a stale kernel object
    // from a crashed previous daemon) already holds the first instance,
    // this fails with ERROR_ACCESS_DENIED and we surface SocketConnect.
    let first_server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)
        .map_err(|e| {
            tracing::debug!(error = %e, pipe = pipe_name, "named pipe creation failed");
            DaemonError::SocketConnect {
                path: PathBuf::from(pipe_name),
            }
        })?;

    let shutdown = CancellationToken::new();
    let handle = WindowsServerHandle {
        pipe_name: pipe_name.to_string(),
        shutdown: shutdown.clone(),
    };

    let pipe_name_owned = pipe_name.to_string();
    let app = std::sync::Arc::new(router(state));
    let join = tokio::spawn(async move {
        accept_loop(first_server, pipe_name_owned, app, shutdown).await;
    });

    Ok((handle, join))
}

/// The accept loop for Windows named pipes.
///
/// Named pipes require a new server instance per accepted connection.
/// The pattern is:
///   1. Call `server.connect().await` — blocks until a client connects.
///   2. Before spawning the handler, create the *next* server instance
///      so the pipe name continues to accept new connections while the
///      current one is being served.
///   3. Move the current connected instance into a fresh tokio task for
///      the hyper/axum service.
///
/// Exits when `shutdown` is cancelled.
async fn accept_loop(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe_name: String,
    app: std::sync::Arc<axum::Router>,
    shutdown: CancellationToken,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    loop {
        // Wait for either shutdown or a client connecting.
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("daemon server (Windows): shutdown signaled, exiting accept loop");
                break;
            }
            connect_result = server.connect() => {
                match connect_result {
                    Ok(()) => {
                        // A client has connected to `server`. Before moving
                        // `server` into the handler task, create the next
                        // pipe instance so new clients can connect immediately
                        // without waiting for the current one to finish.
                        let next = match ServerOptions::new().create(&pipe_name) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "failed to create next pipe instance; \
                                     no new connections will be accepted"
                                );
                                // Move the existing connected server to the
                                // handler and exit — the accept loop cannot
                                // continue without a fresh server instance.
                                let connected = server;
                                let app = std::sync::Arc::clone(&app);
                                tokio::spawn(async move {
                                    serve_connection(connected, app).await;
                                });
                                break;
                            }
                        };

                        // Swap `server` to the new instance so the loop
                        // continues. Move the connected instance to a task.
                        let connected = std::mem::replace(&mut server, next);
                        let app = std::sync::Arc::clone(&app);
                        tokio::spawn(async move {
                            serve_connection(connected, app).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "named pipe connect error, continuing");
                        // Re-create the server instance — the current one
                        // may be in an error state after a failed connect.
                        match ServerOptions::new().create(&pipe_name) {
                            Ok(s) => server = s,
                            Err(create_err) => {
                                tracing::warn!(
                                    error = %create_err,
                                    "could not re-create pipe instance after connect error; \
                                     exiting accept loop"
                                );
                                break;
                            }
                        }
                        // Brief pause to avoid hot-spinning on persistent errors.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    tracing::info!(
        pipe = pipe_name,
        "daemon server (Windows): accept loop exited"
    );
}

/// Serves a single HTTP connection over a connected named pipe.
async fn serve_connection(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    app: std::sync::Arc<axum::Router>,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let app = std::sync::Arc::clone(&app);
        async move {
            let router = (*app).clone();
            router.oneshot(req).await
        }
    });
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
    {
        tracing::debug!(error = %e, "connection service error (Windows)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::cache::TtlCache;
    use crate::daemon::server::{RouterState, DISCOVERY_CACHE_MAX_AGE};
    use crate::oauth::OAuthStateStore;
    use std::sync::Arc;

    fn test_pipe_name() -> String {
        // Use the process ID to avoid collisions when tests run in
        // parallel. Each test gets a unique pipe name.
        format!(r"\\.\pipe\csq-test-{}", std::process::id())
    }

    fn test_state() -> RouterState {
        RouterState {
            cache: Arc::new(TtlCache::with_default_age()),
            discovery_cache: Arc::new(TtlCache::new(DISCOVERY_CACHE_MAX_AGE)),
            base_dir: Arc::new(std::path::PathBuf::from(r"C:\Temp\csq-test")),
            oauth_store: Some(Arc::new(OAuthStateStore::new())),
        }
    }

    /// Smoke test: `serve` binds a named pipe and returns a handle.
    /// The accept loop is running — calling `shutdown()` stops it.
    #[tokio::test]
    async fn serve_creates_pipe_and_shuts_down() {
        let pipe_name = test_pipe_name();
        let (handle, join) = serve(&pipe_name, test_state()).await.unwrap();

        assert_eq!(handle.pipe_name(), pipe_name);

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    /// `first_pipe_instance(true)` must prevent a second `serve` call
    /// on the same pipe name while the first is still running.
    #[tokio::test]
    async fn second_serve_fails_while_first_running() {
        let pipe_name = format!(r"\\.\pipe\csq-test-exclusive-{}", std::process::id());

        let (handle, _join) = serve(&pipe_name, test_state()).await.unwrap();

        // A second daemon on the same pipe must fail.
        let result = serve(&pipe_name, test_state()).await;
        assert!(
            result.is_err(),
            "expected second serve() to fail with SocketConnect"
        );

        handle.shutdown();
    }

    /// Health check round-trip: connect to the pipe as a client and
    /// send a minimal HTTP/1.1 GET /api/health. The server must respond
    /// with HTTP/1.1 200.
    #[tokio::test]
    async fn health_check_over_named_pipe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = format!(r"\\.\pipe\csq-test-health-{}", std::process::id());
        let (handle, _join) = serve(&pipe_name, test_state()).await.unwrap();

        // Give the server task a moment to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mut client = ClientOptions::new().open(&pipe_name).unwrap();

        let request = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        client.write_all(request).await.unwrap();

        let mut buf = Vec::new();
        // Read until the server closes the connection.
        client.read_to_end(&mut buf).await.unwrap();

        let response = String::from_utf8_lossy(&buf);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unexpected response: {response}"
        );

        handle.shutdown();
    }
}
