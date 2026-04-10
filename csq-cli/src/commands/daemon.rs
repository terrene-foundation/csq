//! `csq daemon start/stop/status` — background daemon lifecycle.
//!
//! # M8.4 scope
//!
//! The daemon now runs three subsystems:
//!
//! 1. **Unix-socket IPC server** serving `GET /api/health` (M8.3).
//! 2. **Background token refresher** that wakes every 5 minutes,
//!    discovers Anthropic accounts, and refreshes any whose access
//!    token expires within 2 hours (this slice). Updates a shared
//!    `RefreshStatus` cache that M8.5 routes will read from.
//! 3. **Future HTTP API routes** reading from the cache (M8.5).
//!
//! All three share a single `CancellationToken` — on SIGTERM the
//! daemon cancels, the refresher exits its loop, the server drains,
//! and the PID file is cleaned up via `PidFile::Drop`.
//!
//! Still foreground-only. Backgrounding will happen when the daemon
//! is hosted inside the Tauri tray app (M8.6).

use anyhow::{Context, Result};
use csq_core::daemon::{self, DaemonStatus, PidFile};
use csq_core::http;
use std::path::Path;
use std::sync::Arc;

/// Runs `csq daemon start` in the foreground.
///
/// Acquires the PID file (failing if another daemon is already
/// running), starts the Unix-socket HTTP server, installs signal
/// handlers, and blocks until SIGTERM/SIGINT. On return, the server
/// is stopped (socket removed) and the PID file is removed via
/// `PidFile`'s Drop impl.
pub fn handle_start(base_dir: &Path) -> Result<()> {
    let pid_path = daemon::pid_file_path(base_dir);

    // Acquire PID file; errors if another daemon is already running.
    let pid_file = PidFile::acquire(&pid_path).with_context(|| {
        format!("could not acquire PID file at {}", pid_path.display())
    })?;

    let sock_path = daemon::socket_path(base_dir);

    eprintln!(
        "csq daemon started (PID {}, foreground mode)",
        pid_file.owned_pid()
    );
    eprintln!("  PID file: {}", pid_file.path().display());
    eprintln!("  Socket:   {}", sock_path.display());
    eprintln!(
        "Send SIGTERM (kill {}) or Ctrl-C to stop.",
        pid_file.owned_pid()
    );

    // Multi-threaded runtime so the accept loop and in-flight
    // requests can make progress concurrently with signal handling.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("csq-daemon")
        .build()
        .context("failed to build tokio runtime for daemon")?;

    let base_dir_for_runtime = base_dir.to_path_buf();
    rt.block_on(async move {
        // Bind the Unix socket + axum router.
        #[cfg(unix)]
        {
            // Create the shared refresh-status cache at the daemon
            // level so both the refresher (writer) and the HTTP
            // routes (readers) see the same entries.
            let refresh_cache: Arc<daemon::TtlCache<u16, daemon::RefreshStatus>> =
                Arc::new(daemon::TtlCache::with_default_age());

            // Router state: cache + base_dir, Arc'd so per-request
            // State clones stay cheap.
            let router_state = daemon::server::RouterState {
                cache: Arc::clone(&refresh_cache),
                base_dir: Arc::new(base_dir_for_runtime.clone()),
            };

            match daemon::serve(&sock_path, router_state).await {
                Ok((server, server_join)) => {
                    tracing::info!("IPC server bound at {}", sock_path.display());

                    // Start the background refresher, sharing the
                    // server's shutdown token so both subsystems
                    // exit on the same signal. Passes the shared
                    // cache so refresher writes are visible to the
                    // HTTP routes.
                    let http_post: daemon::HttpPostFn =
                        Arc::new(|url: &str, body: &str| http::post_form(url, body));
                    let refresher = daemon::spawn_refresher(
                        base_dir_for_runtime.clone(),
                        Arc::clone(&refresh_cache),
                        http_post,
                        server.shutdown_token(),
                    );

                    // Block until SIGTERM/SIGINT arrives.
                    wait_for_shutdown().await;

                    eprintln!("csq daemon stopping...");
                    server.shutdown();

                    // Await the refresher with a 5s deadline so a
                    // stuck HTTP call can't block shutdown.
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        refresher.join,
                    )
                    .await
                    {
                        Ok(Ok(())) => tracing::info!("refresher stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "refresher task panicked"),
                        Err(_) => tracing::warn!("refresher did not stop within 5s deadline"),
                    }

                    // Give the accept loop up to 5s to exit.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        server_join,
                    )
                    .await;
                }
                Err(e) => {
                    // Bind failure is fatal — the daemon can't do
                    // anything useful without its IPC socket.
                    eprintln!("error: failed to bind daemon socket at {}: {e}",
                              sock_path.display());
                    return Err::<(), anyhow::Error>(anyhow::anyhow!(
                        "socket bind failed: {e}"
                    ));
                }
            }
        }
        #[cfg(not(unix))]
        {
            eprintln!(
                "warning: Unix-socket IPC server not available on this platform — \
                 Windows named-pipe support lands in M8.6"
            );
            let _ = base_dir_for_runtime;
            wait_for_shutdown().await;
        }
        Ok(())
    })?;

    // Explicit drop for clarity — PidFile::Drop removes the file if
    // it still contains our PID.
    drop(pid_file);
    eprintln!("csq daemon stopped cleanly");

    Ok(())
}

/// Runs `csq daemon stop` — sends SIGTERM to the running daemon and
/// polls for exit.
pub fn handle_stop(base_dir: &Path) -> Result<()> {
    let pid_path = daemon::pid_file_path(base_dir);

    match daemon::stop_daemon(&pid_path) {
        Ok(pid) => {
            eprintln!("csq daemon stopped (PID {pid})");
            Ok(())
        }
        Err(csq_core::error::DaemonError::NotRunning { .. }) => {
            eprintln!("csq daemon not running");
            Ok(())
        }
        Err(csq_core::error::DaemonError::StalePidFile { pid }) => {
            eprintln!("csq daemon stale PID file (PID {pid} not alive) — cleaned up");
            Ok(())
        }
        Err(csq_core::error::DaemonError::IpcTimeout { timeout_ms }) => {
            anyhow::bail!(
                "csq daemon did not exit within {timeout_ms}ms of SIGTERM \
                 — process may be stuck; investigate before sending SIGKILL"
            )
        }
        Err(e) => Err(e.into()),
    }
}

/// Runs `csq daemon status` — reports running/stale/stopped.
///
/// Returns Ok(()) in all cases so `csq daemon status` never fails
/// for informational queries. Exit code reflects status for shell
/// scripting: 0 = running, 1 = stopped/stale.
pub fn handle_status(base_dir: &Path) -> Result<()> {
    let pid_path = daemon::pid_file_path(base_dir);

    match daemon::status_of(&pid_path) {
        DaemonStatus::Running { pid } => {
            println!("running");
            eprintln!("  PID:      {pid}");
            eprintln!("  PID file: {}", pid_path.display());
            eprintln!("  Socket:   {}", daemon::socket_path(base_dir).display());
            Ok(())
        }
        DaemonStatus::Stale { pid } => {
            println!("stale");
            eprintln!("  PID file references dead PID {pid} at {}", pid_path.display());
            eprintln!("  Run `csq daemon start` to clean up and restart.");
            std::process::exit(1);
        }
        DaemonStatus::NotRunning => {
            println!("not running");
            std::process::exit(1);
        }
    }
}

/// Waits for SIGTERM or SIGINT (Unix) / Ctrl-C (Windows).
///
/// Returns as soon as either signal arrives. Must be called from
/// within a tokio runtime context.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt())
            .expect("failed to install SIGINT handler");
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received"),
            _ = int.recv() => tracing::info!("SIGINT received"),
        }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
        tracing::info!("Ctrl-C received");
    }
}
