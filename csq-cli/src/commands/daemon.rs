//! `csq daemon start/stop/status` — background daemon lifecycle.
//!
//! # M8.3 scope
//!
//! The daemon now runs a Unix-socket HTTP server alongside the PID
//! file. Clients can reach `GET /api/health` to verify the daemon
//! is live. Background refresher and usage poller land in M8.4; the
//! wider HTTP API (accounts, usage, refresh, OAuth callback) lands
//! in M8.5; CLI delegation (status/statusline/swap) lands in M8.6.
//!
//! Still foreground-only. Backgrounding will happen when the daemon
//! is hosted inside the Tauri tray app (M8.6).

use anyhow::{Context, Result};
use csq_core::daemon::{self, DaemonStatus, PidFile};
use std::path::Path;

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

    rt.block_on(async move {
        // Bind the Unix socket + axum router.
        #[cfg(unix)]
        {
            match daemon::serve(&sock_path).await {
                Ok((server, join)) => {
                    tracing::info!("IPC server bound at {}", sock_path.display());

                    // Block until SIGTERM/SIGINT arrives.
                    wait_for_shutdown().await;

                    eprintln!("csq daemon stopping...");
                    server.shutdown();

                    // Give the accept loop up to 5s to exit.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
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
