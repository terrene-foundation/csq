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
use csq_core::oauth::OAuthStateStore;
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
    let pid_file = PidFile::acquire(&pid_path)
        .with_context(|| format!("could not acquire PID file at {}", pid_path.display()))?;

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

            // Short-TTL discovery cache shared between the
            // `/api/accounts` and `/api/refresh-status` routes.
            // Bounds the filesystem scan rate so a statusline
            // polling on a tight interval cannot DoS the daemon
            // (M8.5 security review MED #1).
            let discovery_cache: Arc<daemon::TtlCache<(), Vec<csq_core::accounts::AccountInfo>>> =
                Arc::new(daemon::TtlCache::new(
                    daemon::server::DISCOVERY_CACHE_MAX_AGE,
                ));

            // Create the shared OAuth state store for pending
            // paste-code logins. `GET /api/login/{N}` inserts
            // entries; `POST /api/oauth/exchange` consumes them.
            // No TCP callback listener is needed — Anthropic's
            // current OAuth flow for this client_id is paste-code,
            // not loopback-redirect.
            let oauth_store: Arc<OAuthStateStore> = Arc::new(OAuthStateStore::new());

            // Shared shutdown token so every subsystem (server,
            // refresher, usage poller, auto-rotate) exits on the
            // same signal.
            let shutdown = tokio_util::sync::CancellationToken::new();

            // Anthropic endpoints are behind Cloudflare which blocks
            // reqwest's rustls TLS fingerprint (JA3/JA4). Use Node.js
            // subprocess transport for token refresh — its OpenSSL
            // fingerprint passes Cloudflare. Falls back to reqwest if
            // no JS runtime is available.
            let http_post: daemon::HttpPostFn =
                Arc::new(|url: &str, body: &str| http::post_json_node(url, body));

            // Router state: refresh cache + discovery cache +
            // base_dir + OAuth store. Arc'd so per-request
            // State clones stay cheap.
            // Shared Gemini consumer state — same applied-set + quota
            // mutex as the NDJSON drainer (PR-G3, spec 05 §5.8.1).
            let gemini_consumer =
                csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default();

            let router_state = daemon::server::RouterState {
                cache: Arc::clone(&refresh_cache),
                discovery_cache: Arc::clone(&discovery_cache),
                base_dir: Arc::new(base_dir_for_runtime.clone()),
                oauth_store: Some(Arc::clone(&oauth_store)),
                gemini_consumer: gemini_consumer.clone(),
            };

            // PR-C4: clamp Codex invariants before any subsystem starts.
            // Pass 1 flips canonical credentials/codex-N.json to 0o400
            // (INV-P08); Pass 2 rewrites config-N/config.toml when its
            // `cli_auth_credentials_store = "file"` directive has drifted
            // (INV-P03). Both passes are surface-scoped to Codex and
            // mutex-coordinated with the refresher (INV-P09), so they're
            // safe to run before `spawn_refresher`.
            let _reconcile_summary = daemon::run_reconciler(&base_dir_for_runtime);

            match daemon::serve(&sock_path, router_state).await {
                Ok((server, server_join)) => {
                    tracing::info!("IPC server bound at {}", sock_path.display());

                    // Start the background refresher, sharing the
                    // outer shutdown token so it exits on the same
                    // signal as the OAuth callback listener. The
                    // Unix-socket server owns its own shutdown
                    // token (cancelled via `server.shutdown()`
                    // below) — the outer token drives the other
                    // two subsystems.
                    // Codex refresh transport — same Node-subprocess
                    // wrapper but returns the response `Date` header so
                    // the broker can emit `clock_skew_detected` per
                    // spec 07 §7.5 INV-P01 (PR-C4).
                    let http_post_codex: daemon::HttpPostFnCodex =
                        Arc::new(|url: &str, body: &str| http::post_json_node_with_date(url, body));

                    let refresher = daemon::spawn_refresher(
                        base_dir_for_runtime.clone(),
                        Arc::clone(&refresh_cache),
                        http_post,
                        http_post_codex,
                        shutdown.clone(),
                    );

                    // Start the background usage poller, sharing the
                    // same shutdown token. Polls GET /api/oauth/usage
                    // for each Anthropic account every 5 min and writes
                    // quota data to the local quota.json file so
                    // `csq status` shows real percentages.
                    // Usage poller also hits Anthropic (api.anthropic.com)
                    // — same Cloudflare fingerprint issue.
                    let http_get: daemon::HttpGetFn =
                        Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
                            http::get_bearer_node(url, token, headers)
                        });
                    let http_post_probe: daemon::HttpPostProbeFn =
                        Arc::new(|url: &str, headers: &[(String, String)], body: &str| {
                            http::post_json_with_headers(url, headers, body)
                        });
                    let usage_poller = daemon::spawn_usage_poller(
                        base_dir_for_runtime.clone(),
                        http_get,
                        http_post_probe,
                        gemini_consumer.clone(),
                        shutdown.clone(),
                    );

                    // Gemini midnight-LA reset task — zeroes the
                    // per-day request counter at midnight LA per
                    // ADR-G05. Cancellation-aware via the shared
                    // shutdown token.
                    let gemini_midnight =
                        tokio::spawn(csq_core::daemon::usage_poller::gemini::run_midnight_reset(
                            base_dir_for_runtime.clone(),
                            gemini_consumer.clone(),
                            shutdown.clone(),
                        ));

                    // Start the background auto-rotation loop (PR-A1).
                    // Walks term-<pid>/ handle dirs and calls
                    // repoint_handle_dir to atomically repoint symlinks
                    // without touching config-N/ (INV-01). Disabled by
                    // default; enable via {base_dir}/rotation.json.
                    // claude_home is needed to re-materialize settings.json
                    // after each repoint; pass None if $HOME is unavailable
                    // and the rotator becomes a no-op.
                    let claude_home_for_rotate = super::claude_home().ok();
                    let auto_rotator = daemon::spawn_auto_rotate(
                        base_dir_for_runtime.clone(),
                        claude_home_for_rotate,
                        shutdown.clone(),
                    );

                    // Start the handle-dir sweep. Scans term-* dirs
                    // every 60 seconds, preserves each dead dir's
                    // per-session image cache to ~/.claude/image-cache/,
                    // then removes the orphan. See journal 0035.
                    //
                    // If `claude_home()` cannot resolve `~/.claude`
                    // (malformed $CLAUDE_HOME, missing $HOME), pass
                    // `None` so the sweep still runs but skips
                    // preservation rather than routing images into a
                    // fallback path CC will never look at.
                    let claude_home_for_sweep = super::claude_home().ok();
                    let sweep = csq_core::session::spawn_sweep(
                        base_dir_for_runtime.clone(),
                        claude_home_for_sweep,
                        shutdown.clone(),
                    );

                    // Block until SIGTERM/SIGINT arrives.
                    wait_for_shutdown().await;

                    eprintln!("csq daemon stopping...");
                    // Cancel the outer token first so refresher +
                    // usage poller + auto-rotate start winding down.
                    shutdown.cancel();
                    // Then cancel the server's internal token so
                    // the accept loop exits on its next poll.
                    server.shutdown();

                    // Await the refresher with a 5s deadline so a
                    // stuck HTTP call can't block shutdown.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), refresher.join)
                        .await
                    {
                        Ok(Ok(())) => tracing::info!("refresher stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "refresher task panicked"),
                        Err(_) => tracing::warn!("refresher did not stop within 5s deadline"),
                    }

                    // Await the usage poller with a 5s deadline.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), usage_poller.join)
                        .await
                    {
                        Ok(Ok(())) => tracing::info!("usage poller stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "usage poller task panicked"),
                        Err(_) => tracing::warn!("usage poller did not stop within 5s deadline"),
                    }

                    // Await the Gemini midnight-LA reset task with a
                    // 5s deadline.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), gemini_midnight)
                        .await
                    {
                        Ok(Ok(())) => tracing::info!("gemini midnight reset stopped cleanly"),
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "gemini midnight reset task panicked")
                        }
                        Err(_) => {
                            tracing::warn!("gemini midnight reset did not stop within 5s deadline")
                        }
                    }

                    // Await the auto-rotation loop with a 5s deadline.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), auto_rotator.join)
                        .await
                    {
                        Ok(Ok(())) => tracing::info!("auto-rotation loop stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "auto-rotation task panicked"),
                        Err(_) => tracing::warn!("auto-rotation did not stop within 5s deadline"),
                    }

                    // Await the handle-dir sweep with a 5s deadline.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), sweep.join).await
                    {
                        Ok(Ok(())) => tracing::info!("handle-dir sweep stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "handle-dir sweep panicked"),
                        Err(_) => tracing::warn!("handle-dir sweep did not stop within 5s"),
                    }

                    // Give the accept loop up to 5s to exit.
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(5), server_join).await;
                }
                Err(e) => {
                    // Bind failure is fatal — the daemon can't do
                    // anything useful without its IPC socket.
                    eprintln!(
                        "error: failed to bind daemon socket at {}: {e}",
                        sock_path.display()
                    );
                    return Err::<(), anyhow::Error>(anyhow::anyhow!("socket bind failed: {e}"));
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
        Ok::<(), anyhow::Error>(())
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
            eprintln!(
                "  PID file references dead PID {pid} at {}",
                pid_path.display()
            );
            eprintln!("  Run `csq daemon start` to clean up and restart.");
            std::process::exit(1);
        }
        DaemonStatus::NotRunning => {
            println!("not running");
            std::process::exit(1);
        }
    }
}

/// Spawns the daemon in the background by re-executing the current binary
/// with `["daemon", "start"]` (no `-d` flag) and detaching it from the
/// parent's process group.
///
/// This avoids `fork()` entirely — Rust + tokio + fork is undefined
/// behaviour. Re-exec is the safe cross-platform pattern.
pub fn handle_start_background(base_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("could not determine current executable path")?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["daemon", "start"]);

    // Redirect all stdio to /dev/null so the detached process has no
    // inherited file descriptors pointing back to the terminal.
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .context("could not open /dev/null")?;
    cmd.stdin(devnull.try_clone().context("stdin dup")?);
    cmd.stdout(devnull.try_clone().context("stdout dup")?);
    cmd.stderr(devnull.try_clone().context("stderr dup")?);

    // On Unix, place the child in a new process group so it is no
    // longer a member of the terminal's session and won't receive
    // SIGHUP when the terminal closes.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd
        .spawn()
        .context("could not spawn background daemon process")?;

    let pid = child.id();
    // Do NOT call child.wait() — we intentionally let the child outlive us.

    eprintln!("csq daemon started in background (PID {pid})");
    eprintln!("  Binary: {}", exe.display());
    eprintln!("  Base:   {}", base_dir.display());
    eprintln!("Use `csq daemon status` to check, `csq daemon stop` to stop.");

    Ok(())
}

// ── Platform service integration ─────────────────────────────────────────────

/// Install csq as a platform service.
///
/// - macOS: writes a launchd plist to `~/Library/LaunchAgents/` and loads it.
/// - Linux: writes a systemd user unit and enables it.
/// - Windows: prints an informational message (not yet supported).
pub fn handle_install(base_dir: &Path) -> Result<()> {
    let _ = base_dir; // may be used by platform impls in future for log path
    platform_install()
}

/// Uninstall the platform service previously installed by `csq daemon install`.
pub fn handle_uninstall(_base_dir: &Path) -> Result<()> {
    platform_uninstall()
}

// ── macOS launchd ─────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("foundation.terrene.csq.plist"))
}

/// Build the launchd plist XML for the given binary path and log path.
/// Exported for unit-testing the generated XML.
#[cfg(target_os = "macos")]
pub fn build_launchd_plist(exe: &Path, log_path: &Path) -> String {
    let exe_str = exe.display();
    let log_str = log_path.display();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>foundation.terrene.csq</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe_str}</string>
		<string>daemon</string>
		<string>start</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>{log_str}</string>
	<key>StandardErrorPath</key>
	<string>{log_str}</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn platform_install() -> Result<()> {
    let plist_path = launchd_plist_path()?;

    // Check if already installed.
    if plist_path.exists() {
        eprintln!(
            "csq daemon service already installed at {}",
            plist_path.display()
        );
        eprintln!("  Use `csq daemon uninstall` first if you want to reinstall.");
        return Ok(());
    }

    let exe = std::env::current_exe().context("could not determine current executable path")?;
    let home = dirs::home_dir().context("could not determine home directory")?;
    let log_path = home.join(".claude").join("accounts").join("csq-daemon.log");

    // Ensure the LaunchAgents directory exists.
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "could not create LaunchAgents directory at {}",
                parent.display()
            )
        })?;
    }

    let plist_content = build_launchd_plist(&exe, &log_path);
    std::fs::write(&plist_path, &plist_content)
        .with_context(|| format!("could not write plist to {}", plist_path.display()))?;

    // Load the agent.
    let status = std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .status()
        .context("could not run launchctl load")?;

    if !status.success() {
        // Remove the plist so we leave a clean state.
        let _ = std::fs::remove_file(&plist_path);
        anyhow::bail!("launchctl load failed with exit code {:?}", status.code());
    }

    eprintln!("csq daemon service installed and started.");
    eprintln!("  Plist:   {}", plist_path.display());
    eprintln!("  Log:     {}", log_path.display());
    eprintln!("  Binary:  {}", exe.display());
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_uninstall() -> Result<()> {
    let plist_path = launchd_plist_path()?;

    if !plist_path.exists() {
        eprintln!("csq daemon service is not installed (no plist found).");
        return Ok(());
    }

    // Unload first; ignore exit code — the agent may already be stopped.
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .status();

    std::fs::remove_file(&plist_path)
        .with_context(|| format!("could not remove plist at {}", plist_path.display()))?;

    eprintln!("csq daemon service uninstalled.");
    eprintln!("  Removed: {}", plist_path.display());
    Ok(())
}

// ── Linux systemd ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn systemd_unit_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home
        .join(".config")
        .join("systemd")
        .join("user")
        .join("csq.service"))
}

/// Build the systemd user unit file content for the given binary path.
/// Exported for unit-testing the generated unit.
#[cfg(target_os = "linux")]
pub fn build_systemd_unit(exe: &Path) -> String {
    let exe_str = exe.display();
    format!(
        r#"[Unit]
Description=Code Session Quota Daemon

[Service]
Type=simple
ExecStart={exe_str} daemon start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#
    )
}

#[cfg(target_os = "linux")]
fn platform_install() -> Result<()> {
    let unit_path = systemd_unit_path()?;

    if unit_path.exists() {
        eprintln!(
            "csq daemon service already installed at {}",
            unit_path.display()
        );
        eprintln!("  Use `csq daemon uninstall` first if you want to reinstall.");
        return Ok(());
    }

    let exe = std::env::current_exe().context("could not determine current executable path")?;

    // Ensure the systemd user directory exists.
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "could not create systemd user directory at {}",
                parent.display()
            )
        })?;
    }

    let unit_content = build_systemd_unit(&exe);
    std::fs::write(&unit_path, &unit_content)
        .with_context(|| format!("could not write unit file to {}", unit_path.display()))?;

    // Reload systemd user daemon.
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .context("could not run systemctl --user daemon-reload")?;

    if !reload.success() {
        let _ = std::fs::remove_file(&unit_path);
        anyhow::bail!(
            "systemctl --user daemon-reload failed with exit code {:?}",
            reload.code()
        );
    }

    // Enable and start.
    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", "csq.service"])
        .status()
        .context("could not run systemctl --user enable --now csq.service")?;

    if !enable.success() {
        // Leave the unit file in place — the user can retry.
        anyhow::bail!(
            "systemctl --user enable --now failed with exit code {:?}",
            enable.code()
        );
    }

    eprintln!("csq daemon service installed and started.");
    eprintln!("  Unit:    {}", unit_path.display());
    eprintln!("  Binary:  {}", exe.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_uninstall() -> Result<()> {
    let unit_path = systemd_unit_path()?;

    if !unit_path.exists() {
        eprintln!("csq daemon service is not installed (no unit file found).");
        return Ok(());
    }

    // Disable and stop; ignore failure (unit may already be stopped).
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "csq.service"])
        .status();

    std::fs::remove_file(&unit_path)
        .with_context(|| format!("could not remove unit file at {}", unit_path.display()))?;

    // Reload so systemd forgets the unit.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    eprintln!("csq daemon service uninstalled.");
    eprintln!("  Removed: {}", unit_path.display());
    Ok(())
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn platform_install() -> Result<()> {
    eprintln!("Windows service integration is not yet supported.");
    eprintln!("Use `csq daemon start` in a terminal to run the daemon.");
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_uninstall() -> Result<()> {
    eprintln!("Windows service integration is not yet supported.");
    Ok(())
}

// ── Fallback for other platforms ──────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_install() -> Result<()> {
    eprintln!("Platform service integration is not supported on this OS.");
    eprintln!("Use `csq daemon start -d` to run the daemon in the background.");
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_uninstall() -> Result<()> {
    eprintln!("Platform service integration is not supported on this OS.");
    Ok(())
}

/// Waits for SIGTERM or SIGINT (Unix) / Ctrl-C (Windows).
///
/// Returns as soon as either signal arrives. Must be called from
/// within a tokio runtime context.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── macOS plist generation ────────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;
        use std::path::PathBuf;

        fn exe_path() -> PathBuf {
            PathBuf::from("/usr/local/bin/csq")
        }

        fn log_path() -> PathBuf {
            PathBuf::from("/Users/alice/.claude/accounts/csq-daemon.log")
        }

        #[test]
        fn plist_contains_required_label() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert
            assert!(
                plist.contains("<string>foundation.terrene.csq</string>"),
                "plist missing Label: {plist}"
            );
        }

        #[test]
        fn plist_contains_exe_path() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert
            assert!(
                plist.contains("<string>/usr/local/bin/csq</string>"),
                "plist missing exe path: {plist}"
            );
        }

        #[test]
        fn plist_contains_daemon_start_args() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert
            assert!(
                plist.contains("<string>daemon</string>")
                    && plist.contains("<string>start</string>"),
                "plist missing daemon start args: {plist}"
            );
        }

        #[test]
        fn plist_sets_run_at_load_true() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — RunAtLoad key must be followed by <true/>
            let run_at_load_pos = plist
                .find("<key>RunAtLoad</key>")
                .expect("RunAtLoad key missing");
            let after = &plist[run_at_load_pos..];
            assert!(
                after.contains("<true/>"),
                "RunAtLoad not set to true: {plist}"
            );
        }

        #[test]
        fn plist_sets_keep_alive_true() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — KeepAlive key must be followed by <true/>
            let keep_alive_pos = plist
                .find("<key>KeepAlive</key>")
                .expect("KeepAlive key missing");
            let after = &plist[keep_alive_pos..];
            assert!(
                after.contains("<true/>"),
                "KeepAlive not set to true: {plist}"
            );
        }

        #[test]
        fn plist_sets_process_type_background() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert
            assert!(
                plist.contains("<string>Background</string>"),
                "ProcessType not Background: {plist}"
            );
        }

        #[test]
        fn plist_contains_log_paths() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — both stdout and stderr redirect to the log path
            let log_str = log.display().to_string();
            let count = plist.matches(&log_str).count();
            assert_eq!(
                count, 2,
                "expected log path to appear twice (stdout + stderr): {plist}"
            );
        }

        #[test]
        fn plist_is_valid_xml_structure() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — basic XML structure
            assert!(plist.starts_with("<?xml"), "missing XML declaration");
            assert!(plist.contains("<!DOCTYPE plist"), "missing DOCTYPE");
            assert!(
                plist.contains("<plist version=\"1.0\">"),
                "missing plist element"
            );
            assert!(plist.contains("</plist>"), "missing closing plist tag");
            assert!(plist.contains("<dict>"), "missing dict element");
            assert!(plist.contains("</dict>"), "missing closing dict tag");
        }
    }

    // ── Linux systemd unit generation ─────────────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;

        fn exe_path() -> PathBuf {
            PathBuf::from("/home/alice/.cargo/bin/csq")
        }

        #[test]
        fn unit_contains_description() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("Description=Code Session Quota Daemon"),
                "unit missing Description: {unit}"
            );
        }

        #[test]
        fn unit_contains_exec_start_with_exe() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            let expected = format!("ExecStart={} daemon start", exe.display());
            assert!(unit.contains(&expected), "unit missing ExecStart: {unit}");
        }

        #[test]
        fn unit_sets_restart_on_failure() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("Restart=on-failure"),
                "unit missing Restart=on-failure: {unit}"
            );
        }

        #[test]
        fn unit_sets_restart_sec() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("RestartSec=5"),
                "unit missing RestartSec=5: {unit}"
            );
        }

        #[test]
        fn unit_wanted_by_default_target() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("WantedBy=default.target"),
                "unit missing WantedBy=default.target: {unit}"
            );
        }

        #[test]
        fn unit_has_all_three_sections() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("[Unit]"),
                "unit missing [Unit] section: {unit}"
            );
            assert!(
                unit.contains("[Service]"),
                "unit missing [Service] section: {unit}"
            );
            assert!(
                unit.contains("[Install]"),
                "unit missing [Install] section: {unit}"
            );
        }

        #[test]
        fn unit_type_is_simple() {
            // Arrange
            let exe = exe_path();

            // Act
            let unit = build_systemd_unit(&exe);

            // Assert
            assert!(
                unit.contains("Type=simple"),
                "unit missing Type=simple: {unit}"
            );
        }
    }

    // ── Background flag parsing (platform-agnostic) ───────────────────────────

    /// Verifies that the CLI argument parser accepts -d and --background
    /// as synonyms on `csq daemon start`. This tests clap integration
    /// without actually spawning a process.
    mod background_flag {
        use clap::Parser;

        // A minimal copy of the CLI struct that mirrors the real `DaemonCmd`
        // and `Cli` shapes so we can test arg parsing in isolation.
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: TestCmd,
        }

        #[derive(clap::Subcommand, Debug)]
        enum TestCmd {
            Daemon {
                #[command(subcommand)]
                action: TestDaemonCmd,
            },
        }

        #[derive(clap::Subcommand, Debug)]
        enum TestDaemonCmd {
            Start {
                #[arg(short = 'd', long = "background")]
                background: bool,
            },
        }

        #[test]
        fn background_flag_long_form_parses() {
            // Arrange + Act
            let cli = TestCli::try_parse_from(["csq", "daemon", "start", "--background"])
                .expect("--background should parse");

            // Assert
            let TestCmd::Daemon {
                action: TestDaemonCmd::Start { background },
            } = cli.command;
            assert!(background, "--background should set flag to true");
        }

        #[test]
        fn background_flag_short_form_parses() {
            // Arrange + Act
            let cli =
                TestCli::try_parse_from(["csq", "daemon", "start", "-d"]).expect("-d should parse");

            // Assert
            let TestCmd::Daemon {
                action: TestDaemonCmd::Start { background },
            } = cli.command;
            assert!(background, "-d should set flag to true");
        }

        #[test]
        fn start_without_flag_defaults_to_foreground() {
            // Arrange + Act
            let cli = TestCli::try_parse_from(["csq", "daemon", "start"])
                .expect("start without flag should parse");

            // Assert
            let TestCmd::Daemon {
                action: TestDaemonCmd::Start { background },
            } = cli.command;
            assert!(!background, "background should default to false");
        }
    }
}
