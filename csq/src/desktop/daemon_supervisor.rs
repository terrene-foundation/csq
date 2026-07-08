//! In-process daemon supervisor.
//!
//! Runs the csq daemon (refresher + usage poller + auto-rotate + IPC
//! server) inside the Tauri app process itself, so tokens are
//! refreshed for as long as the desktop app is running — no separate
//! `csq daemon start` required.
//!
//! ### Why in-process
//!
//! an internal journal entry (this session): every OAuth account on the author's
//! machine had been expired for 6–80 hours because the user had to
//! remember to run `csq daemon start` manually. Shipping the daemon
//! as a separate CLI process was a solvable foot-gun — the desktop
//! app has a tokio runtime and a long-lived lifetime anyway (tray
//! icon keeps the process alive even when the main window closes),
//! so the daemon can just ride inside it.
//!
//! ### Cohabitation with an external daemon
//!
//! If the user still has `csq daemon start` running in a terminal
//! (e.g. they're debugging), the PID file guard in
//! `PidFile::acquire` rejects our attempt and we silently defer to
//! the external daemon. The supervisor loop then watches for that
//! daemon to go away and takes over when it does. No spin-locking,
//! no zombies: each iteration of the loop either owns the daemon or
//! sleeps 60s and re-polls.
//!
//! ### Shutdown
//!
//! On app exit, the supervisor's `CancellationToken` is fired. The
//! server, refresher, usage poller, and auto-rotator all observe the
//! same token and drain gracefully. The `PidFile` drops last,
//! cleaning up the `.csq-daemon.pid` file.

use csq_core::daemon::{self, detect_daemon, DetectResult, PidFile};
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// Unix-only imports for run_daemon (server, refresher subsystems).
// On Windows, the supervisor loop still detects external daemons and
// acquires the PidFile, but run_daemon is a no-op stub (M8.6).
#[cfg(unix)]
use csq_core::accounts::AccountInfo;
#[cfg(unix)]
use csq_core::daemon::{
    server as daemon_server, HttpGetFn, HttpPostFn, HttpPostFnCodex, HttpPostProbeFn, TtlCache,
};
#[cfg(unix)]
use csq_core::http;
#[cfg(unix)]
use csq_core::oauth::OAuthStateStore;
#[cfg(unix)]
use std::sync::Arc;

/// Minimum wait between failed takeover attempts. Short enough
/// that a crashing external daemon doesn't starve csq for minutes
/// before our supervisor catches the gap.
const BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Maximum wait between failed takeover attempts. 60s keeps the
/// loop from hot-spinning under pathological contention (e.g. two
/// csq apps racing each other to own the same PidFile) while also
/// being well below the 5-minute refresh interval.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Supervisor backoff state. Starts at [`BACKOFF_MIN`], doubles on
/// each failed attempt, caps at [`BACKOFF_MAX`], resets to
/// `BACKOFF_MIN` whenever the supervisor successfully takes over.
///
/// Addresses an internal journal entry design question 1: the fixed 60s poll
/// burns a full minute of refresh downtime every time an external
/// daemon crashes, and hot-loops under pathological contention.
/// Exponential backoff gives instant recovery in the common case
/// (1s) while bounding the worst case (60s).
#[derive(Debug, Clone, Copy)]
struct Backoff {
    current: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: BACKOFF_MIN,
        }
    }

    fn current(&self) -> Duration {
        self.current
    }

    /// Doubles the wait up to [`BACKOFF_MAX`]. Call after a failed
    /// attempt before the next retry.
    fn bump(&mut self) {
        let next = self.current.saturating_mul(2);
        self.current = std::cmp::min(next, BACKOFF_MAX);
    }

    /// Resets to [`BACKOFF_MIN`]. Call whenever the supervisor
    /// successfully owns the daemon (so the next failure recovers
    /// instantly instead of inheriting the previous backoff).
    fn reset(&mut self) {
        self.current = BACKOFF_MIN;
    }
}

/// Top-level handle returned to the Tauri setup() hook. Owns the
/// shutdown token; dropping it does **not** stop the daemon — call
/// [`shutdown`](Self::shutdown) explicitly at app exit.
pub struct SupervisorHandle {
    shutdown: CancellationToken,
}

impl SupervisorHandle {
    /// Fires the shared cancellation token. Any subsystem currently
    /// in-flight drains on its own deadline; the supervisor loop
    /// exits on the next iteration.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Starts the in-process daemon supervisor.
///
/// Spawns a single tokio task that loops forever until `shutdown`
/// fires. Each iteration tries to take ownership of the daemon
/// (`PidFile::acquire` + `serve`), and if another daemon already
/// has it, waits 60s and retries.
///
/// This function returns immediately — the work happens on the
/// returned tokio task.
pub fn start(base_dir: PathBuf) -> SupervisorHandle {
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tauri::async_runtime::spawn(async move {
        supervisor_loop(base_dir, shutdown_clone).await;
    });

    SupervisorHandle { shutdown }
}

/// Supervisor main loop. Owns the lifetime of the in-process daemon
/// across crashes and external-daemon contention.
///
/// Backoff semantics:
/// - Cold start: `BACKOFF_MIN` (1s)
/// - On each failed takeover attempt: double the wait, cap at
///   `BACKOFF_MAX` (60s)
/// - On each successful takeover (PidFile acquired, subsystems
///   spawned): reset to `BACKOFF_MIN` so the next failure recovers
///   instantly
/// - On clean daemon exit (we owned it, cancellation not fired):
///   stay at the reset value and retry after 5s
async fn supervisor_loop(base_dir: PathBuf, cancel: CancellationToken) {
    // Windows honesty guard — an internal journal entry P1-3. The non-unix path
    // of `run_daemon` is a stub with no subsystems. Without this
    // guard the supervisor would still acquire the PidFile, making
    // `detect_daemon` and the tray both report "daemon running"
    // while tokens silently go stale. Until the Windows named-pipe
    // daemon (server_windows.rs exists in csq-core) is wired up end
    // to end, refuse to claim ownership on Windows and surface
    // "daemon not available" instead.
    #[cfg(not(unix))]
    {
        let _ = base_dir;
        log::warn!(
            "in-process daemon is not yet available on this platform \
             (Windows named-pipe daemon pending). Tokens will not refresh \
             automatically. See release notes for manual workflow."
        );
        cancel.cancelled().await;
        return;
    }

    #[cfg(unix)]
    supervisor_loop_unix(base_dir, cancel).await;
}

#[cfg(unix)]
async fn supervisor_loop_unix(base_dir: PathBuf, cancel: CancellationToken) {
    log::info!("daemon supervisor starting");
    let mut backoff = Backoff::new();
    loop {
        // ── 1. Detect current state ──────────────────────────────
        //
        // `detect_daemon` returns `NotRunning` (fresh state),
        // `Healthy` (someone else owns it — observe), `Stale`
        // (cleanup + take over), or `Unhealthy` (another daemon is
        // struggling; back off so we don't race it).
        match detect_daemon(&base_dir) {
            DetectResult::Healthy {
                pid,
                daemon_version,
                ..
            } => {
                // Surface drift loudly so an operator inspecting desktop
                // logs can see why the running daemon's data lags the
                // freshly-installed app. We do not unilaterally take over
                // — that would kill an in-flight CLI flow — but a
                // `warn!` line is enough to point at the remediation.
                if let Some(reason) = daemon::version_drift_reason(&daemon_version) {
                    log::warn!(
                        "external daemon (PID {pid}) reports drift: {reason}; deferring {:?}",
                        backoff.current()
                    );
                } else {
                    log::debug!(
                        "external daemon already running (PID {pid}); deferring {:?}",
                        backoff.current()
                    );
                }
                // Wait and re-poll. If the external daemon dies, the
                // next detect returns NotRunning/Stale and we take over.
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
            DetectResult::Unhealthy { reason } => {
                log::warn!(
                    "existing daemon is unhealthy ({reason}); deferring {:?}",
                    backoff.current()
                );
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
            DetectResult::Stale { reason } => {
                log::info!("stale daemon state detected ({reason}); taking over");
                // Fall through — PidFile::acquire will clean up the
                // stale file by virtue of being a fresh PidFile.
            }
            DetectResult::NotRunning => {
                log::info!("no daemon running; taking over");
            }
        }

        // ── 2. Try to acquire ownership ──────────────────────────
        let pid_path = daemon::pid_file_path(&base_dir);
        let pid_file = match PidFile::acquire(&pid_path) {
            Ok(f) => f,
            Err(e) => {
                // Race: another process grabbed the PidFile between
                // our detect call and our acquire call. Back off
                // exponentially and let the loop observe next
                // iteration. Protects against hot-loops when two
                // csq apps fight over the same account dir.
                log::debug!(
                    "PidFile::acquire failed ({e}); another daemon raced us; backing off {:?}",
                    backoff.current()
                );
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
        };

        // ── 3. Successfully owning the daemon — reset backoff ────
        //
        // Any future failure (subsystem crash, next takeover
        // attempt) starts from BACKOFF_MIN again so we recover
        // instantly in the common case.
        backoff.reset();

        // ── 4. Run one daemon instance until it exits ────────────
        //
        // On Unix: binds the socket, spawns subsystems, waits for
        // either cancellation or a subsystem failure, then cleans up.
        // On Windows: M8.6 — no daemon subsystems yet; hold the
        // PidFile and wait for cancellation.
        if let Err(e) = run_daemon(&base_dir, cancel.clone()).await {
            log::warn!("in-process daemon exited with error: {e}");
        } else {
            log::info!("in-process daemon exited cleanly");
        }
        drop(pid_file);

        // If the outer cancel fired during run_daemon, exit the
        // supervisor loop. Otherwise, the daemon exited for some
        // internal reason and we should retry after a short wait.
        // `BACKOFF_MIN` is the right delay here — we just cleanly
        // released the lock, so the next iteration should try
        // again almost immediately rather than inherit a stale
        // exponential wait from before the takeover.
        if cancel.is_cancelled() {
            return;
        }
        if wait_or_cancelled(&cancel, BACKOFF_MIN).await {
            return;
        }
    }
}

/// Sleeps for `duration` or until the cancellation token fires.
/// Returns `true` if cancelled, `false` if the sleep completed
/// normally. Lets the supervisor loop respect shutdown promptly.
async fn wait_or_cancelled(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

/// One full run of the in-process daemon: bind socket, spawn
/// subsystems, await cancellation, drain cleanly.
///
/// Mirrors the CLI `csq daemon start` startup sequence in
/// `csq-cli/src/commands/daemon.rs` so the subsystem composition
/// stays in exactly one shape — refresher + usage poller +
/// auto-rotate + server, all sharing a single shutdown token.
#[cfg(unix)]
async fn run_daemon(
    base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
) -> Result<(), String> {
    let sock_path = daemon::socket_path(base_dir);

    // Local shutdown token derived from outer_cancel. The server
    // gets its own internal token (created by `serve`); we cancel
    // our subsystems plus the server when the outer token fires.
    let shutdown = outer_cancel.clone();

    let refresh_cache: Arc<TtlCache<u16, daemon::RefreshStatus>> =
        Arc::new(TtlCache::with_default_age());
    let discovery_cache: Arc<TtlCache<(), Vec<AccountInfo>>> =
        Arc::new(TtlCache::new(daemon_server::DISCOVERY_CACHE_MAX_AGE));
    let oauth_store: Arc<OAuthStateStore> = Arc::new(OAuthStateStore::new());

    // Anthropic endpoints are behind Cloudflare which blocks
    // reqwest's rustls TLS fingerprint (JA3/JA4). Use Node.js
    // subprocess transport — its OpenSSL fingerprint passes
    // Cloudflare. Falls back to reqwest if no JS runtime found.
    let http_post: HttpPostFn = Arc::new(|url: &str, body: &str| http::post_json_node(url, body));
    // PR-C4: Codex refresh transport returns body + Date header so the
    // broker can emit `clock_skew_detected` per spec 07 §7.5 INV-P01.
    let http_post_codex: HttpPostFnCodex =
        Arc::new(|url: &str, body: &str| http::post_json_node_with_date(url, body));
    let http_get: HttpGetFn = Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
        http::get_bearer_node(url, token, headers)
    });
    let http_post_probe: HttpPostProbeFn =
        Arc::new(|url: &str, headers: &[(String, String)], body: &str| {
            http::post_json_with_headers(url, headers, body)
        });

    // Shared Gemini consumer state — same applied-set + quota mutex
    // as the NDJSON drainer (PR-G3, spec 05 §5.8.1).
    let gemini_consumer = csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default();

    // FIX-2: mirror the CLI daemon's verify_chain block so the desktop
    // path has the same audit health signal and sentinel as the CLI path.
    // Run synchronous verify_chain in a spawn_blocking call to keep the
    // async runtime free during disk I/O.
    let audit_health: csq_core::audit::AuditHealth = {
        // FIX-5b: clamp timeout floor to 1s (same as CLI daemon).
        let timeout_secs: u64 = std::env::var("CSQ_AUDIT_VERIFY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1))
            .unwrap_or(5);
        let record_limit: usize = std::env::var("CSQ_AUDIT_VERIFY_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let verify_cfg = csq_core::audit::VerifyConfig {
            record_limit,
            keychain_service: csq_core::audit::AUDIT_SIGNING_SERVICE_NAME.to_string(),
        };
        let base_for_verify = base_dir.to_path_buf();
        let verify_future = tokio::task::spawn_blocking(move || {
            // M3 §10.5 (W2a): reconcile the born-canonical EATP attestation chain's
            // own `.chain-broken` sentinel inside the SAME spawn_blocking so the
            // startup timeout covers both chains. Side pass — the EATP chain does
            // not gate daemon startup (the op-chain result below is the authority).
            // Inert until the EATP chain exists (`verify_chain_in` returns
            // Ok(default) for absent `eatp-runs/`).
            let eatp = csq_core::audit::verify_chain_in(
                &base_for_verify,
                &verify_cfg,
                None,
                csq_core::audit::ChainKind::Eatp,
            );
            csq_core::audit::reconcile_chain_sentinel(
                &base_for_verify,
                csq_core::audit::ChainKind::Eatp.runs_subdir(),
                &eatp,
            );
            csq_core::audit::verify_chain(&base_for_verify, &verify_cfg, None)
        });
        let health = match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            verify_future,
        )
        .await
        {
            Ok(Ok(Ok(summary))) if summary.historical_key_gaps.is_empty() => {
                log::info!("audit chain verified clean (desktop daemon startup)");
                csq_core::audit::AuditHealth::Verified
            }
            Ok(Ok(Ok(summary))) => {
                log::warn!(
                    "audit chain DEGRADED ({} historical-key gap(s)) (desktop daemon startup)",
                    summary.historical_key_gaps.len()
                );
                csq_core::audit::AuditHealth::Degraded {
                    gaps: summary.historical_key_gaps,
                }
            }
            Ok(Ok(Err(ref e))) => {
                let h = csq_core::audit::AuditHealth::from_ledger_error(e);
                match &h {
                    // KeychainUnavailable (transient keychain access) → Unknown,
                    // NOT a chain-integrity failure. DEFERRED, not BROKEN.
                    csq_core::audit::AuditHealth::Unknown { reason } => {
                        log::error!(
                            "audit verify could not read the signing key (keychain locked / \
                             access-denied; {reason}) — audit subsystem fail-closed this run \
                             (desktop daemon startup); run `csq audit migrate-keys`"
                        );
                        // Parity with the panic/timeout Unknown arms (and the CLI
                        // daemon): emit an operator-visible stderr line too.
                        eprintln!(
                            "csq desktop daemon: AUDIT VERIFY DEFERRED — the signing key is \
present but the keychain could not be read (locked / access-denied). The chain is NOT \
broken. Audit anchoring/emit are disabled this run. Run `csq audit migrate-keys`."
                        );
                    }
                    _ => {
                        let ek = if let csq_core::audit::AuditHealth::Broken {
                            ref error_kind,
                            ..
                        } = h
                        {
                            error_kind.clone()
                        } else {
                            "audit_chain_integrity_failure".to_string()
                        };
                        log::error!(
                            "audit chain BROKEN ({ek}) — audit subsystem fail-closed (desktop daemon startup)"
                        );
                    }
                }
                h
            }
            // FIX-5a: raise to ERROR + eprintln! — Unknown is as serious as Broken.
            Ok(Err(join_err)) => {
                log::error!(
                    "audit verify task panicked: {join_err} — audit subsystem fail-closed (desktop daemon startup)"
                );
                eprintln!(
                    "csq desktop daemon: AUDIT VERIFY TASK PANICKED. \
Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                );
                csq_core::audit::AuditHealth::Unknown {
                    reason: "audit_verify_task_panicked".to_string(),
                }
            }
            Err(_timeout) => {
                log::error!(
                    "audit verify timed out after {timeout_secs}s — audit subsystem fail-closed (desktop daemon startup)"
                );
                eprintln!(
                    "csq desktop daemon: AUDIT VERIFY TIMED OUT after {timeout_secs}s. \
Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                );
                csq_core::audit::AuditHealth::Unknown {
                    reason: "audit_verify_timeout".to_string(),
                }
            }
        };

        // FIX-1/FIX-2: set/clear cross-process sentinel.
        // FIX-2: Unknown (timeout/panic) leaves sentinel UNCHANGED — a transient
        // condition must not produce a durable write-lockout that outlives it.
        match &health {
            csq_core::audit::AuditHealth::Verified
            | csq_core::audit::AuditHealth::Degraded { .. } => {
                csq_core::audit::clear_chain_broken(base_dir);
            }
            csq_core::audit::AuditHealth::Broken { error_kind, .. } => {
                csq_core::audit::set_chain_broken(base_dir, error_kind);
            }
            csq_core::audit::AuditHealth::Unknown { .. } => {
                // Transient condition — do not set a durable sentinel.
                // The in-RAM audit_health still gates daemon emit/anchor.
            }
        }

        health
    };

    // Clone before move into router_state so the anchor gate below can consult it.
    let audit_health_for_anchor = audit_health.clone();
    let router_state = daemon_server::RouterState {
        cache: Arc::clone(&refresh_cache),
        discovery_cache: Arc::clone(&discovery_cache),
        base_dir: Arc::new(base_dir.to_path_buf()),
        oauth_store: Some(Arc::clone(&oauth_store)),
        gemini_consumer: gemini_consumer.clone(),
        audit_health,
        // #783 — seed the interactive enforcement registry from the fail-closed
        // §10.5 activation gate (absent → empty/503).
        // #784 follow-up — inject the cross-SDK kailash projector (the csq crate
        // owns the seam; csq-core cannot name it).
        // T-M4.3 — inject the PACT governor factory (twin of the CLI daemon path)
        // so a configured operating envelope wires the first production
        // ActionGovernor (fail-closed: an unloadable envelope refuses to open).
        #[cfg(feature = "enterprise")]
        interactive: Arc::new({
            let reg = csq_core::daemon::interactive_live::seed_registry(
                base_dir,
                Some(crate::kailash_projector::make_kailash_projector()),
                Some(crate::kailash_governor::make_governor_factory()),
                // T-M4.5 — inject the lifecycle-audit-sink factory (twin of the CLI
                // daemon path) so every session records a signed audit trail.
                Some(crate::kailash_audit_sink::make_audit_sink_factory()),
            );
            // M3 §10.5 W2b — inject the EATP born-canonical genesis guard (twin
            // of the CLI daemon path). Classifies the genesis record on every
            // session open; non-BornCanonical refuses EATP chain appends but
            // the session still proceeds.
            // M3 §10.5 W3 — inject the EATP session-close attestation writer (twin
            // of the CLI daemon path). Appends a born-canonical session-close
            // attestation on every close (fail-closed-NON-FATAL).
            reg.with_eatp_genesis_guard(crate::kailash_eatp_genesis::make_eatp_genesis_guard(
                base_dir,
            ))
            .with_eatp_attestor(
                crate::kailash_eatp_attest::make_eatp_session_close_attestor(base_dir),
            )
        }),
    };

    // PR-C4: reconciler clamps Codex invariants (canonical 0o400 +
    // config.toml `cli_auth_credentials_store = "file"`) before any
    // subsystem touches them. Mutex-coordinated with the refresher.
    let _reconcile_summary = daemon::run_reconciler(base_dir);

    // M3-7 + M4-5: Phase 4 fail-closed gate (an internal journal entry Delta F / OQ #7;
    // strengthened in M4-5). Refuse to start if the on-disk store predates
    // Phase 4 layout — the live-mirror retirement assumes identity
    // credentials + settings + (where Codex-bound) credentials-codex are
    // seeded for every UUID-keyed slot, and the gate enforces that. The
    // error's `Display` carries operator-actionable next steps per
    // `tauri-commands.md` MUST Rule 6.
    if let Err(e) = csq_core::daemon::startup_reconciler::phase4_gate_check(base_dir) {
        return Err(format!("phase 4 gate refused start: {e}"));
    }

    // Bind the Unix socket first. If bind fails (e.g. another
    // daemon owns it despite the PidFile acquire — shouldn't
    // happen but we guard against it), return so the supervisor
    // loop can back off and retry.
    let (server, server_join) = daemon::serve(&sock_path, router_state)
        .await
        .map_err(|e| format!("socket bind failed: {e}"))?;
    log::info!("in-process daemon socket bound at {}", sock_path.display());

    // Subsystems share `shutdown` so a single cancel drains them
    // all. The server owns its own internal token fired via
    // `server.shutdown()` below.
    let refresher = daemon::spawn_refresher(
        base_dir.to_path_buf(),
        Arc::clone(&refresh_cache),
        http_post,
        http_post_codex,
        shutdown.clone(),
    );
    let usage_poller = daemon::spawn_usage_poller(
        base_dir.to_path_buf(),
        http_get,
        http_post_probe,
        gemini_consumer.clone(),
        shutdown.clone(),
    );
    // Gemini midnight-LA reset task (PR-G3, ADR-G05).
    let gemini_midnight = tokio::spawn(csq_core::daemon::usage_poller::gemini::run_midnight_reset(
        base_dir.to_path_buf(),
        gemini_consumer.clone(),
        shutdown.clone(),
    ));
    // PR-A1: pass claude_home so the rotator can re-materialize
    // settings.json after each handle dir repoint. Reuse the same
    // dirs::home_dir() resolution the sweep uses. None → rotator no-op.
    let claude_home_for_rotate = dirs::home_dir().map(|h| h.join(".claude"));
    let auto_rotator = daemon::spawn_auto_rotate(
        base_dir.to_path_buf(),
        claude_home_for_rotate,
        shutdown.clone(),
    );
    // Sweep preserves each dead handle dir's image-cache into
    // ~/.claude/image-cache/ before removing the orphan. If we
    // cannot resolve ~/.claude (no $HOME in a sandboxed env), pass
    // `None` so the sweep still runs but skips preservation —
    // better to lose images than route them into a fallback path
    // like base_dir/image-cache/ that CC will never find.
    let claude_home_for_sweep = dirs::home_dir().map(|h| h.join(".claude"));
    let sweep = csq_core::session::spawn_sweep(
        base_dir.to_path_buf(),
        claude_home_for_sweep,
        shutdown.clone(),
    );

    // Daemon-written usage-ledger writer (an internal ticket) — mirrors the CLI daemon
    // wiring. The desktop app IS the daemon (in-process supervisor), so this
    // task publishes each slot's usage ledger that `get_account_usage` reads
    // sub-ms instead of running the ~20s live transcript scan on the dashboard
    // render path. Daemon is the SOLE producer; terminals only read
    // (account-terminal-separation.md Rule 1, extended for billing telemetry).
    let claude_home_for_ledger = dirs::home_dir().map(|h| h.join(".claude"));
    let usage_ledger_writer = daemon::spawn_usage_ledger_writer(
        base_dir.to_path_buf(),
        claude_home_for_ledger,
        shutdown.clone(),
        chrono::Utc::now,
    );

    // Background update check — same 24-hour-cached behavior as the
    // CLI. Fires a detached OS thread on daemon start so desktop
    // users see the "csq vX.Y.Z available" notice on app launch.
    // Without this, the CLI emits notices on every command but the
    // desktop app silently misses every release.
    //
    // Edition independence (rules/independence.md): COMMUNITY channel only —
    // an enterprise desktop must not query terrene-foundation/csq or surface a
    // community upgrade notice (mirrors the CLI + desktop update gates).
    if crate::BUILD_EDITION != "enterprise" {
        csq_core::update::auto_update_bg(base_dir.to_path_buf());
    }

    // M14 — external anchoring task (mirrors CLI daemon.rs wiring).
    // FIX-2: gate on audit_health.is_operational() so the anchor is not
    // spawned when the chain is Broken/Unknown (mirrors CLI daemon.rs).
    let anchor_handle = if audit_health_for_anchor.is_operational() {
        let sink_cfg = csq_core::audit::AuditSinkConfig::load(base_dir).unwrap_or_default();
        let sink: Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> =
            resolve_anchor_sink_desktop(&sink_cfg);
        sink.and_then(|s| {
            daemon::spawn_anchor_task(base_dir.to_path_buf(), sink_cfg, s, shutdown.clone())
        })
    } else {
        log::info!(
            "audit chain not operational — anchor task not spawned (desktop daemon startup)"
        );
        None
    };

    // Block until cancellation fires from the app lifecycle.
    outer_cancel.cancelled().await;

    log::info!("in-process daemon stopping");
    server.shutdown();

    // Drain with per-subsystem deadlines so one stuck HTTP call
    // can't wedge app shutdown. The same 5s budget the CLI uses.
    let _ = tokio::time::timeout(Duration::from_secs(5), refresher.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), usage_poller.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), gemini_midnight).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), auto_rotator.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), sweep.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), usage_ledger_writer.join).await;
    if let Some(handle) = anchor_handle {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle.join).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), server_join).await;

    Ok(())
}

/// Resolves the active `LedgerSink` from `sink_cfg` for the desktop daemon.
/// Mirrors `resolve_anchor_sink` in `cli/commands/daemon.rs` — keep the two in sync.
fn resolve_anchor_sink_desktop(
    sink_cfg: &csq_core::audit::AuditSinkConfig,
) -> Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> {
    match sink_cfg.sink.as_str() {
        "none" => None,

        #[cfg(feature = "rekor-sink")]
        "rekor" => {
            match csq_core::audit::impls::sinks::rekor::RekorSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL: M07 in-memory mock substrate — not a durable witness.
                    // See the CLI resolver's comment for the full rationale.
                    log::warn!(
                        "rekor sink uses the in-memory M07 substrate (non-persistent); \
                         real Sigstore Rekor HTTP client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log::warn!("rekor sink initialisation failed — anchor task not started: {e}");
                    None
                }
            }
        }

        #[cfg(feature = "csq-ledger-sink")]
        "csq-ledger" => {
            match csq_core::audit::impls::csq_ledger_sink::CsqLedgerSink::with_defaults() {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    log::warn!(
                        "csq-ledger sink initialisation failed — anchor task not started: {e}"
                    );
                    None
                }
            }
        }

        other => {
            log::warn!(
                "sink '{}' configured but not compiled; rebuild with --features csq/{}-sink",
                other,
                other,
            );
            None
        }
    }
}

/// Windows stub — the csq daemon has no named-pipe backend yet
/// (M8-03). The supervisor loop will just sit on the backoff wait
/// until cancellation fires.
#[cfg(not(unix))]
async fn run_daemon(
    _base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
) -> Result<(), String> {
    log::warn!("in-process daemon not supported on this platform (M8-03 Windows IPC pending)");
    outer_cancel.cancelled().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_min() {
        let b = Backoff::new();
        assert_eq!(b.current(), BACKOFF_MIN);
    }

    #[test]
    fn backoff_doubles_on_bump() {
        let mut b = Backoff::new();
        assert_eq!(b.current(), Duration::from_secs(1));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(2));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(4));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(8));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut b = Backoff::new();
        // Hammer it 20 times — way past the cap.
        for _ in 0..20 {
            b.bump();
        }
        assert_eq!(b.current(), BACKOFF_MAX);
    }

    #[test]
    fn backoff_reset_drops_to_min() {
        let mut b = Backoff::new();
        b.bump();
        b.bump();
        b.bump();
        assert!(b.current() > BACKOFF_MIN);
        b.reset();
        assert_eq!(b.current(), BACKOFF_MIN);
    }

    #[test]
    fn backoff_saturates_on_overflow() {
        // Guard against u128 overflow in Duration multiplication.
        // Doubling a 60s Duration once is 120s; capping to 60s means
        // we never get near overflow in practice — the saturating
        // mul is defense in depth.
        let mut b = Backoff::new();
        for _ in 0..100 {
            b.bump();
        }
        assert_eq!(b.current(), BACKOFF_MAX);
    }
}
