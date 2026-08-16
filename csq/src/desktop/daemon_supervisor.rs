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
//!
//! `csq daemon stop` reaches this same token from OUTSIDE the process,
//! via a platform-specific bridge installed once in [`supervisor_loop`]:
//! a named shutdown event on Windows, a real `SIGTERM` handler on Unix
//! (an internal ticket — without it, the OS default disposition for an
//! unhandled `SIGTERM` would terminate the whole app). A stop-requested
//! sentinel (`csq_core::daemon::stop_sentinel`) additionally prevents the
//! supervisor loop from silently re-acquiring the daemon afterwards.

use csq_core::daemon;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// Imports for run_daemon (server, refresher subsystems). Cross-platform
// as of an internal ticket — the Windows supervisor now runs the same subsystems over a
// named pipe instead of a Unix socket.
use csq_core::accounts::AccountInfo;
use csq_core::daemon::{
    server as daemon_server, HttpGetFn, HttpPostFn, HttpPostFnCodex, HttpPostProbeFn, TtlCache,
};
use csq_core::http;
use csq_core::oauth::OAuthStateStore;
use std::sync::Arc;

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
    // an internal ticket: reopening the desktop app is itself an explicit "start"
    // intent — clear any stop-requested sentinel left by a prior `csq
    // daemon stop` (or a crash that left it set) so this launch is never
    // silently refused. Cheap and best-effort; see `stop_sentinel` doc.
    daemon::clear_stop_requested(&base_dir);

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tauri::async_runtime::spawn(async move {
        supervisor_loop(base_dir, shutdown_clone).await;
    });

    SupervisorHandle { shutdown }
}

/// Supervisor main loop. Delegates to the shared
/// [`csq_core::daemon::supervise::run_forever`] loop, passing the
/// desktop [`run_daemon`] as the per-session body. The detect/acquire/
/// backoff/cohabitation machinery lives in csq-core so the standalone
/// `csq daemon start --supervised` daemon and this in-process supervisor
/// share exactly one implementation (daemon-auth-resilience Wave B).
///
/// an internal ticket — the Windows named-pipe daemon is wired end to end
/// (`run_daemon` binds `daemon::serve_windows` + the same subsystems as
/// Unix), so the detect/acquire/run loop is identical across platforms;
/// only `run_daemon`'s transport bind differs.
async fn supervisor_loop(base_dir: PathBuf, cancel: CancellationToken) {
    // Windows: the desktop app is the PRIMARY daemon host with no per-process
    // SIGTERM, so `csq daemon stop` fires a named event. Bridge it into the
    // top-level `cancel` ONCE for the whole supervisor lifetime — NOT per
    // session. A per-session bridge (inside `run_daemon`) would spawn a fresh
    // `wait_blocking` thread on every subsystem-death restart (an internal ticket) while the
    // prior one orphans (dropping its handle detaches, never aborts, the
    // blocking task), leaking a blocking-pool thread per restart under a
    // death-restart storm (an internal ticket redteam MED-1). This mirrors the CLI
    // supervised path, which spawns its SIGTERM bridge once outside
    // `run_forever` (`handle_start_supervised`). Unix gets the structurally
    // identical bridge below, for the mirror-image reason: unlike Windows,
    // Unix DOES deliver a real SIGTERM to this process (`csq daemon stop` →
    // `kill(pid, SIGTERM)`, `csq-core/src/daemon/lifecycle.rs::stop_daemon`)
    // whenever this app's PID happens to be the PidFile owner — and with no
    // handler installed, the OS default disposition would terminate the
    // WHOLE desktop app, not just the daemon session.
    #[cfg(windows)]
    match csq_core::daemon::create_shutdown_event() {
        Ok(event) => {
            let stop = cancel.clone();
            tokio::task::spawn_blocking(move || {
                event.wait_blocking();
                log::info!("in-process daemon stopping (csq daemon stop)");
                stop.cancel();
            });
        }
        Err(e) => {
            log::warn!(
                "could not create Windows shutdown event ({e}); \
                 `csq daemon stop` will not signal the desktop daemon"
            );
        }
    }

    // Unix (an internal ticket follow-up): install a SIGTERM handler ONCE, same
    // lifetime and same leaked-task rationale as the Windows arm above.
    // Cancels the SAME `cancel` token so both platforms share identical
    // semantics from here down. Never `.expect()`s — this runs inside an
    // already-live GUI app, unlike the CLI's `wait_for_shutdown` (which can
    // afford to panic at process startup); a registration failure is
    // logged and the app keeps running, just without a Unix `csq daemon
    // stop` bridge.
    //
    // Composition with the stop-requested sentinel (`stop_sentinel.rs`):
    // this bridge stops THIS app session's in-process daemon when SIGTERM
    // actually reaches it (i.e. this app's PID was the PidFile owner). The
    // sentinel, checked inside `run_forever` on every iteration, is the
    // OTHER half — it stops the loop from re-acquiring afterwards, and
    // also covers the case where SIGTERM went to some OTHER owner (e.g.
    // the standalone `--supervised` daemon) while this app's loop was
    // merely backing off. Both are needed; neither alone makes `csq
    // daemon stop` true for every cohabitation ordering.
    #[cfg(unix)]
    install_unix_sigterm_bridge(cancel.clone());

    daemon::supervise::run_forever(base_dir, cancel, |base, session_cancel| async move {
        run_daemon(&base, session_cancel).await
    })
    .await;
}

/// Installs a one-shot SIGTERM→cancel bridge for the process's lifetime.
///
/// Split out of [`supervisor_loop`] so it is independently testable: a
/// real signal cannot be raised against a `#[cfg(windows)]` shutdown
/// event, but it CAN be raised against this function directly — see the
/// `unix_sigterm_bridge_cancels_the_token` test below, which sends a
/// genuine `SIGTERM` to the current process and asserts `cancel` fires.
///
/// Returns immediately after spawning the listener task; never blocks,
/// never panics. A registration failure (an exceptional kernel
/// condition — see [`tokio::signal::unix::signal`]'s own error docs) is
/// logged and swallowed: this runs inside an already-live GUI app, so
/// `.expect()`-ing here would crash a running app over a missing
/// SIGTERM bridge, which is strictly worse than the bridge just not
/// existing.
#[cfg(unix)]
fn install_unix_sigterm_bridge(cancel: CancellationToken) {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::spawn(async move {
                term.recv().await;
                log::info!("in-process daemon stopping (SIGTERM / csq daemon stop)");
                cancel.cancel();
            });
        }
        Err(e) => {
            log::warn!(
                "could not install SIGTERM handler ({e}); `csq daemon stop` will not \
                 signal the desktop daemon when this app's PID owns the PidFile"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod sigterm_bridge_tests {
    use super::install_unix_sigterm_bridge;
    use tokio_util::sync::CancellationToken;

    /// Non-vacuity + correctness proof for an internal ticket's Unix half: a
    /// REAL `SIGTERM` raised against the current process reaches the
    /// bridged token, exercising the exact signal `csq daemon stop`
    /// sends (`csq-core/src/daemon/lifecycle.rs::stop_daemon` →
    /// `kill(pid, SIGTERM)`) when this app's PID is the PidFile owner.
    ///
    /// # Why raising a real SIGTERM at the whole test-binary process is
    /// safe here
    ///
    /// `tokio::signal::unix::signal` registers with the process-wide
    /// `signal-hook-registry`, which OVERRIDES the OS default
    /// disposition (process termination) for `SIGTERM` for the
    /// remainder of the process once ANY listener has been registered.
    /// So once `install_unix_sigterm_bridge` returns `Ok`, self-raising
    /// `SIGTERM` cannot terminate the test binary — it can only reach
    /// registered listeners, which is exactly the behavior under test.
    /// `yield_now` gives the listener's registration (synchronous,
    /// inside `signal()` itself, before any task runs) a scheduling
    /// point to complete before the raise — a scheduling nicety, not a
    /// correctness requirement, since the syscall itself is synchronous.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unix_sigterm_bridge_cancels_the_token() {
        let cancel = CancellationToken::new();
        install_unix_sigterm_bridge(cancel.clone());
        tokio::task::yield_now().await;

        // SAFETY: raises SIGTERM against our OWN pid only. See the
        // doc comment above for why this cannot terminate the process.
        unsafe {
            libc::kill(std::process::id() as libc::pid_t, libc::SIGTERM);
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), cancel.cancelled())
            .await
            .expect("a real SIGTERM must cancel the bridged token within 5s");
    }
}

/// One full run of the in-process daemon: bind socket, spawn
/// subsystems, await cancellation, drain cleanly.
///
/// Mirrors the CLI `csq daemon start` startup sequence in
/// `csq-cli/src/commands/daemon.rs` so the subsystem composition
/// stays in exactly one shape — refresher + usage poller +
/// auto-rotate + server, all sharing a single shutdown token.
///
/// Cross-platform as of an internal ticket: the whole body is shared; only the
/// transport bind (`daemon::serve` Unix socket vs `daemon::serve_windows`
/// named pipe) is `#[cfg]`-gated. `daemon::socket_path` already resolves
/// to the named-pipe path on Windows.
async fn run_daemon(
    base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
) -> Result<(), String> {
    // Enterprise license gate for the desktop daemon-hosted enterprise stack (task #77
    // shard 3) — twin of the CLI `handle_start` gate. STARTUP variant (no liveness deny)
    // so a licensed-but-offline-beyond-grace customer can still bring the daemon up to
    // recover their CRL (the full per-op `enforce` would be a fail-closed deadlock).
    // Inert while the placeholder key is baked; community builds carry no gate.
    #[cfg(feature = "enterprise")]
    if let Err(e) = crate::cli::enforce_enterprise_license_startup(base_dir) {
        return Err(format!("enterprise license gate refused daemon start: {e}"));
    }

    let sock_path = daemon::socket_path(base_dir);

    // Local shutdown token — a CHILD of outer_cancel (not a clone). The
    // server gets its own internal token (created by `serve`). When
    // `outer_cancel` fires (app quit / supervisor stop), this child cancels
    // too and every subsystem drains. When a subsystem dies mid-session
    // (an internal ticket), the drain path cancels THIS child to wind the siblings down
    // WITHOUT firing `outer_cancel` — so `run_forever` restarts the session
    // rather than treating it as an intentional stop.
    let shutdown = outer_cancel.child_token();

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
    // an internal ticket — resolve the active transparency-log sink ONCE (twin of the CLI
    // daemon path) so both the anchor HTTP handler (RouterState.anchor_sink) and
    // the cadence drain task below share the same Arc + config. `None` in the
    // default local-only build → handler surfaces `inclusion_proof: null`.
    let anchor_sink_cfg_desktop =
        csq_core::audit::AuditSinkConfig::load(base_dir).unwrap_or_default();
    let anchor_sink_desktop: Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> =
        resolve_anchor_sink_desktop(&anchor_sink_cfg_desktop);
    let router_state = daemon_server::RouterState {
        cache: Arc::clone(&refresh_cache),
        discovery_cache: Arc::clone(&discovery_cache),
        base_dir: Arc::new(base_dir.to_path_buf()),
        oauth_store: Some(Arc::clone(&oauth_store)),
        gemini_consumer: gemini_consumer.clone(),
        audit_health,
        anchor_sink: anchor_sink_desktop.clone(),
        // an internal ticket — seed the interactive enforcement registry from the fail-closed
        // §10.5 activation gate (absent → empty/503).
        // an internal ticket follow-up — inject the cross-SDK kailash projector (the csq crate
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
        // Log before returning, mirroring the CLI twin: the desktop app has no
        // attached console, so the rolling daemon log is the ONLY place an
        // operator can see why the in-process daemon refused to start.
        //
        // `tracing::`, NOT `log::` — the rolling daemon log is fed by the
        // tracing subscriber's file layer, installed via `set_global_default`
        // with no `LogTracer` bridge, so `log::` records go to tauri-plugin-log
        // (stdout / app log dir / webview) and never reach the file this
        // comment is about. Same `error_kind` tag as the CLI twin.
        tracing::error!(
            error_kind = "phase4_gate_refused",
            "phase 4 gate refused start (desktop daemon): {e}"
        );
        return Err(format!("phase 4 gate refused start: {e}"));
    }

    // ── M19: Emit capture-matrix record (sidecar dedup) ──────────────────────
    // Emitted AFTER audit_health is finalised, BEFORE the transport binds —
    // same contract as the CLI twin, via the one shared orchestrator. Before
    // this call existed the desktop in-process daemon never emitted a matrix
    // record at all, so a desktop-only user's chain held ZERO
    // `ProvenanceCaptureMatrix` records forever.
    csq_core::audit::seam::emit_startup_capture_matrix(
        base_dir,
        audit_health_for_anchor.is_operational(),
    );

    // Bind the transport. Unix binds a domain socket; Windows binds a
    // named pipe. Both return a handle with `.shutdown()` + a
    // `JoinHandle<()>`, so the drain tail below is shared (an internal ticket).
    #[cfg(unix)]
    let (server, server_join) = daemon::serve(&sock_path, router_state)
        .await
        .map_err(|e| format!("socket bind failed: {e}"))?;
    #[cfg(windows)]
    let (server, server_join) = daemon::serve_windows(&sock_path.to_string_lossy(), router_state)
        .await
        .map_err(|e| format!("named-pipe bind failed: {e}"))?;
    log::info!("in-process daemon IPC bound at {}", sock_path.display());

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
    // License CRL refresher (task #77 shard 2) — twin of the CLI daemon spawn. Keeps the
    // signed revocation list fresh for the enterprise license gate. Enterprise-only; inert
    // while the placeholder key is baked.
    #[cfg(feature = "enterprise")]
    let crl_refresher = daemon::spawn_crl_refresher(base_dir.to_path_buf(), shutdown.clone());
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
    // settings.json after each handle dir repoint. Uses the SAME resolver as
    // the CLI twin (`$CLAUDE_HOME` override, else `~/.claude`) — a bare
    // `dirs::home_dir().join(".claude")` here silently ignored the operator's
    // `$CLAUDE_HOME` and pointed the rotator at the wrong tree. None → no-op.
    let claude_home_for_rotate = crate::cli::commands::claude_home().ok();
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
    // like base_dir/image-cache/ that CC will never find. Same `$CLAUDE_HOME`-
    // aware resolver as the CLI twin.
    let claude_home_for_sweep = crate::cli::commands::claude_home().ok();
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
    // Same `$CLAUDE_HOME`-aware resolver as the CLI twin; None → writer no-op.
    let claude_home_for_ledger = crate::cli::commands::claude_home().ok();
    let usage_ledger_writer = daemon::spawn_usage_ledger_writer(
        base_dir.to_path_buf(),
        claude_home_for_ledger,
        shutdown.clone(),
        chrono::Utc::now,
    );

    // Parse-cache sweeper (PR-CA9b / T20) — twin of the CLI daemon's spawn.
    // Reads `<base_dir>/coc-roots-seen.jsonl` and GCs stale
    // `<root>/.cache/parsed-<lock_sha>.bin` files older than 30 days OR whose
    // lock_sha no longer matches the root's current COC.lock digest.
    //
    // The desktop in-process daemon previously omitted this entirely, so a
    // user whose ONLY daemon host is the desktop app never GC'd a single parse
    // cache and `csq doctor --json::cache_sweeper` reported `never_run`
    // forever. The two daemons are mutually exclusive (one PidFile), so the
    // omission meant no sweep at all — not a sweep performed elsewhere.
    // Roots path comes from the SHARED resolver that `csq run`'s
    // `record_root_seen` writer also uses; the state snapshot stays under
    // base_dir, where `csq doctor` reads it.
    let coc_cache_sweeper = daemon::spawn_coc_cache_sweeper(
        csq_core::daemon::coc_cache_sweeper::roots_seen_path_or_inert(base_dir),
        base_dir.to_path_buf(),
        shutdown.clone(),
    );

    // Daemon rolling-log GC (#1a-2, daemon-auth-resilience Wave A2) — twin
    // of the CLI daemon's spawn. 14-day retention sweep over the persistent
    // rolling file log this in-process daemon writes via
    // `init_logging_subscriber`'s rolling-file layer (`crate::daemon_log`).
    let log_gc = csq_core::daemon::log_gc::spawn(base_dir.to_path_buf(), shutdown.clone());

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
        // an internal ticket — reuse the sink + config resolved once above for
        // RouterState.anchor_sink (no second config read / resolve).
        anchor_sink_desktop.and_then(|s| {
            daemon::spawn_anchor_task(
                base_dir.to_path_buf(),
                anchor_sink_cfg_desktop,
                s,
                shutdown.clone(),
            )
        })
    } else {
        log::info!(
            "audit chain not operational — anchor task not spawned (desktop daemon startup)"
        );
        None
    };

    // Collect every long-lived subsystem into a uniform set (label +
    // JoinHandle<()>) so the session can watch them for premature exit
    // (an internal ticket — the mass-expiry failure shape one level down) AND drain them
    // with one loop.
    //
    // CONTRACT (an internal ticket redteam LOW-1): every member here MUST run until
    // `shutdown` fires. `await_session_stop` treats ANY return from a member
    // — clean `Ok(())` or panic — as a fault that restarts the whole session.
    // A subsystem that returns early on a benign "nothing to do" condition
    // would trigger a restart storm; such a subsystem must instead idle-loop
    // on `shutdown` (see `auto_rotate::run_loop`), not return.
    //
    // `ipc_server` is the one member that exits on its OWN internal token
    // (fired by `server.shutdown()` during teardown below), NOT the shared
    // `shutdown` — but it still never returns during normal operation, so its
    // premature exit (a panicked accept loop) is a genuine fault worth a
    // restart (an internal ticket): a dead IPC server silently breaks login / status /
    // provision while the refresher keeps going.
    let mut subsystems: Vec<daemon::supervise::Subsystem> = vec![
        ("refresher", refresher.join),
        ("usage_poller", usage_poller.join),
        ("gemini_midnight", gemini_midnight),
        ("auto_rotator", auto_rotator.join),
        ("handle_dir_sweep", sweep.join),
        ("coc_cache_sweeper", coc_cache_sweeper.join),
        ("usage_ledger_writer", usage_ledger_writer.join),
        ("daemon_log_gc", log_gc),
        ("ipc_server", server_join),
    ];
    #[cfg(feature = "enterprise")]
    subsystems.push(("license_crl_refresher", crl_refresher.join));
    if let Some(handle) = anchor_handle {
        subsystems.push(("audit_anchor", handle.join));
    }

    // Block until a graceful stop (`outer_cancel` fires from the app
    // lifecycle / stop event) OR a subsystem dies mid-session (an internal ticket). On
    // Windows the `csq daemon stop` named event is bridged into the top-level
    // cancel token ONCE in `supervisor_loop` (a per-session bridge here would
    // leak a `wait_blocking` thread per restart — an internal ticket redteam MED-1), and
    // `outer_cancel` is a clone of that token (`run_forever` passes
    // `cancel.clone()` per session), so a stop event resolves this wait on
    // every platform. The
    // subsystems share `shutdown` (a child of `outer_cancel`), so on a
    // graceful stop they are already winding down.
    let stop = daemon::supervise::await_session_stop(&outer_cancel, &mut subsystems).await;

    log::info!("in-process daemon stopping");
    server.shutdown();

    if let daemon::supervise::SessionStop::SubsystemExited(name) = &stop {
        // A subsystem died while the daemon was meant to be running. Fire the
        // CHILD `shutdown` token to drain the siblings WITHOUT cancelling
        // `outer_cancel` (so `run_forever` restarts rather than exits), then
        // return Err below.
        log::error!(
            "daemon subsystem '{name}' exited mid-session; draining siblings and restarting"
        );
        shutdown.cancel();
    }

    // Drain every remaining subsystem with a 5s per-handle deadline so one
    // stuck HTTP call can't wedge app shutdown (the dead one, if any, was
    // already removed by `await_session_stop`, so no handle is double-polled).
    // Includes `ipc_server` unless IT exited — `server.shutdown()` above fired
    // its accept loop's exit, so its handle completes here (no separate drain,
    // which would double-poll it — an internal ticket redteam hazard).
    daemon::supervise::drain_subsystems(subsystems, Duration::from_secs(5)).await;

    if let daemon::supervise::SessionStop::SubsystemExited(name) = stop {
        return Err(format!("daemon subsystem exited mid-session: {name}"));
    }

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

// The supervisor loop + backoff tests moved to
// `csq_core::daemon::supervise` alongside the extracted `run_forever`
// loop (daemon-auth-resilience Wave B). This module's remaining logic
// (`run_daemon`, `resolve_anchor_sink_desktop`) is exercised by the
// desktop self-test + live desktop verification (Wave C).
