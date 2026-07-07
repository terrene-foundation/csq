//! `csq daemon` — daemon lifecycle: start, stop, status, install,
//! uninstall.
//!
//! # Run modes
//!
//! The standalone daemon supports three ways to run, all implemented
//! in this file:
//!
//! 1. **Foreground** (`csq daemon start`) — `handle_start`. Blocks
//!    the calling terminal and dies on SIGHUP when that terminal
//!    closes. Interactive debugging only.
//! 2. **Detached** (`csq daemon start -d` / `--background`) —
//!    `handle_start_background`. Re-execs into a new process group
//!    with stdio routed to `/dev/null`. Survives terminal close;
//!    does NOT survive reboot and is not restarted on crash.
//! 3. **Service** (`csq daemon install`) — `handle_install` /
//!    `platform_install`. launchd on macOS (`RunAtLoad` +
//!    `KeepAlive`), systemd user unit on Linux. Survives terminal
//!    close, crash, and reboot — recommended for a long-lived host.
//!
//! # Subsystems
//!
//! A running daemon hosts a Unix-socket IPC/HTTP server, the token
//! refresher, per-surface usage pollers, and the auto-rotation loop.
//! All share one `CancellationToken` — on SIGTERM the daemon cancels,
//! every subsystem drains, and the PID file is removed via
//! `PidFile`'s `Drop` impl.
//!
//! # Not in scope here
//!
//! The Tauri-tray *in-process* daemon (the tray app hosting these
//! subsystems without a separate process) is M8.6 and lives in
//! `csq::desktop::daemon_supervisor`. Windows named-pipe IPC is
//! M8-03. Neither affects the three standalone run modes above —
//! standalone backgrounding (modes 2 and 3) is shipped.

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

            // PR-C4: clamp Codex invariants before any subsystem starts.
            // Pass 1 flips canonical credentials/codex-N.json to 0o400
            // (INV-P08); Pass 2 rewrites config-N/config.toml when its
            // `cli_auth_credentials_store = "file"` directive has drifted
            // (INV-P03). Both passes are surface-scoped to Codex and
            // mutex-coordinated with the refresher (INV-P09), so they're
            // safe to run before `spawn_refresher`.
            let _reconcile_summary = daemon::run_reconciler(&base_dir_for_runtime);

            // M3-7 + M4-5: Phase 4 fail-closed gate (an internal journal entry Delta F /
            // OQ #7; strengthened in M4-5). Refuse to start if the on-disk
            // store predates Phase 4 layout. Error's `Display` carries
            // operator-actionable next steps per `tauri-commands.md` MUST
            // Rule 6.
            if let Err(e) =
                csq_core::daemon::startup_reconciler::phase4_gate_check(&base_dir_for_runtime)
            {
                tracing::error!(
                    error_kind = "phase4_gate_refused",
                    "phase 4 gate refused daemon start: {e}"
                );
                return Err(anyhow::anyhow!("phase 4 gate refused start: {e}"));
            }

            // M05 — Audit-chain verification before IPC socket bind.
            //
            // Per spec 12 §12.13.5: verification NEVER blocks daemon startup.
            // Every outcome (clean, degraded, broken, timeout) maps to an
            // `AuditHealth` variant and the daemon ALWAYS proceeds to socket
            // bind so token-refresh and quota-polling are never taken offline
            // by an audit-chain integrity failure. Protection is achieved via:
            //
            //   (a) Loud logging: ERROR for Broken, WARN for Degraded.
            //   (b) Audit-subsystem fail-closed: anchor task and emit IPC
            //       route both check `audit_health.is_operational()` and skip
            //       / reject when the chain is not healthy.
            //   (c) Operator surfaces: `csq doctor` / `csq daemon status`
            //       expose `audit_health` so the broken state is visible.
            //
            // The prior posture (abort on fatal LedgerError) only protected
            // the client-detection window; it did not protect the on-disk chain
            // itself (a broken chain is already written) and it collaterally
            // took down refresh + polling — both unrelated to audit integrity.
            //
            // The verify step is wrapped in a `tokio::time::timeout` (default
            // 5s, configurable). On timeout: `AuditHealth::Unknown` with
            // reason "audit_verify_timeout" — audit subsystem fails closed.
            let audit_health: csq_core::audit::AuditHealth = {
                // FIX-5b: clamp timeout floor to 1s so CSQ_AUDIT_VERIFY_TIMEOUT_SECS=0
                // (or an unparseable value) cannot silently suppress verification.
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
                let base_for_verify = base_dir_for_runtime.clone();
                let verify_future = tokio::task::spawn_blocking(move || {
                    // M3 §10.5 (W2a): reconcile the born-canonical EATP attestation
                    // chain's own `.chain-broken` sentinel inside the SAME
                    // spawn_blocking so the startup timeout covers both chains. Side
                    // pass — the EATP chain does not gate daemon startup (the op-chain
                    // result below is the authority). Inert until the EATP chain
                    // exists (`verify_chain_in` returns Ok(default) for absent
                    // `eatp-runs/`).
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
                    // ── Clean: all records sig-verified ─────────────────────
                    Ok(Ok(Ok(summary))) if summary.historical_key_gaps.is_empty() => {
                        tracing::info!(
                            verified_count = summary.verified_count,
                            "audit chain verified clean; proceeding to socket bind"
                        );
                        csq_core::audit::AuditHealth::Verified
                    }

                    // ── Degraded: historical-key gaps (Option B) ─────────────
                    Ok(Ok(Ok(summary))) => {
                        for gap in &summary.historical_key_gaps {
                            tracing::warn!(
                                audit_verify_historical_key_gap = true,
                                key_id = gap.key_id.as_str(),
                                first_seq = gap.first_seq,
                                last_seq = gap.last_seq,
                                count = gap.count,
                                "audit chain: historical signing key absent from keychain — \
                                 signature verification degraded for this key's records; \
                                 chain-linking verified end-to-end"
                            );
                        }
                        tracing::warn!(
                            gap_count = summary.historical_key_gaps.len(),
                            "audit chain DEGRADED (historical-key gaps); proceeding to socket \
                             bind — audit subsystem remains operational"
                        );
                        csq_core::audit::AuditHealth::Degraded {
                            gaps: summary.historical_key_gaps,
                        }
                    }

                    // ── LedgerError: Broken (fatal) OR Unknown (transient) ────
                    // KeychainUnavailable (a transient keychain ACCESS error) maps
                    // to Unknown, NOT Broken — surface it as DEFERRED, not BROKEN,
                    // and do not fabricate an integrity-failure tag.
                    Ok(Ok(Err(ref e))) => {
                        let health = csq_core::audit::AuditHealth::from_ledger_error(e);
                        match &health {
                            csq_core::audit::AuditHealth::Unknown { reason } => {
                                tracing::error!(
                                    error_kind = reason.as_str(),
                                    "audit chain verify could not read the signing key \
                                     (keychain locked / access-denied) — audit subsystem \
                                     fail-closed this run; token-refresh and quota-polling \
                                     continue. Run `csq audit migrate-keys` to make the key \
                                     daemon-readable."
                                );
                                eprintln!(
                                    "csq daemon: AUDIT VERIFY DEFERRED — the signing key is \
present but the keychain could not be read (locked / access-denied). The chain is NOT \
broken. Token-refresh and quota-polling are unaffected; audit anchoring/emit are disabled \
this run. Run `csq audit migrate-keys` to make the key daemon-readable."
                                );
                            }
                            _ => {
                                let error_kind = if let csq_core::audit::AuditHealth::Broken {
                                    ref error_kind,
                                    ..
                                } = health
                                {
                                    error_kind.clone()
                                } else {
                                    "audit_chain_integrity_failure".to_string()
                                };
                                tracing::error!(
                                    error_kind = error_kind.as_str(),
                                    "audit chain BROKEN — audit subsystem will fail-closed; \
                                     token-refresh and quota-polling continue normally. \
                                     Run `csq audit verify --full` for diagnosis."
                                );
                                eprintln!(
                                    "csq daemon: AUDIT CHAIN BROKEN ({error_kind}). \
Token-refresh and quota-polling are unaffected. \
Audit anchoring and new audit-record emits are disabled until the chain is repaired. \
Run `csq audit verify --full` for diagnosis."
                                );
                            }
                        }
                        health
                    }

                    // ── Task panicked ────────────────────────────────────────
                    // FIX-5a: raise to ERROR + eprintln! — Unknown is as serious as Broken.
                    Ok(Err(join_err)) => {
                        tracing::error!(
                            error_kind = "audit_verify_task_panicked",
                            "audit verify task panicked: {join_err} — \
                             could not confirm chain soundness; audit subsystem will fail-closed; daemon proceeds"
                        );
                        eprintln!(
                            "csq daemon: AUDIT VERIFY TASK PANICKED. \
Could not confirm chain soundness. Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                        );
                        csq_core::audit::AuditHealth::Unknown {
                            reason: "audit_verify_task_panicked".to_string(),
                        }
                    }

                    // ── Timeout ───────────────────────────────────────────────
                    // FIX-5a: raise to ERROR + eprintln! — Unknown is as serious as Broken.
                    Err(_timeout) => {
                        tracing::error!(
                            error_kind = "audit_verify_timeout",
                            timeout_secs = timeout_secs,
                            "audit chain verify timed out after {timeout_secs}s — \
                             could not confirm chain soundness; audit subsystem will fail-closed; daemon proceeds"
                        );
                        eprintln!(
                            "csq daemon: AUDIT VERIFY TIMED OUT after {timeout_secs}s. \
Could not confirm chain soundness. Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                        );
                        csq_core::audit::AuditHealth::Unknown {
                            reason: "audit_verify_timeout".to_string(),
                        }
                    }
                };

                // FIX-1/FIX-2: set or clear the .chain-broken sentinel so
                // CLI-side writers (op_emit, rotate, anchor) are also gated.
                // FIX-2: Unknown (timeout/panic) leaves the sentinel UNCHANGED —
                // a transient verify failure must not produce a durable write-lockout.
                // Only Broken (a real LedgerError) sets the sentinel.
                match &health {
                    csq_core::audit::AuditHealth::Verified
                    | csq_core::audit::AuditHealth::Degraded { .. } => {
                        csq_core::audit::clear_chain_broken(&base_dir_for_runtime);
                    }
                    csq_core::audit::AuditHealth::Broken { error_kind, .. } => {
                        csq_core::audit::set_chain_broken(&base_dir_for_runtime, error_kind);
                    }
                    csq_core::audit::AuditHealth::Unknown { .. } => {
                        // Transient condition — do not set a durable sentinel.
                        // The in-RAM audit_health still gates daemon emit/anchor.
                    }
                }

                health
            };

            let router_state = daemon::server::RouterState {
                cache: Arc::clone(&refresh_cache),
                discovery_cache: Arc::clone(&discovery_cache),
                base_dir: Arc::new(base_dir_for_runtime.clone()),
                oauth_store: Some(Arc::clone(&oauth_store)),
                gemini_consumer: gemini_consumer.clone(),
                audit_health: audit_health.clone(),
                // #783 — seed the interactive enforcement registry from the
                // fail-closed §10.5 activation gate (absent → empty/503).
                // #784 follow-up — inject the cross-SDK kailash projector (the
                // csq crate owns the seam; csq-core cannot name it).
                // T-M4.3 — inject the PACT governor factory so a configured
                // operating envelope wires the first production ActionGovernor
                // (fail-closed: a present-but-unloadable envelope refuses to open).
                #[cfg(feature = "enterprise")]
                interactive: Arc::new({
                    let reg = daemon::interactive_live::seed_registry(
                        &base_dir_for_runtime,
                        Some(crate::kailash_projector::make_kailash_projector()),
                        Some(crate::kailash_governor::make_governor_factory()),
                        // T-M4.5 — inject the lifecycle-audit-sink factory so every
                        // session records a signed Delegate-lifecycle audit trail.
                        Some(crate::kailash_audit_sink::make_audit_sink_factory()),
                    );
                    // M3 §10.5 W2b — inject the EATP born-canonical genesis guard.
                    // Classifies the genesis record on every session open; non-BornCanonical
                    // refuses EATP chain appends but the session still proceeds.
                    // M3 §10.5 W3 — inject the EATP session-close attestation writer.
                    // Appends a born-canonical session-close attestation on every
                    // close (fail-closed-NON-FATAL — never blocks teardown).
                    reg.with_eatp_genesis_guard(
                        crate::kailash_eatp_genesis::make_eatp_genesis_guard(
                            &base_dir_for_runtime,
                        ),
                    )
                    .with_eatp_attestor(
                        crate::kailash_eatp_attest::make_eatp_session_close_attestor(
                            &base_dir_for_runtime,
                        ),
                    )
                }),
            };

            // ── M19: Emit capture-matrix record (sidecar dedup) ───────────────────
            // Emitted AFTER audit_health is finalised, BEFORE daemon::serve.
            // Skipped when the audit subsystem is not operational (Broken/Unknown),
            // or when the dedup key matches (stable chain_id + same content across
            // restarts). A chain re-genesis changes chain_id → forces a re-emit even
            // when the surface content is identical (Finding C fix).
            // Non-fatal: a failure here logs WARN and continues; the daemon is not
            // blocked.
            //
            // Sidecar advance rule (Finding B fix):
            //   Ok(true)  → record written → advance sidecar.
            //   Ok(false) → chain-broken skip → do NOT advance sidecar; a recovered
            //               chain must re-emit on next startup.
            //   Err(..)   → hard failure → do NOT advance sidecar.
            if audit_health.is_operational() {
                match csq_core::audit::seam::build_capture_matrix(&base_dir_for_runtime) {
                    Ok(payload) => {
                        let content_hash =
                            csq_core::audit::seam::matrix_content_hash(&payload);
                        use csq_core::audit::op_emit::load_chain_id;
                        let chain_id = load_chain_id(&base_dir_for_runtime);
                        let dedup_key = csq_core::audit::seam::sidecar_dedup_key(
                            &chain_id,
                            &content_hash,
                        );
                        let last_key =
                            csq_core::audit::seam::read_last_hash(&base_dir_for_runtime);
                        if last_key.as_deref() != Some(dedup_key.as_str()) {
                            // Matrix changed or chain re-genesised — emit chain record.
                            match csq_core::audit::seam::emit_matrix_record(
                                &base_dir_for_runtime,
                                &chain_id,
                                payload,
                            ) {
                                Ok(true) => {
                                    // Record written — advance sidecar so next restart deduplicates.
                                    if let Err(e) = csq_core::audit::seam::write_last_hash(
                                        &base_dir_for_runtime,
                                        &dedup_key,
                                    ) {
                                        tracing::warn!(
                                            error_kind = "capture_matrix_sidecar_write_failed",
                                            "M19: could not update .last-capture-matrix sidecar: {e}"
                                        );
                                    }
                                }
                                Ok(false) => {
                                    // Chain-broken skip — sidecar NOT advanced so a recovered
                                    // chain re-emits the matrix on next daemon start.
                                    tracing::warn!(
                                        error_kind = "capture_matrix_skipped_no_sidecar_advance",
                                        "M19: capture-matrix emit skipped (chain-broken); \
                                         sidecar NOT advanced — recovered chain will re-emit"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error_kind = "capture_matrix_emit_failed",
                                        "M19: capture-matrix chain record emit failed (non-fatal): {e}"
                                    );
                                }
                            }
                        } else {
                            tracing::debug!(
                                "M19: capture matrix unchanged (dedup key stable); skipping re-emit"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error_kind = "capture_matrix_build_failed",
                            "M19: could not build capture matrix (non-fatal): {e}"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    "M19: capture matrix emit skipped — audit subsystem not operational"
                );
            }

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
                    // then removes the orphan. See an internal journal entry
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

                    // Start the parse-cache sweeper (PR-CA9b / T20). Reads
                    // ~/.csq/coc-roots-seen.jsonl and GCs stale
                    // <root>/.cache/parsed-<lock_sha>.bin files older than
                    // 30 days OR whose lock_sha no longer matches the
                    // root's current COC.lock digest. R2/B59 budget: 30s
                    // wall-clock per tick; partial sweeps resume on the
                    // next tick.
                    let roots_seen_path = base_dir_for_runtime.join("coc-roots-seen.jsonl");
                    let coc_cache_sweeper =
                        daemon::spawn_coc_cache_sweeper(roots_seen_path, shutdown.clone());

                    // M14 — external anchoring task. Reads `audit-sink.json`;
                    // no-op when sink == "none" (default). When a sink is
                    // configured, periodically anchors the chain HEAD to the
                    // external witness and fires immediately on high-impact ops
                    // (KeyRotate, IdentityMint, ReleaseAuth) via head-kind detection.
                    //
                    // Audit-subsystem fail-closed: when `audit_health` is Broken
                    // or Unknown the anchor task is NOT started. Appending new
                    // anchor records to a broken chain is pointless and potentially
                    // misleading. Logs a WARN so the operator can see why anchoring
                    // is inactive. The operator repairs the chain (csq audit verify
                    // --full) and restarts the daemon to resume anchoring.
                    let anchor_handle = if !audit_health.is_operational() {
                        tracing::warn!(
                            error_kind = "audit_anchor_skipped_broken_chain",
                            "audit anchor task NOT started — chain is not operational \
                             (audit_health={:?}). Restart daemon after repairing the chain.",
                            audit_health
                        );
                        None
                    } else {
                        let sink_cfg =
                            csq_core::audit::AuditSinkConfig::load(&base_dir_for_runtime)
                                .unwrap_or_default();
                        let sink: Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> =
                            resolve_anchor_sink(&sink_cfg);
                        sink.and_then(|s| {
                            daemon::spawn_anchor_task(
                                base_dir_for_runtime.clone(),
                                sink_cfg,
                                s,
                                shutdown.clone(),
                            )
                        })
                    };

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

                    // Await the parse-cache sweeper with a 5s deadline.
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        coc_cache_sweeper.join,
                    )
                    .await
                    {
                        Ok(Ok(())) => tracing::info!("coc-cache sweeper stopped cleanly"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "coc-cache sweeper panicked"),
                        Err(_) => tracing::warn!("coc-cache sweeper did not stop within 5s"),
                    }

                    // Await the M14 anchor task with a 5s deadline (if active).
                    if let Some(handle) = anchor_handle {
                        match tokio::time::timeout(std::time::Duration::from_secs(5), handle.join)
                            .await
                        {
                            Ok(Ok(())) => tracing::info!("anchor task stopped cleanly"),
                            Ok(Err(e)) => tracing::warn!(error = %e, "anchor task panicked"),
                            Err(_) => tracing::warn!("anchor task did not stop within 5s"),
                        }
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

/// Resolves the active `LedgerSink` from `sink_cfg`.
///
/// Returns `None` when:
/// - `sink_cfg.sink == "none"` (no external sink configured).
/// - The requested sink was not compiled into this binary (no matching feature flag).
///
/// Compiled-in sinks (activated by their respective `--features` flag):
/// - `"rekor"` → `csq_core::audit::impls::sinks::rekor::RekorSink` (feature `rekor-sink`).
///   **Note:** the M07 ship uses an in-memory mock substrate; a real Sigstore
///   Rekor HTTP client is a documented follow-up. A WARN log marks this so
///   operators are never silently misled into treating the mock as a durable witness.
/// - `"csq-ledger"` → `csq_core::audit::impls::csq_ledger_sink::CsqLedgerSink`
///   (feature `csq-ledger-sink`). `reqwest`-backed; connects to `audit-sink.json`
///   default URL `http://127.0.0.1:8080` unless the operator overrides.
fn resolve_anchor_sink(
    sink_cfg: &csq_core::audit::AuditSinkConfig,
) -> Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> {
    match sink_cfg.sink.as_str() {
        "none" => None,

        #[cfg(feature = "rekor-sink")]
        "rekor" => {
            match csq_core::audit::impls::sinks::rekor::RekorSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL: the M07 RekorSink uses an in-memory mock substrate
                    // (non-persistent across restarts) until a real Sigstore Rekor HTTP
                    // client replaces RekorBackend. Operators MUST NOT treat this as a
                    // durable external witness until the live HTTP client lands.
                    tracing::warn!(
                        event = "anchor_sink_mock_backend",
                        sink = "rekor",
                        "rekor sink uses the in-memory M07 substrate (non-persistent); \
                         real Sigstore Rekor HTTP client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    tracing::warn!(
                        event = "anchor_sink_init_failed",
                        sink = "rekor",
                        error = %e,
                        "rekor sink initialisation failed — anchor task not started"
                    );
                    None
                }
            }
        }

        #[cfg(feature = "csq-ledger-sink")]
        "csq-ledger" => {
            match csq_core::audit::impls::csq_ledger_sink::CsqLedgerSink::with_defaults() {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    tracing::warn!(
                        event = "anchor_sink_init_failed",
                        sink = "csq-ledger",
                        error = %e,
                        "csq-ledger sink initialisation failed — anchor task not started"
                    );
                    None
                }
            }
        }

        other => {
            tracing::warn!(
                event = "anchor_sink_not_compiled",
                sink = other,
                "sink '{}' is configured but not compiled into this binary; \
                 rebuild with --features csq/{}-sink to activate",
                other,
                other,
            );
            None
        }
    }
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
Description=Code Squad Q Daemon

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
                unit.contains("Description=Code Squad Q Daemon"),
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

    // ── B2: resolve_anchor_sink maps config to sink ───────────────────────────

    /// B2 regression: `resolve_anchor_sink` MUST return `None` for `sink = "none"`,
    /// MUST return `None` (with a warn log) for any named sink whose feature flag
    /// is NOT active, and MUST return `Some` whose `name()` matches when the
    /// feature IS active.
    ///
    /// Default-build sub-test: no sink features compiled → "rekor" and
    /// "csq-ledger" both produce `None` + warn.
    ///
    /// Feature-gated sub-tests (`#[cfg(feature = "...")]`): prove that when the
    /// feature is on, the resolver returns a `Some(sink)` with the correct name —
    /// closing the B2 "dead code" gap in the original stub.
    #[test]
    fn resolve_anchor_sink_maps_config_to_sink() {
        use csq_core::audit::AuditSinkConfig;

        // ── Default-build sub-tests (no sink features active) ─────────────────

        // Arrange — "none" config (the default).
        let none_cfg = AuditSinkConfig::default();
        assert_eq!(none_cfg.sink, "none");

        // Act + Assert — "none" must produce None (no task to spawn).
        let result_none = resolve_anchor_sink(&none_cfg);
        assert!(
            result_none.is_none(),
            "sink=\"none\" must resolve to None (no anchor task)"
        );

        // Arrange — unknown/unsupported sink name.
        let unknown_cfg = AuditSinkConfig {
            sink: "unknown-sink-xyz".to_string(),
            ..Default::default()
        };

        // Act + Assert — unknown sink must produce None (not panic).
        let result_unknown = resolve_anchor_sink(&unknown_cfg);
        assert!(
            result_unknown.is_none(),
            "unknown sink name must resolve to None (not compiled)"
        );

        // When neither rekor-sink NOR csq-ledger-sink is compiled, named
        // sinks fall through to the `other` arm and return None.
        #[cfg(not(feature = "rekor-sink"))]
        {
            let rekor_cfg = AuditSinkConfig {
                sink: "rekor".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&rekor_cfg);
            assert!(
                result.is_none(),
                "sink=\"rekor\" must be None when rekor-sink feature is not compiled"
            );
        }

        #[cfg(not(feature = "csq-ledger-sink"))]
        {
            let ledger_cfg = AuditSinkConfig {
                sink: "csq-ledger".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&ledger_cfg);
            assert!(
                result.is_none(),
                "sink=\"csq-ledger\" must be None when csq-ledger-sink feature is not compiled"
            );
        }

        // ── Feature-gated sub-tests (prove Some-under-feature) ────────────────

        // When rekor-sink IS compiled, "rekor" must resolve to Some whose name()=="rekor".
        #[cfg(feature = "rekor-sink")]
        {
            let rekor_cfg = AuditSinkConfig {
                sink: "rekor".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&rekor_cfg);
            assert!(
                result.is_some(),
                "sink=\"rekor\" must resolve to Some when rekor-sink feature is compiled"
            );
            assert_eq!(
                result.unwrap().name(),
                "rekor",
                "resolved rekor sink must report name()==\"rekor\""
            );
        }

        // When csq-ledger-sink IS compiled, "csq-ledger" must resolve to Some
        // whose name()=="csq-ledger".
        #[cfg(feature = "csq-ledger-sink")]
        {
            let ledger_cfg = AuditSinkConfig {
                sink: "csq-ledger".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&ledger_cfg);
            assert!(
                result.is_some(),
                "sink=\"csq-ledger\" must resolve to Some when csq-ledger-sink feature is compiled"
            );
            assert_eq!(
                result.unwrap().name(),
                "csq-ledger",
                "resolved csq-ledger sink must report name()==\"csq-ledger\""
            );
        }
    }
}
