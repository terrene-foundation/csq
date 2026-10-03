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
//! subsystems without a separate process) lives in
//! `csq::desktop::daemon_supervisor`. Both the standalone `csq daemon
//! start` here and the in-process supervisor now run over a Windows
//! named pipe (`daemon::serve_windows`) as well as a Unix socket, with a
//! per-user named-event graceful stop (an internal ticket).

use anyhow::{Context, Result};
use csq_core::daemon::{self, DaemonStatus, PidFile};
use csq_core::http;
use csq_core::oauth::OAuthStateStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Runs `csq daemon start` in the foreground.
///
/// Acquires the PID file (failing if another daemon is already
/// running), starts the Unix-socket HTTP server, installs signal
/// handlers, and blocks until SIGTERM/SIGINT. On return, the server
/// is stopped (socket removed) and the PID file is removed via
/// `PidFile`'s Drop impl.
pub fn handle_start(base_dir: &Path) -> Result<()> {
    // Background keychain work must never raise the unlock dialog, even when
    // this foreground daemon was started from a terminal.
    csq_core::credentials::keychain::declare_background_keychain_process();
    // an internal ticket: an explicit start always undoes a prior explicit stop —
    // clear FIRST, before anything else can observe the sentinel.
    daemon::clear_stop_requested(base_dir);

    // Say this BEFORE blocking in the foreground loop: once we block, the
    // operator is watching a running daemon and will not see a late warning.
    if let Some(warning) = unsupervised_start_advisory(launchd_job_is_loaded()) {
        eprint!("{warning}");
    }

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

    let rt = build_daemon_runtime()?;
    let base = base_dir.to_path_buf();
    rt.block_on(async move {
        // Foreground: bridge SIGTERM/SIGINT (Unix) / the named stop event
        // (Windows) into the session cancel token, then run ONE session.
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_for_signal = cancel.clone();
        tokio::spawn(async move {
            wait_for_shutdown().await;
            cancel_for_signal.cancel();
        });
        run_daemon_session(base, cancel)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    })?;

    // Explicit drop for clarity — PidFile::Drop removes the file if
    // it still contains our PID.
    drop(pid_file);
    eprintln!("csq daemon stopped cleanly");

    Ok(())
}

/// Runs `csq daemon start --supervised` — the launchd-managed background
/// daemon (daemon-auth-resilience Wave B).
///
/// Unlike [`handle_start`] (foreground, single run), this wraps the daemon
/// session in the shared supervisor loop
/// ([`csq_core::daemon::supervise::run_forever`]): it acquires the PidFile
/// per session, restarts the session in-process on a transient failure
/// (exponential backoff), and cohabits with an external daemon via the
/// PidFile guard. launchd's `KeepAlive={SuccessfulExit:false}` is the outer
/// layer — it respawns the whole process on a hard crash, while the
/// in-process loop handles transient session failures without a full
/// process restart.
///
/// This is the recurrence-prevention core for the mass-token-expiry
/// incident (an internal journal entry): the refresher now runs in a launchd-managed
/// process that survives the desktop app quitting or crashing, closing the
/// "no daemon running for 3.5 days" gap.
///
/// The hidden `--supervised` flag is set by the managed plist's
/// `ProgramArguments`; users still run `csq daemon start` (foreground) or
/// `-d` (background) directly.
pub fn handle_start_supervised(base_dir: &Path) -> Result<()> {
    csq_core::credentials::keychain::declare_background_keychain_process();
    // an internal ticket: this is also the path a reboot takes via launchd/systemd
    // `RunAtLoad` — the crash-recovery boundary for a stop-requested
    // sentinel left set by an unclean shutdown. Clear FIRST.
    daemon::clear_stop_requested(base_dir);

    // No PidFile acquire here — `run_forever` acquires it per session so it
    // can cohabit with (and take over from) an external daemon.
    eprintln!("csq daemon started (supervised mode)");
    eprintln!("  Base:   {}", base_dir.display());
    eprintln!("Send SIGTERM or Ctrl-C to stop.");

    let rt = build_daemon_runtime()?;
    let base = base_dir.to_path_buf();
    rt.block_on(async move {
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_for_signal = cancel.clone();
        tokio::spawn(async move {
            wait_for_shutdown().await;
            cancel_for_signal.cancel();
        });
        csq_core::daemon::supervise::run_forever(base, cancel, |b, c| async move {
            run_daemon_session(b, c).await
        })
        .await;
    });

    Ok(())
}

/// Builds the multi-threaded tokio runtime the daemon hosts run on. Two
/// worker threads so the accept loop and in-flight requests make progress
/// concurrently with signal handling.
fn build_daemon_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("csq-daemon")
        .build()
        .context("failed to build tokio runtime for daemon")
}

/// The `csq audit verify` startup step's per-record duration floor (ms),
/// measured on an UNLOADED host: `csq audit verify --full` verified an
/// 11,449-record chain in 2462ms (2026-09, exit 0, clean — "11449 v2
/// records verified, 0 v1 skipped"). 2462/11449 ≈ 0.215 ms/record. This is
/// a FLOOR standing in for typical throughput — NOT a bound
/// (`doc-property-claims.md` MUST-2) — and it EXCLUDES the EATP-chain
/// reconciliation the daemon startup path runs inside the SAME
/// `spawn_blocking` (`csq audit verify --full` does not touch the EATP
/// chain), so the daemon's real per-record cost is this number plus an
/// unmeasured EATP margin.
const AUDIT_VERIFY_MS_PER_RECORD_FLOOR: f64 = 0.215;

/// Margin applied to [`AUDIT_VERIFY_MS_PER_RECORD_FLOOR`] to size the
/// DEFAULT verify timeout. ~7x the measured unloaded floor.
///
/// The margin is INFERENCE, not a direct measurement of the loaded case
/// (`evidence-first-claims.md` MUST-4): the only two loaded data points on
/// THIS code path are "5s (the old fixed default) was insufficient under
/// host load ~100-190" and "30s (an operator override of
/// `CSQ_AUDIT_VERIFY_TIMEOUT_SECS`) was sufficient" — a coarse bracket,
/// not the tight healthy/dead pair `HEALTH_TIMEOUT` had. Absent a tight
/// bracket for this code path, the corroborating evidence is
/// `HEALTH_TIMEOUT`'s independently measured ~20x slowdown for a
/// near-zero-cost health read under a comparable load
/// (`csq-core/src/daemon/detect.rs`); 7x is deliberately SMALLER than
/// that because audit verify is CPU-bound crypto work, whose throughput
/// degrades under scheduling contention differently than an IO-wait
/// latency spike does — the two are not the same mechanism, so
/// borrowing the multiplier directly would overstate the case.
const AUDIT_VERIFY_LOAD_MARGIN: f64 = 7.0;

/// Absolute floor for the derived timeout — covers fixed per-run overhead
/// (process/tokio-task spin-up, the EATP-chain check) on a chain too
/// small for the per-record term to dominate. Equal to the ORIGINAL fixed
/// default, which was adequate for small/fresh chains; only a LARGE chain
/// under load exposed the insufficiency this constant no longer has to
/// cover alone.
const AUDIT_VERIFY_TIMEOUT_MIN_SECS: u64 = 5;

/// Absolute ceiling for the derived timeout, independent of how large an
/// operator sets `CSQ_AUDIT_VERIFY_LIMIT`. `csq daemon start` blocks on
/// this step before binding its IPC socket — spec 12 §12.13.5's "never
/// blocks daemon startup" governs the OUTCOME (every result maps to an
/// `AuditHealth` and startup proceeds), not how long the outcome takes to
/// arrive. An unbounded formula would let a large record-limit override
/// turn a genuinely broken chain into a multi-minute "is the daemon even
/// starting?" hang. An operator who needs longer than this for a real
/// (not-hung) verify at their configured limit can still set
/// `CSQ_AUDIT_VERIFY_TIMEOUT_SECS` explicitly — the explicit override
/// always takes full precedence over this formula.
const AUDIT_VERIFY_TIMEOUT_MAX_SECS: u64 = 60;

/// Bounded attempt count for [`spawn_audit_verify_retry`]'s background
/// retry after a startup `AuditHealth::Unknown` verdict.
///
/// UNRESOLVED-pending-measurement: no representative-host-load timing data
/// exists for how many attempts a transient overload needs to clear. The
/// one live incident that motivated this retry (a 40s startup timeout that
/// left the audit subsystem fail-closed for 2h08m, cleared only by a
/// restart) ran its host at load 165-256 for the ENTIRE window, so no
/// measurement taken from it can separate "the chain verify is slow" from
/// "the machine is saturated" (`instrument-discipline.md` MUST-1) — the
/// data this constant would ideally be derived from does not exist. `5` is
/// a conservative round number bounding worst-case retry duration and log
/// volume; it is NOT a measured pass/fail boundary the way
/// [`derive_audit_verify_timeout_secs`] is. Override via
/// `CSQ_AUDIT_VERIFY_RETRY_MAX_ATTEMPTS` without a rebuild once real
/// under-load timing data exists.
const AUDIT_VERIFY_RETRY_MAX_ATTEMPTS: u32 = 5;

/// Ceiling on the exponential backoff between retry attempts
/// ([`audit_verify_retry_backoff_secs`]).
///
/// Also UNRESOLVED-pending-measurement in the sense above — chosen only to
/// bound the worst case (attempt 5 would otherwise wait 16 * 2^4 = 256s at
/// the default timeout, which this constant does not even need to clamp
/// yet; it exists so a large `CSQ_AUDIT_VERIFY_LIMIT` override cannot turn
/// the backoff schedule into an hours-long wait between attempts).
const AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS: u64 = 600;

/// Backoff before retry attempt `attempt` (0-indexed), in seconds.
///
/// Derived, not fabricated: rather than guessing a wait time (the timing
/// data to derive one does not exist — see
/// [`AUDIT_VERIFY_RETRY_MAX_ATTEMPTS`]'s doc), the base is pinned to the
/// SAME already-justified quantity the verify attempt itself was budgeted
/// against: `verify_timeout_secs`, this run's
/// [`derive_audit_verify_timeout_secs`] output (or its explicit
/// `CSQ_AUDIT_VERIFY_TIMEOUT_SECS` override). A verify that just timed out
/// at its own budget is not worth re-running before at least that much
/// time has passed again, doubling on each subsequent attempt, clamped at
/// [`AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS`].
fn audit_verify_retry_backoff_secs(attempt: u32, verify_timeout_secs: u64) -> u64 {
    let shift = attempt.min(10); // guards the left-shift against overflow
    verify_timeout_secs
        .saturating_mul(1u64 << shift)
        .min(AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS)
}

/// Derives the DEFAULT audit-verify startup timeout from the CONFIGURED
/// `record_limit` — never from the actual (unknown-until-verified) chain
/// length, and never from a fixed constant alone.
///
/// # Why `record_limit` is the right lever, and why its OWN default (10,000) stays unchanged
///
/// `record_limit` is a hard CAP on the verifier's work (`VerifyConfig`,
/// `csq-core/src/audit/verify.rs`) — the verify task never processes more
/// than `record_limit` records regardless of how long the chain actually
/// is. Sizing the timeout off this cap, rather than off the specific
/// 11,449-record chain that motivated this change, keeps the
/// relationship correct as chains grow past whatever number happened to
/// be measured today.
///
/// `record_limit`'s own default (10,000) is left UNCHANGED here — it is a
/// separate, spec-anchored design decision ("spec 12 §12.13 — sufficient
/// for 30 days of daily csq use", `csq-core/src/audit/verify.rs`
/// `VerifyConfig::default`), not the cause of the timeout defect this
/// function fixes: the timeout was too tight FOR THAT SAME 10,000-record
/// cap under load, independent of whether 10,000 is the right number for
/// coverage. Changing a spec-anchored default belongs in its own change,
/// not folded into a timeout-sizing fix.
///
/// # Should a timeout (`AuditHealth::Unknown`) really disable the audit subsystem?
///
/// Considered and left AS-IS: `AuditHealth::Unknown` and `AuditHealth::Broken`
/// are reported as DISTINCT variants at every operator surface (daemon
/// log, `csq doctor`, `csq daemon status` — see `health.rs`'s per-arm
/// logging), so "could not verify" is never silently relabeled "verified
/// broken" — the three-way distinction `durable-instruments.md` MUST-2
/// requires is intact at the REPORTING layer. `is_operational()` folding
/// Unknown into the same "reject new writes" bucket as Broken is a
/// separate, narrower question — a WRITE-GATING decision on a
/// security-bearing path — and there the fail-closed answer is correct:
/// per `guard-reader-writer-parity.md` MUST-2, an unreadable/unclassifiable
/// guard input on a destructive or security-bearing path fails CLOSED, and
/// appending new signed records onto a chain of UNKNOWN integrity is
/// exactly that path.
///
/// # Derivation
///
/// `ceil(record_limit * AUDIT_VERIFY_MS_PER_RECORD_FLOOR *
/// AUDIT_VERIFY_LOAD_MARGIN / 1000)`, clamped to
/// `[AUDIT_VERIFY_TIMEOUT_MIN_SECS, AUDIT_VERIFY_TIMEOUT_MAX_SECS]`.
///
/// At the default `record_limit` of 10,000 this yields **16s**
/// (`ceil(10_000 * 0.215 * 7.0 / 1000) = ceil(15.05) = 16`) — just over 3x
/// the old fixed 5s default (which measurably failed under load on an
/// 11,449-record chain) and just over half the 30s an operator found
/// sufficient at a HIGHER `record_limit` override. That 30s data point
/// does not bound this function's correctness at record_limit=10,000: the
/// operator's actual chain (11,449 records) fell well inside their raised
/// cap, so their 30s run was never driven by anywhere near their
/// configured limit's worth of work. Both known data points sit outside
/// this function's derived value with margin, in the direction that
/// matters (above the known-insufficient 5s).
pub(crate) fn derive_audit_verify_timeout_secs(record_limit: usize) -> u64 {
    let ms = record_limit as f64 * AUDIT_VERIFY_MS_PER_RECORD_FLOOR * AUDIT_VERIFY_LOAD_MARGIN;
    let secs = (ms / 1000.0).ceil() as u64;
    secs.clamp(AUDIT_VERIFY_TIMEOUT_MIN_SECS, AUDIT_VERIFY_TIMEOUT_MAX_SECS)
}

/// One full run of the standalone csq daemon: license gate, bind the IPC
/// transport, spawn every subsystem (refresher, usage poller, auto-rotate,
/// CRL refresher, ledger writer, log GC, anchor, server), then block until
/// `cancel` fires and drain cleanly.
///
/// Returns `Err(String)` on a fast/persistent failure (license-gate
/// refusal, phase-4 gate refusal, socket-bind failure) so the supervisor
/// loop ([`handle_start_supervised`]) backs off instead of hot-looping;
/// `Ok(())` on a clean cancellation-driven shutdown.
///
/// MUST NOT acquire the PidFile — the caller owns it (foreground:
/// [`handle_start`]; supervised: the `run_forever` loop).
/// Runs one audit-chain verify attempt (op-chain full verify + the EATP
/// side-pass) and returns the resulting `AuditHealth` + `records_unverified`,
/// having also applied the `.chain-broken` sentinel side effects for that
/// outcome. Used for BOTH the blocking startup call in [`run_daemon_session`]
/// and each bounded background retry in [`spawn_audit_verify_retry`] after a
/// startup `Unknown` -- the two callers differ only in WHEN they call this
/// and what they do with an `Unknown` result (startup proceeds to socket
/// bind regardless per spec 12 Section 12.13.5; a retry schedules another
/// attempt or gives up). The verify logic, timeout derivation, and sentinel
/// semantics are identical either way -- duplicating them is exactly the
/// risk a retry path would otherwise reintroduce.
async fn attempt_audit_verify(base_dir: &Path) -> (csq_core::audit::AuditHealth, u64) {
    let record_limit: usize = std::env::var("CSQ_AUDIT_VERIFY_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    // FIX-5b: clamp timeout floor to 1s so CSQ_AUDIT_VERIFY_TIMEOUT_SECS=0
    // (or an unparseable value) cannot silently suppress verification.
    // Absent an explicit override, the default scales with the
    // CONFIGURED record_limit — see `derive_audit_verify_timeout_secs`.
    let timeout_secs: u64 = std::env::var("CSQ_AUDIT_VERIFY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.max(1))
        .unwrap_or_else(|| derive_audit_verify_timeout_secs(record_limit));
    let verify_cfg = csq_core::audit::VerifyConfig {
        record_limit,
        keychain_service: csq_core::audit::AUDIT_SIGNING_SERVICE_NAME.to_string(),
    };
    let base_for_verify = base_dir.to_path_buf();
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
    // Set by the two Ok(Ok(Ok(summary))) arms below from
    // `summary.limit_exceeded_count` — the count of oldest records
    // (possibly including the genesis) the verifier SKIPPED because
    // the chain exceeded `record_limit`. Zero for every other arm:
    // Broken/Unknown never produced a summary to read the count from.
    let mut records_unverified: u64 = 0;
    let health = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        verify_future,
    )
    .await
    {
        // ── Verified / TailVerified / Degraded ──────────────────
        //
        // SINGLE PRODUCER. `AuditHealth::from_verify_result` owns the
        // summary→verdict mapping for EVERY surface that reports audit
        // health: `csq doctor --json`, `csq audit verify --json`, and —
        // through the startup snapshot this function returns, which
        // `daemon::server`'s `/api/audit/health` handler serves verbatim —
        // `csq daemon status`.
        //
        // These two arms previously built `AuditHealth::Verified` by hand
        // and never consulted `limit_exceeded_count`. So when 1a1d6976
        // taught `from_verify_result` to return `TailVerified` on a
        // truncated scan, the other two surfaces learned the distinction
        // and THIS one did not: on the same chain, `csq doctor --json`
        // said `tail_verified` while `GET /api/audit/health` still said
        // `verified`. Adding a variant forces CONSUMERS to handle it
        // (that is what the five match sites in 1a1d6976 were); it cannot
        // make a hand-rolled PRODUCER emit it —
        // `guard-reader-writer-parity.md` MUST NOT #2.
        Ok(Ok(Ok(summary))) => {
            records_unverified = summary.limit_exceeded_count;
            let verified_count = summary.verified_count;
            let health = csq_core::audit::AuditHealth::from_verify_result(&Ok(summary));
            match &health {
                csq_core::audit::AuditHealth::Verified => {
                    tracing::info!(
                        verified_count,
                        records_unverified,
                        "audit chain verified clean; proceeding to socket bind"
                    );
                }
                csq_core::audit::AuditHealth::TailVerified { skipped } => {
                    tracing::warn!(
                        audit_verify_tail_only = true,
                        verified_count,
                        skipped = *skipped,
                        "audit chain TAIL-VERIFIED — the {skipped} oldest record(s), \
                         INCLUDING the genesis, were NOT scanned, so the surviving \
                         window's first record is anchored to nothing. Proceeding to \
                         socket bind; the audit subsystem stays operational. Raise \
                         CSQ_AUDIT_VERIFY_LIMIT above the chain length for whole-chain \
                         coverage."
                    );
                }
                csq_core::audit::AuditHealth::Degraded { gaps } => {
                    for gap in gaps {
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
                        gap_count = gaps.len(),
                        "audit chain DEGRADED (historical-key gaps); proceeding to socket \
                         bind — audit subsystem remains operational"
                    );
                }
                // Unreachable by construction: `from_verify_result` maps an
                // `Ok(summary)` to Verified / TailVerified / Degraded only —
                // the error verdicts come from the `Err` arm below. Enumerated
                // rather than wildcarded so a future variant still forces a
                // decision at this call site.
                csq_core::audit::AuditHealth::Broken { .. }
                | csq_core::audit::AuditHealth::Unknown { .. } => {
                    tracing::warn!(
                        error_kind = "audit_verify_verdict_unexpected",
                        "audit verify mapped a clean summary to an error verdict"
                    );
                }
            }
            health
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
                    let error_kind =
                        if let csq_core::audit::AuditHealth::Broken { ref error_kind, .. } = health
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
Could not confirm chain soundness this attempt. Audit anchoring and new audit-record \
emits are disabled until a verify attempt succeeds. `csq audit verify --full` reports whether \
the chain itself is sound, but running it does NOT change this daemon's gate -- only a later \
successful verify (the daemon's own bounded background retry, or a `csq daemon` restart) does."
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
Could not confirm chain soundness this attempt. Audit anchoring and new audit-record \
emits are disabled until a verify attempt succeeds. `csq audit verify --full` reports whether \
the chain itself is sound, but running it does NOT change this daemon's gate -- only a later \
successful verify (the daemon's own bounded background retry, or a `csq daemon` restart) does."
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
        // TailVerified clears alongside Verified/Degraded — outgrowing the
        // record limit is not brokenness. Coverage is reported separately.
        csq_core::audit::AuditHealth::Verified
        | csq_core::audit::AuditHealth::TailVerified { .. }
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

    (health, records_unverified)
}

/// Bounded background retry for a startup `AuditHealth::Unknown` verdict.
///
/// Returns `None` when `startup_health` is already operational (nothing to
/// retry). Otherwise spawns a task that retries [`attempt_audit_verify`] on
/// an exponential backoff ([`audit_verify_retry_backoff_secs`]), up to
/// [`AUDIT_VERIFY_RETRY_MAX_ATTEMPTS`] (env-overridable via
/// `CSQ_AUDIT_VERIFY_RETRY_MAX_ATTEMPTS`), and PROMOTES `shared` in place —
/// via the [`csq_core::audit::SharedAuditHealth`] lock — the first time an
/// attempt returns Verified or Degraded. Every live handler reads `shared`
/// fresh per request, so promotion re-arms the audit subsystem (emit +
/// mcp-gate + anchor-request routes) on the very next request with no
/// daemon restart, per `crate::audit::health`'s module doc.
///
/// On promotion, if an anchor sink is configured and the anchor task was
/// never started at daemon startup (it is skipped precisely when health is
/// not operational — see the M14 anchor-task spawn site above), this also
/// starts it. There is no separate registration path back into
/// `run_daemon_session`'s `subsystems` vec for a task spawned after that
/// vec is built, so this function's own returned task holds the anchor
/// task's `JoinHandle` itself and stays alive until `shutdown` fires —
/// satisfying the CONTRACT (an internal ticket redteam LOW-1) that every tracked
/// subsystem idle-loops on `shutdown` rather than returning early: an early
/// return here (with the anchor task still running) would both read as a
/// spurious daemon-session fault AND detach the anchor task from the
/// session's shutdown drain.
///
/// If the retry budget is exhausted without a definitive result,
/// `audit_health` stays `Unknown` permanently for the rest of this daemon
/// process's life — recoverable only by a `csq daemon` restart, or by a
/// `csq audit verify` / `csq doctor` run (those affect the `.chain-broken`
/// sentinel other writers gate on, but do NOT reach back into this
/// already-running daemon's in-RAM `audit_health`).
fn spawn_audit_verify_retry(
    startup_health: &csq_core::audit::AuditHealth,
    base_dir: PathBuf,
    shared: csq_core::audit::SharedAuditHealth,
    anchor_sink: Option<Arc<dyn csq_core::audit::LedgerSink>>,
    anchor_sink_cfg: csq_core::audit::AuditSinkConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Option<daemon::supervise::Subsystem> {
    if startup_health.is_operational() {
        return None;
    }

    let max_attempts: u32 = std::env::var("CSQ_AUDIT_VERIFY_RETRY_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &u32| *v > 0)
        .unwrap_or(AUDIT_VERIFY_RETRY_MAX_ATTEMPTS);

    let join = tokio::spawn(async move {
        let mut anchor_join: Option<tokio::task::JoinHandle<()>> = None;

        for attempt in 0..max_attempts {
            // Re-derive the verify budget each attempt so an operator env
            // change between attempts takes effect the same as it would on
            // a fresh restart.
            let record_limit: usize = std::env::var("CSQ_AUDIT_VERIFY_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000);
            let verify_timeout_secs: u64 = std::env::var("CSQ_AUDIT_VERIFY_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.max(1))
                .unwrap_or_else(|| derive_audit_verify_timeout_secs(record_limit));
            let backoff = audit_verify_retry_backoff_secs(attempt, verify_timeout_secs);

            tracing::info!(
                attempt = attempt + 1,
                max_attempts,
                backoff_secs = backoff,
                "audit verify background retry: waiting before next attempt"
            );
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(backoff)) => {}
            }
            if shutdown.is_cancelled() {
                return;
            }

            let (new_health, records_unverified) = attempt_audit_verify(&base_dir).await;
            let operational = new_health.is_operational();
            tracing::info!(
                attempt = attempt + 1,
                max_attempts,
                operational,
                records_unverified,
                "audit verify background retry attempt completed"
            );

            if operational {
                {
                    let mut guard = shared.write().expect("audit health lock poisoned");
                    *guard = new_health.clone();
                }
                tracing::warn!(
                    attempt = attempt + 1,
                    "audit health PROMOTED out of Unknown by background retry — audit \
                     subsystem (anchoring + record emit) is re-armed WITHOUT a daemon \
                     restart"
                );
                eprintln!(
                    "csq daemon: AUDIT HEALTH RESTORED after {} background retry \
attempt(s). Audit anchoring and audit-record emits are re-enabled; no restart was \
needed.",
                    attempt + 1
                );

                if let Some(sink) = anchor_sink.clone() {
                    anchor_join = daemon::spawn_anchor_task(
                        base_dir.clone(),
                        anchor_sink_cfg.clone(),
                        sink,
                        shutdown.clone(),
                    )
                    .map(|h| h.join);
                    if anchor_join.is_some() {
                        tracing::info!(
                            "audit anchor task started post-promotion (was skipped at \
                             daemon startup because the chain was not yet operational)"
                        );
                    }
                }
                break;
            }

            if attempt + 1 == max_attempts {
                tracing::error!(
                    error_kind = "audit_verify_retry_exhausted",
                    max_attempts,
                    "audit verify background retry EXHAUSTED its bounded attempt budget \
                     without a definitive result — audit_health remains Unknown; the \
                     audit subsystem stays fail-closed until a `csq daemon` restart"
                );
                eprintln!(
                    "csq daemon: AUDIT VERIFY RETRY EXHAUSTED after {max_attempts} \
attempts without a definitive result. Audit anchoring and audit-record emits remain \
disabled. Restart `csq daemon` to re-attempt from a clean process, or run `csq audit \
verify --full` / `csq doctor` to check whether the chain itself is sound (neither \
changes this daemon's in-RAM gate — only a restart or a later successful background \
retry does)."
                );
            }
        }

        // CONTRACT (an internal ticket redteam LOW-1): never return before `shutdown` fires.
        // An early return here reads as a subsystem fault (restarts the whole
        // daemon session) and, if `anchor_join` is `Some`, detaches the anchor
        // task's handle from the session's shutdown drain while the task itself
        // keeps running undrained. Whether promotion succeeded, failed, or the
        // anchor task is now the thing keeping this alive, idle on shutdown.
        match anchor_join {
            Some(handle) => {
                if let Err(e) = handle.await {
                    tracing::error!(
                        error_kind = "audit_anchor_task_panicked_post_promotion",
                        "audit anchor task (started post-promotion) exited: {e}"
                    );
                }
            }
            None => shutdown.cancelled().await,
        }
    });

    Some(("audit_verify_retry", join))
}

async fn run_daemon_session(
    base_dir: PathBuf,
    cancel: tokio_util::sync::CancellationToken,
) -> std::result::Result<(), String> {
    // `keychain-fix-r11.md` S-LOW-3: install the redacting panic hook before
    // any subsystem starts. Idempotent (`std::sync::Once`) so the supervised
    // loop's in-process session restarts never stack a second hook.
    daemon::panic_hook::install();

    // Enterprise license gate for the daemon-hosted governance / audit /
    // EATP stack (task #77 shard 3). STARTUP variant (structural validity +
    // definitive revocation, no liveness deny) so a licensed-but-offline-
    // beyond-grace customer can still start the daemon whose CRL refresher
    // recovers their cache — the full per-op `enforce` would be a
    // fail-closed deadlock. Inert while the placeholder key is baked;
    // community builds carry no gate. A refusal returns `Err` so the
    // supervised loop backs off (twin of the desktop `run_daemon` gate).
    #[cfg(feature = "enterprise")]
    if let Err(e) = super::super::enforce_enterprise_license_startup(&base_dir) {
        return Err(format!("enterprise license gate refused daemon start: {e}"));
    }

    let base_dir_for_runtime = base_dir;
    let sock_path = daemon::socket_path(&base_dir_for_runtime);
    // Subsystems share this token. It is a CHILD of the caller's `cancel`
    // (not a clone), so:
    //   - when `cancel` fires (SIGTERM bridge / supervisor stop), the child
    //     cancels too and every subsystem drains — the graceful path; and
    //   - when a subsystem dies mid-session (an internal ticket), the session body can
    //     cancel THIS child to drain the siblings WITHOUT firing `cancel`
    //     itself, so `run_forever` sees a fast `Err` and restarts the
    //     session rather than treating it as an intentional stop
    //     (`supervise.rs::run_forever` returns on `cancel.is_cancelled()`).
    let shutdown = cancel.child_token();

    // Bind the IPC transport (Unix socket / Windows named pipe) +
    // axum router, then wire the subsystems. The whole body is
    // cross-platform — only the `serve` bind call and the
    // shutdown-wait are `#[cfg]`-gated per transport (an internal ticket).
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

        // `shutdown` (the subsystem cancel token) is defined at the top
        // of `run_daemon_session` as a clone of the caller's `cancel`.

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
            return Err(format!("phase 4 gate refused start: {e}"));
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
        // The verify step is wrapped in a `tokio::time::timeout` — default
        // sized by `derive_audit_verify_timeout_secs` from the configured
        // record_limit (16s at the 10,000-record default; see that
        // function's doc for the measured floor + margin it rests on),
        // explicit-override-able via `CSQ_AUDIT_VERIFY_TIMEOUT_SECS`. On
        // timeout: `AuditHealth::Unknown` with reason
        // "audit_verify_timeout" — audit subsystem fails closed.

        let (audit_health, audit_records_unverified) =
            attempt_audit_verify(&base_dir_for_runtime).await;

        // The shared handle exists so a FUTURE retry task can promote the
        // verdict out of `Unknown` without a daemon restart (the defect: a
        // single startup timeout left this host's audit subsystem refusing
        // emits for 2h08m, and only a restart cleared it). See
        // `spawn_audit_verify_retry` below, wired in once `anchor_sink` is
        // resolved — the retry task also owns starting the anchor task on
        // promotion. The local `audit_health` binding stays a plain enum so
        // the start-time consumers (`is_operational` at the anchor-task
        // branch and the readiness log) read the startup snapshot only; the
        // shared cell is what a later promotion updates.
        let audit_health_shared = csq_core::audit::new_shared(audit_health.clone());

        // an internal ticket — resolve the active transparency-log sink ONCE so both the
        // anchor HTTP handler (RouterState.anchor_sink, for synchronous
        // inclusion-proof projection on `POST /api/audit/anchor`) and the
        // cadence-driven drain task below share the same Arc + config. In the
        // default local-only build `sink = "none"` (or the requested sink's
        // feature is not compiled in) → `resolve_anchor_sink` returns `None`
        // and the handler surfaces `inclusion_proof: null` (honest).
        let anchor_sink_cfg =
            csq_core::audit::AuditSinkConfig::load(&base_dir_for_runtime).unwrap_or_default();
        let anchor_sink: Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> =
            resolve_anchor_sink(&anchor_sink_cfg);

        let router_state = daemon::server::RouterState {
            cache: Arc::clone(&refresh_cache),
            discovery_cache: Arc::clone(&discovery_cache),
            base_dir: Arc::new(base_dir_for_runtime.clone()),
            oauth_store: Some(Arc::clone(&oauth_store)),
            gemini_consumer: gemini_consumer.clone(),
            audit_health: Arc::clone(&audit_health_shared),
            audit_records_unverified,
            anchor_sink: anchor_sink.clone(),
            // an internal ticket — seed the interactive enforcement registry from the
            // fail-closed §10.5 activation gate (absent → empty/503).
            // an internal ticket follow-up — inject the cross-SDK kailash projector (the
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
                    Some(crate::kailash_audit_sink::make_audit_sink_factory(
                        &base_dir_for_runtime,
                    )),
                );
                // M3 §10.5 W2b — inject the EATP born-canonical genesis guard.
                // Classifies the genesis record on every session open; non-BornCanonical
                // refuses EATP chain appends but the session still proceeds.
                // M3 §10.5 W3 — inject the EATP session-close attestation writer.
                // Appends a born-canonical session-close attestation on every
                // close (fail-closed-NON-FATAL — never blocks teardown).
                reg.with_eatp_genesis_guard(crate::kailash_eatp_genesis::make_eatp_genesis_guard(
                    &base_dir_for_runtime,
                ))
                .with_eatp_attestor(
                    crate::kailash_eatp_attest::make_eatp_session_close_attestor(
                        &base_dir_for_runtime,
                    ),
                )
            }),
        };

        // ── M19: Emit capture-matrix record (sidecar dedup) ───────────────────
        // Emitted AFTER audit_health is finalised, BEFORE daemon::serve.
        // The orchestration (dedup key, sidecar-advance rule, non-fatal error
        // handling) lives in ONE place shared with the desktop in-process
        // daemon twin — see `emit_startup_capture_matrix`'s docstring for why.
        csq_core::audit::seam::emit_startup_capture_matrix(
            &base_dir_for_runtime,
            audit_health.is_operational(),
        );

        // Bind the transport. Unix binds a domain socket
        // (`daemon::serve`); Windows binds a named pipe
        // (`daemon::serve_windows`). Both return a handle exposing
        // `.shutdown()` + a `JoinHandle<()>`, so the entire tail
        // below is shared. `sock_path` already resolves to the
        // named-pipe path on Windows (`daemon::socket_path`).
        #[cfg(unix)]
        let serve_result = daemon::serve(&sock_path, router_state).await;
        #[cfg(windows)]
        let serve_result = daemon::serve_windows(&sock_path.to_string_lossy(), router_state).await;
        match serve_result {
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

                // License CRL refresher (task #77 shard 2): keeps the signed
                // revocation list fresh so the enterprise license gate can fail
                // closed on a revoked/stale license without bricking a paying
                // customer on a network blip. Enterprise-only; inert while the
                // placeholder key is baked.
                #[cfg(feature = "enterprise")]
                let crl_refresher =
                    daemon::spawn_crl_refresher(base_dir_for_runtime.clone(), shutdown.clone());

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
                // Anthropic-only sibling transport that additionally
                // captures the `retry-after` response header (see
                // `csq-core/src/daemon/usage_poller/mod.rs::HttpGetWithRetryAfterFn`).
                let http_get_retry_after: daemon::HttpGetWithRetryAfterFn =
                    Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
                        http::get_bearer_node_with_retry_after(url, token, headers)
                    });
                let http_post_probe: daemon::HttpPostProbeFn =
                    Arc::new(|url: &str, headers: &[(String, String)], body: &str| {
                        http::post_json_with_headers(url, headers, body)
                    });
                let usage_poller = daemon::spawn_usage_poller(
                    base_dir_for_runtime.clone(),
                    http_get,
                    http_get_retry_after,
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
                // Roots path comes from the SHARED resolver that `csq run`'s
                // `record_root_seen` writer also uses — a hardcoded join here
                // is what made this sweeper inert: it read
                // `<base_dir>/coc-roots-seen.jsonl` while the writer populated
                // `~/.csq/coc-roots-seen.jsonl`, so it swept nothing, ever.
                // The state snapshot stays under base_dir, where `csq doctor`
                // reads it.
                let coc_cache_sweeper = daemon::spawn_coc_cache_sweeper(
                    csq_core::daemon::coc_cache_sweeper::roots_seen_path_or_inert(
                        &base_dir_for_runtime,
                    ),
                    base_dir_for_runtime.clone(),
                    shutdown.clone(),
                );

                // Start the daemon-written usage-ledger writer (an internal ticket).
                // Periodically re-derives each account's usage history from
                // CC's transcripts and atomically publishes it to the per-slot
                // ledger, so the desktop dashboard reads a sub-ms ledger
                // instead of running the ~20s live scan on the render path.
                // The daemon is the SOLE producer; terminals only read
                // (account-terminal-separation.md Rule 1, extended for
                // billing telemetry). `claude_home()` → None (no $HOME) makes
                // the writer a no-op, mirroring the sweep/rotator wiring.
                let claude_home_for_ledger = super::claude_home().ok();
                let usage_ledger_writer = daemon::spawn_usage_ledger_writer(
                    base_dir_for_runtime.clone(),
                    claude_home_for_ledger,
                    shutdown.clone(),
                    chrono::Utc::now,
                );

                // Start the daemon rolling-log GC (#1a-2,
                // daemon-auth-resilience Wave A2). 14-day retention sweep
                // over the persistent rolling file log this same `csq
                // daemon` process writes via the `daemon_log` module's
                // subscriber wiring in `cli::run`. Mirrors the
                // coc_cache_sweeper's spawn/tick idiom.
                let log_gc =
                    csq_core::daemon::log_gc::spawn(base_dir_for_runtime.clone(), shutdown.clone());

                // M14 — external anchoring task. Reads `audit-sink.json`;
                // no-op when sink == "none" (default). When a sink is
                // configured, periodically anchors the chain HEAD to the
                // external witness and fires immediately on high-impact ops
                // (KeyRotate, IdentityMint, ReleaseAuth) via head-kind detection.
                //
                // Audit-subsystem fail-closed: when `audit_health` is Broken
                // or Unknown the anchor task is NOT started at startup.
                // Appending new anchor records to a chain of unconfirmed
                // integrity is pointless and potentially misleading. Logs a
                // WARN so the operator can see why anchoring is inactive.
                //
                // Broken vs Unknown differ in what happens next: `Broken` is
                // a definitive `LedgerError` — nothing in-process will change
                // that verdict, so a repair (`csq audit verify --full`) plus
                // a restart is the only path back. `Unknown` (timeout /
                // panic) is NOT definitive — `spawn_audit_verify_retry`
                // (wired below via `audit_verify_retry_handle`) is already
                // retrying in the background and starts this same anchor
                // task itself the moment it promotes the chain to
                // Verified/Degraded, with no restart required.
                let anchor_handle = if !audit_health.is_operational() {
                    let retry_note = match &audit_health {
                        csq_core::audit::AuditHealth::Unknown { .. } => {
                            "a bounded background retry is running (see `csq daemon \
                             status`); it starts anchoring automatically on promotion, \
                             no restart needed. If the retry exhausts its budget, \
                             restart the daemon after repairing the chain."
                        }
                        _ => {
                            "restart the daemon after repairing the chain \
                              (`csq audit verify --full` for diagnosis)."
                        }
                    };
                    tracing::warn!(
                        error_kind = "audit_anchor_skipped_broken_chain",
                        "audit anchor task NOT started at startup — chain is not \
                             operational (audit_health={:?}). {retry_note}",
                        audit_health
                    );
                    None
                } else {
                    // an internal ticket — reuse the sink + config resolved once above for
                    // RouterState.anchor_sink (no second config read / resolve).
                    anchor_sink.clone().and_then(|s| {
                        daemon::spawn_anchor_task(
                            base_dir_for_runtime.clone(),
                            anchor_sink_cfg.clone(),
                            s,
                            shutdown.clone(),
                        )
                    })
                };

                // Bounded background retry for a startup `Unknown` verdict
                // (started only after the socket bind succeeded, so a bind
                // failure below never leaves an orphaned retry task running
                // against a daemon that is about to exit). `None` when
                // startup already produced Verified/Degraded — nothing to
                // retry. Pushed into `subsystems` below.
                let audit_verify_retry_handle = spawn_audit_verify_retry(
                    &audit_health,
                    base_dir_for_runtime.clone(),
                    Arc::clone(&audit_health_shared),
                    anchor_sink.clone(),
                    anchor_sink_cfg.clone(),
                    shutdown.clone(),
                );

                // Collect every long-lived subsystem into a uniform set so
                // the session can watch them for premature exit AND drain
                // them with one loop. Each entry is a stable label + its
                // `JoinHandle<()>` (directly, or via the handle struct's
                // `.join`).
                //
                // CONTRACT (an internal ticket redteam LOW-1): every member here MUST run
                // until `shutdown` fires. `await_session_stop` treats ANY
                // return from a member — clean `Ok(())` or panic — as a fault
                // that restarts the whole session. A subsystem that returns
                // early on a benign "nothing to do" condition would trigger a
                // restart storm; such a subsystem must idle-loop on `shutdown`
                // (see `auto_rotate::run_loop`), not return.
                //
                // `ipc_server` is the one member that exits on its OWN internal
                // token (fired by `server.shutdown()` during teardown below),
                // NOT the shared `shutdown` — but it still never returns during
                // normal operation, so its premature exit (a panicked accept
                // loop) is a genuine fault worth a restart (an internal ticket): a dead IPC
                // server silently breaks login / status / provision while the
                // refresher keeps going.
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
                if let Some(entry) = audit_verify_retry_handle {
                    subsystems.push(entry);
                }

                // Block until EITHER a graceful stop (`cancel` fires: the
                // SIGTERM/SIGINT bridge in foreground, or the supervisor stop
                // when supervised) OR a subsystem dies mid-session (an internal ticket —
                // the mass-expiry failure shape one level down). The
                // subsystems share `shutdown` (a child of `cancel`), so on a
                // graceful stop they are already winding down.
                let stop = daemon::supervise::await_session_stop(&cancel, &mut subsystems).await;

                eprintln!("csq daemon stopping...");
                // Cancel the server's OWN internal token so its accept loop
                // exits on the next poll.
                server.shutdown();

                if let daemon::supervise::SessionStop::SubsystemExited(name) = &stop {
                    // A subsystem exited while the daemon was meant to be
                    // running. Fire the CHILD `shutdown` token to wind the
                    // siblings down (this does NOT cancel the caller's
                    // `cancel`, so `run_forever` restarts rather than exits),
                    // then return `Err` below.
                    tracing::error!(
                        subsystem = %name,
                        error_kind = "daemon_subsystem_exited",
                        "daemon subsystem exited mid-session; draining siblings and restarting"
                    );
                    shutdown.cancel();
                }

                // Drain every remaining subsystem with a 5s per-handle deadline
                // (the dead one, if any, was already removed by
                // `await_session_stop`, so no handle is double-polled). This
                // includes `ipc_server` unless IT was the one that exited —
                // `server.shutdown()` above fired its accept loop's exit, so its
                // handle completes here (no separate drain, which would
                // double-poll it — an internal ticket redteam hazard).
                daemon::supervise::drain_subsystems(subsystems, std::time::Duration::from_secs(5))
                    .await;

                if let daemon::supervise::SessionStop::SubsystemExited(name) = stop {
                    return Err(format!("daemon subsystem exited mid-session: {name}"));
                }
            }
            Err(e) => {
                // Bind failure is fatal — the daemon can't do
                // anything useful without its IPC socket.
                eprintln!(
                    "error: failed to bind daemon socket at {}: {e}",
                    sock_path.display()
                );
                return Err(format!("socket bind failed: {e}"));
            }
        }
    }

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
/// - `"s3"` → `S3ObjectLockSink` (feature `s3-sink`), `"azure"` → `AzureImmutableBlobSink`
///   (feature `azure-sink`), `"gcp"` → `GcpBucketLockSink` (feature `gcp-sink`),
///   `"azure-sql"` → `AzureSqlLedgerSink` (feature `azure-sql-sink`) — all four are
///   M07 in-memory mock substrates (`crate::audit::impls::sinks::{s3,azure,gcp,azure_sql}`).
/// - `"customer-body-store"` → `CustomerBodyStoreSink` (feature `customer-body-store-sink`),
///   `reqwest`-backed, POSTs to `audit-sink.json`'s configured operator endpoint.
///
/// Every arm above is feature-gated in BOTH this crate's `Cargo.toml` (which
/// forwards to the matching `csq-core` feature) and in `csq-core`'s own
/// feature table (`validate_sink_compiled_in`). A sink name recognised by
/// `AuditSinkConfig::set_sink` but missing its `#[cfg(feature = ...)]` arm
/// here falls to the catch-all below and is reported, never silently
/// dropped (issue: `resolve_anchor_sink` previously had arms for only 2 of
/// the 7 catalogued sink kinds).
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

        #[cfg(feature = "s3-sink")]
        "s3" => match csq_core::audit::impls::sinks::s3::S3ObjectLockSink::with_defaults() {
            Ok(s) => {
                // HONEST LABEL (mirrors rekor's — see the comment above): the
                // M07 S3ObjectLockSink is an in-memory mock substrate. Nothing
                // leaves this process; `append` still returns `Ok`, and a
                // signed ReplicationAck still lands in the chain. Operators
                // MUST NOT treat this as durable WORM/Object-Lock storage
                // until a real `aws-sdk-s3` client replaces the mock.
                tracing::warn!(
                    event = "anchor_sink_mock_backend",
                    sink = "s3",
                    "s3 sink uses the in-memory M07 substrate (non-persistent); \
                     real AWS S3 Object Lock client is a pending follow-up"
                );
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::warn!(
                    event = "anchor_sink_init_failed",
                    sink = "s3",
                    error = %e,
                    "s3 sink initialisation failed — anchor task not started"
                );
                None
            }
        },

        #[cfg(feature = "azure-sink")]
        "azure" => {
            match csq_core::audit::impls::sinks::azure::AzureImmutableBlobSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL (mirrors rekor's): in-memory mock substrate,
                    // nothing leaves this process. See the s3 arm above for
                    // the full rationale.
                    tracing::warn!(
                        event = "anchor_sink_mock_backend",
                        sink = "azure",
                        "azure sink uses the in-memory M07 substrate (non-persistent); \
                         real Azure Immutable Blob Storage client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    tracing::warn!(
                        event = "anchor_sink_init_failed",
                        sink = "azure",
                        error = %e,
                        "azure sink initialisation failed — anchor task not started"
                    );
                    None
                }
            }
        }

        #[cfg(feature = "gcp-sink")]
        "gcp" => match csq_core::audit::impls::sinks::gcp::GcpBucketLockSink::with_defaults() {
            Ok(s) => {
                // HONEST LABEL (mirrors rekor's): in-memory mock substrate,
                // nothing leaves this process. See the s3 arm above for
                // the full rationale.
                tracing::warn!(
                    event = "anchor_sink_mock_backend",
                    sink = "gcp",
                    "gcp sink uses the in-memory M07 substrate (non-persistent); \
                     real GCP Cloud Storage Bucket Lock client is a pending follow-up"
                );
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::warn!(
                    event = "anchor_sink_init_failed",
                    sink = "gcp",
                    error = %e,
                    "gcp sink initialisation failed — anchor task not started"
                );
                None
            }
        },

        #[cfg(feature = "azure-sql-sink")]
        "azure-sql" => {
            match csq_core::audit::impls::sinks::azure_sql::AzureSqlLedgerSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL (mirrors rekor's): in-memory mock substrate,
                    // nothing leaves this process. See the s3 arm above for
                    // the full rationale.
                    tracing::warn!(
                        event = "anchor_sink_mock_backend",
                        sink = "azure-sql",
                        "azure-sql sink uses the in-memory M07 substrate (non-persistent); \
                         real Azure SQL ledger-table client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    tracing::warn!(
                        event = "anchor_sink_init_failed",
                        sink = "azure-sql",
                        error = %e,
                        "azure-sql sink initialisation failed — anchor task not started"
                    );
                    None
                }
            }
        }

        #[cfg(feature = "customer-body-store-sink")]
        "customer-body-store" => {
            match csq_core::audit::impls::sinks::customer_body_store::CustomerBodyStoreSink::new(
                csq_core::audit::impls::sinks::customer_body_store::CustomerBodyStoreConfig::default(),
            ) {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    tracing::warn!(
                        event = "anchor_sink_init_failed",
                        sink = "customer-body-store",
                        error = %e,
                        "customer-body-store sink initialisation failed — anchor task not started"
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
///
/// Also sets the [`daemon::set_stop_requested`] sentinel (an internal ticket) so
/// a desktop-app in-process supervisor, if one is cohabiting with the
/// process we just stopped, does NOT silently re-acquire the daemon on
/// its next detect tick. The sentinel is cleared by every `csq daemon
/// start` entry point — this stop is not permanent, only explicit.
pub fn handle_stop(base_dir: &Path) -> Result<()> {
    // an internal ticket: set the stop-requested sentinel BEFORE signalling. A
    // desktop-app in-process supervisor cohabiting with the PidFile owner
    // we are about to stop must see this sentinel on its very next
    // detect/acquire tick, or it silently takes over and "csq daemon
    // stopped" becomes a lie the moment it is printed. Best-effort: a
    // sentinel-write failure does not block the stop signal itself.
    daemon::set_stop_requested(base_dir);

    let pid_path = daemon::pid_file_path(base_dir);

    match daemon::stop_daemon(&pid_path) {
        Ok(pid) => {
            eprintln!("csq daemon stopped (PID {pid})");
            if let Some(note) = managed_stop_advisory(launchd_job_is_loaded()) {
                eprint!("{note}");
            }
            Ok(())
        }
        Err(csq_core::error::DaemonError::NotRunning { .. }) => {
            eprintln!("csq daemon not running");
            Ok(())
        }
        Err(csq_core::error::DaemonError::StalePidFile { pid }) => {
            // THREE paths reach here and the wording must hold for all of
            // them: (a) Unix/dead-PID pre-check — the PID is genuinely gone
            // and its stale file was removed; (b) Windows — the daemon's
            // shutdown event is absent (an exceptional startup failure) even
            // though the PID is ALIVE, so the file is intentionally NOT
            // removed (a live daemon keeps its lock) (an internal ticket redteam R3 LOW);
            // (c) the PID is alive but belongs to an unrelated program
            // because the OS recycled a dead daemon's PID — csq deliberately
            // did not signal it and removed the stale file. Naming (c)
            // explicitly matters: the operator otherwise reads "not
            // reachable" as "my daemon is wedged" and reaches for `kill`.
            eprintln!(
                "csq daemon not reachable for a graceful stop (PID {pid} — already \
                 stopped, or that PID now belongs to an unrelated program after \
                 the OS reused it, or its shutdown channel is unavailable). csq \
                 did not signal the PID. If a daemon is still running, restart it \
                 to restore a working shutdown channel."
            );
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
/// Surfaces the daemon's own audit-chain verdict on `csq daemon status`.
///
/// WHY: on 2026-09-12 this host's audit subsystem sat `Unknown` for 2h08m
/// after a single startup verify timeout — refusing emits and never starting
/// the anchor task — while `csq daemon status` printed only running/PID/
/// socket/posture. The state existed and no surface an operator would think
/// to check carried it. `csq doctor` had it; `daemon status`, the command the
/// misleading remedies actually told people to run, did not.
///
/// Reads the SAME channel doctor reads (`audit_health::try_daemon_audit_health`
/// → `GET /api/audit/health` on the daemon socket) rather than a second route,
/// per `diagnostic-surface-parity.md`. A failed query prints the REASON rather
/// than nothing or a guess: "could not read" and "healthy" must never render
/// the same (`durable-instruments.md` — could-not-measure is a third outcome,
/// not silence).
fn print_audit_health_line(base_dir: &Path) {
    match super::audit_health::try_daemon_audit_health(base_dir) {
        Ok((health, unverified)) => {
            let detail = if unverified > 0 {
                format!(" ({unverified} record(s) unverified)")
            } else {
                String::new()
            };
            eprintln!("  Audit:    {health:?}{detail}");
            if !health.is_operational() {
                eprintln!(
                    "            audit emits and anchoring are DISABLED while this is \
                     not operational."
                );
            }
        }
        Err(reason) => {
            // Not "healthy" and not silence — the operator is told the read
            // did not happen, and why.
            eprintln!("  Audit:    unknown to this command — {reason}");
        }
    }
}

pub fn handle_status(base_dir: &Path) -> Result<()> {
    let pid_path = daemon::pid_file_path(base_dir);

    match daemon::status_of(&pid_path) {
        DaemonStatus::Running { pid } => {
            println!("running");
            eprintln!("  PID:      {pid}");
            eprintln!("  PID file: {}", pid_path.display());
            eprintln!("  Socket:   {}", daemon::socket_path(base_dir).display());
            print_posture_lines(base_dir);
            print_audit_health_line(base_dir);
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
        // Distinct wording from `Stale`: that PID *is* alive, so calling it
        // dead would send the operator hunting for a daemon that isn't
        // theirs. Naming PID reuse explicitly also pre-empts the reflex to
        // `kill` the PID by hand — it belongs to an unrelated program.
        DaemonStatus::PidReused { pid } => {
            println!("stale");
            eprintln!(
                "  Stale PID file at {} names PID {pid}, which is alive but is NOT a",
                pid_path.display()
            );
            eprintln!("  csq process — the OS reused a dead daemon's PID. No daemon is running,");
            eprintln!("  and csq will not signal that PID. Do not kill it by hand.");
            eprintln!("  Run `csq daemon start`; it clears the stale file and takes over.");
            std::process::exit(1);
        }
        DaemonStatus::NotRunning => {
            println!("not running");
            std::process::exit(1);
        }
    }
}

/// The canonical daemon log path: `<base_dir>/csq-daemon.log`.
///
/// Kept as one helper so the detached mode and the launchd/systemd service
/// mode cannot drift onto different files — a split would leave an operator
/// reading a log the running daemon is not writing, which is the failure
/// this whole path exists to prevent.
pub fn daemon_log_path(base_dir: &Path) -> PathBuf {
    base_dir.join("csq-daemon.log")
}

/// Opens the daemon log for APPEND, creating it 0600.
///
/// Append (never truncate): a detached start must not wipe lines the service
/// mode or a previous run wrote. 0600 because the log carries account labels,
/// which are email addresses (`security.md` §2 — the log is an audit-trail
/// surface, not world-readable chat).
fn open_daemon_log_for_append(base_dir: &Path) -> Result<std::fs::File> {
    if let Some(parent) = daemon_log_path(base_dir).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let path = daemon_log_path(base_dir);
    let f = opts
        .open(&path)
        .with_context(|| format!("could not open {}", path.display()))?;
    // `mode()` applies only on CREATE, so an existing file keeps whatever
    // permissions it had. Tighten it explicitly — a log created by an older
    // csq (or by launchd, which uses its own default) may be world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(f)
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

    // Detach stdin from the terminal — the daemon never reads it.
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .context("could not open /dev/null")?;
    cmd.stdin(devnull.try_clone().context("stdin dup")?);

    // stdout/stderr go to the SAME rolling log the launchd/systemd service
    // mode writes (`ensure_managed_daemon_plist` sets this exact path), NOT
    // to /dev/null.
    //
    // Routing them to /dev/null discarded every line a detached daemon ever
    // emitted. Because `tracing` only writes WARN+ here, that meant the one
    // channel reporting real faults was silently destroyed for the mode
    // explicitly documented as "survives terminal close" — i.e. the mode a
    // long-running host actually uses.
    //
    // This is not hypothetical. Kimi dropped the `used` field from its
    // `/usages` payload; the poller detected it correctly and emitted
    // "possible API contract drift" on every tick. Nobody could read it, two
    // slots showed a frozen quota for days, and the cause was only found by
    // starting a FOREGROUND daemon with stdout captured by hand. The warning
    // was right the whole time and had nowhere to go.
    //
    // `log_gc.rs` already garbage-collects `csq-daemon.log.<date>` siblings,
    // so the rest of the system already assumes this file exists.
    //
    // Best-effort by design: if the log cannot be opened (read-only $HOME,
    // full disk, permissions), fall back to /dev/null and start anyway.
    // Losing logs is bad; refusing to start the daemon over logs is worse.
    match open_daemon_log_for_append(base_dir) {
        Ok(log) => {
            cmd.stdout(log.try_clone().context("stdout dup")?);
            cmd.stderr(log);
        }
        Err(e) => {
            tracing::warn!(
                error_kind = "daemon_log_open_failed",
                reason = %e,
                "detached daemon: could not open the log file — output will be discarded"
            );
            cmd.stdout(devnull.try_clone().context("stdout dup")?);
            cmd.stderr(devnull.try_clone().context("stderr dup")?);
        }
    }

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

/// The managed launchd job's label. The plist builder emits this same literal;
/// `launchd_label_matches_plist` pins the two together so this probe can never
/// drift into confidently answering about a job that does not exist.
#[cfg(any(target_os = "macos", test))]
pub(crate) const LAUNCHD_LABEL: &str = csq_core::daemon::recovery::LAUNCHD_LABEL;

/// True when a MANAGED launchd job is currently LOADED for this user.
///
/// `launchctl list <label>` exits 0 when the job is loaded and non-zero when it
/// is not (measured 2026-09-12 on macOS 25.6: 0 loaded, 113 for an unknown
/// label), so the probe discriminates — it is not a check that answers the same
/// way under both hypotheses (`instrument-discipline.md` MUST-1).
///
/// A probe that cannot RUN at all (no `launchctl`, spawn refused) answers
/// `false`. That is the conservative direction: csq stays silent rather than
/// printing recovery advice naming a supervisor that may not exist.
#[cfg(target_os = "macos")]
fn launchd_job_is_loaded() -> bool {
    std::process::Command::new("launchctl")
        .arg("list")
        .arg(LAUNCHD_LABEL)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn launchd_job_is_loaded() -> bool {
    false
}

/// Advisory printed after a SUCCESSFUL `csq daemon stop` on a machine whose
/// daemon is launchd-managed.
///
/// Pure so it is testable without a live launchd: the caller supplies the
/// probe's answer. Returns `None` when unmanaged — an unmanaged stop needs no
/// explanation.
///
/// WHY THIS EXISTS: the managed plist sets `KeepAlive={SuccessfulExit:false}`,
/// which respawns the daemon on a CRASH and deliberately NOT after a clean
/// stop (that "stopped stays stopped" behaviour is intended — see
/// `build_launchd_plist`). The gap was never the policy; it was that `stop`
/// printed "csq daemon stopped" and said nothing about having just disarmed
/// the supervisor, so the refresher stayed off silently until tokens expired
/// and every CLI demanded a fresh login. Observed 2026-09-12.
fn managed_stop_advisory(managed: bool) -> Option<String> {
    if !managed {
        return None;
    }
    Some(format!(
        "\nNOTE: this machine runs the daemon under a MANAGED launchd job.\n\
         \x20     Its KeepAlive policy respawns the daemon on a CRASH but NOT after a\n\
         \x20     clean stop, so it will stay stopped. The token refresher and usage\n\
         \x20     pollers are now OFF; tokens expire while they are off, and the CLIs\n\
         \x20     will eventually require a fresh login.\n\n\
         \x20     {}\n",
        csq_core::daemon::recovery::recovery_guidance_for(
            csq_core::daemon::recovery::RecoveryPlatform::MacOs,
            csq_core::daemon::recovery::DaemonHost::Launchd,
        )
    ))
}

/// Advisory printed BEFORE an unsupervised `csq daemon start` on a machine whose
/// daemon is launchd-managed.
///
/// Pure, for the same reason as [`managed_stop_advisory`].
///
/// WHY THIS EXISTS: `handle_start` runs the daemon in the FOREGROUND, as a child
/// of the invoking shell. Started from a terminal tab, an agent session, or a
/// background job, it dies when that parent dies — and launchd will not revive
/// it, because it only respawns on a crash exit and never saw one. The operator
/// sees "csq daemon started" and reasonably believes supervision was restored.
/// Observed 2026-09-12: a `stop` + foreground `start` pair left the machine with
/// no refresher at all once the session ended.
fn unsupervised_start_advisory(managed: bool) -> Option<String> {
    if !managed {
        return None;
    }
    Some(format!(
        "WARNING: a MANAGED launchd job exists for this daemon, and this start\n\
         \x20        BYPASSES it. The daemon below is a child of the current shell and\n\
         \x20        dies with it — when the terminal tab, agent session, or background\n\
         \x20        job that started it exits. launchd will NOT revive it: it respawns\n\
         \x20        only on a crash exit, and a parent's death is not one it sees.\n\n\
         \x20     {}\n",
        csq_core::daemon::recovery::recovery_guidance_for(
            csq_core::daemon::recovery::RecoveryPlatform::MacOs,
            csq_core::daemon::recovery::DaemonHost::Launchd,
        )
    ))
}

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> Result<std::path::PathBuf> {
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("foundation.terrene.csq.plist"))
}

/// Build the launchd plist XML for the given binary path and log path.
/// Exported for unit-testing the generated XML.
///
/// The MANAGED form (daemon-auth-resilience Wave B):
/// - `ProgramArguments` runs `<exe> daemon start --supervised` — the
///   crash-restart supervisor loop, NOT the foreground daemon.
/// - `KeepAlive={SuccessfulExit:false}` restarts the process ONLY on a
///   non-zero/crash exit; a clean `csq daemon stop` (SIGTERM → exit 0)
///   stays stopped.
/// - `ThrottleInterval=10` bounds launchd's respawn rate under a crash
///   loop (its own floor is 10s; stated explicitly for clarity).
///
/// `exe` MUST be a real file OUTSIDE the app bundle (see
/// [`resolve_managed_daemon_exe`]) — a bundle path is misdetected as
/// Desktop mode by `mode::detect()` and would launch the whole app.
#[cfg(target_os = "macos")]
pub fn build_launchd_plist(exe: &Path, log_path: &Path) -> String {
    // XML-escape: launchd plists are XML 1.0. An unescaped `&`/`<`/`>` in a
    // path (relocated $HOME, unusual install dir) yields a malformed plist
    // that `launchctl load` rejects — which, via the best-effort desktop
    // caller, silently skips the managed-daemon install. Escaping keeps the
    // plist well-formed for ANY path and closes a same-UID injection vector
    // now that the exe can originate from a PATH walk.
    let exe_str = xml_escape(&exe.display().to_string());
    let log_str = xml_escape(&log_path.display().to_string());
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
		<string>--supervised</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Adaptive</string>
	<key>StandardOutPath</key>
	<string>{log_str}</string>
	<key>StandardErrorPath</key>
	<string>{log_str}</string>
</dict>
</plist>
"#
    )
}

/// Minimal XML text escaper for plist `<string>` values (XML 1.0).
#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Resolve the binary path to bake into the managed plist's
/// `ProgramArguments[0]`.
///
/// MUST be a real file OUTSIDE the app bundle so `mode::detect()`
/// resolves it to CLI mode: a bundle path (`.../Contents/MacOS/csq`) is
/// misdetected as Desktop mode by [`crate::mode::detect`] and would
/// launch the whole desktop app instead of the daemon (an internal journal entry).
///
/// Prefers the current exe when it is itself a standalone CLI binary
/// (the `csq daemon install` case, run from a terminal `csq`); falls
/// back to the persistent shim (`~/.local/bin/csq`) for the desktop
/// bundle case where `current_exe()` is the misdetected bundle binary.
#[cfg(target_os = "macos")]
fn resolve_managed_daemon_exe() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy();
        let in_bundle =
            s.contains("/Contents/MacOS/") || s.contains(".app/") || s.contains(".AppImage");
        if !in_bundle && exe.is_file() {
            return Some(exe);
        }
    }
    csq_core::cli_deps::cli_shim::resolve_shim_target()
}

/// Outcome of an idempotent managed-plist install/repair.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPlistOutcome {
    /// Plist was absent and has been written + loaded.
    Installed,
    /// Plist existed but drifted from the expected content; rewritten + reloaded.
    Repaired,
    /// Plist already matched the expected content; nothing changed.
    AlreadyCurrent,
}

/// Idempotently installs or repairs the launchd-managed daemon plist
/// (daemon-auth-resilience Wave B). Safe to call on every desktop launch:
/// - Absent → write + `launchctl load` → [`ManagedPlistOutcome::Installed`].
/// - Present but drifted → unload + rewrite + reload → [`ManagedPlistOutcome::Repaired`].
/// - Present + byte-identical → no-op → [`ManagedPlistOutcome::AlreadyCurrent`].
///
/// The managed plist runs `<shim> daemon start --supervised` under
/// `KeepAlive={SuccessfulExit:false}`, so the token refresher survives
/// the desktop app quitting or crashing — the structural fix for the
/// mass-token-expiry incident (an internal journal entry).
///
/// Best-effort by contract: the desktop caller MUST treat any `Err` as
/// non-fatal (a launchctl hiccup must never block app launch).
#[cfg(target_os = "macos")]
pub fn ensure_managed_daemon_plist() -> Result<ManagedPlistOutcome> {
    let plist_path = launchd_plist_path()?;
    let exe = resolve_managed_daemon_exe()
        .context("could not resolve a managed-daemon binary path (no CLI shim available)")?;
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
    // Same helper the detached mode uses, so the two cannot drift onto
    // different files and leave an operator reading a log nothing writes.
    let log_path = daemon_log_path(&home.join(".claude").join("accounts"));
    let expected = build_launchd_plist(&exe, &log_path);

    // Idempotent: if the on-disk content already matches, do nothing —
    // and (critically) skip the `launchctl load`, which returns non-zero
    // for an already-loaded agent.
    if let Ok(existing) = std::fs::read_to_string(&plist_path) {
        if existing == expected {
            return Ok(ManagedPlistOutcome::AlreadyCurrent);
        }
    }
    let drifted = plist_path.exists();

    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "could not create LaunchAgents directory at {}",
                parent.display()
            )
        })?;
    }

    // A drifted plist must be unloaded before the rewrite so launchd picks
    // up the new ProgramArguments on the reload (best-effort; the agent may
    // not currently be loaded).
    if drifted {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .status();
    }

    if let Err(e) = std::fs::write(&plist_path, &expected) {
        let _ = std::fs::remove_file(&plist_path);
        return Err(e)
            .with_context(|| format!("could not write plist to {}", plist_path.display()));
    }

    // On ANY `launchctl load` failure (spawn error or non-zero exit), remove
    // the freshly-written plist. Otherwise the content-match fast-path at the
    // top of this function would report `AlreadyCurrent` on the next call —
    // permanently skipping the load retry and leaving the managed daemon
    // UNLOADED while reporting success, which silently defeats Wave B's
    // after-app-quit coverage (redteam R2 finding 6; restores the pre-Wave-B
    // `platform_install` cleanup that this extraction dropped).
    match std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            let _ = std::fs::remove_file(&plist_path);
            anyhow::bail!("launchctl load failed with exit code {:?}", status.code());
        }
        Err(e) => {
            let _ = std::fs::remove_file(&plist_path);
            return Err(e).context("could not run launchctl load");
        }
    }

    Ok(if drifted {
        ManagedPlistOutcome::Repaired
    } else {
        ManagedPlistOutcome::Installed
    })
}

#[cfg(target_os = "macos")]
fn platform_install() -> Result<()> {
    // Idempotent drift-repair (Wave B): re-running `csq daemon install`
    // refreshes a drifted plist instead of the old "already installed, do
    // nothing". The desktop app calls the same `ensure_managed_daemon_plist`
    // on launch, so the two converge on one managed plist.
    let outcome = ensure_managed_daemon_plist()?;
    let plist_path = launchd_plist_path()?;
    match outcome {
        ManagedPlistOutcome::AlreadyCurrent => {
            eprintln!("csq daemon service already installed and current.");
            eprintln!("  Plist:   {}", plist_path.display());
        }
        ManagedPlistOutcome::Installed => {
            eprintln!("csq daemon service installed and started.");
            eprintln!("  Plist:   {}", plist_path.display());
        }
        ManagedPlistOutcome::Repaired => {
            eprintln!("csq daemon service configuration repaired and reloaded.");
            eprintln!("  Plist:   {}", plist_path.display());
        }
    }
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
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
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
        // Windows has no SIGTERM. `csq daemon stop` fires a per-user
        // named event; the daemon waits on it here (via a blocking
        // thread) alongside Ctrl-C for the foreground case (an internal ticket). If
        // the event cannot be created (an exceptional kernel condition),
        // fall back to Ctrl-C only so the daemon still runs.
        match csq_core::daemon::create_shutdown_event() {
            Ok(event) => {
                // WaitForSingleObject blocks a thread; run it off the
                // async runtime so the select! below stays responsive.
                let event_wait = tokio::task::spawn_blocking(move || {
                    event.wait_blocking();
                });
                tokio::select! {
                    _ = event_wait => tracing::info!("shutdown event received"),
                    r = tokio::signal::ctrl_c() => {
                        r.expect("failed to install Ctrl-C handler");
                        tracing::info!("Ctrl-C received");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not create Windows shutdown event; \
                     `csq daemon stop` will not signal this daemon — \
                     Ctrl-C only"
                );
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to install Ctrl-C handler");
                tracing::info!("Ctrl-C received");
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Renders the daemon's refresh posture for `csq daemon status`.
///
/// A follower is a deliberate, operator-set state, so it is stated on every
/// status read rather than only when something is wrong; a follower that has
/// gone stale (no leader is covering it) additionally lists the expired slots,
/// because the alternative is an unexplained 401 later. The leader default is
/// printed as a single quiet line so the common single-host case stays terse.
fn print_posture_lines(base_dir: &Path) {
    use csq_core::daemon::posture::{self, PostureSource};

    let eff = posture::load(base_dir);
    eprintln!("  Posture:  {}", eff.posture.as_str());

    if let PostureSource::Unreadable(ref why) = eff.source {
        eprintln!(
            "            ! {} is unreadable ({why}) — this host has stood down to",
            posture::POSTURE_FILE_NAME
        );
        eprintln!("              follower and will NOT refresh tokens. Fix or delete the file.");
    }

    if !eff.is_follower() {
        return;
    }

    eprintln!("            This host never refreshes OAuth tokens; a leader host does.");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let expired = posture::expired_slots(base_dir, now_ms);
    if expired.is_empty() {
        return;
    }
    eprintln!(
        "            ! {} slot(s) have an EXPIRED token — no leader is covering them:",
        expired.len()
    );
    for e in &expired {
        eprintln!(
            "                slot {} ({}) expired {}m ago",
            e.slot,
            e.surface,
            e.expired_for_secs / 60
        );
    }
    eprintln!("            → start/repair the leader daemon, or run");
    eprintln!("              `csq daemon posture leader` to make THIS host the refresher.");
}

/// Runs `csq daemon posture [leader|follower]`.
///
/// With no role, prints the current posture and where it came from. With a
/// role, persists it to `<base_dir>/daemon-posture.json`. The running daemon
/// re-reads that file on its next refresher tick (≤5 minutes), so no restart
/// is needed — and unlike a CLI flag or a plist environment entry, the setting
/// survives the desktop app rewriting the LaunchAgent plist.
pub fn handle_posture(base_dir: &Path, role: Option<&str>) -> Result<()> {
    use csq_core::daemon::posture::{self, DaemonPosture, PostureSource};

    let Some(role) = role else {
        let eff = posture::load(base_dir);
        println!("{}", eff.posture.as_str());
        match eff.source {
            PostureSource::Default => eprintln!(
                "  source: default (no {} on disk)",
                posture::POSTURE_FILE_NAME
            ),
            PostureSource::File => {
                eprintln!("  source: {}", posture::posture_path(base_dir).display())
            }
            PostureSource::Unreadable(why) => eprintln!(
                "  source: {} is UNREADABLE ({why}); stood down to follower",
                posture::posture_path(base_dir).display()
            ),
        }
        return Ok(());
    };

    let posture_value = match role.to_ascii_lowercase().as_str() {
        "leader" => DaemonPosture::Leader,
        "follower" => DaemonPosture::Follower,
        // Fail loudly on an unrecognised role rather than defaulting: silently
        // picking one would leave the operator believing they had set the other.
        other => {
            anyhow::bail!("unknown posture {other:?} — expected `leader` or `follower`");
        }
    };

    posture::save(base_dir, posture_value)
        .with_context(|| format!("writing {}", posture::posture_path(base_dir).display()))?;

    println!("{}", posture_value.as_str());
    match posture_value {
        DaemonPosture::Follower => {
            eprintln!("  This host will stop refreshing OAuth tokens within one refresher");
            eprintln!("  tick (≤5 min). Usage polling, IPC, handle-dir sweep and keychain");
            eprintln!("  sync are unaffected. Make sure another host is the leader.");
        }
        DaemonPosture::Leader => {
            eprintln!("  This host will refresh OAuth tokens within one refresher tick");
            eprintln!("  (≤5 min). Ensure no OTHER host sharing these accounts is also a");
            eprintln!("  leader — two leaders invalidate each other's refresh tokens.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Structural guard: BOTH daemon twins MUST map an audit-verify summary to
    /// an `AuditHealth` through the shared producer
    /// `AuditHealth::from_verify_result`, never by constructing a clean verdict
    /// by hand.
    ///
    /// THE DEFECT THIS GUARDS (2026-09-13). `1a1d6976` taught
    /// `from_verify_result` to return `TailVerified { skipped }` on a truncated
    /// scan, and named three machine-readable surfaces it would make agree:
    /// `csq doctor --json`, `csq audit verify --json`, and
    /// `GET /api/audit/health`. It reached the first two, which call
    /// `from_verify_result`. It did NOT reach the third: the daemon's startup
    /// snapshot — which `daemon::server::audit_health_handler` serves verbatim
    /// and `csq daemon status` prints — was built by two hand-written arms in
    /// these twins that never consulted `limit_exceeded_count`. On the same
    /// chain, `doctor` said `tail_verified` while `/api/audit/health` said
    /// `verified`.
    ///
    /// The reason it looked complete is worth keeping: that commit rested on
    /// the new variant forcing five `match` sites to declare their handling.
    /// Exhaustiveness binds CONSUMERS of a type; it cannot make a hand-rolled
    /// PRODUCER emit a variant (`guard-reader-writer-parity.md` MUST NOT #2).
    /// So no compiler check could have caught this, and none will catch its
    /// recurrence — hence a structural guard.
    ///
    /// WHAT THIS INSTRUMENT CAN AND CANNOT DISCRIMINATE
    /// (`instrument-discipline.md` MUST-1). It REDs when a twin stops calling
    /// `from_verify_result`, and when either twin gains a line that constructs
    /// `Verified` / `TailVerified` / `Degraded` outside a `match` pattern. It
    /// is lexical, so it does NOT prove the call is on the startup path, and it
    /// does not see a construction assembled indirectly (via a helper, or a
    /// `let` bound elsewhere). It scans production code only — it stops at the
    /// `#[cfg(test)]` boundary, where fixtures legitimately construct verdicts.
    ///
    /// A line counts as a pattern (not a construction) when it contains `=>`,
    /// or begins with `|`, or is followed by a line beginning with `|` — the
    /// three shapes the real `match` arms take. A tail-expression construction
    /// is followed by `}`, so it is flagged.
    #[test]
    fn daemon_twins_produce_audit_health_through_the_shared_mapper() {
        const TWINS: [&str; 2] = [
            "src/cli/commands/daemon.rs",
            "src/desktop/daemon_supervisor.rs",
        ];
        const VARIANTS: [&str; 3] = [
            "AuditHealth::Verified",
            "AuditHealth::TailVerified",
            "AuditHealth::Degraded",
        ];

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut violations: Vec<String> = Vec::new();

        for twin in TWINS {
            let path = manifest_dir.join(twin);
            // Normalize line endings: a Windows checkout with `core.autocrlf`
            // turns `\n#[cfg(test)]\n` into `\n#[cfg(test)]\r\n`, the boundary
            // below is never found, the TEST fixtures are scanned as production,
            // and they are flagged for constructing verdicts (measured on the
            // Windows runner 2026-09-25). `.gitattributes` now pins `*.rs` to LF;
            // this keeps the scan correct on a checkout made before that.
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("daemon twin {twin} unreadable: {e}"))
                .replace("\r\n", "\n");

            // Production code only: fixtures below the test boundary
            // legitimately construct verdicts.
            let production = match content.find("\n#[cfg(test)]\n") {
                Some(idx) => &content[..idx],
                None => &content[..],
            };

            assert!(
                production.contains("from_verify_result"),
                "daemon twin {twin} no longer calls AuditHealth::from_verify_result — \
                 its audit-health verdict is being produced some other way. Every twin \
                 MUST share the one producer, or the surfaces that report audit health \
                 drift apart (see this test's doc comment)."
            );

            let lines: Vec<&str> = production.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if !VARIANTS.iter().any(|v| trimmed.contains(v)) {
                    continue;
                }
                if trimmed.contains("=>") || trimmed.starts_with('|') {
                    continue;
                }
                let next_is_alternation = lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.starts_with("//"))
                    .is_some_and(|l| l.starts_with('|'));
                if next_is_alternation {
                    continue;
                }
                violations.push(format!("{twin}:{}: {trimmed}", i + 1));
            }
        }

        assert!(
            violations.is_empty(),
            "daemon twin(s) construct an AuditHealth verdict by hand instead of \
             deriving it from AuditHealth::from_verify_result. A hand-built verdict \
             cannot learn a new variant, which is exactly how a truncated scan kept \
             reporting whole-chain `Verified` on GET /api/audit/health after the other \
             two surfaces were fixed. Offending line(s):\n{}",
            violations.join("\n")
        );
    }

    // ── launchd advisories (PURE — compiled on every platform) ──────────
    //
    // Deliberately OUTSIDE `mod macos`: `managed_stop_advisory` and
    // `unsupervised_start_advisory` are not cfg-gated, so gating their tests
    // to macOS would leave them unexercised on Linux and Windows while still
    // reporting a green suite. A test that does not RUN is not evidence
    // (`instrument-discipline.md` MUST-2) — these were written inside the
    // macOS module first and 616 tests were "filtered out" with zero matches.
    #[test]
    fn advisories_are_silent_when_unmanaged() {
        // An unmanaged machine gets no launchd advice — naming a supervisor
        // that does not exist would send the operator to a command that fails.
        assert!(managed_stop_advisory(false).is_none());
        assert!(unsupervised_start_advisory(false).is_none());
    }

    #[test]
    fn managed_stop_advisory_names_the_consequence_and_the_recovery() {
        let note = managed_stop_advisory(true).expect("managed stop must advise");
        // The CONSEQUENCE: not merely "it stopped", but that it stays stopped
        // and what that costs. This is the sentence whose absence cost a
        // machine its refresher on 2026-09-12.
        assert!(
            note.contains("NOT after a"),
            "must say it does not auto-restart: {note}"
        );
        assert!(
            note.contains("stay stopped"),
            "must say it stays stopped: {note}"
        );
        assert!(note.contains("expire"), "must name the token cost: {note}");
        // The RECOVERY, exact and runnable.
        assert!(
            note.contains("launchctl kickstart -k") && note.contains(LAUNCHD_LABEL),
            "must give the runnable recovery command: {note}"
        );
    }

    #[test]
    fn unsupervised_start_advisory_names_the_shell_lifetime_trap() {
        let warning =
            unsupervised_start_advisory(true).expect("managed + foreground start must warn");
        assert!(
            warning.contains("BYPASSES"),
            "must say it bypasses launchd: {warning}"
        );
        assert!(
            warning.contains("dies with it"),
            "must say the daemon dies with the shell: {warning}"
        );
        assert!(
            warning.contains("NOT revive"),
            "must say launchd will not revive it: {warning}"
        );
        assert!(
            warning.contains("launchctl kickstart -k") && warning.contains(LAUNCHD_LABEL),
            "must give the supervised alternative: {warning}"
        );
    }

    #[test]
    fn daemon_recovery_advisories_verify_loaded_executable_before_restart() {
        for text in [
            managed_stop_advisory(true).unwrap(),
            unsupervised_start_advisory(true).unwrap(),
        ] {
            assert!(
                text.find("correct the intended service executable")
                    .unwrap()
                    < text.find("launchctl kickstart").unwrap()
            );
            assert!(text.contains("restarting the same old binary does not fix"));
            assert!(text.contains("Program/ProgramArguments[0]"));
            assert!(!text.contains("daemon stop && csq daemon start"));
            eprintln!("{text}");
        }
    }

    use super::*;

    // ── audit-verify startup timeout derivation (Defect 1) ─────────────

    /// At the record_limit DEFAULT (10,000), the derived timeout must be
    /// strictly greater than the old fixed 5s default that measurably
    /// failed under load on an 11,449-record chain (host load ~100-190),
    /// and strictly less than the 30s an operator found sufficient at a
    /// HIGHER record_limit override — the interval this function's value
    /// is required to clear, per the two measured data points.
    #[test]
    fn default_record_limit_clears_the_known_insufficient_5s_with_margin() {
        let secs = derive_audit_verify_timeout_secs(10_000);
        assert!(
            secs > 5,
            "5s measurably failed under load on an 11,449-record chain; \
             the derived default must clear it: got {secs}s"
        );
        assert_eq!(
            secs, 16,
            "ceil(10_000 * 0.215 * 7.0 / 1000) = ceil(15.05) = 16; got {secs}"
        );
    }

    /// A near-zero record_limit must not derive a near-zero timeout — fixed
    /// per-run overhead (process/tokio-task spin-up, the EATP-chain check)
    /// exists regardless of record count, so the MIN floor must bind.
    #[test]
    fn tiny_record_limit_clamps_to_the_min_floor() {
        assert_eq!(
            derive_audit_verify_timeout_secs(1),
            AUDIT_VERIFY_TIMEOUT_MIN_SECS
        );
        assert_eq!(
            derive_audit_verify_timeout_secs(0),
            AUDIT_VERIFY_TIMEOUT_MIN_SECS
        );
    }

    /// A large `CSQ_AUDIT_VERIFY_LIMIT` override (the exact shape of the
    /// value the maintainer set to work around Defect 2) must not derive
    /// an unbounded startup-blocking timeout — the MAX ceiling must bind
    /// so a misconfigured cap cannot turn a genuinely hung verify into a
    /// multi-minute "is the daemon even starting?" wait.
    #[test]
    fn large_record_limit_override_clamps_to_the_max_ceiling() {
        assert_eq!(
            derive_audit_verify_timeout_secs(100_000),
            AUDIT_VERIFY_TIMEOUT_MAX_SECS
        );
    }

    /// The derivation is monotone non-decreasing in record_limit within the
    /// unclamped region — a larger configured cap must never derive a
    /// SMALLER timeout than a smaller one.
    #[test]
    fn timeout_is_monotone_in_record_limit() {
        let small = derive_audit_verify_timeout_secs(1_000);
        let default = derive_audit_verify_timeout_secs(10_000);
        let large = derive_audit_verify_timeout_secs(30_000);
        assert!(small <= default, "{small} <= {default}");
        assert!(default <= large, "{default} <= {large}");
    }

    // ── audit-verify background retry (bounded, never wedges past shutdown) ──
    //
    // What is and is not covered here, stated plainly (per
    // `user-path-verification.md` / `instrument-discipline.md`): the pure
    // backoff derivation and the "already operational -> no retry spawned"
    // and "shutdown cancels promptly" contracts are exercised directly below
    // and are deterministic. Full end-to-end promotion (startup Unknown ->
    // later attempt Verified -> `is_operational()` flips true on the shared
    // handle -> anchor task starts) is NOT covered by a fast unit test here:
    // `attempt_audit_verify` calls the real `verify_chain` against the
    // filesystem with no injection seam, so forcing a genuine `Unknown` on
    // the first attempt and a genuine `Verified` on a later one deterministically
    // (without sleeping for a real multi-second timeout, which would be slow
    // and load-sensitive exactly the way the originating incident was) would
    // require either a dependency-injection refactor of `attempt_audit_verify`
    // (out of this shard's scope — that function is deliberately shared,
    // unforked, with the blocking startup path per its own doc) or an
    // `#[ignore]`d slow/flaky test. Recorded here rather than silently omitted.

    /// Backoff before attempt 0 is exactly `verify_timeout_secs` (the base
    /// case), and it doubles on each subsequent attempt.
    #[test]
    fn retry_backoff_doubles_from_the_verify_timeout() {
        let base = 16;
        assert_eq!(audit_verify_retry_backoff_secs(0, base), 16);
        assert_eq!(audit_verify_retry_backoff_secs(1, base), 32);
        assert_eq!(audit_verify_retry_backoff_secs(2, base), 64);
        assert_eq!(audit_verify_retry_backoff_secs(3, base), 128);
    }

    /// The backoff schedule is clamped at
    /// `AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS` — an operator's large
    /// `CSQ_AUDIT_VERIFY_LIMIT` override must not turn the retry loop into an
    /// hours-long wait between attempts.
    #[test]
    fn retry_backoff_is_clamped() {
        let huge_base = 10_000;
        assert_eq!(
            audit_verify_retry_backoff_secs(5, huge_base),
            AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS
        );
        // The shift itself must not overflow for a pathological attempt count.
        assert_eq!(
            audit_verify_retry_backoff_secs(u32::MAX, huge_base),
            AUDIT_VERIFY_RETRY_BACKOFF_MAX_SECS
        );
    }

    /// RED without the fix: before this change, a startup `Unknown` had no
    /// path back to operational short of a restart — there was no retry
    /// function to call at all. GREEN with it: an already-operational
    /// startup result spawns NOTHING (`None`) — the retry exists only to
    /// cover the `Unknown` case, never to duplicate work on a healthy chain.
    #[test]
    fn no_retry_spawned_when_startup_already_operational() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let shared = csq_core::audit::new_shared(csq_core::audit::AuditHealth::Verified);
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle = spawn_audit_verify_retry(
                &csq_core::audit::AuditHealth::Verified,
                std::env::temp_dir(),
                shared,
                None,
                csq_core::audit::AuditSinkConfig::default(),
                shutdown,
            );
            assert!(
                handle.is_none(),
                "an already-operational startup result must not spawn a retry task"
            );
        });
    }

    /// CONTRACT (an internal ticket redteam LOW-1) proof: the retry task idle-loops on
    /// `shutdown` rather than returning early on its own (it never reads as
    /// a spurious daemon-session fault) — but it MUST still react to
    /// `shutdown` PROMPTLY rather than blocking for its full backoff/attempt
    /// budget. Cancelling `shutdown` immediately after spawn must let the
    /// task's `JoinHandle` resolve well within one test-timeout window, long
    /// before the (multi-second, in a real daemon) first backoff would have
    /// elapsed on its own.
    #[tokio::test]
    async fn retry_task_exits_promptly_on_shutdown_without_promoting() {
        let shared = csq_core::audit::new_shared(csq_core::audit::AuditHealth::Unknown {
            reason: "audit_verify_timeout".to_string(),
        });
        let shutdown = tokio_util::sync::CancellationToken::new();
        let handle = spawn_audit_verify_retry(
            &csq_core::audit::AuditHealth::Unknown {
                reason: "audit_verify_timeout".to_string(),
            },
            std::env::temp_dir(),
            std::sync::Arc::clone(&shared),
            None,
            csq_core::audit::AuditSinkConfig::default(),
            shutdown.clone(),
        )
        .expect("an Unknown startup result must spawn a retry task");

        // Cancel immediately — well before the real backoff (>=
        // AUDIT_VERIFY_TIMEOUT_MIN_SECS == 5s) could ever elapse.
        shutdown.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle.1)
            .await
            .expect("retry task must exit promptly on shutdown, not wedge")
            .expect("retry task must not panic on the shutdown path");

        // No attempt ever ran (cancelled during the pre-attempt backoff
        // sleep), so the shared handle must still read Unknown — shutdown
        // must never be misread as a promotion.
        assert!(
            !shared.read().expect("lock").is_operational(),
            "a cancelled-before-first-attempt retry must not promote audit_health"
        );
    }

    // ── detached-mode logging (the observability defect) ──────────────

    /// The detached daemon routed stdout AND stderr to /dev/null, so a
    /// `-d` daemon — the mode documented as "survives terminal close" —
    /// discarded every line it ever emitted. Since `tracing` only writes
    /// WARN+ here, the sole channel reporting real faults was destroyed
    /// for the mode a long-running host actually uses.
    ///
    /// Worked case: Kimi dropped `used` from `/usages`; the poller
    /// emitted "possible API contract drift" every tick; two slots showed
    /// frozen quota for days; the cause was found only by hand-capturing
    /// a FOREGROUND daemon's stdout.
    #[test]
    fn detached_daemon_log_is_the_same_file_the_service_mode_writes() {
        let base = PathBuf::from("/Users/alice/.claude/accounts");
        // The literal the macOS plist test pins, inlined so this test is not
        // macOS-gated — the detached mode and the systemd service mode share
        // this path on Linux too.
        assert_eq!(
            super::daemon_log_path(&base),
            PathBuf::from("/Users/alice/.claude/accounts/csq-daemon.log"),
            "detached and service modes MUST write one file — a split \
             leaves the operator reading a log nothing is writing"
        );
    }

    #[test]
    fn daemon_log_opens_append_and_0600_and_does_not_truncate() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let path = super::daemon_log_path(base);
        std::fs::write(&path, b"pre-existing line\n").unwrap();

        // Deliberately world-readable first: a log created by an older
        // csq, or by launchd's default umask, carries account labels —
        // which are email addresses.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        {
            use std::io::Write;
            let mut f = super::open_daemon_log_for_append(base).unwrap();
            writeln!(f, "second line").unwrap();
        }

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.starts_with("pre-existing line"),
            "must APPEND — a detached start must not wipe what the \
             service mode or a prior run wrote: {body:?}"
        );
        assert!(body.contains("second line"), "new line missing: {body:?}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "log carries account emails — must be tightened even when \
                 it already existed world-readable"
            );
        }
    }

    #[test]
    fn daemon_log_is_created_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert!(!super::daemon_log_path(base).exists());
        let _ = super::open_daemon_log_for_append(base).unwrap();
        assert!(
            super::daemon_log_path(base).exists(),
            "a first detached start must create the log, not fail"
        );
    }

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
        fn launchd_label_matches_plist() {
            // Parity guard: the probe's label and the plist's label are two
            // separate literals. If they drift, `launchctl list` answers about a
            // job that does not exist and BOTH advisories go silent forever —
            // failing open on exactly the state they exist to announce
            // (`guard-reader-writer-parity.md` MUST-1).
            let plist = build_launchd_plist(Path::new("/bin/csq"), Path::new("/tmp/csq.log"));
            assert!(
                plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")),
                "probe label `{LAUNCHD_LABEL}` is absent from the generated plist: {plist}"
            );
        }

        #[test]
        fn plist_contains_daemon_start_supervised_args() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — the managed plist runs the SUPERVISED daemon.
            assert!(
                plist.contains("<string>daemon</string>")
                    && plist.contains("<string>start</string>")
                    && plist.contains("<string>--supervised</string>"),
                "plist missing `daemon start --supervised` args: {plist}"
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
        fn plist_sets_keep_alive_restart_on_crash_only() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — KeepAlive is a dict `{SuccessfulExit: false}` so
            // launchd restarts on crash but leaves a clean stop stopped.
            let keep_alive_pos = plist
                .find("<key>KeepAlive</key>")
                .expect("KeepAlive key missing");
            let after = &plist[keep_alive_pos..];
            // KeepAlive must open a <dict> (NOT a bare <true/>) whose first
            // key is SuccessfulExit=false — restart on crash, not on a clean
            // stop. `<dict>` must precede the SuccessfulExit pair.
            let dict_pos = after.find("<dict>").expect("KeepAlive not a dict");
            let succ_pos = after
                .find("<key>SuccessfulExit</key>")
                .expect("KeepAlive dict missing SuccessfulExit");
            assert!(dict_pos < succ_pos, "KeepAlive dict malformed: {plist}");
            let succ_after = &after[succ_pos..];
            assert!(
                succ_after.starts_with("<key>SuccessfulExit</key>")
                    && succ_after[..40.min(succ_after.len())].contains("<false/>"),
                "KeepAlive SuccessfulExit must be false: {plist}"
            );
        }

        #[test]
        fn plist_escapes_xml_metachars_in_paths() {
            // A path with XML metacharacters (`&`, `<`, `>`) or a literal
            // `</string>` must NOT break out of the <string> element or
            // produce malformed XML — otherwise launchctl rejects the plist
            // and the managed daemon silently never installs (L1).
            let exe = PathBuf::from("/Users/a&b/</string><key>x</key>/csq");
            let log = PathBuf::from("/Users/a&b/log.txt");

            let plist = build_launchd_plist(&exe, &log);

            // The raw metacharacters must be escaped, not present verbatim
            // inside the interpolated value.
            assert!(
                plist.contains("/Users/a&amp;b/&lt;/string&gt;&lt;key&gt;x&lt;/key&gt;/csq"),
                "exe path not XML-escaped: {plist}"
            );
            // No unescaped standalone `&` survives (every `&` starts an entity).
            for (i, _) in plist.match_indices('&') {
                let tail = &plist[i..];
                assert!(
                    tail.starts_with("&amp;")
                        || tail.starts_with("&lt;")
                        || tail.starts_with("&gt;")
                        || tail.starts_with("&quot;")
                        || tail.starts_with("&apos;"),
                    "unescaped '&' at offset {i}: {plist}"
                );
            }
        }

        #[test]
        fn plist_sets_throttle_interval() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert — respawn rate is bounded under a crash loop.
            assert!(
                plist.contains("<key>ThrottleInterval</key>")
                    && plist.contains("<integer>10</integer>"),
                "plist missing ThrottleInterval=10: {plist}"
            );
        }

        /// `ProcessType` MUST be `Adaptive`, never `Background`.
        ///
        /// launchd throttles `Background` jobs hard — low CPU/IO priority, and
        /// on a loaded machine they are descheduled for long stretches. That is
        /// correct for maintenance work and WRONG for csq's daemon, whose whole
        /// job is a 5-minute token-refresh cycle plus synchronous IPC for
        /// `csq status` / `csq run`. Observed starving at load 190-280 on the
        /// maintainer host; `Adaptive` starts Background and is promoted to
        /// Interactive when the job is actually working, which is the shape
        /// this daemon needs.
        ///
        /// This assertion previously required `Background` — it pinned the
        /// defect, so every hand-repair of the plist was reverted by the next
        /// desktop launch (which rewrites it from this template). Both halves
        /// are on the record: `internal-design-docs`
        /// § HOST CONFIG CHANGED sets Adaptive and carries the measurement
        /// above, and `.../HANDOFF-2026-09-12-windows-link-parity.md` § 3
        /// records it back on `Background` the next day.
        #[test]
        fn plist_sets_process_type_adaptive_not_background() {
            // Arrange
            let exe = exe_path();
            let log = log_path();

            // Act
            let plist = build_launchd_plist(&exe, &log);

            // Assert
            assert!(
                plist.contains("<key>ProcessType</key>\n\t<string>Adaptive</string>"),
                "ProcessType must be Adaptive: {plist}"
            );
            assert!(
                !plist.contains("<string>Background</string>"),
                "ProcessType must NOT be Background (launchd starves it): {plist}"
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

        // Mirrors the real `DaemonCmd::Start` shape (incl. the Wave B
        // `--supervised` flag and its `conflicts_with = "background"`) so
        // clap integration is tested without spawning a process.
        #[derive(clap::Subcommand, Debug)]
        enum TestDaemonCmd {
            Start {
                #[arg(short = 'd', long = "background")]
                background: bool,
                #[arg(long = "supervised", hide = true, conflicts_with = "background")]
                supervised: bool,
            },
        }

        #[test]
        fn background_flag_long_form_parses() {
            // Arrange + Act
            let cli = TestCli::try_parse_from(["csq", "daemon", "start", "--background"])
                .expect("--background should parse");

            // Assert
            let TestCmd::Daemon {
                action:
                    TestDaemonCmd::Start {
                        background,
                        supervised,
                    },
            } = cli.command;
            assert!(background, "--background should set flag to true");
            assert!(!supervised, "supervised should default to false");
        }

        #[test]
        fn background_flag_short_form_parses() {
            // Arrange + Act
            let cli =
                TestCli::try_parse_from(["csq", "daemon", "start", "-d"]).expect("-d should parse");

            // Assert
            let TestCmd::Daemon {
                action: TestDaemonCmd::Start { background, .. },
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
                action:
                    TestDaemonCmd::Start {
                        background,
                        supervised,
                    },
            } = cli.command;
            assert!(!background, "background should default to false");
            assert!(!supervised, "supervised should default to false");
        }

        #[test]
        fn supervised_flag_parses() {
            // Arrange + Act — Wave B: the launchd plist passes --supervised.
            let cli = TestCli::try_parse_from(["csq", "daemon", "start", "--supervised"])
                .expect("--supervised should parse");

            // Assert
            let TestCmd::Daemon {
                action:
                    TestDaemonCmd::Start {
                        background,
                        supervised,
                    },
            } = cli.command;
            assert!(supervised, "--supervised should set flag to true");
            assert!(!background, "background should default to false");
        }

        #[test]
        fn supervised_and_background_conflict() {
            // Arrange + Act — the two run-modes are mutually exclusive.
            let result =
                TestCli::try_parse_from(["csq", "daemon", "start", "--supervised", "--background"]);

            // Assert
            assert!(
                result.is_err(),
                "--supervised and --background must conflict"
            );
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

    // ── regression: the 5 sink kinds `resolve_anchor_sink` previously had NO
    // arm for at all (s3, azure, gcp, azure-sql, customer-body-store) ─────────
    //
    // Before this fix, `resolve_anchor_sink` matched only `"rekor"` and
    // `"csq-ledger"`; every other catalogued sink name — even with its
    // feature compiled in — fell to the catch-all `other` arm and returned
    // `None`. Configuration (`AuditSinkConfig::set_sink`, gated by
    // `validate_sink_compiled_in`, which DOES have an arm for all 7 kinds)
    // would succeed, `csq doctor` would render the sink as active, and the
    // daemon would never spawn an anchor task. This test proves each of the
    // 5 missing kinds now resolves to `Some` when its feature is compiled —
    // it RED's against the pre-fix resolver (which has no arm, so these
    // sub-tests could not even reach a `Some` branch; run without the fix
    // and each assertion below fails with `None`).
    #[test]
    fn resolve_anchor_sink_resolves_all_seven_catalogued_kinds() {
        use csq_core::audit::AuditSinkConfig;

        #[cfg(feature = "s3-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "s3".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&cfg);
            assert!(
                result.is_some(),
                "sink=\"s3\" must resolve to Some when s3-sink feature is compiled"
            );
            assert_eq!(result.unwrap().name(), "s3");
        }
        #[cfg(not(feature = "s3-sink"))]
        {
            let cfg = AuditSinkConfig {
                sink: "s3".to_string(),
                ..Default::default()
            };
            assert!(resolve_anchor_sink(&cfg).is_none());
        }

        #[cfg(feature = "azure-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "azure".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&cfg);
            assert!(
                result.is_some(),
                "sink=\"azure\" must resolve to Some when azure-sink feature is compiled"
            );
            assert_eq!(result.unwrap().name(), "azure");
        }
        #[cfg(not(feature = "azure-sink"))]
        {
            let cfg = AuditSinkConfig {
                sink: "azure".to_string(),
                ..Default::default()
            };
            assert!(resolve_anchor_sink(&cfg).is_none());
        }

        #[cfg(feature = "gcp-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "gcp".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&cfg);
            assert!(
                result.is_some(),
                "sink=\"gcp\" must resolve to Some when gcp-sink feature is compiled"
            );
            assert_eq!(result.unwrap().name(), "gcp");
        }
        #[cfg(not(feature = "gcp-sink"))]
        {
            let cfg = AuditSinkConfig {
                sink: "gcp".to_string(),
                ..Default::default()
            };
            assert!(resolve_anchor_sink(&cfg).is_none());
        }

        #[cfg(feature = "azure-sql-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "azure-sql".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&cfg);
            assert!(
                result.is_some(),
                "sink=\"azure-sql\" must resolve to Some when azure-sql-sink feature is compiled"
            );
            assert_eq!(result.unwrap().name(), "azure-sql");
        }
        #[cfg(not(feature = "azure-sql-sink"))]
        {
            let cfg = AuditSinkConfig {
                sink: "azure-sql".to_string(),
                ..Default::default()
            };
            assert!(resolve_anchor_sink(&cfg).is_none());
        }

        #[cfg(feature = "customer-body-store-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "customer-body-store".to_string(),
                ..Default::default()
            };
            let result = resolve_anchor_sink(&cfg);
            assert!(
                result.is_some(),
                "sink=\"customer-body-store\" must resolve to Some when \
                 customer-body-store-sink feature is compiled"
            );
            assert_eq!(result.unwrap().name(), "customer-body-store");
        }
        #[cfg(not(feature = "customer-body-store-sink"))]
        {
            let cfg = AuditSinkConfig {
                sink: "customer-body-store".to_string(),
                ..Default::default()
            };
            assert!(resolve_anchor_sink(&cfg).is_none());
        }
    }

    // ── regression: a resolved sink's WIRING reaches the spawn site ────────
    //
    // `resolve_anchor_sink_resolves_all_seven_catalogued_kinds` proves the
    // resolver returns `Some`. That is necessary but not sufficient — a
    // `Some` that never reaches `daemon::spawn_anchor_task` at all (the real
    // production call site, gated on `if let Some(sink) = anchor_sink`)
    // would reproduce the original defect with better-looking code. This
    // test proves, per new kind, using the REAL production functions (not a
    // reimplementation):
    //
    // 1. the resolved sink's `append`/`verify_at` round-trip through the
    //    trait boundary without erroring or panicking (the panic case is
    //    exactly what `customer_body_store_live_transport_does_not_panic_in_async_context`,
    //    csq-core, exists to catch — see that test's doc comment);
    // 2. `csq_core::daemon::spawn_anchor_task` accepts the resolved sink and
    //    returns `Some(handle)` — i.e. a background task is actually
    //    spawned. Before `6861cac4`, `resolve_anchor_sink` returned `None`
    //    for these kinds, so this call site was never reached at all.
    //
    // WHAT THIS TEST DOES **NOT** PROVE (named per `instrument-discipline.md`
    // MUST-1 — a security review of the prior name, "…_actually_anchors",
    // correctly flagged it as over-claiming): for `s3`/`azure`/`gcp`/
    // `azure-sql` (and `rekor`), the current `LedgerSink` impl is an
    // in-memory `Mutex<HashMap<..>>` mock substrate whose `append` cannot
    // fail — `Ok(SinkReceipt)` is UNCONDITIONAL, nothing leaves the process,
    // and this test's green result is IDENTICAL whether the sink durably
    // anchors or silently drops everything. It cannot discriminate that
    // property, because no mock-backed kind can ever red it. The property
    // "this sink is mock-backed, not a durable witness" is proven instead
    // by `sink_config::tests::is_mock_backed_sink_matches_the_current_catalog_state`
    // (csq-core) and surfaced to the operator via `SinkDoctorSnapshot::mock_backend`
    // + the `anchor_sink_mock_backend` WARN at resolve time — NOT by this test.
    #[tokio::test]
    #[allow(unused_imports)]
    async fn resolve_anchor_sink_new_kinds_reach_the_spawn_site() {
        use csq_core::audit::anchor::test_helpers::sample_signed_record;
        use csq_core::audit::AuditSinkConfig;

        #[cfg(feature = "s3-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "s3".to_string(),
                ..Default::default()
            };
            let sink = resolve_anchor_sink(&cfg).expect("s3 must resolve to Some");
            assert_eq!(sink.name(), "s3");

            let record = sample_signed_record(0, "01JZ000000000000000000S3S3");
            let receipt = sink
                .append(&record)
                .await
                .expect("s3 sink append must succeed");
            assert_eq!(receipt.sink.as_str(), "s3");
            let fetched = sink
                .verify_at(&record.record_id)
                .await
                .expect("s3 sink verify_at must find the appended record");
            assert_eq!(fetched.record_id, record.record_id);

            let dir = tempfile::TempDir::new().unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle =
                daemon::spawn_anchor_task(dir.path().to_path_buf(), cfg, sink, shutdown.clone());
            assert!(
                handle.is_some(),
                "spawn_anchor_task must spawn a task for a resolved s3 sink"
            );
            shutdown.cancel();
            if let Some(h) = handle {
                let _ = h.join.await;
            }
        }

        #[cfg(feature = "azure-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "azure".to_string(),
                ..Default::default()
            };
            let sink = resolve_anchor_sink(&cfg).expect("azure must resolve to Some");
            assert_eq!(sink.name(), "azure");

            let record = sample_signed_record(0, "01JZ000000000000000000ARAR");
            let receipt = sink
                .append(&record)
                .await
                .expect("azure sink append must succeed");
            assert_eq!(receipt.sink.as_str(), "azure");
            let fetched = sink
                .verify_at(&record.record_id)
                .await
                .expect("azure sink verify_at must find the appended record");
            assert_eq!(fetched.record_id, record.record_id);

            let dir = tempfile::TempDir::new().unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle =
                daemon::spawn_anchor_task(dir.path().to_path_buf(), cfg, sink, shutdown.clone());
            assert!(
                handle.is_some(),
                "spawn_anchor_task must spawn a task for a resolved azure sink"
            );
            shutdown.cancel();
            if let Some(h) = handle {
                let _ = h.join.await;
            }
        }

        #[cfg(feature = "gcp-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "gcp".to_string(),
                ..Default::default()
            };
            let sink = resolve_anchor_sink(&cfg).expect("gcp must resolve to Some");
            assert_eq!(sink.name(), "gcp");

            let record = sample_signed_record(0, "01JZ000000000000000000GPGP");
            let receipt = sink
                .append(&record)
                .await
                .expect("gcp sink append must succeed");
            assert_eq!(receipt.sink.as_str(), "gcp");
            let fetched = sink
                .verify_at(&record.record_id)
                .await
                .expect("gcp sink verify_at must find the appended record");
            assert_eq!(fetched.record_id, record.record_id);

            let dir = tempfile::TempDir::new().unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle =
                daemon::spawn_anchor_task(dir.path().to_path_buf(), cfg, sink, shutdown.clone());
            assert!(
                handle.is_some(),
                "spawn_anchor_task must spawn a task for a resolved gcp sink"
            );
            shutdown.cancel();
            if let Some(h) = handle {
                let _ = h.join.await;
            }
        }

        #[cfg(feature = "azure-sql-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "azure-sql".to_string(),
                ..Default::default()
            };
            let sink = resolve_anchor_sink(&cfg).expect("azure-sql must resolve to Some");
            assert_eq!(sink.name(), "azure-sql");

            let record = sample_signed_record(0, "01JZ000000000000000000SQSQ");
            let receipt = sink
                .append(&record)
                .await
                .expect("azure-sql sink append must succeed");
            assert_eq!(receipt.sink.as_str(), "azure-sql");
            let fetched = sink
                .verify_at(&record.record_id)
                .await
                .expect("azure-sql sink verify_at must find the appended record");
            assert_eq!(fetched.record_id, record.record_id);

            let dir = tempfile::TempDir::new().unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle =
                daemon::spawn_anchor_task(dir.path().to_path_buf(), cfg, sink, shutdown.clone());
            assert!(
                handle.is_some(),
                "spawn_anchor_task must spawn a task for a resolved azure-sql sink"
            );
            shutdown.cancel();
            if let Some(h) = handle {
                let _ = h.join.await;
            }
        }

        #[cfg(feature = "customer-body-store-sink")]
        {
            let cfg = AuditSinkConfig {
                sink: "customer-body-store".to_string(),
                ..Default::default()
            };
            let sink = resolve_anchor_sink(&cfg).expect("customer-body-store must resolve to Some");
            assert_eq!(sink.name(), "customer-body-store");

            // Unlike the 4 in-memory mock sinks above, `resolve_anchor_sink`
            // constructs `CustomerBodyStoreSink` with its LIVE `reqwest`
            // transport (`CustomerBodyStoreConfig::default()`'s
            // `http://127.0.0.1:8080`, per its doc comment — this sink is the
            // operator-residency control and genuinely dials a real
            // endpoint). No such endpoint is listening in this test, so the
            // append/verify_at round trip cannot succeed here — the property
            // this block proves is instead the one this fix's own regression
            // test (`customer_body_store_live_transport_does_not_panic_in_async_context`,
            // csq-core) exists for: calling `append`/`verify_at` on the LIVE
            // sink from a real async runtime returns an ordinary
            // `SinkError::Unreachable`, not a panic. Before that fix, this
            // call would have PANICKED the whole test with tokio's "Cannot
            // drop a runtime in a context where blocking is not allowed" —
            // `reqwest::blocking` called inline on an async worker thread.
            let record = sample_signed_record(0, "01JZ000000000000000000CBCB");
            let append_result = sink.append(&record).await;
            assert!(
                matches!(
                    append_result,
                    Err(csq_core::audit::SinkError::Unreachable { .. })
                ),
                "expected Unreachable (no live endpoint), got {append_result:?}"
            );

            let dir = tempfile::TempDir::new().unwrap();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let handle =
                daemon::spawn_anchor_task(dir.path().to_path_buf(), cfg, sink, shutdown.clone());
            assert!(
                handle.is_some(),
                "spawn_anchor_task must spawn a task for a resolved customer-body-store sink"
            );
            shutdown.cancel();
            if let Some(h) = handle {
                let _ = h.join.await;
            }
        }
    }
}
