//! Codex process supervisor for `csq run`/`csq exec`'s interactive Codex
//! launch paths (shard S2 of the cross-slot swap-resume feature).
//!
//! `csq run`'s interactive codex spawn (both the layer-bypass `Inherit`
//! path and the capability-layer `WithLayer { mode: Interactive, .. }`
//! path) no longer `exec`s codex on unix. Instead it spawns codex as a
//! CHILD and supervises it here, so that a `csq swap` invoked as a
//! `!`-shell-out from INSIDE that codex session (see
//! `csq_core::session::codex_supervisor` module doc + `swap.rs`
//! `refuse_or_handoff_if_inside_live_codex_ancestor`) can hand the swap back
//! to THIS process instead of exec'ing over its own (child) process image.
//!
//! `csq exec`'s codex path (`exec.rs::spawn_capture_codex`) already
//! spawns codex as a bounded-timeout, non-interactive `codex exec --json`
//! child with no live terminal a user could shell out from — it already
//! satisfies "never exec" and needs no supervision, so it is untouched by
//! this shard.
//!
//! ## The contract with `csq swap` (shard S3, built in parallel)
//!
//! `csq swap`, when invoked from inside a live codex session, verifies
//! the supervisor recorded in the CURRENT handle dir
//! ([`csq_core::session::codex_supervisor::verify_supervisor_alive`]),
//! writes a [`csq_core::session::codex_supervisor::SwapRequest`] into
//! that SAME handle dir, then sends `SIGUSR1` to the supervisor pid. On
//! `SIGUSR1` the supervisor here consumes the request
//! (`take_swap_request`) and, if one is pending, tears down the current
//! child and relaunches on the target slot.
//!
//! ## Relaunch mechanism
//!
//! The handle dir a supervised codex child runs under is named
//! `term-<pid>` where `pid` is THIS process's own pid — it does not
//! change across a swap (no `exec`, no fork). So relaunching onto a
//! different slot cannot simply call
//! `csq_core::session::create_handle_dir_codex` again for the new
//! account: that function's own orphan-detection would see the OLD
//! `term-<pid>` dir with a `.live-pid` naming THIS (still-alive) process
//! and refuse to remove it ("handle dir is in use by live PID").
//!
//! `swap.rs::exec_replace_swap` solves the equivalent problem for its
//! own (cross-surface, `exec`-based) swap path via
//! `swap::rename_handle_dir_to_sweep_tombstone`. Shard S3 promoted that
//! helper to `pub(crate)` and `tombstone_handle_dir` below now calls it
//! directly rather than carrying its own copy of the
//! `.sweep-tombstone-swap-<pid>-<nanos>` naming convention (the daemon
//! sweep's `cleanup_stale_tombstones` reaps ANY `.sweep-tombstone-`
//! prefixed entry generically either way, so this dedup changes no
//! on-disk behavior — only removes the duplicated logic).
use anyhow::{anyhow, Result};
use csq_core::accounts::markers;
// PRIMARY DIRECTIVE (round 6): `SwapAuditCorrelation` is used unconditionally
// (in `run_supervised`/`run_unsupervised`'s signatures — swap has no
// non-unix analog, but the correlation TYPE still has to type-check there),
// so this import is no longer `#[cfg(unix)]`-gated. Every other `sup::`
// usage that IS unix-only stays inside its own `#[cfg(unix)]` block.
use csq_core::session::codex_supervisor as sup;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

use super::run::fail_loud_on_audit_write_failure;

/// Graceful-stop bound between `SIGTERM` and `SIGKILL` when tearing down a
/// codex child ahead of a cross-slot relaunch (item 3 of the governing
/// task).
///
/// Derivation (two named outcomes, margin stated on each side per
/// `tooling-self-verification.md` Rule 3): codex's own on-exit flush is
/// its sqlite rollout-state write, which `codex_command`'s doc comment
/// (this crate, `run.rs`) already treats as fast relative to the
/// multi-second `daemon/mcp_rewrite.rs::startup_timeout_ms = 5000` this
/// codebase uses elsewhere for "a child subprocess needs a moment to
/// start up cleanly." A HEALTHY exit-on-SIGTERM (flush + quit) is
/// expected to land in the low hundreds of milliseconds; a WEDGED child
/// (stuck on a syscall, deadlocked) will still be alive after several
/// seconds. 3000ms sits with >10x headroom over the healthy case and
/// still keeps a swapping user from waiting more than ~3s when codex is
/// genuinely wedged before we `SIGKILL` and relaunch anyway.
#[cfg(unix)]
const GRACEFUL_STOP_MS: u64 = 3_000;

/// Poll interval while waiting (bounded, unbounded-normal-exit, or
/// graceful-stop) for the child via `try_wait` on the supervisor's
/// synchronous select loop.
#[cfg(unix)]
const POLL_MS: u64 = 25;

/// FM-4 exit codes for "a termination signal arrived in the window between
/// `graceful_stop` tearing down the outgoing child and the relaunch actually
/// happening — exit cleanly rather than relaunching a session nobody asked
/// to continue." Standard `128 + signal` convention, matching
/// [`exit_code_for`] below.
#[cfg(unix)]
const EXIT_CODE_SIGHUP_DURING_SWAP: i32 = 128 + libc::SIGHUP;
#[cfg(unix)]
const EXIT_CODE_SIGTERM_DURING_SWAP: i32 = 128 + libc::SIGTERM;

// D-F6 (round 7): the fixed-deadline override machinery this file used to
// carry here (`force_validation_deadline` / `VALIDATION_DEADLINE_OVERRIDE`)
// was retired along with the fixed `sup::VALIDATION_DEADLINE_SECS` bound it
// overrode — `drive_child` now derives its budget dynamically, per-request,
// from `sup::remaining_validation_budget`. A test that needs a small budget
// constructs a `SwapRequest` whose `requested_at` is old enough that the
// dynamic budget is small, rather than overriding a global.

/// Outcome of driving a supervised child to completion.
#[cfg(unix)]
enum Outcome {
    /// The child exited on its own (no swap request was ever consumed).
    Exited(std::process::ExitStatus),
    /// `child.try_wait()` itself errored (rare — reaping race / OS error).
    SpawnFailed(std::io::Error),
    /// A valid swap request was consumed while a child was running; the
    /// child has ALREADY been torn down (SIGTERM, bounded wait, SIGKILL
    /// if needed) by the time this variant is produced.
    SwapRequested(sup::SwapRequest),
    /// FM-4: `SIGHUP` or `SIGTERM` arrived after a swap's teardown completed
    /// but before the relaunch happened — exit with the carried code
    /// (`EXIT_CODE_SIGHUP_DURING_SWAP` / `EXIT_CODE_SIGTERM_DURING_SWAP`)
    /// instead of relaunching.
    TerminatedBeforeRelaunch(i32),
}

/// Runs `cmd` as a supervised codex child under `handle_dir`, forwarding
/// signals, and relaunching via `relaunch` on a validated cross-slot swap
/// request.
///
/// `relaunch(target_slot, thread_id, audit_emitter)` is invoked AT MOST
/// ONCE (a swap consumes this whole call — real production callers pass
/// a closure that recurses into `launch_codex`, whose own spawn point
/// reaches back into `run_supervised` for the new child, so "the new
/// child is supervised the same way" without an explicit loop here).
/// `thread_id` is `None` when the request carried no discovered codex
/// thread id (relaunch starts a fresh session rather than guessing with
/// `codex resume --last`).
///
/// On Unix this ignores `SIGINT`/`SIGQUIT` for the supervisor itself (the
/// terminal's process group already delivers both directly to the codex
/// child — forwarding them again would be redundant, and NOT ignoring
/// them would kill the supervisor out from under a live child on a bare
/// Ctrl-C, defeating the entire point of supervision), forwards
/// `SIGTERM`/`SIGHUP` to the child, and treats `SIGUSR1` as "check for a
/// pending swap request."
///
/// On non-Unix (Windows), signal-based supervision/swap has no
/// equivalent (documented gap — `csq swap`'s `SIGUSR1` contract is
/// Unix-only); this spawns + waits exactly as the prior
/// `run.rs::exec_or_spawn` non-unix branch did, with no swap handling.
/// `validate` is a closure `launch_codex` builds from its OWN captured
/// invocation — capability-layer intent, `toggles`, `debug`,
/// `coc_cache_enabled` (item 3 of the governing task — cross-slot
/// swap-resume shard S2 follow-up; F2, round 5) — and is forwarded to
/// [`drive_child`], which calls it on every `SIGUSR1` with a pending
/// request instead of re-deriving those values (a fresh
/// `load_capability_layer_toggles(base_dir)` disk read plus hardcoded
/// `debug=false, coc_cache_enabled=true`, the shape this replaced). So a
/// relaunch's admission preflight validates against the EXACT intent the
/// original launch resolved, never an approximation that could refuse (or
/// wrongly admit) a swap the real, flag-respecting relaunch would have
/// decided differently.
#[allow(clippy::too_many_arguments)]
pub fn run_supervised(
    cmd: Command,
    handle_dir: &Path,
    base_dir: &Path,
    // F2 (round 5): the SAME validate closure `launch_codex` builds from
    // its own captured invocation (toggles, debug, coc_cache_enabled,
    // capability-layer intent) — replaces the previous
    // `capability_layer_enabled: bool, layer_is_auto: bool` pair, which
    // `drive_child` forwarded into a SEPARATE call to
    // `validate_codex_relaunch_target` that re-read persisted toggles from
    // disk and hardcoded `debug`/`coc_cache_enabled` rather than using the
    // real invocation's own values. Called at most once per SIGUSR1 (a
    // refused swap keeps the child running and polling continues), so it
    // is `Fn`, not `FnOnce`.
    // D-F6 close-out (round 8): `Send + Sync + 'static` so `run_supervised`
    // can `Arc` it once here and hand a clone to a fresh worker thread on
    // every `SIGUSR1` `drive_child` services — see that function's doc for
    // why the call itself must not run on the poll loop's own thread.
    validate: impl Fn(u16) -> Result<csq_core::types::AccountNum> + Send + Sync + 'static,
    // F4: threaded down to `exit_cleanly_if_terminating_before_spawn` — see
    // that function's doc for why a relaunch's already-evaluated gate
    // record is finalized as Fail/Reject rather than discarded.
    is_relaunch: bool,
    // PRIMARY DIRECTIVE (round 6): `Some(_)` iff THIS spawn is the relaunch
    // half of an accepted swap request — carries that request's audit
    // chain/correlation identity, so a successful `cmd.spawn()` below can
    // write the correlated `AccountSwap` OUTCOME as `Ok` at the ONE point
    // that actually corresponds to "the relaunch spawn succeeded" (never
    // "the relaunch's entire subsequent session exited successfully" —
    // `relaunch(...)`'s own `Result` answers THAT question, several hours
    // too late for this one). `None` for the primary (non-swap) launch.
    swap_correlation: Option<sup::SwapAuditCorrelation>,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
    relaunch: impl FnOnce(
        u16,
        Option<&str>,
        Option<sup::SwapAuditCorrelation>,
        &mut crate::cli::audit_emit::AuditEmitter,
    ) -> Result<()>,
) -> Result<()> {
    let handle_dir_abs =
        std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());

    #[cfg(unix)]
    {
        // D-F6 close-out (round 8): boxed+`Arc`'d exactly once here — the
        // ONE conversion point from "an owned, Send+Sync+'static closure"
        // to "a handle `drive_child` can cheaply clone onto a fresh worker
        // thread per `SIGUSR1`". See `drive_child`'s doc for why a worker
        // thread exists at all.
        let validate: std::sync::Arc<
            dyn Fn(u16) -> Result<csq_core::types::AccountNum> + Send + Sync,
        > = std::sync::Arc::new(validate);
        run_supervised_unix(
            cmd,
            &handle_dir_abs,
            base_dir,
            &validate,
            is_relaunch,
            swap_correlation,
            audit_emitter,
            relaunch,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = relaunch; // no swap handling on non-unix; see module + fn doc.
        let _ = base_dir; // swap-target validation is unix-only (SIGUSR1 has no non-unix analog).
        let _ = validate; // only consulted on the unix relaunch-validation path.
        let _ = is_relaunch; // only consulted on the unix pre-spawn-signal path (F4).
        run_unsupervised(
            cmd,
            &handle_dir_abs,
            base_dir,
            swap_correlation,
            audit_emitter,
        )
    }
}

/// Shared "no supervision, just spawn+wait" path — used on non-Unix, and
/// as the failure fallback when writing the supervisor record fails on
/// Unix (a record that can never be verified is worse than no
/// supervision at all: `verify_supervisor_alive` fails closed on a
/// missing record, so `csq swap` correctly reports "no live supervisor"
/// rather than a swap request nobody will ever consume).
fn run_unsupervised(
    mut cmd: Command,
    handle_dir_abs: &Path,
    base_dir: &Path,
    swap_correlation: Option<sup::SwapAuditCorrelation>,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Some(corr) = &swap_correlation {
                corr.write_outcome_once(
                    base_dir,
                    csq_core::audit::OpOutcome::Failed {
                        reason: csq_core::audit::op_emit::redact_reason(e.to_string()),
                    },
                );
            }
            let _ = std::fs::remove_dir_all(handle_dir_abs);
            let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            audit_emitter.set_end_ts(end_ts);
            fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            return Err(anyhow!("failed to launch codex: {e}"));
        }
    };
    // PRIMARY DIRECTIVE (round 6): the relaunch's spawn succeeded — this IS
    // the point "Ok" is defined against, never the point the whole
    // subsequent session later exits (see `swap_correlation`'s doc).
    if let Some(corr) = &swap_correlation {
        corr.write_outcome_once(base_dir, csq_core::audit::OpOutcome::Ok);
    }
    let child_pid = child.id();
    if let Err(e) = markers::write_live_cc_pid(handle_dir_abs, child_pid) {
        eprintln!("warning: could not record codex child PID: {e}");
    }
    let status = child.wait();
    let _ = std::fs::remove_dir_all(handle_dir_abs);
    let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    audit_emitter.set_end_ts(end_ts);
    fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
    match status {
        Ok(s) if !s.success() => std::process::exit(s.code().unwrap_or(1)),
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!("failed to wait for codex: {e}")),
    }
}

/// F7: writes the standard terminal-reset escape sequences to stdout,
/// IF AND ONLY IF stdout is a tty. Every exit-instead-of-relaunch path
/// (a signal arrived and this process is about to disappear rather than
/// hand off to a fresh codex session) may be leaving the terminal in
/// whatever state the outgoing/interrupted codex TUI left it in — the
/// alternate screen buffer, cursor hidden, mouse tracking or bracketed
/// paste still enabled, or a pushed Kitty keyboard-protocol flag — with no
/// codex process left alive to restore it on its own way out. Called
/// BEFORE any further message this process prints, so the user's next
/// keystroke (into whatever shell prompt reappears) is not swallowed or
/// misrendered by a mode the departing TUI left active.
///
/// Sequences, in order: exit the alternate screen buffer (`CSI ? 1049 l`),
/// show the cursor (`CSI ? 25 h`), disable X10/normal/SGR mouse tracking
/// (`CSI ? 1000;1002;1003;1006 l`), disable bracketed paste
/// (`CSI ? 2004 l`), and pop any Kitty keyboard-protocol push
/// (`CSI < u`). Best-effort: a write failure here (e.g. a broken pipe on a
/// stdout that is a tty but has since gone away) is not itself a reason to
/// change the exit path's own outcome, so it is silently ignored.
#[cfg(unix)]
fn write_terminal_reset_if_tty() {
    use std::io::{IsTerminal, Write};
    if std::io::stdout().is_terminal() {
        let _ = std::io::stdout()
            .write_all(b"\x1b[?1049l\x1b[?25h\x1b[?1000;1002;1003;1006l\x1b[?2004l\x1b[<u");
        let _ = std::io::stdout().flush();
    }
}

/// C-R4-7: exits immediately — WITHOUT spawning, WITHOUT writing an audit
/// record — when `SIGHUP`/`SIGTERM` has already arrived by the time this is
/// called, immediately before `run_supervised_unix`'s own `cmd.spawn()`.
///
/// This closes the window between a relaunch's own teardown finishing
/// (`graceful_stop` returning inside `drive_child`, which already checks
/// both flags — FM-4) and this SECOND, re-entrant call reaching ITS spawn
/// point: the ~4s of `launch_codex` prep (config materialization, capability-
/// layer flattening, spawn-gate evaluation) that runs in between, during
/// which `drive_child`'s poll loop is not running to catch a termination
/// signal. Spawning a session nobody is there to use, and then having the
/// caller's existing `Outcome::SwapRequested` `Err`-handling report it as a
/// "relaunch failed" with a recovery hint, would be actively misleading —
/// nothing failed, the process was just asked to go away — so this exits
/// directly, mirroring `Outcome::TerminatedBeforeRelaunch`'s exit-code
/// convention, rather than returning an `Err` for that handling to
/// (mis)report.
///
/// F4: on a RELAUNCH (`is_relaunch = true`), `audit_emitter` is the FRESH
/// emitter `launch_codex`'s recursive re-entry built for THIS swap attempt
/// (C-F3/S-F4's doc, above), and `evaluate_codex_spawn_gate` has already
/// run against it (`launch_codex`'s M6 T6.1 gate, run unconditionally
/// before `run_supervised` on every entry — enterprise builds) before this
/// function is ever reached. Discarding that record here would silently
/// drop the swap's own governance verdict; instead it is finalized as a
/// real terminal outcome — same shape as `Outcome::TerminatedBeforeRelaunch`
/// (FM-4, `set_end_ts` + `set_result(Fail, Reject)` + `try_flush_now`) —
/// so a signal-interrupted swap leaves exactly ONE audit event describing
/// it, in the same shape every other "supervisor asked to go away before
/// starting a session" outcome uses.
///
/// On the FIRST launch (`is_relaunch = false`) this call's `audit_emitter`
/// is discarded instead: `AuditEmitter`'s `Drop`/`try_flush_now` always
/// flush whatever record they hold, so this calls
/// [`crate::cli::audit_emit::AuditEmitter::discard`] to take the record
/// without a live-IPC POST or a `.pending/` fallback write — the emitter
/// holds no OS resource beyond that record (no file handle, no lock, no
/// socket opened at construction), so `discard()` releases everything
/// there is to release. Unlike a relaunch's fresh emitter, the first
/// launch's emitter has no swap of its own to report on here — this path
/// fires only in the narrow pre-any-session-ever-existing window, and
/// there is no prior FM-4-shaped precedent for reporting "interrupted
/// before the very first spawn" as a distinct audit event.
/// D-F2 (round 7): `swap_correlation` is `Some(_)` iff THIS call is the
/// relaunch half of an accepted swap request (mirrors `run_supervised`'s own
/// `swap_correlation` parameter — see its doc). If a termination signal
/// arrives in this exact window (between `drive_child` returning
/// `Outcome::SwapRequested` in the OUTER call and this recursive re-entry's
/// own spawn point — up to the ~4s of `launch_codex` prep the module doc
/// above already names), the relaunch's spawn is never reached, so nothing
/// would otherwise write the correlated OUTCOME — the preceding INTENT would
/// sit as a silent orphan indistinguishable from a genuine crash. This
/// function now closes that out as `Failed("terminated before relaunch")`
/// BEFORE the audit-flush + `process::exit` below, matching every OTHER
/// termination-before-relaunch site in this file (`Outcome::
/// TerminatedBeforeRelaunch`'s two branches in `drive_child`, above).
#[cfg(unix)]
fn exit_cleanly_if_terminating_before_spawn(
    handle_dir_abs: &Path,
    base_dir: &Path,
    is_relaunch: bool,
    swap_correlation: Option<&sup::SwapAuditCorrelation>,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) {
    let code = if SIGHUP_FLAG.load(std::sync::atomic::Ordering::SeqCst) {
        EXIT_CODE_SIGHUP_DURING_SWAP
    } else if SIGTERM_FLAG.load(std::sync::atomic::Ordering::SeqCst) {
        EXIT_CODE_SIGTERM_DURING_SWAP
    } else {
        return;
    };
    if let Some(corr) = swap_correlation {
        corr.write_outcome_once(
            base_dir,
            csq_core::audit::OpOutcome::Failed {
                reason: csq_core::audit::RedactedString::from_trusted("terminated before relaunch"),
            },
        );
    }
    let _ = std::fs::remove_file(handle_dir_abs.join(sup::SUPERVISOR_FILE));
    let _ = std::fs::remove_dir_all(handle_dir_abs);
    if is_relaunch {
        use csq_core::audit::{Decision, ResultState};
        let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        audit_emitter.set_end_ts(end_ts);
        audit_emitter.set_result(ResultState::Fail, Decision::Reject);
        fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
    } else {
        audit_emitter.discard();
    }
    write_terminal_reset_if_tty();
    eprintln!(
        "csq: a termination signal arrived before the codex relaunch could \
         start — exiting without starting a new session."
    );
    std::process::exit(code);
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_supervised_unix(
    mut cmd: Command,
    handle_dir_abs: &Path,
    base_dir: &Path,
    // D-F6 close-out (round 8): an `Arc` handle, not a bare `&dyn Fn` — see
    // `run_supervised`'s call site for where it is built, and
    // `drive_child`'s doc for why owning a clone per worker thread matters.
    validate: &std::sync::Arc<dyn Fn(u16) -> Result<csq_core::types::AccountNum> + Send + Sync>,
    is_relaunch: bool,
    swap_correlation: Option<sup::SwapAuditCorrelation>,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
    relaunch: impl FnOnce(
        u16,
        Option<&str>,
        Option<sup::SwapAuditCorrelation>,
        &mut crate::cli::audit_emit::AuditEmitter,
    ) -> Result<()>,
) -> Result<()> {
    // C-R4-2: applied BEFORE the `write_supervisor_record` check/branch
    // below, so BOTH the supervised path AND the `run_unsupervised`
    // fallback (taken on a RELAUNCH whose record write failed — by which
    // point THIS process may already hold `SIG_IGN` for SIGINT/SIGQUIT from
    // an earlier child, see `ignore_signal` below) reset the child's own
    // signal dispositions before it execs. `SIG_IGN` is inherited across
    // fork+exec, so a fallback that skipped this reset would leak an
    // uninterruptible Ctrl-C/Ctrl-\ into that child and everything it
    // execs, exactly the FM-1 hazard this call exists to prevent — the
    // prior revision of this fix applied it only on the supervised branch,
    // which is unreachable on the fallback path.
    //
    // FM-1: every child this supervisor ever spawns — the FIRST one and
    // every RELAUNCH — gets SIGINT/SIGQUIT reset to SIG_DFL in the forked
    // child, before exec. For the first spawn this is a no-op (the
    // supervisor has not yet ignored these signals — see the C-F1 note
    // below). For a RELAUNCH it is load-bearing: by the time
    // `run_supervised_unix` re-enters this function body (the `relaunch`
    // closure recurses synchronously into `launch_codex` -> `run_supervised`
    // -> here, all within the SAME process), `ignore_signal(SIGINT)` /
    // `ignore_signal(SIGQUIT)` below have ALREADY run for the FIRST child —
    // and `SIG_IGN` is inherited across fork+exec (only a caught/handled
    // disposition resets to default). Without this reset, every relaunched
    // codex session — and everything IT execs (`!` shell-outs, MCP servers)
    // — would inherit an uninterruptible Ctrl-C/Ctrl-\ for the rest of ITS
    // life too.
    reset_signal_dispositions_before_exec(&mut cmd);

    // A record that cannot be written is a record that can never be
    // verified (`verify_supervisor_alive` reads back what THIS write
    // produces) — fail open to "no supervision" rather than press on
    // with a swap contract nobody can complete.
    if sup::write_supervisor_record(handle_dir_abs).is_err() {
        eprintln!(
            "warning: could not record codex supervisor state — `csq swap` \
             from inside this session will not be able to hand back a swap"
        );
        return run_unsupervised(
            cmd,
            handle_dir_abs,
            base_dir,
            swap_correlation,
            audit_emitter,
        );
    }

    // C-R4-5/FM-7: the tty's baseline (pre-any-codex-spawn) attributes,
    // cached ONCE per PROCESS rather than re-captured on every entry — see
    // `tty_baseline`'s doc comment for why re-capturing on a relaunch would
    // adopt a possibly-already-corrupted state as the new "original".
    let tty_state = tty_baseline();

    // C-R4-7: a SIGHUP/SIGTERM that arrived in the window between this
    // function being entered (on a RELAUNCH: between `graceful_stop`
    // tearing down the outgoing child and reaching this point — up to the
    // ~4s of `launch_codex` prep, a window `drive_child`'s own poll loop is
    // not running to catch) and this spawn point must not still start a
    // codex session nobody is there to use. See the callee's doc comment
    // for why this exits directly rather than returning an `Err` for the
    // caller's existing (misleading, for this case) "relaunch failed"
    // handling to report.
    exit_cleanly_if_terminating_before_spawn(
        handle_dir_abs,
        base_dir,
        is_relaunch,
        swap_correlation.as_ref(),
        audit_emitter,
    );

    // C-(f): handlers are installed (and the flags left at their
    // ALREADY-false default — see `ensure_signal_handlers_installed`'s doc
    // comment) BEFORE this spawn, never after. A `SIGUSR1` sent by a fast
    // writer immediately after `cmd.spawn()` returns is otherwise a race:
    // if it lands before `drive_child` (previously the sole installer) has
    // run, the OS delivers it under this process's default SIGUSR1
    // disposition (terminate) rather than the flag-setting handler, and the
    // request is silently lost rather than merely delayed.
    ensure_signal_handlers_installed();

    // C-F1: the SIGINT/SIGQUIT ignore MUST be installed AFTER `cmd.spawn()`,
    // never before. `signal(2)` dispositions set to `SIG_IGN` are INHERITED
    // across `exec` (only a caught/handled disposition resets to default) —
    // so ignoring these signals before spawning the child would leak
    // `SIG_IGN` into the codex child (and every descendant it execs: `!`
    // shell-outs, MCP servers), making the whole process TREE
    // uninterruptible by Ctrl-C/Ctrl-\ for the rest of its life. Spawning
    // FIRST means the child inherits whatever the default disposition was
    // at fork/exec time (untouched), and only the supervisor's OWN,
    // strictly-later disposition becomes `SIG_IGN`.
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Some(corr) = &swap_correlation {
                corr.write_outcome_once(
                    base_dir,
                    csq_core::audit::OpOutcome::Failed {
                        reason: csq_core::audit::op_emit::redact_reason(e.to_string()),
                    },
                );
            }
            let _ = std::fs::remove_file(handle_dir_abs.join(sup::SUPERVISOR_FILE));
            let _ = std::fs::remove_dir_all(handle_dir_abs);
            let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            audit_emitter.set_end_ts(end_ts);
            fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            return Err(anyhow!("failed to launch codex: {e}"));
        }
    };
    // PRIMARY DIRECTIVE (round 6): the relaunch's spawn succeeded — write
    // the correlated `AccountSwap` OUTCOME as `Ok` HERE, never later. This
    // is strictly earlier than "the relaunch's entire subsequent session
    // exited successfully" (`relaunch(...)`'s own `Result`, which the
    // `Outcome::SwapRequested` handling below reports on separately) — see
    // `swap_correlation`'s doc for why that distinction is load-bearing.
    if let Some(corr) = &swap_correlation {
        corr.write_outcome_once(base_dir, csq_core::audit::OpOutcome::Ok);
    }

    ignore_signal(libc::SIGINT);
    ignore_signal(libc::SIGQUIT);

    let child_pid = child.id();
    if let Err(e) = markers::write_live_cc_pid(handle_dir_abs, child_pid) {
        eprintln!("warning: could not record codex child PID: {e}");
    }

    let outcome = drive_child(&mut child, handle_dir_abs, base_dir, validate, tty_state);

    match outcome {
        Outcome::Exited(status) => {
            let _ = std::fs::remove_dir_all(handle_dir_abs);
            if status.success() {
                // C-F4: deliberately do NOT set end_ts / flush here. This
                // is the normal (non-swap) terminal exit, and for the
                // `LayerControl::WithLayer` caller (`launch_codex`), the
                // code immediately after THIS call sets
                // `ResultState::Pass, Decision::Accept` + end_ts and relies
                // on that emitter's own `Drop` (or a later `try_flush_now`)
                // to emit the record. `AuditEmitter::try_flush_now` takes
                // the record on first flush; flushing it here FIRST would
                // make every one of those caller-side setters a silent
                // no-op against an already-empty `record: None` — the exact
                // bug this fix removes (the caller's Pass/Accept was never
                // actually recorded). The `LayerControl::Inherit` caller has
                // already set `Degraded`/`Bypass` BEFORE calling
                // `run_supervised`, and sets no end_ts of its own — Drop
                // (best-effort) covers that arm, matching its pre-existing
                // behavior.
                Ok(())
            } else {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                // C-F4: a non-zero exit IS a real, final outcome for this
                // run (the process is about to exit and no caller code
                // after this point will run) — record it as such before
                // flushing, rather than leaving the emitter's placeholder
                // `Degraded`/`Bypass` default (from `build_audit_emitter`)
                // as the last word on a run that actually failed.
                audit_emitter.set_result(ResultState::Fail, Decision::Accept);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                std::process::exit(exit_code_for(status));
            }
        }
        Outcome::SpawnFailed(e) => {
            // `child.try_wait()` errored inside `drive_child`'s poll loop
            // (the initial `cmd.spawn()` already succeeded by this point,
            // above — this is a later, rarer OS-level failure).
            let _ = std::fs::remove_dir_all(handle_dir_abs);
            Err(anyhow!("failed to wait for codex: {e}"))
        }
        Outcome::TerminatedBeforeRelaunch(code) => {
            // FM-4: a SIGHUP/SIGTERM arrived after the outgoing child was
            // torn down but before the relaunch happened — the supervisor
            // itself is being asked to go away, so honor that instead of
            // starting a session nobody will be there to use.
            let _ = std::fs::remove_dir_all(handle_dir_abs);
            use csq_core::audit::{Decision, ResultState};
            let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            audit_emitter.set_end_ts(end_ts);
            audit_emitter.set_result(ResultState::Fail, Decision::Reject);
            fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            // F7: same exit-instead-of-relaunch shape as
            // `exit_cleanly_if_terminating_before_spawn` — the outgoing
            // child's `graceful_stop` teardown may not have run to
            // completion (a raw SIGKILL path skips the child's own
            // terminal-mode restore; see `StopOutcome`'s doc), so reset the
            // terminal before this process disappears too.
            write_terminal_reset_if_tty();
            eprintln!(
                "csq: a termination signal arrived before the codex relaunch could \
                 start — exiting without starting a new session."
            );
            std::process::exit(code);
        }
        Outcome::SwapRequested(req) => {
            println!("Switching this terminal to account {}…", req.target_slot);
            tombstone_handle_dir(handle_dir_abs);

            // PRIMARY DIRECTIVE (round 6): this correlation is shared (via
            // its internal `Rc<Cell<bool>>`) with the copy passed INTO
            // `relaunch(...)` below, which writes `Ok` at the recursive
            // spawn's own success point — the idempotency guard means this
            // outer copy's `Failed` write below is safe to attempt
            // UNCONDITIONALLY on any `Err`: if the inner spawn already
            // succeeded (and wrote `Ok`), this is a silent no-op; if it
            // never reached a spawn at all (a preflight failure inside the
            // relaunch's own `launch_codex` call), this IS the correct and
            // only place that failure's outcome gets recorded.
            let correlation = sup::SwapAuditCorrelation::from_request(&req);

            // C-F3/S-F4: finalize + flush the FIRST run's own emitter as a
            // handed-off swap BEFORE building a FRESH emitter for the
            // relaunch. Reusing the same emitter across both runs would mean
            // whichever run flushes first (via `try_flush_now`, which takes
            // the record) silently no-ops every later setter on the SAME
            // emitter for the OTHER run — collapsing two distinct runs into
            // (at most) one audit record. Two runs, two records.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Degraded, Decision::Bypass);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }

            let mut relaunch_emitter = super::run::build_audit_emitter(
                base_dir,
                csq_core::audit::Surface::Codex,
                format!("csq swap→run account {}", req.target_slot),
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            );
            match relaunch(
                req.target_slot,
                req.thread_id.as_deref(),
                correlation.clone(),
                &mut relaunch_emitter,
            ) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if let Some(corr) = &correlation {
                        corr.write_outcome_once(
                            base_dir,
                            csq_core::audit::OpOutcome::Failed {
                                reason: csq_core::audit::op_emit::redact_reason(e.to_string()),
                            },
                        );
                    }
                    // FM-6: `relaunch_emitter` was built fresh above and may
                    // hold an un-flushed record (e.g. a check inside
                    // `launch_codex` that itself returns Err rather than
                    // calling `process::exit` — FM-5) — finalize it as a
                    // real, final Fail/Reject outcome before this
                    // `process::exit`, which bypasses Drop, would otherwise
                    // lose it silently (`fail_loud_on_audit_write_failure`
                    // itself calls `process::exit` on a `.pending/` write
                    // failure, so this must run BEFORE the exit below, not
                    // after — matching M06's established fail-loud pattern
                    // elsewhere in this crate). `AuditEmitter::try_flush_now`
                    // is idempotent: a record already flushed by a check
                    // inside `relaunch` is a safe no-op here.
                    {
                        use csq_core::audit::{Decision, ResultState};
                        let end_ts =
                            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        relaunch_emitter.set_end_ts(end_ts);
                        relaunch_emitter.set_result(ResultState::Fail, Decision::Reject);
                        fail_loud_on_audit_write_failure(relaunch_emitter.try_flush_now());
                    }
                    let recovery =
                        relaunch_recovery_hint(req.target_slot, req.thread_id.as_deref());
                    // F7: the relaunch never reached a spawn, so the
                    // ORIGINAL child's teardown (`graceful_stop` +
                    // `restore_tty_after_stop`, both already run above) is
                    // this path's only chance to leave the terminal sane
                    // before the recovery hint prints — same rationale as
                    // the other two exit-instead-of-relaunch sites.
                    write_terminal_reset_if_tty();
                    // S-F3: `e` is an arbitrary `anyhow::Error` that may wrap
                    // an upstream/vendor error body — the SAME class of
                    // value `security.md` §2 requires be redacted before it
                    // reaches an operator-facing message, not printed raw.
                    eprintln!(
                        "csq: relaunch onto account {} failed: {}\n\
                         Recover with: {recovery}",
                        req.target_slot,
                        csq_core::error::redact_tokens(&e.to_string())
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Drives `child` to either exit or a validated swap request, forwarding
/// `SIGTERM`/`SIGHUP` and consuming `SIGUSR1`-triggered swap requests
/// along the way. Synchronous poll loop (no tokio runtime) — simplest
/// correct mechanism given `SIGINT`/`SIGQUIT` are handled via `SIG_IGN`
/// above (never delivered to this handler) and the remaining three
/// signals only need "did one arrive since I last checked," which a
/// process-wide `AtomicBool` set from a signal handler answers exactly
/// as well as an async signal stream would, at a fraction of the
/// complexity. D-F6 close-out (round 8): this loop's OWN thread never
/// blocks on `validate` — each admission check runs on a short-lived,
/// detached worker thread instead, so the loop's synchronous poll cadence
/// (and therefore its signal-forwarding responsiveness) holds even while a
/// validation call is outstanding. See the `SIGUSR1` branch below for the
/// worker-thread mechanism.
#[cfg(unix)]
fn drive_child(
    child: &mut std::process::Child,
    handle_dir_abs: &Path,
    base_dir: &Path,
    // D-F6 close-out (round 8): an `Arc` handle rather than a bare `&dyn
    // Fn`. `validate_codex_relaunch_target` carries no internal deadline
    // (see `VERDICT_WAIT_TIMEOUT_SECS`'s doc in `codex_supervisor.rs`), so a
    // genuinely HANGING call must not be run on this poll loop's own
    // thread — that would block SIGTERM/SIGHUP forwarding for as long as
    // the hang lasts, with no bound at all (the elapsed-time check could
    // only ever fire once the call returned, i.e. never). Below, every
    // dispatch clones this `Arc` onto a fresh, detached worker thread and
    // waits on that thread's result via `recv_timeout`, polled at the same
    // `POLL_MS` cadence as this function's own outer loop — so a signal
    // arriving mid-validation is still forwarded within one tick, and an
    // abandoned (never-returning) worker leaves nothing else running: its
    // only externally-visible action is a channel `send`, which is a
    // silently-discarded no-op once this function has moved past the
    // `Timeout` branch and dropped its receiver.
    validate: &std::sync::Arc<dyn Fn(u16) -> Result<csq_core::types::AccountNum> + Send + Sync>,
    tty_state: Option<&TtyRawState>,
) -> Outcome {
    // C-(f): handler installation now happens in `run_supervised_unix`,
    // BEFORE `cmd.spawn()` — not here. Calling it again is a harmless no-op
    // (`SIGNAL_HANDLERS_INIT` is a `std::sync::Once`), kept only so this
    // function does not depend on call-site ordering it cannot itself
    // verify.
    ensure_signal_handlers_installed();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Outcome::Exited(status),
            Ok(None) => {}
            Err(e) => return Outcome::SpawnFailed(e),
        }

        if SIGTERM_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = sup::signal_supervisor(child.id(), libc::SIGTERM);
        }
        if SIGHUP_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = sup::signal_supervisor(child.id(), libc::SIGHUP);
        }
        if SIGUSR1_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
            if let Some(req) = sup::take_swap_request(handle_dir_abs) {
                // C-F4: a request can, in principle, sit unconsumed past
                // `STALE_REQUEST_SECS` before its `SIGUSR1` is ever noticed
                // (this supervisor busy inside `graceful_stop`, or simply
                // slow to reach its next poll tick) — the staleness check
                // the WRITE side already applies
                // (`write_swap_request_if_absent`'s tombstone-retry) is
                // re-checked here, once more, at the point of actually
                // acting on it. A stale request's writer is presumed dead;
                // refuse rather than validate/relaunch against it.
                if sup::is_swap_request_stale(&req) {
                    let correlation = sup::SwapAuditCorrelation::from_request(&req);
                    // C-F7: clear the in-flight marker BEFORE writing the
                    // verdict — see the accept/refuse branches below for the
                    // full rationale (favouring "future swaps stay
                    // unwedged" over "this waiter sees the exact verdict").
                    sup::clear_swap_inflight(handle_dir_abs);
                    if let Err(e) = sup::write_swap_verdict(
                        handle_dir_abs,
                        &sup::SwapVerdict {
                            nonce: req.nonce.clone(),
                            outcome: sup::SwapOutcome::Refused("stale request".to_string()),
                        },
                    ) {
                        eprintln!("warning: could not record the stale-request verdict: {e}");
                    }
                    if let Some(corr) = correlation {
                        corr.write_outcome_once(
                            base_dir,
                            csq_core::audit::OpOutcome::Failed {
                                reason: csq_core::audit::RedactedString::from_trusted(
                                    "stale request",
                                ),
                            },
                        );
                    }
                    eprintln!(
                        "csq: swap to account {} refused — stale request",
                        req.target_slot
                    );
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                }
                // S-F3/C-F2: validate the TARGET before tearing down the
                // CURRENT, still-running child. `take_swap_request` has
                // already consumed the request file above (so a refusal
                // here does not leave it wedged for a retry) — on refusal
                // we print the reason and fall through to keep polling;
                // the current codex session is untouched.
                //
                // F2 (round 5): `validate` is the SAME closure `launch_codex`
                // built from its own captured invocation (toggles, debug,
                // coc_cache_enabled, capability-layer intent) — see that
                // function's call sites — so this admission check runs
                // under the exact intent the real relaunch will run under,
                // never a re-derived approximation.
                //
                // D-F6/S-LOW-1 (round 7): replaces the prior FIXED
                // `sup::VALIDATION_DEADLINE_SECS` (8s) deadline. That bound
                // measured only the validation CALL's own elapsed time and
                // ignored how much of the REQUEST's age was already spent
                // before validation even started — a request aged 3s that
                // then took 7.5s to validate (10.5s total) cleared the fixed
                // 8s check (7.5s < 8s) despite already having blown `csq
                // swap`'s 10s wire by the time its verdict could be written.
                // `remaining_validation_budget` measures the SAME quantity
                // this deadline always meant to protect — time left before
                // `csq swap`'s own `VERDICT_WAIT_TIMEOUT_SECS` wire — against
                // THIS request's actual age, not a fixed constant.
                let write_refusal = |reason: String| {
                    sup::clear_swap_inflight(handle_dir_abs);
                    if let Err(write_err) = sup::write_swap_verdict(
                        handle_dir_abs,
                        &sup::SwapVerdict {
                            nonce: req.nonce.clone(),
                            outcome: sup::SwapOutcome::Refused(reason.clone()),
                        },
                    ) {
                        eprintln!(
                            "warning: could not record the swap timeout verdict: {write_err}"
                        );
                    }
                    if let Some(corr) = sup::SwapAuditCorrelation::from_request(&req) {
                        corr.write_outcome_once(
                            base_dir,
                            csq_core::audit::OpOutcome::Failed {
                                reason: csq_core::audit::RedactedString::from_trusted(
                                    reason.clone(),
                                ),
                            },
                        );
                    }
                    eprintln!(
                        "csq: swap to account {} refused — {reason}",
                        req.target_slot
                    );
                };
                let Some(budget) = sup::remaining_validation_budget(&req) else {
                    // No budget left even BEFORE validation would start —
                    // refuse without spending any of it on a call that
                    // cannot possibly resolve in time.
                    write_refusal("validation budget exhausted".to_string());
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                };
                // `validate` carries no INTERNAL deadline of its own, so the
                // WHOLE call is timed here, and an admission that took
                // longer than `budget` is downgraded to a refusal regardless
                // of what it returned. Without this, a merely slow (not
                // dead) validation could resolve Ok after `csq swap`'s own
                // `VERDICT_WAIT_TIMEOUT_SECS` wait had already expired,
                // accepting a swap the terminal had already given up on and
                // reported "undetermined".
                //
                // D-F6 close-out (round 8): `validate` now runs on a
                // detached WORKER THREAD, and this loop waits for its
                // result via `recv_timeout`, ticked at `POLL_MS` — never a
                // single `recv_timeout(budget)` block, which would
                // reintroduce exactly the bug this closes (the WAIT itself
                // would then be the thing blocking signal forwarding for up
                // to `budget`). Every tick re-checks `SIGTERM_FLAG`/
                // `SIGHUP_FLAG` and forwards immediately, exactly as the
                // outer loop above does — so a signal arriving mid-
                // validation is forwarded within one `POLL_MS` tick,
                // whether or not `validate` ever returns.
                //
                // On timeout the worker is ABANDONED: never joined, never
                // signalled to stop (there is no cancellation point to
                // offer `validate_codex_relaunch_target`). This is
                // structurally safe with respect to THIS supervisor's OWN
                // state rather than merely hoped-safe: `result_tx.send(..)`
                // at the very end of the worker's closure is the only
                // action that could affect what `drive_child` itself later
                // reads or decides, and once this loop moves past the
                // `Timeout`/deadline branch, `result_rx` (and, when this
                // whole `SIGUSR1` iteration completes, `result_tx` too) is
                // dropped; a `send` against a receiver nobody is listening
                // on returns `Err` and does nothing further.
                //
                // Item 3 (S-LOW-1/D-F2) correction: the CALL itself is
                // very much NOT side-effect-free — the real
                // `validate_codex_relaunch_target` this closure wraps can
                // print the enterprise license notice, print the
                // layer-auto-engaged stderr note, and append a line to
                // `coc-roots-seen.jsonl` (`run_capability_layer_preflight`'s
                // `record_root_seen`), all before it ever reaches
                // `result_tx.send`. An abandoned worker does not stop
                // running: it keeps executing those side effects to
                // completion, in the background, for as long as the real
                // admission checks take — it is abandoned only in the
                // sense that nothing here still waits on or acts on its
                // eventual answer. `VALIDATION_IN_FLIGHT` below is what
                // stops those side effects from OVERLAPPING: it caps
                // concurrently-outstanding workers at one per process, so
                // a second `SIGUSR1` arriving while a first (possibly
                // already-abandoned) worker is still running is refused
                // outright rather than starting a second worker that
                // could print/append at the same time.
                if VALIDATION_IN_FLIGHT
                    .compare_exchange(
                        false,
                        true,
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    )
                    .is_err()
                {
                    write_refusal("previous validation still running".to_string());
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                }
                let target_slot = req.target_slot;
                let validate_for_worker = std::sync::Arc::clone(validate);
                let (result_tx, result_rx) = std::sync::mpsc::channel();
                let validate_started = std::time::Instant::now();
                // Item 5 (D-F3, worker-thread hermeticity): `run.rs`'s
                // `.coc/`-walk cwd override is a per-THREAD thread-local
                // (`COC_PREFLIGHT_CWD_OVERRIDE`), so a fixture that sets it
                // on the CALLING thread (this poll loop's own thread, which
                // in every existing test IS the test's own thread — see
                // `run_supervised`'s tests) is invisible to a brand-new OS
                // thread spawned below. Snapshot it HERE, on the calling
                // thread, and re-install it inside the worker's own closure
                // (only when compiled for tests) before invoking `validate`,
                // so a real `validate_codex_relaunch_target` call's `.coc/`
                // walk resolves against the fixture's tmp dir instead of
                // silently falling through to the real process cwd.
                #[cfg(test)]
                let coc_cwd_override =
                    crate::cli::commands::run::coc_preflight_cwd_override_snapshot();
                let spawn_result = std::thread::Builder::new()
                    .name("codex-swap-validate".to_string())
                    .spawn(move || {
                        // Cleared on every exit path, including an
                        // unwinding panic inside `validate_for_worker` —
                        // see `ValidationInFlightGuard`'s doc.
                        let _flight_guard = ValidationInFlightGuard;
                        #[cfg(test)]
                        let _cwd_guard = coc_cwd_override
                            .map(crate::cli::commands::run::force_coc_preflight_cwd);
                        let outcome = validate_for_worker(target_slot);
                        // Discarded on purpose: see the doc above this
                        // block for why a lost send is inert, never a bug.
                        let _ = result_tx.send(outcome);
                    });
                if let Err(e) = spawn_result {
                    // Could not even START the worker thread — the closure
                    // (and therefore `ValidationInFlightGuard`) never ran,
                    // so clear the flag we set above ourselves before
                    // refusing identically to a validation error; never
                    // silently accept.
                    VALIDATION_IN_FLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
                    write_refusal(format!("could not start validation: {e}"));
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                }
                let wait_deadline = validate_started + budget;
                let validate_result = loop {
                    if SIGTERM_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        let _ = sup::signal_supervisor(child.id(), libc::SIGTERM);
                    }
                    if SIGHUP_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        let _ = sup::signal_supervisor(child.id(), libc::SIGHUP);
                    }
                    let now = std::time::Instant::now();
                    if now >= wait_deadline {
                        // The worker never reported within `budget` — refuse
                        // without waiting on it further; it is abandoned per
                        // the doc above.
                        break None;
                    }
                    let tick = Duration::from_millis(POLL_MS).min(wait_deadline - now);
                    match result_rx.recv_timeout(tick) {
                        Ok(outcome) => break Some(outcome),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            // The worker thread died without sending (e.g. it
                            // panicked) — treat as a validation error, not a
                            // silent accept.
                            break Some(Err(anyhow!(
                                "validation worker terminated without a result"
                            )));
                        }
                    }
                };
                let Some(validate_result) = validate_result else {
                    write_refusal("validation timed out".to_string());
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                };
                // The worker DID answer within `budget`'s wait window, but
                // may have crossed `budget` in the brief window between its
                // own elapsed-time and this check (e.g. it answered on the
                // very last tick) — preserves the pre-worker-thread
                // semantics of downgrading a late-but-technically-Ok
                // admission to a refusal (D-F6/S-LOW-1, round 7).
                let deadline_exceeded = validate_started.elapsed() > budget;
                match (validate_result, deadline_exceeded) {
                    (Ok(_account), true) => {
                        write_refusal("validation timed out".to_string());
                        std::thread::sleep(Duration::from_millis(POLL_MS));
                        continue;
                    }
                    (Ok(_account), false) => {
                        // F1 (round 5): the supervisor is the single source
                        // of truth for the swap's VERDICT — write the
                        // ACCEPTED verdict now, BEFORE the current child is
                        // torn down, so `csq swap`'s bounded wait never
                        // observes "accepted" any later than the point past
                        // which this session is already committed to going
                        // away. A write failure is logged but does not
                        // abort the swap (`csq swap`'s own wait times out
                        // and reports "undetermined" — a lost verdict write
                        // must never leave the terminal permanently wedged
                        // reporting "switching").
                        //
                        // PRIMARY DIRECTIVE (round 6): the correlated
                        // AccountSwap audit OUTCOME is deliberately NOT
                        // written here — "Ok" is reserved for the point the
                        // RELAUNCH's spawn actually succeeds (see
                        // `run_supervised_unix`'s `cmd.spawn()` handling),
                        // which is strictly later than "validation admitted
                        // this target." Writing `Ok` here would misreport a
                        // swap that is admitted but never actually relaunches
                        // (e.g. `TerminatedBeforeRelaunch` below) as having
                        // succeeded.
                        if let Err(e) = sup::write_swap_verdict(
                            handle_dir_abs,
                            &sup::SwapVerdict {
                                nonce: req.nonce.clone(),
                                outcome: sup::SwapOutcome::Accepted,
                            },
                        ) {
                            eprintln!(
                                "warning: could not record the swap verdict: {e} \
                                 — proceeding with the relaunch anyway"
                            );
                        }
                        // C-R4-1: no separate "mark in flight" call needed
                        // here — `take_swap_request` above already performed
                        // that atomically, as the SAME step that consumed
                        // the request (see its doc comment). The marker is
                        // already in place through this multi-second
                        // validation call and the teardown below.
                        //
                        // (round 6, item 1): wait, bounded, for a `csq swap`
                        // waiter to CONSUME the verdict just written above
                        // before tearing the child down. `run_supervised`
                        // calls `tombstone_handle_dir` moments after this
                        // function returns `Outcome::SwapRequested` — a
                        // rename of the WHOLE handle dir, verdict file
                        // included — which would strand a waiter still
                        // polling the original path with no file to find:
                        // an accepted swap reported as UNDETERMINED. This
                        // does not eliminate that race (the wait can itself
                        // time out), but it closes it for any waiter that
                        // reads within `VERDICT_CONSUME_WAIT_MS`. The
                        // return value is intentionally ignored: a timed-out
                        // wait is not an error here (see that constant's
                        // doc) — teardown proceeds either way.
                        // D-F7 (round 7): capped to whatever wire time
                        // remains given this REQUEST's own age — waiting the
                        // full fixed constant on a request that has already
                        // consumed most of `csq swap`'s own wait budget
                        // stalls teardown for no benefit (see
                        // `consume_wait_bound`'s doc).
                        let _ = sup::wait_for_verdict_consumed(
                            handle_dir_abs,
                            sup::consume_wait_bound(&req),
                        );
                        // C-R4-5: `graceful_stop`'s own return value no
                        // longer gates the restore (see
                        // `restore_tty_after_stop`'s doc comment for why a
                        // cooperative `SIGTERM` exit is NOT proof the child
                        // itself restored the terminal).
                        graceful_stop(child);
                        restore_tty_after_stop(tty_state, restore_tty_state);

                        // FM-4: a SIGHUP/SIGTERM that arrived WHILE this
                        // supervisor was blocked inside `graceful_stop` (the
                        // main loop above is paused for that whole call, so
                        // neither flag gets its normal per-tick handling)
                        // must not be silently dropped — exit cleanly
                        // instead of relaunching a session nobody is there
                        // to use. This IS "termination before relaunch" — the
                        // spawn point that would write `Ok` is never reached
                        // — so the correlated OUTCOME (if any) is `Failed`
                        // here, not left for `run_supervised_unix` to guess.
                        if SIGHUP_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
                            if let Some(corr) = sup::SwapAuditCorrelation::from_request(&req) {
                                corr.write_outcome_once(
                                    base_dir,
                                    csq_core::audit::OpOutcome::Failed {
                                        reason: csq_core::audit::RedactedString::from_trusted(
                                            "terminated before relaunch (SIGHUP)",
                                        ),
                                    },
                                );
                            }
                            return Outcome::TerminatedBeforeRelaunch(EXIT_CODE_SIGHUP_DURING_SWAP);
                        }
                        if SIGTERM_FLAG.swap(false, std::sync::atomic::Ordering::SeqCst) {
                            if let Some(corr) = sup::SwapAuditCorrelation::from_request(&req) {
                                corr.write_outcome_once(
                                    base_dir,
                                    csq_core::audit::OpOutcome::Failed {
                                        reason: csq_core::audit::RedactedString::from_trusted(
                                            "terminated before relaunch (SIGTERM)",
                                        ),
                                    },
                                );
                            }
                            return Outcome::TerminatedBeforeRelaunch(
                                EXIT_CODE_SIGTERM_DURING_SWAP,
                            );
                        }
                        return Outcome::SwapRequested(req);
                    }
                    (Err(e), _) => {
                        // C-F7: clear the in-flight marker BEFORE writing
                        // the verdict — the opposite order from the earlier
                        // revision, which argued a waiting `csq swap` must
                        // see the refusal reason rather than time out. That
                        // is true, but it optimises the WRONG failure mode:
                        // a crash between the two writes left the marker in
                        // place with the verdict-write already done, which
                        // makes `swap_request_pending` report "pending"
                        // forever for every FUTURE swap attempt even though
                        // THIS one resolved. Clearing first means a crash in
                        // that same window merely times out this ONE
                        // waiter's verdict wait (which `csq swap` already
                        // reports as UNDETERMINED, never as a false
                        // success) while leaving future swaps unwedged.
                        // S-LOW-A / C-B5 (round 8b): was `redact_tokens`
                        // only — blind to a filesystem path embedded in
                        // `e`'s `Display` chain (an `io::Error` from the
                        // relaunch attempt this arm handles can carry
                        // one). `op_emit::redact_reason` covers both
                        // token- and home-path-derived leaks (literal AND
                        // OS-canonicalized `$HOME`) in one call, and
                        // returns the `RedactedString` the OUTCOME write
                        // below needs directly — no second redaction pass.
                        let reason = csq_core::audit::op_emit::redact_reason(e.to_string());
                        sup::clear_swap_inflight(handle_dir_abs);
                        if let Err(write_err) = sup::write_swap_verdict(
                            handle_dir_abs,
                            &sup::SwapVerdict {
                                nonce: req.nonce.clone(),
                                outcome: sup::SwapOutcome::Refused(reason.as_str().to_string()),
                            },
                        ) {
                            eprintln!(
                                "warning: could not record the swap refusal verdict: {write_err}"
                            );
                        }
                        // PRIMARY DIRECTIVE (round 6): the correlated
                        // AccountSwap OUTCOME is `Failed(reason)` — the
                        // supervisor, not `csq swap`, is the authority for
                        // it (see `SwapAuditCorrelation`'s doc).
                        if let Some(corr) = sup::SwapAuditCorrelation::from_request(&req) {
                            corr.write_outcome_once(
                                base_dir,
                                csq_core::audit::OpOutcome::Failed {
                                    reason: reason.clone(),
                                },
                            );
                        }
                        eprintln!(
                            "csq: swap to account {} refused — {reason}",
                            req.target_slot
                        );
                    }
                }
            }
            // No pending request — a SIGUSR1 with nothing to consume is
            // ignored (mirrors `take_swap_request`'s "corrupt request ==
            // no request" posture: there is nothing actionable here).
        }

        std::thread::sleep(Duration::from_millis(POLL_MS));
    }
}

/// Outcome of [`graceful_stop`] — whether the child exited cooperatively on
/// its own `SIGTERM` handling, or had to be `SIGKILL`ed. FM-7: a `SIGKILL`ed
/// process gets no chance to run its own terminal-cleanup (raw-mode
/// restore), so the SUPERVISOR must restore it; a cooperative exit is
/// trusted to have already done so itself.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum StopOutcome {
    ExitedOnTerm,
    Killed,
}

/// `SIGTERM` the child, wait up to [`GRACEFUL_STOP_MS`], then `SIGKILL`
/// and reap. FM-7/typed-ahead: flushes any keystrokes queued by the tty
/// driver (destined for the OUTGOING session) exactly once, at the single
/// exit point, regardless of which branch got there.
#[cfg(unix)]
fn graceful_stop(child: &mut std::process::Child) -> StopOutcome {
    let _ = sup::signal_supervisor(child.id(), libc::SIGTERM);
    let deadline = std::time::Instant::now() + Duration::from_millis(GRACEFUL_STOP_MS);
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break StopOutcome::ExitedOnTerm,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            // C-R4-6: kill every live DESCENDANT of the direct child first,
            // then the direct child itself. An npm-installed `codex` runs
            // the real codex process as a GRANDCHILD of the `node` launcher
            // `Command::spawn` actually started — SIGKILL aimed only at
            // `child.id()` kills the launcher and leaves the real process
            // (and anything IT spawned: MCP servers, `!` shell-outs)
            // running, orphaned from this supervisor's view. Signalling an
            // already-dead pid is a harmless `ESRCH`, so ordering between
            // descendants does not matter.
            //
            // Informational item (round 5): `collect_descendant_pids` is a
            // `ps` SNAPSHOT — between that snapshot and the `kill(2)` call
            // below, a descendant can exit and the OS can recycle its pid
            // for an entirely unrelated process (this supervisor holds no
            // `wait()` on descendants the way it does on `child` itself, so
            // nothing here prevents that). Re-verify each pid's start time
            // (the SAME anti-recycling nonce
            // `csq_core::session::codex_supervisor::process_start_time`
            // already provides for supervisor-identity verification)
            // immediately before signalling it — a mismatch (or the pid
            // having gone from "has a start time" to "unreadable", the
            // exited-and-not-yet-recycled case) means this is no longer the
            // SAME process the snapshot named, so it is skipped rather than
            // signalled.
            let descendants: Vec<(u32, Option<String>)> = collect_descendant_pids(child.id())
                .into_iter()
                .map(|pid| (pid, sup::process_start_time(pid)))
                .collect();
            for pid in descendants_still_matching_snapshot(&descendants) {
                let _ = sup::signal_supervisor(pid, libc::SIGKILL);
            }
            let _ = sup::signal_supervisor(child.id(), libc::SIGKILL);
            let _ = child.wait();
            break StopOutcome::Killed;
        }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    };
    flush_typed_ahead_stdin();
    outcome
}

/// Filters a `(pid, snapshot_start_time)` list (as produced by
/// `graceful_stop`'s pre-`SIGKILL` snapshot) down to the pids whose
/// CURRENT start time still matches the snapshot — i.e. the pid was NOT
/// recycled by an unrelated process in the window between the snapshot and
/// this call. `None == None` (the descendant already had no readable start
/// time at snapshot time, and still doesn't) still counts as "matching":
/// signalling an already-gone pid is a harmless `ESRCH` either way, so
/// there is nothing to protect there — the guard exists for the case where
/// the snapshot found a start time and the CURRENT one differs or is now
/// unreadable, meaning the pid identity has moved on.
#[cfg(unix)]
fn descendants_still_matching_snapshot(descendants: &[(u32, Option<String>)]) -> Vec<u32> {
    descendants
        .iter()
        .filter(|(pid, snapshot)| sup::process_start_time(*pid).as_deref() == snapshot.as_deref())
        .map(|(pid, _)| *pid)
        .collect()
}

/// C-R4-6: enumerates every LIVE descendant of `root_pid` (children,
/// grandchildren, ...) via `/bin/ps -axo pid=,ppid=` — the SAME
/// absolute-path, scrubbed-environment invocation pattern
/// `csq_core::session::codex_supervisor::process_start_time` already uses
/// for process identity, so this does not introduce a second, differently
/// hardened `ps` invocation with its own PATH/locale-shadowing exposure.
/// Best-effort: a `ps` failure returns an empty list rather than erroring —
/// the direct-child `SIGKILL` at the call site still fires either way, so
/// this only WIDENS coverage, it is never the sole kill mechanism.
#[cfg(unix)]
fn collect_descendant_pids(root_pid: u32) -> Vec<u32> {
    let output = match std::process::Command::new("/bin/ps")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .args(["-axo", "pid=,ppid="])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut children_of: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid_s), Some(ppid_s)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid_s.parse::<u32>(), ppid_s.parse::<u32>()) else {
            continue;
        };
        children_of.entry(ppid).or_default().push(pid);
    }
    let mut descendants = Vec::new();
    let mut frontier = vec![root_pid];
    while let Some(pid) = frontier.pop() {
        if let Some(kids) = children_of.get(&pid) {
            for &kid in kids {
                descendants.push(kid);
                frontier.push(kid);
            }
        }
    }
    descendants
}

/// Typed-ahead defense: keystrokes a user typed for the OUTGOING codex
/// session, buffered by the tty driver but not yet read by anyone, would
/// otherwise be delivered to whatever reads stdin next (the relaunched
/// session, or nothing at all on the FM-4 exit path) as soon as it starts
/// reading — landing as an unexpected, out-of-context input. `tcflush`
/// discards unread input queued by the driver. Only meaningful when stdin
/// is a TTY (piped/redirected stdin has no typed-ahead concept, and
/// `tcflush` against a non-tty fd is a documented error this function does
/// not care about).
#[cfg(unix)]
fn flush_typed_ahead_stdin() {
    // SAFETY: `isatty`/`tcflush` are plain libc calls against a fixed, valid
    // fd (`STDIN_FILENO`) — no pointers passed in, no allocation.
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) == 1 {
            libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
        }
    }
}

/// FM-7: stdin's tty settings, captured once before the first child spawn.
#[cfg(unix)]
struct TtyRawState(libc::termios);

/// Captures stdin's current tty attributes via `tcgetattr`, or `None` when
/// stdin is not a tty (or the call fails) — there is nothing to restore in
/// either case.
#[cfg(unix)]
fn capture_tty_state_if_tty() -> Option<TtyRawState> {
    // SAFETY: `isatty`/`tcgetattr` are plain libc calls against a fixed,
    // valid fd; `termios` is zero-initialized before `tcgetattr` fills it,
    // and we only ever read it back through `libc`'s own type.
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 1 {
            return None;
        }
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) != 0 {
            return None;
        }
        Some(TtyRawState(termios))
    }
}

/// C-R4-5: the tty's baseline attributes, captured EXACTLY ONCE per process
/// and cached for its remaining lifetime — never re-captured on a relaunch.
#[cfg(unix)]
static TTY_BASELINE: std::sync::OnceLock<Option<TtyRawState>> = std::sync::OnceLock::new();

/// Returns the process-wide tty baseline, capturing it on first call.
///
/// `run_supervised_unix` re-enters (once per relaunch, all within the same
/// process — see `reset_signal_dispositions_before_exec`'s doc comment for
/// why this is a genuine recursive call). A prior revision of this fix
/// called `capture_tty_state_if_tty` fresh on every entry, documented as
/// "captured once per session" — which was true only of a session with
/// zero relaunches. On a relaunch, capturing AGAIN reads whatever raw/
/// cooked state the OUTGOING codex left the terminal in, which may itself
/// already be wrong (C-R4-5: a codex killed by the DEFAULT `SIGTERM`
/// disposition — never caught, never ran its own raw-mode cleanup — leaves
/// the tty raw with nobody having restored it, see `restore_tty_after_stop`
/// below), and would wrongly adopt THAT as the new "original" to restore to
/// on a LATER relaunch. Capturing once, before this process's first spawn,
/// is the only baseline guaranteed to predate every codex child it ever
/// runs.
#[cfg(unix)]
fn tty_baseline() -> Option<&'static TtyRawState> {
    TTY_BASELINE.get_or_init(capture_tty_state_if_tty).as_ref()
}

/// Restores stdin's tty attributes to the captured pre-spawn state.
#[cfg(unix)]
fn restore_tty_state(state: &TtyRawState) {
    // SAFETY: `tcsetattr` against a fixed, valid fd with a `termios` value
    // this same process captured moments (or one relaunch) earlier.
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &state.0);
    }
}

/// C-R4-5: restores stdin's tty state after ANY `graceful_stop` outcome,
/// not only a `SIGKILL`. A codex child that dies from the DEFAULT `SIGTERM`
/// disposition — it never caught the signal, so it never ran its own
/// raw-mode cleanup — is reported by `graceful_stop` as `ExitedOnTerm`,
/// indistinguishable at the `try_wait` level from a COOPERATIVE `SIGTERM`
/// handler that already restored the terminal itself. A prior revision of
/// this fix restored ONLY on `StopOutcome::Killed`, leaving the tty raw in
/// exactly that default-disposition case. Restoring unconditionally is safe
/// even when the child DID restore cooperatively: `tcsetattr` simply
/// re-applies the same attributes, which is a no-op in effect. Split out
/// from the production call site so a test can substitute a recording
/// for `restore` without a real tty.
#[cfg(unix)]
fn restore_tty_after_stop(tty_state: Option<&TtyRawState>, restore: impl FnOnce(&TtyRawState)) {
    if let Some(state) = tty_state {
        restore(state);
    }
}

#[cfg(unix)]
static SIGTERM_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
static SIGHUP_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
static SIGUSR1_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Item 3 (S-LOW-1/D-F2): caps concurrently-outstanding `validate` worker
/// threads (spawned inside `drive_child`'s `SIGUSR1` branch) at ONE per
/// process. `true` while a worker is running OR abandoned-but-still-running
/// past its budget; `false` otherwise. Set with `compare_exchange` right
/// before a worker is spawned (refusing the swap outright on contention,
/// rather than starting a second worker) and cleared by
/// `ValidationInFlightGuard`'s `Drop` inside the worker's own closure — see
/// that type's doc for why the CLEAR happens there rather than in
/// `drive_child`'s poll loop.
#[cfg(unix)]
static VALIDATION_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// RAII guard that clears [`VALIDATION_IN_FLIGHT`] on drop. Constructed as
/// the FIRST statement inside the worker thread's closure, so the flag is
/// cleared on every exit path from that closure — including an unwinding
/// panic from `validate_for_worker` (Rust runs destructors during a
/// `panic=unwind` unwind, which is this workspace's default) — never only
/// on the "the call returned normally" path. Without this, a validate
/// closure that panics would leave `VALIDATION_IN_FLIGHT` stuck `true`
/// forever, refusing every future swap request on this handle dir with
/// "previous validation still running" even though nothing is actually
/// running any more.
#[cfg(unix)]
struct ValidationInFlightGuard;

#[cfg(unix)]
impl Drop for ValidationInFlightGuard {
    fn drop(&mut self) {
        VALIDATION_IN_FLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// FM-2/C-(f): guards the ONE-TIME handler install, now called from
/// `run_supervised_unix` BEFORE `cmd.spawn()` (see that call site's doc
/// comment) rather than from `drive_child` AFTER it.
#[cfg(unix)]
static SIGNAL_HANDLERS_INIT: std::sync::Once = std::sync::Once::new();

#[cfg(unix)]
fn ensure_signal_handlers_installed() {
    // C-(f): the three flags are NOT explicitly re-seeded to `false` here.
    // `AtomicBool::new(false)` already initializes each static to `false`
    // at compile time, so the explicit stores this closure used to perform
    // were always redundant — and, worse, a race: `install_flag_handler`
    // installs the SIGUSR1 handler and RETURNS; if a real SIGUSR1 arrives
    // between that install and the (redundant) `SIGUSR1_FLAG.store(false,
    // ..)` a few lines later, this closure's own store would silently
    // ERASE that genuinely-arrived signal. Removing the stores removes the
    // window entirely — there is nothing left to race.
    SIGNAL_HANDLERS_INIT.call_once(|| {
        install_flag_handler(libc::SIGTERM);
        install_flag_handler(libc::SIGHUP);
        install_flag_handler(libc::SIGUSR1);
    });
}

/// FM-1: resets `SIGINT`/`SIGQUIT` to `SIG_DFL` in the CHILD, before `exec`,
/// via `pre_exec`. Applied to every `Command` this supervisor ever spawns —
/// see the call site's doc comment (`run_supervised_unix`) for why this
/// must be unconditional rather than gated on "is this a relaunch".
#[cfg(unix)]
fn reset_signal_dispositions_before_exec(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `pre_exec`'s closure runs in the forked child between `fork`
    // and `exec`, where only async-signal-safe operations are sound. `signal(2)`
    // with a `SIG_DFL` sentinel touches no allocator, no lock, and no
    // non-async-signal-safe state — it is exactly the kind of call `pre_exec`
    // exists to allow.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
}

/// Async-signal-safe handler body: set the flag, nothing else. Installed
/// once per signal number per process (idempotent — `sigaction` simply
/// overwrites any prior disposition, and re-installing the same handler
/// for the same static is a no-op in effect).
#[cfg(unix)]
extern "C" fn set_sigterm_flag(_: libc::c_int) {
    SIGTERM_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}
#[cfg(unix)]
extern "C" fn set_sighup_flag(_: libc::c_int) {
    SIGHUP_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}
#[cfg(unix)]
extern "C" fn set_sigusr1_flag(_: libc::c_int) {
    SIGUSR1_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
fn install_flag_handler(sig: libc::c_int) {
    let handler: extern "C" fn(libc::c_int) = match sig {
        libc::SIGTERM => set_sigterm_flag,
        libc::SIGHUP => set_sighup_flag,
        libc::SIGUSR1 => set_sigusr1_flag,
        _ => return,
    };
    // SAFETY: `signal(2)` with a function pointer whose body only performs
    // an async-signal-safe atomic store is sound to install from any
    // thread; we never touch non-atomic shared state from the handler.
    unsafe {
        libc::signal(sig, handler as libc::sighandler_t);
    }
}

#[cfg(unix)]
fn ignore_signal(sig: libc::c_int) {
    // SAFETY: SIG_IGN is a sentinel value, not a function pointer call —
    // installing it only changes signal disposition metadata in the
    // kernel, no user code runs.
    unsafe {
        libc::signal(sig, libc::SIG_IGN);
    }
}

#[cfg(unix)]
fn exit_code_for(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Renames `handle_dir_abs` to a `.sweep-tombstone-swap-<pid>-<nanos>`
/// sibling so a fresh `term-<pid>` handle dir can be created at the same
/// path for the target slot, via `swap::rename_handle_dir_to_sweep_tombstone`
/// (shard S3, item 2 of the governing task — deduplicated from a local copy;
/// see module doc). Falls back to a best-effort remove on any failure (no
/// parent, cross-device rename, already gone) so a stale dir never blocks
/// the subsequent `create_handle_dir_codex` for the target slot — this
/// fallback behavior is unchanged from before the dedup.
#[cfg(unix)]
fn tombstone_handle_dir(handle_dir_abs: &Path) {
    if super::swap::rename_handle_dir_to_sweep_tombstone(handle_dir_abs).is_err() {
        let _ = std::fs::remove_dir_all(handle_dir_abs);
    }
}

/// Sandbox/approval/model/config/cwd flags (space-separated OR `=`-joined
/// value form) a codex relaunch must carry forward across a cross-slot swap.
/// Superset of `providers::codex::surface::CALLER_SANDBOX_FLAGS` (which
/// governs only the GH#978 sandbox-suppression decision) — this list also
/// preserves `-m`/`--model`, `-c`/`--config`, and `--cd`, per the governing
/// task's item 3.
const RELAUNCH_VALUE_FLAGS: &[&str] = &[
    "-s",
    "--sandbox",
    "-a",
    "--ask-for-approval",
    "--approval",
    "-m",
    "--model",
    "-c",
    "--config",
    "--cd",
];

/// Boolean (no-value) flags a codex relaunch must carry forward.
const RELAUNCH_BOOL_FLAGS: &[&str] = &[
    "--full-auto",
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
    "--ignore-user-config",
];

/// Splits `original_rest` into the flag tokens a relaunch must preserve,
/// dropping every POSITIONAL — subcommand names (`resume`, `exec`), a
/// session id (including a STALE one from a prior swap's own relaunch
/// argv), and the free-form initial prompt. C-F5/S-F2: a relaunch must
/// never replay the original prompt, and a second swap must never carry
/// forward a `resume <id>` pair left over from an earlier swap — both are
/// positionals under this classifier, so both are dropped uniformly.
fn preserved_relaunch_flags(original_rest: &[String]) -> Vec<String> {
    let mut kept = Vec::new();
    let mut i = 0;
    while i < original_rest.len() {
        let tok = original_rest[i].as_str();
        let flag_name = tok.split_once('=').map(|(name, _)| name).unwrap_or(tok);
        if RELAUNCH_BOOL_FLAGS.contains(&flag_name) {
            kept.push(original_rest[i].clone());
            i += 1;
        } else if RELAUNCH_VALUE_FLAGS.contains(&flag_name) {
            kept.push(original_rest[i].clone());
            i += 1;
            // `--flag=value` already carries its value in `tok`; only the
            // space-separated form (`flag_name == tok`, no `=` present)
            // needs the NEXT token consumed as the value too.
            if flag_name == tok && i < original_rest.len() {
                kept.push(original_rest[i].clone());
                i += 1;
            }
        } else {
            i += 1; // positional: subcommand, session id, prompt — dropped.
        }
    }
    kept
}

/// Builds the relaunch `rest` argv for a codex resume: the caller's
/// PRESERVED flags (see [`preserved_relaunch_flags`]) plus `["resume",
/// thread_id]` when a thread id was discovered, or just the preserved
/// flags (fresh session) plus an operator-facing note when none was.
///
/// Deliberately does NOT return `original_rest` verbatim in the `None` arm
/// (C-F5/S-F2): `original_rest` at a SECOND swap is whatever the FIRST
/// swap's own `relaunch_rest` call produced, which may itself be a stale
/// `["resume", "<id1>"]` pair — replaying it here would resume the WRONG
/// thread, and replaying a bare initial prompt would silently re-submit it
/// to the new session.
///
/// `target_slot` is the relaunch's destination slot (both `run.rs` call
/// sites already resolve it before calling this, as the argument passed to
/// the recursive `launch_codex` call immediately after). Threading it
/// through lets the `None`-arm note (C-R4-15) name the exact slot-scoped
/// command instead of describing the mechanism in the abstract.
pub fn relaunch_rest(
    target_slot: u16,
    thread_id: Option<&str>,
    original_rest: &[String],
) -> Vec<String> {
    let mut rest = preserved_relaunch_flags(original_rest);
    match thread_id {
        Some(id) => {
            rest.push("resume".to_string());
            rest.push(id.to_string());
        }
        None => {
            eprintln!("{}", relaunch_none_arm_note(target_slot));
        }
    }
    rest
}

/// The operator-facing note `relaunch_rest`'s `None` arm prints when no
/// prior thread id was recorded. Factored out of `relaunch_rest` so the
/// exact wording is directly assertable (governing task item 2) rather than
/// only exercisable via a captured-stderr integration test.
///
/// C-R4-15: does NOT recommend running `codex resume` as printed (bare,
/// standalone) — a bare `codex resume` reads `$HOME/.codex` (or whatever
/// `CODEX_HOME` the CALLING shell happens to have), never the slot-scoped
/// config dir a `csq run <account>` invocation sets up. Names the exact
/// slot-scoped command: the real passthrough syntax (`run.rs`'s arg parsing
/// / `relaunch_recovery_hint`'s own `csq run <slot> -- resume <id>`
/// convention) is `csq run <slot> -- resume` — running it with no id lets
/// codex's own resume picker choose, since no thread id was recorded to
/// name one directly.
fn relaunch_none_arm_note(target_slot: u16) -> String {
    format!(
        "note: starting a fresh codex session (no prior thread id was \
         recorded) — to reopen a specific past conversation, run \
         `csq run {target_slot} -- resume` for the account that held \
         it (a bare `codex resume` outside csq reads the wrong \
         config and will not find it)."
    )
}

/// FM-6/C-R4-15: the recovery hint printed after a failed relaunch. Carries
/// the thread id when one was known — `csq run <slot> -- resume <id>` — or,
/// when no thread id was ever discovered, recommends retrying a fresh
/// session on the SAME (already-validated-as-a-target) slot —
/// `csq run <slot>` — rather than a bare `codex resume`, which would read
/// the calling shell's own `$HOME/.codex` / `CODEX_HOME`, not this slot's
/// config dir (see `relaunch_rest`'s `None` arm for the identical mistake in
/// its own note, fixed the same way). Only ever called from the
/// `#[cfg(unix)]` relaunch-failure branch in `run_supervised_unix`.
#[cfg(unix)]
fn relaunch_recovery_hint(target_slot: u16, thread_id: Option<&str>) -> String {
    match thread_id {
        Some(id) => format!("csq run {target_slot} -- resume {id}"),
        None => format!("csq run {target_slot}"),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cli::audit_emit::AuditEmitter;
    use crate::cli::commands::fake_daemon_test_support::{
        spawn_fake_healthy_daemon, FakeHealthyDaemon,
    };
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Path to the `stub-cli` test-fixture binary built by
    /// `cargo build -p csq-core --bin stub-cli --features test-utils`.
    /// Fails loudly (not silently skips) when absent — a hermetic test
    /// that quietly no-ops on a missing fixture is worse than an absent
    /// test (`test(common): fail loudly when the stub-cli helper binary
    /// is not built`, this branch's own prior commit).
    fn stub_cli_path() -> PathBuf {
        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("workspace root")
                    .join("target")
            });
        for profile in ["debug", "release"] {
            let p = target_dir.join(profile).join("stub-cli");
            if p.exists() {
                return p;
            }
        }
        panic!(
            "stub-cli fixture binary not found under {target_dir:?}/{{debug,release}} — \
             build it first: cargo build -p csq-core --bin stub-cli --features test-utils"
        );
    }

    fn test_audit_emitter(_tmp: &Path) -> AuditEmitter {
        // `disabled()` holds no `AuditRecord`, so every setter and
        // `try_flush_now` is a no-op — exactly what a hermetic test
        // needs (no daemon socket, no `.pending/` fallback dir to wire).
        AuditEmitter::disabled()
    }

    fn tmp_handle_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    /// A `base_dir` fixture satisfying `validate_codex_relaunch_target`'s
    /// config + credential-regular-file checks for `slot` — everything a
    /// swap TARGET needs to pass admission before the current child is torn
    /// down. No credential CONTENT is needed: a missing/unreadable
    /// `auth.json` is non-fatal to `check_codex_token_freshness`, and this
    /// fixture never creates one; an empty `config.toml` and an empty
    /// legacy `credentials/codex-<slot>.json` are enough for the two
    /// existence/regular-file checks. No trust envelope is configured, so
    /// the M6 gate (enterprise builds) resolves `SpawnGate::Ungoverned`.
    /// Returns the fixture `TempDir` PLUS the [`FakeHealthyDaemon`] guard —
    /// callers MUST bind both (`let (base_dir, _daemon) = ...`); dropping the
    /// guard early tears down the fake daemon's PID file / env override
    /// while `validate_codex_relaunch_target`'s FM-5 daemon-health check
    /// still needs it.
    fn valid_swap_target_base_dir(slot: u16) -> (tempfile::TempDir, FakeHealthyDaemon) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        provision_codex_config_and_credentials(dir.path(), slot);
        let daemon = spawn_fake_healthy_daemon(dir.path());
        (dir, daemon)
    }

    /// The config + credential half of [`valid_swap_target_base_dir`],
    /// factored out so a caller that needs the fake daemon spawned in a
    /// DIFFERENT process (e.g. a parent test spawning a subprocess helper
    /// that then exits via `process::exit`, per the FM-6 audit-flush test
    /// below) can provision an already-chosen `dir` without also creating a
    /// fresh `TempDir` here.
    fn provision_codex_config_and_credentials(dir: &Path, slot: u16) {
        std::fs::create_dir_all(dir.join(format!("config-{slot}"))).unwrap();
        std::fs::write(dir.join(format!("config-{slot}")).join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml (test fixture)
        std::fs::create_dir_all(dir.join("credentials")).unwrap();
        std::fs::write(
            dir.join("credentials").join(format!("codex-{slot}.json")),
            b"{}",
        )
        .unwrap();
    }

    // Governing task item 4 (test-helper hoist): `spawn_fake_healthy_daemon`
    // / `FakeHealthyDaemon` used to be defined here directly; they now live
    // in the shared `fake_daemon_test_support` module (also used by
    // `swap.rs`'s test module, which previously carried an identical
    // `SwapFakeHealthyDaemon` copy) and are imported via the `use` at the
    // top of this `mod tests` block.

    /// `run_supervised_unix`/`drive_child` install PROCESS-GLOBAL signal
    /// dispositions (`SIG_IGN` for `SIGINT`/`SIGQUIT`) and share
    /// process-wide `AtomicBool` flags across every invocation in this
    /// test binary. `cargo test`'s default parallel runner would let two
    /// such tests race on the SAME signal state (one test's `SIGUSR1` to
    /// its own pid is process-wide, not per-thread).
    ///
    /// Item 4 (D-F3, signal-test harness hazards): this is now
    /// [`csq_core::platform::test_env::signal_lock`] — a mutex shared
    /// across the WHOLE workspace (`cli_deps::auto_update`'s
    /// `InterruptSignalGuard`-adjacent tests, and the desktop
    /// `daemon_supervisor` SIGTERM-bridge test, both of which touch the
    /// SAME process-wide signal disposition table) rather than a mutex
    /// local to this module. A prior version of this doc recorded (and
    /// `auto_update.rs`'s own doc, before this fix, independently
    /// recorded) that the two modules' guards could not be shared because
    /// they lived in different crates — `signal_lock` is what closes that
    /// gap.
    ///
    /// Also installs the handlers HERE, synchronously, before returning —
    /// see [`ensure_signal_handlers_installed`]'s call below. Every test
    /// in this module acquires this guard and then immediately spawns a
    /// thread that sleeps ~100ms before raising a signal against this
    /// process; production code (`run_supervised_unix`) also calls
    /// `ensure_signal_handlers_installed` before spawning the child, but a
    /// test does not enter `run_supervised` until AFTER its writer thread
    /// is already spawned and sleeping. Installing here, first, removes
    /// that ordering as a race entirely rather than relying on the
    /// `Once`'s install being fast enough to win it in practice.
    #[cfg(unix)]
    fn lock_signal_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = csq_core::platform::test_env::signal_lock();
        ensure_signal_handlers_installed();
        // Item 3 (S-LOW-1/D-F2) test hermeticity: `VALIDATION_IN_FLIGHT` is
        // a process-wide static, and several sibling tests in this module
        // deliberately leave a validate worker running FOREVER (a validate
        // closure that never returns, e.g. `drive_child_refuses_within_
        // budget_when_validate_blocks_forever`) — that worker's
        // `ValidationInFlightGuard` therefore never drops, and the flag
        // would otherwise stay `true` for the rest of THIS PROCESS,
        // wedging every later test's own SIGUSR1 cycle behind a
        // "previous validation still running" refusal that has nothing to
        // do with what that later test is exercising. Resetting here is
        // safe: the abandoned closure in those tests has no side effects
        // beyond its own `result_tx.send` (see `drive_child`'s doc), so
        // discarding its claim on the flag at the START of the NEXT test
        // does not resurrect anything the abandoned worker could still
        // observe or mutate.
        VALIDATION_IN_FLIGHT.store(false, Ordering::SeqCst);
        guard
    }

    /// C-(f)/PRIMARY DIRECTIVE: blocks (bounded by `timeout`) until BOTH
    /// on-disk artifacts `run_supervised_unix` writes AFTER a successful
    /// spawn — the supervisor record and the live-pid marker — are present
    /// in `handle_dir`. A bare `sleep(N)` before writing a swap request and
    /// signalling only moves the race to a different fixed delay; this
    /// instead polls for the SAME state production code depends on being
    /// present, so the test's timing tracks the real ordering constraint
    /// rather than a guessed duration.
    fn wait_for_supervisor_ready(handle_dir: &Path, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let supervisor_ready = sup::read_supervisor_record(handle_dir).is_some();
            let child_ready = csq_core::accounts::markers::read_live_cc_pid(handle_dir).is_some();
            if supervisor_ready && child_ready {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// C-(f)/PRIMARY DIRECTIVE: writes `req` into `handle_dir` and sends
    /// `SIGUSR1` to `pid`, REPEATING the signal until the request is
    /// observably consumed (the request file gone, per `take_swap_request`'s
    /// atomic rename — C-R4-1), bounded by an overall `timeout`. This is an
    /// ordering proof, not a bare delay: it does not assume how long
    /// `drive_child`'s poll loop takes to notice the flag, it re-asserts the
    /// signal until the observable effect (consumption) has happened, and
    /// panics loudly if it never does within `timeout` — a genuine
    /// regression still fails the test rather than hanging the suite.
    fn write_request_and_signal_until_consumed(
        handle_dir: &Path,
        pid: u32,
        req: &sup::SwapRequest,
        timeout: Duration,
    ) {
        sup::write_swap_request(handle_dir, req).expect("write swap request");
        let request_path = handle_dir.join(sup::SWAP_REQUEST_FILE);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGUSR1);
            }
            std::thread::sleep(Duration::from_millis(20));
            if !request_path.exists() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "swap request for slot {} was never consumed within \
                     {timeout:?} of repeated SIGUSR1 — the supervisor did \
                     not react",
                    req.target_slot
                );
            }
        }
    }

    /// A `cmd` that runs stub-cli with the given extra args, and a
    /// matching argv-capture path so tests can assert on exactly what
    /// was spawned.
    fn stub_cmd(argv_capture: &Path, extra: &[&str]) -> Command {
        let mut cmd = Command::new(stub_cli_path());
        cmd.arg("--capture-argv").arg(argv_capture);
        cmd.args(extra);
        cmd
    }

    /// F2 (round 5): `run_supervised`'s `validate` parameter for tests that
    /// never send a `SIGUSR1` with a pending request at all — `validate` is
    /// only ever CALLED from `drive_child` when `take_swap_request` returns
    /// `Some`, so a test with no pending request is a precondition proving
    /// `validate` is unreachable, not merely unused.
    fn never_validate(_slot: u16) -> Result<csq_core::types::AccountNum> {
        panic!("validate must not be invoked when no swap request arrives")
    }

    /// F2 (round 5): a `validate` closure over `base_dir` that calls the
    /// REAL `validate_codex_relaunch_target` — for tests that DO exercise a
    /// real `SIGUSR1`/pending-request cycle and need the actual admission
    /// checks (daemon health, config/credential presence, capability-layer
    /// preflight) to run, exactly as `drive_child` does in production.
    /// `toggles = CapabilityLayerToggles::default()` (no toggles file in
    /// any of these fixtures' tmp `base_dir`s — `load_capability_layer_toggles`
    /// would have returned the same default the OLD code hardcoded),
    /// `debug = false`, `coc_cache_enabled = true` — reproducing the OLD
    /// (pre-F2) hardcoded values exactly, since these `drive_child`-focused
    /// tests assert on FORWARDING behavior (does drive_child reach/skip
    /// relaunch), not on capability-layer-preflight specifics — those are
    /// covered directly by the `validate_codex_relaunch_target`-focused
    /// tests near the end of this module.
    /// D-F9 (round 7): delegates to the PRODUCTION `make_validate_relaunch`
    /// (`run.rs`) rather than re-deriving the same call to
    /// `validate_codex_relaunch_target` a second time — this test fixture
    /// used to be an independent, byte-for-byte copy of what `launch_codex`
    /// built inline, and the two had already drifted apart once before this
    /// extraction. Builds a fresh `make_validate_relaunch` closure on every
    /// invocation (rather than once, up front) so this function's own
    /// `base_dir: PathBuf` / default `toggles` can stay owned locals inside
    /// the returned `move` closure, with no lifetime threaded out past it.
    fn default_validate(
        base_dir: PathBuf,
        capability_layer_enabled: bool,
        layer_is_auto: bool,
    ) -> impl Fn(u16) -> Result<csq_core::types::AccountNum> {
        move |slot: u16| {
            let toggles = csq_core::capability_layer::CapabilityLayerToggles::default();
            let validate = crate::cli::commands::run::make_validate_relaunch(
                base_dir.clone(),
                capability_layer_enabled,
                layer_is_auto,
                toggles,
                false,
                true,
            );
            validate(slot)
        }
    }

    #[test]
    fn child_exit_status_propagates_on_success() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());
        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked when no swap request arrives"),
        );
        assert!(
            result.is_ok(),
            "expected Ok(()) for a clean exit: {result:?}"
        );
    }

    #[test]
    fn child_exit_status_nonzero_propagates_as_process_exit() {
        // `run_supervised_unix`'s terminal-exit branch calls
        // `std::process::exit(exit_code_for(status))` on a non-zero
        // status (mirroring `exec_or_spawn`'s pre-existing contract —
        // codex's exit code IS csq's exit code). `process::exit` cannot
        // be exercised in-process without killing the test harness
        // itself, so this asserts the exact mapping function that branch
        // calls, against a REAL child process's real exit status (not a
        // synthetic `ExitStatus`), which is the only non-`process::exit`
        // part of that branch worth separately verifying.
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let mut child = std::process::Command::new(stub_cli_path())
            .arg("--capture-argv")
            .arg(&capture)
            .arg("--exit-code")
            .arg("7")
            .spawn()
            .expect("spawn stub-cli directly");
        let status = child.wait().expect("wait");
        assert_eq!(
            exit_code_for(status),
            7,
            "exit_code_for must surface the child's own exit code"
        );
    }

    #[test]
    fn sigint_to_supervisor_does_not_kill_it_while_child_runs() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Child hangs for 400ms so there's a window to signal the
        // supervisor before it would exit on its own.
        let cmd = stub_cmd(&capture, &["--hang-ms", "400", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let supervisor_pid = Arc::new(AtomicBool::new(false));
        let started = supervisor_pid.clone();

        // We can't send SIGINT to a specific "supervisor" without a
        // separate process — this test instead asserts the mechanism
        // `run_supervised_unix` relies on: after `ignore_signal(SIGINT)`
        // is installed, raising SIGINT against THIS test process must
        // not terminate it, and the eventual child wait must still
        // observe a clean exit. Raise SIGINT against our own pid mid-run
        // by spawning a tiny helper thread that fires it once the child
        // is very likely running.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGINT);
            }
            started.store(true, Ordering::SeqCst);
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked"),
        );
        assert!(
            result.is_ok(),
            "supervisor (and this test process) must survive SIGINT while a child is running: {result:?}"
        );
    }

    #[test]
    fn sigusr1_with_pending_request_triggers_relaunch_with_resume_argv() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        // The handle dir itself is TOMBSTONED (renamed away) mid-test, once
        // the swap request is consumed — matching production
        // (`tombstone_handle_dir`). So the relaunch's own argv-capture file
        // MUST live outside it, in a directory that survives the rename.
        let artifacts = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let relaunch_capture = artifacts.path().join("relaunch_argv.json");
        // Child hangs long enough for us to write a swap request and
        // signal the supervisor before it would exit naturally.
        let cmd = stub_cmd(&capture, &["--hang-ms", "5000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());
        let (base_dir, _daemon) = valid_swap_target_base_dir(7);

        let handle_dir = dir.path().to_path_buf();
        let handle_dir_for_writer = handle_dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 7,
                    thread_id: Some("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c".to_string()),
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let relaunch_capture_clone = relaunch_capture.clone();
        let relaunch_stub = stub_cli_path();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        let result = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            move |slot, thread_id, _, _| {
                called_clone.store(true, Ordering::SeqCst);
                assert_eq!(slot, 7, "relaunch must receive the requested target slot");
                let rest = relaunch_rest(slot, thread_id, &[]);
                assert_eq!(
                    rest,
                    vec![
                        "resume".to_string(),
                        "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c".to_string()
                    ],
                    "relaunch argv must carry `resume <thread_id>` when one was requested"
                );
                let mut relaunch_cmd = Command::new(&relaunch_stub);
                relaunch_cmd
                    .arg("--capture-argv")
                    .arg(&relaunch_capture_clone)
                    .args(&rest)
                    .arg("--exit-code")
                    .arg("0");
                let mut child = relaunch_cmd.spawn().expect("spawn relaunch stub");
                let status = child.wait().expect("wait relaunch stub");
                assert!(status.success());
                Ok(())
            },
        );

        assert!(
            result.is_ok(),
            "relaunch path must return Ok(()): {result:?}"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "relaunch closure must be invoked"
        );

        let raw = std::fs::read_to_string(&relaunch_capture).expect("read relaunch argv capture");
        assert!(
            raw.contains("resume") && raw.contains("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c"),
            "relaunched child's argv must contain resume + the thread id, got: {raw}"
        );
    }

    #[test]
    fn sigusr1_with_no_pending_request_does_not_relaunch() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "300", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(80));
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must NOT be invoked when no request is pending"),
        );
        assert!(
            result.is_ok(),
            "child must run to its natural exit: {result:?}"
        );
    }

    #[test]
    fn relaunch_failure_prints_recovery_message_and_exits_nonzero() {
        // `run_supervised_unix`'s `Outcome::SwapRequested` failure branch
        // calls `std::process::exit(1)` directly (matching
        // `fail_loud_on_audit_write_failure`'s existing precedent
        // elsewhere in this crate: csq owns the exit code at this point,
        // so it must not silently propagate). Exercised out-of-process so
        // the test harness itself survives the exit.
        let exe = std::env::current_exe().expect("current test exe");
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::relaunch_failure_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as relaunch-failure helper");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // C-R4-15: `relaunch_failure_helper`'s `SwapRequest` carries no
        // thread id (target slot 9), so the recovery hint must be
        // `csq run 9` — a bare `codex resume` reads the calling shell's own
        // `$HOME/.codex`, never slot 9's config dir, so it is never a
        // correct recovery hint regardless of thread id.
        assert!(
            stderr.contains("Recover with: csq run 9"),
            "failed relaunch with no discovered thread id must recommend a \
             slot-scoped `csq run <slot>` retry, not a bare `codex resume`, \
             got: {stderr}"
        );
        assert!(
            !output.status.success(),
            "a failed relaunch must exit non-zero"
        );
    }

    /// Round-3 gap (b) / FM-6: a failed relaunch's FRESH `relaunch_emitter`
    /// must be finalized (Fail/Reject) and flushed BEFORE the
    /// `process::exit(1)` that bypasses `Drop` — otherwise the record is
    /// silently lost, with nothing in the audit chain describing the failed
    /// relaunch attempt at all. This reuses `relaunch_failure_helper`
    /// (its `println!` marker gives this test the child's `base_dir`) and
    /// inspects `.pending/` for the fail/reject record FM-6 protects.
    #[test]
    fn relaunch_failure_flushes_a_final_audit_record() {
        let exe = std::env::current_exe().expect("current test exe");
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::relaunch_failure_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as relaunch-failure helper");
        assert!(
            !output.status.success(),
            "a failed relaunch must exit non-zero"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let base_dir_line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("CSQ_TEST_BASE_DIR="))
            .expect("helper must print its base_dir marker");
        let base_dir = PathBuf::from(base_dir_line);
        // Manual cleanup: `process::exit` in the helper skipped its
        // `TempDir::drop`, so this directory is not otherwise reclaimed.
        let _cleanup = scopeguard_remove_dir_all(base_dir.clone());

        let pending_dir = base_dir.join("csq-runs").join(".pending");
        let entries: Vec<_> = std::fs::read_dir(&pending_dir)
            .unwrap_or_else(|e| panic!("read {pending_dir:?}: {e}"))
            .flatten()
            .collect();
        assert!(
            !entries.is_empty(),
            "the failed relaunch's fresh emitter must have flushed a record \
             to .pending/, found none in {pending_dir:?}"
        );

        let mut found_fail_reject = false;
        for entry in &entries {
            let content = std::fs::read_to_string(entry.path()).expect("read pending record");
            let parsed: serde_json::Value =
                serde_json::from_str(&content).expect("parse pending record as JSON");
            if parsed["result_state"] == "fail" && parsed["decision"] == "reject" {
                found_fail_reject = true;
            }
        }
        assert!(
            found_fail_reject,
            "expected a result_state=fail/decision=reject record (the \
             relaunch_emitter FM-6 finalizes before process::exit) among \
             {entries:?}"
        );
    }

    /// Removes `dir` recursively when dropped — a minimal scope-guard so the
    /// helper-process tempdir (never cleaned up by its own `Drop`, since
    /// `process::exit` skipped it) does not leak past this test even if an
    /// assertion above panics.
    struct RemoveDirAllOnDrop(PathBuf);
    impl Drop for RemoveDirAllOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn scopeguard_remove_dir_all(dir: PathBuf) -> RemoveDirAllOnDrop {
        RemoveDirAllOnDrop(dir)
    }

    #[cfg(unix)]
    #[test]
    fn relaunch_recovery_hint_carries_thread_id_when_known() {
        assert_eq!(
            relaunch_recovery_hint(9, Some("thread-abc")),
            "csq run 9 -- resume thread-abc"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relaunch_recovery_hint_falls_back_to_slot_scoped_retry() {
        // C-R4-15: NOT a bare `codex resume` — that reads the calling
        // shell's own `$HOME/.codex`/`CODEX_HOME`, never slot 9's config
        // dir, so it would silently fail to find anything there.
        assert_eq!(relaunch_recovery_hint(9, None), "csq run 9");
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as
    /// a subprocess by `relaunch_failure_prints_recovery_message_and_exits_nonzero`
    /// above, so its `std::process::exit(1)` terminates the HELPER
    /// process rather than the outer test binary.
    #[test]
    #[ignore]
    fn relaunch_failure_helper() {
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "3000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());
        let (base_dir, _daemon) = valid_swap_target_base_dir(9);
        // Round-3 gap (b) / FM-6: `process::exit` below skips `base_dir`'s
        // `TempDir::drop`, so its directory survives on disk after this
        // helper process exits. Printed with a fixed-vocabulary marker so
        // the parent test (`relaunch_failure_flushes_a_final_audit_record`)
        // can locate and inspect its `.pending/` directory, then clean it up
        // itself.
        println!("CSQ_TEST_BASE_DIR={}", base_dir.path().display());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 9,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let _ = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                Err(anyhow!(
                    "simulated relaunch failure: target slot not provisioned"
                ))
            },
        );
        panic!("run_supervised must have called process::exit(1) before returning");
    }

    #[test]
    fn relaunch_parity_shares_flags_with_the_initial_launch() {
        let _guard = lock_signal_state();
        // Drives the PRODUCTION relaunch path: both the initial spawn and
        // the relaunch build their argv through the REAL
        // `run::build_codex_exec_command` — the SAME helper `launch_codex`
        // and its `relaunch` closure both call in production — so any flag
        // added to that helper is automatically present in both without a
        // second, hand-maintained argv list. `build_codex_exec_command`
        // always targets the literal `codex` binary (never spawned in a
        // hermetic test — HARD LIMITS), so this captures its ARGS via
        // `Command::get_args()` and re-targets the stub binary; only the
        // program name changes, the flag-derivation logic that matters here
        // ran for real.
        fn to_stub(prod_cmd: &Command, capture: &Path, extra: &[&str]) -> Command {
            let mut cmd = Command::new(stub_cli_path());
            cmd.arg("--capture-argv").arg(capture);
            cmd.args(prod_cmd.get_args());
            cmd.args(extra);
            cmd.arg("--exit-code").arg("0");
            cmd
        }

        let (base_dir, _daemon) = valid_swap_target_base_dir(3);
        let account = csq_core::types::AccountNum::try_from(3u16).unwrap();

        let dir = tmp_handle_dir();
        // The handle dir is TOMBSTONED (renamed away, taking any file
        // inside it with it) once the swap request is consumed — matching
        // production (`tombstone_handle_dir`). Both argv-capture files MUST
        // live outside it so they are still readable by their ORIGINAL path
        // after the tombstone rename.
        let artifacts = tmp_handle_dir();
        let initial_capture = artifacts.path().join("initial_argv.json");
        let relaunch_capture = artifacts.path().join("relaunch_argv.json");

        let initial_prod_cmd = crate::cli::commands::run::build_codex_exec_command(
            base_dir.path(),
            account,
            dir.path(),
            &[],
        )
        .expect("build initial production command");
        let cmd = to_stub(&initial_prod_cmd, &initial_capture, &["--hang-ms", "5000"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 3,
                    thread_id: Some("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5d".to_string()),
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let base_dir_path = base_dir.path().to_path_buf();
        let artifacts_path = artifacts.path().to_path_buf();
        let relaunch_capture_clone = relaunch_capture.clone();
        let result = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir_path.clone(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            move |slot, thread_id, _, _| {
                let rest = relaunch_rest(slot, thread_id, &[]);
                let relaunch_prod_cmd = crate::cli::commands::run::build_codex_exec_command(
                    &base_dir_path,
                    account,
                    &artifacts_path,
                    &rest,
                )
                .expect("build relaunch production command");
                let mut relaunch_cmd = to_stub(&relaunch_prod_cmd, &relaunch_capture_clone, &[]);
                let mut child = relaunch_cmd.spawn().expect("spawn relaunch");
                child.wait().expect("wait relaunch");
                Ok(())
            },
        );
        assert!(result.is_ok(), "{result:?}");

        let initial = std::fs::read_to_string(&initial_capture).expect("initial argv");
        let relaunched = std::fs::read_to_string(&relaunch_capture).expect("relaunch argv");
        assert!(
            initial.contains("--capture-argv") && initial.contains("--exit-code"),
            "initial argv must carry the shared flags: {initial}"
        );
        assert!(
            relaunched.contains("--capture-argv") && relaunched.contains("--exit-code"),
            "relaunched argv must carry the SAME shared flags (parity): {relaunched}"
        );
        assert!(
            relaunched.contains("resume")
                && relaunched.contains("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5d"),
            "relaunched argv must ADDITIONALLY carry resume + thread id: {relaunched}"
        );
        assert!(
            initial.contains("sqlite_home") && relaunched.contains("sqlite_home"),
            "both commands must carry `-c sqlite_home=...` from the REAL \
             `codex_command` helper (proves the production path actually ran \
             rather than a test-local stand-in), got initial={initial} relaunched={relaunched}"
        );
    }

    #[test]
    fn supervisor_record_removed_on_terminal_exit() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());
        let handle_dir = dir.path().to_path_buf();
        let result = run_supervised(
            cmd,
            &handle_dir,
            &handle_dir,
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("no relaunch expected"),
        );
        assert!(result.is_ok());
        assert!(
            !handle_dir.exists(),
            "the whole handle dir (and with it the supervisor record) must be \
             removed on a terminal, non-swap exit"
        );
    }

    #[test]
    fn graceful_stop_bound_documents_two_named_outcomes() {
        // `tooling-self-verification.md` Rule 3: the constant is verified
        // by NAMING both outcomes, never by a single passing probe, and by
        // calling the REAL `graceful_stop` function — not merely reasoning
        // about a raw `kill` — for the wedged outcome below.

        // Outcome 1 (healthy): a default-SIGTERM-disposition process dies
        // almost immediately.
        let mut healthy_child = std::process::Command::new(stub_cli_path())
            .arg("--exit-code")
            .arg("0")
            .spawn()
            .expect("spawn healthy stub");
        let healthy_started = std::time::Instant::now();
        unsafe {
            libc::kill(healthy_child.id() as libc::pid_t, libc::SIGTERM);
        }
        let _ = healthy_child.wait();
        let healthy_elapsed = healthy_started.elapsed();
        assert!(
            healthy_elapsed < Duration::from_millis(GRACEFUL_STOP_MS / 2),
            "a process with default SIGTERM disposition must die in well under \
             half the graceful-stop bound, got {healthy_elapsed:?}"
        );

        // Outcome 2 (wedged): a SIGTERM-IGNORING process, driven through the
        // REAL `graceful_stop`, must survive the initial SIGTERM, sit out
        // the full `GRACEFUL_STOP_MS` window, and then die from the
        // follow-up SIGKILL (which a `trap` cannot ignore) — never from its
        // own unrelated `sleep 30`.
        let mut wedged_child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .spawn()
            .expect("spawn SIGTERM-ignoring stub");
        // Give the shell a moment to install the trap before signalling —
        // without this, `graceful_stop`'s SIGTERM can race the shell's own
        // startup and arrive before `trap` has run, in which case the
        // DEFAULT (terminate) disposition applies and the child dies almost
        // instantly, exactly like `signal_supervisor_delivers_to_a_real_child`
        // in `codex_supervisor.rs` already documents for the identical race.
        std::thread::sleep(Duration::from_millis(150));
        let wedged_started = std::time::Instant::now();
        graceful_stop(&mut wedged_child);
        let wedged_elapsed = wedged_started.elapsed();
        assert!(
            wedged_elapsed >= Duration::from_millis(GRACEFUL_STOP_MS),
            "graceful_stop must wait out the FULL window before SIGKILL-ing a \
             SIGTERM-ignoring child, got {wedged_elapsed:?}"
        );
        assert!(
            wedged_elapsed < Duration::from_secs(29),
            "graceful_stop must have SIGKILLed the wedged child well before its \
             unrelated `sleep 30` could complete on its own, got {wedged_elapsed:?}"
        );

        let _ = Write::flush(&mut std::io::stdout());
    }

    // ── C-R4-6: graceful_stop's SIGKILL reaches DESCENDANTS, not only the
    //    direct child ──────────────────────────────────────────────────────

    #[test]
    fn graceful_stop_kills_a_grandchild_descendant_too() {
        // A SIGTERM-ignoring shell that backgrounds a `sleep 30` grandchild
        // and then waits — mirrors the real npm-installed-codex shape
        // (`node` launcher -> real codex process) that C-R4-6 exists for:
        // SIGKILL aimed only at the direct child would leave the
        // grandchild running, orphaned from this supervisor's view.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 30 & wait"])
            .spawn()
            .expect("spawn SIGTERM-ignoring parent with a backgrounded child");
        // Give the shell time to install the trap and background the
        // grandchild before collecting descendants (same race guarded
        // against in `graceful_stop_bound_documents_two_named_outcomes`).
        std::thread::sleep(Duration::from_millis(200));

        let descendants = collect_descendant_pids(child.id());
        assert_eq!(
            descendants.len(),
            1,
            "precondition: the backgrounded `sleep 30` must be discoverable \
             as exactly one descendant of the shell before the kill, or this \
             test cannot tell a real fix from a vacuous one — got {descendants:?}"
        );
        let grandchild_pid = descendants[0];
        // Precondition: the grandchild is genuinely alive right now (ESRCH
        // would mean ps mis-parsed or the process already exited on its
        // own, either of which would make the post-kill check meaningless).
        assert_eq!(
            unsafe { libc::kill(grandchild_pid as libc::pid_t, 0) },
            0,
            "precondition: descendant pid {grandchild_pid} must be alive \
             before graceful_stop runs"
        );

        graceful_stop(&mut child);

        // Give the SIGKILL a moment to actually reap the grandchild (kill(2)
        // is async; the grandchild's exit is observed via ESRCH on kill(pid, 0)
        // once its zombie/slot is reclaimed by its new reaper — a brief
        // poll avoids a flaky one-shot check).
        let mut still_alive = true;
        for _ in 0..20 {
            if unsafe { libc::kill(grandchild_pid as libc::pid_t, 0) } != 0 {
                still_alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !still_alive,
            "C-R4-6: graceful_stop must SIGKILL every live descendant of the \
             direct child, not only the direct child itself — grandchild \
             pid {grandchild_pid} was still alive after graceful_stop returned"
        );
    }

    /// Informational item (round 5): a mismatched snapshot start time (the
    /// recycled-pid stand-in) must be filtered OUT rather than signalled —
    /// this is the discriminating case the recycling guard exists for.
    /// A genuinely matching snapshot must be kept.
    #[test]
    fn descendants_still_matching_snapshot_filters_out_a_mismatched_start_time() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a real live process");
        let pid = child.id();
        assert_eq!(
            unsafe { libc::kill(pid as libc::pid_t, 0) },
            0,
            "precondition: process must be alive"
        );
        let real_start_time = sup::process_start_time(pid);
        assert!(
            real_start_time.is_some(),
            "precondition: start time must be readable for a live pid"
        );

        // Genuine match: the snapshot equals the CURRENT start time -> kept.
        let matching = vec![(pid, real_start_time.clone())];
        assert_eq!(
            descendants_still_matching_snapshot(&matching),
            vec![pid],
            "a snapshot matching the pid's real, current start time must be kept"
        );

        // Forged snapshot — a start time that could not possibly be this
        // live process's own (the recycled-pid stand-in: same pid number,
        // different process identity).
        let forged = vec![(pid, Some("Thu Jan  1 00:00:00 1970".to_string()))];
        assert!(
            descendants_still_matching_snapshot(&forged).is_empty(),
            "a mismatched snapshot start time must be filtered out, not signalled \
             — this is the recycled-pid case the guard exists to catch"
        );

        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    // ── C-F1: SIGINT/SIGQUIT ignore must be installed AFTER spawn ──────────

    #[test]
    fn sigint_disposition_resets_before_child_exec() {
        // Out-of-process: a successfully-delivered SIGINT makes `sh`'s own
        // exit non-zero, which (correctly) drives `run_supervised_unix`'s
        // terminal-exit branch to `std::process::exit` — that would kill
        // THIS test harness process if run in-process, so it is exercised
        // via a subprocess, mirroring `relaunch_failure_helper`'s pattern.
        let exe = std::env::current_exe().expect("current test exe");
        let started = std::time::Instant::now();
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::sigint_disposition_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as sigint-disposition helper");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "the supervised child must die from its OWN self-delivered SIGINT \
             (default disposition, because C-F1 installs the supervisor's \
             SIG_IGN AFTER spawn) rather than survive past its `sleep 5` under \
             an inherited SIG_IGN, elapsed={elapsed:?}"
        );
        assert!(
            !output.status.success(),
            "a child killed by its own SIGINT is a non-zero exit for csq"
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `sigint_disposition_resets_before_child_exec` above, so
    /// its `std::process::exit` (from `run_supervised_unix`'s non-zero-exit
    /// branch) terminates the HELPER process, not the outer test binary.
    #[test]
    #[ignore]
    fn sigint_disposition_helper() {
        let dir = tmp_handle_dir();
        // `sh` sends itself SIGINT, then (if that had no effect — the BUG
        // this test regresses) sleeps long enough to make the bug obvious
        // without hanging the suite for the full duration.
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("kill -INT $$; sleep 5");
        let mut audit = test_audit_emitter(dir.path());
        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked"),
        );
        panic!("run_supervised must have called process::exit before returning");
    }

    // ── Item 6 (C-R4-2): the signal reset ALSO covers the run_unsupervised
    //    fallback taken when write_supervisor_record fails ─────────────────

    #[test]
    fn run_unsupervised_fallback_also_resets_sigint_disposition() {
        // Same out-of-process rationale as `sigint_disposition_resets_
        // before_child_exec`: a successfully-delivered SIGINT drives
        // `process::exit`.
        let exe = std::env::current_exe().expect("current test exe");
        let started = std::time::Instant::now();
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::run_unsupervised_fallback_sigint_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as run-unsupervised-fallback-sigint helper");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "C-R4-2: reset_signal_dispositions_before_exec runs BEFORE the \
             write_supervisor_record check, so the run_unsupervised FALLBACK \
             (taken here because the handle dir is read-only) must ALSO \
             reset SIGINT to SIG_DFL before spawning — the child must die \
             from its own self-delivered SIGINT rather than survive under \
             an inherited SIG_IGN, elapsed={elapsed:?}"
        );
        assert!(
            !output.status.success(),
            "a child killed by its own SIGINT is a non-zero exit for csq"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("could not record codex supervisor state"),
            "the helper must actually take the run_unsupervised FALLBACK \
             (write_supervisor_record failing on the chmod'd read-only \
             handle dir) — otherwise this test proves nothing about the \
             fallback branch. stderr={stderr:?}"
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `run_unsupervised_fallback_also_resets_sigint_disposition`
    /// above. Chmods the handle dir read-only BEFORE calling `run_supervised`
    /// so `write_supervisor_record`'s atomic write fails deterministically,
    /// forcing `run_supervised_unix` down its `run_unsupervised` fallback
    /// branch (the eprintln'd "could not record codex supervisor state"
    /// path) — the one C-R4-2 protects.
    #[test]
    #[ignore]
    fn run_unsupervised_fallback_sigint_helper() {
        // Simulate the scenario the C-R4-2 doc comment actually warns about:
        // "by which point THIS process may already hold SIG_IGN for
        // SIGINT/SIGQUIT from an earlier child". Without this, the test
        // process's own SIGINT disposition is the harness's default
        // (SIG_DFL), so a forked child would die from `kill -INT $$`
        // whether or not `reset_signal_dispositions_before_exec` ran on
        // it — the mutation this test exists to catch would NOT red it.
        // Ignoring SIGINT here first makes the two cases (reset applied /
        // reset skipped) actually diverge: `pre_exec`'s explicit SIG_DFL
        // wins over the inherited SIG_IGN only when it runs.
        ignore_signal(libc::SIGINT);
        let dir = tmp_handle_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod handle dir read-only");
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("kill -INT $$; sleep 5");
        let mut audit = test_audit_emitter(dir.path());
        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked"),
        );
        panic!("run_supervised must have called process::exit before returning");
    }

    // ── C-R4-7: a termination signal that arrived BEFORE the spawn point
    //    (not merely during graceful_stop) must exit cleanly WITHOUT
    //    spawning and WITHOUT writing an audit record ─────────────────────

    #[test]
    fn pending_termination_flag_exits_before_spawn_with_no_side_effects() {
        // Out-of-process: `exit_cleanly_if_terminating_before_spawn` calls
        // `std::process::exit`, which would kill the test harness if run
        // in-process. Calls the function DIRECTLY (not the full
        // `run_supervised` -> `drive_child` path): `drive_child`'s OWN poll
        // loop ALSO consumes `SIGTERM_FLAG` (and forwards it to the child
        // as a real signal) on its very first iteration, with no sleep
        // before that first check — racing "sh forks+execs touch" against
        // "drive_child reads the flag and kills the child" and, empirically,
        // usually winning. That race confounds a full-path test: it cannot
        // tell "never spawned" (this function's job) apart from "spawned,
        // killed a moment later by a DIFFERENT guard" — both can produce
        // the exact same 128+SIGTERM exit code with no marker file either
        // way. Calling this function alone removes the confound entirely.
        let exe = std::env::current_exe().expect("current test exe");
        let output = std::process::Command::new(exe)
            .arg(
                "cli::commands::codex_supervise::tests::\
                 pending_termination_flag_exits_before_spawn_helper",
            )
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as pending-termination-flag helper");
        assert_eq!(
            output.status.code(),
            Some(EXIT_CODE_SIGTERM_DURING_SWAP),
            "a SIGTERM_FLAG already set before the spawn point must exit \
             {EXIT_CODE_SIGTERM_DURING_SWAP} (128+SIGTERM); \
             stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by
    /// `pending_termination_flag_exits_before_spawn_with_no_side_effects`
    /// above. Sets `SIGTERM_FLAG` directly (module-private access via
    /// `super::*`), writes a supervisor record first (mirroring what
    /// `run_supervised_unix` has already done by the time it reaches this
    /// call), then calls `exit_cleanly_if_terminating_before_spawn` alone.
    #[test]
    #[ignore]
    fn pending_termination_flag_exits_before_spawn_helper() {
        SIGTERM_FLAG.store(true, Ordering::SeqCst);
        let dir = tmp_handle_dir();
        sup::write_supervisor_record(dir.path()).expect("write supervisor record");
        assert!(
            dir.path().join(sup::SUPERVISOR_FILE).exists(),
            "precondition: the supervisor record must exist before the call \
             under test, so its removal is an observable, meaningful effect"
        );
        let mut audit = test_audit_emitter(dir.path());
        exit_cleanly_if_terminating_before_spawn(
            dir.path(),
            dir.path(),
            /* is_relaunch */ false,
            None,
            &mut audit,
        );
        panic!("exit_cleanly_if_terminating_before_spawn must have called process::exit before returning");
    }

    /// F4: on a RELAUNCH the already-evaluated gate record MUST be
    /// finalized as `Fail`/`Reject` (the same shape as
    /// `Outcome::TerminatedBeforeRelaunch`) rather than discarded — a
    /// discarded record would silently drop the swap's own governance
    /// verdict. Calls the REAL `exit_cleanly_if_terminating_before_spawn`
    /// (not a re-implementation of its branches) with `is_relaunch: true`,
    /// against a socket path that is deliberately never bound, so
    /// `try_flush_now`'s live-IPC attempt fails and falls through to the
    /// `.pending/<run_id>.jsonl` writer (`flush_record`/`write_pending`).
    /// The `pending_dir` is passed in via `CSQ_TEST_PENDING_DIR` rather
    /// than the helper's own ephemeral `tmp_handle_dir()`, specifically so
    /// this OUTER test can inspect it after the subprocess's
    /// `std::process::exit` (unlike `handle_dir_abs`/`SUPERVISOR_FILE`,
    /// which the helper's own tempdir cleanup would otherwise have made
    /// unobservable from here). A pre-fix build that called `discard()`
    /// unconditionally (ignoring `is_relaunch`) would leave `.pending/`
    /// empty and fail this test's file-existence assertion.
    #[test]
    fn relaunch_finalize_writes_a_pending_record() {
        let exe = std::env::current_exe().expect("current test exe");
        let pending_dir = tempfile::TempDir::new().expect("tempdir");
        let output = std::process::Command::new(exe)
            .arg(
                "cli::commands::codex_supervise::tests::\
                 relaunch_finalize_writes_a_pending_record_helper",
            )
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .env("CSQ_TEST_PENDING_DIR", pending_dir.path())
            .output()
            .expect("spawn self as relaunch-finalize helper");
        assert_eq!(
            output.status.code(),
            Some(EXIT_CODE_SIGTERM_DURING_SWAP),
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let pending_path = pending_dir.path().join("f4-relaunch-finalize.jsonl");
        assert!(
            pending_path.exists(),
            "is_relaunch=true must finalize+flush, not discard — .pending/ \
             must contain the record when no daemon is listening"
        );
        let body = std::fs::read_to_string(&pending_path).unwrap();
        assert!(
            body.contains("\"reject\""),
            "the flushed record must carry the Reject decision: {body}"
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `relaunch_finalize_writes_a_pending_record` above.
    /// Calls `exit_cleanly_if_terminating_before_spawn` directly with
    /// `is_relaunch: true`, out-of-process because it ends in
    /// `std::process::exit`.
    #[test]
    #[ignore]
    fn relaunch_finalize_writes_a_pending_record_helper() {
        use csq_core::audit::{Decision, ResultState};

        SIGTERM_FLAG.store(true, Ordering::SeqCst);
        let dir = tmp_handle_dir();
        sup::write_supervisor_record(dir.path()).expect("write supervisor record");
        let pending_dir =
            PathBuf::from(std::env::var("CSQ_TEST_PENDING_DIR").expect("CSQ_TEST_PENDING_DIR set"));
        let mut audit = crate::cli::audit_emit::AuditEmitter::new(
            csq_core::audit::AuditRecord {
                schema_version: "1".to_string(),
                run_id: "f4-relaunch-finalize".to_string(),
                fixture_sha256: "0".repeat(64),
                coc_sha256: "0".repeat(64),
                csq_version: env!("CARGO_PKG_VERSION").to_string(),
                cli_version: "unknown".to_string(),
                surface: csq_core::audit::Surface::Codex,
                model: "unknown".to_string(),
                start_ts: "2026-09-26T00:00:00Z".to_string(),
                end_ts: "2026-09-26T00:00:00Z".to_string(),
                result_state: ResultState::Degraded,
                score_delta_vs_baseline: None,
                rule_ids_cited_original: vec![],
                rule_ids_cited_after_repair: vec![],
                rule_ids_dropped_invalid_format: 0,
                decision: Decision::Bypass,
                spawn_gate: None,
            },
            dir.path().join("csq.sock"), // never bound — forces the .pending/ fallback
            pending_dir,
            "csq run account 9 (relaunch)".to_string(),
        );
        exit_cleanly_if_terminating_before_spawn(
            dir.path(),
            dir.path(),
            /* is_relaunch */ true,
            None,
            &mut audit,
        );
        panic!("exit_cleanly_if_terminating_before_spawn must have called process::exit before returning");
    }

    /// D-F2 (round 7): when a termination signal arrives in the window
    /// between a swap's teardown and its relaunch spawn, the relaunch never
    /// reaches the point that would write the correlated OUTCOME as `Ok` —
    /// so this function must write it as `Failed("terminated before
    /// relaunch")` itself, closing out the INTENT rather than leaving it a
    /// silent orphan indistinguishable from a genuine crash. RED against a
    /// build that ignores `swap_correlation` (the pre-fix signature): the
    /// scan below would find the INTENT still orphaned.
    #[test]
    fn terminated_before_relaunch_writes_failed_outcome_for_swap_correlation() {
        let exe = std::env::current_exe().expect("current test exe");
        let base_dir = tempfile::TempDir::new().expect("tempdir");
        let output = std::process::Command::new(exe)
            .arg(
                "cli::commands::codex_supervise::tests::\
                 terminated_before_relaunch_writes_failed_outcome_helper",
            )
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .env("CSQ_TEST_BASE_DIR", base_dir.path())
            .output()
            .expect("spawn self as D-F2 helper");
        assert_eq!(
            output.status.code(),
            Some(EXIT_CODE_SIGTERM_DURING_SWAP),
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let orphans = csq_core::audit::scan_orphan_intents(base_dir.path())
            .expect("orphan scan must succeed");
        assert!(
            orphans.is_empty(),
            "the correlated INTENT must be resolved (Failed), not left \
             orphaned by a termination-before-relaunch exit: {orphans:?}"
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by
    /// `terminated_before_relaunch_writes_failed_outcome_for_swap_correlation`
    /// above.
    #[test]
    #[ignore]
    fn terminated_before_relaunch_writes_failed_outcome_helper() {
        let base_dir =
            PathBuf::from(std::env::var("CSQ_TEST_BASE_DIR").expect("CSQ_TEST_BASE_DIR set"));
        SIGTERM_FLAG.store(true, Ordering::SeqCst);
        let handle_dir = tmp_handle_dir();
        sup::write_supervisor_record(handle_dir.path()).expect("write supervisor record");

        let chain_id = csq_core::audit::op_emit::load_chain_id(&base_dir);
        let correlation_id =
            csq_core::audit::op_emit::gen_correlation_id().expect("correlation_id");
        let from_slot = csq_core::types::AccountNum::try_from(1u16).unwrap();
        let to_slot = csq_core::types::AccountNum::try_from(2u16).unwrap();
        csq_core::audit::op_emit::emit_intent(
            &base_dir,
            &chain_id,
            csq_core::audit::EventKind::AccountSwap,
            csq_core::audit::EventPayload::AccountSwap(csq_core::audit::AccountSwapPayload {
                from_slot,
                to_slot,
            }),
            correlation_id.clone(),
        )
        .expect("intent write must succeed");

        let req = sup::SwapRequest {
            target_slot: 2,
            chain_id: chain_id.clone(),
            correlation_id: correlation_id.as_str().to_string(),
            from_slot: 1,
            // The request nonce no longer participates in
            // `verify_swap_correlation` (round 8, C-B1/C-B2 — see
            // `AccountSwapPayload`'s doc); `..Default::default()` supplies a
            // fresh one purely to satisfy the struct, unused by this test.
            ..Default::default()
        };
        let corr = sup::SwapAuditCorrelation::from_request(&req).expect("correlation present");

        let mut audit = test_audit_emitter(handle_dir.path());
        exit_cleanly_if_terminating_before_spawn(
            handle_dir.path(),
            &base_dir,
            /* is_relaunch */ true,
            Some(&corr),
            &mut audit,
        );
        panic!("exit_cleanly_if_terminating_before_spawn must have called process::exit before returning");
    }

    // ── FM-1: the SIGINT/SIGQUIT reset must ALSO apply to a RELAUNCHED
    //    child, not just the first spawn ────────────────────────────────────

    #[test]
    fn relaunch_sigint_disposition_resets_before_child_exec() {
        // Out-of-process for the same reason as `sigint_disposition_
        // resets_before_child_exec` above: the relaunched child's own
        // non-zero exit drives `std::process::exit`, which would kill this
        // test harness if run in-process.
        let exe = std::env::current_exe().expect("current test exe");
        let started = std::time::Instant::now();
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::relaunch_sigint_disposition_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as relaunch-sigint-disposition helper");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "the RELAUNCHED child must die from its OWN self-delivered SIGINT \
             (default disposition, because FM-1's `reset_signal_dispositions_\
             before_exec` resets it on EVERY spawn, including a relaunch — \
             not just the first) rather than survive past its `sleep 5` under \
             the supervisor's SIG_IGN (installed after the FIRST child, and \
             inherited by fork+exec absent this fix), elapsed={elapsed:?}"
        );
        assert!(
            !output.status.success(),
            "a relaunched child killed by its own SIGINT is a non-zero exit"
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `relaunch_sigint_disposition_resets_before_child_exec`
    /// above. Drives a REAL swap-relaunch cycle: a first (stub-cli) child is
    /// torn down via a validated swap request, and the RELAUNCH is a
    /// self-signalling `sh` child spawned through a NESTED `run_supervised`
    /// call (the same shape `launch_codex`'s `relaunch` closure uses in
    /// production — it recurses back into `run_supervised` for the new
    /// child) — so the fix under test (applied inside `run_supervised_unix`,
    /// at the SECOND, re-entrant `cmd.spawn()`) is genuinely exercised.
    #[test]
    #[ignore]
    fn relaunch_sigint_disposition_helper() {
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "5000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());
        let base_dir = valid_swap_target_base_dir(6);

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 6,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let _ = run_supervised(
            cmd,
            dir.path(),
            base_dir.0.path(),
            default_validate(base_dir.0.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_slot, _thread_id, _swap_correlation, relaunch_emitter| {
                let inner_dir = tmp_handle_dir();
                let mut relaunch_cmd = std::process::Command::new("sh");
                relaunch_cmd.arg("-c").arg("kill -INT $$; sleep 5");
                run_supervised(
                    relaunch_cmd,
                    inner_dir.path(),
                    inner_dir.path(),
                    never_validate,
                    /* is_relaunch */ true,
                    None,
                    relaunch_emitter,
                    |_, _, _, _| panic!("no further relaunch expected"),
                )
            },
        );
        panic!(
            "run_supervised must have called process::exit before returning \
             (the relaunched child's own self-delivered SIGINT is a non-zero exit)"
        );
    }

    // ── FM-4: a SIGHUP arriving during graceful_stop exits cleanly instead
    //    of relaunching ────────────────────────────────────────────────────

    #[test]
    fn sighup_during_graceful_stop_exits_without_relaunch() {
        // Out-of-process: `Outcome::TerminatedBeforeRelaunch`'s handling
        // calls `std::process::exit`, which would kill the test harness if
        // run in-process.
        let exe = std::env::current_exe().expect("current test exe");
        let started = std::time::Instant::now();
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::sighup_during_graceful_stop_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as sighup-during-graceful-stop helper");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(GRACEFUL_STOP_MS),
            "must wait out the full graceful-stop window (the child ignores \
             SIGTERM) before exiting, got {elapsed:?}"
        );
        assert_eq!(
            output.status.code(),
            Some(129),
            "a SIGHUP arriving during graceful_stop must exit 129 (128+SIGHUP) \
             WITHOUT relaunching, got {:?}",
            output.status
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `sighup_during_graceful_stop_exits_without_relaunch`
    /// above. The supervised child TRAPS (ignores) `SIGTERM`, so
    /// `graceful_stop` sits out the FULL `GRACEFUL_STOP_MS` window — a wide,
    /// deterministic target for the SIGHUP injected 400ms after SIGUSR1
    /// (well inside that window, on both sides).
    #[test]
    #[ignore]
    fn sighup_during_graceful_stop_helper() {
        let dir = tmp_handle_dir();
        let base_dir = valid_swap_target_base_dir(11);
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "trap '' TERM; sleep 30"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            // Give the shell time to install its TERM trap before the swap
            // fires (mirrors `graceful_stop_bound_documents_two_named_
            // outcomes`'s identical race note).
            std::thread::sleep(Duration::from_millis(200));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 11,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });
        std::thread::spawn(|| {
            // Lands squarely inside the 3000ms graceful_stop window this
            // SIGUSR1 triggers (100ms trap-install + 100ms SIGUSR1-processing
            // margin on the near side; ~2600ms of margin on the far side).
            std::thread::sleep(Duration::from_millis(400));
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGHUP);
            }
        });

        let _ = run_supervised(
            cmd,
            dir.path(),
            base_dir.0.path(),
            default_validate(base_dir.0.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                panic!("relaunch must NOT be invoked when SIGHUP arrived during graceful_stop")
            },
        );
        panic!("run_supervised must have called process::exit(129) before returning");
    }

    // ── C-R4-5: tty raw-mode restore fires after ANY graceful_stop outcome,
    //    not only SIGKILL ─────────────────────────────────────────────────

    #[test]
    fn restore_tty_after_stop_always_restores_when_state_was_captured() {
        // SAFETY: a zeroed `termios` is never passed to a real tcsetattr in
        // this test — `restore` below is a recording closure, not
        // `restore_tty_state` — so its content is irrelevant; only whether
        // the closure is INVOKED is under test.
        let state = TtyRawState(unsafe { std::mem::zeroed() });

        // RED (pre-C-R4-5 behavior, regressed deliberately to prove this
        // assertion discriminates): the OLD `restore_tty_if_killed` gated on
        // `StopOutcome::Killed` and would NOT have called `restore` here for
        // `ExitedOnTerm` — the exact default-disposition-SIGTERM case this
        // fix closes. `restore_tty_after_stop` takes no outcome parameter at
        // all now, so it cannot reintroduce that gate.
        let killed_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let killed_calls_clone = killed_calls.clone();
        restore_tty_after_stop(Some(&state), |_| {
            killed_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(
            killed_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a captured tty state must be restored"
        );

        let term_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let term_calls_clone = term_calls.clone();
        restore_tty_after_stop(Some(&state), |_| {
            term_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(
            term_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a captured tty state must ALSO be restored on what would have \
             been the ExitedOnTerm outcome — a default-disposition SIGTERM \
             death never ran the child's own raw-mode cleanup, so this must \
             restore too, not just a SIGKILL"
        );

        // No captured state (non-tty stdin) — must not call `restore`;
        // there is nothing to restore.
        let none_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let none_calls_clone = none_calls.clone();
        restore_tty_after_stop(None, |_| {
            none_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(
            none_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "with no captured tty state there is nothing to restore"
        );
    }

    /// F7: under `cargo test`, stdout is captured (a pipe), never a tty —
    /// `write_terminal_reset_if_tty` must be a genuine no-op there rather
    /// than writing raw escape bytes into the captured test-output stream
    /// (which would corrupt every OTHER test's captured stdout in the same
    /// binary). This is exactly the `is_terminal() == false` branch every
    /// CI run and every local `cargo test` invocation actually takes, so it
    /// is the one branch worth asserting does not panic or hang.
    #[test]
    fn write_terminal_reset_if_tty_is_a_no_op_under_the_test_harness() {
        use std::io::IsTerminal;
        assert!(
            !std::io::stdout().is_terminal(),
            "fixture invariant: `cargo test` stdout must be captured (non-tty), \
             or this test is not exercising the no-op branch it claims to"
        );
        // Must not panic — the only externally observable contract here.
        write_terminal_reset_if_tty();
    }

    // ── C-R4-5: `tty_baseline` caches via OnceLock — never recaptures ───────

    /// `tty_baseline()` is a process-global `OnceLock`, so this must run in
    /// its OWN subprocess: calling it from a normal in-process test would
    /// permanently poison the static for every OTHER test in this binary
    /// (they share one process). Proves the claim in `tty_baseline`'s doc
    /// comment: two calls in the same process return the SAME cached value
    /// (by address), never a fresh capture each time.
    #[test]
    fn tty_baseline_caches_across_calls_subprocess() {
        let exe = std::env::current_exe().expect("current test exe");
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::tty_baseline_caches_across_calls_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .output()
            .expect("spawn self as tty-baseline-caching helper");
        assert!(
            output.status.success(),
            "helper must observe tty_baseline() returning the SAME address \
             on both calls; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Not run by the normal test harness (`#[ignore]`) — invoked ONLY as a
    /// subprocess by `tty_baseline_caches_across_calls_subprocess` above.
    #[test]
    #[ignore]
    fn tty_baseline_caches_across_calls_helper() {
        // A meaningful address comparison needs `tty_baseline()` to return
        // `Some` on both calls — with no tty, both calls return `None` and
        // pointer comparison of the (absent) inner reference is vacuously
        // equal regardless of whether caching happened at all. Repoint fd 0
        // at a real pty slave first (same technique as
        // `flush_typed_ahead_stdin_discards_queued_pty_input`).
        let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(unsafe { libc::grantpt(master_fd) }, 0, "grantpt failed");
        assert_eq!(unsafe { libc::unlockpt(master_fd) }, 0, "unlockpt failed");
        let slave_path = unsafe {
            let ptr = libc::ptsname(master_fd);
            assert!(!ptr.is_null(), "ptsname returned null");
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        };
        let slave_path_c = std::ffi::CString::new(slave_path).unwrap();
        let slave_fd = unsafe { libc::open(slave_path_c.as_ptr(), libc::O_RDWR) };
        assert!(slave_fd >= 0, "open(slave) failed");
        assert_eq!(
            unsafe { libc::dup2(slave_fd, 0) },
            0,
            "dup2(slave, 0) failed"
        );
        assert_eq!(
            unsafe { libc::isatty(0) },
            1,
            "fd 0 must be a tty for this test to exercise the Some(..) branch"
        );

        let first = tty_baseline().map(|r| r as *const TtyRawState);
        let second = tty_baseline().map(|r| r as *const TtyRawState);
        assert!(
            first.is_some(),
            "precondition: tty_baseline() must be Some on a real tty"
        );
        assert_eq!(
            first, second,
            "tty_baseline() must return the SAME cached OnceLock slot on \
             every call within a process — a fresh capture each time would \
             return a different address"
        );
    }

    // ── Round-3 gap (a): typed-ahead stdin is genuinely discarded ───────────

    /// `flush_typed_ahead_stdin` claims: queued-but-unread keystrokes on a
    /// TTY stdin are discarded by `tcflush(STDIN_FILENO, TCIFLUSH)`. This
    /// proves the claim against a REAL pty rather than asserting on the
    /// function's source — `isatty`/`tcflush` operate on the fixed
    /// `STDIN_FILENO` constant, so the only way to exercise the branch this
    /// function actually takes is to make fd 0 a real tty for the duration
    /// of the test.
    ///
    /// Serialized by `lock_signal_state()`: this test temporarily
    /// repoints the WHOLE PROCESS's fd 0, which is exactly the shared,
    /// process-global resource that mutex already exists to protect other
    /// tests in this file from racing on.
    #[test]
    fn flush_typed_ahead_stdin_discards_queued_pty_input() {
        let _guard = lock_signal_state();

        // Open a POSIX pty pair. `posix_openpt`/`grantpt`/`unlockpt`/`ptsname`
        // are POSIX (not BSD-only), so this is portable across the unix
        // targets this crate tests on.
        let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(
            master_fd >= 0,
            "posix_openpt failed: {:?}",
            std::io::Error::last_os_error()
        );
        assert_eq!(unsafe { libc::grantpt(master_fd) }, 0, "grantpt failed");
        assert_eq!(unsafe { libc::unlockpt(master_fd) }, 0, "unlockpt failed");
        let slave_path = unsafe {
            let ptr = libc::ptsname(master_fd);
            assert!(!ptr.is_null(), "ptsname returned null");
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        };
        let slave_path_c = std::ffi::CString::new(slave_path).unwrap();
        let slave_fd = unsafe { libc::open(slave_path_c.as_ptr(), libc::O_RDWR) };
        assert!(
            slave_fd >= 0,
            "open(slave) failed: {:?}",
            std::io::Error::last_os_error()
        );

        // Save the real stdin so it can be restored no matter how this test
        // exits (including a panicking assertion above/below).
        let saved_stdin = unsafe { libc::dup(0) };
        assert!(saved_stdin >= 0, "dup(0) failed");

        let restore = || unsafe {
            libc::dup2(saved_stdin, 0);
            libc::close(saved_stdin);
            libc::close(slave_fd);
            libc::close(master_fd);
        };

        // Repoint fd 0 at the pty slave — this is what makes `isatty
        // (STDIN_FILENO)` true for the duration of the test.
        assert_eq!(
            unsafe { libc::dup2(slave_fd, 0) },
            0,
            "dup2(slave, 0) failed"
        );
        assert_eq!(
            unsafe { libc::isatty(0) },
            1,
            "fd 0 must be a tty after dup2 for this test to exercise the real branch"
        );

        // Write "typed-ahead" keystrokes into the master side and give the
        // line discipline a moment to queue them on the slave's read side
        // (canonical mode holds input until a newline, which this includes).
        let typed = b"queued-keystrokes-nobody-read\n";
        let written = unsafe {
            libc::write(
                master_fd,
                typed.as_ptr() as *const libc::c_void,
                typed.len(),
            )
        };
        assert_eq!(written, typed.len() as isize, "write to pty master failed");
        std::thread::sleep(Duration::from_millis(50));

        // The behavior under test.
        flush_typed_ahead_stdin();

        // Put the slave fd in non-blocking mode and attempt a read: if the
        // flush discarded the queued input, this returns 0 bytes readable
        // (EAGAIN/EWOULDBLOCK) rather than the typed bytes.
        let flags = unsafe { libc::fcntl(slave_fd, libc::F_GETFL) };
        unsafe {
            libc::fcntl(slave_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(slave_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        let read_errno = std::io::Error::last_os_error();

        restore();

        assert!(
            n < 0
                && (read_errno.raw_os_error() == Some(libc::EAGAIN)
                    || read_errno.raw_os_error() == Some(libc::EWOULDBLOCK)),
            "flush_typed_ahead_stdin must have discarded the queued input; \
             instead a read returned n={n} (errno={read_errno:?}) — the \
             typed-ahead keystrokes were still there to be delivered to \
             whatever reads stdin next"
        );
    }

    // ── C-F4: a non-zero exit records Fail/Accept before flushing ──────────

    #[cfg(unix)]
    fn sample_audit_record(run_id: &str) -> csq_core::audit::AuditRecord {
        use csq_core::audit::{AuditRecord, Decision, ResultState, Surface};
        AuditRecord {
            schema_version: "1".to_string(),
            run_id: run_id.to_string(),
            fixture_sha256: "a".repeat(64),
            coc_sha256: "b".repeat(64),
            csq_version: "test".to_string(),
            cli_version: "test".to_string(),
            surface: Surface::Codex,
            model: "unknown".to_string(),
            start_ts: "2026-09-26T00:00:00Z".to_string(),
            end_ts: "2026-09-26T00:00:00Z".to_string(),
            result_state: ResultState::Degraded,
            score_delta_vs_baseline: None,
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Bypass,
            spawn_gate: None,
        }
    }

    #[test]
    fn nonzero_exit_records_fail_and_accept_before_flush() {
        // Out-of-process for the same reason as the SIGINT test above: a
        // non-zero exit drives `std::process::exit`.
        let exe = std::env::current_exe().expect("current test exe");
        let pending_dir = tempfile::TempDir::new().expect("pending tempdir");
        let output = std::process::Command::new(exe)
            .arg("cli::commands::codex_supervise::tests::nonzero_exit_audit_helper")
            .arg("--exact")
            .arg("--nocapture")
            .arg("--ignored")
            .env("CSQ_TEST_AUDIT_PENDING_DIR", pending_dir.path())
            .output()
            .expect("spawn self as nonzero-exit-audit helper");
        assert!(
            !output.status.success(),
            "the child's own non-zero exit becomes csq's exit code"
        );

        let mut entries: Vec<_> = std::fs::read_dir(pending_dir.path())
            .expect("read pending dir")
            .flatten()
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one pending audit record expected from the helper's single run"
        );
        let content =
            std::fs::read_to_string(entries.remove(0).path()).expect("read pending record");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("parse pending record as JSON");
        assert_eq!(
            parsed["result_state"], "fail",
            "a non-zero exit must record ResultState::Fail before the flush, got: {content}"
        );
        assert_eq!(
            parsed["decision"], "accept",
            "a non-zero exit must record Decision::Accept before the flush, got: {content}"
        );
    }

    #[test]
    #[ignore]
    fn nonzero_exit_audit_helper() {
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--exit-code", "3"]);
        let pending_dir = std::path::PathBuf::from(
            std::env::var("CSQ_TEST_AUDIT_PENDING_DIR").expect("pending dir env var"),
        );
        // Never created — forces the `.pending/` fallback deterministically.
        let socket_path = dir.path().join("csq.sock");
        let record = sample_audit_record("nonzero-exit-helper-run");
        let mut audit = AuditEmitter::new(record, socket_path, pending_dir, "test op".to_string());
        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked"),
        );
        panic!("run_supervised must have called process::exit(3) before returning");
    }

    // ── C-F3/S-F4: swap handoff finalizes the ORIGINAL emitter and relaunches
    //    with a FRESH one — two runs, two audit records ────────────────────

    #[test]
    fn swap_handoff_produces_two_distinct_audit_records() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "5000", "--exit-code", "0"]);

        // The ORIGINAL run's emitter: real (non-disabled), pointed at its
        // OWN pending dir + a socket that never exists.
        let original_pending = tempfile::TempDir::new().expect("original pending tempdir");
        let original_socket = dir.path().join("csq.sock");
        let original_record = sample_audit_record("original-run");
        let mut audit = AuditEmitter::new(
            original_record,
            original_socket,
            original_pending.path().to_path_buf(),
            "csq run account 3".to_string(),
        );

        // `base_dir` doubles as BOTH the swap-target validation fixture AND
        // the `build_audit_emitter` root for the FRESH relaunch emitter —
        // `csq-runs/.pending/` under it is where that second record lands.
        let (base_dir, _daemon) = valid_swap_target_base_dir(3);

        let handle_dir_for_writer = dir.path().to_path_buf();
        let supervisor_pid = std::process::id();
        std::thread::spawn(move || {
            // PRIMARY DIRECTIVE: wait for the supervisor's own readiness
            // markers (record + live-pid) rather than a fixed sleep, then
            // re-signal until the request is observably consumed — an
            // ordering proof, not a delay guess.
            assert!(
                wait_for_supervisor_ready(&handle_dir_for_writer, Duration::from_secs(5)),
                "supervisor never became ready (record + live-pid marker) \
                 within 5s"
            );
            write_request_and_signal_until_consumed(
                &handle_dir_for_writer,
                supervisor_pid,
                &sup::SwapRequest {
                    target_slot: 3,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
                Duration::from_secs(5),
            );
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, emitter| {
                // The closure receives the FRESH emitter — assert it is not the
                // disabled/no-op kind by setting a field and letting Drop flush
                // it at the end of this scope.
                use csq_core::audit::{Decision, ResultState};
                emitter.set_result(ResultState::Pass, Decision::Accept);
                Ok(())
            },
        );
        assert!(result.is_ok(), "{result:?}");

        let original_records: Vec<_> = std::fs::read_dir(original_pending.path())
            .expect("read original pending dir")
            .flatten()
            .collect();
        assert_eq!(
            original_records.len(),
            1,
            "the ORIGINAL run's own emitter must have flushed exactly one \
             handed-off-swap record into ITS OWN pending dir"
        );
        let original_content = std::fs::read_to_string(original_records[0].path())
            .expect("read original pending record");
        assert!(
            original_content.contains("\"original-run\""),
            "the flushed record must be the ORIGINAL run's, not a fresh one: {original_content}"
        );

        let relaunch_pending = base_dir.path().join("csq-runs").join(".pending");
        let relaunch_records: Vec<_> = std::fs::read_dir(&relaunch_pending)
            .expect("read relaunch pending dir")
            .flatten()
            .collect();
        assert_eq!(
            relaunch_records.len(),
            1,
            "the RELAUNCH's fresh emitter must flush its OWN, SEPARATE record \
             (via Drop) into base_dir/csq-runs/.pending/ — two runs, two records"
        );
        let relaunch_content = std::fs::read_to_string(relaunch_records[0].path())
            .expect("read relaunch pending record");
        assert!(
            !relaunch_content.contains("\"original-run\""),
            "the relaunch record must NOT be the original run's run_id: {relaunch_content}"
        );
    }

    // ── S-F3/C-F2: an invalid swap target refuses without stopping the
    //    current child ─────────────────────────────────────────────────────

    #[test]
    fn sigusr1_with_invalid_target_slot_does_not_stop_the_child() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        // Deliberately bare — no `config-0/` or `credentials/codex-0.json`
        // (and 0 is out of `AccountNum`'s 1..=999 range regardless).
        let base_dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Child hangs long enough to observe it SURVIVE the refused swap.
        let cmd = stub_cmd(&capture, &["--hang-ms", "600", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 0,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must NOT be invoked for a refused swap target"),
        );
        assert!(
            result.is_ok(),
            "the child must run to its natural (unaffected-by-the-refused-swap) \
             exit: {result:?}"
        );
    }

    // ── FM-5: an unhealthy daemon refuses the swap before the child is
    //    stopped ────────────────────────────────────────────────────────────

    #[test]
    fn sigusr1_with_unhealthy_daemon_does_not_stop_the_child() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        // A FULLY VALID swap target on every OTHER axis (config.toml,
        // legacy credential mirror both present) EXCEPT no daemon fixture
        // — isolating the daemon-health check as the sole refusal cause.
        // NOT `valid_swap_target_base_dir`, which stands up a fake healthy
        // daemon; this test needs the opposite.
        let base_dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(base_dir.path().join("config-8")).unwrap();
        std::fs::write(base_dir.path().join("config-8").join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml (test fixture)
        std::fs::create_dir_all(base_dir.path().join("credentials")).unwrap();
        std::fs::write(
            base_dir.path().join("credentials").join("codex-8.json"),
            b"{}",
        )
        .unwrap();

        let capture = dir.path().join("argv.json");
        // Child hangs long enough to observe it SURVIVE the refused swap.
        let cmd = stub_cmd(&capture, &["--hang-ms", "600", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 8,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            base_dir.path(),
            default_validate(base_dir.path().to_path_buf(), true, true),
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must NOT be invoked when the daemon is down"),
        );
        assert!(
            result.is_ok(),
            "an unhealthy/absent daemon must refuse the swap BEFORE \
             `graceful_stop` runs, leaving the current child to exit on its \
             own: {result:?}"
        );
    }

    // ── C-F5/S-F2: relaunch argv never replays a stale prompt or resume id ─

    #[test]
    fn relaunch_rest_with_no_thread_id_drops_the_original_prompt() {
        let original = vec!["fix the flaky test suite".to_string()];
        let rest = relaunch_rest(3, None, &original);
        assert!(
            rest.is_empty(),
            "a fresh-session relaunch must never replay the original prompt, got: {rest:?}"
        );
    }

    #[test]
    fn relaunch_rest_second_swap_without_id_drops_stale_resume() {
        // First swap resumed thread "id1"; `original_rest` for the SECOND
        // swap is exactly what the FIRST swap's own `relaunch_rest` produced.
        let first_relaunch = relaunch_rest(3, Some("id1"), &[]);
        assert_eq!(
            first_relaunch,
            vec!["resume".to_string(), "id1".to_string()]
        );
        // Second swap discovers NO thread id — must not carry "resume id1"
        // forward from the first.
        let second_relaunch = relaunch_rest(3, None, &first_relaunch);
        assert!(
            second_relaunch.is_empty(),
            "a second swap's fresh-session relaunch must not carry the prior \
             resume id forward, got: {second_relaunch:?}"
        );
    }

    #[test]
    fn relaunch_rest_preserves_sandbox_flag_across_a_resume() {
        let original = vec![
            "-s".to_string(),
            "read-only".to_string(),
            "do the thing".to_string(),
        ];
        let rest = relaunch_rest(3, Some("thread-1"), &original);
        assert_eq!(
            rest,
            vec![
                "-s".to_string(),
                "read-only".to_string(),
                "resume".to_string(),
                "thread-1".to_string(),
            ],
            "the caller's -s read-only must survive the relaunch alongside \
             resume, and the prompt must still be dropped, got: {rest:?}"
        );
    }

    /// Governing task item 2: the `None`-arm note names the exact
    /// slot-scoped relaunch command rather than describing the mechanism
    /// abstractly — verified directly against `relaunch_none_arm_note`,
    /// the function `relaunch_rest`'s `None` arm calls to build the string
    /// it `eprintln!`s.
    #[test]
    fn relaunch_rest_none_arm_still_drops_prompt_regardless_of_slot() {
        let original = vec!["some prior prompt".to_string()];
        for slot in [1u16, 7, 65535] {
            let rest = relaunch_rest(slot, None, &original);
            assert!(
                rest.is_empty(),
                "slot {slot}: fresh-session relaunch must drop the prompt, got: {rest:?}"
            );
        }
    }

    #[test]
    fn relaunch_none_arm_note_names_the_exact_slot_scoped_command() {
        for slot in [1u16, 7, 65535] {
            let note = relaunch_none_arm_note(slot);
            assert!(
                note.contains(&format!("csq run {slot} -- resume")),
                "note must name the exact slot-scoped relaunch command for \
                 slot {slot}, got: {note}"
            );
            assert!(
                note.contains("no prior thread id was"),
                "note must state why no id-specific recovery was offered: {note}"
            );
            assert!(
                note.contains("outside csq"),
                "note must scope the bare-`codex resume` warning to running \
                 outside csq, not recommend it standalone: {note}"
            );
        }
    }

    // ── C-R4-4 completion / F10 (round 5): relaunch validation honors the
    //    ORIGINAL invocation's capability-layer intent ────────────────────
    //
    // F10 (round 5): the two tests this comment used to introduce
    // (`relaunch_validation_honors_original_invocation_{disabled,enabled}_
    // layer`) asserted only `result.is_ok()` for BOTH `enabled=false` and
    // `enabled=true` — and EVERY reachable outcome of
    // `run_capability_layer_preflight` on this admission path (`rest =
    // &[]`) is `Ok(..)`: every `.coc/`-content failure is caught internally
    // and converted to `Ok(LayerControl::Inherit)` (FR-RUN-04's fail-open
    // contract), so a hardcoded `(true, true)` that ignored its arguments
    // entirely would have passed BOTH tests identically to the real
    // threaded values. They were not discriminating tests — see
    // `run.rs::capability_layer_preflight_enabled_flag_changes_the_returned_
    // variant` for the genuinely discriminating regression this proof now
    // lives in (asserting on the returned `LayerControl` VARIANT, which
    // `validate_codex_relaunch_target`'s own `Result<AccountNum>` return
    // type cannot expose).
    //
    // What remains genuinely testable AT THIS layer — and RED under the
    // pre-F2 hardcoded values — is that `drive_child` calls the INJECTED
    // `validate` closure at all, rather than some internal, hardcoded
    // stand-in: a closure that refuses ODD target slots and accepts EVEN
    // ones (an oracle with no relationship to real admission logic) proves
    // the closure's return value, not drive_child's own code, decides the
    // outcome.

    // ── round 6, item 3 (INVEST-NOW F10 replacement): a genuine Err on
    //    this admission path, discriminated by `capability_layer_enabled`,
    //    at BOTH `validate_codex_relaunch_target` itself AND through the
    //    `launch_codex`-shaped `default_validate` closure ─────────────────
    //
    // `run::force_coc_preflight_cwd_err()` forces the ONE reachable `Err`
    // on this path (see that seam's doc in `run.rs`) — every OTHER
    // `.coc/`-content failure is caught internally and downgraded to
    // `Ok(LayerControl::Inherit)` (F10, round 5's finding). With it
    // installed: `enabled=false` short-circuits before the forced Err is
    // ever reached (Ok); `enabled=true` reaches it directly (Err). RED
    // against a `default_validate` (or `validate_codex_relaunch_target`
    // caller) that hardcodes `capability_layer_enabled: true` regardless of
    // its argument — the `enabled=false` assertion below would then also
    // observe Err.

    #[test]
    fn validate_codex_relaunch_target_admits_disabled_and_refuses_enabled_on_forced_preflight_err()
    {
        let (base_dir, _daemon) = valid_swap_target_base_dir(4);
        let _err_guard = crate::cli::commands::run::force_coc_preflight_cwd_err();

        let disabled = crate::cli::commands::run::validate_codex_relaunch_target(
            base_dir.path(),
            4,
            /* capability_layer_enabled */ false,
            /* layer_is_auto */ false,
            &csq_core::capability_layer::CapabilityLayerToggles::default(),
            false,
            true,
        );
        assert!(
            disabled.is_ok(),
            "enabled=false must ADMIT even with the forced cwd-resolution Err \
             in place (the flag short-circuits before that call): {disabled:?}"
        );

        let enabled = crate::cli::commands::run::validate_codex_relaunch_target(
            base_dir.path(),
            4,
            /* capability_layer_enabled */ true,
            /* layer_is_auto */ false,
            &csq_core::capability_layer::CapabilityLayerToggles::default(),
            false,
            true,
        );
        let err = enabled.expect_err(
            "enabled=true must REFUSE when the capability-layer preflight's \
             cwd resolution fails",
        );
        assert!(
            err.to_string().contains("capability-layer check refused"),
            "got: {err}"
        );
    }

    /// D-F9 (round 7): exercises `make_validate_relaunch` ITSELF — not the
    /// test-only `default_validate` re-implementation below, and not a
    /// direct call to `validate_codex_relaunch_target` bypassing the
    /// extracted closure entirely (the two sibling tests above/below this
    /// one). Before this extraction, `launch_codex`'s Inherit and WithLayer
    /// arms each built this closure independently inline; this is the test
    /// that would have caught either copy silently hardcoding
    /// `capability_layer_enabled` rather than forwarding the parameter.
    #[test]
    fn make_validate_relaunch_admits_disabled_and_refuses_enabled_on_forced_preflight_err() {
        let (base_dir, _daemon) = valid_swap_target_base_dir(4);
        let _err_guard = crate::cli::commands::run::force_coc_preflight_cwd_err();
        let toggles = csq_core::capability_layer::CapabilityLayerToggles::default();

        let disabled_closure = crate::cli::commands::run::make_validate_relaunch(
            base_dir.path().to_path_buf(),
            /* capability_layer_enabled */ false,
            /* layer_is_auto */ false,
            toggles,
            false,
            true,
        );
        assert!(
            disabled_closure(4).is_ok(),
            "capability_layer_enabled=false must ADMIT even with the forced \
             cwd-resolution Err in place — the flag must short-circuit \
             before that call is ever reached"
        );

        let enabled_closure = crate::cli::commands::run::make_validate_relaunch(
            base_dir.path().to_path_buf(),
            /* capability_layer_enabled */ true,
            /* layer_is_auto */ false,
            toggles,
            false,
            true,
        );
        let err = enabled_closure(4).expect_err(
            "capability_layer_enabled=true must REFUSE when the \
             capability-layer preflight's cwd resolution fails — if this \
             passes, the closure is hardcoding `enabled` rather than \
             forwarding the parameter",
        );
        assert!(
            err.to_string().contains("capability-layer check refused"),
            "got: {err}"
        );
    }

    #[test]
    fn default_validate_closure_admits_disabled_and_refuses_enabled_on_forced_preflight_err() {
        let (base_dir, _daemon) = valid_swap_target_base_dir(4);
        let _err_guard = crate::cli::commands::run::force_coc_preflight_cwd_err();

        // `default_validate` is the SAME shape `launch_codex` builds (F2,
        // round 5's doc): a closure over the captured invocation's
        // `capability_layer_enabled`/`layer_is_auto`, which calls
        // `validate_codex_relaunch_target` with exactly those values on
        // every `SIGUSR1` — this exercises the CLOSURE, not a direct call.
        let disabled_closure = default_validate(base_dir.path().to_path_buf(), false, false);
        let disabled = disabled_closure(4);
        assert!(
            disabled.is_ok(),
            "the enabled=false closure must ADMIT even with the forced \
             cwd-resolution Err in place: {disabled:?}"
        );

        let enabled_closure = default_validate(base_dir.path().to_path_buf(), true, false);
        let enabled = enabled_closure(4);
        let err = enabled.expect_err(
            "the enabled=true closure must REFUSE when the capability-layer \
             preflight's cwd resolution fails",
        );
        assert!(
            err.to_string().contains("capability-layer check refused"),
            "got: {err}"
        );
    }

    #[test]
    fn drive_child_relaunches_when_the_injected_validate_closure_accepts() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "600", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 4, // even -> the oracle accepts
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let relaunch_called = Arc::new(AtomicBool::new(false));
        let relaunch_called_clone = relaunch_called.clone();
        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            |slot: u16| -> Result<csq_core::types::AccountNum> {
                if slot.is_multiple_of(2) {
                    csq_core::types::AccountNum::try_from(slot).map_err(|e| anyhow!("{e}"))
                } else {
                    Err(anyhow!("odd slot refused by the test oracle"))
                }
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            move |slot, _, _, _| {
                relaunch_called_clone.store(true, Ordering::SeqCst);
                assert_eq!(slot, 4);
                Ok(())
            },
        );
        assert!(
            relaunch_called.load(Ordering::SeqCst),
            "drive_child must relaunch when the INJECTED validate closure \
             (not any internal stand-in) accepts the target"
        );
    }

    #[test]
    fn drive_child_refuses_when_the_injected_validate_closure_refuses() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Child hangs long enough to observe it SURVIVE the refused swap.
        let cmd = stub_cmd(&capture, &["--hang-ms", "600", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 5, // odd -> the oracle refuses
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            |slot: u16| -> Result<csq_core::types::AccountNum> {
                if slot.is_multiple_of(2) {
                    csq_core::types::AccountNum::try_from(slot).map_err(|e| anyhow!("{e}"))
                } else {
                    Err(anyhow!("odd slot refused by the test oracle"))
                }
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must NOT be invoked when the injected closure refuses"),
        );
        assert!(
            result.is_ok(),
            "the child must run to its natural exit when the INJECTED \
             validate closure refuses the target: {result:?}"
        );
    }

    // ── D-F6 (round 7): a validation that overruns the DYNAMIC, per-request
    //    budget is downgraded to a refusal, even when it eventually returns
    //    Ok ─────────────────────────────────────────────────────────────────
    //
    // C-B7 (round 8b): the original version of this test used an 8.0s-aged
    // request against a 700ms validation sleep — `remaining_validation_budget`
    // = 10s wire − 1.5s margin − 8.0s age ≈ 500ms, so the validation closure
    // exceeded ITS budget by only ~200ms. That margin is thin enough for a
    // loaded CI host's scheduler jitter to flip the outcome (the closure
    // finishing just UNDER budget would make this test wrongly expect a
    // refusal that never happens). Widened to a 6.0s-aged request (budget ≈
    // 2.5s) against a 3.5s validation sleep — a full 1.0s of margin — and the
    // child now hangs 6.0s (was 3.0s) so it comfortably outlives the ~3.6s
    // point at which validation actually returns, per the poll-window
    // comment below. RED against code with the D-F6 budget check removed
    // (or reverted to a fixed deadline ≥ 3.5s): the injected closure below
    // always returns `Ok`, so removing the budget check would ACCEPT it and
    // the relaunch closure's `panic!` would fire.
    #[test]
    fn drive_child_refuses_when_validation_exceeds_the_dynamic_budget_even_though_it_returns_ok() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Child hangs long enough to observe it SURVIVE the (budget-)
        // refused swap — comfortably past the ~3.6s point (100ms signal
        // delay + 3.5s validation sleep) at which the refusal is written.
        let cmd = stub_cmd(&capture, &["--hang-ms", "6000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let nonce = sup::gen_swap_nonce();
        let nonce_for_writer = nonce.clone();
        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let aged_requested_at = (chrono::Utc::now() - chrono::Duration::milliseconds(6_000))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 4,
                    thread_id: None,
                    requested_at: aged_requested_at,
                    nonce: nonce_for_writer,
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        // The verdict must be read WHILE the child is still alive: once it
        // exits naturally (its `--hang-ms 6000` elapses), `run_supervised`'s
        // `Outcome::Exited` branch removes the WHOLE handle dir — verdict
        // file included. Poll for it from a separate thread, well inside
        // that window (request signalled at ~100ms, the 3.5s-sleeping
        // closure resolves at ~3.6s, comfortably before the child's own
        // 6.0s natural exit — a ~2.4s margin, versus the original test's
        // ~200ms).
        let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
        let handle_dir_for_reader = dir.path().to_path_buf();
        let nonce_for_reader = nonce.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(5_000);
            loop {
                if let Some(v) = sup::take_swap_verdict(&handle_dir_for_reader, &nonce_for_reader) {
                    let _ = verdict_tx.send(Some(v));
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = verdict_tx.send(None);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            // Always accepts — but takes far longer (3.5s) than the ~2.5s
            // dynamic budget this aged (6.0s) request leaves, so D-F6 must
            // downgrade this to a refusal anyway.
            |slot: u16| -> Result<csq_core::types::AccountNum> {
                std::thread::sleep(Duration::from_millis(3_500));
                csq_core::types::AccountNum::try_from(slot).map_err(|e| anyhow!("{e}"))
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                panic!(
                    "relaunch must NOT be invoked when validation exceeded \
                     the dynamic budget, even though it would have returned Ok"
                )
            },
        );
        assert!(
            result.is_ok(),
            "the child must run to its natural exit when validation exceeds \
             the dynamic budget: {result:?}"
        );

        let verdict = verdict_rx
            .recv_timeout(Duration::from_secs(6))
            .expect("reader thread must report")
            .expect(
                "a Refused verdict must have been written (and observed before \
                 the child's natural exit removed the handle dir) for the \
                 budget-exceeded swap",
            );
        assert_eq!(
            verdict.outcome,
            sup::SwapOutcome::Refused("validation timed out".to_string()),
            "the verdict must name the timeout as the refusal reason"
        );
    }

    // ── round 6, item 1: `drive_child`'s accepted branch must wait for the
    //    verdict to be CONSUMED before tearing the outgoing child down ────
    //
    // A slow-but-live waiter (a "csq swap" stand-in, here a background
    // thread that deliberately delays its `take_swap_verdict` read) must be
    // allowed to catch up before teardown proceeds. This is the RED this
    // test proves: with the wait removed, `graceful_stop`'s SIGTERM kills
    // the child almost immediately after `validate` returns Ok (well before
    // the artificially slow waiter reads the verdict), so the child's death
    // is observed STRICTLY BEFORE the verdict's consumption — the exact
    // "waiter-still-running stand-in observes teardown before consumption"
    // failure named in the governing brief.
    #[test]
    fn drive_child_waits_for_verdict_consumption_before_tearing_down_the_child() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Hangs far longer than this test needs to run — it must be killed
        // by `graceful_stop`'s SIGTERM (default disposition: terminate),
        // never allowed to exit naturally, so its death instant is proof
        // teardown happened, not proof the hang elapsed.
        let cmd = stub_cmd(&capture, &["--hang-ms", "5000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let req = sup::SwapRequest {
            target_slot: 4, // even -> the oracle below accepts
            requested_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ..Default::default()
        };
        let nonce = req.nonce.clone();

        let start = std::time::Instant::now();

        let handle_dir_for_writer = dir.path().to_path_buf();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(&handle_dir_for_writer, &req).expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        // The "csq swap" stand-in: deliberately slow (300ms from test
        // start) to read the verdict, well inside VERDICT_CONSUME_WAIT_MS
        // (1000ms) but well AFTER the ~100ms it takes the writer thread to
        // signal and the near-instant `validate` closure to resolve.
        let (consumed_tx, consumed_rx) = std::sync::mpsc::channel::<Duration>();
        let handle_dir_for_consumer = dir.path().to_path_buf();
        let nonce_for_consumer = nonce.clone();
        let consumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            loop {
                if sup::take_swap_verdict(&handle_dir_for_consumer, &nonce_for_consumer).is_some() {
                    let _ = consumed_tx.send(start.elapsed());
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        // Death watcher: reads the child's pid from `.live-cc-pid` (written
        // unconditionally by `run_supervised` right after `cmd.spawn()`,
        // ahead of `drive_child`), then polls `kill(pid, 0)` until the pid
        // is gone.
        let (death_tx, death_rx) = std::sync::mpsc::channel::<Duration>();
        let handle_dir_for_watcher = dir.path().to_path_buf();
        let watcher = std::thread::spawn(move || {
            let pid = loop {
                if let Some(pid) = markers::read_live_cc_pid(&handle_dir_for_watcher) {
                    break pid;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            loop {
                let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
                if !alive {
                    let _ = death_tx.send(start.elapsed());
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });

        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            |slot: u16| -> Result<csq_core::types::AccountNum> {
                csq_core::types::AccountNum::try_from(slot).map_err(|e| anyhow!("{e}"))
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| Ok(()),
        );

        writer.join().expect("writer thread");
        consumer.join().expect("consumer thread");
        watcher.join().expect("watcher thread");

        let consumed_at = consumed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the verdict must have been consumed by the stand-in waiter");
        let died_at = death_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the child must have been torn down");

        assert!(
            died_at >= consumed_at,
            "the child must not be torn down before the verdict is consumed: \
             consumed_at={consumed_at:?} died_at={died_at:?} — a still-running \
             waiter observed teardown before consumption"
        );
    }

    // ── round 8, D-F6 close-out item (a): a validate seam that never
    //    returns must still be refused within budget, with the Refused
    //    verdict written AND the correlated audit OUTCOME recorded
    //    `Failed` ──────────────────────────────────────────────────────
    //
    // RED — EXECUTED, not reasoned (round 8b, item 13 evidence gap): the
    // worker-thread dispatch (`std::thread::Builder::new().spawn(move ||
    // { validate_for_worker(target_slot) ... })` + `result_rx.recv_timeout`
    // loop, above) was replaced inline with the pre-round-8 synchronous
    // `let validate_result = validate(target_slot);` on `drive_child`'s
    // own poll-loop thread, and this exact test was run under an external
    // bounded timeout (`timeout 20 cargo test ... --exact`): the mutated
    // binary never printed a result — killed by the external bound, `sh`
    // reporting `Terminated` / exit 124 — because the never-returning
    // validate closure now blocks the ONE thread that would otherwise
    // write the Refused verdict. GREEN with the worker-thread dispatch
    // restored: same command, `ok` in 3.57s (no external timeout needed).
    #[test]
    fn drive_child_refuses_within_budget_when_validate_blocks_forever() {
        let _guard = lock_signal_state();
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Child hangs long enough to observe it SURVIVE the (budget-)
        // refused swap, same convention as the sibling dynamic-budget test.
        let cmd = stub_cmd(&capture, &["--hang-ms", "3000", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        // A real, committed INTENT so the refusal's audit OUTCOME write is
        // actually exercised (`verify_swap_correlation` authorizes it)
        // rather than skipped (`SwapAuditCorrelation::from_request` returns
        // `None` for an empty `correlation_id` — the shape every OTHER test
        // in this module deliberately uses to stay out of the audit chain
        // entirely). Mirrors
        // `swap_audit_correlation_write_outcome_once_pairs_with_intent_and_is_idempotent`
        // in `csq-core/src/session/codex_supervisor.rs`.
        let base = dir.path();
        let chain_id = csq_core::audit::op_emit::load_chain_id(base);
        let correlation_record_id =
            csq_core::audit::op_emit::gen_correlation_id().expect("correlation_id");
        let correlation_id = correlation_record_id.as_str().to_string();
        let from_slot = csq_core::types::AccountNum::try_from(2u16).unwrap();
        let to_slot = csq_core::types::AccountNum::try_from(4u16).unwrap();
        let nonce = sup::gen_swap_nonce();
        csq_core::audit::op_emit::emit_intent(
            base,
            &chain_id,
            csq_core::audit::EventKind::AccountSwap,
            csq_core::audit::EventPayload::AccountSwap(csq_core::audit::AccountSwapPayload {
                from_slot,
                to_slot,
            }),
            correlation_record_id,
        )
        .expect("intent write must succeed");

        let nonce_for_writer = nonce.clone();
        let handle_dir_for_writer = dir.path().to_path_buf();
        let chain_id_for_writer = chain_id.clone();
        let correlation_id_for_writer = correlation_id.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            // Aged 8000ms of the ~8500ms fresh budget, leaving ~500ms — same
            // aging trick the sibling dynamic-budget test uses, so this
            // test does not have to wait the full fresh-request budget.
            let aged_requested_at = (chrono::Utc::now() - chrono::Duration::milliseconds(8_000))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 4,
                    thread_id: None,
                    requested_at: aged_requested_at,
                    nonce: nonce_for_writer,
                    chain_id: chain_id_for_writer,
                    correlation_id: correlation_id_for_writer,
                    from_slot: 2,
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        // Same "read the verdict while the child is still alive" pattern as
        // the sibling dynamic-budget test — the child's own natural exit
        // (its `--hang-ms 3000` elapsing) removes the whole handle dir.
        let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
        let handle_dir_for_reader = dir.path().to_path_buf();
        let nonce_for_reader = nonce.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(2_500);
            loop {
                if let Some(v) = sup::take_swap_verdict(&handle_dir_for_reader, &nonce_for_reader) {
                    let _ = verdict_tx.send(Some(v));
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = verdict_tx.send(None);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            // The seam under test: blocks FOREVER (never returns). Only a
            // worker-thread implementation can bound this.
            |_slot: u16| -> Result<csq_core::types::AccountNum> {
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                panic!(
                    "relaunch must NOT be invoked when validation never returns \
                     within budget"
                )
            },
        );
        assert!(
            result.is_ok(),
            "the child must run to its natural exit when validation never \
             returns within budget: {result:?}"
        );

        let verdict = verdict_rx
            .recv_timeout(Duration::from_secs(4))
            .expect("reader thread must report")
            .expect(
                "a Refused verdict must have been written (and observed before \
                 the child's natural exit removed the handle dir) even though \
                 validate never returned",
            );
        assert_eq!(
            verdict.outcome,
            sup::SwapOutcome::Refused("validation timed out".to_string()),
            "the verdict must name the timeout as the refusal reason"
        );

        // The correlated audit OUTCOME must ALSO have been recorded —
        // `write_refusal` calls `SwapAuditCorrelation::from_request(&req)
        // .write_outcome_once(base_dir, OpOutcome::Failed { .. })`. A
        // successful pairing write leaves NO orphan intent behind.
        let orphans = csq_core::audit::scan_orphan_intents(base).expect("scan must succeed");
        assert!(
            orphans.is_empty(),
            "the timeout refusal must have written OpOutcome::Failed, pairing \
             the INTENT — an unpaired orphan means the outcome was never \
             recorded: {orphans:?}"
        );
    }

    // ── item 3 (S-LOW-1/D-F2): a second SIGUSR1 arriving while a prior
    //    (here, simulated-abandoned) validation worker is still running
    //    must be refused outright — "previous validation still running"
    //    — rather than starting a second worker ───────────────────────
    //
    // RED — EXECUTED: with the `VALIDATION_IN_FLIGHT` compare_exchange
    // check (and its surrounding `if` block) deleted from `drive_child`,
    // `cargo test -p csq --features enterprise --lib \
    // codex_supervise::tests::drive_child_refuses_a_second_swap_while_the_first_validation_is_in_flight \
    // -- --exact` failed:
    // `thread 'codex_supervise::tests::...' panicked at .../codex_supervise.rs:NNNN:9:
    // validate must not be invoked when no swap request arrives` — with the
    // guard removed, `never_validate` (which asserts it is unreachable
    // while a request IS pending, per its own doc) was reached, because
    // nothing refused the request before it fell through to the worker
    // spawn. GREEN with the guard restored.
    #[test]
    fn drive_child_refuses_a_second_swap_while_the_first_validation_is_in_flight() {
        let _guard = lock_signal_state();
        // This is a process-wide static (mirrors SIGTERM_FLAG/SIGHUP_FLAG/
        // SIGUSR1_FLAG above, guarded by the SAME `lock_signal_state`
        // mutex) — start from a known-clean state in case a prior test in
        // this binary left a real worker running past its own test's
        // lifetime (it shouldn't, but this test must not depend on that).
        VALIDATION_IN_FLIGHT.store(false, Ordering::SeqCst);

        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        // Long enough to outlive the whole test — this test's point is
        // that the SECOND request is refused before `validate` is ever
        // called, not that the child eventually exits.
        let cmd = stub_cmd(&capture, &["--hang-ms", "1500", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        // Simulate an ALREADY-RUNNING (possibly already-abandoned, per
        // `drive_child`'s doc) validation worker from some earlier
        // `SIGUSR1` this test never itself triggers.
        VALIDATION_IN_FLIGHT.store(true, Ordering::SeqCst);

        let req = sup::SwapRequest {
            target_slot: 4,
            requested_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ..Default::default()
        };
        let nonce = req.nonce.clone();
        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(&handle_dir_for_writer, &req).expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
        let handle_dir_for_reader = dir.path().to_path_buf();
        let nonce_for_reader = nonce.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(1_200);
            loop {
                if let Some(v) = sup::take_swap_verdict(&handle_dir_for_reader, &nonce_for_reader) {
                    let _ = verdict_tx.send(Some(v));
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = verdict_tx.send(None);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            // Must NEVER be invoked: the contention check refuses the
            // request before a worker (and therefore this closure) is
            // ever reached.
            never_validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                panic!("relaunch must NOT be invoked when the swap was refused on contention")
            },
        );
        // Reset immediately after driving the child, before any assertion
        // can fail this test early and leave the static poisoned for every
        // OTHER test sharing `lock_signal_state`'s mutex.
        VALIDATION_IN_FLIGHT.store(false, Ordering::SeqCst);
        assert!(result.is_ok(), "{result:?}");

        let verdict = verdict_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("reader thread must report")
            .expect("a Refused verdict must have been written");
        assert_eq!(
            verdict.outcome,
            sup::SwapOutcome::Refused("previous validation still running".to_string()),
            "the verdict must name the in-flight contention as the refusal reason"
        );
    }

    // ── item 5 (D-F3, worker-thread hermeticity): the `.coc/` cwd
    //    override a test installs on ITS OWN thread must reach the
    //    validate WORKER thread `drive_child` spawns — not just the
    //    thread that called `run_supervised` ─────────────────────────────
    //
    // Isolates the PROPAGATION MECHANISM directly (rather than routing
    // through the full `validate_codex_relaunch_target` admission chain,
    // capability-layer engagement, and a `FakeHealthyDaemon` fixture) so
    // this test's own failure mode can only ever be "the worker thread saw
    // the wrong override", never an unrelated admission-check refusal.
    //
    // RED — EXECUTED: with the `#[cfg(test)] let coc_cwd_override = ...`
    // snapshot line and the worker closure's `#[cfg(test)] let _cwd_guard
    // = ...` re-install both deleted from `drive_child`, `cargo test -p csq
    // --features enterprise --lib codex_supervise::tests::\
    // drive_child_worker_thread_sees_the_coc_preflight_cwd_override_directly \
    // -- --exact` failed:
    // `the worker thread must see the SAME override installed on the
    // calling thread: left: None right: Some("...")` — with nothing
    // carrying the override across the thread spawn, the worker's own
    // `coc_preflight_cwd_override_snapshot()` call saw an empty
    // thread-local. GREEN with both lines restored.
    #[test]
    fn drive_child_worker_thread_sees_the_coc_preflight_cwd_override_directly() {
        let _guard = lock_signal_state();

        let coc_dir = tempfile::TempDir::new().expect("tempdir for .coc/ override target");
        let expected = coc_dir.path().to_path_buf();
        // Installed on THIS (the test's own) thread — the whole point of
        // this test is proving `drive_child`'s worker thread sees it too.
        let _cwd_guard = crate::cli::commands::run::force_coc_preflight_cwd(expected.clone());

        let dir = tmp_handle_dir();
        let capture = dir.path().join("argv.json");
        let cmd = stub_cmd(&capture, &["--hang-ms", "600", "--exit-code", "0"]);
        let mut audit = test_audit_emitter(dir.path());

        let handle_dir_for_writer = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            sup::write_swap_request(
                &handle_dir_for_writer,
                &sup::SwapRequest {
                    target_slot: 4,
                    thread_id: None,
                    requested_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ..Default::default()
                },
            )
            .expect("write swap request");
            // Install the supervisor's SIGUSR1 handler (idempotent, process-wide)
            // first: a signal raised before `run_supervised` installs it would
            // otherwise take the default action and kill the test process.
            ensure_signal_handlers_installed();
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGUSR1);
            }
        });

        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<Option<std::path::PathBuf>>();
        // Deliberately refuses every time — this validate closure's ONLY
        // job is to report what ITS OWN (worker) thread sees when it asks
        // the SAME snapshot function `run.rs`'s real preflight uses.
        // Refusing keeps this test out of the relaunch/admission machinery
        // entirely.
        let validate = move |_slot: u16| -> Result<csq_core::types::AccountNum> {
            let seen = crate::cli::commands::run::coc_preflight_cwd_override_snapshot();
            let _ = seen_tx.send(seen);
            Err(anyhow!(
                "deliberate refusal — this test only inspects what the worker saw"
            ))
        };

        let result = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            validate,
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| {
                panic!("relaunch must not be invoked; validate always refuses in this test")
            },
        );
        assert!(result.is_ok(), "{result:?}");

        let seen = seen_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the worker thread must have reported what it saw");
        assert_eq!(
            seen,
            Some(expected),
            "the worker thread must see the SAME `.coc/` cwd override \
             installed on the calling (test) thread — its absence means \
             the override never crossed the thread spawn"
        );
    }

    // ── round 8, D-F6 close-out item (b): a SIGTERM arriving while
    //    validation is blocked must still be forwarded to the CHILD
    //    promptly, not only once validation eventually resolves ─────────
    //
    // RED — EXECUTED, not reasoned (round 8b, item 13 evidence gap): same
    // inline-validate mutation as the sibling test above, same
    // `timeout 20 cargo test ... --exact` bounded run. Result: `Terminated`
    // / exit 124 — with validate blocking the poll loop's own thread, the
    // SIGTERM-forwarding check at the top of the `SIGUSR1` branch's
    // predecessor iteration never runs again until the (never-returning)
    // call returns, so the child never receives the forwarded signal and
    // the test never completes within the bound. GREEN with the
    // worker-thread dispatch restored: same command, `ok`.
    #[test]
    fn drive_child_forwards_sigterm_promptly_while_validation_is_blocked() {
        let _guard = lock_signal_state();
        let dir = tmp_handle_dir();
        // A SIGTERM-trapping child that exits 0 on receipt — same pattern as
        // `signal_supervisor_delivers_to_a_real_child`, above. NOT `stub_cmd`:
        // `stub-cli` has no signal trap, so a forwarded SIGTERM would kill it
        // via the DEFAULT disposition (`status.success() == false`), which
        // `run_supervised_unix`'s `Outcome::Exited` branch reports as a real,
        // final failure via `std::process::exit(..)` — appropriate for
        // production, but it would tear down THIS TEST BINARY's own process
        // rather than merely fail one test. Trapping and exiting 0 is what
        // this test needs to assert (forwarding happened, promptly) without
        // that side effect.
        //
        // The trap also creates a marker file, and the watcher below polls
        // for THAT — not for the pid to disappear. A child that exits while
        // the supervisor is inside its wait-for-validate loop stays a ZOMBIE
        // until the main poll loop reaps it (only after the validation
        // budget expires), and `kill(pid, 0)` succeeds on a zombie — so a
        // pid-liveness watcher measures reap time, not forwarding time.
        let got_term = dir.path().join("got-term");
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "trap 'touch \"$1\"; exit 0' TERM; while true; do sleep 0.05; done",
            "sh",
            got_term.to_str().expect("utf-8 tempdir"),
        ]);
        let mut audit = test_audit_emitter(dir.path());

        // Aged 3s so the wait-for-validate loop's `budget` is ~5.5s
        // (10s wire - 1.5s margin - 3s age). The budget is deliberately
        // LONG here: it is the "forwarding waited for validation" outcome
        // the latency assertion below must separate from prompt forwarding,
        // so it has to sit far above the assertion's bound. (An 8s age gave
        // a ~500ms budget, which left no room between the two outcomes and
        // made this test fail under host load — 1 in 10 isolated runs on
        // 2026-09-27.) Costs ~5.5s of runtime until the "validation timed
        // out" refusal lets `run_supervised` return.
        let aged_requested_at = (chrono::Utc::now() - chrono::Duration::milliseconds(3_000))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let req = sup::SwapRequest {
            target_slot: 4,
            requested_at: aged_requested_at,
            ..Default::default()
        };

        let test_start = std::time::Instant::now();
        let handle_dir_for_writer = dir.path().to_path_buf();
        let (sigterm_sent_tx, sigterm_sent_rx) = std::sync::mpsc::channel::<Duration>();
        let writer = std::thread::spawn(move || {
            // PRIMARY DIRECTIVE: wait for the supervisor's OWN readiness
            // markers (record + live-pid) — written by `run_supervised_unix`
            // only AFTER `cmd.spawn()` — rather than a fixed sleep guess.
            // `run_supervised` (called on the MAIN test thread, below) has
            // not necessarily even started yet when this thread is spawned.
            assert!(
                wait_for_supervisor_ready(&handle_dir_for_writer, Duration::from_secs(2)),
                "supervisor never became ready (record + live-pid marker) \
                 within 2s"
            );
            // Write + repeat-signal until the request is CONSUMED
            // (`take_swap_request`'s atomic rename) — an ordering proof
            // that the worker thread has been dispatched and is now
            // blocked inside the injected validate closure, never a bare
            // delay.
            write_request_and_signal_until_consumed(
                &handle_dir_for_writer,
                std::process::id(),
                &req,
                Duration::from_secs(2),
            );
            // The validate worker is now blocked (forever — see the
            // closure below). Set `SIGTERM_FLAG` directly rather than
            // raising a REAL `SIGTERM` at this test binary — the same
            // convention every other test in this module uses to reach
            // this state (see e.g.
            // `terminated_before_relaunch_writes_failed_outcome_helper`),
            // since a genuine self-`kill(SIGTERM)` races the handler's
            // installation and can terminate the WHOLE test process rather
            // than being caught by it. `drive_child`'s inner wait-for-
            // validate loop must observe the flag and forward it to the
            // CHILD within one `POLL_MS` tick, independent of `validate`
            // ever returning.
            SIGTERM_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = sigterm_sent_tx.send(test_start.elapsed());
        });

        // Forwarding watcher: polls for the marker the child's TERM trap
        // creates (see the zombie note above for why not pid liveness).
        let (death_tx, death_rx) = std::sync::mpsc::channel::<Duration>();
        let got_term_for_watcher = got_term.clone();
        let watcher = std::thread::spawn(move || loop {
            if got_term_for_watcher.exists() {
                let _ = death_tx.send(test_start.elapsed());
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        });

        let _ = run_supervised(
            cmd,
            dir.path(),
            dir.path(),
            // The seam under test: blocks FOREVER, exactly like the sibling
            // test above — the point is that SIGTERM forwarding does not
            // wait for this to resolve.
            |_slot: u16| -> Result<csq_core::types::AccountNum> {
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
            /* is_relaunch */ false,
            None,
            &mut audit,
            |_, _, _, _| panic!("relaunch must not be invoked — this swap is never validated"),
        );

        writer.join().expect("writer thread");

        let sigterm_sent_at = sigterm_sent_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the SIGTERM-sending thread must report");
        let died_at = death_rx.recv_timeout(Duration::from_secs(10)).expect(
            "the child must be forwarded SIGTERM and die from it — if this \
                 times out, drive_child's poll loop is blocked on the \
                 never-returning validate call and never reached the \
                 forwarding check",
        );

        assert!(
            died_at >= sigterm_sent_at,
            "the child cannot die before SIGTERM is even sent: \
             sigterm_sent_at={sigterm_sent_at:?} died_at={died_at:?}"
        );
        let forward_latency = died_at - sigterm_sent_at;
        assert!(
            forward_latency < Duration::from_millis(2_000),
            "SIGTERM must be forwarded within about one POLL_MS (25ms) tick \
             of the wait-for-validate loop, not only once validation \
             eventually resolves — forward_latency={forward_latency:?} \
             (the two outcomes this bound separates: prompt forwarding lands \
             within tens of ms of the flag; forwarding that waited for the \
             validation budget lands at >= ~5.5s (10s wire - 1.5s margin - \
             3s request age); 2s leaves ~2s of load headroom on the first \
             and ~3.5s on the second)"
        );

        watcher.join().expect("watcher thread");
    }
}
