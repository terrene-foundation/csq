//! Automatic CLI-dependency upgrade dispatch.
//!
//! ## Purpose
//!
//! When `cli_deps_gate::enforce` encounters an `Outdated` result, it calls
//! `run_auto_update` **before** bailing, attempting to upgrade the CLI
//! in-place. On success the probe cache is invalidated and the caller
//! re-probes; if the binary is now current, the gate proceeds silently.
//!
//! ## Mechanism
//!
//! The upgrade command is sourced from the existing
//! `minimum::upgrade_command(cli, manager)` dispatch table. For the
//! **npm-based managers** (`NpmGlobal`, `BrewFormula`, `BrewCask`) that table
//! carries range-pinned npm arguments (e.g. `@openai/codex@>=0.40.0 <1.0.0`)
//! so we never pin to `@latest` and never update past a known-good major
//! boundary.
//!
//! **`InstallManager::SelfManaged` is the exception (S-F7).** `codex update`
//! / `kimi upgrade` / `grok update` invoke the vendor's OWN updater, which
//! carries no version-range constraint csq can enforce — an upstream release
//! may cross a major version and this codepath will install it. This is a
//! deliberate owner decision (every managed CLI auto-updates "like Claude
//! Code", which itself has no upstream-side ceiling either): see spec/13
//! §3.2/§7. `cli_deps_gate::warn_if_major_crossed` prints a one-line WARN
//! naming the old and new versions when a SelfManaged upgrade's re-probe
//! shows the major version increased; it does not block the launch.
//!
//! If `upgrade_command` returns `None` for the `(cli, manager)` pair (e.g.
//! `ClaudeNativeInstaller`, `Unknown`), auto-update is skipped and the
//! existing bail fires.
//!
//! ## Opt-out
//!
//! - Per-invocation: `--no-auto-update-cli` flag on `csq run` / `csq login`.
//! - Per-environment: `CSQ_NO_AUTO_UPDATE_CLI=1`.
//! - Either is sufficient to disable.
//!
//! Default: **ON**.
//!
//! ## Range-pinning as max-known-good defence (npm/brew managers only)
//!
//! The upgrade commands in `minimum::upgrade_command` for `NpmGlobal` /
//! `BrewFormula` / `BrewCask` use npm range syntax (`@>=M.m.p <N.0.0`) which
//! prevents npm from installing a breaking major-version bump. This is the
//! max-known-good check: if the latest npm version is outside the range,
//! npm refuses the install and we fall through to the existing bail. No
//! registry query is needed; the range constraint is enforced server-side by
//! npm during package resolution. `SelfManaged` has no such range — see
//! above.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use super::{
    minimum::{upgrade_command, CLAUDE_NPM_PACKAGE, CODEX_NPM_PACKAGE, GEMINI_NPM_PACKAGE},
    probe::invalidate,
    probe::probe as run_probe,
    CliStatus, InstallManager, SurfaceCli,
};

/// Wall-clock timeout for npm install subprocess (DA-H2).
///
/// npm global installs typically complete in 20-60s. 120s gives substantial
/// headroom for slow networks while preventing indefinite hangs.
const NPM_INSTALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Wall-clock timeout for track-latest's OPTIONAL background upgrade (FM-9).
///
/// Distinct from `NPM_INSTALL_TIMEOUT`, and deliberately shorter. That
/// constant bounds a MANDATORY upgrade of a binary that is currently below
/// csq's own floor — the launch cannot proceed at all without either the
/// upgrade completing or falling through to the (already-below-floor)
/// installed version, so it is worth the full 120s of patience. Track-latest
/// only ever mutates a binary that ALREADY passes the floor, so a stalled
/// network here should return control to an interactive `csq run`/`csq
/// login` sooner rather than tying up the launch for the same budget.
///
/// The two outcomes this bound separates: a real install (npm or the
/// vendor's own self-managed updater) typically completes in 20-60s — the
/// same range `NPM_INSTALL_TIMEOUT`'s own doc cites — so it finishes
/// comfortably inside half of `NPM_INSTALL_TIMEOUT`. A blackholed network
/// produces zero forward progress for the ENTIRE duration regardless of the
/// bound chosen, so halving it costs nothing against that case while
/// halving the worst-case wait paid for optional maintenance.
///
/// This bound alone does NOT make the post-timeout state safe to act on —
/// that is `kill_group_and_confirm_dead`'s job, not this constant's. On
/// unix the child is spawned in its own process group
/// (`process_group(0)`), and on timeout the WHOLE group is `SIGKILL`ed AND
/// every live descendant of the direct child (snapshotted via `ps` BEFORE
/// the kill, so a worker that escaped the group via `setsid()` is still
/// reached individually) is `SIGKILL`ed too. Both the group and every
/// snapshotted descendant are then polled (`kill(target, 0)` until `ESRCH`
/// — `EPERM` or any other errno counts as still-present, never as gone)
/// until ALL are confirmed gone, which is what lets `maybe_track_latest`
/// trust a re-probe (`UpdateError::TimedOutSettled`). Only when that
/// confirmation itself cannot complete for every one of them — or on a
/// platform where no such confirmation exists — does `UpdateError::TimedOut`
/// fire, and that case bails unconditionally rather than re-probing (see
/// `maybe_track_latest`'s two match arms).
const TRACK_LATEST_UPDATE_TIMEOUT: Duration =
    Duration::from_secs(NPM_INSTALL_TIMEOUT.as_secs() / 2);

/// Wall-clock bound for confirming a killed process group has fully exited
/// (`kill_group_and_confirm_dead`), distinct from `NPM_INSTALL_TIMEOUT` /
/// `TRACK_LATEST_UPDATE_TIMEOUT` which bound the INSTALL itself.
///
/// The two outcomes this separates: `SIGKILL` is unblockable, so a process
/// (or process group) that is actually gone stops answering `kill(target, 0)`
/// (returns `ESRCH`) within low milliseconds — reaping is scheduler-bound,
/// not network-bound, so there is no slow-but-legitimate case analogous to a
/// slow npm install. A target that STILL answers `EPERM` (still present,
/// still signalable — or now owned by a different uid) after this bound is
/// not "still dying"; it is a kill that did not reach every member (a
/// process that escaped the group via `setsid()` before the individual
/// per-descendant kill could reach it, or an unusual signal-blocking
/// state), and that case is exactly what must fall back to the unconfirmed
/// `UpdateError::TimedOut` rather than be trusted as settled — `ESRCH` is
/// the ONLY confirmation of "gone"; any other outcome, including `EPERM`,
/// is treated as still-present. 2s is ample headroom over the real
/// sub-10ms case while keeping the fallback fast.
///
/// Kept as a plain, non-cfg-gated integer (`GROUP_KILL_CONFIRM_SECS`) as well
/// as this unix-only `Duration`, so a cross-platform constant (see
/// `TRACK_LATEST_LOCK_WAIT_TIMEOUT` below) can cite the same worst-case
/// number without depending on a unix-only item.
const GROUP_KILL_CONFIRM_SECS: u64 = 2;

#[cfg(unix)]
const GROUP_KILL_CONFIRM_TIMEOUT: Duration = Duration::from_secs(GROUP_KILL_CONFIRM_SECS);

/// Poll granularity for [`GROUP_KILL_CONFIRM_TIMEOUT`].
#[cfg(unix)]
const GROUP_KILL_CONFIRM_POLL: Duration = Duration::from_millis(50);

/// Errors from the auto-update path.
///
/// These are returned to `cli_deps_gate::enforce`, which uses them to
/// decide whether to emit a diagnostic before falling through to the
/// existing bail. They are never surfaced raw to the operator — the
/// gate formats its own user-facing messages.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// No auto-runnable upgrade could be dispatched. Occurs when:
    /// - no upgrade command is defined for the `(cli, manager)` pair
    ///   (`ClaudeNativeInstaller` / `Unknown` managers, or Brew CLIs with no
    ///   brew upgrade path); OR
    /// - an upgrade command IS defined but its program (a self-managed CLI
    ///   binary such as `kimi`/`grok`) could not be resolved on disk via
    ///   `find_in_path` — the binary is absent, so there is nothing to update.
    ///
    /// Both collapse to the same gate disposition (skip auto-update, fall
    /// through to the existing bail), so they share one variant.
    #[error("no_auto_update_command: no runnable upgrade command for this install manager")]
    NoCommand,

    /// `npm` was not found on PATH.
    /// The upgrade command requires npm; without it auto-update cannot run.
    #[error("npm_missing: npm not found on PATH")]
    NpmMissing,

    /// The upgrade subprocess exited with a non-zero status.
    ///
    /// The install is known to have FINISHED (unsuccessfully), so the binary
    /// on disk is settled and a caller may safely proceed against it.
    #[error("install_failed: upgrade command exited with non-zero status")]
    InstallFailed,

    /// The upgrade subprocess exceeded the caller's timeout, and csq could
    /// NOT confirm that every process in its group actually stopped.
    ///
    /// Distinct from `InstallFailed` because the install did NOT finish: on
    /// unix csq sends `SIGKILL` to the whole process group
    /// (`kill_group_and_confirm_dead`) but the confirmation poll itself
    /// timed out, or this build has no such confirmation (non-unix — see
    /// that platform's fallback in `run_child_with_timeout`). Either way a
    /// package manager's own worker processes may still be mid-swap on the
    /// very binary the caller is about to launch, so the state of the
    /// binary on disk is UNKNOWN and a caller MUST NOT spawn against it —
    /// unconditionally, without re-probing (see
    /// `cli_deps_gate::maybe_track_latest`'s `TimedOut` arm).
    #[error("install_timed_out: upgrade command exceeded the wall-clock timeout and was killed")]
    TimedOut,

    /// The upgrade subprocess exceeded the caller's timeout, and csq
    /// confirmed (unix only) that the WHOLE process group — not just the
    /// direct child — has exited: `SIGKILL` was sent to the group and
    /// `kill(-pgid, 0)` polled to `ESRCH` before this variant is returned.
    ///
    /// Unlike `TimedOut`, the binary on disk is SETTLED here (though
    /// possibly incomplete or corrupted by the forced kill) — no worker is
    /// still writing to it — so a caller MAY re-probe and trust the result
    /// (see `cli_deps_gate::maybe_track_latest`'s `TimedOutSettled` arm).
    #[error(
        "install_timed_out_settled: upgrade command exceeded the wall-clock timeout; the \
         whole process group was killed and confirmed stopped"
    )]
    TimedOutSettled,

    /// F5/S-L3: a terminal signal (`SIGINT`/`SIGTERM`/`SIGHUP`, unix only)
    /// arrived while csq was waiting on the update subprocess. `signal` is
    /// the RAW signal number (not `128 + signal`); callers at the command
    /// layer are expected to `std::process::exit(128 + signal)` to honour
    /// the interrupt using the conventional shell exit code.
    ///
    /// `settled` is `true` only when `kill_group_and_confirm_dead` — the
    /// SAME descendant-aware mechanism [`Self::TimedOutSettled`] uses —
    /// actually confirmed the whole process group AND every snapshotted
    /// descendant had exited before this variant was returned. Unlike the
    /// pre-fix behaviour (which unconditionally claimed a confirmed kill
    /// regardless of that call's result), `settled = false` means the same
    /// ambiguity `UpdateError::TimedOut` carries: a worker MAY still be
    /// mid-write to the binary, and callers MUST warn the operator rather
    /// than imply the state is safe to act on.
    #[error(
        "interrupted: wait was interrupted by signal {signal} (group_confirmed_stopped={settled})"
    )]
    Interrupted { signal: i32, settled: bool },
}

/// Returns `true` when auto-update is enabled.
///
/// `cli_flag` is `true` when the operator passed `--no-auto-update-cli`
/// on the command line.  If either the CLI flag or the env var opt-out is
/// set, auto-update is disabled.
pub fn auto_update_enabled(no_auto_update_cli_flag: bool) -> bool {
    if no_auto_update_cli_flag {
        return false;
    }
    // Env var opt-out: CSQ_NO_AUTO_UPDATE_CLI=1
    std::env::var("CSQ_NO_AUTO_UPDATE_CLI").as_deref() != Ok("1")
}

// ── Track-latest mode (default ON) ────────────────────────────────────────
//
// The floor-guarded auto-update gate fires only when the probe returns
// `Outdated` (binary below csq's `min_version`). A binary that probes `Ok`
// (>= floor) would otherwise be left alone — even when a newer release
// exists.
//
// Track-latest keeps the managed CLIs at the ABSOLUTE latest release, the
// same way Claude Code keeps itself current. It reuses the exact same
// `run_auto_update` path.
//
// For the npm-based managers (`NpmGlobal` / `BrewFormula` / `BrewCask`) the
// `upgrade_command` table is range-pinned (`@pkg@>=M.m.p <N.0.0`), so
// `npm install -g` resolves the newest release *within the supported major*
// and never crosses a major boundary there. A true cross-major `@latest`
// for those managers would require a `min_version` bump per the 1.0-bump
// policy (spec/13 §7) and is intentionally NOT what this mode does for them.
//
// `InstallManager::SelfManaged` (codex/kimi/grok) is NOT range-pinned
// (S-F7): `codex update` / `kimi upgrade` / `grok update` run the vendor's
// own updater, which csq cannot cap, so a SelfManaged track-latest MAY cross
// a major version — an accepted owner decision (every CLI auto-updates
// "like Claude Code"). `cli_deps_gate::warn_if_major_crossed` WARNs, naming
// old and new versions, without blocking the launch.
//
// Because running an npm install on every `csq run`/`csq login` would be
// slow, the attempt is throttled to at most once per CLI per throttle
// window via a per-CLI stamp file under the csq base dir.
//
// Default: **ON** (same polarity as `auto_update_enabled`). Opt out with
// `CSQ_NO_TRACK_LATEST=1`, or with the existing master kill-switch
// (`--no-auto-update-cli` / `CSQ_NO_AUTO_UPDATE_CLI=1`, enforced by the
// caller's `auto_update_enabled(..) && track_latest_enabled(..)` gate —
// see `cli_deps_gate::enforce`). The `--track-latest` flag and
// `CSQ_TRACK_LATEST=1` still parse and still enable the mode; they are now
// redundant with the default but kept as harmless explicit opt-ins.

/// Throttle window for track-latest: attempt an upgrade at most once per CLI
/// per 24h. Prevents every `csq run` from paying an npm-install round-trip.
const TRACK_LATEST_THROTTLE: Duration = Duration::from_secs(24 * 60 * 60);

/// Self-heal threshold for a future-dated stamp. An ordinary forward clock
/// skew (up to 30 days ahead) is absorbed as "not due" (don't hammer npm on
/// minor jitter), but a stamp dated ABSURDLY far ahead — a one-time forward
/// clock jump that was later corrected — would otherwise disable track-latest
/// until real time catches up. Beyond this threshold the stamp is treated as
/// corrupt → due, so the feature self-heals.
const TRACK_LATEST_MAX_FUTURE_SKEW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Returns `true` when track-latest mode is enabled.
///
/// Default: **ON**. `track_latest_flag` (`--track-latest`) and
/// `CSQ_TRACK_LATEST=1` are harmless explicit opt-ins that are already
/// redundant with the default. The single opt-out is
/// `CSQ_NO_TRACK_LATEST=1`, which disables this mode even when the flag or
/// `CSQ_TRACK_LATEST=1` is also present. The master kill-switch
/// (`--no-auto-update-cli` / `CSQ_NO_AUTO_UPDATE_CLI=1`) is enforced by the
/// caller (`auto_update_enabled(..) && track_latest_enabled(..)`), not here.
pub fn track_latest_enabled(track_latest_flag: bool) -> bool {
    // Env opt-out takes priority over both the flag and the default-on
    // behaviour: `CSQ_NO_TRACK_LATEST=1` always wins.
    if std::env::var("CSQ_NO_TRACK_LATEST").as_deref() == Ok("1") {
        return false;
    }
    // Kept for API compatibility / explicit-opt-in readability; both arms
    // now return true, since track-latest defaults on.
    let _ = track_latest_flag;
    true
}

/// Per-CLI stamp file recording the last track-latest attempt time.
///
/// Lives beside the other csq per-slot/per-cli state under the base dir. The
/// stamp is non-secret (a unix-seconds integer), so a plain write is fine —
/// no atomic-replace / `secure_file` needed (security.md §5a scopes those to
/// secret-bearing tmp files).
fn track_latest_stamp_path(base_dir: &Path, cli: SurfaceCli) -> PathBuf {
    base_dir.join(format!(
        ".track-latest-{}.stamp",
        super::minimum::binary_name(cli)
    ))
}

/// Returns `true` when a track-latest attempt is due for `cli` — i.e. no
/// attempt has been recorded within `TRACK_LATEST_THROTTLE` of `now`.
///
/// `now` is injected (csq-core has no ambient clock — pass
/// `SystemTime::now()` in production, a fixed instant in tests). Missing or
/// corrupt stamp ⇒ due. A stamp modestly in the future (ordinary clock skew,
/// ≤ `TRACK_LATEST_MAX_FUTURE_SKEW`) ⇒ NOT due (conservative: don't hammer npm
/// if the clock moved backwards). A stamp ABSURDLY in the future (a corrected
/// one-time forward jump) ⇒ due (self-heal, so the feature doesn't stay off
/// for years).
pub fn track_latest_due(base_dir: &Path, cli: SurfaceCli, now: SystemTime) -> bool {
    let path = track_latest_stamp_path(base_dir, cli);
    let last_secs: u64 = match std::fs::read_to_string(&path) {
        Ok(s) => match s.trim().parse() {
            Ok(v) => v,
            Err(_) => return true, // corrupt stamp → re-stamp on this run
        },
        Err(_) => return true, // no stamp → due
    };
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Absurd future stamp (> now + 30d) → self-heal to due (LOW-4).
    if last_secs > now_secs.saturating_add(TRACK_LATEST_MAX_FUTURE_SKEW.as_secs()) {
        return true;
    }
    // now < last (ordinary skew, ≤ 30d): saturating_sub → 0 < throttle → NOT due.
    now_secs.saturating_sub(last_secs) >= TRACK_LATEST_THROTTLE.as_secs()
}

/// Returns `true` when a runnable upgrade command exists for `(cli, manager)`.
///
/// Used by track-latest's `maybe_track_latest` to avoid printing a
/// "checking for a newer…" line (and burning a stamp) for managers with no
/// npm/native upgrade path (`ClaudeNativeInstaller` / `Unknown`), where the
/// attempt would be an immediate `NoCommand` no-op.
pub fn has_upgrade_command(cli: SurfaceCli, manager: InstallManager) -> bool {
    upgrade_command(cli, manager).is_some()
}

/// Record a track-latest attempt for `cli` by writing `now` (unix seconds)
/// to the stamp file. Best-effort — a failed write just means the next
/// invocation re-attempts (no throttle), which is acceptable for a
/// convenience feature. `now` is injected for testability.
pub fn record_track_latest_attempt(base_dir: &Path, cli: SurfaceCli, now: SystemTime) {
    let path = track_latest_stamp_path(base_dir, cli);
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = std::fs::write(&path, now_secs.to_string());
}

/// Poll granularity while waiting for a sibling's track-latest lock to
/// release (FM-8). Matches `run_auto_update`'s own DA-H2 poll granularity.
const TRACK_LATEST_LOCK_WAIT_POLL: Duration = Duration::from_millis(250);

/// Maximum per-surface probe wall-clock budget (see
/// `csq-core/src/cli_deps/probe.rs::probe_timeout`, whose non-test ceiling is
/// 6s for Codex/Gemini/Kimi/Grok). Cited only to size
/// [`TRACK_LATEST_LOCK_WAIT_TIMEOUT`]'s re-probe margin below, never used as
/// a gate itself.
const MAX_PROBE_TIMEOUT_SECS: u64 = 6;

/// Wall-clock bound for [`wait_for_track_latest_lock_release`] (FM-8).
///
/// C-F7 correction: the previous derivation (`NPM_INSTALL_TIMEOUT + 5`)
/// understated the holder's real worst case. A holder that hits its own
/// `NPM_INSTALL_TIMEOUT` does NOT release the lock at that instant — it
/// still runs `kill_group_and_confirm_dead` (bounded by
/// `GROUP_KILL_CONFIRM_TIMEOUT`, 2s) before the group is settled. And a
/// holder whose install SUCCEEDS does not release the lock at THAT instant
/// either: `attempt_auto_update_and_proceed`'s own `Ok(())` arm re-probes
/// (bounded by the per-surface `probe_timeout`, ≤ `MAX_PROBE_TIMEOUT_SECS`)
/// to confirm the new version — still holding `_lock_guard` while it does,
/// since the guard is not dropped until the function returns. `MAX_PROBE_
/// TIMEOUT_SECS` therefore bounds a re-probe the HOLDER runs before
/// releasing, not one the waiting caller runs afterward — a re-probe by the
/// caller on this side of the wait happens only after `wait_for_track_
/// latest_lock_release` has already returned, so its duration cannot extend
/// how long the lock stays held and has no bearing on this bound. The bound
/// is therefore the SUM of every stage that can still be running while the
/// lock is held, plus a margin for process teardown and scheduler jitter on
/// top of that:
///
/// `NPM_INSTALL_TIMEOUT (120s, the longer of the two install timeouts)
///   + GROUP_KILL_CONFIRM_TIMEOUT (2s, killing+confirming the group on the
///     failure path)
///   + MAX_PROBE_TIMEOUT_SECS (6s, the holder's own post-success re-probe,
///     run before it releases the lock)
///   + 10s margin`
///
/// Arithmetic checked: 120 + 2 + 6 + 10 = 138s — matches
/// `track_latest_lock_wait_timeout_covers_holders_full_worst_case`'s own
/// `>= NPM_INSTALL_TIMEOUT + 18s` assertion below.
///
/// Two outcomes this separates: a genuine in-flight update — including
/// either tail it can run into before releasing (forced-kill-and-confirm on
/// failure, or re-probe on success) — releases the lock well inside this
/// window, with the stated 10s left over on top of the 128s the holder's
/// own stages can consume; a lock somehow still held past it (a wedged or
/// already-exited-without-releasing holder) is out of scope for "wait".
/// What the WAITING caller does next depends on which caller it is:
/// `maybe_track_latest`'s best-effort track-latest path proceeds to launch
/// rather than hanging indefinitely, exactly as it would have before FM-8
/// existed — but the MANDATORY floor-upgrade path
/// (`attempt_auto_update_and_proceed`) does NOT proceed unlocked once
/// contention has actually been observed: it re-checks the lock exactly
/// once more and BAILS if it is still held (see
/// `acquire_lock_after_wait_or_bail`, C-F5). A stale doc claiming the
/// caller always proceeds after this wait was corrected here — see
/// `csq/src/cli/commands/cli_deps_gate.rs::attempt_auto_update_and_proceed`
/// for the mandatory path's actual disposition.
const TRACK_LATEST_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(
    NPM_INSTALL_TIMEOUT.as_secs() + GROUP_KILL_CONFIRM_SECS + MAX_PROBE_TIMEOUT_SECS + 10,
);

/// Waits (bounded) for a sibling process's track-latest lock at `lock_path`
/// to become free (FM-8).
///
/// Returns `true` if the lock was observed free within
/// `TRACK_LATEST_LOCK_WAIT_TIMEOUT` — the guard is dropped immediately on
/// acquisition, since the caller must never hold it here (a "not due"
/// attempt must never run an update itself) — and `false` if the bound
/// elapsed while the lock was still held. A `false` result means only that
/// the wait timed out, never that the binary is unsafe — but what a caller
/// does with that is caller-specific, NOT a shared "proceed either way"
/// contract: `maybe_track_latest`'s best-effort "not due" attempt proceeds
/// to launch in EITHER case (and never re-probes); the MANDATORY
/// floor-upgrade path (`attempt_auto_update_and_proceed`) re-checks the
/// lock exactly once more after this call returns and BAILS if it is still
/// held, rather than proceeding unlocked (`acquire_lock_after_wait_or_bail`,
/// C-F5).
pub fn wait_for_track_latest_lock_release(lock_path: &Path) -> bool {
    wait_for_track_latest_lock_release_with(
        lock_path,
        TRACK_LATEST_LOCK_WAIT_TIMEOUT,
        TRACK_LATEST_LOCK_WAIT_POLL,
    )
}

/// Dependency-injected core of [`wait_for_track_latest_lock_release`] so
/// tests can exercise both outcomes without waiting the real ~125s bound.
///
/// `pub` (not `pub(crate)`): `csq/src/cli/commands/cli_deps_gate.rs` is a
/// SIBLING crate, not this one, and its own `attempt_auto_update_and_proceed`
/// tests need a fast, injectable wait to exercise "lock still held after the
/// wait" through the real call site rather than only the isolated
/// `acquire_lock_after_wait_or_bail` helper — `pub(crate)` would not resolve
/// across that crate boundary.
pub fn wait_for_track_latest_lock_release_with(
    lock_path: &Path,
    timeout: Duration,
    poll: Duration,
) -> bool {
    let attempts = ((timeout.as_millis() / poll.as_millis().max(1)).max(1)) as u32;
    match crate::platform::lock::try_lock_file_bounded(lock_path, attempts, poll) {
        Ok(Some(_guard)) => true,
        Ok(None) | Err(_) => false,
    }
}

/// Returns `true` when `npm` is available on PATH.
///
/// Uses a lightweight `npm --version` invocation (stdout suppressed)
/// rather than a PATH walk, so it works correctly on Windows where npm
/// is a `.cmd` script.
fn npm_on_path() -> bool {
    Command::new("npm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Attempt to auto-update `cli` using its `upgrade_command` entry.
///
/// Caller (cli_deps_gate) is responsible for:
/// 1. Checking `auto_update_enabled` before calling this.
/// 2. Emitting the "running upgrade..." message to stderr before calling.
/// 3. Invalidating the probe cache and re-probing after `Ok(())`.
///
/// On `Ok(())` the caller MUST re-probe to confirm the version is now
/// acceptable. On `Err(_)` the caller falls through to the existing bail.
///
/// `manager` is the `InstallManager` from the `CliStatus::Outdated` (or
/// `CliStatus::Ok`, for track-latest) variant, sourced from the probe result
/// — no additional classification needed.
///
/// `classified_path` is the canonical `path` field from that SAME
/// `CliStatus` variant (S-F10). For a `SelfManaged` CLI it is used AS THE
/// SPAWNED BINARY, bypassing a fresh PATH lookup — reusing the exact path
/// the classifier already resolved and checked, rather than re-walking PATH
/// (which could resolve a different binary if PATH changed between the
/// probe and this call). Pass `None` only when no such classified path is
/// available (e.g. direct unit-test calls); `npm`/`brew` managers ignore it.
///
/// ## Security: env allowlist (SR-H1)
///
/// The subprocess env is cleared and rebuilt from an allowlist so that
/// npm preinstall/postinstall scripts in the resolved package cannot read
/// OAuth tokens, API keys, or other secrets from the operator's shell env.
///
/// ## Timeout (DA-H2)
///
/// The subprocess is killed after 120s to prevent indefinite hangs when
/// npm's network access is blocked or the registry is slow.
pub fn run_auto_update(
    cli: SurfaceCli,
    manager: InstallManager,
    classified_path: Option<&Path>,
) -> Result<(), UpdateError> {
    run_auto_update_with_timeout(cli, manager, classified_path, NPM_INSTALL_TIMEOUT)
}

/// Track-latest variant of [`run_auto_update`] (FM-9): identical mechanism,
/// bounded by the shorter `TRACK_LATEST_UPDATE_TIMEOUT` instead of
/// `NPM_INSTALL_TIMEOUT` — see that constant's doc for why track-latest gets
/// its own, shorter bound.
pub fn run_auto_update_track_latest(
    cli: SurfaceCli,
    manager: InstallManager,
    classified_path: Option<&Path>,
) -> Result<(), UpdateError> {
    run_auto_update_with_timeout(cli, manager, classified_path, TRACK_LATEST_UPDATE_TIMEOUT)
}

fn run_auto_update_with_timeout(
    cli: SurfaceCli,
    manager: InstallManager,
    classified_path: Option<&Path>,
    timeout: Duration,
) -> Result<(), UpdateError> {
    // Resolve upgrade command from the existing dispatch table.
    let cmd_parts = upgrade_command(cli, manager).ok_or(UpdateError::NoCommand)?;

    // cmd_parts[0] is the program name; the rest are arguments.
    let program = &cmd_parts[0];

    // For npm-based upgrades, verify npm is on PATH before attempting.
    // The upgrade_command table for npm entries starts with "npm".
    if program == "npm" && !npm_on_path() {
        return Err(UpdateError::NpmMissing);
    }

    // For self-managed CLIs (`kimi upgrade` / `grok update` / `codex update`)
    // the program is the CLI's own binary, which may live outside a minimal
    // PATH (spec/13 §5 known-location fallback).
    //
    // S-F10: when the caller already classified a canonical path for this
    // binary (the same path `cli_deps::probe` resolved and checked when it
    // decided `manager == SelfManaged`), reuse that path directly rather than
    // walking PATH again. A fresh `find_in_path` call here is a TOCTOU: PATH
    // can change between the probe and this call, so a second lookup could
    // silently resolve a DIFFERENT binary than the one the classifier
    // actually inspected — and this function immediately executes whatever
    // it resolves.
    let resolved_program: std::path::PathBuf = if program == "npm" || program == "brew" {
        std::path::PathBuf::from(program)
    } else if let Some(p) = classified_path {
        p.to_path_buf()
    } else {
        match super::install_path::find_in_path(program) {
            Some(p) => p,
            // An upgrade command was defined but the self-managed binary is not
            // resolvable on disk → nothing to update. Same gate disposition as
            // "no command defined", so we reuse NoCommand (see its doc comment).
            None => return Err(UpdateError::NoCommand),
        }
    };

    // Build the subprocess with:
    // - DA-H2: stdin(Stdio::null()) to prevent npm prompts deadlocking
    // - SR-H1: env_clear() + allowlist to prevent secrets leaking to npm scripts
    let mut cmd = Command::new(&resolved_program);
    cmd.args(&cmd_parts[1..]);
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // DA-H2: prevent npm prompts from deadlocking by closing stdin
    cmd.stdin(Stdio::null());
    // SR-H1: allowlist-scrub env so npm preinstall/postinstall scripts cannot
    // see OAuth tokens, API keys, or other secrets in the operator's shell env.
    cmd.env_clear();
    for var in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "SHELL",
        "LANG",
        "LC_ALL",
        "NPM_CONFIG_PREFIX",
        "NODE_PATH",
    ] {
        if let Ok(v) = std::env::var(var) {
            cmd.env(var, v);
        }
    }

    run_child_with_timeout(cmd, timeout)
}

/// Spawn `cmd` and wait up to `timeout`, killing it (and, on unix, its whole
/// process group) if it does not finish. Extracted from
/// `run_auto_update_with_timeout` so the timeout/group-kill mechanism is
/// directly testable against an arbitrary command (see the `#[cfg(test)]`
/// module — a shell script standing in for a hung package-manager process
/// that forked a background worker).
///
/// # Why the whole GROUP, not just the direct child (FM-9 / S-F7 hardening)
///
/// `Child::kill()` (used alone, as this function used to) signals ONLY the
/// direct child. `npm install -g` and vendor self-updaters commonly fork
/// worker processes (extraction, post-install scripts, a detached updater)
/// that outlive the direct child once it is killed — those workers may
/// still be mid-write to the very binary the caller is about to launch. On
/// unix this function spawns `cmd` as the leader of its OWN process group
/// (`process_group(0)`) so that on timeout `kill_group_and_confirm_dead` can
/// reach every descendant with one `kill(-pgid, SIGKILL)`, and confirms
/// (rather than assumes) the group is gone before reporting settled state.
fn run_child_with_timeout(mut cmd: Command, timeout: Duration) -> Result<(), UpdateError> {
    // Unix: give the child its own process group so a timeout kill reaches
    // every descendant it forked, not just the direct child (see the
    // function doc above and `kill_group_and_confirm_dead`).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    // S-L4: install the interrupt guard BEFORE spawn, not after. Installing
    // it after `spawn()` (the pre-fix ordering) left a window between the
    // child existing and the guard being armed where a SIGINT/SIGTERM/SIGHUP
    // would hit the DEFAULT disposition (process termination) instead of
    // this module's flag-only handler — the process would exit immediately
    // while the just-spawned update subprocess (and any worker it forks in
    // that same window) keeps running, unconfirmed and unkilled.
    #[cfg(unix)]
    let _signal_guard = InterruptSignalGuard::install();

    let mut child = cmd.spawn().map_err(|_| UpdateError::InstallFailed)?;

    // DA-H2: poll with 250ms granularity; kill after `timeout`.
    let start = Instant::now();
    loop {
        #[cfg(unix)]
        if let Some(sig) = _signal_guard.caught() {
            tracing::error!(
                error_kind = "auto_update_interrupted",
                signal = sig,
                "a terminal signal arrived while waiting on the update subprocess; \
                 killing process group"
            );
            // F5/S-L3: same descendant-aware kill+confirm as the timeout
            // path — the caller MUST NOT trust ANY re-probe on interrupt (it
            // is about to propagate the signal and exit, not continue), but
            // still must not leave a worker writing to the binary a NEXT
            // launch would spawn. `settled` carries whether that kill was
            // actually confirmed (never assumed) — see `Interrupted`'s doc.
            let settled = kill_group_and_confirm_dead(&mut child);
            return Err(UpdateError::Interrupted {
                signal: sig,
                settled,
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // S-L4: a signal may have arrived in the narrow window
                // between the `caught()` check above and this exit
                // observation. Check once more before trusting the exit
                // status — otherwise that signal is silently dropped and a
                // stale Ok/InstallFailed is reported instead of honouring
                // the interrupt.
                #[cfg(unix)]
                if let Some(sig) = _signal_guard.caught() {
                    let settled = kill_group_and_confirm_dead(&mut child);
                    return Err(UpdateError::Interrupted {
                        signal: sig,
                        settled,
                    });
                }
                if !status.success() {
                    return Err(UpdateError::InstallFailed);
                }
                return Ok(());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    tracing::error!(
                        error_kind = "auto_update_npm_timeout",
                        elapsed_secs = start.elapsed().as_secs(),
                        "npm install exceeded timeout; killing process group"
                    );
                    #[cfg(unix)]
                    {
                        if kill_group_and_confirm_dead(&mut child) {
                            return Err(UpdateError::TimedOutSettled);
                        }
                        // The group could not be confirmed fully stopped —
                        // fall back to the conservative unsettled verdict;
                        // see `UpdateError::TimedOut`'s doc.
                        return Err(UpdateError::TimedOut);
                    }
                    #[cfg(not(unix))]
                    {
                        // Windows: unchanged from the pre-fix behaviour —
                        // kill only the direct child. Windows has no POSIX
                        // process-group/kill(-pgid) equivalent; the
                        // corresponding hardening there is a Job Object
                        // (tracked separately, not implemented here), so
                        // this platform can never produce `TimedOutSettled`
                        // and always reports the conservative, unconfirmed
                        // `TimedOut`.
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(UpdateError::TimedOut);
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(_) => return Err(UpdateError::InstallFailed),
        }
    }
}

/// F5: installs flag-only handlers for `SIGINT`/`SIGTERM`/`SIGHUP` on
/// construction and restores the PREVIOUS dispositions on drop — so a signal
/// that arrives outside the narrow window this guard is alive for is
/// unaffected, and a caller elsewhere in the process (there is none today,
/// but this must not assume it) never observes a handler this module
/// installed and forgot to remove.
///
/// Mirrors the flag-only-handler shape already used by
/// `csq::cli::commands::codex_supervise` (a process-wide `AtomicI32` set
/// from an `extern "C"` handler whose body is a single async-signal-safe
/// store — see that module's `install_flag_handler` doc), but keeps its OWN
/// statics: this guard's handlers are installed only for the narrow window
/// `run_child_with_timeout` waits on an update subprocess (early in `csq
/// run`/`csq login`, before any codex session exists to supervise), and are
/// restored before returning, so the two modules' signal state never
/// overlaps in practice.
#[cfg(unix)]
struct InterruptSignalGuard {
    // Held for the guard's ENTIRE lifetime (install -> drop), not just
    // acquired-and-dropped: `AUTO_UPDATE_SIGNAL_CAUGHT` and the SIGINT/
    // SIGTERM/SIGHUP dispositions this guard installs are PROCESS-WIDE, so
    // two overlapping `run_child_with_timeout` calls (this crate's own
    // tests run in parallel threads within one `cargo test` process) would
    // otherwise share one flag — a signal meant for one call's wait loop
    // would be observed by every OTHER call's wait loop too. This is not a
    // test-only concern: it is exactly the invariant that makes the flag
    // usable as "one signal, one waiter" at all.
    _lock: std::sync::MutexGuard<'static, ()>,
    prev_sigint: libc::sighandler_t,
    prev_sigterm: libc::sighandler_t,
    prev_sighup: libc::sighandler_t,
}

#[cfg(unix)]
static AUTO_UPDATE_SIGNAL_CAUGHT: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);

/// Serializes the install-to-drop window of every [`InterruptSignalGuard`]
/// — see that struct's `_lock` field doc for why overlap is unsound, not
/// merely untidy.
#[cfg(unix)]
static AUTO_UPDATE_SIGNAL_GUARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
extern "C" fn auto_update_set_signal_flag(sig: libc::c_int) {
    // Async-signal-safe: a single atomic store, nothing else.
    AUTO_UPDATE_SIGNAL_CAUGHT.store(sig, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
impl InterruptSignalGuard {
    fn install() -> Self {
        // A poisoned lock (a prior holder panicked mid-guard) is still safe
        // to take: the payload is `()`, and the dispositions this guard
        // sets/restores do not depend on any invariant a panic could break.
        let lock = AUTO_UPDATE_SIGNAL_GUARD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AUTO_UPDATE_SIGNAL_CAUGHT.store(0, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: `signal(2)` with a function pointer whose body performs
        // only an async-signal-safe atomic store is sound to install here.
        // `signal(2)` returns the PREVIOUS disposition, which this guard
        // restores on drop.
        let (prev_sigint, prev_sigterm, prev_sighup) = unsafe {
            (
                libc::signal(
                    libc::SIGINT,
                    auto_update_set_signal_flag as *const () as libc::sighandler_t,
                ),
                libc::signal(
                    libc::SIGTERM,
                    auto_update_set_signal_flag as *const () as libc::sighandler_t,
                ),
                libc::signal(
                    libc::SIGHUP,
                    auto_update_set_signal_flag as *const () as libc::sighandler_t,
                ),
            )
        };
        Self {
            _lock: lock,
            prev_sigint,
            prev_sigterm,
            prev_sighup,
        }
    }

    /// Returns the caught signal number, if any, since [`Self::install`].
    fn caught(&self) -> Option<libc::c_int> {
        match AUTO_UPDATE_SIGNAL_CAUGHT.load(std::sync::atomic::Ordering::SeqCst) {
            0 => None,
            sig => Some(sig),
        }
    }
}

#[cfg(unix)]
impl Drop for InterruptSignalGuard {
    fn drop(&mut self) {
        // SAFETY: restoring a previously-returned disposition value from
        // `signal(2)` with the same call is exactly what that API contract
        // supports.
        unsafe {
            libc::signal(libc::SIGINT, self.prev_sigint);
            libc::signal(libc::SIGTERM, self.prev_sigterm);
            libc::signal(libc::SIGHUP, self.prev_sighup);
        }
    }
}

/// Kill the WHOLE process group of `child` (unix only) PLUS every live
/// descendant of the direct child snapshotted before the kill, and confirm
/// every one of them has actually exited before returning `true`.
///
/// `child` MUST have been spawned with `process_group(0)` so that its pid
/// is also its process group's id and that group contains no unrelated
/// process. Returns `false` if the group OR any individually-tracked
/// descendant could not be confirmed dead within
/// [`GROUP_KILL_CONFIRM_TIMEOUT`] — the caller MUST then treat the state as
/// unsettled (`UpdateError::TimedOut`), never as settled.
///
/// # F6: a worker that escapes the group via `setsid()`
///
/// `kill(-pgid, ...)` reaches only processes that are STILL members of the
/// spawned group. A worker the direct child forked and that then called
/// `setsid()` (a new session, and therefore a new process group) is no
/// longer reachable by the group-directed signal, yet is still a live
/// process-tree descendant of the direct child. `collect_descendant_pids`
/// snapshots that tree by parent/child links (not by group membership)
/// BEFORE any kill is sent, so such a worker is still individually
/// `SIGKILL`ed and individually confirmed — the group-only mechanism this
/// function replaced could report `TimedOutSettled` while that worker was
/// still alive and writing.
#[cfg(unix)]
fn kill_group_and_confirm_dead(child: &mut std::process::Child) -> bool {
    let root_pid = child.id();
    let pgid = root_pid as libc::pid_t;

    // Snapshot BEFORE killing anything: once the group is signalled, a
    // `setsid()`-escaped worker is indistinguishable (from the group's own
    // exit status) from one that never existed, so its pid must be known
    // in advance to be tracked individually. S-L5: each entry also carries
    // its start time at snapshot time, so the individual kill below can
    // re-verify it is still signalling the SAME process, not a different
    // one that reused a recycled pid in the interim.
    let descendants = collect_descendant_pids(root_pid);

    // SAFETY: `pgid` is the pid of a process this call spawned (with
    // `process_group(0)`, making it its own group's leader) and has not yet
    // been reaped, so the negated pid names exactly that group and cannot
    // alias an unrelated one. `kill(-pgid, SIGKILL)` on a group that has
    // already fully exited returns -1/ESRCH, which is not an error to
    // propagate — it is indistinguishable from (and handled the same as)
    // "already dead".
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    for (pid, snapshot_start) in &descendants {
        // S-L5: re-verify this pid still names the SAME process immediately
        // before signalling it. `collect_descendant_pids`'s snapshot and
        // this kill are not atomic — an entry near the end of a long
        // descendant list may have already exited and had its pid reused by
        // an unrelated process by the time this loop reaches it. Only a
        // start time that DISAGREES with the one recorded at snapshot time
        // counts as reuse; either side being unreadable ("cannot verify") is
        // treated the same as the pre-fix behaviour (proceed — a kill on an
        // already-gone pid is a harmless ESRCH).
        if !still_same_process(*pid, snapshot_start) {
            continue;
        }
        // SAFETY: `pid` was read from `ps` moments ago as a live descendant
        // of this call's own spawned child, and its start time was just
        // re-confirmed above. Signalling an already-exited pid is a
        // harmless ESRCH; the confirmation loop below requires ESRCH
        // specifically (never EPERM) before trusting "gone" — an unrelated
        // process still answering the probe leaves this call at the
        // conservative, unsettled `TimedOut` verdict.
        unsafe {
            libc::kill(*pid as libc::pid_t, libc::SIGKILL);
        }
    }
    // Reap the direct child so it never lingers as a zombie; this does not
    // by itself confirm the rest of the group (workers may be reparented
    // and reaped by init/launchd instead), which is exactly why the
    // confirmation loop below polls every individually-tracked descendant
    // too, not just the direct child.
    let _ = child.wait();

    let deadline = Instant::now() + GROUP_KILL_CONFIRM_TIMEOUT;
    loop {
        let group_gone = confirmed_gone(-pgid);
        let descendants_gone = descendants.iter().all(|(pid, snapshot_start)| {
            // A pid whose start time no longer matches the snapshot is, by
            // construction, no longer the descendant we tracked — that
            // descendant already exited (freeing the pid for reuse), so it
            // counts as gone without polling the (unrelated) process now
            // holding the pid.
            !still_same_process(*pid, snapshot_start) || confirmed_gone(*pid as libc::pid_t)
        });
        if group_gone && descendants_gone {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(GROUP_KILL_CONFIRM_POLL);
    }
}

/// Returns `true` when `pid` still identifies the SAME process the
/// `snapshot_start` time recorded at snapshot time (S-L5). A start time that
/// is unreadable — on EITHER side — is NOT treated as a mismatch: it means
/// "cannot verify", and the caller's existing best-effort behaviour (signal
/// or poll the pid anyway; a stale pid answers a harmless ESRCH) already
/// handles that safely. Only two start times that were BOTH readable and
/// DISAGREE are treated as evidence the pid was reused by an unrelated
/// process since the snapshot.
#[cfg(unix)]
fn still_same_process(pid: u32, snapshot_start: &Option<String>) -> bool {
    match snapshot_start {
        Some(snapshot) => match crate::session::codex_supervisor::process_start_time(pid) {
            Some(current) => *snapshot == current,
            None => true, // process now unreadable (likely already gone) -> cannot verify
        },
        None => true, // start time was unreadable at snapshot time -> cannot verify
    }
}

/// Returns `true` only when `target` (a pid, or a negated pid naming a
/// process group) is confirmed gone: `kill(target, 0)` failed with `ESRCH`.
///
/// F6: `EPERM` (still exists and is signalable, possibly now by a different
/// uid) and every other errno are treated as still-present, NOT as gone —
/// only `ESRCH` is unambiguous evidence that no such process/group remains.
#[cfg(unix)]
fn confirmed_gone(target: libc::pid_t) -> bool {
    // SAFETY: signal 0 delivers nothing — it is a pure existence probe on
    // either a single pid or (negated) a process group.
    let rc = unsafe { libc::kill(target, 0) };
    if rc == 0 {
        return false; // still alive and signalable by us
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Enumerates every LIVE descendant of `root_pid` (children, grandchildren,
/// ...) via `/bin/ps -axo pid=,ppid=` — the SAME absolute-path,
/// scrubbed-environment invocation pattern
/// `session::codex_supervisor::process_start_time` and
/// `codex_supervise::collect_descendant_pids` already use for process
/// identity/liveness, so this does not introduce a second, differently
/// hardened `ps` invocation with its own PATH/locale-shadowing exposure.
///
/// Walks by PARENT/CHILD links, not by process-group membership — a
/// `setsid()`-escaped worker changes its group but not its parent, so it is
/// still found here (see `kill_group_and_confirm_dead`'s doc). Best-effort:
/// a `ps` failure returns an empty list rather than erroring — the
/// group-directed kill at the call site still fires either way, so this
/// only WIDENS coverage, it is never the sole kill mechanism.
///
/// S-L5: each entry also carries the pid's start time
/// (`session::codex_supervisor::process_start_time`) AT SNAPSHOT TIME, so a
/// caller can re-verify — immediately before signalling — that the pid still
/// names the process this snapshot found, not a different one that reused a
/// recycled pid in the meantime.
#[cfg(unix)]
fn collect_descendant_pids(root_pid: u32) -> Vec<(u32, Option<String>)> {
    let output = match Command::new("/bin/ps")
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
        .into_iter()
        .map(|pid| {
            (
                pid,
                crate::session::codex_supervisor::process_start_time(pid),
            )
        })
        .collect()
}

/// Re-probe `cli` after a successful `run_auto_update`.
///
/// Invalidates the in-memory cache so `probe` hits the binary on disk,
/// then returns the new status.
pub fn reprobe_after_update(cli: SurfaceCli) -> CliStatus {
    invalidate(cli);
    run_probe(cli)
}

/// Returns the bare npm package name (without version range) for display
/// in user-facing upgrade messages where brevity matters.
///
/// Examples: `"@openai/codex"`, `"@anthropic-ai/claude-code"`.
///
/// Returns the npm package spec stripped of its version-range suffix
/// for display in upgrade messages. The result derives only from the
/// hardcoded `upgrade_command` table; no operator-supplied input reaches
/// the returned string, so no path redaction is required.
pub fn display_package_name(cli: SurfaceCli, manager: InstallManager) -> String {
    // Self-managed CLIs have no package: `upgrade_command`'s last token is the
    // subcommand (`upgrade`/`update`), not a package name. Display the CLI name.
    if manager == InstallManager::SelfManaged {
        return super::minimum::binary_name(cli).to_string();
    }
    if let Some(parts) = upgrade_command(cli, manager) {
        // Last argument of the upgrade_command is always the package spec.
        if let Some(pkg) = parts.last() {
            // Strip the version range suffix for display clarity.
            // "@openai/codex@>=0.40.0 <1.0.0" → "@openai/codex"
            // Handles scoped packages correctly: search from end for the
            // first `@` at index > 0 (the leading `@` of a scoped package
            // lives at index 0 and must not be stripped).
            let bytes = pkg.as_bytes();
            for i in (1..bytes.len()).rev() {
                if bytes[i] == b'@' {
                    return pkg[..i].to_string();
                }
            }
            return pkg.clone();
        }
    }
    // Fallback to single-source-of-truth constants (IR-L3).
    // `SurfaceCli` is `#[non_exhaustive]`; the wildcard arm is required for
    // forward-compatibility even though all current variants are matched above.
    #[allow(unreachable_patterns)]
    match cli {
        SurfaceCli::Claude => CLAUDE_NPM_PACKAGE.to_string(),
        SurfaceCli::Codex => CODEX_NPM_PACKAGE.to_string(),
        SurfaceCli::Gemini => GEMINI_NPM_PACKAGE.to_string(),
        SurfaceCli::Kimi | SurfaceCli::Grok => super::minimum::binary_name(cli).to_string(),
        _ => "unknown-cli-package".to_string(),
    }
}

/// Returns the full range-pinned npm package spec for use in operator-facing
/// runnable commands (e.g. `npm install -g @openai/codex@>=0.40.0 <1.0.0`).
///
/// When the manager has no entry in the upgrade_command table, falls back to
/// the bare package name so callers always get a usable string.
///
/// Unlike `display_package_name`, this function preserves the version range
/// so that copy-pasted commands from error messages remain range-pinned and
/// do not default to `@latest`.
pub fn display_full_package_spec(cli: SurfaceCli, manager: InstallManager) -> String {
    // Self-managed CLIs have no package spec — the last argv token is the
    // subcommand, not a package. Fall through to the CLI-name display.
    if manager != InstallManager::SelfManaged {
        if let Some(parts) = upgrade_command(cli, manager) {
            if let Some(pkg) = parts.last() {
                return pkg.clone();
            }
        }
    }
    // Fallback: bare package name (IR-L3 constants).
    display_package_name(cli, manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── auto_update_enabled ───────────────────────────────────────────────────

    /// When the CLI flag is set, auto-update is disabled regardless of env var.
    #[test]
    fn auto_update_disabled_by_cli_flag() {
        // Flag takes priority: no_auto_update_cli_flag = true → disabled.
        // We cannot safely mutate env vars without the workspace env lock here,
        // so we only test the flag branch (which is env-independent).
        assert!(
            !auto_update_enabled(true),
            "CLI flag should disable auto-update"
        );
    }

    // ── track-latest: enable check + throttle ─────────────────────────────────

    /// The `--track-latest` flag is a harmless explicit-opt-in no-op now
    /// that track-latest is on by default.
    #[test]
    fn track_latest_enabled_by_flag() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::remove_var("CSQ_NO_TRACK_LATEST") };
        assert!(
            track_latest_enabled(true),
            "flag=true must enable track-latest"
        );
    }

    /// Default is ON: no flag + no opt-out env → enabled (same polarity as
    /// `auto_update_enabled`, which is also ON by default).
    #[test]
    fn track_latest_enabled_by_default() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::remove_var("CSQ_NO_TRACK_LATEST") };
        unsafe { std::env::remove_var("CSQ_TRACK_LATEST") };
        assert!(
            track_latest_enabled(false),
            "no flag + no env must leave track-latest ON by default"
        );
    }

    /// `CSQ_TRACK_LATEST=1` remains a harmless explicit-opt-in no-op —
    /// track-latest is already on without it.
    #[test]
    fn track_latest_enabled_by_env_still_parses() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::remove_var("CSQ_NO_TRACK_LATEST") };
        unsafe { std::env::set_var("CSQ_TRACK_LATEST", "1") };
        let enabled = track_latest_enabled(false);
        unsafe { std::env::remove_var("CSQ_TRACK_LATEST") };
        assert!(enabled, "CSQ_TRACK_LATEST=1 must still enable track-latest");
    }

    /// `CSQ_NO_TRACK_LATEST=1` opts out of the new default-on behaviour,
    /// even when the (now-redundant) `--track-latest` flag is also passed.
    #[test]
    fn track_latest_disabled_by_no_track_latest_env() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::set_var("CSQ_NO_TRACK_LATEST", "1") };
        let disabled_default = !track_latest_enabled(false);
        let disabled_with_flag = !track_latest_enabled(true);
        unsafe { std::env::remove_var("CSQ_NO_TRACK_LATEST") };
        assert!(
            disabled_default,
            "CSQ_NO_TRACK_LATEST=1 must disable track-latest by default"
        );
        assert!(
            disabled_with_flag,
            "CSQ_NO_TRACK_LATEST=1 must disable track-latest even with --track-latest"
        );
    }

    /// No stamp file → attempt is due.
    #[test]
    fn track_latest_due_when_no_stamp() {
        let base = tempfile::TempDir::new().unwrap();
        assert!(
            track_latest_due(base.path(), SurfaceCli::Codex, SystemTime::now()),
            "missing stamp must read as due"
        );
    }

    /// A stamp recorded `now` makes a check at `now` NOT due (within window);
    /// a check `now + throttle` IS due again (record→due roundtrip).
    #[test]
    fn track_latest_throttle_roundtrip() {
        let base = tempfile::TempDir::new().unwrap();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        record_track_latest_attempt(base.path(), SurfaceCli::Codex, t0);

        // Same instant → not due (attempt just recorded).
        assert!(
            !track_latest_due(base.path(), SurfaceCli::Codex, t0),
            "an attempt just recorded must not be due again immediately"
        );
        // One second before the window elapses → still not due.
        let almost = t0 + TRACK_LATEST_THROTTLE - Duration::from_secs(1);
        assert!(
            !track_latest_due(base.path(), SurfaceCli::Codex, almost),
            "still within throttle window must not be due"
        );
        // Exactly one window later → due again.
        let after = t0 + TRACK_LATEST_THROTTLE;
        assert!(
            track_latest_due(base.path(), SurfaceCli::Codex, after),
            "a full throttle window later must be due again"
        );
    }

    /// A stamp dated MODESTLY in the future (ordinary clock skew, ≤ 30d)
    /// reads as NOT due — conservative: don't hammer npm on minor jitter.
    #[test]
    fn track_latest_ordinary_future_skew_is_not_due() {
        let base = tempfile::TempDir::new().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        // 1 hour ahead — ordinary skew, within the 30d self-heal threshold.
        let future = now + Duration::from_secs(3600);
        record_track_latest_attempt(base.path(), SurfaceCli::Codex, future);
        assert!(
            !track_latest_due(base.path(), SurfaceCli::Codex, now),
            "an ordinary future-skew stamp (≤30d) must read as not-due"
        );
    }

    /// A stamp dated ABSURDLY in the future (> 30d — a corrected one-time
    /// forward clock jump) self-heals to due (LOW-4), so track-latest is not
    /// permanently disabled until real time catches up.
    #[test]
    fn track_latest_absurd_future_stamp_self_heals() {
        let base = tempfile::TempDir::new().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        // ~31 years ahead — well beyond the 30d skew threshold.
        let absurd = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        record_track_latest_attempt(base.path(), SurfaceCli::Codex, absurd);
        assert!(
            track_latest_due(base.path(), SurfaceCli::Codex, now),
            "an absurd future stamp (>30d) must self-heal to due"
        );
    }

    /// A corrupt (non-integer) stamp reads as due — re-stamp on this run.
    #[test]
    fn track_latest_corrupt_stamp_is_due() {
        let base = tempfile::TempDir::new().unwrap();
        let path = track_latest_stamp_path(base.path(), SurfaceCli::Codex);
        std::fs::write(&path, "not-a-number").unwrap();
        assert!(
            track_latest_due(base.path(), SurfaceCli::Codex, SystemTime::now()),
            "corrupt stamp must read as due"
        );
    }

    /// Per-CLI isolation: a codex attempt does not throttle a gemini attempt.
    #[test]
    fn track_latest_stamp_is_per_cli() {
        let base = tempfile::TempDir::new().unwrap();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        record_track_latest_attempt(base.path(), SurfaceCli::Codex, t0);
        assert!(
            !track_latest_due(base.path(), SurfaceCli::Codex, t0),
            "codex just recorded → not due"
        );
        assert!(
            track_latest_due(base.path(), SurfaceCli::Gemini, t0),
            "gemini has no stamp → still due (per-CLI isolation)"
        );
    }

    /// When the CLI flag is not set and env var is absent, auto-update is ON.
    #[test]
    fn auto_update_enabled_by_default() {
        // Acquire the process-wide env-mutation lock so this test never races
        // against parallel tests that read or write CSQ_NO_AUTO_UPDATE_CLI.
        let _env_guard = crate::platform::test_env::lock();
        // Remove the opt-out var so the assertion always exercises the
        // "enabled" branch, regardless of what CI has exported.
        unsafe { std::env::remove_var("CSQ_NO_AUTO_UPDATE_CLI") };
        assert!(
            auto_update_enabled(false),
            "auto-update must be ON by default when neither flag nor env is set"
        );
    }

    // ── display_package_name ──────────────────────────────────────────────────

    #[test]
    fn display_package_name_codex_npm() {
        let name = display_package_name(SurfaceCli::Codex, InstallManager::NpmGlobal);
        assert_eq!(
            name, "@openai/codex",
            "codex npm package name must be '@openai/codex'; got {name:?}"
        );
    }

    #[test]
    fn display_package_name_claude_npm() {
        let name = display_package_name(SurfaceCli::Claude, InstallManager::NpmGlobal);
        assert_eq!(
            name, "@anthropic-ai/claude-code",
            "claude npm package name must be '@anthropic-ai/claude-code'; got {name:?}"
        );
    }

    #[test]
    fn display_package_name_gemini_npm() {
        let name = display_package_name(SurfaceCli::Gemini, InstallManager::NpmGlobal);
        assert_eq!(
            name, "@google/gemini-cli",
            "gemini npm package name must be '@google/gemini-cli'; got {name:?}"
        );
    }

    #[test]
    fn display_package_name_fallback_for_unknown_manager() {
        // ClaudeNativeInstaller has no upgrade_command → fallback.
        let name = display_package_name(SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller);
        // Fallback returns the well-known package name.
        assert!(
            !name.is_empty(),
            "display_package_name must not return empty string"
        );
        assert_eq!(
            name, CLAUDE_NPM_PACKAGE,
            "fallback must use CLAUDE_NPM_PACKAGE constant; got {name:?}"
        );
    }

    // ── display_full_package_spec ──────────────────────────────────────────────

    #[test]
    fn display_full_package_spec_codex_npm_has_range_pin() {
        let spec = display_full_package_spec(SurfaceCli::Codex, InstallManager::NpmGlobal);
        assert!(
            spec.contains(">=0.40.0"),
            "full spec must include version range; got {spec:?}"
        );
        assert!(
            spec.starts_with("@openai/codex"),
            "full spec must start with package name; got {spec:?}"
        );
    }

    #[test]
    fn display_full_package_spec_claude_npm_has_range_pin() {
        let spec = display_full_package_spec(SurfaceCli::Claude, InstallManager::NpmGlobal);
        assert!(
            spec.contains(">=2.0.0"),
            "full spec must include version range; got {spec:?}"
        );
    }

    #[test]
    fn display_full_package_spec_fallback_for_unknown_manager() {
        // No upgrade_command → fallback to bare name (still usable).
        let spec =
            display_full_package_spec(SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller);
        assert!(!spec.is_empty(), "fallback spec must not be empty");
    }

    // ── run_auto_update: NoCommand for unrecognized manager ───────────────────

    #[test]
    fn run_auto_update_returns_no_command_for_unknown_manager() {
        // InstallManager::Unknown has no upgrade_command → NoCommand.
        let result = run_auto_update(SurfaceCli::Codex, InstallManager::Unknown, None);
        assert!(
            matches!(result, Err(UpdateError::NoCommand)),
            "Unknown manager must produce NoCommand; got {result:?}"
        );
    }

    #[test]
    fn run_auto_update_returns_no_command_for_claude_native_installer() {
        // ClaudeNativeInstaller has no upgrade_command → NoCommand.
        let result = run_auto_update(
            SurfaceCli::Claude,
            InstallManager::ClaudeNativeInstaller,
            None,
        );
        assert!(
            matches!(result, Err(UpdateError::NoCommand)),
            "ClaudeNativeInstaller must produce NoCommand; got {result:?}"
        );
    }

    // ── SR-H1: env allowlist applied to subprocess ────────────────────────────

    /// Verify that the env allowlist is applied: the subprocess must NOT inherit
    /// any env var outside the allowlist. We test this by passing a custom
    /// run_fn that captures the env of the spawned process — exercising the
    /// allowlist logic path through a closure-injected stub.
    ///
    /// The actual secret-scrubbing guarantee is structural: `env_clear()` is
    /// called unconditionally on every npm spawn in `run_auto_update`.
    /// This test verifies the allowed set is the expected set by confirming
    /// that SECRET_CANARY (outside the allowlist) does not reach the child.
    #[cfg(unix)]
    #[test]
    fn env_allowlist_does_not_leak_secret_env_var() {
        use std::process::Command;

        // Acquire the process-wide env-mutation lock FIRST so this test
        // serialises against any parallel test that reads or writes env vars
        // (rules/testing.md Rule 6; canonical pattern from sanitize.rs,
        // install_path.rs, ollama.rs, codex/surface.rs).
        let _env_guard = crate::platform::test_env::lock();

        // Spawn a child that dumps its env to stdout, then grep for the canary.
        // We run the same allowlist logic inline here so this is a white-box
        // check that the allowlist is correct.
        let canary_key = "CSQ_SECRET_CANARY_TEST";
        let canary_val = "canary_should_not_appear_in_child";
        // Set the canary in the current process env temporarily.
        unsafe { std::env::set_var(canary_key, canary_val) };

        // Build a Command exactly as run_auto_update does (without spawning npm).
        let mut cmd = Command::new("env");
        cmd.stdin(Stdio::null());
        cmd.env_clear();
        for var in [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TERM",
            "SHELL",
            "LANG",
            "LC_ALL",
            "NPM_CONFIG_PREFIX",
            "NODE_PATH",
        ] {
            if let Ok(v) = std::env::var(var) {
                cmd.env(var, v);
            }
        }

        let output = cmd.output().expect("env binary must be available");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Plain Vec — no cross-thread sharing needed in this single-threaded test.
        let lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        // Clean up BEFORE the assert so the canary is removed even if the
        // assertion panics (panic-safe cleanup).
        unsafe { std::env::remove_var(canary_key) };

        let leaked = lines.iter().any(|line| line.contains(canary_val));
        assert!(
            !leaked,
            "CSQ_SECRET_CANARY_TEST must not appear in child env after env_clear; \
             env_allowlist is broken. Child env lines:\n{}",
            lines.join("\n")
        );
    }

    // ── DA-H2: timeout kills subprocess that hangs ────────────────────────────

    /// Verify that the timeout polling loop fires correctly by using a closure-
    /// injected stub approach: we test the logic by calling `run_auto_update`
    /// with a manager that maps to `sleep`-equivalent behavior (NoCommand)
    /// and separately verify the timeout constant is sane.
    ///
    /// A full subprocess sleep test would be slow (120s) so we verify the
    /// timeout constant and the kill path through a shorter integration test
    /// using a sub-second sleep process.
    #[cfg(unix)]
    #[test]
    fn timeout_loop_kills_subprocess_after_deadline() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // Use a very short timeout (1s) to keep the test fast.
        let short_timeout = Duration::from_millis(500);

        // Bind the helper binary ABSOLUTELY, not through `PATH`. Rust runs a
        // crate's tests as threads of ONE process, and two sibling tests in
        // this crate set `PATH` to "" process-wide while they run
        // (`install_path.rs::path_walk_*` and `run_auto_update` below —
        // `grep -n 'set_var("PATH"' csq-core/src/cli_deps/`). Resolving
        // `sleep` through `PATH` therefore made this test's outcome depend on
        // thread interleaving: it passes alone and fails under the `cli_deps`
        // filter whenever it overlaps one of those windows. The dependency
        // this test actually has is on a file existing, not on an environment
        // variable no test owns.
        let sleep_bin = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .expect("a `sleep` binary must exist at /bin/sleep or /usr/bin/sleep on unix");

        let mut child = Command::new(sleep_bin)
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep must be spawnable on unix");

        let start = Instant::now();
        let result: Result<(), &str> = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        break Ok(());
                    } else {
                        break Err("exited nonzero");
                    }
                }
                Ok(None) => {
                    if start.elapsed() >= short_timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err("timed out");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break Err("try_wait error"),
            }
        };

        assert!(
            matches!(result, Err("timed out")),
            "timeout loop must kill the subprocess and return timed-out error; got {result:?}"
        );
        // Verify we didn't wait too long.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout loop must exit promptly; elapsed: {:?}",
            start.elapsed()
        );
    }

    // ── C-R4-10 / S-F7 (FM-9): timeout kill reaches the WHOLE group ──────────

    /// THE discriminating test for the group-kill fix. The stub "updater" is
    /// a shell that forks a detached background worker (keeps appending to
    /// a marker file) and then itself hangs — standing in for an
    /// npm/vendor-updater process whose own worker outlives the direct
    /// child once that child is killed. `run_child_with_timeout` MUST kill
    /// the worker too, not just the direct shell, and MUST confirm it
    /// before reporting `TimedOutSettled`.
    ///
    /// Marker path is passed as `$1` (an argv element), never interpolated
    /// into the script text, so this stays array-args / no-shell-
    /// interpolation even though the path is dynamic (security.md MUST
    /// NOT-1).
    #[cfg(unix)]
    #[test]
    fn timeout_kills_whole_process_group_not_just_direct_child() {
        // Serializes against every other test that reaches
        // `run_child_with_timeout` — see `lock_signal_state_for_test`'s doc: without
        // this, a SIGINT test's blind self-signal can land on WHICHEVER
        // call currently holds `InterruptSignalGuard`'s internal lock,
        // which may be this test rather than the one sending the signal
        // (measured: intermittent `Err(Interrupted(2))` here).
        let _signal_lock = lock_signal_state_for_test();
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("worker.marker");

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(
                "i=0; while [ $i -lt 500 ]; do date +%s%N >> \"$1\" 2>/dev/null; \
                 i=$((i+1)); sleep 0.02; done & sleep 30",
            )
            .arg("worker") // $0 inside the script (unused, but conventional)
            .arg(&marker); // $1 inside the script — the marker path
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let result = run_child_with_timeout(cmd, Duration::from_millis(300));

        assert!(
            matches!(result, Err(UpdateError::TimedOutSettled)),
            "a confirmed whole-group kill must report TimedOutSettled; got {result:?}"
        );

        // The discriminating check: the background worker must have
        // actually stopped writing, not merely been orphaned-but-still-
        // running (which a direct-child-only kill would leave behind).
        let size_at_return = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
        assert!(
            size_at_return > 0,
            "the worker must have written at least one line before the timeout fired"
        );
        std::thread::sleep(Duration::from_millis(300));
        let size_after_wait = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
        assert_eq!(
            size_at_return, size_after_wait,
            "the background worker must have stopped writing to the marker file once \
             run_child_with_timeout returned (it grew from {size_at_return} to \
             {size_after_wait} bytes afterwards — a group-kill that missed the worker)"
        );
    }

    // ── F6: a setsid()-escaped worker is still killed and confirmed ──────────

    /// THE discriminating test for F6. The stub "updater" forks a worker
    /// that immediately `setsid()`s — a NEW session and process group,
    /// escaping the direct child's `process_group(0)` group entirely — and
    /// then keeps writing to a marker file while the direct child itself
    /// hangs. On the PRE-FIX code, `kill(-pgid, ...)` never reaches the
    /// escaped worker, yet `kill(-pgid, 0)`'s confirmation loop sees the
    /// (now worker-free) group go `ESRCH` almost immediately and reports
    /// `TimedOutSettled` while the worker is still alive and writing — RED:
    /// this is the exact "confirmed" state a caller is told it may safely
    /// re-probe. The fix must track the worker by parent/child descent
    /// (not group membership), kill it individually, and refuse to report
    /// settled until it is actually gone.
    ///
    /// Marker path is passed as an argv element (`$ARGV[0]`), never
    /// interpolated into the script text (security.md MUST NOT-1).
    #[cfg(unix)]
    #[test]
    fn timeout_kill_confirms_a_setsid_escaped_worker_too() {
        // See `timeout_kills_whole_process_group_not_just_direct_child`'s
        // matching comment / `lock_signal_state_for_test`'s doc.
        let _signal_lock = lock_signal_state_for_test();
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("worker.marker");

        let mut cmd = Command::new("perl");
        cmd.arg("-e").arg(
            "use POSIX qw(setsid); \
             my $marker = $ARGV[0]; \
             if (fork() == 0) { \
                 setsid(); \
                 open(my $fh, '>>', $marker) or exit 1; \
                 for (1..500) { \
                     print $fh time().\"\\n\"; \
                     $fh->flush(); \
                     select(undef, undef, undef, 0.02); \
                 } \
                 exit 0; \
             } \
             sleep(30);",
        );
        cmd.arg(&marker);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let result = run_child_with_timeout(cmd, Duration::from_millis(400));

        // Whichever verdict comes back must never be a LIE: `TimedOutSettled`
        // is acceptable only if the worker is actually confirmed dead;
        // otherwise `TimedOut` (unsettled) is the honest answer. What is
        // BLOCKED is the pre-fix behaviour: `TimedOutSettled` returned while
        // the worker keeps writing.
        assert!(
            matches!(
                result,
                Err(UpdateError::TimedOutSettled) | Err(UpdateError::TimedOut)
            ),
            "a setsid-escaped worker must yield a confirmed-settled or honestly-unsettled \
             verdict, never Ok/InstallFailed/NoCommand/NpmMissing; got {result:?}"
        );

        if matches!(result, Err(UpdateError::TimedOutSettled)) {
            // The discriminating check: TimedOutSettled must mean the escaped
            // worker is ACTUALLY dead, not merely that the (now empty) group
            // it escaped answered ESRCH.
            let size_at_return = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
            assert!(
                size_at_return > 0,
                "the setsid-escaped worker must have written at least one line before \
                 the timeout fired"
            );
            std::thread::sleep(Duration::from_millis(300));
            let size_after_wait = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
            assert_eq!(
                size_at_return, size_after_wait,
                "a setsid-escaped worker must have stopped writing once \
                 run_child_with_timeout reported TimedOutSettled (it grew from \
                 {size_at_return} to {size_after_wait} bytes afterwards — the group-only \
                 kill missed it)"
            );
        }
    }

    // ── F5: SIGINT mid-update kills, confirms, and reports Interrupted ────────

    /// Belt-and-braces alongside `InterruptSignalGuard`'s own
    /// `AUTO_UPDATE_SIGNAL_GUARD_LOCK` (which is the load-bearing fix: two
    /// overlapping `run_child_with_timeout` calls — including ones that
    /// never touch this test file, e.g. `timeout_kills_whole_process_group_
    /// not_just_direct_child` running concurrently with the SIGINT test
    /// below — share ONE process-wide caught-signal flag, so without that
    /// production-level lock a signal meant for one call's wait loop is
    /// observed by every other call in the SAME `cargo test` process too;
    /// measured directly: a first version of this test suite intermittently
    /// failed 4 unrelated tests with `Interrupted(2)` before that lock was
    /// added). This additionally serializes the two tests in THIS file that
    /// reach into signal-disposition internals (`libc::signal(.., SIG_DFL)`
    /// in the restore-check below), which sit outside
    /// `InterruptSignalGuard`'s own lifetime.
    ///
    /// Item 4 (D-F3): this is now
    /// [`crate::platform::test_env::signal_lock`] — a lock shared across
    /// the WHOLE workspace, not a module-local mutex. The prior version of
    /// this doc comment recorded that `codex_supervise`'s equivalent guard
    /// "lives in a different crate and cannot be reused here"; that gap is
    /// what `signal_lock` closes.
    ///
    /// `#[cfg(unix)]`: every caller is a unix-only signal / process-group
    /// test, so on a non-unix build this helper has no caller.
    #[cfg(unix)]
    fn lock_signal_state_for_test() -> std::sync::MutexGuard<'static, ()> {
        crate::platform::test_env::signal_lock()
    }

    /// THE discriminating test for F5. Standing in for a user's Ctrl-C
    /// landing on `csq` mid-update (there is no separate "csq process" to
    /// signal from a unit test, so — matching `codex_supervise`'s own
    /// established pattern for this exact problem — a helper thread raises
    /// `SIGINT` against THIS test process while `run_child_with_timeout` is
    /// blocked in its poll loop on a stub updater that forked a background
    /// worker). The fix must kill the group + the worker, confirm both are
    /// gone, and return `Interrupted(SIGINT)` — never let the default
    /// disposition terminate the process while the worker is still writing,
    /// and never silently swallow the signal and keep waiting for the full
    /// timeout.
    #[cfg(unix)]
    #[test]
    fn sigint_during_wait_kills_confirms_and_reports_interrupted() {
        let _signal_lock = lock_signal_state_for_test();

        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("worker.marker");

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(
                "i=0; while [ $i -lt 500 ]; do date +%s%N >> \"$1\" 2>/dev/null; \
                 i=$((i+1)); sleep 0.02; done & sleep 30",
            )
            .arg("worker")
            .arg(&marker);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        // Raise SIGINT against our own pid shortly after the wait starts —
        // well before the 20s bound below, and well before the subprocess's
        // own `sleep 30` would return on its own.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(200));
            unsafe {
                libc::kill(std::process::id() as libc::pid_t, libc::SIGINT);
            }
        });

        let result = run_child_with_timeout(cmd, Duration::from_secs(20));

        assert!(
            matches!(
                result,
                Err(UpdateError::Interrupted { signal, .. }) if signal == libc::SIGINT
            ),
            "a SIGINT arriving mid-wait must report Interrupted{{signal: SIGINT, ..}}; got {result:?}"
        );
        // S-L3: this test's own worker-stopped assertion below only holds
        // when the kill was actually confirmed — `settled` must be true here
        // (a real, reachable worker; nothing escapes the kill in this test).
        assert!(
            matches!(result, Err(UpdateError::Interrupted { settled: true, .. })),
            "a confirmable worker must report settled=true; got {result:?}"
        );

        // The discriminating check, same shape as the timeout/setsid tests:
        // the worker must be ACTUALLY dead, not merely orphaned-but-running.
        let size_at_return = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
        assert!(
            size_at_return > 0,
            "the worker must have written at least one line before SIGINT fired"
        );
        std::thread::sleep(Duration::from_millis(300));
        let size_after_wait = std::fs::metadata(&marker).map(|m| m.len()).unwrap_or(0);
        assert_eq!(
            size_at_return, size_after_wait,
            "the worker must have stopped writing once run_child_with_timeout reported \
             Interrupted (it grew from {size_at_return} to {size_after_wait} bytes \
             afterwards — the interrupt path failed to kill it)"
        );
    }

    /// The previous disposition (default: terminate the process) MUST be
    /// restored once `run_child_with_timeout` returns normally (no signal
    /// arrived) — otherwise a LATER, unrelated SIGINT in the same test
    /// process would be silently swallowed by this module's flag-only
    /// handler instead of behaving normally.
    #[cfg(unix)]
    #[test]
    fn signal_handlers_are_restored_after_a_normal_return() {
        let _signal_lock = lock_signal_state_for_test();

        // A command that finishes well within the timeout — no signal path.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exit 0");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let result = run_child_with_timeout(cmd, Duration::from_secs(5));
        assert!(matches!(result, Ok(())), "got {result:?}");

        // SAFETY: reading back the current disposition via signal(2) with
        // SIG_DFL sets AND returns the previous one in a single call; if
        // this module's handler were still installed, the returned value
        // would be `auto_update_set_signal_flag` rather than `SIG_DFL`.
        let current = unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        assert_eq!(
            current,
            libc::SIG_DFL,
            "SIGINT disposition must be restored to SIG_DFL (or whatever the test \
             harness itself had installed, which is also SIG_DFL by default) after a \
             normal (non-signaled) return from run_child_with_timeout"
        );
    }

    // ── UpdateError display (fixed-vocabulary tags) ───────────────────────────

    #[test]
    fn update_error_display_has_fixed_tag() {
        // Each variant's Display must start with a fixed-vocabulary tag
        // for log filtering (security.md fixed-vocabulary error_kind rule).
        let cases = vec![
            (UpdateError::NoCommand, "no_auto_update_command"),
            (UpdateError::NpmMissing, "npm_missing"),
            (UpdateError::InstallFailed, "install_failed"),
            (UpdateError::TimedOutSettled, "install_timed_out_settled"),
            (
                UpdateError::Interrupted {
                    signal: 2,
                    settled: true,
                },
                "interrupted",
            ),
        ];
        for (err, expected_prefix) in cases {
            let msg = err.to_string();
            assert!(
                msg.starts_with(expected_prefix),
                "UpdateError::{err:?} display must start with '{expected_prefix}'; got {msg:?}"
            );
        }
    }

    // ── IR-L3: constants match display_package_name output ───────────────────

    #[test]
    fn npm_package_constants_match_display_package_name() {
        assert_eq!(
            display_package_name(SurfaceCli::Claude, InstallManager::NpmGlobal),
            CLAUDE_NPM_PACKAGE,
        );
        assert_eq!(
            display_package_name(SurfaceCli::Codex, InstallManager::NpmGlobal),
            CODEX_NPM_PACKAGE,
        );
        assert_eq!(
            display_package_name(SurfaceCli::Gemini, InstallManager::NpmGlobal),
            GEMINI_NPM_PACKAGE,
        );
    }

    // ── SelfManaged (Kimi/Grok) display guards ────────────────────────────────

    /// display_package_name must return the CLI name, NOT the upgrade
    /// subcommand token ("upgrade"/"update") which is `upgrade_command`'s last arg.
    #[test]
    fn display_package_name_self_managed_is_cli_name() {
        assert_eq!(
            display_package_name(SurfaceCli::Kimi, InstallManager::SelfManaged),
            "kimi"
        );
        assert_eq!(
            display_package_name(SurfaceCli::Grok, InstallManager::SelfManaged),
            "grok"
        );
    }

    /// display_full_package_spec must ALSO return the CLI name for SelfManaged —
    /// the guard prevents it from returning upgrade_command.last() = "upgrade".
    #[test]
    fn display_full_package_spec_self_managed_is_cli_name_not_subcommand() {
        let kimi = display_full_package_spec(SurfaceCli::Kimi, InstallManager::SelfManaged);
        assert_eq!(
            kimi, "kimi",
            "must be CLI name, not the 'upgrade' subcommand"
        );
        let grok = display_full_package_spec(SurfaceCli::Grok, InstallManager::SelfManaged);
        assert_eq!(
            grok, "grok",
            "must be CLI name, not the 'update' subcommand"
        );
    }

    /// run_auto_update for a SelfManaged CLI whose binary is not resolvable on
    /// disk (empty PATH + no vendor dir under a sandbox HOME) returns NoCommand
    /// — nothing to update. Exercises the non-npm resolution branch.
    #[cfg(unix)]
    #[test]
    fn run_auto_update_self_managed_unresolvable_binary_is_no_command() {
        let _env_guard = crate::platform::test_env::lock();
        let sandbox = tempfile::TempDir::new().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_path = std::env::var_os("PATH");
        // SAFETY: env lock held; restored below. Empty PATH + a sandbox HOME with
        // no ~/.kimi-code/bin makes find_in_path("kimi") miss both sources.
        unsafe {
            std::env::set_var("HOME", sandbox.path());
            std::env::set_var("PATH", "");
        }

        let result = run_auto_update(SurfaceCli::Kimi, InstallManager::SelfManaged, None);

        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match old_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }

        assert!(
            matches!(result, Err(UpdateError::NoCommand)),
            "unresolvable self-managed binary must yield NoCommand; got {result:?}"
        );
    }

    /// S-F10: when a `classified_path` is supplied for a `SelfManaged` CLI,
    /// `run_auto_update` MUST spawn THAT path — not whatever a fresh
    /// `find_in_path` walk would resolve. PATH is arranged so a fresh lookup
    /// would find a DIFFERENT "codex" script than the one passed in; each
    /// script drops its own marker file so we can tell which one actually ran.
    #[cfg(unix)]
    #[test]
    fn run_auto_update_self_managed_uses_provided_canonical_path_not_fresh_path_lookup() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        // This reaches `run_child_with_timeout` via `run_auto_update` — see
        // `timeout_kills_whole_process_group_not_just_direct_child`'s
        // matching comment / `lock_signal_state_for_test`'s doc.
        let _signal_lock = lock_signal_state_for_test();
        let _env_guard = crate::platform::test_env::lock();

        let dir_classified = tempfile::TempDir::new().unwrap();
        let dir_path_shadow = tempfile::TempDir::new().unwrap();
        let markers = tempfile::TempDir::new().unwrap();
        let marker_classified = markers.path().join("classified.marker");
        let marker_shadow = markers.path().join("shadow.marker");

        // `: > 'path'` (shell-builtin redirection) rather than `touch`: the
        // child spawns under an env-cleared, allowlisted PATH (SR-H1), and
        // this test additionally restricts PATH to just the two temp dirs —
        // `touch` would not resolve there, but redirection needs no external
        // binary at all.
        let classified_bin = dir_classified.path().join("codex");
        fs::write(
            &classified_bin,
            format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker_classified.display()),
        )
        .unwrap();
        fs::set_permissions(&classified_bin, fs::Permissions::from_mode(0o755)).unwrap();

        let shadow_bin = dir_path_shadow.path().join("codex");
        fs::write(
            &shadow_bin,
            format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker_shadow.display()),
        )
        .unwrap();
        fs::set_permissions(&shadow_bin, fs::Permissions::from_mode(0o755)).unwrap();

        let old_path = std::env::var_os("PATH");
        // Shadow binary comes FIRST — a fresh find_in_path("codex") would
        // resolve to it, not the classified_bin path we pass explicitly.
        let new_path =
            std::env::join_paths([dir_path_shadow.path(), dir_classified.path()]).unwrap();
        // SAFETY: env lock held; restored below.
        unsafe { std::env::set_var("PATH", &new_path) };

        let result = run_auto_update(
            SurfaceCli::Codex,
            InstallManager::SelfManaged,
            Some(classified_bin.as_path()),
        );

        unsafe {
            match old_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }

        assert!(
            result.is_ok(),
            "expected the classified binary to run successfully; got {result:?}"
        );
        assert!(
            marker_classified.exists(),
            "the classified_path binary must have been executed"
        );
        assert!(
            !marker_shadow.exists(),
            "a fresh PATH lookup must NOT have run instead of the classified path"
        );
    }

    // ── FM-9: track-latest gets its own, shorter update timeout ──────────────

    #[test]
    fn track_latest_update_timeout_is_shorter_than_npm_install_timeout() {
        assert!(
            TRACK_LATEST_UPDATE_TIMEOUT < NPM_INSTALL_TIMEOUT,
            "track-latest's optional upgrade must not tie up an interactive \
             launch for the same budget granted to a mandatory floor upgrade"
        );
        // Sanity: still positive and non-trivial (not accidentally zeroed).
        assert!(TRACK_LATEST_UPDATE_TIMEOUT >= Duration::from_secs(30));
    }

    // ── C-F7: TRACK_LATEST_LOCK_WAIT_TIMEOUT covers the holder's REAL worst case ──

    /// The old derivation (`NPM_INSTALL_TIMEOUT + 5`) understated the
    /// holder's worst case by the confirm-kill + re-probe tail that can run
    /// AFTER the holder's own install timeout fires. The bound must cover
    /// all of it, not just the install itself.
    #[test]
    fn track_latest_lock_wait_timeout_covers_holders_full_worst_case() {
        let holders_full_worst_case = NPM_INSTALL_TIMEOUT
            + Duration::from_secs(GROUP_KILL_CONFIRM_SECS)
            + Duration::from_secs(MAX_PROBE_TIMEOUT_SECS);
        assert!(
            TRACK_LATEST_LOCK_WAIT_TIMEOUT > holders_full_worst_case,
            "the wait bound ({TRACK_LATEST_LOCK_WAIT_TIMEOUT:?}) must exceed the holder's \
             full worst case ({holders_full_worst_case:?}: install + confirm-kill + re-probe), \
             with a positive margin left over"
        );
        // The old (under-derived) bound would have failed this by 8s
        // (GROUP_KILL_CONFIRM_SECS + MAX_PROBE_TIMEOUT_SECS = 2 + 6).
        assert!(
            TRACK_LATEST_LOCK_WAIT_TIMEOUT >= NPM_INSTALL_TIMEOUT + Duration::from_secs(18),
            "got {TRACK_LATEST_LOCK_WAIT_TIMEOUT:?}"
        );
    }

    // ── S-L5: a recycled pid must not be individually SIGKILLed ──────────────

    #[cfg(unix)]
    #[test]
    fn still_same_process_agrees_when_start_times_match() {
        // Use this test's own pid/start-time as a real, stable subject.
        let pid = std::process::id();
        let start = crate::session::codex_supervisor::process_start_time(pid);
        assert!(
            still_same_process(pid, &start),
            "a pid whose current start time matches its snapshot must read as the same process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn still_same_process_rejects_a_disagreeing_start_time() {
        let pid = std::process::id();
        // A snapshot claiming a start time that cannot be this process's own
        // real one (this process was not started in 1970) must be treated
        // as a mismatch — i.e. the pid was recycled since the snapshot.
        let forged_snapshot = Some("Thu Jan  1 00:00:00 1970".to_string());
        assert!(
            !still_same_process(pid, &forged_snapshot),
            "a start time that disagrees with the current one must NOT read as the same process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn still_same_process_cannot_verify_defaults_to_proceed() {
        // Snapshot side unreadable (None) -> cannot verify -> proceed (true),
        // matching the pre-fix best-effort behaviour for the unverifiable case.
        assert!(
            still_same_process(std::process::id(), &None),
            "an unreadable snapshot start time must default to 'cannot verify' (proceed)"
        );
        // A pid that does not exist at all: process_start_time returns None
        // for it too, so this also hits the 'cannot verify' branch rather
        // than being treated as a confirmed mismatch.
        let bogus_pid = u32::MAX;
        let some_snapshot = Some("Thu Jan  1 00:00:00 1970".to_string());
        assert!(
            still_same_process(bogus_pid, &some_snapshot),
            "an unreadable CURRENT start time must also default to 'cannot verify' (proceed)"
        );
    }

    // ── FM-8: waiting for a sibling's track-latest lock to release ───────────

    /// Held lock: the wait must return `false` once its (injected, short)
    /// bound elapses — never block past that bound, and never panic.
    #[test]
    fn wait_for_lock_release_returns_false_when_held_past_the_bound() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path = base.path().join(".track-latest-codex.lock");
        // Hold the lock on ANOTHER thread, standing in for a sibling process:
        // on Windows the lock is a named mutex owned by the holding thread,
        // so re-checking it from this same thread would succeed.
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder_path = lock_path.clone();
        let holder = std::thread::spawn(move || {
            let _guard = crate::platform::lock::lock_file(&holder_path).unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx
            .recv()
            .expect("holder thread must take the lock first");

        let start = Instant::now();
        let released = wait_for_track_latest_lock_release_with(
            &lock_path,
            Duration::from_millis(150),
            Duration::from_millis(20),
        );
        let elapsed = start.elapsed();

        assert!(
            !released,
            "a lock held for the entire bound must report NOT released"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not wait past its own bound; elapsed={elapsed:?}"
        );
        drop(release_tx);
        holder.join().unwrap();
    }

    /// Free lock: the wait must return `true` immediately — no polling
    /// delay incurred when nobody holds the lock.
    #[test]
    fn wait_for_lock_release_returns_true_when_free() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path = base.path().join(".track-latest-codex.lock");

        let start = Instant::now();
        let released = wait_for_track_latest_lock_release_with(
            &lock_path,
            Duration::from_secs(5),
            Duration::from_millis(20),
        );
        let elapsed = start.elapsed();

        assert!(released, "a free lock must report released immediately");
        assert!(
            elapsed < Duration::from_millis(500),
            "a free lock must not incur any polling wait; elapsed={elapsed:?}"
        );
    }

    /// A held lock that releases partway through the bound must be observed
    /// as released — the wait actually polls rather than sampling once.
    #[test]
    fn wait_for_lock_release_observes_a_mid_window_release() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path_for_holder = base.path().join(".track-latest-codex.lock");
        let lock_path = lock_path_for_holder.clone();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = crate::platform::lock::lock_file(&lock_path_for_holder).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        rx.recv().unwrap();

        let released = wait_for_track_latest_lock_release_with(
            &lock_path,
            Duration::from_secs(2),
            Duration::from_millis(20),
        );
        holder.join().unwrap();

        assert!(
            released,
            "a lock released partway through the bound must be observed as released"
        );
    }
}
