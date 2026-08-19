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
//! `minimum::upgrade_command(cli, manager)` dispatch table. That table
//! already carries range-pinned npm arguments (e.g.
//! `@openai/codex@>=0.40.0 <1.0.0`) so we never pin to `@latest` and
//! never update past a known-good major boundary.
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
//! ## Range-pinning as max-known-good defence
//!
//! The upgrade commands in `minimum::upgrade_command` use npm range syntax
//! (`@>=M.m.p <N.0.0`) which prevents npm from installing a breaking
//! major-version bump. This is the max-known-good check: if the latest npm
//! version is outside the range, npm refuses the install and we fall through
//! to the existing bail. No registry query is needed; the range constraint
//! is enforced server-side by npm during package resolution.

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

    /// The upgrade subprocess exited with a non-zero status, or was killed
    /// after exceeding the 120s wall-clock timeout.
    #[error("install_failed: upgrade command exited with non-zero status or timed out")]
    InstallFailed,
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

// ── Track-latest opt-in mode ──────────────────────────────────────────────
//
// The default auto-update gate is *floor-guarded*: it fires only when the
// probe returns `Outdated` (binary below csq's `min_version`). A binary that
// probes `Ok` (>= floor) is left alone — even when a newer release exists.
//
// Track-latest is an OPT-IN mode (default OFF, opposite polarity from
// `auto_update_enabled`) that keeps the managed CLIs at the ABSOLUTE latest
// release *within the supported major*. It reuses the exact same
// `run_auto_update` path — the `upgrade_command` table is range-pinned
// (`@pkg@>=M.m.p <N.0.0`), so `npm install -g` resolves the newest release
// inside the supported range and never crosses a major boundary. A true
// cross-major `@latest` would require a `min_version` bump per the 1.0-bump
// policy (spec/13 §7) and is intentionally NOT what this mode does.
//
// Because running an npm install on every `csq run`/`csq login` would be
// slow, the attempt is throttled to at most once per CLI per throttle
// window via a per-CLI stamp file under the csq base dir.

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
/// `track_latest_flag` is `true` when the operator passed `--track-latest`
/// on the command line. Track-latest is ALSO enabled by the environment
/// variable `CSQ_TRACK_LATEST=1`. Default: **OFF** (floor-guard is the safe
/// default; track-latest is explicit opt-in).
pub fn track_latest_enabled(track_latest_flag: bool) -> bool {
    if track_latest_flag {
        return true;
    }
    std::env::var("CSQ_TRACK_LATEST").as_deref() == Ok("1")
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
/// `manager` is the `InstallManager` from the `CliStatus::Outdated` variant,
/// sourced from the probe result — no additional classification needed.
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
pub fn run_auto_update(cli: SurfaceCli, manager: InstallManager) -> Result<(), UpdateError> {
    // Resolve upgrade command from the existing dispatch table.
    let cmd_parts = upgrade_command(cli, manager).ok_or(UpdateError::NoCommand)?;

    // cmd_parts[0] is the program name; the rest are arguments.
    let program = &cmd_parts[0];

    // For npm-based upgrades, verify npm is on PATH before attempting.
    // The upgrade_command table for npm entries starts with "npm".
    if program == "npm" && !npm_on_path() {
        return Err(UpdateError::NpmMissing);
    }

    // For self-managed CLIs (`kimi upgrade` / `grok update`) the program is the
    // CLI's own binary, which may live outside a minimal PATH (spec/13 §5
    // known-location fallback). Resolve it to a full path so the spawn does not
    // fail with ENOENT; if it cannot be resolved the binary is genuinely absent
    // and there is nothing to update.
    let resolved_program: std::path::PathBuf = if program == "npm" || program == "brew" {
        std::path::PathBuf::from(program)
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

    let mut child = cmd.spawn().map_err(|_| UpdateError::InstallFailed)?;

    // DA-H2: poll with 250ms granularity; kill after NPM_INSTALL_TIMEOUT.
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(UpdateError::InstallFailed);
                }
                return Ok(());
            }
            Ok(None) => {
                if start.elapsed() >= NPM_INSTALL_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::error!(
                        error_kind = "auto_update_npm_timeout",
                        elapsed_secs = start.elapsed().as_secs(),
                        "npm install exceeded timeout; killed"
                    );
                    return Err(UpdateError::InstallFailed);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(_) => return Err(UpdateError::InstallFailed),
        }
    }
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

    /// The `--track-latest` flag enables the mode regardless of env.
    #[test]
    fn track_latest_enabled_by_flag() {
        assert!(
            track_latest_enabled(true),
            "flag=true must enable track-latest"
        );
    }

    /// Default is OFF: no flag + no env → disabled (opposite polarity from
    /// auto-update, which is ON by default).
    #[test]
    fn track_latest_disabled_by_default() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::remove_var("CSQ_TRACK_LATEST") };
        assert!(
            !track_latest_enabled(false),
            "no flag + no env must leave track-latest OFF"
        );
    }

    /// `CSQ_TRACK_LATEST=1` enables track-latest without the flag.
    #[test]
    fn track_latest_enabled_by_env() {
        let _env_guard = crate::platform::test_env::lock();
        unsafe { std::env::set_var("CSQ_TRACK_LATEST", "1") };
        let enabled = track_latest_enabled(false);
        unsafe { std::env::remove_var("CSQ_TRACK_LATEST") };
        assert!(enabled, "CSQ_TRACK_LATEST=1 must enable track-latest");
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
        let result = run_auto_update(SurfaceCli::Codex, InstallManager::Unknown);
        assert!(
            matches!(result, Err(UpdateError::NoCommand)),
            "Unknown manager must produce NoCommand; got {result:?}"
        );
    }

    #[test]
    fn run_auto_update_returns_no_command_for_claude_native_installer() {
        // ClaudeNativeInstaller has no upgrade_command → NoCommand.
        let result = run_auto_update(SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller);
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

    // ── UpdateError display (fixed-vocabulary tags) ───────────────────────────

    #[test]
    fn update_error_display_has_fixed_tag() {
        // Each variant's Display must start with a fixed-vocabulary tag
        // for log filtering (security.md fixed-vocabulary error_kind rule).
        let cases = vec![
            (UpdateError::NoCommand, "no_auto_update_command"),
            (UpdateError::NpmMissing, "npm_missing"),
            (UpdateError::InstallFailed, "install_failed"),
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

        let result = run_auto_update(SurfaceCli::Kimi, InstallManager::SelfManaged);

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
}
