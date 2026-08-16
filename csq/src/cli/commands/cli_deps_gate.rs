//! Shared pre-flight gate for CLI-deps version checks.
//!
//! This module is the single authoritative implementation of the disposition
//! table from spec/13 §3 for both `csq login` and `csq run`. Extracting
//! from both callers into one place ensures:
//!
//! 1. **H3/H4 (R1 redteam)**: every `bail!` path runs `error::redact_tokens`
//!    on user-controlled strings before they reach stderr, preventing token
//!    leakage through error messages that include raw CLI output or path strings.
//!
//! 2. **Code deduplication**: the two copies of `pre_flight_check` in
//!    `login.rs` and `run.rs` were byte-for-byte identical except for the
//!    `retry_command` string in the bail messages. A single function with
//!    a `retry_command` parameter eliminates the drift risk.
//!
//! ## Disposition table (spec/13 §3)
//!
//! | Variant               | Default (auto-update ON)       | `--no-auto-update-cli`         | `--ignore-cli-version` |
//! | --------------------- | ------------------------------ | ------------------------------ | ---------------------- |
//! | `Ok`                  | proceed                        | proceed                        | proceed                |
//! | `Outdated`            | attempt update → reprobe       | BAIL                           | WARN + proceed         |
//! | `UnrecognizedVersion` | BAIL                           | BAIL                           | WARN + proceed         |
//! | `Missing`             | BAIL (unconditional)           | BAIL (unconditional)           | BAIL (unconditional)   |
//! | `WrongBinary`         | BAIL (unconditional)           | BAIL (unconditional)           | BAIL (unconditional)   |
//! | `ProbeTimedOut`       | WARN + proceed                 | WARN + proceed                 | WARN + proceed         |
//!
//! **M2 clarification**: `--ignore-cli-version` cannot proceed past
//! `Missing` or `WrongBinary` because there is no binary to run against.
//! The flag only downgrades version-policy bails (`Outdated`,
//! `UnrecognizedVersion`) to WARNs.
//!
//! **Auto-update note**: auto-update fires only on `Outdated`, not on
//! `UnrecognizedVersion` or `Missing`. Unrecognized versions indicate a
//! parsing anomaly (possibly WrongBinary) — running `npm install` could
//! shadow the real binary with a different one. Missing binary requires
//! a full install, not just an upgrade.

use std::path::Path;
use std::time::SystemTime;

use anyhow::{bail, Result};
use csq_core::cli_deps::{
    self, auto_update, CliStatus, InstallManager, SurfaceCli, UpdateError, WrongBinaryReason,
};
use csq_core::error;

/// Enforce the CLI-deps pre-flight gate for a given surface.
///
/// This is the shared implementation used by both `csq login` (via
/// `handle_codex` / `handle_gemini_oauth`) and `csq run` (via `handle`).
///
/// # Parameters
///
/// - `surface`: which CLI binary to probe (`Claude`, `Codex`, or `Gemini`).
/// - `ignore_cli_version`: if `true`, downgrades `Outdated` / `UnrecognizedVersion`
///   bails to WARNs. Has NO effect on `Missing` or `WrongBinary`.
/// - `no_auto_update_cli`: if `true`, disables the auto-update branch for
///   `Outdated`. Equivalent to setting `CSQ_NO_AUTO_UPDATE_CLI=1`. Also acts
///   as the master kill-switch that suppresses `track_latest` (see §3.2).
/// - `track_latest`: if `true` (and not suppressed by `no_auto_update_cli`),
///   attempt a best-effort latest-within-range upgrade on an `Ok` probe
///   (throttled, non-fatal — spec/13 §3.2).
/// - `base_dir`: the csq base dir (`~/.claude/accounts`), used for the
///   per-CLI track-latest throttle stamp + advisory lock.
/// - `retry_command`: the command string to include in bail messages so the
///   user knows exactly what to re-run after fixing the issue. E.g.
///   `"csq run 1"` or `"csq login 1 --provider codex"`.
pub(crate) fn enforce(
    surface: SurfaceCli,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    base_dir: &Path,
    retry_command: &str,
) -> Result<()> {
    enforce_with_fns(
        surface,
        ignore_cli_version,
        no_auto_update_cli,
        track_latest,
        base_dir,
        retry_command,
        auto_update::run_auto_update,
        auto_update::reprobe_after_update,
    )
}

/// Internal implementation with dependency-injection for testability (IR-H2).
///
/// Production callers use `enforce()` which passes the real functions.
/// Tests pass stubs for `run_auto_update_fn` and `reprobe_fn`.
#[allow(clippy::too_many_arguments)]
fn enforce_with_fns(
    surface: SurfaceCli,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    base_dir: &Path,
    retry_command: &str,
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager) -> Result<(), UpdateError>,
    reprobe_fn: impl Fn(SurfaceCli) -> CliStatus,
) -> Result<()> {
    // SurfaceCli is `#[non_exhaustive]` per spec/13 §2 so the wildcard
    // arm is compiler-required, but a literal "unknown" would produce
    // nonsense bail messages ("unknown-cli is not installed. Run `csq
    // cli install unknown`"). Per M2 R2 N1: panic loudly so a future
    // SurfaceCli variant addition forces the maintainer to update this
    // table BEFORE landing the variant.
    let surface_name = match surface {
        SurfaceCli::Codex => "codex",
        SurfaceCli::Gemini => "gemini",
        SurfaceCli::Claude => "claude",
        SurfaceCli::Kimi => "kimi",
        SurfaceCli::Grok => "grok",
        other => unreachable!(
            "cli_deps_gate::enforce called with an un-named SurfaceCli variant {other:?}; \
             add the corresponding `\"<surface_name>\"` arm in this match table before \
             landing the new variant."
        ),
    };

    match cli_deps::probe(surface) {
        CliStatus::Ok { manager, .. } => {
            // Floor is satisfied — proceed silently UNLESS track-latest is
            // enabled, in which case attempt a best-effort upgrade to the
            // latest release within the supported major (throttled, non-fatal).
            //
            // MED-1: `--no-auto-update-cli` / `CSQ_NO_AUTO_UPDATE_CLI=1` is a
            // MASTER "do not automatically mutate my CLIs" switch — it must
            // suppress track-latest too, not just the Outdated floor-update.
            // A "no auto update" flag that still fires an npm install is a
            // footgun. `auto_update_enabled` returns false for either the flag
            // or the env opt-out, so it is the correct superset gate.
            if auto_update::auto_update_enabled(no_auto_update_cli)
                && auto_update::track_latest_enabled(track_latest)
            {
                maybe_track_latest(
                    surface,
                    surface_name,
                    manager,
                    base_dir,
                    &run_auto_update_fn,
                    &reprobe_fn,
                );
            }
        }

        CliStatus::Outdated {
            version,
            min_required,
            manager,
            ..
        } if !ignore_cli_version => {
            // DA-M1: dispatch to helper to keep this arm readable.
            return handle_outdated(
                surface,
                surface_name,
                &version,
                &min_required,
                manager,
                no_auto_update_cli,
                retry_command,
                run_auto_update_fn,
                reprobe_fn,
            );
        }

        CliStatus::UnrecognizedVersion {
            raw_output, path, ..
        } if !ignore_cli_version => {
            // H3 (R1 redteam): chain redact_tokens on top of sanitize_for_display
            // so any token-like strings in CLI version output are suppressed.
            let sanitized = error::redact_tokens(&cli_deps::sanitize_for_display(&raw_output));
            let path_str = error::redact_tokens(&cli_deps::sanitize_for_display(
                &cli_deps::sanitize::redact_path(&path),
            ));
            bail!(
                "Cannot determine {surface_name}-cli version (got: {sanitized}, path: {path_str}). \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }

        CliStatus::Outdated {
            version,
            min_required,
            ..
        } => {
            // ignore_cli_version is true: downgrade BAIL → WARN and proceed.
            // Emit WARN on every honor per spec/13 §3.1 (R2-N3).
            eprintln!(
                "⚠ {surface_name}-cli {version} below minimum {min_required}; \
                 --ignore-cli-version honored"
            );
        }

        CliStatus::UnrecognizedVersion { .. } => {
            // ignore_cli_version is true: downgrade BAIL → WARN and proceed.
            eprintln!("⚠ {surface_name}-cli version unrecognized; --ignore-cli-version honored");
        }

        CliStatus::Missing => {
            // Unconditional bail — flag has no effect; nothing to proceed against.
            // M2 clarification: --ignore-cli-version cannot proceed past Missing
            // (there is no binary to run against).
            bail!(
                "{surface_name}-cli is not installed. \
                 Run `csq cli install {surface_name}`, \
                 then retry `{retry_command}`.{}",
                if ignore_cli_version {
                    " (--ignore-cli-version cannot proceed past Missing: \
                      there is no binary to run against)"
                } else {
                    ""
                }
            );
        }

        CliStatus::WrongBinary {
            raw_version_output,
            path,
            reason,
        } => {
            // Unconditional bail — flag has no effect; nothing to proceed against.
            // M2 clarification: --ignore-cli-version cannot proceed past WrongBinary
            // (the binary present is the wrong one).
            //
            // H3 (R1 redteam): chain redact_tokens on sanitize_for_display to
            // suppress any token-like strings that might appear in raw CLI output.
            let sanitized_output =
                error::redact_tokens(&cli_deps::sanitize_for_display(&raw_version_output));
            let path_str = error::redact_tokens(&cli_deps::sanitize_for_display(
                &cli_deps::sanitize::redact_path(&path),
            ));
            let flag_note = if ignore_cli_version {
                " (--ignore-cli-version cannot proceed past WrongBinary: \
                  there is no correct binary to run against)"
            } else {
                ""
            };
            match reason {
                WrongBinaryReason::InstallPathBlocklisted { .. } => bail!(
                    "`{surface_name}` on PATH is not the supported {surface_name}-cli \
                     (saw: {sanitized_output}, path: {path_str}). \
                     Fix — copy and run: `brew uninstall {surface_name}` (removes the \
                     homebrew-formula {surface_name}; the npm-installed {surface_name} \
                     csq supports stays untouched).{flag_note}"
                ),
                WrongBinaryReason::PrefixMismatch { expected, .. } => bail!(
                    "`{surface_name}` on PATH did not emit a `{expected}` prefix on \
                     --version (saw: {sanitized_output}, path: {path_str}). \
                     Run `which -a {surface_name}` to inspect PATH-shadowing.{flag_note}"
                ),
                WrongBinaryReason::ComponentTooLarge { segment } => bail!(
                    "`{surface_name} --version` returned a malformed semver segment \
                     `{segment}` (path: {path_str}). \
                     Re-install your {surface_name}-cli via your usual package manager.{flag_note}"
                ),
            }
        }

        CliStatus::ProbeTimedOut { path, elapsed_ms } => {
            // Proceed with warning — don't punish the user for a slow --version (R1-C1).
            let path_str = error::redact_tokens(&cli_deps::sanitize_for_display(
                &cli_deps::sanitize::redact_path(&path),
            ));
            eprintln!(
                "⚠ {surface_name} --version probe timed out after {elapsed_ms}ms at \
                 {path_str}; proceeding without version check"
            );
        }
    }

    Ok(())
}

/// Best-effort track-latest upgrade for an already-`Ok` (floor-passing)
/// binary. Non-fatal by design: we already hold a working binary, so ANY
/// failure (offline, npm error, no upgrade path) proceeds with the installed
/// version rather than bailing. Throttled to at most once per CLI per
/// `TRACK_LATEST_THROTTLE` via a per-CLI stamp under `base_dir`.
///
/// The stamp is recorded BEFORE the attempt so a persistent failure (e.g.
/// the operator is offline) does not re-hammer the npm registry on every
/// launch inside the throttle window.
fn maybe_track_latest(
    surface: SurfaceCli,
    surface_name: &str,
    manager: InstallManager,
    base_dir: &Path,
    run_auto_update_fn: &impl Fn(SurfaceCli, InstallManager) -> Result<(), UpdateError>,
    reprobe_fn: &impl Fn(SurfaceCli) -> CliStatus,
) {
    let now = SystemTime::now();
    if !auto_update::track_latest_due(base_dir, surface, now) {
        return;
    }

    // LOW-2: skip silently for managers with no upgrade path (ClaudeNativeInstaller
    // / Unknown) — otherwise the "checking…" line below prints with no resolution,
    // reading like a hang, once per throttle window forever.
    if !auto_update::has_upgrade_command(surface, manager) {
        return;
    }

    // MED-2: serialize concurrent track-latest attempts per CLI with a
    // non-blocking advisory lock, so two simultaneous `csq run` invocations
    // don't both fire `npm install -g` on the same global prefix (concurrent
    // global installs corrupt bin symlinks — the exact binary about to launch).
    // If another process holds the lock it is already handling this CLI, so we
    // skip. A lock-open failure (e.g. unwritable base_dir) also skips — which
    // additionally means an unwritable dir degrades track-latest to OFF rather
    // than firing npm on every launch (LOW-3), since the stamp can't persist.
    let lock_path = base_dir.join(format!(".track-latest-{surface_name}.lock"));
    let _guard = match csq_core::platform::lock::try_lock_file(&lock_path) {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => return,
    };

    // Double-checked due under the lock: a process that held the lock just
    // before us may have already recorded a fresh attempt.
    if !auto_update::track_latest_due(base_dir, surface, now) {
        return;
    }
    // Record BEFORE the attempt so a persistent failure (offline) does not
    // re-hammer the registry on every launch inside the throttle window.
    auto_update::record_track_latest_attempt(base_dir, surface, now);

    eprintln!(
        "csq: track-latest — checking for a newer {surface_name}-cli \
         (latest within the supported range)..."
    );
    match run_auto_update_fn(surface, manager) {
        Ok(()) => {
            // npm/native upgrade exited 0. Re-probe to report the resolved
            // version (an already-latest install is a no-op that also exits
            // 0, so this line is accurate whether or not anything changed).
            match reprobe_fn(surface) {
                CliStatus::Ok { version, .. } => eprintln!(
                    "csq: {surface_name}-cli is at {version} (latest within the supported range)"
                ),
                // LOW-1: the upgrade left the binary in a non-Ok state (partial
                // install, or the resolved build probes as WrongBinary). We still
                // proceed (non-fatal), but WARN so the operator can connect a
                // misbehaving CLI to the track-latest upgrade rather than being
                // silently launched into a broken binary.
                _ => eprintln!(
                    "csq: track-latest upgrade left {surface_name}-cli in an unexpected state; \
                     run `csq cli upgrade {surface_name}` if it misbehaves"
                ),
            }
        }
        // No upgrade command resolved at attempt time — e.g. a self-managed
        // binary that vanished from disk between has_upgrade_command and the
        // spawn. Silent: track-latest is opt-in convenience, not a gate.
        Err(UpdateError::NoCommand) => {}
        // Transient failure (npm missing, install error, timeout). Report
        // softly and proceed — the installed binary already passes the floor.
        Err(_) => {
            eprintln!(
                "csq: track-latest could not update {surface_name}-cli right now; \
                 continuing with the installed version"
            );
        }
    }
}

/// Handle the `Outdated` arm — attempt auto-update or bail. (DA-M1)
///
/// Extracted from `enforce_with_fns` to keep the match arm readable and to
/// provide a single, auditable decision point for the update/bail branch.
#[allow(clippy::too_many_arguments)]
fn handle_outdated(
    surface: SurfaceCli,
    surface_name: &str,
    current_version: &csq_core::cli_deps::Version,
    min_required: &csq_core::cli_deps::Version,
    manager: InstallManager,
    no_auto_update_cli: bool,
    retry_command: &str,
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager) -> Result<(), UpdateError>,
    reprobe_fn: impl Fn(SurfaceCli) -> CliStatus,
) -> Result<()> {
    if auto_update::auto_update_enabled(no_auto_update_cli) {
        return attempt_auto_update_and_proceed(
            surface,
            surface_name,
            current_version,
            min_required,
            manager,
            retry_command,
            run_auto_update_fn,
            reprobe_fn,
        );
    }

    // Auto-update disabled (flag or env var) → existing bail.
    bail!(
        "{surface_name}-cli {current_version} is below the minimum supported ({min_required}). \
         Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
         To proceed at your own risk: `{retry_command} --ignore-cli-version`."
    );
}

/// Attempt to auto-update `surface` and re-probe. Called only when
/// `auto_update_enabled()` is `true` and the probe returned `Outdated`.
///
/// Returns `Ok(())` if the update succeeded AND the re-probe confirmed
/// the version is now acceptable. Returns `Err(_)` if the update failed
/// or the re-probe still shows outdated / unexpected status — the caller
/// falls through to its bail.
///
/// All error paths emit a diagnostic to stderr before returning so the
/// operator understands what happened.
#[allow(clippy::too_many_arguments)]
fn attempt_auto_update_and_proceed(
    surface: SurfaceCli,
    surface_name: &str,
    current_version: &csq_core::cli_deps::Version,
    min_required: &csq_core::cli_deps::Version,
    manager: InstallManager,
    retry_command: &str,
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager) -> Result<(), UpdateError>,
    reprobe_fn: impl Fn(SurfaceCli) -> CliStatus,
) -> Result<()> {
    // IR-M2: use bare name for the "running upgrade..." UX line (brevity).
    let pkg_name = auto_update::display_package_name(surface, manager);
    // IR-M2: use full range-pinned spec for any operator-runnable command in error messages.
    let pkg_full = auto_update::display_full_package_spec(surface, manager);

    // ── UX: "running upgrade…" ────────────────────────────────────────────────
    eprintln!(
        "csq: {surface_name}-cli is outdated ({current_version} < {min_required}); \
         running `npm install -g {pkg_name}` to update..."
    );

    match run_auto_update_fn(surface, manager) {
        Ok(()) => {
            // Update subprocess exited 0 — re-probe to confirm version.
            let new_status = reprobe_fn(surface);
            match new_status {
                CliStatus::Ok {
                    version: new_ver, ..
                } => {
                    eprintln!("csq: updated {surface_name}-cli to {new_ver}");
                    Ok(())
                }
                CliStatus::Outdated {
                    version: still_ver,
                    min_required: still_min,
                    ..
                } => {
                    // npm reported success but version still not acceptable.
                    // Unusual — could be a PATH issue or npm cache.
                    // R4 gold-standards finding: `pkg_full` contains a space and `<` (e.g.
                    // `@openai/codex@>=0.40.0 <1.0.0`); render with single quotes so a
                    // copy-paste into a shell does not get split on whitespace nor parse
                    // the `<` as input redirection.
                    eprintln!(
                        "csq: auto-update ran but {surface_name}-cli is still outdated \
                         ({still_ver} < {still_min}). \
                         Try running `npm install -g '{pkg_full}'` manually \
                         in a new shell, or pass --no-auto-update-cli to suppress."
                    );
                    bail!(
                        "{surface_name}-cli {still_ver} is below the minimum supported \
                         ({still_min}) even after auto-update. \
                         Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
                         To proceed at your own risk: `{retry_command} --ignore-cli-version`."
                    );
                }
                _ => {
                    // Some other status (UnrecognizedVersion, WrongBinary, Missing…)
                    // — fall through to bail.
                    eprintln!(
                        "csq: auto-update ran but {surface_name}-cli returned an unexpected \
                         status. Run `csq cli upgrade {surface_name}` manually."
                    );
                    bail!(
                        "{surface_name}-cli version check failed after auto-update. \
                         Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
                         To proceed at your own risk: `{retry_command} --ignore-cli-version`."
                    );
                }
            }
        }
        Err(UpdateError::NoCommand) => {
            // No upgrade command for this (cli, manager) pair.
            // Silently fall through to the standard bail — no extra message needed
            // since the bail already tells the user to run `csq cli upgrade`.
            bail!(
                "{surface_name}-cli {current_version} is below the minimum supported \
                 ({min_required}). \
                 Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }
        Err(UpdateError::NpmMissing) => {
            // R4 gold-standards finding: shell-quote `pkg_full` (contains space + `<`).
            eprintln!(
                "csq: auto-update failed (npm not found on PATH); \
                 install npm or run `npm install -g '{pkg_full}'` manually."
            );
            bail!(
                "{surface_name}-cli {current_version} is below the minimum supported \
                 ({min_required}). \
                 Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }
        Err(UpdateError::InstallFailed) => {
            // IR-M3: drop the misleading "continuing with existing version" line —
            // we are about to bail, not continue. Show the range-pinned command.
            // R4 gold-standards finding: shell-quote `pkg_full` (contains space + `<`).
            eprintln!(
                "csq: auto-update failed (npm install error). \
                 Run `npm install -g '{pkg_full}'` manually, \
                 or pass --no-auto-update-cli to suppress."
            );
            bail!(
                "{surface_name}-cli {current_version} is below the minimum supported \
                 ({min_required}). \
                 Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::cli_deps::{CliStatus, InstallManager, SurfaceCli, UpdateError, Version};
    use std::path::PathBuf;

    fn dummy_version(major: u32) -> Version {
        Version::new(major, 0, 0)
    }

    fn ok_status(ver: u32) -> CliStatus {
        CliStatus::Ok {
            version: dummy_version(ver),
            path: PathBuf::from("/usr/local/bin/codex"),
            manager: InstallManager::NpmGlobal,
        }
    }

    fn outdated_status() -> CliStatus {
        CliStatus::Outdated {
            version: dummy_version(0),
            min_required: dummy_version(1),
            path: PathBuf::from("/usr/local/bin/codex"),
            manager: InstallManager::NpmGlobal,
        }
    }

    // ── IR-H2: six branches of attempt_auto_update_and_proceed ───────────────

    /// Branch 1: update succeeds + reprobe returns Ok → function returns Ok(()).
    #[test]
    fn update_succeeds_reprobe_ok_returns_ok() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Ok(()),
            |_| ok_status(2),
        );
        assert!(
            result.is_ok(),
            "update+reprobe-ok must return Ok; got {result:?}"
        );
    }

    /// Branch 2: update succeeds + reprobe returns Outdated → bails.
    #[test]
    fn update_succeeds_reprobe_outdated_bails() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Ok(()),
            |_| outdated_status(),
        );
        assert!(
            result.is_err(),
            "still-outdated after update must bail; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("still outdated") || msg.contains("below the minimum"),
            "bail message must indicate still-outdated; got {msg:?}"
        );
    }

    /// Branch 3: update succeeds + reprobe returns unexpected status → bails.
    #[test]
    fn update_succeeds_reprobe_unexpected_bails() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Ok(()),
            |_| CliStatus::Missing,
        );
        assert!(
            result.is_err(),
            "unexpected reprobe status must bail; got {result:?}"
        );
    }

    /// Branch 4: UpdateError::NoCommand → bails with upgrade hint.
    #[test]
    fn update_error_no_command_bails() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Err(UpdateError::NoCommand),
            |_| panic!("reprobe must not be called when update returns NoCommand"),
        );
        assert!(result.is_err(), "NoCommand must bail; got {result:?}");
    }

    /// Branch 5: UpdateError::NpmMissing → bails with npm-not-found message.
    #[test]
    fn update_error_npm_missing_bails() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Err(UpdateError::NpmMissing),
            |_| panic!("reprobe must not be called when update returns NpmMissing"),
        );
        assert!(result.is_err(), "NpmMissing must bail; got {result:?}");
    }

    /// Branch 6: UpdateError::InstallFailed → bails with full range-pinned spec (IR-M2+IR-M3).
    #[test]
    fn update_error_install_failed_bails_with_range_pinned_spec() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Err(UpdateError::InstallFailed),
            |_| panic!("reprobe must not be called when update returns InstallFailed"),
        );
        assert!(result.is_err(), "InstallFailed must bail; got {result:?}");
        // IR-M2: bail message must contain the full range-pinned spec, not just @latest.
        // Note: the range-pinned message now lives in the eprintln! (not bail message),
        // so we verify the bail itself at minimum mentions the upgrade path.
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("below the minimum") || msg.contains("csq cli upgrade"),
            "InstallFailed bail message must contain upgrade guidance; got {msg:?}"
        );
    }

    // ── IR-M3: misleading "continuing" line is absent from InstallFailed ──────

    /// Verify the InstallFailed branch does not produce a "continuing with
    /// existing version" message — we bail, we are not continuing.
    /// This is a structural test of the eprintln! text via the bail message;
    /// the eprintln itself is verified by reading the source.
    #[test]
    fn install_failed_bail_message_does_not_say_continuing() {
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            "csq run 1",
            |_, _| Err(UpdateError::InstallFailed),
            |_| unreachable!(),
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains("continuing with existing"),
            "bail message must not say 'continuing with existing version'; got {msg:?}"
        );
    }

    // ── track-latest: maybe_track_latest fires once, then throttles ───────────

    /// First call (no stamp → due) runs the upgrade fn; the immediately
    /// following call (stamp fresh → within throttle window) does NOT.
    #[test]
    fn maybe_track_latest_fires_once_then_throttles() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let base = tempfile::TempDir::new().unwrap();
        let calls = AtomicUsize::new(0);
        let run_fn = |_: SurfaceCli, _: InstallManager| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let reprobe_fn = |_: SurfaceCli| ok_status(2);

        // First: due → upgrade attempted.
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "first track-latest (no stamp) must attempt the upgrade"
        );

        // Second: stamp fresh → throttled, no attempt.
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second track-latest within the throttle window must NOT re-attempt"
        );
    }

    /// A NoCommand result (no upgrade path for the manager) is a silent no-op
    /// — maybe_track_latest never bails, and the reprobe fn is not consulted.
    #[test]
    fn maybe_track_latest_no_command_is_silent_noop() {
        let base = tempfile::TempDir::new().unwrap();
        // ClaudeNativeInstaller has no upgrade_command → the LOW-2 no-upgrade-
        // path guard exits BEFORE the run/reprobe fns; both must be uncalled and
        // the call must not panic/bail (silent no-op).
        let run_fn = |_: SurfaceCli, _: InstallManager| -> Result<(), UpdateError> {
            panic!("run_auto_update must not run for a manager with no upgrade path")
        };
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run") };
        maybe_track_latest(
            SurfaceCli::Claude,
            "claude",
            InstallManager::ClaudeNativeInstaller,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
    }

    /// MED-1: `--no-auto-update-cli` / `CSQ_NO_AUTO_UPDATE_CLI=1` is a master
    /// kill-switch — the Ok-arm gate predicate
    /// `auto_update_enabled(no_auto_update_cli) && track_latest_enabled(track_latest)`
    /// must be false when the opt-out is set, even with track-latest requested,
    /// and true when it is not set.
    #[test]
    fn track_latest_suppressed_by_no_auto_update_kill_switch() {
        let _env = csq_core::platform::test_env::lock();
        unsafe {
            std::env::remove_var("CSQ_TRACK_LATEST");
            std::env::remove_var("CSQ_NO_AUTO_UPDATE_CLI");
        }
        // Kill-switch flag set + track-latest requested → suppressed.
        assert!(
            !(auto_update::auto_update_enabled(true) && auto_update::track_latest_enabled(true)),
            "--no-auto-update-cli must suppress track-latest"
        );
        // No opt-out + track-latest requested → fires.
        assert!(
            auto_update::auto_update_enabled(false) && auto_update::track_latest_enabled(true),
            "track-latest must fire when no opt-out is set"
        );
        // R2 LOW-B: the ENV variant of the kill-switch (CSQ_NO_AUTO_UPDATE_CLI=1)
        // must also suppress track-latest, even without the CLI flag.
        unsafe { std::env::set_var("CSQ_NO_AUTO_UPDATE_CLI", "1") };
        let env_suppressed =
            !(auto_update::auto_update_enabled(false) && auto_update::track_latest_enabled(true));
        unsafe { std::env::remove_var("CSQ_NO_AUTO_UPDATE_CLI") };
        assert!(
            env_suppressed,
            "CSQ_NO_AUTO_UPDATE_CLI=1 must suppress track-latest too"
        );
    }

    /// R2 Finding 1 (coverage-regression close): `run_auto_update` returning
    /// `NoCommand` AT ATTEMPT TIME (self-managed binary vanished between the
    /// has_upgrade_command guard and the spawn) must be a silent no-op — the
    /// `Err(NoCommand)` match arm, distinct from the has_upgrade_command guard.
    #[test]
    fn maybe_track_latest_upgrade_no_command_at_attempt_time_is_silent_noop() {
        let base = tempfile::TempDir::new().unwrap();
        // NpmGlobal has an upgrade path, so the has_upgrade_command guard passes
        // and we reach the match — where run_auto_update_fn returns NoCommand.
        let run_fn = |_: SurfaceCli, _: InstallManager| Err(UpdateError::NoCommand);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on Err") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
    }

    /// R2 Finding 2 (LOW-1 coverage): an upgrade that exits 0 but leaves the
    /// binary in a non-`Ok` state emits a soft WARN and still proceeds — must
    /// not panic (non-fatal invariant).
    #[test]
    fn maybe_track_latest_reprobe_non_ok_does_not_panic() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn = |_: SurfaceCli, _: InstallManager| Ok(());
        let reprobe_fn = |_: SurfaceCli| CliStatus::Missing;
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
    }

    /// R2 Finding 3 (coverage): a transient `Err(_)` (npm error / timeout) at
    /// this call site — distinct from the Outdated-arm handler — must soft-fail
    /// and proceed without panicking.
    #[test]
    fn maybe_track_latest_install_failed_soft_fail_does_not_panic() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn = |_: SurfaceCli, _: InstallManager| Err(UpdateError::InstallFailed);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on Err") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
    }

    /// R2 Finding 4 (MED-2 direct coverage): when another party holds the
    /// per-CLI lock, `maybe_track_latest` skips WITHOUT running the upgrade —
    /// the concurrent-double-npm guard. Reliable cross-thread on a local
    /// filesystem: `lock_file`/`try_lock_file` each `open()` the path
    /// independently, so the two calls hold separate open file descriptions
    /// and their `flock`s conflict (flock(2)). (Cross-*process* coverage lives
    /// in `platform_integration.rs`; this test exercises the cross-thread path.)
    #[cfg(unix)]
    #[test]
    fn maybe_track_latest_skips_on_lock_contention() {
        let base = tempfile::TempDir::new().unwrap();
        let base_path = base.path().to_path_buf();
        let lock_path = base_path.join(".track-latest-codex.lock");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = csq_core::platform::lock::lock_file(&lock_path).unwrap();
            tx.send(()).unwrap(); // signal: lock held
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        rx.recv().unwrap(); // wait until the holder actually holds the lock
        let run_fn = |_: SurfaceCli, _: InstallManager| -> Result<(), UpdateError> {
            panic!("run_auto_update must not run while the lock is contended")
        };
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            InstallManager::NpmGlobal,
            base_path.as_path(),
            &run_fn,
            &reprobe_fn,
        );
        holder.join().unwrap();
    }

    // ── DA-M1: handle_outdated dispatches correctly ───────────────────────────

    /// When auto-update is disabled, handle_outdated bails without calling the update fn.
    #[test]
    fn handle_outdated_bails_when_auto_update_disabled() {
        // Acquire the process-wide env-mutation lock so this test serialises
        // against any parallel test that reads or writes CSQ_NO_AUTO_UPDATE_CLI
        // (rules/testing.md Rule 6; canonical pattern from auto_update.rs,
        // sanitize.rs, install_path.rs). The lock is the serialisation
        // boundary — manual save/restore is neither panic-safe nor race-free.
        let _env_guard = csq_core::platform::test_env::lock();
        // Ensure the env opt-out var is absent so auto_update_enabled() reads
        // only the CLI flag — not a leftover CI env var.
        unsafe { std::env::remove_var("CSQ_NO_AUTO_UPDATE_CLI") };

        let result = handle_outdated(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            /* no_auto_update_cli= */ true,
            "csq run 1",
            |_, _| panic!("must not call run_auto_update when disabled"),
            |_| panic!("must not call reprobe when disabled"),
        );
        assert!(
            result.is_err(),
            "handle_outdated with disabled auto-update must bail"
        );
    }

    /// When auto-update is enabled and update succeeds with Ok reprobe, returns Ok.
    #[test]
    fn handle_outdated_update_enabled_success_returns_ok() {
        // Acquire the process-wide env-mutation lock so this test serialises
        // against any parallel test that reads or writes CSQ_NO_AUTO_UPDATE_CLI
        // (rules/testing.md Rule 6; canonical pattern from auto_update.rs,
        // sanitize.rs, install_path.rs). The lock is the serialisation
        // boundary — manual save/restore is neither panic-safe nor race-free.
        let _env_guard = csq_core::platform::test_env::lock();
        // Ensure the env opt-out var is absent so auto_update_enabled() reads
        // only the CLI flag and returns true (the "enabled" branch under test).
        unsafe { std::env::remove_var("CSQ_NO_AUTO_UPDATE_CLI") };

        let result = handle_outdated(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            /* no_auto_update_cli= */ false,
            "csq run 1",
            |_, _| Ok(()),
            |_| ok_status(2),
        );
        assert!(
            result.is_ok(),
            "handle_outdated must return Ok on successful update; got {result:?}"
        );
    }
}
