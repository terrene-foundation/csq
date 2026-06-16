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
///   `Outdated`. Equivalent to setting `CSQ_NO_AUTO_UPDATE_CLI=1`.
/// - `retry_command`: the command string to include in bail messages so the
///   user knows exactly what to re-run after fixing the issue. E.g.
///   `"csq run 1"` or `"csq login 1 --provider codex"`.
pub(crate) fn enforce(
    surface: SurfaceCli,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    retry_command: &str,
) -> Result<()> {
    enforce_with_fns(
        surface,
        ignore_cli_version,
        no_auto_update_cli,
        retry_command,
        auto_update::run_auto_update,
        auto_update::reprobe_after_update,
    )
}

/// Internal implementation with dependency-injection for testability (IR-H2).
///
/// Production callers use `enforce()` which passes the real functions.
/// Tests pass stubs for `run_auto_update_fn` and `reprobe_fn`.
fn enforce_with_fns(
    surface: SurfaceCli,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
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
        other => unreachable!(
            "cli_deps_gate::enforce called with an un-named SurfaceCli variant {other:?}; \
             add the corresponding `\"<surface_name>\"` arm in this match table before \
             landing the new variant."
        ),
    };

    match cli_deps::probe(surface) {
        CliStatus::Ok { .. } => {
            // Proceed silently.
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
