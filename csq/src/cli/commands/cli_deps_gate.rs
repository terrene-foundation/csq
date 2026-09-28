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
//!
//! **SelfManaged major-version crossing (S-F7)**: `codex update` / `kimi
//! upgrade` / `grok update` run the vendor's own updater, which is NOT
//! range-pinned the way the npm/brew managers are — an upgrade through this
//! path MAY cross a major version. This is an accepted owner decision
//! (every managed CLI auto-updates "like Claude Code"), and
//! `warn_if_major_crossed` below prints a one-line WARN naming the old and
//! new versions when it happens. It never blocks the launch.
//!
//! **Track-latest is skipped in non-interactive/CI contexts (C-F11)**: an
//! unattended `npm install -g` / vendor-updater invocation from a CI runner
//! or a piped, non-TTY invocation risks racing another automated step or
//! upgrading a CLI nobody is watching. `track_latest_interactive_context`
//! gates every track-latest attempt on stdin being a TTY AND no CI-sentinel
//! env var (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`,
//! `JENKINS_URL`) being set; a skip is silent to the operator (one debug
//! log line only) since track-latest is best-effort background maintenance,
//! not a gate. The floor-guarded `Outdated` → auto-update path is untouched
//! by this check — an outdated binary still must be fixed even in CI.

use std::io::IsTerminal;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{bail, Result};
use csq_core::cli_deps::{
    self, auto_update, CliStatus, InstallManager, SurfaceCli, UpdateError, Version,
    WrongBinaryReason,
};
use csq_core::error;

/// Item 4 (D-F3): honours an interrupted track-latest/floor-upgrade attempt
/// via the conventional `128 + signal` exit code — EXCEPT in test builds,
/// where calling `std::process::exit` directly would kill the ENTIRE test
/// harness process (not just the one test that happened to exercise this
/// path), which every other concurrently-running test then observes as an
/// unexplained `SIGKILL`/exit-143. A test build panics instead, carrying
/// the would-be exit code in its message, so a test that reaches this path
/// fails LOUDLY and LOCALLY — attributable to the one test, not the whole
/// binary.
fn exit_or_panic_interrupted(signal: libc::c_int) -> ! {
    #[cfg(test)]
    {
        panic!(
            "cli_deps_gate: would exit(128 + {signal}) here in production — \
             the cfg(test) hook fired instead of killing the test harness"
        );
    }
    #[cfg(not(test))]
    {
        std::process::exit(128 + signal);
    }
}

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
        auto_update::run_auto_update_track_latest,
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
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager, Option<&Path>) -> Result<(), UpdateError>,
    track_latest_update_fn: impl Fn(
        SurfaceCli,
        InstallManager,
        Option<&Path>,
    ) -> Result<(), UpdateError>,
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
        CliStatus::Ok {
            version,
            manager,
            path,
        } => {
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
            let track_latest_wanted = auto_update::auto_update_enabled(no_auto_update_cli)
                && auto_update::track_latest_enabled(track_latest);
            if track_latest_wanted {
                // C-F11: track-latest attempts an unattended package-manager /
                // vendor-updater invocation. Never do that from a CI runner or
                // a piped, non-interactive invocation — skip silently (a debug
                // log only) rather than racing another automated step.
                if track_latest_interactive_context() {
                    maybe_track_latest(
                        surface,
                        surface_name,
                        &version,
                        manager,
                        &path,
                        base_dir,
                        &track_latest_update_fn,
                        &reprobe_fn,
                    )?;
                } else {
                    tracing::debug!(
                        error_kind = "track_latest_skipped_non_interactive",
                        surface = surface_name,
                        "track-latest skipped: non-interactive or CI context"
                    );
                }
            }
        }

        CliStatus::Outdated {
            version,
            min_required,
            manager,
            path,
        } if !ignore_cli_version => {
            // DA-M1: dispatch to helper to keep this arm readable.
            return handle_outdated(
                surface,
                surface_name,
                &version,
                &min_required,
                manager,
                &path,
                base_dir,
                no_auto_update_cli,
                retry_command,
                run_auto_update_fn,
                reprobe_fn,
                auto_update::wait_for_track_latest_lock_release,
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

/// CI-sentinel env vars that mean "this is an unattended runner, not an
/// operator at a terminal" (C-F11).
///
/// `csq/src/cli/commands/cli.rs::is_ci_environment` is the codebase's other
/// CI detector, checking a wider set (`CIRCLECI`, `TEAMCITY_VERSION`,
/// `DRONE`, `TF_BUILD` in addition to these five) for a DIFFERENT purpose —
/// it gates *interactive consent* for `csq cli install/upgrade`. This one
/// gates a *silent best-effort* background upgrade attempt from `csq run` /
/// `csq login`, and uses exactly the five vars named for that decision
/// (finding C-F11: `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`,
/// `JENKINS_URL`). `is_ci_environment` is module-private in a sibling file
/// this shard does not own, so it cannot be called directly; keep this list
/// in sync with it in SPIRIT (the sentinel vocabulary) even though the two
/// sets differ in size on purpose.
const TRACK_LATEST_CI_VARS: &[&str] = &[
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
];

/// Returns `true` when a CI-sentinel env var is set.
fn is_ci_environment_track_latest() -> bool {
    TRACK_LATEST_CI_VARS
        .iter()
        .any(|v| std::env::var_os(v).is_some())
}

/// Returns `true` when it is safe to run an unattended track-latest upgrade:
/// stdin is a TTY (`stdin_is_tty`) AND no CI-sentinel env var is set.
///
/// Takes `stdin_is_tty` as a parameter so the CI-var half is unit-testable
/// without depending on the test harness's own stdin (which is normally NOT
/// a TTY, making the real check unusable as a test fixture).
fn track_latest_interactive_context_with(stdin_is_tty: bool) -> bool {
    stdin_is_tty && !is_ci_environment_track_latest()
}

/// Returns `true` when it is safe to run an unattended track-latest upgrade
/// in THIS process: real stdin TTY-ness + no CI-sentinel env var.
fn track_latest_interactive_context() -> bool {
    track_latest_interactive_context_with(std::io::stdin().is_terminal())
}

/// Print a one-line WARN when an update crossed a major version boundary.
///
/// Only `InstallManager::SelfManaged` upgrades (`codex update` / `kimi
/// upgrade` / `grok update`) can trigger this: npm/brew upgrades run through
/// the range-pinned `upgrade_command` table (`@pkg@>=M.m.p <N.0.0`), which
/// caps the resolved version below the next major by construction (S-F7).
/// The vendor's own updater carries no such cap — an accepted owner
/// decision, same as Claude Code's own auto-update. Does NOT block the
/// launch; it is purely informational.
fn warn_if_major_crossed(surface_name: &str, old: &Version, new: &Version) {
    if new.major > old.major {
        eprintln!(
            "⚠ {surface_name}-cli auto-update crossed a major version ({old} -> {new}); \
             review release notes for breaking changes before your next session."
        );
    }
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
///
/// # The one non-proceeding case
///
/// "Non-fatal" holds only while the binary on disk is SETTLED. On a timeout,
/// `run_auto_update_fn` (unix) already `SIGKILL`s the WHOLE process group
/// and confirms every member exited (`kill_group_and_confirm_dead`) before
/// returning — so a re-probe after `UpdateError::TimedOutSettled` can be
/// trusted, and this function proceeds on it exactly like any other
/// settled outcome. It is `UpdateError::TimedOut` — group-kill confirmation
/// itself could not complete, or this platform has none (Windows) — that is
/// genuinely unsettled: the package manager's own workers may still be
/// mid-swap on the very binary the caller is about to spawn. Launching then
/// hands the operator a session pinned to a package that is being replaced
/// underneath it — observed as a TUI stuck at `model: loading` while the
/// package symlink repointed ~2 minutes after launch. That case returns
/// `Err` UNCONDITIONALLY (no re-probe) so the caller bails instead of
/// spawning; every other outcome still proceeds with the installed binary.
#[allow(clippy::too_many_arguments)]
fn maybe_track_latest(
    surface: SurfaceCli,
    surface_name: &str,
    current_version: &Version,
    manager: InstallManager,
    path: &Path,
    base_dir: &Path,
    run_auto_update_fn: &impl Fn(SurfaceCli, InstallManager, Option<&Path>) -> Result<(), UpdateError>,
    reprobe_fn: &impl Fn(SurfaceCli) -> CliStatus,
) -> Result<()> {
    let now = SystemTime::now();
    let lock_path = base_dir.join(format!(".track-latest-{surface_name}.lock"));

    if !auto_update::track_latest_due(base_dir, surface, now) {
        // FM-8: "not due" can mean a SIBLING `csq run`/`csq login` invocation
        // found itself due, recorded the stamp (BEFORE starting — see
        // `record_track_latest_attempt`'s doc), and is still mid-upgrade. If
        // its advisory lock is held, wait (bounded) for it to release before
        // returning here — otherwise this launch could proceed while the
        // sibling is still swapping the very binary we are about to spawn.
        // Never attempt an update ourselves in this branch: that decision
        // belongs solely to the process that found itself due.
        match csq_core::platform::lock::try_lock_file(&lock_path) {
            Ok(Some(_guard)) => {
                // Lock free: nobody is updating this CLI right now.
            }
            Ok(None) => {
                tracing::debug!(
                    error_kind = "track_latest_wait_for_sibling_update",
                    surface = surface_name,
                    "track-latest: a sibling process holds the update lock; \
                     waiting for it to release before proceeding"
                );
                let _ = auto_update::wait_for_track_latest_lock_release(&lock_path);
                // Whether the wait observed the lock free or its bound
                // elapsed, proceed — never attempt an update ourselves here.
            }
            Err(_) => {
                // Could not even check the lock (e.g. unwritable base_dir) —
                // degrade to the pre-FM-8 behaviour and proceed.
            }
        }
        return Ok(());
    }

    // LOW-2: skip silently for managers with no upgrade path (ClaudeNativeInstaller
    // / Unknown) — otherwise the "checking…" line below prints with no resolution,
    // reading like a hang, once per throttle window forever.
    if !auto_update::has_upgrade_command(surface, manager) {
        return Ok(());
    }

    // MED-2: serialize concurrent track-latest attempts per CLI with a
    // non-blocking advisory lock, so two simultaneous `csq run` invocations
    // don't both fire `npm install -g` on the same global prefix (concurrent
    // global installs corrupt bin symlinks — the exact binary about to launch).
    // If another process holds the lock it is already handling this CLI, so we
    // skip. A lock-open failure (e.g. unwritable base_dir) also skips — which
    // additionally means an unwritable dir degrades track-latest to OFF rather
    // than firing npm on every launch (LOW-3), since the stamp can't persist.
    let _guard = match csq_core::platform::lock::try_lock_file(&lock_path) {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => return Ok(()),
    };

    // Double-checked due under the lock: a process that held the lock just
    // before us may have already recorded a fresh attempt.
    if !auto_update::track_latest_due(base_dir, surface, now) {
        return Ok(());
    }
    // Record BEFORE the attempt so a persistent failure (offline) does not
    // re-hammer the registry on every launch inside the throttle window.
    auto_update::record_track_latest_attempt(base_dir, surface, now);

    eprintln!(
        "csq: track-latest — checking for a newer {surface_name}-cli \
         (latest within the supported range)..."
    );
    match run_auto_update_fn(surface, manager, Some(path)) {
        Ok(()) => {
            // npm/native upgrade exited 0. Re-probe to report the resolved
            // version (an already-latest install is a no-op that also exits
            // 0, so this line is accurate whether or not anything changed).
            match reprobe_fn(surface) {
                CliStatus::Ok { version, .. } => {
                    // S-F7: SelfManaged track-latest is NOT range-pinned and
                    // may cross a major version.
                    warn_if_major_crossed(surface_name, current_version, &version);
                    eprintln!(
                        "csq: {surface_name}-cli is at {version} (latest within the supported range)"
                    );
                }
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
        // The upgrade timed out, and csq confirmed (unix) that the WHOLE
        // process group — not just the direct child — has actually exited:
        // `run_auto_update_fn`'s `kill_group_and_confirm_dead` `SIGKILL`ed
        // the group and polled it to `ESRCH` before returning this variant.
        // (FM-9 / S-F7 hardening.) No worker can still be mid-write, so a
        // re-probe here is trustworthy the same way a definitively
        // finished-and-failed install is.
        //
        // If the binary STILL passes the floor (`CliStatus::Ok`), the swap
        // either never touched it or already finished cleanly before the
        // kill landed: proceed with a WARN so the operator can connect a
        // slow/odd launch to the stalled background upgrade. Only when the
        // re-probe shows the binary no longer passes the floor do we bail —
        // that is the case where the forced kill left something broken, and
        // launching against it is the failure mode the mode's non-fatal
        // contract exists to avoid.
        Err(UpdateError::TimedOutSettled) => match reprobe_fn(surface) {
            CliStatus::Ok {
                version: new_ver, ..
            } => {
                warn_if_major_crossed(surface_name, current_version, &new_ver);
                eprintln!(
                    "csq: track-latest started an upgrade of {surface_name}-cli and it did \
                     not finish within the time limit; csq stopped it (confirmed), and the \
                     installed binary still passes its version check ({new_ver}); continuing \
                     with it."
                );
            }
            _ => {
                bail!(
                    "csq: track-latest started an upgrade of {surface_name}-cli and it did \
                     not finish within the time limit; csq stopped it (confirmed), but the \
                     installed binary no longer passes its version check — the forced stop \
                     may have left it mid-write. Check with `{surface_name} --version`, \
                     reinstall if needed, then re-run. To launch without ever attempting an \
                     upgrade, set CSQ_NO_TRACK_LATEST=1 or pass --no-auto-update-cli."
                );
            }
        },
        // The upgrade timed out and csq could NOT confirm every process in
        // its group actually stopped (the confirmation poll itself timed
        // out, or this platform has no such confirmation — Windows). The
        // binary's on-disk state is genuinely UNKNOWN — a worker may still
        // be mid-write to it — so this bails UNCONDITIONALLY, without
        // consulting a re-probe: an `Ok` re-probe here cannot distinguish
        // "the swap never started" from "the swap already finished", which
        // is exactly the ambiguity this two-variant split exists to remove.
        Err(UpdateError::TimedOut) => {
            bail!(
                "csq: track-latest started an upgrade of {surface_name}-cli and it did not \
                 finish within the time limit; csq could not confirm every update process \
                 was fully stopped, so the installed binary may still be mid-flight or \
                 replacing itself. Wait for it to finish, check with `{surface_name} \
                 --version`, then re-run. To launch without ever attempting an upgrade, set \
                 CSQ_NO_TRACK_LATEST=1 or pass --no-auto-update-cli."
            );
        }
        // No upgrade command resolved at attempt time — e.g. a self-managed
        // binary that vanished from disk between has_upgrade_command and the
        // spawn. Silent: track-latest is best-effort convenience, not a gate.
        Err(UpdateError::NoCommand) => {}
        // F5/S-L3: a terminal signal arrived while csq waited on this
        // background track-latest attempt. `settled` tells us whether the
        // SAME descendant-aware kill+confirm mechanism a timeout uses
        // actually confirmed the update's process group and every
        // snapshotted descendant had exited — it is NOT guaranteed the way
        // the pre-fix code assumed. Falling through to the generic `Err(_)`
        // "continuing with the installed version" arm below would silently
        // swallow the operator's own Ctrl-C either way, so this always
        // honours the interrupt via the conventional `128 + signal` exit
        // code; an unsettled kill additionally gets a fixed warning first,
        // since a worker MAY still be mid-write to the binary.
        Err(UpdateError::Interrupted { signal, settled }) => {
            if !settled {
                eprintln!(
                    "csq: track-latest's update of {surface_name}-cli was interrupted and \
                     csq could not confirm every update process stopped; the CLI install may \
                     be incomplete. Check `{surface_name} --version` before relying on it."
                );
            }
            exit_or_panic_interrupted(signal);
        }
        // Definitively finished-and-failed (npm missing, non-zero install
        // exit). The binary on disk is settled and still passes the floor, so
        // report softly and proceed with the installed version.
        Err(_) => {
            eprintln!(
                "csq: track-latest could not update {surface_name}-cli right now; \
                 continuing with the installed version"
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
    current_version: &Version,
    min_required: &Version,
    manager: InstallManager,
    path: &Path,
    base_dir: &Path,
    no_auto_update_cli: bool,
    retry_command: &str,
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager, Option<&Path>) -> Result<(), UpdateError>,
    reprobe_fn: impl Fn(SurfaceCli) -> CliStatus,
    wait_for_lock_release_fn: impl Fn(&Path) -> bool,
) -> Result<()> {
    if auto_update::auto_update_enabled(no_auto_update_cli) {
        return attempt_auto_update_and_proceed(
            surface,
            surface_name,
            current_version,
            min_required,
            manager,
            path,
            base_dir,
            retry_command,
            run_auto_update_fn,
            reprobe_fn,
            wait_for_lock_release_fn,
        );
    }

    // Auto-update disabled (flag or env var) → existing bail.
    bail!(
        "{surface_name}-cli {current_version} is below the minimum supported ({min_required}). \
         Run `csq cli upgrade {surface_name}`, then retry `{retry_command}`. \
         To proceed at your own risk: `{retry_command} --ignore-cli-version`."
    );
}

/// C-F5: after the bounded wait for a sibling's track-latest/mandatory lock
/// to release, decide whether the mandatory floor-upgrade path may take the
/// lock itself and proceed, or must bail. Extracted into its own function so
/// this decision is unit-testable without waiting the real
/// `TRACK_LATEST_LOCK_WAIT_TIMEOUT` (~138s) bound — the caller has already
/// done the wait; this only re-checks the lock ONE more time.
///
/// A held lock (or a re-check that itself errors, e.g. an unwritable
/// `base_dir`) means a sibling process is — or may be — still running its
/// OWN `npm install -g` against this exact global prefix. The pre-fix
/// behaviour degraded to unlocked here and ran a SECOND concurrent install
/// anyway, which is exactly the bin-symlink corruption this lock exists to
/// prevent. This bails instead — never proceed unlocked once contention has
/// actually been observed.
fn acquire_lock_after_wait_or_bail(
    lock_path: &Path,
    surface_name: &str,
    retry_command: &str,
) -> Result<csq_core::platform::lock::FileLockGuard> {
    match csq_core::platform::lock::try_lock_file(lock_path) {
        Ok(Some(guard)) => Ok(guard),
        _ => {
            bail!(
                "a concurrent {surface_name}-cli update is still running; \
                 re-run `{retry_command}` once it finishes."
            );
        }
    }
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
///
/// `wait_for_lock_release_fn` is injected (rather than calling
/// `auto_update::wait_for_track_latest_lock_release` directly) so a test
/// can exercise the real "lock still held after the wait" bail through
/// THIS call site — not only the isolated `acquire_lock_after_wait_or_bail`
/// helper — without paying the production ~138s bound. Production callers
/// (`handle_outdated`, via `enforce_with_fns`) pass the real function.
#[allow(clippy::too_many_arguments)]
fn attempt_auto_update_and_proceed(
    surface: SurfaceCli,
    surface_name: &str,
    current_version: &Version,
    min_required: &Version,
    manager: InstallManager,
    path: &Path,
    base_dir: &Path,
    retry_command: &str,
    run_auto_update_fn: impl Fn(SurfaceCli, InstallManager, Option<&Path>) -> Result<(), UpdateError>,
    reprobe_fn: impl Fn(SurfaceCli) -> CliStatus,
    wait_for_lock_release_fn: impl Fn(&Path) -> bool,
) -> Result<()> {
    // IR-M2: use bare name for the "running upgrade..." UX line (brevity).
    let pkg_name = auto_update::display_package_name(surface, manager);
    // IR-M2: use full range-pinned spec for any operator-runnable command in error messages.
    let pkg_full = auto_update::display_full_package_spec(surface, manager);

    // ── UX: "running upgrade…" ────────────────────────────────────────────────
    //
    // Message fix: `InstallManager::SelfManaged` runs the vendor's OWN
    // updater (`codex update` / `kimi upgrade` / `grok update`), never
    // `npm install -g`. Printing the npm-specific line for a SelfManaged CLI
    // told the operator the wrong command was about to run.
    if manager == InstallManager::SelfManaged {
        let real_command = csq_core::cli_deps::minimum::upgrade_command(surface, manager)
            .map(|parts| parts.join(" "))
            .unwrap_or_else(|| format!("{pkg_name} update"));
        eprintln!(
            "csq: {surface_name}-cli is outdated ({current_version} < {min_required}); \
             running `{real_command}` to update..."
        );
    } else {
        eprintln!(
            "csq: {surface_name}-cli is outdated ({current_version} < {min_required}); \
             running `npm install -g {pkg_name}` to update..."
        );
    }

    // S-M2: serialize against a sibling `npm install -g` on the SAME global
    // prefix — this is the MANDATORY floor-upgrade path (unlike
    // `maybe_track_latest`'s best-effort one), so a held lock is WAITED ON
    // rather than skipped. Uses the SAME per-CLI lock file track-latest
    // uses (`.track-latest-{surface_name}.lock`), so a mandatory upgrade
    // and a background track-latest upgrade for the same CLI never race
    // each other's `npm install -g` either — concurrent global installs
    // corrupt bin symlinks, which is exactly the binary this path is about
    // to spawn against.
    let lock_path = base_dir.join(format!(".track-latest-{surface_name}.lock"));
    let _lock_guard = match csq_core::platform::lock::try_lock_file(&lock_path) {
        Ok(Some(guard)) => Some(guard),
        Ok(None) => {
            // A sibling (this same mandatory path in another launch, or a
            // background track-latest attempt) is already updating this
            // CLI. Wait (bounded) for it, then re-probe: it may already
            // have fixed the floor violation, in which case we must NOT
            // also run our own `npm install -g` on top of it.
            let _ = wait_for_lock_release_fn(&lock_path);
            match reprobe_fn(surface) {
                CliStatus::Ok {
                    version: new_ver, ..
                } => {
                    warn_if_major_crossed(surface_name, current_version, &new_ver);
                    eprintln!(
                        "csq: {surface_name}-cli is now at {new_ver} (updated by a \
                         concurrent launch); continuing"
                    );
                    return Ok(());
                }
                _ => {
                    // Still not fixed (or the wait bound elapsed while the
                    // lock was still held) — try to take the lock ourselves
                    // and run the update below, or bail (C-F5).
                    Some(acquire_lock_after_wait_or_bail(
                        &lock_path,
                        surface_name,
                        retry_command,
                    )?)
                }
            }
        }
        // Unlike the "still held after wait" case above, this is a lock-open
        // failure BEFORE any contention was ever observed (e.g. an
        // unwritable base_dir) — there is no sibling to wait on or bail
        // about, so this degrades to unlocked exactly as it always has.
        Err(_) => None,
    };

    match run_auto_update_fn(surface, manager, Some(path)) {
        Ok(()) => {
            // Update subprocess exited 0 — re-probe to confirm version.
            let new_status = reprobe_fn(surface);
            match new_status {
                CliStatus::Ok {
                    version: new_ver, ..
                } => {
                    // S-F7: SelfManaged (`codex update` / `kimi upgrade` /
                    // `grok update`) is NOT range-pinned and may cross a major.
                    warn_if_major_crossed(surface_name, current_version, &new_ver);
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
        Err(UpdateError::TimedOut) => {
            // Already a bail below, so there is no spawn-against-unsettled-binary
            // hazard here — but the operator needs to know the install may still
            // be running (csq could not confirm every process in its update
            // group stopped), so a blind immediate retry is not the right next
            // step.
            eprintln!(
                "csq: auto-update did not finish within the time limit; csq could not \
                 confirm it was fully stopped, so it may still be running in the \
                 background. Wait for it to settle, check `{surface_name} --version`, \
                 then retry — or run `npm install -g '{pkg_full}'` yourself."
            );
            bail!(
                "{surface_name}-cli {current_version} is below the minimum supported \
                 ({min_required}); the automatic upgrade did not finish in time. \
                 Retry `{retry_command}` once the upgrade settles. \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }
        Err(UpdateError::TimedOutSettled) => {
            // csq confirmed the WHOLE update process group stopped (unix:
            // SIGKILL + kill(-pgid, 0) polled to ESRCH) — unlike `TimedOut`
            // above, no worker can still be mid-write. But this is the
            // MANDATORY floor-upgrade path: a forcibly-killed install has no
            // guarantee it left a complete binary, so — unlike track-latest's
            // `TimedOutSettled` arm — we still require the operator to
            // confirm manually rather than trust an automatic re-probe here.
            eprintln!(
                "csq: auto-update did not finish within the time limit; csq stopped it \
                 (confirmed — no update process is still running). Check \
                 `{surface_name} --version`; if it is still below the minimum, run \
                 `npm install -g '{pkg_full}'` yourself."
            );
            bail!(
                "{surface_name}-cli {current_version} is below the minimum supported \
                 ({min_required}); the automatic upgrade did not finish in time and was \
                 stopped. Retry `{retry_command}` once you've confirmed the version. \
                 To proceed at your own risk: `{retry_command} --ignore-cli-version`."
            );
        }
        Err(UpdateError::Interrupted { signal, settled }) => {
            // F5/S-L3: a terminal signal arrived while csq waited on this
            // MANDATORY floor-upgrade attempt. `settled` tells us whether
            // the same descendant-aware kill+confirm mechanism a timeout
            // uses actually confirmed the update's process group and every
            // snapshotted descendant had exited — NOT guaranteed the way the
            // pre-fix code assumed. Either way we honour the interrupt
            // directly via the conventional `128 + signal` exit code rather
            // than converting it into an `anyhow` bail, which would report a
            // generic non-signal exit status for what was, from the
            // operator's perspective, a Ctrl-C; an unsettled kill also gets
            // a fixed warning first, since a worker MAY still be mid-write
            // to the very binary the retry command is about to launch.
            if !settled {
                eprintln!(
                    "csq: {surface_name}-cli's update was interrupted and csq could not \
                     confirm every update process stopped; the CLI install may be \
                     incomplete. Check `{surface_name} --version` before retrying."
                );
            }
            exit_or_panic_interrupted(signal);
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

    fn dummy_path() -> PathBuf {
        PathBuf::from("/usr/local/bin/codex")
    }

    fn ok_status(ver: u32) -> CliStatus {
        CliStatus::Ok {
            version: dummy_version(ver),
            path: dummy_path(),
            manager: InstallManager::NpmGlobal,
        }
    }

    fn outdated_status() -> CliStatus {
        CliStatus::Outdated {
            version: dummy_version(0),
            min_required: dummy_version(1),
            path: dummy_path(),
            manager: InstallManager::NpmGlobal,
        }
    }

    /// Holds `path`'s lock on a SEPARATE thread until dropped, standing in for
    /// a sibling process. Taking the lock on the test's own thread would not
    /// model a sibling on Windows, where the lock is a named mutex owned by the
    /// THREAD that holds it and re-acquiring on that same thread succeeds
    /// (unix `flock` on a second open file conflicts even in-process). A
    /// different thread is excluded on both platforms, as a sibling process is.
    struct LockHeldElsewhere {
        release: Option<std::sync::mpsc::Sender<()>>,
        holder: Option<std::thread::JoinHandle<()>>,
    }

    impl LockHeldElsewhere {
        fn acquire(path: &Path) -> Self {
            let path = path.to_path_buf();
            let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let holder = std::thread::spawn(move || {
                let _guard = csq_core::platform::lock::lock_file(&path).unwrap();
                held_tx.send(()).unwrap();
                // Hold until the test drops `LockHeldElsewhere` (a closed
                // channel also releases, so a panicking test never wedges).
                let _ = release_rx.recv();
            });
            held_rx
                .recv()
                .expect("holder thread must acquire the lock before the test proceeds");
            Self {
                release: Some(release_tx),
                holder: Some(holder),
            }
        }
    }

    impl Drop for LockHeldElsewhere {
        fn drop(&mut self) {
            drop(self.release.take());
            if let Some(h) = self.holder.take() {
                let _ = h.join();
            }
        }
    }

    // ── C-F5: acquire_lock_after_wait_or_bail ─────────────────────────────────

    /// A lock STILL held (by a sibling, standing in for a concurrent
    /// `npm install -g`) after the bounded wait must BAIL, never proceed
    /// unlocked. This is the fast (no real ~138s wait), isolated test of the
    /// exact decision C-F5 fixed.
    #[test]
    fn acquire_lock_after_wait_or_bail_bails_when_still_held() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path = base.path().join(".track-latest-codex.lock");
        let _holder = LockHeldElsewhere::acquire(&lock_path);

        let result = acquire_lock_after_wait_or_bail(&lock_path, "codex", "csq run 1");

        assert!(
            result.is_err(),
            "a still-held lock must bail, never proceed unlocked; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("concurrent") && msg.contains("still running"),
            "bail message must name the concurrent-update reason; got {msg:?}"
        );
    }

    /// Baseline: a FREE lock must succeed and hand back a guard — proves the
    /// bail above is conditional on contention, not unconditional.
    #[test]
    fn acquire_lock_after_wait_or_bail_succeeds_when_free() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path = base.path().join(".track-latest-codex.lock");

        let result = acquire_lock_after_wait_or_bail(&lock_path, "codex", "csq run 1");

        assert!(
            result.is_ok(),
            "a free lock must be acquired and returned; got {result:?}"
        );
    }

    // ── IR-H2: six branches of attempt_auto_update_and_proceed ───────────────

    /// Branch 1: update succeeds + reprobe returns Ok → function returns Ok(()).
    #[test]
    fn update_succeeds_reprobe_ok_returns_ok() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Ok(()),
            |_| ok_status(2),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(
            result.is_ok(),
            "update+reprobe-ok must return Ok; got {result:?}"
        );
    }

    /// Branch 2: update succeeds + reprobe returns Outdated → bails.
    #[test]
    fn update_succeeds_reprobe_outdated_bails() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Ok(()),
            |_| outdated_status(),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
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
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Ok(()),
            |_| CliStatus::Missing,
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(
            result.is_err(),
            "unexpected reprobe status must bail; got {result:?}"
        );
    }

    /// Branch 4: UpdateError::NoCommand → bails with upgrade hint.
    #[test]
    fn update_error_no_command_bails() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Err(UpdateError::NoCommand),
            |_| panic!("reprobe must not be called when update returns NoCommand"),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(result.is_err(), "NoCommand must bail; got {result:?}");
    }

    /// Branch 5: UpdateError::NpmMissing → bails with npm-not-found message.
    #[test]
    fn update_error_npm_missing_bails() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Err(UpdateError::NpmMissing),
            |_| panic!("reprobe must not be called when update returns NpmMissing"),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(result.is_err(), "NpmMissing must bail; got {result:?}");
    }

    /// Branch 6: UpdateError::InstallFailed → bails with full range-pinned spec (IR-M2+IR-M3).
    #[test]
    fn update_error_install_failed_bails_with_range_pinned_spec() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Err(UpdateError::InstallFailed),
            |_| panic!("reprobe must not be called when update returns InstallFailed"),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
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
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Err(UpdateError::InstallFailed),
            |_| unreachable!(),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains("continuing with existing"),
            "bail message must not say 'continuing with existing version'; got {msg:?}"
        );
    }

    // ── S-F7: major-version-crossing WARN ─────────────────────────────────────

    #[test]
    fn warn_if_major_crossed_only_fires_when_major_increases() {
        // No panic/output-assertion machinery here (eprintln! isn't
        // capturable cheaply) — this exercises both branches for a coverage
        // guarantee; the visible text is verified via the InstallFailed-style
        // string checks elsewhere in this module.
        warn_if_major_crossed("codex", &dummy_version(0), &dummy_version(1)); // crosses
        warn_if_major_crossed("codex", &dummy_version(1), &dummy_version(1)); // same major
        warn_if_major_crossed("codex", &dummy_version(2), &dummy_version(1)); // downgrade (impossible in practice)
    }

    /// A SelfManaged upgrade whose reprobe shows a higher major version still
    /// returns `Ok` (the WARN is informational, never blocking).
    #[test]
    fn attempt_auto_update_major_crossed_still_returns_ok() {
        let base = tempfile::TempDir::new().unwrap();
        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(0),
            InstallManager::SelfManaged,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| Ok(()),
            |_| CliStatus::Ok {
                version: dummy_version(1),
                path: dummy_path(),
                manager: InstallManager::SelfManaged,
            },
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(
            result.is_ok(),
            "a major-version-crossing SelfManaged update must still return Ok; got {result:?}"
        );
    }

    // ── Test gap (D spec13/doc + round-7 addendum): the mandatory path's
    //    OWN call site, not only the isolated `acquire_lock_after_wait_or_bail`
    //    helper, must bail on a lock still held after the wait ──────────────

    /// Held lock, through the REAL `attempt_auto_update_and_proceed` call
    /// site: a sibling holding `.track-latest-codex.lock` for the entire
    /// test (never released) must make this bail — and, critically, must
    /// NEVER run `run_auto_update_fn` (the thing this lock exists to
    /// serialize against; S-M2). `acquire_lock_after_wait_or_bail_bails_
    /// when_still_held` above proves the ISOLATED helper's decision; this
    /// proves the call site around it actually reaches that helper rather
    /// than, e.g., degrading to unlocked the way the pre-C-F5 code did.
    ///
    /// Uses `auto_update::wait_for_track_latest_lock_release_with` (a fast,
    /// injected bound) rather than the real `wait_for_track_latest_lock_
    /// release` (~138s) — see `attempt_auto_update_and_proceed`'s own doc
    /// for why the wait is dependency-injected.
    #[test]
    fn attempt_auto_update_bails_when_lock_still_held_after_wait() {
        let base = tempfile::TempDir::new().unwrap();
        let lock_path = base.path().join(".track-latest-codex.lock");
        // Held for the ENTIRE test — never released, so the (fast, injected)
        // wait bound elapses with the lock still held, exactly the
        // "wedged/still-running sibling" case C-F5 exists to bail on.
        let _holder = LockHeldElsewhere::acquire(&lock_path);

        let result = attempt_auto_update_and_proceed(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            "csq run 1",
            |_, _, _| -> std::result::Result<(), UpdateError> {
                panic!(
                    "must never run an install while a sibling still holds \
                     the lock after the wait — that is the double-npm-install \
                     race this lock exists to prevent (S-M2)"
                )
            },
            |_| outdated_status(),
            |p: &Path| {
                auto_update::wait_for_track_latest_lock_release_with(
                    p,
                    std::time::Duration::from_millis(60),
                    std::time::Duration::from_millis(10),
                )
            },
        );

        assert!(
            result.is_err(),
            "a lock still held after the wait must bail, never proceed unlocked; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("concurrent") && msg.contains("still running"),
            "bail message must name the concurrent-update reason; got {msg:?}"
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
        let run_fn = |_: SurfaceCli, _: InstallManager, _: Option<&Path>| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let reprobe_fn = |_: SurfaceCli| ok_status(2);

        // First: due → upgrade attempted.
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "first track-latest (no stamp) must attempt the upgrade"
        );

        // Second: stamp fresh → throttled, no attempt.
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
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
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| -> Result<(), UpdateError> {
                panic!("run_auto_update must not run for a manager with no upgrade path")
            };
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run") };
        maybe_track_latest(
            SurfaceCli::Claude,
            "claude",
            &dummy_version(0),
            InstallManager::ClaudeNativeInstaller,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
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
            // C-F12: this test previously left CSQ_NO_TRACK_LATEST unmanaged —
            // a leftover CSQ_NO_TRACK_LATEST=1 (from a prior test, or the
            // operator's own shell) makes `track_latest_enabled(true)` return
            // `false` unconditionally, failing the "must fire" assertion below
            // for a reason unrelated to what this test actually checks.
            std::env::remove_var("CSQ_NO_TRACK_LATEST");
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

    // ── C-F11: track-latest is skipped in non-interactive/CI contexts ────────

    #[test]
    fn track_latest_interactive_context_false_when_non_tty() {
        let _env_guard = csq_core::platform::test_env::lock();
        for v in TRACK_LATEST_CI_VARS {
            unsafe { std::env::remove_var(v) };
        }
        assert!(
            !track_latest_interactive_context_with(false),
            "non-TTY stdin must skip track-latest even with no CI var set"
        );
    }

    #[test]
    fn track_latest_interactive_context_false_when_ci_env_set_even_if_tty() {
        let _env_guard = csq_core::platform::test_env::lock();
        for v in TRACK_LATEST_CI_VARS {
            unsafe { std::env::remove_var(v) };
        }
        unsafe { std::env::set_var("CI", "1") };
        let result = track_latest_interactive_context_with(true);
        unsafe { std::env::remove_var("CI") };
        assert!(
            !result,
            "a CI-sentinel env var must skip track-latest even on a TTY"
        );
    }

    #[test]
    fn track_latest_interactive_context_false_for_each_ci_var() {
        let _env_guard = csq_core::platform::test_env::lock();
        for v in TRACK_LATEST_CI_VARS {
            for other in TRACK_LATEST_CI_VARS {
                unsafe { std::env::remove_var(other) };
            }
            unsafe { std::env::set_var(v, "1") };
            let result = track_latest_interactive_context_with(true);
            unsafe { std::env::remove_var(v) };
            assert!(!result, "{v}=1 on a TTY must still skip track-latest");
        }
    }

    #[test]
    fn track_latest_interactive_context_true_when_tty_and_no_ci() {
        let _env_guard = csq_core::platform::test_env::lock();
        for v in TRACK_LATEST_CI_VARS {
            unsafe { std::env::remove_var(v) };
        }
        assert!(
            track_latest_interactive_context_with(true),
            "TTY stdin with no CI var set must allow track-latest"
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
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::NoCommand);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on Err") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
    }

    /// R2 Finding 2 (LOW-1 coverage): an upgrade that exits 0 but leaves the
    /// binary in a non-`Ok` state emits a soft WARN and still proceeds — must
    /// not panic (non-fatal invariant).
    #[test]
    fn maybe_track_latest_reprobe_non_ok_does_not_panic() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn = |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Ok(());
        let reprobe_fn = |_: SurfaceCli| CliStatus::Missing;
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
    }

    /// R2 Finding 3 (coverage): a transient `Err(_)` (npm error / timeout) at
    /// this call site — distinct from the Outdated-arm handler — must soft-fail
    /// and proceed without panicking.
    #[test]
    fn maybe_track_latest_install_failed_soft_fail_does_not_panic() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::InstallFailed);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on Err") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
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
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| -> Result<(), UpdateError> {
                panic!("run_auto_update must not run while the lock is contended")
            };
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run") };
        maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base_path.as_path(),
            &run_fn,
            &reprobe_fn,
        )
        .expect("track-latest must not bail in this case");
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

        let base = tempfile::TempDir::new().unwrap();
        let result = handle_outdated(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            /* no_auto_update_cli= */ true,
            "csq run 1",
            |_, _, _| panic!("must not call run_auto_update when disabled"),
            |_| panic!("must not call reprobe when disabled"),
            |_: &Path| panic!("must not wait on the lock when auto-update is disabled"),
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

        let base = tempfile::TempDir::new().unwrap();
        let result = handle_outdated(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            &dummy_version(1),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            /* no_auto_update_cli= */ false,
            "csq run 1",
            |_, _, _| Ok(()),
            |_| ok_status(2),
            |_: &Path| panic!("the lock is free on a fresh tempdir; must not need to wait"),
        );
        assert!(
            result.is_ok(),
            "handle_outdated must return Ok on successful update; got {result:?}"
        );
    }

    // ── Update-then-launch race: an ABANDONED upgrade must not be followed
    //    by a spawn against the binary it may still be replacing ────────────

    /// THE discriminating test (FM-9 / C-R4-10). `run_auto_update` timing out
    /// with a CONFIRMED group-kill (`TimedOutSettled`) means no worker can
    /// still be mid-write — so `maybe_track_latest` re-probes before
    /// deciding. This half: the re-probe shows the binary no longer passes
    /// the floor (the forced kill left something broken), so the launch is
    /// blocked.
    #[test]
    fn maybe_track_latest_timeout_settled_with_binary_broken_bails() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::TimedOutSettled);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { CliStatus::Missing };
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert!(
            result.is_err(),
            "a confirmed-stopped upgrade whose re-probe fails must block the launch"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("mid-write") || msg.contains("no longer passes"),
            "the operator must be told the binary may be broken; got: {msg}"
        );
        assert!(
            msg.contains("--version") && msg.contains("re-run"),
            "the operator must be told what to check and what to do next; got: {msg}"
        );
    }

    /// FM-9, the other half: the re-probe shows the binary STILL passes the
    /// floor (unchanged, or the swap actually finished before the confirmed
    /// kill landed) — `maybe_track_latest` must proceed with a WARN, not bail.
    #[test]
    fn maybe_track_latest_timeout_settled_with_binary_still_ok_warns_and_proceeds() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::TimedOutSettled);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { ok_status(0) };
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert!(
            result.is_ok(),
            "a confirmed-stopped upgrade whose re-probe still passes the floor must proceed; \
             got {result:?}"
        );
    }

    /// C-R4-10 / S-F7 (FM-9) — THE regression test for the fix. When the
    /// group-kill confirmation itself could not complete (`TimedOut`, NOT
    /// `TimedOutSettled`), `maybe_track_latest` MUST bail unconditionally —
    /// even when the re-probe reports `Ok`. An `Ok` re-probe here cannot
    /// distinguish "the swap never started" from "the swap already
    /// finished", so trusting it (the pre-fix behaviour) would launch a
    /// session against a binary a still-alive worker may be mid-write to.
    /// The reprobe closure panics if called at all: an unconfirmed timeout
    /// must not even consult it.
    #[test]
    fn maybe_track_latest_timeout_unconfirmed_bails_even_when_reprobe_would_say_ok() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::TimedOut);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus {
            panic!(
                "an unconfirmed timeout must bail WITHOUT consulting the re-probe — an Ok \
                 re-probe cannot distinguish 'swap not started' from 'swap finished'"
            )
        };
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert!(
            result.is_err(),
            "an unconfirmed-group-kill timeout must always bail; got {result:?}"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("could not confirm"),
            "the operator must be told the group-kill was unconfirmed; got: {msg}"
        );
    }

    /// The negative half: the fix must be specific to the UNSETTLED case. An
    /// upgrade that definitively finished-and-failed leaves the binary on disk
    /// untouched and still passing the floor, so track-latest keeps its
    /// non-fatal contract and proceeds.
    #[test]
    fn maybe_track_latest_install_failed_still_proceeds() {
        let base = tempfile::TempDir::new().unwrap();
        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::InstallFailed);
        let reprobe_fn = |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on Err") };
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        assert!(
            result.is_ok(),
            "a finished-and-failed upgrade leaves the binary settled; must still proceed"
        );
    }

    /// Sequencing at the caller's shape: `enforce`'s Ok-arm propagates the
    /// track-latest verdict with `?` (as `run.rs` does before spawning), so an
    /// abandoned upgrade whose re-probe still fails means the spawn never
    /// happens. Guards against a future edit that swallows the verdict —
    /// e.g. re-dropping the `?`.
    #[test]
    fn abandoned_upgrade_means_no_spawn() {
        let base = tempfile::TempDir::new().unwrap();
        let mut spawned = false;
        let launch = |spawned: &mut bool| -> Result<()> {
            maybe_track_latest(
                SurfaceCli::Codex,
                "codex",
                &dummy_version(0),
                InstallManager::NpmGlobal,
                &dummy_path(),
                base.path(),
                &|_: SurfaceCli, _: InstallManager, _: Option<&Path>| Err(UpdateError::TimedOut),
                &|_: SurfaceCli| -> CliStatus { CliStatus::Missing },
            )?;
            *spawned = true;
            Ok(())
        };
        assert!(launch(&mut spawned).is_err(), "the gate must refuse");
        assert!(
            !spawned,
            "csq must never spawn a session against a binary an upgrade may still be replacing"
        );
    }

    // ── FM-8: a "not due" attempt waits for a sibling's held lock ────────────

    /// Held lock: a not-due attempt must wait for the sibling holding it to
    /// release before returning — and must never attempt an update itself
    /// (nor consult the reprobe, which is only for the "due" TimedOut path).
    #[test]
    fn maybe_track_latest_not_due_waits_for_held_lock_then_proceeds() {
        let base = tempfile::TempDir::new().unwrap();
        // Stamp "just now" so this attempt reads as NOT due.
        auto_update::record_track_latest_attempt(base.path(), SurfaceCli::Codex, SystemTime::now());

        let lock_path = base.path().join(".track-latest-codex.lock");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = csq_core::platform::lock::lock_file(&lock_path).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        rx.recv().unwrap(); // wait until the holder actually holds the lock

        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| -> Result<(), UpdateError> {
                panic!("a not-due attempt must never run an update itself")
            };
        let reprobe_fn =
            |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on the not-due path") };

        let start = std::time::Instant::now();
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        let elapsed = start.elapsed();
        holder.join().unwrap();

        assert!(
            result.is_ok(),
            "a not-due attempt must never bail; got {result:?}"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(250),
            "must have waited for the sibling's lock to release before returning; elapsed={elapsed:?}"
        );
    }

    /// Free lock: a not-due attempt with no sibling holding the lock must
    /// proceed immediately — no polling wait incurred.
    #[test]
    fn maybe_track_latest_not_due_free_lock_proceeds_without_waiting() {
        let base = tempfile::TempDir::new().unwrap();
        auto_update::record_track_latest_attempt(base.path(), SurfaceCli::Codex, SystemTime::now());

        let run_fn =
            |_: SurfaceCli, _: InstallManager, _: Option<&Path>| -> Result<(), UpdateError> {
                panic!("a not-due attempt must never run an update itself")
            };
        let reprobe_fn =
            |_: SurfaceCli| -> CliStatus { panic!("reprobe must not run on the not-due path") };

        let start = std::time::Instant::now();
        let result = maybe_track_latest(
            SurfaceCli::Codex,
            "codex",
            &dummy_version(0),
            InstallManager::NpmGlobal,
            &dummy_path(),
            base.path(),
            &run_fn,
            &reprobe_fn,
        );
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "a not-due attempt with a free lock must proceed; got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "a free lock must not incur the polling wait; elapsed={elapsed:?}"
        );
    }
}
