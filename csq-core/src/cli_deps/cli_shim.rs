//! Desktop→CLI shim refresh.
//!
//! The desktop app and the terminal CLI are the SAME single binary (per the
//! an internal workspace work), but they are installed by two independent channels:
//! the desktop `.app` is auto-updated by the Tauri updater, while the CLI at
//! `~/.local/bin/csq` is installed once by `install.sh` and never touched by a
//! desktop update. After a desktop auto-update the in-process daemon (running
//! the new bundle code) and the terminal CLI drift to different versions and
//! trip the version-skew guard on `csq run` / `login` / `status` / `doctor`.
//!
//! [`ensure_cli_shim`] closes that gap: on desktop launch it refreshes the CLI
//! binary so it is byte-identical to the running bundle.
//!
//! Two mechanisms are DELIBERATELY avoided:
//!
//! - **`cp`**: attaches `com.apple.provenance` on macOS → Gatekeeper SIGKILL
//!   (csq discovery `cp_provenance_gatekeeper_sigkill`). We write a fresh temp
//!   file then `atomic_replace` (rename) instead — the same primitive the
//!   in-place updater uses (`update/apply.rs`).
//! - **symlink into the `.app`**: `mode::detect` canonicalizes `current_exe()`,
//!   which resolves a symlink back into `…/Contents/MacOS/csq`, sees
//!   `/Contents/MacOS/`, and launches DESKTOP mode — so `csq` typed in a
//!   terminal would open the WebView app instead of the CLI. A real-file copy
//!   keeps `current_exe()` at the CLI path so CLI mode is selected correctly.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Outcome of [`ensure_cli_shim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimOutcome {
    /// Target did not exist; created it.
    Installed,
    /// Target existed as a regular file but differed from the source; replaced.
    Updated,
    /// Target was a symlink (or other non-regular file) — CLI-breaking under
    /// `mode::detect` — replaced with a real-file copy.
    ReplacedNonRegular,
    /// Target already byte-identical to the source AND verified runnable;
    /// nothing to do.
    NoOp,
    /// The installed CLI already reports the bundle's version line (version AND
    /// edition) and its signature (signer-pinned on enterprise) and exec verify,
    /// though its bytes differ (typically a standalone-signed copy of the bundle
    /// binary). Left untouched.
    ///
    /// **Consequence, accepted:** identity is the version+edition line, so a
    /// same-version, same-edition REBUILD with different bytes is NOT propagated
    /// to the CLI. Released builds bump the version, which refreshes; a dev host
    /// that rebuilds at an unchanged version uses `scripts/dev-install.sh`, which
    /// replaces the CLI itself. Propagating on byte difference would re-copy a
    /// standalone-signed helper over a good CLI on every launch for no gain.
    SkippedAlreadyCurrent,
    /// Target resolves to the same file as the source (e.g. the bundle exe is
    /// itself on PATH); refused to copy onto self.
    SkippedSameFile,
    /// The refresh was REFUSED with a fixed reason tag (see the `REASON_*`
    /// consts). Any temp file was removed and the previous target (if any) is
    /// untouched — a rejection never makes the CLI worse. (A target that was
    /// ALREADY broken stays broken when every candidate is rejected; this module
    /// can only refuse to make things worse, not repair without a verifying
    /// source.)
    Rejected(&'static str),
}

/// Reason tag: the candidate's signature does not verify at its standalone path
/// (a bundle-bound main executable — an internal ticket / the 2.20.2 exit-137
/// regression), or was not signed by the pinned team.
pub const REASON_SIGNATURE_INVALID: &str = "signature_invalid";
/// Reason tag: `codesign` could not complete (spawn failure, missing tool,
/// timeout) — "could not check", NOT "check failed".
pub const REASON_SIGNATURE_UNVERIFIABLE: &str = "signature_unverifiable";
/// Reason tag: the candidate ran and failed (non-zero exit or a signal such as
/// the kernel's SIGKILL for an invalid signature).
pub const REASON_EXEC_PROBE_FAILED: &str = "exec_probe_failed";
/// Reason tag: the candidate could not be exec-probed (spawn failure or timeout)
/// — "could not check", NOT "check failed".
pub const REASON_EXEC_PROBE_UNVERIFIABLE: &str = "exec_probe_unverifiable";
/// Reason tag: the temp file was swapped (or replaced by a symlink) between
/// write and replace.
pub const REASON_TMP_REPLACED: &str = "tmp_replaced";
/// Reason tag: the target changed (e.g. a concurrent `csq update`) between the
/// refresh decision and the replace.
pub const REASON_TARGET_CHANGED: &str = "target_changed";
/// Reason tag: the enterprise policy could not derive a signing team from the
/// source, so no signer can be pinned (fail closed).
pub const REASON_SIGNER_UNPINNED: &str = "signer_unpinned";
/// Reason tag: the trusted signing team could not be read (`codesign` spawn
/// failure or timeout) — "could not check", NOT "no team".
pub const REASON_SIGNER_UNVERIFIABLE: &str = "signer_unverifiable";
/// Reason tag: a COMMUNITY refresh would overwrite a verified ENTERPRISE CLI.
pub const REASON_EDITION_DOWNGRADE: &str = "edition_downgrade";
/// Reason tag: the verified installed CLI is strictly NEWER than the bundle.
pub const REASON_TARGET_NEWER: &str = "target_newer";
/// Reason tag: another replacer (`csq update`) held the binary replace lock for
/// the whole bounded wait.
pub const REASON_REPLACE_LOCK_BUSY: &str = "replace_lock_busy";
/// Logged (WARN) when an ENTERPRISE bundle replaces a verified, possibly newer
/// COMMUNITY CLI: edition wins over version (`edition-safe-install.md`).
pub const TAG_EDITION_MISMATCH_REPLACED: &str = "edition_mismatch_replaced";

/// Replace-lock wait: `REPLACE_LOCK_ATTEMPTS` tries `REPLACE_LOCK_DELAY` apart.
pub const REPLACE_LOCK_ATTEMPTS: u32 = 50;
/// See [`REPLACE_LOCK_ATTEMPTS`].
pub const REPLACE_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Delay before the ONE retry of an unavailable/timed-out trusted-team check.
pub const TRUSTED_TEAM_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Deadline for ONE bounded subprocess (`--version`, `codesign`, `xattr`).
///
/// It separates two outcomes. HEALTHY: the first exec of a freshly written
/// Developer-ID file pays a one-time Gatekeeper assessment — measured 2026-10-06
/// at 0.36–0.66s under load average ~160 (a warm file: 0.01s). HUNG: a wedged
/// binary or a stalled `syspolicyd`, which never returns. 5s leaves ≥4.3s (~7.5x)
/// above the worst healthy reading, and a hang consumes the configured deadline per
/// call. (The desktop's former 3s advisory probe of an installed, WARM file is
/// gone; this one runs on a detached thread against a FRESH file, where a false
/// timeout rejects a good refresh, so the longer deadline is the right one.)
///
/// The deadline starts BEFORE spawn. Spawn itself cannot be interrupted; once
/// it returns, an exhausted budget kills/reaps the child immediately. Filesystem
/// work, scheduling, and kill/reap latency are not hard real-time bounded.
///
/// Subprocess budget envelopes on macOS (not elapsed-time guarantees): refresh
/// community = target (`verify`, `-dv` ad-hoc fallback, exec) 3 + candidate
/// (`verify`, `-dv`, exec, `xattr`, exec) 5 = 8 calls; enterprise = trusted team
/// (`-dv`, own-pid verify), repeated once on a transient result, 4 + target
/// (`verify`, exec) 2 + candidate (`verify`, exec, `xattr`, exec) 4 = 10 calls.
/// Each subsequent [`installed_cli_verification`] (also used by the
/// [`installed_verified_version_line`] wrapper) resolves its signer again and
/// costs at most 3 community / 6 enterprise calls, including that retry.
/// The desktop reuses ONE final verification for edition, receipt and plist gate;
/// checking a different stale plist program adds one more installed verification.
/// Thus refresh through that gate has at most 14 community / 22 enterprise calls:
/// `14 * SHIM_PROBE_TIMEOUT + REPLACE_LOCK_ATTEMPTS * REPLACE_LOCK_DELAY` = 75s,
/// or `22 * SHIM_PROBE_TIMEOUT + REPLACE_LOCK_ATTEMPTS * REPLACE_LOCK_DELAY +
/// 3 * TRUSTED_TEAM_RETRY_DELAY` = 115.3s. Without a different stale program,
/// the respective envelopes are 60s / 85.2s. The lock actually sleeps at most
/// `(REPLACE_LOCK_ATTEMPTS - 1) * REPLACE_LOCK_DELAY`; these use a conservative
/// 5s allowance. Retry delays apply only to transient team reads, never invalid
/// signatures; actual failure paths usually stop before reaching these sums.
/// Stale-plist metadata handling separately allocates at most three commands
/// (`plutil`, targeted `launchctl list`, `launchctl bootout`), adding
/// `3 * SHIM_PROBE_TIMEOUT` = 15s to
/// those envelopes before plist repair: 90s community / 130.3s enterprise with
/// a different stale program; 75s / 100.2s when it names the final target.
/// Repair independently allocates three more calls (job-state, unload, load),
/// without assuming job state stays unchanged between reads. The complete
/// conservative allocations are thus 105s / 145.3s. Filesystem work is uncapped.
pub const SHIM_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Cap on captured stdout/stderr per bounded subprocess.
const PROBE_OUTPUT_CAP: u64 = 16 * 1024;

/// Result of one bounded check. Separates "the check failed" from "the check
/// could not be made" (`TimedOut`, `Unavailable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome<T> {
    Ok(T),
    /// Ran to completion and said no (non-zero exit, empty output).
    Failed,
    /// Killed by a signal (the number is logged at debug; 9 is the kernel's
    /// Gatekeeper kill, distinct from our own timeout).
    Signaled(i32),
    /// Exceeded [`SHIM_PROBE_TIMEOUT`]; the process group was killed.
    TimedOut,
    /// Could not be spawned (missing tool, exec error) or is refused by policy.
    Unavailable,
}

/// Who must have signed a shim binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerPolicy {
    /// Community builds: any intact signature (ad-hoc included).
    AnySignature,
    /// Enterprise builds: the signing TEAM is taken from a TRUSTED ANCHOR and
    /// pinned on every check (Developer ID leaf required, ad-hoc NOT accepted).
    /// The anchor is NOT the shim source — a team read from the very file being
    /// checked is a comparison of the file against itself. It is the RUNNING
    /// process's own team: `codesign -dv <our pid>` DISPLAYS it and
    /// `codesign --verify -R=<pin> <our pid>` must then validate it (display alone
    /// is not trusted; a certificate rotation needs no code change). The
    /// compiled-in release team (`CSQ_RELEASE_TEAM_ID`) is used ONLY when no team
    /// is displayed at all (an unsigned dev build); a team that was displayed but
    /// failed verification, or an ambiguous display, fails closed
    /// ([`REASON_SIGNER_UNPINNED`]), as does having neither.
    PinTrustedTeam,
}

/// A resolved signer requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    Any,
    Team(String),
}

/// Environment seam for [`ensure_cli_shim_with`]: everything that touches a
/// real executable (exec, codesign, xattr). Production uses [`SystemShimProbe`];
/// tests inject a content-keyed fake so no test spawns a signed binary.
pub trait ShimProbe {
    /// Run `<exe> --version`; the trimmed stdout on success. NEVER called with
    /// the shim SOURCE (see [`ensure_cli_shim`]).
    fn version_probe(&self, exe: &Path) -> ProbeOutcome<String>;
    /// The TRUSTED signing team to pin: the running process's team, accepted only
    /// after `codesign --verify -R=<pin> <our pid>` validates it. The compiled-in
    /// release team applies ONLY when no team is displayed at all. `Failed` = no
    /// trustworthy team (unsigned dev build, a shown team that failed
    /// verification, or an ambiguous display); `TimedOut`/`Unavailable` = could
    /// not check.
    fn trusted_team(&self) -> ProbeOutcome<String>;
    /// Short delay before retrying a transient trusted-team check. Tests may
    /// inject it so retry ordering is checked without sleeping.
    fn wait_before_trusted_team_retry(&self) {
        std::thread::sleep(TRUSTED_TEAM_RETRY_DELAY);
    }
    /// Does `exe`'s code signature verify at its CURRENT path AND satisfy
    /// `signer`? (`Ok` always off macOS.)
    fn signature(&self, exe: &Path, signer: &Signer) -> ProbeOutcome<()>;
    /// Signature verification without any executable-probe fallback.
    fn strict_signature(&self, exe: &Path, signer: &Signer) -> ProbeOutcome<()> {
        self.signature(exe, signer)
    }
    /// Best-effort `xattr -c` on `exe`. **`-c` clears ALL extended attributes**
    /// (provenance, quarantine, everything), so it is only ever called on the
    /// candidate TEMP file this call created, never on an installed target.
    fn clear_provenance(&self, exe: &Path);
    /// Replace-lock wait budget `(attempts, delay)`.
    fn replace_lock_budget(&self) -> (u32, std::time::Duration) {
        (REPLACE_LOCK_ATTEMPTS, REPLACE_LOCK_DELAY)
    }
    /// Called once when the replace lock is found held (observability hook).
    fn on_replace_lock_wait(&self) {}
}

/// The real probe: bounded exec, `codesign`, `xattr -c`.
pub struct SystemShimProbe;

/// Would exec'ing this path launch a DESKTOP instance (`mode::detect` resolves
/// a canonical path under `/Contents/MacOS/` or an AppImage to Desktop mode)?
/// Mirrors `probe_cli_version_output_within`'s intent in the desktop module.
fn is_desktop_launching_path(path: &Path) -> bool {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut components = resolved.components().peekable();
    while let Some(component) = components.next() {
        if component.as_os_str() == "Contents"
            && components
                .next_if(|next| next.as_os_str() == "MacOS")
                .is_some()
            && components.peek().is_some()
        {
            return true;
        }
    }
    resolved.to_string_lossy().contains(".AppImage")
}

impl ShimProbe for SystemShimProbe {
    #[cfg(not(target_os = "macos"))]
    fn strict_signature(&self, _exe: &Path, _signer: &Signer) -> ProbeOutcome<()> {
        // The legacy replacement probe is portable and may be a no-op; the
        // rollback trust helper must not claim verification without a backend.
        ProbeOutcome::Unavailable
    }

    #[cfg(target_os = "macos")]
    fn strict_signature(&self, exe: &Path, signer: &Signer) -> ProbeOutcome<()> {
        let mut command = std::process::Command::new("/usr/bin/codesign");
        command.args(["--verify", "--strict"]);
        if let Signer::Team(team) = signer {
            if !is_team_id(team) {
                return ProbeOutcome::Failed;
            }
            command.arg(pinned_requirement(team));
        }
        command.arg(exe);
        outcome_of(run_bounded(command, SHIM_PROBE_TIMEOUT)).map_unit()
    }

    fn version_probe(&self, exe: &Path) -> ProbeOutcome<String> {
        if is_desktop_launching_path(exe) {
            return ProbeOutcome::Unavailable;
        }
        probe_version_within(exe, SHIM_PROBE_TIMEOUT)
    }

    #[cfg(target_os = "macos")]
    fn trusted_team(&self) -> ProbeOutcome<String> {
        // `codesign -dv <pid>` only DISPLAYS the team of our running process; the
        // display is then VALIDATED by `codesign --verify -R=<pinned requirement>
        // <pid>`, which checks the running code dynamically against that team. A
        // team is trusted only when that verify exits 0.
        let pid = std::process::id().to_string();
        let mut dv = std::process::Command::new("/usr/bin/codesign");
        dv.arg("-dv").arg(&pid);
        let shown = match run_bounded(dv, SHIM_PROBE_TIMEOUT) {
            Bounded::Done { stderr, .. } => {
                parse_team_identifier(&String::from_utf8_lossy(&stderr))
            }
            Bounded::TimedOut => return ProbeOutcome::TimedOut,
            Bounded::SpawnFailed => return ProbeOutcome::Unavailable,
        };
        trust_running_team(shown, verify_running_team, compiled_team())
    }

    #[cfg(not(target_os = "macos"))]
    fn trusted_team(&self) -> ProbeOutcome<String> {
        compiled_team()
    }

    #[cfg(target_os = "macos")]
    fn signature(&self, exe: &Path, signer: &Signer) -> ProbeOutcome<()> {
        let mut verify = std::process::Command::new("/usr/bin/codesign");
        verify.args(["--verify", "--strict"]);
        if let Signer::Team(team) = signer {
            // Re-validate: the team string reaches a code-requirement
            // expression, so anything but a 10-char Apple team id is refused.
            if !is_team_id(team) {
                return ProbeOutcome::Failed;
            }
            verify.arg(pinned_requirement(team));
        }
        verify.arg(exe);
        match outcome_of(run_bounded(verify, SHIM_PROBE_TIMEOUT)) {
            ProbeOutcome::Ok(_) => return ProbeOutcome::Ok(()),
            ProbeOutcome::Failed => {}
            other => return other.map_unit(),
        }
        // Pinned (enterprise): the ONLY accepted signature is one satisfying the
        // `anchor apple generic … = "<team>"` requirement above — a non-zero exit
        // here is final, there is no ad-hoc fallback to take.
        if matches!(signer, Signer::Team(_)) {
            return ProbeOutcome::Failed;
        }
        // Community only: ad-hoc builds are not Developer-ID sealed by the
        // kernel, so a bundle-bound ad-hoc copy that fails `--verify` still
        // runs; for that one shape the exec probe is the gate.
        let mut dv = std::process::Command::new("/usr/bin/codesign");
        dv.arg("-dv").arg(exe);
        match run_bounded(dv, SHIM_PROBE_TIMEOUT) {
            Bounded::Done { stderr, .. } if stderr_is_adhoc(&String::from_utf8_lossy(&stderr)) => {
                ProbeOutcome::Ok(())
            }
            Bounded::Done { .. } => ProbeOutcome::Failed,
            Bounded::TimedOut => ProbeOutcome::TimedOut,
            Bounded::SpawnFailed => ProbeOutcome::Unavailable,
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn signature(&self, _exe: &Path, _signer: &Signer) -> ProbeOutcome<()> {
        ProbeOutcome::Ok(())
    }

    #[cfg(target_os = "macos")]
    fn clear_provenance(&self, exe: &Path) {
        let mut cmd = std::process::Command::new("/usr/bin/xattr");
        cmd.arg("-c").arg(exe);
        match run_bounded(cmd, SHIM_PROBE_TIMEOUT) {
            Bounded::Done { success: true, .. } => {}
            Bounded::Done { code, signal, .. } => {
                tracing::debug!(tag = "xattr_nonzero", ?code, ?signal, "xattr -c failed");
            }
            Bounded::TimedOut => tracing::debug!(tag = "xattr_timeout", "xattr -c timed out"),
            Bounded::SpawnFailed => {
                tracing::debug!(tag = "xattr_spawn_failed", "xattr -c could not be spawned")
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn clear_provenance(&self, _exe: &Path) {}
}

/// The release build's compiled-in team id (`CSQ_RELEASE_TEAM_ID`), the
/// fallback trust anchor; `Failed` when absent or malformed.
fn compiled_team() -> ProbeOutcome<String> {
    match option_env!("CSQ_RELEASE_TEAM_ID") {
        Some(t) if is_team_id(t) => ProbeOutcome::Ok(t.to_string()),
        _ => ProbeOutcome::Failed,
    }
}

/// The trust decision for the running process's team, with the dynamic verify
/// injected: a displayed team is accepted ONLY when `verify(team)` is `Ok`. The
/// compiled-in release team (`compiled`) is consulted ONLY when no team was
/// displayed; a shown-but-unverified team or an ambiguous display is `Failed`
/// (never rescued by `compiled`); a could-not-check verify is reported as such.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn trust_running_team(
    shown: ShownTeam,
    verify: impl FnOnce(&str) -> ProbeOutcome<()>,
    compiled: ProbeOutcome<String>,
) -> ProbeOutcome<String> {
    match shown {
        // Nothing displayed (unsigned/ad-hoc dev build): the compiled-in release
        // team is the only anchor left.
        ShownTeam::None => compiled,
        // Ambiguous display: never trusted, and NOT rescued by the compiled team.
        ShownTeam::Ambiguous => ProbeOutcome::Failed,
        ShownTeam::One(team) => match verify(&team) {
            ProbeOutcome::Ok(_) => ProbeOutcome::Ok(team),
            ProbeOutcome::TimedOut => ProbeOutcome::TimedOut,
            ProbeOutcome::Unavailable => ProbeOutcome::Unavailable,
            // A team WAS shown but did not validate: fail closed — do not fall
            // back to the compiled-in team.
            ProbeOutcome::Failed | ProbeOutcome::Signaled(_) => ProbeOutcome::Failed,
        },
    }
}

/// What `codesign -dv` displayed as the signing team.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum ShownTeam {
    /// No `TeamIdentifier=` line, or `not set` (ad-hoc / unsigned).
    None,
    /// Exactly one well-formed team id.
    One(String),
    /// More than one line, or a malformed value: untrustworthy.
    Ambiguous,
}

/// `codesign --verify -R=<pinned requirement for team> <our own pid>`.
#[cfg(target_os = "macos")]
fn verify_running_team(team: &str) -> ProbeOutcome<()> {
    if !is_team_id(team) {
        return ProbeOutcome::Failed;
    }
    let mut v = std::process::Command::new("/usr/bin/codesign");
    v.args(["--verify", "--strict"])
        .arg(pinned_requirement(team))
        .arg(std::process::id().to_string());
    outcome_of(run_bounded(v, SHIM_PROBE_TIMEOUT)).map_unit()
}

/// The `-R=` code requirement pinning `team` (a validated team id): a Developer
/// ID chain (`anchor apple generic` alone also admits Apple Development
/// certificates; the OID clauses are the Developer ID intermediate
/// 1.2.840.113635.100.6.2.6 and leaf 100.6.1.13).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn pinned_requirement(team: &str) -> String {
    format!(
        "-R=anchor apple generic and certificate leaf[subject.OU] = \"{team}\" \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
}

/// An Apple team identifier: exactly 10 uppercase alphanumerics.
fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// `TeamIdentifier=XXXXXXXXXX` out of `codesign -dv` stderr. A whole line is
/// matched; `not set` (ad-hoc) and malformed ids give `None`. MORE THAN ONE such
/// line gives `None`: an `Executable=` path containing a newline could inject
/// one, so an ambiguous display is never trusted (and the caller additionally
/// validates the team with `codesign --verify -R`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_team_identifier(stderr: &str) -> ShownTeam {
    let ids: Vec<&str> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("TeamIdentifier="))
        .collect();
    match ids.as_slice() {
        [] => ShownTeam::None,
        [one] => {
            let t = one.trim();
            if t == "not set" {
                ShownTeam::None
            } else if is_team_id(t) {
                ShownTeam::One(t.to_string())
            } else {
                ShownTeam::Ambiguous
            }
        }
        _ => ShownTeam::Ambiguous,
    }
}

/// Is this `codesign -dv` stderr an ad-hoc signature? A WHOLE LINE must equal
/// `Signature=adhoc` — a substring match would also accept a line such as
/// `Authority=Signature=adhoc` or text echoed from a path.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn stderr_is_adhoc(stderr: &str) -> bool {
    stderr.lines().any(|l| l == "Signature=adhoc")
}

/// Result of [`run_bounded`].
#[derive(Debug)]
enum Bounded {
    Done {
        success: bool,
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        code: Option<i32>,
        signal: Option<i32>,
        stdout: Vec<u8>,
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        stderr: Vec<u8>,
    },
    TimedOut,
    SpawnFailed,
}

/// The ONE bounded-spawn helper every subprocess here goes through.
///
/// The child runs in its own process group with a scrubbed environment
/// (`env_clear` + `PATH=/usr/bin:/bin` + `HOME`/`LANG`); stdout and stderr are
/// read by capped reader threads whose results are awaited only until the
/// deadline, so a grandchild that inherits a pipe cannot block us. On expiry —
/// and on every exit path — the whole group is SIGKILLed and the child reaped.
fn run_bounded(cmd: std::process::Command, timeout: std::time::Duration) -> Bounded {
    run_bounded_with(cmd, timeout, &mut sigkill_group)
}

/// [`run_bounded`] with ONLY the group-kill sender injected, so a test can see
/// the state of the leader at the instant of the kill.
fn run_bounded_with(
    cmd: std::process::Command,
    timeout: std::time::Duration,
    send: &mut dyn FnMut(u32),
) -> Bounded {
    run_bounded_with_runtime(
        cmd,
        timeout,
        send,
        &mut std::time::Instant::now,
        &mut |cmd| cmd.spawn(),
    )
}

/// Clock/spawn seam: the production clock is monotonic; tests can consume the
/// spawn budget deterministically without scheduler-sensitive elapsed checks.
fn run_bounded_with_runtime(
    cmd: std::process::Command,
    timeout: std::time::Duration,
    send: &mut dyn FnMut(u32),
    now: &mut dyn FnMut() -> std::time::Instant,
    spawn: &mut dyn FnMut(&mut std::process::Command) -> std::io::Result<std::process::Child>,
) -> Bounded {
    run_bounded_with_limits(cmd, timeout, PROBE_OUTPUT_CAP, send, now, spawn)
}

/// Shared runner with caller-specific timeout and per-pipe output ceiling.
fn run_bounded_with_limits(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
    output_cap: u64,
    send: &mut dyn FnMut(u32),
    now: &mut dyn FnMut() -> std::time::Instant,
    spawn: &mut dyn FnMut(&mut std::process::Command) -> std::io::Result<std::process::Child>,
) -> Bounded {
    use std::io::Read;
    use std::process::Stdio;
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = std::env::var_os("HOME") {
        cmd.env("HOME", home);
    }
    if let Some(lang) = std::env::var_os("LANG") {
        cmd.env("LANG", lang);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let deadline = now() + timeout;
    let Ok(mut child) = spawn(&mut cmd) else {
        return Bounded::SpawnFailed;
    };
    let pgid = child.id();
    if now() >= deadline {
        kill_group(&mut child, pgid, send);
        return Bounded::TimedOut;
    }
    let spawn_reader = |r: Option<Box<dyn Read + Send>>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(r) = r {
                let _ = r.take(output_cap).read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    };
    let out_rx = spawn_reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err_rx = spawn_reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    // Detect exit WITHOUT reaping (`waitid(WNOWAIT)`): an exited leader stays a
    // zombie, so its pid — which is also the process-group id — cannot be
    // recycled before the group kill below. `try_wait` would reap it first, and
    // `killpg` could then hit an unrelated group that reused the id.
    let exited = wait_for_exit(&mut child, deadline, now);
    let mut left = || deadline.saturating_duration_since(now());
    let outputs = if exited == Some(true) {
        match (out_rx.recv_timeout(left()), err_rx.recv_timeout(left())) {
            (Ok(o), Ok(e)) => Some((o, e)),
            _ => None,
        }
    } else {
        None
    };
    // Group kill while the leader is still reserved (zombie or running), then reap.
    let status = kill_group(&mut child, pgid, send);
    match (exited, outputs, status) {
        (Some(true), Some((stdout, stderr)), Some(status)) => {
            #[cfg(unix)]
            let signal = {
                use std::os::unix::process::ExitStatusExt;
                status.signal()
            };
            #[cfg(not(unix))]
            let signal = None;
            Bounded::Done {
                success: status.success(),
                code: status.code(),
                signal,
                stdout,
                stderr,
            }
        }
        (None, _, _) => Bounded::SpawnFailed,
        _ => Bounded::TimedOut,
    }
}

/// Poll until the child has exited or `deadline` passes WITHOUT reaping it
/// (`Some(true)` exited, `Some(false)` still running at the deadline, `None` the
/// wait failed).
fn wait_for_exit(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
    now: &mut dyn FnMut() -> std::time::Instant,
) -> Option<bool> {
    loop {
        match child_exited_nowait(child) {
            Some(false) if now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

/// Has the child exited? `Some(true)` leaves it UNREAPED (unix); `None` = the
/// wait itself failed.
#[cfg(unix)]
pub(crate) fn child_exited_nowait(child: &mut std::process::Child) -> Option<bool> {
    // SAFETY: a zeroed siginfo_t is a valid out-parameter for waitid; the call
    // takes a pid we own and writes only into `info`.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if r != 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: si_pid is valid after a successful waitid.
    let pid = unsafe { info.si_pid() };
    #[cfg(not(target_os = "linux"))]
    let pid = info.si_pid;
    Some(pid != 0)
}

#[cfg(not(unix))]
pub(crate) fn child_exited_nowait(child: &mut std::process::Child) -> Option<bool> {
    child.try_wait().ok().map(|s| s.is_some())
}

/// SIGKILL a process GROUP (`killpg` semantics).
#[cfg(unix)]
fn sigkill_group(pgid: u32) {
    // SAFETY: `killpg` takes plain integers; ESRCH (group gone) is fine.
    unsafe {
        libc::killpg(pgid as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn sigkill_group(_pgid: u32) {}

/// Kill the whole process group (children included), THEN reap the direct child
/// and return its status. The signal sender is injected so a test can observe
/// that the leader is still unreaped (pid/pgid reserved) at the moment of the
/// kill.
fn kill_group(
    child: &mut std::process::Child,
    pgid: u32,
    send: &mut dyn FnMut(u32),
) -> Option<std::process::ExitStatus> {
    send(pgid);
    let _ = child.kill();
    child.wait().ok()
}

/// Map a [`Bounded`] to a check outcome (stdout is the value on success).
fn outcome_of(b: Bounded) -> ProbeOutcome<Vec<u8>> {
    match b {
        Bounded::Done {
            success: true,
            stdout,
            ..
        } => ProbeOutcome::Ok(stdout),
        Bounded::Done {
            signal: Some(s), ..
        } => ProbeOutcome::Signaled(s),
        Bounded::Done { .. } => ProbeOutcome::Failed,
        Bounded::TimedOut => ProbeOutcome::TimedOut,
        Bounded::SpawnFailed => ProbeOutcome::Unavailable,
    }
}

impl<T> ProbeOutcome<T> {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn map_unit(self) -> ProbeOutcome<()> {
        match self {
            ProbeOutcome::Ok(_) => ProbeOutcome::Ok(()),
            ProbeOutcome::Failed => ProbeOutcome::Failed,
            ProbeOutcome::Signaled(s) => ProbeOutcome::Signaled(s),
            ProbeOutcome::TimedOut => ProbeOutcome::TimedOut,
            ProbeOutcome::Unavailable => ProbeOutcome::Unavailable,
        }
    }
}

/// `<exe> --version` through [`run_bounded`]; the first non-empty trimmed stdout.
fn probe_version_within(exe: &Path, timeout: std::time::Duration) -> ProbeOutcome<String> {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--version");
    match outcome_of(run_bounded(cmd, timeout)) {
        ProbeOutcome::Ok(out) => {
            let line = String::from_utf8_lossy(&out).trim().to_string();
            if line.is_empty() {
                ProbeOutcome::Failed
            } else {
                ProbeOutcome::Ok(line)
            }
        }
        other => other.map_string(),
    }
}

impl ProbeOutcome<Vec<u8>> {
    fn map_string(self) -> ProbeOutcome<String> {
        match self {
            ProbeOutcome::Ok(_) => ProbeOutcome::Failed,
            ProbeOutcome::Failed => ProbeOutcome::Failed,
            ProbeOutcome::Signaled(s) => ProbeOutcome::Signaled(s),
            ProbeOutcome::TimedOut => ProbeOutcome::TimedOut,
            ProbeOutcome::Unavailable => ProbeOutcome::Unavailable,
        }
    }
}

/// Verify a candidate TEMP copy BEFORE it replaces anything: signature (and
/// signer) at the candidate's own path, then a real exec. A failed exec (non-zero
/// exit or a signal) gets ONE retry after clearing xattrs; a timeout or spawn
/// failure never does (it is "could not check", and xattrs are not the cause).
/// MUTATES the candidate (xattr clear) — use only on a file this call created;
/// installed targets are only ever checked read-only (signature, then exec).
fn verify_candidate(
    probe: &dyn ShimProbe,
    candidate: &Path,
    signer: &Signer,
) -> Result<(), &'static str> {
    match probe.signature(candidate, signer) {
        ProbeOutcome::Ok(_) => {}
        o @ (ProbeOutcome::Failed | ProbeOutcome::Signaled(_)) => {
            tracing::debug!(tag = REASON_SIGNATURE_INVALID, outcome = ?o, "shim candidate signature");
            return Err(REASON_SIGNATURE_INVALID);
        }
        o => {
            tracing::debug!(tag = REASON_SIGNATURE_UNVERIFIABLE, outcome = ?o, "shim candidate signature");
            return Err(REASON_SIGNATURE_UNVERIFIABLE);
        }
    }
    match probe.version_probe(candidate) {
        ProbeOutcome::Ok(_) => return Ok(()),
        o @ (ProbeOutcome::TimedOut | ProbeOutcome::Unavailable) => {
            tracing::debug!(tag = REASON_EXEC_PROBE_UNVERIFIABLE, outcome = ?o, "shim candidate exec");
            return Err(REASON_EXEC_PROBE_UNVERIFIABLE);
        }
        o => tracing::debug!(tag = "exec_probe_retry", outcome = ?o, "shim candidate exec"),
    }
    probe.clear_provenance(candidate);
    match probe.version_probe(candidate) {
        ProbeOutcome::Ok(_) => Ok(()),
        o @ (ProbeOutcome::TimedOut | ProbeOutcome::Unavailable) => {
            tracing::debug!(tag = REASON_EXEC_PROBE_UNVERIFIABLE, outcome = ?o, "shim candidate exec");
            Err(REASON_EXEC_PROBE_UNVERIFIABLE)
        }
        o => {
            tracing::debug!(tag = REASON_EXEC_PROBE_FAILED, outcome = ?o, "shim candidate exec");
            Err(REASON_EXEC_PROBE_FAILED)
        }
    }
}

/// Refresh `target` from `source` using the real [`SystemShimProbe`].
///
/// `expected_version` is the bundle's own `--version` line — the caller's
/// compiled-in value. **The source is NEVER executed:** when it is the bundle's
/// main executable it resolves to Desktop mode under `mode::detect`, so a
/// `--version` probe would launch a second app instance.
pub fn ensure_cli_shim(
    source: &Path,
    target: &Path,
    expected_version: &str,
    policy: &SignerPolicy,
) -> Result<ShimOutcome> {
    ensure_cli_shim_with(source, target, &SystemShimProbe, expected_version, policy)
}

/// `csq 2.21.0 (enterprise)` and `2.21.0 (enterprise)` are the same identity.
fn normalize_version_line(l: &str) -> &str {
    let l = l.trim();
    l.strip_prefix("csq ").unwrap_or(l)
}

/// Identity of the target at decision time: `(dev, ino, len, mtime)`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

fn stamp_of(path: &Path) -> Option<FileStamp> {
    let m = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        (m.dev(), m.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, 0);
    Some(FileStamp {
        dev,
        ino,
        len: m.len(),
        mtime: m.modified().ok(),
    })
}

/// Reason tag: an enterprise refresh has only the bundle-bound main executable
/// as its source (the bundle lacks `Contents/Helpers/csq-cli`).
pub const REASON_SOURCE_BUNDLE_BOUND: &str = "source_bundle_bound";

/// Path of the advisory lock shared by every in-process binary replacer of
/// `binary` (this refresh and `csq update`'s `apply`), so two replacements of
/// the same CLI never interleave their check-then-rename.
pub fn replace_lock_path(binary: &Path) -> PathBuf {
    binary.with_file_name(".csq-replace.lock")
}

/// Take the shared replace lock with a BOUNDED wait (`attempts` tries `delay`
/// apart; `Ok(None)` = still held), opening the lock file `O_NOFOLLOW`/`0o600` so
/// a symlink planted at the lock path is refused (an `Err`), not followed.
/// `on_wait` runs once, when the lock is first found held.
pub fn acquire_replace_lock(
    binary: &Path,
    attempts: u32,
    delay: std::time::Duration,
    on_wait: &mut dyn FnMut(),
) -> Result<Option<crate::platform::lock::FileLockGuard>, crate::error::PlatformError> {
    let path = replace_lock_path(binary);
    let mut waited = false;
    for attempt in 0..attempts.max(1) {
        if let Some(g) = crate::platform::lock::try_lock_file_bounded_nofollow(
            &path,
            1,
            std::time::Duration::ZERO,
        )? {
            return Ok(Some(g));
        }
        if !waited {
            waited = true;
            on_wait();
        }
        if attempt + 1 < attempts {
            std::thread::sleep(delay);
        }
    }
    Ok(None)
}

/// Resolve the signer requirement. Team pinning needs `codesign`, which exists
/// only on macOS: elsewhere (`pin_supported == false`) the signature check is a
/// no-op and the signer is `Any`, so Linux/Windows enterprise refreshes work.
fn resolve_signer(
    policy: &SignerPolicy,
    probe: &dyn ShimProbe,
    pin_supported: bool,
) -> Result<Signer, &'static str> {
    match policy {
        SignerPolicy::AnySignature => Ok(Signer::Any),
        SignerPolicy::PinTrustedTeam if !pin_supported => Ok(Signer::Any),
        SignerPolicy::PinTrustedTeam => {
            let mut team = probe.trusted_team();
            if matches!(team, ProbeOutcome::TimedOut | ProbeOutcome::Unavailable) {
                probe.wait_before_trusted_team_retry();
                team = probe.trusted_team();
            }
            match team {
                ProbeOutcome::Ok(team) if is_team_id(&team) => Ok(Signer::Team(team)),
                ProbeOutcome::Ok(_) | ProbeOutcome::Failed | ProbeOutcome::Signaled(_) => {
                    Err(REASON_SIGNER_UNPINNED)
                }
                ProbeOutcome::TimedOut | ProbeOutcome::Unavailable => {
                    Err(REASON_SIGNER_UNVERIFIABLE)
                }
            }
        }
    }
}

/// Temp path for the candidate. On Windows `CreateProcessW` refuses a file whose
/// extension is not `.exe` for our exec probe (`csq.tmp.<pid>.<n>` has extension
/// `.<n>`), so the name gets a `.exe` suffix there; renaming it over `csq.exe`
/// is unaffected.
fn candidate_tmp_path(target: &Path) -> PathBuf {
    let tmp = crate::platform::fs::unique_tmp_path(target);
    if cfg!(windows) {
        let mut os = tmp.into_os_string();
        os.push(".exe");
        PathBuf::from(os)
    } else {
        tmp
    }
}

/// Remove `tmp` after a failed exclusive create UNLESS the path already existed:
/// then it is not ours (a planted file/symlink) and must not be deleted.
fn remove_unless_foreign(tmp: &Path, e: &anyhow::Error) {
    let foreign = e
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists);
    if !foreign {
        let _ = std::fs::remove_file(tmp);
    }
}

/// The installed CLI's `--version` line, but ONLY when `target` is a regular file
/// whose signature verifies under `signer` (checked BEFORE it is executed) and
/// which runs. An unverified target's claim is never returned.
fn verified_version_line(probe: &dyn ShimProbe, target: &Path, signer: &Signer) -> Option<String> {
    let regular = std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_file());
    if !regular || !matches!(probe.signature(target, signer), ProbeOutcome::Ok(_)) {
        return None;
    }
    match probe.version_probe(target) {
        ProbeOutcome::Ok(l) => Some(l),
        _ => None,
    }
}

/// Installed CLI verification retains uncertainty so cleanup never treats a
/// timeout or unavailable trusted signer as proof that an executable is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledCliVerification {
    Verified(String),
    Invalid,
    Unverifiable,
}

impl InstalledCliVerification {
    pub fn version_line(&self) -> Option<&str> {
        match self {
            Self::Verified(line) => Some(line),
            Self::Invalid | Self::Unverifiable => None,
        }
    }
}

fn installed_cli_verification_with(
    target: &Path,
    policy: &SignerPolicy,
    probe: &dyn ShimProbe,
    pin_supported: bool,
) -> InstalledCliVerification {
    use InstalledCliVerification::{Invalid, Unverifiable, Verified};
    match std::fs::symlink_metadata(target) {
        // A launchd path may legitimately be a symlink. Replacement still
        // requires a regular file, but this diagnostic cannot call it broken.
        Ok(m) if m.file_type().is_symlink() => return Unverifiable,
        Ok(m) if m.file_type().is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o111 == 0 {
                    return Invalid;
                }
            }
        }
        Ok(_) => return Invalid,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Invalid,
        Err(_) => return Unverifiable,
    }
    let Ok(signer) = resolve_signer(policy, probe, pin_supported) else {
        // A missing or invalid trusted anchor is policy uncertainty about the
        // target; it does not establish that the target itself is broken.
        return Unverifiable;
    };
    match probe.signature(target, &signer) {
        ProbeOutcome::Ok(_) => {}
        // Failure to satisfy this signer's requirement is not evidence of an
        // unrunnable executable. Never execute it to settle that uncertainty.
        ProbeOutcome::Failed
        | ProbeOutcome::Signaled(_)
        | ProbeOutcome::TimedOut
        | ProbeOutcome::Unavailable => return Unverifiable,
    }
    match probe.version_probe(target) {
        ProbeOutcome::Ok(line) => Verified(line),
        ProbeOutcome::Failed | ProbeOutcome::Signaled(_) => Invalid,
        ProbeOutcome::TimedOut | ProbeOutcome::Unavailable => Unverifiable,
    }
}

/// Verify an installed CLI with the real probe, retaining failed-check versus
/// could-not-check outcomes. Signature verification always precedes execution.
pub fn installed_cli_verification(
    target: &Path,
    policy: &SignerPolicy,
) -> InstalledCliVerification {
    installed_cli_verification_with(target, policy, &SystemShimProbe, cfg!(target_os = "macos"))
}

/// The verified installed version line (for doctor and the desktop plist gate).
pub fn installed_verified_version_line(target: &Path, policy: &SignerPolicy) -> Option<String> {
    match installed_cli_verification(target, policy) {
        InstalledCliVerification::Verified(line) => Some(line),
        InstalledCliVerification::Invalid | InstalledCliVerification::Unverifiable => None,
    }
}

/// Run a fixed-argument diagnostic command with the same scrubbed environment,
/// process-group cleanup, output cap and deadline as shim probes.
pub fn probe_command(cmd: std::process::Command) -> ProbeOutcome<Vec<u8>> {
    outcome_of(run_bounded(cmd, SHIM_PROBE_TIMEOUT))
}

/// Session-title decorations use a shorter deadline and a larger table ceiling
/// than CLI diagnostic probes. Keep the same reserved process-group cleanup and
/// deadline-bound pipe reads, including when descendants retain stdout.
#[cfg(target_os = "macos")]
pub(crate) fn probe_command_with_limits(
    cmd: std::process::Command,
    timeout: std::time::Duration,
    output_cap: u64,
) -> ProbeOutcome<Vec<u8>> {
    outcome_of(run_bounded_with_limits(
        cmd,
        timeout,
        output_cap,
        &mut sigkill_group,
        &mut std::time::Instant::now,
        &mut |cmd| cmd.spawn(),
    ))
}

/// Bounded command status, retaining completed nonzero codes. Launchd's
/// targeted `list` returns 113 for an absent job; timeout/spawn failure must
/// never be mistaken for that definitive absence.
pub fn probe_command_exit_code(cmd: std::process::Command) -> ProbeOutcome<i32> {
    match run_bounded(cmd, SHIM_PROBE_TIMEOUT) {
        Bounded::Done {
            code: Some(code), ..
        } => ProbeOutcome::Ok(code),
        Bounded::Done {
            signal: Some(signal),
            ..
        } => ProbeOutcome::Signaled(signal),
        Bounded::Done { .. } => ProbeOutcome::Failed,
        Bounded::TimedOut => ProbeOutcome::TimedOut,
        Bounded::SpawnFailed => ProbeOutcome::Unavailable,
    }
}

/// Is the installed CLI at `target` runnable AND signed per `policy`?
pub fn installed_cli_verifies(target: &Path, policy: &SignerPolicy) -> bool {
    installed_verified_version_line(target, policy).is_some()
}

/// Verify a regular executable's signature without running its code. Used both
/// before stopping a managed job and immediately before rollback reload.
pub fn installed_cli_signature_verifies(target: &Path, policy: &SignerPolicy) -> bool {
    installed_cli_signature_verifies_with(
        target,
        policy,
        &SystemShimProbe,
        cfg!(target_os = "macos"),
    )
}

fn installed_cli_signature_verifies_with(
    target: &Path,
    policy: &SignerPolicy,
    probe: &dyn ShimProbe,
    pin_supported: bool,
) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(target) else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    let Ok(signer) = resolve_signer(policy, probe, pin_supported) else {
        return false;
    };
    matches!(probe.strict_signature(target, &signer), ProbeOutcome::Ok(_))
}

/// Parse `MAJOR.MINOR.PATCH` out of a `csq --version` stdout line (`csq 2.19.0
/// (enterprise)` or a bare `2.19.0`). A pre-release/build suffix is truncated at
/// the first `-` or `+` (so `2.19.0-rc1` equals `2.19.0`: the safe direction for
/// a downgrade guard). `None` for anything not three integers.
pub fn parse_version_triple(stdout: &str) -> Option<(u64, u64, u64)> {
    for token in stdout.split_whitespace() {
        let core = token
            .split(['-', '+'])
            .next()
            .unwrap_or(token)
            .trim_start_matches(['v', 'V']);
        let mut parts = core.split('.');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if let (Ok(a), Ok(b), Ok(c)) = (a.parse::<u64>(), b.parse::<u64>(), c.parse::<u64>()) {
            return Some((a, b, c));
        }
    }
    None
}

/// Is the installed `--version` output STRICTLY newer than `bundle_version`?
/// `false` on ambiguity (an unparseable target is not a working csq; the refresh
/// repairs it).
pub fn version_output_is_newer_than(stdout: &str, bundle_version: &str) -> bool {
    match (
        parse_version_triple(stdout),
        parse_version_triple(bundle_version),
    ) {
        (Some(installed), Some(bundle)) => installed > bundle,
        _ => false,
    }
}

/// Refresh `target` to a real-file copy of `source`, under one invariant: **the
/// refresh never MAKES `target` unrunnable.** (A target that is already broken
/// stays broken when every candidate is rejected.)
///
/// The target's version/edition CLAIM is only trusted once its signature has
/// verified under the pinned signer; an unverified target is "not newer, not
/// authoritative" and is simply refreshed. Order:
///
/// 1. Verify the installed target (signature, then exec) → its claimed line.
/// 2. Guards on that VERIFIED claim: a community bundle never overwrites an
///    enterprise CLI; no bundle ever overwrites a strictly newer CLI.
/// 3. Skip when the claim equals `expected_version` (version + edition).
/// 4. Otherwise write a temp file (exclusive create), VERIFY it, then — under the
///    shared replace lock — re-check the temp file and that the target is still
///    what step 1 saw, and `atomic_replace`. Failure removes the temp file, keeps
///    the old target and returns [`ShimOutcome::Rejected`] with a fixed tag.
pub fn ensure_cli_shim_with(
    source: &Path,
    target: &Path,
    probe: &dyn ShimProbe,
    expected_version: &str,
    policy: &SignerPolicy,
) -> Result<ShimOutcome> {
    ensure_cli_shim_impl(
        source,
        target,
        probe,
        expected_version,
        policy,
        cfg!(target_os = "macos"),
    )
}

fn ensure_cli_shim_impl(
    source: &Path,
    target: &Path,
    probe: &dyn ShimProbe,
    expected_version: &str,
    policy: &SignerPolicy,
    pin_supported: bool,
) -> Result<ShimOutcome> {
    let link_meta = std::fs::symlink_metadata(target);
    let is_symlink = link_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let exists = link_meta.is_ok();
    // Every decision below (guards/skip/replace) is made against THIS state.
    let decided_stamp = stamp_of(target);

    // Never copy onto ourselves (e.g. the bundle exe is itself on PATH and the
    // target resolves to the source). Apply the self-copy guard ONLY for
    // regular-file targets: a SYMLINK at the CLI path — even one pointing at the
    // source — MUST be replaced, because `mode::detect` canonicalizes it back
    // into the bundle and launches Desktop mode for a terminal `csq`.
    if !is_symlink {
        if let (Ok(s), Ok(t)) = (source.canonicalize(), target.canonicalize()) {
            if s == t {
                return Ok(ShimOutcome::SkippedSameFile);
            }
        }
    }

    let signer = match resolve_signer(policy, probe, pin_supported) {
        Ok(s) => s,
        Err(tag) => return Ok(ShimOutcome::Rejected(tag)),
    };

    // The target's claimed version line, trusted ONLY after its signature
    // verified (signature first: an unverified binary is never exec'd).
    let installed_line = if exists && !is_symlink {
        verified_version_line(probe, target, &signer)
    } else {
        None
    };

    // For an ENTERPRISE bundle edition wins over version (`edition-safe-install.md`:
    // never leave a host on the wrong edition): a verified COMMUNITY CLI, however
    // new, is replaced rather than kept as "newer".
    if let Some(line) = &installed_line {
        if expected_version.contains("(community)") && line.contains("(enterprise)") {
            return Ok(ShimOutcome::Rejected(REASON_EDITION_DOWNGRADE));
        }
        if expected_version.contains("(enterprise)") && line.contains("(community)") {
            tracing::warn!(
                tag = TAG_EDITION_MISMATCH_REPLACED,
                "verified community CLI will be replaced by the enterprise bundle"
            );
        } else if version_output_is_newer_than(line, expected_version) {
            return Ok(ShimOutcome::Rejected(REASON_TARGET_NEWER));
        }
    }

    let outcome = if !exists {
        ShimOutcome::Installed
    } else if is_symlink {
        // A symlink target breaks `csq` in the terminal (mode::detect resolves
        // it into the bundle → Desktop mode). Always replace it with a real copy.
        ShimOutcome::ReplacedNonRegular
    } else if installed_line.is_some() && files_identical(source, target).unwrap_or(false) {
        return Ok(ShimOutcome::NoOp);
    } else if installed_line
        .as_deref()
        .is_some_and(|l| normalize_version_line(l) == normalize_version_line(expected_version))
    {
        return Ok(ShimOutcome::SkippedAlreadyCurrent);
    } else {
        ShimOutcome::Updated
    };

    // An enterprise (pinned) refresh whose only source is the bundle's main
    // executable can never verify standalone — say so rather than failing deep
    // in codesign. Decided from the path alone (no codesign call).
    if matches!(signer, Signer::Team(_)) && is_desktop_launching_path(source) {
        return Ok(ShimOutcome::Rejected(REASON_SOURCE_BUNDLE_BOUND));
    }

    let bytes = std::fs::read(source)
        .with_context(|| format!("read source binary {}", source.display()))?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Fresh temp file + atomic_replace (rename) — NEVER `cp` (provenance/
    // Gatekeeper) and NEVER a symlink (mode::detect canonicalize trap). The
    // create is EXCLUSIVE so a planted symlink/file at the temp path fails.
    let tmp = candidate_tmp_path(target);
    let written = match write_new_exclusive(&tmp, &bytes) {
        Ok(id) => id,
        Err(e) => {
            remove_unless_foreign(&tmp, &e);
            return Err(e).with_context(|| format!("write temp shim {}", tmp.display()));
        }
    };
    // Verify BEFORE the swap: a candidate that cannot run must never replace a
    // target that can.
    if let Err(reason) = verify_candidate(probe, &tmp, &signer) {
        let _ = std::fs::remove_file(&tmp);
        return Ok(ShimOutcome::Rejected(reason));
    }
    // From here to the rename, serialize against `csq update` (`apply`), which
    // takes the same lock around ITS rename: the re-check and the rename are one
    // critical section with respect to every cooperating replacer.
    let (attempts, delay) = probe.replace_lock_budget();
    let _guard = match acquire_replace_lock(target, attempts, delay, &mut || {
        probe.on_replace_lock_wait()
    }) {
        Ok(Some(g)) => g,
        Ok(None) => {
            let _ = std::fs::remove_file(&tmp);
            return Ok(ShimOutcome::Rejected(REASON_REPLACE_LOCK_BUSY));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::anyhow!(
                "replace lock {}: {e}",
                replace_lock_path(target).display()
            ));
        }
    };
    // The file we verified must still be the file we wrote ...
    if !tmp_is_unchanged(&tmp, &written) {
        let _ = std::fs::remove_file(&tmp);
        return Ok(ShimOutcome::Rejected(REASON_TMP_REPLACED));
    }
    // ... and the target must still be what the decision was made against: a
    // terminal `csq update` landing during the (bounded, possibly long) probes
    // must not be overwritten — least of all downgraded.
    if stamp_of(target) != decided_stamp {
        let _ = std::fs::remove_file(&tmp);
        return Ok(ShimOutcome::Rejected(REASON_TARGET_CHANGED));
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "atomic replace of {} failed: {e}",
            target.display()
        ));
    }
    Ok(outcome)
}

/// Volume/device and full file index of a file we created.
type FileId = (u64, u128);

#[derive(Debug)]
struct WrittenFile {
    identity: FileId,
    len: u64,
    mtime: Option<std::time::SystemTime>,
    // A read-only handle preserves identity without preventing real execution.
    _file: std::fs::File,
}

fn open_candidate_readonly(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A swapped symlink must not be followed; a swapped FIFO must not wait.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .context("open temp shim identity handle")?;
    if !file
        .metadata()
        .context("stat temp shim identity handle")?
        .is_file()
    {
        anyhow::bail!("temp shim identity handle is not a regular file");
    }
    Ok(file)
}

fn file_identity(file: &std::fs::File) -> Result<FileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().context("fstat temp shim")?;
        Ok((m.dev(), u128::from(m.ino())))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
        };
        let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
        // SAFETY: File owns a live handle; the writable buffer and its exact
        // size match FileIdInfo. Read the initialized buffer only on success.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as _,
                FileIdInfo,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error()).context("identify temp shim");
        }
        // SAFETY: successful FileIdInfo query initialized the entire struct.
        let info = unsafe { info.assume_init() };
        Ok((
            info.VolumeSerialNumber,
            u128::from_le_bytes(info.FileId.Identifier),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        anyhow::bail!("temp shim file identity unavailable")
    }
}

/// Create `path` EXCLUSIVELY (`O_EXCL`: fails on any existing entry, including a
/// planted symlink), write `bytes`, set 0o755 through the open fd, and return
/// the file's identity.
fn write_new_exclusive(path: &Path, bytes: &[u8]) -> Result<WrittenFile> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("exclusive create {}", path.display()))?;
    f.write_all(bytes).context("write shim bytes")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("set 0o755 on {}", path.display()))?;
    }
    f.flush().context("flush shim")?;
    let identity = file_identity(&f)?;
    let m = f.metadata().context("fstat temp shim")?;
    // Reserve the original object until its read-only lease is authenticated.
    // Keeping the write handle across verification would make exec fail ETXTBSY.
    let readonly = open_candidate_readonly(path)?;
    let read_metadata = readonly.metadata().context("stat read-only temp shim")?;
    if file_identity(&readonly)? != identity
        || read_metadata.len() != m.len()
        || read_metadata.modified().ok() != m.modified().ok()
    {
        anyhow::bail!("temp shim changed while acquiring identity handle");
    }
    drop(f);
    Ok(WrittenFile {
        identity,
        len: m.len(),
        mtime: m.modified().ok(),
        _file: readonly,
    })
}

/// Is `path` still the regular file (not a symlink) we created?
fn tmp_is_unchanged(path: &Path, written: &WrittenFile) -> bool {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !m.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (m.dev(), u128::from(m.ino())) == written.identity
            && m.len() == written.len
            && m.modified().ok() == written.mtime
    }
    #[cfg(windows)]
    {
        let Ok(file) = open_candidate_readonly(path) else {
            return false;
        };
        let Ok(m) = file.metadata() else {
            return false;
        };
        m.is_file()
            && file_identity(&file).ok() == Some(written.identity)
            && m.len() == written.len
            && m.modified().ok() == written.mtime
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = written;
        false
    }
}

/// Resolve the *source* binary the shim copies from, given the running
/// executable (`current_exe()`).
///
/// On the enterprise macOS build the running binary is `…/Contents/MacOS/csq`,
/// which is signed `--deep` as the bundle's **main** executable — its signature
/// is bound to `Contents/Info.plist` + the sealed-resources envelope. Copied to
/// a standalone path (`~/.local/bin/csq`), that bundle-bound signature is invalid
/// (`invalid Info.plist`), so a hardened-runtime Gatekeeper exec SIGKILLs the CLI
/// (exit 137) — GH an internal ticket. The provenance xattr the copy also picks up is
/// incidental; the broken signature is the load-bearing cause.
///
/// The enterprise signing runbook (`docs/release-signing.md` §2a) ships a
/// **standalone-signed** copy of the same binary at `…/Contents/Helpers/csq-cli`
/// — signed WITHOUT bundle binding, so its signature stays valid at any path.
/// When that helper is present we copy IT; the copied file is then a real,
/// standalone-valid binary that runs in the terminal and (being byte-stable)
/// makes [`ensure_cli_shim`]'s identity check a clean no-op on later launches
/// (no re-sign churn, no recurrence loop).
///
/// Fallback (no helper present — the community ad-hoc build, which does NOT
/// exhibit an internal ticket, or any non-bundle layout): return `current_exe` unchanged, i.e.
/// today's behavior.
pub fn resolve_shim_source(current_exe: &Path) -> PathBuf {
    // The helper sits at `…/Contents/Helpers/csq-cli`, sibling to the running
    // exe's `…/Contents/MacOS/` directory. Only look for it when the running exe
    // is under a `Contents/MacOS/` bundle layout.
    if let Some(macos_dir) = current_exe.parent() {
        if macos_dir.file_name().and_then(|n| n.to_str()) == Some("MacOS") {
            if let Some(contents_dir) = macos_dir.parent() {
                let helper = contents_dir.join("Helpers").join("csq-cli");
                // The `is_file()` → later `read()` (in `ensure_cli_shim`) gap is a
                // TOCTOU window, but it is bounded by the same-user / in-bundle
                // threat model: swapping `Contents/Helpers/csq-cli` requires write
                // access inside the running, Gatekeeper-validated `.app` bundle —
                // a strictly larger compromise this code neither creates nor widens.
                if helper.is_file() {
                    return helper;
                }
            }
        }
    }
    current_exe.to_path_buf()
}

/// Resolve the CLI shim target: `~/.local/bin/csq` (the canonical `install.sh`
/// location) whenever anything already sits there, else the on-PATH `csq` when
/// it is OUTSIDE an app bundle / AppImage, else `~/.local/bin/csq` as the
/// create-path. Returns `None` only when no home directory resolves and no
/// suitable on-PATH `csq` exists.
///
/// **The canonical location outranks the `$PATH` hit, and that ordering is
/// load-bearing.** This function answers "which csq installation must this app
/// keep in sync with the bundle" — NOT "which csq would a subprocess get". The
/// desktop app resolves the second question through a `$PATH` it seeds itself
/// in `augment_subprocess_path`, which prepends `/opt/homebrew/bin`,
/// `/opt/homebrew/sbin` and `/usr/local/bin` AHEAD of `~/.local/bin`. That
/// ordering is right for locating third-party CLIs (claude / codex / gemini)
/// and wrong for choosing which csq to overwrite. Scope of the claim: the
/// augmentation SKIPS any entry already on the inherited `PATH`, so on a host
/// where both locations are already present in the operator's own order this is
/// a no-op for them and `~/.local/bin` can win. Under the launch context that
/// motivates the augmentation at all — Finder/Dock, i.e. the system-default
/// `PATH`, which carries neither — the prepend applies in full and
/// [`crate::cli_deps::install_path::find_in_path`] returns the homebrew copy,
/// while the operator's own interactive shell runs the `~/.local/bin` one. The shim refresh then keeps a binary nobody runs current
/// and lets the binary everybody runs drift — producing exactly the
/// daemon-vs-CLI version skew the refresh exists to prevent (see this module's
/// header). Measured on the maintainer host 2026-09-12: `.app` 2.18.0 and
/// `/opt/homebrew/bin/csq` byte-identical at 2.18.0 (so the refresh was a
/// silent `NoOp`) against `~/.local/bin/csq` 2.19.0, daemon spawning from the
/// stale path.
///
/// Existence — not regular-file-ness — is the test, because a SYMLINK at the
/// canonical path is precisely the `mode::detect` trap [`ensure_cli_shim`]
/// exists to replace ([`ShimOutcome::ReplacedNonRegular`]). Skipping a symlink
/// here would route the refresh to some other path and leave the trap in place.
pub fn resolve_shim_target() -> Option<PathBuf> {
    // `crate::platform::home::home_dir()`: exactly `dirs::home_dir()` in
    // production (test-hermeticity.md Windows hole fix — see that module's
    // doc comment). Previously this read `$HOME` directly, which returned
    // `None` on native Windows outside Git Bash (no `HOME` set) even though
    // every other call site in csq resolved the profile dir via `dirs`.
    let canonical =
        crate::platform::home::home_dir().map(|home| home.join(".local").join("bin").join("csq"));
    let canonical_occupied = canonical.as_ref().is_some_and(|c| canonical_is_occupied(c));
    resolve_shim_target_from(
        canonical,
        canonical_occupied,
        crate::cli_deps::install_path::find_in_path("csq"),
    )
}

/// Is a REPLACEABLE thing sitting at the canonical CLI path?
///
/// `symlink_metadata` and NOT `metadata`, and the difference is load-bearing
/// for exactly one input: a DANGLING symlink. `metadata()` follows the link,
/// fails to stat the missing referent, and reports the path as free — so the
/// refresh would route to the `$PATH` hit and leave the dangling link in place.
/// That link is the `mode::detect` canonicalize trap: a `csq` there resolves
/// into the bundle and runs the terminal CLI in Desktop mode.
/// [`ensure_cli_shim`] exists to replace it ([`ShimOutcome::ReplacedNonRegular`]),
/// and can only do so if this predicate reports it occupied.
///
/// A DIRECTORY is excluded, and that exclusion is not cosmetic. This path does
/// not only receive the shim copy — `resolve_managed_daemon_exe` falls through
/// to [`resolve_shim_target`] whenever `current_exe()` is inside the bundle,
/// which is every Finder launch, so it also becomes the launchd plist's
/// `ProgramArguments[0]`. Claiming a directory here would make `ensure_cli_shim`
/// fail with a non-fatal warn (recoverable) AND point the managed daemon's exec
/// at a directory (not recoverable — the daemon can never start). Treating it as
/// unoccupied instead falls through to the `$PATH` hit, which at worst refreshes
/// a different real binary.
///
/// Extracted from [`resolve_shim_target`] so the predicate PRODUCTION uses is
/// the one under test — a test that recomputes `symlink_metadata` itself proves
/// a std-library fact and leaves this line unpinned.
fn canonical_is_occupied(path: &Path) -> bool {
    match path.symlink_metadata() {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// [`resolve_shim_target`]'s decision, with its two environment reads
/// (`$HOME`, `$PATH`) injected.
///
/// Split out so the PRECEDENCE is testable without mutating process-global
/// environment — `test-hermeticity.md` forbids the `$HOME`/`$PATH` swap this
/// would otherwise need, and an env-locked test would serialize against every
/// other test in the crate. Same extraction the sibling
/// `version_output_is_enterprise` took in the desktop crate.
fn resolve_shim_target_from(
    canonical: Option<PathBuf>,
    canonical_occupied: bool,
    path_hit: Option<PathBuf>,
) -> Option<PathBuf> {
    if canonical_occupied {
        if let Some(canonical) = canonical {
            return Some(canonical);
        }
    }
    if let Some(p) = path_hit {
        let s = p.to_string_lossy();
        // Skip a PATH hit inside the desktop bundle / AppImage — copying onto or
        // next to the bundle is wrong; fall through to ~/.local/bin.
        let in_bundle =
            s.contains("/Contents/MacOS/") || s.contains(".app/") || s.contains(".AppImage");
        if !in_bundle {
            return Some(p);
        }
    }
    canonical
}

/// True iff both files exist with identical length AND identical bytes. Length
/// is checked first so a differently-sized build short-circuits without reading
/// the full binary.
fn files_identical(a: &Path, b: &Path) -> Result<bool> {
    let (ma, mb) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
    if ma.len() != mb.len() {
        return Ok(false);
    }
    Ok(std::fs::read(a)? == std::fs::read(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_exe(path: &Path, content: &[u8]) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    type Hook = Box<dyn Fn(&Path) + Send + Sync>;

    /// Content-keyed fake. Version line = the file's first line (a path under
    /// `/Contents/MacOS/` is `Unavailable`, because production never execs one);
    /// the signature is invalid iff the content contains `BUNDLE-BOUND`, and a
    /// `Team` signer additionally needs `team=<ID>` in the content. `hook` runs on
    /// every signature check (to simulate a concurrent writer).
    struct FakeProbe {
        cleared: std::sync::atomic::AtomicUsize,
        queried: std::sync::Mutex<Vec<PathBuf>>,
        exec_override: Option<ProbeOutcome<String>>,
        sig_override: Option<ProbeOutcome<()>>,
        hook: Option<Hook>,
        trusted: ProbeOutcome<String>,
        trusted_sequence: std::sync::Mutex<std::collections::VecDeque<ProbeOutcome<String>>>,
        trusted_events: std::sync::Mutex<Vec<&'static str>>,
        lock_budget: Option<(u32, std::time::Duration)>,
        lock_waiting: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl FakeProbe {
        fn new() -> Self {
            Self {
                cleared: Default::default(),
                queried: Default::default(),
                exec_override: None,
                sig_override: None,
                hook: None,
                trusted: ProbeOutcome::Ok("4Y4U35PJHX".to_string()),
                trusted_sequence: Default::default(),
                trusted_events: Default::default(),
                lock_budget: None,
                lock_waiting: Default::default(),
            }
        }
        fn cleared(&self) -> usize {
            self.cleared.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl ShimProbe for FakeProbe {
        fn version_probe(&self, exe: &Path) -> ProbeOutcome<String> {
            self.queried.lock().unwrap().push(exe.to_path_buf());
            if let Some(o) = &self.exec_override {
                return o.clone();
            }
            if exe.to_string_lossy().contains("/Contents/MacOS/") {
                return ProbeOutcome::Unavailable;
            }
            match std::fs::read_to_string(exe)
                .ok()
                .and_then(|c| c.lines().next().map(str::to_string))
                .filter(|l| !l.is_empty())
            {
                Some(l) => ProbeOutcome::Ok(l),
                None => ProbeOutcome::Failed,
            }
        }
        fn trusted_team(&self) -> ProbeOutcome<String> {
            self.trusted_events.lock().unwrap().push("team");
            self.trusted_sequence
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.trusted.clone())
        }
        fn wait_before_trusted_team_retry(&self) {
            self.trusted_events.lock().unwrap().push("delay");
        }
        fn signature(&self, exe: &Path, signer: &Signer) -> ProbeOutcome<()> {
            if let Some(h) = &self.hook {
                h(exe);
            }
            if let Some(o) = &self.sig_override {
                return o.clone();
            }
            let c = std::fs::read_to_string(exe).unwrap_or_default();
            let ok = !c.contains("BUNDLE-BOUND")
                && match signer {
                    Signer::Any => true,
                    Signer::Team(t) => c.contains(&format!("team={t}")),
                };
            if ok {
                ProbeOutcome::Ok(())
            } else {
                ProbeOutcome::Failed
            }
        }
        fn clear_provenance(&self, _exe: &Path) {
            self.cleared
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn replace_lock_budget(&self) -> (u32, std::time::Duration) {
            self.lock_budget
                .unwrap_or((REPLACE_LOCK_ATTEMPTS, REPLACE_LOCK_DELAY))
        }
        fn on_replace_lock_wait(&self) {
            self.lock_waiting
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    const EXPECTED: &str = "2.21.0 (enterprise)";

    fn ensure_cli_shim(source: &Path, target: &Path) -> Result<ShimOutcome> {
        ensure_cli_shim_with(
            source,
            target,
            &FakeProbe::new(),
            EXPECTED,
            &SignerPolicy::AnySignature,
        )
    }

    fn dir_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".csq-replace.lock")
            .collect();
        v.sort();
        v
    }

    const V: &str = "csq 2.21.0 (enterprise)\n";

    fn pinned(src: &Path, target: &Path, probe: &FakeProbe, expected: &str) -> Result<ShimOutcome> {
        ensure_cli_shim_impl(
            src,
            target,
            probe,
            expected,
            &SignerPolicy::PinTrustedTeam,
            true,
        )
    }

    #[test]
    fn unverified_target_claiming_a_newer_version_is_refreshed_not_skipped() {
        // B1: a planted (unsigned / wrong-team) csq printing 99.0.0 must NOT be
        // treated as "newer": its claim is not authoritative until it verifies.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}team=4Y4U35PJHX standalone").as_bytes());
        for planted in [
            "csq 99.0.0 (enterprise)\nadhoc-planted",
            "csq 99.0.0 (enterprise)\nteam=AAAAAAAAAA other-team",
        ] {
            let target = dir.path().join(format!(".local/bin/csq{}", planted.len()));
            write_exe(&target, planted.as_bytes());
            let out = pinned(&src, &target, &FakeProbe::new(), EXPECTED).unwrap();
            assert_eq!(out, ShimOutcome::Updated, "{planted}");
        }
    }

    #[test]
    fn verified_newer_target_is_never_downgraded_and_community_never_overwrites_enterprise() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nteam=4Y4U35PJHX new");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.22.0 (enterprise)\nteam=4Y4U35PJHX newer");
        assert_eq!(
            pinned(&src, &target, &FakeProbe::new(), EXPECTED).unwrap(),
            ShimOutcome::Rejected(REASON_TARGET_NEWER)
        );
        write_exe(&target, b"csq 2.21.0 (enterprise)\nsigned-enterprise");
        let out = ensure_cli_shim(&src, &target); // AnySignature, expected enterprise
        assert_eq!(out.unwrap(), ShimOutcome::SkippedAlreadyCurrent);
        let out = ensure_cli_shim_with(
            &src,
            &target,
            &FakeProbe::new(),
            "2.21.0 (community)",
            &SignerPolicy::AnySignature,
        )
        .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_EDITION_DOWNGRADE));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.21.0 (enterprise)\nsigned-enterprise"
        );
    }

    #[test]
    fn source_signed_by_a_different_team_than_the_trusted_anchor_is_rejected() {
        // B2: the pin comes from the trusted anchor, NOT from the source.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}team=AAAAAAAAAA other").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        let out = pinned(&src, &target, &FakeProbe::new(), EXPECTED).unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_SIGNATURE_INVALID));
        assert!(dir_names(target.parent().unwrap()).is_empty());
    }

    #[test]
    fn transient_trusted_team_failure_retries_once_with_delay_and_keeps_team_pin() {
        for first in [ProbeOutcome::TimedOut, ProbeOutcome::Unavailable] {
            let p = FakeProbe::new();
            p.trusted_sequence
                .lock()
                .unwrap()
                .extend([first, ProbeOutcome::Ok("4Y4U35PJHX".into())]);
            assert_eq!(
                resolve_signer(&SignerPolicy::PinTrustedTeam, &p, true),
                Ok(Signer::Team("4Y4U35PJHX".into()))
            );
            assert_eq!(*p.trusted_events.lock().unwrap(), ["team", "delay", "team"]);

            // A recovered anchor still cannot authorize a differently signed
            // candidate: the retry changes availability, never the trust pin.
            let dir = TempDir::new().unwrap();
            let src = dir.path().join("bundle/csq");
            write_exe(&src, format!("{V}team=AAAAAAAAAA other").as_bytes());
            let target = dir.path().join("cli/csq");
            let p = FakeProbe::new();
            p.trusted_sequence
                .lock()
                .unwrap()
                .push_back(ProbeOutcome::TimedOut);
            assert_eq!(
                pinned(&src, &target, &p, EXPECTED).unwrap(),
                ShimOutcome::Rejected(REASON_SIGNATURE_INVALID)
            );
            assert!(!target.exists());
        }
    }

    #[test]
    fn trusted_team_retry_is_bounded_and_never_rescues_an_invalid_anchor() {
        for final_result in [ProbeOutcome::TimedOut, ProbeOutcome::Unavailable] {
            let p = FakeProbe::new();
            p.trusted_sequence.lock().unwrap().extend([
                ProbeOutcome::TimedOut,
                final_result,
                ProbeOutcome::Ok("4Y4U35PJHX".into()),
            ]);
            assert_eq!(
                resolve_signer(&SignerPolicy::PinTrustedTeam, &p, true),
                Err(REASON_SIGNER_UNVERIFIABLE)
            );
            assert_eq!(*p.trusted_events.lock().unwrap(), ["team", "delay", "team"]);
            assert_eq!(p.trusted_sequence.lock().unwrap().len(), 1);
        }
        for invalid in [
            ProbeOutcome::Failed,
            ProbeOutcome::Signaled(9),
            ProbeOutcome::Ok("malformed".into()),
        ] {
            let p = FakeProbe::new();
            p.trusted_sequence
                .lock()
                .unwrap()
                .extend([invalid, ProbeOutcome::Ok("4Y4U35PJHX".into())]);
            assert_eq!(
                resolve_signer(&SignerPolicy::PinTrustedTeam, &p, true),
                Err(REASON_SIGNER_UNPINNED)
            );
            assert_eq!(*p.trusted_events.lock().unwrap(), ["team"]);
        }
        for (policy, pin_supported) in [
            (SignerPolicy::AnySignature, true),
            (SignerPolicy::PinTrustedTeam, false),
        ] {
            let p = FakeProbe::new();
            assert_eq!(resolve_signer(&policy, &p, pin_supported), Ok(Signer::Any));
            assert!(p.trusted_events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn installed_verification_preserves_uncertainty_and_signature_before_exec() {
        use InstalledCliVerification::{Invalid, Unverifiable, Verified};
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("csq");
        write_exe(&target, format!("{V}team=4Y4U35PJHX standalone").as_bytes());
        let policy = SignerPolicy::PinTrustedTeam;
        let p = FakeProbe::new();
        assert_eq!(
            installed_cli_verification_with(&target, &policy, &p, true),
            Verified(V.trim().into())
        );
        for (sig, expected) in [
            (ProbeOutcome::Failed, Unverifiable),
            (ProbeOutcome::Signaled(9), Unverifiable),
            (ProbeOutcome::TimedOut, Unverifiable),
            (ProbeOutcome::Unavailable, Unverifiable),
        ] {
            let mut p = FakeProbe::new();
            p.sig_override = Some(sig);
            assert_eq!(
                installed_cli_verification_with(&target, &policy, &p, true),
                expected
            );
            assert!(
                p.queried.lock().unwrap().is_empty(),
                "never exec an unverified signature"
            );
        }
        for (exec, expected) in [
            (ProbeOutcome::Failed, Invalid),
            (ProbeOutcome::Signaled(9), Invalid),
            (ProbeOutcome::TimedOut, Unverifiable),
            (ProbeOutcome::Unavailable, Unverifiable),
        ] {
            let mut p = FakeProbe::new();
            p.exec_override = Some(exec);
            assert_eq!(
                installed_cli_verification_with(&target, &policy, &p, true),
                expected
            );
        }
        let mut p = FakeProbe::new();
        p.trusted = ProbeOutcome::Failed;
        assert_eq!(
            installed_cli_verification_with(&target, &policy, &p, true),
            Unverifiable
        );
        assert!(p.queried.lock().unwrap().is_empty());
        assert_eq!(
            installed_cli_verification_with(&dir.path().join("absent"), &policy, &p, true),
            Invalid
        );
        assert_eq!(
            installed_cli_verification_with(dir.path(), &policy, &p, true),
            Invalid
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn signature_only_system_probe_reports_unsupported_without_trusting_a_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("csq");
        write_exe(&target, b"unsigned fixture executable");
        assert!(!installed_cli_signature_verifies(
            &target,
            &SignerPolicy::AnySignature
        ));
        assert!(!installed_cli_signature_verifies(
            &target,
            &SignerPolicy::PinTrustedTeam
        ));
    }

    #[test]
    #[cfg(unix)]
    fn installed_verification_does_not_treat_a_symlink_as_a_broken_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let executable = dir.path().join("working-csq");
        write_exe(
            &executable,
            format!("{V}team=4Y4U35PJHX standalone").as_bytes(),
        );
        let link = dir.path().join("csq-link");
        std::os::unix::fs::symlink(&executable, &link).unwrap();
        let probe = FakeProbe::new();
        assert_eq!(
            installed_cli_verification_with(&link, &SignerPolicy::PinTrustedTeam, &probe, true),
            InstalledCliVerification::Unverifiable,
        );
        assert!(probe.trusted_events.lock().unwrap().is_empty());
        assert!(probe.queried.lock().unwrap().is_empty());
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            installed_cli_verification_with(
                &executable,
                &SignerPolicy::PinTrustedTeam,
                &probe,
                true
            ),
            InstalledCliVerification::Invalid,
        );
        assert!(probe.queried.lock().unwrap().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn signature_only_verification_never_executes_or_accepts_links_or_untrusted_team() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("csq");
        write_exe(&target, b"fixture signed team=4Y4U35PJHX");
        let mut probe = FakeProbe::new();
        assert!(installed_cli_signature_verifies_with(
            &target,
            &SignerPolicy::PinTrustedTeam,
            &probe,
            true
        ));
        assert!(probe.queried.lock().unwrap().is_empty());
        probe.sig_override = Some(ProbeOutcome::Failed);
        assert!(!installed_cli_signature_verifies_with(
            &target,
            &SignerPolicy::PinTrustedTeam,
            &probe,
            true
        ));
        assert!(probe.queried.lock().unwrap().is_empty());
        let link = dir.path().join("csq-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!installed_cli_signature_verifies_with(
            &link,
            &SignerPolicy::PinTrustedTeam,
            &FakeProbe::new(),
            true
        ));
        write_exe(&target, b"fixture signed team=OTHERTEAM1");
        let probe = FakeProbe::new();
        assert!(!installed_cli_signature_verifies_with(
            &target,
            &SignerPolicy::PinTrustedTeam,
            &probe,
            true
        ));
        assert!(probe.queried.lock().unwrap().is_empty());
    }

    #[test]
    fn trusted_team_that_cannot_be_read_is_unverifiable_not_unpinned() {
        // N3.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"x");
        let target = dir.path().join(".local/bin/csq");
        for o in [ProbeOutcome::TimedOut, ProbeOutcome::Unavailable] {
            let mut p = FakeProbe::new();
            p.trusted = o;
            assert_eq!(
                pinned(&src, &target, &p, EXPECTED).unwrap(),
                ShimOutcome::Rejected(REASON_SIGNER_UNVERIFIABLE)
            );
        }
    }

    #[test]
    fn off_macos_the_enterprise_policy_resolves_to_any_signer() {
        // F1: no codesign off macOS; pinning there would reject every launch.
        let mut p = FakeProbe::new();
        p.trusted = ProbeOutcome::Failed; // would be signer_unpinned if consulted
        assert_eq!(
            resolve_signer(&SignerPolicy::PinTrustedTeam, &p, false),
            Ok(Signer::Any)
        );
        assert_eq!(
            resolve_signer(&SignerPolicy::PinTrustedTeam, &p, true),
            Err(REASON_SIGNER_UNPINNED)
        );
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}plain").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        let out = ensure_cli_shim_impl(
            &src,
            &target,
            &p,
            EXPECTED,
            &SignerPolicy::PinTrustedTeam,
            false,
        )
        .unwrap();
        assert_eq!(out, ShimOutcome::Installed);
    }

    #[test]
    fn enterprise_with_only_the_bundle_main_exe_reports_source_bundle_bound() {
        // F2: decided from the path alone.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("Q.app/Contents/MacOS/csq");
        write_exe(&src, format!("{V}team=4Y4U35PJHX main").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        assert_eq!(
            pinned(&src, &target, &FakeProbe::new(), EXPECTED).unwrap(),
            ShimOutcome::Rejected(REASON_SOURCE_BUNDLE_BOUND)
        );
        assert!(!target.parent().unwrap().exists(), "nothing created");
    }

    #[cfg(unix)]
    #[test]
    fn group_kill_happens_while_the_leader_is_still_reserved_then_reaps() {
        // B3: at the instant of the kill the exited leader must still be an
        // unreaped zombie (kill(pid,0)==0), so its pid/pgid cannot be recycled.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        for _ in 0..200 {
            if child_exited_nowait(&mut child) == Some(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(child_exited_nowait(&mut child), Some(true));
        let mut reserved_at_kill = None;
        let status = kill_group(&mut child, pid, &mut |_| {
            // SAFETY: signal 0 only probes existence.
            reserved_at_kill = Some(unsafe { libc::kill(pid as i32, 0) } == 0);
        });
        assert_eq!(
            reserved_at_kill,
            Some(true),
            "leader was reaped before the kill"
        );
        assert!(status.is_some_and(|s| s.success()));
        // And it is reaped afterwards.
        assert!(unsafe { libc::kill(pid as i32, 0) } != 0);
    }

    #[cfg(unix)]
    #[test]
    fn replace_lock_serializes_the_refresh_with_a_concurrent_replacer() {
        // I1: while another replacer holds the lock the refresh WAITS (observed
        // through the on_replace_lock_wait hook, not a sleep); when it proceeds it
        // re-checks the target UNDER the lock and aborts.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nbundle");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let mut guard = Some(
            acquire_replace_lock(&target, 1, std::time::Duration::ZERO, &mut || {})
                .unwrap()
                .unwrap(),
        );
        let probe = FakeProbe::new();
        let waiting = probe.lock_waiting.clone();
        let (s2, t2) = (src.clone(), target.clone());
        let h = std::thread::spawn(move || {
            ensure_cli_shim_with(&s2, &t2, &probe, EXPECTED, &SignerPolicy::AnySignature).unwrap()
        });
        let t0 = std::time::Instant::now();
        while !waiting.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(20),
                "never waited"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold",
            "target untouched while the lock is held"
        );
        // The concurrent replacer (csq update) lands while holding the lock.
        let upd = target.with_file_name("csq.upd");
        std::fs::write(&upd, b"csq 2.22.0 (enterprise)\nupdated").unwrap();
        std::fs::rename(&upd, &target).unwrap();
        drop(guard.take());
        assert_eq!(
            h.join().unwrap(),
            ShimOutcome::Rejected(REASON_TARGET_CHANGED)
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.22.0 (enterprise)\nupdated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn held_replace_lock_gives_busy_within_the_bound_and_cleans_up() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nbundle");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let _held = acquire_replace_lock(&target, 1, std::time::Duration::ZERO, &mut || {})
            .unwrap()
            .unwrap();
        let mut probe = FakeProbe::new();
        probe.lock_budget = Some((3, std::time::Duration::from_millis(50)));
        let t0 = std::time::Instant::now();
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_REPLACE_LOCK_BUSY));
        assert!(t0.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold"
        );
        assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_replace_lock_path_is_refused_not_followed() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nbundle");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, replace_lock_path(&target)).unwrap();
        let r = ensure_cli_shim(&src, &target);
        assert!(r.is_err(), "a symlinked lock path must be refused: {r:?}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold"
        );
        assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
    }

    #[test]
    fn enterprise_bundle_replaces_a_verified_newer_community_cli() {
        // Edition wins over version for an enterprise bundle (signer Any = the
        // Linux/Windows shape).
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nnew-enterprise");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.22.0 (community)\nnewer-community");
        let out = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(out, ShimOutcome::Updated);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.21.0 (enterprise)\nnew-enterprise"
        );
        // Same-edition newer is still kept.
        write_exe(&target, b"csq 2.22.0 (enterprise)\nnewer");
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::Rejected(REASON_TARGET_NEWER)
        );
    }

    #[test]
    fn verified_version_line_returns_a_claim_only_for_a_verified_regular_file() {
        let dir = TempDir::new().unwrap();
        let p = FakeProbe::new();
        let bad = dir.path().join("bad");
        write_exe(&bad, b"csq 9.9.9 (enterprise)\nBUNDLE-BOUND");
        assert_eq!(verified_version_line(&p, &bad, &Signer::Any), None);
        let good = dir.path().join("good");
        write_exe(&good, b"csq 2.0.0 (enterprise)\nok");
        assert_eq!(
            verified_version_line(&p, &good, &Signer::Any).as_deref(),
            Some("csq 2.0.0 (enterprise)")
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&good, &link).unwrap();
            assert_eq!(verified_version_line(&p, &link, &Signer::Any), None);
        }
        assert_eq!(
            verified_version_line(&p, &dir.path().join("nope"), &Signer::Any),
            None
        );
    }

    #[test]
    fn running_team_is_trusted_only_after_the_dynamic_verify_passes() {
        let one = || ShownTeam::One("4Y4U35PJHX".to_string());
        let compiled = || ProbeOutcome::Ok("ZZZZZZZZZZ".to_string());
        assert_eq!(
            trust_running_team(one(), |_| ProbeOutcome::Ok(()), compiled()),
            ProbeOutcome::Ok("4Y4U35PJHX".to_string())
        );
        // A displayed team whose verify FAILS (or is signalled) fails closed, even
        // when a compiled-in team exists: it is NOT a fallback.
        for o in [ProbeOutcome::Failed, ProbeOutcome::Signaled(9)] {
            assert_eq!(
                trust_running_team(one(), |_| o.clone(), compiled()),
                ProbeOutcome::Failed
            );
        }
        // Ambiguous display: fail closed, verify never consulted, compiled ignored.
        assert_eq!(
            trust_running_team(
                ShownTeam::Ambiguous,
                |_| panic!("verify must not run on an ambiguous display"),
                compiled()
            ),
            ProbeOutcome::Failed
        );
        assert_eq!(
            trust_running_team(one(), |_| ProbeOutcome::TimedOut, compiled()),
            ProbeOutcome::TimedOut
        );
        // Nothing displayed (unsigned dev build): ONLY now the compiled team is used.
        assert_eq!(
            trust_running_team(
                ShownTeam::None,
                |_| panic!("verify must not run without a team"),
                compiled()
            ),
            ProbeOutcome::Ok("ZZZZZZZZZZ".to_string())
        );
        assert_eq!(
            trust_running_team(ShownTeam::None, |_| panic!(), ProbeOutcome::Failed),
            ProbeOutcome::Failed
        );
    }

    #[test]
    fn two_team_identifier_lines_are_ambiguous_and_untrusted() {
        // An `Executable=` path containing a newline can inject a line.
        let injected =
            "Executable=/x\nTeamIdentifier=AAAAAAAAAA\nIdentifier=y\nTeamIdentifier=4Y4U35PJHX\n";
        assert_eq!(parse_team_identifier(injected), ShownTeam::Ambiguous);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_verify_of_our_own_pid_rejects_a_team_we_are_not_signed_by() {
        // The test binary is not Developer-ID signed by any team.
        assert_ne!(verify_running_team("4Y4U35PJHX"), ProbeOutcome::Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn group_kill_sees_the_leader_unreaped_through_the_real_wait_loop() {
        // B3: through the REAL run_bounded path, at the instant of the group kill
        // the exited leader must still be a reserved zombie (waitid(WNOWAIT)==0).
        // A `try_wait` poll would have reaped it already (waitid -> ECHILD).
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"]);
        let mut observed: Option<bool> = None;
        let out = run_bounded_with(cmd, std::time::Duration::from_secs(10), &mut |pgid| {
            // SAFETY: zeroed siginfo_t is a valid out-param; waitid(WNOWAIT) only observes.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pgid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            observed = Some(r == 0);
            sigkill_group(pgid);
        });
        assert_eq!(observed, Some(true), "leader reaped before the group kill");
        assert!(
            matches!(out, Bounded::Done { code: Some(7), .. }),
            "{out:?}"
        );
    }

    #[test]
    fn a_foreign_path_at_the_temp_name_is_not_removed() {
        // N2.
        let dir = TempDir::new().unwrap();
        let planted = dir.path().join("planted");
        std::fs::write(&planted, b"not ours").unwrap();
        let e = write_new_exclusive(&planted, b"x").unwrap_err();
        remove_unless_foreign(&planted, &e);
        assert!(planted.exists(), "a path we did not create must survive");
        let ours = dir.path().join("ours");
        std::fs::write(&ours, b"ours").unwrap();
        remove_unless_foreign(&ours, &anyhow::anyhow!("some other failure"));
        assert!(!ours.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_candidate_temp_name_ends_in_exe() {
        let p = candidate_tmp_path(Path::new("C:\\u\\csq.exe"));
        assert!(p.to_string_lossy().ends_with(".exe"));
    }

    #[test]
    fn skips_when_installed_cli_has_same_version_edition_and_verifies() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}BUNDLE-BOUND-main").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, format!("{V}standalone-signed").as_bytes());

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::SkippedAlreadyCurrent);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            format!("{V}standalone-signed").as_bytes(),
            "a good installed CLI must not be touched"
        );
    }

    #[test]
    fn source_under_contents_macos_is_never_exec_probed_and_skip_is_reachable() {
        // B1: the bundle main exe resolves to Desktop mode; exec'ing it launches
        // the app. The skip must work WITHOUT ever querying the source.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("Q.app/Contents/MacOS/csq");
        write_exe(&src, format!("{V}BUNDLE-BOUND-main").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, format!("{V}standalone-signed").as_bytes());
        let probe = FakeProbe::new();
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::SkippedAlreadyCurrent);
        assert!(
            !probe.queried.lock().unwrap().iter().any(|p| p == &src),
            "the source must never be exec-probed"
        );
    }

    #[test]
    fn desktop_launching_paths_are_never_exec_probe_candidates() {
        assert!(is_desktop_launching_path(Path::new(
            "/Applications/Q.app/Contents/MacOS/csq"
        )));
        assert!(is_desktop_launching_path(Path::new("/opt/x/csq.AppImage")));
        assert!(!is_desktop_launching_path(Path::new(
            "/Users/u/.local/bin/csq.tmp.1"
        )));
        assert!(!is_desktop_launching_path(Path::new(
            "/Applications/Q.app/Contents/Helpers/csq-cli"
        )));
    }

    #[test]
    fn same_version_but_different_edition_is_refreshed_not_skipped() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nnew");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.21.0 (community)\nold");
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::Updated
        );
    }

    #[test]
    fn same_version_but_installed_signature_broken_is_not_skipped() {
        // The 2.20.2 host state: same version line, signature invalid.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}standalone-ok").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, format!("{V}BUNDLE-BOUND-copy").as_bytes());
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::Updated
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            format!("{V}standalone-ok").as_bytes()
        );
    }

    #[test]
    fn enterprise_adhoc_target_with_matching_version_is_not_skipped() {
        // H1: an ad-hoc (planted) csq reporting the right version line must NOT
        // be kept on enterprise — it is the launchd daemon's ProgramArguments[0].
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}team=4Y4U35PJHX standalone").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, format!("{V}adhoc-planted").as_bytes());
        let out = ensure_cli_shim_impl(
            &src,
            &target,
            &FakeProbe::new(),
            EXPECTED,
            &SignerPolicy::PinTrustedTeam,
            true,
        )
        .unwrap();
        assert_eq!(out, ShimOutcome::Updated);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            format!("{V}team=4Y4U35PJHX standalone").as_bytes()
        );
        // Same target under the community policy IS kept (any signature).
        write_exe(&target, format!("{V}adhoc-planted").as_bytes());
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::SkippedAlreadyCurrent
        );
    }

    #[test]
    fn enterprise_without_derivable_team_fails_closed() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}no-team-here").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let mut probe = FakeProbe::new();
        probe.trusted = ProbeOutcome::Failed;
        let out = ensure_cli_shim_impl(
            &src,
            &target,
            &probe,
            EXPECTED,
            &SignerPolicy::PinTrustedTeam,
            true,
        )
        .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_SIGNER_UNPINNED));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold"
        );
    }

    #[test]
    fn verification_failure_keeps_old_target_and_removes_tmp() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nBUNDLE-BOUND-main");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.2 (enterprise)\nold-good");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::Rejected(REASON_SIGNATURE_INVALID));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.2 (enterprise)\nold-good",
            "old file must survive a failed verification"
        );
        assert_eq!(
            dir_names(target.parent().unwrap()),
            vec!["csq".to_string()],
            "tmp must be removed on the verification-failure branch"
        );
    }

    #[test]
    fn verification_failure_on_fresh_install_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nBUNDLE-BOUND-main");
        let target = dir.path().join(".local/bin/csq");
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::Rejected(REASON_SIGNATURE_INVALID)
        );
        assert!(dir_names(target.parent().unwrap()).is_empty());
    }

    #[test]
    fn identical_bytes_but_unverifiable_target_is_not_a_noop() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, format!("{V}BUNDLE-BOUND").as_bytes());
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, format!("{V}BUNDLE-BOUND").as_bytes());
        assert_eq!(
            ensure_cli_shim(&src, &target).unwrap(),
            ShimOutcome::Rejected(REASON_SIGNATURE_INVALID)
        );
    }

    #[test]
    fn exec_failure_or_signal_clears_xattrs_once_then_rejects() {
        // I3: a non-zero exit / signal (SIGKILL 9) retries once after `xattr -c`.
        for o in [ProbeOutcome::Failed, ProbeOutcome::Signaled(9)] {
            let dir = TempDir::new().unwrap();
            let src = dir.path().join("bundle/csq");
            write_exe(&src, b"x-new");
            let target = dir.path().join(".local/bin/csq");
            write_exe(&target, b"x-old");
            let mut probe = FakeProbe::new();
            probe.exec_override = Some(o.clone());
            let out =
                ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                    .unwrap();
            assert_eq!(
                out,
                ShimOutcome::Rejected(REASON_EXEC_PROBE_FAILED),
                "{o:?}"
            );
            assert_eq!(probe.cleared(), 1, "{o:?}");
            assert_eq!(std::fs::read(&target).unwrap(), b"x-old");
            assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
        }
    }

    #[test]
    fn exec_timeout_or_unavailable_never_clears_xattrs_and_is_unverifiable() {
        // I2/I3: "could not check" is its own tag and never triggers `xattr -c`.
        for o in [ProbeOutcome::TimedOut, ProbeOutcome::Unavailable] {
            let dir = TempDir::new().unwrap();
            let src = dir.path().join("bundle/csq");
            write_exe(&src, b"x-new");
            let target = dir.path().join(".local/bin/csq");
            write_exe(&target, b"x-old");
            let mut probe = FakeProbe::new();
            probe.exec_override = Some(o.clone());
            let out =
                ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                    .unwrap();
            assert_eq!(
                out,
                ShimOutcome::Rejected(REASON_EXEC_PROBE_UNVERIFIABLE),
                "{o:?}"
            );
            assert_eq!(probe.cleared(), 0, "{o:?}");
            assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
        }
    }

    #[test]
    fn signature_check_that_cannot_run_is_unverifiable_not_invalid() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"x-new");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"x-old");
        let mut probe = FakeProbe::new();
        probe.sig_override = Some(ProbeOutcome::TimedOut);
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_SIGNATURE_UNVERIFIABLE));
    }

    #[test]
    fn noop_check_never_clears_xattrs_on_the_installed_target() {
        // H3: the read-only verify must not run `xattr -c` on the live target,
        // even when its exec check fails.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"same-bytes");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"same-bytes");
        let mut probe = FakeProbe::new();
        probe.exec_override = Some(ProbeOutcome::Failed);
        let _ = ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature);
        // Exactly the candidate's single retry — the target's own check added none.
        assert_eq!(probe.cleared(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn readonly_candidate_handle_refuses_symlinks_directories_and_fifos() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let regular = dir.path().join("regular");
        std::fs::write(&regular, b"candidate").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(open_candidate_readonly(&link).is_err());
        assert!(open_candidate_readonly(dir.path()).is_err());
        let fifo = dir.path().join("fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a terminated path in this test's private tempdir, valid mode;
        // mkfifo reads the pointer only during the call and stores no reference.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        // No FIFO writer exists: a blocking read-open would hang here.
        assert!(open_candidate_readonly(&fifo).is_err());
    }

    /// Spawn `cmd` and wait for it, retrying only while the exec itself fails
    /// with ETXTBSY (`ExecutableFileBusy`). A sibling test thread that forks
    /// while `write_new_exclusive`'s write fd is still open passes that
    /// descriptor into its child; Linux refuses `execve` on a file some process
    /// holds open for writing until that fork's child execs or exits. That is a
    /// transient harness race, not a persistent condition — but the retry is
    /// bounded, so a genuinely stuck file still fails fast instead of hanging.
    #[cfg(target_os = "linux")]
    fn exec_retrying_etxtbsy(
        cmd: &mut std::process::Command,
    ) -> std::io::Result<std::process::ExitStatus> {
        const DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);
        const STEP: std::time::Duration = std::time::Duration::from_millis(20);
        let start = std::time::Instant::now();
        loop {
            match cmd.status() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    if start.elapsed() >= DEADLINE {
                        return Err(e);
                    }
                    std::thread::sleep(STEP);
                }
                other => return other,
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_candidate_identity_handle_allows_real_execution() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("candidate");
        let bytes = std::fs::read("/bin/true").unwrap();
        let written = write_new_exclusive(&tmp, &bytes).unwrap();
        let mut cmd = std::process::Command::new(&tmp);
        cmd.env_clear()
            .env("HOME", dir.path())
            .env("CSQ_BASE_DIR", dir.path().join("base"));
        let result = exec_retrying_etxtbsy(&mut cmd);
        assert!(
            result.as_ref().is_ok_and(|status| status.success()),
            "{result:?}"
        );
        assert!(tmp_is_unchanged(&tmp, &written));
    }

    /// Deterministic instance of the ETXTBSY race above: a forked child inherits
    /// THIS test's open write handle on the target and holds it past the first
    /// exec attempt, so a single `status()` fails with `ExecutableFileBusy` and
    /// only the retry can succeed. The child is restricted to async-signal-safe
    /// calls (`nanosleep`, `_exit`): after `fork` in a threaded test process it
    /// must not allocate or touch a lock another thread may hold.
    #[cfg(target_os = "linux")]
    #[test]
    fn exec_retry_survives_an_inherited_write_handle() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("candidate");
        // `fs::copy` copies the source mode, so this is executable (0o755).
        std::fs::copy("/bin/true", &target).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap();

        let delay = libc::timespec {
            tv_sec: 0,
            tv_nsec: 150_000_000,
        };
        // SAFETY: `fork` has no memory-safety preconditions. The child calls
        // ONLY async-signal-safe functions before `_exit`; the inherited write
        // descriptor is exactly the state the test needs it to keep open.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: async-signal-safe calls only — no allocation, no locks.
            unsafe {
                libc::nanosleep(&delay, std::ptr::null_mut());
                libc::_exit(0);
            }
        }
        // Only the child still holds the write handle now.
        drop(writer);

        let mut cmd = std::process::Command::new(&target);
        cmd.env_clear();
        let result = exec_retrying_etxtbsy(&mut cmd);
        let mut child_status: libc::c_int = 0;
        // SAFETY: `pid` is the child created above, reaped exactly once here.
        assert_eq!(unsafe { libc::waitpid(pid, &mut child_status, 0) }, pid);
        assert!(libc::WIFEXITED(child_status));

        assert!(
            result.as_ref().is_ok_and(|status| status.success()),
            "retry did not outlast the inherited write handle: {result:?}"
        );
    }

    #[test]
    fn temp_replacement_with_matching_bytes_and_metadata_is_refused() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("candidate");
        let written = write_new_exclusive(&tmp, b"same bytes").unwrap();
        assert!(tmp_is_unchanged(&tmp, &written));
        let other = dir.path().join("replacement");
        std::fs::write(&other, b"same bytes").unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&other)
            .unwrap();
        file.set_modified(std::fs::metadata(&tmp).unwrap().modified().unwrap())
            .unwrap();
        drop(file);
        std::fs::rename(&other, &tmp).unwrap();
        assert!(!tmp_is_unchanged(&tmp, &written));
    }

    #[test]
    fn temp_modified_in_place_during_verification_is_refused() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nnew");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let mut probe = FakeProbe::new();
        probe.hook = Some(Box::new(|p: &Path| {
            if p.file_name().is_some_and(|n| n != "csq") {
                std::fs::write(p, b"csq 2.21.0 (enterprise)\nmodified after verification").unwrap();
            }
        }));
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_TMP_REPLACED));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold"
        );
        assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
    }

    #[test]
    fn temp_swapped_during_verification_is_refused() {
        // M1: replace the temp path with a different file after it was written.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nnew");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let mut probe = FakeProbe::new();
        let swap_dir = dir.path().to_path_buf();
        probe.hook = Some(Box::new(move |p: &Path| {
            if p.file_name().is_some_and(|n| n != "csq") {
                let other = swap_dir.join("evil");
                std::fs::write(&other, b"csq 2.21.0 (enterprise)\nevil").unwrap();
                std::fs::rename(&other, p).unwrap();
            }
        }));
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_TMP_REPLACED));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.20.0 (enterprise)\nold"
        );
        assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
    }

    #[test]
    fn target_updated_during_probes_is_not_overwritten() {
        // I1: a concurrent `csq update` lands while the candidate is verified.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"csq 2.21.0 (enterprise)\nbundle");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"csq 2.20.0 (enterprise)\nold");
        let mut probe = FakeProbe::new();
        let t = target.clone();
        probe.hook = Some(Box::new(move |p: &Path| {
            if p.file_name().is_some_and(|n| n != "csq") {
                let new = t.with_file_name("csq.updated");
                std::fs::write(&new, b"csq 2.22.0 (enterprise)\nnewer-by-terminal-update").unwrap();
                std::fs::rename(&new, &t).unwrap();
            }
        }));
        let out =
            ensure_cli_shim_with(&src, &target, &probe, EXPECTED, &SignerPolicy::AnySignature)
                .unwrap();
        assert_eq!(out, ShimOutcome::Rejected(REASON_TARGET_CHANGED));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"csq 2.22.0 (enterprise)\nnewer-by-terminal-update",
            "the concurrently-installed newer CLI must survive"
        );
        assert_eq!(dir_names(target.parent().unwrap()), vec!["csq".to_string()]);
    }

    #[test]
    fn exclusive_create_refuses_a_planted_path() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("t");
        std::fs::write(&p, b"planted").unwrap();
        assert!(write_new_exclusive(&p, b"x").is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("l");
            std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
            assert!(write_new_exclusive(&link, b"x").is_err());
            assert!(!dir.path().join("elsewhere").exists());
        }
    }

    #[test]
    fn adhoc_and_team_parsing_match_whole_lines_only() {
        assert!(stderr_is_adhoc(
            "Format=x\nSignature=adhoc\nTeamIdentifier=not set"
        ));
        assert!(!stderr_is_adhoc("Authority=Signature=adhoc"));
        assert!(!stderr_is_adhoc("/tmp/Signature=adhoc/csq: x"));
        assert_eq!(
            parse_team_identifier("A=b\nTeamIdentifier=4Y4U35PJHX\n"),
            ShownTeam::One("4Y4U35PJHX".to_string())
        );
        assert_eq!(parse_team_identifier("A=b"), ShownTeam::None);
        assert_eq!(
            parse_team_identifier("TeamIdentifier=not set"),
            ShownTeam::None
        );
        assert_eq!(
            parse_team_identifier("TeamIdentifier=4Y4U35PJHX\"; x"),
            ShownTeam::Ambiguous
        );
    }

    /// Real `codesign`, hermetic: an ad-hoc-signed private copy of `/bin/echo`.
    /// A pinned team must REJECT it (no ad-hoc fallback — H1); the community
    /// policy accepts it; no team can be derived from it.
    #[cfg(target_os = "macos")]
    #[test]
    fn real_codesign_pins_team_and_rejects_adhoc_on_enterprise() {
        let dir = TempDir::new().unwrap();
        let exe = dir.path().join("echo-adhoc");
        std::fs::copy("/bin/echo", &exe).unwrap();
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "-s", "-"])
            .arg(&exe)
            .status()
            .unwrap();
        assert!(signed.success(), "test setup: ad-hoc sign failed");
        let p = SystemShimProbe;
        if option_env!("CSQ_RELEASE_TEAM_ID").is_none() {
            // The test binary is ad-hoc/unsigned and no release team is compiled
            // in: there is NO trusted team, so an enterprise pin fails closed.
            assert_eq!(p.trusted_team(), ProbeOutcome::Failed);
        }
        assert_eq!(
            p.signature(&exe, &Signer::Team("4Y4U35PJHX".into())),
            ProbeOutcome::Failed,
            "ad-hoc must not satisfy a pinned team"
        );
        assert_eq!(p.signature(&exe, &Signer::Any), ProbeOutcome::Ok(()));
    }

    /// `probe_version_within`, retried while the spawn itself fails: exec of a
    /// script written moments ago can hit ETXTBSY when a parallel test's fork
    /// still holds the write fd. That is a harness race, not probe behaviour.
    #[cfg(unix)]
    fn probe(p: &Path, d: std::time::Duration) -> ProbeOutcome<String> {
        for _ in 0..20 {
            let o = probe_version_within(p, d);
            if o != ProbeOutcome::Unavailable {
                return o;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        ProbeOutcome::Unavailable
    }

    #[cfg(unix)]
    #[test]
    fn real_probe_returns_line_none_for_garbage_and_scrubs_env() {
        let dir = TempDir::new().unwrap();
        let ok = dir.path().join("ok");
        write_exe(&ok, b"#!/bin/sh\necho 'csq 2.21.0 (enterprise)'\n");
        assert_eq!(
            probe(&ok, std::time::Duration::from_secs(10)),
            ProbeOutcome::Ok("csq 2.21.0 (enterprise)".to_string())
        );
        let garbage = dir.path().join("garbage");
        write_exe(&garbage, b"\x00\x01 not an executable");
        assert!(!matches!(
            probe(&garbage, std::time::Duration::from_secs(10)),
            ProbeOutcome::Ok(_)
        ));
        // M2: the child sees ONLY the allowlist (cargo itself exports many
        // CARGO_* vars to this test process, so an inherited env shows up here).
        let envp = dir.path().join("envp");
        write_exe(&envp, b"#!/bin/sh\n/usr/bin/env\n");
        let ProbeOutcome::Ok(dump) = probe(&envp, std::time::Duration::from_secs(10)) else {
            panic!("env dump probe failed");
        };
        let keys: Vec<&str> = dump.lines().filter_map(|l| l.split('=').next()).collect();
        assert!(keys.contains(&"PATH"));
        for k in &keys {
            assert!(
                ["PATH", "HOME", "LANG", "PWD", "SHLVL", "_", "OLDPWD"].contains(k),
                "inherited env var leaked into probe child: {k}"
            );
        }
        assert!(dump.contains("PATH=/usr/bin:/bin"));
        // I2: a signal is reported as a signal, distinct from a timeout.
        let killed = dir.path().join("killed");
        write_exe(&killed, b"#!/bin/sh\nkill -9 $$\n");
        assert_eq!(
            probe(&killed, std::time::Duration::from_secs(10)),
            ProbeOutcome::Signaled(9)
        );
    }

    /// FIFO read end that reports whether any WRITER still holds the FIFO:
    /// `Some(true)` = a writer exists (read would block), `Some(false)` = EOF.
    #[cfg(unix)]
    struct FifoWatch(std::fs::File);
    #[cfg(unix)]
    impl FifoWatch {
        fn new(path: &Path) -> Self {
            use std::os::unix::fs::OpenOptionsExt;
            let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            Self(
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path)
                    .unwrap(),
            )
        }
        fn writer_present(&self) -> bool {
            use std::os::unix::io::AsRawFd;
            let mut b = [0u8; 1];
            // SAFETY: reads at most 1 byte into a valid buffer on an open fd.
            let n = unsafe { libc::read(self.0.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
            n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
        }
        fn wait_until(&self, want_writer: bool) -> bool {
            // Hang guard only (120s); no assertion depends on elapsed time.
            for _ in 0..12_000 {
                if self.writer_present() == want_writer {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            false
        }
    }

    #[cfg(unix)]
    fn deadline_is_hard_with(script_tail: &str) {
        // The stub holds the FIFO's write end (fd 3) in the process that keeps
        // stdout open; the hook runs at the instant of the group kill.
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("fifo");
        let watch = FifoWatch::new(&fifo);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(script_tail.replace("FIFO", fifo.to_str().unwrap()));
        let mut at_kill: Option<(bool, bool)> = None;
        let out = run_bounded_with(cmd, std::time::Duration::from_secs(2), &mut |pgid| {
            let appeared = watch.wait_until(true);
            let still_held = watch.writer_present();
            at_kill = Some((appeared, still_held));
            sigkill_group(pgid);
        });
        assert_eq!(at_kill, Some((true, true)), "writer must exist at the kill");
        assert!(matches!(out, Bounded::TimedOut), "{out:?}");
        assert!(
            watch.wait_until(false),
            "the pipe-holding descendant must die with the group (EOF)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_deadline_includes_spawn_budget_without_wall_clock_assertions() {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        let clock = std::cell::Cell::new(start);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"]);
        let mut kills = Vec::new();
        let out = run_bounded_with_runtime(
            cmd,
            timeout,
            &mut |pgid| {
                kills.push(pgid);
                sigkill_group(pgid);
            },
            &mut || clock.get(),
            &mut |cmd| {
                let child = cmd.spawn()?;
                // Consume the entire spawn budget on a deterministic clock.
                // Moving deadline construction after spawn makes this return
                // Done, proving that a post-spawn deadline is extra time.
                clock.set(start + timeout);
                Ok(child)
            },
        );
        assert!(matches!(out, Bounded::TimedOut), "{out:?}");
        assert_eq!(
            kills.len(),
            1,
            "expired spawn must still kill/reap its child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_probe_deadline_is_hard_even_with_a_pipe_holding_grandchild() {
        // H2: the leader exits at once; a background grandchild keeps stdout (and
        // the FIFO) open "forever". The probe must time out AND kill the group.
        deadline_is_hard_with("sleep 100000 3>FIFO & exit 0");
    }

    #[cfg(unix)]
    #[test]
    fn real_probe_deadline_is_hard_for_a_hung_leader() {
        deadline_is_hard_with("exec sleep 100000 3>FIFO");
    }

    #[test]
    fn installs_when_target_missing() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"binary-v2");
        let target = dir.path().join(".local/bin/csq");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::Installed);
        assert_eq!(std::fs::read(&target).unwrap(), b"binary-v2");
        // Real file, NOT a symlink (mode::detect canonicalize trap defense).
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn updates_when_target_stale() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"binary-v2-longer");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"binary-v1");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::Updated);
        assert_eq!(std::fs::read(&target).unwrap(), b"binary-v2-longer");
    }

    #[test]
    fn noop_when_already_identical() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"same-bytes");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"same-bytes");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::NoOp);
    }

    #[cfg(unix)]
    #[test]
    fn replaces_symlink_target_with_real_copy() {
        // A prior (buggy) symlink install must be replaced by a real file —
        // otherwise mode::detect canonicalizes into the bundle and launches
        // Desktop mode for a terminal `csq`.
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&bundle, b"bundle-bytes");
        let target = dir.path().join(".local/bin/csq");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&bundle, &target).unwrap();
        assert!(std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());

        let outcome = ensure_cli_shim(&bundle, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::ReplacedNonRegular);
        // Now a real file, not a symlink.
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"bundle-bytes");
    }

    #[test]
    fn skips_when_target_is_source() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"self");
        let outcome = ensure_cli_shim(&src, &src).unwrap();
        assert_eq!(outcome, ShimOutcome::SkippedSameFile);
    }

    #[test]
    fn shim_source_prefers_standalone_helper_when_present() {
        // Simulate a bundle layout: …/Contents/MacOS/csq (running) +
        // …/Contents/Helpers/csq-cli (standalone-signed helper, an internal ticket).
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("Code Squad Q.app/Contents/MacOS/csq");
        write_exe(&macos, b"bundle-main-deep-signed");
        let helper = dir.path().join("Code Squad Q.app/Contents/Helpers/csq-cli");
        write_exe(&helper, b"standalone-signed");

        assert_eq!(resolve_shim_source(&macos), helper);
    }

    #[test]
    fn shim_source_falls_back_to_exe_when_helper_absent() {
        // Bundle layout but NO helper (community ad-hoc build / pre-an internal ticket-fix).
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&macos, b"bundle-main");
        // No Contents/Helpers/csq-cli.
        assert_eq!(resolve_shim_source(&macos), macos);
    }

    #[test]
    fn shim_source_falls_back_outside_bundle_layout() {
        // A plain on-PATH binary (Linux, dev cargo build, /usr/local/bin) — no
        // Contents/MacOS/ ancestry, so the helper probe never fires.
        let dir = TempDir::new().unwrap();
        let exe = dir.path().join("usr/local/bin/csq");
        write_exe(&exe, b"plain");
        // Even a stray Helpers dir elsewhere must NOT be picked up.
        assert_eq!(resolve_shim_source(&exe), exe);
    }

    #[test]
    fn shim_source_ignores_helper_that_is_a_directory() {
        // A `csq-cli` that is a directory (not a regular file) must be skipped —
        // `is_file()` guards the copy source.
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&macos, b"main");
        std::fs::create_dir_all(dir.path().join("App.app/Contents/Helpers/csq-cli")).unwrap();
        assert_eq!(resolve_shim_source(&macos), macos);
    }

    // ── resolve_shim_target precedence ────────────────────────────────
    //
    // Each of these RUNS on every platform: the decision is exercised through
    // `resolve_shim_target_from`, whose inputs are injected, so no case depends
    // on the host actually carrying a `/opt/homebrew/bin/csq`.

    /// The regression that motivated the change. A host with BOTH a homebrew
    /// `csq` (which the desktop app's own `augment_subprocess_path` ranks first
    /// on `$PATH`) and the canonical `~/.local/bin/csq` must refresh the
    /// CANONICAL one — the binary the operator's shell actually runs.
    ///
    /// Falsifying result, named up front: before the fix this returned
    /// `/opt/homebrew/bin/csq`, i.e. the `path_hit`.
    #[test]
    fn shim_target_prefers_canonical_over_path_hit() {
        let canonical = PathBuf::from("/home/u/.local/bin/csq");
        let got = resolve_shim_target_from(
            Some(canonical.clone()),
            true,
            Some(PathBuf::from("/opt/homebrew/bin/csq")),
        );
        assert_eq!(got, Some(canonical));
    }

    /// The canonical path is only preferred when something is THERE. A host
    /// that installed csq solely to `/usr/local/bin` keeps that target, so the
    /// fix does not strand single-location installs.
    #[test]
    fn shim_target_falls_back_to_path_hit_when_canonical_absent() {
        let hit = PathBuf::from("/usr/local/bin/csq");
        let got = resolve_shim_target_from(
            Some(PathBuf::from("/home/u/.local/bin/csq")),
            false,
            Some(hit.clone()),
        );
        assert_eq!(got, Some(hit));
    }

    /// A `$PATH` hit INSIDE the bundle is still skipped — copying onto or next
    /// to the running `.app` is wrong — and the canonical create-path is used.
    #[test]
    fn shim_target_skips_in_bundle_path_hit() {
        let canonical = PathBuf::from("/home/u/.local/bin/csq");
        for hit in [
            "/Applications/Code Squad Q.app/Contents/MacOS/csq",
            "/opt/x/csq.AppImage",
        ] {
            let got =
                resolve_shim_target_from(Some(canonical.clone()), false, Some(PathBuf::from(hit)));
            assert_eq!(got, Some(canonical.clone()), "hit {hit}");
        }
    }

    /// With no home AND only an in-bundle `$PATH` hit there is no legitimate
    /// target — the caller must skip the refresh rather than guess.
    #[test]
    fn shim_target_is_none_without_home_or_usable_path_hit() {
        let got = resolve_shim_target_from(
            None,
            false,
            Some(PathBuf::from(
                "/Applications/Code Squad Q.app/Contents/MacOS/csq",
            )),
        );
        assert_eq!(got, None);
    }

    /// `canonical_is_occupied` over all four on-disk shapes, calling the
    /// function PRODUCTION calls rather than recomputing the predicate here.
    ///
    /// The DANGLING-symlink row is the one that discriminates. Falsifying
    /// result, named up front: swap `symlink_metadata` for `metadata` in
    /// `canonical_is_occupied` and that row flips to `false` — the refresh
    /// would then route to the `$PATH` hit and leave a `mode::detect` trap
    /// symlink at the canonical path. The other three rows survive that
    /// mutation, which is precisely why testing only them proves nothing.
    #[cfg(unix)]
    #[test]
    fn canonical_is_occupied_covers_every_on_disk_shape() {
        let dir = TempDir::new().unwrap();

        let regular = dir.path().join("regular");
        write_exe(&regular, b"bin");
        assert!(canonical_is_occupied(&regular), "regular file is occupied");

        let referent = dir.path().join("referent");
        write_exe(&referent, b"bin");
        let live_link = dir.path().join("live-link");
        std::os::unix::fs::symlink(&referent, &live_link).unwrap();
        assert!(
            canonical_is_occupied(&live_link),
            "symlink to an existing file is occupied"
        );

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("gone"), &dangling).unwrap();
        assert!(
            canonical_is_occupied(&dangling),
            "a DANGLING symlink is still occupied — metadata() would say otherwise, \
             and ensure_cli_shim must be routed here to replace the mode::detect trap"
        );

        let a_directory = dir.path().join("a-directory");
        std::fs::create_dir_all(&a_directory).unwrap();
        assert!(
            !canonical_is_occupied(&a_directory),
            "a DIRECTORY must NOT count as occupied — this path also becomes the \
             launchd plist's ProgramArguments[0] via resolve_managed_daemon_exe, and a \
             directory there is a daemon that can never exec"
        );

        assert!(
            !canonical_is_occupied(&dir.path().join("absent")),
            "nothing there is not occupied"
        );
    }

    /// A symlink at the canonical path still wins the precedence decision, so
    /// `ensure_cli_shim` is routed at it and can replace it.
    #[cfg(unix)]
    #[test]
    fn shim_target_treats_canonical_symlink_as_occupied() {
        let dir = TempDir::new().unwrap();
        let canonical = dir.path().join(".local/bin/csq");
        std::fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        let bundle = dir.path().join("Bundle.app/Contents/MacOS/csq");
        write_exe(&bundle, b"bundle");
        std::os::unix::fs::symlink(&bundle, &canonical).unwrap();

        let got = resolve_shim_target_from(
            Some(canonical.clone()),
            canonical_is_occupied(&canonical),
            Some(PathBuf::from("/opt/homebrew/bin/csq")),
        );
        assert_eq!(got, Some(canonical));
    }

    #[cfg(unix)]
    #[test]
    fn shim_target_is_executable_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"x");
        let target = dir.path().join(".local/bin/csq");
        ensure_cli_shim(&src, &target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "shim must be executable");
    }
}
