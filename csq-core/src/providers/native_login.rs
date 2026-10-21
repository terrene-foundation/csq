//! Native-CLI login orchestrator (Wave B / an internal journal entry) — Kimi and Grok.
//!
//! Mirrors [`crate::providers::codex::login::perform_with`]'s
//! dependency-injected shape, but simpler: there is no credential
//! relocation, no UUID mint, and no post-spawn cleanup guard, because the
//! vendor CLI's credentials NEVER leave the slot's vendor home
//! ([`crate::providers::native::native_home_path`]) and self-refresh in
//! place. The only artifact csq writes is the credential-less binding
//! marker ([`crate::providers::native::write_binding`]), and — per the
//! 0135 design lock — that marker is written **only after** the vendor's
//! credential file is confirmed present
//! ([`crate::providers::native::has_credentials`]). A marker therefore
//! means "this slot has a working native login," never merely "a login
//! was attempted."
//!
//! Two entry points, matching the codex CLI/desktop split:
//!
//! - [`login_native_cli`] — the CLI TTY entry. Inherits stdio so the user
//!   sees the vendor's own device-code prompt directly (no piping, no
//!   parsing needed).
//! - [`login_native_with`] — the DI seam a desktop caller drives: pipes
//!   the vendor's stdout, forwards parsed device-code lines to a callback
//!   (so the UI can render the code + open the URL), then waits for exit
//!   and runs the same verify-then-write-marker sequence.
//!
//! See `internal-design-docs`.

use crate::cli_deps::sanitize::redact_path;
use crate::error::redact_tokens;
use crate::providers::catalog::Surface;
use crate::providers::native;
use crate::types::AccountNum;
use anyhow::{anyhow, Context, Result};
use std::io::{BufRead, Read};
use std::path::Path;
use std::process::{Command, ExitStatus};

/// A parsed device-code line from a native vendor CLI's login stdout.
///
/// Unlike codex's shape (URL and code as two separate tokens, sometimes on
/// separate lines), the kimi/grok device-auth URLs embed the code directly
/// in the query string (`?user_code=XXXX-XXXX`) — see
/// [`parse_native_device_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeviceCode {
    /// Full verification URL, exactly as it appeared on the vendor's
    /// stdout line (already host-allowlisted by the parser).
    pub verification_url: String,
    /// The short code the user confirms at `verification_url`.
    pub user_code: String,
}

/// Handle to a spawned vendor login subprocess with piped stdout, returned
/// by the injectable `spawn` closure in [`login_native_with`].
///
/// Boxed trait objects keep the DI seam concrete (no generic parameter
/// threading through every caller). Production wiring
/// ([`login_native_cli`] does NOT use this seam — it inherits stdio
/// instead; a desktop caller would) boxes a live subprocess's piped
/// stdout plus a `wait()` closure. Tests box an in-memory reader plus a
/// canned exit-status closure so no real vendor binary is ever spawned —
/// `csq-core/src/providers/codex/login.rs` tests use the same
/// `ExitStatus::from_raw` pattern for the canned status.
pub struct SpawnedNativeLogin {
    stdout: Box<dyn BufRead + Send>,
    wait: Box<dyn FnOnce() -> std::io::Result<ExitStatus> + Send>,
}

impl SpawnedNativeLogin {
    /// Builds a handle from a piped-stdout reader plus a `wait` closure
    /// that blocks until the subprocess exits and returns its status.
    pub fn new(
        stdout: impl BufRead + Send + 'static,
        wait: impl FnOnce() -> std::io::Result<ExitStatus> + Send + 'static,
    ) -> Self {
        Self {
            stdout: Box::new(stdout),
            wait: Box::new(wait),
        }
    }
}

/// Host-allowlisted device-code parser.
///
/// Returns `Some` only when `line` contains an `https://` URL whose host
/// is an EXACT match for `surface`'s `device_code_host` AND the URL
/// carries a non-empty `user_code` query parameter. A URL on any other
/// host — even if it carries a plausible-looking `user_code` — MUST NOT
/// be surfaced; an attacker-influenced stdout line must not be able to
/// phish the user to a wrong URL.
///
/// Mirrors [`crate::providers::codex::desktop_login`]'s
/// `extract_codex_url` allowlist rigor:
///
/// - HTTPS-only (an `http://` device URL is an exfiltration vector).
/// - Userinfo rejection (defeats
///   `https://www.kimi.com@evil.example.com/...`).
/// - Exact-match host allowlist (no suffix matching, no wildcards).
/// - ANSI escapes stripped before tokenizing (TTY-colorized output).
///
/// Diverges from codex's shape in one respect: codex's device code is a
/// separate same-line or cross-line token that needs its own shape
/// detector (`is_device_code_shape`). The kimi/grok vendor URLs embed the
/// code directly in the query string
/// (`https://www.kimi.com/code/authorize_device?user_code=XXXX-XXXX`,
/// `https://accounts.x.ai/oauth2/device?user_code=XXXX`), so the code is
/// extracted from the URL itself — there is no separate token to hunt
/// for, and therefore no shape-detector false-positive surface.
pub fn parse_native_device_code(line: &str, surface: Surface) -> Option<NativeDeviceCode> {
    let descriptor = native::descriptor(surface)?;
    let stripped = strip_ansi_escapes(line);
    for token in stripped.split_whitespace() {
        let trimmed = trim_token_punct(token);
        if trimmed.len() < 8
            || !trimmed
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            continue;
        }
        let parsed = match ::url::Url::parse(trimmed) {
            Ok(u) => u,
            Err(_) => continue,
        };
        // HTTPS-only — re-assert even though the pre-filter already
        // required it, so a future widened pre-filter can't silently
        // drop this guard (mirrors codex's `extract_codex_url`).
        if parsed.scheme() != "https" {
            continue;
        }
        // Userinfo guard.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            continue;
        }
        // Host allowlist — exact match against this surface's single
        // device-code host.
        let host = match parsed.host_str() {
            Some(h) => h,
            None => continue,
        };
        if host != descriptor.device_code_host {
            continue;
        }
        let user_code = parsed
            .query_pairs()
            .find(|(k, _)| k == "user_code")
            .map(|(_, v)| v.into_owned())
            .filter(|v| !v.is_empty());
        if let Some(user_code) = user_code {
            return Some(NativeDeviceCode {
                verification_url: trimmed.to_string(),
                user_code,
            });
        }
    }
    None
}

/// Strips CSI / SGR ANSI escape sequences (`\x1b[...m` and friends) from a
/// line so a TTY-colorized URL still tokenizes correctly. Private copy of
/// `codex::desktop_login::strip_ansi_escapes` — that function is
/// module-private to `codex::desktop_login`, and the two surfaces have no
/// shared parsing crate to hang a common implementation off of.
fn strip_ansi_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some(&'[') => {
                    chars.next();
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if (0x40u32..=0x7e).contains(&(p as u32)) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if c == '\r' {
            out.push(' ');
            continue;
        }
        out.push(c);
    }
    out
}

/// Strips trailing sentence punctuation around URLs while keeping
/// URL-internal characters. Private copy of
/// `codex::desktop_login::trim_token_punct`.
fn trim_token_punct(token: &str) -> &str {
    token.trim_end_matches(|c: char| {
        !c.is_ascii_alphanumeric()
            && c != '/'
            && c != '-'
            && c != '_'
            && c != '='
            && c != '?'
            && c != '&'
            && c != '%'
    })
}

/// DI seam for the login orchestrator (desktop callers drive this
/// directly; [`login_native_cli`] is a separate, simpler CLI entry).
///
/// `spawn` receives `(home, binary, login_args, home_env)` — the slot's
/// vendor home dir, the vendor binary name, its login argv, and its
/// isolation env-var name — and returns a [`SpawnedNativeLogin`] handle.
/// Every parsed device-code line ([`parse_native_device_code`]) is
/// forwarded to `on_device_code` as it's observed on the piped stdout, so
/// a desktop caller can emit it to the UI as the vendor's own flow
/// progresses.
///
/// On exit 0: verifies the vendor wrote its credential file
/// ([`native::has_credentials`]) BEFORE writing the binding marker
/// ([`native::write_binding`]) — 0135 design lock: "a marker now means
/// the slot has a working native login." On spawn error, non-zero exit,
/// or a missing credential file after exit 0: returns `Err` and the
/// marker is NEVER written (no partial-success state survives on disk).
pub fn login_native_with<S, C>(
    base_dir: &Path,
    slot: AccountNum,
    surface: Surface,
    spawn: S,
    mut on_device_code: C,
) -> Result<()>
where
    S: FnOnce(&Path, &str, &[&str], &str) -> std::io::Result<SpawnedNativeLogin>,
    C: FnMut(NativeDeviceCode),
{
    let descriptor = native::descriptor(surface)
        .ok_or_else(|| anyhow!("surface {surface} is not a native-CLI surface"))?;

    let home = ensure_vendor_home(base_dir, slot, surface)?;

    let mut spawned = spawn(
        &home,
        descriptor.binary,
        descriptor.login_args,
        descriptor.home_env,
    )
    .with_context(|| {
        format!(
            "spawn `{} {}`",
            descriptor.binary,
            descriptor.login_args.join(" ")
        )
    })?;

    // Bound each line read: a compromised/MITM'd vendor binary emitting a
    // newline-less infinite stream must not exhaust memory in the spawn_blocking
    // task (redteam R1 LOW). Device-code lines are short; 64 KiB is generous.
    const MAX_DEVICE_CODE_LINE_BYTES: u64 = 64 * 1024;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = match (&mut spawned.stdout)
            .take(MAX_DEVICE_CODE_LINE_BYTES)
            .read_line(&mut line)
        {
            Ok(n) => n,
            Err(e) => {
                // A read error on the piped stdout does not abort the
                // login — the vendor subprocess is still running and its
                // exit status is the authoritative signal. Redact
                // defensively: on some platforms an I/O error's message
                // can echo buffered bytes.
                tracing::warn!(
                    error_kind = "native_login_stdout_read_failed",
                    surface = surface.as_str(),
                    reason = %redact_tokens(&e.to_string()),
                    "native login stdout read failed; continuing to wait for exit"
                );
                break;
            }
        };
        if bytes_read == 0 {
            break;
        }
        if let Some(code) = parse_native_device_code(&line, surface) {
            on_device_code(code);
        }
    }

    let status = (spawned.wait)()
        .with_context(|| format!("wait for `{}` login subprocess", descriptor.binary))?;
    finish_native_login(base_dir, slot, surface, descriptor, &home, status)
}

/// CLI TTY entry point. Spawns the real vendor binary with **inherited**
/// stdio — the user sees the vendor's own device-code prompt directly,
/// the same UX as `codex login --device-auth` run from the CLI
/// (`handle_codex` in `csq/src/cli/commands/login.rs`). Because stdio is inherited (not piped),
/// there is no device-code line for csq to parse or forward here.
///
/// Resolves the binary via
/// [`crate::cli_deps::install_path::find_in_path`] (known-install-dir
/// aware for kimi/grok, so a self-managed vendor install that isn't on
/// `$PATH` is still found) rather than relying on the OS's own `$PATH`
/// search inside `Command::new`.
///
/// Ends in the same verify-then-write-marker sequence as
/// [`login_native_with`] (`finish_native_login`) so both entry points
/// share one postcondition: a marker exists **iff** the vendor's
/// credential file exists.
pub fn login_native_cli(base_dir: &Path, slot: AccountNum, surface: Surface) -> Result<()> {
    let descriptor = native::descriptor(surface)
        .ok_or_else(|| anyhow!("surface {surface} is not a native-CLI surface"))?;

    let binary_path =
        crate::cli_deps::install_path::find_in_path(descriptor.binary).ok_or_else(|| {
            anyhow!(
                "{} binary not found — install {} and ensure it is on PATH, then retry",
                descriptor.binary,
                descriptor.display_name,
            )
        })?;

    let home = ensure_vendor_home(base_dir, slot, surface)?;

    let mut cmd = Command::new(&binary_path);
    cmd.args(descriptor.login_args);
    // Strip BOTH native home vars before setting this surface's own, so a
    // parent-shell `KIMI_CODE_HOME`/`GROK_HOME` cannot redirect the vendor to
    // the wrong account — parity with `launch_native`'s strip-both discipline
    // (redteam R1 NIT: keep the invariant uniform across every native spawn).
    cmd.env_remove("KIMI_CODE_HOME");
    cmd.env_remove("GROK_HOME");
    cmd.env(descriptor.home_env, &home);
    let status = cmd.status().with_context(|| {
        format!(
            "spawn `{} {}` — is {} installed and on PATH?",
            descriptor.binary,
            descriptor.login_args.join(" "),
            descriptor.binary,
        )
    })?;

    finish_native_login(base_dir, slot, surface, descriptor, &home, status)
}

/// True iff the error is a POSIX **mode-bits-only** failure from `fchmod`
/// (EPERM on e.g. an immutable-flag dir; ENOTSUP/EOPNOTSUPP on FAT and some
/// network filesystems). Only that class may be downgraded to a warning:
/// `secure_dir_fd` verifies the fd is a REAL directory owned by `geteuid`
/// (`O_DIRECTORY | O_NOFOLLOW` + `fstat`) BEFORE it reaches its `fchmod`.
/// The DOWNGRADE additionally requires the caller's stage gate
/// (`verified_existing_owned_dir`; fixcheck2 LOW 5): the path must have
/// pre-existed as a real euid-owned directory, so a mode-bits errno from a
/// CREATE stage (path absent) or from a symlinked path is never downgraded
/// — it refuses.
/// Every other error class — symlink refusal, non-directory refusal,
/// foreign-owner refusal, create failure, ELOOP — is a refusal, and the
/// R3 MED bug was exactly this predicate's absence: `home.is_dir()` follows
/// symlinks, so refusals read as "exists, warn and continue" and vendor
/// tokens then got written through a planted link.
///
/// R3-fix-check LOW 1: this predicate is NECESSARY but NOT SUFFICIENT.
/// Errno alone cannot tell a failed `fchmod` on an existing owner dir from
/// an EPERM raised by the create/open stages, so callers MUST additionally
/// gate the downgrade on [`verified_existing_owned_dir`] (the stage gate):
/// only a target that ALREADY existed as a real, euid-owned directory may
/// downgrade.
fn is_mode_bits_only_failure(e: &crate::error::PlatformError) -> bool {
    #[cfg(unix)]
    {
        if let crate::error::PlatformError::Io(io) = e {
            // Comparisons, not a `matches!` arm list: on Linux
            // `ENOTSUP == EOPNOTSUPP` (both 95), so an OR-pattern of the two
            // is an unreachable duplicate; on macOS they are distinct
            // (45/102) and both must be accepted.
            let code = io.raw_os_error();
            return code == Some(libc::EPERM)
                || code == Some(libc::ENOTSUP)
                || code == Some(libc::EOPNOTSUPP);
        }
        false
    }
    #[cfg(not(unix))]
    {
        // Windows has no POSIX mode bits to fail on; every error is fatal.
        let _ = e;
        false
    }
}

/// R3-fix-check LOW 1 (stage gate): true iff `path` ALREADY exists as a
/// REAL directory (no-follow) owned by `geteuid` — i.e. `ensure_private_dir`
/// on it cannot enter its create stage, only its open + `fchmod` tighten.
/// Only then may the errno-based mode-bits class downgrade to a warning: an
/// EPERM/ENOTSUP raised by the CREATE or OPEN stage on a missing or
/// unverified target refuses like any other failure.
#[cfg(unix)]
fn verified_existing_owned_dir(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            // SAFETY: geteuid has no memory or synchronization preconditions.
            meta.uid() == unsafe { libc::geteuid() }
        }
        _ => false,
    }
}
#[cfg(not(unix))]
fn verified_existing_owned_dir(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Ok(meta) if meta.is_dir())
}

/// Creates the slot's per-slot vendor home and restricts it to `0o700` on
/// Unix (defense-in-depth: the vendor writes its real tokens into this dir at
/// perms of its own choosing, so csq locks the containing dir down — redteam
/// R1 LOW). The chmod is best-effort ONLY for the mode-bits-only failure
/// class on a filesystem that cannot carry it (FAT/network fs); every
/// refusal is fatal.
/// Test-only seam (fixcheck2 LOW 5): lets a unit test force the next
/// [`secure_vendor_dir`] call for one exact path to fail with a chosen raw
/// OS error, so the CALLER-LEVEL stage gate (`existed && mode-bits-only`)
/// is exercised end-to-end — removing either conjunct must red a caller
/// test, not only the predicate's own test.
#[cfg(test)]
mod secure_failure_hook {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static ARMED: RefCell<Option<(PathBuf, i32)>> = const { RefCell::new(None) };
    }

    #[cfg(unix)]
    pub(super) fn arm(path: &Path, errno: i32) {
        ARMED.with(|slot| *slot.borrow_mut() = Some((path.to_path_buf(), errno)));
    }

    pub(super) fn take_for(path: &Path) -> Option<std::io::Error> {
        ARMED.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_ref() {
                Some((armed, errno)) if armed == path => {
                    let errno = *errno;
                    *slot = None;
                    Some(std::io::Error::from_raw_os_error(errno))
                }
                _ => None,
            }
        })
    }
}

/// `ensure_private_dir` behind the test seam above; identical in
/// production builds.
fn secure_vendor_dir(path: &Path) -> Result<(), crate::error::PlatformError> {
    #[cfg(test)]
    if let Some(injected) = secure_failure_hook::take_for(path) {
        return Err(crate::error::PlatformError::Io(injected));
    }
    crate::platform::fs::ensure_private_dir(path)
}

fn ensure_vendor_home(
    base_dir: &Path,
    slot: AccountNum,
    surface: Surface,
) -> Result<std::path::PathBuf> {
    let home = native::native_home_path(base_dir, slot, surface);
    // R3 MED: secure the CONTAINING `native-homes/` FIRST. The recursive
    // create below would otherwise follow a symlinked `native-homes/` and
    // land `home` (and the vendor's real tokens) behind a planted link.
    // Strict helper is correct for this leaf: `native-homes/` itself is not
    // the operator-symlinkable component — only the accounts root above it
    // is (R2 H1).
    if let Some(native_homes) = home.parent() {
        // R3-fix-check LOW 1: the mode-bits downgrade additionally requires
        // the target to have ALREADY existed as a verified euid-owned real
        // directory — only then can the failure be a pure mode-write.
        let native_homes_existed = verified_existing_owned_dir(native_homes);
        if let Err(e) = secure_vendor_dir(native_homes) {
            if !(native_homes_existed && is_mode_bits_only_failure(&e)) {
                return Err(anyhow!(
                    "refusing native vendor home for slot {slot}: \
                     the containing native-homes directory could not be secured: {}",
                    redact_tokens(&e.to_string())
                ));
            }
            tracing::warn!(
                error_kind = "native_homes_secure_failed",
                "native-homes directory for slot {slot} could not be fully secured \
                 (mode bits only): {}",
                redact_tokens(&e.to_string())
            );
        }
    }
    // R2 M3 + R3 MED: route through the shared fail-closed helper (0o700 at
    // creation, no create-then-chmod window). Every refusal — symlink at
    // `home`, foreign owner, non-directory, create/IO failure — is FATAL.
    // Only a verified mode-bits-only failure on a real euid-owned directory
    // (see `is_mode_bits_only_failure`) is surfaced as a warning and
    // tolerated.
    let home_existed = verified_existing_owned_dir(&home);
    if let Err(e) = secure_vendor_dir(&home) {
        if !(home_existed && is_mode_bits_only_failure(&e)) {
            return Err(anyhow!(
                "refusing native vendor home for slot {slot}: {}",
                crate::error::redact_tokens(&e.to_string())
            ));
        }
        tracing::warn!(
            error_kind = "native_home_secure_failed",
            "native vendor home for slot {slot} could not be fully secured (mode bits only): {}",
            crate::error::redact_tokens(&e.to_string())
        );
    }
    Ok(home)
}

/// Shared postcondition sequence for both entry points: on a non-zero
/// exit, error out with no marker written. On exit 0, verify the vendor's
/// credential file landed under `home` before writing the binding
/// marker; on either check failing, error out with no marker written.
fn finish_native_login(
    base_dir: &Path,
    slot: AccountNum,
    surface: Surface,
    descriptor: &native::NativeCli,
    home: &Path,
    status: ExitStatus,
) -> Result<()> {
    if !status.success() {
        return Err(anyhow!(
            "{} login exited with non-zero status — inspect output above and retry",
            descriptor.binary
        ));
    }

    if !native::has_credentials(base_dir, slot, surface) {
        return Err(anyhow!(
            "{} login exited successfully but no credentials were found at {} — retry `{}` \
             manually to see the vendor's own error output",
            descriptor.display_name,
            redact_path(&home.join(descriptor.cred_relpath)),
            descriptor.binary,
        ));
    }

    native::write_binding(base_dir, slot, surface).map_err(|e| {
        tracing::warn!(
            error_kind = e.error_kind_tag(),
            surface = surface.as_str(),
            "native binding write failed after successful vendor login"
        );
        anyhow!(
            "{} login succeeded but the slot {slot} binding marker could not be written \
             (check ~/.claude/accounts permissions)",
            descriptor.display_name,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::process::ExitStatus;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    // `ExitStatus` has no stable cross-platform constructor — mirrors
    // `codex::login`'s test helpers so this file compiles on both Unix
    // (Ubuntu / macOS CI) and Windows CI.
    #[cfg(unix)]
    fn fake_success() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(unix)]
    fn fake_failure() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(1 << 8)
    }

    #[cfg(windows)]
    fn fake_success() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn fake_failure() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(1)
    }

    fn write_fake_creds(home: &Path, surface: Surface) {
        let descriptor = native::descriptor(surface).unwrap();
        let cred_path = home.join(descriptor.cred_relpath);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(&cred_path, "{}").unwrap();
    }

    // ── R3 MED: ensure_vendor_home fails CLOSED ─────────────────────────

    /// R3 MED regression: a SYMLINK planted at the slot's vendor home is a
    /// refusal, not a warning. The former shape checked `home.is_dir()`
    /// (which FOLLOWS the link), downgraded the strict helper's refusal to
    /// a warn, and let the vendor CLI write real tokens through the planted
    /// link.
    #[cfg(unix)]
    #[test]
    fn ensure_vendor_home_refuses_symlinked_home_and_writes_nothing_through_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let home = native::native_home_path(base, slot(7), Surface::Kimi);
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        let outside = dir.path().join("outside-target");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &home).unwrap();

        let err = ensure_vendor_home(base, slot(7), Surface::Kimi)
            .expect_err("a symlinked vendor home must be refused");

        assert!(
            format!("{err:#}").contains("refusing native vendor home"),
            "the refusal must be explicit (MED: fail closed, not warn): {err:#}"
        );
        let names: Vec<_> = std::fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            names.is_empty(),
            "nothing may be written through the link: {names:?}"
        );
        assert!(
            std::fs::symlink_metadata(&home)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted link must be left in place, not replaced or followed"
        );
    }

    /// R3 MED regression: a symlinked `native-homes/` CONTAINER is refused
    /// up front — the former shape's recursive create would have followed
    /// the container link and created the slot home behind it.
    #[cfg(unix)]
    #[test]
    fn ensure_vendor_home_refuses_symlinked_native_homes_container() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let container = base.join("native-homes");
        let outside = dir.path().join("outside-container");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &container).unwrap();

        let err = ensure_vendor_home(base, slot(3), Surface::Grok)
            .expect_err("a symlinked native-homes/ must be refused");

        assert!(
            format!("{err:#}").contains("native-homes"),
            "the refusal must name the container: {err:#}"
        );
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "no slot home may be created behind the container link"
        );
    }

    /// R3-fix-check LOW 1 regression (stage predicate): only a REAL,
    /// euid-owned, pre-existing directory qualifies for the mode-bits
    /// downgrade; a missing path (the create stage may be the failure) and
    /// a symlink never do. The mutation that keeps errno-only classification
    /// (making this predicate unconditional) reds this test.
    #[cfg(unix)]
    #[test]
    fn mode_bits_downgrade_requires_a_verified_existing_owned_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let missing = base.join("missing-home");
        assert!(
            !verified_existing_owned_dir(&missing),
            "a MISSING path must not qualify — the failing stage could be create"
        );
        let real = base.join("real-home");
        std::fs::create_dir(&real).unwrap();
        assert!(
            verified_existing_owned_dir(&real),
            "a real euid-owned directory qualifies"
        );
        let link_target = base.join("link-target");
        std::fs::create_dir(&link_target).unwrap();
        let link = base.join("link-home");
        std::os::unix::fs::symlink(&link_target, &link).unwrap();
        assert!(
            !verified_existing_owned_dir(&link),
            "a symlink must not qualify, even when its target is a real dir"
        );
    }

    // ── parse_native_device_code (directive 4e) ─────────────────────────

    #[test]
    fn parse_native_device_code_accepts_real_kimi_and_grok_urls() {
        let kimi_line =
            "Go to https://www.kimi.com/code/authorize_device?user_code=ABCD-EFGH and sign in";
        let kimi = parse_native_device_code(kimi_line, Surface::Kimi).unwrap();
        assert_eq!(kimi.user_code, "ABCD-EFGH");
        assert_eq!(
            kimi.verification_url,
            "https://www.kimi.com/code/authorize_device?user_code=ABCD-EFGH"
        );

        let grok_line = "Open https://accounts.x.ai/oauth2/device?user_code=WXYZ in your browser";
        let grok = parse_native_device_code(grok_line, Surface::Grok).unwrap();
        assert_eq!(grok.user_code, "WXYZ");
        assert_eq!(
            grok.verification_url,
            "https://accounts.x.ai/oauth2/device?user_code=WXYZ"
        );
    }

    #[test]
    fn parse_native_device_code_rejects_wrong_host() {
        let evil_line =
            "Go to https://evil.example.com/code/authorize_device?user_code=ABCD-EFGH and sign in";
        assert!(parse_native_device_code(evil_line, Surface::Kimi).is_none());

        // Cross-surface: kimi's own (legitimate) host is off-allowlist
        // when checked against grok's descriptor.
        let kimi_line =
            "Go to https://www.kimi.com/code/authorize_device?user_code=ABCD-EFGH and sign in";
        assert!(parse_native_device_code(kimi_line, Surface::Grok).is_none());
    }

    #[test]
    fn parse_native_device_code_rejects_http_and_userinfo() {
        let http_line = "Go to http://www.kimi.com/code/authorize_device?user_code=ABCD-EFGH";
        assert!(parse_native_device_code(http_line, Surface::Kimi).is_none());

        let userinfo_line =
            "Go to https://www.kimi.com@evil.example.com/code/authorize_device?user_code=ABCD-EFGH";
        assert!(parse_native_device_code(userinfo_line, Surface::Kimi).is_none());
    }

    #[test]
    fn parse_native_device_code_rejects_missing_or_empty_user_code() {
        let no_code_line = "Go to https://www.kimi.com/code/authorize_device and sign in";
        assert!(parse_native_device_code(no_code_line, Surface::Kimi).is_none());

        let empty_code_line = "Go to https://www.kimi.com/code/authorize_device?user_code=";
        assert!(parse_native_device_code(empty_code_line, Surface::Kimi).is_none());
    }

    // ── login_native_with: directive 4a (success → marker written) ─────

    #[test]
    fn login_native_with_success_writes_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(3);
        let surface = Surface::Kimi;

        let result = login_native_with(
            base,
            s,
            surface,
            |home, binary, args, home_env| {
                assert_eq!(binary, "kimi");
                assert_eq!(args, &["login"]);
                assert_eq!(home_env, "KIMI_CODE_HOME");
                write_fake_creds(home, surface);
                Ok(SpawnedNativeLogin::new(Cursor::new(Vec::new()), || {
                    Ok(fake_success())
                }))
            },
            |_code| {},
        );

        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(native::marker_exists(base, s, surface));
    }

    // ── login_native_with: directive 4b (non-zero exit → no marker) ────

    #[test]
    fn login_native_with_nonzero_exit_writes_no_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(4);
        let surface = Surface::Grok;

        let result = login_native_with(
            base,
            s,
            surface,
            |home, _binary, _args, _home_env| {
                // Vendor may still have written creds before failing late
                // (e.g. a post-auth network error) — the marker must stay
                // absent regardless, because the exit status is checked
                // FIRST.
                write_fake_creds(home, surface);
                Ok(SpawnedNativeLogin::new(Cursor::new(Vec::new()), || {
                    Ok(fake_failure())
                }))
            },
            |_code| {},
        );

        assert!(result.is_err());
        assert!(!native::marker_exists(base, s, surface));
    }

    // ── login_native_with: directive 4c (exit-0, no cred file → Err) ───

    #[test]
    fn login_native_with_missing_creds_after_exit0_errors_with_no_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(5);
        let surface = Surface::Grok;

        let result = login_native_with(
            base,
            s,
            surface,
            |_home, _binary, _args, _home_env| {
                // Vendor claims success but never wrote its cred file —
                // e.g. the user cancelled in the browser after the
                // subprocess had already exited 0.
                Ok(SpawnedNativeLogin::new(Cursor::new(Vec::new()), || {
                    Ok(fake_success())
                }))
            },
            |_code| {},
        );

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no credentials were found"),
            "unexpected error message: {msg}"
        );
        assert!(!native::marker_exists(base, s, surface));
    }

    // ── login_native_with: directive 4d (device-code forwarded) ────────

    #[test]
    fn login_native_with_forwards_device_code_to_callback() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(6);
        let surface = Surface::Kimi;
        let stdout =
            "Visit https://www.kimi.com/code/authorize_device?user_code=WXYZ-1234 to sign in\n";

        let mut captured: Vec<NativeDeviceCode> = Vec::new();
        let result = login_native_with(
            base,
            s,
            surface,
            |home, _binary, _args, _home_env| {
                write_fake_creds(home, surface);
                Ok(SpawnedNativeLogin::new(
                    Cursor::new(stdout.as_bytes().to_vec()),
                    || Ok(fake_success()),
                ))
            },
            |code| captured.push(code),
        );

        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].user_code, "WXYZ-1234");
        assert_eq!(
            captured[0].verification_url,
            "https://www.kimi.com/code/authorize_device?user_code=WXYZ-1234"
        );
        assert!(native::marker_exists(base, s, surface));
    }

    #[test]
    fn login_native_with_ignores_off_allowlist_device_code_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(8);
        let surface = Surface::Kimi;
        let stdout =
            "Visit https://evil.example.com/code/authorize_device?user_code=WXYZ-1234 to sign in\n";

        let mut captured: Vec<NativeDeviceCode> = Vec::new();
        let result = login_native_with(
            base,
            s,
            surface,
            |home, _binary, _args, _home_env| {
                write_fake_creds(home, surface);
                Ok(SpawnedNativeLogin::new(
                    Cursor::new(stdout.as_bytes().to_vec()),
                    || Ok(fake_success()),
                ))
            },
            |code| captured.push(code),
        );

        assert!(result.is_ok());
        assert!(captured.is_empty(), "off-allowlist line must not forward");
    }

    #[test]
    fn login_native_with_rejects_non_native_surface() {
        let tmp = tempfile::tempdir().unwrap();
        let result = login_native_with(
            tmp.path(),
            slot(1),
            Surface::Codex,
            |_home, _binary, _args, _home_env| {
                Ok(SpawnedNativeLogin::new(Cursor::new(Vec::new()), || {
                    Ok(fake_success())
                }))
            },
            |_code| {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn login_native_with_spawn_error_writes_no_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(9);
        let surface = Surface::Grok;

        let result = login_native_with(
            base,
            s,
            surface,
            |_home, _binary, _args, _home_env| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "grok binary not found",
                ))
            },
            |_code| {},
        );

        assert!(result.is_err());
        assert!(!native::marker_exists(base, s, surface));
    }

    /// fixcheck2 LOW 5 (a): the native-homes/ stage gate at the CALLER — a
    /// mode-bits-only (EPERM) failure on a container that did NOT pre-exist
    /// must REFUSE. Removing the `native_homes_existed &&` conjunct reds
    /// this test (the former predicate-only test stayed green).
    #[cfg(unix)]
    #[test]
    fn ensure_vendor_home_refuses_a_mode_bits_failure_on_a_missing_container() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let container = base.join("native-homes");
        secure_failure_hook::arm(&container, libc::EPERM);
        let err = ensure_vendor_home(base, slot(3), Surface::Grok)
            .expect_err("a mode-bits-only failure on a NON-existing container must refuse");
        assert!(
            format!("{err:#}").contains("could not be secured"),
            "the refusal must name the container failure: {err:#}"
        );
        assert!(
            !container.exists(),
            "nothing may be created past a refused container"
        );
    }

    /// fixcheck2 LOW 5 (b): same gate for the vendor home itself — the
    /// container is real, the home's ensure fails EPERM while the home did
    /// NOT pre-exist → REFUSE. Removing `home_existed &&` reds this test.
    #[cfg(unix)]
    #[test]
    fn ensure_vendor_home_refuses_a_mode_bits_failure_on_a_missing_home() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let home = native::native_home_path(base, slot(4), Surface::Kimi);
        secure_failure_hook::arm(&home, libc::EPERM);
        let err = ensure_vendor_home(base, slot(4), Surface::Kimi)
            .expect_err("a mode-bits-only failure on a NON-existing home must refuse");
        assert!(
            format!("{err:#}").contains("refusing native vendor home"),
            "the refusal must be the home refusal: {err:#}"
        );
        assert!(!home.exists(), "nothing may be created past a refused home");
    }
}
