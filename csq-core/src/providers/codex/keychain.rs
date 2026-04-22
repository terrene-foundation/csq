//! macOS keychain residue probe for Codex.
//!
//! Spec 07 §7.3.3 step 6: on first Codex login on the machine, probe
//! for a pre-existing keychain entry under service `com.openai.codex`
//! and, if present, offer purge before proceeding. The `security`
//! CLI is the same tool csq already uses for Anthropic keychain
//! introspection (`credentials::keychain`), so this module is a
//! narrow sibling focused on codex-cli's service name.
//!
//! On Linux and Windows this probe is a no-op — codex-cli does not
//! populate a system keychain on those platforms; the only storage
//! backend it uses is the `auth.json` file inside `$CODEX_HOME`.
//! A probe call returns [`ProbeResult::Unsupported`] on non-macOS.
//!
//! # Why a narrow module instead of extending `credentials::keychain`
//!
//! `credentials::keychain` reads Claude Code's keychain entries keyed
//! by a SHA-256 hash of the config dir path — that's CC's own
//! service-name shape. Codex writes a flat service name
//! (`com.openai.codex`) that is independent of config-dir hashing
//! and tied to codex-cli, not csq. Putting Codex residue logic in the
//! CC keychain module would conflate two distinct security backends
//! with different threat models and probe semantics.

/// Output of a single keychain residue probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// `com.openai.codex` service entry is present in the user's
    /// login keychain. The caller MUST prompt before proceeding per
    /// spec 07 §7.3.3 step 6.
    Present,
    /// No `com.openai.codex` service entry exists. Login may proceed.
    Absent,
    /// Platform does not expose a keychain we probe. Login may proceed
    /// unconditionally on Linux/Windows.
    Unsupported,
    /// The `security` CLI spawn itself failed in an unexpected way
    /// (binary missing, refused to run). Callers treat this as "do
    /// not block the login" — failing closed here would brick every
    /// Codex login on a misconfigured macOS box that otherwise has
    /// no residue to worry about.
    ProbeFailed,
}

/// The keychain service name codex-cli writes under when its storage
/// backend is `keychain`. Matches the upstream hardcode in
/// `codex-rs/login/src/auth/storage.rs`.
pub const CODEX_KEYCHAIN_SERVICE: &str = "com.openai.codex";

/// Probes the macOS login keychain for a `com.openai.codex` entry.
/// See [`ProbeResult`] for the possible outcomes.
///
/// The probe is a single `security find-generic-password -s <svc>`
/// invocation. No credential material is read or emitted — we only
/// look at the exit code.
#[cfg(target_os = "macos")]
pub fn probe_residue() -> ProbeResult {
    probe_residue_with(CODEX_KEYCHAIN_SERVICE, run_security_find)
}

/// No-op residue probe for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn probe_residue() -> ProbeResult {
    ProbeResult::Unsupported
}

/// Attempts to purge the `com.openai.codex` entry from the user's
/// login keychain. Returns [`Ok(true)`] if an entry was deleted,
/// [`Ok(false)`] if none existed, or [`Err`] with the underlying
/// `security` invocation failure.
#[cfg(target_os = "macos")]
pub fn purge_residue() -> Result<bool, String> {
    purge_residue_with(CODEX_KEYCHAIN_SERVICE, run_security_delete)
}

/// No-op purge for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn purge_residue() -> Result<bool, String> {
    Ok(false)
}

/// Invocation outcome of a `security` CLI call, parameterised so the
/// probe/purge state machines are unit-testable without shelling out.
///
/// Gated on `macos || test` because on non-macOS production builds
/// `probe_residue` / `purge_residue` short-circuit to
/// `Unsupported` / `Ok(false)` and never reach this classifier.
/// `#[allow(dead_code)]` keeps the `#[cfg]` explicit without forcing
/// clippy's `dead_code` lint to flag the seam on Linux clippy runs.
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityExit {
    /// `security` returned exit 0 — entry present / deletion succeeded.
    Found,
    /// `security` returned exit 44 (macOS "item not in keychain") or
    /// non-zero with stderr matching the "not found" vocabulary.
    NotFound,
    /// `security` spawn failed or exited with an unexpected status.
    Error,
}

/// Shape guard applied to every service name before it reaches
/// `security find-generic-password -s <svc>` or its delete sibling.
/// Rejects empty strings (which `security` treats as a wildcard
/// matching the first generic-password entry) and anything not shaped
/// like a reverse-DNS keychain service name. Origin: PR-C3b security
/// review M3. Gated on `macos || test` for the same reason as
/// [`SecurityExit`].
#[cfg(any(target_os = "macos", test))]
fn validate_service_name(service: &str) -> Result<(), &'static str> {
    if service.is_empty() {
        return Err("keychain service name must not be empty");
    }
    if !service.starts_with("com.") {
        return Err("keychain service name must start with 'com.'");
    }
    if !service
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("keychain service name may only contain ASCII alphanumerics, '.', '-', '_'");
    }
    Ok(())
}

/// Test seam for the probe path — production wiring is
/// [`run_security_find`]. The closure gets the service name and
/// returns the classified exit. Callers MUST pass a service name that
/// satisfies [`validate_service_name`]; a bad shape maps to
/// [`ProbeResult::ProbeFailed`] so the login path falls through to
/// the "could not probe" warn branch rather than mis-classifying.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn probe_residue_with(
    service: &str,
    spawn: impl FnOnce(&str) -> SecurityExit,
) -> ProbeResult {
    if validate_service_name(service).is_err() {
        return ProbeResult::ProbeFailed;
    }
    match spawn(service) {
        SecurityExit::Found => ProbeResult::Present,
        SecurityExit::NotFound => ProbeResult::Absent,
        SecurityExit::Error => ProbeResult::ProbeFailed,
    }
}

/// Test seam for the purge path — production wiring is
/// [`run_security_delete`]. Invalid service names hard-error so a
/// buggy caller cannot trick the guard into deleting an unrelated
/// keychain item.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn purge_residue_with(
    service: &str,
    spawn: impl FnOnce(&str) -> SecurityExit,
) -> Result<bool, String> {
    if let Err(why) = validate_service_name(service) {
        return Err(format!("refusing to purge keychain entry: {why}"));
    }
    match spawn(service) {
        SecurityExit::Found => Ok(true),
        SecurityExit::NotFound => Ok(false),
        SecurityExit::Error => Err("security delete-generic-password failed unexpectedly".into()),
    }
}

#[cfg(target_os = "macos")]
fn run_security_find(service: &str) -> SecurityExit {
    // `security find-generic-password -s <svc>` returns exit 0 when
    // found, exit 44 ("The specified item could not be found") when
    // absent. We match on both the exit code AND a substring so that
    // an unusual locale setting on the user's machine doesn't cause
    // us to mis-classify "not found" as a probe failure.
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service])
        .output();
    classify_security_output(out, "could not be found")
}

#[cfg(target_os = "macos")]
fn run_security_delete(service: &str) -> SecurityExit {
    let out = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", service])
        .output();
    classify_security_output(out, "could not be found")
}

#[cfg(target_os = "macos")]
fn classify_security_output(
    result: std::io::Result<std::process::Output>,
    not_found_needle: &str,
) -> SecurityExit {
    let out = match result {
        Ok(o) => o,
        Err(_) => return SecurityExit::Error,
    };
    if out.status.success() {
        return SecurityExit::Found;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains(not_found_needle) {
        return SecurityExit::NotFound;
    }
    if let Some(code) = out.status.code() {
        // 44 = errSecItemNotFound on modern macOS. Belt-and-suspenders
        // with the stderr substring match above.
        if code == 44 {
            return SecurityExit::NotFound;
        }
    }
    SecurityExit::Error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_maps_found_to_present() {
        let r = probe_residue_with("com.test.fixture", |_| SecurityExit::Found);
        assert_eq!(r, ProbeResult::Present);
    }

    #[test]
    fn probe_maps_not_found_to_absent() {
        let r = probe_residue_with("com.test.fixture", |_| SecurityExit::NotFound);
        assert_eq!(r, ProbeResult::Absent);
    }

    #[test]
    fn probe_maps_error_to_probe_failed() {
        let r = probe_residue_with("com.test.fixture", |_| SecurityExit::Error);
        assert_eq!(r, ProbeResult::ProbeFailed);
    }

    #[test]
    fn purge_reports_true_on_found() {
        let deleted = purge_residue_with("com.test.fixture", |_| SecurityExit::Found).unwrap();
        assert!(deleted, "Found exit means an entry was deleted");
    }

    #[test]
    fn purge_reports_false_on_not_found() {
        let deleted = purge_residue_with("com.test.fixture", |_| SecurityExit::NotFound).unwrap();
        assert!(!deleted, "NotFound exit means nothing to delete");
    }

    #[test]
    fn purge_propagates_error_variant() {
        let e = purge_residue_with("com.test.fixture", |_| SecurityExit::Error).unwrap_err();
        assert!(e.contains("failed"), "error should name the failure: {e}");
    }

    #[test]
    fn codex_keychain_service_matches_spec() {
        // Spec 07 §7.3.3 step 6 fixes the service name; this constant
        // is load-bearing for the probe being correct.
        assert_eq!(CODEX_KEYCHAIN_SERVICE, "com.openai.codex");
    }

    #[test]
    fn probe_rejects_empty_service_name() {
        // Origin: PR-C3b security review M3. Empty `-s` argument
        // makes `security find-generic-password` match the first
        // generic-password entry in the keychain — an unrelated item
        // we would mis-classify as Codex residue.
        let r = probe_residue_with("", |_| panic!("spawn must not run for invalid service"));
        assert_eq!(r, ProbeResult::ProbeFailed);
    }

    #[test]
    fn probe_rejects_non_reverse_dns_service_name() {
        let r = probe_residue_with("openai-codex", |_| {
            panic!("spawn must not run for invalid service")
        });
        assert_eq!(r, ProbeResult::ProbeFailed);
    }

    #[test]
    fn probe_rejects_service_name_with_shell_metacharacters() {
        // Even though `security` is invoked argv-style, reject
        // metacharacters so a future refactor that threads `service`
        // into a shell string or path cannot regress.
        let r = probe_residue_with("com.openai.codex; rm -rf", |_| {
            panic!("spawn must not run for invalid service")
        });
        assert_eq!(r, ProbeResult::ProbeFailed);
    }

    #[test]
    fn purge_hard_errors_on_empty_service_name() {
        let err = purge_residue_with("", |_| panic!("must not spawn")).unwrap_err();
        assert!(
            err.contains("refusing to purge"),
            "hard-error must name the refusal: {err}"
        );
    }

    #[test]
    fn validate_service_accepts_spec_name() {
        assert!(validate_service_name(CODEX_KEYCHAIN_SERVICE).is_ok());
        assert!(validate_service_name("com.openai.codex-alt").is_ok());
        assert!(validate_service_name("com.foo.bar_baz").is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_probe_is_unsupported() {
        assert_eq!(probe_residue(), ProbeResult::Unsupported);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_purge_is_noop() {
        assert!(!purge_residue().unwrap());
    }
}
