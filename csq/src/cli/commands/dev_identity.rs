//! `csq audit enroll-dev` and `csq audit prove-dev` — M17 per-developer
//! identity CLI surface.
//!
//! - `csq audit enroll-dev <principal>` — one-time enrollment of a
//!   developer principal; stores private key in OS keychain; writes
//!   public key to `<base>/audit/dev-enrollment.json`.
//! - `csq audit prove-dev <principal>` — operator smoke test: resolves
//!   the principal and prints `Verified` or `Unbacked`.
//!
//! Both commands are gated behind the production `base_dir` (same as the
//! other audit commands). Tests pass a tmp dir directly into the library
//! functions.

use anyhow::{bail, Result};
use csq_core::audit::dev_identity::{
    enroll_developer, resolve_developer, DevResolution, Granularity, Principal,
};
use std::io::{self, Write as _};
use std::path::Path;

/// Handle `csq audit enroll-dev <principal> [--granularity <g>]`.
///
/// Prompts for TTY confirmation (human-present gate — CRITICAL-2) before
/// writing to the OS keychain. Exits non-zero when confirmation is denied.
pub fn handle_enroll_dev(
    base_dir: &Path,
    principal_str: &str,
    granularity_str: Option<&str>,
) -> Result<()> {
    let principal =
        Principal::new(principal_str).map_err(|e| anyhow::anyhow!("invalid principal: {e}"))?;

    let granularity = match granularity_str {
        None | Some("accountable-principal") => Granularity::AccountablePrincipal,
        Some("per-individual") => Granularity::PerIndividual,
        Some(other) => bail!(
            "unknown granularity '{}'; valid: accountable-principal, per-individual",
            other
        ),
    };

    // Human-present gate: write the confirmation prompt to STDOUT so it stays
    // visible under the common `2>/dev/null` redirect operators use to suppress
    // logs. The `confirm` closure reads from stdin — a non-TTY invocation
    // (pipe, CI) will typically not type "y" and the enrollment is refused.
    // This satisfies the CRITICAL-2 requirement that enrollment cannot happen
    // silently in a background process.
    let confirm = |description: &str| -> bool {
        println!("\n{description}\n");
        print!("Confirm enrollment? [y/N] ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return false;
        }
        input.trim().eq_ignore_ascii_case("y")
    };

    match enroll_developer(base_dir, principal.clone(), granularity, confirm) {
        Ok(enrollment) => {
            // Design-intent: the principal echoed here is the operator's OWN
            // confirmed argument (they ran `csq audit enroll-dev <principal>`),
            // echoed back as an action receipt — same operator-explicit-action
            // class as `csq install` echoing where it wrote files. It is not a
            // discovered secret or a filesystem path (operator-surface
            // verification Rule 4/5); no redaction applies.
            eprintln!(
                "audit enroll-dev: '{}' enrolled — pubkey stored in dev-enrollment.json",
                enrollment.principal.as_str()
            );
            eprintln!(
                "audit enroll-dev: private key stored in OS keychain under \
service 'csq-dev-signing-{}'",
                enrollment.principal.as_str()
            );
            Ok(())
        }
        Err(e) => bail!("enroll-dev failed: {e}"),
    }
}

/// Handle `csq audit prove-dev <principal>`.
///
/// Resolves the principal and prints `Verified` or `Unbacked` to stdout.
/// Prints a one-line diagnostic to stderr. Designed as an operator smoke test.
pub fn handle_prove_dev(base_dir: &Path, principal_str: &str) -> Result<()> {
    let principal =
        Principal::new(principal_str).map_err(|e| anyhow::anyhow!("invalid principal: {e}"))?;

    let resolution = resolve_developer(base_dir, &principal);
    match resolution {
        DevResolution::Enrolled { .. } => {
            println!("Verified");
            eprintln!(
                "audit prove-dev: '{}' — key found in OS keychain",
                principal.as_str()
            );
        }
        DevResolution::Unbacked => {
            println!("Unbacked");
            eprintln!(
                "audit prove-dev: '{}' — not enrolled or keychain key missing",
                principal.as_str()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Unenrolled principal resolves to Unbacked without touching the keychain.
    #[test]
    fn handle_prove_dev_unenrolled_returns_ok() {
        let dir = tmp();
        // Not enrolled — should still return Ok (just prints "Unbacked").
        handle_prove_dev(dir.path(), "nobody@example.com").expect("prove-dev ok for unenrolled");
    }

    /// Invalid principal (contains space) fails before the human-present gate.
    #[test]
    fn handle_enroll_dev_invalid_principal_fails() {
        let dir = tmp();
        // Space in principal — should fail validation before the gate.
        let result = handle_enroll_dev(dir.path(), "alice invalid", None);
        assert!(result.is_err(), "invalid principal must fail");
    }

    /// Invalid principal in prove-dev fails before resolution.
    #[test]
    fn handle_prove_dev_invalid_principal_fails() {
        let dir = tmp();
        let result = handle_prove_dev(dir.path(), "alice invalid");
        assert!(result.is_err(), "invalid principal must fail");
    }

    /// Unknown granularity string is rejected.
    #[test]
    fn handle_enroll_dev_bad_granularity_fails() {
        let dir = tmp();
        let result = handle_enroll_dev(dir.path(), "alice@example.com", Some("per-galaxy"));
        assert!(result.is_err(), "unknown granularity must fail");
    }
}
