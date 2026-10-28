//! M17 — DevIdentity error types.
//!
//! All user-string variants follow the redaction pattern used elsewhere in
//! `csq-core/src/audit`: messages use fixed vocabulary and do NOT echo
//! attacker-controlled inputs (per `rules/security.md §2`).

use thiserror::Error;

/// Errors from M17 per-developer identity resolution operations.
///
/// The `Keychain`, `Io`, and `KeyGen` variants carry a fixed `&'static str`
/// operation tag, NOT the raw upstream error. This is deliberate: a
/// `keyring::Error` Display can echo the keychain service name
/// (`csq-dev-signing-<principal>`) on some platforms, which the `Debug`
/// representation (`{:?}`, panic messages, `tracing::debug!`) would then
/// expose. Carrying only a `&'static str` op tag closes that Debug-exposure
/// surface entirely while preserving operator-actionable context. (Review
/// finding MED — keychain/disk error inner-string exposure.)
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DevIdentityError {
    /// The principal string failed validation. The carried string is a
    /// fixed validation message (never the rejected input itself).
    #[error("invalid principal: {0}")]
    InvalidPrincipal(String),

    /// A signing key could not be generated. Carries a fixed op tag.
    #[error("key generation failed ({0})")]
    KeyGen(&'static str),

    /// The OS keychain returned an error. Carries a fixed op tag (NOT the
    /// raw `keyring::Error`, which can echo the service/principal).
    #[error("keychain error ({0})")]
    Keychain(&'static str),

    /// The principal is already enrolled; unenroll first.
    #[error("principal already enrolled — unenroll first")]
    AlreadyEnrolled(String),

    /// The principal is not enrolled.
    #[error("principal not enrolled")]
    NotEnrolled(String),

    /// The enrollment human-present gate refused (operator did not confirm).
    #[error("enrollment refused: {0}")]
    EnrollmentRefused(String),

    /// A filesystem I/O error occurred. Carries a fixed op tag.
    #[error("I/O error ({0})")]
    Io(&'static str),

    /// The challenge-response proof is invalid for the given public key.
    #[error("proof verification failed")]
    ProofInvalid,
}

/// Returns `true` when the error's `Display` OR `Debug` rendering contains a
/// token-shaped run (a contiguous hex sequence of ≥32 chars, the shape of a
/// leaked key seed / OAuth token prefix).
///
/// This is a defense-in-depth test guard. It scans BOTH `to_string()`
/// (Display) and `{:?}` (Debug) — the earlier version scanned only Display
/// and required the WHOLE message to be hex, so it could never fire on a
/// token embedded inside a normal sentence. The substring scan below matches
/// `error::redact_tokens` semantics and actually fires (see the unit test).
#[cfg(any(test, feature = "test-utils"))]
pub fn error_leaks_secret(err: &DevIdentityError) -> bool {
    fn has_hex_run(s: &str, min: usize) -> bool {
        let mut run = 0usize;
        for c in s.chars() {
            if c.is_ascii_hexdigit() {
                run += 1;
                if run >= min {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }
    has_hex_run(&err.to_string(), 32) || has_hex_run(&format!("{err:?}"), 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_leaks_secret_fires_on_embedded_hex_run() {
        // A 64-char hex run embedded inside an otherwise-normal message MUST
        // be detected — this is the case the old whole-string scanner missed.
        let seed = "0".repeat(64);
        let err = DevIdentityError::InvalidPrincipal(format!("rejected value: {seed}"));
        assert!(
            error_leaks_secret(&err),
            "guard must detect a ≥32-char hex run embedded in the message"
        );
    }

    #[test]
    fn error_leaks_secret_clean_on_normal_errors() {
        // Fixed-vocabulary errors carry no token-shaped material.
        assert!(!error_leaks_secret(&DevIdentityError::Keychain("entry")));
        assert!(!error_leaks_secret(&DevIdentityError::Io(
            "write enrollment tmp"
        )));
        assert!(!error_leaks_secret(&DevIdentityError::ProofInvalid));
        assert!(!error_leaks_secret(&DevIdentityError::InvalidPrincipal(
            "principal must be 1..=128 characters".into()
        )));
    }
}
