//! M11 — MultiSig error types.
//!
//! All user-string variants follow the redaction pattern used in `csq-core`:
//! messages use fixed vocabulary and MUST NOT echo attacker-controlled inputs
//! (per `rules/security.md §2`). Public-key material and signature hex ARE
//! safe to surface (public material by definition); private seeds NEVER appear.

use thiserror::Error;

/// Errors from M11 multi-sig authorization and verification operations.
///
/// All variants carry fixed-vocabulary messages or field names that do NOT
/// echo raw incoming bytes beyond hex of PUBLIC material (pubkeys, signatures).
///
/// # Secret-leak guard
///
/// `error_leaks_secret` (test-utils only) detects whether an error's
/// `Display` or `Debug` rendering contains a contiguous hex run of ≥32
/// chars — the shape of a leaked private seed or OAuth token. Fixed-vocab
/// messages and public-key hex (32 bytes = 64 hex chars, which IS above the
/// threshold but is acceptable public material) must be reviewed for the
/// threshold collision; the guard is a defense-in-depth backstop.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MultiSigError {
    /// Fewer valid signatures were collected than the policy threshold requires.
    ///
    /// Fail-closed: the op MUST NOT proceed.
    #[error(
        "multi-sig authorization failed: needed {needed} valid signature(s), got {got} — \
         op cannot proceed"
    )]
    InsufficientSignatures {
        /// Number of valid signatures required by the policy.
        needed: usize,
        /// Number of valid signatures actually collected.
        got: usize,
    },

    /// A signer produced a signature that failed its own self-check against the
    /// signer's own public key. This indicates a corrupt signing key and the
    /// authorization was dropped (not counted). Logged via `tracing::warn`.
    ///
    /// If dropping all corrupt-key signers leaves `got < needed`, the outer
    /// `InsufficientSignatures` variant fires.
    #[error("signer self-check failed ({0}) — corrupt key dropped from authorization count")]
    SignerSelfCheckFailed(&'static str),

    /// An underlying signing operation returned an error.
    #[error("signing operation failed ({0})")]
    SigningFailed(&'static str),

    /// The `authority` blob in a `SignedRecord` claims to be a multi-sig blob
    /// but is structurally malformed (missing required fields, bad hex encoding,
    /// wrong byte lengths, or non-integer threshold).
    ///
    /// A record that CLAIMS multi-sig with a broken blob MUST be rejected
    /// (fail-closed — never silently accept).
    #[error("multi-sig authority blob is malformed: {0}")]
    MalformedAuthorityBlob(&'static str),

    /// A multi-sig record carries fewer valid inner authorizations than its
    /// own `threshold` field requires. Distinct from `InsufficientSignatures`
    /// (which fires during collection) — this fires during verification of
    /// an already-written record.
    #[error(
        "multi-sig record verification failed: threshold {threshold}, \
         valid authorizations {valid} — record is under-threshold"
    )]
    VerificationUnderThreshold {
        /// The threshold field value from the authority blob.
        threshold: u64,
        /// The number of authorizations that verified successfully.
        valid: u64,
    },

    /// A record whose `kind` maps to a guarded op-class (KeyRotate /
    /// IdentityMint / ReleaseAuth), at or after the roster activation seq,
    /// carries NO `multi_sig` authority blob.
    ///
    /// Under active enterprise roster enforcement a guarded op MUST carry a
    /// roster-backed multi-sig authorization. Without this check the fast path
    /// (`authority: None` → `Ok`) would let an attacker who controls a single
    /// (outgoing) signing key forge an authority-less guarded record — bypassing
    /// the N-of-M roster threshold entirely. Fail-closed.
    #[error(
        "guarded op-class record at or after roster activation carries no multi-sig \
         authorization — roster enforcement requires one; record rejected"
    )]
    MissingAuthorizationForGuardedOp,
}

/// Returns `true` when the error's `Display` OR `Debug` rendering contains a
/// token-shaped run (a contiguous hex sequence of ≥32 chars beyond what is
/// expected for public-key material embedded in a known-format message).
///
/// Defense-in-depth test guard. Mirrors `dev_identity::error::error_leaks_secret`.
/// Note: pubkey hex (64 chars) legitimately exceeds the 32-char threshold —
/// the guard is therefore most useful for catching cases where a private seed
/// or token is accidentally interpolated. Tests that surface pubkeys in error
/// messages should verify the display is intentional.
#[cfg(any(test, feature = "test-utils"))]
pub fn error_leaks_secret(err: &MultiSigError) -> bool {
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
    fn error_leaks_secret_clean_on_fixed_vocab_errors() {
        // Fixed-vocabulary errors carry no token-shaped material.
        assert!(!error_leaks_secret(
            &MultiSigError::InsufficientSignatures { needed: 2, got: 1 }
        ));
        assert!(!error_leaks_secret(&MultiSigError::SignerSelfCheckFailed(
            "self_check"
        )));
        assert!(!error_leaks_secret(&MultiSigError::SigningFailed("sign")));
        assert!(!error_leaks_secret(&MultiSigError::MalformedAuthorityBlob(
            "missing threshold"
        )));
        assert!(!error_leaks_secret(
            &MultiSigError::VerificationUnderThreshold {
                threshold: 2,
                valid: 1
            }
        ));
        assert!(!error_leaks_secret(
            &MultiSigError::MissingAuthorizationForGuardedOp
        ));
    }
}
