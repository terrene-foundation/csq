//! PKCE primitives per [RFC 7636].
//!
//! # What PKCE buys us
//!
//! A public OAuth client (csq on a user's laptop) cannot keep a
//! client secret. PKCE (Proof Key for Code Exchange) replaces the
//! static secret with a dynamic per-login proof:
//!
//! 1. Before redirecting to the authorize endpoint, csq generates a
//!    cryptographically-random [`CodeVerifier`] (32 bytes →
//!    base64url → 43 chars, per RFC 7636 §4.1).
//! 2. csq computes [`CodeChallenge`] = `base64url(SHA256(verifier))`
//!    and sends it (not the verifier) in the authorize URL.
//! 3. When Anthropic redirects back with an authorization code, csq
//!    POSTs the token exchange request with the *verifier*. The
//!    Anthropic side checks `SHA256(verifier) == stored challenge`.
//!    An attacker who intercepts the auth code (e.g., from the
//!    browser history) cannot exchange it without knowing the
//!    verifier that only csq's memory holds.
//!
//! # Security invariants
//!
//! - [`CodeVerifier`] wraps `secrecy::SecretString`. Its `Debug`
//!   impl prints `CodeVerifier([REDACTED])` — the raw bytes never
//!   land in a log, panic message, or trace span. Tests assert the
//!   redaction.
//! - The verifier byte length (32) exceeds the RFC 7636 minimum (32
//!   bytes of entropy; 43 base64url chars is the smallest legal
//!   verifier). More entropy buys nothing because Anthropic's
//!   server-side SHA256 check is the bottleneck.
//! - The PRNG is [`getrandom`], which delegates to the OS CSPRNG
//!   (`getentropy` / `BCryptGenRandom` / `/dev/urandom`). We do
//!   **not** use `rand::thread_rng` — `rand` is a heavier dep and
//!   `getrandom` is what `rand` itself wraps for seeding.
//! - No `unsafe`, no panics on the happy path. `generate_verifier`
//!   is infallible on all supported platforms; `getrandom` only
//!   fails on obscure sandboxed targets where OS entropy is
//!   unavailable, and we surface that via `expect` with an actionable
//!   message.
//!
//! [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::fmt;

/// PKCE code verifier — a high-entropy string kept secret by the
/// client until token exchange.
///
/// The inner `SecretString` guarantees the raw bytes never enter
/// `Debug` / `Display` output. Callers that genuinely need the
/// string (e.g., to serialize it into an exchange request body)
/// must explicitly call [`CodeVerifier::expose_secret`].
pub struct CodeVerifier(SecretString);

impl CodeVerifier {
    /// Wraps a pre-existing verifier string. Only call this from
    /// tests, RFC 7636 test-vector checks, or deserialization paths.
    /// Production code should use [`generate_verifier`] to get a
    /// fresh cryptographically-random verifier.
    pub fn new(s: String) -> Self {
        Self(SecretString::from(s))
    }

    /// Returns the raw verifier string. Named like `secrecy`'s own
    /// API so the call site visibly names the unwrap — reviewers
    /// can grep for `.expose_secret()` on `CodeVerifier` and audit
    /// every use.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// Length of the verifier in characters. Per RFC 7636 §4.1 this
    /// must be between 43 and 128. Our generator always produces 43.
    pub fn len(&self) -> usize {
        self.expose_secret().len()
    }

    /// Returns true if the verifier is empty. Only reachable if
    /// [`CodeVerifier::new`] is called with an empty string; the
    /// generator never produces one.
    pub fn is_empty(&self) -> bool {
        self.expose_secret().is_empty()
    }
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CodeVerifier").field(&"[REDACTED]").finish()
    }
}

impl Clone for CodeVerifier {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

/// PKCE code challenge — `base64url(SHA256(verifier))`, no padding.
///
/// The challenge is **not** secret (it's sent in the authorize URL,
/// which ends up in browser history and server logs). Storing it as
/// a plain `String` is deliberate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// Wraps a pre-existing challenge string. Intended for tests
    /// and deserialization only.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Returns the challenge string for embedding in URLs.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generates a fresh [`CodeVerifier`] from 32 bytes of OS-sourced
/// entropy. Always produces a 43-character URL-safe base64 string
/// (the minimum permitted by RFC 7636 §4.1).
///
/// # Panics
///
/// Panics only if the OS CSPRNG is unavailable — a condition that
/// cannot occur on any supported csq platform (macOS, Linux,
/// Windows). On sandboxed targets without `/dev/urandom` the panic
/// is informative rather than silent.
pub fn generate_verifier() -> CodeVerifier {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG unavailable — cannot generate PKCE verifier");
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    // 32 bytes → base64url → ceil(32*4/3) = 43 chars (no padding).
    // Asserted here so any encoder upgrade that breaks this
    // invariant is caught immediately.
    // Use `assert_eq!` (not `debug_assert_eq!`) because this is a
    // safety invariant required by RFC 7636, not a performance
    // sanity check. A future base64 crate upgrade that produced a
    // different width would otherwise silently pass in release.
    // The cost is negligible — this is the cold path, called once
    // per login and once per challenge.
    assert_eq!(encoded.len(), 43);
    CodeVerifier::new(encoded)
}

/// Computes the PKCE code challenge for a given verifier.
///
/// Per RFC 7636 §4.2: `challenge = base64url(sha256(verifier))`,
/// base64url without padding. The challenge is always 43 characters
/// long because sha256 always produces 32 bytes.
pub fn challenge_from_verifier(verifier: &CodeVerifier) -> CodeChallenge {
    let mut hasher = Sha256::new();
    hasher.update(verifier.expose_secret().as_bytes());
    let digest = hasher.finalize();
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    // Use `assert_eq!` (not `debug_assert_eq!`) because this is a
    // safety invariant required by RFC 7636, not a performance
    // sanity check. A future base64 crate upgrade that produced a
    // different width would otherwise silently pass in release.
    // The cost is negligible — this is the cold path, called once
    // per login and once per challenge.
    assert_eq!(encoded.len(), 43);
    CodeChallenge::new(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// RFC 7636 Appendix B test vector.
    ///
    /// The RFC fixes a sample verifier and its corresponding
    /// challenge so every implementation can cross-check. If our
    /// output differs from this value, the SHA256 or base64url
    /// encoding is broken.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc_7636_appendix_b_test_vector() {
        let verifier = CodeVerifier::new(RFC_VERIFIER.to_string());
        let challenge = challenge_from_verifier(&verifier);
        assert_eq!(
            challenge.as_str(),
            RFC_CHALLENGE,
            "challenge must match RFC 7636 Appendix B"
        );
    }

    #[test]
    fn generated_verifier_is_43_chars() {
        let v = generate_verifier();
        assert_eq!(v.len(), 43);
    }

    #[test]
    fn generated_verifier_uses_url_safe_alphabet() {
        let v = generate_verifier();
        let s = v.expose_secret();
        // RFC 7636 §4.1: the verifier MUST use the unreserved set
        // [A-Z] [a-z] [0-9] "-" "." "_" "~". Our base64url-no-pad
        // output uses [A-Z][a-z][0-9]-_ (no "." or "~").
        for c in s.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "unexpected character {c:?} in verifier"
            );
        }
    }

    #[test]
    fn generated_verifiers_are_unique() {
        // 100 draws from a 32-byte space are essentially guaranteed
        // unique. If this ever fails, the RNG is broken.
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let v = generate_verifier();
            assert!(
                seen.insert(v.expose_secret().to_string()),
                "duplicate verifier generated"
            );
        }
    }

    #[test]
    fn challenge_is_43_chars() {
        let v = generate_verifier();
        let c = challenge_from_verifier(&v);
        assert_eq!(c.as_str().len(), 43);
    }

    #[test]
    fn challenge_is_deterministic_for_same_verifier() {
        let v = CodeVerifier::new("same-verifier-value-for-testing".to_string());
        let c1 = challenge_from_verifier(&v);
        let c2 = challenge_from_verifier(&v);
        assert_eq!(c1, c2);
    }

    #[test]
    fn verifier_debug_does_not_leak_secret() {
        let v = CodeVerifier::new("super-secret-verifier-value".to_string());
        let debug_output = format!("{v:?}");
        assert!(
            !debug_output.contains("super-secret-verifier-value"),
            "Debug output leaked the verifier: {debug_output}"
        );
        assert!(
            debug_output.contains("REDACTED"),
            "Debug output should contain [REDACTED] marker: {debug_output}"
        );
    }

    #[test]
    fn verifier_clone_preserves_value() {
        let v1 = CodeVerifier::new("clone-me".to_string());
        let v2 = v1.clone();
        assert_eq!(v1.expose_secret(), v2.expose_secret());
    }

    #[test]
    fn challenge_display_is_the_raw_string() {
        let c = CodeChallenge::new("abc123".to_string());
        assert_eq!(format!("{c}"), "abc123");
    }

    #[test]
    fn verifier_is_empty_for_empty_string() {
        let v = CodeVerifier::new(String::new());
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
    }
}
