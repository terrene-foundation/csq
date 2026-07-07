//! SDK error envelope primitives.
//!
//! Every operator- or consumer-facing error surfaced by an `sdk` op crosses
//! the stdout envelope boundary. Per `rules/security.md` §2 and the SDK plan's
//! cross-shard rule **R2**, that error carries:
//!
//! - a `code` drawn from a **closed vocabulary** ([`SdkErrorCode`]) — never a
//!   `{e}`-interpolated free string, so a consumer can branch on it and no
//!   upstream token can leak through the discriminant; and
//! - a `message` typed [`RedactedString`], which auto-redacts on construction — so an
//!   OAuth body or OS error echoed
//!   into the message cannot carry a `sk-ant-*` / long-hex secret to stdout.

use serde::Serialize;

use csq_redact::RedactedString;

/// Closed error-code vocabulary for every `sdk` envelope.
///
/// Serializes as a stable `snake_case` string (`"invalid_input"`,
/// `"no_healthy_slot"`, …). The set is intentionally small and additive: a
/// consumer matches on these; adding a variant is a compat event, so new
/// failure modes map onto an existing code unless a genuinely new consumer
/// branch is warranted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SdkErrorCode {
    /// Caller passed malformed / conflicting arguments (both prompt sources,
    /// both `--provider` and `--slot`, neither, an empty prompt, …).
    InvalidInput,
    /// A `--provider` was named but no healthy slot serves it.
    NoHealthySlot,
    /// The named provider / slot does not resolve to a known surface.
    ProviderNotFound,
    /// The provider adapter for the requested surface is not available in this
    /// op version (e.g. `csq.exec.v1` grounds only the Claude adapter today).
    Unsupported,
    /// The child process could not be spawned (binary not found, exec error).
    SpawnFailed,
    /// The child exceeded its `--timeout` and was killed.
    Timeout,
    /// The child produced output the adapter could not parse into a completion.
    OutputParseFailed,
    /// The upstream provider reported an error (non-zero exit, `is_error`).
    ProviderError,
    /// An internal csq invariant failed (resolution, IO). Last resort.
    Internal,
    /// An enterprise-only op was invoked but no valid license key is present
    /// (missing, malformed, expired, or signed by the wrong key). The enterprise
    /// binary compiles the enterprise code in but gates it at runtime behind an
    /// Ed25519-signed license key (W4). A community build never emits this code —
    /// it is a reserved member of the closed vocabulary the enterprise gate uses.
    LicenseRequired,
}

impl SdkErrorCode {
    /// The stable wire string for this code (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NoHealthySlot => "no_healthy_slot",
            Self::ProviderNotFound => "provider_not_found",
            Self::Unsupported => "unsupported",
            Self::SpawnFailed => "spawn_failed",
            Self::Timeout => "timeout",
            Self::OutputParseFailed => "output_parse_failed",
            Self::ProviderError => "provider_error",
            Self::Internal => "internal",
            Self::LicenseRequired => "license_required",
        }
    }
}

/// The `error` object attached to any envelope with `ok == false`.
///
/// Construct via [`SdkError::new`] (redacts an untrusted message) or
/// [`SdkError::trusted`] (a csq-authored const label with no secret-derivable
/// content). The `message` is a [`RedactedString`] by type, not by convention.
#[derive(Debug, Clone, Serialize)]
pub struct SdkError {
    pub code: SdkErrorCode,
    pub message: RedactedString,
}

impl SdkError {
    /// Build an error whose message came from an **untrusted** source (OS
    /// error, child stderr, upstream body). The message is redacted on
    /// construction.
    #[must_use]
    pub fn new(code: SdkErrorCode, message: impl AsRef<str>) -> Self {
        Self {
            code,
            message: RedactedString::from_untrusted(message),
        }
    }

    /// Build an error from a **csq-authored** message with no secret-derivable
    /// content (a const label). Skips redaction.
    #[must_use]
    pub fn trusted(code: SdkErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: RedactedString::from_trusted(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_wire_strings_are_snake_case_and_match_serialize() {
        for (code, wire) in [
            (SdkErrorCode::InvalidInput, "invalid_input"),
            (SdkErrorCode::NoHealthySlot, "no_healthy_slot"),
            (SdkErrorCode::ProviderNotFound, "provider_not_found"),
            (SdkErrorCode::Unsupported, "unsupported"),
            (SdkErrorCode::SpawnFailed, "spawn_failed"),
            (SdkErrorCode::Timeout, "timeout"),
            (SdkErrorCode::OutputParseFailed, "output_parse_failed"),
            (SdkErrorCode::ProviderError, "provider_error"),
            (SdkErrorCode::Internal, "internal"),
            (SdkErrorCode::LicenseRequired, "license_required"),
        ] {
            assert_eq!(code.as_str(), wire);
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
        }
    }

    #[test]
    fn error_message_is_redacted_on_construction() {
        // A leaked OAuth token in an untrusted message must not survive.
        let leaked = "refresh failed: sk-ant-oat01-AAAABBBBCCCCDDDDEEEEFFFF0000111122223333";
        let err = SdkError::new(SdkErrorCode::ProviderError, leaked);
        let rendered = serde_json::to_string(&err).unwrap();
        assert!(
            !rendered.contains("sk-ant-oat01-AAAABBBBCCCC"),
            "token must be redacted from the error message: {rendered}"
        );
        assert!(rendered.contains("provider_error"));
    }

    #[test]
    fn trusted_message_is_verbatim() {
        let err = SdkError::trusted(SdkErrorCode::InvalidInput, "prompt must not be empty");
        assert_eq!(err.message.as_str(), "prompt must not be empty");
    }
}
