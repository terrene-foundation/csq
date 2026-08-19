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
///
/// `#[non_exhaustive]`: "closed" describes the vocabulary at any given crate
/// version, not a promise it will never grow — `LicenseRequired` itself landed
/// after the first four codes shipped (W4). Sealing forces an external `match` to
/// carry a `_ =>` fallback, so a future code degrades gracefully instead of
/// failing to compile. Unit-variant construction (`SdkErrorCode::Internal`) is
/// unaffected — only exhaustive matching is restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
    /// The op requires an attended interactive session — a TTY the caller can
    /// block on (a device-auth confirmation, a paste prompt) or a local browser
    /// the provider's own subprocess can drive — and neither is present. Distinct
    /// from [`Self::InvalidInput`]: the caller-supplied arguments are well-formed;
    /// the RUNTIME cannot proceed non-interactively. Exists so a host driving
    /// `csq login` unattended (piped stdin, no TTY, no local display) gets an
    /// immediate, actionable signal instead of the op blocking on a read that
    /// will never be satisfied (an internal ticket).
    InteractionRequired,
    /// An authoring-session request or response named a tenant other than the one
    /// the session was established for (an internal ticket). Distinct from
    /// [`Self::IdentityMismatch`]: the tenant is the outermost isolation boundary, so
    /// a consumer's recovery is to re-open the session under the correct tenant
    /// rather than to re-verify an operator.
    TenantMismatch,
    /// An authoring-session request or response named a verified operator or session
    /// other than the established one, or a response that did not echo its request's
    /// correlation (an internal ticket). One code covers the operator/session pair
    /// deliberately: the consumer's recovery is the same (re-establish the session),
    /// and separate codes would report which half of the pair matched.
    IdentityMismatch,
    /// An authoring-session request's regional-routing evidence was not admitted by
    /// the session's policy (an internal ticket) — a region outside the allowed set, a cited
    /// policy that is not the session's, a restated allowed set that differs from the
    /// session's, or a policy that admits no region at all. Emitted BEFORE any
    /// provider egress; see `crate::authoring_session::EgressAuthorization` for the
    /// type-level mechanism that enforces that ordering.
    RoutingDenied,
    /// An authoring-INTENT turn did not continue the session at the index it awaits
    /// (an internal ticket) — a replay of an already-accepted turn, a gap over a skipped
    /// one, or a response addressing a different turn than its request. Distinct from
    /// [`Self::InvalidInput`] on the precedent [`Self::InteractionRequired`] set: the
    /// caller's arguments are well-formed, and it is the SESSION STATE that disagrees.
    /// The consumer's recovery is mechanical — resend at
    /// `crate::authoring_intent::IntentTurnSequence::expected_index` — which is why
    /// the index is read from the caller's own cursor and never carried in the message.
    TurnOutOfSequence,
    /// An authoring-intent response did not reproduce its request's worker utterance
    /// byte-for-byte (an internal ticket). A separate code because the recovery is neither a
    /// retry nor a re-establishment: the pipeline altered the worker's own words, so
    /// the turn's output must be rejected rather than reissued.
    UtteranceAltered,
    /// An authoring-session response asserted a delivery form factor that the
    /// session's own form-factor signals do not imply (an internal ticket). Distinct from
    /// [`Self::InvalidInput`]: the payload is well-formed; the inference it carries
    /// simply is not the one re-derived from the request's signals. Exists so a
    /// GUESSED form factor cannot reach a consumer wearing the grammar of an inferred
    /// one — see `crate::authoring_distill::DistillationResponse::accept`, which
    /// recomputes the inference rather than trusting it.
    InferenceUnsupported,
    /// An authoring-session memory mutation named an `expected_revision` the item is
    /// not at, so the write or removal did not apply (an internal ticket). Distinct from
    /// [`Self::InvalidInput`]: the request is well-formed and would apply against a
    /// different state, so the consumer's recovery is to re-read the authoritative
    /// state and retry rather than to fix its arguments. A mutation refused with this
    /// code produces NO receipt — nothing was applied to attest to.
    RevisionConflict,
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
            Self::InteractionRequired => "interaction_required",
            Self::TenantMismatch => "tenant_mismatch",
            Self::IdentityMismatch => "identity_mismatch",
            Self::RoutingDenied => "routing_denied",
            Self::TurnOutOfSequence => "turn_out_of_sequence",
            Self::UtteranceAltered => "utterance_altered",
            Self::InferenceUnsupported => "inference_unsupported",
            Self::RevisionConflict => "revision_conflict",
        }
    }
}

/// The `error` object attached to any envelope with `ok == false`.
///
/// Construct via [`SdkError::new`] (redacts an untrusted message) or
/// [`SdkError::trusted`] (a csq-authored const label with no secret-derivable
/// content). The `message` is a [`RedactedString`] by type, not by convention.
///
/// `#[non_exhaustive]`: forces every external construction through [`SdkError::new`]
/// / [`SdkError::trusted`], which is what makes the redaction-by-type guarantee
/// unconditional — there is no external struct-literal path that could hand a
/// pre-built `RedactedString` (bypassing [`RedactedString::from_untrusted`]) or an
/// un-redacted `String` straight into `message`.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct SdkError {
    pub code: SdkErrorCode,
    pub message: RedactedString,
    /// The set of valid values, for a `code` in the "named X does not
    /// resolve to a known Y" family (e.g. [`SdkErrorCode::ProviderNotFound`]).
    /// Lets a consumer recover programmatically instead of re-parsing
    /// `message`. `None` for error classes with no natural "known set"
    /// (e.g. [`SdkErrorCode::Timeout`]). Attach via [`SdkError::with_known`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known: Option<Vec<String>>,
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
            known: None,
        }
    }

    /// Build an error from a **csq-authored** message with no secret-derivable
    /// content (a const label). Skips redaction.
    #[must_use]
    pub fn trusted(code: SdkErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: RedactedString::from_trusted(message),
            known: None,
        }
    }

    /// Attach the set of valid values a "not found" / "unknown X" error was
    /// resolved against — e.g. `registry::known_ids()` for a
    /// [`SdkErrorCode::ProviderNotFound`] on an unrecognized `--provider`.
    #[must_use]
    pub fn with_known(mut self, known: Vec<String>) -> Self {
        self.known = Some(known);
        self
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
            (SdkErrorCode::InteractionRequired, "interaction_required"),
            (SdkErrorCode::TenantMismatch, "tenant_mismatch"),
            (SdkErrorCode::IdentityMismatch, "identity_mismatch"),
            (SdkErrorCode::RoutingDenied, "routing_denied"),
            (SdkErrorCode::TurnOutOfSequence, "turn_out_of_sequence"),
            (SdkErrorCode::UtteranceAltered, "utterance_altered"),
            (SdkErrorCode::InferenceUnsupported, "inference_unsupported"),
            (SdkErrorCode::RevisionConflict, "revision_conflict"),
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

    #[test]
    fn known_is_omitted_when_absent() {
        let err = SdkError::trusted(SdkErrorCode::ProviderNotFound, "unknown provider `bogus`");
        let rendered = serde_json::to_value(&err).unwrap();
        assert!(
            rendered.get("known").is_none(),
            "known must be omitted, not serialized as null: {rendered}"
        );
    }

    #[test]
    fn with_known_attaches_the_valid_set() {
        let err = SdkError::trusted(SdkErrorCode::ProviderNotFound, "unknown provider `bogus`")
            .with_known(vec!["claude".to_string(), "grok".to_string()]);
        let rendered = serde_json::to_value(&err).unwrap();
        assert_eq!(rendered["known"], serde_json::json!(["claude", "grok"]));
        assert_eq!(rendered["code"], "provider_not_found");
    }
}
