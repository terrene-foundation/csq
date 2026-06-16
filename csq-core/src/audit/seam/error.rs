//! Error types for the M18 loom↔csq provenance seam.
//!
//! All error strings use fixed-vocabulary tags (never echo raw input)
//! per `rules/security.md` §2 and `rules/tauri-commands.md` MUST-6.

use crate::audit::persist::AuditV2Error;

/// Fixed-vocabulary rejection reason at the F-SEAM-02 validating frontier.
///
/// Every variant maps to a `&'static str` tag via [`RejectReason::as_tag`].
/// The tag is the ONLY thing that appears in the `seam_event_rejected` chain
/// record — no raw event body, no echoed error string (HIGH-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// The raw bytes were not valid JSON.
    MalformedJson,
    /// A required header field was missing or had the wrong type.
    MissingRequiredField,
    /// The `decision_id` field is present but is not a valid UUID shape
    /// (8-4-4-4-12 hyphen-separated hex).
    ///
    /// Note: for v1 events the `decision_id` is NOT a UUID — it is sha256(raw).
    /// This variant is retained for the legacy test-version scaffolding
    /// (`validate_event` in frontier.rs) and is only reachable through the
    /// legacy `with_test_version` arm.
    DecisionIdNotUuid,
    /// `claimed_decision_ts` is outside the ±24h skew window relative to
    /// the daemon's wall clock.
    TimestampOutOfSkew,
    /// The `surface` field is not registered in the surface registry.
    ///
    /// Retained for the legacy test-version scaffolding arm. The v1 decoder
    /// derives surface from kind+payload and does NOT check the surface registry.
    UnregisteredSurface,
    /// The raw body exceeds the maximum allowed size.
    BodyTooLarge,
    // ── v1 decoder variants ────────────────────────────────────────────────
    /// The v1 event has an unknown `kind` value.
    UnknownKind,
    /// The v1 event's `prev_link` field is present but not a valid SHA-256 hex
    /// string (must be exactly 64 lowercase hex digits).
    PrevLinkNotSha256,
    /// The v1 event's closed shape was violated: an extra key was present at
    /// the top level or in `operator_ref`.
    ClosedShapeViolation,
    /// A payload key matched the credential-shaped key denylist (e.g. `api_key`,
    /// `access_token`) or a payload string value contained a live token.
    CredentialShapedKey,
    /// An `Action` event had neither `file_path` nor `command_sha256` in its
    /// payload — the surface cannot be derived.
    ActionDiscriminatorMissing,
    /// The re-canonicalization oracle check failed: `sha256(raw)` did not
    /// equal `received_bytes_hash` as computed by the precheck. This is an
    /// internal consistency error (should be unreachable in production) but
    /// MUST be checked in release builds so the invariant holds in the shipped
    /// artifact (LOW-2 fix).
    CanonicalHashMismatch,
}

impl RejectReason {
    /// Returns the fixed-vocabulary `&'static str` tag used in chain records
    /// and IPC error responses. NEVER echoes upstream content.
    #[must_use]
    pub fn as_tag(&self) -> &'static str {
        match self {
            RejectReason::MalformedJson => "malformed_json",
            RejectReason::MissingRequiredField => "missing_required_field",
            RejectReason::DecisionIdNotUuid => "decision_id_not_uuid",
            RejectReason::TimestampOutOfSkew => "timestamp_out_of_skew",
            RejectReason::UnregisteredSurface => "unregistered_surface",
            RejectReason::BodyTooLarge => "body_too_large",
            RejectReason::UnknownKind => "unknown_kind",
            RejectReason::PrevLinkNotSha256 => "prev_link_not_sha256",
            RejectReason::ClosedShapeViolation => "closed_shape_violation",
            RejectReason::CredentialShapedKey => "credential_shaped_key",
            RejectReason::ActionDiscriminatorMissing => "action_discriminator_missing",
            RejectReason::CanonicalHashMismatch => "canonical_hash_mismatch",
        }
    }
}

/// Top-level error from [`crate::audit::seam::ingest_provenance_event`].
///
/// Every variant uses fixed-vocabulary tags or opaque wrapping — no raw
/// upstream input echoed per `rules/security.md` §2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeamError {
    /// I/O error writing to `.quarantine/` or `.pending/provenance/`.
    #[error("seam io error: custody write failed")]
    Io(#[from] std::io::Error),

    /// The audit chain write failed (signing key unavailable / chain broken).
    #[error("seam chain write failed")]
    ChainWrite(#[from] AuditV2Error),

    /// The anchored path was reached before `csq audit init` provisioned a
    /// signing key. An unsigned `ProvenanceAnchored` record carrying
    /// `backing: verified` is a false-trust artifact, so the anchored path
    /// fails closed — but with an ACTIONABLE tag so the operator knows the
    /// cause (R2 LOW-3; `tauri-commands.md` MUST-6 named-variant→specific-text).
    /// The rejection path stays unsigned-tolerant and is unaffected.
    #[error("seam anchor requires signing key — run `csq audit init`")]
    AnchorRequiresInit,

    /// The surface registry could not be loaded (I/O or JSON parse error).
    #[error("seam registry load failed")]
    RegistryLoad,

    /// The custody directory has reached the hard ceiling.
    ///
    /// Returned when the quarantine or pending-provenance custody directory
    /// has accumulated `CUSTODY_HARD_CAP` or more files. The ingest
    /// operation is refused; the caller MUST stop sending events until an
    /// operator drains the backlog.
    #[error("seam custody full (hard ceiling reached)")]
    CustodyFull,

    /// Internal error (e.g. chain-id generation failure).
    #[error("seam internal error")]
    Internal,
}
