//! Failure policy derived only from an authenticated session pin.
use super::registry::{Event, FailurePolicy, Registry, RegistryError};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("hook registry admission failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("hook registry pin is invalid")]
    InvalidPin,
    #[error("hook registry pin namespace is unsafe")]
    UnsafePath,
    #[error("hook registry or repository differs from session pin")]
    Mismatch,
    #[error("hook registry pin could not be read or written")]
    Io,
    #[error("deny-class hook could not be admitted at pin creation")]
    Incomplete,
    #[error("hook runtime admission failed: {0}")]
    RuntimeAdmission(super::pin::RowAdmissionError),
    #[error("hook registry admission deadline expired")]
    Deadline,
    #[error("required hook registry signature verifier is unavailable")]
    SignatureUnavailable,
    #[error("reviewed hook registry digest is not configured")]
    TrustUnset,
    #[error("private hook registry pin is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, thiserror::Error)]
#[error("hook registry verification refused: {error}")]
pub struct VerificationFailure {
    pub error: PinError,
    pub policy: FailurePolicy,
}

pub(crate) fn event_policies(registry: &Registry) -> BTreeMap<Event, FailurePolicy> {
    Event::ALL
        .into_iter()
        .map(|event| {
            let deny = registry.default_on_incomplete[&event] == FailurePolicy::Deny
                || registry
                    .rows_for(event)
                    .any(|row| row.on_incomplete == FailurePolicy::Deny);
            (
                event,
                if deny {
                    FailurePolicy::Deny
                } else {
                    FailurePolicy::Continue
                },
            )
        })
        .collect()
}

/// Revalidate the complete policy binding after any verification error. Root
/// identity alone cannot authenticate a tampered saved continue value.
pub(crate) fn verification_failure(
    pin: &super::pin::Pin,
    repo: &std::path::Path,
    event: Event,
    error: PinError,
    deadline: std::time::Instant,
) -> VerificationFailure {
    if std::time::Instant::now() >= deadline
        || matches!(
            &error,
            PinError::InvalidPin | PinError::RuntimeAdmission(_) | PinError::Deadline
        )
    {
        return VerificationFailure {
            error,
            policy: FailurePolicy::Deny,
        };
    }
    let policy = pin
        .validated_fallback_policy(repo, event, deadline)
        .unwrap_or(FailurePolicy::Deny);
    let policy = if std::time::Instant::now() >= deadline {
        FailurePolicy::Deny
    } else {
        policy
    };
    VerificationFailure { error, policy }
}
