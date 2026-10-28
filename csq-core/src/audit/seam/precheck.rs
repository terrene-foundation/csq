//! Version-AGNOSTIC pre-validation for inbound F101-1 events.
//!
//! The precheck runs BEFORE any version-specific decode. It validates:
//! 1. Body size (max `frontier::MAX_BODY_BYTES`).
//! 2. JSON well-formedness.
//! 3. `schema_version` field exists and is an integer.
//!
//! On success it returns the schema version integer AND the SHA-256 hex of the
//! raw bytes (the `decision_id` for v1+ events). The SHA-256 is computed here
//! once and re-used by the versioned decoder (oracle assertion).
//!
//! No surface/UUID/skew check here — those are version-specific.

use crate::audit::seam::error::RejectReason;
use crate::audit::seam::frontier::MAX_BODY_BYTES;

/// Result of a successful precheck.
#[derive(Debug)]
pub struct PrecheckOk {
    /// The `schema_version` integer from the wire.
    pub schema_version: i64,
    /// `sha256(raw bytes)` in lowercase hex — the `decision_id` for v1+ events.
    pub received_bytes_hash: String,
}

/// Run the version-agnostic pre-validation on `raw`.
///
/// Returns `Ok(PrecheckOk)` on success, `Err(RejectReason)` on failure.
pub fn precheck(raw: &[u8]) -> Result<PrecheckOk, RejectReason> {
    // Step 1: body size.
    if raw.len() > MAX_BODY_BYTES {
        return Err(RejectReason::BodyTooLarge);
    }

    // Step 2: JSON well-formedness + schema_version extraction.
    let v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| RejectReason::MalformedJson)?;

    let schema_version = v
        .get("schema_version")
        .and_then(|sv| sv.as_i64())
        .ok_or(RejectReason::MissingRequiredField)?;

    // Step 3: compute sha256 of exact received bytes.
    let received_bytes_hash = crate::audit::persist::sha256_hex(raw);

    Ok(PrecheckOk {
        schema_version,
        received_bytes_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_event_passes_precheck() {
        let raw = br#"{"schema_version":1,"kind":"Decision","ts":"2026-01-01T00:00:00Z"}"#;
        let ok = precheck(raw).expect("valid event must pass precheck");
        assert_eq!(ok.schema_version, 1);
        assert_eq!(ok.received_bytes_hash.len(), 64); // sha256 hex is 64 chars
    }

    #[test]
    fn oversized_body_is_rejected() {
        let oversized = vec![b'x'; MAX_BODY_BYTES + 1];
        assert!(
            matches!(precheck(&oversized), Err(RejectReason::BodyTooLarge)),
            "oversized body must be rejected with BodyTooLarge"
        );
    }

    #[test]
    fn malformed_json_is_rejected() {
        let raw = b"not valid json";
        assert!(
            matches!(precheck(raw), Err(RejectReason::MalformedJson)),
            "malformed JSON must be rejected with MalformedJson"
        );
    }

    #[test]
    fn missing_schema_version_is_rejected() {
        let raw = br#"{"kind":"Decision"}"#;
        assert!(
            matches!(precheck(raw), Err(RejectReason::MissingRequiredField)),
            "missing schema_version must be rejected"
        );
    }

    #[test]
    fn non_integer_schema_version_is_rejected() {
        let raw = br#"{"schema_version":"1","kind":"Decision"}"#;
        assert!(
            matches!(precheck(raw), Err(RejectReason::MissingRequiredField)),
            "string schema_version must be rejected (must be integer)"
        );
    }
}
