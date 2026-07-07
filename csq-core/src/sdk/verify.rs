//! `csq.verify.v1` builder — maps the internal chain-verify result onto the public
//! `csq-sdk` [`VerifyPayload`](super::VerifyPayload) DTO, supplying `EDITION`.
//!
//! This op wraps the existing chain-integrity verdict ([`crate::audit::VerifyJsonOutput`],
//! spec 12 §12.13.5) in the shared SDK envelope so a consumer discovers it via
//! `csq sdk capabilities` and branches on the same `schema` / `ok` surface every op
//! shares. The value it delivers (SDK-plan §S2 value-anchor): **a never-inherit-unproven
//! gate** — a caller runs `csq audit verify --json`, reads `ok`, and refuses to build on
//! an unproven chain.
//!
//! ## Why the builder is app-side
//!
//! The wire SHAPE ([`VerifyPayload`] + its [`VerifyKeyGap`](super::VerifyKeyGap) /
//! [`VerifyFailureDetail`](super::VerifyFailureDetail) sub-DTOs) lives in `csq-sdk`. The
//! MAPPING from csq-core's internal `VerifyJsonOutput` (whose sub-fields are the internal
//! `crate::audit::VerifyJsonKeyGap` / `crate::audit::VerifyFailureDetail` types) onto
//! those wire DTOs is app glue and stays here — the internal audit type is free to evolve
//! without disturbing the public wire contract (an internal journal entry, the mirror decision).
//!
//! ## Verdict semantics
//!
//! Verify ALWAYS produces a verdict, so this op uses [`Envelope::verdict`](super::Envelope::verdict):
//! the payload rides EVERY outcome, and `ok = result.is_ok()` reflects chain health (a
//! clean or historically-degraded chain is `ok:true` / exit 0; a `KeyNotFound`/integrity
//! failure is `ok:false`). The caller (`csq audit verify`) still derives the 3-valued
//! process exit code (0/1/2) from the same `result` via [`crate::audit::exit_code_for_error`];
//! this envelope does not encode it (the binary `ok` cannot carry the partial/integrity
//! distinction — the exit code and the `status` field do).

use super::{Envelope, VerifyPayload, EDITION, SCHEMA_VERIFY_V1};
use crate::audit::{to_json_output, LedgerError, VerifyJsonOutput, VerifySummary};

/// Build the `csq.verify.v1` envelope from a `verify_chain` result.
#[must_use]
pub fn build_verify_envelope(
    result: &Result<VerifySummary, LedgerError>,
) -> Envelope<VerifyPayload> {
    let ok = result.is_ok();
    let json_out = to_json_output(result);
    let payload = payload_from_json_output(json_out, EDITION);
    Envelope::verdict(SCHEMA_VERIFY_V1, None, ok, payload)
}

/// Map csq-core's internal [`VerifyJsonOutput`] onto the public `csq-sdk`
/// [`VerifyPayload`] DTO, converting the two mirrored sub-DTOs and tagging `edition`.
/// Consumes the `VerifyJsonOutput` (moves the gap vec + failure detail — no clone).
fn payload_from_json_output(o: VerifyJsonOutput, edition: &'static str) -> VerifyPayload {
    VerifyPayload {
        status: o.status,
        verified_count: o.verified_count,
        skipped_v1_count: o.skipped_v1_count,
        unknown_kind_count: o.unknown_kind_count,
        historical_key_gaps: o
            .historical_key_gaps
            .into_iter()
            .map(|g| csq_sdk::VerifyKeyGap {
                key_id: g.key_id,
                first_seq: g.first_seq,
                last_seq: g.last_seq,
                count: g.count,
            })
            .collect(),
        failure_detail: o.failure_detail.map(|d| csq_sdk::VerifyFailureDetail {
            kind: d.kind,
            message: d.message,
        }),
        trust_plane_grade: o.trust_plane_grade,
        verification_level_summary: o.verification_level_summary,
        edition,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{KeyId, Sha256Hex};
    use crate::audit::verify::KeyGap;

    // The builder maps `&Result<VerifySummary, LedgerError>` → envelope. Tests
    // construct those values directly (VerifySummary derives Default; LedgerError
    // variants are public) so the unit tests exercise the mapping in isolation,
    // with no chain-staging or keychain dependency.

    fn expected_edition() -> &'static str {
        if cfg!(feature = "enterprise") {
            "enterprise"
        } else {
            "community"
        }
    }

    #[test]
    fn clean_chain_is_ok_true_verdict_with_status_ok_and_edition() {
        let result: Result<VerifySummary, LedgerError> = Ok(VerifySummary {
            verified_count: 7,
            ..VerifySummary::default()
        });
        let env = build_verify_envelope(&result);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.verify.v1");
        assert_eq!(v["ok"], true, "a clean chain is ok:true");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["verified_count"], 7);
        assert!(
            v.get("error").is_none(),
            "verdict envelope carries no error"
        );
        assert!(v.get("failure_detail").is_none(), "ok verdict omits detail");
        // `edition` is always present (the HIGH-1 discriminant).
        assert_eq!(v["edition"], expected_edition());
    }

    #[test]
    fn historical_gap_is_ok_true_status_partial_historical_with_gaps() {
        // Chain-linked but signature-skipped for a rotated-out key → Ok(summary)
        // with gaps → ok:true (exit 0), inheritable-but-degraded.
        let result: Result<VerifySummary, LedgerError> = Ok(VerifySummary {
            verified_count: 4,
            historical_key_gaps: vec![KeyGap {
                key_id: "ed25519:aa".to_string(),
                first_seq: 1,
                last_seq: 3,
                count: 3,
            }],
            ..VerifySummary::default()
        });
        let env = build_verify_envelope(&result);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], true, "degraded-but-linked is ok:true");
        assert_eq!(v["status"], "partial_historical");
        assert_eq!(v["historical_key_gaps"][0]["count"], 3);
        assert!(v.get("failure_detail").is_none());
    }

    #[test]
    fn integrity_failure_is_ok_false_verdict_that_keeps_the_payload() {
        // The load-bearing invariant test: a negative verdict still carries the
        // payload (status + failure_detail) and NO error object.
        let err: Result<VerifySummary, LedgerError> = Err(LedgerError::ChainBroken {
            seq: 3,
            expected_prev: Sha256Hex::genesis(),
            actual_prev: Sha256Hex::genesis(),
        });
        let env = build_verify_envelope(&err);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.verify.v1");
        assert_eq!(v["ok"], false, "an integrity failure is ok:false");
        assert_eq!(v["status"], "integrity_failure");
        assert!(
            v.get("error").is_none(),
            "verdict envelope has NO error object even on failure"
        );
        assert_eq!(
            v["failure_detail"]["kind"], "chain_broken",
            "the failure detail rides the payload, not an error object"
        );
        assert_eq!(v["verified_count"], 0);
        assert_eq!(v["edition"], expected_edition());
    }

    #[test]
    fn key_not_found_is_ok_false_status_partial() {
        // KeyNotFound → exit-2 "partial"; ok:false (Err), status "partial".
        let err: Result<VerifySummary, LedgerError> = Err(LedgerError::KeyNotFound {
            key_id: KeyId::try_new(format!("ed25519:{}", "d".repeat(64))).unwrap(),
        });
        let env = build_verify_envelope(&err);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["status"], "partial");
        assert_eq!(v["failure_detail"]["kind"], "key_not_found");
    }

    #[test]
    fn envelope_serializes_to_a_single_line() {
        // R3: even a message with embedded newlines stays one physical line.
        let err: Result<VerifySummary, LedgerError> = Err(LedgerError::KeyNotFound {
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
        });
        let env = build_verify_envelope(&err);
        let line = env.to_line().unwrap();
        assert_eq!(
            line.matches('\n').count(),
            0,
            "verify envelope must be one physical line: {line}"
        );
    }

    /// Community: the two enterprise-only fields are omitted from the wire
    /// (byte-identical schema), disambiguated by the always-present `edition`.
    #[cfg(not(feature = "enterprise"))]
    #[test]
    fn community_omits_enterprise_only_fields() {
        let result: Result<VerifySummary, LedgerError> = Ok(VerifySummary::default());
        let env = build_verify_envelope(&result);
        let line = env.to_line().unwrap();
        assert!(
            !line.contains("trust_plane_grade"),
            "community wire must omit trust_plane_grade: {line}"
        );
        assert!(
            !line.contains("verification_level_summary"),
            "community wire must omit verification_level_summary: {line}"
        );
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["edition"], "community");
    }
}
