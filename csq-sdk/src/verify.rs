//! `csq.verify.v1` — the chain-integrity verdict payload DTO (S2).
//!
//! This crate holds only the wire SHAPE. The app (`csq-core::sdk::verify::build_verify_envelope`)
//! runs the actual chain verification and MAPS its internal audit result
//! (`VerifyJsonOutput` / `VerifySummary` / `LedgerError`) onto these DTOs, supplying the
//! `EDITION` discriminant. The sub-DTOs [`VerifyKeyGap`] / [`VerifyFailureDetail`] are
//! **mirrors** of csq-core's internal `VerifyJsonKeyGap` / `VerifyFailureDetail`: the
//! internal audit type stays free to evolve while this public wire contract stays stable.
//!
//! ## Why a verdict envelope, not success/failure
//!
//! Verify ALWAYS produces a verdict — `verified_count`, `failure_detail`, and the
//! per-level counts are meaningful even when the chain is broken. So this op uses
//! [`Envelope::verdict`](crate::Envelope::verdict): the payload rides EVERY outcome, and
//! `ok` reflects **chain health** (a clean or historically-degraded chain is `ok:true`; a
//! `KeyNotFound`/integrity failure is `ok:false`). Distinct from `exec`, where `ok:false`
//! means "no completion was produced".
//!
//! ## R1 — hand-authored DTO with an explicit `edition` discriminant
//!
//! Two fields are **enterprise-edition-only** (`None` in a community build):
//! `trust_plane_grade` and `verification_level_summary`. Because `None` serializes as
//! *absent*, a consumer cannot otherwise tell "absent because community" from "absent
//! because the enterprise chain carried no leveled records yet". The always-present
//! `edition` field resolves that ambiguity.
//!
//! ## Moat-leakage audit (R1 / `tauri-commands.md` MUST-3)
//!
//! Every field is either a fixed-vocabulary `&'static str` (`status`, `edition`,
//! `trust_plane_grade`, `failure_detail.kind`), a count (`u64`), a public Ed25519
//! `key_id`, a fixed-vocabulary human string (`failure_detail.message` — token/path-free
//! by the builder's leak-safety invariant), or the enterprise level-count map whose
//! surfacing IS the trust-plane feature. None carries a secret or a moat internal.

use std::collections::BTreeMap;

use serde::Serialize;

/// `skip_serializing_if` predicate — omit a `u64` field when zero (keeps the
/// common-case wire shape byte-identical to the pre-envelope `--json`).
fn u64_is_zero(n: &u64) -> bool {
    *n == 0
}

/// One entry in the `historical_key_gaps` array — the wire mirror of csq-core's
/// internal `VerifyJsonKeyGap`.
///
/// `#[non_exhaustive]`: construct via [`VerifyKeyGap::new`] (all four fields are
/// always present — no optional fields on this DTO).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct VerifyKeyGap {
    /// The `key_id` of the absent historical signing key.
    pub key_id: String,
    /// First sequence number in this contiguous gap run.
    pub first_seq: u64,
    /// Last sequence number in this contiguous gap run.
    pub last_seq: u64,
    /// Number of records in the gap (= `last_seq - first_seq + 1`).
    pub count: u64,
}

impl VerifyKeyGap {
    /// Build a `VerifyKeyGap` from its four always-present fields.
    #[must_use]
    pub fn new(key_id: impl Into<String>, first_seq: u64, last_seq: u64, count: u64) -> Self {
        Self {
            key_id: key_id.into(),
            first_seq,
            last_seq,
            count,
        }
    }
}

/// Typed failure detail — the wire mirror of csq-core's internal `VerifyFailureDetail`.
///
/// **Leak-safety invariant.** `message` crosses the operator stdout boundary. The
/// csq-core builder that fills it MUST interpolate ONLY shape-validated identifiers
/// (`ed25519:<hex>` key ids, record ids, `u64` seqs) or already-redacted sub-fields —
/// never a raw path or upstream body. This DTO is the wire shape; the invariant is
/// enforced at the builder (`csq-core::audit::VerifyFailureDetail::from_ledger_error`).
///
/// `#[non_exhaustive]`: construct via [`VerifyFailureDetail::new`] (both fields are
/// always present — no optional fields on this DTO).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct VerifyFailureDetail {
    /// One of: `"chain_broken"`, `"invalid_signature"`, `"key_not_found"`,
    /// `"keychain_unavailable"`, `"unsigned_record_after_cutoff"`, `"internal"`, … —
    /// a fixed vocabulary a consumer branches on.
    pub kind: &'static str,
    /// Human-readable description (fixed vocabulary — no token/path leakage).
    pub message: String,
}

impl VerifyFailureDetail {
    /// Build a `VerifyFailureDetail` from its two always-present fields.
    #[must_use]
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// The `csq.verify.v1` payload — the chain-integrity verdict plus the `edition`
/// discriminant. Field shapes for `status`, the counts, `historical_key_gaps`,
/// `failure_detail`, `trust_plane_grade`, and `verification_level_summary` are
/// byte-identical to the pre-envelope `csq audit verify --json` (spec 12 §12.13.5); the
/// envelope adds `schema` / `ok` around them and this DTO adds `edition`.
///
/// `#[non_exhaustive]`: construct via [`VerifyPayload::new`] + the `with_*` methods
/// below (fields stay `pub` for in-place mutation by the csq-core builder, e.g. the
/// unlicensed-enterprise field suppression in `csq-core::sdk::verify::build_verify_envelope`
/// — sealing blocks external struct-literal *construction*, not field assignment on
/// an already-built value).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct VerifyPayload {
    /// `"ok"` | `"partial_historical"` | `"partial"` | `"integrity_failure"` — the
    /// verdict status.
    pub status: &'static str,
    /// v2 records chain-linked without error (includes historical-key gap records
    /// whose chain-linking verified but whose signatures were skipped).
    pub verified_count: u64,
    /// v1 records skipped (not counted toward failures).
    pub skipped_v1_count: u64,
    /// Records verified opaque-but-intact (an `EventKind` a newer csq added).
    /// Omitted when `0` (the common case).
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub unknown_kind_count: u64,
    /// Historical-key gaps, present when `status == "partial_historical"`. Omitted
    /// when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub historical_key_gaps: Vec<VerifyKeyGap>,
    /// Typed failure detail when the verdict is negative (`status` is `"partial"` /
    /// `"integrity_failure"`). `None` (omitted) for `"ok"` / `"partial_historical"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<VerifyFailureDetail>,
    /// **Enterprise-only** trust-plane grade (`"COMPATIBLE"` / `"CONFORMANT"` /
    /// `"COMPLETE"`). `None` (omitted) in a community build, on verification failure,
    /// or on an ungradeable chain. Disambiguate community-absent from empty via
    /// [`VerifyPayload::edition`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_plane_grade: Option<&'static str>,
    /// **Enterprise-only** per-level record counts (`"AUTO_APPROVED"` → count, …).
    /// `None` (omitted) in a community build or when no records carry a level.
    /// Disambiguate community-absent from empty via [`VerifyPayload::edition`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_level_summary: Option<BTreeMap<String, u64>>,
    /// Per-record `VerificationLevel` for the record identified by `--record <id>`.
    /// `None` (omitted) when `--record` was not supplied; `"NOT_FOUND"` when the id
    /// was supplied but the record is absent in the chain. Community field — not
    /// enterprise-gated. Back-compat: omitted from wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_verification_level: Option<String>,
    /// The build edition (`"community"` | `"enterprise"`) — the discriminant that lets
    /// a consumer interpret an omitted enterprise-only field. Supplied by the app.
    pub edition: &'static str,
}

impl VerifyPayload {
    /// Build a `VerifyPayload` from its four always-present fields
    /// (`status`, `verified_count`, `skipped_v1_count`, `edition`). The six
    /// optional fields start at their wire-omitted default (`0` / empty / `None`)
    /// — attach them with the `with_*` methods below.
    #[must_use]
    pub fn new(
        status: &'static str,
        verified_count: u64,
        skipped_v1_count: u64,
        edition: &'static str,
    ) -> Self {
        Self {
            status,
            verified_count,
            skipped_v1_count,
            unknown_kind_count: 0,
            historical_key_gaps: Vec::new(),
            failure_detail: None,
            trust_plane_grade: None,
            verification_level_summary: None,
            record_verification_level: None,
            edition,
        }
    }

    /// Set `unknown_kind_count` (omitted from the wire when `0`).
    #[must_use]
    pub fn with_unknown_kind_count(mut self, count: u64) -> Self {
        self.unknown_kind_count = count;
        self
    }

    /// Set `historical_key_gaps` (omitted from the wire when empty).
    #[must_use]
    pub fn with_historical_key_gaps(mut self, gaps: Vec<VerifyKeyGap>) -> Self {
        self.historical_key_gaps = gaps;
        self
    }

    /// Attach the typed failure detail for a negative verdict.
    #[must_use]
    pub fn with_failure_detail(mut self, detail: VerifyFailureDetail) -> Self {
        self.failure_detail = Some(detail);
        self
    }

    /// Attach the enterprise-only trust-plane grade.
    #[must_use]
    pub fn with_trust_plane_grade(mut self, grade: &'static str) -> Self {
        self.trust_plane_grade = Some(grade);
        self
    }

    /// Attach the enterprise-only per-level record-count summary.
    #[must_use]
    pub fn with_verification_level_summary(mut self, summary: BTreeMap<String, u64>) -> Self {
        self.verification_level_summary = Some(summary);
        self
    }

    /// Attach the per-record verification level looked up for `--record <id>`.
    #[must_use]
    pub fn with_record_verification_level(mut self, level: impl Into<String>) -> Self {
        self.record_verification_level = Some(level.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SCHEMA_VERIFY_V1};

    #[test]
    fn clean_verdict_payload_serializes_ok_true_with_edition() {
        let env = Envelope::verdict(
            SCHEMA_VERIFY_V1,
            None,
            true,
            VerifyPayload {
                status: "ok",
                verified_count: 7,
                skipped_v1_count: 0,
                unknown_kind_count: 0,
                historical_key_gaps: vec![],
                failure_detail: None,
                trust_plane_grade: None,
                verification_level_summary: None,
                record_verification_level: None,
                edition: "community",
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.verify.v1");
        assert_eq!(v["ok"], true);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["verified_count"], 7);
        assert_eq!(v["edition"], "community");
        assert!(
            v.get("error").is_none(),
            "verdict envelope carries no error"
        );
        assert!(v.get("failure_detail").is_none(), "ok verdict omits detail");
        // zero/empty/None fields are omitted, keeping the common wire shape minimal.
        assert!(v.get("unknown_kind_count").is_none());
        assert!(v.get("trust_plane_grade").is_none());
    }

    #[test]
    fn negative_verdict_payload_carries_failure_detail_and_gap() {
        let env = Envelope::verdict(
            SCHEMA_VERIFY_V1,
            None,
            false,
            VerifyPayload {
                status: "integrity_failure",
                verified_count: 0,
                skipped_v1_count: 0,
                unknown_kind_count: 0,
                historical_key_gaps: vec![VerifyKeyGap {
                    key_id: "ed25519:aa".to_string(),
                    first_seq: 1,
                    last_seq: 3,
                    count: 3,
                }],
                failure_detail: Some(VerifyFailureDetail {
                    kind: "chain_broken",
                    message: "chain break at seq 3".to_string(),
                }),
                trust_plane_grade: None,
                verification_level_summary: None,
                record_verification_level: None,
                edition: "community",
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert!(
            v.get("error").is_none(),
            "verdict has no error object even on failure"
        );
        assert_eq!(v["failure_detail"]["kind"], "chain_broken");
        assert_eq!(v["historical_key_gaps"][0]["count"], 3);
    }
}
