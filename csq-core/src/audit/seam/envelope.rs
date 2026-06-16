//! F101-1 envelope header projection.
//!
//! `F101Envelope` is the parsed HEADER subset csq depends on being frozen.
//! It deliberately tolerates unknown extra fields (loom owns the format and
//! may add fields csq does not know about; extras stay in the opaque
//! signed-over bytes). This is NOT `#[serde(deny_unknown_fields)]`.
//!
//! The full raw bytes are signed-over as-received (F-SEAM-01(c)); this
//! struct is only a parsed projection for indexing + validation.

use serde::Deserialize;

use super::error::RejectReason;

/// Parsed header projection of a loom F101-1 provenance event.
///
/// Fields listed here are the frozen header contract csq depends on.
/// Unknown extra fields in the inbound JSON are silently tolerated —
/// they live in the signed-over raw bytes, not in this struct.
///
/// `principal` is the CLAIMED actor — it is UNTRUSTED metadata until
/// resolved via M17 `attest_authorship`.
#[derive(Debug, Clone)]
pub struct F101Envelope {
    /// F101-1 schema version string (e.g. `"1"`).
    pub f101_schema_version: String,
    /// Stable event UUID — the idempotent-dedup key.
    ///
    /// loom supplies this; csq performs ingest-time dedup by scanning the chain
    /// for prior `ProvenanceAnchored` records with the same `decision_id`.
    /// A second POST with the same id returns 202 `DuplicateSuppressed` —
    /// the first anchor is authoritative.
    ///
    /// M20 will harden dedup inside the chain-write lock to close the narrow
    /// TOCTOU window in the current O(n) scan.
    pub decision_id: String,
    /// Data-driven surface identifier (e.g. `"cc"`, `"codex"`, `"gemini"`).
    pub surface: String,
    /// Per-source monotonic counter — intra-source ordering evidence.
    pub source_counter: u64,
    /// loom's claimed decision timestamp — EVIDENCE ONLY, never chain order.
    pub claimed_decision_ts: String,
    /// Claimed actor principal — UNTRUSTED until attested via M17.
    pub principal: Option<String>,
    /// `sha256(canonical(human_words))` when the event carried words.
    pub words_hash: Option<String>,
}

/// Serde-level deserialization target. Tolerates unknown fields (no
/// `deny_unknown_fields`) so loom can add fields without breaking csq.
#[derive(Deserialize)]
struct RawF101Header {
    f101_schema_version: Option<serde_json::Value>,
    decision_id: Option<serde_json::Value>,
    surface: Option<serde_json::Value>,
    source_counter: Option<serde_json::Value>,
    claimed_decision_ts: Option<serde_json::Value>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    words_hash: Option<String>,
}

/// Extract a required string field from a JSON value.
///
/// Returns `Err(MissingRequiredField)` when absent, null, or not a string.
fn required_string(
    v: Option<serde_json::Value>,
    _field: &'static str,
) -> Result<String, RejectReason> {
    match v {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s),
        _ => Err(RejectReason::MissingRequiredField),
    }
}

/// Extract a required u64 field from a JSON value.
///
/// Returns `Err(MissingRequiredField)` when absent, null, or not a non-negative
/// integer within u64 range.
fn required_u64(v: Option<serde_json::Value>, _field: &'static str) -> Result<u64, RejectReason> {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or(RejectReason::MissingRequiredField),
        _ => Err(RejectReason::MissingRequiredField),
    }
}

impl F101Envelope {
    /// Parse the envelope from raw bytes.
    ///
    /// Returns `Err(MalformedJson)` on JSON parse failure, or the appropriate
    /// `RejectReason` when a required field is missing/wrong-typed.
    ///
    /// Does NOT validate `decision_id` UUID shape, timestamp skew, or surface
    /// registration — those are done in [`crate::audit::seam::frontier`].
    pub fn parse(raw: &[u8]) -> Result<Self, RejectReason> {
        let header: RawF101Header =
            serde_json::from_slice(raw).map_err(|_| RejectReason::MalformedJson)?;

        let f101_schema_version =
            required_string(header.f101_schema_version, "f101_schema_version")?;
        let decision_id = required_string(header.decision_id, "decision_id")?;
        let surface = required_string(header.surface, "surface")?;
        let source_counter = required_u64(header.source_counter, "source_counter")?;
        let claimed_decision_ts =
            required_string(header.claimed_decision_ts, "claimed_decision_ts")?;

        Ok(F101Envelope {
            f101_schema_version,
            decision_id,
            surface,
            source_counter,
            claimed_decision_ts,
            principal: header.principal,
            words_hash: header.words_hash,
        })
    }
}
