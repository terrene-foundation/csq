//! F101-1 version-dispatched decoder.
//!
//! The public entry point is [`decode`]: given the raw bytes and their
//! precomputed SHA-256 hash, it dispatches to the appropriate versioned
//! sub-decoder and returns a [`DecodedEvent`].
//!
//! The `decode` function is called from `ingest.rs` AFTER the precheck
//! (version extracted + size validated) and BEFORE the ingest-anchored
//! pipeline.

pub mod credential_keys;
pub mod v1;

use crate::audit::seam::error::RejectReason;

pub use v1::OperatorRef;

/// A fully-decoded F101-1 event, ready for the anchor pipeline.
///
/// All fields are either derived by the decoder (e.g. `decision_id`,
/// `surface`) or validated from the wire (e.g. `prev_link`, `operator_ref`).
/// No raw bytes survive into this struct — HIGH-1 structural defense.
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    /// `sha256(exact received bytes)` — the signed-over artifact.
    pub decision_id: String,
    /// Derived surface identifier (artifact target).
    pub surface: String,
    /// Canonical UTC timestamp re-built from the validated Unix seconds.
    pub canonical_ts: String,
    /// The parsed `ts` as Unix seconds (for ordering annotations).
    pub claimed_unix: i64,
    /// Schema version as a string (`"1"`).
    pub schema_version_str: String,
    /// Event kind as a string (`"Decision"`, `"Delegation"`, etc.).
    pub kind: String,
    /// The validated `operator_ref` from the wire.
    pub operator_ref: OperatorRef,
    /// Hash-chain predecessor: `None` = genesis, `Some(sha256hex)` = prior event.
    pub prev_link: Option<String>,
    /// `None` for v1 (v1 has no `words_hash` field; `received_bytes_hash` is
    /// the whole-event commitment per resolved decision 4).
    pub words_hash: Option<crate::audit::types::Sha256Hex>,
    /// v1 wire `session` field (MEDIUM-2: threaded from wire to chain record).
    /// `None` for the legacy test-version scaffolding (test events have no session).
    pub session: Option<String>,
}

/// Decode a raw F101-1 event for a given schema version.
///
/// `version` is the string extracted by the precheck (e.g. `"1"`).
/// `received_bytes_hash` is the sha256 hex already computed; the decoder
/// asserts its own derivation equals it.
/// `now_unix` is used for timestamp skew validation.
///
/// Returns `Err(RejectReason)` on any validation failure.
pub fn decode(
    version: &str,
    raw: &[u8],
    now_unix: i64,
    received_bytes_hash: &str,
) -> Result<DecodedEvent, RejectReason> {
    match version {
        "1" => v1::decode_v1(raw, now_unix, received_bytes_hash),
        _ => {
            // The dispatcher in ingest.rs only calls `decode` for known versions,
            // so reaching this arm is a logic error. Return ClosedShapeViolation
            // so it quarantines rather than panics.
            Err(RejectReason::ClosedShapeViolation)
        }
    }
}
