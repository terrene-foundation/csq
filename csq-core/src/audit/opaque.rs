//! Forward-compatibility: opaque representation of a signed chain record whose
//! [`EventKind`](crate::audit::types::EventKind) is not known to THIS binary
//! (GH an internal ticket).
//!
//! # The problem this solves
//!
//! [`EventKind`](crate::audit::types::EventKind) is a closed serde enum and
//! [`EventPayload`](crate::audit::types::EventPayload) is an adjacently-tagged
//! enum with no catch-all. A csq build that predates a variant a NEWER writer
//! added fails `serde_json::from_str::<SignedRecord>` on that record, and
//! [`verify_chain`](crate::audit::verify::verify_chain) treats the parse failure
//! as `IntegrityBroken` — the chain reads as TAMPERED rather than
//! "written by a newer version". Because the daemon runs `verify_chain` before
//! socket bind, a benign version skew (daemon holding an old binary in memory +
//! a freshly-installed CLI is a NORMAL enterprise state) bricks the daemon.
//!
//! # The fix (Design B — taxonomy untouched)
//!
//! Neither `EventKind`, `EventPayload`, nor any of their ~25 exhaustive-match
//! consumers change — so the canonical form of every KNOWN record is
//! byte-identical by construction and no deployed chain regresses. Instead, when
//! the typed parse fails, the verifier falls back to parsing an [`OpaqueRecord`]
//! that captures every structural field typed and the `payload` + optional EATP
//! blobs VERBATIM via [`RawValue`]. The record then runs the SAME five integrity
//! checks (chain_id, seq-monotonicity, prev_hash link, canonical_hash recompute,
//! Ed25519 signature) plus the multi-sig inner threshold check — ONLY the typed
//! payload SEMANTICS are deferred. An unknown-kind record whose signature and
//! hash-chain verify is reported OPAQUE-BUT-INTACT (WARN + counted); a
//! signature- or hash-INVALID unknown record stays `IntegrityBroken`.
//!
//! # Why `RawValue` and not `serde_json::Value`
//!
//! `canonical_bytes_for` (persist.rs) is the signing pre-image; Check 4
//! recomputes `sha256(canonical_bytes)` and compares it to the stored
//! `canonical_hash`. `serde_json`'s `Map` is a `BTreeMap` (no `preserve_order`),
//! so round-tripping an unknown payload through `serde_json::Value` SORTS its
//! keys, while the writer emitted them in struct-declaration order — the bytes
//! diverge and Check 4 fails (trading one false-tampered for another).
//! [`RawValue`] captures the verbatim source bytes and re-emits them unchanged,
//! preserving byte-identity.
//!
//! # The drift seam
//!
//! [`OpaqueCanonicalView`] MUST mirror `persist::CanonicalView` in field order
//! and `skip_serializing_if` conditions exactly. A field added to `CanonicalView`
//! MUST be added here in the same position. This is pinned by
//! `opaque_canonical_reconstruction_is_byte_identical_to_typed` (below), which
//! reconstructs the canonical bytes of a KNOWN record through BOTH paths and
//! asserts byte-equality — drift is caught in CI at introduction, and the
//! failure direction is fail-closed (false-tampered on opaque records, never
//! false-valid).
//!
//! # Scope boundary (honest)
//!
//! This path handles a NEW `EventKind` within the EXISTING v2 record envelope. A
//! record carrying a NEW top-level CANONICAL field (a v2→v3 envelope change) is
//! NOT reconstructable by an older reader (it cannot know where the field sits in
//! canonical order) and correctly stays `IntegrityBroken` — that is a
//! `schema_version` bump, a different forward-compat axis. See spec 25 §25.12.2.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::audit::types::{Ed25519Signature, KeyId, RecordId, Sha256Hex};

/// A signed chain record whose `EventKind` is not recognized by this binary.
///
/// Structural identity/hash/signature fields are captured with their typed
/// newtypes (v2-envelope-stable — a malformed one means the record is genuinely
/// broken, which the fall-through in `verify_chain` reports as `IntegrityBroken`).
/// The `kind` is captured as a raw `String` (the whole point — it is unknown),
/// and `payload` + the optional EATP blobs are captured VERBATIM as [`RawValue`]
/// so canonical-hash reconstruction is byte-identical to the writer's output.
///
/// `#[serde(deny_unknown_fields)]` is intentionally NOT applied: a future writer
/// may add a NON-canonical top-level field (as `signature` is today), and
/// ignoring it lets the record still verify. A future CANONICAL field is a
/// different matter — it breaks the Check-4 recompute regardless (see module
/// doc "Scope boundary").
#[derive(Deserialize)]
pub(crate) struct OpaqueRecord {
    pub(crate) schema_version: String,
    pub(crate) record_id: RecordId,
    pub(crate) chain_id: RecordId,
    pub(crate) seq: u64,
    pub(crate) prev_hash: Sha256Hex,
    /// The raw, unrecognized `EventKind` tag string.
    pub(crate) kind: String,
    /// The verbatim payload JSON object (`{"kind":"<tag>","data":{...}}`).
    pub(crate) payload: Box<RawValue>,
    pub(crate) ts: String,
    pub(crate) key_id: KeyId,
    pub(crate) canonical_hash: Sha256Hex,
    pub(crate) signature: Ed25519Signature,

    // ── EATP optional fields — captured verbatim when present. ──────────────
    #[serde(default)]
    pub(crate) actor: Option<Box<RawValue>>,
    #[serde(default)]
    pub(crate) authority: Option<Box<RawValue>>,
    #[serde(default)]
    pub(crate) trust: Option<Box<RawValue>>,
    #[serde(default)]
    pub(crate) eatp_start_ts: Option<String>,
    #[serde(default)]
    pub(crate) eatp_end_ts: Option<String>,
    #[serde(default)]
    pub(crate) op_phase: Option<Box<RawValue>>,
    #[serde(default)]
    pub(crate) verification_level: Option<Box<RawValue>>,
}

/// Canonical serialization view for an [`OpaqueRecord`].
///
/// Field order and `skip_serializing_if` conditions MUST match
/// `persist::CanonicalView` exactly. Enforced by
/// `opaque_canonical_reconstruction_is_byte_identical_to_typed`.
#[derive(Serialize)]
struct OpaqueCanonicalView<'a> {
    schema_version: &'a str,
    record_id: &'a str,
    chain_id: &'a str,
    seq: u64,
    prev_hash: &'a str,
    kind: &'a str,
    payload: &'a RawValue,
    ts: &'a str,
    key_id: &'a str,
    canonical_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eatp_start_ts: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eatp_end_ts: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    op_phase: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_level: Option<&'a RawValue>,
}

impl OpaqueRecord {
    /// Canonical JSON bytes for this record with `canonical_hash` set to
    /// `canonical_hash_field`.
    ///
    /// Mirrors `persist::canonical_bytes_for`: the WRITER computes the record's
    /// own `canonical_hash` by serializing with the field set to the genesis
    /// sentinel, so Check 4 passes `Sha256Hex::GENESIS` here; seeding the NEXT
    /// record's `prev_hash` uses the record's real stored hash, so that path
    /// passes `self.canonical_hash.as_str()`.
    pub(crate) fn canonical_bytes(&self, canonical_hash_field: &str) -> Vec<u8> {
        let view = OpaqueCanonicalView {
            schema_version: &self.schema_version,
            record_id: self.record_id.as_str(),
            chain_id: self.chain_id.as_str(),
            seq: self.seq,
            prev_hash: self.prev_hash.as_str(),
            kind: &self.kind,
            payload: &self.payload,
            ts: &self.ts,
            key_id: self.key_id.as_str(),
            canonical_hash: canonical_hash_field,
            actor: self.actor.as_deref(),
            authority: self.authority.as_deref(),
            trust: self.trust.as_deref(),
            eatp_start_ts: self.eatp_start_ts.as_deref(),
            eatp_end_ts: self.eatp_end_ts.as_deref(),
            op_phase: self.op_phase.as_deref(),
            verification_level: self.verification_level.as_deref(),
        };
        // Same halt-on-fatal rationale as `persist::canonical_bytes_for`:
        // `serde_json::to_vec` over `&str`/u64/`&RawValue` can only fail under
        // allocator exhaustion, at which point the audit pipeline cannot continue.
        serde_json::to_vec(&view).expect("OpaqueCanonicalView serialization must not fail")
    }

    /// The `authority` blob parsed as a [`serde_json::Value`] for the multi-sig
    /// inner-threshold check, or `None` when the record carries no authority.
    ///
    /// This parse feeds ONLY the multi-sig membership/threshold logic; it never
    /// touches canonical bytes (which use the verbatim [`RawValue`]), so the
    /// `BTreeMap` key-reordering that `serde_json::Value` performs is harmless
    /// here — the multi-sig check reads fields by name, not by byte position.
    /// Returns `Err` on a structurally-broken authority blob so the caller can
    /// fail closed.
    pub(crate) fn authority_value(&self) -> Result<Option<serde_json::Value>, serde_json::Error> {
        match &self.authority {
            None => Ok(None),
            Some(raw) => serde_json::from_str(raw.get()).map(Some),
        }
    }
}

/// Reconstructs the canonical bytes for an opaque record with the genesis
/// sentinel in the `canonical_hash` position (Check-4 pre-image).
pub(crate) fn canonical_bytes_for_opaque_check4(r: &OpaqueRecord) -> Vec<u8> {
    r.canonical_bytes(Sha256Hex::GENESIS)
}

/// Reconstructs the canonical bytes for an opaque record with its real stored
/// `canonical_hash` — the pre-image for the NEXT record's `prev_hash` link.
pub(crate) fn canonical_bytes_for_opaque_link(r: &OpaqueRecord) -> Vec<u8> {
    r.canonical_bytes(r.canonical_hash.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::persist::canonical_bytes_for_test;
    use crate::audit::types::{
        CsqRunPayload, EatpActor, EatpAuthority, EatpTrust, Ed25519PublicKey, EventKind,
        EventPayload, KeyRotatePayload, RotationReason, SignedRecord,
    };

    /// Build a fully-populated KNOWN record (KeyRotate + every EATP optional set)
    /// so the byte-identity pin exercises every field of both canonical views.
    fn fully_populated_known_record() -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01HZ7Y2N3M4P5Q6R7S8T9V0WXY").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 7,
            prev_hash: Sha256Hex::try_new("a".repeat(64)).unwrap(),
            kind: EventKind::KeyRotate,
            payload: EventPayload::KeyRotate(KeyRotatePayload {
                previous_key_id: KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap(),
                new_key_id: KeyId::try_new(format!("ed25519:{}", "2".repeat(64))).unwrap(),
                incoming_pubkey: Ed25519PublicKey::default(),
                rotation_reason: RotationReason::Operator,
            }),
            ts: "2026-05-28T12:34:56+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "3".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::try_new("b".repeat(64)).unwrap(),
            signature: Ed25519Signature::new([9u8; 64]),
            actor: Some(EatpActor(serde_json::json!({"agent": "z", "a": 1}))),
            authority: Some(EatpAuthority(serde_json::json!({"role": "root"}))),
            trust: Some(EatpTrust(serde_json::json!({"tier": "L3"}))),
            eatp_start_ts: Some("2026-05-28T12:34:00+00:00".to_string()),
            eatp_end_ts: Some("2026-05-28T12:35:00+00:00".to_string()),
            op_phase: None,
            verification_level: None,
        }
    }

    fn parse_opaque(record: &SignedRecord) -> OpaqueRecord {
        let json = serde_json::to_string(record).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    /// STRUCTURAL PIN (drift seam): the canonical bytes reconstructed via the
    /// opaque path MUST be byte-identical to the typed `canonical_bytes_for` for
    /// a KNOWN record. This pins `OpaqueCanonicalView` against `CanonicalView` —
    /// any field-order or skip-condition drift fails here in CI, at introduction.
    #[test]
    fn opaque_canonical_reconstruction_is_byte_identical_to_typed() {
        let record = fully_populated_known_record();
        let opaque = parse_opaque(&record);
        let typed = canonical_bytes_for_test(&record);
        let via_opaque = opaque.canonical_bytes(opaque.canonical_hash.as_str());
        assert!(
            typed == via_opaque,
            "opaque canonical reconstruction diverged from typed CanonicalView — \
             check OpaqueCanonicalView field order / skip_serializing_if parity.\n\
             typed  ({} bytes): {}\nopaque ({} bytes): {}",
            typed.len(),
            String::from_utf8_lossy(&typed),
            via_opaque.len(),
            String::from_utf8_lossy(&via_opaque),
        );
    }

    /// Byte-identity must also hold with the MINIMAL record shape (no EATP
    /// optionals) so the `skip_serializing_if` branches are exercised in both
    /// present and absent states.
    #[test]
    fn opaque_canonical_reconstruction_byte_identical_minimal() {
        let record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01HZ7Y2N3M4P5Q6R7S8T9V0WXY").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "run-001".to_string(),
            }),
            ts: "2026-05-28T12:34:56+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::try_new("c".repeat(64)).unwrap(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        let opaque = parse_opaque(&record);
        assert!(
            canonical_bytes_for_test(&record)
                == opaque.canonical_bytes(opaque.canonical_hash.as_str())
        );
    }

    /// The Check-4 pre-image swaps the genesis sentinel into the canonical_hash
    /// position exactly as the typed writer does — so recomputing over the
    /// sentinel matches `canonical_bytes_for` on a genesis-hash clone.
    #[test]
    fn opaque_check4_preimage_uses_genesis_sentinel() {
        let mut record = fully_populated_known_record();
        let opaque = parse_opaque(&record);
        // Typed Check-4 pre-image: clone with canonical_hash := genesis.
        record.canonical_hash = Sha256Hex::genesis();
        let typed_sentinel = canonical_bytes_for_test(&record);
        assert!(canonical_bytes_for_opaque_check4(&opaque) == typed_sentinel);
    }

    /// A record whose `kind` string is UNKNOWN parses as an OpaqueRecord (it
    /// would fail `SignedRecord` deserialize) and reconstructs canonical bytes
    /// deterministically — the core forward-compat capability.
    #[test]
    fn unknown_kind_parses_as_opaque_and_reconstructs() {
        let record = fully_populated_known_record();
        let json = serde_json::to_string(&record).unwrap();
        // Rewrite BOTH kind tags (top-level + payload) to a future variant.
        let future = json.replace(
            "\"kind\":\"key_rotate\"",
            "\"kind\":\"quantum_attestation_v9\"",
        );
        assert!(
            serde_json::from_str::<SignedRecord>(&future).is_err(),
            "a future kind must NOT parse as a typed SignedRecord (else no bug to fix)"
        );
        let opaque: OpaqueRecord =
            serde_json::from_str(&future).expect("future kind MUST parse as OpaqueRecord");
        assert_eq!(opaque.kind, "quantum_attestation_v9");
        // Reconstruction is stable (idempotent) — the actual signature check is
        // covered by verify.rs integration tests against a signed chain.
        let a = opaque.canonical_bytes(opaque.canonical_hash.as_str());
        let opaque2: OpaqueRecord = serde_json::from_str(&future).unwrap();
        let b = opaque2.canonical_bytes(opaque2.canonical_hash.as_str());
        assert!(a == b);
    }
}
