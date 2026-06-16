//! F101-1 schema version "1" typed decoder.
//!
//! Decodes the frozen v1 event shape into a [`DecodedEvent`] (exported from
//! `decode::mod`). The decoder is the authoritative owner of:
//!
//! - `decision_id` = `sha256(exact received bytes)` — derived here; never
//!   re-canonicalized (F-SEAM-01(c)).
//! - `surface` — derived from `kind` + `payload` per the surface-derivation rules.
//! - `prev_link` — decoded from the wire; `None` = genesis.
//!
//! ## Wire shape (order-independent via serde)
//!
//! The v1 wire event carries keys in lexicographic order; this decoder uses
//! typed serde structs with `#[serde(deny_unknown_fields)]` so an extra key
//! at the top level is rejected with `ClosedShapeViolation`. `OperatorRef` is
//! also closed.
//!
//! ## Key validation
//!
//! After serde decode, the `payload` is screened by
//! `credential_keys::screen`. This is the second credential screen
//! (the first is the value-side `redact_tokens` already applied in
//! `ingest_rejected`).

use serde::Deserialize;
use serde_json::Value;

use crate::audit::seam::error::RejectReason;
use crate::audit::seam::frontier::{parse_iso8601_to_unix_pub, SKEW_WINDOW_SECS};
use crate::audit::types::Sha256Hex;

use super::super::decode::DecodedEvent;
use super::credential_keys;

/// The wire v1 event — closed shape, order-independent via serde.
///
/// `#[serde(deny_unknown_fields)]` ensures any extra key at the top level is
/// rejected with `ClosedShapeViolation` (HIGH-1: no leakage through unknown
/// fields in the decoded projection; raw bytes are still signed-over).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Event {
    schema_version: i64,
    kind: String,
    ts: String,
    session: String,
    operator_ref: OperatorRef,
    payload: Value,
    #[serde(default)]
    prev_link: Option<String>,
}

/// Closed `operator_ref` sub-object.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRef {
    pub verified_id: String,
    pub person_id: String,
    #[serde(default)]
    pub display_id: Option<String>,
}

/// Decode a raw v1 event body into a [`DecodedEvent`].
///
/// Called from `decode::decode` when `schema_version == "1"`.
/// `now_unix` is used for timestamp skew validation.
/// `received_bytes_hash` is the sha256 already computed by the precheck; the
/// decoder asserts its own derivation equals it (a second-oracle check).
pub(super) fn decode_v1(
    raw: &[u8],
    now_unix: i64,
    received_bytes_hash: &str,
) -> Result<DecodedEvent, RejectReason> {
    // Step 1: typed decode — closed shape.
    let event: V1Event =
        serde_json::from_slice(raw).map_err(|_| RejectReason::ClosedShapeViolation)?;

    // Step 2: schema_version must be 1.
    if event.schema_version != 1 {
        return Err(RejectReason::MissingRequiredField);
    }

    // Step 3: kind must be a known enum variant.
    let kind = match event.kind.as_str() {
        "Decision" | "Delegation" | "Action" | "HumanInput" => event.kind.clone(),
        _ => return Err(RejectReason::UnknownKind),
    };

    // Step 4: timestamp parse + skew check.
    // Re-use frontier's parser (made pub(crate) for v1).
    let claimed_unix =
        parse_iso8601_to_unix_pub(&event.ts).ok_or(RejectReason::TimestampOutOfSkew)?;
    let abs_delta = now_unix.saturating_sub(claimed_unix).unsigned_abs() as i64;
    if abs_delta > SKEW_WINDOW_SECS {
        return Err(RejectReason::TimestampOutOfSkew);
    }

    // Re-serialize to canonical timestamp (H2 fix).
    let canonical_ts = crate::audit::seam::frontier::unix_to_canonical_ts_pub(claimed_unix);

    // Step 5: session non-empty.
    if event.session.is_empty() {
        return Err(RejectReason::MissingRequiredField);
    }

    // Step 6: operator_ref fields non-empty.
    if event.operator_ref.verified_id.is_empty() || event.operator_ref.person_id.is_empty() {
        return Err(RejectReason::MissingRequiredField);
    }

    // Step 7: prev_link must be None or a valid Sha256Hex (64 lowercase hex).
    if let Some(ref pl) = event.prev_link {
        if Sha256Hex::try_new(pl).is_err() {
            return Err(RejectReason::PrevLinkNotSha256);
        }
    }

    // Step 8: derive surface from kind + payload.
    let surface = derive_surface(&kind, &event.payload)?;

    // Step 9: screen the ENTIRE event for credential-shaped keys / live token
    // values — NOT just `payload`. `session` and the `operator_ref` fields
    // (verified_id / person_id / display_id) are attacker-controlled free-text
    // that flow verbatim into the signed chain record + the auditor-shipped
    // PROVENANCE.json (R3 security M-1). Screening only `payload` left them as a
    // token-smuggling vector. Re-parsing `raw` as an untyped Value lets the
    // recursive screen cover every key + string value at once. The conformance
    // vector's values (hex verified_id, `pid-…`, `sess-…`, journal paths) carry
    // no live-token prefix, so they pass.
    let full_event: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| RejectReason::MalformedJson)?;
    credential_keys::screen(&full_event).map_err(|_| RejectReason::CredentialShapedKey)?;

    // Step 10: derive decision_id = sha256(exact received bytes).
    // The precheck already computed this; assert equality (oracle check).
    // LOW-2: promoted from debug_assert_eq! to a real guard so the
    // re-canonicalization oracle holds in the shipped release artifact.
    let decision_id = crate::audit::persist::sha256_hex(raw);
    if decision_id != received_bytes_hash {
        return Err(RejectReason::CanonicalHashMismatch);
    }

    Ok(DecodedEvent {
        decision_id,
        surface,
        canonical_ts,
        claimed_unix,
        schema_version_str: "1".to_string(),
        kind,
        operator_ref: event.operator_ref,
        prev_link: event.prev_link,
        words_hash: None,             // v1 has no words_hash field
        session: Some(event.session), // MEDIUM-2: thread session through
    })
}

/// Derive the surface identifier from the event `kind` and `payload`.
///
/// Surface-derivation rules:
/// - `Decision`    → `payload.journal_path` (string, required)
/// - `Delegation`  → `payload.subagent_type` (string) else `"delegation:" + payload.tool`
/// - `Action`      → `payload.file_path` (if present) else `"shell"` when
///   `payload.command_sha256` present; else `ActionDiscriminatorMissing`
/// - `HumanInput`  → `"human-input"` (fixed)
///
/// All derived surfaces are then validated: max 256 bytes, no ASCII control chars.
fn derive_surface(kind: &str, payload: &Value) -> Result<String, RejectReason> {
    let raw_surface = match kind {
        "Decision" => {
            let jp = payload
                .get("journal_path")
                .and_then(Value::as_str)
                .ok_or(RejectReason::MissingRequiredField)?;
            jp.to_string()
        }
        "Delegation" => {
            if let Some(st) = payload.get("subagent_type").and_then(Value::as_str) {
                st.to_string()
            } else {
                let tool = payload
                    .get("tool")
                    .and_then(Value::as_str)
                    .ok_or(RejectReason::MissingRequiredField)?;
                format!("delegation:{tool}")
            }
        }
        "Action" => {
            if let Some(fp) = payload.get("file_path").and_then(Value::as_str) {
                fp.to_string()
            } else if payload
                .get("command_sha256")
                .and_then(Value::as_str)
                .is_some()
            {
                "shell".to_string()
            } else {
                return Err(RejectReason::ActionDiscriminatorMissing);
            }
        }
        "HumanInput" => "human-input".to_string(),
        _ => return Err(RejectReason::UnknownKind),
    };

    // Validate derived surface: max 256 bytes, no ASCII control characters.
    if raw_surface.is_empty() || raw_surface.len() > 256 {
        return Err(RejectReason::MissingRequiredField);
    }
    if raw_surface.bytes().any(|b| b < 0x20) {
        return Err(RejectReason::MissingRequiredField);
    }

    Ok(raw_surface)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Derive now_unix from the conformance vector ts "2026-06-09T15:44:57.000Z"
    fn conformance_now_unix() -> i64 {
        // 2026-06-09T15:44:57Z
        parse_iso8601_to_unix_pub("2026-06-09T15:44:57Z").expect("ts must parse")
    }

    /// The 374-byte conformance vector (byte-exact).
    const CONFORMANCE_VECTOR: &[u8] = br#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/0252-esperie-DECISION-427-variant-only-mechanical-distribution.md","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sess-CONFORMANCE-V1-0001","ts":"2026-06-09T15:44:57.000Z"}"#;
    const EXPECTED_DECISION_ID: &str =
        "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a";

    #[test]
    fn sha256_of_vector_equals_expected() {
        let hash = crate::audit::persist::sha256_hex(CONFORMANCE_VECTOR);
        assert_eq!(
            hash, EXPECTED_DECISION_ID,
            "sha256(conformance vector) must equal the pinned EXPECTED_DECISION_ID"
        );
    }

    #[test]
    fn decoder_derives_correct_triple() {
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(CONFORMANCE_VECTOR);
        let decoded = decode_v1(CONFORMANCE_VECTOR, now, &hash).expect("must decode");

        assert_eq!(decoded.decision_id, EXPECTED_DECISION_ID);
        assert_eq!(
            decoded.surface,
            "journal/0252-esperie-DECISION-427-variant-only-mechanical-distribution.md"
        );
        assert!(
            decoded.prev_link.is_none(),
            "genesis event has no prev_link"
        );
        assert_eq!(decoded.kind, "Decision");
    }

    #[test]
    fn extra_key_rejected_closed_shape() {
        // An extra key at the top level must be rejected.
        let raw = br#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/foo.md","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z","extra_field":"bad"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::ClosedShapeViolation)),
            "extra key must produce ClosedShapeViolation; got {result:?}"
        );
    }

    #[test]
    fn non_hex_prev_link_rejected() {
        let raw = br#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/foo.md","tool":"Write"},"prev_link":"not-a-hex-string","schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::PrevLinkNotSha256)),
            "non-hex prev_link must produce PrevLinkNotSha256; got {result:?}"
        );
    }

    #[test]
    fn credential_key_in_payload_rejected() {
        let raw = br#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"api_key":"harmless","journal_path":"journal/foo.md","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::CredentialShapedKey)),
            "api_key in payload must produce CredentialShapedKey; got {result:?}"
        );
    }

    #[test]
    fn live_token_in_payload_rejected() {
        // A live sk-ant-* value under a benign key must fail the value screen.
        let raw_str = r#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"sk-ant-api03-XXXX1234567890abcdef1234567890abcdef12","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z"}"#.to_string();
        let raw = raw_str.as_bytes();
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::CredentialShapedKey)),
            "live token in payload must produce CredentialShapedKey; got {result:?}"
        );
    }

    #[test]
    fn live_token_in_session_rejected() {
        // R3 security M-1: a live token smuggled in the top-level `session`
        // field (NOT payload) must be rejected — the whole-event screen covers it.
        let raw = br#"{"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/foo.md","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sk-ant-oat01-XXXX1234567890abcdef1234567890abcdef12","ts":"2026-06-09T15:44:57.000Z"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::CredentialShapedKey)),
            "live token in session must be rejected (R3 M-1); got {result:?}"
        );
    }

    #[test]
    fn live_token_in_operator_ref_rejected() {
        // R3 security M-1: a live token smuggled in operator_ref.display_id must
        // be rejected — operator_ref free-text reaches the bundle too.
        let raw = br#"{"kind":"Decision","operator_ref":{"display_id":"ghp_FAKETESTTOKENDONOTUSE000000000000000","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/foo.md","tool":"Write"},"prev_link":null,"schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::CredentialShapedKey)),
            "live token in operator_ref must be rejected (R3 M-1); got {result:?}"
        );
    }

    #[test]
    fn action_missing_discriminator_rejected() {
        let raw = br#"{"kind":"Action","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"description_chars":42},"prev_link":null,"schema_version":1,"session":"sess-001","ts":"2026-06-09T15:44:57.000Z"}"#;
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(raw);
        let result = decode_v1(raw, now, &hash);
        assert!(
            matches!(result, Err(RejectReason::ActionDiscriminatorMissing)),
            "Action with neither file_path nor command_sha256 must fail; got {result:?}"
        );
    }

    // ── LOW-4: positive tests for every surface-derivation branch ──

    #[test]
    fn surface_delegation_with_subagent_type() {
        let now = conformance_now_unix();
        let raw = serde_json::to_vec(&serde_json::json!({
            "kind": "Delegation",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-10e7dd16",
                "verified_id": "548F2C562EB4246D025FA80A70552B124755B685"
            },
            "payload": {
                "subagent_type": "rust-specialist",
                "tool": "Agent"
            },
            "prev_link": null,
            "schema_version": 1,
            "session": "sess-001",
            "ts": "2026-06-09T15:44:57.000Z"
        }))
        .unwrap();
        let hash = crate::audit::persist::sha256_hex(&raw);
        let decoded =
            decode_v1(&raw, now, &hash).expect("Delegation with subagent_type must decode");
        assert_eq!(
            decoded.surface, "rust-specialist",
            "Delegation with subagent_type: surface must equal subagent_type"
        );
    }

    #[test]
    fn surface_delegation_tool_fallback() {
        let now = conformance_now_unix();
        let raw = serde_json::to_vec(&serde_json::json!({
            "kind": "Delegation",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-10e7dd16",
                "verified_id": "548F2C562EB4246D025FA80A70552B124755B685"
            },
            "payload": {
                "tool": "Task"
            },
            "prev_link": null,
            "schema_version": 1,
            "session": "sess-001",
            "ts": "2026-06-09T15:44:57.000Z"
        }))
        .unwrap();
        let hash = crate::audit::persist::sha256_hex(&raw);
        let decoded = decode_v1(&raw, now, &hash).expect("Delegation tool-fallback must decode");
        assert_eq!(
            decoded.surface, "delegation:Task",
            "Delegation without subagent_type: surface must be 'delegation:' + tool"
        );
    }

    #[test]
    fn surface_action_write_file_path() {
        let now = conformance_now_unix();
        let raw = serde_json::to_vec(&serde_json::json!({
            "kind": "Action",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-10e7dd16",
                "verified_id": "548F2C562EB4246D025FA80A70552B124755B685"
            },
            "payload": {
                "file_path": "src/lib.rs",
                "description_chars": 42
            },
            "prev_link": null,
            "schema_version": 1,
            "session": "sess-001",
            "ts": "2026-06-09T15:44:57.000Z"
        }))
        .unwrap();
        let hash = crate::audit::persist::sha256_hex(&raw);
        let decoded = decode_v1(&raw, now, &hash).expect("Action with file_path must decode");
        assert_eq!(
            decoded.surface, "src/lib.rs",
            "Action-write: surface must equal file_path"
        );
    }

    #[test]
    fn surface_action_shell_command_sha256() {
        let now = conformance_now_unix();
        let raw = serde_json::to_vec(&serde_json::json!({
            "kind": "Action",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-10e7dd16",
                "verified_id": "548F2C562EB4246D025FA80A70552B124755B685"
            },
            "payload": {
                "command_sha256": "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a",
                "description_chars": 10
            },
            "prev_link": null,
            "schema_version": 1,
            "session": "sess-001",
            "ts": "2026-06-09T15:44:57.000Z"
        }))
        .unwrap();
        let hash = crate::audit::persist::sha256_hex(&raw);
        let decoded = decode_v1(&raw, now, &hash).expect("Action with command_sha256 must decode");
        assert_eq!(
            decoded.surface, "shell",
            "Action-shell: surface must be 'shell' when command_sha256 present"
        );
    }

    #[test]
    fn surface_human_input() {
        let now = conformance_now_unix();
        let raw = serde_json::to_vec(&serde_json::json!({
            "kind": "HumanInput",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-10e7dd16",
                "verified_id": "548F2C562EB4246D025FA80A70552B124755B685"
            },
            "payload": {
                "description_chars": 42
            },
            "prev_link": null,
            "schema_version": 1,
            "session": "sess-001",
            "ts": "2026-06-09T15:44:57.000Z"
        }))
        .unwrap();
        let hash = crate::audit::persist::sha256_hex(&raw);
        let decoded = decode_v1(&raw, now, &hash).expect("HumanInput must decode");
        assert_eq!(
            decoded.surface, "human-input",
            "HumanInput: surface must be fixed 'human-input'"
        );
    }

    // ── MEDIUM-2 regression: session field is threaded to DecodedEvent ──

    #[test]
    fn session_is_threaded_through_decoded_event() {
        let now = conformance_now_unix();
        let hash = crate::audit::persist::sha256_hex(CONFORMANCE_VECTOR);
        let decoded = decode_v1(CONFORMANCE_VECTOR, now, &hash).expect("must decode");
        assert_eq!(
            decoded.session.as_deref(),
            Some("sess-CONFORMANCE-V1-0001"),
            "MEDIUM-2: session must be threaded from wire to DecodedEvent"
        );
    }

    #[test]
    fn key_order_independence_produces_different_decision_id() {
        // A reordered JSON decodes successfully but yields a different decision_id
        // (documents byte-hashing).
        let original = CONFORMANCE_VECTOR;
        let reordered = br#"{"schema_version":1,"kind":"Decision","operator_ref":{"display_id":"esperie","person_id":"pid-esperie-10e7dd16","verified_id":"548F2C562EB4246D025FA80A70552B124755B685"},"payload":{"journal_path":"journal/0252-esperie-DECISION-427-variant-only-mechanical-distribution.md","tool":"Write"},"prev_link":null,"session":"sess-CONFORMANCE-V1-0001","ts":"2026-06-09T15:44:57.000Z"}"#;

        let now = conformance_now_unix();
        let orig_hash = crate::audit::persist::sha256_hex(original);
        let reord_hash = crate::audit::persist::sha256_hex(reordered);

        let orig_decoded = decode_v1(original, now, &orig_hash).expect("original must decode");
        let reord_decoded = decode_v1(reordered, now, &reord_hash).expect("reordered must decode");

        // Same logical content but different decision_id (byte-hash, not semantic).
        assert_ne!(
            orig_decoded.decision_id, reord_decoded.decision_id,
            "reordered JSON must yield a different decision_id (byte-hashing not semantic)"
        );
        // Same surface since payload.journal_path is identical.
        assert_eq!(orig_decoded.surface, reord_decoded.surface);
    }
}
