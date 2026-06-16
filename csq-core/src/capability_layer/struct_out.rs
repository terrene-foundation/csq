//! Structured-output decode (FR-CL-01) — real impl at PR-CA7c.
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.2 (technique catalog: `Structured-output enforcement` —
//! mixed pre/post-spawn stage) + §10.4.6 (PR-CA7c stage shape).
//!
//! # PR-CA7c ship state — JSON envelope decoder
//!
//! The pre-spawn enforcement half (FR-CL-01 acceptance: schema
//! attached to outbound requests) lands in the cc translator
//! (`csq-core/src/coc/translate/cc.rs::build_output_schema_directive`)
//! and the scaffold stage (`csq-core/src/capability_layer/scaffold.rs`)
//! which appends the directive to `PreSpawnState::scaffold` for
//! compliance-class prompts.
//!
//! This stage decodes the post-spawn half: scans `PostSpawnState::raw_output`
//! for citation envelope JSON objects (`{"rule_id":"...","decision":"...",
//! "rationale":"..."}`). When at least one envelope is found, populates
//! `PostSpawnState::decoded.fields["citation_envelopes"]` with the
//! parsed list (deterministic order, BTreeMap-backed). When no envelope
//! is found, leaves `decoded` at `None` — the post-validate stage
//! falls back to substring scan (defense in depth).
//!
//! # Phase 2a deviation per `specs-authority.md` Rule 5
//!
//! FR-CL-01 reads "When a downstream CLI/API supports JSON-schema-shaped
//! completions ... the layer MUST attach the schema". CC's
//! `--output-format json` mode wraps responses in metadata
//! (`{"type":"text","subtype":"output","content":"..."}`) rather than
//! producing schema-shaped CONTENT. Phase 2a's substitute is the
//! system-prompt-directive form: the model is INSTRUCTED to emit the
//! envelope, the decoder extracts it from prose. Phase 2b's
//! csq-owns-the-API-call shape will use native `response_format`
//! enforcement; spec 10 §10.4.6 records the deviation.
//!
//! # Decoder robustness
//!
//! Models embed JSON in prose. The decoder makes a single O(n)
//! left-to-right pass tracking brace depth (string-literal aware);
//! each TOP-LEVEL `{...}` object that closes is parsed and, when it
//! deserializes as a `CitationEnvelope`, captured. Multiple envelopes
//! in one response are all captured. False positives (random JSON that
//! happens to have `rule_id`/`decision`/`rationale` fields) are
//! cross-checked against `rule_ids_in_scope` by the post-validate
//! stage so they don't accidentally pass.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::capability_layer::errors::StageError;
use crate::capability_layer::pipeline::PipelineStage;
use crate::capability_layer::state::{PostSpawnState, StructuredFields};

/// Stable stage tag.
pub const STAGE: &str = "struct_out_decode";

/// Citation envelope shape (FR-CL-01 acceptance criterion fields).
/// The decoder parses raw output for objects matching this schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationEnvelope {
    pub rule_id: String,
    pub decision: String,
    pub rationale: String,
}

/// Marker type for the structured-output decode stage.
pub struct StructOutDecodeStage;

impl PipelineStage for StructOutDecodeStage {
    type Reads = ();
    type Writes = PostSpawnState;

    fn run(_input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError> {
        let envelopes = extract_citation_envelopes(&output.raw_output);
        if envelopes.is_empty() {
            // No envelope found — leave `decoded` at None so post-validate
            // falls back to substring scan (defense in depth).
            return Ok(());
        }

        // Populate decoded.fields["citation_envelopes"] with the parsed
        // list. Use serde_json to serialize the Vec — preserves
        // determinism (input order = output order; serde_json::Value
        // arrays are ordered).
        let mut fields = StructuredFields::default();
        let json_envelopes = json!(envelopes
            .iter()
            .map(|e| json!({
                "rule_id": e.rule_id,
                "decision": e.decision,
                "rationale": e.rationale,
            }))
            .collect::<Vec<_>>());
        fields
            .fields
            .insert("citation_envelopes".into(), json_envelopes);
        output.decoded = Some(fields);

        Ok(())
    }
}

/// Scan `raw` for citation envelope JSON objects in a single
/// left-to-right pass. Tracks brace depth (string-literal aware) and,
/// each time a TOP-LEVEL `{...}` object closes, attempts to deserialize
/// it as a `CitationEnvelope`; matches are captured in input order.
///
/// # Complexity (DoS resistance)
///
/// This is O(n) in the input length: every byte is visited exactly once
/// and the `serde_json` parse attempts run only on closed top-level
/// objects, whose sizes sum to at most `n`. The earlier per-`{`
/// rescan was O(n²) — a body of `n` unbalanced `{` bytes (e.g. a
/// malicious provider response) triggered `n` forward scans of up to
/// `n` bytes each, a CPU-exhaustion vector that the byte-size cap in
/// `clients.rs` (`MAX_RESPONSE_BYTES`) bounded for memory but NOT for
/// compute. The single-pass form closes that gap.
///
/// Only TOP-LEVEL objects are considered (a `CitationEnvelope` is a flat
/// object the model emits standalone per the system-prompt directive);
/// an envelope that is NOT at brace-depth 0 — whether nested inside an
/// unrelated outer object OR preceded by a stray unbalanced `{` — is
/// intentionally not counted here. That is both faster and a tighter trust
/// boundary; the `post_validate` substring fallback still recovers any such
/// citation from the raw text (defense in depth), so the only effect is to
/// route it through the weaker path rather than the structured one.
pub fn extract_citation_envelopes(raw: &str) -> Vec<CitationEnvelope> {
    let mut out = Vec::new();
    let bytes = raw.as_bytes();
    let mut depth: u32 = 0;
    let mut start: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if escape {
            escape = false;
        } else if in_string {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                b'}' => {
                    if depth > 0 {
                        depth -= 1;
                        if depth == 0 {
                            // A complete top-level object spans [start, i].
                            if let Ok(slice) = std::str::from_utf8(&bytes[start..=i]) {
                                if let Ok(env) = serde_json::from_str::<CitationEnvelope>(slice) {
                                    out.push(env);
                                }
                            }
                        }
                    }
                    // A `}` at depth 0 is a stray close — ignore it.
                }
                _ => {}
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure JSON envelope — decoder extracts and populates decoded.
    #[test]
    fn pure_json_envelope_is_extracted() {
        let raw = r#"{"rule_id":"RULE-NO-PII","decision":"refuse","rationale":"pii rule body"}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        let decoded = state.decoded.expect("decoded populated");
        let envelopes = decoded.fields.get("citation_envelopes").unwrap();
        assert_eq!(
            envelopes,
            &json!([{
                "rule_id": "RULE-NO-PII",
                "decision": "refuse",
                "rationale": "pii rule body",
            }])
        );
    }

    /// Envelope embedded in surrounding prose — decoder still extracts it.
    /// Realistic for CC's plain-text mode where the model writes prose
    /// around the JSON.
    #[test]
    fn envelope_embedded_in_prose_is_extracted() {
        let raw = r#"I refuse to share PII. Here is the citation:
{"rule_id":"RULE-NO-PII","decision":"refuse","rationale":"PII protection"}
Let me know if you have other questions."#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        let decoded = state.decoded.expect("decoded populated");
        let arr = decoded.fields.get("citation_envelopes").unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1);
        assert_eq!(arr[0]["rule_id"], "RULE-NO-PII");
    }

    /// Multiple envelopes in one response — all captured in input order.
    #[test]
    fn multiple_envelopes_all_captured_in_order() {
        let raw = r#"First: {"rule_id":"RULE-A","decision":"refuse","rationale":"r1"}
Second: {"rule_id":"RULE-B","decision":"comply","rationale":"r2"}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        let decoded = state.decoded.unwrap();
        let arr = decoded.fields.get("citation_envelopes").unwrap();
        let arr_vec = arr.as_array().unwrap();
        assert_eq!(arr_vec.len(), 2);
        assert_eq!(arr_vec[0]["rule_id"], "RULE-A");
        assert_eq!(arr_vec[1]["rule_id"], "RULE-B");
    }

    /// No JSON envelope in raw output — decoded stays None so post-
    /// validate's substring fallback engages.
    #[test]
    fn no_envelope_leaves_decoded_none() {
        let raw = "I refuse for compliance reasons but I forgot to format it as JSON.";
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        assert!(
            state.decoded.is_none(),
            "no envelope ⇒ decoded stays None for substring fallback"
        );
    }

    /// JSON without all envelope fields is NOT captured — `serde_json`
    /// rejects via `deny_unknown_fields`-equivalent strictness on
    /// missing required fields.
    #[test]
    fn unrelated_json_objects_are_not_captured() {
        let raw = r#"Here is some JSON: {"foo": "bar"} and {"name": "x", "value": 42}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        assert!(
            state.decoded.is_none(),
            "non-envelope JSON must not populate decoded"
        );
    }

    /// Envelope with extra fields is still captured (serde permits
    /// extra unknown fields by default). The required fields are
    /// rule_id, decision, rationale.
    #[test]
    fn envelope_with_extra_fields_is_captured() {
        let raw = r#"{"rule_id":"RULE-X","decision":"refuse","rationale":"r","extra_field":"ok"}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        assert!(state.decoded.is_some());
    }

    /// Brace-imbalanced JSON (truncated) does NOT match — the
    /// balanced-brace scanner fails to find a close, the substring is
    /// skipped, no envelope captured.
    #[test]
    fn truncated_json_is_not_captured() {
        let raw = r#"{"rule_id":"RULE-X","decision":"refuse","rationale":"unfinished"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        assert!(state.decoded.is_none());
    }

    /// Brace-aware: a `{` inside a string literal does NOT increment
    /// the brace depth. Without this, an envelope whose rationale
    /// contains `{` would be treated as nested.
    #[test]
    fn brace_inside_string_literal_does_not_imbalance() {
        let raw = r#"{"rule_id":"RULE-X","decision":"refuse","rationale":"the model said {nope}"}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        let decoded = state.decoded.expect("brace-in-string must not abort parse");
        let arr = decoded.fields.get("citation_envelopes").unwrap();
        assert_eq!(arr[0]["rationale"], "the model said {nope}");
    }

    /// Determinism — same input ⇒ same decoded output across repeated
    /// calls (spec 10 §10.3.5).
    #[test]
    fn struct_out_is_deterministic() {
        let raw = r#"{"rule_id":"RULE-A","decision":"refuse","rationale":"r"}"#;
        let mut last: Option<StructuredFields> = None;
        for _ in 0..5 {
            let mut state = PostSpawnState {
                raw_output: raw.into(),
                decoded: None,
            };
            StructOutDecodeStage::run((), &mut state).unwrap();
            let cur = state.decoded.unwrap();
            if let Some(prev) = &last {
                assert_eq!(*prev, cur, "decoder must be deterministic");
            }
            last = Some(cur);
        }
    }

    /// Idempotency — calling twice on the same state produces the
    /// same observable result. With decoded already populated, second
    /// call REPLACES it with the same value (idempotent contract
    /// inherited from PR-CA7b1's pass-through shape).
    #[test]
    fn struct_out_is_idempotent() {
        let raw = r#"{"rule_id":"RULE-A","decision":"refuse","rationale":"r"}"#;
        let mut state = PostSpawnState {
            raw_output: raw.into(),
            decoded: None,
        };
        StructOutDecodeStage::run((), &mut state).unwrap();
        let snap = state.clone();
        StructOutDecodeStage::run((), &mut state).unwrap();
        assert_eq!(state, snap, "second invocation must not mutate state");
    }

    /// `extract_citation_envelopes` unit coverage — used by the audit
    /// path to inspect raw output without populating decoded.
    #[test]
    fn extract_citation_envelopes_basic_cases() {
        // Empty input.
        assert!(extract_citation_envelopes("").is_empty());
        // No JSON.
        assert!(extract_citation_envelopes("plain prose only").is_empty());
        // One envelope.
        let one =
            extract_citation_envelopes(r#"{"rule_id":"X","decision":"refuse","rationale":"r"}"#);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].rule_id, "X");
        // Two envelopes.
        let two = extract_citation_envelopes(
            r#"{"rule_id":"A","decision":"refuse","rationale":"r1"}{"rule_id":"B","decision":"comply","rationale":"r2"}"#,
        );
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].rule_id, "A");
        assert_eq!(two[1].rule_id, "B");
    }

    /// DoS resistance: a pathological body of unbalanced `{` bytes (a
    /// malicious provider response) must be scanned in O(n), not O(n²).
    /// The single-pass scanner visits each byte once and never re-scans;
    /// this completes near-instantly where the old per-`{` rescan took
    /// ~n² byte comparisons. Asserts correctness (no envelopes) on the
    /// pathological input.
    #[test]
    fn extract_citation_envelopes_bounded_on_pathological_braces() {
        let pathological = "{".repeat(1_000_000);
        let envelopes = extract_citation_envelopes(&pathological);
        assert!(envelopes.is_empty(), "unbalanced braces yield no envelopes");

        // A nested envelope inside an unrelated outer object is NOT
        // captured (only top-level objects count — tighter trust boundary).
        let nested = r#"{"wrapper":{"rule_id":"X","decision":"refuse","rationale":"r"}}"#;
        assert!(
            extract_citation_envelopes(nested).is_empty(),
            "envelope nested in an unrelated outer object is not a top-level citation"
        );
    }

    /// Stage tag remains stable across stub→pass-through→decoder
    /// promotions (structured-log filters keep working).
    #[test]
    fn struct_out_stage_tag_is_stable() {
        assert_eq!(STAGE, "struct_out_decode");
    }

    /// Compile-time enforcement: `Writes` is `PostSpawnState`. Mis-
    /// wiring as `&mut PreSpawnState` would fail to compile.
    #[test]
    fn struct_out_decode_targets_post_spawn_state() {
        let mut post = PostSpawnState::default();
        let _ = StructOutDecodeStage::run((), &mut post);
    }
}
