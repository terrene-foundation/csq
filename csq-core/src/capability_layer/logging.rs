//! Capability-layer logging redaction extensions.
//!
//! Spec: internal-design-docs § Group 1
//! NFR: NFR-OBS-02 (zero raw tokens in logs)
//! Mitigations: T2 (MCP payload exposure), B8 (Vertex SA structural fields)
//!
//! This module wraps `csq_core::error::redact_tokens` (the load-bearing
//! token-pattern primitive) with two outer policies:
//!
//! 1. Tool-call argument redaction — JSON value walk; redact long string
//!    fields by default; honor a compile-time per-tool allowlist.
//! 2. Vertex SA structural-field strip — replace values of structurally
//!    identifying JSON keys (`private_key_id`, `client_email`, `client_id`,
//!    `private_key`) with `[REDACTED]`. Handles JSON-escaped serializations.
//!
//! `redact_log_line` chains all three passes for capability-layer log lines.
//!
//! # Design notes
//!
//! This module is purely additive (PR-CA11a). No existing emit boundary is
//! rewired in this PR — that happens in PR-CA11b. All public API signatures
//! match the plan exactly so PR-CA11b callers can drop in without changes.

use crate::error::redact_tokens;

/// Threshold above which string-typed tool-call arg fields are auto-redacted
/// (matches the existing `error.rs::HEX_MIN_LEN` for cross-rule symmetry).
pub const TOOL_ARG_REDACT_THRESHOLD_CHARS: usize = 32;

/// Compile-time per-tool allowlist of arg-field names that are NOT redacted
/// even if longer than the threshold. Adding a tool/field here is a
/// security-reviewer-required step — fail-closed by default.
///
/// Only top-level field names are matched (the `tool_name` + `field_name`
/// pair). Nested object fields always use the default-redact policy.
const TOOL_ARG_ALLOWLIST: &[(&str, &[&str])] = &[
    ("read_file", &["path"]),
    ("write_file", &["path"]),
    ("bash", &["command"]),
    ("str_replace_based_edit_tool", &["path"]),
    // Add new tool/field pairs here AFTER security-review.
];

/// Vertex SA structural fields whose values are stripped to `[REDACTED]`.
/// `private_key` is also covered by the existing PEM-block redactor in
/// `error.rs::redact_pem_blocks`; including it here protects against
/// non-PEM serializations (e.g., a single-line escaped payload).
const VERTEX_SA_STRUCTURAL_KEYS: &[&str] =
    &["private_key_id", "client_email", "client_id", "private_key"];

/// Redact a tool-call args JSON value.
///
/// String fields longer than [`TOOL_ARG_REDACT_THRESHOLD_CHARS`] (and not in
/// the per-tool allowlist) are replaced with `[REDACTED:len=NN]` (preserving
/// the original char count for analyst debugging without leaking the content).
/// Recursive over nested objects and arrays. Non-string scalars (numbers,
/// booleans, null) are untouched.
///
/// The `tool_name` is used to check the allowlist for the **top level** of
/// the JSON object only. Nested object fields always use the default-redact
/// policy regardless of `tool_name`.
///
/// Returns a NEW `serde_json::Value` (the input is not mutated).
pub fn redact_tool_call_args(tool_name: &str, args: &serde_json::Value) -> serde_json::Value {
    redact_value(tool_name, args, /*top_level=*/ true)
}

/// Internal recursive helper.
///
/// `top_level` is `true` only for the outermost object so that the per-tool
/// allowlist applies at the first level only. Nested fields always use the
/// default-redact policy.
fn redact_value(tool_name: &str, value: &serde_json::Value, top_level: bool) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let redacted_v = if top_level {
                    redact_field(tool_name, k, v)
                } else {
                    // Nested: no allowlist, but still recurse into sub-objects/arrays.
                    redact_field("", k, v)
                };
                new_map.insert(k.clone(), redacted_v);
            }
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(arr) => {
            let new_arr = arr
                .iter()
                .map(|elem| {
                    // Array elements: apply default-redact policy directly.
                    // For strings: threshold check with no allowlist.
                    // For objects/arrays: recurse.
                    // For scalars: pass through.
                    match elem {
                        serde_json::Value::String(s) => {
                            let char_count = s.chars().count();
                            if char_count > TOOL_ARG_REDACT_THRESHOLD_CHARS {
                                serde_json::Value::String(format!("[REDACTED:len={}]", char_count))
                            } else {
                                elem.clone()
                            }
                        }
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            redact_value("", elem, /*top_level=*/ false)
                        }
                        other => other.clone(),
                    }
                })
                .collect();
            serde_json::Value::Array(new_arr)
        }
        // Non-string scalars are passed through unchanged.
        other => other.clone(),
    }
}

/// Decide whether a single field value should be redacted.
///
/// For objects and arrays: recurse. For strings: check allowlist then threshold.
/// For all other scalars: pass through unchanged.
fn redact_field(tool_name: &str, field_name: &str, value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let char_count = s.chars().count();
            if char_count > TOOL_ARG_REDACT_THRESHOLD_CHARS
                && !is_allowlisted(tool_name, field_name)
            {
                serde_json::Value::String(format!("[REDACTED:len={}]", char_count))
            } else {
                value.clone()
            }
        }
        // Objects and arrays: recurse (top_level=false for nested content).
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            redact_value(tool_name, value, /*top_level=*/ false)
        }
        // Numbers, booleans, null — pass through.
        other => other.clone(),
    }
}

/// Return `true` if `field_name` is allowlisted for `tool_name`.
///
/// An unknown tool has no allowlist entries, so every long field is redacted.
fn is_allowlisted(tool_name: &str, field_name: &str) -> bool {
    for (t, fields) in TOOL_ARG_ALLOWLIST {
        if *t == tool_name {
            return fields.contains(&field_name);
        }
    }
    false
}

/// Redact Vertex SA structural fields from a log-line string.
///
/// Handles:
/// - bare JSON: `{"private_key_id":"abc"}` → `{"private_key_id":"[REDACTED]"}`
/// - JSON-escaped: `{\"private_key_id\":\"abc\"}` → `{\"private_key_id\":\"[REDACTED]\"}`
/// - mixed prose + JSON snippet: `error: {"client_email":"a@b"}` (snippet redacted)
///
/// Run BEFORE `error::redact_tokens` for the structural fields; after for
/// the per-char token patterns. `redact_log_line` chains the order.
///
/// # Known limitation
///
/// This function assumes that Vertex SA field values do NOT contain embedded
/// quote characters. If a value contains an embedded `"` (bare) or `\"` (escaped),
/// redaction will stop early at that embedded quote and may leak the remainder
/// of the value. In practice, Vertex SA JSON values are identifiers, email
/// addresses, and PEM blocks — none of which contain raw quote characters.
pub fn redact_vertex_sa_structural(s: &str) -> String {
    let mut result = s.to_string();
    for key in VERTEX_SA_STRUCTURAL_KEYS {
        // Pass 1: bare JSON form — "key":"value" → "key":"[REDACTED]"
        result = redact_key_bare(&result, key);
        // Pass 2: JSON-escaped form — \"key\":\"value\" → \"key\":\"[REDACTED]\"
        result = redact_key_escaped(&result, key);
    }
    result
}

/// Redact values for a key in bare JSON form: `"key":"<value>"`.
///
/// Replaces `"<value>"` with `"[REDACTED]"`.
fn redact_key_bare(s: &str, key: &str) -> String {
    // Pattern to search for: `"key":"`
    let search = format!("\"{}\":\"", key);
    if !s.contains(&search) {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;

    while cursor < s.len() {
        let rest = &s[cursor..];
        match rest.find(&search) {
            None => {
                out.push_str(rest);
                break;
            }
            Some(idx) => {
                // Emit everything before the match.
                out.push_str(&rest[..idx + search.len()]);
                cursor += idx + search.len();

                // Now cursor is pointing right after the opening `"` of the value.
                // Find the closing `"` (unescaped) — we assume values have no embedded quotes.
                let value_start = cursor;
                let remaining = &s[value_start..];
                let value_end = remaining.find('"').unwrap_or(remaining.len());

                // Emit the redacted placeholder and skip the original value + closing quote.
                out.push_str("[REDACTED]\"");
                cursor = value_start + value_end + 1; // +1 to skip the closing `"`
            }
        }
    }
    out
}

/// Redact values for a key in JSON-escaped form: `\"key\":\"<value>\"`.
///
/// Replaces `\"<value>\"` with `\"[REDACTED]\"`.
fn redact_key_escaped(s: &str, key: &str) -> String {
    // Pattern to search for: `\"key\":\"`
    let search = format!("\\\"{}\\\":\\\"", key);
    // Closing delimiter in escaped form: `\"`
    let close = "\\\"";

    if !s.contains(&search) {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;

    while cursor < s.len() {
        let rest = &s[cursor..];
        match rest.find(&search) {
            None => {
                out.push_str(rest);
                break;
            }
            Some(idx) => {
                // Emit everything before + including the matched key pattern.
                out.push_str(&rest[..idx + search.len()]);
                cursor += idx + search.len();

                // Now find the closing `\"` that terminates the value.
                let value_start = cursor;
                let remaining = &s[value_start..];
                let value_end = remaining.find(close).unwrap_or(remaining.len());

                // Emit the redacted placeholder and skip the original value + closing `\"`.
                out.push_str("[REDACTED]\\\"");
                cursor = value_start + value_end + close.len();
            }
        }
    }
    out
}

/// Top-level emit-boundary redactor for capability-layer log lines.
///
/// Runs the full chain in this order:
///   1. `redact_vertex_sa_structural` — structural-field strip; handles both
///      bare and JSON-escaped forms.
///   2. `error::redact_tokens` — per-char token patterns + PEM blocks.
///
/// Idempotent: applying twice equals applying once.
pub fn redact_log_line(s: &str) -> String {
    let after_structural = redact_vertex_sa_structural(s);
    redact_tokens(&after_structural)
}

// ---------------------------------------------------------------------------
// redact_response_body_shape — per-provider 401/403 body redactor scaffold
// ---------------------------------------------------------------------------

/// Provider enum for `redact_response_body_shape`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBodyProvider {
    Openai,
    Google,
    Anthropic,
}

/// Compiled-in fixture content for each provider.
///
/// The fixture JSON files live under `coc-eval/redaction-fixtures/` and are
/// committed with placeholder content until the operator runs
/// `coc-eval/scripts/characterize-error-bodies.sh`. When the fixture's
/// `redacted_body` field is `null` (placeholder state), this function is a
/// no-op and emits a structured `audit_redaction_fixture_unset` WARN tag.
///
/// The `include_str!` paths are relative to this source file.
const OPENAI_FIXTURE_JSON: &str =
    include_str!("../../../coc-eval/redaction-fixtures/openai-401-shapes.json");
const GOOGLE_FIXTURE_JSON: &str =
    include_str!("../../../coc-eval/redaction-fixtures/google-401-shapes.json");
const ANTHROPIC_FIXTURE_JSON: &str =
    include_str!("../../../coc-eval/redaction-fixtures/anthropic-401-shapes.json");

/// Parsed fixture content (cached per provider via `OnceLock`).
struct ProviderFixture {
    /// The parsed fixture JSON value. `None` if the fixture is in placeholder state.
    redacted_body: Option<String>,
    /// Regex patterns to apply. Empty when the fixture is a placeholder.
    extraction_patterns: Vec<regex::Regex>,
}

use std::sync::OnceLock;

/// Returns the parsed fixture for the given provider, parsing once and caching.
fn get_fixture(provider: ResponseBodyProvider) -> &'static ProviderFixture {
    static OPENAI: OnceLock<ProviderFixture> = OnceLock::new();
    static GOOGLE: OnceLock<ProviderFixture> = OnceLock::new();
    static ANTHROPIC: OnceLock<ProviderFixture> = OnceLock::new();

    let (lock, json_str) = match provider {
        ResponseBodyProvider::Openai => (&OPENAI, OPENAI_FIXTURE_JSON),
        ResponseBodyProvider::Google => (&GOOGLE, GOOGLE_FIXTURE_JSON),
        ResponseBodyProvider::Anthropic => (&ANTHROPIC, ANTHROPIC_FIXTURE_JSON),
    };

    lock.get_or_init(|| parse_fixture(json_str))
}

fn parse_fixture(json_str: &str) -> ProviderFixture {
    let v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                audit_tag = "audit_redaction_fixture_unset",
                "failed to parse provider fixture JSON; redact_response_body_shape is a no-op"
            );
            return ProviderFixture {
                redacted_body: None,
                extraction_patterns: Vec::new(),
            };
        }
    };

    // When `redacted_body` is JSON null the fixture is in placeholder state.
    let redacted_body = v
        .get("redacted_body")
        .and_then(|b| b.as_str())
        .map(|s| s.to_string());

    if redacted_body.is_none() {
        let schema_version = v
            .get("schema_version")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        tracing::warn!(
            audit_tag = "audit_redaction_fixture_unset",
            schema_version = schema_version,
            "provider fixture is in placeholder state; redact_response_body_shape is a no-op. \
             Run coc-eval/scripts/characterize-error-bodies.sh to populate."
        );
    }

    // Parse extraction_patterns — array of regex strings.
    let extraction_patterns = v
        .get("extraction_patterns")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .filter_map(|pat| match regex::Regex::new(pat) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::warn!(
                            audit_tag = "audit_redaction_fixture_pattern_invalid",
                            pattern = pat,
                            error = %e,
                            "skipping invalid extraction pattern"
                        );
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    ProviderFixture {
        redacted_body,
        extraction_patterns,
    }
}

/// Reads the per-provider 401/403 captured-shape fixture (compiled in via
/// `include_str!` for stability) and applies the shape's per-token-pattern
/// regex to the input. Returns the redacted string.
///
/// When the fixture file is empty / placeholder (`redacted_body` is `null`),
/// this function is a no-op: returns the input unchanged and emits a
/// structured `audit_redaction_fixture_unset` log tag at WARN. The
/// placeholder state is intentional — the operator-run probe
/// (`coc-eval/scripts/characterize-error-bodies.sh`) populates the fixtures;
/// the redactor activates once real captures land.
///
/// Per spec 12 §12.4 emit-boundary contract — call this BEFORE
/// `redact_log_line` for response-body-derived strings.
pub fn redact_response_body_shape(provider: ResponseBodyProvider, input: &str) -> String {
    let fixture = get_fixture(provider);

    // Placeholder state: no-op.
    if fixture.redacted_body.is_none() {
        return input.to_string();
    }

    // Apply extraction_patterns in order (empty in placeholder state).
    let mut result = input.to_string();
    for pattern in &fixture.extraction_patterns {
        result = pattern.replace_all(&result, "[REDACTED]").into_owned();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── redact_tool_call_args ──────────────────────────────────────────────────

    /// Allowlist hit: `read_file` with `path` longer than threshold → unchanged.
    #[test]
    fn allowlist_hit_read_file_path_preserved() {
        let long_path = "/very/long/path/that/exceeds/32/chars/to/trigger/threshold";
        assert!(long_path.chars().count() > TOOL_ARG_REDACT_THRESHOLD_CHARS);
        let args = json!({"path": long_path});
        let result = redact_tool_call_args("read_file", &args);
        assert_eq!(result["path"].as_str().unwrap(), long_path);
    }

    /// Allowlist miss (unknown tool): long field is redacted.
    #[test]
    fn allowlist_miss_unknown_tool_long_field_redacted() {
        let long_val: String = "x".repeat(40);
        let args = json!({"any_field": long_val});
        let result = redact_tool_call_args("unknown_tool", &args);
        let s = result["any_field"].as_str().unwrap();
        assert_eq!(s, "[REDACTED:len=40]");
    }

    /// Allowlist miss: known tool (`read_file`), unlisted field (`content`) → redacted.
    /// Listed field (`path`) → preserved.
    #[test]
    fn allowlist_miss_known_tool_unlisted_field_redacted_listed_preserved() {
        let long_content: String = "x".repeat(64);
        let long_path = "/very/long/path/that/exceeds/32/chars/to/trigger/threshold";
        let args = json!({"content": long_content, "path": long_path});
        let result = redact_tool_call_args("read_file", &args);
        assert_eq!(result["content"].as_str().unwrap(), "[REDACTED:len=64]");
        assert_eq!(result["path"].as_str().unwrap(), long_path);
    }

    /// Threshold boundary: exactly 32-char string → NOT redacted (threshold is `> 32`).
    #[test]
    fn threshold_boundary_32_chars_not_redacted() {
        let exactly_32: String = "a".repeat(32);
        assert_eq!(exactly_32.chars().count(), 32);
        let args = json!({"field": exactly_32.clone()});
        let result = redact_tool_call_args("unknown_tool", &args);
        assert_eq!(result["field"].as_str().unwrap(), exactly_32);
    }

    /// Threshold boundary: 33-char string → redacted.
    #[test]
    fn threshold_boundary_33_chars_redacted() {
        let thirty_three: String = "a".repeat(33);
        assert_eq!(thirty_three.chars().count(), 33);
        let args = json!({"field": thirty_three});
        let result = redact_tool_call_args("unknown_tool", &args);
        assert_eq!(result["field"].as_str().unwrap(), "[REDACTED:len=33]");
    }

    /// Nested object: long field inside nested object is redacted.
    #[test]
    fn nested_object_long_field_redacted() {
        let long_val: String = "x".repeat(40);
        let args = json!({"args": {"long_field": long_val}});
        let result = redact_tool_call_args("any_tool", &args);
        assert_eq!(
            result["args"]["long_field"].as_str().unwrap(),
            "[REDACTED:len=40]"
        );
    }

    /// Array of strings: each element evaluated independently against the threshold.
    #[test]
    fn array_elements_evaluated_independently() {
        let short = "short"; // 5 chars
        let long_val: String = "l".repeat(40);
        let args = json!({"items": [short, long_val.as_str()]});
        let result = redact_tool_call_args("any_tool", &args);
        let items = result["items"].as_array().unwrap();
        assert_eq!(items[0].as_str().unwrap(), short);
        assert_eq!(items[1].as_str().unwrap(), "[REDACTED:len=40]");
    }

    /// Non-string scalars (integer, boolean, null) are passed through unchanged.
    #[test]
    fn non_string_scalars_passed_through_unchanged() {
        let args = json!({
            "count": 42,
            "flag": true,
            "nothing": null
        });
        let result = redact_tool_call_args("any_tool", &args);
        assert_eq!(result["count"].as_i64().unwrap(), 42);
        assert!(result["flag"].as_bool().unwrap());
        assert!(result["nothing"].is_null());
    }

    /// Empty args object returns empty object.
    #[test]
    fn empty_args_returns_empty_object() {
        let args = json!({});
        let result = redact_tool_call_args("any_tool", &args);
        assert!(result.as_object().unwrap().is_empty());
    }

    /// UTF-8 multi-byte: 32 Unicode emoji chars (each 4 bytes) — `chars().count()` is 32,
    /// `len()` is 128. Must NOT be redacted (proves we use `chars().count()`).
    #[test]
    fn utf8_multibyte_chars_count_not_byte_len() {
        // Each emoji is 4 bytes; 32 of them → byte len=128 but char count=32.
        let emoji32: String = "😀".repeat(32);
        assert_eq!(emoji32.chars().count(), 32);
        assert!(emoji32.len() > 32, "sanity: byte len must exceed 32");
        let args = json!({"field": emoji32.clone()});
        let result = redact_tool_call_args("unknown_tool", &args);
        // char count == 32, which is NOT > 32, so NOT redacted.
        assert_eq!(result["field"].as_str().unwrap(), emoji32);
    }

    /// UTF-8 multi-byte: 33 Unicode emoji chars → redacted with correct char count.
    #[test]
    fn utf8_multibyte_33_chars_redacted_with_char_count() {
        let emoji33: String = "😀".repeat(33);
        assert_eq!(emoji33.chars().count(), 33);
        let args = json!({"field": emoji33});
        let result = redact_tool_call_args("unknown_tool", &args);
        assert_eq!(result["field"].as_str().unwrap(), "[REDACTED:len=33]");
    }

    /// Allowlist: `bash` tool — `command` field is preserved even if long.
    #[test]
    fn allowlist_bash_command_preserved() {
        let long_cmd: String = "echo ".to_string() + &"x".repeat(40);
        assert!(long_cmd.chars().count() > TOOL_ARG_REDACT_THRESHOLD_CHARS);
        let args = json!({"command": long_cmd.clone()});
        let result = redact_tool_call_args("bash", &args);
        assert_eq!(result["command"].as_str().unwrap(), long_cmd);
    }

    /// Allowlist: `str_replace_based_edit_tool` — `path` preserved, other long fields redacted.
    #[test]
    fn allowlist_str_replace_tool_path_preserved_other_redacted() {
        let long_path = "/very/long/path/that/certainly/exceeds/the/threshold/here";
        let long_content: String = "x".repeat(50);
        let args = json!({"path": long_path, "new_string": long_content});
        let result = redact_tool_call_args("str_replace_based_edit_tool", &args);
        assert_eq!(result["path"].as_str().unwrap(), long_path);
        assert_eq!(result["new_string"].as_str().unwrap(), "[REDACTED:len=50]");
    }

    // ── redact_vertex_sa_structural ────────────────────────────────────────────

    /// `private_key_id` redacted in bare JSON form.
    #[test]
    fn vertex_sa_private_key_id_bare_json_redacted() {
        let input = r#"{"private_key_id":"abcdef0123456789"}"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\"private_key_id\":\"[REDACTED]\""),
            "expected key redacted, got: {result}"
        );
        assert!(
            !result.contains("abcdef0123456789"),
            "value must not appear in output"
        );
    }

    /// `client_email` redacted in bare JSON form.
    #[test]
    fn vertex_sa_client_email_bare_json_redacted() {
        let input = r#"{"client_email":"service@project.iam.gserviceaccount.com"}"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\"client_email\":\"[REDACTED]\""),
            "got: {result}"
        );
        assert!(
            !result.contains("service@project.iam.gserviceaccount.com"),
            "email must not appear in output"
        );
    }

    /// `client_id` redacted in bare JSON form.
    #[test]
    fn vertex_sa_client_id_bare_json_redacted() {
        let input = r#"{"client_id":"123456789012345678901"}"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\"client_id\":\"[REDACTED]\""),
            "got: {result}"
        );
        assert!(
            !result.contains("123456789012345678901"),
            "client_id must not appear in output"
        );
    }

    /// `private_key` redacted in bare JSON form (non-PEM value).
    #[test]
    fn vertex_sa_private_key_bare_json_redacted() {
        let input = r#"{"private_key":"MIIEvAIBADANBgkqhkiG9w0BAQ"}"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\"private_key\":\"[REDACTED]\""),
            "got: {result}"
        );
        assert!(
            !result.contains("MIIEvAIBADANBgkqhkiG9w0BAQ"),
            "key material must not appear in output"
        );
    }

    /// JSON-escaped form: `\"private_key_id\":\"value\"` → `\"private_key_id\":\"[REDACTED]\"`.
    #[test]
    fn vertex_sa_private_key_id_escaped_json_redacted() {
        let input = r#"{\"private_key_id\":\"abcdef0123456789\"}"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\\\"private_key_id\\\":\\\"[REDACTED]\\\""),
            "got: {result}"
        );
        assert!(
            !result.contains("abcdef0123456789"),
            "escaped value must not appear in output"
        );
    }

    /// Mixed prose + bare JSON snippet: the JSON part is redacted.
    #[test]
    fn vertex_sa_mixed_prose_and_json_snippet_redacted() {
        let input = r#"error connecting to vertex: {"client_email":"svc@proj.iam.gserviceaccount.com"} please retry"#;
        let result = redact_vertex_sa_structural(input);
        assert!(
            result.contains("\"client_email\":\"[REDACTED]\""),
            "got: {result}"
        );
        assert!(
            !result.contains("svc@proj.iam.gserviceaccount.com"),
            "email must not appear in output"
        );
        // Surrounding prose must survive.
        assert!(
            result.contains("error connecting to vertex:"),
            "prose before must survive"
        );
        assert!(result.contains("please retry"), "prose after must survive");
    }

    /// Idempotence: applying twice produces the same result as applying once.
    #[test]
    fn vertex_sa_structural_is_idempotent() {
        let input = r#"{"private_key_id":"abcdef","client_email":"a@b.com"}"#;
        let once = redact_vertex_sa_structural(input);
        let twice = redact_vertex_sa_structural(&once);
        assert_eq!(once, twice, "applying twice must equal applying once");
    }

    /// Non-target key is not redacted.
    #[test]
    fn vertex_sa_non_target_key_untouched() {
        let input = r#"{"public_key":"this is not a secret"}"#;
        let result = redact_vertex_sa_structural(input);
        assert_eq!(result, input, "non-target key must be untouched");
    }

    // ── redact_log_line ────────────────────────────────────────────────────────

    /// Both Vertex SA structural field AND a token prefix appear on the same
    /// line: both are redacted by the chain.
    #[test]
    fn redact_log_line_chains_structural_and_token_passes() {
        // client_email (structural field) + sk-ant-oat01- (known OAuth token prefix)
        let input = r#"auth failed for {"client_email":"svc@proj.iam.gserviceaccount.com"} with token sk-ant-oat01-abc123DEF456"#;
        let result = redact_log_line(input);
        assert!(
            !result.contains("svc@proj.iam.gserviceaccount.com"),
            "structural field must be redacted, got: {result}"
        );
        assert!(
            !result.contains("sk-ant-oat01-"),
            "OAuth token prefix must be redacted, got: {result}"
        );
        assert!(
            result.contains("[REDACTED]"),
            "must contain at least one redaction marker"
        );
    }

    /// `redact_log_line` is idempotent: applying twice equals applying once.
    #[test]
    fn redact_log_line_is_idempotent() {
        let input = r#"{"private_key_id":"abc123"} token sk-ant-oat01-xyz789"#;
        let once = redact_log_line(input);
        let twice = redact_log_line(&once);
        assert_eq!(once, twice, "redact_log_line must be idempotent");
    }

    /// Backward compatibility: inputs that only contain token-pattern content
    /// (no Vertex SA structural fields) produce output equivalent to calling
    /// `redact_tokens` directly — no regression.
    #[test]
    fn redact_log_line_no_regression_vs_redact_tokens() {
        let input = "OAuth error with token sk-ant-oat01-abc123LONGER and hex 0123456789abcdef0123456789abcdef";
        let expected = redact_tokens(input);
        let actual = redact_log_line(input);
        assert_eq!(
            actual, expected,
            "redact_log_line must not regress redact_tokens behavior for token-only inputs"
        );
    }

    /// `redact_log_line` handles a bare log line with no secrets: unchanged
    /// modulo the inner `redact_tokens` pass (which is a no-op for clean inputs).
    #[test]
    fn redact_log_line_clean_input_passes_through() {
        let input = "pipeline stage scaffold completed in 42ms";
        let result = redact_log_line(input);
        assert_eq!(result, input);
    }

    /// All four Vertex SA keys are stripped in a single compound JSON object
    /// by the structural pass before the token pass runs.
    #[test]
    fn redact_log_line_all_four_vertex_sa_keys_in_compound_object() {
        let input = r#"{"type":"service_account","private_key_id":"key123","client_email":"svc@p.iam.gserviceaccount.com","client_id":"987654321","private_key":"MIIEvAIBADANBgkqhkiG9w0BAQ"}"#;
        let result = redact_log_line(input);
        assert!(
            !result.contains("key123"),
            "private_key_id value must be redacted"
        );
        assert!(
            !result.contains("svc@p.iam.gserviceaccount.com"),
            "client_email must be redacted"
        );
        assert!(!result.contains("987654321"), "client_id must be redacted");
        assert!(
            !result.contains("MIIEvAIBADANBgkqhkiG9w0BAQ"),
            "private_key material must be redacted"
        );
        assert!(
            result.contains("service_account"),
            "non-target field value must survive"
        );
    }

    // ── redact_response_body_shape ─────────────────────────────────────────────

    /// Placeholder fixture (all three providers at PR-CA11b ship time): the
    /// function returns the input unchanged and does not panic.
    #[test]
    fn placeholder_openai_fixture_is_noop() {
        let input = "some openai error body content here";
        let result = redact_response_body_shape(ResponseBodyProvider::Openai, input);
        assert_eq!(
            result, input,
            "placeholder fixture must return input unchanged"
        );
    }

    #[test]
    fn placeholder_google_fixture_is_noop() {
        let input = "some google error body content here";
        let result = redact_response_body_shape(ResponseBodyProvider::Google, input);
        assert_eq!(
            result, input,
            "placeholder fixture must return input unchanged"
        );
    }

    #[test]
    fn placeholder_anthropic_fixture_is_noop() {
        let input = "some anthropic error body content here";
        let result = redact_response_body_shape(ResponseBodyProvider::Anthropic, input);
        assert_eq!(
            result, input,
            "placeholder fixture must return input unchanged"
        );
    }

    /// All three compiled-in fixture files must parse as valid JSON with
    /// `schema_version` == "1". This verifies the `include_str!` paths resolve
    /// at compile time AND the fixture shape is correct.
    #[test]
    fn all_fixture_files_have_schema_version_one() {
        for json_str in [
            OPENAI_FIXTURE_JSON,
            GOOGLE_FIXTURE_JSON,
            ANTHROPIC_FIXTURE_JSON,
        ] {
            let v: serde_json::Value =
                serde_json::from_str(json_str).expect("fixture must be valid JSON");
            let version = v
                .get("schema_version")
                .and_then(|s| s.as_str())
                .expect("fixture must have schema_version field");
            assert_eq!(version, "1", "schema_version must be '1'");
        }
    }

    /// Forward-compat synthetic fixture test: if extraction_patterns is populated
    /// the function applies them. Uses a hand-authored JSON fixture string to
    /// simulate a populated fixture without requiring operator capture.
    #[test]
    fn populated_extraction_patterns_are_applied() {
        // Build a synthetic fixture JSON with one pattern.
        let synthetic_fixture_json = r#"{
            "schema_version": "1",
            "provider": "openai",
            "captured_at": "2099-01-01T00:00:00Z",
            "captured_against_csq_sha": "abc123",
            "status_code": 401,
            "redacted_body": "redacted body here",
            "extraction_patterns": ["sk-SYNTHETIC-[A-Z0-9]+"]
        }"#;

        // Parse the fixture manually using the same parse_fixture function
        // (tested in isolation here without going through the OnceLock cache).
        let fixture = parse_fixture(synthetic_fixture_json);

        // Fixture has a non-null redacted_body, so patterns should be applied.
        assert!(
            fixture.redacted_body.is_some(),
            "populated fixture must have redacted_body"
        );
        assert_eq!(
            fixture.extraction_patterns.len(),
            1,
            "one extraction pattern expected"
        );

        // Apply the pattern to a test input.
        let input = r#"{"error":"invalid_api_key","key":"sk-SYNTHETIC-ABCDEF12"}"#;
        let mut result = input.to_string();
        for pattern in &fixture.extraction_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").into_owned();
        }

        assert!(
            !result.contains("sk-SYNTHETIC-ABCDEF12"),
            "synthetic key must be redacted by the pattern, got: {result}"
        );
        assert!(
            result.contains("[REDACTED]"),
            "result must contain redaction marker"
        );
    }
}
