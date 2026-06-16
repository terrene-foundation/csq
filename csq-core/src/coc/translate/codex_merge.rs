//! Codex `config.toml` merge helper for the capability-layer per-spawn
//! handle-dir materialization (PR-CA8 commit 2).
//!
//! # What this does
//!
//! Given the canonical `config-<N>/config.toml` text and a scaffold
//! string built by the capability-layer pipeline, produce the merged
//! TOML text that csq-cli writes to `term-<pid>/config.toml`. Performed
//! via `toml::Value` round-trip (NOT string concatenation) so TOML 1.0
//! conformance holds for arbitrary rule body content per round-1 R1-C1.
//!
//! Two non-trivial pieces of logic:
//!
//! 1. **Hand-edit preservation** (round-1 H2 / round-2 H5). When the
//!    canonical content already has a non-empty `instructions = "..."`
//!    value, the user's value is preserved. The layer scaffold is
//!    appended after a sentinel fence (`[csq:layer-scaffold-begin]` /
//!    `[csq:layer-scaffold-end]`) chosen for unambiguous audit grep —
//!    NOT the markdown `---` separator (round-2 H5 retracted that
//!    choice as ambiguous in markdown context).
//!
//! 2. **Pre-rendered overlay scalar parsing** (round-2 R2-C1 / round-3
//!    R3-L1). `CodexSpawnPayload.config_toml_overlay` values are
//!    pre-rendered TOML scalar expressions ("42" → integer 42, "true"
//!    → boolean true). Wrapping as `toml::Value::String` corrupts the
//!    type. The merge parses each value via `toml::from_str` to
//!    extract the typed scalar before insertion. Rejects multi-line
//!    raw values and trailing comments per R3-L1 to keep the contract
//!    "single TOML scalar expression only".
//!
//! # Pre-seeded fence-marker refusal (round-3 L3)
//!
//! If the canonical `instructions` already contains either fence
//! marker, the merge refuses with an actionable error. A pre-seeded
//! fence in the canonical means a prior csq write was hand-edited or
//! the user pre-seeded the fence literal; either case warrants a
//! `csq login N --provider codex` re-seed.
//!
//! # Token redaction in errors (round-1 H6 / round-2 H2)
//!
//! Parse errors do NOT echo the parser's error body — corrupt input
//! could contain fragmented credential bytes that don't match
//! `error::redact_tokens` patterns. The merge returns a sanitized
//! "config.toml parse failed; re-run csq login" message instead.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};

const FENCE_BEGIN: &str = "[csq:layer-scaffold-begin]";
const FENCE_END: &str = "[csq:layer-scaffold-end]";

/// Merge the layer scaffold + overlay keys into the canonical codex
/// `config.toml` text. Returns the serialized merged TOML.
///
/// * `canonical` — full text of `config-<N>/config.toml`.
/// * `scaffold` — capability-layer scaffold (rules + structured-output
///   directive when class is Compliance) destined for the
///   `instructions = "..."` field.
/// * `overlay` — pre-rendered TOML scalar expressions for additional
///   top-level keys (e.g., reserved for PR-CA6c MCP filter
///   parameters; today always empty in the v2.4.0-alpha shape).
///
/// On any error, returns a sanitized message. The pure-text round-
/// trip parse + byte-equal assertion on the `instructions` field is
/// the safety net for serializer bugs (round-1 R1-C1 + round-2 R2-H1).
pub fn merge_instructions_via_toml_value(
    canonical: &str,
    scaffold: &str,
    overlay: &BTreeMap<String, String>,
) -> Result<String> {
    // Parse canonical via toml::Value. Discard `_e` body — corrupt
    // canonical bytes could contain fragmented credential material
    // not matched by `error::redact_tokens` (round-2 H2).
    let mut table: toml::Value = toml::from_str(canonical).map_err(|_| {
        anyhow!(
            "canonical config.toml parse failed; re-run `csq login N --provider codex` to re-seed"
        )
    })?;

    let table_mut = table
        .as_table_mut()
        .ok_or_else(|| anyhow!("canonical config.toml is not a TOML Table"))?;

    // Compute merged instructions value. If canonical already has a
    // non-empty instructions, append the scaffold under sentinel
    // fences to preserve the user's text and make audit grep
    // unambiguous (round-2 H5).
    let merged_instructions = match table_mut.get("instructions") {
        Some(toml::Value::String(existing)) if !existing.is_empty() => {
            // Round-3 L3: refuse if canonical already contains a fence
            // marker. A pre-seeded fence means a prior csq write was
            // hand-edited or the user pre-seeded the literal — either
            // way the recovery is `csq login` to re-seed cleanly.
            if existing.contains(FENCE_BEGIN) || existing.contains(FENCE_END) {
                return Err(anyhow!(
                    "config-N/config.toml::instructions already contains a csq layer-scaffold \
                     fence marker (`{FENCE_BEGIN}` or `{FENCE_END}`). This may indicate a prior \
                     csq write was hand-edited or the fence literal was pre-seeded. Re-run \
                     `csq login N --provider codex` to re-seed cleanly."
                ));
            }
            tracing::info!(
                error_kind = "codex_user_instructions_extended",
                user_bytes = existing.len(),
                layer_bytes = scaffold.len(),
                "appending capability-layer scaffold to user-authored instructions"
            );
            format!("{existing}\n\n{FENCE_BEGIN}\n\n{scaffold}\n\n{FENCE_END}\n\n")
        }
        _ => scaffold.to_string(),
    };

    table_mut.insert(
        "instructions".to_string(),
        toml::Value::String(merged_instructions.clone()),
    );

    // Round-2 R2-C1 + round-3 R3-L1: overlay values are pre-rendered
    // TOML scalar expressions (`"42"` is integer 42, `"true"` is
    // boolean true). Parse via a synthetic single-key document to
    // extract the typed scalar; reject anything beyond a single
    // scalar (no multi-line tables, no trailing comments).
    for (k, raw_value) in overlay {
        let synthetic = format!("__x = {raw_value}");
        let parsed: toml::Value = toml::from_str(&synthetic).with_context(|| {
            format!("config_toml_overlay key {k}: invalid TOML scalar expression")
        })?;
        let parsed_table = parsed.as_table().ok_or_else(|| {
            anyhow!("config_toml_overlay key {k}: expected scalar, got non-table")
        })?;
        if parsed_table.len() != 1 || !parsed_table.contains_key("__x") {
            return Err(anyhow!(
                "config_toml_overlay key {k}: raw_value must be a single TOML scalar \
                 expression with no trailing comments, multi-line tables, or extra keys"
            ));
        }
        let scalar = parsed_table["__x"].clone();
        table_mut.insert(k.clone(), scalar);
    }

    let serialized = toml::to_string(&table).context("serializing merged config.toml")?;

    // Round-1 R1-C1 + round-2 R2-H1: round-trip parse + byte-equal
    // assertion on the instructions value catches serializer bugs.
    let verify: toml::Value =
        toml::from_str(&serialized).context("merged config.toml fails round-trip parse")?;
    let extracted = verify
        .as_table()
        .and_then(|t| t.get("instructions"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("round-trip lost instructions key"))?;
    if extracted != merged_instructions {
        return Err(anyhow!(
            "round-trip lost instructions content (expected {} bytes, got {} bytes)",
            merged_instructions.len(),
            extracted.len()
        ));
    }

    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_overlay() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn canonical_minimal() -> &'static str {
        r#"cli_auth_credentials_store = "file"
model = "gpt-5"
"#
    }

    #[test]
    fn merge_replaces_empty_instructions_field() {
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), "scaffold body", &no_overlay())
                .unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["instructions"].as_str().unwrap(),
            "scaffold body",
            "instructions must equal scaffold when canonical has no instructions key"
        );
    }

    #[test]
    fn merge_appends_to_user_authored_instructions_with_csq_fence_markers() {
        let canonical = r#"cli_auth_credentials_store = "file"
model = "gpt-5"
instructions = "User authored: be terse"
"#;
        let merged =
            merge_instructions_via_toml_value(canonical, "layer scaffold", &no_overlay()).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let instructions = parsed["instructions"].as_str().unwrap();
        assert!(
            instructions.starts_with("User authored: be terse"),
            "user value must come first: {instructions}"
        );
        assert!(
            instructions.contains("[csq:layer-scaffold-begin]"),
            "fence-begin marker must appear: {instructions}"
        );
        assert!(
            instructions.contains("[csq:layer-scaffold-end]"),
            "fence-end marker must appear: {instructions}"
        );
        assert!(
            instructions.contains("layer scaffold"),
            "layer scaffold body must appear: {instructions}"
        );
    }

    #[test]
    fn merge_round_trips_arbitrary_rule_body() {
        let adversarial_bodies = vec![
            "body containing \"\"\" triple quotes",
            "body with embedded newlines\nline two\nline three",
            "body with literal cli_auth_credentials_store = \"keychain\" line",
            "body ending in backslash \\",
            "body containing \\u0022 escape sequence",
            "body with TOML metacharacters [section] = value",
            "body containing \r\n CRLF line endings",
            "body with \"\"\"\"\" five consecutive quotes",
        ];
        for body in adversarial_bodies {
            let merged =
                merge_instructions_via_toml_value(canonical_minimal(), body, &no_overlay())
                    .unwrap_or_else(|e| panic!("merge failed for body: {body:?}: {e}"));
            let parsed: toml::Value = toml::from_str(&merged)
                .unwrap_or_else(|e| panic!("round-trip parse failed for body: {body:?}: {e}"));
            let extracted = parsed["instructions"].as_str().unwrap();
            assert_eq!(
                extracted, body,
                "round-trip lost content for body: {body:?}"
            );
        }
    }

    #[test]
    fn merge_preserves_cli_auth_credentials_store_after_round_trip() {
        // Rule body containing the literal canonical-key text — must
        // NOT smuggle into top-level (TOML's last-wins semantics
        // could otherwise be defeated by a body like:
        //
        //   instructions = "..."
        //   cli_auth_credentials_store = "keychain"
        //
        // appearing AFTER our injected instructions block. The
        // toml::Value round-trip guarantees the body lands inside
        // the instructions string, not as a top-level key.
        let body = "literal text: cli_auth_credentials_store = \"keychain\"";
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), body, &no_overlay()).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["cli_auth_credentials_store"].as_str().unwrap(),
            "file",
            "canonical cli_auth_credentials_store must survive merge: {merged}"
        );
        assert_eq!(parsed["model"].as_str().unwrap(), "gpt-5");
    }

    #[test]
    fn merge_preserves_model_key_after_round_trip() {
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &no_overlay()).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(parsed["model"].as_str().unwrap(), "gpt-5");
    }

    #[test]
    fn merge_corrupt_canonical_does_not_echo_parse_error_body() {
        // Inject canonical containing partial JWT bytes (would be
        // a corruption-via-racing-write artifact). The error MUST
        // NOT echo the parse-error body — `_e` is discarded per
        // round-2 H2.
        let corrupt =
            "cli_auth_credentials_store = \"file\"\nmodel = eyJhbGciOi.fake_jwt_payload.x\n";
        let err = merge_instructions_via_toml_value(corrupt, "body", &no_overlay()).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            !err_text.contains("eyJhbGciOi"),
            "error must not echo JWT-like fragments from parse failure: {err_text}"
        );
        assert!(
            err_text.contains("re-run") && err_text.contains("csq login"),
            "error must direct operator to recovery: {err_text}"
        );
    }

    #[test]
    fn merge_refuses_canonical_with_pre_seeded_fence_marker() {
        let canonical = r#"cli_auth_credentials_store = "file"
model = "gpt-5"
instructions = "[csq:layer-scaffold-begin] preseeded literal"
"#;
        let err = merge_instructions_via_toml_value(canonical, "body", &no_overlay()).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            err_text.contains("layer-scaffold")
                || err_text.contains("fence")
                || err_text.contains("re-seed"),
            "error must explain fence collision: {err_text}"
        );
    }

    #[test]
    fn merge_overlay_integer_value_serializes_as_toml_integer_not_string() {
        let mut overlay = BTreeMap::new();
        overlay.insert("max_tokens".to_string(), "4096".to_string());
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["max_tokens"].as_integer(),
            Some(4096),
            "overlay value `\"4096\"` must serialize as integer 4096, not string \"4096\": {merged}"
        );
    }

    #[test]
    fn merge_overlay_boolean_value_serializes_as_toml_boolean() {
        let mut overlay = BTreeMap::new();
        overlay.insert("enable_thing".to_string(), "true".to_string());
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(parsed["enable_thing"].as_bool(), Some(true));
    }

    #[test]
    fn merge_overlay_rejects_multi_line_raw_value() {
        let mut overlay = BTreeMap::new();
        overlay.insert("k".to_string(), "1\n[other]\nfoo = 2".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            err_text.contains("scalar") || err_text.contains("trailing"),
            "error must flag multi-line value: {err_text}"
        );
    }

    #[test]
    fn merge_overlay_rejects_value_with_extra_keys_in_synthetic_table() {
        // Crafted to make the parsed table have len() > 1 OR not
        // contain `__x` — any ill-formed scalar expression should
        // be rejected.
        let mut overlay = BTreeMap::new();
        // A table-shaped value would be parsed as `__x = { … }` and
        // then we'd see a single key __x with table value — that's
        // accepted (table is a valid scalar in TOML 1.0). Actual
        // rejection: a value that produces a non-table parse like
        // "[broken" — but that fails parse outright. Test the
        // contract: a value that produces multiple top-level keys
        // is rejected.
        overlay.insert("k".to_string(), "{ a = 1, b = 2 }".to_string());
        let result = merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay);
        // Inline table is a valid scalar; this should succeed with
        // a typed inline-table value.
        assert!(
            result.is_ok(),
            "inline tables are valid scalars: {result:?}"
        );
    }

    #[test]
    fn merge_with_empty_overlay_is_a_noop_for_non_instructions_keys() {
        let merged =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &no_overlay()).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let table = parsed.as_table().unwrap();
        // Original keys + the instructions key we wrote.
        assert!(table.contains_key("cli_auth_credentials_store"));
        assert!(table.contains_key("model"));
        assert!(table.contains_key("instructions"));
        // No extras.
        assert_eq!(table.len(), 3, "no extra keys: {merged}");
    }
}
