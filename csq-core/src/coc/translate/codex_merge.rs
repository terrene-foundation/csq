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
        // Discard the parser's error body — same token-leak discipline as
        // the canonical-parse `map_err(|_| ...)` above (LOW-I / round-2
        // H2). `with_context` would otherwise wrap the raw
        // `toml::de::Error` as the anyhow chain's source, and
        // `toml::de::Error::Display` echoes a snippet of the OFFENDING
        // INPUT (the raw scalar expression, which could carry fragmented
        // credential material) — visible to any `{err:?}`/`{err:#}`
        // formatting even though the top-level `{err}` Display looks safe.
        let parsed: toml::Value = toml::from_str(&synthetic)
            .map_err(|_| anyhow!("config_toml_overlay key {k}: invalid TOML scalar expression"))?;
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
        // MED-K: `parsed_table.len() != 1` above catches EXTRA keys, not a
        // COMPOSITE `__x` value — `raw_value = "{ }"` parses to exactly one
        // key (`__x`) holding an inline TABLE, which passes that check.
        // Inserting a table/array wholesale REPLACES the existing top-level
        // key of the same name (e.g. `overlay["cli_auth_credentials_store"]
        // = "{ }"` would silently clobber it). Reject composites
        // explicitly; only true scalars may reach the `insert` below — this
        // guards the VALUE side (mirrors the identical fix in
        // kimi_merge.rs — zero-tolerance Rule 1a). The TARGET side (a
        // scalar overlay at a key whose EXISTING canonical value is a
        // table/array) is a SEPARATE clobber class, guarded immediately
        // below — round-11 MED-1 ported kimi_merge.rs's target-aware guard
        // to close it here too (see that guard's comment for why a
        // composite-value-only check is insufficient).
        if matches!(scalar, toml::Value::Table(_) | toml::Value::Array(_)) {
            let kind = if scalar.is_table() { "table" } else { "array" };
            return Err(anyhow!(
                "config_toml_overlay key {k}: raw_value must be a scalar (string, \
                 integer, float, boolean, or datetime), got a TOML {kind} — a composite \
                 value would silently REPLACE the existing top-level `{k}` key wholesale \
                 instead of merging into it"
            ));
        }
        // Round-11 MED-1: the composite check above guards the VALUE side
        // only. `insert` REPLACES whatever lives at `k` — so a SCALAR
        // overlay at a key whose EXISTING canonical value is a table/array
        // wholesale-deletes that subtree. Codex's `config.toml` carries
        // table keys too — e.g. `mcp_servers`, which
        // `daemon::mcp_rewrite::rewrite_codex_config_mcp_servers` maintains
        // (`run.rs`'s own doc: "The overlay is reserved for future
        // MCP-filter parameters") — so a future overlay entry named
        // `mcp_servers` carrying a rendered scalar would silently
        // wholesale-delete the operator's MCP server table. Refuse
        // target-aware, mirroring kimi_merge.rs's identical guard.
        if let Some(existing) = table_mut.get(k) {
            if matches!(existing, toml::Value::Table(_) | toml::Value::Array(_)) {
                return Err(anyhow!(
                    "config_toml_overlay key {k}: the canonical config already has a \
                     table/array at `{k}` — a scalar overlay would REPLACE it wholesale, \
                     silently deleting its contents (e.g. the `mcp_servers` table). csq \
                     does not overlay composite keys; edit config.toml directly to \
                     restructure `{k}`"
                ));
            }
        }
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
        // A multi-line raw_value that injects a second top-level
        // assignment produces a parsed table with TWO keys (`__x` and
        // `extra`) — the `len() != 1` branch this test targets.
        let mut overlay = BTreeMap::new();
        overlay.insert("k".to_string(), "1\nextra = 2".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        assert!(
            format!("{err}").contains("scalar"),
            "error must flag the extra-key defect"
        );
    }

    /// MED-K non-vacuity: an inline TABLE parses to exactly one key
    /// (`__x`) — the `len() != 1` check above does NOT catch it — but a
    /// table is a COMPOSITE, not a scalar. Was PREVIOUSLY accepted
    /// (`merge_overlay_rejects_value_with_extra_keys_in_synthetic_table`'s
    /// prior body asserted `result.is_ok()` for exactly this input,
    /// pinning the bug). MUST now be rejected — see the clobber
    /// regression test below for why.
    #[test]
    fn merge_rejects_table_shaped_overlay_value() {
        let mut overlay = BTreeMap::new();
        overlay.insert("k".to_string(), "{ a = 1, b = 2 }".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("composite") || msg.contains("table"),
            "error must name the defect: {msg}"
        );
    }

    #[test]
    fn merge_rejects_array_shaped_overlay_value() {
        let mut overlay = BTreeMap::new();
        overlay.insert("k".to_string(), "[1, 2, 3]".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("array"), "error must name the defect: {msg}");
    }

    /// MED-K regression, the exact clobber the finding demonstrated:
    /// BEFORE the fix, `overlay["cli_auth_credentials_store"] = "{ }"`
    /// validated and would have silently wiped the credential-store field
    /// this canonical carries. Proves the guard fires on the credential
    /// field specifically, not just some generic key.
    #[test]
    fn merge_rejects_overlay_value_that_would_clobber_credential_field() {
        let mut overlay = BTreeMap::new();
        overlay.insert("cli_auth_credentials_store".to_string(), "{ }".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        assert!(format!("{err}").contains("cli_auth_credentials_store"));
    }

    /// LOW-I non-vacuity: an overlay value that fails the initial
    /// `toml::from_str` parse (as opposed to the later "multiple keys"
    /// semantic check exercised above) is rejected with the sanitized
    /// message.
    #[test]
    fn merge_rejects_invalid_overlay_scalar_expression() {
        let mut overlay = BTreeMap::new();
        overlay.insert("bad".to_string(), "not valid toml {{{".to_string());
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid TOML scalar expression"),
            "error must name the defect: {msg}"
        );
    }

    /// LOW-I regression: `{err:?}` (anyhow's Debug chain, which — unlike
    /// the top-level `{err}` Display — walks the FULL source chain) must
    /// NOT echo a JWT-like fragment embedded in a malformed overlay scalar
    /// expression. Before the fix, `.with_context(...)` wrapped the raw
    /// `toml::de::Error` as the anyhow chain's source, and
    /// `toml::de::Error`'s own Display quotes the offending source line
    /// verbatim (confirmed empirically) — this test pins that the
    /// `map_err(|_| ...)` fix discards it, mirroring
    /// `merge_corrupt_canonical_does_not_echo_parse_error_body` above for
    /// the canonical-parse leg.
    #[test]
    fn merge_overlay_parse_error_does_not_echo_scalar_value_via_debug_chain() {
        let mut overlay = BTreeMap::new();
        overlay.insert(
            "bad".to_string(),
            "eyJhbGciOi.fake_jwt_fragment.x not-a-scalar {{{".to_string(),
        );
        let err =
            merge_instructions_via_toml_value(canonical_minimal(), "body", &overlay).unwrap_err();
        let debug_text = format!("{err:?}");
        assert!(
            !debug_text.contains("eyJhbGciOi"),
            "error Debug chain must not echo JWT-like fragments from a malformed \
             overlay value: {debug_text}"
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

    // ── Round-11 MED-1: scalar overlay at a table/array key (ported from
    // kimi_merge.rs's identical D4-1/R4-1 guard) ────────────────────────

    /// `overlay["mcp_servers"] = "\"x\""` would wholesale-replace the
    /// `[mcp_servers]` table `daemon::mcp_rewrite::
    /// rewrite_codex_config_mcp_servers` maintains — refused target-aware.
    #[test]
    fn merge_rejects_scalar_overlay_at_mcp_servers_table_key() {
        let canonical = r#"cli_auth_credentials_store = "file"
model = "gpt-5"

[mcp_servers.filesystem]
command = "npx"
"#;
        let mut overlay = BTreeMap::new();
        overlay.insert("mcp_servers".to_string(), "\"x\"".to_string());
        let err = merge_instructions_via_toml_value(canonical, "body", &overlay).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mcp_servers") && msg.contains("REPLACE"),
            "error must name the key and the clobber: {msg}"
        );
    }

    /// Array variant: a scalar overlay at a key whose existing canonical
    /// value is an ARRAY is refused the same way as a table — the clobber
    /// class is table/array symmetric (mirrors kimi_merge.rs's
    /// `merge_rejects_scalar_overlay_at_hooks_array_key`).
    #[test]
    fn merge_rejects_scalar_overlay_at_existing_array_key() {
        let canonical = r#"cli_auth_credentials_store = "file"
model = "gpt-5"
some_array = [1, 2, 3]
"#;
        let mut overlay = BTreeMap::new();
        overlay.insert("some_array".to_string(), "\"x\"".to_string());
        let err = merge_instructions_via_toml_value(canonical, "body", &overlay).unwrap_err();
        assert!(format!("{err}").contains("some_array"));
    }

    /// Positive control: a scalar overlay at an ABSENT key still inserts
    /// fine even when the canonical carries an unrelated table
    /// (`mcp_servers`) — the target-aware guard is per-key, not "any table
    /// exists anywhere → refuse everything".
    #[test]
    fn merge_allows_scalar_overlay_at_absent_key_alongside_existing_table() {
        let canonical = r#"cli_auth_credentials_store = "file"
model = "gpt-5"

[mcp_servers.filesystem]
command = "npx"
"#;
        let mut overlay = BTreeMap::new();
        overlay.insert("max_tokens".to_string(), "4096".to_string());
        let merged = merge_instructions_via_toml_value(canonical, "body", &overlay).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(parsed["max_tokens"].as_integer(), Some(4096));
        assert_eq!(
            parsed["mcp_servers"]["filesystem"]["command"]
                .as_str()
                .unwrap(),
            "npx",
            "the unrelated mcp_servers table must survive untouched: {merged}"
        );
    }
}
