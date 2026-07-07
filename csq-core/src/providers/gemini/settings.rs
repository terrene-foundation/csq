//! Generates the `handle-dir/.gemini/settings.json` content that
//! pre-seeds `gemini-cli` to use API-key auth (not OAuth) before
//! every spawn.
//!
//! Per OPEN-G01 (an internal journal entry RESOLVED) the handle-dir
//! `GEMINI_CLI_HOME/.gemini/settings.json` fully isolates from the
//! user-level `~/.gemini/settings.json` — no fallback observed when
//! the handle-dir variant exists. Pre-seeding is therefore a cheap
//! settings-drift reassertion (in [`super::probe`]) rather than active
//! filesystem manipulation of the user's home dir.
//!
//! # Schema
//!
//! `gemini-cli` 0.38.x reads (csq-managed fields shown):
//!
//! ```json
//! {
//!   "security": {
//!     "auth": {
//!       "selectedType": "gemini-api-key"
//!     }
//!   },
//!   "model": {
//!     "name": "<selected-model>"
//!   },
//!   "system_instruction": "<capability-layer scaffold or absent>"
//! }
//! ```
//!
//! `selectedType` is written for every Gemini binding mode as a UX
//! shortcut so gemini-cli does not interactively prompt for auth
//! choice on first spawn (NOT a ToS-driven defense — the original EP1
//! framing was retracted in an internal journal entry). The pinned value depends
//! on the binding's auth mode:
//!
//! - **ApiKey** / **VertexSa** → `selectedType = "gemini-api-key"`.
//! - **CodeAssistOAuth** → `selectedType = "oauth-personal"`. Journal
//!   0054 inverted the previous "leave unset" behavior: gemini-cli
//!   v0.41.2 does NOT auto-discover `~/.gemini/oauth_creds.json` when
//!   `selectedType` is empty; it prompts for first-run auth method
//!   on every project entry until pinned. The value `"oauth-personal"`
//!   is what gemini-cli itself writes after a user selects "Sign in
//!   with Google" interactively.
//!
//! # csq-managed vs unmanaged keys (PR-CA8b commit 4)
//!
//! csq-managed: `security.auth.selectedType`, `model.name`,
//! `system_instruction`. The writer overwrites these on every
//! reassertion when the layer is active. All other top-level keys
//! (e.g. `mcpServers`, user-authored ToS preferences) are preserved
//! by the JSON-merge writer per round-1 H2 / round-3 R3-H1.
//!
//! `system_instruction` ownership semantics (round-3 R3-H1):
//! csq-managed ONLY when the capability layer is active. The layer-
//! OFF (Inherit) path through [`super::probe::reassert_settings_drift`]
//! preserves any existing `system_instruction` value verbatim
//! (whether user-authored or written by a prior layer-on spawn).

use serde_json::{json, Map, Value};

/// The selected-type value csq writes for ApiKey / VertexSa bindings.
/// Public so the drift detector can compare against it.
pub const SELECTED_TYPE_API_KEY: &str = "gemini-api-key";

/// The selected-type value csq writes for Code Assist OAuth bindings.
/// an internal journal entry: gemini-cli v0.41.2 prompts interactively for auth
/// method when `selectedType` is unset (it does NOT auto-discover
/// `~/.gemini/oauth_creds.json`). Pinning this value tells gemini-cli
/// to use the existing OAuth creds without showing the first-run
/// "How would you like to authenticate?" picker.
pub const SELECTED_TYPE_OAUTH_PERSONAL: &str = "oauth-personal";

/// Renders a fresh settings.json blob with the csq-managed fields.
/// Used when no existing settings.json exists at the handle dir
/// (DriftOutcome::SeededFresh path).
///
/// `model_name` empty string → omits the model section so gemini-cli
/// falls back to its own default. `system_instruction == None` →
/// omits the field entirely (matches v2.3.1 byte-equivalence).
///
/// `pin_selected_type`:
///   - `Some(v)` (typically `SELECTED_TYPE_API_KEY`): writes
///     `security.auth.selectedType = v`. Used for ApiKey + VertexSa
///     bindings as a UX shortcut so gemini-cli does not interactively
///     prompt for auth choice on first spawn.
///   - `None`: omits the `security.auth.selectedType` field entirely.
///     Used for Code Assist OAuth bindings — gemini-cli auto-discovers
///     `~/.gemini/oauth_creds.json` without csq pinning anything.
pub fn render(
    model_name: &str,
    system_instruction: Option<&str>,
    pin_selected_type: Option<&str>,
) -> String {
    let mut value = match pin_selected_type {
        Some(v) => json!({
            "security": {
                "auth": {
                    "selectedType": v,
                }
            }
        }),
        None => json!({}),
    };
    if !model_name.is_empty() {
        value["model"] = json!({ "name": model_name });
    }
    if let Some(instr) = system_instruction {
        value["system_instruction"] = Value::String(instr.to_string());
    }
    serde_json::to_string_pretty(&value).expect("static schema serializes")
}

/// JSON-merges the csq-managed fields into the existing settings
/// content (PR-CA8b commit 4 / round-1 H2). Preserves any user-
/// authored top-level keys csq does not manage (e.g. `mcpServers`,
/// `ui.theme`, custom user fields).
///
/// `existing` is the raw JSON text already in the file; `None` or a
/// parse failure both fall through to a fresh render.
///
/// `system_instruction == None` strips the field if present (per
/// round-3 R3-H1 semantics: csq owns the field only when the layer
/// is active; the layer-OFF call site preserves the existing value
/// by passing it back as `Some(...)` — that is, the back-compat
/// wrapper `reassert_settings_drift` reads existing and
/// passes the preserved value forward, so this `None` path is the
/// explicit "strip" intent from a layer-on→layer-off transition
/// inside the same handle dir, which today never happens because
/// the layer-off back-compat wrapper preserves verbatim).
pub fn merge_managed_into_existing(
    existing: Option<&str>,
    model_name: &str,
    system_instruction: Option<&str>,
    pin_selected_type: Option<&str>,
) -> String {
    // Try to parse existing; on any parse failure, fall through to
    // fresh render — `null` settings or invalid JSON is treated as
    // "drifted from empty" per the v2.3.1 contract.
    let mut root: Value = match existing {
        Some(s) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(_)) => serde_json::from_str(s).unwrap(),
            _ => return render(model_name, system_instruction, pin_selected_type),
        },
        None => return render(model_name, system_instruction, pin_selected_type),
    };

    // Ensure root is a Map (already guaranteed by the parse-check
    // above, but be defensive).
    let obj = match root.as_object_mut() {
        Some(o) => o,
        None => return render(model_name, system_instruction, pin_selected_type),
    };

    // security.auth.selectedType — overwrite for API-key / Vertex SA
    // bindings (`Some`); leave untouched for Code Assist OAuth (`None`).
    if let Some(pin) = pin_selected_type {
        let security = obj
            .entry("security")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(security_obj) = security.as_object_mut() {
            let auth = security_obj
                .entry("auth")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(auth_obj) = auth.as_object_mut() {
                auth_obj.insert("selectedType".to_string(), Value::String(pin.to_string()));
            }
        }
    }

    // model.name — overwrite when non-empty (csq-managed).
    if !model_name.is_empty() {
        let model = obj
            .entry("model")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(model_obj) = model.as_object_mut() {
            model_obj.insert("name".to_string(), Value::String(model_name.to_string()));
        }
    }

    // system_instruction — set or strip per parameter (csq-managed
    // when the layer is active; back-compat wrapper passes the
    // preserved-existing value forward to maintain layer-OFF
    // verbatim per round-3 R3-H1).
    match system_instruction {
        Some(instr) => {
            obj.insert(
                "system_instruction".to_string(),
                Value::String(instr.to_string()),
            );
        }
        None => {
            obj.remove("system_instruction");
        }
    }

    serde_json::to_string_pretty(&root).expect("merged settings serialize")
}

/// Parses a settings.json blob and extracts the `selectedType`
/// value, if present. Returns `None` on parse failure or missing
/// path — the caller treats both as "drifted" and re-asserts.
pub fn extract_selected_type(content: &str) -> Option<String> {
    let v: Value = serde_json::from_str(content).ok()?;
    v.get("security")?
        .get("auth")?
        .get("selectedType")?
        .as_str()
        .map(|s| s.to_string())
}

/// Parses a settings.json blob and extracts `model.name` if present.
/// Used by the AlreadyCorrect gate in `reassert_settings_drift_with_system_instruction`.
pub fn extract_model_name(content: &str) -> Option<String> {
    let v: Value = serde_json::from_str(content).ok()?;
    v.get("model")?.get("name")?.as_str().map(|s| s.to_string())
}

/// Parses a settings.json blob and extracts the top-level
/// `system_instruction` field if present.
pub fn extract_system_instruction(content: &str) -> Option<String> {
    let v: Value = serde_json::from_str(content).ok()?;
    v.get("system_instruction")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_selected_type_api_key() {
        let s = render("gemini-2.5-pro", None, Some(SELECTED_TYPE_API_KEY));
        assert!(s.contains("\"selectedType\": \"gemini-api-key\""));
        assert!(s.contains("\"name\": \"gemini-2.5-pro\""));
    }

    #[test]
    fn render_without_model_omits_model_section() {
        let s = render("", None, Some(SELECTED_TYPE_API_KEY));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("model").is_none(),
            "empty model name must omit section"
        );
        assert_eq!(v["security"]["auth"]["selectedType"], "gemini-api-key");
    }

    #[test]
    fn render_with_system_instruction_includes_field() {
        let s = render(
            "gemini-2.5-pro",
            Some("layer scaffold body"),
            Some(SELECTED_TYPE_API_KEY),
        );
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["system_instruction"], "layer scaffold body");
    }

    #[test]
    fn render_without_system_instruction_omits_field() {
        let s = render("gemini-2.5-pro", None, Some(SELECTED_TYPE_API_KEY));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("system_instruction").is_none(),
            "None must omit system_instruction field for v2.3.1 byte-equivalence"
        );
    }

    #[test]
    fn extract_selected_type_round_trip() {
        let rendered = render("gemini-2.5-pro", None, Some(SELECTED_TYPE_API_KEY));
        let extracted = extract_selected_type(&rendered).unwrap();
        assert_eq!(extracted, "gemini-api-key");
    }

    #[test]
    fn extract_selected_type_oauth_personal() {
        let user_level = r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#;
        assert_eq!(
            extract_selected_type(user_level).as_deref(),
            Some("oauth-personal")
        );
    }

    #[test]
    fn extract_selected_type_missing_returns_none() {
        assert!(extract_selected_type("{}").is_none());
        assert!(extract_selected_type("not json").is_none());
        assert!(extract_selected_type(r#"{"security": {}}"#).is_none());
    }

    #[test]
    fn extract_model_name_works() {
        let v = r#"{"model":{"name":"gemini-2.5-pro"}}"#;
        assert_eq!(extract_model_name(v).as_deref(), Some("gemini-2.5-pro"));
        assert!(extract_model_name(r#"{"model":{}}"#).is_none());
    }

    #[test]
    fn extract_system_instruction_works() {
        let v = r#"{"system_instruction":"hello"}"#;
        assert_eq!(extract_system_instruction(v).as_deref(), Some("hello"));
        assert!(extract_system_instruction("{}").is_none());
    }

    // ============================================================
    // PR-CA8b commit 4 — JSON-merge writer (round-1 H2 fix)
    // ============================================================

    /// PR-CA8b R1-H2: JSON-merge preserves user-authored top-level
    /// keys csq does not manage (mcpServers, ui.theme, etc.).
    #[test]
    fn gemini_settings_writer_preserves_unmanaged_keys() {
        let existing = r#"{
            "security": {
                "auth": {"selectedType": "oauth-personal"}
            },
            "mcpServers": {
                "filesystem": {"command": "mcp-fs"}
            },
            "ui": {
                "theme": "dark"
            }
        }"#;
        let merged = merge_managed_into_existing(
            Some(existing),
            "gemini-2.5-pro",
            Some("layer body"),
            Some(SELECTED_TYPE_API_KEY),
        );
        let v: Value = serde_json::from_str(&merged).unwrap();
        // csq-managed: overwritten.
        assert_eq!(v["security"]["auth"]["selectedType"], "gemini-api-key");
        assert_eq!(v["model"]["name"], "gemini-2.5-pro");
        assert_eq!(v["system_instruction"], "layer body");
        // Unmanaged: preserved verbatim.
        assert_eq!(v["mcpServers"]["filesystem"]["command"], "mcp-fs");
        assert_eq!(v["ui"]["theme"], "dark");
    }

    /// PR-CA8b: merge from None falls through to fresh render.
    #[test]
    fn gemini_settings_writer_includes_system_instruction_when_present() {
        let merged = merge_managed_into_existing(
            None,
            "gemini-2.5-pro",
            Some("layer body"),
            Some(SELECTED_TYPE_API_KEY),
        );
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["system_instruction"], "layer body");
        assert_eq!(v["security"]["auth"]["selectedType"], "gemini-api-key");
    }

    /// PR-CA8b R3-H1 / R2-H6: when system_instruction is None, the
    /// merge STRIPS the field entirely from the merged output (the
    /// caller is responsible for whether to pass None — the back-
    /// compat wrapper passes the preserved-existing value to avoid
    /// stripping user content; the layer-on path passes Some(...)
    /// to set it).
    #[test]
    fn gemini_settings_writer_strips_system_instruction_when_none() {
        let existing = r#"{
            "security": {"auth": {"selectedType": "gemini-api-key"}},
            "model": {"name": "gemini-2.5-pro"},
            "system_instruction": "stale prior layer text"
        }"#;
        let merged = merge_managed_into_existing(
            Some(existing),
            "gemini-2.5-pro",
            None,
            Some(SELECTED_TYPE_API_KEY),
        );
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert!(
            v.get("system_instruction").is_none(),
            "None param must strip the field: {merged}"
        );
    }

    /// PR-CA8b: merge with malformed existing JSON falls through to
    /// fresh render (treat parse failure as "drifted from empty"
    /// per v2.3.1 contract).
    #[test]
    fn gemini_settings_writer_falls_through_to_render_on_parse_failure() {
        let merged = merge_managed_into_existing(
            Some("{ this is not json"),
            "gemini-2.5-pro",
            Some("layer body"),
            Some(SELECTED_TYPE_API_KEY),
        );
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["security"]["auth"]["selectedType"], "gemini-api-key");
        assert_eq!(v["system_instruction"], "layer body");
    }

    /// Stage 2 of an internal journal entry: render() with `pin_selected_type =
    /// None` (OAuth-mode binding) emits NO `security.auth.selectedType`
    /// field. gemini-cli auto-discovers `~/.gemini/oauth_creds.json`.
    #[test]
    fn render_oauth_mode_omits_selected_type() {
        let s = render("gemini-2.5-pro", None, None);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("security").is_none() || v["security"].get("auth").is_none(),
            "OAuth mode must omit security.auth.selectedType: {s}"
        );
        // Model still pinned.
        assert_eq!(v["model"]["name"], "gemini-2.5-pro");
    }

    /// Stage 2 of an internal journal entry: merge_managed_into_existing with
    /// `pin_selected_type = None` PRESERVES any existing selectedType
    /// value verbatim — does NOT overwrite to gemini-api-key. This is
    /// the binding-mode-aware writer behavior for OAuth slots.
    #[test]
    fn merge_oauth_mode_preserves_existing_oauth_personal_selected_type() {
        let existing = r#"{
            "security": {"auth": {"selectedType": "oauth-personal"}},
            "model": {"name": "gemini-2.5-pro"}
        }"#;
        let merged = merge_managed_into_existing(
            Some(existing),
            "gemini-2.5-pro",
            None,
            None, // OAuth binding: don't pin
        );
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(
            v["security"]["auth"]["selectedType"], "oauth-personal",
            "OAuth-mode merge must preserve existing selectedType, got: {merged}"
        );
    }

    /// Stage 2 of an internal journal entry: merge_managed_into_existing with
    /// `pin_selected_type = None` and a fresh (empty) existing leaves
    /// the field unset entirely.
    #[test]
    fn merge_oauth_mode_fresh_omits_selected_type_entirely() {
        let merged = merge_managed_into_existing(None, "gemini-2.5-pro", None, None);
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert!(
            v.get("security").is_none() || v["security"].get("auth").is_none(),
            "fresh OAuth-mode merge must omit security.auth.selectedType: {merged}"
        );
        assert_eq!(v["model"]["name"], "gemini-2.5-pro");
    }

    /// PR-CA8b: omit system_instruction (None) on a fresh render
    /// preserves v2.3.1 byte-equivalence — the field is absent.
    #[test]
    fn gemini_settings_writer_omits_system_instruction_when_layer_off_preserves_v23_shape() {
        // Fresh-from-empty + layer-off → no system_instruction field
        // (matches v2.3.1 settings.json shape exactly).
        let merged =
            merge_managed_into_existing(None, "gemini-2.5-pro", None, Some(SELECTED_TYPE_API_KEY));
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert!(v.get("system_instruction").is_none());
    }
}
