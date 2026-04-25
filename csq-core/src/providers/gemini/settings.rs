//! Generates the `handle-dir/.gemini/settings.json` content that
//! pre-seeds `gemini-cli` to use API-key auth (not OAuth) before
//! every spawn.
//!
//! Per OPEN-G01 (journal 0003 RESOLVED) the handle-dir
//! `GEMINI_CLI_HOME/.gemini/settings.json` fully isolates from the
//! user-level `~/.gemini/settings.json` — no fallback observed when
//! the handle-dir variant exists. Pre-seeding is therefore a cheap
//! re-assertion (EP1 in [`super::probe`]) rather than active
//! filesystem manipulation of the user's home dir.
//!
//! # Schema
//!
//! `gemini-cli` 0.38.x reads:
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
//!   }
//! }
//! ```
//!
//! `selectedType` MUST be `"gemini-api-key"` for csq-managed slots.
//! Any other value is a drift signal — [`super::probe`]
//! re-asserts it before every spawn.

use serde_json::json;

/// The selected-type value csq always writes for managed Gemini
/// slots. Public so the drift detector can compare against it.
pub const SELECTED_TYPE_API_KEY: &str = "gemini-api-key";

/// Renders the pre-seed settings.json content. `model_name` is the
/// caller's chosen Gemini model (`gemini-2.5-pro`, etc.); empty
/// string omits the model section so gemini-cli falls back to its
/// own default.
pub fn render(model_name: &str) -> String {
    let mut value = json!({
        "security": {
            "auth": {
                "selectedType": SELECTED_TYPE_API_KEY,
            }
        }
    });
    if !model_name.is_empty() {
        value["model"] = json!({ "name": model_name });
    }
    serde_json::to_string_pretty(&value).expect("static schema serializes")
}

/// Parses a settings.json blob and extracts the `selectedType`
/// value, if present. Returns `None` on parse failure or missing
/// path — the caller treats both as "drifted" and re-asserts.
pub fn extract_selected_type(content: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    v.get("security")?
        .get("auth")?
        .get("selectedType")?
        .as_str()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_selected_type_api_key() {
        let s = render("gemini-2.5-pro");
        assert!(s.contains("\"selectedType\": \"gemini-api-key\""));
        assert!(s.contains("\"name\": \"gemini-2.5-pro\""));
    }

    #[test]
    fn render_without_model_omits_model_section() {
        let s = render("");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("model").is_none(),
            "empty model name must omit section"
        );
        assert_eq!(v["security"]["auth"]["selectedType"], "gemini-api-key");
    }

    #[test]
    fn extract_selected_type_round_trip() {
        let rendered = render("gemini-2.5-pro");
        let extracted = extract_selected_type(&rendered).unwrap();
        assert_eq!(extracted, "gemini-api-key");
    }

    #[test]
    fn extract_selected_type_oauth_personal() {
        // The drift case: user-level settings.json with OAuth.
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
}
