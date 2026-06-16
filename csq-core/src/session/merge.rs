//! Settings deep merge — overlay profile on top of default settings.

use serde_json::{Map, Value};

/// Deep-merges `overlay` into `base`, returning a new `Value`.
///
/// Semantics:
/// - Objects are merged recursively (keys in both are merged by key)
/// - Arrays are **replaced** (not concatenated) by the overlay
/// - Scalars are replaced by the overlay
/// - Keys in `base` not in `overlay` are preserved
/// - Keys in `overlay` not in `base` are added
pub fn merge_settings(base: &Value, overlay: &Value) -> Value {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            let mut merged = base_map.clone();
            for (key, overlay_val) in overlay_map {
                if let Some(base_val) = merged.get(key) {
                    merged.insert(key.clone(), merge_settings(base_val, overlay_val));
                } else {
                    merged.insert(key.clone(), overlay_val.clone());
                }
            }
            Value::Object(merged)
        }
        // Any non-object overlay replaces the base
        (_, overlay) => overlay.clone(),
    }
}

/// Attempts to repair a truncated JSON object by appending missing closing
/// braces. Used when a settings file was cut off mid-write by a previous
/// crash or interrupted save.
///
/// Only repairs JSON that starts with `{`. Returns None if the input doesn't
/// look like a recoverable object.
pub fn repair_truncated_json(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('{') {
        return None;
    }

    // If it already parses, no repair needed
    if serde_json::from_str::<Value>(trimmed).is_ok() {
        return Some(trimmed.to_string());
    }

    // Count unmatched opening braces
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;

    for c in trimmed.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
    }

    if depth <= 0 {
        return None; // Not a truncation — some other problem
    }

    // Append missing closing braces
    let mut repaired = trimmed.to_string();
    // Remove trailing comma if present before appending braces
    repaired = repaired
        .trim_end_matches(|c: char| c == ',' || c.is_whitespace())
        .to_string();
    for _ in 0..depth {
        repaired.push('}');
    }

    // Verify repair succeeded
    if serde_json::from_str::<Value>(&repaired).is_ok() {
        Some(repaired)
    } else {
        None
    }
}

/// Represents the set of key names that point to model IDs in a settings file.
/// All must be updated atomically when switching models.
pub const MODEL_KEYS: &[&str] = &[
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
];

/// Updates all MODEL_KEYS in a settings object to point to the given model.
///
/// The keys live under `env` in the settings schema. Returns a new Value
/// with the updates applied.
pub fn set_model(settings: &Value, model_id: &str) -> Value {
    let mut settings = settings.clone();

    if let Some(obj) = settings.as_object_mut() {
        let env_obj = obj
            .entry("env".to_string())
            .or_insert_with(|| Value::Object(Map::new()));

        if let Some(env) = env_obj.as_object_mut() {
            for key in MODEL_KEYS {
                env.insert(key.to_string(), Value::String(model_id.to_string()));
            }
        }
    }

    settings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_scalars_replaced() {
        let base = json!({"key": "old"});
        let overlay = json!({"key": "new"});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"key": "new"}));
    }

    #[test]
    fn merge_nested_objects() {
        let base = json!({"a": {"b": 1, "c": 2}});
        let overlay = json!({"a": {"b": 99}});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"a": {"b": 99, "c": 2}}));
    }

    #[test]
    fn merge_arrays_replaced_not_concatenated() {
        let base = json!({"items": [1, 2, 3]});
        let overlay = json!({"items": [4, 5]});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"items": [4, 5]}));
    }

    #[test]
    fn merge_preserves_base_keys() {
        let base = json!({"a": 1, "b": 2, "c": 3});
        let overlay = json!({"b": 99});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"a": 1, "b": 99, "c": 3}));
    }

    #[test]
    fn merge_adds_new_keys_from_overlay() {
        let base = json!({"a": 1});
        let overlay = json!({"b": 2, "c": 3});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"a": 1, "b": 2, "c": 3}));
    }

    #[test]
    fn merge_empty_base() {
        let base = json!({});
        let overlay = json!({"a": 1});
        let merged = merge_settings(&base, &overlay);
        assert_eq!(merged, json!({"a": 1}));
    }

    #[test]
    fn repair_missing_single_brace() {
        let result = repair_truncated_json(r#"{"a": 1"#).unwrap();
        assert_eq!(result, r#"{"a": 1}"#);
    }

    #[test]
    fn repair_missing_multiple_braces() {
        let result = repair_truncated_json(r#"{"a": {"b": {"c": 1"#).unwrap();
        assert_eq!(result, r#"{"a": {"b": {"c": 1}}}"#);
    }

    #[test]
    fn repair_valid_json_unchanged() {
        let input = r#"{"a": 1}"#;
        let result = repair_truncated_json(input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn repair_trailing_comma_removed() {
        let result = repair_truncated_json(r#"{"a": 1,"#).unwrap();
        assert_eq!(result, r#"{"a": 1}"#);
    }

    #[test]
    fn repair_non_object_returns_none() {
        assert!(repair_truncated_json("[1, 2").is_none());
        assert!(repair_truncated_json("just text").is_none());
    }

    #[test]
    fn repair_with_strings_containing_braces() {
        let result = repair_truncated_json(r#"{"a": "value with { brace""#).unwrap();
        assert_eq!(result, r#"{"a": "value with { brace"}"#);
    }

    #[test]
    fn set_model_updates_all_keys() {
        let settings = json!({
            "env": {
                "ANTHROPIC_API_KEY": "sk-key",
                "ANTHROPIC_MODEL": "old-model"
            }
        });

        let updated = set_model(&settings, "new-model");
        let env = updated.get("env").unwrap();

        for key in MODEL_KEYS {
            assert_eq!(env.get(key).unwrap().as_str().unwrap(), "new-model");
        }
        // Other keys preserved
        assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "sk-key");
    }

    #[test]
    fn set_model_creates_env_if_missing() {
        let settings = json!({"other": "value"});
        let updated = set_model(&settings, "new-model");

        let env = updated.get("env").unwrap();
        for key in MODEL_KEYS {
            assert_eq!(env.get(key).unwrap().as_str().unwrap(), "new-model");
        }
        assert_eq!(updated.get("other").unwrap(), "value");
    }
}
