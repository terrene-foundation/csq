//! Claude settings policy shared by handle preparation and read-only diagnostics.

use serde_json::Value;

const AUTO_COMPACT_WINDOW: &str = "autoCompactWindow";

/// Reports root and per-model override presence, regardless of the override value.
/// Provider context-window environment variables are independent settings.
pub fn autocompact_override_forms(settings: &Value) -> (bool, bool) {
    let root = settings
        .as_object()
        .is_some_and(|object| object.contains_key(AUTO_COMPACT_WINDOW));
    let per_model = settings
        .get("modelSettings")
        .and_then(Value::as_object)
        .is_some_and(|models| {
            models.values().any(|model| {
                model
                    .as_object()
                    .is_some_and(|object| object.contains_key(AUTO_COMPACT_WINDOW))
            })
        });
    (root, per_model)
}

/// Removes the two Claude JSON override forms from a slot or previous-handle input.
/// Global input and the final merged settings must not be passed through this filter.
/// Removes a model entry only when removing its override leaves that object empty.
/// The caller owns the output value; source settings files are never written here.
pub fn strip_autocompact_overrides(settings: &mut Value) {
    let Some(root) = settings.as_object_mut() else {
        return;
    };
    root.remove(AUTO_COMPACT_WINDOW);
    if let Some(models) = root.get_mut("modelSettings").and_then(Value::as_object_mut) {
        models.retain(|_, model| {
            let Some(object) = model.as_object_mut() else {
                return true;
            };
            let removed = object.remove(AUTO_COMPACT_WINDOW).is_some();
            !removed || !object.is_empty()
        });
    }
}

/// Reports slot-supplied percentage and provider-window overrides forbidden by policy.
/// User-global values are outside this slot policy and must pass through unchanged.
pub fn autocompact_env_override_forms(
    settings: &Value,
    allow_provider_window: bool,
) -> (bool, bool) {
    let Some(env) = settings.get("env").and_then(Value::as_object) else {
        return (false, false);
    };
    (
        env.contains_key("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"),
        !allow_provider_window && env.contains_key("CLAUDE_CODE_AUTO_COMPACT_WINDOW"),
    )
}

/// Filters a slot overlay before merge; a published third-party slot may supply its window.
/// Percentage overrides are global-only. Every other environment property is preserved.
pub fn strip_slot_autocompact_env(settings: &mut Value, allow_provider_window: bool) {
    let Some(env) = settings.get_mut("env").and_then(Value::as_object_mut) else {
        return;
    };
    env.remove("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE");
    if !allow_provider_window {
        env.remove("CLAUDE_CODE_AUTO_COMPACT_WINDOW");
    }
}

/// Whether this slot has the published API-key binding required for a slot-supplied window.
/// Uses the config marker and canonical provider accessor, never directory-name inference.
/// Missing, mixed OAuth, unreadable or incomplete binding evidence denies the exception.
/// Reads binding metadata/settings and checks credential-path absence, never credential bytes.
pub fn slot_allows_provider_window(
    base_dir: &std::path::Path,
    config_dir: &std::path::Path,
) -> bool {
    use crate::accounts::{markers, profiles, third_party};
    let Some(slot) = markers::resolve_marker_to_slot(base_dir, config_dir) else {
        return false;
    };
    // The marker's binding must describe this canonical slot directory, not a
    // different slot whose published API-key evidence happens to be healthy.
    if config_dir != base_dir.join(format!("config-{slot}")) {
        return false;
    }
    let Ok(profile) = profiles::load(&profiles::profiles_path(base_dir)) else {
        return false;
    };
    let slot_key = slot.get().to_string();
    if profile.by_slot.contains_key(&slot_key)
        || profile
            .by_slot_identity
            .get(&slot_key)
            .and_then(|label| label.strip_prefix("apikey:"))
            .and_then(crate::providers::get_provider)
            .is_none()
    {
        return false;
    }
    // Stat errors other than confirmed absence cannot establish OAuth-free custody.
    for path in [
        config_dir.join(".credentials.json"),
        base_dir.join("credentials").join(format!("{slot}.json")),
    ] {
        if !matches!(std::fs::symlink_metadata(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return false;
        }
    }
    matches!(third_party::is_third_party_slot(base_dir, slot), Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn slot_env_policy_preserves_other_values_and_requires_window_exception() {
        let original = json!({"env": {
            "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": null,
            "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1048576",
            "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "1048576",
            "KEEP": true
        }, "other": {"autoCompactWindow":42}});
        for allow_window in [false, true] {
            let mut settings = original.clone();
            assert_eq!(
                autocompact_env_override_forms(&settings, allow_window),
                (true, !allow_window)
            );
            strip_slot_autocompact_env(&mut settings, allow_window);
            let mut expected = original.clone();
            expected["env"]
                .as_object_mut()
                .unwrap()
                .remove("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE");
            if !allow_window {
                expected["env"]
                    .as_object_mut()
                    .unwrap()
                    .remove("CLAUDE_CODE_AUTO_COMPACT_WINDOW");
            }
            assert_eq!(settings, expected);
            assert_eq!(
                autocompact_env_override_forms(&settings, allow_window),
                (false, false)
            );
            strip_slot_autocompact_env(&mut settings, allow_window);
            assert_eq!(settings, expected);
        }
        for original in [
            json!(null),
            json!([]),
            json!({"env":null}),
            json!({"env":[]}),
        ] {
            let mut settings = original.clone();
            strip_slot_autocompact_env(&mut settings, false);
            assert_eq!(settings, original);
            assert_eq!(
                autocompact_env_override_forms(&settings, false),
                (false, false)
            );
        }
    }

    #[test]
    fn r2_final_policy_marker_cannot_borrow_a_different_published_slot() {
        let _guard = crate::platform::test_env::lock();
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        for n in [9u16, 10] {
            crate::accounts::third_party::bind_provider_to_slot(
                base,
                "zai",
                crate::types::AccountNum::try_from(n).unwrap(),
                Some("sk-fixture-zai"),
                None,
            )
            .unwrap();
        }
        let config = base.join("config-9");
        std::fs::write(
            config.join("settings.json"),
            br#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576"}}"#,
        )
        .unwrap();
        crate::accounts::markers::write_csq_account_legacy(
            &config,
            crate::types::AccountNum::try_from(10u16).unwrap(),
        )
        .unwrap();
        assert_eq!(
            crate::accounts::markers::resolve_marker_to_slot(base, &config)
                .unwrap()
                .get(),
            10
        );
        let sources: Vec<_> = [
            config.join("settings.json"),
            config.join(".csq-account"),
            base.join("profiles.json"),
            base.join("config-10/settings.json"),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
        for n in [9u16, 10] {
            assert!(!base.join(format!("config-{n}/.credentials.json")).exists());
            assert!(!base.join(format!("credentials/{n}.json")).exists());
        }
        // Keep the public two-argument gate: the old implementation follows marker 10.
        let allowed = slot_allows_provider_window(base, &config);
        for (path, bytes) in sources {
            assert!(std::fs::read(path).unwrap() == bytes);
        }
        assert!(
            !allowed,
            "config-9 borrowed config-10's published provider proof"
        );
        let report = crate::session::settings_diagnostics::collect_autocompact_settings(base);
        assert!(report
            .findings
            .iter()
            .any(|f| f.location == "config-9/settings.json" && f.provider_window));
    }

    #[test]
    fn provider_window_exception_requires_real_publication_and_no_oauth_evidence() {
        let _guard = crate::platform::test_env::lock();
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let slot = crate::types::AccountNum::try_from(9u16).unwrap();
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            slot,
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        let config = base.join("config-9");
        assert!(slot_allows_provider_window(base, &config));
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let published = std::fs::read(&profiles_path).unwrap();
        let mut profile = crate::accounts::profiles::load(&profiles_path).unwrap();
        profile.by_slot_identity.remove("9");
        crate::accounts::profiles::save(&profiles_path, &profile).unwrap();
        assert!(
            !slot_allows_provider_window(base, &config),
            "endpoint alone is insufficient"
        );
        std::fs::write(&profiles_path, &published).unwrap();
        std::fs::write(config.join(".credentials.json"), b"{}").unwrap();
        assert!(
            !slot_allows_provider_window(base, &config),
            "mixed OAuth evidence denies exception"
        );
        std::fs::remove_file(config.join(".credentials.json")).unwrap();
        std::fs::write(config.join(".csq-account"), b"unreadable-marker").unwrap();
        assert!(!slot_allows_provider_window(base, &config));
    }

    #[test]
    fn autocompact_presence_recognizes_each_form_even_with_null_or_false_values() {
        for (settings, expected) in [
            (json!({}), (false, false)),
            (json!({"autoCompactWindow": null}), (true, false)),
            (
                json!({"modelSettings":{"m":{"autoCompactWindow":false}}}),
                (false, true),
            ),
            (
                json!({"autoCompactWindow":[],"modelSettings":{"m":{"autoCompactWindow":0}}}),
                (true, true),
            ),
            (
                json!({"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576"}}),
                (false, false),
            ),
            (json!({"other":{"autoCompactWindow":1}}), (false, false)),
            (
                json!({"modelSettings":{"autoCompactWindow":1}}),
                (false, false),
            ),
        ] {
            assert_eq!(autocompact_override_forms(&settings), expected);
        }
    }

    #[test]
    fn autocompact_strip_preserves_every_other_setting_and_only_newly_empty_models_are_removed() {
        let mut settings = json!({
            "autoCompactWindow": 1000000,
            "modelSettings": {
                "remove": {"autoCompactWindow": null},
                "keep": {"autoCompactWindow": false, "effort": "high"},
                "empty": {},
                "scalar": 7,
                "nested": {"other":{"autoCompactWindow":42}}
            },
            "env": {"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576"},
            "other": {"autoCompactWindow":42}
        });
        let expected = json!({
            "modelSettings": {
                "keep": {"effort":"high"},
                "empty": {},
                "scalar": 7,
                "nested": {"other":{"autoCompactWindow":42}}
            },
            "env": {"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576"},
            "other": {"autoCompactWindow":42}
        });
        strip_autocompact_overrides(&mut settings);
        assert_eq!(settings, expected);
        assert_eq!(autocompact_override_forms(&settings), (false, false));
        strip_autocompact_overrides(&mut settings);
        assert_eq!(settings, expected);
    }

    #[test]
    fn autocompact_strip_keeps_unrelated_shapes_and_empty_model_settings() {
        for original in [
            json!(null),
            json!([]),
            json!(false),
            json!("settings"),
            json!({"modelSettings":null}),
            json!({"modelSettings":[]}),
            json!({"modelSettings":{}}),
            json!({"modelSettings":{"empty":{}}}),
        ] {
            let mut settings = original.clone();
            strip_autocompact_overrides(&mut settings);
            assert_eq!(settings, original);
            assert_eq!(autocompact_override_forms(&settings), (false, false));
        }
        let mut only_override = json!({"modelSettings":{"m":{"autoCompactWindow":1}}});
        strip_autocompact_overrides(&mut only_override);
        assert_eq!(only_override, json!({"modelSettings":{}}));
    }
}
