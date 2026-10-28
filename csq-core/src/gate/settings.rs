//! Source-aware Claude 2.1.292 settings admission for Shape A.
//! Unknown trusted settings refuse activation instead of acquiring flag scope.
//! This composer does not prove workspace trust, register hooks, or deliver MCP.
use super::{
    pin::VerifiedRegistry,
    registry::{self, Event, Surface},
};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, path::Path, str::FromStr};

/// Descriptor-relative, no-follow, bounded source read. Missing sources are
/// empty; malformed JSON, aliases and special files never become empty sources.
pub fn read_source_json(root: &Path, relative: &str) -> Result<Value, SettingsError> {
    if !registry::valid_relative_file(relative) {
        return Err(SettingsError::Invalid("source_path".into()));
    }
    let mut file = match super::pin::open_contained(root, relative) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err(SettingsError::Invalid("source_read".into())),
    };
    let bytes = super::pin::read_bounded(&mut file, registry::MAX_MANIFEST_BYTES)
        .map_err(|_| SettingsError::Invalid("source_read".into()))?;
    let value = settings_json(&bytes)?;
    if !value.is_object() {
        return Err(SettingsError::InvalidObject);
    }
    Ok(value)
}

// Native .claude.json includes fractional telemetry. Registry's integer-only
// parser cannot serve this boundary; refuse duplicate keys without rejecting
// valid native numbers, and never inspect unrelated telemetry as trust.
fn settings_json(bytes: &[u8]) -> Result<Value, SettingsError> {
    struct Unique(Value);
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("JSON with unique keys")
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Unique, E> {
                    serde_json::Number::from_f64(value)
                        .map(|number| Unique(Value::Number(number)))
                        .ok_or_else(|| E::custom("invalid number"))
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Unique, A::Error> {
                    let mut out = Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if out.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                        out.insert(key, map.next_value::<Unique>()?.0);
                    }
                    Ok(Unique(Value::Object(out)))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> Result<Unique, A::Error> {
                    let mut out = Vec::new();
                    while let Some(value) = sequence.next_element::<Unique>()? {
                        out.push(value.0);
                    }
                    Ok(Unique(Value::Array(out)))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|value| value.0)
        .map_err(|_| SettingsError::Invalid("source_json".into()))
}

/// Compose only after original registrations have a complete authenticated
/// equivalence proof. The registry is supplied by the private-pin verifier.
pub fn compose_registered(
    project: &Value,
    local: &Value,
    persisted_trust: bool,
    has_project_mcp: bool,
    verified: &VerifiedRegistry,
) -> Result<Value, SettingsError> {
    if has_project_mcp {
        return Err(SettingsError::ProjectMcp);
    }
    let mut seen = BTreeSet::new();
    let mut stripped = Vec::new();
    for source in [project, local] {
        let mut fields = source
            .as_object()
            .ok_or(SettingsError::InvalidObject)?
            .clone();
        if let Some(hooks) = fields.remove("hooks") {
            admit_registrations(&hooks, verified, &mut seen)?;
        }
        stripped.push(Value::Object(fields));
    }
    let expected: BTreeSet<_> = verified
        .registry
        .hooks
        .iter()
        .filter(|row| row.surfaces.contains(&Surface::Claude))
        .map(|row| (row.event, row.order))
        .collect();
    if seen != expected {
        return Err(SettingsError::Unsupported("hooks.coverage".into()));
    }
    // Validate supported field shapes even when native trust permits only the
    // conservative deny projection. Environment/plugins are named refusals.
    compose(&stripped[0], &stripped[1], true, false)?;
    compose(&stripped[0], &stripped[1], persisted_trust, false)
}

fn admit_registrations(
    hooks: &Value,
    verified: &VerifiedRegistry,
    seen: &mut BTreeSet<(Event, u64)>,
) -> Result<(), SettingsError> {
    let events = hooks
        .as_object()
        .ok_or_else(|| SettingsError::Invalid("hooks".into()))?;
    for (name, groups) in events {
        let event =
            Event::from_str(name).map_err(|_| SettingsError::Unsupported("hooks.event".into()))?;
        let groups = groups
            .as_array()
            .ok_or_else(|| SettingsError::Invalid("hooks.groups".into()))?;
        for group in groups {
            let fields = group
                .as_object()
                .ok_or_else(|| SettingsError::Invalid("hooks.group".into()))?;
            if fields
                .keys()
                .any(|key| !matches!(key.as_str(), "matcher" | "hooks"))
            {
                return Err(SettingsError::Unsupported("hooks.group_fields".into()));
            }
            let matcher = match fields.get("matcher") {
                None => "",
                Some(Value::String(text)) => text,
                _ => return Err(SettingsError::Invalid("hooks.matcher".into())),
            };
            let commands = fields
                .get("hooks")
                .and_then(Value::as_array)
                .ok_or_else(|| SettingsError::Invalid("hooks.commands".into()))?;
            for command in commands {
                admit_command(command, event, matcher, verified, seen)?;
            }
        }
    }
    Ok(())
}

fn admit_command(
    command: &Value,
    event: Event,
    matcher: &str,
    verified: &VerifiedRegistry,
    seen: &mut BTreeSet<(Event, u64)>,
) -> Result<(), SettingsError> {
    let fields = command
        .as_object()
        .ok_or_else(|| SettingsError::Invalid("hooks.command".into()))?;
    if fields
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "command" | "timeout"))
        || fields.get("type").and_then(Value::as_str) != Some("command")
    {
        return Err(SettingsError::Unsupported("hooks.command_fields".into()));
    }
    let text = fields
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| SettingsError::Invalid("hooks.command".into()))?;
    if text.len() > 8192
        || text
            .chars()
            .any(|c| c.is_control() || "'\"\\$`;|&<>*?[](){}".contains(c))
    {
        return Err(SettingsError::Unsupported("hooks.shell_syntax".into()));
    }
    let words: Vec<_> = text.split_ascii_whitespace().collect();
    if words.first() != Some(&"node") || !matches!(words.len(), 2 | 3) {
        return Err(SettingsError::Unsupported("hooks.node_command".into()));
    }
    let timeout = match fields.get("timeout") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| SettingsError::Invalid("hooks.timeout".into()))?,
        ),
    };
    let rows: Vec<_> = verified
        .rows
        .iter()
        .filter(|admitted| {
            admitted.row.event == event && admitted.row.surfaces.contains(&Surface::Claude)
        })
        .collect();
    let selected = if words.len() == 2 {
        let matching: Vec<_> = rows
            .into_iter()
            .filter(|admitted| {
                admitted.row.matcher == matcher
                    && admitted.admission.as_ref().is_ok_and(|source| {
                        words[1] == admitted.row.file
                            || Some(words[1]) == source.source_path().to_str()
                    })
            })
            .collect();
        if matching.len() != 1 {
            return Err(SettingsError::Unsupported("hooks.row_registration".into()));
        }
        matching
    } else {
        if !matcher.is_empty() || words[2] != event.as_str() {
            return Err(SettingsError::Unsupported(
                "hooks.runtime_registration".into(),
            ));
        }
        let bindings =
            super::runtime_mapping::prove_runtime_pools(verified, event, Surface::Claude)
                .map_err(|_| SettingsError::Unsupported("hooks.runtime_mapping_unproved".into()))?;
        let runtime_matches: Vec<_> = verified
            .registry
            .runtimes
            .iter()
            .zip(&verified.runtimes)
            .enumerate()
            .filter(|(_, (entry, source))| {
                (words[1] == entry.entry || Some(words[1]) == source.source_path().to_str())
                    && entry.entry_sha256.as_deref()
                        == Some(registry::sha256(source.as_bytes()).as_str())
            })
            .map(|(index, _)| index)
            .collect();
        if runtime_matches.len() != 1 {
            return Err(SettingsError::Unsupported(
                "hooks.runtime_registration".into(),
            ));
        }
        let binding = bindings
            .iter()
            .find(|binding| binding.runtime_index == runtime_matches[0])
            .ok_or_else(|| SettingsError::Unsupported("hooks.runtime_mapping_unproved".into()))?;
        let mut selected: Vec<_> = rows
            .into_iter()
            .filter(|row| binding.row_ids.contains(&row.row.id))
            .collect();
        selected.sort_by_key(|row| row.row.order);
        selected
    };
    for admitted in selected {
        let row = &admitted.row;
        if timeout != row.timeout
            || admitted.admission.as_ref().is_err()
            || admitted
                .admission
                .as_ref()
                .is_ok_and(|source| registry::sha256(source.as_bytes()) != row.file_sha256)
        {
            return Err(SettingsError::Unsupported("hooks.row_metadata".into()));
        }
        if seen
            .iter()
            .rfind(|(seen_event, _)| *seen_event == event)
            .is_some_and(|(_, last)| *last >= row.order)
            || !seen.insert((event, row.order))
        {
            return Err(SettingsError::Unsupported(
                "hooks.order_or_duplicate".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    Local,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettingsError {
    #[error("Claude settings must be an object")]
    InvalidObject,
    #[error("Claude setting cannot safely acquire flag scope: {0}")]
    Unsupported(String),
    #[error("Claude setting is malformed: {0}")]
    Invalid(String),
    #[error("project MCP requires separate native-authorized delivery")]
    ProjectMcp,
}

/// `persisted_trust` is a launch-owner decision from the effective native
/// workspace key, never a field taken from settings, payload, or registry.
/// Untrusted imports intentionally retain only permissions.deny; this is the
/// authorized conservative policy, not a claim of native behavioral parity.
pub fn compose(
    project: &Value,
    local: &Value,
    persisted_trust: bool,
    has_project_mcp: bool,
) -> Result<Value, SettingsError> {
    if has_project_mcp {
        return Err(SettingsError::ProjectMcp);
    }
    let mut merged = Map::new();
    for (scope, settings) in [(Scope::Project, project), (Scope::Local, local)] {
        let fields = settings.as_object().ok_or(SettingsError::InvalidObject)?;
        for (key, value) in fields {
            if key == "permissions" {
                permissions(&mut merged, value, persisted_trust)?;
            } else if persisted_trust {
                trusted_field(&mut merged, scope, key, value)?;
            }
        }
    }
    Ok(Value::Object(merged))
}

fn permissions(
    merged: &mut Map<String, Value>,
    value: &Value,
    trusted: bool,
) -> Result<(), SettingsError> {
    let fields = value
        .as_object()
        .ok_or_else(|| SettingsError::Invalid("permissions".into()))?;
    let result = merged
        .entry("permissions")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("permissions is created only by this composer");
    for (key, value) in fields {
        let path = format!("permissions.{key}");
        if !trusted && key != "deny" {
            continue;
        }
        match key.as_str() {
            "allow" | "ask" | "deny" => {
                let rules = value
                    .as_array()
                    .filter(|rules| rules.iter().all(Value::is_string))
                    .ok_or_else(|| SettingsError::Invalid(path.clone()))?;
                let out = result
                    .entry(key.clone())
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .expect("rule arrays are created only by this composer");
                for rule in rules {
                    if !out.contains(rule) {
                        out.push(rule.clone());
                    }
                }
            }
            "defaultMode" => match value.as_str() {
                // Native project/local source admission ignores these modes.
                Some("auto" | "bypassPermissions") => {}
                Some("default" | "acceptEdits" | "plan" | "dontAsk") => {
                    result.insert(key.clone(), value.clone());
                }
                _ => return Err(SettingsError::Invalid(path)),
            },
            _ => return Err(SettingsError::Unsupported(path)),
        }
    }
    Ok(())
}

fn trusted_field(
    merged: &mut Map<String, Value>,
    scope: Scope,
    key: &str,
    value: &Value,
) -> Result<(), SettingsError> {
    match key {
        // Hook delivery is replaced separately, never copied into flag scope.
        "$schema" if value.is_string() => {}
        "$schema" => return Err(SettingsError::Invalid("$schema".into())),
        "hooks" => {
            // Native preprocessing salvages many malformed hooks, but a
            // non-object shape can still invalidate the whole original source.
            // Nonempty original-source validation belongs to the runner's
            // registry equivalence path; do not rehabilitate it on import.
            if !value.as_object().is_some_and(Map::is_empty) {
                return Err(SettingsError::Unsupported("hooks".into()));
            }
        }
        // These getters deliberately exclude both native project/local scopes.
        "modelPicker" => {}
        "autoMode" => validate_auto_mode(value)?,
        // Native getters exclude project, but accept local (handled below).
        "skipDangerousModePermissionPrompt" | "skipWorkflowUsageWarning" if !value.is_boolean() => {
            return Err(SettingsError::Invalid(key.into()));
        }
        "skipDangerousModePermissionPrompt" | "skipWorkflowUsageWarning"
            if scope == Scope::Project => {}
        "model" if value.as_str().is_some_and(|s| !s.is_empty()) => {
            merged.insert(key.into(), value.clone());
        }
        "effortLevel" if matches!(value.as_str(), Some("low" | "medium" | "high" | "xhigh")) => {
            merged.insert(key.into(), value.clone());
        }
        "skipDangerousModePermissionPrompt" | "skipWorkflowUsageWarning" if value.is_boolean() => {
            merged.insert(key.into(), value.clone());
        }
        "env" if value.as_object().is_some_and(Map::is_empty) => {}
        "statusLine" => status_line(merged, value)?,
        "model"
        | "effortLevel"
        | "skipDangerousModePermissionPrompt"
        | "skipWorkflowUsageWarning" => return Err(SettingsError::Invalid(key.into())),
        // Environment, plugin, model-map and restrictive-any-scope settings
        // need their own audited native source filter/merge. Refusal is visible.
        _ => return Err(SettingsError::Unsupported(key.into())),
    }
    Ok(())
}

fn validate_auto_mode(value: &Value) -> Result<(), SettingsError> {
    let fields = value
        .as_object()
        .ok_or_else(|| SettingsError::Invalid("autoMode".into()))?;
    for (key, value) in fields {
        let valid = match key.as_str() {
            "allow" | "soft_deny" | "hard_deny" | "environment" => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            "classifyAllShell" => value.is_boolean(),
            _ => return Err(SettingsError::Unsupported(format!("autoMode.{key}"))),
        };
        if !valid {
            return Err(SettingsError::Invalid(format!("autoMode.{key}")));
        }
    }
    Ok(())
}

fn status_line(merged: &mut Map<String, Value>, value: &Value) -> Result<(), SettingsError> {
    let fields = value
        .as_object()
        .ok_or_else(|| SettingsError::Invalid("statusLine".into()))?;
    if fields.get("type").and_then(Value::as_str) != Some("command")
        || fields.get("command").and_then(Value::as_str).is_none()
    {
        return Err(SettingsError::Invalid("statusLine".into()));
    }
    for (key, value) in fields {
        let valid = match key.as_str() {
            "type" => value.as_str() == Some("command"),
            "command" => value.as_str().is_some_and(|s| !s.is_empty()),
            "padding" => value.as_u64().is_some(),
            _ => return Err(SettingsError::Unsupported(format!("statusLine.{key}"))),
        };
        if !valid {
            return Err(SettingsError::Invalid(format!("statusLine.{key}")));
        }
    }
    let out = merged
        .entry("statusLine")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("statusLine is created only by this composer");
    out.extend(fields.clone());
    Ok(())
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;

#[cfg(test)]
mod registration_tests {
    use super::super::{
        pin::Pin,
        registry::tests::{fixture, sealed},
    };
    use super::*;
    use serde_json::json;

    fn admitted() -> (tempfile::TempDir, super::super::pin::VerifiedRegistry) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".claude/hooks")).unwrap();
        std::fs::write(temp.path().join(".claude/hooks/guard.js"), b"hook").unwrap();
        std::fs::write(
            temp.path().join(super::super::pin::MANIFEST_FILE),
            sealed(fixture(b"hook")),
        )
        .unwrap();
        let verified = Pin::capture_operator(temp.path())
            .unwrap()
            .verify(temp.path())
            .unwrap();
        (temp, verified)
    }

    #[test]
    fn original_registry_equivalent_hook_can_be_replaced_without_losing_permissions() {
        let (_temp, verified) = admitted();
        let project = json!({"hooks":{"PreToolUse":[{"matcher":"Bash|Edit","hooks":[{"type":"command","command":"node .claude/hooks/guard.js","timeout":30}]}]},"permissions":{"deny":["Bash(rm *)"],"allow":["Read"]}});
        assert_eq!(
            compose_registered(&project, &json!({}), true, false, &verified).unwrap(),
            json!({"permissions":{"deny":["Bash(rm *)"],"allow":["Read"]}})
        );
    }

    fn registration() -> Value {
        json!({"hooks":{"PreToolUse":[{"matcher":"Bash|Edit","hooks":[{"type":"command","command":"node .claude/hooks/guard.js","timeout":30}]}]},"permissions":{"deny":["Bash(rm *)"],"allow":["Read"]}})
    }

    #[test]
    fn hook_coverage_duplicates_shell_and_metadata_mismatch_refuse() {
        let (_temp, verified) = admitted();
        assert!(compose_registered(&json!({}), &json!({}), true, false, &verified).is_err());
        assert!(
            compose_registered(&registration(), &registration(), true, false, &verified).is_err()
        );
        for mutation in 0..7 {
            let mut project = registration();
            let command = &mut project["hooks"]["PreToolUse"][0]["hooks"][0];
            match mutation {
                0 => command["command"] = "node .claude/hooks/foreign.js".into(),
                1 => command["command"] = "node .claude/hooks/guard.js; true".into(),
                2 => command["command"] = "node\n.claude/hooks/guard.js".into(),
                3 => command["timeout"] = 29.into(),
                4 => command["async"] = true.into(),
                5 => project["hooks"]["PreToolUse"][0]["matcher"] = "Bash".into(),
                _ => project["hooks"]["PreToolUse"][0]["unexpected"] = true.into(),
            }
            assert!(
                compose_registered(&project, &json!({}), true, false, &verified).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn pinned_runtime_requires_literal_event_matcher_timeout_and_source_hash() {
        let (_temp, mut verified) = admitted();
        let project = json!({"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"node .claude/hooks/guard.js PreToolUse","timeout":30}]}]}});
        assert_eq!(
            compose_registered(&project, &json!({}), true, false, &verified).unwrap(),
            json!({})
        );
        for (command, matcher) in [
            ("node .claude/hooks/guard.js Stop", ""),
            ("node .claude/hooks/guard.js --event PreToolUse", ""),
            ("node .claude/hooks/guard.js PreToolUse", "Bash"),
        ] {
            let mut changed = project.clone();
            changed["hooks"]["PreToolUse"][0]["matcher"] = matcher.into();
            changed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = command.into();
            assert!(compose_registered(&changed, &json!({}), true, false, &verified).is_err());
        }
        verified.registry.runtimes[0].entry_sha256 = Some("a".repeat(64));
        assert!(compose_registered(&project, &json!({}), true, false, &verified).is_err());
    }

    fn runtime_registration() -> Value {
        json!({"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"node .claude/hooks/guard.js PreToolUse","timeout":30}]}]}})
    }

    #[test]
    fn runtime_mapping_with_multiple_declarations_refuses() {
        let (_temp, mut verified) = admitted();
        verified
            .registry
            .runtimes
            .push(verified.registry.runtimes[0].clone());
        assert_eq!(
            compose_registered(&runtime_registration(), &json!({}), true, false, &verified),
            Err(SettingsError::Unsupported(
                "hooks.runtime_mapping_unproved".into()
            ))
        );
    }

    #[test]
    fn runtime_mapping_across_multiple_pools_refuses() {
        let (temp, _verified) = admitted();
        let mut registry = fixture(b"hook");
        let mut second = registry["hooks"][0].clone();
        second["matcher"] = "Write".into();
        second["order"] = 11.into();
        second["source"] = "loom-template".into();
        second["pool"] = "template".into();
        registry["hooks"].as_array_mut().unwrap().push(second);
        std::fs::write(
            temp.path().join(super::super::pin::MANIFEST_FILE),
            sealed(registry),
        )
        .unwrap();
        let verified = Pin::capture_operator(temp.path())
            .unwrap()
            .verify(temp.path())
            .unwrap();
        assert_eq!(
            compose_registered(&runtime_registration(), &json!({}), true, false, &verified),
            Err(SettingsError::Unsupported(
                "hooks.runtime_mapping_unproved".into()
            ))
        );
    }

    #[test]
    fn runtime_mapping_for_zero_row_event_refuses_without_dropping_original_command() {
        let (_temp, verified) = admitted();
        let mut project = registration();
        project["hooks"]["Stop"] = json!([{"hooks":[{"type":"command","command":"node .claude/hooks/guard.js Stop","timeout":30}]}]);
        assert_eq!(
            compose_registered(&project, &json!({}), true, false, &verified),
            Err(SettingsError::Unsupported(
                "hooks.runtime_mapping_unproved".into()
            ))
        );
    }

    #[test]
    fn configuration_carriers_refuse_even_before_native_workspace_trust() {
        let (_temp, verified) = admitted();
        for key in ["env", "enabledPlugins", "extraKnownMarketplaces"] {
            let mut project = registration();
            project[key] = json!({"value":"unreviewed"});
            assert_eq!(
                compose_registered(&project, &json!({}), false, false, &verified),
                Err(SettingsError::Unsupported(key.into()))
            );
        }
        assert_eq!(
            compose_registered(&registration(), &json!({}), true, true, &verified),
            Err(SettingsError::ProjectMcp)
        );
        assert_eq!(
            compose_registered(&registration(), &json!({}), false, false, &verified).unwrap(),
            json!({"permissions":{"deny":["Bash(rm *)"]}})
        );
    }

    #[test]
    fn bounded_settings_json_allows_native_fractions_but_refuses_duplicate_keys() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        std::fs::write(&path, br#"{"lastTotalCost":1.25,"projects":{}}"#).unwrap();
        assert_eq!(
            read_source_json(temp.path(), "settings.json").unwrap()["lastTotalCost"],
            1.25
        );
        std::fs::write(&path, br#"{"projects":{},"projects":{"foreign":{}}}"#).unwrap();
        assert!(read_source_json(temp.path(), "settings.json").is_err());
        std::fs::write(&path, vec![b' '; registry::MAX_MANIFEST_BYTES + 1]).unwrap();
        assert!(read_source_json(temp.path(), "settings.json").is_err());
        assert_eq!(
            read_source_json(temp.path(), "absent.json").unwrap(),
            json!({})
        );
    }

    #[cfg(unix)]
    #[test]
    fn settings_sources_refuse_leaf_and_parent_symlinks_without_reading_targets() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("foreign.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join("settings.json")).unwrap();
        assert!(read_source_json(temp.path(), "settings.json").is_err());
        let foreign = temp.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("settings.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&foreign, temp.path().join(".claude")).unwrap();
        assert!(read_source_json(temp.path(), ".claude/settings.json").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
    }
}
