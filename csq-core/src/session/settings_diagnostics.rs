//! Read-only, bounded diagnostics for Claude auto-compact settings in csq-owned layers.

use super::{
    handle_dir::read_regular_bounded,
    settings_policy::{
        autocompact_env_override_forms, autocompact_override_forms, slot_allows_provider_window,
    },
};
use crate::accounts::identity_store::{settings_path_for, IdentityId};
use crate::types::AccountNum;
use serde::Serialize;
use std::path::Path;

/// Only typed relative locations and presence flags cross the operator/IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoCompactSettingsReport {
    pub guidance: &'static str,
    pub findings: Vec<AutoCompactSettingsFinding>,
    /// Fixed location labels; unreadable includes malformed, oversized and nonregular files.
    pub unreadable: Vec<String>,
}

pub const AUTO_COMPACT_GUIDANCE: &str = "Source overlays remain unchanged. csq filters these overrides when preparing terminal settings. Existing terminals receive filtered settings at their next swap or relaunch.";

impl Default for AutoCompactSettingsReport {
    fn default() -> Self {
        Self {
            guidance: AUTO_COMPACT_GUIDANCE,
            findings: Vec::new(),
            unreadable: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoCompactSettingsFinding {
    pub location: String,
    pub root: bool,
    pub per_model: bool,
    pub pct_override: bool,
    pub provider_window: bool,
}

/// Collects only SOURCE config-N and canonical UUID settings overlays.
/// Materialized term directories and user-global settings are outside this report.
/// Provider windows require the policy helper's published API-key slot proof;
/// unreadable proof denies the exception. Credential contents are never opened.
pub fn collect_autocompact_settings(base: &Path) -> AutoCompactSettingsReport {
    let mut report = AutoCompactSettingsReport::default();
    for entry in entries(base, "accounts", &mut report) {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(slot) = name
            .strip_prefix("config-")
            .and_then(|n| n.parse::<u16>().ok())
            .and_then(|n| AccountNum::try_from(n).ok())
            .filter(|slot| name == format!("config-{}", slot.get()))
        else {
            // In particular, never inspect term files, markers or liveness.
            continue;
        };
        let location = format!("config-{}/settings.json", slot.get());
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            report.unreadable.push(location);
            continue;
        }
        let config_dir = entry.path();
        let allow_provider_window = slot_allows_provider_window(base, &config_dir);
        inspect(
            &config_dir.join("settings.json"),
            location,
            allow_provider_window,
            &mut report,
        );
    }
    let identities = base.join("identities");
    // identities/ itself is also a scope boundary, not a link to another tree.
    match identities.symlink_metadata() {
        Ok(m) if !m.is_dir() => report.unreadable.push("identities".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => report.unreadable.push("identities".into()),
        Ok(_) => {
            for entry in entries(&identities, "identities", &mut report) {
                let Some(uuid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<IdentityId>().ok())
                else {
                    continue;
                };
                if entry.file_name() != uuid.to_canonical_string().as_str() {
                    continue;
                }
                let label = format!("identities/{uuid}/settings.json");
                if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                    report.unreadable.push(label);
                    continue;
                }
                // UUID overlays alone do not prove an API-key slot. The canonical
                // policy helper also denies its exception for by_slot UUID bindings.
                inspect(&settings_path_for(base, uuid), label, false, &mut report);
            }
        }
    }
    report.findings.sort_by(|a, b| a.location.cmp(&b.location));
    report.unreadable.sort();
    report.unreadable.dedup();
    report
}

fn entries(
    path: &Path,
    label: &str,
    report: &mut AutoCompactSettingsReport,
) -> Vec<std::fs::DirEntry> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(_) => {
                    report.unreadable.push(label.into());
                    None
                }
            })
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            report.unreadable.push(label.into());
            Vec::new()
        }
    }
}

fn inspect(
    path: &Path,
    location: String,
    allow_provider_window: bool,
    report: &mut AutoCompactSettingsReport,
) {
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            report.unreadable.push(location);
            return;
        }
        // A settings link could name a credential file or a global file. Report unknown
        // rather than follow it outside this collector's explicitly authorized scope.
        Ok(m) if !m.is_file() => {
            report.unreadable.push(location);
            return;
        }
        Ok(_) => {}
    }
    match read_regular_bounded(path, true)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(serde_json::Value::is_object)
    {
        Some(value) => {
            let (root, per_model) = autocompact_override_forms(&value);
            let (pct_override, provider_window) =
                autocompact_env_override_forms(&value, allow_provider_window);
            if root || per_model || pct_override || provider_window {
                report.findings.push(AutoCompactSettingsFinding {
                    location,
                    root,
                    per_model,
                    pct_override,
                    provider_window,
                });
            }
        }
        None => report.unreadable.push(location),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn autocompact_report_guidance_is_shared_and_defaulted() {
        let report = AutoCompactSettingsReport::default();
        assert_eq!(report.guidance, AUTO_COMPACT_GUIDANCE);
        assert_eq!(
            serde_json::to_value(&report).unwrap()["guidance"],
            AUTO_COMPACT_GUIDANCE
        );
    }
    const UUID: &str = "11111111-1111-4111-8111-111111111111";

    fn put(base: &Path, location: &str, contents: &str) {
        let path = base.join(location);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn autocompact_diagnostic_forms_are_independent_and_unproven_env_is_reported() {
        let dir = TempDir::new().unwrap();
        put(
            dir.path(),
            "config-1/settings.json",
            r#"{"autoCompactWindow":null}"#,
        );
        put(
            dir.path(),
            "config-2/settings.json",
            r#"{"modelSettings":{"private-model":{"autoCompactWindow":42}}}"#,
        );
        let allowed = r#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576","CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"50","autoCompactWindow":"allowed","ANTHROPIC_AUTH_TOKEN":"synthetic-provider-token"}}"#;
        put(dir.path(), "config-3/settings.json", allowed);
        let report = collect_autocompact_settings(dir.path());
        assert_eq!(
            report.findings,
            vec![
                AutoCompactSettingsFinding {
                    location: "config-1/settings.json".into(),
                    root: true,
                    per_model: false,
                    pct_override: false,
                    provider_window: false,
                },
                AutoCompactSettingsFinding {
                    location: "config-2/settings.json".into(),
                    root: false,
                    per_model: true,
                    pct_override: false,
                    provider_window: false,
                },
                AutoCompactSettingsFinding {
                    location: "config-3/settings.json".into(),
                    root: false,
                    per_model: false,
                    pct_override: true,
                    provider_window: true,
                },
            ]
        );
        assert!(report.unreadable.is_empty());
        let json = serde_json::to_string(&report).unwrap();
        for secret in ["private-model", "synthetic-provider-token", "1048576"] {
            assert!(!json.contains(secret));
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config-3/settings.json")).unwrap(),
            allowed
        );
    }

    #[test]
    fn autocompact_diagnostic_only_accepts_canonical_producer_names() {
        let dir = TempDir::new().unwrap();
        for location in [
            "config-01/settings.json",
            "config-+1/settings.json",
            "term-001/settings.json",
            "term-+1/settings.json",
            "identities/ABCDEFAB-1111-4111-8111-111111111111/settings.json",
            "identities/abcdefab111141118111111111111111/settings.json",
        ] {
            put(dir.path(), location, r#"{"autoCompactWindow":1}"#);
        }
        assert_eq!(
            collect_autocompact_settings(dir.path()),
            AutoCompactSettingsReport::default()
        );
    }

    #[test]
    fn autocompact_diagnostic_covers_identity_source_and_ignores_all_terms() {
        let dir = TempDir::new().unwrap();
        let forbidden = r#"{"autoCompactWindow":1,"modelSettings":{"x":{"autoCompactWindow":2}}}"#;
        put(
            dir.path(),
            &format!("identities/{UUID}/settings.json"),
            forbidden,
        );
        for pid in [10, 20, 30, 40] {
            put(dir.path(), &format!("term-{pid}/settings.json"), forbidden);
        }
        put(dir.path(), "term-20/.live-pid", "200");
        put(dir.path(), "term-30/.live-pid", "300");
        put(dir.path(), "term-30/.live-cc-pid", "301");
        put(dir.path(), "term-40/.live-pid", "400");
        let report = collect_autocompact_settings(dir.path());
        assert_eq!(
            report
                .findings
                .iter()
                .map(|f| f.location.as_str())
                .collect::<Vec<_>>(),
            vec!["identities/11111111-1111-4111-8111-111111111111/settings.json"]
        );
        assert!(report.findings.iter().all(|f| f.root && f.per_model));
        assert!(report.unreadable.is_empty());
    }

    #[test]
    fn autocompact_diagnostic_unusable_and_enumeration_errors_are_unknown() {
        let dir = TempDir::new().unwrap();
        put(dir.path(), "config-1/settings.json", "{broken");
        put(dir.path(), "config-2/settings.json", "[]");
        put(
            dir.path(),
            "config-3/settings.json",
            &" ".repeat((1 << 20) + 1),
        );
        std::fs::create_dir_all(dir.path().join("config-4/settings.json")).unwrap();
        put(dir.path(), "term-50/.live-pid", "bad");
        put(dir.path(), "identities", "not a directory");
        let report = collect_autocompact_settings(dir.path());
        assert!(report.findings.is_empty());
        assert_eq!(
            report.unreadable,
            [
                "config-1/settings.json",
                "config-2/settings.json",
                "config-3/settings.json",
                "config-4/settings.json",
                "identities"
            ]
        );
        let file_base = dir.path().join("not-a-directory");
        std::fs::write(&file_base, "{}").unwrap();
        assert!(!collect_autocompact_settings(&file_base)
            .unreadable
            .is_empty());
        assert_eq!(
            collect_autocompact_settings(&dir.path().join("absent")),
            AutoCompactSettingsReport::default()
        );
    }

    #[cfg(unix)]
    #[test]
    fn autocompact_diagnostic_fifo_and_links_are_unknown_without_reading_targets() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("config-1/settings.json");
        std::fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated TempDir path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        std::fs::create_dir_all(dir.path().join("config-2")).unwrap();
        symlink("missing", dir.path().join("config-2/settings.json")).unwrap();
        let report = collect_autocompact_settings(dir.path());
        assert_eq!(
            report.unreadable,
            ["config-1/settings.json", "config-2/settings.json"]
        );
        assert!(report.findings.is_empty());
    }
    #[test]
    fn r1_h2_source_env_flags_are_presence_only_and_unproven_window_is_forbidden() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let pct = r#"{"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":null}}"#;
        let window = r#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"private-window","ANTHROPIC_BASE_URL":"private-endpoint","ANTHROPIC_AUTH_TOKEN":"private-token"}}"#;
        put(base, "config-1/settings.json", pct);
        put(base, "config-2/settings.json", window);
        put(base, "config-2/.csq-account", "2");
        put(
            base,
            "config-2/.credentials.json",
            "unreadable-credential-payload",
        );
        put(
            base,
            "config-3/settings.json",
            r#"{"env":{"CLAUDE_CODE_MAX_CONTEXT_TOKENS":"private-context"}}"#,
        );
        let report = collect_autocompact_settings(base);
        assert!(report.unreadable.is_empty());
        assert_eq!(
            report.findings.len(),
            2,
            "SOURCE environment override missing"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["pct_override"], true);
        assert_eq!(json["findings"][0]["provider_window"], false);
        assert_eq!(json["findings"][1]["pct_override"], false);
        assert_eq!(json["findings"][1]["provider_window"], true);
        assert_eq!(
            std::fs::read_to_string(base.join("config-1/settings.json")).unwrap(),
            pct
        );
        assert_eq!(
            std::fs::read_to_string(base.join("config-2/settings.json")).unwrap(),
            window
        );
        let serialized = serde_json::to_string(&report).unwrap();
        for value in [
            "private-window",
            "private-endpoint",
            "private-token",
            "private-context",
            "unreadable-credential-payload",
        ] {
            assert!(
                !serialized.contains(value),
                "diagnostic leaked source value"
            );
        }
    }

    #[test]
    fn r1_h2_published_provider_window_allowed_but_percentage_reported() {
        let _guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = AccountNum::try_from(9u16).unwrap();
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            slot,
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        let config = base.join("config-9");
        let path = config.join("settings.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = serde_json::json!("private-window");
        value["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] = serde_json::json!("private-pct");
        let source = serde_json::to_vec(&value).unwrap();
        std::fs::write(&path, &source).unwrap();
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let profiles_before = std::fs::read(&profiles_path).unwrap();
        let marker_before = std::fs::read(config.join(".csq-account")).unwrap();
        let report = collect_autocompact_settings(base);
        assert_eq!(
            report.findings.len(),
            1,
            "published source percentage missing"
        );
        assert!(report.unreadable.is_empty());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["location"], "config-9/settings.json");
        assert_eq!(json["findings"][0]["pct_override"], true);
        assert_eq!(json["findings"][0]["provider_window"], false);
        assert_eq!(std::fs::read(&path).unwrap(), source);
        assert_eq!(std::fs::read(&profiles_path).unwrap(), profiles_before);
        assert_eq!(
            std::fs::read(config.join(".csq-account")).unwrap(),
            marker_before
        );
        let output = serde_json::to_string(&report).unwrap();
        for secret in ["sk-fixture-zai", "private-window", "private-pct"] {
            assert!(!output.contains(secret));
        }
    }

    #[test]
    fn r1_h2_identity_only_source_flags_all_forbidden_forms() {
        let dir = TempDir::new().unwrap();
        let location = format!("identities/{UUID}/settings.json");
        let original = r#"{"autoCompactWindow":false,"modelSettings":{"private-model":{"autoCompactWindow":null}},"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":false,"CLAUDE_CODE_AUTO_COMPACT_WINDOW":null}}"#;
        put(dir.path(), &location, original);
        let report = collect_autocompact_settings(dir.path());
        assert_eq!(report.findings.len(), 1);
        assert!(report.unreadable.is_empty());
        let json = serde_json::to_value(&report).unwrap();
        for flag in ["root", "per_model", "pct_override", "provider_window"] {
            assert_eq!(
                json["findings"][0][flag], true,
                "missing presence flag {flag}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join(location)).unwrap(),
            original
        );
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("private-model"));
    }

    #[cfg(unix)]
    #[test]
    fn r1_h2_term_and_global_files_are_never_source_findings_or_unknown() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        put(base, "term-10/settings.json", r#"{"autoCompactWindow":1}"#);
        std::fs::create_dir_all(base.join("term-10/.live-pid")).unwrap();
        std::fs::create_dir_all(base.join("term-20")).unwrap();
        for relative in [
            "settings.json",
            "term-20/settings.json",
            "term-20/.live-pid",
        ] {
            let path = base.join(relative);
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: the valid NUL-terminated TempDir path outlives this call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }
        symlink("missing-target", base.join("term-30")).unwrap();
        assert_eq!(
            collect_autocompact_settings(base),
            AutoCompactSettingsReport::default()
        );
        assert!(base.join("settings.json").symlink_metadata().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn r1_h2_recognized_source_directory_links_remain_unknown() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        put(target.path(), "settings.json", r#"{"autoCompactWindow":1}"#);
        symlink(target.path(), dir.path().join("config-1")).unwrap();
        symlink(target.path(), dir.path().join("identities")).unwrap();
        let report = collect_autocompact_settings(dir.path());
        assert!(report.findings.is_empty());
        assert_eq!(report.unreadable, ["config-1/settings.json", "identities"]);
    }
}
