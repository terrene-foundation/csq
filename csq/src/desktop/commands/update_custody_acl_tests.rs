//! Portable authority tests: real build-produced manifests + capabilities.
//! No Webview/IPC process, updater, installer, account, network or global env access.

use std::collections::BTreeMap;
use std::path::Path;
use tauri::ipc::{Origin, RuntimeAuthority};
use tauri::utils::acl::{
    capability::{Capability, CapabilityFile},
    get_capabilities,
    manifest::Manifest,
    resolved::Resolved,
    APP_ACL_KEY,
};
use tauri::utils::{config::Config, platform::Target};

const RAW_BYPASSES: [&str; 6] = [
    "plugin:updater|check",
    "plugin:updater|download_and_install",
    "plugin:updater|install",
    "plugin:updater|download",
    "plugin:process|restart",
    "plugin:process|exit",
];
const CUSTODY_COMMANDS: [&str; 2] = ["install_update_with_custody", "restart_with_custody"];
const OBSOLETE_COMMANDS: [&str; 2] = ["install_windows_update", "get_update_install_mode"];

fn current_capabilities(directory: &Path, capabilities: &mut BTreeMap<String, Capability>) {
    for entry in std::fs::read_dir(directory).expect("capability source directory must be readable")
    {
        let entry = entry.expect("capability source entry must be readable");
        let kind = entry
            .file_type()
            .expect("capability source kind must be readable");
        if kind.is_dir() {
            current_capabilities(&entry.path(), capabilities);
        } else {
            assert!(kind.is_file(), "capability source must be a regular file");
            match entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
            {
                Some("json" | "toml") => {}
                Some("json5") => {
                    panic!("add configured json5 capability loading before qualification")
                }
                _ => continue,
            }
            let loaded = CapabilityFile::load(entry.path()).expect("capability source must parse");
            let loaded = match loaded {
                CapabilityFile::Capability(capability) => vec![capability],
                CapabilityFile::List(capabilities) | CapabilityFile::NamedList { capabilities } => {
                    capabilities
                }
            };
            for capability in loaded {
                assert!(
                    capabilities
                        .insert(capability.identifier.clone(), capability)
                        .is_none(),
                    "capability identifiers must be unique"
                );
            }
        }
    }
}

fn authority(target: Target, injected_capability: Option<Capability>) -> RuntimeAuthority {
    // These are the outputs of THIS csq build script, not checked-in gen/ files.
    // Old production emits the same file names and supports these same public APIs.
    let manifests_json =
        std::fs::read_to_string(Path::new(env!("OUT_DIR")).join("acl-manifests.json"))
            .expect("production build ACL manifests must be readable");
    let manifests: BTreeMap<String, Manifest> =
        serde_json::from_str(&manifests_json).expect("production build ACL manifests must parse");
    let capabilities_json =
        std::fs::read_to_string(Path::new(env!("OUT_DIR")).join("capabilities.json"))
            .expect("production build capabilities must be readable");
    let built_capabilities: BTreeMap<String, Capability> =
        serde_json::from_str(&capabilities_json).expect("production build capabilities must parse");
    assert!(
        manifests.contains_key(APP_ACL_KEY),
        "real application ACL manifest is required"
    );
    assert!(
        manifests.contains_key("updater"),
        "real updater plugin manifest is required"
    );
    assert!(
        manifests.contains_key("process"),
        "real process plugin manifest is required"
    );

    // Fail closed on stale generated capabilities, rather than certifying old bytes.
    let mut source_capabilities = BTreeMap::new();
    current_capabilities(
        &csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")).join("capabilities"),
        &mut source_capabilities,
    );
    assert_eq!(
        serde_json::to_value(&built_capabilities).unwrap(),
        serde_json::to_value(&source_capabilities).unwrap(),
        "production capabilities output is stale; rebuild before measuring authority"
    );

    let config_json = include_str!("../../../tauri.conf.json");
    let config: Config =
        serde_json::from_str(config_json).expect("production configuration must parse");
    let mut capabilities = get_capabilities(&config, built_capabilities, None)
        .expect("production capability selection must resolve");
    if let Some(capability) = injected_capability {
        assert!(capabilities
            .insert(capability.identifier.clone(), capability)
            .is_none());
    }
    let resolved = Resolved::resolve(&manifests, capabilities, target)
        .expect("production permission references must resolve for this target");
    assert!(
        resolved.has_app_acl,
        "application command access must be enforced"
    );
    // The Unix dev-dependency uses Tauri's defaults, including dynamic-acl.
    RuntimeAuthority::new(manifests, resolved)
}

fn allowed(authority: &RuntimeAuthority, command: &str, window: &str, webview: &str) -> bool {
    authority
        .resolve_access(command, window, webview, &Origin::Local)
        .is_some()
}

#[test]
fn all_desktop_targets_deny_every_raw_update_and_process_bypass() {
    for target in [Target::Windows, Target::MacOS, Target::Linux] {
        let authority = authority(target, None);
        for command in RAW_BYPASSES {
            assert!(
                !allowed(&authority, command, "main", "main"),
                "raw bypass unexpectedly authorized on {target}: {command}"
            );
        }
    }
}

#[test]
fn all_desktop_targets_allow_only_custody_update_commands_on_main() {
    for target in [Target::Windows, Target::MacOS, Target::Linux] {
        let authority = authority(target, None);
        for command in CUSTODY_COMMANDS {
            assert!(
                allowed(&authority, command, "main", "main"),
                "canonical custody command missing on {target}: {command}"
            );
        }
        for command in OBSOLETE_COMMANDS {
            assert!(
                !allowed(&authority, command, "main", "main"),
                "obsolete updater route remains authorized on {target}: {command}"
            );
        }
    }
}

#[test]
fn every_desktop_target_denies_update_authority_outside_main_window() {
    for target in [Target::Windows, Target::MacOS, Target::Linux] {
        let authority = authority(target, None);
        for command in RAW_BYPASSES
            .into_iter()
            .chain(CUSTODY_COMMANDS)
            .chain(OBSOLETE_COMMANDS)
        {
            for webview in ["other", "main"] {
                assert!(
                    !allowed(&authority, command, "other", webview),
                    "non-main window authorized on {target}: {command}"
                );
            }
        }
    }
}

#[test]
fn additive_grant_control_exposes_every_reintroduced_bypass_on_each_target() {
    for target in [Target::Windows, Target::MacOS, Target::Linux] {
        // This real additive capability would defeat a default.json-only scan.
        // The production-denial test above must reject the authority it creates.
        let unsafe_grant: Capability = serde_json::from_value(serde_json::json!({
            "identifier": "test-only-reintroduced-bypass",
            "windows": ["main"],
            "permissions": [
                "updater:allow-check", "updater:allow-download-and-install",
                "updater:allow-install", "updater:allow-download",
                "process:allow-restart", "process:allow-exit"
            ]
        }))
        .unwrap();
        let authority = authority(target, Some(unsafe_grant));
        for command in RAW_BYPASSES {
            assert!(
                allowed(&authority, command, "main", "main"),
                "positive control did not expose bypass on {target}: {command}"
            );
        }
    }
}
