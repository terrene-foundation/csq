//! Compose only the exact native workspace's admitted project/local settings.
//! This helper never creates trust, drops an unsupported carrier, or runs hooks.
use anyhow::{anyhow, Result};
use csq_core::gate::{
    pin::VerifiedRegistry,
    settings::{self, SettingsError},
};
use csq_core::session::workspace_trust;
use serde_json::Value;
use std::{fs, path::Path};

pub(super) fn compose(repo: &Path, handle: &Path, verified: &VerifiedRegistry) -> Result<Value> {
    let key = workspace_trust::native_key(repo)
        .map_err(|_| anyhow!("gate composition refused: native_workspace_key"))?;
    let repo = repo
        .canonicalize()
        .map_err(|_| anyhow!("gate composition refused: repository"))?;
    let metadata = fs::symlink_metadata(handle)
        .map_err(|_| anyhow!("gate composition refused: native_handle"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow!("gate composition refused: native_handle"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(anyhow!("gate composition refused: native_handle"));
        }
    }
    let handle = handle
        .canonicalize()
        .map_err(|_| anyhow!("gate composition refused: native_handle"))?;
    if handle.starts_with(&repo) {
        return Err(anyhow!("gate composition refused: native_handle"));
    }
    let native = settings::read_source_json(&handle, ".claude.json").map_err(named_error)?;
    let entry = match native.get("projects") {
        None => None,
        Some(Value::Object(projects)) => projects.get(&key),
        _ => return Err(anyhow!("gate composition refused: native_trust_shape")),
    };
    let trusted = match entry {
        None => false,
        Some(Value::Object(entry)) => match entry.get("hasTrustDialogAccepted") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            _ => return Err(anyhow!("gate composition refused: native_trust_shape")),
        },
        _ => return Err(anyhow!("gate composition refused: native_trust_shape")),
    };
    // Any project MCP file needs its own native-approved carrier. Presence is
    // sufficient for refusal; never open a FIFO or silently ignore an alias.
    let has_mcp = match fs::symlink_metadata(repo.join(".mcp.json")) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(anyhow!("gate composition refused: project_mcp")),
    };
    let project =
        settings::read_source_json(&repo, ".claude/settings.json").map_err(named_error)?;
    let local =
        settings::read_source_json(&repo, ".claude/settings.local.json").map_err(named_error)?;
    settings::compose_registered(&project, &local, trusted, has_mcp, verified).map_err(named_error)
}

fn named_error(error: SettingsError) -> anyhow::Error {
    // Unknown source keys can themselves contain paths or attacker text. Emit
    // only fixed carrier names; do not interpolate arbitrary JSON/error bodies.
    let code = match error {
        SettingsError::ProjectMcp => "project_mcp",
        SettingsError::Unsupported(key) if key == "env" => "environment",
        SettingsError::Unsupported(key)
            if matches!(key.as_str(), "enabledPlugins" | "extraKnownMarketplaces") =>
        {
            "plugins"
        }
        SettingsError::Unsupported(key) if key.starts_with("hooks.") => "hook_registry_equivalence",
        SettingsError::Unsupported(_) => "unsupported_setting",
        SettingsError::Invalid(_) | SettingsError::InvalidObject => {
            "malformed_or_unreadable_settings"
        }
    };
    anyhow!("gate composition refused: {code}")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use csq_core::gate::{pin::Pin, registry};
    use serde_json::json;

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        VerifiedRegistry,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = root.join("repo");
        let handle = root.join("handle");
        fs::create_dir_all(repo.join(".claude/hooks")).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        fs::create_dir(&handle).unwrap();
        let mut registry: Value = serde_json::from_slice(include_bytes!(
            "../../../../csq-core/tests/fixtures/hook_registry_1b/sample.json"
        ))
        .unwrap();
        registry["hooks"] = json!([registry["hooks"][0].clone()]);
        registry["runtimes"] = json!([registry["runtimes"][0].clone()]);
        let body = b"private composition test source";
        let digest = registry::sha256(body);
        registry["hooks"][0]["deps"] = json!([]);
        registry["hooks"][0]["file_sha256"] = digest.clone().into();
        registry["runtimes"][0]["deps"] = json!([]);
        registry["runtimes"][0]["entry_sha256"] = digest.into();
        for path in [
            registry["hooks"][0]["file"].as_str().unwrap(),
            registry["runtimes"][0]["entry"].as_str().unwrap(),
        ] {
            fs::write(repo.join(path), body).unwrap();
        }
        registry["content_sha256"] =
            registry::sha256(&registry::canonical_content_bytes(&registry).unwrap()).into();
        fs::write(
            repo.join(csq_core::gate::pin::MANIFEST_FILE),
            serde_json::to_vec(&registry).unwrap(),
        )
        .unwrap();
        let row = &registry["hooks"][0];
        let project = json!({"hooks":{"PreToolUse":[{"matcher":row["matcher"],"hooks":[{"type":"command","command":format!("node {}", row["file"].as_str().unwrap()),"timeout":row["timeout"]}]}]},"permissions":{"deny":["Bash(rm *)"],"allow":["Read"]}});
        fs::write(
            repo.join(".claude/settings.json"),
            serde_json::to_vec(&project).unwrap(),
        )
        .unwrap();
        let verified = Pin::capture_operator(&repo).unwrap().verify(&repo).unwrap();
        (temp, repo, handle, verified)
    }

    #[test]
    fn effective_native_handle_exact_trust_flag_controls_allow_rules() {
        let (_temp, repo, handle, verified) = fixture();
        let parent_key = repo.parent().unwrap().to_str().unwrap();
        fs::write(handle.join(".claude.json"), serde_json::to_vec(&json!({"projects":{parent_key:{"hasTrustDialogAccepted":true}},"lastTotalCost":1.25})).unwrap()).unwrap();
        assert_eq!(
            compose(&repo, &handle, &verified).unwrap(),
            json!({"permissions":{"deny":["Bash(rm *)"]}})
        );
        let key = workspace_trust::native_key(&repo).unwrap();
        for trusted in [false, true] {
            fs::write(handle.join(".claude.json"), serde_json::to_vec(&json!({"projects":{key.clone():{"hasTrustDialogAccepted":trusted}},"lastTotalCost":1.25})).unwrap()).unwrap();
            let settings = compose(&repo, &handle, &verified).unwrap();
            assert_eq!(settings["permissions"]["allow"].is_array(), trusted);
            assert_eq!(settings["permissions"]["deny"], json!(["Bash(rm *)"]));
            assert!(settings.get("hooks").is_none());
        }
    }

    #[test]
    fn critical_carriers_refuse_by_name_and_unknown_keys_never_echo_paths() {
        let (_temp, repo, handle, verified) = fixture();
        for (key, expected) in [
            ("env", "environment"),
            ("enabledPlugins", "plugins"),
            ("/private/canary", "unsupported_setting"),
        ] {
            fs::write(
                repo.join(".claude/settings.local.json"),
                serde_json::to_vec(&json!({key:{"value":true}})).unwrap(),
            )
            .unwrap();
            let error = compose(&repo, &handle, &verified).unwrap_err().to_string();
            assert!(error.ends_with(expected));
            assert!(!error.contains("canary"));
        }
        fs::remove_file(repo.join(".claude/settings.local.json")).unwrap();
        fs::write(repo.join(".mcp.json"), b"{}").unwrap();
        assert!(compose(&repo, &handle, &verified)
            .unwrap_err()
            .to_string()
            .ends_with("project_mcp"));
    }

    #[test]
    fn malformed_native_trust_and_symlinked_handle_or_settings_refuse() {
        let (_temp, repo, handle, verified) = fixture();
        fs::write(
            handle.join(".claude.json"),
            b"{\"projects\":{},\"projects\":{}}",
        )
        .unwrap();
        assert!(compose(&repo, &handle, &verified).is_err());
        fs::write(handle.join(".claude.json"), b"{}").unwrap();
        let linked = handle.with_file_name("linked-handle");
        std::os::unix::fs::symlink(&handle, &linked).unwrap();
        assert!(compose(&repo, &linked, &verified).is_err());
        let settings = repo.join(".claude/settings.json");
        fs::remove_file(&settings).unwrap();
        std::os::unix::fs::symlink(handle.join(".claude.json"), &settings).unwrap();
        assert!(compose(&repo, &handle, &verified).is_err());
    }
}
