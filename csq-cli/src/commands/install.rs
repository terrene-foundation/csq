//! `csq install` — set up the `~/.claude/accounts` directory and patch settings.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

pub fn handle() -> Result<()> {
    let base_dir = super::base_dir()?;
    let claude_home = super::claude_home()?;

    println!("Installing csq...");
    println!();

    // Create directories
    let credentials_dir = base_dir.join("credentials");
    std::fs::create_dir_all(&credentials_dir)
        .context("creating credentials directory")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&credentials_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    println!("  ✓ Created {}", base_dir.display());
    println!("  ✓ Created {}", credentials_dir.display());

    // Detect and report v1.x statusline before overwriting
    let old_cmd = detect_v1_statusline(&claude_home);
    patch_settings_json(&claude_home)?;
    if let Some(ref cmd) = old_cmd {
        println!("  ✓ Migrated statusline: {cmd} → csq statusline");
    } else {
        println!("  ✓ Patched {}/settings.json", claude_home.display());
    }

    // Clean up v1.x artifacts
    let cleaned = cleanup_v1_artifacts(&claude_home);
    if !cleaned.is_empty() {
        println!();
        println!("  Cleaned v1.x artifacts:");
        for item in &cleaned {
            println!("    - {item}");
        }
    }

    println!();
    println!("csq installed successfully.");
    println!();
    println!("Next steps:");
    println!("  1. Run `csq login 1` to authenticate your first account");
    println!("  2. Run `csq status` to verify");
    println!("  3. Run `csq run 1` to start a Claude Code session");

    Ok(())
}

fn patch_settings_json(claude_home: &Path) -> Result<()> {
    let path = claude_home.join("settings.json");
    std::fs::create_dir_all(claude_home)?;

    // Read existing settings.
    // On parse failure, DO NOT silently replace — refuse to run and
    // ask the user to repair the file manually. This prevents data loss
    // of user's MCP servers, hooks, and custom permissions.
    let mut value: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            serde_json::from_str(&content).map_err(|e| {
                anyhow!(
                    "failed to parse existing {} ({e}).\n\
                     Refusing to overwrite to prevent data loss.\n\
                     Fix the JSON manually and re-run `csq install`.",
                    path.display()
                )
            })?
        }
        _ => serde_json::json!({}),
    };

    // Ensure top-level is an object.
    let obj = value.as_object_mut().ok_or_else(|| {
        anyhow!("{} is not a JSON object", path.display())
    })?;

    // Insert the statusLine using CC's expected NESTED schema:
    //   { "statusLine": { "type": "command", "command": "csq statusline" } }
    // The flat `statusLineCommand` key would never be read by CC.
    obj.insert(
        "statusLine".to_string(),
        serde_json::json!({
            "type": "command",
            "command": "csq statusline"
        }),
    );

    // Atomic write via temp file + rename
    let json = serde_json::to_string_pretty(&value)?;
    let tmp = csq_core::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, json.as_bytes())
        .with_context(|| format!("writing temp file {}", tmp.display()))?;
    csq_core::platform::fs::atomic_replace(&tmp, &path)
        .map_err(|e| anyhow!("atomic replace: {e}"))?;
    Ok(())
}

/// Detects a v1.x statusline command in settings.json.
/// Returns the old command string if it exists and is NOT already
/// the v2.x `csq statusline` command.
fn detect_v1_statusline(claude_home: &Path) -> Option<String> {
    let path = claude_home.join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;

    let cmd = value
        .get("statusLine")
        .and_then(|sl| sl.get("command"))
        .and_then(|c| c.as_str())?;

    if cmd.contains("csq statusline") {
        None // Already v2.x
    } else {
        Some(cmd.to_string())
    }
}

fn cleanup_v1_artifacts(claude_home: &Path) -> Vec<String> {
    let mut cleaned = Vec::new();

    let accounts_dir = claude_home.join("accounts");

    // v1.x artifacts in ~/.claude/
    let claude_home_artifacts = [
        "statusline-command.sh",
        "rotate.md",
        "auto-rotate-hook.sh",
    ];

    // v1.x artifacts in ~/.claude/accounts/
    let accounts_artifacts = [
        "statusline-quota.sh",
        "rotation-engine.py",
        "auto-rotate-hook.sh",
    ];

    for name in &claude_home_artifacts {
        if backup_artifact(&claude_home.join(name)) {
            cleaned.push(name.to_string());
        }
    }

    for name in &accounts_artifacts {
        if backup_artifact(&accounts_dir.join(name)) {
            cleaned.push(format!("accounts/{name}"));
        }
    }

    // Remove Python cache from v1.x rotation engine
    let pycache = accounts_dir.join("__pycache__");
    if pycache.is_dir() && std::fs::remove_dir_all(&pycache).is_ok() {
        cleaned.push("accounts/__pycache__/".to_string());
    }

    cleaned
}

/// Backs up a file by renaming to `.bak`. Returns true if the file
/// existed and was successfully renamed.
fn backup_artifact(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let bak_ext = if ext.is_empty() {
        "bak".to_string()
    } else {
        format!("{ext}.bak")
    };
    let bak = path.with_extension(bak_ext);
    std::fs::rename(path, &bak).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn patch_settings_json_fresh() {
        let dir = TempDir::new().unwrap();
        patch_settings_json(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            v["statusLine"]["command"].as_str().unwrap(),
            "csq statusline"
        );
    }

    #[test]
    fn patch_settings_json_preserves_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"local": {}}, "statusLine": {"type": "command", "command": "bash old.sh"}}"#,
        )
        .unwrap();

        patch_settings_json(dir.path()).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        // statusLine updated
        assert_eq!(
            v["statusLine"]["command"].as_str().unwrap(),
            "csq statusline"
        );
        // mcpServers preserved
        assert!(v["mcpServers"]["local"].is_object());
    }

    #[test]
    fn detect_v1_statusline_old_command() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"statusLine": {"type": "command", "command": "bash ~/.claude/accounts/statusline-quota.sh"}}"#,
        )
        .unwrap();

        let result = detect_v1_statusline(dir.path());
        assert_eq!(
            result.as_deref(),
            Some("bash ~/.claude/accounts/statusline-quota.sh")
        );
    }

    #[test]
    fn detect_v1_statusline_already_v2() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            r#"{"statusLine": {"type": "command", "command": "csq statusline"}}"#,
        )
        .unwrap();

        assert!(detect_v1_statusline(dir.path()).is_none());
    }

    #[test]
    fn cleanup_backs_up_v1_files() {
        let dir = TempDir::new().unwrap();
        let accounts = dir.path().join("accounts");
        std::fs::create_dir_all(&accounts).unwrap();

        // Create some v1 artifacts
        std::fs::write(dir.path().join("statusline-command.sh"), "#!/bin/bash").unwrap();
        std::fs::write(accounts.join("rotation-engine.py"), "# python").unwrap();
        std::fs::write(accounts.join("statusline-quota.sh"), "#!/bin/bash").unwrap();

        let cleaned = cleanup_v1_artifacts(dir.path());

        // Originals gone
        assert!(!dir.path().join("statusline-command.sh").exists());
        assert!(!accounts.join("rotation-engine.py").exists());

        // .bak files created
        assert!(dir.path().join("statusline-command.sh.bak").exists());
        assert!(accounts.join("rotation-engine.py.bak").exists());
        assert!(accounts.join("statusline-quota.sh.bak").exists());

        assert_eq!(cleaned.len(), 3);
    }

    #[test]
    fn cleanup_removes_pycache() {
        let dir = TempDir::new().unwrap();
        let pycache = dir.path().join("accounts").join("__pycache__");
        std::fs::create_dir_all(&pycache).unwrap();
        std::fs::write(pycache.join("module.pyc"), "bytes").unwrap();

        let cleaned = cleanup_v1_artifacts(dir.path());

        assert!(!pycache.exists());
        assert!(cleaned.contains(&"accounts/__pycache__/".to_string()));
    }

    #[test]
    fn backup_artifact_missing_is_noop() {
        let dir = TempDir::new().unwrap();
        assert!(!backup_artifact(&dir.path().join("nonexistent.sh")));
    }
}
