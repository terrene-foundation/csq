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
    std::fs::create_dir_all(&credentials_dir).context("creating credentials directory")?;

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

    // Per-slot statusline migration — journal 0059.
    //
    // CC merges settings with per-slot winning over global for leaf
    // fields. Earlier csq versions wrote `statusLine.command =
    // "bash ~/.claude/accounts/statusline-quota.sh"` into every
    // config-<N>/settings.json. A later global upgrade to
    // `csq statusline` has no effect on those slots because the
    // stale per-slot value still wins. Walk every per-slot settings
    // file and strip the statusLine key when it points at a known
    // legacy wrapper so global inherits forever.
    let migrated_slots = migrate_per_slot_statuslines(&base_dir)?;
    if !migrated_slots.is_empty() {
        let summary = migrated_slots
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  ✓ Cleared stale per-slot statusLine on slot(s): {summary}");
    }

    // Seed an empty keybindings.json if the user doesn't already
    // have one. CC expects this file to exist; without it the UI
    // logs a keybinding-error on every launch. Non-destructive —
    // we only create it when missing, never overwrite.
    if seed_keybindings_json(&claude_home)? {
        println!("  ✓ Seeded {}/keybindings.json", claude_home.display());
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
    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} is not a JSON object", path.display()))?;

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

/// Creates `<claude_home>/keybindings.json` with `{"bindings": []}`
/// only if the file does not already exist. Returns `Ok(true)`
/// when the file was created, `Ok(false)` when it was already
/// present (no-op). Never overwrites — user customization wins.
///
/// CC logs a keybinding-error on every launch when this file is
/// absent. csq's handle-dir model then symlinks each terminal's
/// `keybindings.json` to the global one, so seeding the global
/// eliminates the error across every spawned session.
fn seed_keybindings_json(claude_home: &Path) -> Result<bool> {
    std::fs::create_dir_all(claude_home)?;
    let path = claude_home.join("keybindings.json");
    if path.exists() {
        return Ok(false);
    }
    let tmp = csq_core::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, b"{\n  \"bindings\": []\n}\n")
        .with_context(|| format!("writing temp file {}", tmp.display()))?;
    csq_core::platform::fs::atomic_replace(&tmp, &path)
        .map_err(|e| anyhow!("atomic replace: {e}"))?;
    Ok(true)
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

/// Walks `<base_dir>/config-<N>/settings.json` files and removes the
/// `statusLine` block whenever its `command` matches a known v1.x
/// shell wrapper (`statusline-quota.sh`, `statusline-command.sh`).
///
/// Removal — not rewrite — is deliberate. The only reason a per-slot
/// `statusLine` key exists is that a much earlier csq installer wrote
/// one before csq learned to patch global. Today, csq statusline
/// belongs in global; removing the per-slot override lets global
/// cascade forever and insulates slots from future statusline
/// contract changes.
///
/// A `statusLine.command` containing `csq statusline` is treated as
/// already current and left alone. A user-custom command that does
/// not match a known legacy wrapper is also preserved — csq will
/// never silently overwrite user customisation.
///
/// Returns the sorted list of slot numbers whose per-slot statusLine
/// was removed so the caller can surface a summary line. Unparseable
/// settings files are skipped silently: the parse-failure branch of
/// `patch_settings_json` already teaches the user how to recover, so
/// we don't repeat it per slot.
fn migrate_per_slot_statuslines(base_dir: &Path) -> Result<Vec<u16>> {
    let mut migrated: Vec<u16> = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return Ok(migrated), // base_dir doesn't exist yet — no slots
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(slot_str) = name_str.strip_prefix("config-") else {
            continue;
        };
        let Ok(slot) = slot_str.parse::<u16>() else {
            continue;
        };

        let settings_path = entry.path().join("settings.json");
        let content = match std::fs::read_to_string(&settings_path) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => continue,
        };
        let mut value: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(obj) = value.as_object_mut() else {
            continue;
        };

        let cmd_is_legacy = obj
            .get("statusLine")
            .and_then(|sl| sl.get("command"))
            .and_then(|c| c.as_str())
            .map(is_legacy_statusline_wrapper)
            .unwrap_or(false);
        if !cmd_is_legacy {
            continue;
        }

        obj.remove("statusLine");

        let json = serde_json::to_string_pretty(&value)?;
        let tmp = csq_core::platform::fs::unique_tmp_path(&settings_path);
        std::fs::write(&tmp, json.as_bytes())
            .with_context(|| format!("writing temp file {}", tmp.display()))?;
        csq_core::platform::fs::atomic_replace(&tmp, &settings_path)
            .map_err(|e| anyhow!("atomic replace: {e}"))?;

        migrated.push(slot);
    }

    migrated.sort();
    Ok(migrated)
}

/// Returns true when the `statusLine.command` string points at a
/// known v1.x shell wrapper that csq has since deprecated. User-
/// written commands that don't contain one of these tokens are left
/// alone.
fn is_legacy_statusline_wrapper(cmd: &str) -> bool {
    cmd.contains("statusline-quota.sh") || cmd.contains("statusline-command.sh")
}

fn cleanup_v1_artifacts(claude_home: &Path) -> Vec<String> {
    let mut cleaned = Vec::new();

    let accounts_dir = claude_home.join("accounts");

    // v1.x artifacts in ~/.claude/
    let claude_home_artifacts = ["statusline-command.sh", "rotate.md", "auto-rotate-hook.sh"];

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
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
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

    #[test]
    fn seed_keybindings_creates_when_missing() {
        let dir = TempDir::new().unwrap();
        let created = seed_keybindings_json(dir.path()).unwrap();
        assert!(created, "should return true when file was created");

        let path = dir.path().join("keybindings.json");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(v.get("bindings").is_some_and(|b| b.is_array()));
    }

    // ── migrate_per_slot_statuslines ─────────────────────────

    fn write_slot_settings(base: &Path, slot: u16, json: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    fn read_slot_settings(base: &Path, slot: u16) -> serde_json::Value {
        let path = base.join(format!("config-{slot}")).join("settings.json");
        let content = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[test]
    fn migrate_strips_legacy_wrapper_and_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(
            dir.path(),
            3,
            r#"{
                "statusLine": {"type":"command","command":"bash ~/.claude/accounts/statusline-quota.sh"},
                "permissions": {"read": true},
                "plugins": ["foo"],
                "effortLevel": "high"
            }"#,
        );

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();

        assert_eq!(migrated, vec![3]);
        let v = read_slot_settings(dir.path(), 3);
        assert!(v.get("statusLine").is_none(), "statusLine must be removed");
        assert_eq!(v["permissions"]["read"], true);
        assert_eq!(v["plugins"][0], "foo");
        assert_eq!(v["effortLevel"], "high");
    }

    #[test]
    fn migrate_leaves_csq_statusline_value_alone() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(
            dir.path(),
            2,
            r#"{"statusLine":{"type":"command","command":"csq statusline"}}"#,
        );

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();

        assert!(migrated.is_empty());
        let v = read_slot_settings(dir.path(), 2);
        assert_eq!(v["statusLine"]["command"], "csq statusline");
    }

    #[test]
    fn migrate_preserves_user_custom_statusline() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(
            dir.path(),
            5,
            r#"{"statusLine":{"type":"command","command":"my-custom-tool --slot 5"}}"#,
        );

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();

        assert!(
            migrated.is_empty(),
            "user custom commands must be preserved"
        );
        let v = read_slot_settings(dir.path(), 5);
        assert_eq!(v["statusLine"]["command"], "my-custom-tool --slot 5");
    }

    #[test]
    fn migrate_matches_statusline_command_sh_wrapper() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(
            dir.path(),
            4,
            r#"{"statusLine":{"type":"command","command":"bash ~/.claude/statusline-command.sh"}}"#,
        );

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();
        assert_eq!(migrated, vec![4]);
    }

    #[test]
    fn migrate_handles_many_slots_and_returns_sorted() {
        let dir = TempDir::new().unwrap();
        // Slots 1, 6, 10 have legacy; 2 has csq; 7 has no statusLine.
        let legacy = r#"{"statusLine":{"type":"command","command":"bash ~/.claude/accounts/statusline-quota.sh"}}"#;
        let csq = r#"{"statusLine":{"type":"command","command":"csq statusline"}}"#;
        let none = r#"{"permissions":{}}"#;
        write_slot_settings(dir.path(), 10, legacy);
        write_slot_settings(dir.path(), 1, legacy);
        write_slot_settings(dir.path(), 6, legacy);
        write_slot_settings(dir.path(), 2, csq);
        write_slot_settings(dir.path(), 7, none);

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();
        assert_eq!(migrated, vec![1, 6, 10]);
    }

    #[test]
    fn migrate_skips_unparseable_settings_files() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 1, "not valid json {{{");

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();
        assert!(migrated.is_empty());
        // File is untouched (still not-valid-json bytes).
        let raw = std::fs::read_to_string(dir.path().join("config-1/settings.json")).unwrap();
        assert_eq!(raw, "not valid json {{{");
    }

    #[test]
    fn migrate_skips_non_config_directories() {
        let dir = TempDir::new().unwrap();
        // A `term-1234` handle dir with a legacy-looking statusLine
        // should NOT be touched by the per-slot migration.
        let term_dir = dir.path().join("term-1234");
        std::fs::create_dir_all(&term_dir).unwrap();
        std::fs::write(
            term_dir.join("settings.json"),
            r#"{"statusLine":{"type":"command","command":"bash ~/.claude/accounts/statusline-quota.sh"}}"#,
        )
        .unwrap();

        let migrated = migrate_per_slot_statuslines(dir.path()).unwrap();
        assert!(migrated.is_empty());
        // term dir file still has the legacy statusLine.
        let content = std::fs::read_to_string(term_dir.join("settings.json")).unwrap();
        assert!(content.contains("statusline-quota.sh"));
    }

    #[test]
    fn migrate_no_base_dir_is_ok() {
        let dir = TempDir::new().unwrap();
        // Path does not exist at all.
        let migrated = migrate_per_slot_statuslines(&dir.path().join("nonexistent")).unwrap();
        assert!(migrated.is_empty());
    }

    #[test]
    fn is_legacy_wrapper_detection() {
        assert!(is_legacy_statusline_wrapper(
            "bash ~/.claude/accounts/statusline-quota.sh"
        ));
        assert!(is_legacy_statusline_wrapper("statusline-command.sh"));
        assert!(!is_legacy_statusline_wrapper("csq statusline"));
        assert!(!is_legacy_statusline_wrapper("my-custom-tool"));
        assert!(!is_legacy_statusline_wrapper(""));
    }

    #[test]
    fn seed_keybindings_preserves_existing_content() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keybindings.json");
        // Pretend the user already set up custom bindings.
        std::fs::write(
            &path,
            r#"{"bindings": [{"key": "ctrl+s", "command": "save"}]}"#,
        )
        .unwrap();

        let created = seed_keybindings_json(dir.path()).unwrap();
        assert!(!created, "should return false when file already exists");

        // Custom bindings must survive — we never overwrite.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("ctrl+s"));
        assert!(content.contains("save"));
    }
}
