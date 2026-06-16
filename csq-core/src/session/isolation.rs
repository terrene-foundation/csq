//! Config directory isolation via symlinks (Unix) and junctions (Windows).
//!
//! Shared items (history, sessions, commands, skills, agents, rules) link
//! back to `~/.claude`. Isolated items (credentials, markers, settings)
//! are per-terminal copies.

use crate::error::CredentialError;
use std::path::Path;
use tracing::{debug, warn};

/// Items that are **shared** across all terminals — symlinked back to `~/.claude`.
///
/// This list must cover everything CC reads/writes under `CLAUDE_CONFIG_DIR`
/// that is NOT account-specific. Missing items here = broken features in
/// handle-dir terminals (e.g. missing `projects` = can't `--resume`).
pub const SHARED_ITEMS: &[&str] = &[
    // Conversation + session data
    "projects",
    "sessions",
    "history",
    "history.jsonl",
    // User customization
    "commands",
    "skills",
    "agents",
    "rules",
    "snippets",
    // Infrastructure
    "mcp",
    "plugins",
    "todos",
    "tasks",
    "plans",
    "teams",
    // CC internals that must be shared
    "statsig",
    "telemetry",
    "cache",
    "checkpoints",
    "ide",
    "chrome",
    "usage-data",
    "paste-cache",
    "shell-snapshots",
    "file-history",
    "downloads",
    "backups",
    "debug",
    "session-env",
    "keybindings.json",
    "settings.local.json",
    "settings-default.json",
    "__store.db",
    "stats-cache.json",
    "kailash-learning",
];

/// Items that are **isolated** per terminal — never linked, per-config copies.
/// Listed here for documentation; they are created/written by other modules.
///
/// `settings.json` is technically per-terminal but is neither symlinked nor
/// a per-config copy — it is **materialized** by `handle_dir::materialize_handle_settings`
/// as a deep-merge of `~/.claude/settings.json` (user global customization)
/// and `config-<N>/settings.json` (slot-specific overlay). See the doc on
/// that function for rationale.
pub const ISOLATED_ITEMS: &[&str] = &[
    ".credentials.json",
    ".current-account",
    ".csq-account",
    ".live-pid",
    ".claude.json",
    "accounts",
    "settings.json",
    ".quota-cursor",
];

/// Creates the `~/.claude/<item>` target when it's missing so the
/// subsequent symlink has something to point at. Shape-aware:
///
/// - file-shaped (`keybindings.json`, `history.jsonl`, `__store.db`,
///   `settings.local.json`, `settings-default.json`,
///   `stats-cache.json`) are seeded with content CC will accept
///   (`{"bindings": []}` for keybindings, `{}` for other JSON,
///   empty bytes for `.jsonl`/`.db`).
/// - dir-shaped (`projects`, `sessions`, `mcp`, etc.) get
///   `create_dir_all`.
///
/// Returns `Ok(false)` if the target already exists (no-op).
/// Returns `Ok(true)` after successfully creating the missing
/// target. Returns `Err` on filesystem failure — callers may
/// choose to `warn!` and continue, but MUST NOT proceed to
/// symlink a non-existent target shaped as a directory.
///
/// The pre-alpha.18 code always called `create_dir_all`, which
/// turned `~/.claude/keybindings.json` into a DIRECTORY the first
/// time `csq run` ran on a fresh install. CC then failed to parse
/// the directory as JSON and logged a keybinding-error on every
/// launch.
pub fn ensure_shared_target(target: &Path, item: &str) -> Result<bool, std::io::Error> {
    if target.exists() {
        return Ok(false);
    }

    if let Some(default_bytes) = default_content_for(item) {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, default_bytes)?;
    } else {
        std::fs::create_dir_all(target)?;
    }
    Ok(true)
}

/// Returns the default byte content for a file-shaped shared item,
/// or `None` when the item is directory-shaped. Used by
/// [`ensure_shared_target`] to pre-create missing targets with
/// content CC can parse.
fn default_content_for(item: &str) -> Option<&'static [u8]> {
    match item {
        "keybindings.json" => Some(b"{\n  \"bindings\": []\n}\n"),
        "settings.local.json" | "settings-default.json" | "stats-cache.json" => Some(b"{}\n"),
        "history.jsonl" => Some(b""),
        "__store.db" => Some(b""),
        _ => None,
    }
}

/// Creates or updates the isolated config directory.
///
/// For each entry in [`SHARED_ITEMS`]:
/// - If `~/.claude/<item>` exists, ensure `config_dir/<item>` is a symlink to it
/// - If the config dir already has a regular file/dir where a symlink should be, it is preserved
/// - If `~/.claude/<item>` doesn't exist yet, it's created as an empty directory
///
/// Returns the list of items successfully linked.
pub fn isolate_config_dir(
    home_claude: &Path,
    config_dir: &Path,
) -> Result<Vec<String>, CredentialError> {
    std::fs::create_dir_all(config_dir).map_err(|e| CredentialError::Io {
        path: config_dir.to_path_buf(),
        source: e,
    })?;

    let mut linked = Vec::new();

    for item in SHARED_ITEMS {
        let target = home_claude.join(item);
        let link = config_dir.join(item);

        // Shape-aware seed: `.json`/`.jsonl`/`.db` items become
        // files with parseable default content; other names get
        // `create_dir_all`. See `ensure_shared_target` for the bug
        // this replaces (pre-alpha.18 created keybindings.json as
        // a directory, breaking CC every launch).
        if let Err(e) = ensure_shared_target(&target, item) {
            warn!(path = %target.display(), error = %e, "failed to create shared target");
            continue;
        }

        match ensure_symlink(&target, &link) {
            Ok(()) => {
                linked.push(item.to_string());
                debug!(item = %item, "linked shared item");
            }
            Err(e) => {
                warn!(item = %item, error = %e, "failed to link shared item");
            }
        }
    }

    Ok(linked)
}

/// Ensures `link` is a symlink pointing to `target`.
///
/// - If `link` doesn't exist: creates a new symlink
/// - If `link` is already a symlink to `target`: no-op
/// - If `link` is a symlink to something else: removes and recreates
/// - If `link` is a regular file/dir: preserves it (does not overwrite)
fn ensure_symlink(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    if link.exists() || link.symlink_metadata().is_ok() {
        if let Ok(meta) = link.symlink_metadata() {
            if meta.file_type().is_symlink() {
                // Check if it points to our target
                if let Ok(current) = std::fs::read_link(link) {
                    if current == target {
                        return Ok(()); // Already correct
                    }
                }
                // Symlink to wrong target — remove and recreate
                std::fs::remove_file(link)?;
            } else {
                // Real file/dir — preserve it, don't clobber user data
                debug!(
                    path = %link.display(),
                    "preserving existing non-symlink entry"
                );
                return Ok(());
            }
        }
    }

    create_symlink(target, link)
}

/// Creates a symlink. On Unix uses `symlink`, on Windows uses a directory junction
/// (via `mklink /J`) for directories, falling back to copy for files.
///
/// Public alias for use by `handle_dir` module.
pub fn create_symlink_pub(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    create_symlink(target, link)
}

fn create_symlink(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        create_symlink_windows(target, link)
    }
}

#[cfg(windows)]
fn create_symlink_windows(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    // Try directory junction first (no admin required)
    if target.is_dir() {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output();

        match status {
            Ok(output) if output.status.success() => return Ok(()),
            _ => {
                warn!("mklink /J failed, falling back to copy");
            }
        }

        // Fallback: copy the directory
        copy_dir_recursive(target, link)?;
        return Ok(());
    }

    // Files: try hardlink, fall back to copy
    match std::fs::hard_link(target, link) {
        Ok(()) => Ok(()),
        Err(_) => std::fs::copy(target, link).map(|_| ()),
    }
}

#[cfg(windows)]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Removes the stale `.live-pid` file if present.
///
/// Called when setting up a new session — the previous session's PID
/// is no longer valid.
pub fn remove_stale_pid(config_dir: &Path) {
    let pid_path = config_dir.join(".live-pid");
    if pid_path.exists() {
        let _ = std::fs::remove_file(&pid_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn isolate_creates_shared_links() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-1");

        // Pre-create one target
        std::fs::create_dir_all(home.join("commands")).unwrap();

        let linked = isolate_config_dir(&home, &config).unwrap();
        assert!(!linked.is_empty());

        // commands should be a symlink
        let commands_link = config.join("commands");
        assert!(commands_link.exists());
        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(&commands_link).unwrap();
            assert!(meta.file_type().is_symlink());
        }
    }

    #[test]
    fn isolate_creates_missing_targets() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-2");

        // home/.claude doesn't exist yet
        let linked = isolate_config_dir(&home, &config).unwrap();
        assert!(!linked.is_empty());

        // All targets should now exist
        for item in SHARED_ITEMS {
            assert!(home.join(item).exists(), "target {item} should exist");
        }
    }

    // ── file-vs-dir regression suite for ensure_shared_target ──────────
    //
    // Pre-alpha.18, the loop always called create_dir_all on the target,
    // turning `~/.claude/keybindings.json` into a DIRECTORY on first run.
    // CC then logged a parse error on every launch. These tests pin the
    // correct shape for every file-named SHARED_ITEMS entry and verify
    // the default content is parseable.

    #[test]
    fn ensure_shared_target_creates_keybindings_as_json_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("keybindings.json");

        let created = ensure_shared_target(&target, "keybindings.json").unwrap();
        assert!(created, "first call should create the target");

        let meta = std::fs::metadata(&target).unwrap();
        assert!(
            meta.is_file(),
            "keybindings.json MUST be a file, not a directory — CC parses it as JSON"
        );
        let content = std::fs::read_to_string(&target).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("seeded keybindings.json must be valid JSON");
        assert!(parsed.get("bindings").is_some_and(|b| b.is_array()));
    }

    #[test]
    fn ensure_shared_target_creates_other_json_files_as_empty_object() {
        let dir = TempDir::new().unwrap();
        for name in [
            "settings.local.json",
            "settings-default.json",
            "stats-cache.json",
        ] {
            let target = dir.path().join(name);
            ensure_shared_target(&target, name).unwrap();
            let meta = std::fs::metadata(&target).unwrap();
            assert!(meta.is_file(), "{name} must be a file");
            let content = std::fs::read_to_string(&target).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("{name} must be valid JSON: {content:?}"));
            assert!(parsed.is_object(), "{name} must be a JSON object");
        }
    }

    #[test]
    fn ensure_shared_target_creates_jsonl_as_empty_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("history.jsonl");
        ensure_shared_target(&target, "history.jsonl").unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        assert!(meta.is_file(), "history.jsonl must be a file");
        assert_eq!(meta.len(), 0, "jsonl seed should be an empty file");
    }

    #[test]
    fn ensure_shared_target_creates_store_db_as_empty_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("__store.db");
        ensure_shared_target(&target, "__store.db").unwrap();
        assert!(std::fs::metadata(&target).unwrap().is_file());
    }

    #[test]
    fn ensure_shared_target_creates_dir_items_as_directories() {
        let dir = TempDir::new().unwrap();
        for name in ["projects", "sessions", "mcp", "plugins", "commands"] {
            let target = dir.path().join(name);
            ensure_shared_target(&target, name).unwrap();
            assert!(
                std::fs::metadata(&target).unwrap().is_dir(),
                "{name} must be a directory"
            );
        }
    }

    #[test]
    fn ensure_shared_target_is_noop_when_target_exists() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("keybindings.json");
        // Pre-seed with custom content — MUST NOT be overwritten.
        std::fs::write(&target, r#"{"bindings":[{"key":"cmd+s"}]}"#).unwrap();

        let created = ensure_shared_target(&target, "keybindings.json").unwrap();
        assert!(!created, "existing target → returns false, no overwrite");

        let content = std::fs::read_to_string(&target).unwrap();
        assert!(
            content.contains("cmd+s"),
            "user custom bindings must survive"
        );
    }

    #[test]
    fn isolate_seeds_keybindings_as_file_not_directory() {
        // The exact bug user reported: on a fresh install running
        // `csq run N` once, `~/.claude/keybindings.json` ends up as
        // a DIRECTORY and CC logs `keybinding error` on every launch.
        // Post-fix it must be a FILE containing valid JSON.
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-1");

        isolate_config_dir(&home, &config).unwrap();

        let path = home.join("keybindings.json");
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            meta.is_file(),
            "regression: ~/.claude/keybindings.json must be a FILE"
        );
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.get("bindings").is_some());
    }

    #[test]
    fn isolate_seeds_all_file_items_as_files() {
        // Gate test: EVERY file-named SHARED_ITEMS entry must end up
        // as a file. Any new file-named item added to the list will
        // fail here until default_content_for is extended.
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-1");

        isolate_config_dir(&home, &config).unwrap();

        for item in SHARED_ITEMS {
            let path = home.join(item);
            if !path.exists() {
                continue;
            }
            let meta = std::fs::metadata(&path).unwrap();
            // File-shaped items end in one of these suffixes.
            let is_file_shape =
                item.ends_with(".json") || item.ends_with(".jsonl") || item.ends_with(".db");
            if is_file_shape {
                assert!(
                    meta.is_file(),
                    "shared item {item} should be a FILE (not a directory)"
                );
            } else {
                assert!(meta.is_dir(), "shared item {item} should be a DIRECTORY");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn isolate_preserves_existing_non_symlink() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-3");

        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(home.join("commands")).unwrap();

        // Pre-create a real directory (not symlink) in config
        std::fs::create_dir_all(config.join("commands")).unwrap();
        std::fs::write(config.join("commands/user-data.txt"), b"important").unwrap();

        isolate_config_dir(&home, &config).unwrap();

        // User data preserved
        assert!(config.join("commands/user-data.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn isolate_replaces_stale_symlink() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join(".claude");
        let config = dir.path().join("config-4");
        let old_target = dir.path().join("old-target");

        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&old_target).unwrap();
        std::fs::create_dir_all(home.join("commands")).unwrap();

        // Create symlink pointing to old target
        std::os::unix::fs::symlink(&old_target, config.join("commands")).unwrap();

        isolate_config_dir(&home, &config).unwrap();

        // Symlink should now point to the new target
        let link_target = std::fs::read_link(config.join("commands")).unwrap();
        assert_eq!(link_target, home.join("commands"));
    }

    #[test]
    fn remove_stale_pid_removes_file() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let pid_path = config.join(".live-pid");
        std::fs::write(&pid_path, "12345").unwrap();
        assert!(pid_path.exists());

        remove_stale_pid(&config);
        assert!(!pid_path.exists());
    }

    #[test]
    fn remove_stale_pid_no_error_if_missing() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        remove_stale_pid(&config); // Should not panic
    }
}
