//! Config directory isolation via symlinks (Unix) and junctions (Windows).
//!
//! Shared items (history, sessions, commands, skills, agents, rules) link
//! back to `~/.claude`. Isolated items (credentials, markers, settings)
//! are per-terminal copies.

use crate::error::CredentialError;
use std::path::Path;
use tracing::{debug, warn};

/// Items that are **shared** across all terminals — symlinked back to `~/.claude`.
pub const SHARED_ITEMS: &[&str] = &[
    "history", "sessions", "commands", "skills", "agents", "rules", "mcp", "plugins", "snippets",
    "todos",
];

/// Items that are **isolated** per terminal — never linked, per-config copies.
/// Listed here for documentation; they are created/written by other modules.
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

        // Ensure target exists (create empty dir if missing)
        if !target.exists() {
            if let Err(e) = std::fs::create_dir_all(&target) {
                warn!(path = %target.display(), error = %e, "failed to create shared target");
                continue;
            }
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
