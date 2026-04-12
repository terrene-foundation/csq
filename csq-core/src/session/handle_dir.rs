//! Handle-dir model: ephemeral `term-<pid>` directories with symlinks to `config-N`.
//!
//! Each `csq run` creates a `term-<pid>` handle directory that contains symlinks
//! pointing at the permanent `config-<N>` account directory. `csq swap` atomically
//! repoints these symlinks. The daemon sweeps orphaned handle dirs when the PID dies.
//!
//! See `specs/02-csq-handle-dir-model.md` for the authoritative spec.

use crate::accounts::markers;
use crate::error::CredentialError;
use crate::session::isolation::{self, SHARED_ITEMS};
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Items in the handle dir that are symlinks to `config-N/<item>`.
/// These get repointed on swap.
///
/// `.claude.json` is intentionally EXCLUDED — CC writes per-project state
/// (the `projects` map) into it, and symlinking to config-N's copy leaks
/// project history from every directory that account was ever used in.
/// This causes `--resume` to show sessions from all projects instead of
/// filtering to the current CWD. Letting CC create a fresh `.claude.json`
/// per handle dir restores correct project-scoped behavior.
const ACCOUNT_BOUND_ITEMS: &[&str] = &[
    ".credentials.json",
    ".csq-account",
    ".current-account",
    "settings.json",
    ".quota-cursor",
];

/// Creates an ephemeral handle directory `term-<pid>` under `base_dir`.
///
/// Populates it with:
/// - Symlinks to `config-<account>/<item>` for each account-bound item
/// - Symlinks to `~/.claude/<item>` for each shared item
/// - A `.live-pid` file with the csq CLI PID
///
/// Returns the absolute path to the created handle directory.
///
/// # Errors
///
/// - If `config-<account>` doesn't exist
/// - If the handle dir already exists (PID collision from prior crash —
///   caller should sweep first)
/// - On any I/O failure
pub fn create_handle_dir(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    pid: u32,
) -> Result<PathBuf, CredentialError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!("config-{account} does not exist"),
        });
    }

    let handle_dir = base_dir.join(format!("term-{}", pid));

    // Detect orphan from prior crash with same PID.
    //
    // SAFETY: Before removing, read `.live-pid` and verify the recorded
    // PID is dead. Without this check, PID recycling could make us wipe
    // out a live terminal's handle dir. We only remove dirs whose PID
    // is definitely dead OR whose `.live-pid` is missing/unreadable
    // (corrupt orphan from our own earlier crash).
    if handle_dir.exists() {
        let live_pid_path = handle_dir.join(".live-pid");
        let recorded_pid: Option<u32> = std::fs::read_to_string(&live_pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok());

        if let Some(recorded) = recorded_pid {
            if is_pid_alive(recorded) {
                return Err(CredentialError::Corrupt {
                    path: handle_dir.clone(),
                    reason: format!(
                        "handle dir term-{pid} is in use by live PID {recorded}. \
                         Refusing to remove. If you believe this is stale, stop \
                         the process and rerun."
                    ),
                });
            }
        }

        warn!(
            pid,
            recorded = ?recorded_pid,
            "handle dir already exists with dead or missing PID — removing orphan"
        );
        std::fs::remove_dir_all(&handle_dir).map_err(|e| CredentialError::Io {
            path: handle_dir.clone(),
            source: e,
        })?;
    }

    // Use create_dir (not create_dir_all) to detect collisions
    std::fs::create_dir(&handle_dir).map_err(|e| CredentialError::Io {
        path: handle_dir.clone(),
        source: e,
    })?;

    // Symlink account-bound items to config-N
    for item in ACCOUNT_BOUND_ITEMS {
        let target = config_dir.join(item);
        let link = handle_dir.join(item);
        // Only create symlink if the target exists in config-N
        if target.exists() || target.symlink_metadata().is_ok() {
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked account-bound item");
        }
    }

    // Symlink shared items to ~/.claude
    for item in SHARED_ITEMS {
        let target = claude_home.join(item);
        let link = handle_dir.join(item);

        // Ensure target exists (create empty dir if missing)
        if !target.exists() {
            std::fs::create_dir_all(&target).ok();
        }

        if target.exists() {
            // Use ensure_symlink logic: skip if non-symlink exists
            if link.symlink_metadata().is_ok() {
                continue; // shouldn't happen in a fresh dir, but be safe
            }
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked shared item");
        }
    }

    // Copy .claude.json from config-N, scoping `projects` to CWD.
    copy_claude_json_stripped(&config_dir, &handle_dir);

    // Write .live-pid with the csq CLI PID
    markers::write_live_pid(&handle_dir, pid)?;

    info!(pid, account = %account, path = %handle_dir.display(), "handle dir created");
    Ok(handle_dir)
}

/// Atomically repoints the account-bound symlinks in a handle dir
/// to point at a new `config-<target>` directory.
///
/// Uses rename-over (NOT delete + create) for atomicity.
///
/// # Errors
///
/// - If the handle dir is not a `term-<pid>` dir (refuses legacy `config-N`)
/// - If `config-<target>` doesn't exist
/// - On any I/O failure during repoint
pub fn repoint_handle_dir(
    base_dir: &Path,
    handle_dir: &Path,
    target: AccountNum,
) -> Result<(), CredentialError> {
    // Verify this is a handle dir, not a config dir
    let dir_name = handle_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if !dir_name.starts_with("term-") {
        return Err(CredentialError::Corrupt {
            path: handle_dir.to_path_buf(),
            reason: format!(
                "expected term-<pid> handle dir, got {dir_name}. \
                 Run `csq run {target}` to launch with handle-dir isolation."
            ),
        });
    }

    let new_config = base_dir.join(format!("config-{}", target));
    if !new_config.is_dir() {
        return Err(CredentialError::Corrupt {
            path: new_config,
            reason: format!("config-{target} does not exist"),
        });
    }

    // Atomic repoint: create temp symlink then rename over existing
    for item in ACCOUNT_BOUND_ITEMS {
        let new_target = new_config.join(item);
        let link_path = handle_dir.join(item);
        let tmp_path = handle_dir.join(format!("{item}.swap-tmp"));

        // Only repoint if the target exists in the new config dir
        if !new_target.exists() && new_target.symlink_metadata().is_err() {
            // Remove the old symlink if the new config doesn't have this item
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
            continue;
        }

        // Create new symlink at temp path
        if tmp_path.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        create_symlink(&new_target, &tmp_path).map_err(|e| CredentialError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;

        // Atomic rename over existing symlink
        std::fs::rename(&tmp_path, &link_path).map_err(|e| CredentialError::Io {
            path: link_path.clone(),
            source: e,
        })?;

        debug!(item, account = %target, "repointed symlink");
    }

    info!(account = %target, handle = %handle_dir.display(), "handle dir repointed");
    Ok(())
}

/// Copies `.claude.json` from `config_dir` into `handle_dir`, scoping
/// the `projects` map to only the current working directory.
///
/// CC uses `projects` in `.claude.json` to track per-project settings
/// AND to enumerate resumable sessions. If we copy the full map, `--resume`
/// shows sessions from every directory this account was ever used in.
/// If we strip it entirely, CC thinks there are no projects and `/resume`
/// says "No conversations found". The fix: keep only entries whose key
/// matches the current CWD or is a subdirectory of it.
///
/// This works together with `scope_projects_to_cwd` — `.claude.json`
/// tells CC which projects exist, `projects/` provides the session data.
fn copy_claude_json_stripped(config_dir: &Path, handle_dir: &Path) {
    let src = config_dir.join(".claude.json");
    let dst = handle_dir.join(".claude.json");

    let content = match std::fs::read_to_string(&src) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Scope the `projects` map to the current CWD and its subdirs.
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy().to_string();
        if let Some(obj) = json.as_object_mut() {
            if let Some(projects) = obj.get("projects").cloned() {
                if let Some(proj_map) = projects.as_object() {
                    let mut scoped = serde_json::Map::new();
                    for (key, val) in proj_map {
                        if key == &cwd_str || key.starts_with(&format!("{cwd_str}/")) {
                            scoped.insert(key.clone(), val.clone());
                        }
                    }
                    obj.insert("projects".to_string(), serde_json::Value::Object(scoped));
                }
            }
        }
    }

    if let Ok(out) = serde_json::to_string_pretty(&json) {
        let _ = std::fs::write(&dst, out);
        debug!("copied .claude.json (scoped projects to CWD)");
    }
}

/// Sweeps orphaned `term-*` handle directories under `base_dir`.
///
/// A handle dir is orphaned when its PID is no longer alive.
/// This function is idempotent — safe to call repeatedly.
///
/// Returns the number of directories removed.
pub fn sweep_dead_handles(base_dir: &Path) -> usize {
    let mut removed = 0;

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("term-") {
            continue;
        }

        let pid: u32 = match name.strip_prefix("term-").and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        if is_pid_alive(pid) {
            continue;
        }

        let path = entry.path();
        info!(pid, path = %path.display(), "sweeping orphaned handle dir");
        if let Err(e) = std::fs::remove_dir_all(&path) {
            warn!(pid, error = %e, "failed to remove orphaned handle dir");
        } else {
            removed += 1;
        }
    }

    if removed > 0 {
        info!(removed, "handle dir sweep complete");
    }
    removed
}

/// Checks if the handle dir at `CLAUDE_CONFIG_DIR` is a `term-<pid>` dir.
/// Returns the resolved path if it is, or an error string if it's a legacy `config-N`.
pub fn resolve_handle_dir_from_env(base_dir: &Path) -> Result<PathBuf, String> {
    let raw = std::env::var("CLAUDE_CONFIG_DIR")
        .map_err(|_| "CLAUDE_CONFIG_DIR not set — run inside a csq-managed session".to_string())?;

    let config_dir = PathBuf::from(&raw);
    let dir_name = config_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if dir_name.starts_with("config-") {
        return Err(format!(
            "This terminal is using the legacy config-dir model ({dir_name}). \
             Swap affects ALL terminals sharing this config dir. \
             Relaunch with `csq run N` for per-terminal handle-dir isolation."
        ));
    }

    if !dir_name.starts_with("term-") {
        return Err(format!(
            "CLAUDE_CONFIG_DIR does not point to a csq handle dir: {raw}"
        ));
    }

    // Verify it's under base_dir
    let canon_base = base_dir
        .canonicalize()
        .map_err(|e| format!("bad base: {e}"))?;
    let canon_dir = config_dir
        .canonicalize()
        .map_err(|e| format!("bad config dir: {e}"))?;

    if !canon_dir.starts_with(&canon_base) {
        return Err(format!(
            "CLAUDE_CONFIG_DIR escapes base directory: {}",
            canon_dir.display()
        ));
    }

    Ok(canon_dir)
}

/// Cross-platform PID liveness check.
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) succeeds if the process exists AND we have permission.
        // ESRCH (3) = no such process. EPERM (1) = exists but different user.
        unsafe {
            let ret = libc::kill(pid as i32, 0);
            if ret == 0 {
                return true;
            }
            // EPERM means the process exists but we can't signal it
            *libc::__error() != libc::ESRCH
        }
    }

    #[cfg(windows)]
    {
        use std::ptr;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() || handle == ptr::null_mut() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Sweep interval: 60 seconds.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Handle to a running sweep task.
pub struct SweepHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns a periodic handle-dir sweep task.
///
/// Scans `base_dir/term-*/` every 60 seconds and removes orphans
/// whose PID is no longer alive. Shares a cancellation token with
/// the daemon so it stops on shutdown.
pub fn spawn_sweep(
    base_dir: PathBuf,
    shutdown: tokio_util::sync::CancellationToken,
) -> SweepHandle {
    let join = tokio::spawn(async move {
        // Small startup delay to avoid racing with session creation
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }

        loop {
            let dir = base_dir.clone();
            let _ = tokio::task::spawn_blocking(move || sweep_dead_handles(&dir)).await;

            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("handle-dir sweep cancelled, exiting");
                    return;
                }
                _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    });

    SweepHandle { join }
}

/// Platform-specific symlink creation.
fn create_symlink(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    isolation::create_symlink_pub(target, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_config_dir(base: &Path, account: u16) -> PathBuf {
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        // Write minimal credential marker
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        std::fs::write(config.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config.join("settings.json"), "{}").unwrap();
        std::fs::write(config.join(".claude.json"), "{}").unwrap();
        config
    }

    #[test]
    fn create_handle_dir_populates_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 99999).unwrap();

        assert!(handle.exists());
        assert_eq!(handle.file_name().unwrap().to_str().unwrap(), "term-99999");

        // Account-bound symlinks should exist
        #[cfg(unix)]
        {
            let cred_link = handle.join(".credentials.json");
            assert!(cred_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            let target = std::fs::read_link(&cred_link).unwrap();
            assert!(target.ends_with("config-1/.credentials.json"));
        }

        // .live-pid should contain PID
        assert_eq!(markers::read_live_pid(&handle), Some(99999));
    }

    #[test]
    fn repoint_handle_dir_changes_targets() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 88888).unwrap();

        // Repoint to account 2
        repoint_handle_dir(base, &handle, account2).unwrap();

        #[cfg(unix)]
        {
            let target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
            assert!(target.ends_with("config-2/.credentials.json"));
            let target = std::fs::read_link(handle.join(".csq-account")).unwrap();
            assert!(target.ends_with("config-2/.csq-account"));
        }
    }

    #[test]
    fn repoint_refuses_legacy_config_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let result = repoint_handle_dir(base, &config, AccountNum::try_from(2u16).unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("term-"), "error should mention term-: {err}");
    }

    #[test]
    fn sweep_removes_dead_handles() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Create a handle dir with PID 1 (init, always alive on Unix)
        // and one with a definitely-dead PID
        let alive = base.join("term-1");
        std::fs::create_dir_all(&alive).unwrap();
        std::fs::write(alive.join(".live-pid"), "1").unwrap();

        let dead = base.join("term-999999999");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        let removed = sweep_dead_handles(base);

        assert!(!dead.exists(), "dead handle dir should be removed");
        // PID 1 (init) should still be alive on unix, so term-1 stays
        #[cfg(unix)]
        assert!(alive.exists(), "live handle dir should remain");

        assert!(removed >= 1);
    }

    #[test]
    fn sweep_ignores_config_dirs() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let removed = sweep_dead_handles(base);
        assert_eq!(removed, 0);
        assert!(config.exists(), "config dirs must not be swept");
    }
}
