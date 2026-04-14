//! `csq swap N` — swap the active account in the current terminal.
//!
//! In the handle-dir model, swap atomically repoints symlinks in the
//! `term-<pid>` handle directory. In legacy mode (`config-N` dir),
//! falls back to the old credential-copy approach with a warning.

use anyhow::{anyhow, Result};
use csq_core::rotation;
use csq_core::session::handle_dir;
use csq_core::types::AccountNum;
use std::path::Path;

pub fn handle(base_dir: &Path, target: AccountNum) -> Result<()> {
    let config_dir_str = std::env::var("CLAUDE_CONFIG_DIR").map_err(|_| {
        anyhow!("CLAUDE_CONFIG_DIR not set — this command must run inside a csq-managed session")
    })?;

    let config_dir = std::path::PathBuf::from(&config_dir_str);
    let dir_name = config_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if dir_name.starts_with("term-") {
        // Handle-dir model: repoint symlinks + re-materialize settings.json
        let claude_home = super::claude_home()?;
        handle_dir::repoint_handle_dir(base_dir, &claude_home, &config_dir, target)?;

        // Notify the daemon to clear its caches
        notify_daemon_cache_invalidation(base_dir);

        println!(
            "Swapped to account {} — CC will pick up on next API call",
            target
        );
    } else if dir_name.starts_with("config-") {
        // Legacy model: credential copy (with deprecation warning)
        eprintln!(
            "warning: running in legacy config-dir mode ({dir_name}). \
             Swap affects ALL terminals sharing this dir. \
             Relaunch with `csq run {target}` for per-terminal isolation."
        );

        let validated = super::validated_config_dir(base_dir)?;
        let result = rotation::swap_to(base_dir, &validated, target)?;

        let expires_in_min = (result.expires_at_ms / 1000).saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        ) / 60;

        notify_daemon_cache_invalidation(base_dir);

        println!(
            "Swapped to account {} — token valid {}m",
            result.account, expires_in_min
        );
    } else {
        return Err(anyhow!(
            "CLAUDE_CONFIG_DIR does not point to a csq-managed directory: {config_dir_str}"
        ));
    }

    Ok(())
}

/// Best-effort cache invalidation: POST /api/invalidate-cache to
/// the daemon if it's reachable.
#[cfg(unix)]
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    let sock = csq_core::daemon::socket_path(base_dir);
    if !sock.exists() {
        return;
    }
    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
}

#[cfg(not(unix))]
fn notify_daemon_cache_invalidation(_base_dir: &Path) {
    // Windows named-pipe invalidation is not yet implemented (M8-03).
}
