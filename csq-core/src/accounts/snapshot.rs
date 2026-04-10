//! Account snapshot — statusline-triggered identity check with PID caching.
//!
//! Called on every statusline render. Uses a cheap PID-alive check to
//! avoid expensive process tree walks on every render cycle.

use super::identity;
use super::markers;
use crate::platform::process::{find_cc_pid, is_pid_alive};
use crate::types::AccountNum;
use std::path::Path;
use tracing::debug;

/// Snapshots the current account for statusline rendering.
///
/// **Cheap path** (<1ms): if `.live-pid` exists and the process is alive,
/// returns the cached `.current-account` value without any process tree walk.
///
/// **Expensive path**: walks the process tree to find the CC PID, reads
/// `.csq-account`, and writes `.current-account` + `.live-pid` for future
/// cheap-path hits.
///
/// Returns None if the account cannot be determined.
pub fn snapshot_account(config_dir: &Path, base_dir: &Path) -> Option<AccountNum> {
    // Cheap path: check if cached PID is still alive
    if let Some(pid) = markers::read_live_pid(config_dir) {
        if is_pid_alive(pid) {
            // PID still alive — use cached account
            if let Some(account) = markers::read_current_account(config_dir) {
                return Some(account);
            }
        }
        debug!(pid, "cached PID is dead, re-snapshotting");
    }

    // Expensive path: determine account and cache
    let account = identity::which_account(config_dir, base_dir)?;

    // Cache the result: write .current-account
    if let Err(e) = markers::write_current_account(config_dir, account) {
        debug!(error = %e, "failed to write .current-account");
    }

    // Write CC PID for future cheap-path hits
    if let Ok(Some(cc_pid)) = find_cc_pid() {
        if let Err(e) = markers::write_live_pid(config_dir, cc_pid) {
            debug!(error = %e, "failed to write .live-pid");
        }
    }

    Some(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn snapshot_writes_markers() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-4");
        std::fs::create_dir_all(&config).unwrap();

        let result = snapshot_account(&config, dir.path());

        // Should resolve via dir name fallback
        assert_eq!(result, Some(AccountNum::try_from(4u16).unwrap()));

        // Should have written .current-account
        assert_eq!(
            markers::read_current_account(&config),
            Some(AccountNum::try_from(4u16).unwrap())
        );
    }

    #[test]
    fn snapshot_uses_cached_pid() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(2u16).unwrap();

        // Set up cached state: current account + live PID (own PID)
        markers::write_current_account(&config, account).unwrap();
        markers::write_live_pid(&config, std::process::id()).unwrap();

        // Should return cached account without re-snapshotting
        let result = snapshot_account(&config, dir.path());
        assert_eq!(result, Some(account));
    }

    #[test]
    fn snapshot_re_snapshots_when_pid_dead() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(6u16).unwrap();

        // Set up stale cached state with a dead PID
        markers::write_current_account(&config, account).unwrap();
        markers::write_live_pid(&config, 99_999_999).unwrap();

        // Should re-snapshot (dead PID triggers expensive path)
        let result = snapshot_account(&config, dir.path());
        assert_eq!(result, Some(account));
    }

    #[test]
    fn snapshot_returns_none_for_unknown_dir() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("unknown");
        std::fs::create_dir_all(&config).unwrap();

        assert_eq!(snapshot_account(&config, dir.path()), None);
    }
}
