//! `csq swap N` — swap the active account in the current config directory.

use anyhow::Result;
use csq_core::rotation;
use csq_core::types::AccountNum;
use std::path::Path;

pub fn handle(base_dir: &Path, target: AccountNum) -> Result<()> {
    let config_dir = super::validated_config_dir(base_dir)?;

    let result = rotation::swap_to(base_dir, &config_dir, target)?;

    let expires_in_min = (result.expires_at_ms / 1000).saturating_sub(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    ) / 60;

    // Notify the daemon to clear its caches so that /api/accounts
    // and /api/refresh-status reflect the new active account
    // immediately. Silent on failure — the daemon may not be running.
    notify_daemon_cache_invalidation(base_dir);

    println!(
        "Swapped to account {} — token valid {}m",
        result.account, expires_in_min
    );
    Ok(())
}

/// Best-effort cache invalidation: POST /api/invalidate-cache to
/// the daemon if it's reachable. Failures are silently ignored
/// because the swap itself has already succeeded and the cache will
/// expire naturally within 5 seconds anyway.
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
