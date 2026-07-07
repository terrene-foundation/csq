//! `csq keychain-sync` — refresh the macOS keychain entries Claude Code reads.
//!
//! Current Claude Code reads each session's OAuth credential from a
//! per-config-dir keychain item (`Claude Code-credentials-{hash}`), NOT from
//! the `.credentials.json` file csq symlinks into the handle dir. csq refreshes
//! the file (and identity store) but historically never wrote the keychain, so
//! after a daemon token rotation the keychain copy goes stale and CC returns
//! 401 on every session. This command mirrors every live handle dir's CURRENT
//! on-disk credential into its keychain item. CC re-checks the keychain ~every
//! 30s, so active sessions recover without a restart.
//!
//! `csq run` / `csq swap` already sync the handle dir they touch, and the daemon
//! refresher sweeps automatically on each token rotation; this command is the
//! manual sweep for sessions that rotated mid-run before the daemon's next
//! refresh tick, or when the daemon is not running.

use anyhow::Result;
use std::path::Path;

/// Sync every `term-*` handle dir under `base_dir` (the accounts dir). Handle
/// dirs with no mirrorable Anthropic OAuth credential (3P / Codex / dangling /
/// expired / already-current-in-keychain) are skipped. Delegates to the shared
/// `keychain::sync_all_handle_dirs` (the same sweep the daemon runs post-refresh)
/// so the command and the daemon stay byte-identical in behavior.
pub fn handle(base_dir: &Path) -> Result<()> {
    let (synced, skipped, failed) = csq_core::credentials::keychain::sync_all_handle_dirs(base_dir);
    println!("keychain-sync: synced={synced} skipped={skipped} failed={failed}");
    if synced > 0 {
        println!("Claude Code re-checks the keychain ~every 30s; active sessions recover shortly.");
    }
    if failed > 0 {
        anyhow::bail!("{failed} handle dir(s) failed to sync");
    }
    Ok(())
}
