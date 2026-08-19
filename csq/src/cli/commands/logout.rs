//! `csq logout N` — remove all on-disk state for an account.
//!
//! Wraps [`csq_core::accounts::logout::logout_account`] with user-
//! facing prompting, daemon cache invalidation, and clear messaging
//! for each failure mode. Refuses to delete state from under a live
//! `claude` process — the user must exit those terminals first.

use anyhow::{anyhow, Result};
use csq_core::accounts::logout::{logout_account, LogoutError};
use csq_core::types::AccountNum;
use std::io::{self, Write};
use std::path::Path;

pub fn handle(base_dir: &Path, account: AccountNum, yes: bool) -> Result<()> {
    if !yes && !confirm(account)? {
        println!("Aborted.");
        return Ok(());
    }

    match logout_account(base_dir, account) {
        Ok(summary) => {
            let mut parts = Vec::new();
            if summary.canonical_removed {
                parts.push("canonical credential");
            }
            if summary.config_dir_removed {
                parts.push("config dir");
            }
            if summary.profiles_entry_removed {
                parts.push("profiles entry");
            }
            if summary.gemini_vault_cleared {
                parts.push("gemini vault entry");
            }
            if summary.keychain_cleared {
                parts.push("keychain item");
            }
            let what = if parts.is_empty() {
                "nothing (already empty)".to_string()
            } else {
                parts.join(", ")
            };
            println!("Logged out account {account}: removed {what}.");

            notify_daemon_cache_invalidation(base_dir);
            Ok(())
        }
        Err(LogoutError::InUse {
            account: a, pids, ..
        }) => Err(anyhow!(
            "account {a} is in use by live process(es) {pids:?} — exit those terminals first, then retry"
        )),
        Err(LogoutError::NotConfigured { account: a }) => {
            println!("Account {a} is not configured — nothing to remove.");
            Ok(())
        }
        Err(e) => Err(anyhow!("logout failed: {e}")),
    }
}

fn confirm(account: AccountNum) -> Result<bool> {
    eprint!(
        "Remove all credentials, config-{account}/ directory, and profiles entry for account {account}? [y/N] "
    );
    io::stderr().flush().ok();

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let answer = buf.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Best-effort cache invalidation: notify the daemon (Unix socket or
/// Windows named pipe) that on-disk account state changed. Routes through
/// the single cross-platform chokepoint — see `csq_core::daemon::notify`
/// (an internal ticket).
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    csq_core::daemon::notify::cache_invalidation(base_dir);
}
