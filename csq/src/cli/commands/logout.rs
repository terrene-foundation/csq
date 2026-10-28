//! `csq logout N` — remove all on-disk state for an account.
//!
//! Wraps [`csq_core::accounts::logout::logout_account`] with user-
//! facing prompting, daemon cache invalidation, and clear messaging
//! for each failure mode. Refuses to delete state from under a live
//! `claude` process — the user must exit those terminals first.

use anyhow::{anyhow, Result};
use csq_core::accounts::logout::{logout_account, LogoutError, LogoutSummary};
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
            for line in success_lines(&summary) {
                println!("{line}");
            }

            notify_daemon_cache_invalidation(base_dir);
            Ok(())
        }
        Err(LogoutError::InUse {
            account: a,
            pids,
            unreadable_dirs,
        }) => Err(in_use_error(a, &pids, &unreadable_dirs)),
        Err(LogoutError::NotConfigured { account: a }) => {
            println!("Account {a} is not configured — nothing to remove.");
            Ok(())
        }
        Err(e) => Err(anyhow!("logout failed: {e}")),
    }
}

/// The operator-visible result of a successful logout, one line per element.
///
/// The second line exists because a logout can SUCCEED while its identity
/// credential folder stays on disk: `logout_account` refuses to delete
/// `identities/<UUID>/` without that identity's credential lock, and reports
/// the deferred cleanup on `LogoutSummary::identity_dir_pending_removal`.
/// Saying so plainly is the difference between a documented, retried cleanup
/// and a silent credential left at rest after a logout the user believes
/// completed. No paths (only the account number), matching the rest of this
/// command's output (`security.md` MUST-2).
fn success_lines(summary: &LogoutSummary) -> Vec<String> {
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
    let mut lines = vec![format!(
        "Logged out account {}: removed {what}.",
        summary.account
    )];
    if summary.identity_dir_pending_removal {
        lines.push(format!(
            "Account {}: the local credential folder was NOT removed (its credential lock \
             was busy or the delete failed). The account is already tombstoned, so no \
             running process can write to it; the next cleanup pass will remove it.",
            summary.account
        ));
    }
    // R3 sec M-D / corr L-3: an unconfirmed keychain clear whose retry could
    // not be queued is NOT "queued for automatic retry". Say the item may
    // survive instead of reporting a clean logout.
    if summary.keychain_retry_queue_failed {
        lines.push(format!(
            "Account {}: a keychain item could not be confirmed cleared, and the automatic \
             retry could NOT be queued (the retry spool is full or unwritable). The item \
             may still exist in the login keychain.",
            summary.account
        ));
    }
    lines
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

/// The `csq logout` refusal for an account still bound to a live or unreadable handle dir.
fn in_use_error(account: AccountNum, pids: &[u32], unreadable_dirs: &[String]) -> anyhow::Error {
    anyhow!(csq_core::accounts::logout::in_use_message(
        account,
        pids,
        unreadable_dirs
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_logout_unreadable_marker_names_the_dir_not_a_session() {
        let a = AccountNum::try_from(7u16).unwrap();
        let msg = in_use_error(a, &[], &["term-1234".to_string()]).to_string();
        assert_eq!(
            msg,
            "account 7: handle dir term-1234 has a pid marker that cannot be read; inspect it and remove it if stale, then retry"
        );
        assert!(!msg.contains("process"), "{msg}");
    }

    #[test]
    fn cli_logout_live_pid_still_says_exit_terminals() {
        let a = AccountNum::try_from(7u16).unwrap();
        let msg = in_use_error(a, &[42], &[]).to_string();
        assert!(
            msg.contains("[42]") && msg.contains("exit those terminals"),
            "{msg}"
        );
    }

    /// D237 round 2, ROOT ruling D(2): when `logout_account` refused the
    /// identity-dir delete because its credential lock was busy, the CLI must
    /// say plainly that the local credential folder was NOT removed and that
    /// the next cleanup pass removes it — never print only the removed parts.
    ///
    /// Non-vacuity: dropping the `identity_dir_pending_removal` branch from
    /// `success_lines` reds the two-line assertion below by assertion.
    #[test]
    fn cli_logout_states_a_deferred_credential_folder_removal() {
        let account = AccountNum::try_from(7u16).unwrap();
        let mut summary = LogoutSummary {
            account,
            canonical_removed: true,
            config_dir_removed: true,
            profiles_entry_removed: true,
            quota_entry_removed: false,
            identity_dir_removed: false,
            identity_dir_pending_removal: true,
            native_home_removed: false,
            gemini_vault_cleared: false,
            keychain_cleared: false,
            keychain_retry_queue_failed: false,
        };

        let lines = success_lines(&summary);
        assert_eq!(
            lines.len(),
            2,
            "deferred cleanup needs its own line: {lines:?}"
        );
        assert!(
            lines[1].contains("credential folder was NOT removed"),
            "the notice must state the credential folder was not removed: {lines:?}"
        );
        assert!(
            lines[1].contains("next cleanup pass will remove it"),
            "the notice must name the cleanup that removes it: {lines:?}"
        );
        assert!(
            !lines[1].contains('/') && !lines[1].contains('\\'),
            "the notice must carry no path: {lines:?}"
        );

        summary.identity_dir_pending_removal = false;
        let lines = success_lines(&summary);
        assert_eq!(
            lines.len(),
            1,
            "a completed delete must not claim a deferred cleanup: {lines:?}"
        );
    }

    /// R3 sec M-D / corr L-3: when an unconfirmed keychain clear could not be
    /// queued for retry, the operator MUST be told the item may survive —
    /// never a clean "Logged out ... removed" line with the loss only in a
    /// log. `keychain_retry_queue_failed` is the wire that carries it.
    ///
    /// RED mutation: drop the `keychain_retry_queue_failed` branch from
    /// `success_lines` — the two-line assertion below fails by assertion.
    #[test]
    fn cli_logout_states_a_keychain_retry_that_was_not_queued() {
        let account = AccountNum::try_from(9u16).unwrap();
        let summary = LogoutSummary {
            account,
            canonical_removed: true,
            config_dir_removed: true,
            profiles_entry_removed: true,
            quota_entry_removed: false,
            identity_dir_removed: true,
            identity_dir_pending_removal: false,
            native_home_removed: false,
            gemini_vault_cleared: false,
            keychain_cleared: false,
            keychain_retry_queue_failed: true,
        };

        let lines = success_lines(&summary);
        assert_eq!(
            lines.len(),
            2,
            "an unqueued keychain retry needs its own line: {lines:?}"
        );
        assert!(
            lines[1].contains("could NOT be queued"),
            "the notice must state the retry was not queued: {lines:?}"
        );
        assert!(
            lines[1].contains("may still exist"),
            "the notice must state the item may survive: {lines:?}"
        );
        assert!(
            !lines[1].contains('/') && !lines[1].contains('\\'),
            "the notice must carry no path: {lines:?}"
        );
    }
}
