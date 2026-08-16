//! `csq unlock N` — release a stuck login lock.
//!
//! A `csq login N` that hangs (e.g. Claude Code's OAuth browser callback
//! 404s and never completes) holds `.login-N.lock` for as long as its process
//! is alive. A live-but-hung holder is never auto-reclaimed (the flock only
//! releases when the holder *exits*), so every subsequent re-auth — CLI and
//! desktop — is blocked. This command shows what is holding the lock,
//! terminates the stuck login on confirmation, and clears the lock files so
//! the operator can retry.
//!
//! Companion to the `handle_direct` watchdog timeout (which prevents most
//! hangs at the source); this is the manual recovery affordance for a lock
//! that is already stuck.

use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use csq_core::accounts::login_lock;
use csq_core::cli_deps::sanitize::redact_home_prefix;
use csq_core::types::AccountNum;

pub fn handle(base_dir: &Path, account: AccountNum, yes: bool) -> Result<()> {
    let holder = login_lock::inspect_lock(base_dir, account)
        .map_err(|e| anyhow::anyhow!("failed to inspect login lock for slot {account}: {e}"))?;

    let Some(holder) = holder else {
        println!("No login lock is held for slot {account} — nothing to release.");
        return Ok(());
    };

    // Show the operator what is holding the lock so they can confirm it is
    // their own stuck login (and not, say, a live login they still want).
    match (holder.pid, holder.alive) {
        (Some(pid), Some(true)) => {
            println!("Slot {account} login lock is held by PID {pid} (running).");
            if let Some(cmd) = &holder.command {
                // Design-intent operator display: the holder's command line lets
                // the operator confirm it is a stuck `csq login`. Home prefix is
                // redacted so the full path is not disclosed on the terminal.
                println!("  command: {}", redact_home_prefix(cmd));
            }
        }
        (Some(pid), Some(false)) => {
            println!(
                "Slot {account} login lock names PID {pid}, which is no longer running \
                 (stale lock files)."
            );
        }
        _ => {
            println!(
                "Slot {account} login lock files are present but name no live holder \
                 (stale)."
            );
        }
    }

    let will_kill = matches!(holder.alive, Some(true));
    if !yes && !confirm(account, will_kill)? {
        println!("Aborted — the login lock was left in place.");
        return Ok(());
    }

    let report = login_lock::force_release(base_dir, account, will_kill)
        .map_err(|e| anyhow::anyhow!("failed to release login lock for slot {account}: {e}"))?;

    if let Some(pid) = report.killed_pid {
        println!("Terminated the stuck login (PID {pid}).");
    }
    if report.removed_files.is_empty() && !report.had_lock {
        println!("No login lock was held for slot {account}.");
    } else {
        println!(
            "Cleared the login lock for slot {account}. You can retry: `csq login {account}` \
             (or use the desktop app's Add Account flow)."
        );
    }
    Ok(())
}

/// Interactive confirmation. `will_kill` distinguishes "terminate a running
/// login" from "clear stale files" so the operator understands the action.
fn confirm(account: AccountNum, will_kill: bool) -> Result<bool> {
    if will_kill {
        eprint!("Terminate the login holding slot {account}'s lock and clear it? [y/N] ");
    } else {
        eprint!("Clear the stale login lock files for slot {account}? [y/N] ");
    }
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let answer = buf.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
