//! `csq move FROM TO` — change a slot's number.
//!
//! Wraps [`csq_core::accounts::move_slot::move_account`] with user-
//! facing prompting, daemon cache invalidation, and clear messaging
//! for each failure mode. Phase 3 (M3-6) removed the live-process
//! refusal; handle dirs symlink to `identities/<UUID>/` so credential
//! reads survive the slot rename. The renderer prints an informational
//! line when live processes were bound at move time.
//!
//! # Phase 2 (M2-4) daemon notification
//!
//! After a successful move, two IPC notifications are fired (fire-and-forget):
//!
//! 1. `POST /api/invalidate-cache` — clears the full cache (already present
//!    from Phase 1, retained for backward-compat with older daemon versions).
//! 2. `POST /api/slot-swap {"from": N, "to": M}` — targeted per-slot
//!    invalidation: the daemon drops refresh-status cache entries for both
//!    slot numbers (SEC-2.11). Both calls use the Unix socket and silently
//!    no-op if the daemon is not running.

use anyhow::{anyhow, Result};
use csq_core::accounts::move_slot::{move_account, MoveError};
use csq_core::types::AccountNum;
use std::io::{self, Write};
use std::path::Path;

pub fn handle(base_dir: &Path, from: AccountNum, to: AccountNum, yes: bool) -> Result<()> {
    if from == to {
        return Err(anyhow!("FROM and TO are the same slot"));
    }

    if !yes && !confirm(from, to)? {
        println!("Aborted.");
        return Ok(());
    }

    match move_account(base_dir, from, to) {
        Ok(summary) => {
            let mut parts = Vec::new();
            if summary.config_dir_moved {
                parts.push("config dir".to_string());
            }
            for surface in &summary.canonical_creds_moved {
                parts.push(format!("{} canonical credentials", surface));
            }
            if summary.profiles_entry_moved {
                parts.push("profiles entry".to_string());
            }
            if summary.quota_entry_moved {
                parts.push("quota entry".to_string());
            }
            let what = if parts.is_empty() {
                "nothing".to_string()
            } else {
                parts.join(", ")
            };
            println!("Moved slot {from} → {to}: renamed {what}.");

            if let Some(line) = format_live_pid_info_line(from, &summary.live_pids_bound) {
                println!("{line}");
            }

            notify_daemon_cache_invalidation(base_dir);
            notify_daemon_slot_swap(base_dir, from, to);
            Ok(())
        }
        Err(MoveError::SameSlot) => Err(anyhow!("FROM and TO are the same slot")),
        Err(MoveError::NotConfigured { from: f }) => {
            println!("Slot {f} is not configured — nothing to move.");
            Ok(())
        }
        Err(MoveError::TargetExists { to: t }) => Err(anyhow!(
            "target slot {t} is already configured — `csq logout {t}` first or pick another target"
        )),
        Err(e) => Err(anyhow!("move failed: {e}")),
    }
}

fn confirm(from: AccountNum, to: AccountNum) -> Result<bool> {
    eprint!(
        "Move account from slot {from} to slot {to}? Renames config dir, credentials, profile + quota entries. [y/N] "
    );
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Formats the Phase 3 (M3-6) "moved while N processes were bound" notice.
///
/// Returns `Some(line)` when at least one live process was bound to the
/// source slot at move time; `None` otherwise. Pulled out as a pure helper
/// so the renderer's behavior is unit-testable without `println!` capture.
pub(crate) fn format_live_pid_info_line(from: AccountNum, live_pids: &[u32]) -> Option<String> {
    if live_pids.is_empty() {
        return None;
    }
    Some(format!(
        "Note: moved while {} process(es) were bound to slot {} (PIDs {:?}) \
         — they will swap targets on next API call.",
        live_pids.len(),
        from,
        live_pids
    ))
}

fn notify_daemon_cache_invalidation(base_dir: &Path) {
    #[cfg(unix)]
    {
        let sock = csq_core::daemon::socket_path(base_dir);
        if sock.exists() {
            let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
        }
    }
    #[cfg(not(unix))]
    let _ = base_dir;
}

/// Fire-and-forget targeted per-slot cache invalidation (SEC-2.11).
///
/// Routes through `csq_core::daemon::notify_slot_swap` — the single
/// production chokepoint shared with the desktop `move_account` Tauri
/// command. Do NOT inline the body-building here.
fn notify_daemon_slot_swap(base_dir: &Path, from: AccountNum, to: AccountNum) {
    #[cfg(unix)]
    {
        let sock = csq_core::daemon::socket_path(base_dir);
        let _ = csq_core::daemon::notify_slot_swap(&sock, from.get(), to.get());
    }
    #[cfg(not(unix))]
    {
        let _ = (base_dir, from, to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M3-6 AC-7: when the move summary's `live_pids_bound` is non-empty,
    /// the renderer emits the informational notice. When empty, no notice.
    #[test]
    fn cli_move_renderer_prints_live_pid_info_line_when_summary_nonempty() {
        let from = AccountNum::try_from(3u16).unwrap();

        // Non-empty → returns a notice naming the slot, the count, and each PID.
        let line = format_live_pid_info_line(from, &[1234, 5678])
            .expect("non-empty live_pids must produce a notice line");
        assert!(line.contains("2 process(es)"), "line: {line}");
        assert!(line.contains("slot 3"), "line: {line}");
        assert!(line.contains("1234"), "line: {line}");
        assert!(line.contains("5678"), "line: {line}");
        assert!(
            line.contains("swap targets on next API call"),
            "line must explain user impact; got: {line}"
        );

        // Empty → no notice at all (None, so the renderer skips the println!).
        assert!(
            format_live_pid_info_line(from, &[]).is_none(),
            "empty live_pids must produce no notice"
        );
    }
}
