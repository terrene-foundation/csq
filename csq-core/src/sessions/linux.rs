//! Linux backend for live CC session discovery.
//!
//! Walks `/proc/*` for processes owned by the current UID and reads:
//!
//! - `/proc/<pid>/comm` for the executable name (must be `claude`).
//! - `/proc/<pid>/environ` for the NUL-separated env (must contain
//!   `CLAUDE_CONFIG_DIR`).
//! - `/proc/<pid>/cwd` via `readlink` for the working directory.
//! - `/proc/<pid>/stat` field 22 (`starttime`) for the start-time
//!   in clock ticks since boot, converted to Unix seconds via
//!   `/proc/stat` btime + clk_tck (we approximate with a simpler
//!   elapsed-seconds-via-`/proc/uptime` calculation).
//!
//! All file reads are best-effort — a process that exits between
//! enumeration and inspection is silently skipped.

use super::{parse_term_session_id, SessionInfo};
use std::fs;
use std::path::PathBuf;

/// Returns the list of live CC sessions for the current user.
pub fn list() -> Vec<SessionInfo> {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(info) = read_process(pid) {
            out.push(info);
        }
    }
    out
}

/// Reads one `/proc/<pid>/` entry into a `SessionInfo`, or returns
/// `None` if the process is not a CC session or cannot be read.
fn read_process(pid: u32) -> Option<SessionInfo> {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));

    // Filter: comm must be `claude`.
    let comm = fs::read_to_string(proc_dir.join("comm")).ok()?;
    if comm.trim() != "claude" {
        return None;
    }

    // Filter: env must contain CLAUDE_CONFIG_DIR.
    let environ = fs::read(proc_dir.join("environ")).ok()?;
    let config_dir = parse_environ(&environ, "CLAUDE_CONFIG_DIR")?;
    let config_dir = PathBuf::from(config_dir);
    let account_id = SessionInfo::extract_account_id(&config_dir);

    let cwd = fs::read_link(proc_dir.join("cwd"))
        .ok()
        .unwrap_or_else(|| PathBuf::from(""));

    let started_at = read_start_time(&proc_dir);

    // Terminal identity env vars — populated by iTerm2 clones like
    // WezTerm, by iTerm2 itself when run on Linux (rare but real),
    // or empty for plain `xterm`. Linux users with tmux get
    // TMUX instead — not parsed here.
    let term_session_id = parse_environ(&environ, "TERM_SESSION_ID");
    let (term_window, term_tab, term_pane) = term_session_id
        .as_deref()
        .map(parse_term_session_id)
        .unwrap_or((None, None, None));
    let iterm_profile = parse_environ(&environ, "ITERM_PROFILE");

    // Controlling TTY — field 7 of /proc/<pid>/stat is `tty_nr`
    // (a packed major/minor device number). Rather than decode it,
    // read the /proc/<pid>/fd/0 symlink which resolves to the
    // controlling terminal's device path (e.g. `/dev/pts/3`).
    let tty = fs::read_link(proc_dir.join("fd/0"))
        .ok()
        .and_then(|p| {
            p.to_str()
                .map(|s| s.trim_start_matches("/dev/").to_string())
        })
        .filter(|s| !s.is_empty() && !s.contains("null") && !s.contains("socket"));

    Some(SessionInfo {
        pid,
        cwd,
        config_dir,
        account_id,
        started_at,
        tty,
        term_window,
        term_tab,
        term_pane,
        iterm_profile,
        terminal_title: None, // osascript is macOS-only; no Linux equivalent yet
    })
}

/// Parses a NUL-separated `KEY=VALUE\0KEY=VALUE\0...` blob for a
/// specific key and returns the value as an owned `String`.
fn parse_environ(blob: &[u8], key: &str) -> Option<String> {
    let needle = format!("{key}=");
    for entry in blob.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(entry).ok()?;
        if let Some(v) = s.strip_prefix(&needle) {
            return Some(v.to_string());
        }
    }
    None
}

/// Reads the Unix-seconds start time of a process from its
/// `/proc/<pid>/stat` file, cross-referenced with `/proc/stat`
/// `btime` and `sysconf(_SC_CLK_TCK)`.
///
/// Returns `None` on any parse failure — the session row still
/// renders without a start time if this fails.
fn read_start_time(proc_dir: &std::path::Path) -> Option<u64> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    // Field 22 is starttime in clock ticks since boot.
    // But there's a gotcha: field 2 (comm) is in parens and may
    // contain spaces or close-parens. Find the LAST `)` and split
    // from there.
    let close = stat.rfind(')')?;
    let after_comm = stat[close + 1..].trim();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After field 2, fields are 1-indexed in this slice: index 0 is
    // field 3, ..., index 19 is field 22 (starttime).
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;

    let clk_tck = 100u64; // Nearly universal on Linux. Avoids libc dep.
    let starttime_secs = starttime_ticks / clk_tck;

    // /proc/stat has a line `btime <unix_seconds>` giving system
    // boot time.
    let system_stat = fs::read_to_string("/proc/stat").ok()?;
    let mut btime: Option<u64> = None;
    for line in system_stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            btime = rest.trim().parse().ok();
            break;
        }
    }
    let btime = btime?;
    Some(btime + starttime_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_environ_finds_key() {
        let blob = b"PATH=/bin\0USER=alice\0CLAUDE_CONFIG_DIR=/x/config-3\0HOME=/h\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/x/config-3".to_string())
        );
    }

    #[test]
    fn parse_environ_handles_missing_key() {
        let blob = b"PATH=/bin\0USER=alice\0";
        assert_eq!(parse_environ(blob, "CLAUDE_CONFIG_DIR"), None);
    }

    #[test]
    fn parse_environ_avoids_substring_match() {
        let blob = b"FAKE_CLAUDE_CONFIG_DIR=wrong\0CLAUDE_CONFIG_DIR=/right\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/right".to_string())
        );
    }

    #[test]
    fn parse_environ_tolerates_trailing_nul() {
        let blob = b"USER=alice\0";
        assert_eq!(parse_environ(blob, "USER"), Some("alice".to_string()));
    }

    #[test]
    fn parse_environ_tolerates_empty_entries() {
        // Some kernels leave extra NULs at the end of /proc/environ.
        let blob = b"\0\0USER=alice\0\0CLAUDE_CONFIG_DIR=/x/config-1\0\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/x/config-1".to_string())
        );
    }
}
