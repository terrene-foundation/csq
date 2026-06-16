//! Live Claude Code session discovery.
//!
//! Enumerates running `claude` processes under the current UID and
//! extracts, per process:
//!
//! 1. `CLAUDE_CONFIG_DIR` from the environment — this tells us
//!    which `~/.claude/accounts/config-N/` the session is bound to.
//! 2. The process `cwd` — which working directory the user started
//!    the session in (how they recognize "terminal #5").
//! 3. Start time — how long ago the session launched.
//!
//! From `CLAUDE_CONFIG_DIR` the caller can cross-reference the
//! dir's current active account, quota state, and credentials.
//!
//! ### Why this exists
//!
//! The tray quick-swap heuristic targets "the most recently modified
//! config-N", which works most of the time but is invisible: users
//! can't see which terminal is bound to which `config-N` until they
//! run `lsof` by hand. When a user has 8 accounts across 15 terminal
//! windows and terminal #5 hits a rate limit, they need:
//!
//! - to know *that it was terminal #5*, and
//! - to swap **only that terminal's** config dir to a fresh account
//!   without disturbing the other 14.
//!
//! This module provides the data. The desktop sessions view renders
//! it; the Tauri `swap_to_dir` command does the targeted swap.
//!
//! ### Platform strategy
//!
//! - **macOS** — `ps -E -o pid=,command=` dumps the environ inline
//!   for processes owned by the current UID. We parse the line,
//!   peel the command, and walk the remaining `KEY=VALUE` pairs.
//!   `lsof -a -p <pid> -d cwd -Fn` gives the cwd (can't rely on
//!   `ps -o cwd=` because macOS omits it).
//! - **Linux** — `/proc/<pid>/environ` is NUL-separated and readable
//!   by the process owner without root. `readlink /proc/<pid>/cwd`
//!   gives the cwd. `/proc/<pid>/stat` gives the start time.
//! - **Windows** — stub: returns an empty vector. Reading another
//!   process's environ on Windows requires
//!   `NtQueryInformationProcess` + `PEB` walking which needs unsafe
//!   code and careful version gating. Deferred once macOS/Linux are
//!   validated on real Windows targets.
//!
//! ### Privacy
//!
//! We filter to processes owned by the **current UID**. `ps -E`
//! already enforces this on macOS for non-root callers; on Linux
//! `/proc/<pid>/environ` returns EACCES on cross-UID reads.
//!
//! ### Filtering
//!
//! A process is a "CC session" iff:
//! 1. Its command's first token (argv\[0\] basename) is `claude`.
//! 2. Its environment contains `CLAUDE_CONFIG_DIR`.
//!
//! The command filter drops child processes that inherit
//! `CLAUDE_CONFIG_DIR` from their parent (pyright-langserver,
//! node MCP servers, etc.) — we only want one row per top-level
//! `claude` process.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single discovered live Claude Code session.
///
/// All fields are derived from OS process state; none are read
/// from the csq credential store or quota file. Callers that want
/// quota/account data should cross-reference `config_dir` via
/// `accounts::discovery` + `quota::state`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    /// OS process ID.
    pub pid: u32,
    /// Working directory at process creation (read once; not live).
    pub cwd: PathBuf,
    /// Value of `CLAUDE_CONFIG_DIR` in the process's environment.
    pub config_dir: PathBuf,
    /// Account number extracted from `config_dir` (`config-<N>`).
    /// `None` if the dir doesn't match the expected shape.
    pub account_id: Option<u16>,
    /// Unix seconds since epoch when the process started. `None`
    /// if the platform couldn't report it.
    pub started_at: Option<u64>,
    /// Controlling TTY device, e.g. `"ttys003"`. `None` if the
    /// process is not attached to a terminal (unlikely for a
    /// top-level `claude` invocation but defended for safety).
    pub tty: Option<String>,
    /// Parsed iTerm2 window index from `TERM_SESSION_ID`.
    /// `TERM_SESSION_ID=w3t2p0:UUID` yields `term_window=3`,
    /// `term_tab=2`, `term_pane=0`. `None` outside iTerm2.
    pub term_window: Option<u8>,
    /// Parsed iTerm2 tab index. See `term_window`.
    pub term_tab: Option<u8>,
    /// Parsed iTerm2 pane index. See `term_window`.
    pub term_pane: Option<u8>,
    /// iTerm2 profile name from `ITERM_PROFILE` env var.
    /// Useful when the user has multiple named profiles
    /// (e.g. "Work", "Personal", "Terrene").
    pub iterm_profile: Option<String>,
    /// Human-readable terminal tab title resolved via
    /// `osascript` against iTerm2 (macOS only, best-effort).
    /// `None` outside iTerm2 or when the osascript query fails.
    pub terminal_title: Option<String>,
}

impl SessionInfo {
    /// Derives the account number from a `config-N` directory name.
    /// Returns `None` for any other shape.
    pub(crate) fn extract_account_id(config_dir: &std::path::Path) -> Option<u16> {
        let name = config_dir.file_name()?.to_str()?;
        let num_str = name.strip_prefix("config-")?;
        let num: u16 = num_str.parse().ok()?;
        if (1..=999).contains(&num) {
            Some(num)
        } else {
            None
        }
    }
}

/// Parses `TERM_SESSION_ID` (iTerm2 format) into `(window, tab, pane)`.
///
/// The format is `w<N>t<M>p<K>:<uuid>` where each of N, M, K is a
/// 1-3 digit integer. Anything else returns `None, None, None`.
///
/// Example: `"w3t2p0:3B8385EC-9D2C-4E26-A416-2E04BCA60DA3"` →
/// `(Some(3), Some(2), Some(0))`.
pub(crate) fn parse_term_session_id(raw: &str) -> (Option<u8>, Option<u8>, Option<u8>) {
    let prefix = match raw.split(':').next() {
        Some(p) => p,
        None => return (None, None, None),
    };
    // Walk the prefix character by character: `w` then digits, `t`
    // then digits, `p` then digits. Anything unexpected bails out.
    let mut chars = prefix.chars().peekable();
    let take_num = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| -> Option<u8> {
        let mut digits = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                chars.next();
            } else {
                break;
            }
        }
        digits.parse().ok()
    };

    if chars.next() != Some('w') {
        return (None, None, None);
    }
    let window = take_num(&mut chars);
    if chars.next() != Some('t') {
        return (window, None, None);
    }
    let tab = take_num(&mut chars);
    if chars.next() != Some('p') {
        return (window, tab, None);
    }
    let pane = take_num(&mut chars);
    (window, tab, pane)
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::list as list_impl;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::list as list_impl;

// The pure Windows env-block parser compiles everywhere so its
// unit tests run on macOS/Linux CI. The `windows.rs` syscall
// wrapper that feeds this parser is Windows-only because it
// depends on `windows-sys` FFI types.
//
// `#[allow(dead_code)]` on non-Windows targets because the
// functions are only called from the syscall wrapper, which is
// cfg-gated out. Their tests still exercise them on every
// platform, which is the whole point of splitting them out.
#[cfg(target_os = "windows")]
mod windows;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod windows_parse;
#[cfg(target_os = "windows")]
pub use windows::list as list_impl;

/// Discover live CC sessions for the current user.
///
/// Silently skips processes whose env or cwd cannot be read — most
/// such failures mean the process has exited between enumeration
/// and per-process inspection. A completely broken platform
/// backend returns an empty vector, never panics.
pub fn list() -> Vec<SessionInfo> {
    list_impl()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extract_account_id_valid() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("/a/b/config-5")),
            Some(5)
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-999")),
            Some(999)
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-1")),
            Some(1)
        );
    }

    #[test]
    fn extract_account_id_rejects_out_of_range() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-0")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-1000")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-99999")),
            None
        );
    }

    #[test]
    fn extract_account_id_rejects_bad_shape() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-abc")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("other-5")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("/a/b/")),
            None
        );
    }

    #[test]
    fn list_does_not_panic() {
        // Smoke test — the important invariant is that `list()`
        // never panics on a live system, even when the platform
        // backend encounters unexpected state (permission errors,
        // short-lived child processes, missing /proc entries).
        let _ = list();
    }

    // ── parse_term_session_id ──────────────────────────────

    #[test]
    fn parse_term_session_id_full_iterm_format() {
        let (w, t, p) = parse_term_session_id("w3t2p0:3B8385EC-9D2C-4E26-A416-2E04BCA60DA3");
        assert_eq!(w, Some(3));
        assert_eq!(t, Some(2));
        assert_eq!(p, Some(0));
    }

    #[test]
    fn parse_term_session_id_multi_digit_indices() {
        // Users with 10+ tabs are a thing.
        let (w, t, p) = parse_term_session_id("w12t45p3:abc");
        assert_eq!(w, Some(12));
        assert_eq!(t, Some(45));
        assert_eq!(p, Some(3));
    }

    #[test]
    fn parse_term_session_id_missing_prefix_returns_none() {
        assert_eq!(
            parse_term_session_id("not-iterm-format"),
            (None, None, None)
        );
        assert_eq!(parse_term_session_id(""), (None, None, None));
    }

    #[test]
    fn parse_term_session_id_partial_prefix() {
        // Window only — still useful, return what we have.
        let (w, t, p) = parse_term_session_id("w3:abc");
        assert_eq!(w, Some(3));
        assert_eq!(t, None);
        assert_eq!(p, None);
    }

    #[test]
    fn parse_term_session_id_no_uuid_part() {
        // Valid prefix but no colon/uuid — still parses the prefix.
        let (w, t, p) = parse_term_session_id("w1t1p0");
        assert_eq!(w, Some(1));
        assert_eq!(t, Some(1));
        assert_eq!(p, Some(0));
    }

    #[test]
    fn parse_term_session_id_rejects_huge_numbers() {
        // u8 overflow — takes what fits and stops.
        let (w, _, _) = parse_term_session_id("w99999t1p1:abc");
        assert_eq!(w, None); // 99999 > u8::MAX
    }
}
