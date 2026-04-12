//! macOS backend for live CC session discovery.
//!
//! Uses `ps -E -o pid=,command=` to get one line per process owned
//! by the current UID, with the environment appended to `command`.
//! `ps -E` dumps all env vars after the argv joined by spaces,
//! which means the real command and the env are separated only by
//! whitespace — we split on the first `<space>KEY=` token where
//! `KEY` looks like an env-var name to find the boundary.
//!
//! For the cwd we shell out to `lsof -a -p <pid> -d cwd -Fn` which
//! returns a single-line `nPATH` record, more reliable than
//! `ps -o cwd=` (which macOS omits for non-Console sessions).

use super::{parse_term_session_id, SessionInfo};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Returns the list of live CC sessions for the current user.
pub fn list() -> Vec<SessionInfo> {
    let output = match Command::new("ps")
        .args(["-E", "-o", "pid=,command="])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output);

    // Resolve iTerm2 window + session titles keyed by TTY. Uses a
    // 10s cache so consecutive polls don't each pay the osascript
    // cost. Empty map when iTerm isn't running — the title column
    // falls through to window/tab indices or TTY.
    let titles = read_iterm_titles_by_tty();

    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(mut info) = parse_ps_line(line) {
            if let Some(ref tty) = info.tty {
                if let Some((window_name, session_name)) = titles.get(tty) {
                    info.terminal_title = Some(format_terminal_title(window_name, session_name));
                }
            }
            out.push(info);
        }
    }
    out
}

/// Combines iTerm's window name and session name into a single
/// display string. Examples:
///
/// - `("✳ terrene", "✳ arbor (claude)")` → `"terrene · arbor"`
/// - `("✳ Claude Code", "✳ Claude Code (claude)")` → `"Claude Code"`
///   (collapsed — when window and session are the same, show once)
/// - `("", "✳ arbor (claude)")` → `"arbor"`
/// - `("✳ terrene", "")` → `"terrene"`
///
/// iTerm prefixes titles with status icons like `✳` (active) or
/// `⠂` (idle) and appends the current command in parens like
/// `(claude)`. Both are stripped so the display stays clean.
pub(crate) fn format_terminal_title(window_name: &str, session_name: &str) -> String {
    let w = strip_iterm_decorations(window_name);
    let s = strip_iterm_decorations(session_name);
    match (w.is_empty(), s.is_empty()) {
        (true, true) => String::new(),
        (false, true) => w,
        (true, false) => s,
        (false, false) if w == s => w,
        (false, false) => format!("{w} · {s}"),
    }
}

/// Strips iTerm2's status-icon prefix (`✳ `, `⠂ `, similar) and the
/// trailing `(command)` annotation from a title string. Returns
/// the whitespace-trimmed core.
fn strip_iterm_decorations(raw: &str) -> String {
    // Leading status icon: a non-ASCII char followed by a space.
    // iTerm uses `✳` (U+2733) for active and `⠂` (U+2802 braille)
    // for idle. We match by "not ASCII letter/digit" as the first
    // char, then one space.
    let mut s = raw.trim();
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        if !first.is_ascii_alphanumeric() {
            // Check that the next char is a space.
            if chars.next() == Some(' ') {
                s = &s[first.len_utf8() + 1..];
            }
        }
    }
    // Trailing `(foo)` annotation — drop it entirely.
    if let Some(paren_idx) = s.rfind(" (") {
        if s.ends_with(')') {
            s = &s[..paren_idx];
        }
    }
    s.trim().to_string()
}

/// Parses a single `pid command ENV=...` line.
///
/// Returns `None` for any line that isn't a CC session: non-`claude`
/// commands, processes without `CLAUDE_CONFIG_DIR`, malformed lines.
fn parse_ps_line(line: &str) -> Option<SessionInfo> {
    let trimmed = line.trim_start();
    // First whitespace-delimited field is the PID.
    let mut split = trimmed.splitn(2, char::is_whitespace);
    let pid: u32 = split.next()?.parse().ok()?;
    let rest = split.next()?.trim_start();

    // The "command" field from `ps -E` contains:
    //   argv[0] argv[1] ... argv[N] KEY1=VAL1 KEY2=VAL2 ...
    // with no delimiter between argv and env. Split on the first
    // ` KEY=` token where KEY matches `[A-Z_][A-Z0-9_]*`.
    let (command, env_str) = split_command_and_env(rest);

    // Filter: first token of command must be `claude` (basename).
    let argv0 = command.split_whitespace().next()?;
    let basename = std::path::Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    if basename != "claude" {
        return None;
    }

    // Parse env for CLAUDE_CONFIG_DIR.
    let config_dir = parse_env_var(env_str, "CLAUDE_CONFIG_DIR")?;
    let config_dir = PathBuf::from(config_dir);
    let account_id = SessionInfo::extract_account_id(&config_dir);

    // Terminal identity env vars — iTerm sets these unconditionally.
    let term_session_id = parse_env_var(env_str, "TERM_SESSION_ID");
    let (term_window, term_tab, term_pane) = term_session_id
        .map(parse_term_session_id)
        .unwrap_or((None, None, None));
    let iterm_profile = parse_env_var(env_str, "ITERM_PROFILE").map(|s| s.to_string());

    // cwd via `lsof -a -p <pid> -d cwd -Fn`.
    let cwd = read_cwd_via_lsof(pid).unwrap_or_else(|| PathBuf::from(""));

    // Start time via `ps -o etimes=` for the same PID.
    let started_at = read_start_time(pid);

    // Controlling TTY via `ps -o tty=`. Normalized to the basename
    // (`ttys003`) so osascript lookups against iTerm's `tty of
    // session` (which returns `/dev/ttys003`) can join cleanly.
    let tty = read_tty(pid).map(|t| {
        t.trim_start_matches("/dev/")
            .trim_start_matches('/')
            .to_string()
    });

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
        terminal_title: None, // filled in by caller after osascript
    })
}

/// Reads the controlling TTY for a process via `ps -o tty=`.
///
/// Returns `None` if the process is detached (TTY = `"??"`) or
/// the ps call fails.
fn read_tty(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "tty="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() || s == "??" {
        None
    } else {
        Some(s)
    }
}

/// How long a cached osascript result stays fresh.
///
/// `list_sessions` polls every 5s from the desktop app, so a 10s
/// TTL means osascript runs at most every other poll — one
/// subprocess call per ~10s instead of every 5s. Tab titles and
/// window names update within that window on the next poll; that's
/// fast enough for a UX where the user changes tabs and glances
/// at the dashboard.
///
/// Design question 2 from journal 0026: decided to cache instead
/// of calling per-poll because `osascript` is ~120ms and doing it
/// at every list tick burns CPU for stale data.
const ITERM_CACHE_TTL: Duration = Duration::from_secs(10);

/// A resolved `{tty → (window_name, session_name)}` tuple from
/// the last osascript walk. The outer Option is None on first
/// call, Some afterwards.
type IntermediateCache = (HashMap<String, (String, String)>, Instant);
static ITERM_CACHE: OnceLock<Mutex<Option<IntermediateCache>>> = OnceLock::new();

fn iterm_cache() -> &'static Mutex<Option<IntermediateCache>> {
    ITERM_CACHE.get_or_init(|| Mutex::new(None))
}

/// Queries iTerm2 via AppleScript for `{TTY → (window_name,
/// session_name)}` tuples.
///
/// Returns the window title (stable per iTerm window) **and** the
/// session title (changes per-tab, often derived from the running
/// command). The caller combines them as `"window · session"` for
/// display so users see e.g. `"terrene · arbor"`.
///
/// This is a best-effort lookup. If iTerm2 isn't running, the
/// user denied automation permission, or AppleScript fails, we
/// return an empty map and the sessions view falls through to the
/// env-based tags (`Window N • Tab M`, TTY, etc.).
///
/// ### iTerm2 AppleScript gotchas
///
/// - `tabs` do NOT have a `name` property directly — querying it
///   returns `Can't get name of item 1 of every tab (-1728)`. You
///   must walk into `sessions of tab` and read `name of session`.
/// - `windows` DO have a `name` property — that's the title you
///   set in iTerm preferences (or iTerm derives from the active
///   tab). That's what the user means by "window name".
///
/// ### Cache
///
/// Each call returns a clone of the cached result if it's under
/// [`ITERM_CACHE_TTL`] old, otherwise re-runs the osascript and
/// refreshes the cache. Thread-safe via a mutex; the osascript
/// invocation happens inside the lock so concurrent callers
/// coalesce on a single subprocess.
fn read_iterm_titles_by_tty() -> HashMap<String, (String, String)> {
    // Serve from cache if fresh.
    {
        let guard = iterm_cache().lock().expect("iterm cache lock poisoned");
        if let Some((map, when)) = guard.as_ref() {
            if when.elapsed() < ITERM_CACHE_TTL {
                return map.clone();
            }
        }
    }

    // Cache miss — query iTerm2. Note: NO `pgrep` short-circuit
    // because iTerm2 doesn't run as a process literally named
    // `iTerm2` (the actual binary name varies by install path),
    // so `pgrep -x iTerm2` finds nothing even when iTerm is
    // running. We rely on osascript failing fast (~70ms) when
    // iTerm isn't running.
    //
    // Tabs don't have a `name` property in iTerm's AppleScript
    // dictionary — querying it errors with `-1728`. We read
    // `name of session` (tab title) instead, and `name of w`
    // for the window title.
    const SCRIPT: &str = r#"
        set out to ""
        try
            tell application "iTerm2"
                repeat with w in windows
                    set winName to name of w
                    repeat with t in tabs of w
                        repeat with s in sessions of t
                            set out to out & (tty of s) & "|" & winName & "|" & (name of s) & linefeed
                        end repeat
                    end repeat
                end repeat
            end tell
        on error
            return ""
        end try
        return out
    "#;

    let output = Command::new("osascript").args(["-e", SCRIPT]).output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            // Update cache with empty result so we don't hammer
            // osascript every poll when iTerm isn't running.
            let mut guard = iterm_cache().lock().expect("iterm cache lock poisoned");
            *guard = Some((HashMap::new(), Instant::now()));
            return HashMap::new();
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut map = HashMap::new();
    for line in stdout.lines() {
        // Each line is `<tty>|<window_name>|<session_name>`.
        // iTerm returns `/dev/ttys003` for the TTY; strip the
        // `/dev/` prefix to match `ps -o tty=` output.
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() != 3 {
            continue;
        }
        let tty = parts[0].trim().trim_start_matches("/dev/").to_string();
        let window_name = parts[1].trim().to_string();
        let session_name = parts[2].trim().to_string();
        if !tty.is_empty() {
            map.insert(tty, (window_name, session_name));
        }
    }

    // Store in cache for the next call.
    {
        let mut guard = iterm_cache().lock().expect("iterm cache lock poisoned");
        *guard = Some((map.clone(), Instant::now()));
    }
    map
}

/// Splits a `ps -E` command+env string into (command, env) halves.
///
/// The boundary is the first occurrence of ` KEY=` where `KEY`
/// matches an env-var name regex. Everything before it is `command`;
/// everything starting at `KEY=` onward is the environment blob.
fn split_command_and_env(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            let after = i + 1;
            // Look ahead for an env-var-shape token: [A-Z_][A-Z0-9_]*=
            let mut j = after;
            let mut saw_upper_or_underscore = false;
            while j < bytes.len() {
                let c = bytes[j];
                if c == b'=' {
                    if j > after && saw_upper_or_underscore {
                        // Found boundary — env starts at `after`.
                        return (s[..i].trim_end(), &s[after..]);
                    }
                    break;
                }
                let is_first = j == after;
                let valid = if is_first {
                    c.is_ascii_uppercase() || c == b'_'
                } else {
                    c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'
                };
                if !valid {
                    break;
                }
                if c.is_ascii_uppercase() || c == b'_' {
                    saw_upper_or_underscore = true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    // No env portion found — everything is the command.
    (s, "")
}

/// Finds `KEY=VALUE` in a space-delimited env blob and returns the
/// value up to the next ` KEY=` token.
///
/// The `ps -E` env blob is space-delimited, but env values can
/// themselves contain spaces (e.g. `PATH=/a/b /c/d`). We use the
/// same heuristic as `split_command_and_env` to find the end of a
/// value: the next ` KEY=` token.
fn parse_env_var<'a>(env: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    // Key must appear either at the start or preceded by a space.
    let start = if env.starts_with(&needle) {
        needle.len()
    } else {
        let anchor = format!(" {needle}");
        env.find(&anchor)? + anchor.len()
    };
    let tail = &env[start..];
    // Walk forward until we hit ` KEY=` where KEY is env-var shaped.
    let (value, _) = split_command_and_env(tail);
    Some(value)
}

/// Reads the cwd of a process via `lsof`.
///
/// Returns `None` on any failure — `lsof` may deny access, the
/// process may have exited, or the output format may be
/// unexpected. The session row still renders without a cwd if this
/// call fails; we just lose the "which terminal is this" signal.
fn read_cwd_via_lsof(pid: u32) -> Option<PathBuf> {
    let output = Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // lsof -Fn output: each field starts with a type character.
    //   p<pid>
    //   f<fd>
    //   n<name>      ← this is cwd
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('n') {
            return Some(PathBuf::from(rest));
        }
    }
    None
}

/// Reads the Unix-seconds start time of a process via `ps -o
/// lstart=`. Returns `None` on any failure.
fn read_start_time(pid: u32) -> Option<u64> {
    // `ps -o lstart=` returns a local-time string like
    // `Fri Apr 11 21:30:45 2026`. Parse via a minimal format walk;
    // avoid pulling in `chrono` just for this. Fall back to None.
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let s = text.trim();
    if s.is_empty() {
        return None;
    }
    // Heuristic: walk the current epoch back by the process's
    // reported "elapsed" seconds via `ps -o etimes=`, which is way
    // easier to parse than `lstart`.
    let etimes_out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "etimes="])
        .output()
        .ok()?;
    if !etimes_out.status.success() {
        return None;
    }
    let etimes: u64 = String::from_utf8_lossy(&etimes_out.stdout)
        .trim()
        .parse()
        .ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(etimes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_and_env_handles_no_env() {
        let (cmd, env) = split_command_and_env("claude --resume csq");
        assert_eq!(cmd, "claude --resume csq");
        assert_eq!(env, "");
    }

    #[test]
    fn split_command_and_env_finds_boundary_on_uppercase_key() {
        let (cmd, env) = split_command_and_env("claude --resume csq PATH=/a/b USER=x");
        assert_eq!(cmd, "claude --resume csq");
        assert_eq!(env, "PATH=/a/b USER=x");
    }

    #[test]
    fn split_command_and_env_respects_env_values_with_spaces() {
        let (cmd, env) = split_command_and_env("claude PATH=/a /b USER=x");
        assert_eq!(cmd, "claude");
        assert_eq!(env, "PATH=/a /b USER=x");
    }

    #[test]
    fn split_command_and_env_rejects_lowercase_keys_as_env_boundaries() {
        // `foo=bar` is not an env-var shape (lowercase) — must be
        // kept with the command, not treated as env start.
        let (cmd, env) = split_command_and_env("some-cmd foo=bar USER=x");
        assert_eq!(cmd, "some-cmd foo=bar");
        assert_eq!(env, "USER=x");
    }

    #[test]
    fn parse_env_var_finds_first_match() {
        let env = "PATH=/a/b USER=alice CLAUDE_CONFIG_DIR=/x/y/config-3 HOME=/h";
        assert_eq!(
            parse_env_var(env, "CLAUDE_CONFIG_DIR"),
            Some("/x/y/config-3")
        );
        assert_eq!(parse_env_var(env, "USER"), Some("alice"));
        assert_eq!(parse_env_var(env, "HOME"), Some("/h"));
    }

    #[test]
    fn parse_env_var_at_start() {
        let env = "CLAUDE_CONFIG_DIR=/x/y/config-3 USER=alice";
        assert_eq!(
            parse_env_var(env, "CLAUDE_CONFIG_DIR"),
            Some("/x/y/config-3")
        );
    }

    #[test]
    fn parse_env_var_not_found() {
        let env = "PATH=/a USER=alice";
        assert_eq!(parse_env_var(env, "CLAUDE_CONFIG_DIR"), None);
    }

    #[test]
    fn parse_env_var_avoids_substring_match() {
        // `FAKE_PATH=x` should NOT match when we ask for `PATH`.
        let env = "FAKE_PATH=x PATH=/a";
        assert_eq!(parse_env_var(env, "PATH"), Some("/a"));
    }

    #[test]
    fn parse_ps_line_claude_session() {
        let line = "37459 claude --resume csq PATH=/bin USER=esperie CLAUDE_CONFIG_DIR=/Users/esperie/.claude/accounts/config-8 HOME=/Users/esperie";
        // Note: this test only exercises the parse path. read_cwd_via_lsof
        // and read_start_time will fail for this fake PID, leaving cwd
        // empty and started_at=None, which is the expected graceful
        // degradation.
        let info = parse_ps_line(line).unwrap();
        assert_eq!(info.pid, 37459);
        assert_eq!(
            info.config_dir,
            PathBuf::from("/Users/esperie/.claude/accounts/config-8")
        );
        assert_eq!(info.account_id, Some(8));
    }

    #[test]
    fn parse_ps_line_skips_non_claude() {
        let line = "99999 node server.js CLAUDE_CONFIG_DIR=/a/config-1";
        assert!(parse_ps_line(line).is_none());
    }

    #[test]
    fn parse_ps_line_skips_claude_without_config_dir() {
        let line = "99999 claude --help PATH=/bin USER=x";
        assert!(parse_ps_line(line).is_none());
    }

    #[test]
    fn parse_ps_line_accepts_absolute_claude_path() {
        let line = "111 /opt/homebrew/bin/claude CLAUDE_CONFIG_DIR=/x/config-2";
        let info = parse_ps_line(line).unwrap();
        assert_eq!(info.pid, 111);
        assert_eq!(info.account_id, Some(2));
    }

    // ── Terminal identity (iTerm2) ──────────────────────────

    #[test]
    fn parse_ps_line_extracts_iterm_identity() {
        let line = "37459 claude --resume csq \
            PATH=/bin \
            TERM_SESSION_ID=w3t2p0:3B8385EC-9D2C-4E26-A416-2E04BCA60DA3 \
            ITERM_PROFILE=Default \
            CLAUDE_CONFIG_DIR=/Users/esperie/.claude/accounts/config-8 \
            HOME=/Users/esperie";
        let info = parse_ps_line(line).unwrap();
        assert_eq!(info.term_window, Some(3));
        assert_eq!(info.term_tab, Some(2));
        assert_eq!(info.term_pane, Some(0));
        assert_eq!(info.iterm_profile.as_deref(), Some("Default"));
    }

    #[test]
    fn parse_ps_line_no_iterm_env_leaves_fields_none() {
        // Non-iTerm terminal (e.g. plain tmux) has no TERM_SESSION_ID
        // or ITERM_PROFILE — those fields should come out as None,
        // not cause parsing to fail.
        let line = "50000 claude CLAUDE_CONFIG_DIR=/x/config-5";
        let info = parse_ps_line(line).unwrap();
        assert_eq!(info.term_window, None);
        assert_eq!(info.term_tab, None);
        assert_eq!(info.term_pane, None);
        assert_eq!(info.iterm_profile, None);
    }

    // ── format_terminal_title + decorations ────────────────

    #[test]
    fn strip_iterm_decorations_removes_status_icon() {
        assert_eq!(strip_iterm_decorations("✳ terrene"), "terrene");
        assert_eq!(strip_iterm_decorations("⠂ Claude Code"), "Claude Code");
    }

    #[test]
    fn strip_iterm_decorations_removes_trailing_command() {
        assert_eq!(strip_iterm_decorations("✳ arbor (claude)"), "arbor");
        assert_eq!(
            strip_iterm_decorations("✳ Claude Code (node)"),
            "Claude Code"
        );
    }

    #[test]
    fn strip_iterm_decorations_leaves_plain_titles_intact() {
        assert_eq!(strip_iterm_decorations("Plain title"), "Plain title");
    }

    #[test]
    fn strip_iterm_decorations_handles_empty() {
        assert_eq!(strip_iterm_decorations(""), "");
        assert_eq!(strip_iterm_decorations("   "), "");
    }

    #[test]
    fn format_terminal_title_window_and_session() {
        // User's canonical case: window "terrene", session "arbor".
        let out = format_terminal_title("✳ terrene", "✳ arbor (claude)");
        assert_eq!(out, "terrene · arbor");
    }

    #[test]
    fn format_terminal_title_collapses_when_identical() {
        // iTerm often propagates the tab title up to the window
        // title. When both are the same we show once, not twice.
        let out = format_terminal_title("✳ Claude Code", "✳ Claude Code (claude)");
        assert_eq!(out, "Claude Code");
    }

    #[test]
    fn format_terminal_title_window_only() {
        assert_eq!(format_terminal_title("✳ terrene", ""), "terrene");
    }

    #[test]
    fn format_terminal_title_session_only() {
        assert_eq!(format_terminal_title("", "✳ arbor (claude)"), "arbor");
    }

    #[test]
    fn format_terminal_title_both_empty() {
        assert_eq!(format_terminal_title("", ""), "");
    }
}
