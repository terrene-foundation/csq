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

    // Resolve iTerm2 tab titles keyed by TTY once per `list()` call.
    // `osascript` is ~50ms so we pay it once and join by TTY below.
    // An empty map is fine — the title column just shows blank.
    let tab_titles = read_iterm_tab_titles_by_tty();

    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(mut info) = parse_ps_line(line) {
            if let Some(ref tty) = info.tty {
                info.terminal_title = tab_titles.get(tty).cloned();
            }
            out.push(info);
        }
    }
    out
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

/// Queries iTerm2 via AppleScript for `{TTY → tab title}` pairs.
///
/// This is a best-effort lookup — if iTerm2 is not running, the
/// user denies automation permission, or the AppleScript fails for
/// any reason, we return an empty map and the sessions view just
/// omits the terminal title column for those rows. The user still
/// gets TTY + window/tab indices from the env vars.
///
/// The AppleScript walks every window → tab → session and joins
/// each session's `tty` to its tab's `name`. Sessions inside the
/// same tab all get the same title (tabs, not panes, are the unit
/// users label).
///
/// 1-second timeout on the osascript call so a hung iTerm2 process
/// can't wedge `list_sessions`.
fn read_iterm_tab_titles_by_tty() -> HashMap<String, String> {
    // Cheap process-existence check before shelling out — if
    // iTerm2 isn't running, the osascript call would produce a
    // "Can't get application" error and slow down the whole path.
    let iterm_running = Command::new("pgrep")
        .args(["-x", "iTerm2"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !iterm_running {
        return HashMap::new();
    }

    const SCRIPT: &str = r#"
        set out to ""
        tell application "iTerm2"
            repeat with w in windows
                repeat with t in tabs of w
                    set tabName to name of t
                    repeat with s in sessions of t
                        set out to out & (tty of s) & "|" & tabName & linefeed
                    end repeat
                end repeat
            end repeat
        end tell
        return out
    "#;

    // `-e` runs the script inline; two-arg form avoids any shell
    // metachar concerns.
    let output = Command::new("osascript").args(["-e", SCRIPT]).output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return HashMap::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut map = HashMap::new();
    for line in stdout.lines() {
        // Each line is `<tty>|<tab name>`. iTerm's `tty of session`
        // returns `/dev/ttys003` — strip the prefix to match `ps
        // -o tty=` which returns just `ttys003`.
        if let Some((tty_raw, title)) = line.split_once('|') {
            let tty = tty_raw.trim().trim_start_matches("/dev/").to_string();
            let title = title.trim().to_string();
            if !tty.is_empty() && !title.is_empty() {
                map.insert(tty, title);
            }
        }
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
}
