//! Pure parser for the Windows environment block format.
//!
//! Lives outside `windows.rs` so its unit tests run on every
//! platform's CI (macOS / Linux / Windows). The syscall wrappers
//! that feed this parser are Windows-only and live in `windows.rs`.
//!
//! See `windows.rs` for the full PEB-walking strategy that
//! produces the `&[u16]` block this module parses.

use std::collections::HashMap;

/// Parses a UTF-16 Windows environment block into a `{KEY → VALUE}`
/// map.
///
/// Format: a contiguous array of NUL-terminated UTF-16 strings
/// shaped like `KEY=VALUE`, followed by an extra NUL to terminate
/// the whole block. This is what `GetEnvironmentStringsW` returns
/// and what `RTL_USER_PROCESS_PARAMETERS.Environment` points to.
///
/// Behavior:
/// - Empty entries (anywhere in the block) are skipped.
/// - Entries without `=` are skipped as malformed.
/// - Entries starting with `=` (Windows' per-drive cwd vars like
///   `=C:=C:\Users\foo`) are skipped — `split_once` on `=` yields
///   an empty key which we reject.
/// - Values containing `=` are preserved; `split_once` splits only
///   at the **first** `=`.
/// - Parsing stops at the double-NUL terminator.
///
/// Pure function: allocates one HashMap and some short-lived
/// `String`s via `from_utf16_lossy`. No syscalls, no unsafe.
pub fn parse_environment_block(block: &[u16]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut start = 0;
    for (i, &ch) in block.iter().enumerate() {
        if ch == 0 {
            if i > start {
                let entry = String::from_utf16_lossy(&block[start..i]);
                if let Some((k, v)) = entry.split_once('=') {
                    if !k.is_empty() {
                        map.insert(k.to_string(), v.to_string());
                    }
                }
            }
            start = i + 1;
            // Double-NUL terminator: an empty entry at `start`.
            if block.get(start).copied() == Some(0) {
                break;
            }
        }
    }
    map
}

/// Returns true if a UTF-16 NUL-terminated buffer holds
/// `claude.exe` case-insensitively. Compares as allocated
/// `String` after finding the NUL — the 260-char tax of
/// `PROCESSENTRY32W::szExeFile` makes a stack allocation
/// unnecessary.
pub fn exe_matches_claude(buf: &[u16]) -> bool {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let name = String::from_utf16_lossy(&buf[..len]).to_ascii_lowercase();
    name == "claude.exe"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_env_block(entries: &[&str]) -> Vec<u16> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend(entry.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    #[test]
    fn parse_env_block_finds_keys() {
        let block = build_env_block(&[
            "PATH=C:\\Windows",
            "USER=alice",
            "CLAUDE_CONFIG_DIR=C:\\Users\\alice\\.claude\\accounts\\config-3",
        ]);
        let env = parse_environment_block(&block);
        assert_eq!(env.get("USER").map(String::as_str), Some("alice"));
        assert_eq!(
            env.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            Some("C:\\Users\\alice\\.claude\\accounts\\config-3")
        );
    }

    #[test]
    fn parse_env_block_empty() {
        let block: Vec<u16> = vec![0, 0];
        assert!(parse_environment_block(&block).is_empty());
    }

    #[test]
    fn parse_env_block_skips_windows_drive_variables() {
        // Windows CMD sets per-drive cwd vars like `=C:=C:\foo`.
        // The leading `=` means split_once gives key `""`, which
        // we reject.
        let block = build_env_block(&["=C:=C:\\foo", "USER=bob"]);
        let env = parse_environment_block(&block);
        assert_eq!(env.get("USER").map(String::as_str), Some("bob"));
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn parse_env_block_handles_values_with_equals() {
        // `FOO=a=b=c` — the value contains equals signs. split_once
        // on '=' splits at the first one: key=FOO, value=a=b=c.
        let block = build_env_block(&["FOO=a=b=c"]);
        let env = parse_environment_block(&block);
        assert_eq!(env.get("FOO").map(String::as_str), Some("a=b=c"));
    }

    #[test]
    fn parse_env_block_skips_malformed_entries() {
        // Entries without an `=` are skipped (malformed).
        let block = build_env_block(&["USER=alice", "NOEQUALS", "FOO=bar"]);
        let env = parse_environment_block(&block);
        assert_eq!(env.len(), 2);
        assert!(env.contains_key("USER"));
        assert!(env.contains_key("FOO"));
    }

    #[test]
    fn parse_env_block_stops_at_double_nul() {
        // Anything after the double-NUL terminator is ignored.
        let mut block = build_env_block(&["USER=alice"]);
        // Append a stray entry after the terminator.
        block.extend("STRAY=value".encode_utf16());
        block.push(0);
        let env = parse_environment_block(&block);
        assert_eq!(env.len(), 1);
        assert!(env.contains_key("USER"));
        assert!(!env.contains_key("STRAY"));
    }

    #[test]
    fn parse_env_block_unicode_values() {
        // Some env values (e.g. USERPROFILE) contain non-ASCII chars.
        let block = build_env_block(&["USERPROFILE=C:\\Users\\Ålice"]);
        let env = parse_environment_block(&block);
        assert_eq!(
            env.get("USERPROFILE").map(String::as_str),
            Some("C:\\Users\\Ålice")
        );
    }

    #[test]
    fn exe_matches_claude_case_insensitive() {
        let mut buf = [0u16; 260];
        let name: Vec<u16> = "CLAUDE.EXE".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert!(exe_matches_claude(&buf));

        let mut buf = [0u16; 260];
        let name: Vec<u16> = "claude.exe".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert!(exe_matches_claude(&buf));
    }

    #[test]
    fn exe_matches_claude_rejects_other_processes() {
        let mut buf = [0u16; 260];
        let name: Vec<u16> = "notepad.exe".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert!(!exe_matches_claude(&buf));
    }

    #[test]
    fn exe_matches_claude_rejects_partial_match() {
        let mut buf = [0u16; 260];
        let name: Vec<u16> = "claude.exe.bak".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert!(!exe_matches_claude(&buf));
    }
}
