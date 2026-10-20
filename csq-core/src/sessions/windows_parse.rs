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

/// `ERROR_INVALID_PARAMETER`: what `OpenProcess` reports for a pid that does not exist.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Whether a failed `OpenProcess`'s `GetLastError` means the process is gone. Any other
/// code (notably `ERROR_ACCESS_DENIED`) is a refusal to read it, which says nothing about
/// whether it exists, so it is undetermined, never "not a session".
pub fn open_failure_means_gone(code: u32) -> bool {
    code == ERROR_INVALID_PARAMETER
}

/// Whether two process-token user SIDs name the same user, from their raw bytes. `None`
/// when either could not be read or is not a well-formed SID (revision 1, total length
/// `8 + 4 * sub-authority count`): an unreadable owner is undetermined, never "another
/// user" and never "the same user". For two well-formed SIDs, byte equality is what
/// `EqualSid` compares (revision, sub-authority count, authority, sub-authorities).
pub fn owner_verdict(target: Option<&[u8]>, own: Option<&[u8]>) -> Option<bool> {
    fn well_formed(sid: &[u8]) -> bool {
        sid.len() >= 8 && sid[0] == 1 && sid.len() == 8 + 4 * usize::from(sid[1])
    }
    let (t, o) = (target?, own?);
    (well_formed(t) && well_formed(o)).then(|| t == o)
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

/// Whether a UTF-16 NUL-terminated image name is a CLI csq launches (`claude`, `codex`,
/// `codex-<triple>`, `gemini`, `kimi`, `grok`, each with `.exe`, case-insensitive): a session
/// image for the between-hop check ([`super::is_cli_image_name`]).
pub fn exe_is_session_image(buf: &[u16]) -> bool {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    super::is_cli_image_name(&String::from_utf16_lossy(&buf[..len]))
}

/// The between-hop probe of a Windows process from its image name (read from the process
/// snapshot), whatever its owner: a CLI image is a session, any other readable image is
/// not. LIMIT: the snapshot carries the image NAME only, so a `node.exe` running a CLI's
/// script, and a renamed image, are not seen here (the full image path and argv need
/// `QueryFullProcessImageNameW` and a PEB read, neither implemented).
pub fn hop_probe_from_image(image: &[u16]) -> super::HopProbe {
    super::HopProbe::Process {
        session_image: exe_is_session_image(image),
        codex_wrapper: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v.resize(260, 0);
        v
    }

    #[test]
    fn claude_and_codex_images_are_sessions_and_any_other_readable_image_is_not() {
        for yes in ["claude.exe", "CLAUDE.EXE", "codex.exe", "Codex.exe"] {
            assert!(exe_is_session_image(&w(yes)), "{yes}");
        }
        for no in [
            "powershell.exe",
            "node.exe",
            "codex.cmd",
            "codex-helper.exe",
            "claude.exe.bak",
            "xcodex.exe",
        ] {
            assert!(!exe_is_session_image(&w(no)), "{no}");
        }
    }

    #[test]
    fn a_windows_hop_is_classified_by_image_whatever_its_owner() {
        use super::super::classify_hop;
        for yes in [
            "codex.exe",
            "codex-x86_64-pc-windows-msvc.exe",
            "gemini.exe",
            "grok.exe",
        ] {
            assert_eq!(
                classify_hop(hop_probe_from_image(&w(yes))),
                Some(true),
                "{yes}"
            );
        }
        assert_eq!(
            classify_hop(hop_probe_from_image(&w("pwsh.exe"))),
            Some(false)
        );
    }

    /// S-1-5-21-1-2-3-1001: revision 1, 5 sub-authorities.
    fn sid(rid: u32) -> Vec<u8> {
        let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, rid] {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    #[test]
    fn owner_verdict_same_different_and_unreadable_are_three_outcomes() {
        assert_eq!(
            owner_verdict(Some(&sid(1001)), Some(&sid(1001))),
            Some(true)
        );
        assert_eq!(
            owner_verdict(Some(&sid(1002)), Some(&sid(1001))),
            Some(false),
            "a different user is a determinate no"
        );
        assert_eq!(owner_verdict(None, Some(&sid(1001))), None, "target token");
        assert_eq!(owner_verdict(Some(&sid(1001)), None), None, "own token");
        let mut torn = sid(1001);
        torn.pop();
        assert_eq!(
            owner_verdict(Some(&torn), Some(&torn)),
            None,
            "truncated SID"
        );
        let mut bad_rev = sid(1001);
        bad_rev[0] = 2;
        assert_eq!(
            owner_verdict(Some(&bad_rev), Some(&bad_rev)),
            None,
            "revision"
        );
        assert_eq!(owner_verdict(Some(&[]), Some(&[])), None, "empty");
    }

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
    fn only_invalid_parameter_means_the_process_is_gone() {
        assert!(open_failure_means_gone(87));
        assert!(
            !open_failure_means_gone(5),
            "access denied is a refusal, not absence"
        );
        assert!(!open_failure_means_gone(0));
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
