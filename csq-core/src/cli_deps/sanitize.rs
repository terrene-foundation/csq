//! Terminal-control-character sanitizer for third-party CLI output.
//!
//! Per spec/13 §10, every string captured from a third-party subprocess
//! MUST pass through `sanitize_for_display` before printing to the user
//! terminal. This guards against terminal injection via malicious
//! `--version` output (e.g. OSC-52 clipboard write, cursor movement
//! sequences, character-set switching).

/// Strip control characters from subprocess output before printing.
///
/// Strips:
/// - Every char in `\x00..=\x1f` EXCEPT `\t` (`\x09`).
/// - `\x7f` (DEL).
///
/// Caps the result to 200 **chars (Unicode codepoints)** — NOT bytes.
/// Using `char`-based capping avoids splitting multi-byte UTF-8 sequences
/// while still bounding the output to a safe display width. A 200-char
/// output may be up to 800 bytes (4 bytes per emoji), which is still
/// well within any terminal line budget.
pub fn sanitize_for_display(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c == '\t' || (c >= ' ' && c != '\x7f'))
        .take(200)
        .collect()
}

/// Replaces the operator's `$HOME` prefix with `~` so paths emitted to
/// operator-facing stdout / `--json` / `eprintln!` chat don't leak the
/// username. Used by fields where the full path is diagnostically useful
/// (e.g. which JS runtime was picked, which hook file is missing) but
/// the `$HOME` prefix is incidental.
///
/// Per `rules/operator-surface-verification.md` Rule 1. Returns the input
/// unchanged when `$HOME` is unset, empty, or the input does not start
/// with the operator's home directory (e.g. `/opt/homebrew/bin/node`).
///
/// Handles a trailing `/` on `$HOME` (e.g. `$HOME=/root/` on some CI
/// images) by canonicalizing it away before comparing prefixes —
/// otherwise `redact_home_prefix("/root/.nvm/node")` against
/// `$HOME=/root/` would emit `~.nvm/node` (missing the separator).
pub fn redact_home_prefix(p: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return p.to_string();
    };
    let Some(home_str) = home.to_str() else {
        return p.to_string();
    };
    let home_trimmed = home_str.trim_end_matches('/');
    if home_trimmed.is_empty() {
        return p.to_string();
    }
    if let Some(rest) = p.strip_prefix(home_trimmed) {
        // `rest` either starts with `/` (the natural separator) or is empty
        // (input == $HOME exactly). Anything else means the prefix matched
        // a parent directory whose name happens to be a prefix of $HOME's
        // last component — bail out and return the input unchanged.
        if rest.is_empty() {
            return "~".to_string();
        }
        if let Some(rest) = rest.strip_prefix('/') {
            return format!("~/{rest}");
        }
    }
    p.to_string()
}

/// Ergonomic wrapper over [`redact_home_prefix`] for callers holding a
/// `&Path` (the common case in CLI command handlers — `path.display()`
/// interpolation in `println!` / `eprintln!` / `anyhow!` / `bail!`).
///
/// Per `rules/operator-surface-verification.md` Rule 1, every operator-
/// facing `path.display()` callsite in `csq/src/cli/commands/**` (and
/// `csq-cli/src/**`) MUST route through this helper (or `redact_home_prefix`
/// directly) unless the subcommand is in the Rule 5 exempt set OR the
/// field carries a Rule 3 design-intent inline comment.
///
/// ```rust
/// # use std::path::Path;
/// # use csq_core::cli_deps::sanitize::redact_path;
/// // DO — wrap path.display() in operator-facing chat
/// // eprintln!("write failed at {}: {e}", redact_path(&tmp));
///
/// // DO NOT — leak full host path in error messages
/// // return Err(anyhow!("write failed at {}: {e}", tmp.display()));
/// ```
pub fn redact_path(p: &std::path::Path) -> String {
    redact_home_prefix(&p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_osc52_escape_sequence() {
        // OSC-52 clipboard write: \x1b]52;c;<base64>\x07
        let raw = "\x1b]52;c;SGVsbG8gV29ybGQ=\x07";
        let sanitized = sanitize_for_display(raw);
        assert!(
            !sanitized.contains('\x1b'),
            "ESC must be stripped; got: {sanitized:?}"
        );
        assert!(
            !sanitized.contains('\x07'),
            "BEL must be stripped; got: {sanitized:?}"
        );
    }

    #[test]
    fn caps_at_200_chars_ascii() {
        // 250 ASCII 'x' characters — result must be exactly 200 codepoints.
        let raw: String = "x".repeat(250);
        let sanitized = sanitize_for_display(&raw);
        assert_eq!(
            sanitized.chars().count(),
            200,
            "result must be capped at 200 codepoints; char count got {}",
            sanitized.chars().count()
        );
    }

    #[test]
    fn caps_at_200_codepoints_emoji() {
        // 1000 emoji (U+1F600, 4 bytes each in UTF-8).
        // Result must be exactly 200 codepoints and valid UTF-8.
        let raw: String = "\u{1F600}".repeat(1000);
        let sanitized = sanitize_for_display(&raw);
        let codepoint_count = sanitized.chars().count();
        assert_eq!(
            codepoint_count, 200,
            "emoji-heavy input: expected 200 codepoints, got {codepoint_count}"
        );
        // Verify no broken UTF-8 by checking round-trip through bytes.
        let bytes = sanitized.as_bytes();
        assert!(
            std::str::from_utf8(bytes).is_ok(),
            "sanitized output must be valid UTF-8"
        );
    }

    #[test]
    fn preserves_tab() {
        let raw = "a\tb";
        let sanitized = sanitize_for_display(raw);
        assert_eq!(sanitized, "a\tb", "tab must be preserved");
    }

    #[test]
    fn strips_del() {
        // \x7f = DEL
        let raw = "hello\x7fworld";
        let sanitized = sanitize_for_display(raw);
        assert_eq!(sanitized, "helloworld", "DEL must be stripped");
    }

    #[test]
    fn strips_all_control_bytes_except_tab() {
        // Build a string with all bytes 0x00..=0x1f, except 0x09 (\t).
        let mut raw = String::new();
        for b in 0u8..=0x1fu8 {
            raw.push(b as char);
        }
        let sanitized = sanitize_for_display(&raw);
        // Only the tab should remain.
        assert_eq!(sanitized, "\t", "only tab must survive; got: {sanitized:?}");
    }

    #[test]
    fn normal_version_string_unchanged() {
        let raw = "codex-cli 0.128.0";
        let sanitized = sanitize_for_display(raw);
        assert_eq!(sanitized, raw);
    }

    #[test]
    fn strips_newlines_and_carriage_returns() {
        // \n = 0x0a, \r = 0x0d — both are control bytes
        let raw = "codex-cli 0.128.0\r\n";
        let sanitized = sanitize_for_display(raw);
        assert_eq!(sanitized, "codex-cli 0.128.0");
    }

    fn with_home<R>(home: Option<&str>, f: impl FnOnce() -> R) -> R {
        // Use the workspace-wide test env mutex (per `rules/testing.md`
        // §4/4b shared-env discipline) so HOME mutation here serializes
        // against sibling modules that also mutate HOME (e.g.
        // `daemon::usage_poller::gemini_oauth::tests`). A module-local
        // mutex would only protect within `cli_deps::sanitize::tests` —
        // round-6 redteam discovery.
        let _g = crate::platform::test_env::lock();
        let prior = std::env::var_os("HOME");
        match home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let out = f();
        match prior {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        out
    }

    #[test]
    fn redact_home_prefix_replaces_home_with_tilde() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_prefix("/Users/jack/.nvm/v22/bin/node"),
                "~/.nvm/v22/bin/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_returns_input_when_home_unset() {
        with_home(None, || {
            assert_eq!(
                redact_home_prefix("/Users/jack/.nvm/node"),
                "/Users/jack/.nvm/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_returns_input_when_home_empty() {
        with_home(Some(""), || {
            assert_eq!(
                redact_home_prefix("/Users/jack/.nvm/node"),
                "/Users/jack/.nvm/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_handles_root_home() {
        // `$HOME=/` is the degenerate case; trimming the trailing slash
        // makes it empty, which is handled by the empty-home guard. The
        // input is returned unchanged.
        with_home(Some("/"), || {
            assert_eq!(
                redact_home_prefix("/Users/jack/.nvm/node"),
                "/Users/jack/.nvm/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_handles_trailing_slash_in_home() {
        with_home(Some("/root/"), || {
            assert_eq!(
                redact_home_prefix("/root/.nvm/v22/bin/node"),
                "~/.nvm/v22/bin/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_passes_through_non_home_paths() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_prefix("/opt/homebrew/bin/node"),
                "/opt/homebrew/bin/node"
            );
        });
    }

    #[test]
    fn redact_home_prefix_no_double_redaction() {
        // Input already starts with `~/`; HOME doesn't match the literal
        // `~`, so the helper returns input unchanged.
        with_home(Some("/Users/jack"), || {
            assert_eq!(redact_home_prefix("~/.nvm/node"), "~/.nvm/node");
        });
    }

    #[test]
    fn redact_home_prefix_does_not_match_prefix_collision() {
        // `$HOME=/Users/jack` should NOT match a path whose first
        // component shares a prefix like `/Users/jackdaw/...`. The
        // `strip_prefix(home_trimmed)`-then-`strip_prefix('/')` chain
        // catches this: after stripping `/Users/jack`, `rest` would
        // be `daw/...` (no leading slash), and the second strip fails.
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_prefix("/Users/jackdaw/work/file"),
                "/Users/jackdaw/work/file"
            );
        });
    }

    #[test]
    fn redact_home_prefix_collapses_exact_home_match() {
        // Input == $HOME exactly → returns `~`. Edge case but worth
        // pinning so future refactors don't emit `~/` (extra slash).
        with_home(Some("/Users/jack"), || {
            assert_eq!(redact_home_prefix("/Users/jack"), "~");
        });
    }
}
