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
/// `\` is a path separator on Windows ONLY. On Unix it is a legal filename
/// character, so treating it as a separator there would collapse
/// `/Users/jack\weird` (a file named `jack\weird` under `/Users`) into
/// `~/weird` — a DIFFERENT path. The `cfg!` gate is load-bearing, not
/// defensive.
fn is_path_sep(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

pub fn redact_home_prefix(p: &str) -> String {
    // Windows has no `HOME`; the home directory is `USERPROFILE`. `HOME` is
    // present under git-bash/MSYS, so check it first (a deliberately-set HOME still
    // wins) and fall back only on Windows — adding a USERPROFILE fallback on Unix
    // would redact against a variable Unix does not define as home.
    //
    // This comment previously asserted `HOME` is also present "on GitHub's windows
    // runners". Measured 2026-08-19 on windows-latest: it is `NotPresent`. The
    // fallback below is therefore load-bearing on CI, not just belt-and-braces —
    // which is exactly why the claim mattered enough to correct rather than drop.
    let home = std::env::var_os("HOME").or_else(|| {
        if cfg!(windows) {
            std::env::var_os("USERPROFILE")
        } else {
            None
        }
    });
    let Some(home) = home else {
        return p.to_string();
    };
    let Some(home_str) = home.to_str() else {
        return p.to_string();
    };
    let home_trimmed = home_str.trim_end_matches(is_path_sep);
    if home_trimmed.is_empty() {
        return p.to_string();
    }
    if let Some(rest) = p.strip_prefix(home_trimmed) {
        // `rest` either starts with a separator or is empty (input == $HOME
        // exactly). Anything else means the prefix matched a parent directory
        // whose name happens to be a prefix of $HOME's last component — bail
        // out and return the input unchanged.
        if rest.is_empty() {
            return "~".to_string();
        }
        // Only the LEADING separator is normalised to `/`, so the redaction
        // marker is always `~/` on every platform; the remainder keeps its
        // native separators. Real Windows paths mix them — the leak that
        // found this was `C:\Users\runneradmin\.tmpXXXX\skills/SKILL-BLOCKED`,
        // backslashes from `Path::join` and a forward slash from a literal.
        if let Some(rest) = rest.strip_prefix(is_path_sep) {
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

/// Redacts every occurrence of the operator's `$HOME` prefix found
/// ANYWHERE within `s`, not just at position 0. Generalizes
/// [`redact_home_prefix`] (which only strips a match at the START of
/// the string) for callers formatting an error whose `Display` chain
/// embeds a path mid-sentence — e.g. `ConfigError::InvalidJson`'s
/// `"invalid JSON in {path}: {reason}"`, or a hand-built
/// `std::io::Error::new(kind, format!("... {}", path.display()))`
/// (confirmed in `providers::codex::tos::acknowledge_at`, whose
/// `io::Error` cannot be pattern-matched by variant to reach a `path`
/// field directly).
///
/// Per `rules/operator-surface-verification.md` Rule 1 / `tauri-commands.md`
/// MUST-3. Returns the input unchanged when `$HOME` is unset or empty.
pub fn redact_home_anywhere(s: &str) -> String {
    let home = std::env::var_os("HOME").or_else(|| {
        if cfg!(windows) {
            std::env::var_os("USERPROFILE")
        } else {
            None
        }
    });
    let Some(home) = home else {
        return s.to_string();
    };
    let Some(home_str) = home.to_str() else {
        return s.to_string();
    };
    let home_trimmed = home_str.trim_end_matches(is_path_sep);
    if home_trimmed.is_empty() {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find(home_trimmed) {
        let (before, after_match) = rest.split_at(idx);
        let after = &after_match[home_trimmed.len()..];
        out.push_str(before);
        if after.is_empty() {
            out.push('~');
            rest = after;
            break;
        }
        if after.starts_with(is_path_sep) {
            // `is_path_sep` chars are single-byte ASCII, so slicing at [1..]
            // never splits a multi-byte codepoint.
            out.push_str("~/");
            rest = &after[1..];
        } else {
            // Not a real boundary (e.g. the match is a prefix of a longer
            // component like `/Users/jackson`) — keep the literal text and
            // resume scanning right after it so we make forward progress.
            out.push_str(home_trimmed);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Renders any `Display` value for the IPC / operator boundary with
/// BOTH filesystem-path AND token/secret redaction applied. Use where
/// the concrete error type's `Display` cannot be pattern-matched
/// per-variant to route a `path` field through [`redact_path`]
/// directly (`std::io::Error`, a `tokio::task::JoinError`, or any
/// error type reached generically through a bound). Composes
/// [`redact_home_anywhere`] with [`crate::error::redact_tokens`] so a
/// single call covers both leak classes.
///
/// `rules/tauri-commands.md` MUST-3; `rules/security.md` MUST-2.
pub fn redact_display<E: std::fmt::Display>(e: E) -> String {
    crate::error::redact_tokens(&redact_home_anywhere(&e.to_string()))
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

    /// Every test above is written with `/`, so on Windows they exercise a
    /// shape the platform never produces — and the redaction was silently
    /// inert there. `Path::join` builds `\`, so `$HOME`-rooted paths never
    /// matched the `strip_prefix('/')` guard and the RAW home path was
    /// returned. This built the fixture from real `Path` joins so it asserts
    /// the invariant in the platform's own separator on both.
    ///
    /// Caught by CI, not by review: `materialize_error_display_never_leaks_
    /// raw_home_path` failed on `windows-latest` with the leak quoted in
    /// full — `C:\Users\runneradmin\.tmpoWBNxz\skills/SKILL-BLOCKED`.
    #[test]
    fn redact_home_prefix_handles_the_platform_native_separator() {
        let home = std::path::Path::new(if cfg!(windows) {
            r"C:\Users\jack"
        } else {
            "/Users/jack"
        });
        let nested = home.join(".config").join("csq").join("token.json");
        // Non-negotiable precondition: on Windows this string MUST contain a
        // backslash, else the test is asserting the Unix shape again and
        // proves nothing about the bug it exists for.
        assert_eq!(
            nested.to_str().unwrap().contains('\\'),
            cfg!(windows),
            "fixture did not use the native separator: {}",
            nested.display()
        );
        with_home(Some(home.to_str().unwrap()), || {
            let out = redact_home_prefix(nested.to_str().unwrap());
            assert!(
                out.starts_with("~/"),
                "expected the `~/` marker on every platform, got {out:?}"
            );
            assert!(
                !out.contains("jack"),
                "raw home path survived redaction: {out:?}"
            );
        });
    }

    /// The prefix-collision guard (`/Users/jack` must NOT match
    /// `/Users/jackdaw/...`) has to survive the separator widening — a
    /// `strip_prefix` that accepted "any separator OR nothing" would collapse
    /// a sibling directory into `~`.
    #[test]
    fn redact_home_prefix_collision_guard_holds_on_native_separator() {
        let home = std::path::Path::new(if cfg!(windows) {
            r"C:\Users\jack"
        } else {
            "/Users/jack"
        });
        let sibling = std::path::Path::new(if cfg!(windows) {
            r"C:\Users\jackdaw\work\file"
        } else {
            "/Users/jackdaw/work/file"
        });
        with_home(Some(home.to_str().unwrap()), || {
            assert_eq!(
                redact_home_prefix(sibling.to_str().unwrap()),
                sibling.to_str().unwrap(),
                "a sibling whose name merely starts with $HOME's last \
                 component must pass through untouched"
            );
        });
    }

    /// On Unix `\` is a legal FILENAME character, so it must NOT be treated as
    /// a separator there: `/Users/jack\weird` is a file named `jack\weird`
    /// under `/Users`, a different path from `$HOME/weird`. Pins the `cfg!`
    /// gate in `is_path_sep` so a future "simplification" to an unconditional
    /// `c == '/' || c == '\\'` fails here.
    #[cfg(unix)]
    #[test]
    fn redact_home_prefix_does_not_treat_backslash_as_separator_on_unix() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_prefix(r"/Users/jack\weird"),
                r"/Users/jack\weird"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_redacts_mid_sentence_path() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_anywhere(
                    "invalid JSON in /Users/jack/.claude/accounts/rotation.json: unexpected EOF"
                ),
                "invalid JSON in ~/.claude/accounts/rotation.json: unexpected EOF"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_redacts_multiple_occurrences() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_anywhere(
                    "atomic replace at /Users/jack/.claude/a: rename /Users/jack/.claude/a.tmp -> /Users/jack/.claude/a failed"
                ),
                "atomic replace at ~/.claude/a: rename ~/.claude/a.tmp -> ~/.claude/a failed"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_does_not_match_prefix_collision() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_anywhere("base dir does not exist: /Users/jackson/.claude/accounts"),
                "base dir does not exist: /Users/jackson/.claude/accounts"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_returns_input_when_home_unset() {
        with_home(None, || {
            assert_eq!(
                redact_home_anywhere(
                    "invalid JSON in /Users/jack/.claude/accounts/rotation.json: x"
                ),
                "invalid JSON in /Users/jack/.claude/accounts/rotation.json: x"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_passes_through_clean_message() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_anywhere("key too short (need at least 30 bytes)"),
                "key too short (need at least 30 bytes)"
            );
        });
    }

    #[test]
    fn redact_home_anywhere_exact_home_at_end_of_string() {
        with_home(Some("/Users/jack"), || {
            assert_eq!(
                redact_home_anywhere("base directory does not exist: /Users/jack"),
                "base directory does not exist: ~"
            );
        });
    }

    #[test]
    fn redact_display_redacts_both_path_and_token() {
        with_home(Some("/Users/jack"), || {
            let msg = "invalid JSON in /Users/jack/.claude/accounts/rotation.json: \
                       token=sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let out = redact_display(msg);
            assert!(!out.contains("/Users/jack"), "path leaked: {out}");
            assert!(!out.contains("sk-ant-oat01"), "token leaked: {out}");
        });
    }
}
