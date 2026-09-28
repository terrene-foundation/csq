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
    let Some(home_str) = resolved_home_string() else {
        return s.to_string();
    };
    let literal = home_str.trim_end_matches(is_path_sep);
    // Also redact the CANONICALIZED home (a symlinked `$HOME`, or macOS's
    // `/tmp` -> `/private/tmp`): a path canonicalized before being
    // formatted into an error carries the resolved form, not the literal
    // `$HOME` value. The LONGER needle runs first so a canonical form that
    // CONTAINS the literal one (e.g. `/private/tmp/h` vs `/tmp/h`) is not
    // half-rewritten by the shorter pass before it can match.
    match canonical_home_string() {
        Some(canon) => {
            let canon = canon.trim_end_matches(is_path_sep);
            if canon.is_empty() || canon == literal {
                redact_needle_anywhere(s, literal)
            } else if canon.len() >= literal.len() {
                redact_needle_anywhere(&redact_needle_anywhere(s, canon), literal)
            } else {
                redact_needle_anywhere(&redact_needle_anywhere(s, literal), canon)
            }
        }
        None => redact_needle_anywhere(s, literal),
    }
}

/// Resolves the operator's home directory as a `String` — `$HOME`, falling
/// back to `$USERPROFILE` on Windows only (mirrors [`redact_home_prefix`]'s
/// resolution). Returns `None` when unset or not valid UTF-8; callers treat
/// that as "nothing to redact", never as an error.
// `pub(crate)`: item 7's `redact_reason` reorder fix needs the literal
// needle directly (not only via `redact_home_anywhere`'s already-applied
// pass) to decide whether it or `canonical_home_string()` should run
// first.
pub(crate) fn resolved_home_string() -> Option<String> {
    let home = std::env::var_os("HOME").or_else(|| {
        if cfg!(windows) {
            std::env::var_os("USERPROFILE")
        } else {
            None
        }
    })?;
    home.to_str().map(str::to_string)
}

/// Resolves the operator's home directory the same way
/// [`resolved_home_string`] does, then canonicalizes it (resolves symlinks —
/// e.g. macOS's `/tmp` -> `/private/tmp`, or a symlinked home directory).
///
/// `pub(crate)` — used by [`crate::audit::op_emit::redact_reason`] so an
/// `io::Error`'s `Display` chain that embeds the OS-RESOLVED path (which
/// does not literally match `$HOME`) is still caught. Returns `None` when
/// unset, not valid UTF-8, or the canonicalize call itself fails (a
/// nonexistent home directory, permission denied) — callers fall back to
/// the literal-`$HOME` pass alone rather than erroring.
pub(crate) fn canonical_home_string() -> Option<String> {
    let home = resolved_home_string()?;
    std::fs::canonicalize(&home)
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
}

/// The shared boundary-safe matching loop behind [`redact_home_anywhere`]:
/// replaces every occurrence of `needle` found anywhere in `s` with `~`
/// (exact match) or `~/` (followed by a path separator), leaving a
/// needle that is merely a PREFIX of a longer path component (e.g. `needle`
/// = `/Users/jack` against `/Users/jackson`) untouched, so a name collision
/// never corrupts unrelated text.
///
/// Trims trailing path separators off `needle` before matching (so a
/// caller passing e.g. `$HOME=/root/` still matches `/root/.nvm/node`
/// correctly) and does NOTHING — returns `s` unchanged — when the trimmed
/// needle is empty. This is what makes a degenerate needle (an unset home
/// directory, or `HOME=/`, whose only separator IS the trailing one) safe:
/// `"/".trim_end_matches(is_path_sep)` is `""`, and an empty needle would
/// otherwise match at every byte offset, replacing every path separator in
/// `s` with `~/` and destroying it — the return-unchanged guard is load-
/// bearing, not defensive.
///
/// `pub(crate)` — the second call site is
/// [`crate::audit::op_emit::redact_reason`]'s canonical-`$HOME` pass.
pub(crate) fn redact_needle_anywhere(s: &str, needle: &str) -> String {
    let needle_trimmed = needle.trim_end_matches(is_path_sep);
    if needle_trimmed.is_empty() {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find(needle_trimmed) {
        let (before, after_match) = rest.split_at(idx);
        let after = &after_match[needle_trimmed.len()..];
        out.push_str(before);
        // Item 7 (S-LOW-2): the RIGHT-boundary check below (`after` is
        // empty or starts with a separator) was the only boundary this
        // function checked. A genuine absolute-path needle (every real
        // needle here: `$HOME` or its canonicalized form) starts with its
        // OWN leading separator, so requiring the PRECEDING byte to
        // ALSO be a separator is too strict — it would reject the
        // overwhelmingly common case of a path appearing after plain
        // prose ("failed to write /Users/jack/x", preceded by a space).
        // The genuine hazard is narrower: the preceding byte is an
        // ALPHANUMERIC character, which would make the match a SUFFIX of
        // a longer, unrelated identifier with no separator of its own
        // between the two (e.g. `needle` = `Users/jack` recurring inside
        // `DataUsers/jack` — right after `Data`, no separator, a real
        // word-boundary violation). Whitespace, punctuation, another
        // separator, or the start of the string are all safe left
        // boundaries; only "looks like the same contiguous word/path
        // component" is not. (`out`'s last char is checked, not just this
        // iteration's `before`, so a boundary carried over from a prior
        // non-matching iteration is still seen correctly.)
        let left_ok = !matches!(out.chars().last(), Some(c) if c.is_alphanumeric());
        if !left_ok {
            // Same non-boundary handling as the right-boundary "keep and
            // resume" branch below: not a real match, make forward
            // progress without touching the text.
            out.push_str(needle_trimmed);
            rest = after;
            continue;
        }
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
            out.push_str(needle_trimmed);
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

    /// S-LOW-4: `$HOME` set to a SYMLINK into a real tempdir (mirrors macOS's
    /// `/tmp` -> `/private/tmp`, and any tempdir-backed `$HOME` in a test
    /// harness). A path canonicalized before being formatted into an error
    /// (`std::fs::canonicalize`) carries the RESOLVED target, not the
    /// symlink `$HOME` value — `redact_home_anywhere` must catch that form
    /// too, not just the literal `$HOME` string.
    #[test]
    #[cfg(unix)]
    fn redact_home_anywhere_redacts_canonicalized_symlinked_home() {
        let real_dir = tempfile::tempdir().expect("real tempdir");
        let real_target = real_dir
            .path()
            .canonicalize()
            .expect("canonicalize real dir");
        let parent = real_target
            .parent()
            .expect("tempdir has a parent")
            .to_path_buf();
        let link_name = format!("redact-home-symlink-test-{}", std::process::id());
        let link_path = parent.join(&link_name);
        std::os::unix::fs::symlink(&real_target, &link_path).expect("create symlink");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_home(Some(link_path.to_str().unwrap()), || {
                // The code under test canonicalizes $HOME/subdir before
                // formatting it into an error, which resolves through the
                // symlink to `real_target/subdir` — the exact shape a
                // `std::fs::canonicalize` call on a path under a
                // symlinked $HOME would produce.
                let canonicalized_child = real_target.join("accounts/rotation.json");
                let msg = format!(
                    "invalid JSON in {}: unexpected EOF",
                    canonicalized_child.display()
                );
                let redacted = redact_home_anywhere(&msg);
                assert_eq!(
                    redacted, "invalid JSON in ~/accounts/rotation.json: unexpected EOF",
                    "canonicalized $HOME form must be redacted, not just the literal symlink path"
                );
            });
        }));
        let _ = std::fs::remove_file(&link_path);
        result.expect("test body panicked");
    }

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
        // `resolved_home_string` falls back to USERPROFILE on Windows, so
        // "no home" must clear that too or the fallback answers instead.
        let prior_userprofile = std::env::var_os("USERPROFILE");
        match home {
            Some(h) => std::env::set_var("HOME", h),
            None => {
                std::env::remove_var("HOME");
                if cfg!(windows) {
                    std::env::remove_var("USERPROFILE");
                }
            }
        }
        let out = f();
        match prior {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        match prior_userprofile {
            Some(p) => std::env::set_var("USERPROFILE", p),
            None => std::env::remove_var("USERPROFILE"),
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

    /// S-LOW-A / C-B5 (round 8b): `HOME=/` must be a no-op, never a
    /// destructive replace-every-separator pass. `"/".trim_end_matches(
    /// is_path_sep)` is `""`, and `redact_needle_anywhere`'s empty-needle
    /// guard is what makes this safe — pinning it here at the
    /// `redact_home_anywhere` public entry point, not just on the shared
    /// helper directly.
    #[test]
    fn redact_home_anywhere_is_not_destructive_when_home_is_root() {
        with_home(Some("/"), || {
            let raw = "atomic replace at /var/tmp/a: rename /var/tmp/a.tmp -> /var/tmp/a failed";
            assert_eq!(
                redact_home_anywhere(raw),
                raw,
                "HOME=/ must not corrupt every path separator in the input"
            );
        });
    }

    /// S-LOW-A / C-B5 (round 8b): `canonical_home_string` resolves a
    /// symlinked home directory to its real target, DIFFERENT from the
    /// literal `$HOME` value — the case `redact_reason`'s canonical-home
    /// pass exists to catch (`op_emit::redact_reason`'s test of the same
    /// name covers the full scrub; this pins the resolver alone).
    #[cfg(unix)]
    #[test]
    fn canonical_home_string_resolves_a_symlinked_home_and_differs_from_the_literal() {
        use std::os::unix::fs::symlink;

        let _g = crate::platform::test_env::lock();
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real-home");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("home-link");
        symlink(&real, &link).unwrap();
        let expected = std::fs::canonicalize(&real).unwrap();

        let prior = std::env::var_os("HOME");
        std::env::set_var("HOME", &link);
        let canon = canonical_home_string();
        match prior {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }

        let canon = canon.expect("a real, existing home directory must canonicalize");
        assert_eq!(canon, expected.to_str().unwrap());
        assert_ne!(
            canon,
            link.to_str().unwrap(),
            "canonical form must differ from the literal (symlinked) HOME"
        );
    }

    // ── item 7 (S-LOW-2): a match needs a LEFT boundary too, not only the
    //    right-boundary check this function already had ─────────────────
    //
    // RED — EXECUTED: with the `left_ok` check (and its `if !left_ok`
    // early-continue) removed from `redact_needle_anywhere`, `cargo test
    // -p csq-core --lib \
    // cli_deps::sanitize::tests::redact_needle_anywhere_requires_a_left_boundary_too \
    // -- --exact` failed on the first assertion:
    // `left: "/System/Volumes/Data~/jack/file"
    //  right: "/System/Volumes/DataUsers/jack/file"` — the needle
    // `Users/jack` matched mid-component (right after `Data`, with no
    // separator before it) and was redacted anyway, because only the
    // RIGHT side of the match was ever checked. GREEN with `left_ok`
    // restored.
    #[test]
    fn redact_needle_anywhere_requires_a_left_boundary_too() {
        // `Users/jack` (no leading separator) matches inside
        // `DataUsers/jack` at a position preceded by `a` (the end of
        // `Data`) — a real, right-boundary-confirmed match (`/file`
        // follows) with NO genuine left boundary. Must be left untouched.
        assert_eq!(
            redact_needle_anywhere("/System/Volumes/DataUsers/jack/file", "Users/jack"),
            "/System/Volumes/DataUsers/jack/file",
            "a match with no left boundary (mid-component) must not be redacted"
        );
        // The SAME needle at a genuine left boundary (preceded by `/`,
        // i.e. the start of a real path component) IS redacted.
        assert_eq!(
            redact_needle_anywhere("/System/Volumes/Data/Users/jack/file", "Users/jack"),
            "/System/Volumes/Data/~/file",
            "the same needle at a genuine left boundary must still be redacted"
        );
    }

    /// `canonical_home_string` must not panic or error when `HOME` is
    /// unset — mirrors `redact_home_anywhere`'s unset-HOME contract.
    #[test]
    fn canonical_home_string_returns_none_when_home_is_unset() {
        with_home(None, || {
            assert_eq!(canonical_home_string(), None);
        });
    }
}
