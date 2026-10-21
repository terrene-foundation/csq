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
    SepStyle::native().is_sep(c)
}

/// Which platform's path grammar a redaction pass applies. Production
/// always uses [`SepStyle::native`]; the explicit parameter exists so the
/// Windows grammar (backslash separators, `%5C` encoded separators,
/// ASCII-case-insensitive matching, the `\\?\` verbatim prefix) is unit-
/// testable on every platform by feeding Windows-shaped strings to the
/// pure functions, instead of only on a Windows runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SepStyle {
    Unix,
    Windows,
}

/// The Win32 verbatim-path prefix `std::fs::canonicalize` returns on
/// Windows (`\\?\C:\Users\…`), literal and in `sqlite_uri_path`'s
/// percent-encoded form. `\\?\UNC\` shares the literal prefix; stripping
/// it would leave `UNC\server\…`, which is not the home path, so a strip
/// of that form never produces a matching needle and is harmless.
const VERBATIM_PREFIX: &str = r"\\?\";
const VERBATIM_PREFIX_ENCODED: &str = "%5C%5C%3F%5C";

#[cfg(test)]
thread_local! {
    /// Test-only count of `SepStyle::fold` calls on this thread.
    static FOLD_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl SepStyle {
    fn native() -> Self {
        if cfg!(windows) {
            SepStyle::Windows
        } else {
            SepStyle::Unix
        }
    }

    fn is_sep(self, c: char) -> bool {
        c == '/' || (self == SepStyle::Windows && c == '\\')
    }

    /// Byte length of a path separator at the start of `s` — a literal
    /// separator (1) or a percent-ENCODED one (3: `%2F`, and `%5C` on
    /// Windows only, either hex case) — or `None`. The encoded forms are
    /// needed because `sqlite_uri_path` encodes `\` as `%5C`, so on Windows
    /// the separator FOLLOWING an encoded home needle is itself encoded;
    /// accepting only a literal separator rejected every such match and
    /// leaked the home path (Windows CI, `failing_attach_stderr_never_leaks_
    /// a_home_path_containing_a_space`). `%5C` stays Windows-only for the
    /// same reason `\` does: on Unix it is a filename byte, not a separator.
    ///
    /// `allow_encoded` is true ONLY when the needle itself is percent-encoded
    /// (contains `%`): a plain needle followed by a literal `%2F` (a legal
    /// filename byte sequence, e.g. `/home/jack%2Fx`) is a sibling, not a
    /// path boundary.
    fn sep_len_at(self, s: &str, allow_encoded: bool) -> Option<usize> {
        let first = s.chars().next()?;
        if self.is_sep(first) {
            return Some(1);
        }
        if !allow_encoded {
            return None;
        }
        let enc = s.get(..3)?;
        if enc.eq_ignore_ascii_case("%2F")
            || (self == SepStyle::Windows && enc.eq_ignore_ascii_case("%5C"))
        {
            return Some(3);
        }
        None
    }

    /// A match-folded copy of `s`, byte-for-byte the same length and with the
    /// same char boundaries as `s`, so offsets found in it are valid in `s`
    /// (`None` on Unix, which matches exactly). Windows paths are
    /// case-insensitive (`c:\users\x` and `C:\Users\X` are one directory, as
    /// are `%5c`/`%5C`) and accept `/` for `\`, so the fold lower-cases, maps
    /// `/` to `\` and the encoded `%2F` to `%5C`. Lower-casing is per-char
    /// folding applied PER CHARACTER with one fixed mapping, identical for
    /// text and needle: a char is lower-cased only when its lowercase is a
    /// single char of the same UTF-8 length (`É` -> `é`), else kept as is
    /// (`İ`, Kelvin `K`, `ẞ`). No whole-string fallback, so the two sides
    /// can never pick different modes.
    fn fold(self, s: &str) -> Option<String> {
        if self != SepStyle::Windows {
            return None;
        }
        #[cfg(test)]
        FOLD_CALLS.with(|c| c.set(c.get() + 1));
        let mut base = String::with_capacity(s.len());
        for c in s.chars() {
            let mut it = c.to_lowercase();
            match (it.next(), it.next()) {
                (Some(l), None) if l.len_utf8() == c.len_utf8() => base.push(l),
                _ => base.push(c),
            }
        }
        Some(base.replace('/', "\\").replace("%2f", "%5c"))
    }

    /// `s` with a leading verbatim prefix (literal or encoded) removed, on
    /// Windows only; `None` when there is none.
    fn strip_verbatim(self, s: &str) -> Option<&str> {
        if self != SepStyle::Windows {
            return None;
        }
        s.strip_prefix(VERBATIM_PREFIX).or_else(|| {
            s.get(..VERBATIM_PREFIX_ENCODED.len())
                .filter(|p| p.eq_ignore_ascii_case(VERBATIM_PREFIX_ENCODED))
                .map(|_| &s[VERBATIM_PREFIX_ENCODED.len()..])
        })
    }
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
    redact_home_prefix_with(p, home_str, SepStyle::native())
}

/// The pure core of [`redact_home_prefix`]: `home` and the separator
/// grammar are parameters so the Windows grammar is testable everywhere.
fn redact_home_prefix_with(p: &str, home: &str, style: SepStyle) -> String {
    let home_trimmed = home.trim_end_matches(|c| style.is_sep(c));
    // A verbatim `\\?\` home and a plain path name the same directory (and
    // vice versa): compare both with the prefix removed.
    let home_trimmed = style.strip_verbatim(home_trimmed).unwrap_or(home_trimmed);
    if home_trimmed.is_empty() {
        return p.to_string();
    }
    let p_cmp = style.strip_verbatim(p).unwrap_or(p);
    let head_matches = match style {
        SepStyle::Unix => p_cmp.starts_with(home_trimmed),
        SepStyle::Windows => p_cmp
            .get(..home_trimmed.len())
            .is_some_and(|h| h.eq_ignore_ascii_case(home_trimmed)),
    };
    if head_matches {
        let rest = &p_cmp[home_trimmed.len()..];
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
        if let Some(rest) = rest.strip_prefix(|c| style.is_sep(c)) {
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
    let redacted = match canonical_home_string() {
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
    };
    // T4: also redact the PERCENT-ENCODED form of the literal `$HOME` —
    // `session::shared_state::codex_sqlite::sqlite_uri_path` builds a
    // `file:`-URI form of a path (for a read-only sqlite3 connection) by
    // percent-encoding every byte outside RFC 3986's unreserved set, so a
    // HOME containing a space (or any other reserved character) reaches
    // sqlite3's stderr as `%20`, not a literal space — a needle search for
    // the literal home string would silently miss it. Most home paths have
    // no such bytes, in which case this pass is a no-op equal to the
    // literal one already run above.
    // The CANONICAL home needs the same pass: a symlinked `$HOME` whose
    // target contains a reserved byte surfaces in its resolved, encoded form.
    // Longer needle first, as above.
    let mut raws: Vec<String> = vec![literal.to_string()];
    if let Some(canon) = canonical_home_string() {
        raws.push(canon.trim_end_matches(is_path_sep).to_string());
    }
    // Windows 8.3 short names (`RUNNER~1` for `runneradmin`) name the same
    // directory but are a different string; neither the literal nor the
    // canonical (long-name) needle matches them. The right-boundary check in
    // `redact_one_needle` keeps `RUNNER~1` from eating `RUNNER~10`.
    let shorts: Vec<String> = raws
        .iter()
        .filter_map(|raw| short_path_string(raw))
        .map(|sh| sh.trim_end_matches(is_path_sep).to_string())
        .filter(|sh| !sh.is_empty() && !raws.contains(sh))
        .collect();
    let redacted = shorts
        .iter()
        .fold(redacted, |acc, sh| redact_needle_anywhere(&acc, sh));
    raws.extend(shorts);
    let mut needles: Vec<String> = raws
        .iter()
        .map(|raw| (percent_encode_unreserved(raw), raw))
        .filter(|(enc, raw)| enc != *raw && !enc.is_empty())
        .map(|(enc, _)| enc)
        .collect();
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    needles
        .iter()
        .fold(redacted, |acc, needle| redact_needle_anywhere(&acc, needle))
}

/// The 8.3 short form of `path` from `GetShortPathNameW`, when the OS has
/// one that differs from `path`. `None` on non-Windows, on a failed call
/// (path missing, 8.3 generation disabled) and when the result is identical.
#[cfg(windows)]
pub(crate) fn short_path_string(path: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    // Bounded per-raw-value cache: render paths call this per redaction and
    // the answer is stable for a given home string.
    const CACHE_CAP: usize = 16;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(hit) = guard.get(path) {
            return hit.clone();
        }
    }
    let computed = short_path_string_uncached(path);
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= CACHE_CAP {
            guard.clear();
        }
        guard.insert(path.to_string(), computed.clone());
    }
    computed
}

#[cfg(windows)]
fn short_path_string_uncached(path: &str) -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated and live; `buf` is writable for the
    // `buf.len()` units passed.
    let n =
        unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    // 0 = failure; n >= len = buffer too small (the value is the needed size).
    if n == 0 || n >= buf.len() {
        tracing::debug!(
            error_kind = "short_path_unavailable",
            "8.3 short-name lookup failed"
        );
        return None;
    }
    let short = std::ffi::OsString::from_wide(&buf[..n])
        .into_string()
        .ok()?;
    (short != path).then_some(short)
}

#[cfg(not(windows))]
pub(crate) fn short_path_string(_path: &str) -> Option<String> {
    None
}

/// RFC 3986 unreserved-set percent-encoding, byte-for-byte identical to
/// `session::shared_state::codex_sqlite::sqlite_uri_path`'s scheme (ALPHA /
/// DIGIT / `-` / `.` / `_` / `~` / `/` pass through literally; everything
/// else becomes `%XX`), so the needle this produces matches exactly what
/// that function would have put into a `file:` URI.
fn percent_encode_unreserved(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(*b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
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
    redact_needle_anywhere_with(s, needle, SepStyle::native())
}

/// [`redact_needle_anywhere`] under an explicit separator grammar. On
/// Windows a verbatim (`\\?\`, literal or percent-encoded) needle is ALSO
/// run with the prefix stripped — `canonicalize` returns the verbatim form
/// but most error text carries the plain one — and a plain match that sits
/// right after a verbatim prefix in `s` absorbs that prefix, so neither
/// spelling of the home path survives in either direction.
fn redact_needle_anywhere_with(s: &str, needle: &str, style: SepStyle) -> String {
    let needle_trimmed = needle.trim_end_matches(|c| style.is_sep(c));
    let stripped = style
        .strip_verbatim(needle_trimmed)
        .filter(|n| !n.trim_end_matches(|c| style.is_sep(c)).is_empty());
    // Longer (verbatim) needle first, so the stripped pass never half-
    // rewrites it.
    let once = redact_one_needle(s, needle_trimmed, style);
    match stripped {
        Some(plain) => redact_one_needle(&once, plain, style),
        None => once,
    }
}

fn redact_one_needle(s: &str, needle: &str, style: SepStyle) -> String {
    let needle_trimmed = needle.trim_end_matches(|c| style.is_sep(c));
    if needle_trimmed.is_empty() {
        return s.to_string();
    }

    // Folded ONCE per call; every offset below indexes the folded copy and
    // the original alike (see `SepStyle::fold`), so the walk is linear.
    let folded_s = style.fold(s);
    let folded_needle = style.fold(needle_trimmed);
    let hay: &str = folded_s.as_deref().unwrap_or(s);
    let pat: &str = folded_needle.as_deref().unwrap_or(needle_trimmed);
    let allow_encoded = needle_trimmed.contains('%');

    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(rel) = hay[pos..].find(pat) {
        let idx = pos + rel;
        let before = &s[pos..idx];
        let matched = &s[idx..idx + pat.len()];
        let after = &s[idx + pat.len()..];
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
        //
        // On Windows a verbatim prefix (`\\?\`, literal or `%5C%5C%3F%5C`) or
        // an encoded separator (`%5C`/`%2F`, which end in the alphanumerics
        // `C`/`F`) directly before the match is itself a boundary.
        let left_ok = !matches!(out.chars().last(), Some(c) if c.is_alphanumeric())
            || (style == SepStyle::Windows
                && (ends_with_verbatim_prefix(&out) || ends_with_encoded_sep(&out)));
        if !left_ok {
            // Same non-boundary handling as the right-boundary "keep and
            // resume" branch below: not a real match, make forward
            // progress without touching the text. `matched` (the original
            // bytes), not the needle: Windows matching folds case.
            out.push_str(matched);
            pos = idx + pat.len();
            continue;
        }
        let boundary = if after.is_empty() {
            Some(0)
        } else {
            style.sep_len_at(after, allow_encoded)
        };
        let Some(sep_len) = boundary else {
            // Not a real boundary (e.g. the match is a prefix of a longer
            // component like `/Users/jackson`) — keep the literal text and
            // resume scanning right after it so we make forward progress.
            out.push_str(matched);
            pos = idx + pat.len();
            continue;
        };
        // A plain-form match preceded by a verbatim prefix is the verbatim
        // spelling of the same path: drop the prefix rather than leave a
        // `\\?\~/` stub.
        if style == SepStyle::Windows {
            if let Some(n) = verbatim_prefix_len_at_end(&out) {
                out.truncate(out.len() - n);
            }
        }
        if sep_len == 0 {
            out.push('~');
            pos = s.len();
            break;
        }
        // Separators (literal or `%XX`) are ASCII, so slicing at
        // `sep_len` never splits a multi-byte codepoint.
        out.push_str("~/");
        pos = idx + pat.len() + sep_len;
    }
    out.push_str(&s[pos..]);
    out
}

/// Length of a verbatim prefix (literal or encoded, either hex case) that
/// `s` ends with, if any.
fn verbatim_prefix_len_at_end(s: &str) -> Option<usize> {
    [VERBATIM_PREFIX, VERBATIM_PREFIX_ENCODED]
        .into_iter()
        .find(|prefix| {
            s.len() >= prefix.len()
                && s.is_char_boundary(s.len() - prefix.len())
                && s[s.len() - prefix.len()..].eq_ignore_ascii_case(prefix)
        })
        .map(str::len)
}

fn ends_with_verbatim_prefix(s: &str) -> bool {
    verbatim_prefix_len_at_end(s).is_some()
}

/// `s` ends with an encoded separator, `%5C` or `%2F` in either hex case.
fn ends_with_encoded_sep(s: &str) -> bool {
    s.len() >= 3
        && s.is_char_boundary(s.len() - 3)
        && (s[s.len() - 3..].eq_ignore_ascii_case("%5C")
            || s[s.len() - 3..].eq_ignore_ascii_case("%2F"))
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

    /// L4: the PERCENT-ENCODED form of the CANONICAL home must be redacted
    /// too (a symlinked `$HOME` whose real target contains a space).
    #[test]
    #[cfg(unix)]
    fn redact_home_anywhere_redacts_percent_encoded_canonical_home() {
        let real_dir = tempfile::tempdir().expect("real tempdir");
        let real_target = real_dir
            .path()
            .canonicalize()
            .expect("canonicalize")
            .join("real home");
        std::fs::create_dir(&real_target).expect("mkdir");
        let link_path = real_dir
            .path()
            .canonicalize()
            .unwrap()
            .join(format!("link-home-{}", std::process::id()));
        std::os::unix::fs::symlink(&real_target, &link_path).expect("symlink");

        let encoded_real = percent_encode_unreserved(real_target.to_str().unwrap());
        with_home(Some(link_path.to_str().unwrap()), || {
            let redacted = redact_home_anywhere(&format!("sqlite3: unable to open {encoded_real}"));
            assert!(
                !redacted.contains("real%20home"),
                "percent-encoded canonical home leaked: {redacted}"
            );
            assert!(redacted.contains('~'), "{redacted}");
        });
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

    struct FixtureEnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl FixtureEnvRestore {
        fn capture(keys: &[&'static str]) -> Self {
            Self(
                keys.iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            )
        }
    }
    impl Drop for FixtureEnvRestore {
        fn drop(&mut self) {
            for (key, previous) in self.0.drain(..).rev() {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn with_home<R>(home: Option<&str>, f: impl FnOnce() -> R) -> R {
        // Use the workspace-wide test env mutex (per `rules/testing.md`
        // §4/4b shared-env discipline) so HOME mutation here serializes
        // against sibling modules that also mutate HOME (e.g.
        // `daemon::usage_poller::gemini_oauth::tests`). A module-local
        // mutex would only protect within `cli_deps::sanitize::tests` —
        // round-6 redteam discovery.
        let _g = crate::platform::test_env::lock();
        // Windows fallback is restored on unwind as well as success.
        let _restore = FixtureEnvRestore::capture(&["HOME", "USERPROFILE"]);
        match home {
            Some(h) => std::env::set_var("HOME", h),
            None => {
                std::env::remove_var("HOME");
                if cfg!(windows) {
                    std::env::remove_var("USERPROFILE");
                }
            }
        }
        f()
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

    // ── Windows-grammar redaction, exercised on EVERY platform ────────────
    //
    // These feed Windows-shaped strings to the pure `_with` cores under
    // `SepStyle::Windows`, so a Unix host verifies the Windows grammar too.

    /// The Windows CI leak: `sqlite_uri_path` encodes `\` as `%5C`, so the
    /// separator FOLLOWING the encoded home is itself encoded and the old
    /// literal-only right boundary rejected the match.
    #[test]
    fn windows_encoded_home_followed_by_an_encoded_separator_is_redacted() {
        let home = r"C:\Users\RUNNER~1\AppData\Local\Temp\.tmpAb12\home with space";
        let needle = percent_encode_unreserved(home);
        let msg = format!("unable to open database: file:{needle}%5C.csq-test-x.sqlite?mode=ro");
        let out = redact_needle_anywhere_with(&msg, &needle, SepStyle::Windows);
        assert_eq!(
            out,
            "unable to open database: file:~/.csq-test-x.sqlite?mode=ro"
        );
        // Either hex case, and an encoded forward slash.
        let lower = msg.replace("%5C.csq", "%5c.csq");
        assert_eq!(
            redact_needle_anywhere_with(&lower, &needle, SepStyle::Windows),
            "unable to open database: file:~/.csq-test-x.sqlite?mode=ro"
        );
        let slash = format!("file:{needle}%2Fx");
        assert_eq!(
            redact_needle_anywhere_with(&slash, &needle, SepStyle::Windows),
            "file:~/x"
        );
        // An encoded non-separator after the needle is still a collision.
        let collide = format!("file:{needle}%20two%5Cx");
        assert_eq!(
            redact_needle_anywhere_with(&collide, &needle, SepStyle::Windows),
            collide
        );
    }

    /// On Unix `\` is a filename byte, so `%5C` is NOT a boundary there;
    /// `%2F` (an encoded `/`) is.
    #[test]
    fn unix_encoded_backslash_is_not_a_boundary_but_encoded_slash_is() {
        let needle = percent_encode_unreserved("/home/a b");
        let bs = format!("{needle}%5Cx");
        assert_eq!(
            redact_needle_anywhere_with(&bs, &needle, SepStyle::Unix),
            bs
        );
        let fs = format!("{needle}%2Fx");
        assert_eq!(
            redact_needle_anywhere_with(&fs, &needle, SepStyle::Unix),
            "~/x"
        );
    }

    /// Windows paths are case-insensitive: a lower-case drive letter (or
    /// any ASCII case difference) names the same home directory.
    #[test]
    fn windows_drive_letter_and_ascii_case_differences_are_redacted() {
        let home = r"C:\Users\RUNNER~1";
        assert_eq!(
            redact_needle_anywhere_with(
                r"open c:\users\runner~1\x failed",
                home,
                SepStyle::Windows
            ),
            "open ~/x failed"
        );
        let enc = percent_encode_unreserved(home);
        assert_eq!(
            redact_needle_anywhere_with(
                "file:c%3a%5cUsers%5CRUNNER~1%5cx",
                &enc,
                SepStyle::Windows
            ),
            "file:~/x"
        );
        assert_eq!(
            redact_home_prefix_with(r"c:\USERS\runner~1\x", home, SepStyle::Windows),
            "~/x"
        );
        // Unix keeps exact-case matching.
        assert_eq!(
            redact_needle_anywhere_with("/HOME/jack/x", "/home/jack", SepStyle::Unix),
            "/HOME/jack/x"
        );
    }

    /// `canonicalize` on Windows returns the verbatim `\\?\` form AND the
    /// LONG name (`runneradmin`, not the 8.3 `RUNNER~1`). Each spelling of
    /// the home must be redacted whichever spelling the needle carries.
    #[test]
    fn windows_verbatim_prefix_is_redacted_in_both_directions() {
        let canon = r"\\?\C:\Users\runneradmin\home";
        // Verbatim needle, plain (long-name) text.
        assert_eq!(
            redact_needle_anywhere_with(
                r"read C:\Users\runneradmin\home\a failed",
                canon,
                SepStyle::Windows
            ),
            "read ~/a failed"
        );
        // Plain needle, verbatim text: the prefix is absorbed, no `\\?\~/` stub.
        assert_eq!(
            redact_needle_anywhere_with(
                r"read \\?\C:\Users\runneradmin\home\a",
                r"C:\Users\runneradmin\home",
                SepStyle::Windows
            ),
            "read ~/a"
        );
        // Encoded verbatim needle against encoded plain text.
        let enc = percent_encode_unreserved(canon);
        assert_eq!(
            redact_needle_anywhere_with(
                "file:C%3A%5CUsers%5Crunneradmin%5Chome%5Ca",
                &enc,
                SepStyle::Windows
            ),
            "file:~/a"
        );
        // Prefix redaction: verbatim path, plain home and vice versa.
        assert_eq!(
            redact_home_prefix_with(
                r"\\?\C:\Users\runneradmin\home\a",
                r"C:\Users\runneradmin\home",
                SepStyle::Windows
            ),
            "~/a"
        );
        assert_eq!(
            redact_home_prefix_with(r"C:\Users\runneradmin\home\a", canon, SepStyle::Windows),
            "~/a"
        );
    }

    /// The 8.3 short name and the long name are different strings; the
    /// short-name needle redacts short-name text and leaves an unrelated
    /// long-name sibling alone (the canonical, long-name needle covers it).
    #[test]
    fn windows_short_name_needle_does_not_match_a_longer_component() {
        assert_eq!(
            redact_needle_anywhere_with(
                r"C:\Users\RUNNER~1\x C:\Users\RUNNER~10\y",
                r"C:\Users\RUNNER~1",
                SepStyle::Windows
            ),
            r"~/x C:\Users\RUNNER~10\y"
        );
    }

    #[test]
    fn windows_encoded_verbatim_prefix_is_absorbed_with_no_stub() {
        let needle = "C%3A%5CUsers%5Cjack";
        let text = "file:%5C%5C%3F%5CC%3A%5CUsers%5Cjack%5Cx";
        assert_eq!(
            redact_needle_anywhere_with(text, needle, SepStyle::Windows),
            "file:~/x"
        );
        // Literal prefix, plain needle, same absorb.
        assert_eq!(
            redact_needle_anywhere_with(
                r"\\?\C:\Users\jack\x",
                r"C:\Users\jack",
                SepStyle::Windows
            ),
            "~/x"
        );
    }

    #[test]
    fn windows_forward_slashes_in_the_home_path_are_redacted() {
        let home = r"C:\Users\x";
        assert_eq!(
            redact_needle_anywhere_with("open C:/Users/x/a.txt", home, SepStyle::Windows),
            "open ~/a.txt"
        );
        let enc = percent_encode_unreserved(home);
        assert_eq!(
            redact_needle_anywhere_with("file:C%3A%2FUsers%2Fx%2Fa", &enc, SepStyle::Windows),
            "file:~/a"
        );
        // Mixed separators and a collision stay correct.
        assert_eq!(
            redact_needle_anywhere_with("C:/Users/xy/a", home, SepStyle::Windows),
            "C:/Users/xy/a"
        );
    }

    #[test]
    fn plain_needle_does_not_treat_a_literal_encoded_separator_as_a_boundary() {
        for style in [SepStyle::Unix, SepStyle::Windows] {
            let (needle, text) = if style == SepStyle::Unix {
                ("/home/jack", "/home/jack%2Fx /home/jack%5Cx")
            } else {
                (r"C:\home\jack", r"C:\home\jack%2Fx C:\home\jack%5Cx")
            };
            assert_eq!(
                redact_needle_anywhere_with(text, needle, style),
                text,
                "{style:?}"
            );
        }
    }

    #[test]
    fn windows_non_ascii_case_folds_when_length_preserving() {
        assert_eq!(
            redact_needle_anywhere_with(
                r"open C:\Users\JOSÉ\x",
                r"C:\Users\josé",
                SepStyle::Windows
            ),
            "open ~/x"
        );
        assert_eq!(
            redact_needle_anywhere_with(
                r"open c:\users\josé\x",
                r"C:\Users\JOSÉ",
                SepStyle::Windows
            ),
            "open ~/x"
        );
        // Unix stays exact.
        assert_eq!(
            redact_needle_anywhere_with("/home/JOSÉ/x", "/home/josé", SepStyle::Unix),
            "/home/JOSÉ/x"
        );
        // A length-changing char elsewhere falls back to ASCII folding and
        // must not panic or misalign offsets.
        assert_eq!(
            redact_needle_anywhere_with(
                "İ C:\\Users\\JACK\\x",
                r"C:\Users\jack",
                SepStyle::Windows
            ),
            "İ ~/x"
        );
    }

    #[test]
    fn windows_matching_is_linear_in_repeated_hits() {
        let text = r"C:\h\a ".repeat(20_000);
        let out = redact_needle_anywhere_with(&text, r"C:\h", SepStyle::Windows);
        assert_eq!(out, "~/a ".repeat(20_000));
    }

    /// Exactly two folds per `redact_one_needle` call (text once, needle
    /// once) however many hits there are. RED against a re-fold-per-hit
    /// mutation: the count then scales with the hit count.
    #[test]
    fn windows_fold_runs_once_per_side_per_needle_call() {
        let text = r"C:\h\a ".repeat(50);
        FOLD_CALLS.with(|c| c.set(0));
        let out = redact_one_needle(&text, r"C:\h", SepStyle::Windows);
        assert_eq!(out, "~/a ".repeat(50));
        assert_eq!(FOLD_CALLS.with(|c| c.get()), 2);
    }

    /// Item 1: needle and text share one per-char mapping, so a text char
    /// whose lowercase changes length can never disable folding for the
    /// needle (`İ`, Kelvin `K`, `ẞ`).
    #[test]
    fn windows_fold_is_one_per_char_mapping_for_text_and_needle() {
        for text in [
            "İ C:\\Users\\JOSÉ\\x",
            "\u{212A} C:\\Users\\JOSÉ\\x",
            "ẞ c:\\users\\josé\\x",
            "Ω c:\\USERS\\JOSÉ\\x",
        ] {
            let out = redact_needle_anywhere_with(text, "C:\\Users\\JOSÉ", SepStyle::Windows);
            assert!(!out.to_lowercase().contains("jos"), "leaked: {out}");
            assert!(out.ends_with("~/x"), "{out}");
        }
    }

    /// 8.3 helper is inert off Windows (no fabricated needle).
    #[cfg(not(windows))]
    #[test]
    fn short_path_string_is_none_off_windows() {
        assert_eq!(short_path_string("/tmp"), None);
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
