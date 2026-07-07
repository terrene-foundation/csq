//! `csq-redact` — token redaction + the [`RedactedString`] newtype.
//!
//! This is the community (Apache-2.0) leaf crate that both csq editions and the
//! public `csq-sdk` crate depend on for secret redaction. It holds two things,
//! extracted verbatim from `csq-core` (W1 of the SDK-crate plan,
//! `internal-design-docs`):
//!
//! - [`redact_tokens`] (+ [`redact_excerpt`], [`redact_pem_blocks`]) — the
//!   fixed-vocabulary secret scrubber specified in
//!   `csq-core`'s `specs/19-direct-api-security-prerequisites.md`. Pure `std`;
//!   no csq-core dependency.
//! - [`RedactedString`] — the newtype whose only untrusted constructor routes
//!   through [`redact_tokens`], so an error variant carrying an operator-facing
//!   message cannot be built from raw token-bearing bytes (`rules/security.md`
//!   §2 — structural, not docstring-discipline, defense).
//!
//! `csq-core` re-exports every item from here (`crate::error::redact_tokens`,
//! `crate::audit::types::RedactedString`) so the ~540 existing callsites are
//! unchanged. New code — notably `csq-sdk` — depends on this crate directly.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Returns true if `c` is a valid API-key body character.
#[inline]
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Returns true if `c` is a valid hex digit.
#[inline]
fn is_hex_char(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// Known OAuth token prefixes that are ALWAYS redacted regardless of body length.
///
/// These are credential prefixes: any occurrence is a real token. The variable
/// body portion may be short in test inputs (e.g. `LEAKED`), so we must not
/// apply a minimum-length guard to them.
///
/// `ya29.` — Google OAuth2 access tokens issued by `gemini auth login`
/// for Code Assist subscriptions. Format is `ya29.<base64url body with
/// dots>`. Added in Stage 2 / Phase B' of an internal journal entry per redteam
/// round 1: serde_json error Display + tracing `%e` formatting echoed
/// fragments of malformed `oauth_creds.json`, and Google tokens use
/// `.` as a body separator which `is_key_char` does not include —
/// so the matcher captures the leading body chunk only, but that is
/// enough to render the token unusable while still keeping the
/// telemetry diagnostic.
const KNOWN_TOKEN_PREFIXES: &[&str] = &["sk-ant-oat01-", "sk-ant-ort01-", "ya29.", "1//"];

/// Prefix-with-minimum-body token classes.
///
/// Each entry is `(prefix, min_body_chars)`. A token matches when the prefix
/// appears in the input AND is followed by at least `min_body_chars` valid
/// key-body characters (`[A-Za-z0-9\-_]`). The threshold avoids false
/// positives on short strings that happen to start with a matching prefix
/// (e.g. `rt_queue_size`, `sk-dev`).
///
/// - `sk-*` (≥20 body) — Anthropic API keys `sk-ant-api03-*`, Z.AI, MiniMax,
///   and other OpenAI-style providers.
/// - `sess-*` (≥20 body) — OpenAI session-cookie format (reserved; not
///   observed in auth.json but present in other OpenAI surfaces per
///   redteam H6 / PR-C00 plan §3.3).
/// - `rt_*` (≥20 body) — Codex refresh tokens. Observed in live
///   `~/.codex/auth.json` post PR-C00 re-login (an internal journal entry): 90-char
///   total length, `rt_` prefix + 87-char base64url body.
///
/// - `AIza*` (≥30 body) — Google AI Studio API keys. Observed shape is
///   `AIza` + 35 base64url body chars (39 total). The 30-char floor
///   distinguishes a real key from short test fixtures while still
///   matching legitimate keys; Google's documented format does not vary
///   the length so a tighter floor is safe. Added by PR-G2a per the
///   security-reviewer hook-error-leakage inventory (§5).
const TOKEN_PREFIXES_WITH_BODY: &[(&str, usize)] =
    &[("sk-", 20), ("sess-", 20), ("rt_", 20), ("AIza", 30)];

/// Minimum length of each JWT segment's body after its header prefix.
///
/// Real-world JWTs (OpenAI id_token / access_token observed in
/// `~/.codex/auth.json` per an internal journal entry) have segments hundreds of chars
/// long. 17 is a safe floor — any JWT shorter than 20 chars per segment is
/// not a real token and is unlikely to survive upstream verification.
const JWT_SEGMENT_MIN_BODY: usize = 17;

/// Replaces token-like strings with `[REDACTED]`.
///
/// Five patterns are covered (the API-key custody + redaction contract
/// is specified in `specs/19-direct-api-security-prerequisites.md`):
///
/// 0. **Credential-context** — an opaque credential of more than 8 chars
///    following a credential marker: the `Bearer ` scheme (RFC 6750 §2.1)
///    OR a field marker (`x-api-key`, `x-goog-api-key`, `api_key`,
///    `api-key`, `apikey`, `authorization`) in HTTP-header or JSON
///    value position. Catches generic 3P keys that carry no known prefix
///    and are not hex/JWT (e.g. a Z.AI `<id>.<secret>` key in a 4xx
///    body). The marker + separator text is preserved.
///
/// 1. **Known OAuth prefixes** (`sk-ant-oat01-`, `sk-ant-ort01-`): always
///    redacted, regardless of body length.  These are Anthropic OAuth
///    access/refresh token prefixes; any occurrence in a string is a real
///    credential.
///
/// 2. **Prefix-with-body tokens** — prefixes in [`TOKEN_PREFIXES_WITH_BODY`]
///    followed by at least the class's minimum body length. Covers `sk-*`
///    (Anthropic + 3P API keys), `sess-*` (OpenAI session tokens), and `rt_*`
///    (Codex refresh tokens). Short strings like `sk-short` or `rt_queue_size`
///    are left intact.
///
/// 3. **Long bare hex strings** — ≥32 consecutive hex digits (`[0-9a-fA-F]`).
///    Covers 3P API keys that are raw 128-bit (32-char) or longer hex tokens.
///    Shorter runs (e.g. git SHAs in log messages, short error codes) are left
///    intact.
///
/// 4. **JWT triple-segment** — `eyJ<b64url>+.eyJ<b64url>+.<b64url>+` where
///    each segment body is ≥[`JWT_SEGMENT_MIN_BODY`] chars. Covers OpenAI
///    Codex access_token and id_token (both JWTs per an internal journal entry live
///    capture). The `eyJ` prefix is the base64url encoding of `{"` — any
///    JWT header or payload opens with a JSON object and therefore this
///    prefix. The three-segment `.`-delimited structure pins the match to
///    actual JWTs.
///
/// Exposed `pub` so modules outside this file can redact user-facing
/// error strings before they reach tracing, the IPC cache, or error
/// messages. Used by `credentials::refresh` to scrub serde_json parse
/// errors that may echo a fragment of the OAuth form body on
/// malformed response bodies.
pub fn redact_tokens(s: &str) -> String {
    redact_tokens_inner(s)
}

/// Redact-then-truncate a response body excerpt to at most `cap` chars.
///
/// Token-leak defense: redacts BEFORE truncation so a token that
/// straddles the `cap` boundary cannot escape the regex (round-1
/// redteam H1-sec). Used by every probe cell that surfaces a
/// `redacted_response_excerpt` on FAIL.
///
/// `cap` is in chars (not bytes); the typical caller passes 256.
pub fn redact_excerpt(body: &[u8], cap: usize) -> String {
    let s = String::from_utf8_lossy(body);
    let redacted = redact_tokens(&s);
    redacted.chars().take(cap).collect()
}

fn redact_tokens_inner(s: &str) -> String {
    // Minimum length of a bare hex run treated as a secret.
    const HEX_MIN_LEN: usize = 32;

    // Pre-process: collapse any PEM block to `[REDACTED]` BEFORE the
    // per-char scan. PEM blocks span multiple lines; the per-char loop
    // below cannot detect them in one pass without significant rework.
    // Vertex SA JSON contains a `private_key` field whose value is a
    // PEM block; logging that field with `format!("{e}")` would leak
    // the private key end-to-end. Added by PR-G2a per security-reviewer
    // §5 ("Vertex SA path" row).
    let pem_stripped = redact_pem_blocks(s);
    let s = pem_stripped.as_str();

    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;

    // Build a lightweight view back into a str position for prefix matching.
    // We keep a parallel byte offset so we can use `str::find` on slices.
    // Since all key chars are ASCII, char index == byte index for the spans we
    // examine — but we use `char` iteration to be safe with the rest of the
    // string.
    let bytes = s.as_bytes();
    // Byte offset corresponding to chars[i].
    // We maintain this separately because chars may be multi-byte.
    let char_byte_offsets: Vec<usize> = s
        .char_indices()
        .map(|(byte_pos, _)| byte_pos)
        .chain(std::iter::once(s.len()))
        .collect();

    while i < len {
        let byte_i = char_byte_offsets[i];
        // Word-boundary guard: prefix patterns (1, 2, 4) only match when the
        // preceding char is NOT a key-body char. Prevents false positives
        // where a prefix string appears mid-word (e.g. `rt_` inside
        // `signature_part_long_enough_to_match`).
        let word_boundary = i == 0 || !is_key_char(chars[i - 1]);

        // --- Pattern 0: credential-context redaction (M1-PRE / spec 19) ---
        // Generic catch-all for opaque credentials that carry no known
        // shape prefix (`sk-`, `sess-`, `rt_`, `AIza`), are not pure hex,
        // and are not JWTs — e.g. a Z.AI `<id>.<secret>` key echoed in an
        // upstream 4xx body. Keyed on a credential CONTEXT marker so the
        // false-positive surface stays narrow. Two marker forms:
        //   - scheme form  — `Bearer <token>` (RFC 6750 §2.1); the token
        //     starts immediately after the trailing space.
        //   - field form   — `x-api-key: <tok>`, `"api_key":"<tok>"`,
        //     `authorization: <tok>` (HTTP-header OR JSON value position);
        //     the token starts after a run of separators (`:="' \t`).
        // A token of more than `CRED_CONTEXT_MIN_BODY` chars immediately
        // following a marker is redacted; the marker + separator text is
        // preserved verbatim, only the credential is replaced. Match is
        // case-insensitive on the marker. Runs BEFORE the shape patterns
        // so it backstops keys whose shape no prefix/hex/JWT pattern
        // recognizes. Bare generic words (`key`, `token`, `secret`,
        // `password`) are deliberately EXCLUDED — too high a
        // false-positive rate in prose; only the high-confidence
        // API-key/authorization markers are matched. Added by M1-PRE per
        // security-reviewer R1 (Pattern-0 generic-key false-negative for
        // keys echoed without a `Bearer ` scheme).
        let mut matched_cred_ctx = false;
        if word_boundary {
            const CRED_CONTEXT_MIN_BODY: usize = 8;
            // Separators between a field marker and its value.
            #[inline]
            fn is_cred_sep(c: char) -> bool {
                matches!(c, ':' | '=' | '"' | '\'' | ' ' | '\t')
            }
            // Lowercase markers (all ASCII → byte len == char len). A
            // trailing space marks a scheme form (token starts
            // immediately); otherwise it is a field form (a separator run
            // must follow before the token).
            const CRED_MARKERS: &[&str] = &[
                "bearer ",        // scheme (RFC 6750)
                "x-goog-api-key", // google header (distinct prefix; order not load-bearing)
                "x-api-key",      // anthropic / 3p header
                "api_key",        // json field
                "api-key",        // json / header field
                "apikey",         // json field
                "authorization",  // header / json field
            ];
            for marker in CRED_MARKERS {
                let mlen = marker.len();
                if s.get(byte_i..byte_i + mlen)
                    .map(|w| w.eq_ignore_ascii_case(marker))
                    != Some(true)
                {
                    continue;
                }
                let after_marker = i + marker.chars().count();
                let tok_start = if marker.ends_with(' ') {
                    after_marker // scheme: token starts right after the space
                } else {
                    // Field form: a separator MUST follow the marker word
                    // (else `api_keyX` / `authorization_id` is not a field).
                    if after_marker >= len || !is_cred_sep(chars[after_marker]) {
                        continue;
                    }
                    let mut sp = after_marker;
                    while sp < len && is_cred_sep(chars[sp]) {
                        sp += 1;
                    }
                    sp
                };
                let mut j = tok_start;
                // Consume the credential up to the first whitespace or
                // quote (covers base64url `+/=`, dotted JWT/`ya29.` bodies,
                // `-`/`_`); trailing prose survives.
                while j < len && !chars[j].is_whitespace() && !matches!(chars[j], '"' | '\'' | '`')
                {
                    j += 1;
                }
                if j - tok_start > CRED_CONTEXT_MIN_BODY {
                    // Preserve the marker + separator bytes verbatim.
                    out.push_str(&s[byte_i..char_byte_offsets[tok_start]]);
                    out.push_str("[REDACTED]");
                    i = j;
                    matched_cred_ctx = true;
                }
                break; // this marker owns the position
            }
        }
        if matched_cred_ctx {
            continue;
        }

        // --- Pattern 1: known OAuth token prefixes (always redact) ---
        // SAFETY: use `s.get(...)` (Option-returning) instead of
        // `&s[..]` (panicking) because `byte_i + plen` may land
        // inside a multibyte UTF-8 character, e.g. when the input
        // contains an em-dash and plen extends across it. Observed
        // live as a panic during codex login error formatting:
        // "end byte index 110 is not a char boundary; it is inside
        // '—' (bytes 109..112) of ...". Pre-existing bug (was there
        // since redact_tokens was first written); surfaced when the
        // codex spawn-failure error string flowed through redaction.
        let mut matched_known = false;
        if word_boundary {
            for prefix in KNOWN_TOKEN_PREFIXES {
                let plen = prefix.len();
                if s.get(byte_i..byte_i + plen) == Some(*prefix) {
                    // Consume until a delimiter or end of string.
                    let mut j = i + prefix.chars().count();
                    while j < len && is_key_char(chars[j]) {
                        j += 1;
                    }
                    out.push_str("[REDACTED]");
                    i = j;
                    matched_known = true;
                    break;
                }
            }
        }
        if matched_known {
            continue;
        }

        // --- Pattern 1.5: truncated sk- + hex echoes (security review HIGH-2) ---
        // Some 3P bridges echo a TRUNCATED prefix of the API key in
        // 4xx response bodies — observed: `Invalid: sk-1db4356…`. The
        // full key (32+ hex body) is caught by Pattern 2's 20-char
        // floor, but a truncated 4-19 hex run slips past. Pure-hex
        // body distinguishes a real (truncated) DeepSeek-style key
        // from test fixtures like `sk-test`, `sk-dev`, `sk-prod`.
        // 4-char floor avoids false positives on `sk-1` random
        // strings while catching anything that could leak meaningful
        // key material.
        let mut matched_truncated_sk = false;
        if word_boundary && s.get(byte_i..byte_i + 3) == Some("sk-") {
            let body_start = i + 3;
            let mut j = body_start;
            while j < len && is_key_char(chars[j]) {
                j += 1;
            }
            let body_len = j - body_start;
            let all_hex = body_len > 0 && (body_start..j).all(|k| chars[k].is_ascii_hexdigit());
            if all_hex && (4..20).contains(&body_len) {
                out.push_str("[REDACTED]");
                i = j;
                matched_truncated_sk = true;
            }
        }
        if matched_truncated_sk {
            continue;
        }

        // --- Pattern 2: prefix-with-body tokens (sk-*, sess-*, rt_*) ---
        let mut matched_prefixed = false;
        if word_boundary {
            for (prefix, min_body) in TOKEN_PREFIXES_WITH_BODY {
                let plen_bytes = prefix.len();
                let plen_chars = prefix.chars().count();
                // SAFETY: see Pattern 1 — must use `get` to avoid
                // panicking when `plen_bytes` crosses a multibyte
                // char boundary in the input.
                if s.get(byte_i..byte_i + plen_bytes) != Some(*prefix) {
                    continue;
                }
                let mut j = i + plen_chars;
                while j < len && is_key_char(chars[j]) {
                    j += 1;
                }
                let body_len = j - (i + plen_chars);
                if body_len >= *min_body {
                    out.push_str("[REDACTED]");
                    i = j;
                    matched_prefixed = true;
                    break;
                }
            }
        }
        if matched_prefixed {
            continue;
        }

        // --- Pattern 4: JWT triple-segment (`eyJ<b64url>+.eyJ<b64url>+.<b64url>+`) ---
        // Three base64url segments separated by dots; each segment body
        // must be ≥ JWT_SEGMENT_MIN_BODY chars. Placed BEFORE hex because
        // an `eyJ...` prefix would otherwise be partially consumed by the
        // hex-match (first char `e` is a valid hex digit).
        if word_boundary
            && i + 3 <= len
            && chars[i] == 'e'
            && chars[i + 1] == 'y'
            && chars[i + 2] == 'J'
        {
            let seg1_body_start = i + 3;
            let mut j = seg1_body_start;
            while j < len && is_key_char(chars[j]) {
                j += 1;
            }
            let seg1_body_len = j - seg1_body_start;
            // Must have first dot AND second `eyJ` AND body length.
            if seg1_body_len >= JWT_SEGMENT_MIN_BODY
                && j < len
                && chars[j] == '.'
                && j + 4 <= len
                && chars[j + 1] == 'e'
                && chars[j + 2] == 'y'
                && chars[j + 3] == 'J'
            {
                let seg2_body_start = j + 4;
                let mut k = seg2_body_start;
                while k < len && is_key_char(chars[k]) {
                    k += 1;
                }
                let seg2_body_len = k - seg2_body_start;
                if seg2_body_len >= JWT_SEGMENT_MIN_BODY && k < len && chars[k] == '.' {
                    let seg3_start = k + 1;
                    let mut m = seg3_start;
                    while m < len && is_key_char(chars[m]) {
                        m += 1;
                    }
                    let seg3_len = m - seg3_start;
                    if seg3_len >= JWT_SEGMENT_MIN_BODY + 3 {
                        out.push_str("[REDACTED]");
                        i = m;
                        continue;
                    }
                }
            }
        }

        // --- Pattern 3: long bare hex string ---
        // Only enter if bytes[byte_i] is a hex digit to avoid slow scanning.
        if byte_i < bytes.len() && (bytes[byte_i] as char).is_ascii_hexdigit() {
            let mut j = i;
            while j < len && is_hex_char(chars[j]) {
                j += 1;
            }
            let hex_len = j - i;
            if hex_len >= HEX_MIN_LEN {
                out.push_str("[REDACTED]");
                i = j;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

/// Replaces every `-----BEGIN <tag>-----...-----END <tag>-----` block
/// in `s` with `[REDACTED]`. Multi-line aware. The opening and closing
/// dash-strings are NOT redacted on their own — they are common in
/// non-secret contexts (markdown headings, ASCII art) — only the full
/// block with both markers triggers redaction.
///
/// Intentionally permissive on the tag (we accept any `-----BEGIN X-----`
/// for any reasonable X) because PEM types proliferate (`PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY`,
/// `CERTIFICATE`, etc.) and the failure mode is leaking a key, not
/// leaking a certificate.
///
/// Called from [`redact_tokens`] as a pre-processing step. Public so
/// the test module can exercise it directly.
pub fn redact_pem_blocks(s: &str) -> String {
    const BEGIN_MARKER: &str = "-----BEGIN ";
    const END_MARKER: &str = "-----END ";
    if !s.contains(BEGIN_MARKER) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    while cursor < s.len() {
        let rest = &s[cursor..];
        let begin_idx = match rest.find(BEGIN_MARKER) {
            Some(i) => i,
            None => {
                out.push_str(rest);
                break;
            }
        };
        // Emit text before the BEGIN marker as-is.
        out.push_str(&rest[..begin_idx]);
        let after_begin = &rest[begin_idx..];
        // Find the matching END marker after the BEGIN. We accept any
        // line ending after the END tag's `-----`.
        let end_idx = match after_begin.find(END_MARKER) {
            Some(i) => i,
            None => {
                // Unterminated PEM block. Redact the rest defensively
                // — half a private key is still half too much in a log.
                out.push_str("[REDACTED]");
                break;
            }
        };
        // Advance past the END marker AND the closing `-----` and the
        // line break (if any) so the trailing dashes don't leak.
        let after_end = &after_begin[end_idx + END_MARKER.len()..];
        let close_dash_idx = after_end.find("-----");
        let consumed_after_end = match close_dash_idx {
            Some(i) => i + 5, // length of "-----"
            None => after_end.len(),
        };
        out.push_str("[REDACTED]");
        cursor += begin_idx + end_idx + END_MARKER.len() + consumed_after_end;
    }
    out
}

/// Operator-facing error message that is structurally guaranteed to
/// have been routed through [`redact_tokens`] before construction.
///
/// Per `rules/security.md` §2: relying on "callers must redact"
/// docstring discipline is exactly the failure pattern token leaks
/// reproduce. This newtype's only constructor — [`Self::from_untrusted`]
/// — runs redaction on every input, so error variants that carry an
/// operator-facing message cannot be constructed with raw token-bearing
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedString(String);

impl RedactedString {
    /// Wraps `s` after running [`redact_tokens`] on it. Use this for
    /// any string crossing from an external source (HTTP body, sink
    /// response, OS error) into an operator-facing error variant.
    pub fn from_untrusted(s: impl AsRef<str>) -> Self {
        Self(redact_tokens(s.as_ref()))
    }

    /// Wraps `s` WITHOUT redaction. Use ONLY for strings whose
    /// provenance is fully under csq control and contains no
    /// secret-derivable content (e.g. const error labels).
    pub fn from_trusted(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the redacted string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RedactedString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RedactedString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Deserialization re-redacts so round-tripping a tampered file
        // is also safe — the on-disk shape is post-redaction, but a
        // forged file with raw tokens still passes through redact.
        let s = String::deserialize(d)?;
        Ok(Self::from_untrusted(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- redact_tokens ---

    #[test]
    fn redact_tokens_oat01_prefix() {
        // Arrange
        let input = "token=sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "token=[REDACTED]");
    }

    #[test]
    fn redact_tokens_ort01_prefix() {
        // Arrange
        let input = "refresh=sk-ant-ort01-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "refresh=[REDACTED]");
    }

    /// Stage 2 / Phase B' of an internal journal entry: Google OAuth2 access
    /// tokens issued by `gemini auth login` start with `ya29.` then a
    /// dot-delimited base64url body. The redactor catches the prefix
    /// plus the leading body chunk; that is enough to render the
    /// token unusable while still keeping the surrounding error
    /// telemetry diagnostic.
    #[test]
    fn redact_tokens_google_ya29_prefix() {
        let input = "bearer=ya29.a0Ae_FAKE_token_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let output = redact_tokens(input);
        // `is_key_char` doesn't include `.`, so redaction captures
        // ya29. + the first dot-delimited segment (which contains the
        // bearer-relevant entropy). Subsequent `.<seg>` chunks remain
        // but are not credentials standalone.
        assert!(output.starts_with("bearer=[REDACTED]"), "got: {output}");
        assert!(
            !output.contains("ya29.a0Ae_FAKE_token"),
            "leading body must be redacted: {output}"
        );
    }

    /// Even a short body with the `ya29.` prefix is redacted —
    /// KNOWN_TOKEN_PREFIXES applies regardless of body length.
    #[test]
    fn redact_tokens_google_ya29_short_body() {
        let input = "{\"access_token\":\"ya29.x\"}";
        let output = redact_tokens(input);
        assert!(
            !output.contains("ya29.x"),
            "short ya29.* must redact: {output}"
        );
    }

    #[test]
    fn redact_tokens_anthropic_api_key() {
        // Arrange – sk-ant-api03-* style (Anthropic API keys, not OAuth tokens)
        let input = "key=sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "key=[REDACTED]");
    }

    #[test]
    fn redact_tokens_generic_sk_key() {
        // Arrange – generic long sk-* key (e.g. Z.AI, MiniMax, OpenAI-style)
        let input = "Authorization: Bearer sk-proj-FAKEKEYTESTDONOTUSE0000000000000";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "Authorization: Bearer [REDACTED]");
    }

    /// M1-PRE: OpenAI `sk-proj-*` API keys. Covered by the `sk-` (≥20
    /// body) prefix pattern; this test pins that coverage explicitly so
    /// a future refactor of `TOKEN_PREFIXES_WITH_BODY` cannot silently
    /// drop OpenAI keys.
    #[test]
    fn redact_tokens_openai_sk_proj_key() {
        let input = "key=sk-proj-FAKEKEYTESTDONOTUSE0000000000000";
        let output = redact_tokens(input);
        assert_eq!(output, "key=[REDACTED]");
    }

    /// M1-PRE (security-reviewer R1): a generic opaque bearer token with
    /// no known prefix, not pure hex, not a JWT — the gap the
    /// credential-context Pattern 0 closes. Without Pattern 0 this string
    /// passes through every prefix/hex/JWT pattern untouched.
    #[test]
    fn redact_tokens_generic_bearer_opaque() {
        // Opaque mixed-case alnum+underscore body; starts with 'X'
        // (not a hex digit), no sk-/sess-/rt_/AIza prefix, no eyJ JWT
        // header — uncatchable by Patterns 1-4.
        let input = "Authorization: Bearer Xq9_zP2mWv8Lr4Tn6Ks1Bd3Hf5Gj7Yc0Aa2Ee4Uu6";
        let output = redact_tokens(input);
        assert_eq!(output, "Authorization: Bearer [REDACTED]");
    }

    /// M1-PRE: a short token (≤ the 8-char floor) after a credential
    /// marker is NOT redacted — keeps the false-positive surface narrow
    /// (`Bearer none`, `Bearer null`, short opaque codes).
    #[test]
    fn redact_tokens_bearer_short_token_not_redacted() {
        let input = "header Bearer none ok"; // 4-char body, ≤ 8 floor
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// M1-PRE: the >8-char floor boundary — exactly 8 survives, 9 redacts.
    #[test]
    fn redact_tokens_cred_context_floor_boundary() {
        // 8-char body: not redacted.
        assert_eq!(redact_tokens("Bearer abcdefgh end"), "Bearer abcdefgh end");
        // 9-char body: redacted.
        assert_eq!(
            redact_tokens("Bearer abcdefghi end"),
            "Bearer [REDACTED] end"
        );
    }

    /// M1-PRE: scheme match is case-insensitive (`bearer`/`Bearer`/
    /// `BEARER`) but the original scheme bytes are preserved verbatim;
    /// only the credential is redacted.
    #[test]
    fn redact_tokens_bearer_lowercase_scheme_preserved() {
        let input = "authorization: bearer Xq9zP2mWv8Lr4Tn6Ks1Bd3Hf5Gj7Yc0Aa";
        let output = redact_tokens(input);
        assert_eq!(output, "authorization: bearer [REDACTED]");
    }

    /// M1-PRE: Pattern 0 stops at the first delimiter so trailing prose
    /// after the credential survives intact.
    #[test]
    fn redact_tokens_bearer_preserves_trailing_text() {
        let input = "got Bearer Xq9zP2mWv8Lr4Tn6Ks1Bd3Hf5Gj7 then failed";
        let output = redact_tokens(input);
        assert_eq!(output, "got Bearer [REDACTED] then failed");
    }

    /// M1-PRE (security-reviewer R1 HIGH): the load-bearing fix — an
    /// opaque 3P key echoed in a JSON error body in `"api_key":"…"` value
    /// position, with NO `Bearer ` scheme. Before the field-marker
    /// extension this slipped through every shape pattern.
    #[test]
    fn redact_tokens_field_context_api_key_json() {
        let input = r#"{"error":"bad","api_key":"Xq9zP2mWv8Lr4Tn6Ks1Bd3Hf5"}"#;
        let output = redact_tokens(input);
        assert_eq!(output, r#"{"error":"bad","api_key":"[REDACTED]"}"#);
    }

    /// M1-PRE: HTTP-header form `x-api-key: <opaque>` redacts the value.
    #[test]
    fn redact_tokens_field_context_x_api_key_header() {
        let input = "x-api-key: Xq9zP2mWv8Lr4Tn6Ks1Bd3Hf5 (rejected)";
        let output = redact_tokens(input);
        assert_eq!(output, "x-api-key: [REDACTED] (rejected)");
    }

    /// M1-PRE (security-reviewer R1 HIGH): a Z.AI-style `<hex>.<alnum>`
    /// key — the `.` breaks the hex run below the 32-char floor and the
    /// alnum tail has no known prefix, so it is invisible to Patterns
    /// 1-4. The field-marker context (`x-api-key`) is what redacts it.
    #[test]
    fn redact_tokens_zai_style_key_with_field_context() {
        let key = "1a2b3c4d5e6f7a8b9c0d1e2f.AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        // Sanity: bare (no context, no recognizable shape) it is NOT
        // caught — this is the documented residual (spec 19 §19.2), the
        // reason the field-context layer exists.
        let bare = format!("invalid key {key} supplied");
        assert_eq!(
            redact_tokens(&bare),
            bare,
            "bare shapeless key is the residual"
        );
        // With a credential-context marker it IS redacted.
        let ctx = format!("x-api-key: {key}");
        assert_eq!(redact_tokens(&ctx), "x-api-key: [REDACTED]");
    }

    /// M1-PRE: a field marker followed by a NON-separator char (e.g.
    /// `api_keyed`, `authorization_id`) is NOT a field context and does
    /// not redact the following word.
    #[test]
    fn redact_tokens_field_marker_requires_separator() {
        let input = "the api_keyed_handler_function_name was called";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// M1-PRE: over-redaction after a credential marker is INTENTIONAL —
    /// a >8-char non-secret word following `marker + separator` is
    /// redacted (fail-safe: over-redact a log excerpt rather than risk a
    /// leak). This test pins the deliberate tradeoff so a future "fix"
    /// that narrows it (and reintroduces under-redaction) is caught.
    #[test]
    fn redact_tokens_marker_over_redaction_is_intentional() {
        // `pendingreview` (13 chars > 8) after `authorization:` is prose,
        // not a credential — but the conservative redactor masks it.
        assert_eq!(
            redact_tokens("authorization: pendingreview failed"),
            "authorization: [REDACTED] failed"
        );
    }

    #[test]
    fn redact_tokens_short_sk_not_redacted() {
        // Arrange – "sk-" followed by fewer than 20 chars must NOT be redacted
        let input = "error code sk-short (retry)";

        // Act
        let output = redact_tokens(input);

        // Assert – unchanged
        assert_eq!(output, input);
    }

    /// Truncated sk- + hex echoes (security review HIGH-2). Some 3P
    /// bridges echo a partial key in 4xx response bodies. Pattern 1.5
    /// must catch the truncated form even though it's below Pattern
    /// 2's 20-char floor.
    #[test]
    fn redact_tokens_truncated_sk_hex_echo() {
        let cases = [
            ("Invalid: sk-1db4356", "Invalid: [REDACTED]"),
            ("key=sk-abcdef0123 ok", "key=[REDACTED] ok"),
            ("rejected sk-deadbeef", "rejected [REDACTED]"),
            // Boundary: exactly 4 hex chars triggers (the H2 floor).
            ("[ sk-1234 ]", "[ [REDACTED] ]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_tokens(input), expected, "input: {input}");
        }
    }

    /// Regression: `redact_tokens` must not panic on inputs that
    /// contain multibyte UTF-8 characters within a prefix-length
    /// window of the cursor. Observed live as a panic during codex
    /// login error formatting:
    /// "end byte index 110 is not a char boundary; it is inside '—'
    /// (bytes 109..112) of `spawn ... — is codex-cli installed and on
    /// PATH?`". The em-dash is at bytes 109..112; the prefix scan
    /// from byte 97 with plen=13 (KNOWN_TOKEN_PREFIXES) crossed into
    /// the em-dash and panicked. Fix: use `s.get(...)` (Option) on
    /// every prefix slice instead of `&s[..]` (panicking).
    #[test]
    fn redact_tokens_does_not_panic_on_em_dash_in_prefix_window() {
        let input = "spawn `codex login --device-auth`: spawn `codex login --device-auth`: No such file or directory (os error 2) — is codex-cli installed and on PATH?";
        // Must not panic.
        let output = redact_tokens(input);
        // Result: no real tokens in the input, so output should match.
        assert_eq!(output, input);
    }

    /// Pattern 1.5 must NOT trigger on alphabetic-bodied test
    /// fixtures (sk-test, sk-dev, sk-prod). Hex-only check
    /// distinguishes them.
    #[test]
    fn redact_tokens_short_sk_alphabetic_not_redacted() {
        let cases = ["sk-test", "sk-dev", "sk-prod", "sk-stub", "sk-abcz"];
        for input in cases {
            let output = redact_tokens(input);
            assert_eq!(output, input, "input must not redact: {input}");
        }
    }

    #[test]
    fn redact_tokens_long_hex_string() {
        // Arrange – 32-char hex token (e.g. MiniMax / Z.AI API key)
        let input = "x-api-key: abcdef1234567890abcdef1234567890";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "x-api-key: [REDACTED]");
    }

    #[test]
    fn redact_tokens_64_char_hex_string() {
        // Arrange – 64-char hex (SHA-256-sized API key)
        let hex64 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let input = format!("token={hex64}");

        // Act
        let output = redact_tokens(&input);

        // Assert
        assert_eq!(output, "token=[REDACTED]");
    }

    #[test]
    fn redact_tokens_short_hex_not_redacted() {
        // Arrange – 31-char hex run (just under the threshold) must NOT be redacted
        let input = "hash=abcdef1234567890abcdef123456789";

        // Act
        let output = redact_tokens(input);

        // Assert – unchanged (31 hex chars < 32)
        assert_eq!(output, input);
    }

    #[test]
    fn redact_tokens_plain_text_unchanged() {
        // Arrange
        let input = "no secrets here, just a normal log message";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, input);
    }

    #[test]
    fn redact_tokens_mixed_content_preserves_surrounding_text() {
        // Arrange – key appears mid-sentence; text before and after must survive
        let input =
            "failed to POST: x-api-key=sk-minimax-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "failed to POST: x-api-key=[REDACTED] ok");
    }

    #[test]
    fn redact_tokens_multiple_secrets_in_one_string() {
        // Arrange – two independent keys in the same string
        let key1 = "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key2 = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let input = format!("access={key1} refresh={key2}");

        // Act
        let output = redact_tokens(&input);

        // Assert
        assert_eq!(output, "access=[REDACTED] refresh=[REDACTED]");
    }

    #[test]
    fn redact_tokens_empty_string() {
        assert_eq!(redact_tokens(""), "");
    }

    // --- Codex-specific redactor patterns (PR-C0, an internal journal entry) ---

    /// Codex refresh tokens use the `rt_` prefix (observed in
    /// `~/.codex/auth.json` post re-login).
    #[test]
    fn redact_tokens_codex_rt_prefix() {
        let input = "refresh=rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let output = redact_tokens(input);
        assert_eq!(output, "refresh=[REDACTED]");
    }

    /// Short `rt_` strings (e.g. variable names in logs) must NOT be redacted.
    #[test]
    fn redact_tokens_short_rt_not_redacted() {
        let input = "rt_queue_size value exceeded";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: Google AI Studio API keys (`AIza` + 35 chars).
    #[test]
    fn redact_tokens_google_aiza_key() {
        // Google's documented key shape: AIza + 35 base64url chars.
        let input = "x-goog-api-key: AIzaFAKETESTKEYDONOTUSE0000000000000000";
        let output = redact_tokens(input);
        assert_eq!(output, "x-goog-api-key: [REDACTED]");
    }

    /// PR-G2a: short `AIza` strings (under the 30-char body floor)
    /// must NOT be redacted — they are not real keys and matching
    /// them would create false positives in error fixtures and test
    /// data that uses the prefix illustratively.
    #[test]
    fn redact_tokens_short_aiza_not_redacted() {
        let input = "see also AIzaShortNotReal";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: `AIza` mid-word must NOT trigger redaction (word
    /// boundary guard from the existing redactor design).
    #[test]
    fn redact_tokens_aiza_mid_word_not_redacted() {
        let input = "module_AIzaFAKETESTKEYDONOTUSE0000000000000000";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: PEM block (Vertex SA JSON private_key field). One of
    /// the worst leak modes — a stack-trace `format!("{e}")` near a
    /// JSON parse error containing a PEM block would otherwise dump
    /// the entire signing key. Multi-line aware.
    #[test]
    fn redact_tokens_pem_private_key_block() {
        let input = "parse error: \"private_key\": \"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\nAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\\n\"";
        let output = redact_tokens(input);
        assert!(
            output.contains("[REDACTED]"),
            "PEM block must be redacted: {output}"
        );
        assert!(
            !output.contains("MIIEvQIBADANBgkqhkiG"),
            "key body must not appear in output: {output}"
        );
        assert!(
            !output.contains("-----BEGIN"),
            "BEGIN marker must not survive: {output}"
        );
    }

    /// PR-G2a: PEM with the `RSA PRIVATE KEY` tag (legacy format)
    /// must also redact. Permissive tag matching catches every PEM
    /// type without enumerating them.
    #[test]
    fn redact_tokens_pem_rsa_private_key_block() {
        let input = "key: -----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----";
        let output = redact_tokens(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("ABCDEF"));
    }

    /// PR-G2a: an unterminated PEM block — defensive redaction. We
    /// would rather over-redact a malformed log line than leak half
    /// a key.
    #[test]
    fn redact_tokens_pem_unterminated_block_redacted() {
        let input = "leaked: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n[truncated]";
        let output = redact_tokens(input);
        assert!(!output.contains("MIIEvQ"));
        assert!(output.contains("[REDACTED]"));
    }

    /// PR-G2a: text containing "-----BEGIN" without a PAIRED PEM
    /// shape (no END marker AND no tag) should not be aggressively
    /// redacted. This documents the chosen behaviour: presence of
    /// `-----BEGIN ` + space implies an attempted PEM, so we redact;
    /// presence of `------BEGIN` (six dashes) or `-----BEGIN-` (no
    /// space) does not.
    #[test]
    fn redact_tokens_text_without_pem_shape_passes_through() {
        let input = "section -----BEGINNING----- of file";
        let output = redact_tokens(input);
        // The "-----BEGINNING-----" string has no following space
        // after BEGIN, so the BEGIN_MARKER `"-----BEGIN "` does NOT
        // match. Expect pass-through.
        assert_eq!(output, input);
    }

    /// OpenAI `sess-*` session tokens (plan §3.3 prefix).
    #[test]
    fn redact_tokens_codex_sess_prefix() {
        let input = "cookie=sess-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let output = redact_tokens(input);
        assert_eq!(output, "cookie=[REDACTED]");
    }

    /// JWT triple-segment (Codex id_token / access_token format per
    /// an internal journal entry).
    #[test]
    fn redact_tokens_jwt_triple_segment() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abcdefghijklmnopqrstuvwxyz";
        let output = redact_tokens(input);
        assert_eq!(output, "Authorization: Bearer [REDACTED]");
    }

    /// Realistic long JWT (simulates ~2000-char OpenAI id_token).
    #[test]
    fn redact_tokens_long_jwt() {
        let seg1 = "a".repeat(400);
        let seg2 = "b".repeat(400);
        let seg3 = "c".repeat(64);
        let jwt = format!("eyJ{seg1}.eyJ{seg2}.{seg3}");
        let input = format!("token={jwt}");
        let output = redact_tokens(&input);
        assert_eq!(output, "token=[REDACTED]");
    }

    /// Two-segment `eyJ.eyJ` (malformed JWT — no signature) is NOT redacted
    /// via the JWT pattern. It may still trip other patterns (e.g. hex) but
    /// the JWT pattern specifically requires all three segments.
    #[test]
    fn redact_tokens_two_segment_eyj_not_matched_as_jwt() {
        // Use long-but-non-hex body to avoid pattern-3 false match.
        let seg1 = "z".repeat(40);
        let seg2 = "z".repeat(40);
        let input = format!("header=eyJ{seg1}.eyJ{seg2}");
        let output = redact_tokens(&input);
        // Unchanged — no third segment
        assert_eq!(output, input);
    }

    /// Single-segment `eyJ` is NOT redacted — could be any base64url string
    /// that happens to start with `eyJ` (e.g. encoded data in logs).
    #[test]
    fn redact_tokens_single_segment_eyj_not_matched() {
        let input = "prefix=eyJhbGciOiJIUzI1NiJ9 no dots here";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// JWT mid-sentence: surrounding text must survive.
    ///
    /// Uses segment bodies ≥ `JWT_SEGMENT_MIN_BODY` so the pattern fires;
    /// realistic OpenAI id_tokens have seg bodies in the hundreds of chars,
    /// not the test-minimum 17.
    #[test]
    fn redact_tokens_jwt_mid_sentence() {
        let input = "upstream said: eyJhbGciOiJIUzI1NiJ9XXX.eyJpc3MiOiJjc3EifQYYYY.ZZZZsignaturebytesgohere and then more text";
        let output = redact_tokens(input);
        assert_eq!(output, "upstream said: [REDACTED] and then more text");
    }

    /// Multiple distinct token classes in one string redact independently.
    #[test]
    fn redact_tokens_mixed_codex_and_anthropic() {
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(30),
            "b".repeat(30),
            "c".repeat(30)
        );
        let input =
            format!("codex-access={jwt} anthropic-oat=sk-ant-oat01-XXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        let output = redact_tokens(&input);
        assert_eq!(output, "codex-access=[REDACTED] anthropic-oat=[REDACTED]");
    }

    // -- RedactedString ------------------------------------------------------

    #[test]
    fn redacted_string_redacts_tokens() {
        let r = RedactedString::from_untrusted("error containing sk-ant-oat01-leakedtoken-abcdef");
        assert!(!r.as_str().contains("leakedtoken-abcdef"));
    }

    #[test]
    fn redacted_string_passes_clean_through() {
        let r = RedactedString::from_untrusted("ordinary message");
        assert_eq!(r.as_str(), "ordinary message");
    }
}
