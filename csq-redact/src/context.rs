//! Shared credential-context spans; profile-specific value policy stays explicit.
//! Only a <=64-scalar marker is NFKC-folded. Cyrillic а/А are the explicit
//! supported confusables; neither secret values nor the full body are folded.
use crate::chat::{key, run};
#[path = "context_value.rs"]
mod value;
use unicode_normalization::UnicodeNormalization;
use value::{line_end, plausible, quote, rejected_prefix, spaces, value_span, word_value};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ContextProfile {
    Diagnostic,
    Chat,
}
const MARKER_LIMIT: usize = 64;
const QUOTE_LIMIT: usize = 1024;

pub(super) fn escaped_boundary(tail: &[u8]) -> bool {
    matches!(
        tail,
        b"\\u0022" | b"\\u0027" | b"\\u0020" | b"\\u000a" | b"\\u000A"
    )
}
fn ci(s: &str, marker: &str) -> bool {
    s.eq_ignore_ascii_case(marker)
}
fn suffix(s: &str, marker: &str) -> bool {
    s.get(s.len().saturating_sub(marker.len())..)
        .is_some_and(|v| ci(v, marker))
}
fn marker_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '＿' | '－')
}
fn marker(s: &str, i: usize) -> Option<(String, usize)> {
    let mut end = i;
    for (count, (offset, c)) in s[i..].char_indices().enumerate() {
        if !marker_char(c) {
            break;
        }
        if count == MARKER_LIMIT {
            return None;
        }
        end = i + offset + c.len_utf8();
    }
    if end == i {
        return None;
    }
    let folded: String = s[i..end]
        .nfkc()
        .map(|c| match c {
            'а' => 'a',
            'А' => 'A',
            other => other,
        })
        .collect();
    if folded.len() > MARKER_LIMIT * 2 || !folded.is_ascii() {
        return None;
    }
    Some((folded, end))
}
fn threshold(value: &str) -> bool {
    let count = value.chars().count();
    count > 8 || ((4..=8).contains(&count) && value.bytes().any(|v| v.is_ascii_digit()))
}
fn legacy_span(s: &str, end: usize, bearer: bool) -> Option<(usize, usize)> {
    let mut start = end;
    if bearer {
        if s.as_bytes().get(start) != Some(&b' ') {
            return None;
        }
        start += 1;
    } else {
        let separator = |c| matches!(c, ':' | '=' | '"' | '\'' | ' ' | '\t');
        if !s[start..].chars().next().is_some_and(separator) {
            return None;
        }
        while let Some(c) = s[start..].chars().next().filter(|c| separator(*c)) {
            start += c.len_utf8();
        }
    }
    let finish = start
        + s[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`'))
            .unwrap_or(s.len() - start);
    threshold(&s[start..finish]).then_some((start, finish))
}

fn names(name: &str) -> (bool, bool, bool) {
    if ci(name, "public_TOKEN") {
        return (false, false, false);
    }
    let bytes = name.as_bytes();
    let mut begin = 0;
    let mut sensitive = false;
    let mut generic = false;
    let mut last = "";
    for i in 0..=bytes.len() {
        let boundary = i == bytes.len()
            || matches!(bytes[i], b'_' | b'-')
            || (i > begin && bytes[i].is_ascii_uppercase() && bytes[i - 1].is_ascii_lowercase());
        if !boundary {
            continue;
        }
        let part = &name[begin..i];
        if !part.is_empty() {
            last = part;
            sensitive |= [
                "password",
                "passwd",
                "passphrase",
                "secret",
                "token",
                "credential",
                "credentials",
                "auth",
                "apikey",
                "pwd",
            ]
            .iter()
            .any(|m| suffix(part, m));
            generic |= ["key", "pwd", "token"].iter().any(|m| ci(part, m));
            sensitive |= ci(part, "key");
        }
        begin = if i < bytes.len() && matches!(bytes[i], b'_' | b'-') {
            i + 1
        } else {
            i
        };
    }
    let ignored = [
        "id", "name", "type", "path", "file", "count", "size", "len", "url",
    ]
    .iter()
    .any(|m| ci(last, m));
    (
        sensitive && !ignored,
        generic,
        suffix(name, "authorization"),
    )
}
/// Byte spans always refer to the original input, including compatibility markers.
pub(super) fn context(s: &str, i: usize, profile: ContextProfile) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let escaped = profile == ContextProfile::Chat
        && (escaped_boundary(&b[i.saturating_sub(6)..i])
            || (i >= 2 && b[i - 2] == b'\\' && matches!(b[i - 1], b'n' | b'r' | b't')));
    if !escaped
        && s[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return None;
    }
    let (mut name, mut end) = marker(s, i)?;
    let mut split_authorization = false;
    if ci(&name, "authoriz") {
        let after_space = spaces(s, end, false);
        if after_space > end {
            if let Some((suffix, suffix_end)) = marker(s, after_space) {
                if ci(&suffix, "ation") {
                    name.push_str(&suffix);
                    end = suffix_end;
                    split_authorization = true;
                }
            }
        }
    }
    let (sensitive, generic, authorization) = names(&name);
    let bearer = ci(&name, "bearer");
    let cookie = ci(&name, "cookie");
    let password = ci(&name, "password");
    let legacy = [
        "x-goog-api-key",
        "x-api-key",
        "api_key",
        "api-key",
        "apikey",
        "authorization",
    ]
    .iter()
    .any(|v| ci(&name, v));
    let mut cursor = end;
    if let Some((width, _)) = quote(s, cursor) {
        cursor += width;
    }
    cursor = spaces(s, cursor, false);
    let tail = &s[cursor..];
    let width = if tail.starts_with([':', '=']) {
        1
    } else if tail.get(..3).is_some_and(|v| ci(v, "%3D")) || tail.starts_with('：') {
        3
    } else if tail
        .get(..6)
        .is_some_and(|v| ci(v, "\\u003a") || ci(v, "\\u003d"))
    {
        6
    } else {
        0
    };
    if split_authorization && width == 0 {
        return None;
    }
    // Preserve exactly the diagnostic Marker-0 separator/threshold semantics.
    if profile == ContextProfile::Diagnostic && (legacy || bearer) {
        return legacy_span(s, end, bearer);
    }
    let xml = b.get(end) == Some(&b'>') && i > 0 && b[i - 1] == b'<';
    let command =
        name.starts_with("--") && (suffix(&name, "password") || ci(&name, "--client-secret"));
    let netrc = password && cursor > end && !rejected_prefix(s, cursor);
    if width == 0 && !bearer && !xml && !command && !netrc {
        return None;
    }
    let mut lookback = i.saturating_sub(QUOTE_LIMIT);
    while !s.is_char_boundary(lookback) {
        lookback += 1;
    }
    let preceding = &s[lookback..i];
    let environment = profile == ContextProfile::Chat
        && !split_authorization
        && width == 1
        && b.get(cursor) == Some(&b'=')
        && preceding
            .rsplit_once('\n')
            .map_or(preceding, |(_, tail)| tail)
            .bytes()
            .all(|v| matches!(v, b' ' | b'\t'));
    cursor += if xml { 1 } else { width };
    if width > 0
        && b.get(cursor)
            .is_some_and(|v| matches!(v, b'>' | b'=' | b':'))
    {
        cursor += 1;
    }
    cursor = spaces(s, cursor, width > 0);
    if cursor >= s.len() {
        return None;
    }
    if password && width > 0 {
        if let Some(span) = quoted_continuation(s, cursor) {
            return Some(span);
        }
    }
    if profile == ContextProfile::Diagnostic {
        let named_assignment = sensitive
            && (name.contains(['_', '-'])
                || ["accessToken", "refreshToken", "clientSecret"]
                    .iter()
                    .any(|v| ci(&name, v)));
        if !named_assignment && !command && !cookie {
            return None;
        }
    } else if !sensitive && !authorization && !bearer && !cookie {
        return None;
    }
    if ci(&name, "secret")
        && s[cursor..]
            .get(..17)
            .is_some_and(|v| ci(v, "permission denied"))
        && s[cursor + 17..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric())
    {
        return None;
    }
    if cookie {
        return Some((cursor, line_end(s, cursor)));
    }
    let query = preceding
        .rsplit_once('?')
        .is_some_and(|(_, tail)| !tail.contains(char::is_whitespace));
    if (generic || !xml) && rejected_prefix(s, cursor) {
        return None;
    }
    // Never scan beyond a boundary that publication will leave unconsumed.
    let scope_end = if xml {
        cursor + s[cursor..].find('<').unwrap_or(s.len() - cursor)
    } else {
        s.len()
    };
    let (start, finish) = value_span(&s[..scope_end], cursor, environment, query)?;
    if authorization {
        let scheme_end = run(b, start, key);
        let credential = spaces(s, scheme_end, false);
        let token_scope = if start != cursor {
            &s[..finish]
        } else {
            &s[..scope_end]
        };
        // A raw value has no scheme separator. Never scan its remaining suffix
        // only to discard that scan, and preserve query/quote/XML boundaries.
        if credential > scheme_end && credential < token_scope.len() {
            let token_end = word_value(token_scope, credential, query);
            if token_end > credential && token_end - credential >= 8 {
                // Newly supported split markers can introduce an opaque value
                // followed by prose. Keep neither long word potentially secret.
                if split_authorization && finish - start >= 8 {
                    return Some((start, token_end));
                }
                // A redacted credential is not token-shaped. Keep its exact
                // placeholder stable instead of consuming the public scheme
                // on the next pass (including persisted-chat resume).
                if s.get(credential..token_end) == Some(crate::chat::MASK)
                    || token_shaped(&s[credential..token_end])
                {
                    return Some((credential, token_end));
                }
                // With a short scheme and a malformed long credential, masking
                // the entire value is safer than preserving either word.
                if finish - start < 8 {
                    return Some((start, token_end));
                }
            }
        }
        return (finish - start >= 8).then_some((start, finish));
    }
    let candidate = &s[start..finish];
    if profile == ContextProfile::Diagnostic && !threshold(candidate) {
        return None;
    }
    if bearer && candidate.len() < 8 {
        return None;
    }
    let numeric_credential = command || (width > 0 && sensitive) || bearer;
    if (generic || !xml) && !plausible(candidate, numeric_credential) {
        return None;
    }
    Some((start, finish))
}

fn quoted_continuation(s: &str, cursor: usize) -> Option<(usize, usize)> {
    let (width, q) = quote(s, cursor)?;
    if width != 1 || quote(s, cursor + width) != Some((width, q)) {
        return None;
    }
    let mut next = cursor + width * 2;
    let empty_end = next;
    while s.as_bytes().get(next) == Some(&b' ') {
        next += 1;
    }
    if next == empty_end || quote(s, next).is_none() {
        return None;
    }
    let span = value_span(s, next, false, false)?;
    (span.1 > span.0).then_some(span)
}

pub(super) fn token_shaped(s: &str) -> bool {
    value::token_shaped(s)
}
