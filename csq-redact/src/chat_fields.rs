//! Bounded field syntax for the finite transcript redaction profile.
use super::{key, private_pem, run, MASK};
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
fn names(name: &str) -> (bool, bool, bool) {
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
fn spaces(s: &str, mut i: usize, yaml: bool) -> usize {
    let b = s.as_bytes();
    loop {
        if b.get(i).is_some_and(|v| matches!(v, b' ' | b'\t')) {
            i += 1;
            continue;
        }
        let width = if b.get(i) == Some(&b'\n') {
            1
        } else if s
            .get(i..)
            .is_some_and(|v| v.starts_with("\\n") || v.starts_with("\\r") || v.starts_with("\\t"))
        {
            2
        } else {
            0
        };
        if width > 0 && yaml && b.get(i + width).is_some_and(|v| matches!(v, b' ' | b'\t')) {
            i += width;
            continue;
        }
        return i;
    }
}
fn quote(s: &str, i: usize) -> Option<(usize, u8)> {
    let b = s.as_bytes();
    if b.get(i).is_some_and(|v| matches!(v, b'"' | b'\'')) {
        return Some((1, b[i]));
    }
    if b.get(i) == Some(&b'\\') && b.get(i + 1).is_some_and(|v| matches!(v, b'"' | b'\'')) {
        return Some((2, b[i + 1]));
    }
    for (marker, value) in [("\\u0022", b'"'), ("\\u0027", b'\'')] {
        if s.get(i..i + 6).is_some_and(|v| ci(v, marker)) {
            return Some((6, value));
        }
    }
    None
}
fn line_end(s: &str, i: usize) -> usize {
    i + s[i..].find(['\n', '\r']).unwrap_or(s.len() - i)
}
fn word_value(s: &str, i: usize, query: bool) -> usize {
    let end = run(s.as_bytes(), i, |v| {
        !v.is_ascii_whitespace() && !matches!(v, b'"' | b'\'' | b'`' | b'<' | b'}' | b',')
    });
    if query {
        s[i..end].find('&').map_or(end, |at| i + at)
    } else {
        end
    }
}

fn value_span(s: &str, i: usize, environment: bool, query: bool) -> Option<(usize, usize)> {
    if s[i..].starts_with(MASK) {
        return None;
    }
    if let Some(end) = private_pem(s, i) {
        return Some((i, end));
    }
    if s[i..].starts_with("-----BEGIN ") {
        return None;
    }
    if let Some((width, q)) = quote(s, i) {
        let start = i + width;
        // A quoted PEM remains a recognised multiline key, not generic prose.
        if let Some(end) = private_pem(s, start) {
            return Some((start, end));
        }
        // Bounded close search; an overlong candidate consumes its line once.
        let mut stop = (start + QUOTE_LIMIT).min(s.len());
        while !s.is_char_boundary(stop) {
            stop -= 1;
        }
        stop = start + s[start..stop].find(['\n', '\r']).unwrap_or(stop - start);
        let mut j = start;
        while j < stop {
            if let Some((close_width, value)) = quote(s, j) {
                if value == q && close_width == width {
                    return Some((start, j));
                }
            }
            if s.as_bytes()[j] == b'\\' && width == 1 && j + 1 < stop {
                j += 2;
            } else {
                j += 1;
            }
        }
        let end = line_end(s, start);
        return (end > start).then_some((start, end));
    }
    let end = if environment {
        line_end(s, i)
    } else {
        word_value(s, i, query)
    };
    // Detect private PEM glued to a value before the first whitespace delimiter.
    let look_end = if s.as_bytes().get(end) == Some(&b' ') {
        end + 1
    } else {
        end
    };
    if let Some(at) = s[i..look_end].find("-----BEGIN ") {
        if let Some(pem_end) = private_pem(s, i + at) {
            return Some((i, pem_end));
        }
    }
    (end > i).then_some((i, end))
}
pub(super) fn token_shaped(s: &str) -> bool {
    s.len() >= 8
        && s.bytes()
            .all(|v| key(v) || matches!(v, b'+' | b'/' | b'=' | b'.'))
}
fn plausible(s: &str) -> bool {
    if s.starts_with(MASK) || s.starts_with(['/', '.', '{', '<']) || s.contains("://") {
        return false;
    }
    if s.bytes().all(|v| v.is_ascii_digit()) {
        return false;
    }
    ![
        "string",
        "number",
        "boolean",
        "bool",
        "str",
        "int",
        "integer",
        "id",
        "undefined",
        "null",
        "policies",
        "is",
        "press",
        "required",
        "enter",
    ]
    .iter()
    .any(|v| ci(s, v))
}
pub(super) fn context(s: &str, i: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let end = run(b, i, key);
    let name = &s[i..end];
    if name.is_empty() {
        return None;
    }
    let (sensitive, generic, authorization) = names(name);
    let bearer = ci(name, "bearer");
    let cookie = ci(name, "cookie");
    if !sensitive && !authorization && !bearer && !cookie {
        return None;
    }
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
    let xml = b.get(end) == Some(&b'>') && i > 0 && b[i - 1] == b'<';
    let command = name.starts_with("--") && suffix(name, "password");
    let netrc =
        ci(name, "password") && cursor > end && plausible(&s[cursor..word_value(s, cursor, false)]);
    if width == 0 && !bearer && !xml && !command && !netrc {
        return None;
    }
    let mut lookback = i.saturating_sub(QUOTE_LIMIT);
    while !s.is_char_boundary(lookback) {
        lookback += 1;
    }
    let preceding = &s[lookback..i];
    let environment = width == 1
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
    if cookie {
        return Some((cursor, line_end(s, cursor)));
    }
    let query = preceding
        .rsplit_once('?')
        .is_some_and(|(_, tail)| !tail.contains(char::is_whitespace));
    let (start, mut finish) = value_span(s, cursor, environment, query)?;
    if xml {
        finish = s[start..finish].find('<').map_or(finish, |at| start + at);
    }
    if authorization {
        let scheme_end = run(b, start, key);
        let credential = spaces(s, scheme_end, false);
        let token_end =
            word_value(s, credential, false).min(if start != cursor { finish } else { s.len() });
        if credential == scheme_end
            || token_end <= credential
            || !token_shaped(&s[credential..token_end])
        {
            return None;
        }
        return Some((
            credential,
            token_end.min(if start != cursor { finish } else { s.len() }),
        ));
    }
    let candidate = &s[start..finish];
    if bearer && !token_shaped(candidate) {
        return None;
    }
    if (generic || !xml) && !plausible(candidate) {
        return None;
    }
    Some((start, finish))
}
