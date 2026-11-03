//! Profile-neutral bounded value grammar. Diagnostic shape matching stays separate.
use super::{ci, QUOTE_LIMIT};
use crate::chat::{key, private_pem, MASK};

pub(super) fn spaces(s: &str, mut i: usize, yaml: bool) -> usize {
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
pub(super) fn quote(s: &str, i: usize) -> Option<(usize, u8)> {
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
pub(super) fn line_end(s: &str, i: usize) -> usize {
    let end = i + s[i..].find(['\n', '\r']).unwrap_or(s.len() - i);
    #[cfg(test)]
    crate::context_work_tests::record(end - i);
    end
}
pub(super) fn word_value(s: &str, i: usize, query: bool) -> usize {
    let end = i + s.as_bytes()[i..]
        .iter()
        .position(|&v| {
            v.is_ascii_whitespace()
                || matches!(v, b'"' | b'\'' | b'`' | b'<' | b'}' | b',')
                || (query && v == b'&')
        })
        .unwrap_or(s.len() - i);
    #[cfg(test)]
    crate::context_work_tests::record(end - i);
    end
}

pub(super) fn value_span(
    s: &str,
    i: usize,
    environment: bool,
    query: bool,
) -> Option<(usize, usize)> {
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
pub(super) fn plausible(s: &str, numeric_credential: bool) -> bool {
    if s.bytes().all(|v| v.is_ascii_digit()) {
        // The caller applies its profile's length policy. Explicit credentials
        // must not acquire a second, contradictory nine-digit minimum here.
        return numeric_credential && !s.is_empty();
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
// Inspect only the value opener and a bounded ASCII URI-scheme prefix. Reject
// public paths before any unbounded quoted fallback or environment scan.
pub(super) fn rejected_prefix(s: &str, cursor: usize) -> bool {
    let start = cursor + quote(s, cursor).map_or(0, |(width, _)| width);
    let tail = &s[start..];
    if tail.starts_with(MASK) || tail.starts_with(['/', '.', '{', '<']) {
        return true;
    }
    let bytes = tail.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    for i in 1..=64.min(bytes.len()) {
        if tail.get(i..i + 3) == Some("://") {
            return true;
        }
        if !bytes
            .get(i)
            .is_some_and(|v| v.is_ascii_alphanumeric() || matches!(v, b'+' | b'-' | b'.'))
        {
            return false;
        }
    }
    false
}
