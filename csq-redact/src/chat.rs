//! Transcript-specific scanner. Legacy diagnostic redaction stays unchanged.

const MASK: &str = "[REDACTED]";
// Owner policy: saved chats mask every >=32-byte hex run, including git SHAs.
// Retained switch enables a one-line isolated regression control.
const KEEP_DELIMITED_GIT_SHA: bool = false;
#[path = "chat_fields.rs"]
mod fields;

/// Scrub supported credential shapes from chat text in a bounded, incremental scan.
///
/// Covers csq token prefixes/JWTs, GitHub, AWS access IDs, Slack, Stripe,
/// credential fields, Authorization schemes, URL userinfo and private-key PEM.
/// Every hex run of 32+ bytes is masked, including delimited 40/64-byte git
/// SHAs and hex.alphanumeric composites. This is not universal secret detection.
/// An unterminated, explicitly labelled PRIVATE KEY consumes the remaining text
/// conservatively; generic unfinished `-----BEGIN ` prose is preserved.
pub fn redact_chat(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let boundary = word_boundary(b, i);
        if let Some(end) = private_pem(s, i) {
            out.push_str(MASK);
            i = end;
            continue;
        }
        if boundary {
            if let Some((start, end)) = fields::context(s, i) {
                out.push_str(&s[i..start]);
                out.push_str(MASK);
                i = end;
                continue;
            }
            if let Some((start, end)) = userinfo(s, i) {
                out.push_str(&s[i..start]);
                out.push_str(MASK);
                i = end;
                continue;
            }
            if let Some(end) = prefixed(s, i).or_else(|| jwt(s, i)) {
                out.push_str(MASK);
                i = end;
                continue;
            }
        }
        if let Some((end, redact)) = hex_span(s, i) {
            if redact {
                out.push_str(MASK);
            } else {
                out.push_str(&s[i..end]);
            }
            i = end;
            continue;
        }
        // Advance complete UTF-8 scalars; no char vector or offset vector.
        if let Some(c) = s[i..].chars().next() {
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn word_boundary(b: &[u8], i: usize) -> bool {
    i == 0
        || !key(b[i - 1])
        || fields::escaped_boundary(safe_tail(b, i))
        || (i >= 2 && b[i - 2] == b'\\' && matches!(b[i - 1], b'n' | b'r' | b't'))
}

fn safe_tail(b: &[u8], i: usize) -> &[u8] {
    &b[i.saturating_sub(6)..i]
}

fn key(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}
fn run(b: &[u8], mut i: usize, predicate: fn(u8) -> bool) -> usize {
    while i < b.len() && predicate(b[i]) {
        i += 1;
    }
    i
}

fn hex_span(s: &str, i: usize) -> Option<(usize, bool)> {
    let b = s.as_bytes();
    if !b[i].is_ascii_hexdigit() || (i > 0 && b[i - 1].is_ascii_hexdigit()) {
        return None;
    }
    let end = run(b, i, |v| v.is_ascii_hexdigit());
    let count = end - i;
    if count < 32 {
        return None;
    }
    let dotted_suffix = b.get(end) == Some(&b'.') && b.get(end + 1).is_some_and(|v| key(*v));
    let glued = run(b, end, key);
    let composite = if dotted_suffix {
        run(b, end + 1, key)
    } else {
        glued
    };
    let right_delimited = b.get(end).is_none_or(|v| !key(*v)) && !dotted_suffix;
    let dotted_prefix = i >= 2 && b[i - 1] == b'.' && key(b[i - 2]);
    let left_delimited = word_boundary(b, i) && !dotted_prefix;
    let git_sha =
        KEEP_DELIMITED_GIT_SHA && matches!(count, 40 | 64) && left_delimited && right_delimited;
    Some((composite.max(end), !git_sha))
}

fn prefixed(s: &str, i: usize) -> Option<usize> {
    let b = s.as_bytes();
    for prefix in super::KNOWN_TOKEN_PREFIXES {
        if s[i..].starts_with(prefix) {
            return Some(run(b, i + prefix.len(), |v| key(v) || v == b'.'));
        }
    }
    for (prefix, minimum) in super::TOKEN_PREFIXES_WITH_BODY.iter().copied().chain([
        ("ghp_", 30),
        ("gho_", 30),
        ("ghu_", 30),
        ("ghs_", 30),
        ("ghr_", 30),
        ("rk_live_", 16),
        ("rk_test_", 16),
        ("sk_test_", 16),
        ("xoxe-", 8),
        ("xapp-", 8),
        ("ASIA", 16),
        ("GOCSPX-", 8),
        ("npm_", 30),
        ("glpat-", 20),
        ("github_pat_", 30),
        ("AKIA", 16),
        ("xoxa-", 8),
        ("xoxb-", 8),
        ("xoxp-", 8),
        ("xoxr-", 8),
        ("sk_live_", 16),
    ]) {
        if !s[i..].starts_with(prefix) {
            continue;
        }
        let start = i + prefix.len();
        let end = run(b, start, key);
        if matches!(prefix, "AKIA" | "ASIA")
            && (end - start != 16
                || !b[start..end]
                    .iter()
                    .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit()))
        {
            continue;
        }
        if end - start >= minimum {
            return Some(end);
        }
        if prefix == "sk-" && end - start >= 4 && b[start..end].iter().all(u8::is_ascii_hexdigit) {
            return Some(end);
        }
    }
    None
}

fn jwt(s: &str, i: usize) -> Option<usize> {
    let b = s.as_bytes();
    if !s[i..].starts_with("eyJ") {
        return None;
    }
    let first = run(b, i + 3, key);
    if first - i - 3 < super::JWT_SEGMENT_MIN_BODY
        || !s.get(first..).is_some_and(|v| v.starts_with(".eyJ"))
    {
        return None;
    }
    let second = run(b, first + 4, key);
    if second - first - 4 < super::JWT_SEGMENT_MIN_BODY || b.get(second) != Some(&b'.') {
        return None;
    }
    let third = run(b, second + 1, key);
    (third - second > super::JWT_SEGMENT_MIN_BODY).then_some(third)
}

fn private_pem(s: &str, i: usize) -> Option<usize> {
    let tail = &s[i..];
    if !tail.starts_with("-----BEGIN ") {
        return None;
    }
    // Bounded tag parse: malformed generic markers never search the suffix.
    let tag_end = tail.get(11..)?.bytes().take(64).position(|v| v == b'-')? + 11;
    let tag = tail.get(11..tag_end)?;
    if !tail.get(tag_end..)?.starts_with("-----") || !tag.contains("PRIVATE KEY") {
        return None;
    }
    let close = format!("-----END {tag}-----");
    Some(
        tail[tag_end + 5..]
            .find(&close)
            .map_or(s.len(), |offset| i + tag_end + 5 + offset + close.len()),
    )
}

fn userinfo(s: &str, i: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    if !b[i].is_ascii_alphabetic()
        || (i > 0 && (b[i - 1].is_ascii_alphanumeric() || matches!(b[i - 1], b'+' | b'-' | b'.')))
    {
        return None;
    }
    let scheme_end = run(b, i, |v| {
        v.is_ascii_alphanumeric() || matches!(v, b'+' | b'-' | b'.')
    });
    if !s.get(scheme_end..).is_some_and(|v| v.starts_with("://")) {
        return None;
    }
    let start = scheme_end + 3;
    let end = run(b, start, |v| {
        !v.is_ascii_whitespace() && !matches!(v, b'/' | b'?' | b'#' | b'"' | b'\'' | b'`')
    });
    let at = b[start..end].iter().rposition(|v| *v == b'@')?;
    let user_end = start + at;
    if let Some(colon) = b[start..user_end].iter().position(|v| *v == b':') {
        return (start + colon + 1 < user_end).then_some((start + colon + 1, user_end));
    }
    let token = &s[start..user_end];
    (fields::token_shaped(token) && (token.len() >= 16 || prefixed(s, start).is_some()))
        .then_some((start, user_end))
}
