//! Dependency-free producing-build and report-decoder token grammar.
pub(crate) fn validate_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn validate_build_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn number(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}
fn identifiers(value: &str, prerelease: bool) -> bool {
    value.split('.').all(|id| {
        !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (!prerelease || !id.bytes().all(|b| b.is_ascii_digit()) || number(id))
    })
}
pub(crate) fn validate_build_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (head, build) = value
        .split_once('+')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let (core, pre) = head
        .split_once('-')
        .map_or((head, None), |(a, b)| (a, Some(b)));
    let mut parts = core.split('.');
    (0..3).all(|_| parts.next().is_some_and(number))
        && parts.next().is_none()
        && pre.is_none_or(|s| identifiers(s, true))
        && build.is_none_or(|s| identifiers(s, false))
}
