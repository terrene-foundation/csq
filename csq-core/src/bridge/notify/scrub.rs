//! Disclosure scrubbing for outbound owner pings.
//!
//! Two layers run on every text before it can reach the transport:
//!
//! 1. [`scrub_bot_token`] removes the live Telegram bot token structurally —
//!    the whole `<bot id>:<secret>` value AND each `:`-separated part. Neither
//!    shared scrubber covers this shape: `redact_tokens` has no
//!    `<digits>:<secret>` pattern, and `scrub_secrets` splits a secret on `.`
//!    only, so the bare 35-char secret half would otherwise survive.
//! 2. `crate::error::redact_tokens` applies the shared shape set (OAuth and
//!    API-key prefixes, bearer/field credential context, long hex, JWT, PEM).
//!
//! Secret material is never collected into a `Vec<String>`: every prefix is a
//! borrowed slice of the `SecretString`'s contents, and the partially scrubbed
//! intermediates are [`Zeroizing`].
//!
//! The count returned is the number of `[REDACTED]` markers the two layers
//! ADDED, computed as a marker delta over the raw text, so a caller who
//! literally wrote `[REDACTED]` is not miscounted.

use zeroize::Zeroizing;

/// The marker both scrub layers emit.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// Shortest prefix removed structurally.
///
/// A truncated echo shorter than this carries too little of the secret to be
/// usable, and matching it would over-redact ordinary prose.
const MIN_PREFIX_CHARS: usize = 6;

/// Longest prefix enumerated per base. The whole secret is always removed in
/// full; this only bounds the work for a pathologically long token.
const MAX_PREFIX_CHARS: usize = 256;

/// Scrubs `text` for delivery to the pinned owner.
///
/// Returns the scrubbed text, whether anything was redacted, and how many
/// `[REDACTED]` markers were added.
pub(crate) fn scrub_for_delivery(text: &str, token: &str) -> (String, bool, usize) {
    let raw_markers = text.matches(REDACTED).count();
    let layer1 = scrub_bot_token(text, token);
    let layer2 = crate::error::redact_tokens(&layer1);
    let added = layer2.matches(REDACTED).count().saturating_sub(raw_markers);
    (layer2, added > 0, added)
}

/// Removes the bot token, and every prefix of at least [`MIN_PREFIX_CHARS`]
/// chars of it and of each `:`-separated part, longest first.
fn scrub_bot_token(text: &str, token: &str) -> String {
    let mut bases: Vec<&str> = Vec::new();
    if !token.is_empty() {
        bases.push(token);
        for part in token.split(':') {
            if part.chars().count() >= MIN_PREFIX_CHARS && !bases.contains(&part) {
                bases.push(part);
            }
        }
    }

    let mut out = Zeroizing::new(text.to_string());
    for base in bases {
        let top = base.chars().count().min(MAX_PREFIX_CHARS);
        if top < MIN_PREFIX_CHARS {
            continue;
        }
        // Longest first: replacing the full token before its prefixes means a
        // shorter prefix cannot match inside text a longer one already
        // replaced, so no occurrence is counted twice.
        for len in (MIN_PREFIX_CHARS..=top).rev() {
            let prefix = &base[..prefix_end(base, len)];
            if out.contains(prefix) {
                out = Zeroizing::new(out.replace(prefix, REDACTED));
            }
        }
    }
    out.to_string()
}

/// Byte offset of the end of the first `len` chars of `base`.
///
/// `len` may equal the base's char count, in which case the offset is the
/// base's byte length. Callers pass a `len` already proved to be at most the
/// char count, so this never lands inside a multi-byte sequence.
fn prefix_end(base: &str, len: usize) -> usize {
    base.char_indices()
        .nth(len)
        .map(|(offset, _)| offset)
        .unwrap_or(base.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    #[test]
    fn the_bare_secret_half_is_removed() {
        let text = "leaked half AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw oops".to_owned();
        let (out, redacted, count) = scrub_for_delivery(&text, TOKEN);
        assert!(!out.contains("AAHdqTcvCH1vGW"), "{out}");
        assert!(!out.contains("JxfSeofSAs0K5"), "{out}");
        assert!(out.contains("leaked half"), "prose survives: {out}");
        assert!(redacted);
        assert!(count >= 1);
    }

    #[test]
    fn a_truncated_secret_prefix_is_removed() {
        let (out, redacted, _) = scrub_for_delivery("start AAHdqTcvCH1v then", TOKEN);
        assert!(!out.contains("AAHdqTcv"), "{out}");
        assert!(redacted);
    }

    #[test]
    fn the_whole_token_is_removed() {
        let text = format!("token={TOKEN} end");
        let (out, _, _) = scrub_for_delivery(&text, TOKEN);
        assert!(!out.contains("123456789:"), "{out}");
        assert!(!out.contains("AAHdqTcv"), "{out}");
    }

    #[test]
    fn the_shared_shape_set_still_runs() {
        let text = "key=sk-ant-oat01-FAKETESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (out, redacted, count) = scrub_for_delivery(text, TOKEN);
        assert!(!out.contains("FAKETEST"), "{out}");
        assert!(redacted);
        assert_eq!(count, 1);
    }

    #[test]
    fn clean_text_is_unchanged_and_not_counted() {
        let (out, redacted, count) = scrub_for_delivery("build finished", TOKEN);
        assert_eq!(out, "build finished");
        assert!(!redacted);
        assert_eq!(count, 0);
    }

    #[test]
    fn a_literal_marker_in_the_input_is_not_counted() {
        let (out, redacted, count) = scrub_for_delivery("already [REDACTED] here", TOKEN);
        assert_eq!(out, "already [REDACTED] here");
        assert!(!redacted);
        assert_eq!(count, 0);
    }

    #[test]
    fn prefix_end_handles_multibyte_bases() {
        let base = "ééééééé";
        let end = prefix_end(base, 3);
        assert_eq!(&base[..end], "ééé");
        assert_eq!(prefix_end(base, 7), base.len());
    }
}
