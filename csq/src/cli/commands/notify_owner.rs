//! `csq notify-owner` — send a short Telegram message to the pinned owner.
//!
//! The destination is the owner pinned by `csq telegram pair`; this command
//! cannot address another chat, pass a token, or name a config path. The text
//! is read from **stdin** by default: argv is visible to every local process
//! (`ps`) and lands in shell history before the in-process scrub can run, so a
//! positional text is an explicit, documented opt-in for non-sensitive
//! messages.
//!
//! The state directory is the canonical per-user one, resolved inside
//! `csq_core::bridge::notify`; a conflicting `CSQ_BASE_DIR` is refused rather
//! than allowed to split the bridge state (config, kill marker, budget).
//!
//! On success the command prints one line naming the fixed outcome and, when
//! the scrub fired, the number of `[REDACTED]` markers. It never prints the
//! message, the chat id or the token.

use anyhow::{Context, Result};
use csq_core::bridge::notify::{send_owner_ping, MAX_TEXT_UTF16};
use std::io::Read;
use zeroize::Zeroizing;

/// Upper bound on stdin bytes.
///
/// Four bytes per UTF-16 code unit (the widest encoding) plus a small margin,
/// so any text that could pass the unit cap is read whole and a genuinely
/// oversized input is REFUSED rather than silently truncated. An input that
/// hits this cap is necessarily over the unit cap: 4-byte characters yield
/// `cap/4 > MAX_TEXT_UTF16` units, and any wider mix yields more.
const STDIN_MAX_BYTES: u64 = (MAX_TEXT_UTF16 as u64) * 4 + 2;

/// Dispatches `csq notify-owner [TEXT]`.
pub fn handle(text: Option<&str>) -> Result<()> {
    let (raw, from_stdin) = match text {
        Some(text) if text != "-" => (Zeroizing::new(text.to_owned()), false),
        _ => (read_text_from_stdin()?, true),
    };
    // A here-doc or a pipe usually ends with one newline; it is not part of
    // the owner-visible message. An argv text is used exactly as given.
    let text = if from_stdin {
        raw.trim_end_matches(['\r', '\n'])
    } else {
        raw.as_str()
    };
    let outcome = send_owner_ping(text).map_err(|error| {
        anyhow::anyhow!("owner ping refused: {error} ({})", error.error_kind_tag())
    })?;
    if outcome.redacted {
        println!(
            "owner_ping: {} (redacted={})",
            outcome.outcome, outcome.redaction_count
        );
    } else {
        println!("owner_ping: {}", outcome.outcome);
    }
    Ok(())
}

/// Reads the message text from stdin, bounded and zeroized.
///
/// Invalid UTF-8 at the cap means the input was truncated inside a multi-byte
/// character (or was never text); both are refused with fixed text rather
/// than reported as an I/O error.
fn read_text_from_stdin() -> Result<Zeroizing<String>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(STDIN_MAX_BYTES)
        .read_to_end(&mut bytes)
        .context("could not read the message from stdin")?;
    // The Vec's bytes move into the String — no second copy of the text.
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("the message is not valid UTF-8 (or is over the size cap)"))?;
    Ok(Zeroizing::new(text))
}
