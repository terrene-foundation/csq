//! `redact-body` — Read stdin, apply `csq_core::error::redact_tokens`, write to stdout.
//!
//! Used by `coc-eval/scripts/characterize-error-bodies.sh` to scrub captured
//! 401/403 response bodies before they are written to the fixture files under
//! `coc-eval/redaction-fixtures/`. The submitted bad key is stripped from the
//! body by `redact_tokens` before the fixture is committed.
//!
//! # Usage
//!
//! ```text
//! echo '{"error":"invalid_api_key","message":"sk-INVALID-000 is not valid"}' | redact-body
//! ```
//!
//! Reads all of stdin to a String, applies `redact_tokens`, and prints the
//! redacted result to stdout with no trailing newline (the shell caller adds
//! one if needed). Exits 0 on success; exits 1 on I/O error.

use std::io::Read;

fn main() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    print!("{}", csq_core::error::redact_tokens(&buf));
    Ok(())
}
