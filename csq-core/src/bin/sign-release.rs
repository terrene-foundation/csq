//! `sign-release` — Ed25519 signer for csq release binaries.
//!
//! Used in the GitHub Actions release workflow to sign each CLI
//! binary with the Foundation's release-signing private key. The
//! resulting `<binary>.sig` files are uploaded alongside the binaries
//! and verified by `csq update install` via
//! `csq_core::update::verify::verify_signature`.
//!
//! # Usage
//!
//! ```text
//! sign-release <key-hex> <input-file> [<input-file>...]
//! ```
//!
//! The key MUST be a 64-character lowercase hex string (32 bytes).
//! For each input file the signer writes `<input>.sig` containing
//! the 64-byte raw Ed25519 signature.
//!
//! # Security
//!
//! - The private key is read from a CLI argument by design — the CI
//!   step pipes it from a GitHub Secret and the surrounding shell
//!   discards it after this binary exits. We do NOT read from a file
//!   so the key never lands on disk.
//! - The signer never logs the key bytes. Errors mention argument
//!   positions only.
//! - On any failure the signer exits non-zero so the CI step fails
//!   loudly rather than producing unsigned artifacts.

use ed25519_dalek::{Signer, SigningKey};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let key_hex = match args.next() {
        Some(k) => k,
        None => {
            eprintln!("usage: sign-release <key-hex> <input> [<input>...]");
            return ExitCode::from(2);
        }
    };
    let inputs: Vec<String> = args.collect();
    if inputs.is_empty() {
        eprintln!("error: at least one input file required");
        return ExitCode::from(2);
    }

    let key_bytes = match hex::decode(&key_hex) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("error: signing key must be hex-encoded");
            return ExitCode::from(2);
        }
    };
    if key_bytes.len() != 32 {
        eprintln!(
            "error: signing key must decode to exactly 32 bytes, got {}",
            key_bytes.len()
        );
        return ExitCode::from(2);
    }
    let key_array: [u8; 32] = match key_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("error: key length conversion failed");
            return ExitCode::from(2);
        }
    };
    let signing_key = SigningKey::from_bytes(&key_array);

    let mut had_error = false;
    for input in &inputs {
        match std::fs::read(input) {
            Ok(bytes) => {
                let signature = signing_key.sign(&bytes);
                let sig_path = format!("{input}.sig");
                if let Err(e) = std::fs::write(&sig_path, signature.to_bytes()) {
                    eprintln!("error: failed to write {sig_path}: {e}");
                    had_error = true;
                } else {
                    eprintln!("signed: {input} -> {sig_path}");
                }
            }
            Err(e) => {
                eprintln!("error: failed to read {input}: {e}");
                had_error = true;
            }
        }
    }

    // Drop the signing key from memory before returning. Rust will
    // do this automatically when `signing_key` goes out of scope but
    // we make it explicit so a future refactor can't accidentally
    // hold a reference past this point.
    drop(signing_key);

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
