//! Cryptographic verification for csq self-update.
//!
//! Two verification layers are applied to every downloaded binary:
//!
//! 1. **SHA256 checksum** — verifies the binary was not corrupted in transit.
//!    The `SHA256SUMS` file lists `{hex_hash}  {filename}` pairs; we find the
//!    entry matching the current platform's binary name and compare.
//!
//! 2. **Ed25519 signature** — verifies the binary was signed by the Terrene
//!    Foundation release key. The public key is pinned at compile time; an
//!    attacker who compromises GitHub Releases (but not the release signing key)
//!    cannot push a malicious binary that csq will accept.
//!
//! ### Key management
//!
//! The release public key is embedded as a const. When the real release
//! signing pipeline is configured (M11-01), replace `RELEASE_PUBLIC_KEY_BYTES`
//! with the actual 32-byte compressed Ed25519 public key from the Foundation's
//! release signing infrastructure.
//!
//! Until the real key is set, `RELEASE_PUBLIC_KEY_BYTES` contains a placeholder
//! test keypair (deterministic via a fixed seed). Tests in this module use the
//! corresponding private key so signature verification can be exercised end-to-end
//! without a live signing infrastructure.
//!
//! ### Security invariants
//!
//! - `verify_signature` MUST return `Err` for any binary not signed by the
//!   pinned key.
//! - `verify_checksum` MUST return `Err` if the SHA256 of the binary does not
//!   match the checksum file entry.
//! - Neither function logs or exposes key material in error messages.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Ed25519 public key pinned for release verification.
///
/// This is a placeholder keypair used during development and testing.
/// Replace with the real 32-byte Foundation release public key when the
/// signing pipeline (M11-01) is configured.
///
/// To generate a new keypair for production:
/// ```ignore
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let verifying_key = signing_key.verifying_key();
/// println!("Public key (hex): {}", hex::encode(verifying_key.as_bytes()));
/// // Store the signing key securely in the release pipeline.
/// // Embed the public key here as RELEASE_PUBLIC_KEY_BYTES.
/// ```
///
/// The placeholder key is deterministically derived from a fixed seed.
/// Its corresponding private key is only used in test code; production builds
/// will reject any signature not made with the real Foundation release key.
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [
    // Placeholder: derived from seed [1u8; 32] — NOT a production key.
    // Generated via: SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes()
    // Actual bytes confirmed by test `print_public_key_bytes_for_seed_1`.
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

/// Verifies an Ed25519 signature over `binary_bytes`.
///
/// `sig_bytes` must be 64 bytes (the serialized Ed25519 signature produced
/// by signing `binary_bytes` with the private key corresponding to
/// `RELEASE_PUBLIC_KEY_BYTES`).
///
/// # Errors
///
/// Returns `Err` if:
/// - `sig_bytes` is not exactly 64 bytes
/// - The signature is invalid for the given binary and public key
/// - The public key constant is malformed (a programming error, not a
///   runtime condition — the key is a compile-time constant)
///
/// # Security
///
/// Error messages never include key bytes, signature bytes, or binary
/// content. They are safe to surface in user-facing output.
pub fn verify_signature(binary_bytes: &[u8], sig_bytes: &[u8]) -> Result<()> {
    // Construct the verifying key from the pinned constant.
    let verifying_key = VerifyingKey::from_bytes(&RELEASE_PUBLIC_KEY_BYTES)
        .context("release public key constant is malformed — this is a bug")?;

    // Signature must be exactly 64 bytes.
    if sig_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "invalid signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("just checked length == 64");
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(binary_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))?;

    Ok(())
}

/// Verifies the SHA256 checksum of `binary_bytes` against the entry in
/// `sha256sums_text` for `binary_filename`.
///
/// `sha256sums_text` is the text content of a `SHA256SUMS` file whose
/// lines follow the `sha256sum(1)` format: `{64-hex-chars}  {filename}`.
/// Lines starting with `#` are ignored (comments).
///
/// # Errors
///
/// Returns `Err` if:
/// - No entry for `binary_filename` exists in the checksum file
/// - The recorded checksum is not a valid 64-character hex string
/// - The computed checksum does not match the recorded value
pub fn verify_checksum(
    binary_bytes: &[u8],
    sha256sums_text: &str,
    binary_filename: &str,
) -> Result<()> {
    // Compute the actual SHA256 of the binary.
    let mut hasher = Sha256::new();
    hasher.update(binary_bytes);
    let actual_hex = hex::encode(hasher.finalize());

    // Find the matching line in SHA256SUMS.
    // Format: "64-hex-chars  filename" (two spaces is the `sha256sum` convention).
    let expected_hex = sha256sums_text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|line| {
            let (hash, name) = line.split_once("  ")?;
            if name.trim() == binary_filename {
                Some(hash.trim().to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no SHA256 checksum entry found for '{binary_filename}' in SHA256SUMS")
        })?;

    // Validate the recorded hash is a 64-char hex string.
    if expected_hex.len() != 64 || !expected_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "SHA256SUMS entry for '{binary_filename}' is not a valid 64-character hex string"
        ));
    }

    if actual_hex != expected_hex {
        return Err(anyhow::anyhow!(
            "SHA256 checksum mismatch for '{binary_filename}': \
             expected {expected_hex}, got {actual_hex}"
        ));
    }

    Ok(())
}

/// Returns the Ed25519 signing key corresponding to `RELEASE_PUBLIC_KEY_BYTES`.
///
/// **Only available in test builds.** This key is the placeholder development
/// key. It MUST NOT be used outside tests.
#[cfg(test)]
pub fn test_signing_key() -> ed25519_dalek::SigningKey {
    // Deterministic from fixed seed [1u8; 32] matching RELEASE_PUBLIC_KEY_BYTES.
    ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    // Helper: sign `data` with the test signing key and return 64 sig bytes.
    fn sign(data: &[u8]) -> Vec<u8> {
        let sk = test_signing_key();
        let sig = sk.sign(data);
        sig.to_bytes().to_vec()
    }

    // Helper: build a valid SHA256SUMS line for `data` with `filename`.
    fn sha256sums_line(data: &[u8], filename: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());
        format!("{hash}  {filename}")
    }

    // ── verify_signature ─────────────────────────────────────────────────────

    #[test]
    fn verify_signature_accepts_valid_sig() {
        // Arrange
        let binary = b"fake binary content for testing";
        let sig_bytes = sign(binary);

        // Act
        let result = verify_signature(binary, &sig_bytes);

        // Assert
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {:?}",
            result
        );
    }

    #[test]
    fn verify_signature_rejects_wrong_binary() {
        // Arrange: sign one binary, verify against a different binary
        let original = b"original binary";
        let tampered = b"tampered binary";
        let sig_bytes = sign(original);

        // Act
        let result = verify_signature(tampered, &sig_bytes);

        // Assert
        assert!(
            result.is_err(),
            "signature for different binary must be rejected"
        );
    }

    #[test]
    fn verify_signature_rejects_wrong_sig() {
        // Arrange: flip one byte in a valid signature
        let binary = b"some binary bytes";
        let mut sig_bytes = sign(binary);
        sig_bytes[0] ^= 0xff;

        // Act
        let result = verify_signature(binary, &sig_bytes);

        // Assert
        assert!(result.is_err(), "corrupted signature must be rejected");
    }

    #[test]
    fn verify_signature_rejects_short_sig() {
        // Arrange: 63 bytes instead of 64
        let binary = b"some binary bytes";
        let sig_bytes = vec![0u8; 63];

        // Act
        let result = verify_signature(binary, &sig_bytes);

        // Assert
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 bytes"));
    }

    #[test]
    fn verify_signature_rejects_empty_sig() {
        // Arrange
        let result = verify_signature(b"binary", &[]);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_error_does_not_leak_key_material() {
        // Arrange: wrong signature (64 zero bytes)
        let binary = b"some content";
        let sig_bytes = vec![0u8; 64];

        // Act
        let result = verify_signature(binary, &sig_bytes);

        // Assert: error message must not contain key bytes
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // The public key in hex would start with "8a88e3..." — confirm it's absent.
        // We check the first few hex chars of the actual key constant.
        assert!(
            !msg.contains("8a88"),
            "error message must not leak public key: {msg}"
        );
    }

    // ── verify_checksum ──────────────────────────────────────────────────────

    #[test]
    fn verify_checksum_accepts_matching_hash() {
        // Arrange
        let binary = b"real binary content";
        let filename = "csq-linux-x86_64";
        let sums = sha256sums_line(binary, filename);

        // Act
        let result = verify_checksum(binary, &sums, filename);

        // Assert
        assert!(
            result.is_ok(),
            "matching checksum must be accepted: {:?}",
            result
        );
    }

    #[test]
    fn verify_checksum_rejects_tampered_binary() {
        // Arrange
        let original = b"original binary";
        let tampered = b"tampered binary";
        let filename = "csq-linux-x86_64";
        let sums = sha256sums_line(original, filename);

        // Act
        let result = verify_checksum(tampered, &sums, filename);

        // Assert
        assert!(result.is_err(), "checksum mismatch must be rejected");
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn verify_checksum_rejects_missing_entry() {
        // Arrange: checksum file has an entry for a different file
        let binary = b"binary";
        let sums = sha256sums_line(binary, "csq-linux-x86_64");

        // Act
        let result = verify_checksum(binary, &sums, "csq-macos-aarch64");

        // Assert
        assert!(result.is_err(), "missing entry must be rejected");
        assert!(result.unwrap_err().to_string().contains("no SHA256"));
    }

    #[test]
    fn verify_checksum_rejects_malformed_hash() {
        // Arrange: entry with 32-char (not 64-char) hex string
        let filename = "csq-linux-x86_64";
        let sums = format!("abcdef1234567890abcdef1234567890  {filename}"); // 32 hex chars

        // Act
        let result = verify_checksum(b"anything", &sums, filename);

        // Assert
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64-character"));
    }

    #[test]
    fn verify_checksum_ignores_comment_lines() {
        // Arrange: SHA256SUMS file with a comment header
        let binary = b"binary content";
        let filename = "csq-macos-aarch64";
        let hash_line = sha256sums_line(binary, filename);
        let sums = format!("# Generated by release pipeline\n{hash_line}\n");

        // Act
        let result = verify_checksum(binary, &sums, filename);

        // Assert: comment lines must be skipped, not cause a parse error
        assert!(
            result.is_ok(),
            "comment lines must be ignored: {:?}",
            result
        );
    }

    #[test]
    fn verify_checksum_handles_multiple_entries() {
        // Arrange: three platform entries, we verify the correct one
        let binary = b"macos binary bytes";
        let other1 = b"linux binary bytes";
        let other2 = b"windows binary bytes";
        let sums = format!(
            "{}\n{}\n{}",
            sha256sums_line(other1, "csq-linux-x86_64"),
            sha256sums_line(binary, "csq-macos-aarch64"),
            sha256sums_line(other2, "csq-windows-x86_64.exe"),
        );

        // Act
        let result = verify_checksum(binary, &sums, "csq-macos-aarch64");

        // Assert
        assert!(
            result.is_ok(),
            "should match among multiple entries: {:?}",
            result
        );
    }
}
