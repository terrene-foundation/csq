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
/// Foundation release-signing public key (Ed25519, 32 bytes).
///
/// Generated 2026-04-13. The corresponding private key lives ONLY in
/// the `terrene-foundation/csq` GitHub Actions secret
/// `RELEASE_SIGNING_KEY` and is read by the release workflow's
/// signing step (`csq-core/src/bin/sign-release.rs`). It MUST NOT
/// exist anywhere else — not on a developer machine, not in any
/// commit, not in any backup. If the private key is lost, generate
/// a new keypair and bump the public key constant here in a
/// dedicated commit.
///
/// To rotate (e.g. after a suspected compromise):
///
/// 1. In a clean ephemeral workspace, run a one-off binary that
///    calls `SigningKey::generate(&mut OsRng)` and prints the
///    private key as hex (stdout) and the public key as a Rust
///    array literal (stderr).
/// 2. Pipe the private key into
///    `gh secret set RELEASE_SIGNING_KEY --repo terrene-foundation/csq`.
/// 3. Securely delete the local private key file.
/// 4. Replace `RELEASE_PUBLIC_KEY_BYTES` here, commit, push, tag a
///    new release. Old releases signed with the rotated-out key
///    are still verifiable from cached binaries but the release
///    workflow will sign new artifacts with the new key.
///
/// Production deployments verify every downloaded binary against
/// this constant via `verify_signature` before the atomic swap. A
/// signature made with the old key fails verification — that is
/// the intended behavior of rotation.
///
/// # Test override
///
/// Under `#[cfg(test)]` the constant is overridden with the
/// deterministic seed-1 placeholder so the existing
/// `verify_signature_*` tests can sign with `test_signing_key()`
/// and still verify against the constant. Production builds get
/// the real Foundation key.
#[cfg(not(test))]
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x25, 0x57, 0x92, 0x5f, 0x72, 0x04, 0xd4, 0x95, 0x7a, 0x58, 0x17, 0x2f, 0xef, 0x81, 0x65, 0xaa,
    0x34, 0x67, 0x98, 0xcf, 0x81, 0xec, 0xd2, 0xea, 0x7b, 0x96, 0x9f, 0x91, 0xe4, 0x1a, 0x93, 0xe1,
];

#[cfg(test)]
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [
    // Seed-1 derived placeholder — used only in test builds so the
    // sign+verify round-trip in `test_signing_key()` works against
    // the same key. Production builds compile in the Foundation key
    // above instead.
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

/// Returns `true` if `RELEASE_PUBLIC_KEY_BYTES` is still the placeholder
/// test key derived from seed `[1u8; 32]`. When this returns true, binary
/// verification would accept signatures from anyone who reads the source
/// code, so `csq update install` MUST refuse to proceed.
pub fn is_placeholder_key() -> bool {
    // The placeholder key's first 4 bytes are 0x8a88e3dd. A real
    // Foundation key will have different bytes. We compare the full
    // 32 bytes against the known placeholder to be future-proof.
    const PLACEHOLDER: [u8; 32] = [
        0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d,
        0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f,
        0x6f, 0x5c,
    ];
    RELEASE_PUBLIC_KEY_BYTES == PLACEHOLDER
}

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
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature byte conversion failed after length check"))?;
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
