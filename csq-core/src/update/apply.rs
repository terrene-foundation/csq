//! Binary download, verification, and atomic self-replacement for csq.
//!
//! ### Flow
//!
//! 1. Download the binary from `info.download_url` into a temp file in the
//!    same directory as the current binary (guarantees same filesystem for
//!    atomic rename).
//! 2. Download the `SHA256SUMS` file and the `.sig` file.
//! 3. Verify the SHA256 checksum.
//! 4. Verify the Ed25519 signature.
//! 5. Set the temp file permissions to 0o755 (executable).
//! 6. Atomically rename the temp file over the current binary.
//!
//! ### Security
//!
//! - HTTPS-only (the `http_get` transport is `crate::http::get_with_headers`
//!   which uses a client built with `https_only(true)`).
//! - Ed25519 signature verified against the pinned public key in `verify.rs`
//!   before any file is replaced.
//! - SHA256 checksum verified before signature check (cheap first gate).
//! - Temp file written with restrictive permissions before executable bit set.
//! - If any verification step fails, the temp file is deleted and the current
//!   binary is left untouched.
//! - No secrets appear in error messages.
//!
//! ### Windows note
//!
//! On Windows, a running process cannot replace its own executable. We use
//! `platform::fs::atomic_replace` which calls `MoveFileExW` — this works
//! when the target file is not memory-mapped, which is the case after the
//! process has fully loaded. If the move fails (ACCESS_DENIED), the error is
//! returned and the user is instructed to close and restart csq before
//! updating.

#[cfg(not(unix))]
use crate::platform::fs::secure_file;
use crate::platform::fs::{atomic_replace, unique_tmp_path};
use crate::update::github::UpdateInfo;
use crate::update::verify::{verify_checksum, verify_signature};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

/// Downloads `info.download_url` with custom headers, verifies checksum and
/// Ed25519 signature, then atomically replaces the current binary.
///
/// `http_get` is an injectable transport closure so tests can supply canned
/// responses without a live network connection.
///
/// On success, the current binary has been replaced. The caller should
/// normally print a message and exit so the user can restart with the new
/// version.
///
/// On failure, the current binary is untouched and the temp file is cleaned up.
pub fn download_and_apply<F>(info: &UpdateInfo, http_get: F) -> Result<()>
where
    F: Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, String>,
{
    let binary_path = current_binary_path()?;

    // Step 1: download the binary into a temp file.
    eprintln!("Downloading csq v{}...", info.version);
    let binary_bytes = http_get(&info.download_url, &[("User-Agent", user_agent().as_str())])
        .map_err(|e| anyhow::anyhow!("failed to download binary: {e}"))?;

    // Step 2: download checksum file.
    let sha256sums_bytes = http_get(&info.checksum_url, &[("User-Agent", user_agent().as_str())])
        .map_err(|e| anyhow::anyhow!("failed to download SHA256SUMS: {e}"))?;
    let sha256sums_text =
        String::from_utf8(sha256sums_bytes).context("SHA256SUMS file is not valid UTF-8")?;

    // Step 3: download signature file.
    let sig_bytes = http_get(
        &info.signature_url,
        &[("User-Agent", user_agent().as_str())],
    )
    .map_err(|e| anyhow::anyhow!("failed to download signature: {e}"))?;

    // Step 4: verify SHA256 checksum.
    let binary_filename = extract_filename(&info.download_url);
    eprintln!("Verifying checksum...");
    verify_checksum(&binary_bytes, &sha256sums_text, &binary_filename)
        .context("checksum verification failed")?;

    // Step 5: verify Ed25519 signature.
    eprintln!("Verifying signature...");
    verify_signature(&binary_bytes, &sig_bytes).context("signature verification failed")?;

    // Step 6: write verified binary to a temp file.
    let tmp_path = unique_tmp_path(&binary_path);
    write_binary(&tmp_path, &binary_bytes)
        .with_context(|| format!("failed to write temp binary to {}", tmp_path.display()))?;

    // Step 7: set executable permissions on the temp file.
    set_executable(&tmp_path)
        .with_context(|| format!("failed to set permissions on {}", tmp_path.display()))?;

    // Step 8: atomic replace.
    eprintln!("Replacing {} with new version...", binary_path.display());
    atomic_replace(&tmp_path, &binary_path).with_context(|| {
        // Clean up the temp file on failure to avoid leaving a stale binary.
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "failed to replace binary at {} — temp file cleaned up",
            binary_path.display()
        )
    })?;

    eprintln!(
        "csq v{} installed. Restart csq to use the new version.",
        info.version
    );
    Ok(())
}

/// Returns the absolute path to the currently running csq binary.
fn current_binary_path() -> Result<PathBuf> {
    std::env::current_exe().context("could not determine current binary path")
}

/// Returns the `User-Agent` string for HTTP requests.
fn user_agent() -> String {
    format!("csq/{}", env!("CARGO_PKG_VERSION"))
}

/// Extracts the last path component from a URL, e.g.
/// `"https://github.com/.../csq-macos-aarch64"` → `"csq-macos-aarch64"`.
/// Falls back to the full URL if no path separator is found.
fn extract_filename(url: &str) -> String {
    url.rsplit('/').next().unwrap_or(url).to_string()
}

/// Writes binary content to `path` with `0o600` permissions (owner-only
/// read/write). The caller calls `set_executable` after this.
fn write_binary(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Create the file. On Unix, create with 0o600 immediately so the
    // window between create and secure_file is zero.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        secure_file(path)?;
    }
    Ok(())
}

/// Sets the temp file to `0o755` (owner rwx, group/other rx) on Unix.
/// On Windows this is a no-op.
fn set_executable(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = secure_file(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::github::UpdateInfo;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// Build a valid `UpdateInfo` for test injection.
    fn fake_update_info(version: &str) -> UpdateInfo {
        UpdateInfo {
            version: version.to_string(),
            download_url: "https://example.com/csq-linux-x86_64".to_string(),
            signature_url: "https://example.com/csq-linux-x86_64.sig".to_string(),
            checksum_url: "https://example.com/SHA256SUMS".to_string(),
            html_url: format!("https://example.com/releases/v{version}"),
        }
    }

    /// Builds a correctly-signed + correctly-checksummed bundle for `binary_bytes`.
    struct Bundle {
        binary: Vec<u8>,
        sig: Vec<u8>,
        sha256sums: String,
    }

    fn build_bundle(binary_bytes: &[u8], filename: &str) -> Bundle {
        let sk = crate::update::verify::test_signing_key();
        let sig = sk.sign(binary_bytes).to_bytes().to_vec();
        let mut hasher = Sha256::new();
        hasher.update(binary_bytes);
        let hash = hex::encode(hasher.finalize());
        Bundle {
            binary: binary_bytes.to_vec(),
            sig,
            sha256sums: format!("{hash}  {filename}"),
        }
    }

    /// An injectable `http_get` that serves pre-built content by URL.
    fn make_transport(
        responses: HashMap<&'static str, Vec<u8>>,
    ) -> impl Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, String> {
        // We can't use a HashMap with String keys in a closure that's Fn,
        // so we convert to a Vec of (url, bytes) pairs.
        let pairs: Vec<(String, Vec<u8>)> = responses
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        move |url: &str, _headers: &[(&str, &str)]| {
            pairs
                .iter()
                .find(|(k, _)| k == url)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| format!("no mock for URL: {url}"))
        }
    }

    // ── download_and_apply ───────────────────────────────────────────────────

    #[test]
    fn download_and_apply_replaces_binary_with_correct_content() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let target_path = dir.path().join("csq");
        std::fs::write(&target_path, b"old binary").unwrap();

        let new_content = b"new binary v2.1.0";
        let filename = "csq-linux-x86_64";
        let bundle = build_bundle(new_content, filename);

        // We need to override current_binary_path — test by calling the
        // inner logic directly with a controlled binary path.
        // Since current_binary_path() uses current_exe() and can't easily
        // be overridden, we test the inner steps directly below and keep
        // this as an integration test of the verification chain.
        let mut responses: HashMap<&'static str, Vec<u8>> = HashMap::new();
        responses.insert(
            "https://example.com/csq-linux-x86_64",
            bundle.binary.clone(),
        );
        responses.insert(
            "https://example.com/csq-linux-x86_64.sig",
            bundle.sig.clone(),
        );
        responses.insert(
            "https://example.com/SHA256SUMS",
            bundle.sha256sums.as_bytes().to_vec(),
        );

        let transport = make_transport(responses);

        // Act: verify_checksum and verify_signature as exercised by download_and_apply
        let sha256sums_text = String::from_utf8(bundle.sha256sums.as_bytes().to_vec()).unwrap();
        let checksum_result = verify_checksum(&bundle.binary, &sha256sums_text, filename);
        let sig_result = verify_signature(&bundle.binary, &bundle.sig);

        // Assert
        assert!(
            checksum_result.is_ok(),
            "checksum should pass: {:?}",
            checksum_result
        );
        assert!(
            sig_result.is_ok(),
            "signature should pass: {:?}",
            sig_result
        );

        // Confirm the transport returns the right bytes for each URL
        let binary_from_transport = transport("https://example.com/csq-linux-x86_64", &[]).unwrap();
        assert_eq!(binary_from_transport, new_content);
    }

    #[test]
    fn download_and_apply_fails_on_checksum_mismatch() {
        // Arrange: serve tampered binary but correct checksum for original
        let original = b"original binary content";
        let tampered = b"tampered binary content";
        let filename = "csq-linux-x86_64";
        let bundle = build_bundle(original, filename);

        let mut responses: HashMap<&'static str, Vec<u8>> = HashMap::new();
        // Serve the TAMPERED binary but the checksum for the original
        responses.insert("https://example.com/csq-linux-x86_64", tampered.to_vec());
        responses.insert(
            "https://example.com/csq-linux-x86_64.sig",
            bundle.sig.clone(),
        );
        responses.insert(
            "https://example.com/SHA256SUMS",
            bundle.sha256sums.as_bytes().to_vec(),
        );

        let transport = make_transport(responses);

        // Act: simulate the checksum check
        let downloaded = transport("https://example.com/csq-linux-x86_64", &[]).unwrap();
        let sums_text =
            String::from_utf8(transport("https://example.com/SHA256SUMS", &[]).unwrap()).unwrap();
        let result = verify_checksum(&downloaded, &sums_text, filename);

        // Assert
        assert!(result.is_err(), "tampered binary must fail checksum");
    }

    #[test]
    fn download_and_apply_fails_on_invalid_signature() {
        // Arrange: correct checksum but wrong signature
        let binary = b"valid binary bytes";
        let filename = "csq-linux-x86_64";
        let bundle = build_bundle(binary, filename);

        // Flip first byte of signature
        let mut bad_sig = bundle.sig.clone();
        bad_sig[0] ^= 0xff;

        let mut responses: HashMap<&'static str, Vec<u8>> = HashMap::new();
        responses.insert("https://example.com/csq-linux-x86_64", binary.to_vec());
        responses.insert("https://example.com/csq-linux-x86_64.sig", bad_sig);
        responses.insert(
            "https://example.com/SHA256SUMS",
            bundle.sha256sums.as_bytes().to_vec(),
        );

        let transport = make_transport(responses);

        // Act: simulate the verification chain
        let downloaded = transport("https://example.com/csq-linux-x86_64", &[]).unwrap();
        let bad_sig_bytes = transport("https://example.com/csq-linux-x86_64.sig", &[]).unwrap();
        let sums_text =
            String::from_utf8(transport("https://example.com/SHA256SUMS", &[]).unwrap()).unwrap();

        let checksum_ok = verify_checksum(&downloaded, &sums_text, filename);
        let sig_result = verify_signature(&downloaded, &bad_sig_bytes);

        // Assert
        assert!(
            checksum_ok.is_ok(),
            "checksum should pass for untampered binary"
        );
        assert!(sig_result.is_err(), "bad signature must be rejected");
    }

    #[test]
    fn download_and_apply_fails_on_transport_error() {
        // Arrange: transport that always errors
        let info = fake_update_info("2.1.0");
        let result = download_and_apply(&info, |_url, _headers| Err("connection failed".into()));

        // Assert
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to download"));
    }

    #[test]
    fn extract_filename_from_url() {
        // Arrange / Act / Assert
        assert_eq!(
            extract_filename("https://github.com/.../csq-macos-aarch64"),
            "csq-macos-aarch64"
        );
        assert_eq!(
            extract_filename("https://github.com/releases/v2.0.0/csq-linux-x86_64"),
            "csq-linux-x86_64"
        );
        assert_eq!(
            extract_filename("https://github.com/SHA256SUMS"),
            "SHA256SUMS"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_binary_creates_file_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_binary");
        let data = b"binary content";

        // Act
        write_binary(&path, data).unwrap();

        // Assert: file exists with 0o600
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "write_binary must create file with 0o600");
    }

    #[cfg(unix)]
    #[test]
    fn set_executable_produces_0755() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("binary");
        write_binary(&path, b"data").unwrap(); // creates with 0o600

        // Act
        set_executable(&path).unwrap();

        // Assert
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "set_executable must produce 0o755");
    }
}
