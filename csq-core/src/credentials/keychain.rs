//! Keychain integration — service name derivation and read-only access.
//!
//! csq does NOT write to the keychain. CC owns its own keychain
//! entries: when launched with `CLAUDE_CONFIG_DIR=config-N`, CC's
//! `claude auth login` writes the credential JSON to a generic
//! password whose service name is `Claude Code-credentials-{hash}`,
//! where `{hash}` is the first 8 hex characters of SHA-256 of the
//! NFC-normalized config dir path. csq only READS that entry to
//! recover credentials in the rare case where CC writes the keychain
//! but skips `.credentials.json` (observed: some CC versions / some
//! configurations write keychain-only on first login).
//!
//! Without this fallback, `csq login N` cannot capture credentials
//! after `claude auth login` exits — see journal 0040 §1 and the
//! account-7 regression caught while testing alpha.6.
//!
//! On non-macOS platforms the read is a no-op stub: CC does not use
//! the keychain crate on Linux or Windows.

use super::CredentialFile;
use crate::error::PlatformError;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

/// Derives the keychain service name CC uses for a given config
/// directory.
///
/// Format: `Claude Code-credentials-{hash}` where `{hash}` is the
/// first 8 hex characters of SHA-256 of the NFC-normalized path.
pub fn service_name(config_dir: &Path) -> String {
    let normalized: String = config_dir.to_string_lossy().nfc().collect();
    let hash = Sha256::digest(normalized.as_bytes());
    let prefix = hex::encode(&hash[..4]); // 4 bytes = 8 hex chars
    format!("Claude Code-credentials-{prefix}")
}

/// Reads credentials from the system keychain that CC wrote for the
/// given config directory.
///
/// On macOS: uses the `security` CLI to find the generic password,
/// then attempts to parse the value as raw JSON (CC's modern
/// format) before falling back to a hex-decode (CC's legacy format).
///
/// Returns `None` if the keychain entry doesn't exist, can't be
/// read, or contains malformed data — the caller is expected to
/// chain a file-based fallback.
pub fn read(config_dir: &Path) -> Option<CredentialFile> {
    let svc = service_name(config_dir);
    match read_impl(&svc) {
        Ok(creds) => Some(creds),
        Err(e) => {
            warn!(
                service = %svc,
                error = %e,
                "keychain read failed (fallback to file path)"
            );
            None
        }
    }
}

// ── macOS implementation ──────────────────────────────────────────────
//
// Uses the `security` CLI tool (already trusted on macOS) instead of
// the `security-framework` crate so the read does not trigger a
// per-binary keychain authorization prompt on every debug rebuild
// (the binary hash changes each time and macOS treats it as a new
// caller).

#[cfg(target_os = "macos")]
fn read_impl(service: &str) -> Result<CredentialFile, PlatformError> {
    let account = keychain_account();
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", &account, "-w"])
        .output()
        .map_err(|e| PlatformError::Keychain(format!("security command: {e}")))?;

    if !output.status.success() {
        return Err(PlatformError::Keychain(
            "keychain entry not found".to_string(),
        ));
    }

    let raw = String::from_utf8(output.stdout)
        .map_err(|e| PlatformError::Keychain(format!("utf8: {e}")))?;
    let raw = raw.trim();

    // CC writes raw JSON; older csq versions wrote hex-encoded JSON.
    // Try raw JSON first, fall back to hex-decode for legacy entries.
    let json = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let bytes =
            hex::decode(raw).map_err(|e| PlatformError::Keychain(format!("hex decode: {e}")))?;
        String::from_utf8(bytes).map_err(|e| PlatformError::Keychain(format!("utf8: {e}")))?
    };

    serde_json::from_str(&json).map_err(|e| PlatformError::Keychain(format!("json parse: {e}")))
}

/// Keychain account parameter. CC uses the system username, which
/// macOS GUI apps don't always inherit through `$USER`, so we walk
/// `$USER` → `$USERNAME` → `getpwuid(getuid())` before giving up.
#[cfg(target_os = "macos")]
fn keychain_account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return Err(std::env::VarError::NotPresent);
            }
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            name.to_str()
                .map(|s| s.to_string())
                .map_err(|_| std::env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| "credentials".to_string())
}

// ── non-macOS stub ────────────────────────────────────────────────
//
// CC does not interact with the OS keychain on Linux or Windows; it
// stores credentials directly in `<CLAUDE_CONFIG_DIR>/.credentials.json`
// on those platforms. The read stub returns NotFound so the caller's
// file fallback runs unconditionally.

#[cfg(not(target_os = "macos"))]
fn read_impl(_service: &str) -> Result<CredentialFile, PlatformError> {
    Err(PlatformError::Keychain(
        "keychain read not implemented on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_format() {
        let svc = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        assert!(svc.starts_with("Claude Code-credentials-"));
        assert_eq!(svc.len(), "Claude Code-credentials-".len() + 8);
    }

    #[test]
    fn service_name_deterministic() {
        let path = Path::new("/Users/test/.claude/accounts/config-1");
        assert_eq!(service_name(path), service_name(path));
    }

    #[test]
    fn service_name_different_for_different_paths() {
        let a = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        let b = service_name(Path::new("/Users/test/.claude/accounts/config-2"));
        assert_ne!(a, b);
    }

    #[test]
    fn service_name_nfc_normalization() {
        // NFC normalization: é as single codepoint vs e + combining accent.
        let composed = service_name(Path::new("/tmp/caf\u{00e9}"));
        let decomposed = service_name(Path::new("/tmp/caf\u{0065}\u{0301}"));
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn service_name_known_paths_match_v1_python_parity() {
        // Golden values computed from v1.x Python:
        //   hashlib.sha256(unicodedata.normalize('NFC', path).encode()).hexdigest()[:8]
        // Locking these in confirms csq still derives the same name CC writes to.
        let cases = [
            (
                "/Users/test/.claude/accounts/config-1",
                "Claude Code-credentials-cfdcc24b",
            ),
            (
                "/Users/test/.claude/accounts/config-2",
                "Claude Code-credentials-550a6ea2",
            ),
        ];
        for (path, expected) in &cases {
            assert_eq!(
                &service_name(Path::new(path)),
                expected,
                "v1 parity failure for {path}"
            );
        }
    }
}
