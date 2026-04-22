//! Credential file I/O — load, save, and canonical save with mirroring.

use super::mutex::AccountMutexTable;
use super::CredentialFile;
use crate::error::CredentialError;
use crate::platform::fs::{atomic_replace, secure_file, secure_file_readonly};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Loads a credential file from disk.
///
/// Returns `CredentialError::NotFound` if the file does not exist,
/// `CredentialError::Corrupt` if the JSON is invalid.
pub fn load(path: &Path) -> Result<CredentialFile, CredentialError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredentialError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            CredentialError::Io {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    if content.trim().is_empty() {
        return Err(CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "empty file".into(),
        });
    }

    serde_json::from_str(&content).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Saves a credential file to disk with atomic write + secure permissions.
pub fn save(path: &Path, creds: &CredentialFile) -> Result<(), CredentialError> {
    let json = serde_json::to_string_pretty(creds).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("serialization failed: {e}"),
    })?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    // Use a unique temp file name to prevent race conditions when
    // multiple callers save to the same path concurrently (per-PID
    // AND per-thread via atomic counter).
    let tmp = crate::platform::fs::unique_tmp_path(path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;

    // Set permissions on the temp file BEFORE rename so the credential
    // file is never world-readable at its final path.
    secure_file(&tmp).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;

    atomic_replace(&tmp, path).map_err(|e| CredentialError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;

    Ok(())
}

/// Saves credentials to both canonical and live paths. Surface is
/// derived from the [`CredentialFile`] variant; the write target
/// paths are automatically Anthropic or Codex.
///
/// Thin wrapper over [`save_canonical_for`] for pre-PR-C2a callers
/// that do not inspect the return surface.
///
/// If the canonical write succeeds but the live write fails, a warning
/// is logged but the error is not propagated — the canonical file is
/// the authoritative source.
pub fn save_canonical(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    save_canonical_for(base_dir, account, creds)
}

/// Surface-dispatched canonical write.
///
/// Per spec 07 INV-P08 / INV-P09:
///
/// 1. Surface is derived from `creds.surface()` (PR-C2b) — no caller
///    surface parameter, so data shape and path shape cannot drift.
/// 2. Acquires the per-`(Surface, AccountNum)` write mutex from the
///    process-global [`AccountMutexTable`]. Serialises concurrent
///    writers within one process; cross-process serialisation is the
///    flock'd `refresh-lock` path in [`crate::broker::check`].
/// 3. Writes the canonical file atomically (atomic_replace + 0o600
///    via [`secure_file`], identical to [`save`]).
/// 4. For [`Surface::Codex`] only, flips the canonical file to 0o400
///    after the write — the canonical Codex credential file lives at
///    0o400 outside narrow refresh windows per INV-P08. Anthropic
///    canonicals stay at 0o600 (unchanged behaviour).
/// 5. Writes the live mirror into the account's `config-<N>/` dir.
///    Mirror failures are logged with a fixed-vocabulary tag and
///    swallowed; the canonical is authoritative.
///
/// The 0o600-first-then-0o400 ordering matters on POSIX: `atomic_replace`
/// overwrites the target's inode, so the newly-written tmp file's mode
/// (set by [`secure_file`] before rename) is what lands on disk. A
/// prior-file-at-0o400 state is therefore not a writability obstacle.
/// The post-write flip to 0o400 is the active INV-P08 guarantee.
pub fn save_canonical_for(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let surface = creds.surface();
    let slot_mutex = AccountMutexTable::global().get_or_insert(surface, account);
    let _guard = slot_mutex.lock().expect("per-account write mutex poisoned");

    let canonical = canonical_path_for(base_dir, account, surface);
    save(&canonical, creds)?;

    if surface == Surface::Codex {
        // INV-P08: Codex canonical lives at 0o400 between refresh windows.
        // Tolerate a missing platform-fs helper on non-unix via the helper's
        // own no-op Windows branch.
        if let Err(e) = secure_file_readonly(&canonical) {
            warn!(
                account = %account,
                surface = %surface,
                error_kind = "canonical_mode_flip_failed",
                "failed to flip canonical credential file to 0o400 after write"
            );
            return Err(CredentialError::Io {
                path: canonical,
                source: std::io::Error::other(e.to_string()),
            });
        }
    }

    let live = live_path_for(base_dir, account, surface);
    if let Err(e) = save(&live, creds) {
        // Journal 0063 L2 / PR-B2 — fixed error-kind tag per security.md Rule 2.
        // Was `error = %e` which formats CredentialError's Display; while
        // Display shouldn't carry tokens today, emitting `{e}` here ties log
        // content to error struct shape, so a future Display refactor that
        // embeds upstream payload fragments (e.g. include the invalid JSON
        // slice for Corrupt variants) could silently regress this log site.
        // Fixed-vocabulary tag is forward-safe and matches the mirror-write
        // failure mode one-to-one.
        let kind = match &e {
            CredentialError::Io { .. } => "mirror_write_io",
            CredentialError::Corrupt { .. } => "mirror_write_corrupt",
            CredentialError::NotFound { .. } => "mirror_write_not_found",
            _ => "mirror_write_other",
        };
        warn!(
            account = %account,
            surface = %surface,
            error_kind = kind,
            "failed to mirror credentials to live config dir (canonical save succeeded)"
        );
    }

    Ok(())
}

/// Returns the canonical credential file path for the
/// [`Surface::ClaudeCode`] surface: `{base_dir}/credentials/{N}.json`.
///
/// Thin wrapper over [`canonical_path_for`] preserving the pre-PR-C2a
/// 2-argument signature for existing Anthropic-only call sites.
pub fn canonical_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    canonical_path_for(base_dir, account, Surface::ClaudeCode)
}

/// Surface-dispatched canonical credential file path.
///
/// | Surface     | Path                                       |
/// |-------------|--------------------------------------------|
/// | ClaudeCode  | `{base_dir}/credentials/{N}.json`          |
/// | Codex       | `{base_dir}/credentials/codex-{N}.json`    |
///
/// The Codex path shape is fixed by spec 07 §7.2.2.
pub fn canonical_path_for(base_dir: &Path, account: AccountNum, surface: Surface) -> PathBuf {
    let filename = match surface {
        Surface::ClaudeCode => format!("{}.json", account),
        Surface::Codex => format!("codex-{}.json", account),
    };
    base_dir.join("credentials").join(filename)
}

/// Returns the live credential file path for the [`Surface::ClaudeCode`]
/// surface: `{base_dir}/config-{N}/.credentials.json`.
///
/// Thin wrapper over [`live_path_for`] preserving the pre-PR-C2a
/// 2-argument signature for existing Anthropic-only call sites.
pub fn live_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    live_path_for(base_dir, account, Surface::ClaudeCode)
}

/// Surface-dispatched live-mirror credential file path.
///
/// | Surface     | Path (inside `config-{N}/`)  |
/// |-------------|------------------------------|
/// | ClaudeCode  | `.credentials.json`          |
/// | Codex       | `codex-auth.json`            |
///
/// The Codex path shape is fixed by spec 07 §7.2.2.
pub fn live_path_for(base_dir: &Path, account: AccountNum, surface: Surface) -> PathBuf {
    let filename = match surface {
        Surface::ClaudeCode => ".credentials.json",
        Surface::Codex => "codex-auth.json",
    };
    base_dir.join(format!("config-{}", account)).join(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn sample_creds() -> CredentialFile {
        CredentialFile::Anthropic(crate::credentials::AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test".into()),
                expires_at: 1775726524877,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn sample_codex_creds() -> CredentialFile {
        CredentialFile::Codex(crate::credentials::CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: crate::credentials::CodexTokensFile {
                account_id: Some("test-account-uuid".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.test-at.sig".into(),
                refresh_token: Some("rt_test".into()),
                id_token: Some("eyJhbGciOiJIUzI1NiJ9.test-id.sig".into()),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        })
    }

    #[test]
    fn round_trip_load_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        let original = sample_creds();
        save(&path, &original).unwrap();

        let loaded = load(&path).unwrap();
        let a = loaded.anthropic().expect("sample is Anthropic");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test"
        );
        assert_eq!(a.claude_ai_oauth.expires_at, 1775726524877);
    }

    #[test]
    fn load_missing_file_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        match load(&path) {
            Err(CredentialError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn load_corrupt_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { .. }) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn load_empty_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(reason.contains("empty"), "reason: {reason}");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        save(&path, &sample_creds()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deep").join("creds.json");

        save(&path, &sample_creds()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn canonical_save_writes_both_files() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        save_canonical(dir.path(), account, &sample_creds()).unwrap();

        assert!(canonical_path(dir.path(), account).exists());
        assert!(live_path(dir.path(), account).exists());
    }

    #[test]
    fn canonical_and_live_paths_correct() {
        let base = Path::new("/home/user/.claude/accounts");
        let account = AccountNum::try_from(7u16).unwrap();

        assert_eq!(
            canonical_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/credentials/7.json")
        );
        assert_eq!(
            live_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/config-7/.credentials.json")
        );
    }

    #[test]
    fn flatten_preserves_unknown_fields() {
        let json = r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-t",
                "refreshToken": "sk-ant-ort01-t",
                "expiresAt": 1000,
                "scopes": [],
                "futureField": 42
            },
            "futureTopLevel": "hello"
        }"#;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rt.json");

        let creds: CredentialFile = serde_json::from_str(json).unwrap();
        save(&path, &creds).unwrap();

        let loaded = load(&path).unwrap();
        let reserialized = serde_json::to_value(&loaded).unwrap();

        assert_eq!(reserialized["futureTopLevel"], "hello");
        assert_eq!(reserialized["claudeAiOauth"]["futureField"], 42);
    }

    // ── PR-C2a tests: surface-param paths + mutex + mode-flip ──────────

    #[test]
    fn canonical_path_for_claude_code_matches_legacy() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(3u16).unwrap();
        assert_eq!(
            canonical_path_for(base, account, Surface::ClaudeCode),
            canonical_path(base, account)
        );
    }

    #[test]
    fn canonical_path_for_codex_prefixes_filename() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(3u16).unwrap();
        assert_eq!(
            canonical_path_for(base, account, Surface::Codex),
            PathBuf::from("/base/credentials/codex-3.json")
        );
    }

    #[test]
    fn live_path_for_claude_code_matches_legacy() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(4u16).unwrap();
        assert_eq!(
            live_path_for(base, account, Surface::ClaudeCode),
            live_path(base, account)
        );
    }

    #[test]
    fn live_path_for_codex_is_codex_auth_json() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(4u16).unwrap();
        assert_eq!(
            live_path_for(base, account, Surface::Codex),
            PathBuf::from("/base/config-4/codex-auth.json")
        );
    }

    #[test]
    fn save_canonical_claude_code_matches_save_canonical_for() {
        // Both paths must write to the same files for Surface::ClaudeCode.
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        save_canonical(dir.path(), account, &sample_creds()).unwrap();
        assert!(canonical_path(dir.path(), account).exists());
        assert!(live_path(dir.path(), account).exists());

        // Overwrite via explicit surface form — same paths are hit.
        save_canonical_for(dir.path(), account, &sample_creds()).unwrap();
        assert!(canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists());
    }

    #[test]
    fn save_canonical_for_codex_writes_codex_prefixed_paths() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();

        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();

        let canonical = canonical_path_for(dir.path(), account, Surface::Codex);
        let live = live_path_for(dir.path(), account, Surface::Codex);
        assert!(
            canonical.exists(),
            "codex canonical must land at {canonical:?}"
        );
        assert!(live.exists(), "codex live mirror must land at {live:?}");
        assert_eq!(
            canonical.file_name().unwrap().to_str().unwrap(),
            "codex-6.json"
        );
        assert_eq!(
            live.file_name().unwrap().to_str().unwrap(),
            "codex-auth.json"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_claude_code_leaves_canonical_at_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();

        save_canonical_for(dir.path(), account, &sample_creds()).unwrap();

        let canonical = canonical_path_for(dir.path(), account, Surface::ClaudeCode);
        let mode = std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "ClaudeCode canonical must remain at 0o600 (no mode-flip)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_codex_leaves_canonical_at_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(8u16).unwrap();

        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();

        let canonical = canonical_path_for(dir.path(), account, Surface::Codex);
        let mode = std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o400,
            "Codex canonical must be flipped to 0o400 after write (INV-P08)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_codex_round_trip_400_write_400() {
        // INV-P08 round-trip: canonical sits at 0o400; a subsequent write
        // must succeed despite the prior mode and leave the file at 0o400.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();

        // First write: file lands at 0o400.
        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();
        let canonical = canonical_path_for(dir.path(), account, Surface::Codex);
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o400,
        );

        // Second write: atomic_replace must still succeed even though the
        // prior file is 0o400 (non-writable). This verifies the writer
        // does not rely on the prior mode being 0o600.
        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o400,
            "second Codex write must end at 0o400",
        );
    }

    #[test]
    fn save_canonical_for_concurrent_writers_produce_valid_file() {
        // The per-account mutex serialises writers. All threads must
        // complete without error and the final file must be well-formed
        // (fully written, not truncated mid-replace).
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(11u16).unwrap();
        let base = Arc::new(dir.path().to_path_buf());

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let base = Arc::clone(&base);
                thread::spawn(move || save_canonical_for(&base, account, &sample_creds()))
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("write must succeed under mutex");
        }

        let canonical = canonical_path(&base, account);
        // File must be parseable JSON — no torn writes.
        let loaded = load(&canonical).expect("post-write canonical must parse");
        let a = loaded.anthropic().expect("sample is Anthropic");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test"
        );
    }

    // ── PR-C2b tests: enum-variant-driven dispatch ─────────────────────

    #[test]
    fn save_canonical_for_dispatches_to_codex_when_variant_is_codex() {
        // save_canonical_for no longer accepts a Surface parameter — the
        // write target is derived from the CredentialFile variant. This
        // test verifies a Codex variant lands at the codex-prefixed
        // canonical without the caller naming the surface.
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(12u16).unwrap();

        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();

        assert!(
            canonical_path_for(dir.path(), account, Surface::Codex).exists(),
            "Codex variant must write to codex-prefixed canonical"
        );
        assert!(
            !canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "Codex variant must NOT write to ClaudeCode canonical"
        );
    }

    #[test]
    fn save_canonical_for_dispatches_to_anthropic_when_variant_is_anthropic() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(13u16).unwrap();

        save_canonical_for(dir.path(), account, &sample_creds()).unwrap();

        assert!(
            canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "Anthropic variant must write to ClaudeCode canonical"
        );
        assert!(
            !canonical_path_for(dir.path(), account, Surface::Codex).exists(),
            "Anthropic variant must NOT write to Codex canonical"
        );
    }
}
