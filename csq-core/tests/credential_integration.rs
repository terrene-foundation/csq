//! Integration tests for credential management.
//!
//! Tests keychain service name parity, round-trip file operations,
//! refresh token merge, concurrent access, and canonical save mirroring.

use csq_core::credentials::file::{canonical_path, live_path, load, save, save_canonical};
use csq_core::credentials::keychain::service_name;
use csq_core::credentials::refresh::{
    merge_refresh, refresh_token, RefreshResponse, TOKEN_ENDPOINT,
};
use csq_core::credentials::{CredentialFile, OAuthPayload};
use csq_core::types::{AccessToken, AccountNum, RefreshToken};
use std::collections::HashMap;
use tempfile::TempDir;

fn sample_creds() -> CredentialFile {
    CredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new("sk-ant-oat01-integration-test".into()),
            refresh_token: RefreshToken::new("sk-ant-ort01-integration-test".into()),
            expires_at: 1775726524877,
            scopes: vec![
                "user:file_upload".into(),
                "user:inference".into(),
                "user:mcp_servers".into(),
                "user:profile".into(),
                "user:sessions:claude_code".into(),
            ],
            subscription_type: Some("max".into()),
            rate_limit_tier: Some("default_claude_max_20x".into()),
            extra: HashMap::new(),
        },
        extra: HashMap::new(),
    }
}

// ── Keychain service name parity ──────────────────────────────────────

#[test]
fn keychain_service_name_known_paths() {
    // Golden values computed from v1.x Python:
    //   hashlib.sha256(unicodedata.normalize('NFC', path).encode()).hexdigest()[:8]
    // This is the single most critical parity test for credential migration.
    let expected = [
        (
            "/Users/test/.claude/accounts/config-1",
            "Claude Code-credentials-cfdcc24b",
        ),
        (
            "/Users/test/.claude/accounts/config-2",
            "Claude Code-credentials-550a6ea2",
        ),
        (
            "/Users/test/.claude/accounts/config-3",
            "Claude Code-credentials-d705092c",
        ),
        (
            "/home/user/.claude/accounts/config-1",
            "Claude Code-credentials-abf1dc4a",
        ),
        (
            "/tmp/.claude/accounts/config-1",
            "Claude Code-credentials-dbea6435",
        ),
    ];

    for (path, expected_name) in &expected {
        let actual = service_name(std::path::Path::new(path));
        assert_eq!(
            &actual, expected_name,
            "v1.x parity failure for path {path}: got {actual}, expected {expected_name}"
        );
    }
}

// ── Round-trip file operations ────────────────────────────────────────

#[test]
fn full_credential_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("creds.json");

    let original = sample_creds();
    save(&path, &original).unwrap();

    // Read back the raw JSON to verify structure
    let raw = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

    // Verify CC-compatible key names (camelCase)
    assert!(parsed["claudeAiOauth"].is_object());
    assert!(parsed["claudeAiOauth"]["accessToken"].is_string());
    assert!(parsed["claudeAiOauth"]["refreshToken"].is_string());
    assert!(parsed["claudeAiOauth"]["expiresAt"].is_number());
    assert!(parsed["claudeAiOauth"]["subscriptionType"].is_string());
    assert!(parsed["claudeAiOauth"]["rateLimitTier"].is_string());

    // Load and verify values
    let loaded = load(&path).unwrap();
    assert_eq!(
        loaded.claude_ai_oauth.access_token.expose_secret(),
        "sk-ant-oat01-integration-test"
    );
    assert_eq!(loaded.claude_ai_oauth.scopes.len(), 5);
    assert_eq!(
        loaded.claude_ai_oauth.subscription_type.as_deref(),
        Some("max")
    );
}

#[test]
fn unknown_fields_survive_round_trip() {
    let json = r#"{
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-test",
            "refreshToken": "sk-ant-ort01-test",
            "expiresAt": 1000,
            "scopes": [],
            "subscriptionType": "max",
            "rateLimitTier": "tier",
            "futureOAuthField": {"nested": true},
            "anotherFuture": [1, 2, 3]
        },
        "futureTopLevel": "preserved",
        "futureNested": {"a": 1}
    }"#;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("future.json");

    let creds: CredentialFile = serde_json::from_str(json).unwrap();
    save(&path, &creds).unwrap();
    let loaded = load(&path).unwrap();
    let reserialized = serde_json::to_value(&loaded).unwrap();

    assert_eq!(reserialized["futureTopLevel"], "preserved");
    assert_eq!(reserialized["futureNested"]["a"], 1);
    assert_eq!(
        reserialized["claudeAiOauth"]["futureOAuthField"]["nested"],
        true
    );
    assert_eq!(reserialized["claudeAiOauth"]["anotherFuture"][1], 2);
}

// ── Refresh merge verification ────────────────────────────────────────

#[test]
fn refresh_merge_preserves_all_metadata() {
    let original = sample_creds();

    let response = RefreshResponse {
        access_token: "sk-ant-oat01-refreshed-new".into(),
        refresh_token: "sk-ant-ort01-refreshed-new".into(),
        expires_in: 18000,
        scope: None,
    };

    let merged = merge_refresh(&original, &response);

    // Tokens updated
    assert_eq!(
        merged.claude_ai_oauth.access_token.expose_secret(),
        "sk-ant-oat01-refreshed-new"
    );
    assert_eq!(
        merged.claude_ai_oauth.refresh_token.expose_secret(),
        "sk-ant-ort01-refreshed-new"
    );

    // Expiry updated (should be ~18000s from now)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(merged.claude_ai_oauth.expires_at > now_ms);
    assert!(merged.claude_ai_oauth.expires_at < now_ms + 20_000_000);

    // Metadata preserved
    assert_eq!(
        merged.claude_ai_oauth.subscription_type.as_deref(),
        Some("max")
    );
    assert_eq!(
        merged.claude_ai_oauth.rate_limit_tier.as_deref(),
        Some("default_claude_max_20x")
    );
    assert_eq!(merged.claude_ai_oauth.scopes.len(), 5);
}

#[test]
fn refresh_merge_with_extra_fields_preserved() {
    let json = r#"{
        "claudeAiOauth": {
            "accessToken": "old",
            "refreshToken": "old",
            "expiresAt": 1000,
            "scopes": ["a"],
            "customField": "must survive refresh"
        }
    }"#;

    let original: CredentialFile = serde_json::from_str(json).unwrap();

    let response = RefreshResponse {
        access_token: "new".into(),
        refresh_token: "new".into(),
        expires_in: 18000,
        scope: None,
    };

    let merged = merge_refresh(&original, &response);
    let value = serde_json::to_value(&merged).unwrap();

    assert_eq!(
        value["claudeAiOauth"]["customField"],
        "must survive refresh"
    );
}

// ── Canonical save ────────────────────────────────────────────────────

#[test]
fn canonical_save_creates_correct_directory_structure() {
    let dir = TempDir::new().unwrap();
    let account = AccountNum::try_from(5u16).unwrap();

    save_canonical(dir.path(), account, &sample_creds()).unwrap();

    let canonical = canonical_path(dir.path(), account);
    let live = live_path(dir.path(), account);

    assert!(canonical.exists(), "canonical file should exist");
    assert!(live.exists(), "live file should exist");

    // Both should have the same content
    let c_content = std::fs::read_to_string(&canonical).unwrap();
    let l_content = std::fs::read_to_string(&live).unwrap();
    assert_eq!(c_content, l_content);

    // Both should be valid credential files
    let c_loaded = load(&canonical).unwrap();
    let l_loaded = load(&live).unwrap();
    assert_eq!(
        c_loaded.claude_ai_oauth.access_token.expose_secret(),
        l_loaded.claude_ai_oauth.access_token.expose_secret()
    );
}

// ── Concurrent access ─────────────────────────────────────────────────

#[test]
fn concurrent_credential_saves() {
    use std::sync::Arc;
    use std::thread;

    let dir = TempDir::new().unwrap();
    let path = Arc::new(dir.path().join("concurrent.json"));

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let path = Arc::clone(&path);
            thread::spawn(move || {
                for j in 0..50 {
                    let creds = CredentialFile {
                        claude_ai_oauth: OAuthPayload {
                            access_token: AccessToken::new(format!("t{i}_{j}")),
                            refresh_token: RefreshToken::new(format!("r{i}_{j}")),
                            expires_at: 1000 + i * 100 + j,
                            scopes: vec![],
                            subscription_type: None,
                            rate_limit_tier: None,
                            extra: HashMap::new(),
                        },
                        extra: HashMap::new(),
                    };
                    let _ = save(&path, &creds);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Final file must be valid JSON
    let loaded = load(&path).unwrap();
    assert!(
        loaded
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .starts_with('t'),
        "final access token should be from one of the writers"
    );
}

// ── File permission verification ──────────────────────────────────────

#[cfg(unix)]
#[test]
fn all_credential_files_have_600_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let account = AccountNum::try_from(1u16).unwrap();

    save_canonical(dir.path(), account, &sample_creds()).unwrap();

    for path in [
        canonical_path(dir.path(), account),
        live_path(dir.path(), account),
    ] {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file {:?} should be 0o600", path);
    }
}

// ── save_canonical partial failure ────────────────────────────────────

#[cfg(unix)]
#[test]
fn save_canonical_succeeds_when_live_dir_unwritable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let account = AccountNum::try_from(2u16).unwrap();

    // Create the live config dir and make it unwritable
    let live_dir = dir.path().join("config-2");
    std::fs::create_dir_all(&live_dir).unwrap();
    std::fs::set_permissions(&live_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

    // save_canonical should succeed — canonical write works, live fails silently
    let result = save_canonical(dir.path(), account, &sample_creds());
    assert!(
        result.is_ok(),
        "canonical save should succeed even when live dir is unwritable"
    );

    // Canonical file should exist
    assert!(canonical_path(dir.path(), account).exists());

    // Restore permissions for cleanup
    std::fs::set_permissions(&live_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// ── refresh_token URL and body verification ───────────────────────────

#[test]
fn refresh_token_passes_correct_url_and_body() {
    let existing = sample_creds();

    let captured_url = std::cell::RefCell::new(String::new());
    let captured_body = std::cell::RefCell::new(String::new());

    let result = refresh_token(&existing, |url, body| {
        *captured_url.borrow_mut() = url.to_string();
        *captured_body.borrow_mut() = body.to_string();
        Ok(br#"{"access_token":"new","refresh_token":"new","expires_in":18000}"#.to_vec())
    });

    assert!(result.is_ok());
    assert_eq!(*captured_url.borrow(), TOKEN_ENDPOINT);

    let body = captured_body.borrow();
    assert!(
        body.starts_with("grant_type=refresh_token&refresh_token="),
        "body: {body}"
    );
    assert!(
        body.contains("sk-ant-ort01-integration-test"),
        "body should contain the refresh token"
    );
}

// ── IPC error string mapping ──────────────────────────────────────────

#[test]
fn csq_error_ipc_mapping_coverage() {
    use csq_core::error::*;

    // NotFound -> NOT_FOUND
    let err = CsqError::Credential(CredentialError::NotFound {
        path: std::path::PathBuf::from("/tmp/test"),
    });
    let s: String = err.into();
    assert!(s.starts_with("NOT_FOUND:"), "got: {s}");

    // RefreshTokenInvalid -> LOGIN_REQUIRED
    let err = CsqError::Broker(BrokerError::RefreshTokenInvalid { account: 1 });
    let s: String = err.into();
    assert!(s.starts_with("LOGIN_REQUIRED:"), "got: {s}");

    // StateMismatch -> CSRF_ERROR
    let err = CsqError::OAuth(OAuthError::StateMismatch);
    let s: String = err.into();
    assert!(s.starts_with("CSRF_ERROR:"), "got: {s}");

    // Other -> INTERNAL_ERROR
    let err = CsqError::Platform(PlatformError::Io(std::io::Error::other("test")));
    let s: String = err.into();
    assert!(s.starts_with("INTERNAL_ERROR:"), "got: {s}");
}

// ── OAuthError body sanitization ──────────────────────────────────────

#[test]
fn oauth_error_http_redacts_tokens_in_body() {
    use csq_core::error::OAuthError;

    let err = OAuthError::Http {
        status: 401,
        body: "invalid token: sk-ant-oat01-leaked-value and sk-ant-ort01-leaked-refresh".into(),
    };
    let display = format!("{err}");
    assert!(
        !display.contains("leaked-value"),
        "access token should be redacted: {display}"
    );
    assert!(
        !display.contains("leaked-refresh"),
        "refresh token should be redacted: {display}"
    );
    assert!(
        display.contains("[REDACTED]"),
        "should contain redaction marker: {display}"
    );
}
