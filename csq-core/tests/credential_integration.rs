//! Integration tests for credential management.
//!
//! Tests keychain service name parity, round-trip file operations,
//! refresh token merge, concurrent access, and canonical save mirroring.

use csq_core::credentials::file::{canonical_path, live_path, load, save, save_canonical};
use csq_core::credentials::keychain::service_name;
use csq_core::credentials::refresh::{merge_refresh, RefreshResponse};
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
    // Verify deterministic output for known paths
    let paths_and_expected_prefix = [
        "/Users/test/.claude/accounts/config-1",
        "/Users/test/.claude/accounts/config-2",
        "/Users/test/.claude/accounts/config-3",
        "/home/user/.claude/accounts/config-1",
        "/tmp/.claude/accounts/config-1",
    ];

    let mut names: Vec<String> = vec![];
    for path in &paths_and_expected_prefix {
        let name = service_name(std::path::Path::new(path));
        assert!(name.starts_with("Claude Code-credentials-"));
        assert_eq!(name.len(), "Claude Code-credentials-".len() + 8);
        // Each path should produce a unique name
        assert!(
            !names.contains(&name),
            "duplicate service name for {path}: {name}"
        );
        names.push(name);
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
