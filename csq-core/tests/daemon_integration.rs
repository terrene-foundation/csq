//! Integration tests for the daemon client–server round-trip.
//!
//! These tests start a real axum server on a temporary Unix socket,
//! then exercise the `daemon::client::http_get_unix` helper against
//! it — proving the full stack from CLI client through the HTTP
//! layer to the handler and back.
//!
//! The existing unit tests in `daemon/server.rs` use raw
//! `tokio::net::UnixStream` writes and reads, which test the
//! handler logic but bypass the `client.rs` parser. These
//! integration tests prove the two halves compose correctly.

#![cfg(unix)]

use csq_core::credentials::{self, CredentialFile, OAuthPayload};
use csq_core::daemon::{
    cache::TtlCache,
    client::{http_get_unix, http_get_unix_with_timeout},
    server::{serve, RouterState, DISCOVERY_CACHE_MAX_AGE},
};
use csq_core::oauth::OAuthStateStore;
use csq_core::types::{AccessToken, AccountNum, RefreshToken};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn make_router_state(base: &Path) -> RouterState {
    RouterState {
        cache: Arc::new(TtlCache::with_default_age()),
        discovery_cache: Arc::new(TtlCache::new(DISCOVERY_CACHE_MAX_AGE)),
        base_dir: Arc::new(base.to_path_buf()),
        oauth_store: Some(Arc::new(OAuthStateStore::new())),
        oauth_port: csq_core::oauth::DEFAULT_REDIRECT_PORT,
    }
}

fn install_creds(base: &Path, account: u16) {
    let num = AccountNum::try_from(account).unwrap();
    let creds = CredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new(format!("at-{account}")),
            refresh_token: RefreshToken::new(format!("rt-{account}")),
            expires_at: 9_999_999_999_999,
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        },
        extra: HashMap::new(),
    };
    credentials::save(
        &csq_core::credentials::file::canonical_path(base, num),
        &creds,
    )
    .unwrap();
}

/// Helper: starts a server, runs the test body, shuts down.
async fn with_server<F, Fut>(base: &Path, f: F)
where
    F: FnOnce(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let sock = base.join("csq-test.sock");
    let (handle, join) = serve(&sock, make_router_state(base))
        .await
        .unwrap();

    f(sock.clone()).await;

    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

// ─── Health ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_health_round_trip() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/health").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"status\":\"ok\""));
        assert!(resp.body.contains("\"version\":\""));
    })
    .await;
}

// ─── Accounts ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_accounts_empty() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/accounts").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"accounts\":[]"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_accounts_discovers_installed_creds() {
    let dir = TempDir::new().unwrap();
    install_creds(dir.path(), 1);
    install_creds(dir.path(), 2);

    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/accounts").unwrap();
        assert_eq!(resp.status, 200);

        let json: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        let accounts = json["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().any(|a| a["id"] == 1));
        assert!(accounts.iter().any(|a| a["id"] == 2));
    })
    .await;
}

// ─── Login ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_login_returns_authorize_url() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/login/3").unwrap();
        assert_eq!(resp.status, 200);

        let json: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        let auth_url = json["auth_url"].as_str().unwrap();
        assert!(
            auth_url.contains("oauth/authorize"),
            "auth_url should be an Anthropic authorize URL: {auth_url}"
        );
        assert_eq!(json["account"], 3);
        assert!(json["expires_in_secs"].as_u64().unwrap() > 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_login_rejects_invalid_account() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/login/0").unwrap();
        assert_eq!(resp.status, 400);
    })
    .await;
}

// ─── Refresh status ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_refresh_status_empty() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/refresh-status").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"statuses\":[]"));
    })
    .await;
}

// ─── 404 ─────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_unknown_route_404() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_get_unix(&sock, "/api/nonexistent").unwrap();
        assert_eq!(resp.status, 404);
    })
    .await;
}

// ─── Timeout ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_connect_fails_after_shutdown() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("csq-test.sock");

    let (handle, join) = serve(&sock, make_router_state(dir.path()))
        .await
        .unwrap();

    // Verify it works first
    let resp = http_get_unix(&sock, "/api/health").unwrap();
    assert_eq!(resp.status, 200);

    // Shut down
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    // Client should fail to connect
    let err = http_get_unix_with_timeout(&sock, "/api/health", Duration::from_millis(200));
    assert!(err.is_err(), "should fail after shutdown");
}
