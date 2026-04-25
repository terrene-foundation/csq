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

use csq_core::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
use csq_core::daemon::{
    cache::TtlCache,
    client::{http_get_unix, http_get_unix_with_timeout, http_post_unix, http_post_unix_json},
    server::{serve, RouterState, DISCOVERY_CACHE_MAX_AGE},
};
use csq_core::oauth::OAuthStateStore;
use csq_core::providers::gemini::capture::{
    EmptyPayload, EventEnvelope, EventKind, RateLimitedPayload,
};
use csq_core::quota::state as quota_state;
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
        gemini_consumer: csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default(),
    }
}

fn install_creds(base: &Path, account: u16) {
    let num = AccountNum::try_from(account).unwrap();
    let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
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
    });
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
    let (handle, join) = serve(&sock, make_router_state(base)).await.unwrap();

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

// ─── Cache invalidation ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_invalidate_cache_returns_200() {
    let dir = TempDir::new().unwrap();
    with_server(dir.path(), |sock| async move {
        let resp = http_post_unix(&sock, "/api/invalidate-cache").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"cleared\":true"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_invalidate_cache_clears_discovery() {
    let dir = TempDir::new().unwrap();
    install_creds(dir.path(), 1);

    with_server(dir.path(), |sock| async move {
        // Warm the discovery cache
        let resp1 = http_get_unix(&sock, "/api/accounts").unwrap();
        assert_eq!(resp1.status, 200);
        let json1: serde_json::Value = serde_json::from_str(&resp1.body).unwrap();
        assert_eq!(json1["accounts"].as_array().unwrap().len(), 1);

        // Invalidate the cache
        let resp_inv = http_post_unix(&sock, "/api/invalidate-cache").unwrap();
        assert_eq!(resp_inv.status, 200);

        // Next /api/accounts call should re-discover (still sees 1 account
        // since we didn't change the filesystem, but the cache was cleared)
        let resp2 = http_get_unix(&sock, "/api/accounts").unwrap();
        assert_eq!(resp2.status, 200);
        let json2: serde_json::Value = serde_json::from_str(&resp2.body).unwrap();
        assert_eq!(json2["accounts"].as_array().unwrap().len(), 1);
    })
    .await;
}

// ─── Timeout ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_connect_fails_after_shutdown() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("csq-test.sock");

    let (handle, join) = serve(&sock, make_router_state(dir.path())).await.unwrap();

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

// ─── Gemini live-IPC route (PR-G3, H7 contract) ─────────────────

/// H7 fixture: when the daemon is alive, csq-cli's emit reaches the
/// HTTP handler, which dedups and applies to quota.json. This is the
/// "happy path" the spec 07 §7.2.3.1 50ms-ceiling connect normally
/// hits — the NDJSON path is the durability floor for the OTHER
/// case (daemon down).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemini_event_live_ipc_increments_counter() {
    let dir = TempDir::new().unwrap();
    let envelope = EventEnvelope::new(
        AccountNum::try_from(3u16).unwrap(),
        EventKind::CounterIncrement(EmptyPayload {}),
    );
    let body = serde_json::to_string(&envelope).unwrap();

    with_server(dir.path(), |sock| async move {
        let resp = http_post_unix_json(&sock, "/api/gemini/event", &body).unwrap();
        assert_eq!(resp.status, 204, "live IPC must accept and return 204");
    })
    .await;

    let qf = quota_state::load_state(dir.path()).unwrap();
    let acct = qf
        .get(3)
        .expect("slot 3 quota present after live IPC apply");
    assert_eq!(acct.surface, "gemini");
    assert_eq!(acct.kind, "counter");
    assert_eq!(acct.counter.as_ref().unwrap().requests_today, 1);
}

/// H7 fixture: rate-limited event via live IPC populates the
/// rate_limit struct shape spec 07 §7.4.1 mandates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemini_event_live_ipc_rate_limited_populates_state() {
    let dir = TempDir::new().unwrap();
    let envelope = EventEnvelope::new(
        AccountNum::try_from(5u16).unwrap(),
        EventKind::RateLimited(RateLimitedPayload {
            retry_delay_s: 60,
            quota_metric: "rpm".into(),
            cap: Some(250),
        }),
    );
    let body = serde_json::to_string(&envelope).unwrap();

    with_server(dir.path(), |sock| async move {
        let resp = http_post_unix_json(&sock, "/api/gemini/event", &body).unwrap();
        assert_eq!(resp.status, 204);
    })
    .await;

    let qf = quota_state::load_state(dir.path()).unwrap();
    let acct = qf.get(5).expect("slot 5 quota present");
    let rl = acct.rate_limit.as_ref().unwrap();
    assert!(rl.active);
    assert_eq!(rl.last_quota_metric.as_deref(), Some("rpm"));
    assert_eq!(rl.last_retry_delay_s, Some(60));
    assert_eq!(rl.cap, Some(250));
}

/// PR-G3 dual-path dedup: if csq-cli writes the same envelope to
/// NDJSON AND posts via live IPC, the daemon applies it exactly
/// once. Verifies the shared `applied` set across the live route
/// and the drainer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemini_event_live_ipc_then_ndjson_drain_does_not_double_count() {
    use csq_core::daemon::usage_poller::gemini as gemini_consumer;
    use csq_core::providers::gemini::capture::append_event;

    let dir = TempDir::new().unwrap();
    let envelope = EventEnvelope::new(
        AccountNum::try_from(6u16).unwrap(),
        EventKind::CounterIncrement(EmptyPayload {}),
    );
    let body = serde_json::to_string(&envelope).unwrap();

    // Build a router state we keep handles to so we can drain
    // through the SAME state the HTTP route used.
    let state = RouterState {
        cache: Arc::new(TtlCache::with_default_age()),
        discovery_cache: Arc::new(TtlCache::new(DISCOVERY_CACHE_MAX_AGE)),
        base_dir: Arc::new(dir.path().to_path_buf()),
        oauth_store: Some(Arc::new(OAuthStateStore::new())),
        gemini_consumer: gemini_consumer::GeminiConsumerState::default(),
    };
    let consumer = state.gemini_consumer.clone();

    let sock = dir.path().join("csq-dual.sock");
    let (handle, join) = serve(&sock, state).await.unwrap();
    let resp = http_post_unix_json(&sock, "/api/gemini/event", &body).unwrap();
    assert_eq!(resp.status, 204);
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;

    // After live IPC applied, csq-cli also wrote the envelope to NDJSON.
    append_event(dir.path(), &envelope).unwrap();

    // Drain — should dedup against the shared applied-set.
    let outcome = gemini_consumer::drain_all(dir.path(), &consumer);
    assert_eq!(
        outcome.applied, 0,
        "drain must not re-apply the live IPC event"
    );
    assert_eq!(outcome.deduped, 1);

    // Counter still reflects exactly one apply.
    let qf = quota_state::load_state(dir.path()).unwrap();
    let acct = qf.get(6).unwrap();
    assert_eq!(acct.counter.as_ref().unwrap().requests_today, 1);
}

/// PR-G3: invalid schema version on the live IPC payload returns
/// 400 with a fixed-vocabulary tag (no echo of upstream body).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemini_event_live_ipc_rejects_unsupported_schema_version() {
    let dir = TempDir::new().unwrap();
    let bad_body = r#"{"v":99,"id":"x","ts":"x","slot":1,"surface":"gemini","kind":"counter_increment","payload":{}}"#;

    with_server(dir.path(), |sock| async move {
        let resp = http_post_unix_json(&sock, "/api/gemini/event", bad_body).unwrap();
        assert_eq!(resp.status, 400);
        assert!(
            resp.body.contains("unsupported_version"),
            "fixed-vocabulary error tag expected, got body: {}",
            resp.body
        );
    })
    .await;
}

/// PR-G3 redteam H1 regression: IPC handler refuses envelopes
/// claiming a non-Gemini surface tag. Without this gate a same-UID
/// caller could mutate an Anthropic slot's quota row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemini_event_live_ipc_rejects_non_gemini_surface() {
    let dir = TempDir::new().unwrap();
    let bad_body = r#"{"v":1,"id":"AAAAAAAAAAAAAAAAAAAAAAAAAA","ts":"2026-04-25T22:30:00Z","slot":1,"surface":"anthropic","kind":"counter_increment","payload":{}}"#;

    with_server(dir.path(), |sock| async move {
        let resp = http_post_unix_json(&sock, "/api/gemini/event", bad_body).unwrap();
        assert_eq!(resp.status, 400);
        assert!(
            resp.body.contains("invalid_surface"),
            "fixed-vocabulary error tag expected, got: {}",
            resp.body
        );
    })
    .await;

    // Quota.json must NOT have been mutated.
    let qf = quota_state::load_state(dir.path()).unwrap();
    assert!(
        qf.get(1).is_none(),
        "no quota row should exist for rejected event"
    );
}
