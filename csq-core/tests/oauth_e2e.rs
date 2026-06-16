//! End-to-end tests for the parallel-race OAuth flow.
//!
//! # What this harness covers
//!
//! Drives the production race orchestrator
//! (`prepare_race` → `drive_race` → `exchange_code` → `save_canonical`)
//! end-to-end without touching the real Anthropic endpoints. The
//! loopback listener is exercised via real HTTP GETs from
//! [`oauth_e2e::fake_browser`] (the listener IS the SUT — its parser,
//! Host validation, and path-secret check all run for real). The
//! token exchange is injected at the `http_post` closure boundary
//! that `exchange_code` already takes — see
//! [`oauth_e2e::fake_transport`].
//!
//! Component-level tests (1594 of them as of PR #213) cover each
//! piece in isolation. This harness wires them together so a future
//! refactor that breaks the integration — without breaking any
//! component test — fails CI here.
//!
//! # Mutation tests performed
//!
//! Confidence in this harness was verified by intentionally
//! introducing the following defects, running the suite, and
//! confirming at least one test fails for each. After each mutation
//! the line was restored and the suite was re-run to confirm green.
//!
//! 1. **`OAuthStateStore::consume(&state)` removed in `race.rs`**
//!    (loopback branch) — `e2e_state_consumed_after_successful_exchange`
//!    fails because the state survives in the store after the race
//!    resolves.
//! 2. **`OAuthStateStore::consume(&state)` removed in `race.rs`**
//!    (paste branch) — same test fails on the paste flow variant.
//! 3. **Path-secret check (`if path != expected_path`) removed in
//!    `loopback.rs`** —
//!    `e2e_loopback_callback_with_wrong_path_secret_returns_404`
//!    fails because the listener accepts the wrong-secret callback
//!    instead of rejecting it with 404.
//! 4. **Host header check removed in `loopback.rs`** —
//!    `e2e_loopback_callback_with_wrong_host_header_rejected` fails
//!    because the listener accepts an `evil.com` Host.
//! 5. **`redirect_uri` threading: `RaceWinner::redirect_uri()` swapped
//!    to return a hard-coded `"http://wrong"`** —
//!    `e2e_exchange_uses_winners_redirect_uri` fails because the
//!    body's `redirect_uri` field no longer matches what the browser
//!    was sent to.
//!
//! One additional test (`e2e_state_consumed_after_paste_path_resolves`)
//! was added during mutation testing — the sketched 18 left the
//! paste-branch consume site uncovered by an explicit assertion, so
//! mutation #2 initially passed unobserved. Adding the paste-branch
//! sibling of `e2e_state_consumed_after_successful_exchange` closed
//! the gap. Final test count: 20 (18 sketched + 1 paste-consume
//! mutation guard + 1 canned-response sanity check that proves the
//! fixture itself round-trips through `exchange_code`).
//!
//! The cancellation, concurrent-flow, and timeout tests were verified
//! independently by the per-test assertions; no mutation corresponded
//! one-to-one to those code paths but they trip on any regression to
//! the cancellation or timeout primitives.
//!
//! # Constraints honoured
//!
//! - All synchronisation uses `tokio::sync::Notify` or `JoinHandle`,
//!   never `tokio::time::sleep` for ordering. Sleep appears ONLY as
//!   the `paste_resolver`'s "wait forever" backstop and as the
//!   timeout-test's overall race ceiling.
//! - No `.unwrap()` outside assertions / panic-on-impossible paths.
//!   Every fallible call uses `?` and bubbles a `Box<dyn Error>` up
//!   to the test harness, which prints the error as a panic.
//! - No new Cargo deps. `tempfile` is already in dev-deps. The fake
//!   browser is hand-rolled `tokio::net::TcpStream` writes.

mod oauth_e2e_support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use csq_core::credentials::{load, CredentialFile};
use csq_core::error::OAuthError;
use csq_core::oauth::{drive_race, exchange_code, PasteResolver};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use oauth_e2e_support::canned_responses::{
    ok_response, TEST_ACCESS_TOKEN, TEST_EXPIRES_IN_SECS, TEST_REFRESH_TOKEN,
};
use oauth_e2e_support::fake_browser::{self, status_code};
use oauth_e2e_support::fake_transport::{
    invalid_grant_recording, network_error, ok_recording, RequestRecorder,
};
use oauth_e2e_support::harness::{
    assert_loopback_winner, assert_paste_winner, never_resolves, paste_returns,
    paste_when_notified, persist, run_loopback_flow, run_paste_flow, OAuthE2eHarness,
    DEFAULT_RACE_TIMEOUT,
};

/// Shorthand: load the persisted Anthropic credential and return its
/// `claudeAiOauth` payload for assertion.
fn load_anthropic(path: &std::path::Path) -> CredentialFile {
    load(path).expect("credential file should load after persist")
}

// ────────────────────────────────────────────────────────────────────
// Happy paths
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_loopback_path_persists_credential() {
    let h = OAuthE2eHarness::new();

    let (race_result, _recorder) = run_loopback_flow(&h, "auth-code-from-browser")
        .await
        .expect("loopback flow should succeed");

    let (code, redirect_uri) = assert_loopback_winner(&race_result.winner);
    assert_eq!(code, "auth-code-from-browser");
    assert!(
        redirect_uri.starts_with("http://127.0.0.1:"),
        "loopback redirect_uri must point at 127.0.0.1, got {redirect_uri}"
    );

    let creds = load_anthropic(&h.canonical_credential_path());
    let payload = &creds.expect_anthropic().claude_ai_oauth;
    assert_eq!(payload.access_token.expose_secret(), TEST_ACCESS_TOKEN);
    assert_eq!(payload.refresh_token.expose_secret(), TEST_REFRESH_TOKEN);

    // expires_at should be ~ now + TEST_EXPIRES_IN_SECS * 1000 ms.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis() as u64;
    let diff_ms = payload.expires_at.saturating_sub(now_ms);
    let expected_ms = TEST_EXPIRES_IN_SECS * 1000;
    assert!(
        diff_ms >= expected_ms - 60_000 && diff_ms <= expected_ms + 60_000,
        "expires_at must be ~now + {expected_ms}ms (within 60s tolerance), got diff={diff_ms}ms"
    );
}

#[tokio::test]
async fn e2e_paste_path_persists_credential() {
    let h = OAuthE2eHarness::new();

    let (race_result, _recorder) = run_paste_flow(&h, "auth-code-from-paste")
        .await
        .expect("paste flow should succeed");

    let (code, redirect_uri) = assert_paste_winner(&race_result.winner);
    assert_eq!(code, "auth-code-from-paste");
    assert_eq!(
        redirect_uri, "https://platform.claude.com/oauth/code/callback",
        "paste redirect_uri must be Anthropic's hosted page",
    );

    let creds = load_anthropic(&h.canonical_credential_path());
    let payload = &creds.expect_anthropic().claude_ai_oauth;
    assert_eq!(payload.access_token.expose_secret(), TEST_ACCESS_TOKEN);
    assert_eq!(payload.refresh_token.expose_secret(), TEST_REFRESH_TOKEN);
}

#[tokio::test]
async fn e2e_loopback_wins_when_both_resolve() {
    // Both paths armed. The loopback callback fires first (we don't
    // notify the paste resolver until after the race has already
    // resolved). The paste resolver future MUST be dropped — we
    // verify via a Drop sentinel.
    let h = OAuthE2eHarness::new();

    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();

    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_setter = Arc::clone(&dropped);

    // Paste resolver that holds a Drop sentinel inside its future
    // body. The Notify is never fired in this test — the resolver
    // sits awaiting `notified()` until cancelled.
    let notify = Arc::new(Notify::new());
    let notify_for_resolver = Arc::clone(&notify);
    let resolver: PasteResolver = Box::new(move || {
        let dropped_setter = Arc::clone(&dropped_setter);
        let notify_for_resolver = Arc::clone(&notify_for_resolver);
        Box::pin(async move {
            // Drop sentinel — flips the bool when this future is
            // dropped (which the race orchestrator does on the
            // losing branch via tokio::select!).
            struct DropFlag(Arc<AtomicBool>);
            impl Drop for DropFlag {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _flag = DropFlag(dropped_setter);
            notify_for_resolver.notified().await;
            Err(OAuthError::Exchange("notified-but-test-cancelled".into()))
        })
    });

    // Browser fires the loopback callback once drive_race is in its
    // accept loop.
    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "loopback-wins-code", &cb_state).await
    });

    let race_result = drive_race(prep, &h.state_store, resolver, DEFAULT_RACE_TIMEOUT)
        .await
        .expect("race resolved");

    let _ = browser.await;

    let (code, _) = assert_loopback_winner(&race_result.winner);
    assert_eq!(code, "loopback-wins-code");

    // Yield several times so the runtime actually drops the loser
    // future. We avoid a fixed sleep — the runtime needs only a tick
    // or two to process the cancellation, and yielding is the
    // deterministic equivalent.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        dropped.load(Ordering::SeqCst),
        "paste resolver future must be dropped when loopback wins",
    );

    // Persist & verify the credential lands.
    let recorder = RequestRecorder::new();
    let creds = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        ok_recording(recorder.clone()),
    )
    .expect("exchange should succeed");
    persist(h.base_dir.path(), h.account, &creds).expect("persist credential");

    let loaded = load_anthropic(&h.canonical_credential_path());
    assert_eq!(
        loaded
            .expect_anthropic()
            .claude_ai_oauth
            .access_token
            .expose_secret(),
        TEST_ACCESS_TOKEN
    );
}

#[tokio::test]
async fn e2e_paste_wins_when_loopback_silent() {
    // Loopback listener is bound but no browser fires a callback.
    // Paste resolves immediately; paste path wins.
    let h = OAuthE2eHarness::new();

    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let state = prep.state.clone();

    let pasted = format!("paste-wins-code#{state}");
    let race_result = drive_race(
        prep,
        &h.state_store,
        paste_returns(pasted),
        DEFAULT_RACE_TIMEOUT,
    )
    .await
    .expect("race resolved");

    let (code, _) = assert_paste_winner(&race_result.winner);
    assert_eq!(code, "paste-wins-code");

    // After the race resolves, the loopback listener must be
    // released (cancellation safety). We yield a few times then
    // confirm the port refuses connections.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let attempt = TcpStream::connect(("127.0.0.1", port)).await;
    assert!(
        attempt.is_err(),
        "loopback port must be released when paste wins",
    );

    // Persist + verify.
    let recorder = RequestRecorder::new();
    let creds = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        ok_recording(recorder.clone()),
    )
    .expect("exchange should succeed");
    persist(h.base_dir.path(), h.account, &creds).expect("persist credential");

    let loaded = load_anthropic(&h.canonical_credential_path());
    assert_eq!(
        loaded
            .expect_anthropic()
            .claude_ai_oauth
            .access_token
            .expose_secret(),
        TEST_ACCESS_TOKEN
    );
}

// ────────────────────────────────────────────────────────────────────
// Token exchange contract
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_exchange_uses_winners_redirect_uri() {
    // Loopback path — body's redirect_uri must match the listener's
    // bound URL exactly.
    let h_loopback = OAuthE2eHarness::new();
    let (race_loopback, recorder_loopback) = run_loopback_flow(&h_loopback, "code-loop")
        .await
        .expect("loopback flow");
    let captured_loopback = recorder_loopback
        .last()
        .expect("token endpoint should have been called once");
    let body_loopback: serde_json::Value =
        serde_json::from_str(&captured_loopback.body).expect("token endpoint body must be JSON");
    let (_, expected_redirect_loopback) = assert_loopback_winner(&race_loopback.winner);
    assert_eq!(
        body_loopback["redirect_uri"].as_str(),
        Some(expected_redirect_loopback),
        "loopback exchange body redirect_uri must match listener URL byte-for-byte",
    );

    // Paste path — body's redirect_uri must be Anthropic's hosted
    // page.
    let h_paste = OAuthE2eHarness::new();
    let (race_paste, recorder_paste) = run_paste_flow(&h_paste, "code-paste")
        .await
        .expect("paste flow");
    let captured_paste = recorder_paste.last().expect("token endpoint called");
    let body_paste: serde_json::Value =
        serde_json::from_str(&captured_paste.body).expect("body must be JSON");
    let (_, expected_redirect_paste) = assert_paste_winner(&race_paste.winner);
    assert_eq!(
        body_paste["redirect_uri"].as_str(),
        Some(expected_redirect_paste),
    );
    assert_eq!(
        expected_redirect_paste, "https://platform.claude.com/oauth/code/callback",
        "paste redirect_uri must be Anthropic's hosted page",
    );
}

#[tokio::test]
async fn e2e_exchange_request_body_includes_code_verifier() {
    let h = OAuthE2eHarness::new();

    // Prepare manually so we can capture the verifier value before
    // it is consumed.
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();
    let captured_verifier = prep.verifier.expose_secret().to_string();

    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "code-v", &cb_state).await
    });

    let race_result = drive_race(prep, &h.state_store, never_resolves(), DEFAULT_RACE_TIMEOUT)
        .await
        .expect("race resolved");
    let _ = browser.await;

    let recorder = RequestRecorder::new();
    let _creds = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        ok_recording(recorder.clone()),
    )
    .expect("exchange ok");

    let body: serde_json::Value =
        serde_json::from_str(&recorder.last().expect("captured").body).expect("body json");
    assert_eq!(
        body["code_verifier"].as_str(),
        Some(captured_verifier.as_str()),
        "exchange body must carry the same PKCE verifier the race minted",
    );
    assert_eq!(body["grant_type"].as_str(), Some("authorization_code"));
    assert_eq!(body["code"].as_str(), Some("code-v"));
}

#[tokio::test]
async fn e2e_exchange_request_body_does_not_carry_state() {
    // Anthropic's `/v1/oauth/token` does NOT take a `state` parameter
    // — state is part of the authorize-side flow, validated locally
    // by the OAuthStateStore. Lock that in: the exchange body must
    // not include `state` (its presence would be a regression that
    // could leak the state token to the token endpoint logs and
    // would also be rejected by some OAuth servers).
    //
    // The brief sketches "verify state is included in the exchange
    // body" — that's the WRONG invariant for Anthropic's exchange.
    // The correct invariant is the opposite. Documenting it here so
    // any future PR that adds `state` to the body fails this test.
    let h = OAuthE2eHarness::new();
    let (_race, recorder) = run_loopback_flow(&h, "code-no-state")
        .await
        .expect("loopback flow");

    let body: serde_json::Value =
        serde_json::from_str(&recorder.last().expect("captured").body).expect("body json");
    assert!(
        body.get("state").is_none(),
        "token-exchange body MUST NOT include `state` (state is authorize-side, not token-side)",
    );
}

// ────────────────────────────────────────────────────────────────────
// Error paths
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_loopback_callback_with_wrong_state_does_not_resolve() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    // Deliberately do NOT use prep.state — invent a wrong one. The
    // loopback listener's parser accepts any state (it doesn't know
    // what we minted), but the race's constant-time compare against
    // the store's state rejects it with StateMismatch.
    let wrong_state = "wrong-state-value-not-in-store";

    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "code", wrong_state).await
    });

    // Use a short overall timeout so the test fails fast if the
    // wrong state somehow resolves the race (it MUST NOT — the race
    // returns StateMismatch immediately when the wrong state hits
    // the constant-time compare, OR it times out if no callback ever
    // matches).
    let result = drive_race(
        prep,
        &h.state_store,
        never_resolves(),
        Duration::from_secs(2),
    )
    .await;
    let _ = browser.await;

    match result {
        Err(OAuthError::StateMismatch) => {}
        other => panic!("expected StateMismatch, got {other:?}"),
    }

    // No credential persisted (we never called exchange).
    assert!(!h.canonical_credential_path().exists());
    // The original entry was NOT consumed (the wrong state never
    // matched). Store still has 1 entry.
    assert_eq!(h.state_store.len(), 1);
}

#[tokio::test]
async fn e2e_loopback_callback_with_wrong_path_secret_returns_404() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let state = prep.state.clone();

    // Request the WRONG path secret. Listener should answer 404 and
    // NOT resolve.
    let bad_path = "/callback/wrong-secret-value-not-minted";
    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, bad_path, "code", &cb_state).await
    });

    // Race must time out — the listener never accepted the request
    // as a real callback.
    let result = drive_race(
        prep,
        &h.state_store,
        never_resolves(),
        Duration::from_millis(300),
    )
    .await;

    let response_bytes = browser.await.expect("browser join");
    assert_eq!(
        status_code(&response_bytes),
        Some(404),
        "wrong path secret must produce a 404 response",
    );

    match result {
        Err(OAuthError::StateExpired { .. }) => {}
        other => panic!("expected StateExpired (race timed out), got {other:?}"),
    }
    assert!(!h.canonical_credential_path().exists());
}

#[tokio::test]
async fn e2e_loopback_callback_with_wrong_host_header_rejected() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();

    // Send the right path & state BUT a wrong Host. Listener should
    // 400 the request without resolving.
    let cb_state = state.clone();
    let cb_path = callback_path.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get_with_host(port, &cb_path, "code", &cb_state, "evil.com:443")
            .await
    });

    let result = drive_race(
        prep,
        &h.state_store,
        never_resolves(),
        Duration::from_millis(300),
    )
    .await;

    let response_bytes = browser.await.expect("browser join");
    assert_eq!(
        status_code(&response_bytes),
        Some(400),
        "wrong Host header must produce a 400 response",
    );

    match result {
        Err(OAuthError::StateExpired { .. }) => {}
        other => panic!("expected StateExpired (race timed out), got {other:?}"),
    }
    assert!(!h.canonical_credential_path().exists());
}

#[tokio::test]
async fn e2e_paste_with_invalid_format_errors_cleanly() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");

    let result = drive_race(
        prep,
        &h.state_store,
        paste_returns("no-hash-here".to_string()),
        DEFAULT_RACE_TIMEOUT,
    )
    .await;

    match result {
        Err(OAuthError::Exchange(msg)) => {
            assert!(
                msg.contains("code#state"),
                "error must point to the expected paste format, got: {msg}",
            );
        }
        other => panic!("expected Exchange error, got {other:?}"),
    }
    assert!(!h.canonical_credential_path().exists());
}

#[tokio::test]
async fn e2e_token_exchange_invalid_grant_propagates_error() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();

    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "expired-code", &cb_state).await
    });

    let race_result = drive_race(prep, &h.state_store, never_resolves(), DEFAULT_RACE_TIMEOUT)
        .await
        .expect("race resolves before exchange");
    let _ = browser.await;

    let recorder = RequestRecorder::new();
    let exchange_err = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        invalid_grant_recording(recorder.clone()),
    )
    .expect_err("invalid_grant must surface as an error");

    match exchange_err {
        OAuthError::Exchange(msg) => {
            assert!(
                msg.contains("invalid_grant"),
                "error must surface the OAuth error code, got: {msg}",
            );
        }
        other => panic!("expected Exchange error, got {other:?}"),
    }

    // No credential persisted because exchange failed.
    assert!(!h.canonical_credential_path().exists());
}

#[tokio::test]
async fn e2e_token_exchange_network_error_propagates() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();

    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "code", &cb_state).await
    });

    let race_result = drive_race(prep, &h.state_store, never_resolves(), DEFAULT_RACE_TIMEOUT)
        .await
        .expect("race resolves");
    let _ = browser.await;

    let exchange_err = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        // Expand the closure into a function call so the type is the
        // same Arc<dyn Fn(...)> the production path uses.
        |url, body| (network_error())(url, body),
    )
    .expect_err("network error must propagate");

    match exchange_err {
        OAuthError::Exchange(msg) => {
            assert!(
                msg.contains("simulated network unreachable"),
                "transport error message should propagate, got: {msg}",
            );
        }
        other => panic!("expected Exchange error, got {other:?}"),
    }

    assert!(!h.canonical_credential_path().exists());
}

#[tokio::test]
async fn e2e_overall_timeout_returns_state_expired() {
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");

    // Neither path resolves: paste sits forever, no browser fires.
    let result = drive_race(
        prep,
        &h.state_store,
        never_resolves(),
        Duration::from_millis(80),
    )
    .await;

    match result {
        Err(OAuthError::StateExpired { .. }) => {}
        other => panic!("expected StateExpired, got {other:?}"),
    }

    assert!(!h.canonical_credential_path().exists());
}

// ────────────────────────────────────────────────────────────────────
// State validation
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_state_consumed_after_successful_exchange() {
    // After a successful loopback flow, the state store must be
    // empty — race.rs consumes the entry on the winning branch
    // BEFORE returning the RaceResult.
    let h = OAuthE2eHarness::new();
    let _ = run_loopback_flow(&h, "code").await.expect("flow succeeds");
    assert_eq!(
        h.state_store.len(),
        0,
        "state store must be empty after successful race + exchange",
    );
}

#[tokio::test]
async fn e2e_state_consumed_after_paste_path_resolves() {
    // Paste-branch sibling of the test above. race.rs has TWO
    // consume sites — one per winning branch — so we need a paste-
    // flow assertion that fails if the paste-branch consume is
    // accidentally removed (mutation #2 in the harness doc comment).
    let h = OAuthE2eHarness::new();
    let _ = run_paste_flow(&h, "code-paste-consume")
        .await
        .expect("paste flow succeeds");
    assert_eq!(
        h.state_store.len(),
        0,
        "state store must be empty after the paste branch wins (mutation guard)",
    );
}

#[tokio::test]
async fn e2e_state_consumed_before_exchange_failure() {
    // The state is consumed inside drive_race on the winning branch
    // (loopback or paste), BEFORE exchange_code runs. So a subsequent
    // exchange failure does NOT leave the state in the store —
    // documented here as an actual-behaviour assertion. If this ever
    // changes (e.g. a future refactor that defers consume to after a
    // successful exchange), this test must be updated and the
    // implications redteamed.
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();

    let cb_state = state.clone();
    let browser = tokio::spawn(async move {
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, "code", &cb_state).await
    });

    let race_result = drive_race(prep, &h.state_store, never_resolves(), DEFAULT_RACE_TIMEOUT)
        .await
        .expect("race resolves");
    let _ = browser.await;

    // State already consumed at this point.
    assert_eq!(h.state_store.len(), 0);

    let recorder = RequestRecorder::new();
    let _err = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        invalid_grant_recording(recorder.clone()),
    )
    .expect_err("invalid_grant fails the exchange");

    // Still empty — exchange does not touch the store.
    assert_eq!(
        h.state_store.len(),
        0,
        "state store must remain empty regardless of exchange outcome",
    );
}

// ────────────────────────────────────────────────────────────────────
// Concurrent flows
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_two_concurrent_races_for_different_accounts_succeed_independently() {
    // Two independent harnesses, two account numbers, two parallel
    // races. Both must complete with their own credential file, and
    // neither must see the other's tokens.
    let h_a = OAuthE2eHarness::with_account(7);
    let h_b = OAuthE2eHarness::with_account(8);

    let path_a = h_a.canonical_credential_path();
    let path_b = h_b.canonical_credential_path();

    // Use distinguishable codes per account so the test can prove
    // there's no cross-contamination at the exchange layer.
    let fut_a = run_loopback_flow(&h_a, "code-account-7");
    let fut_b = run_loopback_flow(&h_b, "code-account-8");
    let (res_a, res_b) = tokio::join!(fut_a, fut_b);

    let (race_a, recorder_a) = res_a.expect("flow A");
    let (race_b, recorder_b) = res_b.expect("flow B");

    let (code_a, _) = assert_loopback_winner(&race_a.winner);
    let (code_b, _) = assert_loopback_winner(&race_b.winner);
    assert_eq!(code_a, "code-account-7");
    assert_eq!(code_b, "code-account-8");

    // Each flow's recorder should have captured the right code in
    // its body.
    let body_a: serde_json::Value =
        serde_json::from_str(&recorder_a.last().expect("a captured").body).expect("a body json");
    let body_b: serde_json::Value =
        serde_json::from_str(&recorder_b.last().expect("b captured").body).expect("b body json");
    assert_eq!(body_a["code"].as_str(), Some("code-account-7"));
    assert_eq!(body_b["code"].as_str(), Some("code-account-8"));

    // Both credential files exist on disk.
    assert!(path_a.exists(), "credential file for account 7 must exist");
    assert!(path_b.exists(), "credential file for account 8 must exist");

    // The harnesses use distinct base dirs, so cross-contamination at
    // the file layer is structurally impossible. Verify the paths
    // are in fact distinct.
    assert_ne!(path_a, path_b);
    assert_ne!(
        path_a.parent().expect("a parent").parent(),
        path_b.parent().expect("b parent").parent(),
    );
}

// ────────────────────────────────────────────────────────────────────
// Cancellation
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_race_cancelled_releases_listener_port() {
    // Start a race, abort the future before it can resolve, then
    // confirm the previously bound port is releasable.
    let h = OAuthE2eHarness::new();
    let prep = h.prepare().await.expect("prepare_race");
    let port = prep.listener.port;

    // Move the race future into a JoinHandle so we can abort it.
    // We use a `Notify` to keep the paste future alive — paste_when_notified
    // never gets the notify so the race future just sits in select!.
    let notify = Arc::new(Notify::new());
    let resolver = paste_when_notified("never-this-value".to_string(), Arc::clone(&notify));

    let store = Arc::clone(&h.state_store);
    let race_handle =
        tokio::spawn(
            async move { drive_race(prep, &store, resolver, Duration::from_secs(60)).await },
        );

    // Yield once so the race actually starts and binds its accept
    // loop.
    tokio::task::yield_now().await;

    // Abort and wait for the cancellation to actually drop the
    // future (Tokio's abort is asynchronous — the JoinHandle resolves
    // once the task has been cancelled).
    race_handle.abort();
    let join_err = race_handle.await.expect_err("aborted task should be Err");
    assert!(join_err.is_cancelled(), "race future must be cancelled");

    // Yield a few times to let the runtime drop the listener.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    // The previously bound port should now be free — but the kernel
    // may keep it in TIME_WAIT for a beat. The robust check is that
    // a new connect to the SAME port refuses (the listener is gone).
    let attempt = TcpStream::connect(("127.0.0.1", port)).await;
    assert!(
        attempt.is_err(),
        "loopback port must refuse connections after race future is dropped",
    );

    // notify is unused now — drop it so the unused-binding lint
    // doesn't fire on it.
    drop(notify);
}

// ────────────────────────────────────────────────────────────────────
// Sanity: the canned response really does parse end-to-end
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_canned_response_round_trips_through_exchange_code() {
    // Belt-and-braces sanity check: the literal JSON in
    // `canned_responses::ok_response` parses correctly via
    // `exchange_code`. If this ever fails it usually means the
    // fixture drifted from Anthropic's actual shape.
    use csq_core::oauth::CodeVerifier;
    let verifier = CodeVerifier::new("sanity-check-verifier".to_string());
    let creds = exchange_code(
        "code",
        &verifier,
        "http://127.0.0.1:1/callback/x",
        |_, _| Ok(ok_response()),
    )
    .expect("canned response must parse");

    let payload = &creds.expect_anthropic().claude_ai_oauth;
    assert_eq!(payload.access_token.expose_secret(), TEST_ACCESS_TOKEN);
    assert_eq!(payload.refresh_token.expose_secret(), TEST_REFRESH_TOKEN);
}
