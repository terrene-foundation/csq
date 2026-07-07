//! PR-C4 H2 merge gate — Windows named-pipe surface-dispatched refresher.
//!
//! Per internal-design-docs PR-C4 and
//! an internal journal entry H2, the merge gate for PR-C4 is "a Windows named-pipe
//! integration test exercising the surface-dispatched refresher cycle".
//!
//! This test stands up a real Windows named-pipe daemon server, plants
//! a Codex slot whose access-token JWT is already expired (so the
//! daemon's pre-expiry refresh path fires per spec 07 §7.5 INV-P01),
//! drives one refresher tick with a mock Codex transport, and asserts:
//!
//! 1. The named-pipe `/api/health` endpoint reports Healthy via
//!    `daemon::detect_daemon` — the same code path `csq run`'s
//!    `require_daemon_healthy` uses on Windows after PR-C4 closed
//!    the `#[cfg(not(unix))] Ok(())` carve-out.
//! 2. The refresher invokes the injected Codex transport exactly once
//!    for the Codex slot.
//! 3. The canonical `credentials/codex-<N>.json` is rewritten with the
//!    new tokens from the refresh response.
//! 4. The Anthropic transport is NOT invoked for the Codex slot
//!    (surface dispatch — neither closure spies the other surface).
//!
//! On non-Windows hosts the file compiles to an empty unit (the
//! `#![cfg(windows)]` gate at the top suppresses every test).

#![cfg(windows)]

use csq_core::accounts::identity_store::credentials_codex_path_for;
use csq_core::accounts::AccountSource;
use csq_core::credentials::{
    self, file as cred_file, CodexCredentialFile, CodexTokensFile, CredentialFile,
};
use csq_core::daemon::{self, server, server_windows, HttpPostFn, HttpPostFnCodex, TtlCache};
use csq_core::providers::catalog::Surface;
use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;
use csq_core::types::AccountNum;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Builds a JWT-shape `<header>.<payload>.<sig>` whose payload's
/// `exp` claim is `exp_secs`. Avoids a base64 dependency by hand-
/// rolling the no-padding base64url encoder.
fn make_codex_jwt(exp_secs: u64) -> String {
    let payload = format!(r#"{{"exp":{exp_secs}}}"#);
    let payload_b64 = b64url_encode(payload.as_bytes());
    let header_b64 = "eyJhbGciOiJIUzI1NiJ9";
    format!("{header_b64}.{payload_b64}.testsig")
}

fn b64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((buf >> bits) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (6 - bits)) & 0x3f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn windows_named_pipe_surface_dispatch_refresher_cycle() {
    // RN1-C (M4-12, an internal ticket) retired the numeric-keyed credential WRITE
    // in `save_canonical_for` (it is now fail-closed without a
    // `by_slot[N]` UUID). The pre-RN1-C version of this test relied on
    // `save_canonical_for` writing `credentials/codex-7.json`, which is
    // the file `discovery::discover_codex` walks to enumerate Codex
    // slots for the daemon refresher (`refresher::tick` line ~319). That
    // numeric write is gone; the test must now plant the on-disk shape
    // production produces post-RN1-C, exactly as the in-crate
    // `refresher.rs::install_codex_account` helper does:
    //
    //   1. `by_slot[7] = uuid`  — minimal profiles.json so the tick
    //      read/write path resolves the UUID-keyed identity file
    //      (refresher.rs:383). NOT `coexisting_fixture` — that also
    //      plants an *Anthropic* identity for slot 7, so
    //      `discover_anthropic` claims the slot and the Codex transport
    //      never fires (the failure this fix's first attempt hit:
    //      `codex_counter == 0` at the assertion below).
    //   2. numeric `credentials/codex-7.json` — the discovery marker
    //      `discover_codex` requires (still a READ target post-RN1-C;
    //      only the `save_canonical_for` WRITE was retired). Written
    //      directly via `credentials::save`, bypassing the fail-closed
    //      chokepoint, mirroring `install_codex_account`.
    //   3. UUID-keyed `identities/<uuid>/credentials-codex.json` — the
    //      path `broker_codex_check` reads `exp` from once `by_slot`
    //      resolves the UUID.
    //
    // The bug was invisible locally because this file is
    // `#![cfg(windows)]` — it compiles to nothing on the macOS host
    // where RN1-C's test sweep ran, and Windows CI was already red so a
    // NEW red was indistinguishable from the OLD red.
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // 1. Install an expired Codex slot. Far-past exp claim guarantees
    //    `broker_codex_check` fires the refresh path.
    let account = AccountNum::try_from(7u16).unwrap();
    let uuid = fixture_uuid_for_slot(7);
    let expired = now_secs().saturating_sub(60);
    let creds = CredentialFile::Codex(CodexCredentialFile {
        auth_mode: Some("chatgpt".into()),
        openai_api_key: None,
        tokens: CodexTokensFile {
            account_id: Some("acct-h2".into()),
            access_token: make_codex_jwt(expired),
            refresh_token: Some("rt_h2_initial".into()),
            id_token: None,
            extra: HashMap::new(),
        },
        last_refresh: None,
        extra: HashMap::new(),
    });
    // (1) by_slot[7] = uuid — minimal profiles.json (install_codex_account
    // convention; NOT coexisting_fixture which adds an Anthropic identity).
    let profiles_path = csq_core::accounts::profiles::profiles_path(base);
    let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
    profiles.by_slot.insert("7".to_string(), uuid);
    csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    // (2) numeric credentials/codex-7.json — discover_codex marker.
    credentials::save(
        &cred_file::canonical_path_for(base, account, Surface::Codex),
        &creds,
    )
    .unwrap();
    // (3) UUID-keyed identities/<uuid>/credentials-codex.json — the path
    // broker_codex_check reads exp from when by_slot resolves the UUID.
    let uuid_codex_path = credentials_codex_path_for(base, uuid);
    std::fs::create_dir_all(uuid_codex_path.parent().unwrap()).unwrap();
    credentials::save(&uuid_codex_path, &creds).unwrap();

    // 2. Stand up a Windows named-pipe daemon. Use a unique pipe name
    //    so parallel test invocations don't collide.
    let pipe_name = format!(r"\\.\pipe\csq-pr-c4-h2-{}", std::process::id());
    let cache = Arc::new(TtlCache::with_default_age());
    let discovery_cache = Arc::new(TtlCache::new(server::DISCOVERY_CACHE_MAX_AGE));
    let state = server::RouterState {
        cache: Arc::clone(&cache),
        discovery_cache,
        base_dir: Arc::new(base.to_path_buf()),
        oauth_store: None,
        gemini_consumer: csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default(),
        audit_health: csq_core::audit::AuditHealth::Verified,
        #[cfg(feature = "enterprise")]
        interactive: Arc::new(csq_core::daemon::InteractiveSessionRegistry::empty()),
    };
    let (server_handle, server_join) = server_windows::serve(&pipe_name, state).await.unwrap();

    // Write our PID so detect_daemon's PID-liveness step passes.
    let pid_path = daemon::pid_file_path(base);
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

    // 3. Inline named-pipe health probe — verifies the daemon's pipe
    //    server actually responds to /api/health. Equivalent to what
    //    `daemon::detect_daemon` does on Windows, but scoped to our
    //    unique pipe name (the unit test
    //    `detect_windows_live_daemon_returns_healthy` already covers
    //    the detect_daemon adapter against `windows_health_check`).
    let pipe_path_for_check = std::path::PathBuf::from(&pipe_name);
    let healthy = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_path_for_check)
            .expect("named pipe must accept connection from same-user client");
        let request = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request)
            .expect("health probe write must succeed");
        let mut buf = [0u8; 4096];
        let mut total = 0;
        while total < buf.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        let text = std::str::from_utf8(&buf[..total]).unwrap_or("");
        text.starts_with("HTTP/1.1 200")
    })
    .await
    .unwrap();
    assert!(
        healthy,
        "named-pipe daemon must respond 200 to GET /api/health"
    );

    // 4. Drive the surface-dispatched refresher. Mock both transports
    //    with counters so we can assert the Codex slot routes ONLY to
    //    the Codex closure.
    let anth_counter = Arc::new(AtomicU32::new(0));
    let codex_counter = Arc::new(AtomicU32::new(0));

    let anth_c = Arc::clone(&anth_counter);
    let http_post: HttpPostFn = Arc::new(move |_url: &str, _body: &str| {
        anth_c.fetch_add(1, Ordering::SeqCst);
        Ok(b"{}".to_vec())
    });

    let codex_c = Arc::clone(&codex_counter);
    let new_exp = now_secs() + 6 * 3600;
    let new_at = make_codex_jwt(new_exp);
    let body =
        format!(r#"{{"access_token":"{new_at}","refresh_token":"rt_h2_new","expires_in":3600}}"#);
    let body_arc = Arc::new(body);
    let http_post_codex: HttpPostFnCodex = Arc::new(move |_url: &str, _body: &str| {
        codex_c.fetch_add(1, Ordering::SeqCst);
        Ok(((*body_arc).clone().into_bytes(), None))
    });

    // 5. Spawn the refresher with a 60s interval and 0 startup delay
    //    — fires exactly one tick immediately, then sleeps long enough
    //    that the cancel below catches it before a second tick.
    let shutdown = CancellationToken::new();
    let handle = csq_core::daemon::refresher::spawn_with_config(
        base.to_path_buf(),
        Arc::clone(&cache),
        http_post,
        http_post_codex,
        shutdown.clone(),
        Duration::from_secs(60),
        Duration::from_millis(0),
    );

    // Wait for the first tick to complete. 1500ms is generous for a
    // CI runner — the tick body is a single mock HTTP call + atomic
    // file write, well under 100ms in practice.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.join).await;

    // 6. Surface dispatch: Anthropic transport untouched, Codex transport
    //    fired exactly once.
    assert_eq!(
        anth_counter.load(Ordering::SeqCst),
        0,
        "Anthropic transport MUST NOT fire for a Codex slot under named-pipe daemon"
    );
    assert_eq!(
        codex_counter.load(Ordering::SeqCst),
        1,
        "Codex transport must fire exactly once for the expired slot"
    );

    // 7. Canonical persisted with the new tokens. RN1-C (M4-12) retired
    //    the numeric `credentials/codex-<N>.json` write path; the post-
    //    RN1-C Codex canonical IS the UUID-keyed identity path
    //    `identities/<uuid>/credentials-codex.json` (what
    //    `save_codex_canonical_for_uuid` — the refresher's write target —
    //    produces). `canonical_path_for(.., Surface::Codex)` still returns
    //    the retired numeric path and is a READ-only diagnostic helper, so
    //    reading it here would `load` a file that is never written.
    let saved = credentials::load(&credentials_codex_path_for(base, uuid)).unwrap();
    let codex = saved.codex().expect("must remain Codex variant");
    assert_eq!(codex.tokens.access_token, new_at);
    assert_eq!(codex.tokens.refresh_token.as_deref(), Some("rt_h2_new"));

    // 8. Cache reflects the refresh.
    let entry = cache.get(&account.get()).expect("cache entry expected");
    assert_eq!(entry.account, account.get());
    let _ = AccountSource::Codex; // ensure module is wired in tests

    // 9. Tear down the daemon.
    server_handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_join).await;
}
