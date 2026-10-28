//! Live OAuth parallel-race integration tests.
//!
//! Both tests are gated `#[ignore]` because they require the user
//! to interactively complete an OAuth flow with Anthropic — there
//! is no recorded fixture to replay against. They are NOT run by
//! `cargo test`; the operator runs them with:
//!
//! ```bash
//! cargo test -p csq-core --test oauth_race_live -- --ignored --nocapture
//! ```
//!
//! # What each test exercises
//!
//! 1. `live_loopback_path` — binds the listener, opens the
//!    browser to the auto URL, and waits for the loopback callback.
//!    The user authorises in their default browser; the test exits
//!    when the loopback path wins.
//!
//! 2. `live_paste_path` — same setup but the user is expected to
//!    copy the manual URL to a separate device, complete the
//!    authorisation there, and paste the displayed `<code>#<state>`
//!    back into the test stdin.
//!
//! Neither test writes credentials to disk (no `save_canonical`
//! call). They terminate after the race resolves, validating only
//! that the orchestration shape works end-to-end against the live
//! Anthropic authorize endpoint.
//!
//! # Why not in CI
//!
//! Anthropic's authorize endpoint requires a live human at a
//! browser; there is no headless completion path. CI integration
//! would either need a recorded HAR replay (incompatible with
//! Cloudflare's TLS fingerprint check) or a dedicated test
//! account whose credentials would be exposed in the workflow's
//! browser session.

use csq_core::oauth::{self, RaceWinner};
use csq_core::types::AccountNum;
use std::sync::Arc;
use std::time::Duration;

fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).status();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .status();
}

#[tokio::test]
#[ignore = "live OAuth — requires interactive browser authorization"]
async fn live_loopback_path() {
    let store = Arc::new(oauth::OAuthStateStore::new());
    let prep = oauth::prepare_race(&store, AccountNum::try_from(99).unwrap())
        .await
        .expect("prepare_race");

    eprintln!();
    eprintln!("=== Live loopback OAuth test ===");
    eprintln!("Opening browser to:");
    eprintln!("  {}", prep.auto_url);
    eprintln!();
    eprintln!("Authorize in the browser. The test exits when the");
    eprintln!("loopback callback fires (you should NOT need to paste).");

    open_in_browser(&prep.auto_url);

    // Paste resolver that never resolves — forces the loopback
    // path to be the only winner.
    let never: oauth::PasteResolver = Box::new(|| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(86400)).await;
            Err(csq_core::error::OAuthError::Exchange("never".into()))
        })
    });

    let result = oauth::drive_race(prep, &store, never, Duration::from_secs(600))
        .await
        .expect("race resolved");

    match result.winner {
        RaceWinner::Loopback {
            code, redirect_uri, ..
        } => {
            assert!(!code.is_empty(), "captured code should be non-empty");
            assert!(redirect_uri.starts_with("http://127.0.0.1:"));
            eprintln!("✓ Loopback path won. Code captured.");
        }
        other => panic!("expected Loopback winner, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "live OAuth — requires interactive paste of authorization code"]
async fn live_paste_path() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let store = Arc::new(oauth::OAuthStateStore::new());
    let prep = oauth::prepare_race(&store, AccountNum::try_from(99).unwrap())
        .await
        .expect("prepare_race");

    eprintln!();
    eprintln!("=== Live paste-code OAuth test ===");
    eprintln!("Open this URL on a SEPARATE device or browser session:");
    eprintln!("  {}", prep.manual_url);
    eprintln!();
    eprintln!("After authorizing, copy the displayed code and paste");
    eprintln!("it (with the '#<state>' suffix) into this terminal:");

    let paste_resolver: oauth::PasteResolver = Box::new(|| {
        Box::pin(async {
            let stdin = tokio::io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| csq_core::error::OAuthError::Exchange(format!("stdin: {e}")))?;
            Ok(line.trim().to_string())
        })
    });

    let result = oauth::drive_race(prep, &store, paste_resolver, Duration::from_secs(600))
        .await
        .expect("race resolved");

    match result.winner {
        RaceWinner::Paste {
            code, redirect_uri, ..
        } => {
            assert!(!code.is_empty());
            assert!(redirect_uri.starts_with("https://platform.claude.com/"));
            eprintln!("✓ Paste path won. Code captured.");
        }
        other => panic!("expected Paste winner, got {other:?}"),
    }
}
