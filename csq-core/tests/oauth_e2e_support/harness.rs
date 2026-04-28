//! `OAuthE2eHarness` — convenience wrapper for the E2E flow.
//!
//! Per-test usage:
//!
//! 1. `let h = OAuthE2eHarness::new();` — fresh tempdir, fresh state
//!    store, account number 5.
//! 2. Call one of the `race_*` methods to drive a race scenario, OR
//!    call `prepare_race` directly for tests that need to inspect the
//!    listener mid-flight.
//! 3. The harness exposes the recorder, the tempdir, and the state
//!    store so per-test assertions can read them after the race
//!    resolves.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use csq_core::credentials::{save_canonical, CredentialFile};
use csq_core::error::OAuthError;
use csq_core::oauth::{
    drive_race, exchange_code, prepare_race, OAuthStateStore, PasteResolver, RacePreparation,
    RaceResult, RaceWinner,
};
use csq_core::types::AccountNum;
use tempfile::TempDir;

use super::fake_browser;
use super::fake_transport::{ok_recording, RequestRecorder};

/// Default per-test race timeout. Chosen so the timeout test can
/// observe expiry within ~120 ms while normal-path tests still have
/// 5 s of headroom.
pub const DEFAULT_RACE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OAuthE2eHarness {
    pub base_dir: TempDir,
    pub state_store: Arc<OAuthStateStore>,
    pub account: AccountNum,
}

impl OAuthE2eHarness {
    /// Creates a fresh harness scoped to account 5. Each test creates
    /// its own — no shared state across tests.
    pub fn new() -> Self {
        let base_dir = TempDir::new().expect("create tempdir for E2E harness");
        let state_store = Arc::new(OAuthStateStore::new());
        let account = AccountNum::try_from(5).expect("5 is a valid account number");
        Self {
            base_dir,
            state_store,
            account,
        }
    }

    /// Same as `new` but for a caller-chosen account slot. Used by
    /// the cross-contamination test that races two accounts in
    /// parallel.
    pub fn with_account(account_num: u16) -> Self {
        let base_dir = TempDir::new().expect("create tempdir for E2E harness");
        let state_store = Arc::new(OAuthStateStore::new());
        let account = AccountNum::try_from(account_num).expect("valid account number");
        Self {
            base_dir,
            state_store,
            account,
        }
    }

    /// Convenience: the canonical credential file path for this
    /// harness's account, i.e. `{tempdir}/credentials/{N}.json`.
    pub fn canonical_credential_path(&self) -> std::path::PathBuf {
        self.base_dir
            .path()
            .join("credentials")
            .join(format!("{}.json", self.account))
    }

    /// Calls `prepare_race` with this harness's store and account.
    /// Exposed so individual tests can inspect the bound listener
    /// before entering the race (e.g. to fire a callback against the
    /// known port + path secret).
    pub async fn prepare(&self) -> Result<RacePreparation, OAuthError> {
        prepare_race(&self.state_store, self.account).await
    }
}

impl Default for OAuthE2eHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Persists the credentials returned by a successful `exchange_code`
/// to the harness's tempdir using the production
/// `save_canonical` path. Returns the canonical credential path so
/// the caller can read the file back and assert on its contents.
pub fn persist(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), Box<dyn std::error::Error>> {
    save_canonical(base_dir, account, creds).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Runs the full happy-path flow:
///
/// `prepare_race` → spawn a "browser" that calls the loopback path →
/// `drive_race` with a never-resolving paste resolver → `exchange_code`
/// against a recording fake transport → `save_canonical`.
///
/// Returns the [`RaceResult`] (so tests can assert on `winner`) and
/// the [`RequestRecorder`] (so tests can inspect what hit the token
/// endpoint).
///
/// `code` is the authorization code the fake browser sends; tests
/// assert this round-trips through the race and into the token POST
/// body.
pub async fn run_loopback_flow(
    h: &OAuthE2eHarness,
    code: &str,
) -> Result<(RaceResult, RequestRecorder), Box<dyn std::error::Error>> {
    let prep = h.prepare().await?;
    let port = prep.listener.port;
    let callback_path = prep.listener.callback_path();
    let state = prep.state.clone();
    let code_owned = code.to_string();

    // Spawn the fake browser AFTER the listener is bound but BEFORE
    // we enter drive_race. The accept loop is set up inside
    // drive_race, so we need to issue the request after the await
    // point — a sync `tokio::spawn` here returns immediately and the
    // task only actually runs after we await on the race.
    let browser_handle = tokio::spawn(async move {
        // Yield once so drive_race has a chance to enter its accept
        // loop before we connect. Without this the connect can race
        // ahead of the accept and produce a transient "connection
        // refused" on slow hosts.
        tokio::task::yield_now().await;
        fake_browser::callback_get(port, &callback_path, &code_owned, &state).await
    });

    let race_result =
        drive_race(prep, &h.state_store, never_resolves(), DEFAULT_RACE_TIMEOUT).await?;

    // Drain the browser task so any panic surfaces.
    let _ = browser_handle.await;

    let recorder = RequestRecorder::new();
    let creds = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        ok_recording(recorder.clone()),
    )?;

    persist(h.base_dir.path(), h.account, &creds)?;

    Ok((race_result, recorder))
}

/// Runs the full happy-path flow via the paste path. The paste
/// resolver returns immediately with a well-formed `<code>#<state>`
/// pair so the loopback listener never receives traffic.
pub async fn run_paste_flow(
    h: &OAuthE2eHarness,
    code: &str,
) -> Result<(RaceResult, RequestRecorder), Box<dyn std::error::Error>> {
    let prep = h.prepare().await?;
    let state = prep.state.clone();
    let pasted = format!("{code}#{state}");

    let race_result = drive_race(
        prep,
        &h.state_store,
        paste_returns(pasted),
        DEFAULT_RACE_TIMEOUT,
    )
    .await?;

    let recorder = RequestRecorder::new();
    let creds = exchange_code(
        race_result.winner.code(),
        &race_result.verifier,
        race_result.winner.redirect_uri(),
        ok_recording(recorder.clone()),
    )?;

    persist(h.base_dir.path(), h.account, &creds)?;

    Ok((race_result, recorder))
}

// ─── PasteResolver builders ────────────────────────────────────────

/// Paste resolver that resolves immediately with the given pasted
/// value.
pub fn paste_returns(value: String) -> PasteResolver {
    Box::new(move || Box::pin(async move { Ok(value) }))
}

/// Paste resolver that never resolves. Forces the loopback path to
/// be the only winner.
pub fn never_resolves() -> PasteResolver {
    Box::new(|| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(86_400)).await;
            Err(OAuthError::Exchange("never".to_string()))
        })
    })
}

/// Paste resolver gated on a [`tokio::sync::Notify`]. Resolves with
/// the given value only after the caller calls `notify.notify_one()`.
/// Used by the "both paths active, loopback wins" test to keep the
/// paste future alive long enough to be cancelled.
pub fn paste_when_notified(value: String, notify: Arc<tokio::sync::Notify>) -> PasteResolver {
    Box::new(move || {
        Box::pin(async move {
            notify.notified().await;
            Ok(value)
        })
    })
}

/// Convenience: assert the captured `RaceWinner` is the Loopback
/// variant and return the `(code, redirect_uri)` pair.
pub fn assert_loopback_winner(winner: &RaceWinner) -> (&str, &str) {
    match winner {
        RaceWinner::Loopback { code, redirect_uri } => (code, redirect_uri),
        other => panic!("expected Loopback winner, got {other:?}"),
    }
}

/// Convenience: assert the captured `RaceWinner` is the Paste variant
/// and return the `(code, redirect_uri)` pair.
pub fn assert_paste_winner(winner: &RaceWinner) -> (&str, &str) {
    match winner {
        RaceWinner::Paste { code, redirect_uri } => (code, redirect_uri),
        other => panic!("expected Paste winner, got {other:?}"),
    }
}
