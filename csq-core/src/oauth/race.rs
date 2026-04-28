//! Parallel-race OAuth orchestrator.
//!
//! Mirrors CC's `services/oauth/index.ts:58-86` pattern: start a
//! loopback callback listener and a paste-code resolver in parallel,
//! return whichever completes first, cancel the loser cleanly.
//!
//! # Why race
//!
//! The user has two ways to complete an OAuth login:
//!
//! 1. Their browser opens the auto URL (`?redirect_uri=http://127.0.0.1:<port>/callback`).
//!    Anthropic redirects back to the loopback listener. No paste needed.
//! 2. The browser cannot open (remote SSH, sandbox, missing default
//!    browser) so they manually paste the URL into a different
//!    machine, copy the code Anthropic shows, and paste it back.
//!
//! Either path resolves the same OAuth flow against the same PKCE
//! verifier and state token. The race orchestrator drives both
//! paths simultaneously and binds the winner.
//!
//! # State validation
//!
//! Both paths run through the SAME [`OAuthStateStore::consume`]
//! call. The store enforces single-use semantics, so even if both
//! paths somehow resolve simultaneously, only one consume succeeds —
//! the second sees [`OAuthError::StateMismatch`] and returns harmless.
//!
//! Defense-in-depth: csq validates state locally, BEFORE calling
//! the token endpoint. CC's reference flow trusts the server's
//! state echo; we deliberately do not — the local state store is
//! cheap and catches a class of bugs (state mismatch, replay) that
//! the server might silently accept.
//!
//! # Cancellation
//!
//! `tokio::select!` drops the loser's future automatically on the
//! winner's resolution. The loopback listener releases its bound
//! port on drop (proven by `loopback::tests::dropping_listener_releases_port`).
//! The paste_resolver MUST itself be cancellation-safe: dropping
//! the future MUST NOT leave stdin in a half-read state that
//! corrupts later reads. The CLI implementation reads one line
//! atomically so dropping the future can only abort an in-flight
//! `read_line`, which is fine.

use crate::error::OAuthError;
use crate::oauth::constants::PASTE_CODE_REDIRECT_URI;
use crate::oauth::login::build_auth_url;
use crate::oauth::loopback::{generate_path_secret, CallbackParams, LoopbackListener};
use crate::oauth::pkce::{challenge_from_verifier, generate_verifier, CodeVerifier};
use crate::oauth::state_store::{constant_time_eq_state, OAuthStateStore};
use crate::types::AccountNum;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Default overall race timeout. Generous — a user who walks away
/// to approve an MFA challenge can take several minutes. After
/// this point the race aborts and surfaces [`OAuthError::StateExpired`].
pub const DEFAULT_OVERALL_TIMEOUT: Duration = Duration::from_secs(600);

/// A type-erased paste-code resolver future.
///
/// The CLI wires this to "read one line from stdin"; tests wire
/// canned futures to drive both winner paths deterministically.
///
/// The string the future resolves to MUST be in CC's paste format:
/// `<authorization_code>#<state_token>` (a single `#` separator).
/// See `services/oauth/index.ts:138-153` in the CC source — the
/// hosted code page joins the two values with `#` so the user
/// pastes a single token.
pub type PasteResolver =
    Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<String, OAuthError>> + Send>> + Send>;

/// Inputs to [`race_login`].
pub struct RaceConfig {
    /// State store the verifier + state are inserted into and
    /// later consumed from. Both paths share one store.
    pub state_store: Arc<OAuthStateStore>,
    /// Account this login targets. Bound onto the [`OAuthStateStore`]
    /// entry so the consume side knows which credential slot to write.
    pub account: AccountNum,
    /// Resolver for the paste-code path. Receives no arguments —
    /// the caller closes over its own stdin reader.
    pub paste_resolver: PasteResolver,
    /// Hard ceiling on the total race. Defaults to
    /// [`DEFAULT_OVERALL_TIMEOUT`] in [`race_login`] if you want
    /// the production value; tests override with millisecond-scale
    /// values to exercise the timeout path.
    pub overall_timeout: Duration,
}

/// Which path won the race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceWinner {
    /// The browser hit the loopback listener.
    Loopback { code: String, redirect_uri: String },
    /// The user pasted the code from Anthropic's hosted page.
    Paste { code: String, redirect_uri: String },
}

impl RaceWinner {
    /// Convenience: returns the `redirect_uri` that must be passed
    /// verbatim to [`crate::oauth::exchange_code`]. PKCE binds the
    /// authorization code to its original redirect_uri, so the
    /// exchange MUST match the URI the authorize URL carried.
    pub fn redirect_uri(&self) -> &str {
        match self {
            RaceWinner::Loopback { redirect_uri, .. } => redirect_uri,
            RaceWinner::Paste { redirect_uri, .. } => redirect_uri,
        }
    }

    /// Convenience: returns the captured authorization code.
    pub fn code(&self) -> &str {
        match self {
            RaceWinner::Loopback { code, .. } => code,
            RaceWinner::Paste { code, .. } => code,
        }
    }
}

/// What the orchestrator returns once the race resolves.
///
/// `Debug` is implemented manually to avoid printing the verifier
/// (which would expose the PKCE secret in any panic message that
/// formats this type). The verifier is shown as `[REDACTED]`.
pub struct RaceResult {
    /// Which path won. Carries the captured code + redirect_uri.
    pub winner: RaceWinner,
    /// The auto URL (loopback redirect). The CLI opens this in
    /// the browser. Returned even after the race resolves so
    /// callers can log it for support / replay.
    pub auto_url: String,
    /// The manual / paste-code URL. The CLI prints this after a
    /// short delay so the user can paste it on a separate device.
    pub manual_url: String,
    /// State token shared by both URLs. Useful for tracing.
    pub state: String,
    /// PKCE verifier. The caller MUST pass this to
    /// [`crate::oauth::exchange_code`] alongside [`RaceWinner::code`]
    /// and [`RaceWinner::redirect_uri`]. Held until the exchange
    /// completes, then dropped (zeroized via `secrecy::SecretString`).
    pub verifier: CodeVerifier,
}

impl std::fmt::Debug for RaceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaceResult")
            .field("winner", &self.winner)
            .field("auto_url", &self.auto_url)
            .field("manual_url", &self.manual_url)
            .field("state", &self.state)
            .field("verifier", &"[REDACTED]")
            .finish()
    }
}

/// Bound listener handle returned by [`prepare_race`].
///
/// Exposed so the CLI can print URLs (and start the browser)
/// before entering the actual race loop. Drop this to release the
/// listener without consuming the verifier.
pub struct RacePreparation {
    /// The bound loopback listener. Will be moved into
    /// [`drive_race`] when the race starts.
    pub listener: LoopbackListener,
    pub auto_url: String,
    pub manual_url: String,
    pub state: String,
    pub verifier: CodeVerifier,
    /// The challenge sent in both URLs. Stored so a subsequent
    /// rebuild (e.g., the CLI re-printing the URLs) doesn't
    /// recompute SHA256.
    #[allow(dead_code)]
    pub(crate) challenge_str: String,
    /// The full loopback redirect URI used in `auto_url`. Stored so
    /// `drive_race` can pass it verbatim to `exchange_code` (PKCE
    /// binds the issued code to the original redirect_uri, so the
    /// exchange MUST match byte-for-byte). Includes the per-race
    /// `/callback/<path_secret>` path.
    pub(crate) loopback_redirect: String,
}

/// Two-phase split of [`race_login`] so the CLI can:
///
/// 1. Bind the listener and build the URLs (this function).
/// 2. Print the auto URL and try to open the browser.
/// 3. Enter the actual race loop ([`drive_race`]).
///
/// Splitting the bind from the accept lets the CLI surface a
/// useful error early ("port refused / sandbox forbids loopback")
/// without entering the long-running race.
///
/// # Path-secret minting (SEC-R1-01)
///
/// A fresh 16-byte URL-safe base64 secret is minted per call and
/// embedded in the loopback redirect URI as
/// `http://127.0.0.1:<port>/callback/<path_secret>`. The listener
/// only accepts requests on that exact path (combined with a
/// matching `Host:` header). A same-host attacker who scrapes the
/// auto URL (e.g., from a tauri event) gets the secret too — the
/// secret alone is not the security boundary; combined with the
/// Host check and the local single-use state token it raises the
/// bar against cross-origin browser fetches.
pub async fn prepare_race(
    state_store: &OAuthStateStore,
    account: AccountNum,
) -> Result<RacePreparation, OAuthError> {
    let path_secret = generate_path_secret();
    let listener = LoopbackListener::bind(path_secret.clone()).await?;
    let port = listener.port;
    let callback_path = listener.callback_path();

    let verifier = generate_verifier();
    let challenge = challenge_from_verifier(&verifier);
    // Insert a CLONE of the verifier into the store so the
    // orchestrator can keep its copy for the eventual token
    // exchange. The store retains its copy until consume()
    // removes it on the winning path. Both copies wrap the same
    // SecretString contents but are zeroized independently on
    // drop.
    //
    // If the store is at capacity, propagate the error directly
    // (UX-R1-L2). The orchestrator never silently drops a request.
    let state = state_store.insert(verifier.clone(), account)?;

    let loopback_redirect = format!("http://127.0.0.1:{port}{callback_path}");
    let auto_url = build_auth_url(&state, &challenge, &loopback_redirect);
    let manual_url = build_auth_url(&state, &challenge, PASTE_CODE_REDIRECT_URI);

    Ok(RacePreparation {
        listener,
        auto_url,
        manual_url,
        state,
        verifier,
        challenge_str: challenge.as_str().to_string(),
        loopback_redirect,
    })
}

/// Drives the actual race once preparation is complete.
///
/// `tokio::select!` polls the loopback accept and the paste
/// resolver concurrently. On the first resolution:
/// - The loser's future is dropped (closing the listener or
///   aborting the stdin read).
/// - The captured code + state are validated against the store.
/// - Returns the [`RaceResult`].
///
/// On overall_timeout: both futures are cancelled, the store
/// retains the entry until the next sweep / TTL expiry, and we
/// return [`OAuthError::StateExpired`].
pub async fn drive_race(
    prep: RacePreparation,
    state_store: &OAuthStateStore,
    paste_resolver: PasteResolver,
    overall_timeout: Duration,
) -> Result<RaceResult, OAuthError> {
    let RacePreparation {
        listener,
        auto_url,
        manual_url,
        state,
        verifier,
        challenge_str: _,
        loopback_redirect: auto_redirect,
    } = prep;

    let race = async {
        let listener_fut = listener.accept_one();
        let paste_fut = paste_resolver();

        // Pin both for tokio::select!.
        tokio::pin!(listener_fut);
        tokio::pin!(paste_fut);

        tokio::select! {
            // Loopback path — the browser hit our listener.
            res = &mut listener_fut => {
                let CallbackParams { code, state: cb_state } = res?;
                // SEC-R2-06: constant-time comparison. State tokens are
                // 43 base64url chars (32 bytes of CSPRNG output) — short
                // and known-length, but a per-byte early-exit comparison
                // gives a same-host attacker a timing oracle on every
                // failed match. Routing through `subtle::ConstantTimeEq`
                // collapses the timing surface to "checked" whether the
                // strings match or not.
                if !constant_time_eq_state(&cb_state, &state) {
                    // Validate against the original we minted.
                    // Anthropic must echo state verbatim; if it
                    // doesn't, treat as CSRF.
                    return Err(OAuthError::StateMismatch);
                }
                // Single-use consume. Pass returns the verifier we
                // already hold; the entry is removed atomically.
                let _pending = state_store.consume(&state)?;
                Ok(RaceWinner::Loopback {
                    code,
                    redirect_uri: auto_redirect.clone(),
                })
            }
            // Paste path — the user typed the code in.
            res = &mut paste_fut => {
                let pasted = res?;
                let (code, paste_state) = split_paste_value(&pasted)?;
                // SEC-R2-06: constant-time compare on the paste path too.
                if !constant_time_eq_state(paste_state, &state) {
                    return Err(OAuthError::StateMismatch);
                }
                let _pending = state_store.consume(&state)?;
                Ok(RaceWinner::Paste {
                    code: code.to_string(),
                    redirect_uri: PASTE_CODE_REDIRECT_URI.to_string(),
                })
            }
        }
    };

    let winner = match tokio::time::timeout(overall_timeout, race).await {
        Ok(r) => r?,
        Err(_) => {
            return Err(OAuthError::StateExpired {
                ttl_secs: overall_timeout.as_secs(),
            });
        }
    };

    Ok(RaceResult {
        winner,
        auto_url,
        manual_url,
        state,
        verifier,
    })
}

/// Splits CC's paste format `<code>#<state>` into its two parts.
///
/// Returns [`OAuthError::Exchange`] with a sanitised message if the
/// pasted value doesn't contain `#`. Empty parts are also rejected
/// (a `#` with nothing on either side is not a valid paste).
fn split_paste_value(value: &str) -> Result<(&str, &str), OAuthError> {
    // Trim only the trailing newline / CR the CLI's read_line
    // leaves behind. Inner whitespace is rejected — Anthropic's
    // paste codes never contain spaces.
    let trimmed = value.trim_end_matches(['\r', '\n', ' ', '\t']);
    let (code, state) = trimmed
        .split_once('#')
        .ok_or_else(|| OAuthError::Exchange("paste did not contain code#state".to_string()))?;
    if code.is_empty() {
        return Err(OAuthError::Exchange(
            "paste was empty before the # separator".to_string(),
        ));
    }
    if state.is_empty() {
        return Err(OAuthError::Exchange(
            "paste was empty after the # separator".to_string(),
        ));
    }
    Ok((code, state))
}

/// One-call orchestrator — convenience wrapper around
/// [`prepare_race`] + [`drive_race`].
///
/// The CLI uses [`prepare_race`] + [`drive_race`] separately so it
/// can print URLs and open the browser between the two phases.
/// Tests use this single-call form unless they specifically need
/// to assert on the bound port before entering the race.
pub async fn race_login(cfg: RaceConfig) -> Result<RaceResult, OAuthError> {
    let prep = prepare_race(&cfg.state_store, cfg.account).await?;
    drive_race(
        prep,
        &cfg.state_store,
        cfg.paste_resolver,
        cfg.overall_timeout,
    )
    .await
}

// ─── helpers used by both production and tests ──────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn acct(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Mock paste resolver that never resolves. Used to force the
    /// loopback path to win.
    fn never_resolves() -> PasteResolver {
        Box::new(|| {
            Box::pin(async {
                // Sleep effectively forever — caller is expected to
                // drop us via tokio::select!.
                tokio::time::sleep(Duration::from_secs(86400)).await;
                Err(OAuthError::Exchange("never".to_string()))
            })
        })
    }

    /// Mock paste resolver that resolves immediately with the given
    /// pasted value.
    fn paste_returns(value: String) -> PasteResolver {
        Box::new(move || Box::pin(async move { Ok(value) }))
    }

    /// Drop sentinel — flips an `AtomicBool` true on drop. Used to
    /// prove the paste resolver future is cancelled when loopback
    /// wins.
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Sends the loopback callback to the bound port. Spawned by
    /// the loopback-wins tests after the race has started. Caller
    /// passes the callback path (including the per-race secret)
    /// returned by `prep.listener.callback_path()`.
    async fn fire_loopback_callback(port: u16, callback_path: &str, code: &str, state: &str) {
        let request = format!(
            "GET {callback_path}?code={code}&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to loopback");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    }

    #[tokio::test]
    async fn race_loopback_wins_when_listener_resolves_first() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(1)).await.unwrap();
        let port = prep.listener.port;
        let state = prep.state.clone();
        let callback_path = prep.listener.callback_path();
        let expected_redirect = format!("http://127.0.0.1:{port}{callback_path}");

        // Fire the loopback callback after the race starts. The
        // paste resolver never resolves, so loopback must win.
        let cb_port = port;
        let cb_state = state.clone();
        let cb_path = callback_path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            fire_loopback_callback(cb_port, &cb_path, "loopback-code", &cb_state).await;
        });

        let result = drive_race(prep, &store, never_resolves(), Duration::from_secs(5))
            .await
            .expect("race resolved");

        match result.winner {
            RaceWinner::Loopback { code, redirect_uri } => {
                assert_eq!(code, "loopback-code");
                assert_eq!(redirect_uri, expected_redirect);
            }
            other => panic!("expected Loopback, got {other:?}"),
        }
        // State store entry must be consumed.
        assert_eq!(store.len(), 0);
    }

    #[tokio::test]
    async fn race_paste_wins_when_paste_resolves_first() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(2)).await.unwrap();
        let state = prep.state.clone();

        // Paste resolves immediately; loopback never receives a
        // request.
        let paste_value = format!("paste-code#{state}");
        let result = drive_race(
            prep,
            &store,
            paste_returns(paste_value),
            Duration::from_secs(5),
        )
        .await
        .expect("race resolved");

        match result.winner {
            RaceWinner::Paste { code, redirect_uri } => {
                assert_eq!(code, "paste-code");
                assert_eq!(redirect_uri, PASTE_CODE_REDIRECT_URI);
            }
            other => panic!("expected Paste, got {other:?}"),
        }
        assert_eq!(store.len(), 0);
    }

    #[tokio::test]
    async fn race_validates_state_via_store_on_paste_path() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(3)).await.unwrap();

        // Paste a wrong state — race must reject.
        let result = drive_race(
            prep,
            &store,
            paste_returns("paste-code#wrong-state".to_string()),
            Duration::from_secs(5),
        )
        .await;

        assert!(matches!(result, Err(OAuthError::StateMismatch)));
        // Original entry is NOT consumed (the bad state never matched).
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn race_handles_invalid_paste_format_no_panic() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(4)).await.unwrap();

        let result = drive_race(
            prep,
            &store,
            paste_returns("no-hash-here".to_string()),
            Duration::from_secs(5),
        )
        .await;

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("code#state"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn race_handles_paste_with_empty_code() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(5)).await.unwrap();
        let state = prep.state.clone();

        let result = drive_race(
            prep,
            &store,
            paste_returns(format!("#{state}")),
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(result, Err(OAuthError::Exchange(_))));
    }

    #[tokio::test]
    async fn race_handles_paste_with_empty_state_part() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(5)).await.unwrap();

        let result = drive_race(
            prep,
            &store,
            paste_returns("code#".to_string()),
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(result, Err(OAuthError::Exchange(_))));
    }

    #[tokio::test]
    async fn race_overall_timeout_returns_state_expired() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(6)).await.unwrap();

        let result = drive_race(prep, &store, never_resolves(), Duration::from_millis(80)).await;

        match result {
            Err(OAuthError::StateExpired { ttl_secs }) => {
                // 80ms rounded down is 0 secs — that's expected
                // because Duration::as_secs truncates.
                assert!(ttl_secs == 0 || ttl_secs == 1, "got {ttl_secs}");
            }
            other => panic!("expected StateExpired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn race_returns_distinct_auto_and_manual_urls() {
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(7)).await.unwrap();
        let auto = prep.auto_url.clone();
        let manual = prep.manual_url.clone();
        let port = prep.listener.port;
        let state = prep.state.clone();

        // Resolve via paste so the test completes quickly.
        let result = drive_race(
            prep,
            &store,
            paste_returns(format!("c#{state}")),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert!(
            auto.contains(&format!("http%3A%2F%2F127.0.0.1%3A{port}%2Fcallback%2F")),
            "auto_url should contain the loopback redirect (encoded, with /callback/ prefix): {auto}"
        );
        assert!(
            manual.contains("platform.claude.com%2Foauth%2Fcode%2Fcallback"),
            "manual_url should contain the paste-code redirect (encoded): {manual}"
        );
        assert!(auto.contains(&format!("state={state}")));
        assert!(manual.contains(&format!("state={state}")));
        // Result echoes them back unchanged.
        assert_eq!(result.auto_url, auto);
        assert_eq!(result.manual_url, manual);
    }

    #[tokio::test]
    async fn race_loopback_winner_drops_paste_resolver() {
        // Cancellation safety: when loopback wins, the paste
        // resolver future is dropped. We prove this by handing in
        // a future that holds a Drop sentinel.
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(8)).await.unwrap();
        let port = prep.listener.port;
        let state = prep.state.clone();

        let dropped = Arc::new(AtomicBool::new(false));
        let drop_flag = DropFlag(Arc::clone(&dropped));
        let resolver: PasteResolver = Box::new(move || {
            Box::pin(async move {
                // Hold the sentinel inside the future. When the
                // future is dropped (because loopback won), the
                // sentinel drops too.
                let _holder = drop_flag;
                tokio::time::sleep(Duration::from_secs(86400)).await;
                Err(OAuthError::Exchange("never".to_string()))
            })
        });

        let cb_port = port;
        let cb_state = state.clone();
        let cb_path = prep.listener.callback_path();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            fire_loopback_callback(cb_port, &cb_path, "loopback-wins", &cb_state).await;
        });

        let result = drive_race(prep, &store, resolver, Duration::from_secs(5))
            .await
            .expect("race resolved");
        assert!(matches!(result.winner, RaceWinner::Loopback { .. }));

        // Give the runtime a tick to actually drop the loser.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "paste resolver future must be dropped when loopback wins"
        );
    }

    #[tokio::test]
    async fn race_paste_winner_releases_loopback_port() {
        // L9 (UX-R1-L5): use paste_returns(...) — immediate — rather
        // than a wall-clock-coupled paste_returns_delayed. Race
        // ordering does the work: the loopback listener never
        // receives a connection, so paste wins by default.
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(9)).await.unwrap();
        let port = prep.listener.port;
        let state = prep.state.clone();

        let _ = drive_race(
            prep,
            &store,
            paste_returns(format!("c#{state}")),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // After the race, the listener should be dropped → port
        // released. Give the runtime a tick.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let attempt = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            attempt.is_err(),
            "loopback port must be released when paste wins"
        );
    }

    #[tokio::test]
    async fn race_login_one_call_times_out_when_neither_path_resolves() {
        // Smoke test for the convenience wrapper [`race_login`].
        // Both paths hang → orchestrator times out → StateExpired.
        // Per-path win mechanics are covered by the prepare_race +
        // drive_race tests above.
        let store = Arc::new(OAuthStateStore::new());
        let result = race_login(RaceConfig {
            state_store: store,
            account: acct(10),
            paste_resolver: never_resolves(),
            overall_timeout: Duration::from_millis(80),
        })
        .await;
        assert!(matches!(result, Err(OAuthError::StateExpired { .. })));
    }

    #[test]
    fn split_paste_value_handles_simple_case() {
        let (c, s) = split_paste_value("code123#state456").unwrap();
        assert_eq!(c, "code123");
        assert_eq!(s, "state456");
    }

    #[test]
    fn split_paste_value_strips_trailing_whitespace() {
        let (c, s) = split_paste_value("code123#state456\r\n").unwrap();
        assert_eq!(c, "code123");
        assert_eq!(s, "state456");
    }

    #[test]
    fn split_paste_value_rejects_no_separator() {
        assert!(matches!(
            split_paste_value("noseparator"),
            Err(OAuthError::Exchange(_))
        ));
    }

    #[test]
    fn split_paste_value_rejects_empty_code() {
        assert!(matches!(
            split_paste_value("#state"),
            Err(OAuthError::Exchange(_))
        ));
    }

    #[test]
    fn split_paste_value_rejects_empty_state() {
        assert!(matches!(
            split_paste_value("code#"),
            Err(OAuthError::Exchange(_))
        ));
    }

    // ── HIGH 1 (SEC-R1-01) regression tests ─────────────────────

    #[tokio::test]
    async fn race_uses_random_path_secret_per_invocation() {
        // Two consecutive races must mint distinct path secrets.
        // Same-host attacker who scrapes one race's auto URL cannot
        // pre-compute or reuse the secret for the next race.
        let store_a = Arc::new(OAuthStateStore::new());
        let store_b = Arc::new(OAuthStateStore::new());
        let prep_a = prepare_race(&store_a, acct(1)).await.unwrap();
        let prep_b = prepare_race(&store_b, acct(1)).await.unwrap();
        assert_ne!(
            prep_a.listener.callback_path(),
            prep_b.listener.callback_path(),
            "two races must mint distinct path secrets"
        );
    }

    #[tokio::test]
    async fn race_url_includes_path_secret_in_redirect_uri() {
        // The auto URL must include the per-race path secret in the
        // loopback redirect URI. Without it the listener has no way
        // to distinguish a legitimate browser callback from a
        // cooperating same-host attacker who guessed `/callback`.
        let store = Arc::new(OAuthStateStore::new());
        let prep = prepare_race(&store, acct(2)).await.unwrap();

        let callback_path = prep.listener.callback_path();
        // Sanity: the callback path is `/callback/<22-char-base64url>`
        // — the leading prefix and a non-trivial suffix.
        assert!(callback_path.starts_with("/callback/"));
        assert!(
            callback_path.len() > "/callback/".len(),
            "callback_path must include the path secret: {callback_path}"
        );

        // The encoded callback path appears in the auto URL's
        // redirect_uri query param. We percent-encode the literal `/`
        // so the assertion matches the URL-encoded form.
        let encoded_path = callback_path.replace('/', "%2F");
        assert!(
            prep.auto_url.contains(&encoded_path),
            "auto_url must embed the per-race callback path: auto={}, expected fragment={}",
            prep.auto_url,
            encoded_path
        );

        // The manual URL uses Anthropic's paste-code redirect; it
        // must NOT include the loopback callback path.
        assert!(
            !prep.manual_url.contains(&encoded_path),
            "manual_url must not include the loopback path: {}",
            prep.manual_url
        );
    }
}
