//! Login initiation — builds the Anthropic authorize URL and
//! records the pending PKCE state.
//!
//! # Flow
//!
//! 1. Caller invokes [`start_login`] with a reference to the
//!    daemon's [`OAuthStateStore`], the target account number, and
//!    the redirect port (usually [`DEFAULT_REDIRECT_PORT`]).
//! 2. `start_login` generates a fresh [`CodeVerifier`], computes
//!    its [`CodeChallenge`], stores the verifier + account in the
//!    state store (keyed by a random state token), and returns a
//!    [`LoginRequest`] containing the authorize URL the caller
//!    should open in a browser plus the state token for debugging.
//! 3. The caller (the M8.7b `GET /api/login/{N}` handler) returns
//!    the URL to the frontend / dashboard, which opens it in the
//!    user's browser.
//! 4. After authorization, Anthropic redirects to
//!    `http://127.0.0.1:{port}/oauth/callback?code=X&state=Y`. The
//!    M8.7b callback listener calls
//!    [`crate::oauth::exchange_code`] with the `code` and the
//!    verifier retrieved via [`OAuthStateStore::consume`].
//!
//! # Security notes
//!
//! - The verifier is **never** serialized into the authorize URL.
//!   Only the challenge (one-way SHA256) is sent. Even if the URL
//!   ends up in a log or browser history, the verifier is safe.
//! - The state token is single-use (enforced by the store). Replay
//!   attacks on the callback are prevented.
//! - The returned [`LoginRequest`] includes the state token so
//!   *optional* frontend code can correlate a login-initiation
//!   response to its eventual callback. The frontend does not need
//!   to hold the verifier — only the daemon does.

use crate::error::{CredentialError, CsqError};
use crate::oauth::constants::{
    redirect_uri, scopes_joined, DEFAULT_REDIRECT_PORT, OAUTH_AUTHORIZE_URL, OAUTH_CLIENT_ID,
};
use crate::oauth::pkce::{challenge_from_verifier, generate_verifier};
use crate::oauth::state_store::OAuthStateStore;
use crate::types::AccountNum;
use serde::Serialize;

/// The result of a successful [`start_login`] call.
///
/// `auth_url` is the full Anthropic authorize URL (GET) that the
/// caller should open in a browser. `state` is the generated
/// anti-CSRF token that will come back in the callback query
/// parameters — the caller only needs it for correlation /
/// debugging; the state store already holds it.
#[derive(Debug, Clone, Serialize)]
pub struct LoginRequest {
    pub auth_url: String,
    pub state: String,
    /// The account slot this login targets. Echoed back so the
    /// frontend can disambiguate parallel logins (rare but
    /// possible via MAX_PENDING).
    pub account: u16,
    /// Seconds remaining before the state token expires. The
    /// frontend can use this to cancel the spinner with a clear
    /// message if the user walks away.
    pub expires_in_secs: u64,
}

/// Initiates an OAuth login for `account`.
///
/// Generates PKCE + state, records them in the store, and builds
/// the authorize URL. The returned [`LoginRequest`] is ready to be
/// serialized to the frontend.
///
/// # Errors
///
/// Returns [`CsqError::Credential`] with
/// [`CredentialError::InvalidAccount`] if the account number is
/// out of range. PKCE and state generation are infallible on
/// supported platforms (they panic only if the OS CSPRNG is
/// unavailable, which cannot happen on macOS/Linux/Windows).
pub fn start_login(
    store: &OAuthStateStore,
    account: AccountNum,
    port: u16,
) -> Result<LoginRequest, CsqError> {
    // AccountNum already guarantees 1..=999, but we defensively
    // re-check so a future widening of AccountNum's range doesn't
    // silently allow 0 here.
    if account.get() == 0 {
        return Err(CsqError::Credential(CredentialError::InvalidAccount(
            "0".to_string(),
        )));
    }

    let verifier = generate_verifier();
    let challenge = challenge_from_verifier(&verifier);
    let state = store.insert(verifier, account);

    let redirect = redirect_uri(port);

    // urlencoding::encode performs application/x-www-form-urlencoded
    // percent-encoding, which matches the query-string encoding
    // Anthropic's authorize endpoint expects. The colons and slashes
    // inside redirect_uri must be percent-encoded because they're
    // query values, not path components.
    //
    // # INVARIANT: param keys MUST be static string literals.
    //
    // The format! below concatenates `k` verbatim without percent-
    // encoding. That is safe **only** because every key in this
    // array is a compile-time constant composed of lowercase
    // letters and underscores. If you ever need to add a dynamic
    // key, percent-encode both sides of the `=` sign. Grepping
    // this file for `urlencoding::encode` should show both the
    // key and value being encoded once that invariant weakens.
    let params = [
        ("client_id", OAUTH_CLIENT_ID.to_string()),
        ("response_type", "code".to_string()),
        ("redirect_uri", redirect),
        ("scope", scopes_joined()),
        ("code_challenge", challenge.as_str().to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("state", state.clone()),
    ];

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let auth_url = format!("{OAUTH_AUTHORIZE_URL}?{query}");

    Ok(LoginRequest {
        auth_url,
        state,
        account: account.get(),
        expires_in_secs: super::STATE_TTL.as_secs(),
    })
}

/// Convenience wrapper: builds a login request against the default
/// redirect port. Kept so the M8.7b route handler does not need to
/// import [`DEFAULT_REDIRECT_PORT`] itself.
pub fn start_login_default_port(
    store: &OAuthStateStore,
    account: AccountNum,
) -> Result<LoginRequest, CsqError> {
    start_login(store, account, DEFAULT_REDIRECT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::constants::{OAUTH_CLIENT_ID, OAUTH_SCOPES};
    use crate::oauth::state_store::OAuthStateStore;

    fn acct(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Parses `?k=v&k2=v2...` into a Vec of (key, decoded_value).
    /// Minimal because we control the input — no fragment handling,
    /// no repeated-key support.
    fn parse_query(url: &str) -> Vec<(String, String)> {
        let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        q.split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                let v = urlencoding::decode(v)
                    .map(|cow| cow.into_owned())
                    .unwrap_or_else(|_| v.to_string());
                (k.to_string(), v)
            })
            .collect()
    }

    fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn start_login_returns_login_request() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(3), 8420).unwrap();
        assert_eq!(req.account, 3);
        assert!(!req.state.is_empty());
        assert!(req.auth_url.starts_with("https://"));
        assert!(req.expires_in_secs > 0);
    }

    #[test]
    fn authorize_url_contains_all_required_params() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(1), 8420).unwrap();
        let params = parse_query(&req.auth_url);

        assert_eq!(param(&params, "client_id"), Some(OAUTH_CLIENT_ID));
        assert_eq!(param(&params, "response_type"), Some("code"));
        assert_eq!(
            param(&params, "redirect_uri"),
            Some("http://127.0.0.1:8420/oauth/callback")
        );
        assert_eq!(param(&params, "code_challenge_method"), Some("S256"));
        // state should round-trip intact
        assert_eq!(param(&params, "state"), Some(req.state.as_str()));

        let scope = param(&params, "scope").expect("scope present");
        for s in OAUTH_SCOPES {
            assert!(
                scope.contains(s),
                "scope param should contain {s}, got: {scope}"
            );
        }

        let challenge = param(&params, "code_challenge").expect("challenge present");
        assert_eq!(challenge.len(), 43, "SHA256→base64url is 43 chars");
    }

    #[test]
    fn authorize_url_uses_correct_base_url() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(1), 8420).unwrap();
        assert!(
            req.auth_url
                .starts_with("https://platform.claude.com/v1/oauth/authorize?"),
            "auth_url should start with Anthropic authorize endpoint: {}",
            req.auth_url
        );
    }

    #[test]
    fn start_login_records_pending_state() {
        let store = OAuthStateStore::new();
        assert_eq!(store.len(), 0);
        let _req = start_login(&store, acct(2), 8420).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn state_token_can_be_consumed_after_start_login() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(5), 8420).unwrap();

        let pending = store.consume(&req.state).expect("consume");
        assert_eq!(pending.account, acct(5));
        // The verifier's challenge should match what was in the URL.
        let challenge = challenge_from_verifier(&pending.code_verifier);
        let params = parse_query(&req.auth_url);
        assert_eq!(param(&params, "code_challenge"), Some(challenge.as_str()));
    }

    #[test]
    fn parallel_logins_get_distinct_states() {
        let store = OAuthStateStore::new();
        let r1 = start_login(&store, acct(1), 8420).unwrap();
        let r2 = start_login(&store, acct(2), 8420).unwrap();
        assert_ne!(r1.state, r2.state);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn default_port_wrapper_uses_8420() {
        let store = OAuthStateStore::new();
        let req = start_login_default_port(&store, acct(1)).unwrap();
        let params = parse_query(&req.auth_url);
        assert_eq!(
            param(&params, "redirect_uri"),
            Some("http://127.0.0.1:8420/oauth/callback")
        );
    }

    #[test]
    fn different_ports_produce_different_redirect_uris() {
        let store = OAuthStateStore::new();
        let r1 = start_login(&store, acct(1), 8420).unwrap();
        let r2 = start_login(&store, acct(1), 9999).unwrap();
        let p1 = parse_query(&r1.auth_url);
        let p2 = parse_query(&r2.auth_url);
        assert_ne!(param(&p1, "redirect_uri"), param(&p2, "redirect_uri"));
    }
}
