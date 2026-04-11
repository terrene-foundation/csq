//! Login initiation — builds the Anthropic authorize URL and
//! records the pending PKCE state for the paste-code OAuth flow.
//!
//! # Flow
//!
//! 1. Caller invokes [`start_login`] with a reference to the
//!    [`OAuthStateStore`] and the target account number.
//! 2. `start_login` generates a fresh [`CodeVerifier`], computes
//!    its [`CodeChallenge`], stores the verifier + account in the
//!    state store (keyed by a random state token), and returns a
//!    [`LoginRequest`] containing the Anthropic authorize URL the
//!    caller should open in a browser.
//! 3. The user authorizes on Anthropic's page. Anthropic then
//!    displays an authorization code on its paste-code callback
//!    page at `https://platform.claude.com/oauth/code/callback`.
//! 4. The user copies the displayed code and pastes it back into
//!    the calling app. The app looks up the verifier in the state
//!    store (via [`OAuthStateStore::consume`] keyed by the state
//!    token returned from step 2) and calls
//!    [`crate::oauth::exchange_code`] with the paste-code redirect
//!    URI to swap the code for an access/refresh token pair.
//!
//! # Why paste-code instead of loopback
//!
//! Anthropic retired loopback OAuth (`http://127.0.0.1:8420/...`)
//! for this client_id. The current `claude` CLI and the csq
//! desktop app both use the paste-code redirect that Anthropic's
//! authorize endpoint serves at `claude.com/cai/oauth/authorize`.
//!
//! # Security notes
//!
//! - The verifier is **never** serialized into the authorize URL.
//!   Only the challenge (one-way SHA256) is sent. Even if the URL
//!   ends up in a log or browser history, the verifier is safe.
//! - The state token is single-use (enforced by the store). Replay
//!   attacks on the paste-code exchange are prevented.
//! - The returned [`LoginRequest`] includes the state token so the
//!   caller can correlate the initiation response with the
//!   eventual paste-code submission.

use crate::error::{CredentialError, CsqError};
use crate::oauth::constants::{
    scopes_joined, OAUTH_AUTHORIZE_URL, OAUTH_CLIENT_ID, PASTE_CODE_REDIRECT_URI,
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

/// Initiates an OAuth paste-code login for `account`.
///
/// Generates PKCE + state, records them in the store, and builds
/// the authorize URL using Anthropic's current paste-code flow:
///
/// - `redirect_uri` is [`PASTE_CODE_REDIRECT_URI`] (Anthropic's own
///   callback page), **not** a loopback URL
/// - an extra `code=true` parameter signals paste-code mode to the
///   authorize endpoint
///
/// After the user authorizes, Anthropic shows a code on-screen.
/// The caller is expected to collect that code from the user and
/// pass it to [`crate::oauth::exchange_code`] with the same
/// verifier (retrieved via [`OAuthStateStore::consume`]) and the
/// exact same `redirect_uri` byte-for-byte.
///
/// # Errors
///
/// Returns [`CsqError::Credential`] with
/// [`CredentialError::InvalidAccount`] if the account number is
/// out of range. PKCE and state generation are infallible on
/// supported platforms (they panic only if the OS CSPRNG is
/// unavailable, which cannot happen on macOS/Linux/Windows).
pub fn start_login(store: &OAuthStateStore, account: AccountNum) -> Result<LoginRequest, CsqError> {
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
    //
    // Parameter order matches `claude auth login`'s live output as
    // observed on 2026-04-11: `code=true` appears first, then the
    // standard OAuth params. Anthropic's authorize endpoint is not
    // documented to be order-sensitive, but matching the reference
    // client keeps any server-side quirks from surprising us.
    let params = [
        ("code", "true".to_string()),
        ("client_id", OAUTH_CLIENT_ID.to_string()),
        ("response_type", "code".to_string()),
        ("redirect_uri", PASTE_CODE_REDIRECT_URI.to_string()),
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

/// Convenience wrapper: builds a paste-code login request.
///
/// Previously wrapped [`start_login`] with a default port for the
/// loopback flow. With paste-code, there's no port, so this is a
/// thin alias kept for callers that were using the name.
pub fn start_login_default_port(
    store: &OAuthStateStore,
    account: AccountNum,
) -> Result<LoginRequest, CsqError> {
    start_login(store, account)
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
        let req = start_login(&store, acct(3)).unwrap();
        assert_eq!(req.account, 3);
        assert!(!req.state.is_empty());
        assert!(req.auth_url.starts_with("https://"));
        assert!(req.expires_in_secs > 0);
    }

    #[test]
    fn authorize_url_contains_all_required_params() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(1)).unwrap();
        let params = parse_query(&req.auth_url);

        assert_eq!(param(&params, "client_id"), Some(OAUTH_CLIENT_ID));
        assert_eq!(param(&params, "response_type"), Some("code"));
        assert_eq!(
            param(&params, "redirect_uri"),
            Some(PASTE_CODE_REDIRECT_URI)
        );
        assert_eq!(param(&params, "code"), Some("true"));
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
        let req = start_login(&store, acct(1)).unwrap();
        assert!(
            req.auth_url
                .starts_with("https://claude.com/cai/oauth/authorize?"),
            "auth_url should start with Anthropic authorize endpoint: {}",
            req.auth_url
        );
    }

    #[test]
    fn authorize_url_includes_org_create_api_key_scope() {
        // Regression: Anthropic's current Claude Code login includes
        // `org:create_api_key` as the first scope. Verified against
        // live `claude auth login` output on 2026-04-11. If this
        // scope is missing, the credential can't be used for the
        // full Claude Code surface.
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(1)).unwrap();
        let params = parse_query(&req.auth_url);
        let scope = param(&params, "scope").expect("scope present");
        assert!(
            scope.contains("org:create_api_key"),
            "scope must include org:create_api_key, got: {scope}"
        );
    }

    #[test]
    fn start_login_records_pending_state() {
        let store = OAuthStateStore::new();
        assert_eq!(store.len(), 0);
        let _req = start_login(&store, acct(2)).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn state_token_can_be_consumed_after_start_login() {
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(5)).unwrap();

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
        let r1 = start_login(&store, acct(1)).unwrap();
        let r2 = start_login(&store, acct(2)).unwrap();
        assert_ne!(r1.state, r2.state);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn paste_code_redirect_is_fixed_anthropic_endpoint() {
        // The paste-code redirect is a constant — it doesn't change
        // per-login or per-port. Lock that in so a future rewrite
        // doesn't accidentally re-introduce a port parameter.
        let store = OAuthStateStore::new();
        let req = start_login(&store, acct(1)).unwrap();
        let params = parse_query(&req.auth_url);
        assert_eq!(
            param(&params, "redirect_uri"),
            Some("https://platform.claude.com/oauth/code/callback")
        );
    }
}
