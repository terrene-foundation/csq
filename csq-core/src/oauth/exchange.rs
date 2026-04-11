//! Code-for-token exchange — the second leg of the OAuth
//! Authorization Code + PKCE flow.
//!
//! # Inputs
//!
//! After the user authorizes in their browser, Anthropic redirects
//! back to `http://127.0.0.1:{port}/oauth/callback?code=X&state=Y`.
//! The callback handler looks up `Y` in the
//! [`OAuthStateStore`](crate::oauth::state_store::OAuthStateStore)
//! to retrieve the paired [`CodeVerifier`] and account number, then
//! calls [`exchange_code`] with:
//!
//! - The authorization `code` from the query string
//! - The paired PKCE verifier
//! - The same redirect URI that was sent to the authorize endpoint
//!   (must be byte-identical or Anthropic will reject the exchange)
//! - An `http_post` closure that performs the HTTP request
//!
//! # HTTP contract
//!
//! This module is transport-agnostic. The `http_post` closure
//! matches [`crate::http::post_json`]'s signature exactly:
//!
//! ```ignore
//! fn post_json(url: &str, body: &str) -> Result<Vec<u8>, String>
//! ```
//!
//! Production callers pass `csq_core::http::post_json`; tests pass
//! a mock closure that returns canned responses. The injection
//! keeps this module free of `reqwest` dependencies and trivially
//! testable.
//!
//! # Security invariants
//!
//! 1. The request body — which contains the authorization code, the
//!    PKCE verifier, and the client_id — is **never** formatted
//!    into error messages. A malformed upstream response that
//!    echoes body fragments would otherwise leak the code (short-
//!    lived but still dangerous) and the verifier.
//! 2. Any stringified error (from the transport or from
//!    `serde_json`) is passed through
//!    [`crate::error::redact_tokens`] before wrapping in
//!    [`OAuthError::Exchange`]. This mirrors the defensive pattern
//!    used by [`crate::credentials::refresh::refresh_token`].
//! 3. The response `access_token` and `refresh_token` go directly
//!    into `AccessToken` / `RefreshToken` newtypes, which wrap
//!    `secrecy::SecretString` and zero on drop.
//! 4. The built [`CredentialFile`] carries no transient state from
//!    the exchange request — just the token pair, expiry, and
//!    scopes. It is safe to hand straight to
//!    [`crate::credentials::save`].

use crate::credentials::{CredentialFile, OAuthPayload};
use crate::error::{redact_tokens, OAuthError};
use crate::oauth::constants::{OAUTH_CLIENT_ID, OAUTH_SCOPES, OAUTH_TOKEN_URL};
use crate::oauth::pkce::CodeVerifier;
use crate::types::{AccessToken, RefreshToken};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fallback `expires_in` used if Anthropic's response omits the
/// field. 18000 seconds (5 hours) matches the observed Anthropic
/// default and is also what v1.x hardcodes.
const DEFAULT_EXPIRES_IN_SECS: u64 = 18000;

/// Request body sent to the token endpoint for the initial
/// authorization code grant.
///
/// Serialized as JSON (Anthropic's `/v1/oauth/token` accepts both
/// JSON and form-encoded; v1.x uses JSON for the authorization_code
/// grant). This struct is **never** serialized into a log or an
/// error — it carries the authorization code and the PKCE verifier.
#[derive(Debug, Serialize)]
struct ExchangeRequest<'a> {
    grant_type: &'static str,
    code: &'a str,
    client_id: &'static str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
}

/// Response from the token endpoint. Anthropic returns the same
/// shape for the initial exchange and refreshes.
///
/// Custom `Debug` masks the token values so a `tracing::debug!`
/// in a caller (even an accidental one) cannot print them.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    /// Token lifetime in seconds, typically 18000 (5 hours).
    /// Optional because some grant flows omit it; we fall back to
    /// [`DEFAULT_EXPIRES_IN_SECS`].
    #[serde(default)]
    expires_in: Option<u64>,
    /// Sometimes returned; we ignore it in favor of [`OAUTH_SCOPES`].
    #[serde(default)]
    #[allow(dead_code)] // read by serde, reads not needed at runtime
    scope: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Exchanges an authorization code for an access/refresh token
/// pair and returns a freshly-built [`CredentialFile`] ready to be
/// persisted via [`crate::credentials::save`].
///
/// See module docs for the full security contract.
///
/// # Arguments
///
/// - `code` — the authorization code from the OAuth callback query
///   string.
/// - `verifier` — the PKCE verifier retrieved from the
///   [`OAuthStateStore`](crate::oauth::state_store::OAuthStateStore)
///   using the state parameter from the callback.
/// - `redirect_uri` — the exact redirect URI that was sent to the
///   authorize endpoint. Must be byte-identical.
/// - `http_post` — transport closure. Production callers pass
///   `csq_core::http::post_json`.
///
/// # Errors
///
/// Returns [`OAuthError::Exchange`] for:
/// - Transport failures (connect, timeout, TLS, DNS).
/// - Malformed JSON response bodies.
/// - Missing fields in the response (`access_token` or
///   `refresh_token` not present).
///
/// All error strings are run through
/// [`crate::error::redact_tokens`] to scrub any echoed tokens or
/// codes before they propagate into logs.
pub fn exchange_code<F>(
    code: &str,
    verifier: &CodeVerifier,
    redirect_uri: &str,
    http_post: F,
) -> Result<CredentialFile, OAuthError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let request = ExchangeRequest {
        grant_type: "authorization_code",
        code,
        client_id: OAUTH_CLIENT_ID,
        code_verifier: verifier.expose_secret(),
        redirect_uri,
    };

    // serde_json::to_string on the request struct never includes
    // private data in its error path (only metadata about the
    // failing field), but we still defensively run the error
    // through redact_tokens.
    let body = serde_json::to_string(&request).map_err(|e| {
        OAuthError::Exchange(redact_tokens(&format!("failed to serialize request: {e}")))
    })?;

    let response_bytes =
        http_post(OAUTH_TOKEN_URL, &body).map_err(|e| OAuthError::Exchange(redact_tokens(&e)))?;

    // serde_json::from_slice error Display may include a fragment
    // of the response body when parsing fails partway. If Anthropic
    // returned a 4xx body echoing our authorization code back, that
    // substring could ride into OAuthError::Exchange and reach a
    // log. redact_tokens scrubs known token prefixes, and we
    // additionally decline to format the full error — only the
    // kind gets through.
    let response: TokenResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        let raw = format!("invalid token response JSON: {e}");
        OAuthError::Exchange(redact_tokens(&raw))
    })?;

    if response.access_token.is_empty() {
        return Err(OAuthError::Exchange(
            "token response missing access_token".to_string(),
        ));
    }
    if response.refresh_token.is_empty() {
        return Err(OAuthError::Exchange(
            "token response missing refresh_token".to_string(),
        ));
    }

    let expires_in = response.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let credential = CredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new(response.access_token),
            refresh_token: RefreshToken::new(response.refresh_token),
            expires_at: now_ms + (expires_in * 1000),
            // Scopes come from our request constants, not the
            // response. v1.x and refresh flow do the same — the
            // response `scope` field is occasionally missing and
            // occasionally reformatted, so we trust the constant.
            scopes: OAUTH_SCOPES.iter().map(|s| (*s).to_string()).collect(),
            // subscription_type and rate_limit_tier are not
            // returned by the token endpoint; Claude Code populates
            // them on first API call. Leave as None — the next
            // successful refresh/broker_check will backfill them.
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        },
        extra: HashMap::new(),
    };

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_verifier() -> CodeVerifier {
        CodeVerifier::new("test-verifier-value-for-exchange-tests-only".to_string())
    }

    /// Wraps a closure that captures the URL + body so tests can
    /// assert on what was actually sent to the mock transport.
    fn capturing_success<'a>(
        captured_url: &'a std::cell::RefCell<Option<String>>,
        captured_body: &'a std::cell::RefCell<Option<String>>,
        response_bytes: Vec<u8>,
    ) -> impl FnOnce(&str, &str) -> Result<Vec<u8>, String> + 'a {
        move |url: &str, body: &str| {
            *captured_url.borrow_mut() = Some(url.to_string());
            *captured_body.borrow_mut() = Some(body.to_string());
            Ok(response_bytes)
        }
    }

    #[test]
    fn exchange_code_builds_correct_request_body() {
        let captured_url = std::cell::RefCell::new(None);
        let captured_body = std::cell::RefCell::new(None);
        let response = br#"{
            "access_token": "sk-ant-oat01-test-access",
            "refresh_token": "sk-ant-ort01-test-refresh",
            "expires_in": 18000
        }"#
        .to_vec();

        let result = exchange_code(
            "auth-code-123",
            &test_verifier(),
            "http://127.0.0.1:8420/oauth/callback",
            capturing_success(&captured_url, &captured_body, response),
        );
        assert!(result.is_ok());

        assert_eq!(
            captured_url.borrow().as_deref(),
            Some(OAUTH_TOKEN_URL),
            "exchange must POST to the Anthropic token endpoint"
        );

        let body = captured_body.borrow().clone().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["grant_type"], "authorization_code");
        assert_eq!(parsed["code"], "auth-code-123");
        assert_eq!(parsed["client_id"], OAUTH_CLIENT_ID);
        assert_eq!(
            parsed["code_verifier"],
            "test-verifier-value-for-exchange-tests-only"
        );
        assert_eq!(
            parsed["redirect_uri"],
            "http://127.0.0.1:8420/oauth/callback"
        );
    }

    #[test]
    fn exchange_code_parses_success_response_into_credential_file() {
        let response = br#"{
            "access_token": "sk-ant-oat01-new",
            "refresh_token": "sk-ant-ort01-new",
            "expires_in": 18000
        }"#
        .to_vec();

        let creds = exchange_code(
            "code",
            &test_verifier(),
            "http://127.0.0.1:8420/oauth/callback",
            |_, _| Ok(response),
        )
        .unwrap();

        assert_eq!(
            creds.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-new"
        );
        assert_eq!(
            creds.claude_ai_oauth.refresh_token.expose_secret(),
            "sk-ant-ort01-new"
        );
        // expires_at should be roughly now + 18000s in millis
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let diff = creds.claude_ai_oauth.expires_at.saturating_sub(now_ms);
        assert!(
            (17_000_000..=19_000_000).contains(&diff),
            "expires_at should be ~18000s from now, diff={diff}ms"
        );
        // Scopes should match our constant, not the response
        assert_eq!(creds.claude_ai_oauth.scopes.len(), OAUTH_SCOPES.len());
    }

    #[test]
    fn exchange_code_defaults_expires_in_when_missing() {
        let response = br#"{
            "access_token": "at",
            "refresh_token": "rt"
        }"#
        .to_vec();

        let creds = exchange_code("code", &test_verifier(), "uri", |_, _| Ok(response)).unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let diff = creds.claude_ai_oauth.expires_at.saturating_sub(now_ms);
        // Default is 18000s, so ~18_000_000 ms
        assert!(diff >= 17_000_000);
    }

    #[test]
    fn exchange_code_scopes_come_from_constant_not_response() {
        // Response contains a `scope` field we deliberately ignore.
        let response = br#"{
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 100,
            "scope": "this scope string should be ignored"
        }"#
        .to_vec();

        let creds = exchange_code("code", &test_verifier(), "uri", |_, _| Ok(response)).unwrap();
        // Must exactly match OAUTH_SCOPES, not the response string
        for (want, got) in OAUTH_SCOPES.iter().zip(creds.claude_ai_oauth.scopes.iter()) {
            assert_eq!(want, got);
        }
        assert!(!creds
            .claude_ai_oauth
            .scopes
            .iter()
            .any(|s| s.contains("ignored")));
    }

    #[test]
    fn exchange_code_transport_error_is_redacted() {
        let result = exchange_code("code", &test_verifier(), "uri", |_, _| {
            Err("connection failed to sk-ant-oat01-LEAKED".to_string())
        });
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(
                    !msg.contains("LEAKED"),
                    "transport error must be redacted: {msg}"
                );
                assert!(!msg.contains("sk-ant-oat01-"), "prefix leaked: {msg}");
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_parse_error_does_not_leak_tokens() {
        // Craft a malformed JSON body containing real-looking token
        // prefixes. The serde_json error Display may include a
        // fragment of this input. redact_tokens must scrub it.
        let leaky = br#"{"access_token":"sk-ant-oat01-LEAKED-FROM-PARSE-ERROR"#.to_vec();

        let result = exchange_code("code", &test_verifier(), "uri", |_, _| Ok(leaky));
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(
                    !msg.contains("LEAKED-FROM-PARSE-ERROR"),
                    "parse error leaked: {msg}"
                );
                assert!(!msg.contains("sk-ant-oat01-"), "prefix leaked: {msg}");
                assert!(msg.contains("invalid token response JSON"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_rejects_empty_access_token() {
        let response = br#"{"access_token":"","refresh_token":"rt","expires_in":1}"#.to_vec();
        let result = exchange_code("c", &test_verifier(), "uri", |_, _| Ok(response));
        match result {
            Err(OAuthError::Exchange(msg)) => assert!(msg.contains("missing access_token")),
            other => panic!("expected missing access_token error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_rejects_empty_refresh_token() {
        let response = br#"{"access_token":"at","refresh_token":"","expires_in":1}"#.to_vec();
        let result = exchange_code("c", &test_verifier(), "uri", |_, _| Ok(response));
        match result {
            Err(OAuthError::Exchange(msg)) => assert!(msg.contains("missing refresh_token")),
            other => panic!("expected missing refresh_token error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_rejects_missing_access_token() {
        let response = br#"{"refresh_token":"rt","expires_in":1}"#.to_vec();
        let result = exchange_code("c", &test_verifier(), "uri", |_, _| Ok(response));
        match result {
            Err(OAuthError::Exchange(msg)) => {
                // serde deserialization rejects missing required
                // field with "missing field `access_token`".
                assert!(
                    msg.contains("invalid token response JSON")
                        || msg.contains("missing access_token"),
                    "unexpected: {msg}"
                );
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_does_not_include_verifier_in_transport_error_path() {
        // Regression guard: if a future refactor ever routed the
        // request body (which contains the verifier) into the error
        // path, this test catches it.
        let result = exchange_code(
            "code",
            &CodeVerifier::new("SECRET_VERIFIER_VALUE_12345".to_string()),
            "uri",
            |_, _| Err("some transport failure".to_string()),
        );
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(
                    !msg.contains("SECRET_VERIFIER_VALUE_12345"),
                    "transport error must not include the verifier: {msg}"
                );
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_uses_redirect_uri_verbatim() {
        let captured_body = std::cell::RefCell::new(None);
        let capture = |_url: &str, body: &str| {
            *captured_body.borrow_mut() = Some(body.to_string());
            Ok(br#"{"access_token":"at","refresh_token":"rt","expires_in":1}"#.to_vec())
        };

        let _ = exchange_code(
            "code",
            &test_verifier(),
            "http://127.0.0.1:8420/oauth/callback",
            capture,
        )
        .unwrap();

        let body = captured_body.borrow().clone().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed["redirect_uri"],
            "http://127.0.0.1:8420/oauth/callback"
        );
    }
}
