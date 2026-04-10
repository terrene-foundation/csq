//! OAuth constants — single source of truth for the Anthropic PKCE
//! flow.
//!
//! # Why one file
//!
//! v1.x defined `CLIENT_ID`, `SCOPES`, `TOKEN_URL` in three separate
//! Python files (`rotation-engine.py`, `dashboard/refresher.py`,
//! `dashboard/oauth.py`). Security analysis L1 called this out as a
//! risk: a rotation on the Anthropic side would require edits in
//! three places, and drift between them is silent. This module
//! collapses every OAuth constant into one place so the rest of
//! `csq-core` only ever references them from here.
//!
//! # Stability contract
//!
//! These values are defined by Anthropic, not by csq. If Anthropic
//! ever rotates the client_id or changes the authorize URL, this
//! file is the only place that needs to change. Tests that hard-code
//! specific constants (e.g., verifying the authorize URL builder in
//! `login.rs`) read from these constants so the wiring stays
//! coherent.

/// Anthropic OAuth client ID for Claude Code.
///
/// Extracted from v1.x `dashboard/oauth.py` and `rotation-engine.py`.
/// Stable for the life of Claude Code's OAuth app registration.
pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// OAuth scopes requested on every new login.
///
/// Stored as a `&[&str]` rather than a space-joined string so
/// callers can re-serialize for either:
///
/// - the authorize URL (`scope=...` query param, space-joined)
/// - the `scopes` array inside `credentials/{N}.json`
///
/// The ordering matches v1.x verbatim. Order is not semantically
/// significant to Anthropic but keeping it stable makes test
/// assertions trivial.
pub const OAUTH_SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
];

/// Space-joined scopes, used as the `scope` query param in the
/// authorize URL. Computed lazily from [`OAUTH_SCOPES`].
pub fn scopes_joined() -> String {
    OAUTH_SCOPES.join(" ")
}

/// Anthropic OAuth authorize endpoint. Users are redirected here
/// from the browser; Anthropic handles login, presents the consent
/// screen, and then 302s back to the configured `redirect_uri`.
pub const OAUTH_AUTHORIZE_URL: &str = "https://platform.claude.com/v1/oauth/authorize";

/// Anthropic OAuth token endpoint. Both `authorization_code` (first
/// login, M8.7) and `refresh_token` (refresher, M8.4) grants POST
/// here. Mirrors the constant in
/// [`crate::credentials::refresh::TOKEN_ENDPOINT`]; this module
/// re-exports it so every OAuth caller can use a single import
/// path.
pub const OAUTH_TOKEN_URL: &str = crate::credentials::refresh::TOKEN_ENDPOINT;

/// Default TCP port for the OAuth callback listener.
///
/// v1.x hardcodes this port and Anthropic's OAuth app registration
/// for the Claude Code client_id permits `http://127.0.0.1:8420/...`
/// as a valid redirect URI. Using a different port would require
/// Anthropic to register it.
///
/// If 8420 is in use (another csq daemon, another app), M8.7b's
/// startup path will surface a clear error and instruct the user to
/// stop the conflicting process — we do NOT fall through to an
/// ephemeral port because Anthropic would reject the redirect.
pub const DEFAULT_REDIRECT_PORT: u16 = 8420;

/// Builds the redirect URI for the OAuth callback.
///
/// Always binds to `127.0.0.1` (loopback only) — the public network
/// must never see the callback. Per security finding S12, binding
/// to `0.0.0.0` would expose the callback to any process on the
/// same subnet that can guess the state token; `127.0.0.1` keeps
/// the attack surface local to the machine.
pub fn redirect_uri(port: u16) -> String {
    format!("http://127.0.0.1:{port}/oauth/callback")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_is_uuid_shaped() {
        // 36 chars, 4 hyphens, hex+dash only.
        assert_eq!(OAUTH_CLIENT_ID.len(), 36);
        assert_eq!(OAUTH_CLIENT_ID.chars().filter(|c| *c == '-').count(), 4);
        assert!(OAUTH_CLIENT_ID
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn scopes_not_empty_and_have_no_whitespace_individually() {
        assert!(!OAUTH_SCOPES.is_empty());
        for scope in OAUTH_SCOPES {
            assert!(
                !scope.contains(' '),
                "individual scopes must not contain whitespace: {scope}"
            );
            assert!(!scope.is_empty());
        }
    }

    #[test]
    fn scopes_joined_is_space_separated() {
        let joined = scopes_joined();
        let parts: Vec<&str> = joined.split(' ').collect();
        assert_eq!(parts.len(), OAUTH_SCOPES.len());
        for (want, got) in OAUTH_SCOPES.iter().zip(parts.iter()) {
            assert_eq!(want, got);
        }
    }

    #[test]
    fn authorize_url_is_https() {
        assert!(OAUTH_AUTHORIZE_URL.starts_with("https://"));
    }

    #[test]
    fn token_url_is_https() {
        assert!(OAUTH_TOKEN_URL.starts_with("https://"));
    }

    #[test]
    fn token_url_matches_refresh_endpoint() {
        // Defensive invariant: the OAuth module and the refresh module
        // must agree on the token endpoint. If v1.x ever changes,
        // break at compile time rather than at a runtime 404.
        assert_eq!(OAUTH_TOKEN_URL, crate::credentials::refresh::TOKEN_ENDPOINT);
    }

    #[test]
    fn redirect_uri_is_loopback_only() {
        let uri = redirect_uri(8420);
        assert_eq!(uri, "http://127.0.0.1:8420/oauth/callback");
        // Defense-in-depth: no variant of the builder should ever
        // produce a non-loopback host.
        assert!(uri.contains("127.0.0.1"));
        assert!(!uri.contains("0.0.0.0"));
    }

    #[test]
    fn default_redirect_port_matches_v1() {
        // v1.x hardcodes 8420 in dashboard/oauth.py. Keep them in
        // sync so migration from v1 → v2 does not require an
        // Anthropic app-registration change.
        assert_eq!(DEFAULT_REDIRECT_PORT, 8420);
    }
}
