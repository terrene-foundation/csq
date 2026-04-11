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
/// **Scope set history**: csq v1.x used five user scopes (`user:profile`,
/// `user:inference`, `user:sessions:claude_code`, `user:mcp_servers`,
/// `user:file_upload`). Claude Code's current login flow adds
/// `org:create_api_key` as the first scope — verified against live
/// `claude auth login` output on 2026-04-11. The extra scope is
/// required for full Claude Code functionality and is what every
/// current OAuth login carries, so we match it here.
pub const OAUTH_SCOPES: &[&str] = &[
    "org:create_api_key",
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
/// screen, and — depending on the `redirect_uri` — either 302s
/// back to a loopback listener (legacy v2 design) or displays a
/// paste-code for the user to copy (current Claude Code design).
///
/// **Endpoint history** (2026-04-11):
/// - v1.x csq (`dashboard/oauth.py`) and csq v2 used
///   `https://platform.claude.com/v1/oauth/authorize`. That URL now
///   returns 404 from the origin server — Anthropic retired it.
/// - The current authorize endpoint, observed live from Claude
///   Code's `claude` CLI login output, is
///   `https://claude.com/cai/oauth/authorize`.
///
/// Both csq v1.x and csq v2 have therefore been broken for new
/// logins since the endpoint moved — token refresh still works
/// because the token endpoint remained stable.
pub const OAUTH_AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";

/// Anthropic OAuth token endpoint. Both `authorization_code` (first
/// login, M8.7) and `refresh_token` (refresher, M8.4) grants POST
/// here. Mirrors the constant in
/// [`crate::credentials::refresh::TOKEN_ENDPOINT`]; this module
/// re-exports it so every OAuth caller can use a single import
/// path.
pub const OAUTH_TOKEN_URL: &str = crate::credentials::refresh::TOKEN_ENDPOINT;

/// Paste-code OAuth redirect URI.
///
/// Anthropic's current OAuth flow for the Claude Code client_id
/// uses a "paste-code" redirect, not a loopback listener. When the
/// authorize URL carries this redirect plus `code=true`, Anthropic
/// displays the authorization code on its own page after the user
/// approves; the user then copies the code and pastes it back into
/// the requesting app, which exchanges it at the token endpoint.
///
/// This replaces the v1 loopback redirect
/// (`http://127.0.0.1:8420/oauth/callback`). Loopback is no longer
/// accepted by Anthropic's authorize endpoint for this client_id.
pub const PASTE_CODE_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";

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
    fn paste_code_redirect_uri_is_https_and_anthropic_host() {
        // The paste-code redirect is served by Anthropic, so it
        // must be https and on one of their hosts. Pin the exact
        // value so a typo during a future refactor breaks loudly
        // rather than producing a request Anthropic silently
        // rejects.
        assert_eq!(
            PASTE_CODE_REDIRECT_URI,
            "https://platform.claude.com/oauth/code/callback"
        );
        assert!(PASTE_CODE_REDIRECT_URI.starts_with("https://"));
    }
}
