//! OAuth 2.0 Authorization Code + PKCE flow for adding new Anthropic accounts.
//!
//! # Module layout
//!
//! - [`constants`] — single source of truth for the Anthropic OAuth
//!   client_id, scopes, authorize URL, default redirect port, and
//!   redirect URI builder. Fixes the L1 security finding (v1.x had
//!   the client_id duplicated across three Python files).
//! - [`pkce`] — `CodeVerifier` / `CodeChallenge` newtypes with
//!   [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
//!   primitives. The verifier wraps `secrecy::SecretString` so it
//!   never leaks through `Debug` / logging.
//! - [`state_store`] — bounded, TTL'd, single-use map of pending
//!   login states. CSRF protection plus abandonment cleanup.
//! - [`login`] — [`login::start_login`] produces the browser
//!   authorize URL and records the pending state.
//! - [`exchange`] — [`exchange::exchange_code`] swaps the returned
//!   authorization code for an access/refresh token pair via
//!   `POST {token_url}`.
//!
//! # M8.7a scope (this slice)
//!
//! This module is **library-only**. The daemon-side routes
//! (`GET /api/login/{N}`, the `127.0.0.1:8420` TCP callback
//! listener, `GET /oauth/callback`) land in M8.7b. Splitting keeps
//! the security review small — this PR has no new network surface;
//! M8.7b adds the network wiring against primitives that are
//! already unit-tested.
//!
//! # Security invariants
//!
//! 1. `CodeVerifier` wraps `SecretString` — `Debug` prints
//!    `[REDACTED]`, never the raw bytes. Tests assert this.
//! 2. Error paths run through [`crate::error::redact_tokens`] before
//!    wrapping, per journal entry 0007-RISK (no `%e` into tracing).
//!    **Important scope note:** `redact_tokens` currently only
//!    scrubs the `sk-ant-oat01-` and `sk-ant-ort01-` prefixes —
//!    that is, long-lived access and refresh tokens. It does NOT
//!    scrub OAuth *authorization codes* or *PKCE verifiers*,
//!    neither of which has a stable prefix. For the exchange flow
//!    the real defense is **structural**: [`exchange::exchange_code`]
//!    never formats the request body (which contains the code and
//!    verifier) into an error string, and the dedicated regression
//!    test `exchange_code_does_not_include_verifier_in_transport_error_path`
//!    locks this in. See journal entry 0010-RISK for the full
//!    scope of `redact_tokens`.
//! 3. Token exchange request bodies are never formatted into error
//!    strings. If the upstream echoes the code back in a 4xx body,
//!    the echo is scrubbed in the `OAuthError::Exchange` variant.
//! 4. State tokens are generated with `getrandom` (the same source
//!    the OS gives `/dev/urandom` et al.) — not `rand::thread_rng`.
//! 5. `OAUTH_SCOPES` is defined exactly once (in [`constants`]).
//!    Every module that needs it re-imports the constant.

pub mod constants;
pub mod exchange;
pub mod login;
pub mod pkce;
pub mod state_store;

pub use constants::{
    scopes_joined, OAUTH_AUTHORIZE_URL, OAUTH_CLIENT_ID, OAUTH_SCOPES, OAUTH_TOKEN_URL,
    PASTE_CODE_REDIRECT_URI,
};
pub use exchange::exchange_code;
pub use login::{start_login, start_login_default_port, LoginRequest};
pub use pkce::{challenge_from_verifier, generate_verifier, CodeChallenge, CodeVerifier};
pub use state_store::{OAuthStateStore, PendingState, MAX_PENDING, STATE_TTL};
