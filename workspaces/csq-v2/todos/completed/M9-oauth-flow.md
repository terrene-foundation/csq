# M9: OAuth Flow (Dashboard)

Priority: P1 (Fast-Follow)
Effort: 1 autonomous session
Dependencies: M8 (Daemon Core — HTTP API for callback)
Phase: 3

---

## M9-01: Build PKCE code generation

`generate_code_verifier()` — 43 chars, URL-safe base64. `generate_code_challenge(verifier)` — SHA256 + base64url. Per RFC 7636.

- Scope: 9.4-9.5
- Complexity: Trivial
- Acceptance:
  - [x] Verifier: 43 chars, URL-safe alphabet
  - [x] Challenge: SHA256(verifier), base64url-encoded, no padding
  - [x] Matches RFC 7636 Appendix B test vectors

## M9-02: Build OAuth state store with TTL

`OAuthStateStore` per GAP-10 resolution. 10-minute TTL. Background cleanup every 60s. Bounded to 100 entries. Single-use consumption on callback.

- Scope: GAP-10
- Complexity: Moderate
- Acceptance:
  - [x] Fresh state: lookup succeeds
  - [x] Expired state (>10min): rejected with StateExpired
  - [x] Consumed state: second lookup fails (single-use)
  - [x] 101st entry: oldest evicted

## M9-03: Build OAuth login initiation

`start_login(account)` — generate state + code_verifier, store in state store, build authorize URL with all required params (client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method). Return URL for browser redirect.

- Scope: 9.1
- Complexity: Moderate
- Acceptance:
  - [x] Authorize URL contains all required params
  - [x] State stored in state store
  - [x] URL is well-formed and URL-encoded
  - [x] Callback listener binds to `127.0.0.1` only (not `0.0.0.0`) — security finding S12

## M9-04: Build OAuth callback handler

`handle_callback(code, state)` — consume state (single-use), retrieve code_verifier, exchange code for tokens, save credentials to canonical + mirror, save profile, clear broker-failure flag.

- Scope: 9.2
- Complexity: Complex
- Depends: M9-02, M9-05
- Acceptance:
  - [x] State consumed (replay rejected)
  - [x] Missing state: CSRF error
  - [x] Code exchanged successfully
  - [x] Credentials saved atomically
  - [x] Profile updated with email

## M9-05: Build code-for-token exchange

`exchange_code(code, code_verifier, redirect_uri)` — POST to Anthropic token endpoint. Request body: `grant_type=authorization_code`, `code`, `client_id`, `code_verifier`, `redirect_uri`. Parse response into `CredentialFile`.

- Scope: 9.3
- Complexity: Moderate
- Acceptance:
  - [x] Mock server: correct request body format
  - [x] Successful exchange: CredentialFile returned
  - [x] Error response: OAuthError::Exchange
