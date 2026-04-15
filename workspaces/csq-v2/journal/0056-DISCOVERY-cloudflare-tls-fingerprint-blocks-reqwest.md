# 0056 — DISCOVERY: Cloudflare TLS fingerprint blocks reqwest/rustls

**Date:** 2026-04-15
**Status:** Resolved (PR #125, #126)
**Severity:** P0 — all accounts unable to auto-refresh

## Finding

Anthropic endpoints (`platform.claude.com`, `api.anthropic.com`) are
behind Cloudflare, which performs JA3/JA4 TLS fingerprinting. The
`reqwest` crate with `rustls-tls-webpki-roots` produces a TLS
handshake fingerprint that Cloudflare rejects with `429
rate_limit_error` on every request, regardless of actual volume.

**Proof:** Same endpoint, same JSON body, same headers — Node.js
(`https.request`) succeeds immediately, `reqwest` and system `curl`
both get 429. The differentiator is the TLS handshake, not the HTTP
layer.

## Impact

- Token refresher silently failed for all accounts since the
  Cloudflare policy change (unknown date)
- Usage poller also affected (429 on `GET /api/oauth/usage`)
- User had to manually re-auth every account when tokens expired
- The 429 response body (`rate_limit_error`) was indistinguishable
  from real rate limiting, masking the root cause

## Correction to journal 0052

Journal 0052 attributed the mass refresh failure to the `scope` field
in the refresh body. That was wrong. CC's own `refreshOAuthToken`
(in `services/oauth/client.ts:146-168`) sends `scope` in the refresh
body and it works fine.

The `400 invalid_scope` error observed in journal 0052 may have been
a symptom of the same Cloudflare fingerprint issue (different error
response at different times), or it may have been a genuine but
transient server-side restriction that has since been relaxed.

**The `scope` field is safe to include in refresh bodies.** CC sends
it. Our code currently omits it (no harm), but the prohibition in
the provider-integration skill was based on a misdiagnosis.

## Resolution

- **PR #125:** Added `post_json_node()` and `get_bearer_node()` in
  `csq-core/src/http.rs` — shell out to `node` for Anthropic
  endpoints, piping request bodies via stdin (not argv) so tokens
  stay out of `ps` output
- Wired into CLI daemon, desktop daemon, and OAuth exchange paths
- No reqwest fallback — if `node`/`bun` not found, error immediately
- Also added exponential backoff (10min x 2^n, cap 80min) and
  stop-on-rate-limit within refresher ticks
- **PR #126:** Fixed `oauth-replay.yml` workflow parse error
  (`secrets.*` in step-level `if`)

## Diagnostic pattern

If refresh/usage-polling fails with `rate_limit_error` but manual
`claude auth login` (authorization_code flow) works:

1. Test the same request via `node -e '...'` instead of reqwest/curl
2. If node succeeds → Cloudflare TLS fingerprint issue
3. Check that `post_json_node` is wired (not `post_json`)
