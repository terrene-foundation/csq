---
type: RISK
date: 2026-04-10
created_at: 2026-04-10T22:30:00Z
author: co-authored
session_id: m8-cache-refresher
session_turn: 120
project: csq-v2
topic: Error chains can leak OAuth tokens through serde_json parse errors
phase: redteam
tags: [m8, security, credentials, error-handling, logging]
---

# RISK: Error chains echo secrets through upstream parse failures

## Discovery

During M8.4 (background refresher), the security reviewer found that
`serde_json::Error::Display` can include fragments of the failing
input bytes when a parse aborts partway through. The refresher
passes `post_form(url, body)` where `body` is the OAuth refresh
form — `grant_type=refresh_token&refresh_token=sk-ant-ort01-...`.
If Anthropic returns a malformed body (HTML error page from an
upstream proxy, truncated JSON) and that body happens to echo our
submitted refresh token (observed behavior for `invalid_grant`
responses), serde_json's parse-error Display would carry the token
substring into `OAuthError::Exchange(msg)`. From there:

```
OAuthError::Exchange(msg)
  → CsqError::OAuth(...)
  → BrokerError::RefreshFailed { reason: e.to_string() }
  → tracing::warn!(account, error = %e, "broker_check errored")
```

The cache label was always safe ("failed"/"error"), but tracing
output is widely accessible (CI logs, support bundles, systemd
journal). One malformed upstream response → token in logs →
operator / support staff can read it.

## Fix (landed in PR #43)

1. Made `error::redact_tokens` `pub` — it was already scrubbing
   `sk-ant-oat01-` and `sk-ant-ort01-` prefixes, just not exposed
   outside the `error` module.
2. `credentials::refresh::refresh_token` now runs both the
   transport error path AND the serde parse error path through
   `redact_tokens` before wrapping in `OAuthError::Exchange`.
3. Refresher's `Ok(Err(e))` branch no longer logs `%e`. Instead
   it maps `CsqError` to a short fixed-cardinality tag via
   `error_kind_tag(&e)` and logs `error_kind = "oauth"` etc.
4. Two regression tests added in
   `csq-core/src/credentials/refresh.rs`:
   - `refresh_token_parse_error_does_not_leak_token` — feeds a
     malformed body containing `sk-ant-ort01-LEAKED-SECRET-TOKEN`
     and asserts the error message does not contain the substring.
   - `refresh_token_transport_error_does_not_leak_token` — same
     assertion for the transport error path.

## Remaining risk

The pattern is broader than this one fix. Any future code that:

- Parses an upstream response into a typed struct via serde
- Wraps parse errors via `format!("{e}")` or `.to_string()`
- Lets that error reach `tracing::*!` or a user-facing API

...can re-open the same hole. Mitigations going forward:

1. **Module invariant**: any module that touches OAuth, API keys,
   or refresh tokens MUST route ALL error-formatting through
   `error::redact_tokens`. Enforce via code review.
2. **Test invariant**: every such module MUST have a regression
   test feeding a leaky body and asserting the error doesn't
   contain the token prefixes.
3. **Log invariant**: no `error = %e` logging anywhere in the
   refresher, poller, OAuth callback, or HTTP handlers. Use
   `error_kind_tag` or a similar fixed-vocabulary tag.

## For Discussion

1. Should `redact_tokens` be applied at the `CsqError::Display`
   impl level so it's automatic, rather than relying on every
   caller to remember? The downside is an accidentally-redacted
   diagnostic the developer needed to see.
2. `redact_tokens` only knows about Anthropic OAuth token
   prefixes (`sk-ant-oat01-`, `sk-ant-ort01-`). Third-party
   provider keys (MiniMax, Z.AI, Claude direct API) have
   different shapes. Should we expand the redactor or add a
   provider-aware variant?
3. Would a clippy lint against `%e` in tracing macros within
   `daemon/`, `credentials/`, and `broker/` modules be worth the
   effort, or is code review + regression tests sufficient?
