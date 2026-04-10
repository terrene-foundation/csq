---
name: redact_tokens scope does not cover OAuth authorization codes
description: Clarifies the scope of error::redact_tokens and the structural defense that protects short-lived OAuth codes and PKCE verifiers
type: RISK
date: 2026-04-10
created_at: 2026-04-10T00:00:00Z
author: co-authored
session_id: m87a
session_turn: 2
project: csq-v2
topic: OAuth PKCE module bootstrap (M8.7a)
phase: implement
tags: [oauth, security, redaction, defense-in-depth, m8.7, risk-0007-followup]
---

# RISK: `redact_tokens` scope ≠ "every secret"

## Context

Journal entry `0007-RISK-error-body-echo-leaks-secrets.md` established the invariant that all OAuth-adjacent error formatting must go through `error::redact_tokens` before reaching tracing / IPC / user-facing output. That journal entry was written in the context of the M8.4 refresher and M8.5 HTTP routes, where the sensitive secrets were Anthropic **access and refresh tokens** — long-lived values with the stable prefixes `sk-ant-oat01-` and `sk-ant-ort01-`.

M8.7a (this PR) introduced the OAuth PKCE login primitives, which deal with two new classes of secret that do NOT have stable prefixes:

1. **OAuth authorization codes** returned from the Anthropic authorize endpoint (short-lived, ~minutes, single-use).
2. **PKCE code verifiers** generated client-side and held in `CodeVerifier` (single-login lifetime, never transmitted outside the exchange request body).

The M8.7a security review (`security-reviewer`) raised a MEDIUM finding (M1) noting that `redact_tokens` as written does not cover these values. This journal entry documents that gap explicitly so future contributors do not mistakenly believe `redact_tokens` is a universal scrubber.

## What `redact_tokens` actually does

```rust
// csq-core/src/error.rs
pub fn redact_tokens(s: &str) -> String {
    let mut result = s.to_string();
    for prefix in ["sk-ant-oat01-", "sk-ant-ort01-"] {
        while let Some(start) = result.find(prefix) {
            let end = result[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
                .map(|i| start + i)
                .unwrap_or(result.len());
            result.replace_range(start..end, "[REDACTED]");
        }
    }
    result
}
```

It scrubs the two known Anthropic token prefixes. That is **all** it scrubs.

## What it does NOT cover

| Secret                   | Prefix      | Typical source                        | Why the redactor misses it                         |
| ------------------------ | ----------- | ------------------------------------- | -------------------------------------------------- |
| OAuth authorization code | none stable | Anthropic callback query string       | No prefix to match on                              |
| PKCE code verifier       | none        | client-side, `CodeVerifier`           | Random URL-safe base64, looks like any other token |
| OAuth state token        | none        | `OAuthStateStore::insert`             | Random URL-safe base64                             |
| Keychain service name    | none        | `credentials::keychain::service_name` | Hash output, not a token                           |

If any of these ever reaches a `tracing::warn!("{e}")` or a returned error string, `redact_tokens` passes them through unchanged.

## What protects them today

The defense is **structural**, not redaction-based:

1. **`exchange::exchange_code` never formats the request body into any error path.** The body is constructed once via `serde_json::to_string(&ExchangeRequest)`, handed to the `http_post` closure, and then dropped. If the HTTP call succeeds, the body is gone before any response parsing. If it fails, the transport error is a reqwest error sanitized by `sanitize_err` (which strips URLs) and passed through `redact_tokens` (which is a no-op on an authorization code but at least scrubs any `sk-ant-*` echoes).
2. **The `CodeVerifier` newtype wraps `SecretString`** which has a custom `Debug` impl printing `[REDACTED]`. The verifier can only leak if a caller explicitly calls `.expose_secret()` and concatenates the result into a String that then reaches `format!`. Grep for `.expose_secret()` on `CodeVerifier` — the only call sites are inside `exchange::exchange_code` (JSON serialization) and a test harness.
3. **Regression tests lock the structural defense**:
   - `exchange_code_does_not_include_verifier_in_transport_error_path` — transport errors cannot echo the verifier
   - `exchange_code_parse_error_does_not_leak_tokens` — malformed response JSON cannot echo tokens via serde error Display
   - `exchange_code_transport_error_is_redacted` — the `sk-ant-*` fallback still runs for refresh tokens if they somehow end up in a transport error string
   - `post_json_error_does_not_leak_body` — the transport layer itself does not format the request body into errors

## What to NOT do

- **Do NOT** extend `redact_tokens` to match `code=` or `code_verifier=` substrings. This would be fragile because authorization codes have no fixed format, and a greedy regex would cause false positives on unrelated content.
- **Do NOT** route `CodeVerifier::expose_secret()` output into any string that might be formatted or logged. The structural guarantee depends on that value never leaving the exchange request body.
- **Do NOT** assume a future secret type is automatically protected by `redact_tokens`. When adding a new secret type to `csq-core`, explicitly audit every error path and add a regression test naming the secret.

## What to DO

- **When adding a new OAuth-adjacent module**, explicitly cross-reference this journal entry so the reviewer knows `redact_tokens` is not a universal shield.
- **When the code exchange grows a new caller** (e.g., M8.7b wires the `GET /oauth/callback` route to it), audit that caller's error path for the same "no request body in errors" invariant.
- **If a future Anthropic API change introduces a new token prefix** (e.g., `sk-ant-sess01-` for session tokens), add that prefix to the `redact_tokens` loop alongside the existing two. This is the only scalable extension of `redact_tokens`.

## Cross-references

- [0007-RISK-error-body-echo-leaks-secrets.md](0007-RISK-error-body-echo-leaks-secrets.md) — the parent RISK that established the `redact_tokens` invariant
- [0009-DECISION-oauth-constants-single-source.md](0009-DECISION-oauth-constants-single-source.md) — the M8.7a constants consolidation decision
- `csq-core/src/error.rs::redact_tokens` — the redactor itself
- `csq-core/src/oauth/exchange.rs::exchange_code` — the structural-defense call site
- `csq-core/src/oauth/pkce.rs::CodeVerifier` — the `SecretString` wrapper with custom `Debug`

## For Discussion

1. **Should `redact_tokens` be renamed to `redact_anthropic_tokens` to make its scope unambiguous at call sites?** The name implies a broader contract than the function delivers. A rename would ripple through ~15 call sites but would make every future reviewer's mental model correct by default. Is the rename worth the diff churn, or is this journal entry sufficient as the canonical reference?

2. **Structural defenses rely on discipline — how do we catch a regression where a future contributor formats the verifier into an error?** One option: a clippy lint forbidding `format!` / `println!` / `tracing::*` arguments that include `expose_secret()`. That would require a custom lint plugin. A simpler option: a CI grep that fails on `expose_secret.*format` patterns in `csq-core/src/oauth/`. Is either worth implementing, or do the existing regression tests suffice?

3. **If a future secret type is added without a stable prefix (e.g., a new PKCE variant), the `redact_tokens` extension model does not apply.** The journal here says "structural defense is the answer" but structural defense is case-by-case and requires per-module review. Should we formalize a "secret inventory" document listing every secret type, its redaction strategy, and its enforcing test? The inventory would live alongside the journal and be updated on every new-secret PR.
