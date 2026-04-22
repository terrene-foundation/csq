---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T05:48:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c00
session_turn: 24
project: codex
topic: OPEN-C04 RESOLVED — reqwest/rustls body-stripped by Cloudflare on OpenAI endpoints; csq uses Node subprocess (already Foundation-approved pattern from journal 0056) for wham/usage + /oauth/token; PR-C0.5 fires
phase: analyze
tags:
  [
    codex,
    transport,
    cloudflare,
    reqwest,
    rustls,
    node,
    OPEN-C04,
    pr-c00,
    pr-c0.5,
  ]
---

# Decision — OPEN-C04: Codex transport via Node subprocess

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` lists OPEN-C04 as a PR-gating precondition for PR-C4 (refresher) and PR-C5 (`wham/usage` poller): "Live probe `auth.openai.com/oauth/token` + `chatgpt.com/backend-api/wham/usage` via reqwest/rustls + Node fetch + curl. If reqwest gets 403 where Node doesn't → reuse Node transport. If resolved 'Node transport required', fires PR-C0.5."

Memory (`discovery_cloudflare_tls_fingerprint.md`): reqwest/rustls was previously blocked by Cloudflare JA3/JA4 on Anthropic endpoints, forcing csq to adopt a Node.js subprocess pattern (journal `csq-v2/0056`). OPEN-C04 asks whether the same failure class extends to OpenAI's Cloudflare-fronted surface.

## Probes

Environment: macOS 25.3.0, Node v25.9.0, Rust reqwest 0.12 with default-features=false + rustls-tls.

Three transports issued identical HTTP payloads against both endpoints. User-Agent set to `csq/open-c04-probe` across all three (where controllable). The access_token was expired at probe time — so the comparison point is NOT "does it succeed?" but "what response body does each transport see?".

### Probe 1 — `chatgpt.com/backend-api/wham/usage` (GET with Bearer)

| Transport      | Status | `cf-ray` header | `server` header | Response body                                                                                                                                                 |
| -------------- | ------ | --------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| curl           | 401    | —               | —               | `{"error":{"message":"Provided authentication token is expired. Please try signing in again.","type":null,"code":"token_expired","param":null},"status":401}` |
| Node fetch     | 401    | 9f0255aaff96…   | cloudflare      | `{"detail":"Could not parse your authentication token. Please try signing in again."}`                                                                        |
| reqwest/rustls | 401    | 9f025672dbd6…   | cloudflare      | `{"error":{},"status":401}` — **body stripped**                                                                                                               |

### Probe 2 — `auth.openai.com/oauth/token` (POST deliberately-bogus refresh_token)

| Transport      | Status | `cf-ray`      | Response body                                                                                                                                            |
| -------------- | ------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| curl           | 401    | —             | `{"error":{"message":"Could not validate your token. Please try signing in again.","type":"invalid_request_error","param":null,"code":"token_expired"}}` |
| Node fetch     | 401    | 9f0255abab8c… | (same as curl — full JSON error body)                                                                                                                    |
| reqwest/rustls | 401    | 9f0256752a00… | `{"error":{}}` — **body stripped**                                                                                                                       |

## Discovery

All three transports REACH the OpenAI origin (401 status, `cf-ray` present, `server: cloudflare`). No hard block. BUT — body fidelity differs by transport:

- **curl** (OpenSSL default, `curl/*` User-Agent): full JSON error body in both endpoints.
- **Node fetch** (OpenSSL, Node's HTTP/2 stack): full body on `/oauth/token`; slightly different error message on `/wham/usage` ("Could not parse your authentication token" vs curl's "token_expired"). The Node body is less uniform with curl's but remains structured and parseable.
- **reqwest/rustls**: body STRIPPED to `{"error": {}, "status": 401}` or `{"error": {}}`. The OpenAI origin's structured error payload is replaced with a sanitized envelope somewhere in the Cloudflare → reqwest path.

This matches the Anthropic failure class from journal `csq-v2/0056` — Cloudflare's bot/fingerprint heuristics degrade body detail for non-browser-looking TLS clients without returning a hard 403. The symptom on OpenAI is LESS aggressive than Anthropic (status still correct, some JSON structure preserved) but severe enough to break:

- Error-kind routing (`token_expired` vs `invalid_request_error` vs nothing)
- Refresh_token_reused detection (code field required per spec 05 §5.7)
- `wham/usage` schema capture (arbitrary payload stripping)
- `RESOURCE_EXHAUSTED` / 429 parsing (Google-style error details needed in §5.8 parity code path)

## Decision

**Adopt the Node subprocess transport pattern (journal `csq-v2/0056`) for Codex's `/oauth/token` refresh and `/backend-api/wham/usage` poll.** PR-C0.5 fires per plan.

- `csq-core/src/http/codex.rs` (new in PR-C0.5) — thin wrapper that executes a Node subprocess for Codex endpoint calls, passing tokens via stdin to avoid argv exposure, parsing JSON response from stdout. Same architecture as the Anthropic Node bridge.
- Reuse existing `bundled Node` resolution logic — `csq-desktop` already ships a Node runtime for the Anthropic path; Codex piggybacks. No new runtime dependency.
- Unit tests: `node_transport_parses_wham_usage_response`, `node_transport_parses_oauth_refresh_response`, `node_transport_surfaces_401_token_expired`, `node_transport_redacts_refresh_token_from_argv_and_errors`.
- Fallback: if Node runtime missing at runtime (shouldn't happen — bundled), surface `error_kind = "codex_transport_unavailable"`; daemon marks the slot as quota-unknown.

### Why Node and not curl?

Node is already bundled for Anthropic; adding curl as a dependency doubles the attack surface for a capability already covered by Node. curl's command-line-argument injection story is also weaker (argv is world-readable via `ps`; Node's stdin transport is not). Node's body fidelity is not perfect (see Probe 1 wham/usage "could not parse" discrepancy with curl) but it is sufficient for structured-error routing — the `type` + `code` fields carry the semantics csq needs.

### What about the Node/curl wham body discrepancy?

Node saw "Could not parse" where curl saw "token_expired" — two OpenAI server error paths triggered by the same expired access_token. Hypothesis: User-Agent-based routing at Cloudflare (curl's default `curl/*` UA is on a whitelist; Node's `undici` UA or csq's custom UA is routed to a stricter token-format validator). Csq's Node subprocess SHOULD emit `User-Agent: csq-codex/<version>` — no attempt to impersonate curl, because impersonation breaks in unpredictable ways and violates Cloudflare ToS. The "parse vs expired" wording variance is absorbed by mapping BOTH strings to `error_kind = "codex_token_invalid"` in the redactor.

## Why this matters

1. **PR-C4 + PR-C5 are unblocked on transport.** Implementation can start against the Node bridge contract; reqwest paths are abandoned for OpenAI Cloudflare-fronted endpoints.

2. **Architecturally consistent with Anthropic.** csq now has a uniform rule: any Cloudflare-fronted provider surface routes through the Node subprocess. This becomes a spec-level invariant worth pinning (spec 05 or spec 07). Future surfaces (e.g. potential xAI or Perplexity integration) inherit the same discipline.

3. **Body-stripping confirms PR-C4's structural defense is still warranted.** Even with Node transport, body fidelity is not 100% (wham "could not parse" example). The refresher must not rely on a specific error message wording — it must key on `code` / `type` fields and fall back to status codes. Lint-enforceable via a test that randomises error message strings while holding code/type stable.

4. **rustls is unsalvageable here — do not try to tune it.** Cloudflare's JA3/JA4 fingerprint database updates continuously; any "fix" to make rustls look more browser-like today is broken tomorrow and also violates Cloudflare's ToS (impersonation). The Node bridge is the architecturally clean answer.

## Alternatives considered

1. **Use `reqwest` with native-tls (system OpenSSL) instead of rustls.** Would likely produce the same full body as curl on macOS (shared OpenSSL). But: (a) requires a system OpenSSL link on Linux/Windows which we've avoided for portability; (b) unclear whether Cloudflare fingerprints native-tls the same as rustls; (c) keeping two TLS backends is maintenance overhead. REJECTED.

2. **Inline `hyper` + a custom rustls ClientConfig that mimics Chrome's cipher-suite order.** Theoretically works — tools like `ja3transport` exist. Rejected because: (a) this is TLS impersonation, Cloudflare-ToS-violating; (b) fragile — Cloudflare updates fingerprints weekly; (c) csq already has the Node bridge. REJECTED.

3. **Drop PR-C5 from v2.1 and ship quota as "Counter mode on spawn events" similar to Gemini §5.8.** Avoids the transport question entirely. But: loses the subscription-quota accuracy that's the whole point of OpenAI ChatGPT subscription integration; v2.1.0 marketing positioning depends on "live utilization". REJECTED.

## Limits of this probe

- **All three transports received the same status code (401). If the discrepancy were in status rather than body, the user-facing symptom would differ.** Probe did not exercise actual success (no fresh access_token available) or actual 429. Follow-up in PR-C5 post-merge: capture a real 429 response body via all three transports when rate-limiting occurs naturally.

- **WebSocket transport (`wss://api.openai.com/v1/responses`) not probed.** Codex uses WebSocket for inference — csq does NOT poll the WebSocket endpoint (that's the user's `codex` process's concern) but if a future feature (e.g. session-scoped usage events) needs to read WebSocket responses, the Cloudflare story reopens.

- **Did not test HTTP/2 vs HTTP/1.1 explicitly.** Node and reqwest default to HTTP/2; curl defaults to 1.1. If the body-stripping is HTTP/2-specific rather than TLS-fingerprint-specific, a reqwest+http1 probe might succeed. Cost-benefit analysis: the Node bridge is already the chosen path; this investigation is not blocking.

## Decision consequences

- **PR-C0.5 fires.** A new PR (between PR-C0 and PR-C1 in the sequence) lands the Node bridge for Codex.
- **Spec 05 §5.7 transport note added (this PR, PR-C00).** "Codex endpoints use Node subprocess transport per journal 0007; direct reqwest calls return body-stripped responses under Cloudflare fingerprinting."
- **Spec 07 §7.7.4 status flip.** OPEN-C04 → RESOLVED with transport decision cited.
- **PR-C4 unblocked but adjusted.** Refresher module calls into `http::codex::refresh_tokens` (Node bridge) rather than using reqwest directly.
- **PR-C5 unblocked on transport; still blocked on §5.7 schema capture pending user re-auth (journal 0008).**

## For Discussion

1. **The Anthropic Node bridge (journal csq-v2/0056) was added because of a HARD 403 block. OpenAI's fingerprinting is softer (body-strip, not block). Is the Node bridge proportionate, or is there a lighter alternative like "use reqwest, accept the body strip, key only on status + content-length"?** (Current lean: the body carries the error_code field we need for refresh_token_reused detection, which status-code-only cannot provide. So the Node bridge pays for itself.)

2. **Probe 1 showed Node and curl returning different error wordings on `wham/usage`. If OpenAI ever unifies those wordings at the backend, one of our assumptions (the Cloudflare-routes-based-on-UA hypothesis) collapses — what's the robustness story if the observed variance disappears?** (Lean: our code keys on `code` / `type` fields, not wording, so robustness is structural rather than wording-dependent. This is intentional.)

3. **reqwest/native-tls on macOS would likely produce full bodies (shared OpenSSL with curl). Is it worth keeping a conditional "use native-tls on macOS, Node bridge on Linux/Windows" path, or is the uniformity of "Node bridge everywhere" more valuable?** (Lean: uniformity wins; two code paths double testing cost.)

## Cross-references

- Spec 05 §5.7 (Codex wham/usage) — transport note added this PR
- Spec 07 §7.7.4 (OPEN-C04) — status flipped by this PR
- `workspaces/csq-v2/journal/0056` — Anthropic Node bridge origin (pattern reused here)
- Memory: `discovery_cloudflare_tls_fingerprint.md` — prior Anthropic finding, now extended to OpenAI
- Plan §PR-C0.5 — fires per this decision
- Plan §PR-C4 — refresher calls `http::codex::refresh_tokens`
- Plan §PR-C5 — poller calls `http::codex::fetch_usage`
- Journal 0009 (this PR) — OPEN-C05 no-echo finding (removes additional structural-defense urgency)
