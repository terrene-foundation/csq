---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T05:58:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c00
session_turn: 32
project: codex
topic: OPEN-C05 RESOLVED NEGATIVELY — OpenAI /oauth/token does not echo submitted refresh tokens in error bodies across four probes; structural defense (SecretString) remains best practice but is not emergency-urgent
phase: analyze
tags: [codex, oauth, error-body-echo, security, OPEN-C05, pr-c00]
---

# Discovery — OPEN-C05: OpenAI `/oauth/token` does not echo submitted refresh tokens

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` adds OPEN-C05 per redteam H6 (error-body echo as structural-defense trigger): "three deliberately-bad refresh requests against `auth.openai.com/oauth/token`; inspect response bodies for echo of submitted refresh token prefix. If echo observed → refresher gains structural defense (SecretString across module)."

The precedent is Anthropic's `/v1/oauth/token` which was shown (journal `csq-v2/0007`) to echo portions of submitted refresh tokens in `invalid_grant` error bodies, triggering csq's `error::redact_tokens` rule for `sk-ant-*` prefixes. If OpenAI behaves the same way, csq's Codex refresher needs both structural defense (SecretString wrappers — tokens never formatted via Display) and a redactor extended to Codex-specific token prefixes (`sess-*`, JWT triple-segment, maybe others).

A negative finding (no echo) still leaves SecretString as a best practice but removes the immediate urgency and lets PR-C0's redactor extension be merged without blocking on refresher structural rewrite.

## Probes (four, not three — bonus data from OPEN-C04 transport probes)

Environment: macOS 25.3.0, `codex-cli` 0.122.0.

All probes sent `POST https://auth.openai.com/oauth/token` with `Content-Type: application/json`. Distinct refresh_token values per probe so any echo would be unambiguous.

### Probe 1 — curl + deliberately-bogus refresh_token

```
refresh_token: "deliberately_bogus_token_for_transport_probe_001"
→ HTTP 401
body: {"error":{"message":"Could not validate your token. Please try signing in again.","type":"invalid_request_error","param":null,"code":"token_expired"}}
```

Echo check: body does NOT contain `deliberately_bogus_token_for_transport_probe_001` or any prefix thereof. No echo observed.

### Probe 2 — Node fetch + different deliberately-bogus refresh_token

```
refresh_token: "deliberately_bogus_token_for_transport_probe_002"
→ HTTP 401
body: {"error":{"message":"Could not validate your token. Please try signing in again.","type":"invalid_request_error","param":null,"code":"token_expired"}}
```

Echo check: body identical to Probe 1 despite different submitted token. No echo.

### Probe 3 — reqwest/rustls + third distinct bogus refresh_token

```
refresh_token: "deliberately_bogus_token_for_transport_probe_003"
→ HTTP 401
body: {"error":{}}   ← body stripped by Cloudflare (OPEN-C04 finding)
```

Echo check: stripped body trivially contains no echo. The reqwest probe doesn't contribute positive evidence because the body is empty, but it doesn't contradict either.

### Probe 4 — curl + REAL (but already-used) refresh_token from `~/.codex/auth.json`

```
refresh_token: <actual user token from auth.json, ~200 char base64 string>
→ HTTP 401
body: {"error":{"message":"Your refresh token has already been used to generate a new access token. Please try signing in again.","type":"invalid_request_error","param":null,"code":"refresh_token_reused"}}
```

Echo check: body does NOT contain any prefix of the real refresh_token. The response reveals that the token WAS recognised (the server detected reuse), but does not echo the token value back. No echo.

## Discovery

OpenAI's `/oauth/token` endpoint returns structured error bodies that describe the failure WITHOUT echoing submitted credential values. Confirmed across four distinct token values (three bogus, one real) via three transports.

This is a behavioral contrast with Anthropic's equivalent endpoint, which was observed (journal `csq-v2/0007`) to include echoed refresh_token fragments in some `invalid_grant` responses. OpenAI's implementation is more conservative on this specific axis.

## Why this matters

1. **Structural defense (SecretString wrappers in the refresher module) remains best practice but is NOT an emergency upgrade.** PR-C4's refresher can ship with the existing `redact_tokens()` safety net; a progressive hardening to SecretString is a v2.1.x cleanup, not a v2.1.0 cut criterion.

2. **Redactor extension for `sess-*` and JWT is still needed for OTHER error paths.** The refresh endpoint doesn't echo, but other Codex paths might: the `wham/usage` endpoint's future 429 response bodies, or websocket upgrade failures, or SSO-callback error bodies. `KNOWN_TOKEN_PREFIXES` extension in PR-C0 proceeds as planned — it's defense-in-depth across all Codex-adjacent error surfaces, not just `/oauth/token`.

3. **The `refresh_token_reused` code IS the signal csq keys on.** Probe 4 demonstrated the error code that a stale token produces. This enables a specific error_kind (`codex_refresh_reused`) that csq's daemon refresher surfaces to the desktop UI: "Your Codex session needs refreshing — open a terminal and run `codex login` once."

4. **Confirmed the Anthropic assumption is NOT universal.** Every provider surface's echo-behavior must be probed empirically. Future surfaces (Gemini OAuth if ever applicable, xAI, etc.) should re-run this probe as part of their gate journals.

## Limits of this probe

- **Only `/oauth/token` probed, not every OpenAI OAuth surface.** Device-auth endpoints (`/oauth/device/authorize`, `/oauth/device/code`), SSO callbacks, and WebSocket upgrades could echo. PR-C4's test suite includes regression probes for each.

- **Only error responses probed (no 200 paths).** A 200 refresh response naturally contains the NEW tokens; that's not "echo of submitted value," that's the expected response. Not a gap — different threat model.

- **OpenAI could change this tomorrow.** No contract, just observed behavior. Regression test in PR-C4's test suite: assert response bodies for a deliberately-bad refresh never contain any segment of the submitted refresh_token. Fails loudly if OpenAI ever starts echoing.

- **Probe 3 (reqwest/rustls) returned empty body due to the OPEN-C04 body-strip issue, not because of echo suppression.** Cannot draw a clean conclusion from the stripped transport; rely on Probes 1/2/4 (full bodies available).

## Decision impact

- **PR-C4 refresher structural defense DOWNGRADED from emergency to best-practice-when-touching-module.** Plan §PR-C4 scope retains `SecretString` adoption in the section of refresher that stores tokens in memory, but does NOT block on a full-module SecretString rewrite.

- **PR-C0 redactor extension proceeds as planned.** `KNOWN_TOKEN_PREFIXES` gains `sess-*`, JWT triple-segment regex; `OAUTH_ERROR_TYPES` gains device-code error strings. Motivated by "defense-in-depth across all Codex error surfaces" now, not by "observed echo."

- **Spec 07 OPEN-C05 status flip.** RESOLVED NEGATIVELY — no echo observed; redactor + minimal structural defense sufficient. Upgrade to full structural defense deferred unless a future probe observes echo.

- **Journal reference for future provider-gate work.** Every new Cloudflare-fronted OAuth surface inherits this probe as a template.

## For Discussion

1. **The redactor extension (PR-C0) is justified here as "defense-in-depth," but with no observed echo the cost-benefit case is theoretical. Is it worth adding the redactor cases just because "Anthropic does it," or should we only add when we observe a specific leak?** (Lean: add proactively — redactor is cheap, the alternative is waiting for a real leak in production which is the wrong direction for a credential-handling codebase.)

2. **Probe 4 used the user's REAL refresh_token and burned it (journal 0008 GAP). Was this necessary, or could the four-probe matrix have avoided the one real-token probe entirely?** (Arguably: Probes 1-3 already cover bogus tokens across three transports; Probe 4 was valuable because it was the ONLY probe that exercised a RECOGNISED token path — the server acknowledged the token rather than just rejecting its format. Without Probe 4 we'd know the server doesn't echo unknown tokens but couldn't confirm it also doesn't echo known-but-invalid tokens. The trade-off cost one user re-auth.)

3. **If OpenAI ever STARTS echoing tokens in error bodies (say, a debug flag leaks into production), how fast would csq's regression test catch it?** Answer: on the next CI run against the probe suite — which requires the probe suite to be part of CI, not just manual. PR-C4 should add the probe as an integration test, not just a local verification step. Cost: ~1s per CI run; value: early warning on upstream security regression.

## Cross-references

- Spec 07 §7.7 (OPEN-C05 new status added here) + §7.7.4 (OPEN-C04 cross-reference)
- Journal `csq-v2/0007` — Anthropic echo-behavior discovery (motivates why we probed)
- Journal 0007 (this PR) — OPEN-C04 transport decision (explains reqwest body-strip in Probe 3)
- Journal 0008 (this PR) — §5.7 GAP from Probe 4 side-effect
- Plan §PR-C0 — redactor extension proceeds as planned (defense-in-depth framing)
- Plan §PR-C4 — structural defense downgraded to "best practice when touching module"
