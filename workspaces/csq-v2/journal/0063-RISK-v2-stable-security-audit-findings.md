---
type: RISK
date: 2026-04-21
created_at: 2026-04-22T00:05:00+08:00
author: co-authored
session_id: 2026-04-21-stable-v2-readiness
session_turn: 39
project: csq-v2
topic: security-reviewer audit for v2.0.0 stable readiness surfaces 1 HIGH (download_and_apply bypass), 3 MEDIUMs (cancel_login error redaction, Tauri capability over-grant, JSONL breadcrumb escape), 7 LOWs
phase: analyze
tags:
  [
    security,
    v2-stable,
    updater,
    placeholder-key,
    download_and_apply,
    tauri-capability,
    oauth-error-leak,
    redteam-input,
  ]
---

# 0063 — RISK: v2.0.0-stable security audit findings

**Audit:** `workspaces/csq-v2/01-analysis/05-v2-stable-security-audit.md` (full detail with file:line evidence and fix recommendations).
**Status:** H1 is a v2.0.0 blocker. M1–M3 are fix-in-session preferred, deferrable to 2.0.1 if release schedule forces. L1–L7 informational.

## Findings summary

### HIGH (1)

- **H1 — `csq_core::update::download_and_apply` lacks `is_placeholder_key()` gate at the core entry point.** The CLI wrapper guards; the core function does not. Any future caller (a Tauri command, a doctor subcommand, a rogue test) skips the gate and trusts whatever key is in `verify.rs`. Source of truth for the gate should be the core function, not the CLI wrapper.
  - **Blast radius:** If the Foundation ever rotates the release key back to the seed-1 placeholder (intentionally or via a regression during rotation), any caller of the core function reaches RCE-as-current-user. The placeholder's private key is deterministically derivable from the committed source.
  - **Fix:** move the check to the top of `csq-core/src/update/apply.rs::download_and_apply`. Add regression test asserting the check fires.

### MEDIUM (3)

- **M1 — `cancel_login` IPC returns `format!("cancel failed: {e}")` on a fallback `OAuthError`.** Today structurally unreachable (consume only returns two matched variants), but a future widening of the error type could leak body content into IPC response.
- **M2 — Tauri capability grants `updater:default`, `autostart:default`, `process:default`, `opener:default` to the main-window renderer.** Capability breadth is wider than actual use. If the renderer is ever compromised (XSS via a content field), it can open URLs, restart the app, or invoke the updater plugin.
- **M3 — Resurrection-log JSONL breadcrumb writes interpolated path with only double-quote escaping.** Paths with backslashes or control chars corrupt the forensic trail. Non-exploitable (same-user threat model); fix is trivial (`serde_json::to_string`).

### LOW (7)

- L1: `OAuthError::Http { body }` field is `pub` (redacted on Display, not on field access).
- L2: `credentials::file::save_canonical` mirror-write logs `%e` instead of fixed error-kind tag.
- L3: `credentials::keychain::read` logs `%e` from the `security` shellout.
- L4: `OAuthError::Exchange(recovery_err.to_string())` walks Display chain.
- L5: `http.rs::get_bearer_node` static-URL invariant is implicit — document it.
- L6: `is_placeholder_key` comparison is tight — noted for completeness.
- L7: Several Tauri commands accept `base_dir: String` without the `canonicalize + starts_with` guard that `swap_session` uses.

## Passed checks (no findings)

Atomic writes, subscription preservation, AccountNum validation, CRLF injection defense on `daemon::client`, 3-layer Unix socket security, no TCP credential routes, no hardcoded tokens, .gitignore hygiene, no `shell=true` / `sh -c` injection, SecretString zeroization, OAuth state store bounds + TTL, PKCE RFC 7636 conformance, token redaction coverage, response body caps, refresher backoff, peer UID check on Unix socket, Tauri CSP, dependency versions current with no known open CVEs.

## What a red-teamer would hit first — ranked

1. **Run `csq_core::update::download_and_apply` directly** via a subcrate dep or rogue test (H1). Structural fix required.
2. **Pass a crafted `base_dir` through a Tauri command** that doesn't canonicalize (L7). Defense-in-depth gap; same-user model makes this safe today.
3. **Poison `.claude.json.cachedGrowthBookFeatures.tengu_auto_mode_config`** to silently downgrade csq-swapped terminals to Sonnet. Not a csq bug — but document `csq doctor` should diff this cache.

## Consequences

- H1 is added as an explicit blocker in the release gate checklist (journal 0062 Group E).
- M1–M3 are entered as "fix-in-session preferred; acceptable to defer to 2.0.1 only if schedule forces and explicit release-notes language calls them out."
- L1–L7 are informational; they don't block stable but should land in an incremental security-hygiene PR post-2.0.0.

## For Discussion

1. **H1 — fix-site choice.** Moving `is_placeholder_key()` into `download_and_apply` closes the structural gap. Alternative: make the CLI wrapper the only way to reach `download_and_apply` by making the core function pub(crate) and adding a `csq_core::update::install()` public entrypoint that includes the check. Which pattern is more aligned with how csq-core is consumed by csq-cli and csq-desktop in the future?
2. **M2 — capability narrowing vs release urgency.** Narrowing `opener:default` requires touching capability JSON and verifying no frontend code regresses on explicit URL permissions. Worth doing before 2.0.0, or is the schedule tight enough to accept the "trusted-renderer" assumption in release notes and narrow in 2.0.1?
3. **L7 — base_dir canonicalization sweep.** The `swap_session` guard exists but wasn't propagated to `swap_account`, `rename_account`, `remove_account`, etc. Was this deliberate (base_dir for those was considered fixed-by-daemon-handshake) or an oversight? If deliberate, is it documented anywhere a future contributor would read?
