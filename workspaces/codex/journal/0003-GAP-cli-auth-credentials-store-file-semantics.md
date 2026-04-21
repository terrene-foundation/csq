---
type: GAP
date: 2026-04-21
created_at: 2026-04-21T00:00:00Z
author: agent
session_id: 2026-04-21-codex-analyze
session_turn: 17
project: codex
topic: Load-bearing unknown — does cli_auth_credentials_store = "file" disable codex in-process refresh?
phase: analyze
tags: [blocker, verification, oauth, codex, open-c01]
---

# Gap — `cli_auth_credentials_store = "file"` semantics for in-process refresh

## The gap

Spec 07 INV-P01 (daemon is sole refresher for Codex) and INV-P02 (daemon is a hard prerequisite for Codex slots) both depend on a specific property of the openai/codex CLI: that setting `cli_auth_credentials_store = "file"` in `$CODEX_HOME/config.toml` causes codex to NOT attempt in-process refresh of its access token. If codex still refreshes in-process — just storing the refreshed token in `auth.json` instead of in the OS keychain — then two concurrent codex processes on the same machine will still race on the refresh endpoint, reproducing openai/codex#10332.

This is spec 07 §7.7.1 OPEN-C01, classified as Blocker for PR1.

## Why we don't know

Current evidence:

- openai/codex documentation describes `cli_auth_credentials_store` as "where tokens are stored" with values `file | keyring | auto`. This is a storage-location flag, not explicitly a behavior flag.
- openai/codex#10332 describes the refresh race and OpenAI's own guidance ("one `auth.json` per runner") but does NOT state whether the `file` mode disables in-process refresh.
- raine/claude-codex-proxy (a third-party adapter) maintains its own copy of ChatGPT OAuth creds and does its own refresh — implying that codex's refresh behavior is NOT something the proxy is depending on.
- No direct source read of openai/codex `codex-rs/login/src/auth/*` has been performed in this session.

## Consequences if the assumption is wrong

INV-P01/P02 as written do not hold. The daemon-sole-refresher discipline collapses at the point where two csq-managed terminals on the same Codex account both run `codex` concurrently — each codex process would, 30 minutes before expiry, independently hit the refresh endpoint, and one would lose.

Spec 07 would need one of the following alternative mechanisms:

1. **A codex-side flag that disables in-process refresh.** If exists, csq pre-seeds it in config.toml alongside `cli_auth_credentials_store`.
2. **A minimum-codex-version precondition.** csq probes `codex --version` on first spawn and refuses below a version that is known to respect file-mode as a behavior contract. Requires upstream coordination.
3. **An upstream patch.** The Foundation files a PR to openai/codex that adds a `CODEX_DISABLE_SELF_REFRESH=1` env var or equivalent. Long lead time.
4. **A tighter refresh window.** Daemon refreshes so aggressively (e.g., 4h before expiry) that codex's in-process threshold (e.g., 30m before) never fires. Fragile; depends on codex not shortening its threshold in future releases.

Option 1 is cheapest; option 2 is most defensive; option 3 is most robust. csq cannot proceed without picking one.

## Resolution method

1. `git clone https://github.com/openai/codex` and read `codex-rs/login/src/auth/storage.rs` + `codex-rs/login/src/auth/refresh.rs` (paths inferred from the earlier research agent's citations).
2. Search for any conditional that gates in-process refresh on storage mode.
3. If ambiguous, construct the minimal repro: two codex processes, same `CODEX_HOME`, wait for one to refresh, observe the second.
4. Update spec 07 §7.7.1 OPEN-C01 with the resolution (either confirm INV-P01 as-is, or add the alternative mechanism).

## Timing

BEFORE PR1 lands. PR1 is the surface refactor; it codifies INV-P01/P02 in code structure. Shipping PR1 without OPEN-C01 resolved risks locking in an invariant that the implementation cannot actually maintain.

Estimated effort: 1–2 hours of direct source reading + 30 min of empirical validation if needed. One autonomous session.

## For Discussion

1. If the source read is inconclusive (codex's refresh behavior is behavior-coupled to network conditions or retry logic not directly visible in the storage layer), what's an acceptable lower bar — empirical validation on a test subscription, or requiring a codex-maintainer confirmation via GitHub issue? The empirical test risks burning a refresh token for no useful data; the issue route is slow.
2. If the answer is "codex refreshes regardless of storage mode," the fourth mitigation ("tighter refresh window") is fragile but immediate. What's the window that's actually safe given codex's default 30-min-before-expiry threshold — 1h, 2h, more? Consider clock skew and daemon restart windows.
3. Does this same class of verification apply to Gemini? Gemini-with-API-key has no refresh, so INV-P01 doesn't apply. But if we ever reconsider the Gemini ToS position (currently: OAuth rerouting is banned, so we don't use it), the same question would surface. Is there value in documenting a generalized "verify-surface-auth-semantics-before-INV-P01-extends-to-it" checklist?

## References

- spec 07 §7.7.1 OPEN-C01
- spec 07 INV-P01, INV-P02
- workspaces/codex/01-analysis/01-research/03-architecture-decision-records.md ADR-C15 (Open)
- workspaces/codex/01-analysis/01-research/04-risk-analysis.md §4 G1, §2 R2
- openai/codex#10332
- raine/claude-codex-proxy (counterexample: its own refresh logic)
