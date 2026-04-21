---
type: DECISION
date: 2026-04-21
created_at: 2026-04-21T00:00:00Z
author: co-authored
session_id: 2026-04-21-codex-analyze
session_turn: 17
project: codex
topic: Provider surface dispatch architecture for Codex native-CLI integration
phase: analyze
tags: [architecture, surface, codex, spec-07, daemon, refresher]
---

# Decision — Provider surface dispatch architecture for Codex

## Context

csq today launches only the `claude` CLI. Third-party providers (MiniMax, Z.AI, Ollama) are bolted onto that single-binary model by pointing `claude` at alternative `ANTHROPIC_BASE_URL`s. Adding Codex (OpenAI ChatGPT subscription) cannot follow that pattern — Codex has its own native CLI (`codex`) with its own on-disk contract (`CODEX_HOME`) and a fundamentally different OAuth refresh model with a single-use refresh token that races across concurrent processes (openai/codex#10332, #15502).

Three candidate architectures were evaluated:

1. **Translation proxy (embedded):** bundle a local Anthropic-API-to-OpenAI-Responses proxy (raine/claude-codex-proxy or similar) and continue running `claude` against it. Loses prompt caching, extended thinking, tool-result images, and GPT-5-Codex harness fit. Maintenance burden of a translation layer csq does not own.
2. **Separate binary with copy-paste integration:** fork the existing csq code paths, produce a parallel "csq-codex" code base. Doubles maintenance and drifts.
3. **Surface abstraction in csq-core:** introduce a `Surface` enum (`ClaudeCode | Codex | Gemini`) on the existing `Provider` struct; parameterize spawn command, home env var, handle-dir layout, login flow, quota dispatch, and model-config target. Refactor existing providers as `Surface::ClaudeCode`. Codex and Gemini become first-class additions of the same abstraction.

## Decision

Choose option 3: surface abstraction in csq-core, formalized as new spec 07 "Provider Surface Dispatch" (specs/07-provider-surface-dispatch.md). Codex is the first surface implementation; Gemini is the second and shares the abstraction.

The shape:

- `Surface` enum added to `Provider`.
- Per-surface dispatch tables for `spawn_command`, `home_env_var`, `home_subdir`, `model_config`, `quota_kind`.
- Handle-dir layout is surface-parameterized (spec 07 §7.2).
- Login, refresh, quota polling, model-config writes, and token redaction all dispatch by surface.
- Cross-surface `csq swap` warns about transcript loss and `exec`s the new binary in place (INV-P05 + INV-P10).
- Refreshable surfaces require the daemon (INV-P02); API-key-only surfaces (MM, Z.AI, Gemini) do not.
- Codex-specific hardening: daemon-sole-refresher per-account mutex (INV-P01), config.toml pre-seed BEFORE codex login (INV-P03), 0400/0600 mode-flip coordinated by mutex (INV-P08), per-account mutex lifecycle (INV-P09).

## Alternatives considered

- **Translation proxy** rejected because it's a feature-parity loss for Codex users and an indirection csq would have to maintain. See workspaces/codex/01-analysis/01-research/03-architecture-decision-records.md ADR-C01.
- **Separate binary** rejected because it fragments the UX and doubles the maintenance surface for no offsetting benefit.
- **"All-of-the-above"** (proxy for some users, native for others) considered briefly; rejected because it confuses the user about what they're running and bloats the spec matrix.

## Consequences

- Adds spec 07. Amends spec 02 (cross-reference only — base invariants unchanged for the ClaudeCode case).
- PR1 (surface refactor) is behavior-neutral for existing users but touches ~10 files across catalog, discovery, refresher, usage poller, handle-dir, and swap — **highest regression risk** in the PR sequence per the deep-analyst complexity scoring.
- Unlocks Gemini as PR-N additive work.
- Introduces one load-bearing precondition (OPEN-C01): does `cli_auth_credentials_store = "file"` disable codex's in-process refresh? If not, INV-P01 needs a different mechanism.
- `quota.json` gains a `schema_version: 2` with surface + kind tagging; one-shot migration on daemon startup.
- Spec 02 INV-02 is amended via spec 07 INV-P04 for per-surface persistence carve-outs (Codex sessions survive handle-dir sweep via symlink into `config-<N>/codex-sessions/`).
- Users get the native codex CLI experience with csq's multi-account rotation — no feature-parity claim to Claude Code.

## For Discussion

1. If `cli_auth_credentials_store = "file"` turns out to NOT disable codex's in-process refresh, which alternative mechanism best preserves INV-P01 — (a) a codex upstream env var if one exists, (b) a minimum-codex-version precondition that exits early on problematic versions, or (c) an upstream patch coordinated through openai/codex? The risk analysis flags this as ADR-C15 Open; the first option is cheapest, the last is most robust.
2. Compare the surface abstraction's 80/15/5 product-focus split (06-product-positioning.md §6) to what csq-v2 originally assumed. The original was "one binary (claude), many providers (catalog)"; the new model is "many surfaces, each with a binary and its catalog subset". Is the 15% per-surface code genuinely parameterization, or is it accumulating toward a fork once a fourth surface lands?
3. If the daemon-hard-prerequisite rule (INV-P02) turns out to harm onboarding (users expecting `csq run` to just work), what's the cheapest retreat — auto-start the daemon silently, or add a one-click "start daemon" banner in the desktop app and keep `csq run` failing closed?

## References

- specs/07-provider-surface-dispatch.md
- workspaces/codex/briefs/01-vision.md
- workspaces/codex/01-analysis/01-research/03-architecture-decision-records.md (ADR-C01 through ADR-C15)
- workspaces/codex/01-analysis/01-research/04-risk-analysis.md (complexity scoring, G-series gaps)
- openai/codex#10332 (refresh-token single-use race), #15502 (copy breaks refresh)
