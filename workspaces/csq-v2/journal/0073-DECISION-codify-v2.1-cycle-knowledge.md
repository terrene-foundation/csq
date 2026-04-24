---
type: DECISION
date: 2026-04-24
created_at: 2026-04-24T04:10:00Z
author: co-authored
session_id: 2026-04-24-codify-v2.1
session_turn: 32
project: csq-v2
topic: Codify the v2.1 cycle's institutional knowledge into existing skills. Two skills updated (`daemon-architecture`, `provider-integration`) covering the four major architectural shifts that shipped in PR-C00 → PR-C9b plus issues #184/#185: (1) the daemon's startup reconciler now exists and runs four passes including a new `pass4` migration pattern; (2) Codex is a first-class second surface with its own auth flow, canonical layout, in-flight repoint path, usage poller, and Node transport; (3) `repoint_handle_dir_codex`'s credential-before-marker ordering is the canonical example of the "rewrite credential before identifier" invariant the M-CDX-1 finding established; (4) on-disk artifact migrations have a reusable shape (`pass4_strip_legacy_api_key_helper` is the template) — idempotent, mtime-preserving, atomic + secure_file + §5a tmp cleanup, structured-log per rewrite, retire after telemetry window. No new agents created (the existing 14 cover the v2.1 work). No L5 evolved skills or instincts to integrate (`.claude/learning/evolved/skills/` and `.claude/learning/instincts/personal/` are both empty). cc-artifacts compliance: both updated skills stay well under the 200-line skim threshold (daemon-architecture 167 lines, provider-integration 258 lines).
phase: codify
tags:
  [
    codify,
    v2.1,
    daemon-architecture,
    provider-integration,
    codex,
    startup-reconciler,
    migration-pattern,
  ]
---

# Decision — codify v2.1 cycle knowledge

## Context

The v2.1 cycle shipped 8 PRs across 2 sessions (PR-C9a/b/c convergence, version bump, two issue fixes, v2.1.1 release):

| PR    | Scope                                                              |
| ----- | ------------------------------------------------------------------ |
| #180  | PR-C9a round-1 redteam — 14 fixes + M10 same-surface Codex repoint |
| #181  | PR-C9b round-2 — M-CDX-1 + L-CDX-1 + L-CDX-3 + M8 ship-as-is       |
| #182  | PR-C9c — v2.1.0 release notes + CHANGELOG                          |
| #183  | chore — workspace version bump to 2.1.0                            |
| #186  | fix(install) — handle-dir statusline migration (#185)              |
| #187  | fix(daemon) — apiKeyHelper migration `pass4` (#184)                |
| #188  | release — v2.1.1 patch with both issue fixes                       |
| (tag) | v2.1.0 + v2.1.1 published with full Mac/Linux/Windows artifacts    |

The Codex surface (PR-C00 → PR-C9c) and the two patch fixes need to compound into the institutional skill set so the next session inherits the architectural decisions, not just the code.

## Decision

Two skill updates landed:

### 1. `daemon-architecture` SKILL.md (167 lines)

- **Subsystem table** gains the startup reconciler (runs once, before anything) and explicitly distinguishes the Anthropic poller from the Codex poller (`usage_poller/codex.rs`, parses `wham/usage` per journal 0010).
- **New section: Startup Reconciler (PR-C4 + later)** documents all four passes with a table:
  - `pass1_codex_credential_mode` (INV-P08, 0o600 → 0o400 with mutex)
  - `pass2_codex_config_toml` (INV-P03, `cli_auth_credentials_store="file"` repair)
  - `pass3_quota_v1_to_v2` (idempotent schema migration)
  - `pass4_strip_legacy_api_key_helper` (issue #184, the new migration pattern)
- **Migration-pattern shape** is documented as the canonical home for future on-disk artifact migrations: idempotent, mtime-preserving on no-op, atomic via `unique_tmp_path` + `secure_file` (clamps perms) + `atomic_replace`, per-failure-branch tmp cleanup per `security.md` §5a, structured-log with `error_kind = "migrate_*"`, retire after 3-month telemetry window. Future `passN` migrations follow this shape.

### 2. `provider-integration` SKILL.md (258 lines)

- **Header** updated from "csq v2.0" to "csq v2.1"; description expanded to include Codex.
- **New section: Codex Surface (v2.1, journals 0001-0010, 0023)** covers:
  - `Surface::ClaudeCode` / `Surface::Codex` enum dispatch as the input to every routing decision (auto_rotate, swap, refresher, usage_poller).
  - v2.1 auto-rotate is **ClaudeCode-only by design** — `find_target` short-circuits on non-ClaudeCode current account.
  - Codex device-auth flow vs Anthropic paste-code; subprocess hardening (PR-C9a: bounded BufReader, sync_channel, wait-before-join, cancel command, re-entrancy guard).
  - Canonical credential layout table: `credentials/codex-N.json` (0o400), `config-N/config.toml` (0o600), `codex-sessions/`, `codex-history.jsonl`, plus `term-<pid>/` symlinks. Notes the `auth.json` canonical-direct asymmetry and its M-CDX-1 ordering implication.
  - Same-surface Codex swap is in-flight via `repoint_handle_dir_codex` (M10, journal 0023). Pre-PR-C9a behavior dropped the user's conversation; the dispatcher routing matrix is unit-tested via the extracted `route(src, tgt) -> RouteKind` helper (L-CDX-3).
  - Usage polling: `wham/usage` (NOT `/api/oauth/usage`) per journal 0010 schema. Two-window rate-limit, `used_percent` is 0–100, top-level PII requires redaction. Raw-body capture for forensic drift detection. Circuit breaker.
  - Node.js subprocess transport (journal 0007) reuse for Codex endpoints.
  - Cross-surface swap path (`cross_surface_exec`) and Windows `#[cfg(unix)]` limitation.

## What was NOT codified

- **No new agents.** The existing 14 cover the v2.1 work without gaps. `rust-desktop-specialist`, `tauri-platform-specialist`, `security-reviewer`, and `deep-analyst` all engaged during PR-C9a/b without anyone needing a Codex-specific specialist.
- **No new skills.** The two updated skills absorb everything; a separate `codex-integration` skill would duplicate cross-references and force future readers to chase between provider-integration and codex-integration for related material.
- **No L5 evolved-skill integration.** `.claude/learning/evolved/skills/` and `.claude/learning/instincts/personal/` are both empty — the L5 system has no observations crystallized into instincts yet for this project. The `observations.jsonl` is populated but no `/checkpoint` or `/learn` has been run to evolve them.
- **No agent description updates.** None of the existing 14 agent descriptions were drifted by the v2.1 work; the agent rosters describe roles that are scope-stable across the surface-dispatch transition.
- **No journal-citation rule update for `terrene/.claude/rules/journal.md`.** Per `cross-repo.md` MUST Rule 3, csq does not modify parent-repo files. The recommendation from journal 0024 §FD #2 (combine #3 of journal 0022 + #3 of journal 0023 into a single new SHOULD rule) is parked for the next root-level session.

## Quality gates

cc-artifacts compliance audit:

- **Skill descriptions under 120 chars.** `daemon-architecture` h1 (Daemon Architecture — csq v2.1) and `provider-integration` h1 (Provider Integration — csq v2.1) both ~30 chars; description lines under each are 1 sentence (~120 chars each).
- **No agents over 400 lines.** Agent files unchanged this cycle; existing roster within budget.
- **No commands over 150 lines.** No commands modified.
- **Skills follow progressive disclosure.** Both updated skills' SKILL.md is the entry point; existing sub-files (none in either) untouched. Quick-reference tables (`Subsystem Overview`, `Startup Reconciler`, `Canonical credential layout`) front the deep prose.
- **No CLAUDE.md duplication.** Updates cite specs/journals rather than restating CLAUDE.md.
- **Path-scoped rules.** No rule files modified this cycle; rule-authoring requirements not invoked.

## Alternatives considered

**A. Create a new `codex-integration` skill rather than expanding `provider-integration`.** Rejected — the surface dispatch is the unifying concept; splitting it forces future readers to chase cross-references between the two skills for shared material (settings file structure, polling strategy, quota storage, token redaction). The single-skill model with a Codex section anchored on the surface enum keeps the Anthropic ↔ Codex symmetry visible.

**B. Create a new `migration-patterns` skill capturing the `pass4` shape as a reusable template.** Rejected at N=1 — the pattern is documented in-line in the daemon-architecture skill where it lives. Re-evaluate when a third migration lands; at N=3 the abstraction has structural justification (same heuristic as journal 0024 §FD #1's RepointStrategy decision).

**C. Update the existing `redteam` skill / process docs with the 3-then-1 cadence proven on Codex.** Rejected as scope creep — the cadence is already in user memory (`feedback_redteam_efficiency`); promoting it to a skill rule forces all future redteam invocations to match the cadence even when 1-then-1 or 3-then-3 might be the right choice. Memory captures preference; skill captures invariant.

## Consequences

- The next agent walking into a Codex bug has the canonical credential layout + symlink asymmetry + ordering invariant in `provider-integration` SKILL.md without needing to read journals 0001-0024.
- The next agent landing a new on-disk artifact migration has `pass4_strip_legacy_api_key_helper` as a working template plus the documented "idempotent + mtime-preserving + §5a-cleanup + structured-log + 3-month-retirement" shape in `daemon-architecture` SKILL.md.
- The startup reconciler is now visible as a daemon subsystem — prior sessions had to read `daemon/mod.rs` to discover it.
- v2.1 release docs (`docs/releases/v2.1.0.md`, `docs/releases/v2.1.1.md`) and the journal trail (`workspaces/codex/journal/0001-0025` + `workspaces/csq-v2/journal/0072-0073`) remain the deep-dive references; the skills are the navigable index.

## R-state of v2.1 codification

| Knowledge slice                            | Where it lives now                                                           | Future-session retrieval cost |
| ------------------------------------------ | ---------------------------------------------------------------------------- | ----------------------------- |
| Surface dispatch architecture              | `provider-integration` SKILL.md                                              | Single skill load             |
| Codex auth flow (device-auth)              | `provider-integration` SKILL.md                                              | Single skill load             |
| Codex canonical layout + symlink asymmetry | `provider-integration` SKILL.md                                              | Single skill load             |
| `wham/usage` schema + transport            | `provider-integration` SKILL.md (with journal 0010 cite)                     | Single skill load             |
| Same-surface Codex repoint (M10)           | `provider-integration` SKILL.md (with journal 0023 cite)                     | Single skill load             |
| M-CDX-1 ordering invariant                 | `provider-integration` SKILL.md (with journal 0024 cite)                     | Single skill load             |
| Startup reconciler 4-pass structure        | `daemon-architecture` SKILL.md                                               | Single skill load             |
| On-disk migration pattern                  | `daemon-architecture` SKILL.md (with security.md §5a cite)                   | Single skill load             |
| Auto-rotate ClaudeCode-only invariant      | `daemon-architecture` subsystem table + `provider-integration` Codex section | Either skill                  |

## For Discussion

1. **The codify pass updated two skills with substantial Codex content but did NOT create a `codex-integration` skill. Counterfactual: when surface count grows to N=3 (Gemini, Bedrock, etc.), the surface-dispatch section of `provider-integration` will be the largest section by line count and the asymmetry between surfaces will be hard to scan. Should we plan now for a multi-skill split keyed on `Surface::*` enum variants, or wait for the third surface to force the issue? (Lean: wait. The same N=3 trigger applies as for the `RepointStrategy` trait extraction — at N=2 the inline coverage is faster to read; at N=3 the abstraction has structural justification.)**

2. **The migration-pattern documentation is in `daemon-architecture` but the migration mechanism (`unique_tmp_path` + `secure_file` + `atomic_replace` + §5a cleanup) is also documented in `security.md` §5a, in `csq-core/src/providers/settings.rs::save_settings`, and now in `csq-core/src/daemon/migrate_legacy_api_key_helper.rs::migrate_one`. Three places say similar things. Counterfactual: had we created a single `secure-write-pattern` reference (e.g. a doc-comment-block in `csq-core/src/platform/fs.rs`), the codify pass would have one canonical citation target instead of three. Worth refactoring the docs in the next cycle? (Lean: yes — small effort, high payoff. Move the canonical pattern doc into `csq-core/src/platform/fs.rs` next to the helpers themselves; have the three users cite it.)**

3. **L5 (`.claude/learning/`) is empty for csq — no observations have crystallized into instincts. Counterfactual: had observations been actively ingested via `/checkpoint` and `/learn` over the v2.1 cycle, the codify pass would have had additional inputs (e.g. instincts captured from the redteam fixes' patterns). Should we run `/checkpoint` after each session-cycle (PR-C9a, PR-C9b, etc.) to feed L5 systematically, or is the manual-codify-via-skill model sufficient? (Lean: the manual model is sufficient for now — L5 instincts are most valuable when they capture cross-cycle patterns the human author wouldn't articulate explicitly. With only one author and one session-pair worth of work, the journal + skill loop is doing what L5 would do automatically. Re-evaluate at a higher author count or longer session cadence.)**

## Cross-references

- `.claude/skills/daemon-architecture/SKILL.md` — startup reconciler section + migration-pattern shape.
- `.claude/skills/provider-integration/SKILL.md` — Codex surface section.
- `workspaces/codex/journal/0001-0025` — the v2.1 Codex cycle journal trail.
- `workspaces/csq-v2/journal/0072` — apiKeyHelper migration decision (the `pass4` template).
- `docs/releases/v2.1.0.md`, `docs/releases/v2.1.1.md` — public release narratives.
- `.claude/rules/cc-artifacts.md` — compliance audit anchor for this codify pass.
- `.claude/rules/security.md` §5a — partial-failure tmp cleanup pattern referenced from both skills.
- `.claude/learning/` — empty as of this codify pass; L5 integration deferred.
