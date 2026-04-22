---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T19:10:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c3
session_turn: 40
project: codex
topic: PR-C3 decomposed into C3a (data-layer primitives — discover_codex + create_handle_dir_codex + AccountSource::Codex) / C3b (csq login --provider codex + device-auth + keychain residue) / C3c (csq run launch_codex + env allowlist) so each PR carries one reviewable concern
phase: implement
tags: [codex, pr-c3, decomposition, discovery, handle-dir]
---

# Decision — Split PR-C3 into C3a (discovery + handle-dir), C3b (login flow), C3c (launch)

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` §PR-C3 lists the full codex login orchestration:

- `csq-core/src/providers/codex/{mod,surface,login,keychain}.rs` — new module
- `csq-cli/src/commands/login.rs` — dispatch on `--provider codex` → device-auth per §7.3.3
- `csq-cli/src/commands/setkey.rs` — hard-refuse Codex (FR-CLI-05)
- `csq-cli/src/commands/run.rs` — `launch_codex()`: verify daemon, verify config.toml, create handle dir, env_clear() + allowlist, exec codex
- `csq-core/src/session/handle_dir.rs` — Codex symlink set per §7.2.2

Plus three items deferred from PR-C1 per journal 0011:

- `discover_codex()` — reads `credentials/codex-<N>.json`
- `create_handle_dir_codex()` — Codex-specific symlink layout
- Refresher source-based filter — union of `discover_anthropic` and `discover_codex`

Shipping all eight items in one PR is a repeat of the PR-C2 anti-pattern that journal 0012 split: a reviewer opening a diff that mixes (a) data-layer primitives, (b) OAuth device-auth flow, and (c) process exec + env handling cannot focus on any single concern without also auditing the others.

## Decision

Ship PR-C3 in three atomic PRs, each carrying one reviewable concern. Downstream PRs depend only on primitives that the upstream PR landed; no flag-off gating is required.

- **PR-C3a** — **data-layer primitives** (this PR):
  - `discover_codex()` in `accounts/discovery.rs` — reads `credentials/codex-<N>.json` files and yields `AccountInfo` with `source: Codex` and `surface: Codex`.
  - `create_handle_dir_codex()` in `session/handle_dir.rs` — creates `term-<pid>` with the Codex symlink set per spec 07 §7.2.2: `.csq-account`, `auth.json`, `config.toml`, `sessions`, `history.jsonl`, plus an ephemeral `log/` dir and `.live-pid`. No `settings.json` / `.claude.json` materialization — Codex does not consume those.
  - `AccountSource::Codex` variant added to the `AccountSource` enum.
  - Tests.
- **PR-C3b** — **`csq login --provider codex` + device-auth + keychain residue probe**:
  - New `csq-core/src/providers/codex/{mod,surface,login,keychain}.rs` module.
  - `csq login N --provider codex` dispatches to device-auth per spec 07 §7.3.3 via the PR-C0.5 Node bridge.
  - `csq setkey N --provider codex` hard-refuses (FR-CLI-05).
  - Keychain residue probe on decline: refuses to proceed if `codex-cli`'s own keychain entry is dirty.
  - Consumes PR-C3a's `discover_codex` to surface new Codex accounts after login succeeds.
- **PR-C3c** — **`csq run` launch flow**:
  - `launch_codex()` in `csq-cli/src/commands/run.rs`: verifies daemon is running, verifies `config.toml` exists, invokes `create_handle_dir_codex` (from PR-C3a), sets `CODEX_HOME`, `env_clear()` + allowlist, exec codex.
  - Integration tests for write-order (config.toml before `codex login` is ever invoked), daemon-down → exit 2, sweep preserves codex-sessions.
  - Refresher source-based filter lands here too: `discover_codex` is chained into `daemon::refresher::tick` alongside `discover_anthropic`. Deferred from PR-C1 per journal 0011 item 1; natural home is PR-C4 but landing it in C3c with broker_check's Anthropic-only dispatch untouched is also fine (Codex accounts iterate but are skipped by the current filter until PR-C4 wires `broker_check_codex`).

## Alternatives considered

**A. Ship PR-C3 as one PR.** Matches the plan literally. Rejected — same anti-pattern as PR-C2 monolithic, and this PR would be ~1500+ LOC across four concerns (discovery, handle-dir, login-flow, exec-flow). Reviewer attention collapses.

**B. Ship PR-C3a + PR-C3bc (combine login + launch).** Tighter scope than A but still mixes device-auth (high-rigor OAuth flow) with process exec (high-rigor subprocess handling). Rejected — each deserves its own reviewable diff.

**C. Ship PR-C3c before PR-C3b.** Would require stubbing the provider module. Rejected — the launch flow's handle dir is Codex-specific already (PR-C3a ships it); its primary dependency is "a Codex slot exists", which PR-C3b provides.

## Consequences

- PR-C3a ships narrow — discovery + handle-dir + enum variant + tests. Est. ~400 LOC Rust, ~100 LOC tests.
- PR-C3b owns device-auth: highest rigor PR in the Codex chain after OAuth primitives (PR-C0.5). Keychain residue probe lives there because it's a pre-login check.
- PR-C3c owns process exec + env handling: `env_clear()` + explicit allowlist matter for security posture (no leaked Anthropic env into Codex).
- Total Codex-chain PR count grows: C00 → C0 → C0.5 → C1 → C2a → C2b → C3a → C3b → C3c → C4 → ... — 10+ PRs for v2.1 Codex. That's expected; rigor per PR > fewer PRs.
- Journal 0012 established the pattern for PR-C2; journal 0013 extends it. If future `/codify` passes see three decomposition journals in a row (0011, 0012, 0013), that's evidence the pattern deserves to be in `.claude/rules/` or similar.

## For Discussion

1. **PR-C3a carries the three items deferred from PR-C1 (journal 0011) — does landing `discover_codex` before its refresher-consumer (PR-C4) count as "primitive without consumer" dead code, or the same structural-spine-first discipline that PR-C1, C2a, and C2b all validated?** (Lean: structural spine. `discover_codex` has an immediate consumer in PR-C3b — surfacing the new Codex account post-login requires this function. PR-C4's refresher integration is secondary.)

2. **The plan lists FOUR files under PR-C3 (`providers/codex/{mod,surface,login,keychain}.rs`) as a new module. This decomposition doesn't touch those in PR-C3a — the module's entire contents are PR-C3b's scope. Is deferring an entire module to a downstream PR a reasonable interpretation of the plan, or does the plan imply that even empty module scaffolding should land first?** (Lean: defer entirely. An empty module stub adds zero primitive value; PR-C3b lands the whole module at once.)

3. **Journal 0011 said the refresher source-based filter is part of PR-C3 (item 1). The decomposition puts it in PR-C3c or PR-C4, not C3a. If the refresher integration hit a blocker (Codex broker_check design surprise) in PR-C4, could PR-C3a/b/c still ship independently — i.e. are they actually decoupled, or is there a hidden coupling via the refresher?** (Lean: decoupled. PR-C3a's `discover_codex` is pure data; PR-C3b's login writes a valid Codex credential file; PR-C3c's launch spawns `codex` with the right env. None requires the refresher to be Codex-aware; the daemon is a hard prerequisite for spawn (INV-P02) but its refresher can keep operating on Anthropic-only for weeks while C3a/b/c land.)

## Cross-references

- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C3 (the plan being decomposed)
- `workspaces/codex/journal/0011-DECISION-pr-c1-scope-deferrals.md` (three items deferred from PR-C1, distributed across C3a/b and C4)
- `workspaces/codex/journal/0012-DECISION-pr-c2-decomposition-mutex-first.md` (precedent for data-layer vs consumer-layer split)
- `specs/07-provider-surface-dispatch.md` §7.2.2 (Codex handle-dir layout), §7.3 (device-auth flow — PR-C3b), §7.5 INV-P02 (daemon prerequisite for Codex spawn — PR-C3c)
