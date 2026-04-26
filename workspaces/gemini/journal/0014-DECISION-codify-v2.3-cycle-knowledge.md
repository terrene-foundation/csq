---
type: DECISION
date: 2026-04-26
created_at: 2026-04-26T13:30:00Z
author: agent
session_id: 2026-04-26-codify-v2.3
session_turn: 60
project: gemini
topic: Codify the v2.3 cycle's institutional knowledge into existing skills. Two skills updated (`daemon-architecture` v2.1 → v2.3, `provider-integration` v2.1 → v2.3) covering the four major architectural shifts that shipped in PR-G2a → PR-G5 plus v2.3.1's D7 fix and the test_env hardening: (1) the Gemini surface is API-key-only with a 7-layer ToS guard pinned to gemini-cli 0.38.x; (2) Gemini quota is event-driven via NDJSON event log (not polled), inverting v2.1's INV-P02 daemon-required-for-spawn for Gemini specifically; (3) `platform::secret` is the new encryption-at-rest primitive with five backends; (4) the daemon gains a Gemini event consumer subsystem that drains CLI-written NDJSON. Plus a new `testing.md` rule §6 codifying `test_env::lock()` requirement after PR #205+#206 audit. No new agents created (existing 14 cover the v2.3 work). No L5 evolved skills or instincts to integrate. cc-artifacts compliance: daemon-architecture 186 lines, provider-integration 335 lines (over the 200-line "well under" target the v2.1 codify pass used; flagged for §FD discussion below).
phase: codify
tags:
  [
    codify,
    v2.3,
    daemon-architecture,
    provider-integration,
    gemini,
    platform-secret,
    ndjson-event-log,
    tos-guard,
    test-env-lock,
  ]
---

# Decision — codify v2.3 cycle knowledge

## Context

The v2.3 cycle shipped 11 PRs across multiple sessions:

| PR   | Scope                                                               |
| ---- | ------------------------------------------------------------------- |
| #192 | PR-G2a — `platform::secret` + `providers::gemini` scaffolding       |
| #193 | PR-G2a.2 — Linux Secret Service + AES-GCM file fallback             |
| #194 | PR-G2a.3 — Windows DPAPI + Credential Manager                       |
| #195 | PR-G1 — `Surface::Gemini` variant + dispatch wiring                 |
| #196 | PR-G2b — flip `platform::secret` literals to `Surface::Gemini`      |
| #197 | PR-G3 — NDJSON event log + daemon consumer + live IPC route         |
| #198 | PR-G4a — `setkey gemini` + `spawn_gemini` end-to-end + run dispatch |
| #199 | PR-G4b — models switch + cross-surface swap + 4 catalog entries     |
| #200 | PR-G5 — desktop UI                                                  |
| #201 | release v2.3.0                                                      |
| #202 | csq-cli orchestration cleanup (collapse to csq-core helpers)        |
| #203 | D7 — vault-delete on desktop unbind                                 |
| #204 | release v2.3.1                                                      |
| #205 | fix Linux detect XDG_RUNTIME_DIR flake (mutex order)                |
| #206 | test_env audit + workspace-wide hardening                           |

The Gemini surface (PR-G0 through PR-G5), v2.3.1 patches, and the test_env hardening need to compound into the institutional skill set so the next session inherits the architectural decisions, not just the code.

## Decision

Two skill updates landed:

### 1. `daemon-architecture` SKILL.md (186 lines, was 167)

- **Subsystem table** gains the **Gemini event consumer** (`daemon/usage_poller/gemini.rs`, "per tick", drains the CLI-written NDJSON event log into `quota.json`). Auto-rotator row updated to "ClaudeCode-only (INV-P11); refuses Codex/Gemini dirs".
- **New section: Gemini NDJSON Event Log Consumer (PR-G3, v2.3)** documents the event-driven (not polled) model, the durability floor contract from spec 07 §7.2.3.1 (50 ms non-blocking connect ceiling, drop-on-unavailable, NDJSON-as-disk-fallback, 0o600, ASCII-only single-JSON-per-line, slot-in-filename, `.corrupt.<unix_ms>` rotation on parse failure), and the **INV-P02 inversion** (Codex requires the daemon for `csq run`; Gemini does not, because quota is event-driven).
- **Header bumped** csq v2.1 → csq v2.3.

### 2. `provider-integration` SKILL.md (335 lines, was 258)

- **Header bumped** csq v2.1 → csq v2.3; description expanded to include Gemini.
- **New section: Gemini Surface (v2.3, journals 0001-0013)** covers:
  - The two key inversions vs. Codex: API-key only (no OAuth, ADR-G09) + no daemon required for `csq run` (INV-P02 inverted).
  - Auth: stdin-only API-key paste OR Vertex SA JSON path. `AIza` prefix guard at the CLI boundary; redactor learns `AIza*` in v2.3.
  - csq-core orchestration helpers (`provision_api_key_via_vault`, `set_model_name`, `is_known_gemini_model`, `delete_api_key_from_vault`, `spawn_gemini`) as the single source — csq-cli + csq-desktop call these directly. The desktop "remove account" path calls `delete_api_key_from_vault` BEFORE touching the marker (D7 / v2.3.1 / journal 0013).
  - Canonical layout table: `credentials/gemini-<N>.json` (binding marker, NOT a credential), `accounts/.gemini-tos-acknowledged-<slot>`, `accounts/gemini-events-<N>.ndjson`, `platform::secret` namespace `gemini/<slot>`.
  - **7-layer ToS defense table (EP1–EP7)** with each layer's location + check, plus the whitelist-pinning convention (gemini-cli 0.38.x; bump = updated whitelist OR refusal dialog, never silent fall-through).
  - **`platform::secret` primitive subsection** with the five-backend table (macos / linux / file / windows / in-memory), the `secret-in-memory` dev-deps-only feature flag rationale (rooted in journal 0013 + v2.3.1 fix at `158f28c`), and the drop-vault-on-unbind D7 invariant.
  - Cross-surface swap behaviour (mirrors Codex shape) and the static 4-entry model catalog rationale (no `/models` endpoint).

### 3. `.claude/rules/testing.md` §6 (PR #206, already merged)

The codify pass also retroactively records a rule that PR #206 already landed: tests mutating process env MUST acquire `crate::platform::test_env::lock()`. The rule body has BLOCKED responses + DO/DO NOT examples + Origin pointer to journal 0021 finding 11 + PR #205 + #206. Existing §6 (Component Mount Sequence) renumbered to §7. This rule is workspace-scoped (paths includes `**/*test*.rs`).

## What was NOT codified

- **No new agents.** The existing 14 cover the v2.3 work without gaps. `rust-desktop-specialist`, `tauri-platform-specialist`, `security-reviewer`, and `deep-analyst` all engaged during PR-G2a/G2a.2/G2a.3/G3 without anyone needing a Gemini-specific or platform-secret-specific specialist.
- **No new skills.** The two updated skills absorb everything; a separate `gemini-integration` skill would duplicate cross-references and force future readers to chase between provider-integration and gemini-integration for shared material (settings file structure, polling strategy, quota storage, token redaction). The single-skill model with a Gemini section anchored on the surface enum keeps the Anthropic ↔ Codex ↔ Gemini symmetry visible. (Same reasoning the v2.1 codify pass used; see journal 0073 alternative A.)
- **No `platform-secret` standalone skill.** The five-backend table + audit ledger + drop-vault-on-unbind invariant fit cleanly inside `provider-integration` because every current user of `platform::secret` is a provider surface (Gemini today; future Bedrock / Vertex AI tomorrow). At N=2 surfaces using the primitive, the abstraction has structural justification — re-evaluate then.
- **No new top-level invariants in `daemon-architecture`'s "Key Invariants".** INV-P02 inversion for Gemini is documented in the new "Gemini NDJSON Event Log Consumer" section rather than added as a numbered invariant — the inversion is surface-scoped, not daemon-wide.
- **No L5 evolved-skill integration.** `.claude/learning/evolved/skills/` and `.claude/learning/instincts/personal/` remain empty; same situation as v2.1 codify pass. Re-evaluate at higher author count or longer session cadence.
- **No journal-citation rule update for `terrene/.claude/rules/journal.md`.** Per `cross-repo.md` MUST Rule 3, csq does not modify parent-repo files. The carry-forward from v2.1 codify pass (combine §FD #3 of journal 0022 + §FD #3 of journal 0023 + §FD #2 of this journal) is parked for the next root-level session.

## Quality gates

cc-artifacts compliance audit:

- **Skill descriptions under 120 chars.** `daemon-architecture` h1 (Daemon Architecture — csq v2.3) and `provider-integration` h1 (Provider Integration — csq v2.3) both ~30 chars; description lines under each are 1-2 sentences (~120-180 chars).
- **No agents over 400 lines.** Agent files unchanged this cycle; existing roster within budget.
- **No commands over 150 lines.** No commands modified.
- **Skills follow progressive disclosure.** Both updated skills' SKILL.md is the entry point; existing sub-files (none in either) untouched. Quick-reference tables (`Subsystem Overview`, `7-layer ToS defense`, `platform::secret` backends, canonical layout) front the deep prose.
- **Skill line counts.** daemon-architecture 186 (close to but under v2.1 codify's 200-line "well under" target). provider-integration 335 (OVER the 200-line target — flagged in §FD #1).
- **No CLAUDE.md duplication.** Updates cite specs/journals rather than restating CLAUDE.md.
- **Path-scoped rules.** `.claude/rules/testing.md` has `paths: ["**/tests/**", "**/*test*.rs", "**/*tests.rs", "**/test_*.rs", "**/*spec*.rs"]`. The new §6 inherits this scope — env-mutation enforcement only fires on test files.

## Alternatives considered

**A. Create a new `gemini-integration` skill rather than expanding `provider-integration`.** Rejected — the surface dispatch is the unifying concept; splitting it forces future readers to chase cross-references between the two skills for shared material (settings file structure, polling strategy, quota storage, token redaction). Same alternative the v2.1 codify pass rejected for Codex; same answer for Gemini. The single-skill model with a Gemini section anchored on the `Surface::Gemini` enum keeps the cross-surface symmetry visible.

**B. Create a new `platform-secret` skill capturing the 5-backend pattern + drop-on-unbind invariant.** Rejected at N=1 user (Gemini) — the pattern is documented in-line in the provider-integration skill where it lives. Re-evaluate when a second surface needs `platform::secret` (Bedrock / Vertex AI standalone are the obvious candidates); at N=2 the abstraction has structural justification.

**C. Add a `secure-write-pattern` skill or refactor the doc into `csq-core/src/platform/fs.rs`.** This is a carry-forward from journal 0073 §FD #2 — the canonical secure-write pattern (`unique_tmp_path` + `secure_file` + `atomic_replace` + §5a tmp cleanup) is now documented in three places (`security.md` §5a, `daemon-architecture` migration-pattern shape, `provider-integration` Gemini provisioning). Decision: defer the refactor again. Justification: v2.3 added more callers (vault writes, event-log writes) but did not change the canonical pattern. The drift cost is still bounded by `security.md` §5a being authoritative; re-evaluate when a fourth caller surfaces.

**D. Promote the test_env::lock convention to a fully separate "test-flake-prevention" skill.** Rejected — testing.md §6 already covers it with paths-scoping + DO/DO NOT examples + BLOCKED responses + journal pointer. A skill would duplicate the rule body.

## Consequences

- The next agent walking into a Gemini bug has the canonical layout + 7-layer ToS guard + INV-P02 inversion + drop-on-unbind invariant in `provider-integration` SKILL.md without needing to read journals 0001-0013.
- The next agent landing a new platform-secret backend has the five-backend table + audit pattern + dev-deps-only feature flag rationale in one place. The `secret-in-memory` cargo-feature pattern is the canonical example for "test-only override that doesn't leak into release builds".
- The Gemini event consumer is now visible as a daemon subsystem — prior sessions had to read `daemon/usage_poller/gemini.rs` to discover the event-driven model.
- The next agent writing an env-mutating test sees `test_env::lock()` requirement in the rule layer (testing.md §6) AND the rationale + lock-order in the source layer (`csq-core/src/platform/test_env.rs` doc-comment). The flake we hit on PR #204 is class-level prevented.
- v2.3 release docs (`docs/releases/v2.3.0.md`, `docs/releases/v2.3.1.md`) and the journal trail (`workspaces/gemini/journal/0001-0013` + this entry) remain the deep-dive references; the skills are the navigable index.

## R-state of v2.3 codification

| Knowledge slice                                    | Where it lives now                                                              | Future-session retrieval cost |
| -------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------- |
| Surface dispatch architecture (3 surfaces)         | `provider-integration` SKILL.md                                                 | Single skill load             |
| Gemini API-key-only auth (ADR-G09)                 | `provider-integration` SKILL.md                                                 | Single skill load             |
| 7-layer ToS guard (EP1-EP7) + whitelist pinning    | `provider-integration` SKILL.md                                                 | Single skill load             |
| `platform::secret` 5-backend pattern               | `provider-integration` SKILL.md                                                 | Single skill load             |
| `secret-in-memory` dev-deps-only feature flag      | `provider-integration` SKILL.md (with v2.3.1 + journal 0013 cite)               | Single skill load             |
| Drop-vault-on-unbind invariant (D7)                | `provider-integration` SKILL.md (with journal 0013 cite)                        | Single skill load             |
| Gemini canonical layout (markers, NDJSON, vault)   | `provider-integration` SKILL.md                                                 | Single skill load             |
| Gemini cross-surface swap (mirrors Codex shape)    | `provider-integration` SKILL.md                                                 | Single skill load             |
| Static 4-entry model catalog (no /models endpoint) | `provider-integration` SKILL.md                                                 | Single skill load             |
| NDJSON event log consumer subsystem                | `daemon-architecture` SKILL.md                                                  | Single skill load             |
| Event-delivery contract (spec 07 §7.2.3.1)         | `daemon-architecture` SKILL.md (with spec cite)                                 | Single skill load             |
| INV-P02 inversion for Gemini                       | `daemon-architecture` SKILL.md                                                  | Single skill load             |
| `test_env::lock()` requirement                     | `.claude/rules/testing.md` §6 + `csq-core/src/platform/test_env.rs` doc-comment | Rule + source                 |

## For Discussion

1. **provider-integration SKILL.md is now 335 lines, well past the v2.1 codify pass's "well under 200" line-count comfort target.** Counterfactual: if the file had been split at the v2.1 boundary (one skill per surface — `provider-integration-anthropic`, `provider-integration-codex`, `provider-integration-gemini`), the v2.3 update would have been a clean addition rather than an enlargement of an already-busy file. Should we (a) accept 335 lines because cc-artifacts.md MUST 2 only requires "progressive disclosure", not a fixed line count, and the quick-reference tables front the prose; (b) extract the 7-layer ToS table + the platform::secret 5-backend table into sub-files (`provider-integration/gemini-tos-guard.md`, `provider-integration/platform-secret.md`) the way agent files extract reference material; or (c) split the skill at the surface boundary (one skill per `Surface::*` variant)? **Lean: (a) for now**, with a hard ceiling at 500 lines (twice current). The skill answers routine Qs without sub-file reads — that is the cc-artifacts.md MUST 2 contract. Splitting at N=3 surfaces would force every Anthropic-only debugging session to load a separate skill from every Codex-only debugging session and vice versa, which is the opposite of the v2.1 codify pass's "single skill keeps surface symmetry visible" reasoning. Re-evaluate at N=4 surfaces or when a single surface section grows past ~150 lines on its own.

2. **The canonical secure-write pattern is now documented in four places** (counting the v2.3 vault writes + NDJSON event log writes added since journal 0073 §FD #2): `security.md` §5a, `daemon-architecture` migration-pattern subsection, `provider-integration` Gemini provisioning, and the new `csq-core/src/providers/gemini/capture.rs` + `csq-core/src/platform/secret/file.rs`. Counterfactual: had the journal 0073 §FD #2 refactor (move the canonical pattern doc into `csq-core/src/platform/fs.rs`) landed in the v2.1 → v2.3 interval, the Gemini cycle would have one less drift-prone duplicate. Should we land the refactor now? **Lean: yes — small effort, high payoff.** Bundle it with the next time someone touches `platform::fs` or adds a new caller. Trigger: a fifth caller surfaces (e.g. Bedrock provisioning), or a journal entry catches a drift between any two of the four.

3. **L5 (`.claude/learning/`) is still empty for csq** — same observation as v2.1 codify pass. Counterfactual: had observations been actively ingested via `/checkpoint` and `/learn` over the v2.3 cycle (across the Gemini chain + flake fixes + audit hardening), the codify pass would have inputs the manual codify model can't reach (e.g. instincts captured from the parallel-agent dispatch pattern in PR #202 + #203, or the redact-then-format error-leakage pattern that the test_env audit exposed). Should we run `/checkpoint` after each session-cycle? **Lean: defer again.** Same reasoning as v2.1 §FD #3 — single author, journal+skill loop is doing what L5 would do automatically. Re-evaluate when L5 has at least a few crystallized instincts to test against, OR when the project gains a second active author.

## Cross-references

- `.claude/skills/daemon-architecture/SKILL.md` — Gemini event consumer subsystem + INV-P02 inversion.
- `.claude/skills/provider-integration/SKILL.md` — Gemini surface, 7-layer ToS guard, `platform::secret` primitive.
- `.claude/rules/testing.md` §6 — `test_env::lock()` rule.
- `csq-core/src/platform/test_env.rs` — doc-comment with mutator inventory + lock-order rule.
- `workspaces/gemini/journal/0001-0013` — the v2.3 Gemini cycle journal trail.
- `docs/releases/v2.3.0.md`, `docs/releases/v2.3.1.md` — public release narratives.
- `.claude/rules/cc-artifacts.md` — compliance audit anchor for this codify pass.
- `.claude/rules/security.md` §5a — partial-failure tmp cleanup pattern referenced by `provider-integration` Gemini provisioning + `daemon-architecture` migration-pattern shape.
- `workspaces/csq-v2/journal/0073-DECISION-codify-v2.1-cycle-knowledge.md` — the v2.1 codify pass this entry mirrors structurally.
- `.claude/learning/` — empty as of this codify pass; L5 integration deferred (§FD #3).
