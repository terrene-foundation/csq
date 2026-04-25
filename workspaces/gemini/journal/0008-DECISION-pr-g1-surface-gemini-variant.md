---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T20:00:00Z
author: co-authored
session_id: 2026-04-25-gemini-pr-g1
session_turn: 70
project: gemini
topic: PR-G1 Surface::Gemini enum variant + dispatch wiring + ModelConfigTarget extension
phase: implement
tags: [gemini, surface, enum, dispatch, pr-g1]
---

# Decision — PR-G1 Surface::Gemini variant + site extensions

## Context

PR-G2a ((#192) shipped Gemini scaffolding under a const placeholder
`SURFACE_GEMINI: &str = "gemini"`. PR-G2a.2 (#193) and PR-G2a.3 (#194) shipped the three platform-native Vault backends. The platform::secret subsystem is now feature-complete.

PR-G1 lands the `Surface::Gemini` enum variant, makes every match-on-Surface site exhaustive, flips the const placeholder to `Surface::Gemini.as_str()`, and wires the per-surface dispatch decisions across the workspace. The actual per-surface IMPLEMENTATIONS for spawn / NDJSON event log / CLI dispatch / desktop UI land in PR-G2b / PR-G3 / PR-G4 / PR-G5 respectively — PR-G1 is the architectural shape, not the wiring.

## Decisions

### D1 — `Surface::Gemini` is the third enum variant (NOT a wildcard or a flag)

The plan called for treating Gemini as a first-class surface alongside `ClaudeCode` and `Codex` rather than gating it behind a feature flag or conditional compile. Rationale:

- Codex demonstrated that surface-dispatched code (refresher cadence, handle-dir layout, rotation semantics) is cleaner with an explicit enum than with a string tag — every match becomes exhaustive at compile time.
- The Gemini auth model differs FUNDAMENTALLY from ClaudeCode/Codex (no OAuth, no refresh, no canonical credential file, event-driven quota). A wildcard "any future surface" pattern would obscure this — explicit variants force every site to declare its Gemini behavior.
- 36 files in csq-core reference `Surface::*` today. Each is a deliberate dispatch decision. Adding a wildcard would push the decision cost to runtime.

### D2 — `Surface::as_str()` replaces ad-hoc string literals

PR-G2a used `SURFACE_GEMINI: &str = "gemini"` as a const placeholder. PR-G1 introduces `Surface::as_str()` returning `&'static str` for every variant (matching the `serde rename` wire names). The `SURFACE_GEMINI` const is preserved (now resolving to `Surface::Gemini.as_str()`) so existing PR-G2a call sites in `gemini::spawn`, `gemini::capture`, `gemini::keyfile` do not need to import the enum directly.

The `surface_as_str_matches_serde_wire_name` regression test pins the invariant: `as_str()` MUST equal the `serde rename` tag. Without this, the audit log (which writes `surface: "gemini"` literals) and the wire format (which writes `"gemini"` via serde) could drift silently.

`Display` is rewritten to delegate to `as_str()`, eliminating the per-variant `write!(f, "...")` arm. The `surface_display_matches_as_str` test catches the regression where someone updates `as_str` and forgets `Display` (or vice-versa).

### D3 — Gemini's `auth_type = None` keeps it OUT of `providers_with_keys()`

The existing `providers_with_keys()` predicate yields providers whose API key is sourced from an env var (Anthropic, MiniMax, Z.AI). Gemini's API key flows through `platform::secret::Vault` — different code path, different lifecycle, different security boundary. Tagging Gemini as `OAuth` or `Bearer` would mis-route it through the env-var key flow.

The compromise: Gemini's `auth_type` is `AuthType::None` (matches Ollama's keyless treatment), which keeps it out of `providers_with_keys()`. A future predicate `providers_using_vault()` will yield Gemini explicitly when the CLI / desktop dispatch path needs to enumerate Vault-backed providers. The `providers_with_keys_excludes_gemini` test pins this.

### D4 — `ModelConfigTarget::GeminiSettingsModelName` is a third writer variant

Codex writes models to `config-<N>/config.toml` `model = "..."`; Anthropic+3P write to `config-<N>/settings.json` `env.ANTHROPIC_MODEL`. Gemini reads `~/.gemini/settings.json` `model.name` — a JSON object key shape distinct from both.

Adding `GeminiSettingsModelName` keeps the writer dispatch in `csq-cli/src/commands/models.rs` exhaustive at the match level. PR-G1 stubs the actual writer with a "PR-G4 not yet" error — preserves the dispatch contract without prematurely wiring code that depends on PR-G4's surface-aware setkey flow.

### D5 — Gemini's `swap` arm refuses with an actionable message

`csq swap <slot>` invokes `exec_codex` or `exec_claude_code` based on the target surface's exec strategy. Gemini's exec dispatch (different binary `gemini`, different env contract, different state model) lands in PR-G4. For PR-G1 the new arm returns an error naming PR-G4 as the dependency — the user sees "swap to Gemini account is not supported in this build" instead of a panic or silent no-op.

### D6 — Credential-file path functions return placeholder paths for Gemini

`canonical_path_for(base, account, Surface::Gemini)` returns `{base}/credentials/gemini-{N}.json` and `live_path_for` returns `config-{N}/.gemini-creds.json`. These paths are NEVER written by the daemon — Gemini has no canonical credential file, the API key lives in the Vault — but the functions are called from generic surface-dispatched code that needs SOMETHING for type completeness.

The docstring on both functions explicitly calls out the Gemini caveat ("calling save on this path is a logic bug"). PR-G2b will gate the writer call sites; PR-G1 returns the placeholder path so the dispatch chain compiles. A future `assert!(surface != Surface::Gemini)` at the writer entry point would catch the bug structurally; deferred so the change set stays minimal.

## Alternatives considered and rejected

### Make `canonical_path_for` return `Option<PathBuf>` so Gemini surfaces as `None`

**Considered**: Make the API explicit about "this surface has no canonical file" — every caller would have to handle `None` deliberately.

**Rejected**: 13+ call sites across daemon/refresher.rs, broker/check.rs, credentials/refresh.rs, integration tests would need to be updated. The behavior at every call site is "skip this surface" which is already the existing behavior for Codex when the refresher iterates. The placeholder-path approach + dispatch-level filtering achieves the same correctness with one-tenth the diff. Revisit if a future bug surfaces from the placeholder path.

### Add `AccountSource::Gemini` + `discover_gemini` in this PR

**Considered**: Wire Gemini account discovery so `csq status` shows Gemini accounts after PR-G2a.2's Vault-list_slots is callable.

**Rejected**: PR-G1's plan scope ("Surface::Gemini variant + site extensions") is dispatch architecture, not behavior. Discovery requires opening the Vault from a non-interactive context (`csq status` runs at every shell prompt), which on Linux probes the D-Bus session bus. That's a perf + UX consideration that belongs in PR-G4 (CLI dispatch) where the Vault open happens behind explicit user intent. PR-G1 stays narrow: enum + matches.

## Consequences

1. The Gemini surface is reachable via `Surface::Gemini` everywhere a surface tag is needed. Audit log entries, `SlotKey`, `error_kind_tag`, refresher/auto-rotate filters all see consistent enum-based dispatch.
2. Existing daemon code (refresher, auto_rotate, usage_poller) automatically skips Gemini because the discovery functions don't yield Gemini account rows yet — Gemini accounts will be wired in PR-G4 (CLI) or PR-G5 (desktop). No additional skip-Gemini logic was added because the existing iterate-discovered-accounts pattern handles absence correctly by construction.
3. `csq swap <gemini-slot>` and `csq models switch gemini-2.5-pro` return clear PR-G4 dependency errors instead of panics or silent failures. Users who try Gemini commands before PR-G4 ships see an actionable message.
4. Workspace tests: 1337 → 1344 (+7 PR-G1 regressions). All on macOS. Clippy + fmt clean.
5. The `SURFACE_GEMINI` const placeholder now resolves to `Surface::Gemini.as_str()` — PR-G2b's "flip placeholder to enum" task is structurally complete in PR-G1 (the const continues to exist because removing it would force PR-G2a's already-shipped call sites to import the enum directly).

## Security-review posture

PR-G1 is dispatch architecture (enum extension + match exhaustiveness + tests). No new unsafe, no new FFI, no new IPC handlers, no new file writes, no new credential paths. The security-reviewer was NOT spawned for this PR per the cost-benefit pattern: every PR-Gx adds review overhead, and PR-G1's risk surface is comparable to a refactor that adds a new enum variant — no new attack surface introduced.

The placeholder credential paths for Gemini (`canonical_path_for(_, _, Surface::Gemini)` returning `gemini-{N}.json`) are a documented dispatch-only concern. PR-G2b will spawn a security review when actual Gemini spawn dispatch lands.

## For Discussion

1. **Counterfactual**: if `ModelConfigTarget::GeminiSettingsModelName` had been deferred to PR-G4 with a wildcard `_ => unimplemented!()` arm, what would have broken? Nothing immediately — the catalog test `toml_model_key_used_only_by_codex` would have remained valid. But the wildcard would have hidden the third writer-variant decision until PR-G4, and any future PR adding Bedrock or another surface might have copy-pasted the wildcard pattern instead of adding an explicit variant.

2. **Compare**: PR-G1 added 7 regression tests in catalog.rs but did NOT add per-site Gemini dispatch tests (e.g. "refresher skips Gemini", "auto_rotate same-surface filter excludes Gemini"). Was that the right call? Yes for two reasons: (a) the existing `discover_anthropic + discover_codex` pattern already excludes Gemini by construction — adding negative tests for absent behavior is brittle; (b) PR-G3/G4/G5 will add the actual Gemini code paths and their own positive tests will pin the dispatch contract.

3. **Evidence**: the `surface_as_str_matches_serde_wire_name` test compares `as_str()` against `serde_json::to_string(&variant)`. Could this regress silently if someone changes both in the same commit (e.g. renaming both arms simultaneously)? Yes — but at that point the wire format itself has changed, which is a deliberate breaking change that would surface in every consumer of the JSON format. The test catches the more likely regression: someone updating one without the other.

## Cross-references

- workspaces/gemini/02-plans/01-implementation-plan.md PR-G1 section
- workspaces/gemini/journal/0005, 0006, 0007 — preceding PR-G2a / PR-G2a.2 / PR-G2a.3 decision records
- csq-core/src/providers/catalog.rs — Surface enum + ModelConfigTarget + Provider entry
- csq-core/src/providers/gemini/mod.rs — `SURFACE_GEMINI` const now resolves to enum
- csq-cli/src/commands/swap.rs — Gemini arm refuses with PR-G4 dependency message
- csq-cli/src/commands/models.rs — `GeminiSettingsModelName` arm refuses with PR-G4 dependency message
- csq-core/src/credentials/file.rs — `canonical_path_for` / `live_path_for` placeholder paths for Gemini
