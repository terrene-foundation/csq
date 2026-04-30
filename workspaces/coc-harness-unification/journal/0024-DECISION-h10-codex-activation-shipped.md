---
type: DECISION
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h10-codex
session_turn: 1
project: coc-harness-unification
topic: H10 ships — codex activation (capability + compliance + safety)
phase: implement
tags: [coc-eval, codex, h10, multi-cli]
---

# H10 — Codex activation shipped

## What landed

- **`coc-eval/lib/launcher.py`** — new `codex_launcher` mirroring `cc_launcher`'s shape. Builds `codex exec --sandbox read-only "<prompt>"` argv for capability/compliance/safety; `_build_codex_args("implementation", …)` raises (ADR-B gates impl × codex out at the runner). Env: `CODEX_HOME=<stub_home>` + `HOME=<home_root>`, XDG\_\* stripped per H7/H8 hardening. Refuses sandbox_profile (codex's `--sandbox` is the boundary).
- **`build_stub_home` extension** — best-effort symlinks `~/.codex/auth.json` and `~/.codex/config.toml` into the per-fixture stub_home alongside cc's `.credentials.json`. Containment check (`_is_within(src, ~/.codex)`) prevents chaining a credential symlink that points outside the user's codex root.
- **`CLI_REGISTRY["codex"]`** — second concrete entry. Replaces the H7-era `cli != "cc"` `RuntimeError` gate in `runner._run_one_attempt` with a `CLI_REGISTRY.get(cli)` lookup; the launcher is dispatched via `cli_entry.launcher(inputs)`.
- **`coc-eval/lib/auth.py`** — `_probe_codex` runs `codex --version` (best-effort) + `codex exec --sandbox read-only "ping"` (10s timeout). `_AUTH_ERROR_PATTERNS` extended with codex-specific `unauthorized`, `Token expired`, `Sign in to ChatGPT`.
- **`PERMISSION_MODE_MAP` / `SANDBOX_PROFILE_MAP` / `CLI_TIMEOUT_MS`** — codex entries already populated structurally in earlier H steps; H10 verifies they map to `read-only` / `None` / `60_000` for capability/compliance/safety. Implementation × codex stays `None` (skipped).
- **`specs/08-coc-eval-harness.md`** — new "Codex activation (H10)" section.

## Lib pytest delta

`531 → 548 passed, 2 skipped` (+17 H10 tests):

- `tests/lib/test_codex_launcher_h10.py` (17 tests) — argv shape per suite, env CODEX_HOME, no CLAUDE_CONFIG_DIR leak, full LaunchSpec, wrong-CLI rejection, sandbox-profile rejection, registry membership, auth probe shape + caching, codex error vocabulary in `is_auth_error_line`, runner dispatches via registry, build_stub_home symlinks codex auth when present + skips when absent.
- `test_cli_registry.py::test_phase1_registry_post_h10` updated to expect `{"cc", "codex"}` (was `{"cc"}` pre-H10).

## Live codex gate (in progress at journal-write time)

`python coc-eval/run.py capability compliance safety --cli codex --format jsonl`. C1+C2 PASS observed; full result will be appended to the PR.

Plan §H10 acceptance: capability C1+C3 pass, compliance ≥7/9, safety ≥4/5.

## Why this shape

- **codex's `--sandbox read-only` is the boundary, not bwrap.** cc with `--dangerously-skip-permissions` needed the cc-style process-level sandbox (write-confined.sb / bwrap) for implementation. codex's CLI carries its own kernel-mediated sandbox; layering bwrap on top would conflict (bwrap unshares PIDs in ways codex's sandbox expects to control). The launcher refuses non-None sandbox_profile to surface this contract loud.
- **stub_home is shared between cc and codex.** Both files (`.credentials.json` and `auth.json`) coexist in the same per-fixture stub_home. The model running cc only reads `.credentials.json` via CLAUDE_CONFIG_DIR; codex only reads `auth.json` via CODEX_HOME. Sharing keeps the fixture lifecycle simple.
- **Best-effort codex auth setup.** If `~/.codex/auth.json` is absent, build_stub_home succeeds without it. The codex auth probe then fails and the runner stamps `skipped_cli_auth` for codex cells. No silent fall-through to the user's real codex auth.
- **Registry-driven dispatch replaces the cc-only guard.** The H7-era `cli != "cc"` RuntimeError was a Phase 1 placeholder; H10's `CLI_REGISTRY.get(cli)` is the structural answer. H11 (gemini) will register a third entry without further dispatch changes.

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H10
- H9 ship journal: `journal/0022-DECISION-h9-aggregator-shipped.md`
- H10 round-1 review: `journal/0025-RISK-h10-codex-security-review-round1-converged.md` (this session)
- Spec: `specs/08-coc-eval-harness.md` (new "Codex activation (H10)" section)

## For Discussion

- **Q1 (challenge assumption):** codex_launcher refuses non-None sandbox_profile. If a future ADR landed cc-style sandbox layering on top of codex's --sandbox (defense-in-depth), that refusal becomes the wrong shape. Is "refuse" the right default vs "accept and layer", and what evidence would flip the decision?
- **Q2 (counterfactual):** codex auth files are symlinked best-effort. If a user has `~/.codex/auth.json` but the file is empty/corrupt, the symlink lands and codex's probe fails differently than if the file were absent (different exit code paths). Is "absent → skipped_cli_auth, corrupt → error_invocation" the right operator UX, and does the auth probe need to distinguish?
- **Q3 (extend):** H10 ships codex for capability/compliance/safety. The implementation × codex pair stays gated (ADR-B). What evidence would justify activating that pair — and is the existing tiered_artifact backend portable to codex's stdout shape (codex `exec` returns plain text, no JSON envelope to parse)?
