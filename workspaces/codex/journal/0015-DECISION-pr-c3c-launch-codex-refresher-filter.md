---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T23:30:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c3c
session_turn: 22
project: codex
topic: PR-C3c — `csq run` launch_codex (spec 07 §7.5 INV-P02 daemon prerequisite + handle-dir spawn + env scrub) and refresher iterate-and-skip for Codex slots (structural chain for PR-C4). Two security review findings (1 HIGH, 1 MEDIUM) resolved inline per zero-tolerance Rule 5.
phase: implement
tags:
  [
    codex,
    pr-c3c,
    launch-codex,
    refresher-filter,
    toctou,
    openai-env-scrub,
    daemon-prerequisite,
  ]
---

# Decision — PR-C3c: launch_codex + refresher filter

## Context

Journal 0013 decomposed PR-C3 into C3a (discovery + handle-dir, PR #172) / C3b (login, PR #173) / C3c (this PR: launch). PR-C3c closes the Codex chain's middle layer by wiring `csq run <N>` to detect a Codex-bound slot, verify the daemon is healthy (INV-P02), create a handle dir, scrub cross-surface env, and exec `codex`. The refresher gains a chained `discover_codex` iteration that skips Codex slots structurally so PR-C4 can drop `broker_codex_check` into one `match` arm without touching the discovery path.

Spec 07 §7.5 INV-P02 pins the daemon as a hard prerequisite for Codex spawn — without it, codex-cli's on-expiry in-process refresh fires (openai/codex#10332 single-use RT race), burning the refresh token. §7.2.2 fixes the handle-dir symlink set (auth.json, config.toml, sessions, history.jsonl). §7.5 INV-P04 requires daemon sweep to not dereference persistent-state symlinks (covered by PR-C3a's `create_handle_dir_codex` + PR-C0's `integration_codex_sweep` tests).

## Decision

Ship three surgical changes:

- **`csq-cli/src/commands/run.rs::launch_codex`**: new function. `require_daemon_healthy` → `verify_codex_config_toml` → `verify_codex_canonical_is_regular_file` → `create_handle_dir_codex` → `strip_sensitive_env` + explicit `CLAUDE_CONFIG_DIR`/`CLAUDE_HOME` removal → set `CODEX_HOME=term-<pid>` → `exec_or_spawn`. Dispatch branch in `handle` routes here when `credentials/codex-<N>.json` exists (via `symlink_metadata`, so dangling symlinks refuse to fall through to the Claude path).
- **`resolve_account` extension**: chain `discover_codex` after `discover_anthropic` so the single-Codex-user case auto-picks a Codex slot and multi-slot listings render ` [codex]` hints.
- **`csq-core/src/daemon/refresher.rs::tick`**: extend discovery list with `discover_codex(base_dir)` and `continue` on `AccountSource::Codex` inside the per-account loop. Emits a `skipped_codex` counter in the tick summary for telemetry alignment. PR-C4 replaces the `continue` with `broker_codex_check`.

### Security review — H1 and M1 resolved inline

Per `.claude/rules/zero-tolerance.md` Rule 5, findings above LOW are fixed in-session.

- **H1 (missing `OPENAI_*` + `CODEX_HOME` stripping)**: `strip_sensitive_env` previously stripped `ANTHROPIC_*` + `AWS_BEARER_TOKEN_BEDROCK` + `CLAUDE_API_KEY` — the symmetric Codex-side attack surface (`OPENAI_BASE_URL` / `OPENAI_API_KEY` / `OPENAI_API_BASE` / `OPENAI_ORG_ID`) was exposed, letting a poisoned dotfile exfiltrate Codex JWTs to an attacker endpoint. Fix: extend the filter to `OPENAI_*` + `CODEX_HOME`. `CODEX_HOME` scrubbing makes csq's explicit `cmd.env(HOME_ENV_VAR, handle_dir)` the only authoritative value. Required a follow-up ordering fix — `strip_sensitive_env` must run BEFORE `cmd.env(HOME_ENV_VAR, …)` or the strip re-removes the value we just set. Regression: `strip_sensitive_env_covers_openai_and_codex_home`.

- **M1 (TOCTOU symlink-swap on canonical)**: dispatch uses `symlink_metadata` (succeeds on dangling + symlink-to-anywhere), `create_handle_dir_codex` then uses `exists()` (follows symlinks). Between the two stat calls, a same-user attacker could swap `credentials/codex-<N>.json` from a regular file to a symlink pointing at attacker content; the subsequent handle dir's `auth.json → credentials/codex-<N>.json` symlink chain would then resolve through both hops to the attacker's tokens. Fix: new `verify_codex_canonical_is_regular_file` check — rejects any canonical whose `symlink_metadata` reports `is_symlink()` or non-file. PR-C3b's `save_canonical_for` always writes a regular file, so a symlink here is unambiguous evidence of external mutation. Regression: `codex_canonical_symlink_is_refused`.

### Windows daemon-detection gap (journaled, not resolved)

`require_daemon_healthy` is `#[cfg(unix)]` only; the `#[cfg(not(unix))]` path returns `Ok(())` unconditionally. Windows named-pipe daemon detection (M8-03) is PR-C4's H2 gate. Refusing spawn on Windows today would brick every Windows user whose daemon is live but whose pipe client isn't wired yet; allowing spawn lets codex-cli's in-process refresh fire during a long session. The trade matches csq's zero-brick philosophy (user can at least work), and PR-C4's H2 gate closes it — the `#[cfg(not(unix))]` comment names PR-C4 as the load-bearing reference.

## Alternatives considered

**A. Ship PR-C3 monolithic.** Rejected per journal 0013 — repeat of the PR-C2 / PR-C3 anti-pattern.

**B. Wire `broker_codex_check` in PR-C3c rather than PR-C4.** Rejected. `broker_codex_check` depends on the PR-C0.5 Node transport + redactor + error-variant expansion — enough code to deserve its own review boundary. Iterate-and-skip in C3c keeps the refresher discovery path honest (Codex slots appear in telemetry) while deferring the high-rigor refresh logic to its own diff.

**C. Chain `discover_codex` everywhere discovery is called (rotation, auto-rotate, etc.).** Rejected. Those callers will need per-surface handling (e.g. `auto_rotate.rs` already filters to same-surface candidates per INV-P11). Landing the refresher change alone keeps PR-C3c's blast radius bounded to the two spots that actually need to see Codex slots today.

**D. Implement full `env_clear + allowlist` instead of `env_remove`.** Rejected for this PR. An allowlist requires knowing exactly which env vars `codex-cli` needs (PATH, HOME, locale, at minimum) and maintaining that list across platforms. The extended `env_remove` set (ANTHROPIC*\*, OPENAI*\*, CODEX_HOME, CLAUDE_API_KEY, AWS_BEARER_TOKEN_BEDROCK, CLAUDE_CONFIG_DIR, CLAUDE_HOME) covers every currently-known exfiltration vector. Full `env_clear + allowlist` is a PR-C3c-follow-up hardening target tracked in workspaces/codex but out of scope.

## Consequences

- `csq run <N>` on a Codex-bound slot works end-to-end on Unix when the daemon is running. On Windows the daemon check is a no-op, matching the existing Windows carve-out — covered by journal 0015 + PR-C4's H2 merge gate.
- Refresher telemetry now sees Codex slots. PR-C4 drops `broker_codex_check` into one `match` arm; no discovery-path changes required.
- FR-CLI-05 (PR-C3b) + dispatch-in-run (PR-C3c) now form a coherent pair: the slot that refuses `csq setkey` is also the slot that routes to `launch_codex`. Same filesystem check (`credentials/codex-<N>.json` exists as regular file, not symlink) used in both paths.
- Env scrubbing is now symmetric across surfaces: Anthropic + Codex launches both refuse to inherit `ANTHROPIC_*` OR `OPENAI_*` from the parent. A mis-provisioned slot cannot leak credentials across surfaces via a parent-shell export.
- The TOCTOU guard (M1 fix) formalizes what `save_canonical_for` has always promised — the canonical is a regular file, never a symlink. Any external process that mutates this path gets a loud abort at spawn time, not silent acceptance.

## For Discussion

1. **The H1 fix exposed an ordering bug that wasn't in the security review: if `cmd.env(HOME_ENV_VAR, …)` ran BEFORE `strip_sensitive_env`, the newly-added `CODEX_HOME` strip would remove the explicit value we just set. Does this kind of "fix that introduces an ordering constraint" deserve a standing rule, or is it rare enough that catching it via tests is sufficient?** (Lean: rare enough. The constraint is self-documenting at the call site via the strip-before-set ordering comment, and the `strip_sensitive_env_covers_openai_and_codex_home` test would catch a regression. Extracting a `build_codex_command(handle_dir)` helper would hide the ordering rather than document it.)

2. **M1's `verify_codex_canonical_is_regular_file` is a pre-flight check at the CLI layer. Should the same invariant live in `create_handle_dir_codex` itself (csq-core) so the desktop's future Add-Account flow inherits the guard?** (Lean: move to csq-core in PR-C3c-followup or PR-C4. Today the CLI is the only caller; once the desktop wires up, having the check in two places diverges. Defer to avoid a cross-PR csq-core modification.)

3. **If the Windows named-pipe daemon detection had landed in v2.0.0 (counterfactual to journal 0067 H10), PR-C3c's `#[cfg(not(unix))]` path would be a full `detect_daemon` call rather than `Ok(())`. Does deferring the Windows check today create a ratchet where PR-C4 inherits a pre-existing "Windows lets Codex spawn without daemon" footgun, or is the same PR-C4 that adds `broker_codex_check` the natural place to close this?** (Lean: natural place. The Windows pipe client is one cohesive change; splitting it between "detection" and "refresh" would require two landing points. PR-C4 H2 is the single gate.)

## Cross-references

- `workspaces/codex/journal/0013-DECISION-pr-c3-decomposition-discovery-first.md` (this PR completes the 3-way split)
- `workspaces/codex/journal/0014-DECISION-pr-c3b-codex-login-device-auth.md` (login flow PR-C3b merged as PR #173; this PR launches the result)
- `specs/07-provider-surface-dispatch.md` §7.2.2 (Codex on-disk layout), §7.5 INV-P02 (daemon prerequisite), INV-P04 (handle dir persistence carveouts — sweep safety)
- `csq-core/src/session/handle_dir.rs::create_handle_dir_codex` (PR-C3a primitive consumed here)
- `csq-core/src/providers/codex/surface.rs::{config_toml_path, CLI_BINARY, HOME_ENV_VAR}` (PR-C3b constants consumed here)
- `csq-core/src/daemon/detect.rs::detect_daemon` (INV-P02 check)
- `csq-core/tests/integration_codex_sweep.rs` (PR-C0 sweep test — exercises INV-P04 for Codex symlinks)
- `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings)
- `.claude/rules/security.md` (strip_sensitive_env invariants)
