---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T00:00:00Z
author: co-authored
session_id: 2026-04-25-gemini-pr-g2a
session_turn: 28
project: gemini
topic: platform::secret design — reconciled rust-desktop-specialist + security-reviewer recommendations
phase: implement
tags: [gemini, platform-secret, vault, security, pr-g2a, design]
---

# Decision — `platform::secret` design reconciliation

## Context

PR-G2a (workspaces/gemini/02-plans/01-implementation-plan.md, line 67-80) requires a new encryption-at-rest primitive for Gemini API keys (`AIza*`) and Vertex SA JSON paths. Codex does NOT use this — sole-owned by Gemini per H8/M3. Two specialists were dispatched in parallel for design; their recommendations conflicted on three load-bearing points.

## Conflicts and resolutions

| #   | Decision                              | rust-desktop                                  | security-reviewer                                                        | **Decision**                                                                                   |
| --- | ------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| 1   | Linux backend                         | AES-GCM file as **sole** backend (skip D-Bus) | Secret Service when present + opt-in file fallback (NEVER auto-fallback) | **Security-reviewer wins.** Auto-fallback silently degrades the threat model.                  |
| 2   | macOS/Windows when native unavailable | Could fall back to file                       | Refuse-to-operate (`BackendUnavailable`)                                 | **Security-reviewer wins.** No silent degradation.                                             |
| 3   | Caching                               | Not addressed                                 | NO in-process caching; each `get` re-reads                               | **Security-reviewer wins.** Caching extends cleartext lifetime; keychain is microsecond-cheap. |

Where they aligned (no conflict): trait shape (`set/get/delete/list_slots`), `SecretString` boundary, audit log mandatory, NDJSON format, no read command on Tauri IPC, `setrlimit(RLIMIT_CORE, 0)` on subprocess, Vertex SA file mode check.

## What shipped in PR-G2a (#192)

- Trait + macOS Keychain backend (sole production backend in this PR)
- In-memory backend (feature-gated `secret-in-memory`)
- NDJSON audit log: 0o600, 30-day retention, NEVER logs secret/length/prefix/hash
- Linux + Windows: stub files; real impls land PR-G2a.2 / PR-G2a.3
- `CSQ_SECRET_BACKEND` env override for opt-in file backend (rejects unknown values)
- 5s hard timeout per op (no daemon-blocking hangs)
- 70 new tests across 22 secret/audit + 6 redactor + 7 keyfile + 5 settings + 4 probe + 13 spawn + 4 capture + 8 tos_guard + 1 lint

## Open questions deferred

- **Q1 (PR-G2b)**: macOS keychain access groups — does csq-cli need separate entitlements from the desktop bundle to avoid per-rebuild auth prompts? PR-G2a uses native API uniformly; CLI may see prompts during dev rebuilds. PR-G2b decides one API or two.
- **Q2 (out of scope for v2.3.0)**: Linux TPM integration. Machine-bound key derivation does NOT protect against same-UID. TPM via `tss2` would close the gap; defer to a future PR.
- **Q4**: `aes-gcm` crate has not been Foundation-audited; RustCrypto's own audit deemed sufficient for Apache-2.0 release.
- **Q5**: Windows `LocalSystem` posture — daemon refuses to start under SYSTEM (DPAPI binds to user profile). Documented as PR-G2a.3 invariant.
- **Q7**: iCloud Keychain may resurrect deleted entries. Documented as known limitation in PR-G2a.3 release notes.

## Consequences

1. PR-G2a unblocks Gemini provisioning code path on macOS NOW (in-memory tests verify the contract; live keychain tests gated behind `--include-ignored` for security-reviewer sign-off).
2. Linux users get `BackendUnavailable` until PR-G2a.2 lands; this is intentional (no silent file fallback).
3. Windows users get `BackendUnavailable` until PR-G2a.3 lands.
4. The `Vault` trait is the stable surface — PR-G2a.2/.3 ship without API churn.

## For Discussion

- **Counterfactual**: If we had picked rust-desktop's "AES-GCM file as sole Linux backend", how much faster would PR-G2a.2 ship? Answer: ~1 session faster, but with permanent threat-model degradation visible in the security audit.
- **Challenge**: Could we have shipped the Linux Secret Service backend in PR-G2a too? Answer: the `secret-service` crate adds a `zbus` async D-Bus dep that needs its own security review; splitting keeps each PR reviewable in one sitting per implementation-plan §M3.
- **Evidence**: What proves the in-memory backend is safe to ship? It is feature-gated (`secret-in-memory`) AND not in `default`, AND `open_default_vault` only routes there when both the env var is set AND the feature is on. Production builds reject the env var.

## Cross-references

- PR #192 (merged 2026-04-25, commit 3c0451f)
- workspaces/gemini/02-plans/01-implementation-plan.md PR-G2a section
- workspaces/gemini/journal/0003 (OPEN-G01 RESOLVED — informs why drift detector is cheap re-assertion)
- workspaces/gemini/journal/0004 (OPEN-G02 RESOLVED — informs why pre-spawn `.env` scan is mandatory)
- .claude/rules/security.md §1, §2, §5, §5a (atomic writes, no secrets in logs, fail-closed on lock contention, partial-failure cleanup)
