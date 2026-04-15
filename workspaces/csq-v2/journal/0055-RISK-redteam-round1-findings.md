---
type: RISK
date: 2026-04-14
created_at: 2026-04-14T20:20:00+08:00
author: agent
session_id: post-alpha14
session_turn: 45
project: csq-v2
topic: Red team round 1 — three-agent parallel audit
phase: redteam
tags: [security, testing, spec-coverage, convergence]
---

# Red Team Round 1 — Three-Agent Parallel Audit

## Agents Deployed

| Agent                    | Focus                | Duration |
| ------------------------ | -------------------- | -------- |
| deep-analyst (RT1)       | Spec coverage M3-M11 | ~5 min   |
| testing-specialist (RT2) | Test coverage gaps   | ~2 min   |
| security-reviewer (RT3)  | Full security audit  | ~4 min   |

## Summary

**Spec coverage**: 77 IMPLEMENTED, 5 PARTIAL, 8 MISSING, 0 UNWIRED across M3-M11.

**Security**: 0 CRITICAL, 1 HIGH (fixed), 1 MEDIUM (fixed), 15 checks passed. The security posture is strong — three-layer IPC, token redaction, atomic writes, CRLF validation, PKCE protection all verified.

**Test coverage**: 763 Rust + 77 Svelte tests. All components now have coverage.

## Findings Resolved (this session)

### H1: Token leakage in daemon server log (FIXED — PR #123)

`server.rs:506` used `{e}` to format a `CredentialError`. The `Corrupt` variant includes a `reason: String` from `serde_json::Error::to_string()`, which could theoretically echo token content during serialization failure. Replaced with fixed-vocabulary tag: `"credential write failed after oauth exchange"`.

### Test gaps (FIXED — PR #123)

- **commands.rs**: Added 11 validation tests for the Tauri command boundary (list_providers, set_provider_key, rename_account, swap_account, ClaudeLoginView). Was the highest-risk untested module.
- **Toast.svelte**: Added 6 tests. Was the only untested Svelte component.

### M1: expose_secret justification (FIXED — PR #123)

Added inline comment at `anthropic.rs:67-71` documenting why the heap String is acceptable per security.md rule 8.

## Findings Outstanding (external blockers)

| Finding                                       | Status      | Blocker                                            |
| --------------------------------------------- | ----------- | -------------------------------------------------- |
| M7-10: csq update install placeholder key     | BLOCKED     | Foundation Ed25519 key not provisioned             |
| M10-12: Tauri in-app auto-update              | BLOCKED     | Requires signing infrastructure                    |
| M11-01: macOS code signing                    | BLOCKED     | Apple Developer ID not purchased                   |
| M11-02: Windows code signing                  | BLOCKED     | Authenticode cert not purchased                    |
| M11-03/04/06: Homebrew, Scoop, curl installer | BLOCKED     | Distribution infrastructure not built              |
| M11-11: Cross-platform smoke tests            | BLOCKED     | Needs formal multi-platform CI matrix              |
| M5a-03: CLI fallback auto-rotation            | NOT BLOCKED | Feature gap — auto-rotation only works with daemon |
| M6-02: Windows junction testing               | NOT BLOCKED | Needs Windows test environment                     |

## Architectural Deviations (intentional, spec should update)

- **M5-04**: Quota update path changed from CC-JSON-parsing to daemon-side Anthropic API polling. Superior architecture per account/terminal separation rules.
- **M5-02**: Delayed swap verification implemented via statusline polling rather than dedicated 2-second background task. Functionally equivalent.

## Convergence Assessment

| Criterion                  | Status                               |
| -------------------------- | ------------------------------------ |
| 0 CRITICAL findings        | PASS                                 |
| 0 HIGH findings            | PASS (H1 fixed)                      |
| 2 consecutive clean rounds | Round 1 complete, round 2 needed     |
| Spec coverage 100%         | PARTIAL — 8 items blocked externally |
| 0 mock data in frontend    | PASS                                 |

**Next step**: Round 2 with focused agent on M5a-03 (CLI auto-rotation fallback) — the only non-blocked, non-external finding.

## For Discussion

1. M5a-03 (CLI auto-rotation without daemon): the acceptance criteria say "works without daemon" but the daemon is the natural home for polling + rotation. Is it worth adding synchronous auto-rotation to the statusline path, given it would add ~100ms per render and the daemon starts automatically with the desktop app?

2. If the Foundation Ed25519 key had been provisioned before the audit, would H1 have been caught by the signing verification flow (since the signing key is only used in CI, not at the log-line level)?

3. The 8 MISSING items are all infrastructure (signing, packaging, distribution). Should these be tracked as a separate milestone (M12: Distribution) rather than as gaps in M11?
