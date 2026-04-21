---
type: DECISION
date: 2026-04-21
created_at: 2026-04-22T00:00:00+08:00
author: co-authored
session_id: 2026-04-21-stable-v2-readiness
session_turn: 38
project: csq-v2
topic: definition of "stable" for v2.0.0 and the release gate checklist that converts the brief's seven-bullet definition into verifiable commands, gates, user journeys, and documented limitations
phase: analyze
tags:
  [
    release,
    v2-stable,
    gate-checklist,
    golden-path,
    signing-blocker,
    windows-smoke,
    notarization,
    autonomous-execution,
  ]
---

# 0062 — DECISION: v2.0.0 stable definition and release gate checklist

**Produced:** `workspaces/csq-v2/02-plans/04-v2-stable-release-checklist.md`.
**Source brief:** `workspaces/csq-v2/briefs/03-v2-stable-readiness.md`.
**Trigger:** User asked for a concrete, runnable release checklist that converts the brief's 7-bullet "what stable means" sketch into gates a release captain can execute without interpretation.

## Decision

Stable for csq v2.0.0 is the conjunction of 12 verifiable properties (D1…D12 in the checklist). Every property is either a one-line shell command, a CI job status, or a documented manual procedure with a specific pass criterion. Judgement-call properties are BLOCKED from the stable definition.

Stable is cut when all gates in Groups A–E are green:

- **Group A — Code health** (automated in CI): version bump, tests, clippy, fmt, svelte tests, no stubs, no command panics, gitignore covers credentials.
- **Group B — Signing and updater** (external + CI): Foundation Ed25519 key provisioned, Tauri updater key provisioned, `RELEASE_PUBLIC_KEY_BYTES` is not the placeholder seed, `latest.json` reachable, DMG / AppImage / MSI launch on fresh profiles.
- **Group C — Golden-path smoke** (manual, 5 journeys × 3 platforms): first install, second account, in-flight swap, overnight quota stability, alpha.21 → 2.0.0 upgrade.
- **Group D — Documentation and governance**: release notes, spec refresh (spec 05 §5.3 / §5.4), changelog, README, red-team resolution status.
- **Group E — Security review**: no secrets in history, redaction coverage, daemon IPC three-layer invariants (journal 0006), OAuth TCP/socket partition (journal 0011), subscription-metadata guard (journal 0029).

## Alternatives considered

1. **Adopt the brief's 7 bullets verbatim as the stable definition.** Rejected: bullets 1 ("no user-blocking bugs on the golden path") and 5 ("smoke-tests on a fresh macOS") are not verifiable — they are judgement calls with no specific output.
2. **Define stable as "all CI jobs green plus a manual sign-off."** Rejected: CI does not cover fresh-profile installs, DMG Gatekeeper behavior, Windows SmartScreen behavior, or upgrade-path credential preservation.
3. **Defer Windows to a "preview" label and ship 2.0.0 as macOS + Linux only.** Considered. The code is as complete on Windows as on Linux, but fresh-profile manual validation is thinner. Recommend: ship Windows first-class with the L4 caveat — "preview" telegraphs less confidence than the Rust tests on the Windows CI matrix actually warrant — but this is a human call.
4. **Block on Apple notarization** (L1). Rejected: cert not provisioned. Blocking indefinitely is worse than shipping with honest release-notes text + tested right-click-Open bypass. L1 is documented, not blocking.
5. **Block on Foundation Ed25519 release-signing key** (L2). Rejected for auto-update install only, not for cutting the release. `csq update check` works with any key; `csq update install` requires the real key. Ship with the L2 caveat: users download the new installer for 2.0.0 → 2.0.1 until the key is provisioned.

## Why remove "judgement calls" from the stable definition

The brief's language ("no user-blocking bugs", "smoke-tests pass", "red-team findings resolved") is honest intent but unverifiable as a gate. `rules/zero-tolerance.md` forbids "residual risks — accepted under same-user threat model"; the same logic applies to release gates. If a gate reads "no user-blocking bugs," every release captain decides differently what "user-blocking" means, and the gate becomes a nil enforcement.

## Consequences

- The checklist at `workspaces/csq-v2/02-plans/04-v2-stable-release-checklist.md` is the authoritative release gate. When it conflicts with the brief, the checklist wins.
- Two brief claims are superseded by source review:
  1. "ChangeModelModal first-open bug" (brief §Newly discovered, item 5) — fixed this session; see journal 0061.
  2. "Windows named-pipe IPC is not implemented" (brief §Known limitations, item 3) — `csq-core/src/daemon/server_windows.rs` and `client_windows.rs` are fully implemented with a three-layer security model. The actual gap is fresh-profile Windows smoke validation, recorded as L4.
- Two brief items (R6, R11) are deferred to 2.0.1 with explicit rationale.
- Specs 05 §5.3 and §5.4 freshness is a v2.0.0 blocker (gate D1-2) because `rules/specs-authority.md` forbids shipping with specs marked stale.
- A concrete seven-step release runbook is included so a release captain can execute end-to-end without re-reading the full document.

## Follow-up actions

1. Refresh spec 05 §5.3 and §5.4 from journal 0032 data — blocker for D1-2.
2. Create `docs/releases/v2.0.0.md` with verbatim §4 limitation text — blocker for D1-1.
3. Create `CHANGELOG.md` if absent — blocker for D1-4.
4. Bump workspace version in `Cargo.toml` + `tauri.conf.json` from `2.0.0-alpha.21` to `2.0.0` — blocker for A1.
5. Provision Foundation Ed25519 signing key, OR confirm L2 release-notes language — blocker for B3 or acceptance of L2.
6. Close security H1 (move `is_placeholder_key()` gate into `csq-core::update::download_and_apply`). Blocker for E4 equivalent (security posture).
7. Run Journey 1 smoke on a Windows 11 VM and decide first-class vs. preview labeling — blocker for C7 or acceptance of L4.

## For Discussion

1. The brief identified "ChangeModelModal first-open bug" and "Windows named-pipe IPC missing" as open items; source review shows both are already addressed. Does that mean the brief was drafted from a stale session snapshot, or is there a test that reproduces either bug on the current `main` commit that was missed? Should the brief be updated in place (journal precedent says no — briefs are immutable) or superseded by this decision journal?
2. L2 (auto-update install blocked on placeholder Ed25519 key) is the only limitation gated by an external Foundation action. If the key is not provisioned before the target release date, would the release captain prefer (a) ship 2.0.0 with L2 documented honestly and take the small UX hit of manual-reinstall for 2.0.1, or (b) hold the release until the key lands?
3. If the checklist had instead adopted the brief's 7 bullets verbatim, which of the 5 user journeys in §3 would still have been caught? Only Journey 5 (alpha→stable upgrade) explicitly maps to brief bullet 3; Journeys 1–4 would fall under the judgement-call bullets 1 and 5 and could be signed off without ever running. Is that the actual risk profile we wanted to close, or is there a simpler structural fix (e.g., require every stable release to produce a smoke-test video artifact)?
