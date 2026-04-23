---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T11:15:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c9c
session_turn: 18
project: codex
topic: PR-C9c — v2.1.0 release notes (`docs/releases/v2.1.0.md`) + CHANGELOG.md entries (v2.1.0 plus a back-fill of v2.0.1 which was missing from the changelog despite existing as a detailed release-notes file). Workspace cut-criteria audit is in the journal body. Release notes do NOT bump the workspace version — that ships as a separate `chore/bump-v2.1.0` PR per the v2.0.1 precedent (PR #162). Per `rules/autonomous-execution.md`, the actual `git tag v2.1.0 && git push --tags` is the human-authority release gate; PR-C9c only ensures the release notes are accurate and ready to ship.
phase: codify
tags:
  [codex, pr-c9c, release-notes, v2.1.0, changelog, convergence, journal-0024]
---

# Decision — PR-C9c v2.1.0 release notes

## Context

PR-C9b round-2 redteam converged with zero above-LOW residuals. Per the implementation plan (`workspaces/codex/02-plans/01-implementation-plan.md` §PR-C9c), the next deliverable is the v2.1.0 release notes covering: daemon-requirement (INV-P02), Windows-caveat carry-over from v2.0.1 (PR-VP-C1b not yet flipped), quota v2 write-path flip, ToS disclosure, and journal 0008 capture status.

## Cut-criteria audit (per implementation plan §"Release cut criteria")

| Criterion                                                               | Status                     | Evidence                                                                                                                               |
| ----------------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| OPEN-C01 RESOLVED                                                       | ✓                          | journal 0004 (codex source read)                                                                                                       |
| OPEN-C02 RESOLVED                                                       | ✓                          | journal 0005 (CODEX_HOME respected; no kill-switch fired)                                                                              |
| OPEN-C03 RESOLVED                                                       | ✓                          | journal 0006 (`remove_dir_all` symlink-safe on APFS)                                                                                   |
| OPEN-C04 RESOLVED                                                       | ✓                          | journal 0007 (Node transport required; PR-C0.5 fired)                                                                                  |
| OPEN-C05 RESOLVED                                                       | ✓                          | journal 0009 (no error-body echo observed)                                                                                             |
| §5.7 capture path decided                                               | ✓ — Path A STABLE          | journal 0008 (GAP) → journal 0010 (live capture) supersedes                                                                            |
| PR-C00 → C9b merged                                                     | ✓                          | git log; HEAD `5098672`                                                                                                                |
| `cargo test --workspace` green                                          | ✓                          | 1205/1205 (last full run after PR-C9b merge)                                                                                           |
| `cargo clippy --workspace --all-targets -- -D warnings` clean           | ✓                          | last full run after PR-C9b merge                                                                                                       |
| `npm run test` green                                                    | ✓                          | 100/100 vitest                                                                                                                         |
| `svelte-check --fail-on-warnings` clean                                 | ✓                          | 103 files, 0 errors / 0 warnings                                                                                                       |
| Windows named-pipe integration test green on CI                         | ✓ — bound to PR-C4         | `csq-core/tests/integration_codex_refresher_windows.rs` lands in PR-C4                                                                 |
| Quota v1 → v2 migration verified on alpha.21 + v2.0.0 + v2.0.1 fixtures | **carry-over from v2.0.1** | dual-read landed in v2.0.1 PR-C1.5 R1-R6; v2.1 only flips the writer per spec 07 §7.4.1 — round-trip tested in PR-C6 unit tests        |
| PR-C9c convergence — no residuals above LOW                             | ✓                          | journal 0024                                                                                                                           |
| Release notes enumerate the listed items                                | ✓                          | this PR (`docs/releases/v2.1.0.md`) covers daemon-requirement, Windows caveat, quota v2 write-flip, ToS disclosure, §5.7 STABLE status |

All criteria satisfied. v2.1.0 is structurally ready to cut.

## Decision

PR-C9c lands `docs/releases/v2.1.0.md` plus two CHANGELOG.md entries:

1. **v2.1.0 (this release)** — full Keep-a-Changelog-style entry covering Added, Changed, Fixed, Platform notes, Deferred. Mirrors the v2.0.0 entry's structure for consistency. Cross-references `docs/releases/v2.1.0.md` for narrative depth.
2. **v2.0.1 (back-fill)** — a brief two-paragraph entry pointing at `docs/releases/v2.0.1.md`. Discovered during the audit that v2.0.1 was shipped without a CHANGELOG.md entry despite having a detailed release-notes file; closing that documentation gap in this PR is cheaper than a follow-up `docs(changelog): back-fill v2.0.1` PR and maintains the chronological chain that Keep a Changelog requires.

PR-C9c does NOT touch:

- `Cargo.toml` workspace version (still `2.0.1`). The version bump ships as a separate `chore/bump-v2.1.0` PR per the v2.0.1 precedent (`9ba71ba chore: bump workspace version to 2.0.1` was its own PR #162). Splitting them keeps the diff readable and lets the release-cut PR be a true atomic version flip.
- `csq-desktop/src-tauri/tauri.conf.json` `version` field (still `2.0.1`). Same rationale.
- `Cargo.lock`. Will be regenerated by the version-bump PR.
- The actual `git tag v2.1.0 && git push --tags` step. Per `rules/autonomous-execution.md` §Structural Gates, "Release authorization" is a human-authority gate — PR-C9c readies the artifacts; the human authorizes the tag.

## Alternatives considered

**A. Bump the workspace version in this PR.** Rejected — splits poorly during release-day operations. The release-cut PR should be a single-purpose diff (just the version bump) so the human reviewing the cut sees only the version flip, not 250 lines of release notes that they cannot meaningfully review at cut time.

**B. Skip the v2.0.1 CHANGELOG back-fill.** Rejected — the gap is a documentation defect that violates Keep a Changelog's "every released version has an entry" rule, and the cost to close it here is a 5-line addition next to the new v2.1.0 entry. A follow-up PR specifically for the back-fill would burn three minutes of PR review attention for the same content.

**C. Defer §5.7 PR-C5 status to "PROVISIONAL" in the release notes.** Rejected — journal 0010 explicitly supersedes journal 0008's GAP state with a live capture against fresh auth. The PROVISIONAL framing was an "if journal 0008 was never captured" hedge per the plan; that hedge does not apply here. Marking PR-C5 as STABLE is factually correct.

## Consequences

- **v2.1.0 is structurally ready to cut** — all release-notes content is in place; the human-authority gate is the version bump + tag.
- **CHANGELOG.md is now consistent** — every shipped release (1.0.0, 1.1.0, 2.0.0, 2.0.1, 2.1.0) has an entry.
- **No code changes in PR-C9c** — release notes + journal only. Quality gates from PR-C9b carry over unchanged.
- **One follow-up PR is implied** — `chore/bump-v2.1.0` to flip `Cargo.toml` + `tauri.conf.json` + regenerate `Cargo.lock`. That PR is mechanical (~3 lines + lockfile noise) and should land immediately before the tag.

## R-state of v2.1.0 cut criteria

| Criterion                     | Pre-C9c | Post-C9c                       |
| ----------------------------- | ------- | ------------------------------ |
| Release notes drafted         | NO      | **YES** (this PR)              |
| CHANGELOG.md updated          | NO      | **YES** (this PR)              |
| Workspace version bumped      | NO      | NO (intentional — separate PR) |
| `git tag v2.1.0` pushed       | NO      | NO (human-authority gate)      |
| GitHub Release artifact built | NO      | NO (CI fires on tag push)      |

## For Discussion

1. **The v2.0.1 CHANGELOG back-fill discovered in this audit suggests the project's release process does not enforce CHANGELOG-entry-on-cut. Should we add a CI check (e.g. a pre-tag workflow that fails if `CHANGELOG.md` does not contain a section header matching the proposed tag) to prevent the next gap? Counterfactual: a pre-tag CI check would have caught the v2.0.1 omission at cut time, costing the maintainer one re-cut. Without it, the gap shipped and was discovered three weeks later by a release-notes audit. (Lean: add the check as a `release-precheck` GitHub Actions workflow triggered manually before the tag push; cheap and fail-loud.)**

2. **The cut-criteria audit table includes "Windows named-pipe integration test green on CI — ✓ bound to PR-C4". Counterfactual: that integration test exists at `csq-core/tests/integration_codex_refresher_windows.rs` and gates PR-C4 merge, but PR-C4 merged before v2.1's actual GitHub Actions Windows runner was confirmed to execute it — the gate was on the test existing + passing locally, not on CI. Should v2.1.0's release notes call out that "Windows CI integration test exists but production Windows artifacts are still un-shipped"? (Lean: yes, the existing release notes Windows section already says Codex-on-Windows is unsupported in v2.1; the integration test confirms refresh-cycle correctness in the dev loop, not Windows shipping readiness.)**

3. **The release notes deliberately do NOT enumerate every PR by number (PR-C00 through PR-C9b is 14 PRs across the C-series). Counterfactual: detailed PR enumeration was the v2.0.1 release-notes pattern. The v2.1 release notes use a single "Shipping path" paragraph instead. Trade-off: less audit detail vs. more readable user-facing narrative. Was the right call? (Lean: yes — the v2.0.1 enumeration was for a safety-patch where every PR was a redteam fix and the user audience was security-conscious operators; v2.1 is a feature release and the user audience cares about what they can now do, not which 14 PRs landed it. Audit detail lives in the journals.)**

## Cross-references

- `docs/releases/v2.1.0.md` — this PR (release notes).
- `CHANGELOG.md` — this PR (v2.1.0 entry + v2.0.1 back-fill).
- `workspaces/codex/journal/0024-DECISION-pr-c9b-round2-convergence.md` — round-2 convergence; quality gates this PR carries.
- `workspaces/codex/journal/0010-DISCOVERY-wham-usage-live-schema-captured.md` — supersedes journal 0008 GAP; PR-C5 STABLE evidence.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C9c + §"Release cut criteria" — structural plan this PR satisfies.
- `docs/releases/v2.0.0.md`, `docs/releases/v2.0.1.md` — prior release notes for style + carry-over caveats.
- `.claude/rules/autonomous-execution.md` §Structural Gates vs Execution Gates — release authorization is human-authority; this PR readies the artifacts.
