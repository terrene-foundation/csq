---
name: Red-team convergence for post-v2.0.0 multi-workstream plan
description: 19 findings (3 CRITICAL, 8 HIGH, 8 MEDIUM) against v2.0.1 patch + Codex v2.1 + Gemini v2.2 plans; each resolved with plan amendments
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T17:30:00Z
author: co-authored
session_id: post-v2.0.0-planning
session_turn: 8
project: csq
topic: red-team pass over unified roadmap + 3 implementation plans
phase: redteam
tags:
  [
    redteam,
    convergence,
    v2.0.1,
    v2.1-codex,
    v2.2-gemini,
    planning,
    zero-tolerance,
  ]
---

# Red-Team Convergence: Post-v2.0.0 Plan

Four parallel deep-analyst red-team passes over the unified roadmap + 3 implementation plans surfaced 19 findings. Per `zero-tolerance.md` Rule 5, every finding above LOW resolved in-session by amending the plans. No residuals carried to "accepted" status.

## Findings and resolutions

### CRITICAL

**C-CR1 — Gemini EP4 config knob defeats ToS compliance claim** (gemini F4)

Break: EP4 (response-body sentinel) is disableable. If the knob is on but EP4 fails (future gemini-cli version string mismatch), EP1-EP3 can all pass while OAuth actually executes. If the knob is off, csq ships a ToS compliance guard the user can silently disable. Can't claim defense-in-depth ToS compliance AND user-disableable last-line defense.

Resolution: remove the config knob from EP4. Replace with (a) whitelist versioned by gemini-cli minor release, (b) auto-update whitelist on `gemini --version` mismatch with dialog, (c) log first-hit telemetry for whitelist tuning. EP4 moves from "7 layers, 1 disableable" to "7 mandatory layers." If whitelist maintenance burden proves unacceptable post-launch, reclassify EP4 as advisory and update gemini brief positioning — do NOT leave the knob as an escape hatch.

Plan amendment: gemini PR-G3 scope — drop "config knob to disable" line; add whitelist versioning + version-mismatch dialog.

---

**C-CR2 — Gemini event-drop corrupts quota for up to 24h** (gemini F5)

Break: plan §Guiding principles #4 says "CLI sends IPC events to daemon; drop when daemon down." Plan §#5 says "Gemini does NOT require daemon to spawn." Scenario: user runs `csq run 5` (Gemini) for 1h with daemon down → every counter increment dropped → daemon starts → quota.json shows pre-downtime value, off by 1h of real spawns → counter stays wrong until midnight-LA reset. UI renders stale counter as truth. Violates `account-terminal-separation.md` Rule 1 spirit: daemon-as-sole-writer assumes daemon has upstream polling source; Gemini has no upstream — CLI IS the ground truth.

Resolution: CLI writes durable event log `~/.claude/accounts/gemini-events-<slot>.ndjson` with `O_APPEND` + `fsync` per event. Daemon on startup + on reconnect drains the log, updates quota.json atomically, truncates log. Single-writer-to-quota.json invariant preserved (daemon); events are durable (CLI). Sub-ms per-spawn cost.

Plan amendment: gemini PR-G3 scope — add NDJSON event log + daemon startup-drain. Spec 05 §5.8 (pinned by PR-G0) must document the durability contract.

---

**C-CR3 — Codex §5.7 live capture pollutes user `~/.codex/` if OPEN-C02 negative** (codex F2)

Break: journal 0008 (§5.7 schema capture) deferred to "after PR-C3 ships login". PR-C3 requires OPEN-C02 resolved. If OPEN-C02 shows codex ignores `CODEX_HOME` for sessions/history, capturing journal 0008 from a real Codex account pollutes the user's production `~/.codex/` with csq test data. Plan has no pre-capture cleanup contract.

Resolution: add pre-capture kill-switch to journal 0008 gate: "If OPEN-C02 resolves negative, §5.7 capture is BLOCKED until (a) wrapper-script mitigation implemented, (b) user's `~/.codex/` pre-snapshotted via `rsync -a ~/.codex/ ~/.codex.bak-<timestamp>/`, (c) post-probe diff-and-delete of csq-injected rows."

Plan amendment: codex plan gate table adds explicit kill-switch clause under §5.7 entry.

---

### HIGH

**H1 — Shared-spine analysis understates collisions** (spine F1)

Break: ROADMAP says catalog.rs is THE spine. Actually 4+ files collide: catalog.rs + quota/state.rs (Codex v1→v2 AND Gemini v2 counter extension) + usage_poller/mod.rs (3 PRs across 2 streams mutate the dispatch table) + server.rs IPC + Tauri capability manifest (each new command needs re-narrowing per journal 0065 B3).

Resolution: insert new task/PR between codex PR-C1 and PR-C6 — **PR-C1.5 quota schema freeze review** that pulls Gemini counter shape forward into spec 07 §7.4, designing v2 once. Also: codex PR-C1 scope gains a one-line capability-manifest audit.

---

**H2 — Windows wiring vs Codex PR-C4 refresher regression trap** (spine F2)

Break: v2.0.1 PR-VP-C1 wires Windows named-pipe refresher BEFORE Codex PR-C4 adds surface dispatch. Windows path validated only against pre-dispatch code. When Codex PR-C4 rekeys cooldowns to `(Surface, AccountNum)`, Windows silently regresses because Windows CI gating is weak.

Resolution: bind Windows named-pipe integration test to Codex PR-C4 merge gate. PR-C4 cannot merge without Windows CI pass on surface-dispatched refresher.

---

**H3 — PR-A1 handle-dir rewrite collides with Codex PR-C1 surface filter** (spine F3)

Break: PR-A1 rewrites `auto_rotate::tick` and `find_target` to walk handle dirs. Codex PR-C1 adds same-surface filter to the same functions. Two spec-02 updates within one release train is the incremental-mutation pattern `specs-authority.md` Rule 4 blocks.

Resolution: PR-A1 scope adds a `Surface::ClaudeCode`-only filter stub (one-line TODO citing PR-C1). PR-C1 flips the stub to real Surface enum. Alternative: defer A1 to v2.1.0 keeping v2.0.0's gate-off guard. Chosen: stub approach — keeps P0-1 fixed in the patch train.

---

**H4 — Codex PR-C0 bundles transport ADR with docs+code** (codex F1)

Break: OPEN-C04's resolution is an architectural decision (reqwest vs Node transport) that reaches PR-C4 and PR-C5. Bundling with redactor code hides the decision. Rollback requires unwinding unrelated changes.

Resolution: split PR-C0 into

- **PR-C00** — three verification journals (0005/0006/0007) + spec 07 §7.7 status flips + spec 05 §5.7 transport note; docs-only
- **PR-C0** — redactor extension + `secure_file_readonly()` + integration test; code-only
- **PR-C0.5** (conditional, only if OPEN-C04 resolves "Node transport required") — one ADR journal (0009) + new endpoint handlers in existing Node transport harness

---

**H5 — Codex §5.7 test-account + PII scrub story missing** (codex F3)

Break: `wham/usage` capture is from user's real account → consumes real quota, emits telemetry, contains PII. No sanitizer, no gitignore, no redaction assertion.

Resolution: codex PR-C5 scope adds

- `tests/fixtures/codex/wham-usage-golden.json` with PII-scrubbed sample
- `tests/fixtures/codex/scrub.sh` — swap `email`, `account_id`, `sub` JWT claim to literal `REDACTED`
- `.gitignore` entry for `accounts/codex-wham-raw.json` + `accounts/codex-wham-drift.json`
- Pre-commit assertion: no real email / `acct_*` identifier in golden
- Ship with `PROVISIONAL` parser tag if no real capture available; upgrade to `STABLE` via journal 0008b follow-up

---

**H6 — Codex error-body echo investigation is a test-bullet not a gate** (codex F4)

Break: PR-C4 test plan mentions "error-body echo investigation completed and journaled before merge" — no journal placeholder, no effort estimate, no branch point. Could be rubber-stamped with "no echo observed in one sample."

Resolution: promote to **OPEN-C05** gate (new row in codex plan gate table). Verification: three deliberately-bad refresh requests per security-analysis §4 steps 1-4. If echo observed → refresher gains structural defense (SecretString across the module). Effort 0.3 session. PR-C4 starts with OPEN-C05 RESOLVED.

---

**H7 — Gemini IPC surface + daemon-discovery race** (gemini F1)

Break: new IPC message types re-open the capability-narrowing audit from journal 0065 B3. INV-P02 inversion creates bootstrap race: Gemini CLI doesn't require daemon but must send events if daemon alive. Plan silent on socket-path discovery.

Resolution: spec 07 §7.2.3 (pinned by PR-G0) must include event-delivery contract — (a) socket-path resolution rule (`$XDG_RUNTIME_DIR/csq.sock` or `~/.claude/accounts/csq.sock`), (b) non-blocking `connect()` with 50ms timeout, (c) explicit "drop-on-unavailable" semantics with structured log. Test `event_sent_from_cli_when_daemon_alive_reaches_handler` in PR-G3. Capability-manifest audit in PR-G3 scope.

---

**H8 — Gemini platform::secret orphaned ownership** (gemini F3)

Break: plan hedges "owned by Codex PR-C2 if it lands it first, else Gemini PR-G2". Codex PR-C2 actually uses existing `secure_file` + `atomic_replace` — no reason to introduce `platform::secret`. The hedge creates review-time ambiguity.

Resolution: PR-G2 claims sole ownership explicitly. Drop "if Codex hasn't landed it" clause. Add security-reviewer sign-off on all three backends (macOS Keychain, Linux keyring, Windows DPAPI) as PR-gate, not release-gate.

---

**H9 — Version-jump skips dual-read shakedown** (release F1)

Break: v2.0.0 → v2.1.0 tray update hits quota.json v1→v2 migration. Rollback story = "reinstall v2.0.0 from GitHub". Real-world tray update can have lingering v2.0.0 daemon racing v2.1.0 writer.

Resolution: add **PR-B8** to v2.0.1 patch — quota.json dual-read deserialiser (accepts v1 AND v2 shapes; continues writing v1). v2.1 only adds write path. Migration becomes two releases wide; v2.0.1 ships and shakes out read-path in production before v2.1 flips write path.

---

**H10 — Windows wire-and-merge without VM is dishonest** (release F2)

Break: v2.0.1 PR-VP-C1 allowed to merge without fresh-profile Windows 11 VM smoke (C2 external). If merged, tray shows "Daemon running" on Windows while tokens silently don't refresh.

Resolution: split PR-VP-C1 into

- **PR-VP-C1a** — code merge, feature-flagged OFF on Windows (`#[cfg(all(windows, feature = "windows-daemon"))]`)
- **PR-VP-C1b** — flag flip after fresh-profile VM smoke green

PR-VP-C1a lands in v2.0.1. PR-VP-C1b ships in v2.0.2 or v2.1 after C2 resolves.

---

**H11 — Codex §5.7 capture is single point of failure contradicting release cut criteria** (release F3)

Break: release cut criteria lists "One successful wham/usage live probe captured" as HARD gate. Risk flag 1 says parser ships `PROVISIONAL` if account unavailable. Documents disagree — zero-tolerance Rule 5 violation.

Resolution: reclassify Codex account as **external provisioning blocker** (same class as L1 Apple cert, L3 Windows EV). Two paths:

- **Path A** — v2.1 release authorization blocked until maintainer provisions a Codex account and captures journal 0008. Default.
- **Path B** — If Path A stalls >N weeks, drop PR-C5 from v2.1 cut and ship Codex **quota integration** in v2.1.1. Requires explicit release-authorization decision by user.

Plan amendment: remove the risk-flag softening; add the named blocker with path-A/path-B choice to release cut criteria.

---

**H12 — v2.0.1 has no red-team convergence PR** (release F5)

Break: v2.0.1 touches 7 PRs across credential/quota/daemon paths. v2.1 gets PR-C9 convergence; v2.0.1 gets nothing. A1 specifically reshapes the exact file that corrupted `config-N` in alpha.21.

Resolution: add **PR-VP-final** to v2.0.1 plan — two-agent redteam convergence (one agent attacks A1 handle-dir walk, one attacks B5/B6/VP-C1a IPC parity). Scope: ≤0.5 session per agent. Cut criterion: every finding above LOW resolved inline per zero-tolerance Rule 5. Release notes land in PR-VP-final after convergence declares done.

---

### MEDIUM

**M1 — Codex PR-C9 convergence scope dishonest** (codex F5)

Break: 8 PRs × multi-round convergence ≠ one PR. User memory `feedback_redteam_efficiency` constrains to "3 parallel agents round 1 only; switch to 1 focused agent by round 3."

Resolution: split PR-C9 into

- **PR-C9a** — redteam round 1, 3 parallel agents across C1-C8
- **PR-C9b** — redteam round 2, 1 focused agent on round-1 residuals
- **PR-C9c** — convergence declaration + release notes

Each PR has a journal entry closing the round. Release notes land only in PR-C9c.

---

**M2 — Concurrent spec edits PR-G0 vs PR-C1** (gemini F2)

Break: both touch spec 07. PR-C1 §7.1 restructure + PR-G0 §7.2.3 pin can collide on section numbering.

Resolution: section-ownership split documented in ROADMAP and this journal —

- **Codex owns**: spec 07 §7.1 (enum/catalog), §7.3.3 (Codex login), §7.7 (gates), spec 05 §5.7
- **Gemini owns**: spec 07 §7.2.3 (GEMINI_CLI_HOME), §7.3.4 (Gemini provision), spec 05 §5.8
- **Shared**: spec 07 §7.4 (quota.json schema) — PR-C1.5 (new) designs once for both

---

**M3 — Gemini parallelism is only 16%** (release F4)

Break: only PR-G0 runs parallel with Codex PR-C1. If Codex slips (OPEN-C02 negative forcing PR-C3 redesign), Gemini slips 1:1.

Resolution: identify Gemini work independent of Surface enum —

- `platform::secret` macOS/Linux/Windows backends (new files, no Surface dep)
- ToS-guard EP1-EP7 scaffolding (new files)
- `reassert_api_key_selected_type` drift detector (new helper)

Use const placeholder `const SURFACE_GEMINI: &str = "gemini";` in these PRs; swap to enum in PR-G1. Split PR-G2 scope: **PR-G2a** (Surface-independent scaffolding, land parallel with Codex) + **PR-G2b** (Surface-dependent wiring, after PR-G1). Gemini becomes independently shippable as v2.1.5 API-key-only-surface if Codex slips badly.

---

**M4 — `.session-notes` as uncommitted authority** (release F6)

Break: `.session-notes` cited by ROADMAP and v2.0.1 plan as authoritative. It's modified and uncommitted. No frontmatter, no sequential ID, mutable across sessions. FM-3 (multi-session amnesia) masquerading as authority.

Resolution: promote authoritative content to **journal 0068** (new, proper frontmatter, immutable per journal.md Rule "No Overwriting"). Remove `.session-notes` from authoritative-inputs lists. Demote `.session-notes` to scratch status. The v2.0.1 backlog is now journal 0068, not session notes.

---

## New plan items created

| ID                            | Source finding | Added to                                     |
| ----------------------------- | -------------- | -------------------------------------------- |
| PR-B8                         | H9             | v2.0.1 patch plan                            |
| PR-VP-C1a / PR-VP-C1b         | H10            | v2.0.1 patch plan (split)                    |
| PR-VP-final                   | H12            | v2.0.1 patch plan                            |
| PR-C00                        | H4             | Codex plan (split)                           |
| PR-C0.5 (conditional)         | H4             | Codex plan                                   |
| PR-C1.5                       | H1             | Codex plan (between C1 and C6)               |
| PR-C9a / PR-C9b / PR-C9c      | M1             | Codex plan (split of C9)                     |
| OPEN-C05 gate                 | H6             | Codex plan gate table                        |
| PR-G2a / PR-G2b               | M3             | Gemini plan (split of G2)                    |
| Journal 0068 (v2.0.1 backlog) | M4             | new entry, replaces .session-notes authority |

## Contradictions closed

- L2 release-checklist text at `04-v2-stable-release-checklist.md:217-222` remains a separate task (#2) — independent of red-team findings.
- §6a release-checklist scope drift remains resolved by journal 0068 becoming the authoritative backlog.

## For Discussion

1. H11 (Codex account provisioning as external blocker) creates a dependency csq has never had before — a paid third-party subscription for the maintainer. Is that acceptable given the Foundation-independence rule, or does it require a Foundation-provisioned test account? If the maintainer personally funds it, do we capture and PII-scrub ONE snapshot into the repo forever, or re-capture on every spec drift?

2. Resolution C-CR2 introduces a persistent file (`gemini-events-<slot>.ndjson`) that outlives any single CLI process. This is architecturally novel for csq — every other state file is owned by the daemon. Does this create a new security surface (the ndjson log contains timestamps + slot numbers, not tokens, but it's a spawn-activity record)? Should it be 0600 + gitignored + pruned on quota.json commit?

3. If EP4 whitelist maintenance (C-CR1 resolution) proves infeasible when gemini-cli ships a breaking version change, the Gemini stream's ToS compliance story collapses. Does v2.2 need a named fallback — e.g. "csq refuses Gemini spawn if gemini-cli version is above pinned N" — or does csq's role end at "we did 6 of 7 layers right, the 7th is advisory"?
