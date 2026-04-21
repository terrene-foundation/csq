# csq — Post v2.0.0 Unified Roadmap

Cross-workspace coordination. Three parallel workstreams exist after v2.0.0 shipped (2026-04-22). This document is the single source of truth for landing order, blocking dependencies, and release cut-points. Per-workspace plans (`csq-v2/02-plans/`, `codex/02-plans/`, `gemini/02-plans/`) own the detailed PR breakdown.

**Red-team convergence**: plans amended per `csq-v2/journal/0067-DECISION-redteam-post-v2.0.0-plan-convergence.md` (19 findings resolved in-session per `zero-tolerance.md` Rule 5). All references below reflect post-convergence state.

**Authoritative inputs**:

- `csq-v2/journal/0062..0068` — v2.0.0 gate definition, security audit, auto-rotate discovery, red-team convergences, codified lessons, post-v2.0.0 red-team (0067), v2.0.1 backlog (0068)
- `codex/01-analysis/01-research/` + `codex/journal/0001..0004` — Codex provider research
- `gemini/01-analysis/01-research/` + `gemini/journal/0001..0002` — Gemini provider research
- `specs/07-provider-surface-dispatch.md` v1.0.2 (INV-P01 through INV-P11)
- `specs/05-quota-polling-contracts.md` v1.2.0 (§5.7 Codex PROPOSED, §5.8 Gemini PROPOSED)

`.session-notes` is scratch status only, NOT authoritative (per journal 0067 M4; backlog promoted to journal 0068).

---

## Release sequence

| Release             | Scope                                                                                     | Gate                                                                                      | Ships when                                               |
| ------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| **v2.0.1 patch**    | Safety fixes + quota.json dual-read shakedown + Windows daemon code (feature-flagged off) | A1+B5+B6+B8 green; VP-final redteam convergence                                           | Workstream V2-P complete                                 |
| **v2.1.0 — Codex**  | Surface dispatch refactor + Codex integration + quota.json v2 write-path flip             | All INV-P\* satisfied; OPEN-C02/C03/C04/C05 resolved; journal 0008 captured               | Workstream V2-P + codex PR-C9c complete                  |
| **v2.2.0 — Gemini** | Gemini integration on top of surface dispatch                                             | OPEN-G01/G02 resolved; EP1-EP7 ToS guard shipped (no disable knob); CLI-durable event log | Workstream V2-P + codex complete + gemini PR-G5 complete |

**Why v2.1 minor-bump not v2.0.2**: quota.json schema v2 is a one-way write-path flip. PR-B8 (added by redteam convergence H9) ships v1+v2 dual-read in v2.0.1 so v2.1 only flips the write path. The shakedown window is a full release wide.

---

## The shared spine (expanded after redteam)

Four collision points across streams, not one (per journal 0067 H1):

### Primary — `csq-core/src/providers/catalog.rs`

Surface enum refactor (Codex PR-C1). Blocks Gemini PR-G1. Extends `Provider` per spec 07 §7.1.1.

### Quota schema — `csq-core/src/quota/state.rs` + spec 07 §7.4

Codex PR-C6 flips write path to v2. Gemini PR-G3 extends v2 with counter fields. Schema-design-once gate: **PR-C1.5 — quota schema freeze review** lands between PR-C1 and PR-C6, designing v2 against both Codex and Gemini consumer shapes.

### Dispatch table — `csq-core/src/daemon/usage_poller/mod.rs`

Codex PR-C1 (surface-dispatch scaffold), PR-C5 (Codex entry), Gemini PR-G3 (Gemini entry). Three PRs across two streams — land sequentially per plan's PR order.

### IPC + Tauri capability manifest

New IPC commands reopen the capability-narrowing audit from journal 0065 B3. Codex PR-C1 scope gains a one-line capability-manifest audit; Gemini PR-G3 repeats audit for Gemini message types.

---

## Spec 07 section ownership (prevents concurrent-edit collisions, per journal 0067 M2)

| Section                                            | Owner                                                    | Ships in        |
| -------------------------------------------------- | -------------------------------------------------------- | --------------- |
| §7.1 Surface enum + catalog                        | Codex PR-C1                                              | v2.1.0          |
| §7.2.2 Codex handle-dir layout                     | Codex PR-C3                                              | v2.1.0          |
| §7.2.3 Gemini handle-dir + event-delivery contract | Gemini PR-G0                                             | v2.2.0          |
| §7.3.3 Codex login                                 | Codex PR-C3                                              | v2.1.0          |
| §7.3.4 Gemini provisioning                         | Gemini PR-G2                                             | v2.2.0          |
| §7.4 quota.json v2 schema (SHARED)                 | PR-C1.5 (new)                                            | v2.1.0          |
| §7.7 open preconditions                            | Codex PR-C00 (Codex gates) + Gemini PR-G0 (Gemini gates) | v2.1.0 / v2.2.0 |

---

## Workstream V2-P — v2.0.1 Safety Patch

Goal: close high-impact deferred items + ship quota.json dual-read so v2.1's write-path flip has a shakedown release.

Detailed plan: `csq-v2/02-plans/05-v2.0.1-patch-plan.md`
Backlog authority: `csq-v2/journal/0068-GAP-v2.0.1-backlog-authoritative-inventory.md`

Must-do PRs:

| ID          | Deliverable                                                 | Notes                                                               |
| ----------- | ----------------------------------------------------------- | ------------------------------------------------------------------- |
| PR-A1       | auto-rotate Option A (with Surface::ClaudeCode filter stub) | Stub flips to real enum in Codex PR-C1                              |
| PR-A2       | `csq run N` re-materialize term-<pid>/settings.json         | Same spec surface as A1                                             |
| PR-B5       | broker::sync subscription_type preservation                 | MED user-visible                                                    |
| PR-B6       | bind_provider_to_slot RMW                                   | Prevents silent settings loss                                       |
| PR-B8       | quota.json v1+v2 dual-read                                  | **Added by redteam convergence** (H9); shakedown for v2.1 migration |
| PR-VP-C1a   | Windows daemon supervisor wiring — feature-flagged off      | Code merges; flag stays off until VM smoke                          |
| PR-VP-C1b   | flag flip after fresh-profile Win11 VM smoke                | External gate (C2); ships in v2.0.2 or rolls into v2.1              |
| PR-B2       | fixed error-kind tag migration                              | Hardening                                                           |
| PR-B7       | parking_lot migration                                       | LOW hardening                                                       |
| PR-VP-final | two-agent redteam convergence + release notes               | **Added by redteam convergence** (H12)                              |

External-infra: L1 Apple cert, L3 Windows EV cert, L4/C2 Windows VM provisioning, C5 alpha.21→2.0.0 update UX validation.

---

## Workstream V2.1-Codex — Codex Integration

Detailed plan: `codex/02-plans/01-implementation-plan.md`

PR sequence (post-convergence):

| PR      | Scope                                                                                    | Notes                                                                  |
| ------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| PR-C00  | three verification journals (0005/0006/0007) + spec status flips                         | **Split from PR-C0** (H4); docs-only                                   |
| PR-C0   | redactor extension + `secure_file_readonly()` + integration test                         | code-only                                                              |
| PR-C0.5 | (conditional) transport ADR journal 0009 + endpoint handlers                             | fires only if OPEN-C04 resolves "Node transport required"              |
| PR-C1   | Surface enum + behaviour-neutral refactor                                                | SHARED SPINE — blocks Gemini PR-G1                                     |
| PR-C1.5 | quota schema freeze review (Codex + Gemini consumer shape)                               | **Added by redteam convergence** (H1)                                  |
| PR-C2   | CredentialFile surface split                                                             |                                                                        |
| PR-C3   | Codex login orchestration                                                                |                                                                        |
| PR-C4   | refresher Codex extension + startup reconciler + **Windows named-pipe integration test** | Windows test added by H2                                               |
| PR-C5   | usage_poller codex module                                                                | Ships `PROVISIONAL` if no real capture; PII-scrub script in scope (H5) |
| PR-C6   | quota.json v1→v2 write-path flip                                                         | reads stay dual per PR-B8                                              |
| PR-C7   | swap cross-surface + models switch                                                       |                                                                        |
| PR-C8   | Codex desktop UI                                                                         |                                                                        |
| PR-C9a  | redteam round 1 (3 parallel agents)                                                      | **Split from PR-C9** (M1)                                              |
| PR-C9b  | redteam round 2 (1 focused agent)                                                        |                                                                        |
| PR-C9c  | convergence + release notes                                                              |                                                                        |

Gates (updated):

- **OPEN-C01** RESOLVED — journal 0004 via openai/codex source read
- **OPEN-C02** (CODEX_HOME honor) — pre-capture kill-switch added per H3: if resolves negative, journal 0008 capture BLOCKED until wrapper mitigation + `~/.codex/` pre-snapshot
- **OPEN-C03** (remove_dir_all symlink safety) — integration test
- **OPEN-C04** (Cloudflare fingerprint) — resolution decides if PR-C0.5 fires
- **OPEN-C05** (error-body echo investigation) — **new gate per H6**; three deliberately-bad refresh requests; PR-C4 starts with this RESOLVED
- **§5.7 live capture** (journal 0008) — now an explicit external provisioning blocker per H11. Two paths: (A) maintainer provisions Codex account, captures; (B) if stalled, defer PR-C5 quota work to v2.1.1. User authorization required for Path B.

---

## Workstream V2.2-Gemini — Gemini Integration

Detailed plan: `gemini/02-plans/01-implementation-plan.md`

PR sequence (post-convergence):

| PR     | Scope                                                                                                                | Notes                                                 |
| ------ | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| PR-G0  | close OPEN-G01/G02 + pin event-delivery contract in spec 07 §7.2.3                                                   | parallel with Codex PR-C1                             |
| PR-G1  | Surface::Gemini variant + surface-dispatched extensions                                                              | **blocked by Codex PR-C1**                            |
| PR-G2a | `platform::secret` + ToS-guard EP1-EP7 scaffolding + drift detector (Surface-independent via const placeholder)      | **Split for parallelism** (M3); can land pre-PR-C1    |
| PR-G2b | wire PR-G2a into Surface::Gemini                                                                                     | after PR-G1                                           |
| PR-G3  | event-driven daemon consumer + **CLI-durable event log (NDJSON + daemon startup drain)** + capability-manifest audit | **event-log added by C-CR2**; no disable knob (C-CR1) |
| PR-G4  | cli surface-aware spawn + setkey + models switch                                                                     |                                                       |
| PR-G5  | desktop UI                                                                                                           |                                                       |

Gates:

- **OPEN-G01** (`GEMINI_CLI_HOME` shields user-level settings?) — PR-G0
- **OPEN-G02** (modelVersion field REST vs SSE + `.env` precedence) — PR-G0
- **Event-delivery contract** — socket-path resolution rule, 50ms non-blocking connect, drop-on-unavailable semantics pinned in spec 07 §7.2.3 by PR-G0 (per H7)
- **EP4 whitelist versioning** — PR-G3 tests regression against pinned gemini-cli minor version; NO config knob (per C-CR1)

`platform::secret` ownership: **Gemini PR-G2a owns it** (H8). Codex does NOT use it.

---

## Cross-stream dependency map (post-convergence)

```
V2-P (v2.0.1 safety patch)
  PR-A1 auto-rotate (with Surface stub) ──┐
  PR-A2 run.rs settings ──┐               │
  PR-B5/B6 subscription guards ──────┐    │
  PR-B8 quota dual-read ─────────────┤    │ ◀── shakedown for v2.1 migration
  PR-VP-C1a (flagged off) ───────────┤    │
  PR-B2/B7 hardening ────────────────┤    │
  PR-VP-final redteam ───────────────┘    │
                                          │
                                          └──> ship v2.0.1
                                                │
                                                v
V2.1-Codex                                      │
  PR-C00 docs-only gates ──┐                    │
  PR-C0 code gates ────────┤                    │
  PR-C0.5 (cond) transport │                    │
  PR-C1 Surface enum ──────┤ ◀── shared spine   │
  PR-C1.5 quota schema ────┤ ◀── NEW           │
  PR-C2 creds split        │                    │
  PR-C3 codex login        │ (OPEN-C02 kill-    │
  PR-C4 refresher + win    │  switch if neg)    │
  PR-C5 usage_poller       │                    │
  PR-C6 quota write-flip   │                    │
  PR-C7 swap + models      │                    │
  PR-C8 desktop UI         │                    │
  PR-C9a/b/c convergence ──┘                    │
                                                │
                                                └──> ship v2.1.0
                                                       │
                                                       v
V2.2-Gemini
  PR-G0 journals + contract ────────┐
  PR-G2a scaffolding ───────────────┤ ◀── parallel with Codex
  PR-G1 Gemini variant ─────────────┤ ◀── needs Codex PR-C1
  PR-G2b wire scaffolding           │
  PR-G3 event-driven + NDJSON log   │
  PR-G4 cli surface-aware           │
  PR-G5 desktop UI ─────────────────┘
                                         │
                                         └──> ship v2.2.0
```

---

## Contradictions closed (flagged at plan creation, resolved in redteam)

1. Release-checklist stale L2 text — still open as task #2 (independent of redteam).
2. Checklist §6a scope drift — resolved. Journal 0068 is the authoritative v2.0.1 backlog.
3. Journal 0064 §For Discussion Q1 (0018 vs live code) — still open as task #3 (pre-work for PR-A1).

---

## Session-local housekeeping

Uncommitted edits (committed by task #1):

- `specs/_index.md` (M) — registers spec 07
- `specs/02-csq-handle-dir-model.md` (M) — §2.8 cross-reference
- `specs/05-quota-polling-contracts.md` (M) — §5.7 + §5.8
- `specs/07-provider-surface-dispatch.md` (??) — new spec

`.session-notes` is NOT committed by task #1. Per journal 0067 M4, it is demoted to scratch status; its authoritative content now lives in journal 0068.

Operational cleanup (owner: user):

- `rm -rf "/Applications/Code Session Quota.app.alpha.4.bak"`

---

## Convention for cross-workspace references

When a PR in one workspace touches a file owned by another workspace's plan, the PR description MUST cite the other workspace's PR that defines the contract. Example: codex PR-C1 defines the Surface enum → gemini PR-G1 description links to PR-C1 merge commit. Post-C1 merge, the ROADMAP gets a one-line SHA annotation under "shared spine."
