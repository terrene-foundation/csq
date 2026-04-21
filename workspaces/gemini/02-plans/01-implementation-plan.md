# csq-gemini — Implementation Plan (v2.2.0 release)

Adds Google Gemini as a third surface. API-key only — OAuth subscription rerouting rejected per Google ToS with 7-layer guard (no disable knob). Event-driven quota with CLI-durable event log.

**Authoritative inputs**: `briefs/01-vision.md`, `01-analysis/01-research/`, `journal/0001..0002`, `specs/07-provider-surface-dispatch.md` v1.0.2, `specs/05-quota-polling-contracts.md` §5.8.

**Coordination**: `workspaces/ROADMAP.md` — release sequence; `workspaces/codex/02-plans/01-implementation-plan.md` — upstream shared-spine; `workspaces/csq-v2/journal/0067` — red-team convergence.

**Red-team amendments**: C-CR1 (EP4 disable knob removed), C-CR2 (CLI-durable NDJSON event log), H7 (event-delivery contract pinned in spec 07 §7.2.3), H8 (platform::secret sole ownership), M2 (section-ownership split), M3 (PR-G2 split for parallelism).

---

## Scope recap

Gemini ships **API-key only** (AI Studio paste or Vertex SA JSON path). OAuth subscription rerouting rejected per Google ToS with active 7-layer defense (EP1–EP7). All 7 mandatory — no disable knob.

Versus Codex:

- no OAuth refresh subsystem, no daemon prerequisite for spawn (ADR-G09, INV-P02 inverted)
- **event-driven quota with CLI-durable NDJSON event log** — CLI writes `gemini-events-<slot>.ndjson` with `O_APPEND` + `fsync`; daemon drains on startup/reconnect; single-writer-to-quota.json invariant preserved
- new `platform::secret` encryption-at-rest primitive (owned solely by Gemini PR-G2a)
- 7-layer ToS-guard with versioned whitelist pinned to gemini-cli minor release

---

## Guiding principles

1. **Surface dispatch is shared with Codex** — PR-G1 extends `Surface` enum, no new dispatch architecture.

2. **API key lifecycle is load-bearing** — encrypted at rest; stdin-only on CLI; never in argv or event payloads. Redactor covers `AIza*` and PEM.

3. **Drift detector runs on every spawn** (EP1). Ships in PR-G2a; not separable.

4. **Single-writer-to-quota.json preserved via CLI-durable event log** (C-CR2). CLI never writes `quota.json` directly; CLI writes NDJSON events that outlive the CLI process; daemon drains events and writes quota.json atomically. Events are durable across daemon-down periods.

5. **Gemini does NOT require daemon to spawn** (INV-P02 inverted). Event-delivery contract pinned in spec 07 §7.2.3 (non-blocking 50ms connect; drop-on-unavailable semantics; NDJSON fallback log).

6. **No disable knob on EP4** (C-CR1). If whitelist maintenance proves infeasible, csq reclassifies EP4 as advisory and updates positioning — disable knob is not an option.

---

## Pre-implementation gates

| Gate                                     | Verification                                                                                                                                                                                                                                                           | Journal           | Effort      |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----------- |
| OPEN-G01                                 | Empirical: seed `~/.gemini/settings.json` with `selectedType=oauth-personal` + `oauth_creds.json`; run `GEMINI_CLI_HOME=/tmp/x gemini -p "ping"`; inspect auth header. If user-level wins → PR-G2a drift detector branches to "refuse provisioning" or "active rename" | 0003              | 0.3 session |
| OPEN-G02                                 | Live capture: REST `generateContent` + SSE `streamGenerateContent` probes; record `modelVersion` location each. Env precedence: `/tmp/.env` (bad) vs `Command::env` (good). Pin outcomes in spec 05 §5.8 + spec 07 §7.2.3                                              | 0004              | 0.5 session |
| **Event-delivery contract** (new per H7) | Pin in spec 07 §7.2.3 as part of PR-G0: socket-path resolution rule (`$XDG_RUNTIME_DIR/csq.sock` or `~/.claude/accounts/csq.sock`); non-blocking connect timeout 50ms; drop-on-unavailable semantics with structured log; NDJSON fallback durability contract          | (PR-G0 spec edit) | 0.2 session |

---

## PR sequence

### PR-G0 — chore(gates): OPEN-G01/G02 + event-delivery contract (docs-only)

- `workspaces/gemini/journal/0003-DISCOVERY-gemini-auth-precedence.md`
- `workspaces/gemini/journal/0004-DISCOVERY-gemini-response-shape-and-env-precedence.md`
- `specs/07-provider-surface-dispatch.md` §7.2.3 — pin auth precedence + event-delivery contract (H7)
- `specs/05-quota-polling-contracts.md` §5.8 — pin `modelVersion` location + env precedence + NDJSON event log durability contract

**Tests**: none (docs).

**Depends on**: nothing. **Parallel with Codex PR-C1.**

---

### PR-G2a — feat(core): platform::secret + ToS-guard scaffolding + drift detector (Surface-independent)

**Per M3 — split for parallelism.** Uses const placeholder `const SURFACE_GEMINI: &str = "gemini";`. PR-G1 swaps to enum.

- `csq-core/src/platform/secret/{macos,linux,windows}.rs` — **sole ownership per H8**. macOS Keychain, Linux keyring, Windows DPAPI backends. `security-reviewer` sign-off on all three backends is a PR-gate (not release-gate).
- `csq-core/src/providers/gemini/{mod,keyfile,settings,probe,spawn,capture}.rs` — new module. Uses const placeholder for surface.
- `csq-core/src/error.rs` — extend `redact_tokens` for `AIza*`, PEM, Google error-code allowlist
- Lint: ban direct `Command::new("gemini")` outside `spawn_gemini`
- Env allowlist per security §3.3
- Pre-spawn `.env` scan (EP2/EP3/EP6)
- `reassert_api_key_selected_type(handle_dir)` drift detector (EP1) — called before every exec
- EP4 response-body sentinel with **versioned whitelist** pinned to `gemini-cli` minor release. Auto-update whitelist on `gemini --version` mismatch via dialog. Log first-hit telemetry for whitelist tuning. **No disable knob** (C-CR1).

**Tests**: settings-preseed survives respawn; key never fallthrough to env file; env introspection shows allowlist; redactor cases 1-7; whitelist regression against pinned gemini-cli minor.

**Depends on**: PR-G0. **Can land before Codex PR-C1 per M3.**

---

### PR-G1 — feat(providers): Surface::Gemini variant + site extensions

- `csq-core/src/providers/catalog.rs` — Gemini entry per spec 07 §7.1.2
- Surface-dispatched site extensions across refresher.rs (skip), auto_rotate.rs (same-surface filter), usage_poller/anthropic.rs cooldowns, discovery.rs (genai URLs), handle_dir.rs (`ACCOUNT_BOUND_ITEMS` surface-param), credentials/file.rs (preservation no-op), error.rs (error_kind_tag Gemini), rotation/swap.rs (no preservation)

**Tests**: 7 regressions from risk analysis §3.

**Depends on**: **Codex PR-C1** (Surface enum on main).

---

### PR-G2b — feat(providers): wire PR-G2a scaffolding into Surface::Gemini

- Flip const `SURFACE_GEMINI` placeholders → real `Surface::Gemini` enum usages
- Wire `providers::gemini::spawn::spawn_gemini` into Surface dispatch chain
- Capability-manifest audit for new Tauri commands (H1 audit applied to Gemini)

**Tests**: spawn dispatches via enum; capability narrowing covers new commands.

**Depends on**: PR-G1, PR-G2a.

---

### PR-G3 — feat(daemon): event-driven Gemini consumer + CLI-durable NDJSON event log

**Per C-CR2 — CLI-durable event log is the load-bearing change from the original plan.**

- `csq-core/src/providers/gemini/capture.rs` (extends PR-G2a) — event emitter writes `~/.claude/accounts/gemini-events-<slot>.ndjson` with `O_APPEND` + `fsync` per event. File 0600. One line per event, JSON-encoded.
- `csq-core/src/daemon/usage_poller/gemini.rs` — IPC consumer + NDJSON drain. On daemon startup: enumerate `gemini-events-*.ndjson`, parse each line, apply to quota.json atomically (per-slot mutex), truncate log. On reconnect: drain recent entries. Live IPC path still exists for same-session immediacy; NDJSON is the durability floor.
- New IPC message types: `GeminiCounterIncrement`, `GeminiRateLimited`, `GeminiEffectiveModelObserved`
- Midnight-America/Los_Angeles reset task (tokio `sleep_until`)
- Response-body sentinel (EP4) via csq-cli stderr wrapper (versioned whitelist from PR-G2a)
- Schema-drift circuit breaker (5-strike → `QuotaKind::Unknown`)
- Quota.json v2 extension (Gemini-reserved fields from Codex PR-C1.5): `counter`, `rate_limit`, `selected_model`, `effective_model`, `mismatch_count_today`, `is_downgrade`
- **Capability-manifest audit** per H1 — new IPC commands accounted for in `src-tauri/capabilities/main.json`

**Tests**:

- `ndjson_event_survives_daemon_restart` — write event with daemon down, start daemon, drain, assert quota.json reflects event
- `ndjson_log_truncated_after_successful_drain`
- `effective_model_recorded_on_response`
- 429 fixture parsed
- Schema-drift → circuit breaker → `QuotaKind::Unknown`
- Midnight reset fires (virtual clock)
- Live IPC + NDJSON dual-path do not double-count (same event ID)
- `event_sent_from_cli_when_daemon_alive_reaches_handler` (H7 test)

**Depends on**: PR-G2b; Codex PR-C1.5 (quota schema frozen with Gemini fields).

---

### PR-G4 — feat(cli): Gemini surface-aware spawn + setkey + models switch

- `csq-cli/src/commands/setkey.rs` — Gemini branch, stdin-only (FR-G-CLI-03)
- `csq-cli/src/commands/run.rs` — surface-dispatches to `spawn_gemini`
- `csq-cli/src/commands/models.rs` — writes `settings.json` `model.name` via atomic_replace under per-slot mutex
- `csq-cli/src/commands/swap.rs` — cross-surface exec-in-place (INV-P05)
- `csq login --provider gemini` refuses (FR-G-CLI-06)

**Tests**: `setkey_gemini_argv_refused`; `models_switch_writes_settings_atomically`; `cross_surface_swap_from_gemini_cleans_handle_dir`.

**Depends on**: PR-G3.

---

### PR-G5 — feat(desktop): Gemini UI

- `AddAccountModal.svelte` — 2 tabs (AI Studio paste / Vertex SA); ToS disclosure; oauth_creds residue warning
- `ChangeModelModal.svelte` — static list + preview note
- `AccountCard.svelte` — Gemini chip + downgrade badge + "quota: n/a" rendering when events not yet drained
- Tauri commands: `gemini_provision`, `gemini_switch_model`, `gemini_probe_tos_residue` — no secret fields in Serialize outputs

**Tests**: null-state rendering of `effective_model`; Tauri IPC audit (no plaintext key).

**Depends on**: PR-G4.

---

## Shared vs divergent code with Codex

### Shared (owned by Codex PRs — cited, not redefined)

- `Surface` enum — Codex PR-C1
- Quota.json v2 schema including Gemini-reserved fields — Codex PR-C1.5
- Quota write-path flip — Codex PR-C6
- Cross-surface swap INV-P05/INV-P10 — Codex PR-C7
- Auto-rotation same-surface filter INV-P11 — Codex PR-C1 (flipping v2.0.1 PR-A1 stub)
- `error_kind_tag` enum — both extend

### Gemini sole-owned (per H8, M3)

- `platform::secret` encryption-at-rest primitive (Codex does NOT use it)
- 7-layer ToS guard EP1–EP7 with versioned whitelist + no disable knob
- CLI-durable NDJSON event log (`gemini-events-<slot>.ndjson`)
- Event-delivery contract (socket-path resolution, 50ms connect, drop-on-unavailable)
- Midnight-LA reset task
- Client-side counter + 429 parser
- Per-response `modelVersion` capture + debouncer
- `~/.gemini/oauth_creds.json` residue modal
- Vertex temp-file 0600 spawn handshake

---

## Drift-detector FR-G-CORE-04

Lands in **PR-G2a** (not standalone). One helper `reassert_api_key_selected_type(handle_dir)` called inside `spawn_gemini` before every exec. Branches on OPEN-G01 outcome: if user-level wins, PR-G2a must actively refuse provisioning or rename `oauth_creds.json`. Observational tuning applies only to the silent-downgrade detector debounce window.

---

## Risk flags

1. **EP4 whitelist maintenance cadence.** Whitelist pinned to gemini-cli minor release. If Google ships a patch that changes OAuth-execution stderr strings, EP4 either rejects the new version (version-mismatch dialog) or accepts with updated whitelist. If maintenance cadence proves infeasible (e.g. gemini-cli releases weekly with breaking stderr changes), v2.2 updates positioning to "EP4 is advisory" — reclassification, not disable knob. Documented per zero-tolerance Rule 5 "external dependency" exception.

2. **Silent-downgrade detector false positives.** 3-in-5-minute debounce is a guess; tune from observational data. Config knob on the debounce window is acceptable (not a ToS control).

3. **NDJSON event log as new security surface.** Log contains timestamps + slot numbers, not tokens. 0600 permissions + gitignored + pruned on daemon drain. New file outside csq's prior state-ownership model — documented in spec 05 §5.8 by PR-G0.

4. **PR-G1 blocks on Codex PR-C1.** Mitigated per M3 by moving platform::secret + ToS-guard scaffolding to PR-G2a which runs parallel.

---

## Release cut criteria

v2.2.0 ships when:

- [ ] OPEN-G01/G02 RESOLVED with verification journals
- [ ] Event-delivery contract pinned in spec 07 §7.2.3
- [ ] Codex v2.1.0 shipped (hard prerequisite)
- [ ] PR-G0 through PR-G5 merged
- [ ] `cargo test --workspace` green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `npm run test` + `svelte-check --fail-on-warnings` clean
- [ ] 7-layer ToS-guard: each EP exercises a test case; whitelist regression test green
- [ ] NDJSON event log durability verified: daemon-down → events queue → daemon-up → quota reflects queued events
- [ ] Silent-downgrade detector config knob documented
- [ ] `.env` short-circuit scan verified against real `.env` in CWD
- [ ] `platform::secret` security-reviewer sign-off on all three backends
- [ ] Release notes enumerate: API-key-only, ToS disclosure, no-daemon-required-to-spawn, NDJSON durability contract, EP4 whitelist pinned to gemini-cli version
