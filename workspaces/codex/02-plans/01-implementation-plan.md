# csq-codex — Implementation Plan (v2.1.0 release)

Adds Codex (OpenAI ChatGPT subscription) as a first-class `Surface` alongside ClaudeCode. Surface dispatch + daemon pre-expiry refresh + wham/usage polling + desktop UX.

**Authoritative inputs**: `briefs/01-vision.md`, `01-analysis/01-research/`, `journal/0001..0004`, `specs/07-provider-surface-dispatch.md` v1.0.2, `specs/05-quota-polling-contracts.md` §5.7.

**Coordination**: `workspaces/ROADMAP.md` — release sequence; `workspaces/csq-v2/journal/0067` — red-team convergence (findings applied below).

**Red-team amendments**: H1 (PR-C1.5 quota schema freeze added), H2 (PR-C4 gains Windows named-pipe integration test), H4 (PR-C0 split into C00/C0/C0.5), H5 (PR-C5 PII scrub + gitignore + PROVISIONAL tag), H6 (OPEN-C05 error-body echo gate), H11 (§5.7 external provisioning blocker), M1 (PR-C9 split into C9a/C9b/C9c), C-CR3 (OPEN-C02 negative-resolution kill-switch).

---

## Scope recap

csq-codex adds Codex as a first-class `Surface`. Surface enum + dispatch in `providers::catalog`; behaviour-neutral refactor of existing providers to `Surface::ClaudeCode`; `providers::codex` module (device-auth login + pre-seeded `config.toml`); `daemon::refresher` + `daemon::usage_poller` surface-dispatched; `quota.json` v2 write-path flip (read path landed in v2.0.1 PR-B8); token redaction for `sess-*` + JWT; desktop UX (AddAccountModal, ChangeModelModal live fetch, ToS disclosure, keychain-residue probe).

**NOT** building: translation proxy, CC feature parity, Windows-at-v2.1, Team/Enterprise pooling.

---

## Guiding principles

1. **Surface dispatch is the contract** (spec 07 §7.1.2).
2. **Daemon is a hard prerequisite** for Codex (INV-P02). No in-process refresh fallback.
3. **Pre-expiry by 2h** (INV-P01). Clock-skew via HTTP `Date` header.
4. **One-way write-path flip** at v2.1 — read compatibility landed in v2.0.1 PR-B8 for shakedown.
5. **Structural defence first** (journal 0065 B2 pattern).

---

## Pre-implementation gates

All MUST be RESOLVED before the blocking PR merges. Gates live in `workspaces/codex/journal/`.

| Gate                       | Verification                                                                                                                                                                                                                                                                                                                                                                                                                       | Journal     | Blocks       |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------ |
| OPEN-C01                   | RESOLVED 2026-04-22 via openai/codex source read                                                                                                                                                                                                                                                                                                                                                                                   | 0004        | done         |
| OPEN-C02                   | `CODEX_HOME=/tmp/x codex -e 'print("hi")' && find /tmp/x ~/.codex -newer /tmp/x` — record paths. **Kill-switch per C-CR3**: if resolves negative (codex ignores `CODEX_HOME` for sessions/history), §5.7 capture (journal 0008) is BLOCKED until (a) wrapper-script mitigation implemented, (b) user `~/.codex/` pre-snapshotted via `rsync -a ~/.codex/ ~/.codex.bak-<ts>/`, (c) post-probe diff-and-delete of csq-injected rows. | 0005        | PR-C3        |
| OPEN-C03                   | `tests/integration_codex_sweep.rs`: symlink `term-<pid>/sessions → config-<N>/codex-sessions/` with sentinel; run `sweep_dead_handles`; assert sentinel survives on APFS + ext4                                                                                                                                                                                                                                                    | 0006        | PR-C3        |
| OPEN-C04                   | Live probe `auth.openai.com/oauth/token` + `chatgpt.com/backend-api/wham/usage` via reqwest/rustls + Node fetch + curl. If reqwest gets 403 where Node doesn't → reuse Node transport. **If resolved "Node transport required", fires PR-C0.5**.                                                                                                                                                                                   | 0007        | PR-C4, PR-C5 |
| **OPEN-C05** (new, per H6) | Error-body echo investigation per security-analysis §4 steps 1-4: three deliberately-bad refresh requests against `auth.openai.com/oauth/token`; inspect response bodies for echo of submitted refresh token prefix. If echo observed → refresher gains structural defence (SecretString across module).                                                                                                                           | new journal | PR-C4        |
| §5.7 schema capture        | ONE live `wham/usage` call against real Codex account; enumerate keys. **External provisioning blocker per H11**: Path A (maintainer provisions account) default; Path B (drop PR-C5 from v2.1 cut, ship quota in v2.1.1) requires user authorization.                                                                                                                                                                             | 0008        | PR-C5        |

---

## PR sequence

### PR-C00 — chore(gates): verification journals + spec status flips (docs-only)

**Split from PR-C0 per H4.** Documentation only; no code.

- `workspaces/codex/journal/0005..0007` — verification journals for OPEN-C02/C03/C04
- New journal for OPEN-C05 (error-body echo)
- `specs/07-provider-surface-dispatch.md` §7.7 statuses → RESOLVED with citations
- `specs/05-quota-polling-contracts.md` §5.7 transport note

**Depends on**: task #1 (specs committed).

---

### PR-C0 — feat(core): redactor extension + platform::fs helper (code)

- `csq-core/src/error.rs` — extend `KNOWN_TOKEN_PREFIXES` for `sess-*`; JWT triple-segment regex; `codex_*` variants in `error_kind_tag`; extend `OAUTH_ERROR_TYPES` with device-code error strings
- `csq-core/src/platform/fs.rs` — `secure_file_readonly()` (0o400 sibling of `secure_file()`)
- `tests/integration_codex_sweep.rs`

**Tests**: 5 redactor unit tests per §3.3 security analysis; 0o400 round-trip; sweep safety on APFS + ext4.

**Depends on**: PR-C00.

---

### PR-C0.5 — feat(http): Node transport Codex endpoint handlers (CONDITIONAL, fires only if OPEN-C04 "Node required")

- new journal 0009 (DECISION-codex-http-transport-via-node-subprocess)
- `csq-core/src/http/` — export Codex endpoint handlers reusing journal 0056 Node subprocess pattern

**Depends on**: PR-C0; OPEN-C04 resolved "Node required". If OPEN-C04 resolves "reqwest OK", this PR is skipped and PR-C4/C5 use existing reqwest path.

---

### PR-C1 — feat(providers): Surface enum + behaviour-neutral refactor (SHARED SPINE)

- `csq-core/src/providers/catalog.rs` — add `Surface`, `ModelConfigTarget`, `QuotaKind`; tag all 4 current providers `Surface::ClaudeCode`; add `Surface::Codex` stub
- `csq-core/src/accounts/discovery.rs` — `surface: Surface` on `AccountSource`
- `csq-core/src/daemon/refresher.rs:283,304` — rename `discover_anthropic` → `discover_refreshable`; filter on `Surface::ClaudeCode`
- `csq-core/src/daemon/usage_poller/mod.rs` + `anthropic.rs:21,46` — cooldowns keyed `(Surface, AccountNum)` (INV-P09)
- `csq-core/src/daemon/auto_rotate.rs:331` — **flip v2.0.1 PR-A1 stub** to real same-surface filter (INV-P11). Per journal 0067 H3.
- `csq-core/src/rotation/swap.rs:64` — subscription-preservation guard only if `Surface::ClaudeCode`
- `csq-core/src/session/handle_dir.rs:37-41` — surface-indexed `ACCOUNT_BOUND_ITEMS`
- **Capability-manifest audit** (per H1): one-line check that new IPC commands added by subsequent Codex PRs are accounted for in `src-tauri/capabilities/main.json` narrowing

**Tests**: 5 named regressions from risk analysis §3.

**Depends on**: PR-C0 (+ PR-C0.5 if fired).

**Post-merge**: tag SHA in ROADMAP "shared spine" for Gemini PR-G1 to cite.

---

### PR-C1.5 — chore(spec): quota schema v2 freeze review (NEW per H1)

**Purpose**: design quota.json schema v2 once to accommodate both Codex (utilization) and Gemini (counter) consumer shapes, before PR-C6 flips write path.

- `specs/07-provider-surface-dispatch.md` §7.4 — pin schema v2 with `surface`, `kind`, `schema_version`, plus Gemini-reserved fields `counter`, `rate_limit`, `selected_model`, `effective_model`, `mismatch_count_today`, `is_downgrade` (all optional, null-default)
- Cross-reference gemini plan PR-G3 for consumer shape expectations
- Regression test: parse v2 synthetic fixture with Gemini fields → v1+v2 dual-read in v2.0.1 PR-B8 tolerates → no panic

**Depends on**: PR-C1.

---

### PR-C2 — feat(credentials): CredentialFile surface-tagged enum

- `csq-core/src/credentials/mod.rs:27` — split `Anthropic { claude_ai_oauth }` vs `Codex { tokens }`
- `csq-core/src/credentials/file.rs:114,135` — parameterise `canonical_path` / `live_path` by `Surface` → `credentials/codex-<N>.json`
- 0400↔0600 mode-flip helper via `secure_file_readonly()`
- Per-account mutex `DashMap<(Surface, AccountNum), Arc<Mutex<()>>>` (INV-P08, INV-P09)

**Tests**: parallel `csq login 4 --provider codex` serialise; logout prunes; 0400→0600→write→0400 crash reconciler.

**Depends on**: PR-C1.5.

---

### PR-C3 — feat(providers): codex login orchestration + keychain residue probe

- `csq-core/src/providers/codex/{mod,surface,login,keychain}.rs` — new module
- `csq-cli/src/commands/login.rs:49-89` — dispatch on `--provider codex` → device-auth per §7.3.3
- `csq-cli/src/commands/setkey.rs` — hard-refuse Codex (FR-CLI-05)
- `csq-cli/src/commands/run.rs` — `launch_codex()`: verify daemon, verify config.toml, create handle dir with Codex symlink set, env_clear() + allowlist, exec codex
- `csq-core/src/session/handle_dir.rs` — Codex symlink set: auth.json, config.toml, sessions, history.jsonl per §7.2.2

**Tests**: write-order (config.toml before codex login); post-login tamper (`cli_auth_credentials_store = "file"`); keychain residue + refuse-on-decline; daemon-down → exit 2; sweep preserves codex-sessions.

**Depends on**: PR-C2; OPEN-C02 RESOLVED (with kill-switch if negative).

---

### PR-C4 — feat(daemon): refresher Codex extension + startup reconciler + Windows test (H2)

- `csq-core/src/daemon/refresher.rs` — surface-dispatched `broker_anthropic_check` vs `broker_codex_check`; Codex via OPEN-C04 transport; 2h pre-expiry (INV-P01); clock-skew via Date header; atomic_replace under per-account mutex with 0400↔0600 dance; `invalid_grant` → LOGIN-NEEDED (FR-CORE-03 step 5)
- `csq-core/src/daemon/startup_reconciler.rs` — new; 0600→0400 reconciler; config.toml drift rewrite
- Every `{e}` near Codex refresh → `sanitize_body` + `error_kind_tag`
- **Windows named-pipe integration test** (H2): surface-dispatched refresher cycle on Windows CI runner; merge gate — PR-C4 cannot merge without Windows CI pass

**Tests**: two-codex-process neither fires in-process refresh; clock-skew warning; invalid_grant → LOGIN-NEEDED; Windows named-pipe round-trip under surface dispatch.

**Depends on**: PR-C3; OPEN-C04 + OPEN-C05 RESOLVED; v2.0.1 PR-VP-C1a merged (Windows code exists to test against).

---

### PR-C5 — feat(daemon): usage_poller codex module + PII scrub (H5)

- `csq-core/src/daemon/usage_poller/codex.rs` — versioned parser per §5.7; `QuotaKind::Unknown` degradation; raw-body capture to `accounts/codex-wham-raw.json` + `codex-wham-drift.json` (0600, redactor-first); circuit breaker 5-fail → 15min → 80min cap
- `usage_poller/mod.rs` — dispatch table for `Surface::Codex`
- `tests/fixtures/codex/wham-usage-golden.json` — PII-scrubbed golden (per H5)
- `tests/fixtures/codex/scrub.sh` — swap `email`, `account_id`, `sub` JWT claim → `REDACTED`
- `.gitignore` — `accounts/codex-wham-raw.json`, `accounts/codex-wham-drift.json`
- Pre-commit assertion: no real email or `acct_*` identifier in golden
- **Ships PROVISIONAL if journal 0008 not captured.** Upgrade to STABLE via follow-up journal 0008b.

**Tests**: golden-file parse; drift → Unknown; circuit breaker state machine; raw-body redactor round-trip; 429/5xx through redact_tokens; PII assertion on golden.

**Depends on**: PR-C4; journal 0008 captured (or ships PROVISIONAL).

---

### PR-C6 — feat(quota): write-path flip to v2 schema

- `csq-core/src/quota/state.rs` — flip write path to schema v2 (read path landed v2.0.1 PR-B8; v1 reader still works)
- Daemon startup: idempotent rewrite of existing v1 files to v2 shape; atomic; crash-safe
- `csq-desktop/src-tauri/src/commands.rs` — response gains `surface` field

**Tests**: v1 file → v2 after startup; idempotent; crash-sim after rename; Tauri IPC audit (no secrets per `tauri-commands.md` MUST Rule 3).

**Depends on**: PR-C1.5 (schema frozen).

---

### PR-C7 — feat(cli): csq swap cross-surface exec + csq models switch Codex path

- `csq-cli/src/commands/swap.rs:13-66` — surface-mismatch → transcript-loss warning + [y/N]; `--yes` bypass; source handle dir cleanup before exec (INV-P10); same-surface retains `repoint_handle_dir()`
- `csq-cli/src/commands/models.rs` — dispatch on `ModelConfigTarget::TomlModelKey` → atomic replace of config.toml preserving other keys; `--force` for uncached models (FR-CLI-04)

**Tests**: cross-surface unconfirmed → exit 1; `--yes`; same-surface silent; source handle dir removed; R4 config.toml race guard.

**Depends on**: PR-C3.

---

### PR-C8 — feat(desktop): Codex UI

- `csq-desktop/src/lib/components/AddAccountModal.svelte` — device-code step; ToS disclosure gated on `accounts/codex-tos-accepted.json`
- `ChangeModelModal.svelte` — 1.5s fetch `chatgpt.com/backend-api/codex/models` + on-disk cache + "Cached Nm ago" + bundled cold-start list
- `AccountList.svelte` — surface badge with `aria-label`
- `csq-desktop/src-tauri/src/commands.rs` — `start_codex_login`, `complete_codex_login`, `list_codex_models`, `acknowledge_codex_tos`

**Tests**: Vitest ToS gate; cold-cache never empty; surface badge keyboard-focusable; IPC audit (no tokens).

**Depends on**: PR-C3, PR-C6.

---

### PR-C9a — chore(redteam): round 1 — 3 parallel agents (M1)

Three agents attack PR-C1 through PR-C8 in parallel. Journal entry closes the round with findings. Per `feedback_redteam_efficiency`.

---

### PR-C9b — chore(redteam): round 2 — 1 focused agent

One agent focuses on round-1 residuals. Journal entry closes round 2.

---

### PR-C9c — chore(release): convergence + release notes

All findings above LOW resolved inline. Release notes enumerate: daemon-requirement, Windows-caveat carry-over from v2.0.1 (if VP-C1b not yet flipped), quota v2 write-path flip, ToS disclosure, journal 0008 capture status (STABLE vs PROVISIONAL).

**Depends on**: PR-C9b.

---

## Release cut criteria (post-convergence)

v2.1.0 ships when:

- [ ] OPEN-C02/C03/C04/C05 RESOLVED with verification journals
- [ ] **§5.7 capture path decided**: Path A — journal 0008 captured, PR-C5 STABLE; OR Path B — user authorizes drop to v2.1.1, PR-C5 deferred
- [ ] PR-C00 through PR-C9c merged (C0.5 conditional)
- [ ] `cargo test --workspace` green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `npm run test` + `svelte-check --fail-on-warnings` clean
- [ ] **Windows named-pipe integration test green on CI** (bound to PR-C4)
- [ ] Quota.json v1→v2 migration verified on alpha.21 + v2.0.0 + v2.0.1 fixture files (v2.0.1 dual-read tolerates round-trip)
- [ ] PR-C9c convergence complete — no residuals above LOW
- [ ] Release notes enumerate: daemon-requirement, quota v2 one-way migration (read shipped v2.0.1), Windows-caveat carry-over or resolution, §5.7 path A/B status
