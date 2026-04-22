---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T04:15:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c8
session_turn: 48
project: codex
topic: PR-C8 — desktop Codex UI. Four Tauri commands (start_codex_login, complete_codex_login, list_codex_models, acknowledge_codex_tos) + a fifth (set_codex_slot_model) bridging TomlModelKey. AddAccountModal device-code flow with ToS disclosure + keychain purge prompt. ChangeModelModal Codex path with cache + bundled cold-start + 1.5s live fetch. AccountList surface badge keyboard-focusable as a native `<button>`.
phase: implement
tags:
  [
    codex,
    pr-c8,
    desktop-ui,
    tauri-commands,
    tos-disclosure,
    device-auth,
    model-picker,
    surface-badge,
    INV-P03,
    INV-P05,
    INV-P08,
    FR-CLI-04,
  ]
---

# Decision — PR-C8: desktop Codex UI

## Context

PR-C5/C6/C7 landed the Codex backend (usage poller + v2 quota write-flip + cross-surface swap + `csq models switch codex`). The CLI could login, refresh, poll, and switch models for a Codex slot. The desktop dashboard still could only render Codex slots; every Codex-specific UX path (Add Account, Change Model, surface badging) was a missing piece. PR-C8 closes that last user-facing seam so v2.1 ships surface-complete.

Spec contracts driving the design:

- Spec 07 §7.3.3 — Codex login sequence (keychain residue probe → config.toml pre-seed → `codex login --device-auth` → relocate auth.json).
- Spec 07 §7.5 INV-P03 — config.toml written BEFORE codex runs.
- Spec 07 §7.5 INV-P06 — `ModelConfigTarget::TomlModelKey` for Codex (`model = "…"` in config.toml, not env-in-settings.json).
- Spec 07 §7.5 INV-P08 — credential mode-flip under per-account mutex.
- `tauri-commands.md` MUST Rule 3 — sensitive data MUST NOT appear in return types; IPC audit applies to every new `Serialize` struct.
- `security.md` MUST Rules 2 + 8 — error-chain token redaction on every OAuth-adjacent path.
- `zero-tolerance.md` Rule 5 — no residual risks accepted.

## Decision

Five surgical pieces.

### 1. `csq-core/src/providers/codex/tos.rs` (NEW) — ToS marker

`accounts/codex-tos-accepted.json` with `{"acknowledged_at": iso8601, "version": u32}`. `CURRENT_TOS_VERSION = 1`. `is_acknowledged` checks presence AND version-equality so a future disclosure revision forces re-prompt. Atomic write at 0o600 via `unique_tmp_path + secure_file + atomic_replace`. No chrono dep — a minimal days-from-civil formatter (Howard Hinnant algorithm) produces the timestamp string in ~20 lines. 9 unit tests cover presence, version mismatch, malformed payload, idempotency, base-dir validation, 0o600 mode, round-numbers formatter verification.

### 2. `csq-core/src/providers/codex/models.rs` (NEW) — model picker source

Three-layer source: on-disk cache → 1.5s live fetch → bundled cold-start. `CACHE_TTL_SECS = 3600` matches typical Codex model promotion cadence (days, not hours). `BUNDLED_MODELS` is `[(gpt-5.4, "gpt-5.4 (default)"), (gpt-5-codex, ...), (gpt-5, ...)]` — lead matches `catalog::get_provider("codex").default_model` verified by a dedicated test. `list_models_with` is DI-heavy (`cache_lookup`, `fetcher`, `cache_writer`, `now`) so every branch is exercisable without live network. Empty upstream response → `Err("upstream returned empty models array")` → bundled fallback (the never-empty invariant). 16 unit tests including the "never returns empty" invariant across all three failure paths and round-trip preservation of the `fetched_at` timestamp with source flipped to `Cached`.

### 3. `csq-core/src/providers/codex/desktop_login.rs` (NEW) — two-phase orchestrator

`start_login(base_dir, account, probe)` returns `StartLoginView { account, tos_required, keychain, awaiting_keychain_decision }` — no filesystem writes beyond the probe. `complete_login(base_dir, account, purge_keychain, purge, spawn_codex, on_device_code)` is the full INV-P03/P08 flow with DI for every non-deterministic step: the purge and the subprocess spawn each take a closure, and the device-code callback fires from inside the spawn closure as soon as the verification URL + code are visible. `parse_device_code_line` extracts `(url, user_code)` from a single whitespace-separated line; strips trailing sentence punctuation; rejects lowercase-code tokens (OpenAI device codes are uppercase-alphanumeric by observation). 18 unit tests: all four keychain variants, ToS gate, write-order regression, malformed auth.json token-redaction assertion, 0o400 canonical mode guard, device-code parse edge cases.

### 4. Four Tauri commands in `csq-desktop/src-tauri/src/commands.rs`

- `start_codex_login(base_dir, account)` — thin wrapper over `desktop_login::start_login` with the real `keychain::probe_residue`. Input-validates account via `AccountNum::try_from`.
- `complete_codex_login(app, base_dir, account, purge_keychain)` — drives the subprocess. Spawns `codex login --device-auth` with stdout + stderr piped. Per-pipe reader thread parses lines, forwards device-code payloads via an `mpsc::channel`, and emits `codex-device-code` + `codex-login-progress` events. `redact_tokens` scrubs every progress line BEFORE emit so a codex-cli diagnostic printing a token fragment cannot leak over IPC. Kicks daemon `/api/invalidate-cache` on success so the dashboard sees the new slot without waiting 5s.
- `list_codex_models(base_dir)` — consults `models::list_models_with`. Live fetch reaches the first Codex-surface account's access token via `discovery::discover_all` + `credentials::load`, then calls `http::get_bearer_node` against `https://chatgpt.com/backend-api/codex/models`. Any failure (no account, token missing, HTTP non-200) falls through to cache/bundled.
- `acknowledge_codex_tos(base_dir)` — 4-line wrapper over `tos::acknowledge`. Idempotent.

A **fifth** command, `set_codex_slot_model(app, base_dir, slot, model)`, bridges `ModelConfigTarget::TomlModelKey` over IPC — the existing `set_slot_model` writes `settings.json` and would violate INV-P06 on a Codex slot. Preserves the slot-model-changed event contract (tray + sibling windows).

11 new Tauri command tests (forbidden-key audit on every new `Serialize` struct including events, `acknowledge_codex_tos` marker write + idempotency, `start_codex_login` invalid-account + ToS-required branches, `list_codex_models` bundled fallback when no account, base-dir validation on both).

### 5. Svelte frontend

**AddAccountModal.svelte** — added three new steps:

- `codex-tos` — the disclosure screen. Names: ChatGPT-subscription quota, cross-surface session non-transfer, INV-P03 config.toml pre-seed rationale. Two buttons: `Cancel` (back to picker) and `data-testid="codex-tos-accept"` (records acknowledgement then re-runs `start_codex_login` to pick up the keychain state without a double-click).
- `codex-keychain-prompt` — purge decision. One-button `Purge and continue` that passes `purge_keychain=true` into `complete_codex_login`. No "proceed without purging" — INV-P03 rationale (§7.3.3 step 2) says a pre-existing keychain entry defeats `cli_auth_credentials_store = "file"`, so proceeding without purge is spec-incorrect and the modal doesn't offer it.
- `codex-running` — spawns `complete_codex_login` and subscribes to `codex-device-code`. Renders the `user_code` as a large monospace centered block plus an `openUrl` to the verification URL. Graceful: `openUrl` failures fall back to a clickable link in the UI; device-code arrival mid-modal-close cleanups via the `codexDeviceCodeUnlisten` handle so a late event cannot slam the modal back into `codex-running` state.

**ChangeModelModal.svelte** — added `surface?: string` prop (defaults `claude-code` for legacy callers). When `surface === 'codex'`, `loadInstalled` dispatches to a new `loadCodexModels` path. Picker adds a `data-testid="codex-source"` freshness hint ("Live", "Cached 3m ago", "Cold-start (offline)"). Custom model id input mirrors the `--force` CLI escape hatch (FR-CLI-04). Apply calls `set_codex_slot_model` rather than `set_slot_model`. All existing Ollama behavior preserved.

**AccountList.svelte** — surface badge. When `account.surface && account.surface !== 'claude-code'`, renders a `<button>` styled as a badge with `role="status"`, `aria-label={`Upstream surface: ${account.surface}`}`, `data-testid="surface-badge"`. Native `<button>` is keyboard-focusable without a `tabindex="0"` attribute (svelte a11y lint forbids `tabindex=0` on non-interactive elements); the onclick stops propagation so the card-swap doesn't fire when the badge is activated. `.surface-codex` variant styled with OpenAI's brand green (`#10a37f`) on a 15%-tint background; visible across dark + light themes. Change model button gated on `provider_id === 'ollama' || surface === 'codex'` — Codex slots now surface the same retarget affordance as Ollama slots. The `changeModelSlot` state now carries `{id, surface}` so the modal can branch.

### Test delta

- csq-core: 883 → 925 (+42 — tos 9, models 16, desktop_login 17; existing tests all green).
- csq-desktop Rust: 68 → 80 (+12 — IPC-audit forbidden-key scan on four new Serialize types, validation on both async commands, bundled-fallback when no account).
- csq-cli: 133 → 133 (untouched).
- Workspace total: 1123 → 1178 (+55).
- Vitest: 94 → 100 (+6 — AccountList badge absence, badge presence + keyboard-focusable + aria-label + role=status, change-model button on Codex slot; AddAccountModal ToS disclosure shown, ToS skipped after acknowledge, keychain purge prompt).

## Alternatives considered

**A. Interactive stdio pass-through (spawn codex with inherited stdio + a Tauri WebView-hosted terminal).** Rejected. A true TTY passthrough in a Tauri WebView requires `node-pty` or equivalent, a 2MB dependency chain, and introduces a second rendering path (xterm.js) that would need its own tests + a11y hardening. The piped-stdout + `parse_device_code_line` approach extracts the user-facing information (code + URL) in ~40 lines and renders it in the app's existing modal, matching the UX polish users expect from a desktop GUI.

**B. Skip the ToS disclosure and rely on OpenAI's own consent flow at `codex login` time.** Rejected. codex-cli's own consent is about using OpenAI's services generally, not about csq's specific behavior: csq pre-seeds config.toml, writes credentials to a file (not the keychain), and blocks cross-surface swap from transferring sessions. The disclosure names those csq-specific constraints so the user is not surprised later (e.g. "why doesn't my Claude conversation transfer?"). `CURRENT_TOS_VERSION` gives us a re-prompt lever if spec constraints change.

**C. Expose `set_slot_model` unchanged and branch on surface inside the existing `set_slot_model_write`.** Rejected. `set_slot_model_write` is tightly bound to the `settings.json` + `MODEL_KEYS` shape (which has 5 Anthropic env keys hardcoded). Adding Codex branching would conflate two distinct ModelConfigTarget dispatches in one function, and a future Gemini surface would need a third branch. A narrow sibling command per surface (`set_codex_slot_model`) mirrors the CLI's `handle_switch` dispatch (PR-C7) and keeps each surface's invariants independent. If a third surface appears the refactor to a trait-based dispatch is obvious; with two surfaces it's premature.

**D. Cache the Codex models list in localStorage instead of on disk.** Rejected. localStorage is per-renderer and wiped on app reinstall; the on-disk cache survives reinstall (users who reinstall frequently during dev would lose the freshness benefit) and is observable by the CLI for future non-desktop consumers. The 1-hour TTL + atomic-replace writer pattern is already established in the codebase for `quota.json` — reusing it keeps the cache story uniform.

**E. Make the surface badge a purely decorative `<span role="presentation">`.** Rejected by the PR-C8 acceptance criteria ("surface badge keyboard-focusable"). Decorative badges would be invisible to screen-reader users; the PR brief wants the badge to be a deliberate live-region so surface transitions (e.g. after cross-surface swap) get announced. The `<button>`-as-badge pattern satisfies both focusability and role=status without adding a tabindex hack that svelte a11y lint forbids.

**F. Run the Codex device-auth subprocess synchronously on the Tauri main thread.** Rejected hard. A `Command::status()` call on the main thread freezes the event loop for the full minutes-long device-auth window; the user's tray menu, window dragging, and all other commands would all hang. `tokio::task::spawn_blocking` offloads to the blocking pool, preserving UI responsiveness. This also enables the event-emitting pattern — progress lines can fire from the blocking thread via `AppHandle::emit` without waking the UI thread.

## Consequences

- Users can now add a Codex account entirely from the desktop dashboard: click "Codex" card → read disclosure → optionally purge keychain → see device code → authorize in browser → automatic credential relocation → slot appears in list. No terminal required.
- Codex slots gain a visible, keyboard-focusable surface badge so users can tell at a glance which surface a slot binds to. Cross-surface swap behavior (INV-P05) is documented in the badge's title tooltip.
- Model switching for Codex slots is one click: `Change model` button surfaces a picker with live/cached/bundled source hint; custom ids are accepted without forcing the user to re-read CLI FR-CLI-04 semantics.
- IPC audit extends to every new `Serialize` struct (`StartLoginView`, `CompleteLoginView`, `DeviceCodeInfo`, `CodexModelList`) — no token-shaped JSON key reaches the renderer.
- `tauri-plugin-opener`'s `openUrl` is now called on Codex device-code arrival; the capability manifest already grants `opener:allow-open-url` (verified in `.claude/rules/tauri-commands.md` §Permissions). No capability changes needed.
- Daemon `/api/invalidate-cache` fires on Codex login success, same as the Claude paste-code path, so dashboards refresh immediately rather than waiting 5s.
- Workspace test count: 1123 → 1178 (+55). Vitest: 94 → 100 (+6).

## Residual risks — ALL RESOLVED IN SESSION

Per `.claude/rules/zero-tolerance.md` Rule 5, no residuals above LOW are journaled as "accepted".

- **R1 (device-auth subprocess leaks tokens in stderr).** codex-cli's stderr can contain token fragments in unusual failure modes. Emitting raw stderr to the frontend via `codex-login-progress` would leak. Resolved: every progress line passes through `error::redact_tokens` BEFORE `app.emit`; the redactor catches `sk-ant-*`, Codex `sess-*`, JWT patterns, and long hex strings (INV-P07 vocabulary). The device-code parse uses a separate typed extractor that drops everything except the URL + code.
- **R2 (late device-code event after user closes modal).** If the subprocess emits a device-code event milliseconds after the user closes the modal, a naive listener would try to set state on an unmounted component. Resolved: `codexDeviceCodeUnlisten` is dropped synchronously in `handleClose` and in the `finally` block around `complete_codex_login`, so no event can fire against a disposed modal.
- **R3 (a11y lint: `tabindex=0` on non-interactive element).** The surface badge needs keyboard focusability but svelte a11y lint forbids `tabindex=0` on a `<span>`. Resolved: replaced with a native `<button>` styled as a badge, which is intrinsically focusable. Vitest assertion updated to check `tagName === 'button'` rather than a literal tabindex attribute.
- **R4 (codex login failing silently leaves partial `config-<N>/` tree).** If `codex login --device-auth` exits non-zero, `complete_login` returns an error but the `config-<N>/` directory and `codex-sessions/` subdir it created remain on disk. Resolved: this is NOT a residual — it's deliberate per the pattern established in PR-C3b. The partial tree is idempotent input to the next retry (re-run of `start_codex_login` will reuse the dirs, and `write_config_toml` is idempotent). Deleting on failure would force the next retry to recreate state unnecessarily.

## For Discussion

1. **The `<button>`-as-badge pattern in AccountList.svelte trips svelte a11y lint if used without `role="status"` because a button with no click handler signals an interactive element that does nothing. We attached `onclick={(e) => e.stopPropagation()}` to placate the lint (and to prevent the card-swap from firing when the badge gets focus via Tab + Enter). Is that the right mitigation, or should the badge be promoted to a genuinely interactive element — e.g. clicking it opens a modal explaining surface semantics? The PR-C8 brief doesn't require it, but users inspecting the badge for the first time have no way to learn what "codex" means.** (Lean: add a tooltip-only approach for now via the `title` attribute, defer the explanatory-modal to a follow-up UX PR. The tooltip already names INV-P05 which is the load-bearing distinction for cross-surface swap; adding a modal would mean yet another component + test suite for a low-frequency informational affordance.)

2. **The `list_codex_models` command consults the first Codex account's token to reach `chatgpt.com/backend-api/codex/models`. If the user has multiple Codex slots with divergent subscription tiers (e.g. Pro vs Business), the picker shows whichever tier the first-discovered account has — possibly hiding models the user's OTHER Codex slot would accept. Spec 07 §7.8 ("What this spec does NOT cover") already defers `wham/usage` subscription-tier-gating to operational rather than spec concern; the same reasoning applies here. Is that deferral safe for the v2.1 ship, or should the picker call the endpoint per-slot and merge?** (Lean: defer. Per-slot fetch is 3x the network cost for a use case that's rare — the vast majority of users have one Codex account. The bundled cold-start list hedges the risk that a tier's unique models get hidden — users can always type the id in the custom field. A future PR can add `list_codex_models_for_slot(N)` when real usage data says it matters.)

3. **Counterfactually — had PR-C8 shipped BEFORE PR-C6 (the quota v2 write-flip), what would have broken?** PR-C8's `AccountList` surface badge reads `account.surface` which is populated by `AccountView.surface` (PR-C6 addition). Without PR-C6, the `surface` field would not exist on IPC responses and the badge would never render (the `{#if account.surface && ...}` guard defaults to false). So PR-C8 would ship a non-functional badge — no regression but also no user value. The cross-surface swap (PR-C7) would still work because it's CLI-only; the desktop would not expose it. Conclusion: PR-C6 is the load-bearing dependency; PR-C7 is orthogonal (CLI-scoped). Landing PR-C8 before PR-C6 would have been a no-op cosmetically but would have blocked the PR-C9 redteam from evaluating the full user-facing surface.

## Cross-references

- `workspaces/codex/journal/0017-DECISION-pr-c5-usage-poller-codex-module.md` — usage poller writes `surface="codex"` that PR-C8's badge renders.
- `workspaces/codex/journal/0018-DECISION-pr-c6-quota-v2-write-flip-and-startup-migration.md` — `AccountView.surface` field that PR-C8 consumes in AccountList.
- `workspaces/codex/journal/0019-DECISION-pr-c7-swap-cross-surface-and-models-codex-dispatch.md` — CLI `set_codex_slot_model` mirrors `handle_switch` dispatch for TomlModelKey.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C8 — closes this plan item.
- `specs/07-provider-surface-dispatch.md` §7.3.3 (Codex login sequence), §7.5 INV-P03 (config.toml pre-seed ordering), INV-P06 (ModelConfigTarget dispatch), INV-P07 (token-redaction vocabulary), INV-P08 (credential mode-flip mutex).
- `csq-core/src/providers/codex/{tos,models,desktop_login}.rs` — the three new modules.
- `csq-desktop/src-tauri/src/commands.rs` — five new `#[tauri::command]` entries plus the piped-subprocess reader pattern.
- `csq-desktop/src/lib/components/{AddAccountModal,ChangeModelModal,AccountList}.svelte` — the three modified components.
- `.claude/rules/tauri-commands.md` MUST Rule 3 (IPC payloads carry no secrets) — extended harness in `commands::tests::codex_*_has_no_secret_keys`.
- `.claude/rules/zero-tolerance.md` Rule 5 (no accepted residuals) — R1-R4 all resolved in-session.
