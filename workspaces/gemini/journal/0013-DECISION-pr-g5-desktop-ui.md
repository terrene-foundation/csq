---
type: DECISION
date: 2026-04-26
created_at: 2026-04-26T13:00:00Z
author: agent
session_id: 2026-04-26-gemini-pr-g5
session_turn: 18
project: gemini
topic: PR-G5 — desktop UI (AddAccountModal Gemini tab + ChangeModelModal static list + AccountCard chip + 6 Tauri commands)
phase: implement
tags: [gemini, csq-desktop, svelte, tauri, ui, pr-g5, v2.2.0]
---

# Decision — PR-G5: desktop UI for Gemini surface

## Context

PR-G4a (#198) and PR-G4b (#199) finished the csq-cli Gemini surface
(`csq setkey gemini`, `csq run`, `csq models switch`, `csq swap`). PR-G5
is the only remaining v2.2.0 deliverable per
`workspaces/gemini/02-plans/01-implementation-plan.md` §PR-G5 — the
desktop UI work that lifts Gemini onto the dashboard.

The implementation plan named six things:

- `AddAccountModal.svelte` — Gemini panel with two tabs (AI Studio
  paste / Vertex SA file picker), a ToS disclosure modal, and an
  inline `~/.gemini/oauth_creds.json` residue warning per FR-G-UI-01.
- `ChangeModelModal.svelte` — static Gemini model list with a
  preview-tier downgrade warning per FR-G-UI-02.
- `AccountCard.svelte` (renders in `AccountList.svelte`) — Gemini
  surface badge + downgrade chip + "quota: n/a" rendering per
  FR-G-UI-03.
- Three Tauri commands: `gemini_provision`, `gemini_switch_model`,
  `gemini_probe_tos_residue`.
- Capability audit (H1) for any new permissions.

The session also carried two structural questions from the prior PRs:

- **D4 factoring threshold** — journal 0012 deferred factoring
  `commands/run.rs::launch_gemini` and `commands/swap.rs::exec_gemini`
  (~70 LOC each, ~50 LOC overlap) into
  `csq-core::providers::gemini::session.rs` until a third caller
  appeared.
- **Vault delete on unbind ownership** — journal 0011 §FD #1 left the
  vault delete call unwired; expected PR-G5 to clarify whether
  desktop or CLI owns it.

## Decisions

### D1 — Six Tauri commands, not three

The plan said three (`gemini_provision`, `gemini_switch_model`,
`gemini_probe_tos_residue`). Implementation needed six because the
provision step splits cleanly along auth-mode lines and the ToS step
needs both query and mutate:

- `is_gemini_tos_acknowledged(base_dir) -> bool`
- `acknowledge_gemini_tos(base_dir) -> ()`
- `gemini_probe_tos_residue() -> Option<String>`
- `gemini_provision_api_key(base_dir, slot, key) -> ()`
- `gemini_provision_vertex_sa(base_dir, slot, sa_path) -> String`
- `gemini_switch_model(base_dir, slot, model) -> ()`

The Codex case had six commands too (`start_codex_login`,
`complete_codex_login`, `cancel_codex_login`, `list_codex_models`,
`set_codex_slot_model`, `acknowledge_codex_tos`); the parity is
incidental but the shape is the same — query / mutate / probe split
by single-responsibility.

### D2 — D4 deferral confirmed: PR-G5 is NOT the third caller of `spawn_gemini`

The Tauri commands here are provision / switch / probe — none of
them call `spawn_gemini` or its launch helpers. The desktop launches
Gemini sessions through the existing `swap_session` command, which
already routes through `commands/swap.rs::exec_gemini`. Number of
callers of `launch_gemini` / `exec_gemini` is still 2.

The break-even threshold from journal 0012 D4 stays unmet. No
`csq-core::providers::gemini::session.rs` factoring in this PR. If
v2.3 brings a fourth surface or an in-app launch button, the
threshold flips.

### D3 — Provisioning orchestration factored into csq-core

Per the session notes ("factor into csq-core, do NOT depend
csq-desktop on csq-cli"), the desktop calls into csq-core directly
rather than re-implementing the orchestration in commands.rs. New
public helpers in
`csq-core/src/providers/gemini/provisioning.rs`:

- `BoundSurface { ClaudeCode, Codex }` enum + `as_tag()` for stable
  log tags
- `detect_other_surface_binding(base_dir, slot) -> Option<BoundSurface>`
  — Codex check first, ClaudeCode second; treats dangling symlinks
  as bound (parity with `is_gemini_bound_slot`)
- `provision_api_key_via_vault(base_dir, slot, key, vault) -> Result<(), ProvisionError>`
  — orchestrates `vault.set` + `write_binding` with rollback on
  marker failure
- `provision_vertex_sa(base_dir, slot, sa_path) -> Result<PathBuf, ProvisionError>`
  — validates path + writes binding, returns canonical
- `set_model_name(base_dir, slot, model) -> Result<(), ProvisionError>`
  — atomic update of `binding.model_name`
- `is_known_gemini_model(s) -> bool` — desktop static-picker
  validator (canonical ids only — aliases are a CLI-side concern)

csq-cli's existing private helpers (`provision_api_key`,
`provision_vertex`, `write_gemini_model_to_binding` in
`commands/setkey.rs` and `commands/models.rs`) were NOT refactored to
call the new csq-core helpers in this PR — that's a follow-up. The
duplication is contained (~30 LOC) and the cleanup doesn't block
v2.2.0.

### D4 — Tauri-plugin-dialog with `dialog:allow-open` only

The Vertex SA tab needs an OS file picker. Two viable shapes:

- A: add `tauri-plugin-dialog` with the narrow `dialog:allow-open`
  permission
- B: implement a path-input field with manual typing

Picked A. Manual typing is hostile UX for an absolute-path
requirement, and the `:allow-open` sub-permission scopes the renderer
to "show a file open dialog" — it does NOT grant `dialog:default`
which would also bundle save / message / ask. Per
`rules/tauri-commands.md` Permission Grant Shape, narrow always.

The `:allow-open` grant is the only third-party-plugin sub-permission
added. The `core:default` and `log:default` grants are framework
primitives that pre-date PR-G5.

### D5 — Gemini fields on AccountView are `skip_serializing_if = "Option::is_none"`

FR-G-UI-03 requires the AccountCard to render Gemini-specific
counter / 429 reset / downgrade UI. Two options:

- A: add a discriminated-union field (`account_kind: Anthropic | Gemini`)
- B: add four optional fields (`gemini_counter_today`,
  `gemini_rate_limit_reset_at`, `gemini_selected_model`,
  `gemini_effective_model`) populated only when `surface == "gemini"`

Picked B because the existing AccountView is not discriminated
(Anthropic-specific fields like `five_hour_pct` exist alongside
`provider_id` for 3P slots) and refactoring to a tagged union
across all surfaces is a v2.3-grade change. The `skip_serializing_if`
attribute keeps the wire shape stable for non-Gemini accounts —
verified via `account_view_anthropic_keys_whitelisted` test which
asserts the four new keys do NOT appear in the serialized payload
when their values are `None`.

A test (`account_view_surface_gemini_variant_serializes_quota_fields`)
pins the wire shape when populated AND verifies no secret material
(API key, `AIza` substring) leaks into the IPC payload.

### D6 — Static client-side Gemini model list, no IPC fetch

Per FR-G-UI-02, the Gemini model list is static (`auto`,
`gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite`,
`gemini-3-pro-preview`). Codex's list is dynamic (`list_codex_models`
fetches from `chatgpt.com/backend-api/codex/models`). No equivalent
endpoint exists for Gemini's API-key tier. The static list lives in
ChangeModelModal.svelte as a `const GEMINI_MODELS` array; the
canonical-id boundary check is `is_known_gemini_model` in csq-core.

The desktop static picker submits canonical ids only — aliases
(`pro`, `flash`) are a CLI-side affordance handled by
`csq-cli::commands::models::resolve_gemini_model`. The Tauri command
boundary check refuses aliases to keep the desktop / CLI surface
contracts distinct.

### D7 — Vault residue cleanup ownership: deferred again

Journal 0011 §FD #1 asked who calls `vault.delete` on `unbind`. PR-G5
does not provision a `csq logout` or `csq rmkey` desktop equivalent,
so the question stays open. The closest the desktop comes is
"replace existing binding with a different one" — which today is
guarded by `detect_other_surface_binding` refusing to clobber, and
the user has to drop to CLI to `csq logout N` first. A future desktop
"remove account" path that handles a Gemini slot will need a
companion vault-delete IPC; not in PR-G5 scope.

## Consequences

### Tests

PR-G5 ships +49 tests:

- **csq-core**: +14 in `providers::gemini::provisioning` (new
  orchestration helpers + boundary cases) + +11 in
  `providers::gemini::tos` (mirror of codex/tos.rs)
- **csq-desktop (Rust)**: +20 — 19 boundary tests for the 6 new
  Tauri commands + 1 wire-shape test for AccountView Gemini variant
- **csq-desktop (Vitest)**: +16 — 6 in AccountList, 4 in
  ChangeModelModal, 6 in AddAccountModal

Cargo: 1436 → 1469 (+33). Vitest: 100 → 116 (+16). Total +49.

`cargo clippy --workspace --all-targets -- -D warnings` clean.
`cargo fmt --all -- --check` clean.
`npm run check` — 0 errors, 2 unchanged baseline warnings (pre-existing
button-in-button on the surface-badge in AccountList — line 458 is
the same as the prior 424; the line number shifted from my
insertions but the markup is unchanged).

### Wire-shape implications

The four new optional fields on `AccountView` are
`skip_serializing_if = "Option::is_none"`. Non-Gemini accounts have
the identical wire shape as before PR-G5; Gemini accounts grow four
metadata keys (counter, ISO timestamp, two model names). No secret
material crosses IPC.

### Capability audit

`grep -Eh '"[a-z-]+:default"' csq-desktop/src-tauri/capabilities/*.json`
shows only `core:default` and `log:default`, both framework-level
Tauri primitives. The new `dialog:allow-open` is the narrow
sub-permission, NOT `dialog:default`. No `:default` 3P plugin grants.

### Spec touchpoints

No spec edits required. FR-G-UI-01..03 in
`01-analysis/01-research/01-functional-requirements.md` are the
operative contracts; the implementation matches them
field-for-field. The four-field `AccountView` extension is a
desktop-side UI concern, not a csq-core contract — it's documented
in this journal rather than the specs index.

## What's left (post-v2.2.0)

- **D4 reconsider** — when a v2.3 surface or in-app launch button
  becomes a third caller of `launch_gemini` / `exec_gemini`, factor
  into `csq-core::providers::gemini::session::launch`.
- **csq-cli refactor** — `setkey.rs::handle_gemini` and
  `models.rs::write_gemini_model_to_binding` can call the new
  csq-core helpers (`provision_api_key_via_vault`, `set_model_name`)
  directly, removing the contained ~30 LOC of duplication. Cosmetic;
  not blocking.
- **D7 vault-delete on unbind** — a desktop "remove Gemini account"
  path that calls `vault.delete` plus `provisioning::unbind` (today
  only the CLI's `csq logout` knows the orphan-key risk; the desktop
  removal flow has no Gemini equivalent yet).
- **Manual smoke test** — provision a real AI Studio key on a real
  account, switch the model in the UI, verify the AccountCard
  reflects the new selected/effective model after first call. The
  unit + Vitest tests cover validation + IPC contract; the
  end-to-end with a live `gemini-cli` binary is the only remaining
  gap in the test plan.

## For Discussion

1. **D5 wire-shape choice — does `skip_serializing_if` on four
   Gemini fields scale?** Today's AccountView has 14 fields plus 4
   Gemini fields. v2.3 brings (probably) a Bedrock surface with its
   own 2-3 surface-specific fields. By v2.4 we're at 22+ fields,
   and renderers branch on `surface` plus a small forest of
   `if (account.gemini_*)` / `if (account.bedrock_*)` checks. The
   tagged-union refactor (option A in D5) becomes increasingly
   right-shaped at N=3 surfaces and is unambiguously right by N=4.
   When does the cost flip? Probably when the next surface actually
   ships, not pre-emptively now — but the question is worth pinning
   in the v2.3 brief.

2. **Counterfactual — if `csq-core` had refused to expose Vault as a
   trait object.** The desktop calls `provision_api_key_via_vault`
   which takes `&dyn Vault`. If Vault had been a generic
   `provision_api_key_via_vault<V: Vault>` we couldn't call it from
   the Tauri command without hauling the concrete vault type
   through (the desktop holds `Box<dyn Vault>` from
   `open_default_vault`). Today's `&dyn Vault` is the load-bearing
   shape choice that lets the desktop and CLI share the
   orchestration; if a future feature requires a vault method that
   isn't object-safe (associated types, `Self: Sized` bounds), the
   factoring breaks down and we'd need a separate adapter trait.

3. **Evidence question — does the four-field "skip_serializing_if"
   approach match what real users see?** When a Gemini slot has been
   provisioned but no events have drained yet (`csq run` hasn't
   fired), all four `gemini_*` fields are `None`. The AccountCard
   shows `quota: n/a` and no downgrade chip. The Anthropic 5h/7d
   bars are suppressed for Gemini surface. So the user sees a card
   with just the surface badge and the "n/a" quota note — minimal,
   correct, and explicit about the unknown state. This was verified
   via the new Vitest case
   `renders 'quota: n/a' for Gemini slot with no counter yet`. Is
   the n/a state actionable enough? Or should it carry a "spawn
   `csq run N` to populate" hint? The current minimalism wins on
   the assumption that the user just provisioned the slot and
   expects it empty until first use.
