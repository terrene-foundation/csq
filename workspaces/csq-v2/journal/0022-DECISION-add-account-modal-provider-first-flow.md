---
type: DECISION
date: 2026-04-11
created_at: 2026-04-11T20:15:00+08:00
author: co-authored
session_id: session-2026-04-11c
session_turn: 201
project: csq-v2
topic: Add Account modal uses a provider-first picker with auth-type-branched substeps, system browser for OAuth, and paste-code as the only Claude sign-in flow
phase: implement
tags: [desktop, ux, oauth, providers, add-account]
---

# DECISION: Add Account modal is provider-first with auth-type-branched substeps

## Context

csq v2 supports three providers (Claude/MiniMax/Z.AI) with two distinct auth types: OAuth for Claude (paste-code flow — see 0020), bearer API key for MiniMax and Z.AI. Pre-session, the dashboard had a single "+ Add Account" button that dispatched to a hardcoded `start_login` returning `"Run csq login N in your terminal"` — no in-app flow, no multi-provider support.

The user explicitly flagged multi-provider support as a requirement: "there's more than just anthropic, we have z.ai and minimax". Earlier in the session they also asked to "follow up with Option B and fallback to A", meaning embedded webview first, system browser second.

## Choice

**Provider-first picker, auth-type-branched substeps, single modal.**

1. User clicks `+ Add Account` → modal opens to **Step 1: provider picker** showing Claude / MiniMax / Z.AI cards (Ollama hidden — keyless, not an Add Account target).
2. Branch by `provider.auth_type`:
   - `OAuth` (Claude) → **Step 2a: paste-code**. Calls `start_claude_login`, opens the authorize URL in the **system browser** (no embedded webview), shows an "Authorization code" input field + a `<details>`-collapsed fallback URL textarea, calls `submit_oauth_code` on submit.
   - `Bearer` (MiniMax, Z.AI) → **Step 2b: bearer-form**. Password-masked input for the API key, optional base URL hint, calls `set_provider_key` on submit.
3. Both branches converge on **Step 3: success** or **Step 3: error** with retry.

## Why system browser, not embedded webview

Earlier in the session I built the embedded-webview path (Option B) as asked. During the OAuth endpoint migration (see 0019), we discovered Anthropic retired loopback and moved to paste-code. **Paste-code requires the user to copy a code off Anthropic's page and paste it back into csq-desktop.** The embedded webview offers no advantage for this flow:

- The user still has to switch contexts (look at the code, copy it, come back to csq)
- Password managers don't see embedded webviews reliably
- Cloudflare-fronted `claude.com/cai/oauth/authorize` may bot-challenge non-standard user agents (journal 0019 confirmed a 403 cf-mitigated response to a plain webview UA)
- A system browser is one fewer surface for csq to maintain

So the whole webview machinery (child `WebviewWindow`, navigation event listener, auto-close on callback) was dismantled when the paste-code rewrite landed. Option A wins **not because Option B failed** but because paste-code makes Option B redundant.

## Why fallback URL is always visible behind `<details>`, not hidden until `openUrl` errors

Original design: show the fallback URL only when `openUrl` throws. Rejected: the one-line `console.warn` swallow (journal 0021 Trap 3) meant users couldn't tell the difference between "browser opened, waiting for you" and "browser failed silently, you need to copy the URL". Always surfacing the URL behind a `<details>` summary costs one line of vertical space and means the user can always recover without restarting the modal. The error banner at the top of the step separately surfaces `openUrl` exceptions when they do fire.

## Why paste-code input is plain text, not password-masked

The bearer-form uses `type="password"` for API keys (they are long secrets). The paste-code input uses `type="text"` because:

1. The authorization code is short-lived (seconds-to-minutes)
2. Password masking hides paste errors — users can't verify they pasted the right string if they can't see it
3. The code is single-use and burned by the first `submit_oauth_code` call, so visible retention in the DOM between paste and submit is not a meaningful secret exposure

## Alternatives considered

1. **Claude-only flow with a separate "Add 3P Provider" UI** — rejected: doubles the button count in the dashboard, makes 3P feel second-class when users care about rotation across providers equally.
2. **Provider selection as a dropdown inside a single Claude form** — rejected: the two auth types require entirely different input fields (paste code vs API key), not a field swap. Step machine is clearer than a polymorphic form.
3. **Keep Option B (embedded webview) as a fallback** — rejected: with paste-code, the webview adds complexity without value. See above.
4. **Show Ollama in the picker** — rejected: Ollama is keyless and locally served; "adding" it is just `ollama pull` + starting the daemon. It appears as a discovered account via `discover_all`, not via the Add Account flow.

## Consequences

**Good:**

- Single entry point for all three providers
- Paste-code UX mirrors `claude auth login` — users familiar with the CLI recognize the flow
- Fallback URL always visible → `openUrl` failures are recoverable without restarting
- ~60 KB JS bundle reduction (no child WebviewWindow spawning code)

**Bad:**

- **Untested**: no one has exercised the paste-code submit path end-to-end against a live Anthropic token endpoint. User declined to run a real login because they already have 8 live accounts and didn't want to overwrite credentials.
- The code input being plain text means a bystander looking over the shoulder sees the authorization code. Acceptable because the code is burned on submit and has no ongoing value, but noted.
- MiniMax and Z.AI key paths have been typed but not validation-probed end-to-end in a UI session.

## Consequences for architecture

- `AppState.oauth_port: Option<u16>` — dropped. Paste-code has no port.
- `forward_oauth_event` helper and `oauth-login-complete` / `oauth-login-failed` Tauri events — dropped. Paste-code submits synchronously from the frontend; no listener needed.
- `AddAccountModal.svelte` step machine — five kinds: `picker`, `paste-code`, `bearer-form`, `success`, `error`. Clean state transitions, no cross-branch state.
- `start_claude_login`, `submit_oauth_code`, `cancel_login`, `list_providers`, `set_provider_key` — all Tauri commands landed.

## For Discussion

1. **Is the paste-code input being `type="text"` the right call for a shoulder-surfing threat model?** The rationale (short-lived, single-use, can't validate masked paste) is sound for an individual developer laptop, but would it hold up in a shared-workspace scenario (a user streaming their screen on Twitch, a coworker looking over a shoulder)? The counter-argument is that a long-lived API key in the bearer-form IS password-masked — if shoulder surfing is a real threat, the inconsistency between the two forms is suspicious. Should both forms be masked with a "show code" toggle?
2. **Ollama is hidden from the picker because "adding" it is just `ollama pull`** — but this means a user who genuinely wants to configure an Ollama model has no in-app flow and has to edit `settings-ollama.json` by hand. Is that the right call given the user's stated goal of eliminating CLI for normal account management? Compare with the csq philosophy of "dashboard replaces terminal for account operations".
3. **If Anthropic adds a second OAuth client_id** (e.g. a separate one for Claude Code on mobile or for enterprise SSO), does this modal architecture extend cleanly, or would it require a second picker level ("Claude Personal / Claude Enterprise")? The current provider picker reads from `providers::PROVIDERS` — nothing stops us adding `claude-enterprise` as a separate catalog entry, but the UX trade-off is more clicks for the 99% case where a user has one subscription type.

## Cross-references

- 0019-DISCOVERY-anthropic-oauth-endpoint-migration.md — endpoint move that eliminated Option B's value
- 0020-DECISION-paste-code-oauth-as-canonical-flow.md — backend architecture supporting this modal
- 0021-DISCOVERY-tauri-2-10-runtime-gotchas.md — Trap 3 (opener permission scope) is why the fallback URL is always visible
- `csq-desktop/src/lib/components/AddAccountModal.svelte` — the component
- `csq-desktop/src-tauri/src/commands.rs` — `start_claude_login`, `submit_oauth_code`, `list_providers`, `set_provider_key`, `cancel_login`
