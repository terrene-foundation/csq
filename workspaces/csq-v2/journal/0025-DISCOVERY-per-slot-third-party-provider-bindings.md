---
type: DISCOVERY
date: 2026-04-11
created_at: 2026-04-11T22:25:00+08:00
author: co-authored
session_id: session-2026-04-11f
session_turn: 85
project: csq-v2
topic: Third-party provider slots are per-directory (config-9/settings.json), not per-global (settings-mm.json at base). Discovery must walk config-N dirs to find them, and rotation must refuse to rotate OAuth credentials into a 3P-bound dir.
phase: implement
tags: [desktop, discovery, 3p-providers, rotation, data-model]
---

# DISCOVERY: Per-slot 3P provider bindings are the real data model; synthetic 9xx slots were a placeholder

## Context

The user reported having set "9 and 10" as slots — expecting them to show up in the dashboard. Pre-discovery, `discover_all` returned slots 1-8 (OAuth) + 901 (Z.AI) + 902 (MiniMax) — no 9 or 10. The user's actual state was:

```
~/.claude/accounts/
  credentials/1.json ... 8.json        ← OAuth slots 1-8
  config-9/settings.json               ← env.ANTHROPIC_BASE_URL=api.minimax.io/anthropic
  config-10/settings.json              ← env.ANTHROPIC_BASE_URL=api.z.ai/api/anthropic
  settings-mm.json                     ← legacy global MiniMax (no longer how the user thinks about it)
  settings-zai.json                    ← legacy global Z.AI
```

The `.csq-account` marker in each `config-N/` dir confirmed the user's intent: `config-9/.csq-account = 9`, `config-10/.csq-account = 10`. They were using `config-N` as the **canonical** location for 3P provider bindings, keyed by slot number, not the legacy global settings-*.json files at the base dir level.

## Finding

There are TWO parallel conventions for 3P providers in csq-core:

1. **Legacy global** — `{base}/settings-mm.json`, `{base}/settings-zai.json`, each taking a synthetic slot in the 9xx range (hardcoded 901, 902). These are read by `discover_third_party`.
2. **Per-slot** — `{base}/config-N/settings.json` with `env.ANTHROPIC_BASE_URL` + `env.ANTHROPIC_AUTH_TOKEN`, binding slot N to a provider. These are NOT read by any existing discovery function.

The dashboard reflected (1) only, so the user's (2) binding was invisible — slots 9 and 10 literally did not render.

## Fix

Added `discover_per_slot_third_party(base_dir)` that walks `{base}/config-*/settings.json`, extracts the base URL, classifies the provider via host-substring match (`provider_from_base_url`), and emits `AccountInfo` keyed on the slot number from the dir name. Integrated into `discover_all` at priority 2 (after OAuth, before legacy 3P).

Suppression rule: the legacy global `discover_third_party` output is filtered to drop any entry whose provider name matches a per-slot binding already emitted. Example: per-slot `config-9 → MiniMax` suppresses legacy `902 MiniMax` so the user sees only `#9 MiniMax` in the dashboard, not `#9 MiniMax` and `#902 MiniMax` side-by-side.

Also added routing guards in two places:

1. **Tray click handler** (`perform_tray_swap`) — short-circuits any click on a 3P slot with `"3P slots can only be swapped from the dashboard Sessions tab"`. The Toast surfaces it cleanly instead of letting `rotation::swap_to` fail with a cryptic `credentials/9.json: NotFound`.
2. **`swap_session` Tauri command** — refuses both cases: target is a 3P slot OR source config dir is already bound to a 3P provider. The second case is the dangerous one — `rotation::swap_to` would successfully write `.credentials.json` into the config dir, corrupting the 3P binding because the dir would then have BOTH a `settings.json` (pointing at MiniMax) and a `.credentials.json` (pointing at the rotated OAuth account). CC reads the credentials file first, so the 3P binding is effectively lost.

## Verification

Live test on the author's `~/.claude/accounts` (which is what prompted the fix):

```
slot=1    label=jack.hong@esperie.com               source=Anthropic
slot=2    label=momopoqmomo@gmail.com               source=Anthropic
...
slot=8    label=jack@kailash.ai                     source=Anthropic
slot=9    label=MiniMax                             source=ThirdParty { provider: "MiniMax" }
slot=10   label=Z.AI                                source=ThirdParty { provider: "Z.AI" }
```

Ten unified slots, no 901/902 duplicates, MiniMax and Z.AI at their intended positions.

## Consequences

- `get_accounts` IPC now returns slots 9 and 10 for the user; they render in the Accounts tab.
- The tray menu shows 10 entries with 3P slots suffixed `(dashboard)` so the user knows tray click on them routes differently.
- `swap_session` is harder to misuse: rotating a 3P-bound config dir to an OAuth account fails fast with a message pointing at the right workflow.
- Test delta: 507 → 526 Rust tests (+19: 16 discovery + 3 is_third_party_slot).
- **Quota tracking for 3P slots is NOT yet wired** — the existing quota cursor + poller uses hardcoded 901/902 slot keys for MiniMax/Z.AI. A slot-9 MiniMax binding will show 0% quota in the dashboard until the poller is updated to scan per-slot bindings. Follow-up issue: rewrite `broker::poller` (or wherever 3P quota lives) to key off the discovered slot numbers instead of constants.
- **The legacy `settings-mm.json` / `settings-zai.json` path is no longer the recommended way to bind 3P providers**. It's retained for backward compat but suppressed when a per-slot binding exists. A future session should either migrate existing global bindings into per-slot form or document them as deprecated.

## For Discussion

1. The per-slot binding model lets a user have DIFFERENT 3P providers in different slots (slot 9 = MiniMax, slot 10 = Z.AI, slot 11 = another MiniMax key). The legacy global model only allows one per provider. Is the per-slot freedom a feature or an attractive-nuisance — when would two slots bound to the same provider (e.g. two MiniMax keys) ever be correct, and should the rotation logic prefer one over the other?
2. `provider_from_base_url` uses host-substring matching (`contains("minimax")`). A user proxying MiniMax through a company firewall at `mm-proxy.internal.corp` would fail to classify. What's the right UX: show as "Third-party" with no provider name, or let the user override via a field in `settings.json`?
3. The 3P binding check in `swap_session` refuses rotation from a 3P-bound dir to an OAuth account. But what about rotating from one MiniMax key to another MiniMax key (both 3P)? That's a legitimate use case (failover between API keys) and the current check blocks it. Is the right fix to allow 3P→3P of the same provider, or require the user to edit settings.json directly?
