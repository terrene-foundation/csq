---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T00:05:00+08:00
author: co-authored
session_id: 2026-04-13-alpha-7
session_turn: 40
project: csq-v2
topic: alpha.7 slot-bind wrote apiKeyHelper into config-N/settings.json, triggering CC auth conflict between env.ANTHROPIC_AUTH_TOKEN and apiKeyHelper; hotfixed in alpha.8
phase: implement
tags: [alpha-7, alpha-8, bug, apikeyhelper, cc-settings, third-party, hotfix]
---

# 0043 — DISCOVERY — apiKeyHelper auth conflict on slot bind

**Status**: Fixed in v2.0.0-alpha.8 (PR #101, tag pushed, 16 assets
published).
**Predecessor**: 0042 (alpha.7 — third-party slot binding shipped).

## Symptom

User installed alpha.7 on a second Mac, ran
`csq setkey zai --slot 10 --key …`, then `csq run 10`. CC started but
printed:

```
⚠ Auth conflict: Both a token (ANTHROPIC_AUTH_TOKEN) and an API key
(apiKeyHelper) are set. This may lead to unexpected behavior.
  · Trying to use ANTHROPIC_AUTH_TOKEN? Unset the apiKeyHelper setting.
  · Trying to use apiKeyHelper?      Unset the ANTHROPIC_AUTH_TOKEN env var.
```

`csq run 9` (MiniMax) showed the same warning.

## Root cause

`csq-core::providers::settings::default_settings` (catalog-driven
defaults) serializes each provider's `system_primer` string into the
`apiKeyHelper` field:

```rust
if let Some(primer) = provider.system_primer {
    settings.insert("apiKeyHelper".to_string(), Value::String(primer.to_string()));
}
```

`apiKeyHelper` in CC is a **shell command that outputs an API key** —
not a system prompt. The provider catalog misused the field name.

The bug was **latent** before alpha.7 because the only consumer of
`default_settings` was the global `settings-<provider>.json` write
path, and CC never reads that file (it's an internal csq overlay
store). Alpha.7's new `bind_provider_to_slot` reused
`default_settings` to produce `config-<N>/settings.json`, which CC
_does_ read. The latent bug went fatal.

CC's resolution order is `env token` OR `apiKeyHelper exec`, so when
both are present it refuses to pick and emits the conflict warning on
every start. The primer string was never interpreted as a command —
CC just detected the conflict and warned.

## Fix

`bind_provider_to_slot` strips `apiKeyHelper` from the settings Value
before writing, unconditionally. Bearer-auth providers authenticate
via `env.ANTHROPIC_AUTH_TOKEN`; the primer belongs in a system-prompt
mechanism, not this field.

The global `settings-<provider>.json` path is **untouched** — the
field stays inert there, and ripping it out of the shared
`default_settings` risks surprising any other consumer. A proper
cleanup (move the primer to a system-prompt field, or drop it
entirely from the catalog) belongs in its own PR and is in the
alpha.9 queue.

Regression test: `bind_strips_api_key_helper` asserts the field is
absent from the written slot file while `ANTHROPIC_AUTH_TOKEN` is
preserved.

## User workaround (no reinstall)

```bash
for f in ~/.claude/settings.json ~/.claude/accounts/config-*/settings.json; do
  [ -f "$f" ] || continue
  if jq -e 'has("apiKeyHelper")' "$f" >/dev/null 2>&1; then
    jq 'del(.apiKeyHelper)' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  fi
done
```

Existing alpha.7-bound slots need this once; future
`csq setkey --slot N` calls land clean on alpha.8.

## For Discussion

1. The primer lives in `Provider::system_primer` and gets serialized
   into `apiKeyHelper` by `default_settings`. Alpha.8 strips it only
   at the slot-bind sink. Should alpha.9 instead delete the
   `apiKeyHelper` insertion from `default_settings` itself, and what
   code paths could that break — does anything downstream of
   `settings-<provider>.json` actually read the field?

2. This bug was invisible in CI because the unit tests for
   `bind_provider_to_slot` asserted the positive (token + base URL
   present) but not the negative (apiKeyHelper absent). If the
   regression test had been added during alpha.7 TDD, the bug would
   have been caught pre-merge. What other slot-bound settings fields
   deserve "must not be present" assertions — and is there a generic
   way to enumerate them from CC's settings schema?

3. If the user's first run after alpha.7 had been `csq setkey claude
--slot N --key sk-ant-…` (the Claude provider has no
   `system_primer`), would the bug have been discovered? Counterfactual:
   the catalog happens to only set `system_primer` for non-Anthropic
   providers, which is exactly the path the alpha.7 feature targeted.
   The bug was maximally reachable.
