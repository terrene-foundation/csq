---
type: DISCOVERY
date: 2026-04-17
created_at: 2026-04-17T14:30:00+08:00
author: co-authored
session_id: 2026-04-17-post-alpha14-gui-launch-fixes
project: csq-v2
topic: `csq setkey <provider> --slot N` followed by ESC + Enter silently binds the slot to the provider with a one-byte garbage token, and `csq login N` can't undo it
phase: implement
tags:
  [
    cli,
    tty,
    setkey,
    third-party,
    minimax,
    zai,
    login-flow,
    validation,
    unbind,
    auth-conflict,
  ]
---

# 0058 — DISCOVERY: `csq setkey` + ESC silently binds slot with garbage token, and `csq login` can't undo it

**Status:** Resolved (this branch)
**Severity:** P1 — one misstep at the prompt permanently pins a slot to a 3P provider with no self-recovery path.

## Context

Two symptoms, one root cause, plus a second cause that kept the first one stuck.

**Symptom A.** User ran `csq setkey mm --slot 1`, pressed **ESC** intending to cancel when the hidden prompt appeared, then pressed **Enter**. No error surfaced. From then on, `csq 1` launched CC against MiniMax instead of the user's Anthropic account.

**Symptom B.** The user then ran `csq login 1` to re-authenticate Anthropic on slot 1. OAuth completed and `credentials/1.json` rotated, but CC kept routing every request through MiniMax. Nothing the user did from the CLI could recover slot 1 without manually deleting a file.

## The two bugs

### B1 — Hidden-key reader treats ESC as data

`csq-cli/src/commands/setkey.rs::read_hidden_line` puts the TTY into non-canonical mode and reads bytes one at a time. The match arm before this branch:

- `\n` / `\r` → submit
- `0x04` (Ctrl-D) → cancel if empty, submit otherwise
- `0x08` / `0x7f` (backspace, DEL) → pop
- everything else → push to buffer

ESC (`0x1b`) landed in "everything else". Pressing ESC then Enter produced `key = "\x1b"` (one byte, non-empty), which passed the `if key.is_empty()` guard in `bind_provider_to_slot` and ran all three bind steps to completion:

1. `config-1/settings.json` written with
   `ANTHROPIC_BASE_URL=https://api.minimax.io/anthropic`,
   `ANTHROPIC_AUTH_TOKEN="\x1b"`, and MiniMax's model keys.
2. `profiles.json[1]` upserted with `method=api_key`, `provider=mm`.
3. `.csq-account` marker set to 1.

Everything after that works exactly as if the user had typed a real MiniMax JWT: discovery classifies slot 1 as 3P, the 3P usage poller polls MiniMax with the garbage token (getting 401 in the real endpoint), and `csq run 1` sets `CLAUDE_CONFIG_DIR=config-1`, giving CC the MiniMax env vars to route on.

### B2 — `csq login N` doesn't clear a pre-existing 3P binding

`csq-core/src/accounts/login.rs::finalize_login` is the post-login bookkeeping shared by the CLI `csq login` path and the desktop Add Account flow. Before this change it:

1. Wrote the `.csq-account` marker.
2. Read the OAuth email from `.claude.json` and upserted `profiles.json[N]` as `method=oauth`.
3. Cleared `broker_failed` sentinel.

It did **not** touch `config-N/settings.json`. CC consults env vars from settings before it consults OAuth credentials (spec 01 §1.x; tauri-commands rule 3 covers the general "env overrides" principle). So the fresh OAuth tokens sat untouched in `credentials/1.json`, never used, while CC kept pulling `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` out of `settings.json` and sending every request to MiniMax.

The `subscription_type: null` that shows up on these slots' OAuth credentials during investigation is a **red herring**: with 3P env vars in place, CC never exercises the OAuth subscription path at all. The refresher preserves whatever `subscription_type` was already in the file; OAuth exchange doesn't return it; CC backfills it on first Anthropic API call. But CC never makes an Anthropic API call on a 3P-pinned slot, so the field stays `null` indefinitely — a symptom of the binding, not a cause.

## Why the shape gate matters independently

Even once ESC cancels the prompt, `bind_provider_to_slot` should reject keys that are obviously not real credentials. Defense in depth: if a future revision of the reader regresses ESC handling (or if a user pipes garbage on stdin via `echo x | csq setkey mm --slot N`), the bound slot still can't be written. Real keys are dozens of bytes at minimum; control characters aren't in any provider's key alphabet.

## Resolution

Three changes, one PR:

### 1. `read_hidden_line` treats ESC as cancel

Extracted the per-byte state machine into a pure `handle_key_byte` function with a `KeyInputStep` return. ESC (`0x1b`) returns `Err("cancelled")` unconditionally, at any position in the buffer. Ten unit tests added covering submit-on-newline, submit-on-CR, ESC-empty, ESC-partial (the historical failure), Ctrl-D-empty (cancel), Ctrl-D-nonempty (submit), backspace, DEL, overflow, and plain-byte accumulation.

### 2. `bind_provider_to_slot` validates key shape

New `validate_key_shape` helper with three rejection tiers:

- Empty key → `"api key is empty"` (preserved behavior).
- `key.len() < MIN_KEY_LEN` (8) → `"api key too short"`.
- Any byte `< 0x20` or `== 0x7f` → error message **explicitly mentions ESC** so a confused user who hit ESC at the prompt immediately connects the dots.

`MIN_KEY_LEN = 8` is a conservative floor — far below real provider keys (MiniMax JWTs are kilobytes, Z.AI keys are 40+ chars). Pre-existing tests that used 1–5 byte test keys were updated to 8+ bytes.

### 3. `finalize_login` unbinds any 3P settings on the slot

New `unbind_provider_from_slot` symmetric with `bind_provider_to_slot`:

- Reads `config-N/settings.json`.
- Strips `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, and every key in `session::merge::MODEL_KEYS` from the `env` block.
- Collapses an emptied `env` block and an emptied root object: if the whole file would be `{}`, deletes it instead of writing `{}` (some downstream readers treat a present-but-empty settings differently from absent).
- **Preserves non-3P env keys** the user may have hand-added (e.g. `NODE_ENV`, `HTTP_PROXY`). Only the known 3P keys get stripped.
- Returns `Ok(false)` (not an error) for missing files, malformed JSON, and already-unbound slots. Malformed JSON is logged but not destructively truncated.

`finalize_login` now calls this function _before_ the profile upsert. Failures propagate — we'd rather the user see "login cleanup failed" than silent success followed by "login didn't take."

## Unblock path for already-stuck machines

For any slot currently pinned to a 3P provider with a junk token:

```bash
rm ~/.claude/accounts/config-<N>/settings.json
# optional: remove the stale "method=api_key provider=mm" entry from profiles.json,
# or re-run `csq login N` under the new binary which will repair the profile too.
```

After the new binary ships, `csq login N` does the same cleanup automatically.

## Impact on invariants

- **Rule `account-terminal-separation.md`** — unchanged. Quota, credentials, and marker discipline all preserved.
- **Spec 02 (handle-dir model)** — handle dirs are unaffected; this is purely about `config-N/settings.json`.
- **Spec 04 (daemon)** — refresher / poller behavior unchanged.
- **`bind_provider_to_slot` contract** — tightened (rejects short and control-char keys). No caller was relying on submitting keys shorter than 8 bytes in real use; two unit tests that did have been updated.

## Consequences & follow-ups

1. **UI parity.** The desktop "Add MiniMax provider" modal almost certainly has the same open-loop (accept any non-empty string as a key). Worth auditing `csq-desktop/src/lib/components/...` for the equivalent validation — any frontend key collector should reject control bytes and enforce `MIN_KEY_LEN` before calling `set_provider_key`. Tauri-commands rule 2 applies (validate at the handler boundary).
2. **`csq doctor`.** Should detect slots where `config-N/settings.json` has 3P env vars AND `credentials/N.json` holds valid OAuth creds — that's an inconsistent state a user might want flagged even outside the login flow. Falls into the same `csq doctor` milestone that covers node-runtime detection (journal 0057).
3. **Provider-specific minimums.** `MIN_KEY_LEN = 8` is a one-size floor. If a future provider ever uses 4-char API keys, tighten per provider. Unlikely; real keys trend longer.
4. **Observability.** The unbind is logged via `tracing::info!`. In the stuck-machine scenario, that's the evidence the user will point at to confirm the fix took. `get_update_status`-style UI surfaces could read the daemon log for a one-shot "last login cleared MiniMax from slot N" banner.

## For discussion

1. The defense-in-depth split between (1) ESC-cancels in the reader and (2) shape validation in `bind_provider_to_slot` is redundant in the happy path — any key that survives (1) will also survive (2). Is the duplication worth the complexity, or would a single well-placed gate (at the prompt, with a richer validation predicate) be cleaner? What scenarios does each gate catch that the other doesn't?
2. `finalize_login` now fails hard if `unbind_provider_from_slot` returns `Err`. If the filesystem is truly broken (read-only, full), the user can't log in at all — but arguably they can't `csq run` either, so maybe the hard-fail is honest. If instead this had been a best-effort `let _ = ...`, what new failure mode would that introduce?
3. The `subscription_type: null` investigation that preceded these fixes is a good example of pattern-matching on the most salient artifact instead of tracing the actual data flow. The 3P env block was hiding in plain sight in `settings.json`; the OAuth credential file looked "almost right." What would make the next "slot stuck on wrong provider" investigation reach for settings.json first — a diagnostic tool, a structural change in where 3P bindings are stored, or a logging change?
