# 0042 — DECISION — alpha.7: Third-Party Slot Binding

**Date**: 2026-04-13
**Status**: Implemented, pending release
**Predecessor**: 0041 (alpha.6 — logout, setkey, providers, Add Account redesign)

## Context

Alpha.6 shipped `csq setkey mm` / `csq setkey zai`, but the command stored
the key globally in `settings-<provider>.json` with no way to attach it to
a numbered slot. `csq run 9 -p mm` was a stub that errored at the
`--profile` check, and the slot path before that hard-failed with
`credential file not found: credentials/9.json` because the launch path
loaded OAuth credentials unconditionally.

Result: a user who ran `csq setkey mm`, validated the key, and tried to
launch a MiniMax session on slot 9 hit a wall. The slot was discoverable
(`config-9/settings.json` was already present from a prior workflow) but
not runnable. The session-notes "alpha.7 work queue" called this out as
"3P 'card click' UX beyond the error message" and "csq run semantics for
3P aren't implemented."

## Decision

Implement Option A from the in-session triage:

1. **Slot-aware setkey** — `csq setkey <provider> --slot N --key KEY`
   writes `config-<N>/settings.json` from the provider's defaults +
   key, upserts `profiles.json[N]` with `method: "api_key"` and a
   `provider` extra field, and writes the `.csq-account` marker.
2. **3P-aware run** — `csq run N` detects per-slot 3P bindings via
   `discover_per_slot_third_party()` and routes through a new
   `launch_third_party()` that skips the OAuth broker check, the
   canonical credential load, and `copy_credentials_for_session`. The
   handle-dir's `settings.json` symlink resolves to `config-<N>`, so CC
   reads `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` on startup
   without any env passthrough from csq.

## Architecture

The single write path lives in a new module
`csq-core/src/accounts/third_party.rs`:

```
bind_provider_to_slot(base_dir, provider_id, slot, key)
    ├── validate provider exists, has base URL + key env var
    ├── create config-<N>/ if missing
    ├── default_settings(provider) → inject key → atomic write
    │       (unique_tmp → write → secure_file → atomic_replace)
    ├── profiles::set_profile(N, AccountProfile {
    │       email: "apikey:<provider>",
    │       method: "api_key",
    │       extra: { provider: <id> },
    │   })
    └── markers::write_csq_account(config_dir, slot)
```

The CLI handler (`csq-cli/src/commands/setkey.rs`) gains a fourth
parameter `slot: Option<AccountNum>`. If `Some`, it calls
`bind_provider_to_slot`; if `None`, it preserves the legacy global
`settings-<provider>.json` path so existing flows still work.

The run handler splits cleanly into `launch_third_party` and
`launch_anthropic`, with a shared `exec_or_spawn` helper that
deduplicates the Unix-`exec` vs Windows-`spawn` plumbing.

## What Was Considered and Rejected

- **Re-implementing `--profile mm` as a runtime overlay** — would
  duplicate the slot model in a second dimension (slot N + profile mm
  ≠ slot 9), and the user would have to remember which slot maps to
  which provider. Slot binding is the simpler mental model and matches
  how Anthropic OAuth slots already work.
- **Synthetic 3P slots in the 901/902 range** — the existing
  `discover_third_party` synthetic slots are useful for the
  setkey-without-slot fallback, but launching a CC session against
  slot 901 has no clean path to a `config-N/` and would require
  another special case in the run command.
- **Letting CC read keys from `settings-mm.json` directly via
  `CLAUDE_CONFIG_DIR`** — would require `settings-mm.json` to live
  inside a CC-readable config dir, which conflicts with its current
  role as a global "default key" store.

## Tests

8 new unit tests in `csq-core/src/accounts/third_party.rs::tests`:

- `bind_writes_settings_json_with_env`
- `bind_creates_profile_entry`
- `bind_writes_csq_account_marker`
- `bind_makes_slot_discoverable_as_third_party` (round-trips through
  `discovery::discover_per_slot_third_party`)
- `bind_rejects_empty_key`
- `bind_rejects_unknown_provider`
- `bind_overwrites_existing_slot_settings`
- `bind_preserves_other_profile_entries`

Workspace totals: **596 csq-core lib + 36 cli + 12 integration + 34
desktop + 10 daemon + 7 platform = 695 tests passing**, clippy
`-D warnings` clean, fmt clean.

## Security Review

`security-reviewer` returned CONDITIONAL PASS with two LOW findings,
both fixed in-session before commit (zero-tolerance rule 5 — no
residual risks):

- **L1**: `secure_file(&tmp).ok()` swallowed the chmod error,
  potentially publishing the credential file at the umask default.
  Now propagates as `ConfigError::InvalidJson { reason:
"secure_file: ..." }`. Fail closed.
- **L2**: The `serialize:` arm interpolated the serde error via
  `format!("serialize: {e}")` over a `Value` containing the API key.
  In practice `serde_json::to_string_pretty` over a `Value` is
  infallible, but a future `Serialize` impl that included the value
  in its error message could echo the key. Replaced with a fixed
  string `"settings serialize failed"`. Defense in depth.

PASSED checks (recorded for future reference):

- Atomic write order: `unique_tmp_path → write → secure_file →
atomic_replace` matches `security.md` rules 4 + 5.
- Path traversal: `slot: AccountNum` is the validated newtype
  (1..=999), `Display` writes a bare integer, `format!("config-{}",
slot)` cannot produce path separators. `provider_id` flows from a
  closed clap enum.
- `with_context` chain in `setkey.rs:50` interpolates `provider_id`
  and `slot`, never the key.
- `strip_sensitive_env` still strips `ANTHROPIC_*`, `AWS_BEARER_*`,
  `CLAUDE_API_KEY` from the child before exec on the 3P path
  (`run.rs`). A poisoned dotfile cannot redirect traffic before CC
  reads the slot's `settings.json`.
- 3P slots have no `credentials/<N>.json` and no quota writes —
  compatible with the daemon's "only the daemon writes quota" rule
  (3P slots are excluded from the OAuth usage poller).

## User-Facing Change

```bash
# Before (alpha.6): no path to attach a key to a slot
csq setkey mm                    # validates + saves global only
csq run 9 -p mm                  # ERROR: failed to load canonical credentials

# After (alpha.7): bind once, run normally
csq setkey mm --slot 9 --key sk-…
csq run 9                        # 3P slot detected, launches CC against MiniMax
```

The README "Using third-party APIs" section is rewritten with the
new flow, including a step-by-step explanation of what `--slot`
writes to disk and what `csq run` does to launch the slot.

## Outstanding (not in this release)

Items still in the alpha.7+ queue from session notes 0041:

- Architectural cutover: csq runs its own OAuth flow, deletes
  `keychain.rs` for real
- Same-email duplicate-slot badge in `AccountList.svelte`
- Bump GitHub Actions versions (deprecated 2026-09-16)
- Windows desktop smoke test
