---
type: DISCOVERY
date: 2026-04-21
created_at: 2026-04-21T00:00:00Z
author: agent
session_id: 2026-04-21-codex-analyze
session_turn: 17
project: codex
topic: Codex refresh-token single-use race and the daemon-sole-refresher mitigation
phase: analyze
tags: [oauth, refresh-token, race-condition, daemon, codex, security]
---

# Discovery — Codex refresh-token race class and mitigation path

## Context

The openai/codex CLI uses OpenAI's OAuth device-auth flow. On each refresh, the server rotates the refresh token — old refresh tokens become immediately invalid. If two codex processes on the same machine share a single `$CODEX_HOME/auth.json` and both attempt to refresh before the other writes the result back, one wins and the other sees `refresh_token was already used` and must be re-logged-in.

This is documented in openai/codex#10332 (race across multiple app-server instances) and openai/codex#15502 (copying auth.json between CODEX_HOMEs permanently breaks the copy). OpenAI's own guidance: "Use one `auth.json` per runner or per serialized workflow stream."

## Discovery

The failure class is structurally identical to the Anthropic refresh-token race csq already solves via `credentials/N.refresh-lock` + daemon-held `tokio::sync::Mutex` per account. The same mitigation pattern applies to Codex:

- Canonical credential file lives in a daemon-writable location (`credentials/codex-<N>.json`, separate from `config-<N>` which is user-editable).
- Every handle dir for an account symlinks to the same canonical file; copies are forbidden (enforced by symlink-only layout per spec 07 §7.2.2).
- Daemon holds a per-account `tokio::sync::Mutex` and is the sole writer of the canonical file.
- `csq run` for a Codex slot refuses to launch if the daemon is not running (INV-P02), preventing codex from independently refreshing when csq cannot coordinate.

## Why this matters

1. **csq's existing moat applies directly.** The Anthropic refresh-coordination machinery csq built (spec 04 INV-06, the refresh-lock pattern, supervised refresher subsystem) extends cleanly to Codex. We do NOT need to build a new concurrency model; we need to parameterize the existing one by surface.
2. **The assumption is load-bearing.** If `cli_auth_credentials_store = "file"` does not actually prevent codex from refreshing in-process (OPEN-C01 in spec 07 §7.7.1), the file-symlink approach alone doesn't stop two running codex processes from both refreshing. The daemon-sole-refresher pattern still solves it — but only if the daemon is actually refreshing early enough that codex never sees a stale token. That means the refresh window (currently 2h before expiry for Anthropic per spec 04 INV-06) must apply to Codex too, AND codex's in-process refresh threshold must be later than that.
3. **Keychain escalation is a separate threat.** On macOS, codex's default is to store tokens in the OS keychain. This bypasses the file-symlink discipline entirely — two codex processes both refreshing against a keychain-backed token reproduces the race at a different layer. ADR-C04 pre-seeds `cli_auth_credentials_store = "file"` in `config-<N>/config.toml` BEFORE running `codex login`, forcing file-based storage from the first login onward. ADR-C11 probes for pre-existing keychain residue and refuses to provision the slot if the user declines purge.

## Follow-up actions

- Resolve OPEN-C01 before PR1 ships. The verification method is in spec 07 §7.7.1: read openai/codex source at `codex-rs/login/src/auth/*`, observe behavior with two running processes.
- Integration test for the mutex dance (INV-P08): two parallel `csq login N --provider codex` invocations serialize correctly; mode-flip 0400↔0600 never corrupts the file.
- Integration test for INV-P01 regression: under daemon control, a refresh cycle completes, all sibling terminals see the new token via symlink stat, and no process observes `refresh_token was already used` under simulated concurrency.

## For Discussion

1. If OPEN-C01 resolves with "`cli_auth_credentials_store = "file"` does NOT disable in-process refresh", is the right move to (a) patch codex upstream, (b) gate csq on a codex version that supports disabling, or (c) accept that csq's mitigation is "make refresh happen before codex notices"? The evidence from the earlier research agent run is ambiguous; a direct source read is the next step.
2. Compare the Codex race to journal 0052 (Anthropic `invalid_scope` on refresh). Both are load-bearing OAuth-edge-case stories. The Anthropic case turned out to be a parameter bug in our request (scope inclusion), not a concurrency issue. For Codex, is there a similar single-parameter mistake that could produce a "false race" we're mistakenly architecting around? Verify by reading the actual refresh requests codex emits.
3. If the daemon is the sole refresher and it goes down mid-session, codex will eventually refresh in-process and burn the refresh token. INV-P02 catches this at launch time, but not at mid-session. Is the right mitigation (a) daemon supervisor with faster restart, (b) codex health-check that fails closed when daemon is down, or (c) accept the narrow failure window?

## References

- openai/codex#10332 — concurrent refresh race
- openai/codex#15502 — copying auth.json breaks refresh
- spec 07 INV-P01, INV-P02, INV-P08, INV-P09
- spec 07 §7.7.1 OPEN-C01 (the load-bearing verification)
- csq-core/src/daemon/refresher.rs — existing Anthropic mutex pattern
- journal 0052 (csq-v2) — related class of OAuth-edge-case bug
