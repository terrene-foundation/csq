---
type: DECISION
date: 2026-04-13
created_at: 2026-04-13T17:25:00+08:00
author: co-authored
session_id: 2026-04-13-alpha-6
session_turn: 100
project: csq-v2
topic: alpha.6 ships csq logout, hidden setkey, MM/Z.AI catalog updates, desktop Add Account redesign with Re-auth lock and sibling-quota inheritance, plus a keychain restoration that retracts an earlier mistake in this session
phase: implement
tags: [alpha-6, logout, setkey, providers, desktop, keychain, oauth, release]
---

# alpha.6 — logout + setkey UX + provider catalog + desktop Add Account redesign

## Released

**v2.0.0-alpha.6** tagged from `3684d1f` (PR #98 merged). Release workflow `24335672481` published 16 cross-platform assets in ~5 min, all 8 jobs green. csq-core 588 lib + 12 integration tests, csq-cli 36 + 34, total **685 tests passing**, clippy + fmt clean.

## What shipped

### 1. `csq logout N` (and `csq remove N` alias)

New `csq_core::accounts::logout::logout_account` helper plus a CLI command and a desktop **× Remove** button on every account card. Cleans up:

- `credentials/N.json` (canonical credential)
- `config-N/` (entire dir — INV-01 says it's permanent for the account's lifetime, and logout ends that lifetime)
- `profiles.json` entry
- `quota.json[N]` (added late in the session after the user noticed slot recycling could inherit a previous tenant's quota)

**Safety**: refuses with `LogoutError::InUse` if any live `term-*` handle dir's `.csq-account` symlink resolves to the target account AND `.live-pid` references an alive PID. The user must exit those terminals first. Tests use `Command::new("true").spawn() + wait()` to get a guaranteed-dead PID — `u32::MAX` does NOT work because `pid_t` is `i32` and `u32::MAX as i32 == -1`, which `kill(2)` treats as "every process".

The desktop button is two-tap: first click arms it (button reads "Confirm" red, 4-second auto-disarm), second click commits. A transparent `.armed-overlay` click-trap above the card body cancels on any other interaction.

### 2. `csq setkey {mm,zai,claude}` hidden TTY input

Three bugs fixed at once:

- **Long MiniMax JWT keys were silently truncated.** `read_to_string` on stdin runs the tty in canonical mode, which on Darwin/BSD caps the line buffer at `MAX_CANON=1024` bytes. Real Coding-Plan keys are 1000–1500+ chars and got cut mid-key, then the truncated value was saved and rejected with 401. Z.AI keys (~64 chars) fit so they appeared to work — that's why the bug presented as "zai works, mm fails".
- **Key was echoed in the terminal** (ECHO is on in cooked mode).
- **Enter alone did not submit** (`read_to_string` reads to EOF, requiring Ctrl-D).

Fix: when stdin is a tty, switch into non-canonical mode with `tcgetattr`/`tcsetattr` (clearing `ICANON | ECHO | ECHONL`), read byte-by-byte until newline. RAII guard restores termios on drop. Piped stdin keeps the old `read_to_string` fallback. Verified via Python `pty` harness with a 1800-char Z key paste: not echoed, not truncated, stored intact. Added `libc.workspace = true` to csq-cli (already in workspace; no new transitive crates).

### 3. MiniMax catalog — `api.minimax.io` + `MiniMax-M2.7-highspeed`

`api.minimax.chat/anthropic/v1/messages` rejects Coding-Plan `sk-cp-*` keys with `401 invalid api key`. Live-verified with a single-shot probe: `api.minimax.io/anthropic/v1/messages` returns `200` (or `529 overloaded` under load) with the same key. Journal 0026 already knew the live host was wrong but worked around it per-slot via `load_3p_base_url_for_slot` — alpha.6 fixes the catalog default so new `setkey mm` runs write the correct URL.

Default model also bumped from `MiniMax-M2` to `MiniMax-M2.7-highspeed` (the M2 wildcard quota covers both, but the highspeed shard has materially better latency under load).

### 4. Z.AI catalog — `glm-5.1`

Default model bumped from `glm-4.6` to `glm-5.1`. Old IDs survive as aliases in the models registry so `csq models switch` still resolves them.

### 5. Desktop Add Account modal redesign

- **Slot picker** at the top of the modal (1..=999, defaults to next free slot, validates against `takenSlots` from `get_accounts`). The OAuth provider button disables when the slot is invalid or already taken.
- **Seamless OAuth via shell-out** as the primary path. New `csq_core::accounts::login::find_claude_binary` walks `$PATH` then a fixed list of well-known install dirs (`/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.npm-global/bin`, `~/.bun/bin`, `~/.cargo/bin`, `~/.volta/bin`, `n/bin`). This list matters because Finder-launched apps inherit only the minimal Finder `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`) — the user's shell-installed `claude` is invisible to bare `Command::new("claude")`. This is what disabled `start_claude_login` in alpha.5 (journal 0040 §2). Resolving the absolute path here lets the desktop revive shell-out and stop forcing every user through the in-process paste-code workaround.
- **Paste-code fallback** triggers automatically when `start_claude_login` returns `CLAUDE_NOT_FOUND` (i.e. `find_claude_binary` returned None). The modal calls `begin_claude_login` + `openUrl` and switches to the paste-code step transparently.
- **Re-auth mode** via a new `reauthSlot` prop. When set, the slot input is locked, the "already in use" warning is suppressed (re-auth on a configured slot is the _correct_ behaviour, not an error), and the OAuth provider button stays enabled. Without this, the alpha.6 modal couldn't re-authenticate expired accounts because the slot was always reported as taken.

### 6. Sibling-quota inheritance

`get_accounts` builds a `HashMap<email, &AccountQuota>` from accounts that have populated quota data, then for any account whose own `quota.json` entry is missing (or only has `null` windows), it borrows the sibling's numbers. Same Anthropic identity = same backend quota, so the displayed numbers are identical by construction. Without this, a freshly-added duplicate-email slot showed `0%` for up to 5 minutes after Add Account (the daemon's poll interval).

### 7. Shared `csq_core::accounts::login::finalize_login`

Single source of truth for post-login bookkeeping (marker write, profile email read from `<config>/.claude.json`, broker-failed clear). Both `csq login` and the desktop `start_claude_login` and `submit_oauth_code` paths call it. CLI lost ~70 LoC of duplicated `get_email_from_cc` + `update_profile`. Fixes "Account 8 added but shows 'unknown'" — desktop wasn't writing to `profiles.json` at all before this.

### 8. 3P card click guard

`swap_account` now scans `discovery::discover_all` and refuses with a typed `THIRD_PARTY_NOT_SWAPPABLE` error when the slot is a 3P provider. 3P slots have no `credentials/N.json` — the legacy `rotation::swap_to` path crashed with "credential file not found: credentials/9.json" when users clicked an MM card. The dashboard now strips the typed prefix and shows the human sentence: _"account 9 is a MiniMax slot. Open a new terminal and run `csq run mm` to use this provider — desktop swap only works for Anthropic OAuth accounts."_

### 9. `csq login N` cache invalidation

Added a `notify_daemon_cache_invalidation(base_dir)` call to `finalize()` so the desktop sees newly-added accounts within 5 seconds of the terminal command finishing instead of waiting on a daemon restart. Mirrors `swap.rs` and `logout.rs`.

## The keychain mistake (and the retraction)

Earlier in this session I deleted `csq-core/src/credentials/keychain.rs` based on the alpha.5 session notes' instruction:

> "Delete `csq_core::credentials::keychain` module — dead code after `rotation/swap.rs` stopped calling `keychain::write`. Read-path callers in `csq-cli/.../login.rs` and `csq-desktop/.../commands.rs` should be inlined to `None` returns."

This was wrong. The 707 stale entries the alpha.5 cleanup purged were dead **handle-dir** keychain entries (one per `term-<pid>` whose dir got swept after CC wrote to it). CC's **config-dir** keychain entries are alive and load-bearing: when launched with `CLAUDE_CONFIG_DIR=config-N`, CC writes the credential JSON to the keychain at service name `Claude Code-credentials-{sha256(NFC(config_dir))[:8]}`, and on the user's modern macOS install **the credential JSON sometimes lives there without a sibling `.credentials.json` file**.

Confirmed via the account-7 regression: after `csq login 7` ran successfully via the alpha.5 binary, `config-7/.claude.json` had `oauthAccount.emailAddress: jack@kailash.ai` (CC wrote that), but `config-7/.credentials.json` did NOT exist. The credential JSON was only in the keychain at service `Claude Code-credentials-49132b3c`. csq's read path (which I'd just inlined to file-only) returned None → `discovery::discover_anthropic` couldn't find account 7 → desktop hid it → user reported "7 is still not showing".

**Restoration**: brought back `keychain.rs` as **read-only**. Write side stays dead (csq still doesn't generate stale entries; `security-framework` write-path calls stay deleted). Read uses the `security` CLI (already trusted on macOS, doesn't trigger per-binary auth prompts on debug rebuilds). Re-exported `service_name` and `read` from `credentials/mod.rs`. Restored the integration test that locks v1.x parity hashes byte-for-byte against CC's hash format. Added 5 unit tests around `service_name`. Added the fallback chain back in csq-cli `login.rs` and csq-desktop `commands.rs`: `keychain::read(...).or_else(|| credentials::load(...))`.

**Lesson for future sessions**: don't take "dead code" claims at face value. Verify with a grep for live keychain entries (`security dump-keychain | grep '^class: "genp"' -A 5`) before deleting. The handle-dir / config-dir distinction matters.

Account 7 was backfilled directly from the keychain blob (no re-OAuth needed) by reading `security find-generic-password -w` and writing the JSON to both `credentials/7.json` and `config-7/.credentials.json` with `0o600` permissions, plus a `profiles.json` entry.

## Decision: ship narrow alpha.6, defer the architectural cutover to alpha.7

The "pristine" fix for the credential-storage ambiguity is to stop sharing storage with CC entirely — csq runs its own OAuth flow, writes to its own files, hands those files to CC. That eliminates `keychain.rs` for real and removes the brittle dependency on CC's hash format. The code already exists (`csq_core::oauth::login::start_login` + `exchange_code` + the `OAuthStateStore`) — it's just used as the fallback path instead of the default.

Decided to defer this to alpha.7 because:

- alpha.6 is shippable with the keychain restoration (it's small, tested, mirrors alpha.5's behaviour)
- The cutover is ~half a day of focused work on its own and would require throwing away the desktop modal redesign for retesting
- Anthropic's OAuth client_id is currently CC's, so csq would need to either reverse-engineer the port-discovery bridge (journal 0039) or get its own client_id

Captured as alpha.7 work-queue items in `.session-notes`.

## Test totals after alpha.6

- csq-core lib: 588 (was 568 in alpha.5)
- csq-core integration: 12 (was 12 in alpha.5)
- csq-cli: 36 (was 36 in alpha.5)
- csq-desktop: 34 (was 34)
- Total: **685+ tests passing**, clippy `-D warnings` clean, fmt clean

## PR + release links

- PR: https://github.com/terrene-foundation/csq/pull/98
- Tag: https://github.com/terrene-foundation/csq/releases/tag/v2.0.0-alpha.6
- Release workflow run: `24335672481`
