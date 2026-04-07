# Claude Squad

Account rotation, quota tracking, and profile overlays for Claude Code. Pool multiple Claude Max subscriptions with automatic, quota-aware switching — or use it on a single account just for the statusline and profile overlays. Each terminal isolated, no cross-contamination.

## The problem

Claude Max has rolling rate limits (5-hour and 7-day windows). Heavy users hit these regularly. Manually switching with `/login` interrupts flow and requires guessing which account has capacity.

## What Claude Squad does

- **In-place account swap** — `! csq swap N` from inside CC switches the current terminal to account N without restart, in the same conversation. CC picks up the new credentials on its next API call.
- **Per-terminal isolation** — each terminal runs with its own `CLAUDE_CONFIG_DIR`, so swapping one terminal doesn't affect others. 15+ concurrent csq terminals work without contention.
- **Shared history & memory** — conversations, projects, and auto-memory are symlinked from `~/.claude`, so `/resume` works across all accounts.
- **Context & cost in statusline** — see `⚡csq #5:jack 5h:42% | ctx:241k 24% | $5.39` at a glance.
- **Quota visibility** — `csq status` shows all accounts with 5h and 7d usage, so you can pick the one with most capacity.
- **Unlimited accounts** — log in as many accounts as you have (1, 7, 20 — no cap).
- **Profile overlays** — start a terminal with a different API provider via `csq run N -p mm` (overlays deep-merge onto the canonical default settings).
- **Cross-platform** — macOS, Linux, WSL, and Windows (via Git Bash). Tested in CI on all three.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/terrene-foundation/claude-squad/main/install.sh | bash
```

Or clone and run locally:

```bash
git clone https://github.com/terrene-foundation/claude-squad.git
cd claude-squad
bash install.sh
```

The installer auto-detects your platform (macOS / Linux / WSL / Git Bash) and configures the right credential storage and package manager hints. Windows users run the same command from Git Bash (which Claude Code already requires).

## Quick start

If you only have **one** Claude account, just run:

```bash
csq          # equivalent to vanilla `claude` — csq stays out of your way
csq --resume # passes flags straight through
```

With zero csq accounts configured, `csq` is invisible — it just execs `claude`.

If you only have one csq account configured, `csq` runs on that account automatically. Once you log in a second account, csq starts asking which one you want.

## Setup (one-time per account)

Save each account's credentials to a numbered slot (any positive integer — 1, 2, 3, … 20, …):

```bash
csq login 1   # opens browser, log in to account 1, saves creds
csq login 2   # repeat for each account
csq login 3
# ...as many as you need
```

You can also save the credentials of an already-logged-in CC session — just run `csq login N` from inside that CC instance and it captures the current keychain entry.

## Daily use

With multiple accounts, start each terminal on a specific one — each gets its own keychain slot:

```bash
csq run 1     # terminal 1 → account 1 (own keychain entry)
csq run 3     # terminal 2 → account 3 (separate keychain entry)
csq run 5     # terminal 3 → account 5 (separate keychain entry)
```

If you have only one account configured, `csq` (no number) auto-resolves it. With zero accounts, `csq` is invisible — it just runs vanilla `claude`.

Any extra arguments are passed straight through to `claude`:

```bash
csq run 5 --resume          # resume the most recent conversation
csq run 5 --resume <id>     # resume a specific session
csq run 3 -p "summarize X"  # one-shot prompt
```

Each terminal survives reboots. The account assignment persists because the keychain entry is tied to the config directory, not the process. Conversation history, projects, and memory are shared across all accounts (symlinked from `~/.claude`), so `/resume` finds the same sessions regardless of which account you're on.

### When rate limited

Inside the rate-limited CC session, type:

```
!csq swap 3       # swap THIS terminal to account 3
```

The `!` prefix runs the command as a local shell op — no LLM call needed, so it works even when CC is rate-limited. The next message you send in CC will automatically use account 3's token, in the same conversation, no restart.

This works because Claude Code picks up updates to `.credentials.json` on its next interaction. `swap_to()` updates the file and the per-config-dir keychain entry, so the swap takes effect right away. Verified empirically.

If you want to know which account to swap to, run `!csq suggest` first.

### From terminal

```bash
csq status              # show all accounts with quota and reset times
csq suggest             # suggest which account to /login to
csq run 4               # start CC on account 4 (default settings)
csq run 4 -p mm         # start CC on account 4 with MiniMax provider
csq run 4 --resume      # resume the most recent conversation
csq swap 3              # in-place swap THIS terminal to account 3
csq setkey mm           # add/update MiniMax API key (interactive, hidden input)
csq listkeys            # show configured providers with masked keys
csq cleanup             # remove stale PID cache files
csq help                # full command list
```

## Using other AI providers (MiniMax, Z.AI, direct API)

csq can route Claude Code through different API providers using **profile overlays**. Each provider needs an API key set up once, then you start terminals with that provider.

### Step 1: Add your API key

```bash
csq setkey mm                    # MiniMax — prompts for your key (hidden input)
csq setkey zai                   # Z.AI — same
csq setkey claude                # Claude direct API key (bypasses OAuth)
```

Or pass the key directly (shows in shell history):

```bash
csq setkey mm sk-your-key-here
```

You only need to do this once per provider. csq creates the profile file with all the right settings (API URL, model names, timeouts). To check what's configured:

```bash
csq listkeys                     # shows all profiles with masked key fingerprints
csq rmkey zai                    # removes a profile entirely
```

### Step 2: Start a terminal with that provider

```bash
csq run 5 -p mm                  # terminal 5, routed through MiniMax
csq run 3 -p zai                 # terminal 3, routed through Z.AI
csq run 1                        # terminal 1, default Claude Max (OAuth)
```

Each terminal is isolated — one can use MiniMax while another uses Claude Max. The provider is set at terminal start and doesn't change during the session.

### How it works (profile overlays)

Profiles are JSON files at `~/.claude/settings-<name>.json` that get deep-merged onto your default `~/.claude/settings.json` at terminal start. `csq setkey` creates and manages these files for you. You can also edit them manually if you need to tweak model names, timeouts, or other settings.

When you run `csq run 5 -p mm`, csq:

1. Reads `~/.claude/settings.json` (your full default — hooks, statusline, plugins, etc.)
2. Reads `~/.claude/settings-mm.json` (the overlay `csq setkey mm` created)
3. Deep-merges them (overlay keys win; your default hooks/statusline/plugins carry through)
4. Writes the result to `config-5/settings.json` for that terminal only

**Properties:**

- **Your default settings are never modified.** csq only reads `~/.claude/settings.json`, never writes to it.
- **Each terminal is a fresh start.** To switch providers, start a new terminal with a different `-p` flag.
- **Providers can't be hot-swapped mid-session.** API routing is set at startup. If you need a different provider, open a new terminal.

## How it works

### Per-terminal isolation

Claude Code uses `CLAUDE_CONFIG_DIR` to determine which keychain entry to read/write. The keychain service name is `Claude Code-credentials-<sha256(dir)[:8]>`. Each config directory gets a unique keychain slot.

```
csq run 3
  → CLAUDE_CONFIG_DIR=~/.claude/accounts/config-3
  → keychain: Claude Code-credentials-41cfdf87
  → isolated from all other terminals
```

### Shared artifacts

Only credentials, account identity, and `settings.json` stay isolated. Everything else in `~/.claude` (projects, sessions, history, plugins, commands, agents, skills, memory) is symlinked into each `config-N/` on every `csq run`. So all terminals see the same conversations, the same `/resume` list, and the same auto-memory — only the account and (optionally) the profile change.

Files that stay isolated per config dir:

- `.credentials.json` — OAuth tokens for this terminal's account
- `.current-account` — slot number this terminal is on
- `.claude.json` — onboarding state
- `settings.json` — fresh snapshot built from `~/.claude/settings.json` plus optional `-p` overlay

### Statusline data flow

```
Statusline fires (each render)
  → Feeds rate_limits JSON to rotation engine
  → Engine updates per-account quota in quota.json (stale-data protection
    via .quota-cursor — only writes when CC has actually made an API call
    on the current account, not when stale rate_limits leak through after
    a swap)
  → Engine back-syncs the live .credentials.json to credentials/N.json
    (content-matched by refresh token, race-proof) so a future swap from
    another terminal sees the latest tokens
```

### Manual swap, not auto-rotate

csq does **not** silently change accounts. Auto-rotate was removed because
CC's statusline JSON still contains the previous account's `rate_limits`
right after a swap, which made auto-rotate fire on stale data and thrash
between accounts. Users now read the statusline (which shows quota for all
accounts) and manually swap with `! csq swap N` when they want to switch.

### Credential storage

- **macOS**: per-config-dir keychain entry (`Claude Code-credentials-{sha256(dir)[:8]}`) with file fallback
- **Linux / WSL / Windows**: file-only (`.credentials.json` in the per-config-dir)

csq writes cached credentials directly during swap and never calls the OAuth
refresh endpoint itself. CC handles its own token refresh on its next API
call. This avoids hammering Anthropic's per-client-id refresh throttle.

## Files

| File                  | Installed to          | Purpose                                                           |
| --------------------- | --------------------- | ----------------------------------------------------------------- |
| `rotation-engine.py`  | `~/.claude/accounts/` | Core engine: quota tracking, in-place swap, credential back-sync  |
| `csq`                 | `~/.local/bin/`       | CLI: login, run, status, suggest, swap, cleanup, profile overlays |
| `statusline-quota.sh` | `~/.claude/accounts/` | Statusline hook: feeds quota to engine, shows account + %         |

### Data files

| File                                           | Purpose                                                |
| ---------------------------------------------- | ------------------------------------------------------ |
| `~/.claude/accounts/credentials/N.json`        | Stored OAuth creds per account (mode 600)              |
| `~/.claude/accounts/profiles.json`             | Email → account number mapping                         |
| `~/.claude/accounts/quota.json`                | Per-account quota from statusline                      |
| `~/.claude/accounts/config-N/`                 | Per-account CC config dir                              |
| `~/.claude/accounts/config-N/.current-account` | Tracks which account's creds are in this keychain slot |

## Requirements

| Platform           | Shell    | Credential storage         | Other          |
| ------------------ | -------- | -------------------------- | -------------- |
| macOS              | bash     | macOS Keychain + file      | Python 3, jq\* |
| Linux              | bash     | file (`.credentials.json`) | Python 3, jq\* |
| WSL                | bash     | file (`.credentials.json`) | Python 3, jq\* |
| Windows (Git Bash) | Git Bash | file (`.credentials.json`) | Python 3, jq\* |

\*jq is optional — without it the statusline simply doesn't show quota; everything else works.

Claude Code is required on every platform. On Windows, Git for Windows ships Git Bash, which CC already needs — no extra install.

You also need one or more Claude accounts. Single-account mode is fully supported; multi-account swap needs ≥2.

## Use in VS Code

The VS Code Claude Code extension reads the same `~/.claude/settings.json` that csq writes, so the statusline and `! csq swap N` should both work in VS Code's Claude Code panel. **However**, VS Code has known issues with hooks (Anthropic issues #16114, #18547, #28774) — the statusline may not always render and notification hooks may not fire. If you rely on the statusline or auto-features, run csq from a terminal CC session for the most reliable experience. The core swap functionality (`! csq swap N`) is a shell command and works regardless of hook reliability.

No VS Code extension or plugin is needed. Install csq once via the regular installer; VS Code picks it up automatically.

## Uninstall

### macOS / Linux / WSL

```bash
rm -rf ~/.claude/accounts
rm ~/.local/bin/csq          # or ~/bin/csq
# Remove hooks and statusLine from ~/.claude/settings.json
```

### Windows (Git Bash)

**IMPORTANT**: On Windows, csq creates directory junctions inside `config-N/` directories. Plain `rm -rf` follows junctions and deletes the TARGET contents (your real `~/.claude/projects/`, `~/.claude/sessions/`, etc.). Remove the junctions first:

```bash
# Remove junctions inside config-N before removing the parent
for d in ~/.claude/accounts/config-*/; do
    for item in "$d"*; do
        [ -L "$item" ] && rm "$item"
    done
done
rm -rf ~/.claude/accounts
rm ~/.local/bin/csq
# Remove hooks and statusLine from ~/.claude/settings.json
```

## Troubleshooting

**`csq swap` says swap succeeded but CC shows "rate limited"** — the access token in `credentials/N.json` may be in a stuck state on Anthropic's side (invalidated, flagged, or revoked). Run `csq login N` to capture a fresh token via a full OAuth flow.

**`python3` not found on Windows** — Windows Python registers as `python` or `py`. The installer detects this automatically. If it fails, install Python 3 from python.org (check "Add to PATH").

**Symlinks fail on Windows** — csq uses directory junctions (`mklink /J`) on Windows, which don't need admin privileges. If junction creation fails, csq falls back to copying. For full symlink support, enable Developer Mode in Windows Settings.

**Statusline shows wrong account number** — usually means a stale cache. `csq cleanup` removes stale PID cache files, then run `csq status` to refresh.

**Auto-rotate is disabled** — csq does NOT silently swap accounts behind your back. Auto-rotation was removed because it triggered on stale `rate_limits` data after manual swaps. Use `! csq swap N` when you want to switch.

## License

Apache 2.0 — [Terrene Foundation](https://terrene.foundation)
