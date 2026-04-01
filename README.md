# Claude Squad

Multi-account rotation for Claude Code. Run 15+ terminals across 7 Claude Max accounts with intelligent, automatic quota management.

## What it does

- **Auto-rotates** accounts when rate limits hit — no manual intervention
- **Drains accounts smartly** — uses accounts whose weekly quota expires soonest first
- **Multi-terminal aware** — 15 terminals coordinate via file locks, no conflicts
- **Shows quota in statusline** — see usage and reset timers at a glance
- **Zero-browser switching** — swaps credentials in macOS Keychain, no `/login` needed after setup

## Install

```bash
curl -sfL https://raw.githubusercontent.com/terrene-foundation/claude-squad/main/install.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/terrene-foundation/claude-squad.git
cd claude-squad
bash install.sh
```

The installer walks you through logging in to each account (one-time browser auth per account).

## How it works

### The priority algorithm

**Use-it-or-lose-it**: Accounts with weekly quota resetting soonest get drained first.

```
Account 1: weekly resets in 1 day  → HIGH PRIORITY (use before it resets)
Account 2: weekly resets in 5 days → low priority (save for later)
```

When an account hits its 5-hour rate limit, it's temporarily "parked". The system switches to the next best account. When the 5-hour window resets, it switches back if that account is still highest priority.

### Multi-terminal coordination

Each terminal claims an account via a lockfile-coordinated assignment table. The system load-balances — if 3 terminals are on account 1, a new terminal will prefer account 2.

### Auto-rotation flow

```
Statusline renders (every few seconds)
  → Updates quota-state.json with current rate_limits
  → Checks: should this terminal rotate?
  → If yes: swaps Keychain credentials silently
  → Next API call uses the new account
```

No user action required. No browser. No `/login`.

## Usage

### Inside Claude Code

The system is fully automatic. When you hit a rate limit, it rotates for you.

Manual rotation is also available:

```
/rotate         # Show recommendation + rotate if needed
```

### From terminal

```bash
ccc quota       # Show all accounts with quota, priority, terminal assignments
ccc swap 3      # Manually switch to account 3
ccc status      # List configured accounts
ccc login 4     # Add a new account (browser, one-time)
ccc extract 4   # Save credentials after login
ccc help        # Full command list
```

## Files installed

| File | Location | Purpose |
|---|---|---|
| `rotation-engine.py` | `~/.claude/accounts/` | Core rotation logic + quota tracking |
| `ccc` | `~/.local/bin/` | CLI for account management |
| `auto-rotate-hook.sh` | `~/.claude/accounts/` | Hook: checks rotation on each message |
| `statusline-quota.sh` | `~/.claude/accounts/` | Statusline: shows quota + feeds data |
| `rotate.md` | `~/.claude/commands/` | `/rotate` slash command |

### Data files (created at runtime)

| File | Purpose |
|---|---|
| `~/.claude/accounts/credentials/N.json` | OAuth credentials per account (600 perms) |
| `~/.claude/accounts/quota-state.json` | Real-time quota data from all terminals |
| `~/.claude/accounts/assignments.json` | Which terminal PID owns which account |
| `~/.claude/accounts/profiles.json` | Account emails and auth methods |
| `~/.claude/accounts/rotation-history.jsonl` | Audit log of all rotations |

## Requirements

- macOS (uses macOS Keychain for credential storage)
- Claude Code CLI
- Python 3
- jq
- One or more Claude Max subscriptions

## How credentials work

Each account's OAuth credentials (access token + refresh token) are extracted from the macOS Keychain after a one-time browser login. On rotation, the engine writes the target account's credentials back to the Keychain and updates `~/.claude/.credentials.json` so Claude Code picks up the new credentials.

Claude Code automatically refreshes expired access tokens using the stored refresh token. No re-authentication needed.

## Uninstall

```bash
rm -rf ~/.claude/accounts
rm ~/.local/bin/ccc
rm ~/.claude/commands/rotate.md
# Remove the UserPromptSubmit hook from ~/.claude/settings.json manually
```

## License

Apache 2.0 — Terrene Foundation
