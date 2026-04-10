# Claude Squad

Multi-provider session manager for Claude Code. Run Claude Code against local models (Ollama), third-party APIs (MiniMax, Z.AI), or pool multiple Claude Max subscriptions — all with per-terminal isolation, shared history, and a statusline.

## What it does

- **Any model provider** — `csq run 1 -p ollama` runs CC against a local Qwen/Gemma/GLM model via Ollama. `csq run 2 -p mm` routes through MiniMax. `csq run 3` uses your Claude Max subscription. Each terminal can use a different provider.
- **Per-terminal isolation** — each terminal gets its own `CLAUDE_CONFIG_DIR` and keychain slot. Swapping one terminal doesn't affect others. 15+ concurrent csq terminals work without contention.
- **Shared history & memory** — conversations, projects, and auto-memory are symlinked from `~/.claude`, so `/resume` works across all accounts and providers.
- **Context & cost in statusline** — see `csq #5:jack 5h:42% | ctx:241k 24% | $5.39` at a glance.
- **In-place account swap** — `! csq swap N` from inside CC switches credentials without restarting the conversation.
- **Quota visibility** — `csq status` shows all accounts with 5h and 7d usage, reset times, and capacity.
- **Profile overlays** — providers deep-merge onto your default settings, preserving hooks, plugins, and statusline.
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

The installer auto-detects your platform (macOS / Linux / WSL / Git Bash) and configures credential storage.

## Using local models (Ollama)

Run Claude Code against any model in Ollama — no API key needed, no rate limits, fully local.

### Prerequisites

Install [Ollama](https://ollama.com) and pull a model:

```bash
ollama pull gemma4           # 9.6 GB — recommended: fast, COC-compliant
ollama pull qwen3.5          # 6.6 GB — capable but slow on local hardware
```

Claude Code requires a large context window. Recommended: **256k tokens** (set via Ollama's `num_ctx` parameter or model defaults).

### Setup (one-time)

```bash
csq setkey ollama            # creates the Ollama profile (no key needed)
```

This creates `~/.claude/settings-ollama.json` with:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:11434",
    "ANTHROPIC_AUTH_TOKEN": "ollama",
    "ANTHROPIC_API_KEY": "",
    "ANTHROPIC_MODEL": "qwen3:latest",
    "ANTHROPIC_SMALL_FAST_MODEL": "qwen3:latest",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "qwen3:latest",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "qwen3:latest",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "qwen3:latest",
    "API_TIMEOUT_MS": "3000000",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
```

To change the model: `csq models ollama <model-name>` (or edit `~/.claude/settings-ollama.json` manually).

### Run

```bash
csq run 1 -p ollama          # start CC on account 1, routed through Ollama
```

See [Ollama's Claude Code integration docs](https://docs.ollama.com/integrations/claude-code) for more options.

## Using third-party APIs (MiniMax, Z.AI)

### MiniMax (M2.7)

```bash
csq setkey mm                # prompts for your MiniMax API key (hidden input)
```

Creates `~/.claude/settings-mm.json` with:

| Setting              | Value                              |
| -------------------- | ---------------------------------- |
| `ANTHROPIC_BASE_URL` | `https://api.minimax.io/anthropic` |
| `ANTHROPIC_MODEL`    | `MiniMax-M2.7-highspeed`           |
| All model aliases    | `MiniMax-M2.7-highspeed`           |

```bash
csq run 1 -p mm              # start CC routed through MiniMax
```

To change the model: `csq models mm <model-name>` (or edit `~/.claude/settings-mm.json` manually).

### Z.AI (GLM-5.1)

```bash
csq setkey zai               # prompts for your Z.AI API key (hidden input)
```

Creates `~/.claude/settings-zai.json` with:

| Setting              | Value                            |
| -------------------- | -------------------------------- |
| `ANTHROPIC_BASE_URL` | `https://api.z.ai/api/anthropic` |
| `ANTHROPIC_MODEL`    | `glm-5.1`                        |
| All model aliases    | `glm-5.1`                        |

```bash
csq run 1 -p zai             # start CC routed through Z.AI
```

### Claude direct API key

If you have a direct Anthropic API key (not OAuth/Max subscription):

```bash
csq setkey claude            # prompts for your API key
csq run 1 -p claude          # uses ANTHROPIC_API_KEY auth instead of OAuth
```

### How profiles work

Profiles are JSON files at `~/.claude/settings-<name>.json` that get deep-merged onto your default `~/.claude/settings.json` at terminal start. `csq setkey` creates and manages these files. You can edit them manually to change model names, timeouts, or add other settings.

When you run `csq run 5 -p mm`, csq:

1. Reads `~/.claude/settings.json` (your full default — hooks, statusline, plugins, etc.)
2. Reads `~/.claude/settings-mm.json` (the overlay)
3. Deep-merges them (overlay keys win; your default hooks/statusline/plugins carry through)
4. Writes the result to `config-5/settings.json` for that terminal only

Your default settings are never modified. Each terminal gets a fresh settings snapshot.

### Managing profiles

```bash
csq listkeys                 # show configured providers with masked key fingerprints
csq rmkey zai                # remove a profile entirely
```

### Model management

```bash
csq models                   # show all profiles + current models
csq models zai               # list available models for Z.AI
csq models zai glm-4.7       # switch zai to a different model
csq models ollama            # list locally installed ollama models
```

When a newer model is available, `csq models` shows an update indicator:

```
Profile      Model                          Status
zai          glm-4.7                        (update: glm-5.1)
mm           MiniMax-M2.7-highspeed         (latest)
```

The model catalog updates automatically — csq auto-updates from GitHub on every `csq run` (silently, in the background, with a 3s timeout for offline safety).

## Model benchmarks

csq ships two benchmark harnesses for testing how well models work with [COC](https://github.com/terrene-foundation/kailash-coc-claude-py) (Cognitive Orchestration for Codegen) artifacts. For the full COC framework and what these benchmarks measure, see the [kailash-coc-claude-py benchmark results](https://github.com/terrene-foundation/kailash-coc-claude-py#benchmarks).

### COC governance leaderboard (100 pts, 5-run averaged)

| Model               | Cooperative (/50) | Adversarial (/50) | Total (/100) |
| ------------------- | :---------------: | :---------------: | :----------: |
| **Claude Opus 4.6** |       50.0        |       43.0        |   **93.0**   |
| **Z.AI GLM-5.1**    |       49.0        |       36.8        |   **85.8**   |
| **MiniMax M2.7**    |       49.6        |       21.0        |   **70.6**   |
| **gemma4** (local)  |       45          |       10          |    **55**    |
| **qwen3.5** (local) |       25          |       26          |    **51**    |

All cloud models are 5-run averaged. Local models (Ollama) are single-run. Full per-test breakdowns and analysis at [kailash-coc-claude-py](https://github.com/terrene-foundation/kailash-coc-claude-py#benchmarks).

### Running benchmarks

```bash
# 100-point governance benchmark (rule obedience)
python3 test-coc-bench.py default "Claude Opus 4.6" --runs 5
python3 test-coc-bench.py mm "MiniMax M2.7" --runs 5
python3 test-coc-bench.py zai "Z.AI GLM-5.1" --runs 5
python3 test-coc-bench.py ollama "gemma4" --model-override gemma4:latest

# Implementation eval — COC vs bare comparison
python3 coc-eval/runner.py default "Claude Opus 4.6" --mode full
python3 coc-eval/runner.py default "Claude Opus" --tests EVAL-A004
```

Both harnesses use `coc-env/` as the reference environment. The harness resets between tests and captures file artifacts to verify what was actually written to disk.

## Multi-account rotation (Claude Max)

Pool multiple Claude Max subscriptions for uninterrupted sessions. When one account hits a rate limit, swap to another.

### The problem

Claude Max has rolling rate limits (5-hour and 7-day windows). Heavy users hit these regularly. Manually switching with `/login` interrupts flow and requires guessing which account has capacity.

### Setup (one-time per account)

```bash
csq login 1   # opens browser, log in to account 1, saves creds
csq login 2   # repeat for each account
csq login 3
# ...as many as you need
```

You can also capture credentials from an already-logged-in CC session — run `csq login N` from inside that CC instance.

### Daily use

```bash
csq run 1                    # terminal 1 on account 1
csq run 3                    # terminal 2 on account 3
csq run 5                    # terminal 3 on account 5
```

If you have only one account, `csq` (no number) auto-resolves. With zero accounts, `csq` is invisible — just runs vanilla `claude`.

Any extra arguments pass through to `claude`:

```bash
csq run 5 --resume           # resume the most recent conversation
csq run 5 --resume <id>      # resume a specific session
csq run 3 -p "summarize X"   # one-shot prompt
```

### When rate limited

Inside the rate-limited CC session, type:

```
!csq swap 3       # swap THIS terminal to account 3
```

The `!` prefix runs the command as a local shell op — works even when CC is rate-limited. The next message you send uses account 3's token, in the same conversation, no restart.

If you want to know which account to swap to:

```
!csq suggest      # shows the account with most capacity
```

### Quick start (single account)

```bash
csq              # equivalent to vanilla `claude` — csq stays out of your way
csq --resume     # passes flags straight through
```

## Command reference

```bash
csq run N [-p provider]      # start CC on account N, optional provider profile
csq run N --resume           # resume most recent conversation on account N
csq status                   # show all accounts with quota and reset times
csq suggest                  # suggest which account to swap to
csq swap N                   # in-place swap THIS terminal to account N
csq login N                  # save account N's credentials (opens browser)
csq setkey <provider> [key]  # add/update provider API key
csq listkeys                 # show configured providers with masked keys
csq rmkey <provider>         # remove a provider profile
csq cleanup                  # remove stale PID cache files
csq help                     # full command list
```

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

Only credentials, account identity, and `settings.json` stay isolated. Everything else in `~/.claude` (projects, sessions, history, plugins, commands, agents, skills, memory) is symlinked into each `config-N/` on every `csq run`. So all terminals see the same conversations, the same `/resume` list, and the same auto-memory — only the account and profile change.

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
