# Code Session Quota (csq)

Multi-provider session manager for Claude Code. Run Claude Code against local models (Ollama), third-party APIs (MiniMax, Z.AI), or pool multiple Claude Max subscriptions -- all with per-terminal isolation, shared history, a desktop dashboard, and a statusline.

<table>
<tr>
<td><img src="docs/screenshots/accounts.png" width="380" alt="Accounts view with quota bars and rank badges"></td>
<td><img src="docs/screenshots/sessions.png" width="380" alt="Sessions view with sort and swap"></td>
</tr>
</table>

## What it does

- **Desktop dashboard** -- see all accounts, quota bars, token health, and reset times at a glance. Sort by custom order, 5h reset, or 7d reset. Ranked badges show which accounts to use first.
- **Any model provider** -- bind a provider to a slot with `csq setkey mm --slot 9 --key …`, then launch with `csq run 9`. Mix Claude Max OAuth slots, MiniMax, Z.AI, and local Ollama in the same account list.
- **Per-terminal isolation** -- each terminal gets its own `CLAUDE_CONFIG_DIR` and keychain slot. Swapping one terminal doesn't affect others. 15+ concurrent terminals work without contention.
- **Shared history & memory** -- conversations, projects, and auto-memory are symlinked from `~/.claude`, so `/resume` works across all accounts and providers.
- **Background daemon** -- auto-refreshes OAuth tokens and polls Anthropic for usage data. No manual token management after initial login.
- **In-place account swap** -- `! csq swap N` from inside CC switches credentials without restarting the conversation.
- **Context & cost in statusline** -- see `csq #5:alice 5h:42% | ctx:241k 24% | $5.39` at a glance.
- **System tray** -- tray icon with per-account quick-swap menu. Icon color reflects health (green/yellow/red).
- **Cross-platform** -- macOS, Linux, and Windows. Tested in CI on all three.

## Install

csq ships **unsigned, unnotarized** binaries for all three platforms (no Apple Developer ID, no Authenticode — the recurring cost isn't justified for an alpha release). The CLI works identically to a signed build; the desktop app triggers a one-time Gatekeeper warning on first launch that you have to bypass.

**macOS first-launch bypass** — fastest path (one terminal command):

```bash
xattr -cr "/Applications/Code Session Quota.app"
open "/Applications/Code Session Quota.app"
```

This clears the `com.apple.quarantine` extended attribute the browser
attaches on download, which is the only thing triggering Gatekeeper.
After that the app launches normally and every subsequent launch is
a plain double-click.

**macOS first-launch bypass** — System Settings path (no terminal):

1. Mount the `.dmg`, drag the `.app` to `/Applications/` as usual
2. Double-click the app. You'll see **"Apple could not verify `Code Session Quota` is free of malware..."** — click **Done**
3. Open **System Settings** → **Privacy & Security** → scroll to the **Security** section near the bottom
4. You'll see _"Code Session Quota was blocked from use because it is not from an identified developer."_ — click **Open Anyway**
5. Enter your password, confirm; from then on double-click works

> The classic "right-click → Open → Open" bypass **no longer works on
> macOS Sonoma+** for unnotarized apps — Apple removed that path in 2023. System Settings is now the only UI bypass, or use the `xattr`
> command above.

**If you see "file is damaged and can't be opened"** — that's the old
`v2.0.0-alpha.4` bundle with a broken Tauri bundler signature. Upgrade
to `v2.0.0-alpha.5` or later; or run this once as a one-shot fix on
the damaged copy:

```bash
xattr -cr "/Applications/Code Session Quota.app"
codesign --force --deep --sign - "/Applications/Code Session Quota.app"
open "/Applications/Code Session Quota.app"
```

CLI binaries download via the install script without any warnings. The desktop app ships as `.dmg` (macOS), `.AppImage`/`.deb`/`.rpm` (Linux), and `.msi` (Windows). You can also build any component from source.

### Prerequisites

- **Claude Code** — install via [docs.anthropic.com/en/docs/claude-code](https://docs.anthropic.com/en/docs/claude-code)
- Building from source: **Rust** 1.94+ ([rustup.rs](https://rustup.rs)) and, for the desktop app, **Node.js** 22+

### CLI — binary install (recommended)

<table>
<tr>
<th>macOS</th>
<th>Linux</th>
<th>Windows</th>
</tr>
<tr>
<td>

```bash
curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | bash
```

Installs to `~/.local/bin/csq`. SHA256 verified against the release's `SHA256SUMS`.

Works on both Apple Silicon (`aarch64`) and Intel (`x86_64`).

</td>
<td>

```bash
curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | bash
```

Installs to `~/.local/bin/csq`. SHA256 verified against the release's `SHA256SUMS`.

`x86_64` only. For `aarch64` Linux, build from source.

</td>
<td>

```powershell
# PowerShell
$url = "https://github.com/terrene-foundation/csq/releases/latest/download/csq-windows-x86_64.exe"
New-Item -ItemType Directory -Force "$env:USERPROFILE\.local\bin" | Out-Null
Invoke-WebRequest $url -OutFile "$env:USERPROFILE\.local\bin\csq.exe"
```

Then add `%USERPROFILE%\.local\bin` to `PATH` if it isn't already.

</td>
</tr>
</table>

After install:

```bash
csq --version    # should print: csq 2.0.0-alpha.7
csq doctor       # runs diagnostics
csq login 1      # authenticate your first account
```

### CLI — from source

```bash
git clone https://github.com/terrene-foundation/csq.git
cd csq
cargo build --release -p csq-cli
cp target/release/csq ~/.local/bin/csq    # or anywhere on your $PATH
```

### Desktop app — binary install

Download the latest artifact for your platform from [GitHub Releases](https://github.com/terrene-foundation/csq/releases).

<table>
<tr>
<th>macOS</th>
<th>Linux</th>
<th>Windows</th>
</tr>
<tr>
<td>

**`csq-desktop-macos.dmg`**

1. Double-click the `.dmg` to mount it
2. Drag `Code Session Quota.app` to `Applications`
3. Right-click the app → **Open** → **Open** (first launch only)

macOS remembers your choice after the first launch.

</td>
<td>

**`csq-desktop-linux.AppImage`** — no install, just run:

```bash
chmod +x csq-desktop-linux.AppImage
./csq-desktop-linux.AppImage
```

Or install system-wide with **`csq-desktop-linux.deb`** / **`csq-desktop-linux.rpm`**:

```bash
sudo dpkg -i csq-desktop-linux.deb
# or
sudo rpm -i csq-desktop-linux.rpm
```

</td>
<td>

**`csq-desktop-windows.msi`**

1. Double-click the `.msi` to run the installer
2. On first launch: **More info** → **Run anyway** (SmartScreen)

SmartScreen remembers your choice after the first launch.

</td>
</tr>
</table>

### Desktop app — from source

```bash
git clone https://github.com/terrene-foundation/csq.git    # skip if already cloned
cd csq/csq-desktop
npm install
npx @tauri-apps/cli build
```

Artifacts land at `target/release/bundle/<format>/`:

| Platform | Outputs                                         |
| -------- | ----------------------------------------------- |
| macOS    | `macos/Code Session Quota.app`, `dmg/*.dmg`     |
| Linux    | `deb/*.deb`, `rpm/*.rpm`, `appimage/*.AppImage` |
| Windows  | `msi/*.msi`, `nsis/*-setup.exe`                 |

### Development mode

```bash
cd csq-desktop && npx @tauri-apps/cli dev    # hot-reload desktop
cargo run -p csq-cli -- run 1                # run CLI from source without install
```

## Upgrading from an earlier csq

csq has been through three generations. Find your current version below
and follow the matching path. **Your accounts and credentials in
`~/.claude/accounts/` are preserved across every generation** — the
credential file layout (`credentials/N.json` + `config-N/`) has been
stable since the original Python version.

```bash
csq --version    # tells you which generation you're on
```

### From the Python era (v1.x — `pip install csq` / git clone)

The original csq was a stdlib-only Python tool (`rotation-engine.py`).
If you installed it via `pip` or by cloning the repo and adding it to
`$PATH`, that version is no longer maintained. Migrate to the Rust v2:

```bash
# Optional — uninstall the old Python version
pip uninstall csq    # if you used pip
# Or just delete your old git checkout — credentials live in
# ~/.claude/accounts/ and are not touched by uninstall

# Install the current Rust binary
curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | bash
csq --version    # csq 2.0.0-alpha.7
```

Your accounts at `~/.claude/accounts/credentials/N.json` are picked
up automatically by the Rust version — same paths, same JSON schema,
no migration step needed. Run `csq doctor` to verify the daemon can
see all your accounts.

> **About commands**: a few v1.x command flags were renamed in v2.
> `csq run N` and `csq swap N` are unchanged. If a script references
> a flag that no longer exists, run `csq help` for the current
> surface.

### From an early Rust release (`v2.0.0-alpha.1`, `alpha.2`, or `alpha.3`)

`csq update install` exists in your installed binary but will refuse
with _"the release signing key has not been configured"_ — the
Foundation Ed25519 key was first wired into a public release at
`alpha.4` and your old binary still has the dev placeholder.
(`alpha.3` was tagged but never published — its CI build failed.)
Re-run the installer **once** to pick up `alpha.4`, after which
auto-update works for every subsequent release:

```bash
curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | bash
csq --version    # csq 2.0.0-alpha.7
csq update check # should now report up-to-date
```

After this one-shot upgrade, the canonical path is `csq update install`
(see below) — you won't need the curl-pipe again.

### From `v2.0.0-alpha.4` or later — `csq update install`

Once you're on `alpha.4` or later, csq verifies releases against the
Foundation's Ed25519 signing key and can upgrade itself in place:

```bash
csq update check         # see if a newer version exists
csq update install       # download, verify SHA256 + Ed25519, atomic swap
```

The CLI also runs a background check on every invocation and prints
`csq vX.Y.Z available — run csq update install to upgrade` to stderr
when a release lands. Cached for 24 hours per machine. The desktop
app does the same check on launch and surfaces the notice via system
log.

### Desktop app upgrades

The desktop bundle (`Code Session Quota.app` on macOS, `.msi` on
Windows, `.deb`/`.rpm`/`.AppImage` on Linux) is a separate artifact
from the CLI binary and currently upgrades by re-downloading from
[GitHub Releases](https://github.com/terrene-foundation/csq/releases).
The CLI binary inside the desktop bundle and the standalone CLI binary
are interchangeable — installing the standalone CLI does NOT replace
the desktop bundle, and vice versa. If you use both, upgrade both.

The desktop daemon runs the same background update check as the CLI
and prints to the system log on launch when an update is available;
in-app notification UI is on the roadmap for a future release.

### What if I have local changes?

`csq` does not modify the user's `~/.claude/accounts/` data structure
across versions, so an upgrade is safe even if you're mid-session:

- Running CC sessions: each session uses an ephemeral
  `term-<pid>/` handle dir under `~/.claude/accounts/`. The daemon
  sweep preserves any pasted images into `~/.claude/image-cache/`
  before removing dead handle dirs, so closing your terminal and
  upgrading does not lose work.
- The daemon: stop it before upgrading the desktop app
  (`Quit` from the tray menu, or `csq daemon stop` for the CLI
  daemon). The new version will re-launch on next CLI invocation
  or on app start.

## Using local models (Ollama)

Run Claude Code against any model in Ollama -- no API key needed, no rate limits, fully local.

### Prerequisites

Install [Ollama](https://ollama.com) and pull a model:

```bash
ollama pull gemma4           # 9.6 GB -- recommended: fast, COC-compliant
ollama pull qwen3.5          # 6.6 GB -- capable but slow on local hardware
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

Third-party providers are assigned to numbered slots the same way OAuth accounts are. Each slot gets its own `config-<N>/settings.json` with the provider's base URL, API key, and default model. You then launch it with plain `csq run <N>`.

### MiniMax (M2.7)

```bash
csq setkey mm --slot 9 --key sk-…   # validates the key, writes config-9/settings.json
csq run 9                           # launches CC routed through MiniMax on slot 9
```

`csq setkey mm --slot 9` writes `~/.claude/accounts/config-9/settings.json` with:

| Setting                | Value                              |
| ---------------------- | ---------------------------------- |
| `ANTHROPIC_BASE_URL`   | `https://api.minimax.io/anthropic` |
| `ANTHROPIC_AUTH_TOKEN` | your key                           |
| `ANTHROPIC_MODEL`      | `MiniMax-M2.7-highspeed`           |

It also upserts `profiles.json[9]` with `method: "api_key"` and writes the `.csq-account` marker so the dashboard and `csq run` can identify the slot.

Omitting `--key` prompts for the key with hidden input (paste-safe for long JWTs). Omitting `--slot` falls back to the legacy global `settings-mm.json` store (no slot binding — useful only if you plan to attach it to a slot later).

### Z.AI (GLM-5.1)

```bash
csq setkey zai --slot 10 --key …
csq run 10
```

Writes `config-10/settings.json` with:

| Setting                | Value                            |
| ---------------------- | -------------------------------- |
| `ANTHROPIC_BASE_URL`   | `https://api.z.ai/api/anthropic` |
| `ANTHROPIC_AUTH_TOKEN` | your key                         |
| `ANTHROPIC_MODEL`      | `glm-5.1`                        |

### Claude direct API key

If you have a direct Anthropic API key (not OAuth/Max subscription):

```bash
csq setkey claude --slot 11 --key sk-ant-…
csq run 11
```

### How slot binding works

When you run `csq setkey <provider> --slot <N> --key <KEY>`, csq:

1. Validates the key against the provider (best-effort probe).
2. Creates `~/.claude/accounts/config-<N>/` if missing.
3. Writes `config-<N>/settings.json` with the provider's `env` block (base URL, token, model keys).
4. Upserts `profiles.json[N]` with `method: "api_key"` and `provider: <id>`.
5. Writes the `.csq-account` marker.

When you then run `csq run <N>`, csq:

1. Detects the slot is third-party via `discover_per_slot_third_party()` (it reads `env.ANTHROPIC_BASE_URL` from `config-<N>/settings.json`).
2. Skips the OAuth credential load — third-party slots have no `credentials/<N>.json` on purpose.
3. Creates an ephemeral `term-<pid>` handle dir with a `settings.json` symlink back to `config-<N>`.
4. Execs `claude` with `CLAUDE_CONFIG_DIR` set to the handle dir. CC reads the provider env from the symlinked `settings.json` at startup and routes every request through the provider.

Your default `~/.claude/settings.json` is never modified. Each terminal gets a fresh handle dir that is swept when the process exits.

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

The model catalog updates automatically -- csq auto-updates from GitHub on every `csq run` (silently, in the background, with a 3s timeout for offline safety).

## Model benchmarks

csq routes Claude Code to any provider -- but which models actually work well? We ship benchmark harnesses that test model performance under real workloads.

### Which model should I use?

| Model               | Provider | Runs  |   Speed   | Cooperative (/50) | Adversarial (/50) | Total (/100) |
| ------------------- | -------- | ----- | :-------: | :---------------: | :---------------: | :----------: |
| **Claude Opus 4.6** | default  | 5-run | 13s/task  |       50.0        |       43.0        |   **93.0**   |
| **Z.AI GLM-5.1**    | zai      | 5-run | 46s/task  |       49.0        |       36.8        |   **85.8**   |
| **MiniMax M2.7**    | mm       | 5-run | 14s/task  |       49.6        |       21.0        |   **70.6**   |
| **gemma4**          | ollama   | 1-run | 165s/task |        45         |        10         |    **55**    |
| **qwen3.5**         | ollama   | 1-run | 175s/task |        25         |        26         |    **51**    |

**What this means for choosing a provider:**

- **Claude Opus** is the clear leader -- near-perfect rule adherence and the only model that consistently refuses adversarial prompts. Use this when quality matters.
- **GLM-5.1** is the strongest non-Claude model (85.8). Good for cost-sensitive workloads where you can review outputs.
- **MiniMax M2.7** is fast (14s/task, comparable to Claude) but weak on adversarial tests. Use for speed when you're actively supervising.
- **gemma4** (local, free) completes everything but rarely enforces rules under pressure. Good for experimentation and offline work.
- **qwen3.5** (local, free) is too slow for practical use on most hardware (175s/task, 50% timeout rate).

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

**How `csq login N` works** (from `v2.0.0-alpha.5`): if the `claude`
binary is on your `PATH`, csq delegates the OAuth flow to
`claude auth login` with an isolated `CLAUDE_CONFIG_DIR=config-N/`.
Same seamless UX as running `claude auth login` directly — browser
opens, you sign in, Claude Code's hosted-callback page bridges the
authorization code back automatically. csq imports the credentials
from the isolated dir when CC exits, then writes `credentials/N.json`
with the atomic-replace helpers.

If `claude` isn't on your `PATH`, csq falls back to an in-process
paste-code flow: it opens the authorize URL, then prompts on stdin
for the authorization code Anthropic's hosted callback page displays.
Paste the code and csq completes the exchange via the daemon.

To free a slot, run `csq logout N` (CLI) or click "Remove" on the slot
card in the desktop dashboard. Both clear `credentials/N.json`,
`config-N/`, the `profiles.json` entry, and the cached quota.

### Daily use

```bash
csq run 1                    # terminal 1 on account 1
csq run 3                    # terminal 2 on account 3
csq run 5                    # terminal 3 on account 5
```

If you have only one account, `csq` (no number) auto-resolves. With zero accounts, `csq` is invisible -- just runs vanilla `claude`.

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

The `!` prefix runs the command as a local shell op -- works even when CC is rate-limited. The next message you send uses account 3's token, in the same conversation, no restart.

If you want to know which account to swap to:

```
!csq suggest      # shows the account with most capacity
```

### Quick start (single account)

```bash
csq              # equivalent to vanilla `claude` -- csq stays out of your way
csq --resume     # passes flags straight through
```

## Desktop app

The desktop app provides a live dashboard for managing accounts and sessions. It runs an in-process daemon that handles token refresh, usage polling, and credential fanout -- no separate process needed.

<table>
<tr>
<td width="50%">

**Accounts tab**

- Quota bars (5h and 7d) with color coding
- Token health badges (healthy/expiring/expired)
- Reset countdowns with ranked badges (1, 2, 3...)
- Sort by custom order, 5h reset, or 7d reset
- Maxed-out accounts excluded from rankings
- Re-auth button on expired accounts
- Double-click to rename any account

</td>
<td width="50%">

**Sessions tab**

- Every running `claude` process appears automatically
- Account labels update in real-time after renames
- Quota per session at a glance
- Sort by custom order, title, or account
- Click "Swap" to change any session's account
- "Restart needed" badge for stale sessions
- Double-click to give sessions custom names

</td>
</tr>
</table>

**System tray**: icon with per-account quick-swap menu. Icon color reflects health. "Launch on login" toggle for auto-start.

## Command reference

```bash
# Session management
csq run N                    # start CC on account N (OAuth or 3P-bound slot)
csq run N --resume           # resume most recent conversation on account N
csq swap N                   # in-place swap THIS terminal to account N
csq status                   # show all accounts with quota and reset times
csq suggest                  # suggest which account to swap to
csq statusline               # compact status for shell prompt integration

# Account management
csq login N                  # save account N's credentials (opens browser)
csq repair-credentials       # fix cross-slot credential contamination

# Provider slots (MiniMax, Z.AI, Claude API key)
csq setkey <provider> --slot N --key KEY  # bind provider to slot N
csq setkey <provider>                     # store key globally (no slot)
csq listkeys                              # show configured providers with masked keys
csq rmkey <provider>                      # remove a provider profile
csq models                   # show all profiles + current models
csq models <provider> <name> # switch a provider to a different model

# System
csq daemon start             # start background daemon
csq daemon stop              # stop background daemon
csq daemon status            # check daemon health
csq doctor                   # run diagnostics and report system health
csq install                  # install csq into ~/.claude (create dirs, patch settings)
csq update                   # check for newer releases on GitHub
```

## How it works

### Per-terminal isolation

Claude Code uses `CLAUDE_CONFIG_DIR` to determine which keychain entry to read/write. Each config directory gets a unique keychain slot.

```
csq run 3
  -> CLAUDE_CONFIG_DIR=~/.claude/accounts/config-3
  -> isolated credentials, settings, identity
  -> shared history, projects, memory (symlinked from ~/.claude)
```

### Shared artifacts

Only credentials, account identity, and `settings.json` stay isolated. Everything else in `~/.claude` (projects, sessions, history, plugins, commands, agents, skills, memory) is symlinked into each `config-N/` on every `csq run`. So all terminals see the same conversations, the same `/resume` list, and the same auto-memory.

### Background daemon

The daemon runs in-process inside the desktop app (or standalone via `csq daemon start`) and handles:

- **Token refresh** -- checks every 5 minutes, refreshes tokens expiring within 2 hours
- **Usage polling** -- polls Anthropic's `/api/oauth/usage` for each account's real quota
- **Credential fanout** -- distributes refreshed tokens to all terminals using that account
- **IPC server** -- Unix socket for CLI and desktop communication

### Account/terminal separation

- **Account** = an authenticated Anthropic identity with its own credentials and quota
- **Terminal** = a CC instance that borrows an account's credentials
- Quota comes from Anthropic's API (polled by the daemon), not from individual terminals
- The `.csq-account` marker file in each config dir is the source of truth for identity

### Credential storage

- **macOS**: per-config-dir keychain entry via `security-framework` with file fallback
- **Linux / WSL / Windows**: file-only (`.credentials.json` in the per-config-dir)
- All credential files written atomically (temp + rename) with `0600` permissions

## Architecture

csq is a Rust workspace with three crates:

| Crate         | Purpose                                                             |
| ------------- | ------------------------------------------------------------------- |
| `csq-core`    | OAuth, credentials, quota, daemon, session discovery, rotation      |
| `csq-cli`     | CLI binary (`csq run`, `csq login`, `csq status`, `csq swap`, etc.) |
| `csq-desktop` | Tauri 2.x desktop app with Svelte 5 frontend                        |

### Files

| Path                                       | Purpose                                  |
| ------------------------------------------ | ---------------------------------------- |
| `~/.claude/accounts/credentials/N.json`    | OAuth credentials per account (mode 600) |
| `~/.claude/accounts/profiles.json`         | Account labels and email mappings        |
| `~/.claude/accounts/quota.json`            | Per-account quota from Anthropic API     |
| `~/.claude/accounts/config-N/`             | Per-terminal CC config directory         |
| `~/.claude/accounts/config-N/.csq-account` | Account identity marker                  |
| `~/.claude/settings-<provider>.json`       | Provider profile overlays                |

### Platform support

| Platform | CLI  | Desktop | Daemon         | Session discovery     |
| -------- | ---- | ------- | -------------- | --------------------- |
| macOS    | Full | Full    | Full           | Full (ps + osascript) |
| Linux    | Full | Full    | Full           | Full (/proc)          |
| Windows  | Full | Full    | Planned (M8.6) | Full (PEB walking)    |

## Use in VS Code

The VS Code Claude Code extension reads the same `~/.claude/settings.json` that csq writes, so the statusline and `! csq swap N` both work in VS Code's Claude Code panel. The core swap functionality (`! csq swap N`) is a shell command and works regardless of hook reliability.

No VS Code extension or plugin is needed. Install csq once via the regular installer; VS Code picks it up automatically.

## Troubleshooting

**Statusline not showing** -- check that `~/.claude/accounts/statusline-quota.sh` exists and that your `~/.claude/settings.json` has `"statusLine": {"type":"command","command":"bash ~/.claude/accounts/statusline-quota.sh"}`. Run `csq doctor` for diagnostics.

**`csq swap` says swap succeeded but CC shows "rate limited"** -- the access token may be stuck on Anthropic's side. Run `csq login N` to capture a fresh token via a full OAuth flow.

**Desktop app shows "restart needed"** -- this means credentials were swapped after that CC session started. CC caches credentials in memory, so you need to `/exit` and relaunch that session for the swap to take effect.

**Wrong model after swap** -- check `~/.claude/accounts/config-N/.claude.json` for a `cachedGrowthBookFeatures.tengu_auto_mode_config` flag. Anthropic's A/B testing can silently override model selection. Delete the cache entry to fix.

**Symlinks fail on Windows** -- csq uses directory junctions (`mklink /J`) on Windows, which don't need admin privileges. If junction creation fails, csq falls back to copying.

## Uninstall

```bash
rm -rf ~/.claude/accounts
rm ~/.local/bin/csq          # or ~/bin/csq
# Remove statusLine and hooks from ~/.claude/settings.json
```

**Windows**: remove directory junctions inside `config-N/` before deleting:

```bash
for d in ~/.claude/accounts/config-*/; do
    for item in "$d"*; do
        [ -L "$item" ] && rm "$item"
    done
done
rm -rf ~/.claude/accounts
```

## Development

```bash
cargo test --workspace              # 646 Rust tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cd csq-desktop && npm run tauri dev # desktop dev mode
cd csq-desktop && npx vitest run    # Svelte tests
```

## License

Apache 2.0 -- [Terrene Foundation](https://terrene.foundation)
