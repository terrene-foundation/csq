#!/usr/bin/env bash
set -euo pipefail

# ─── Claude Squad Installer ───────────────────────────────
# Multi-account rotation for Claude Code
# https://github.com/terrene-foundation/claude-squad

REPO_URL="https://raw.githubusercontent.com/terrene-foundation/claude-squad/main"
ACCOUNTS_DIR="$HOME/.claude/accounts"
CREDS_DIR="$ACCOUNTS_DIR/credentials"
# Prefer ~/bin if it exists and is on PATH, else ~/.local/bin
if [[ -d "$HOME/bin" ]] && echo "$PATH" | grep -q "$HOME/bin"; then
    BIN_DIR="$HOME/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}!${NC} $*"; }
err()   { echo -e "${RED}✗${NC} $*" >&2; }
header(){ echo -e "\n${BOLD}$*${NC}"; }

# ─── Preflight ─────────────────────────────────────────────

header "Claude Squad — Multi-Account Rotation"
echo "Manages multiple Claude Max accounts with intelligent quota-based rotation."
echo ""

# Check prerequisites
if ! command -v claude &>/dev/null; then
    err "Claude Code not found. Install from https://claude.ai/code"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    err "Python 3 not found."
    exit 1
fi

if ! command -v jq &>/dev/null; then
    err "jq not found. Install: brew install jq"
    exit 1
fi

if [[ "$(uname)" != "Darwin" ]]; then
    err "macOS required (uses macOS security for credential storage)."
    exit 1
fi

ok "Prerequisites met"

# ─── Install Files ─────────────────────────────────────────

header "Installing files..."

mkdir -p "$ACCOUNTS_DIR/credentials" "$BIN_DIR"

# Download or copy files based on context
if [[ -f "$(dirname "$0")/rotation-engine.py" ]]; then
    # Running from cloned repo
    SRC="$(cd "$(dirname "$0")" && pwd)"
    info "Installing from local repo: $SRC"
    cp "$SRC/rotation-engine.py" "$ACCOUNTS_DIR/rotation-engine.py"
    cp "$SRC/ccc" "$BIN_DIR/ccc"
    cp "$SRC/auto-rotate-hook.sh" "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    cp "$SRC/statusline-quota.sh" "$ACCOUNTS_DIR/statusline-quota.sh"
    cp "$SRC/rotate.md" "$HOME/.claude/commands/rotate.md"
else
    # Running via curl | bash
    info "Downloading from GitHub..."
    curl -sfL "$REPO_URL/rotation-engine.py" -o "$ACCOUNTS_DIR/rotation-engine.py"
    curl -sfL "$REPO_URL/ccc" -o "$BIN_DIR/ccc"
    curl -sfL "$REPO_URL/auto-rotate-hook.sh" -o "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    curl -sfL "$REPO_URL/statusline-quota.sh" -o "$ACCOUNTS_DIR/statusline-quota.sh"
    curl -sfL "$REPO_URL/rotate.md" -o "$HOME/.claude/commands/rotate.md"
fi

chmod +x "$ACCOUNTS_DIR/rotation-engine.py"
chmod +x "$BIN_DIR/ccc"
chmod +x "$ACCOUNTS_DIR/auto-rotate-hook.sh"
chmod +x "$ACCOUNTS_DIR/statusline-quota.sh"

ok "Files installed"

# ─── Patch settings.json ──────────────────────────────────

header "Configuring Claude Code settings..."

SETTINGS_FILE="$HOME/.claude/settings.json"

if [[ ! -f "$SETTINGS_FILE" ]]; then
    echo '{}' > "$SETTINGS_FILE"
fi

# Add hooks and statusline using python (safe JSON merge)
python3 -c "
import json, sys

f = '$SETTINGS_FILE'
try:
    settings = json.load(open(f))
except:
    settings = {}

changed = False

# Add UserPromptSubmit hook for auto-rotation
hook_cmd = 'bash ~/.claude/accounts/auto-rotate-hook.sh'
hooks = settings.setdefault('hooks', {})
uph = hooks.setdefault('UserPromptSubmit', [])

# Check if already installed
already = any(
    hook_cmd in h.get('command', '')
    for entry in uph
    for h in entry.get('hooks', [])
)

if not already:
    uph.append({
        'matcher': '',
        'hooks': [{'type': 'command', 'command': hook_cmd}]
    })
    changed = True
    print('Added auto-rotate hook')
else:
    print('Auto-rotate hook already installed')

# Add statusline if not custom
sl = settings.get('statusLine', {})
if not sl or sl.get('command', '') == 'bash ~/.claude/statusline-command.sh':
    # Patch the statusline to include quota capture
    settings['statusLine'] = {
        'type': 'command',
        'command': 'bash ~/.claude/accounts/statusline-quota.sh'
    }
    changed = True
    print('Updated statusline for quota display')
else:
    print(f'Custom statusline detected — not overwriting')
    print(f'  Add quota capture manually: see README.md')

if changed:
    with open(f, 'w') as fh:
        json.dump(settings, fh, indent=2)
    print('Settings saved')
else:
    print('No changes needed')
"

ok "Settings configured"

# ─── PATH Check ───────────────────────────────────────────

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "$BIN_DIR is not in your PATH"
    echo "  Add to your shell profile:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ─── Account Setup ────────────────────────────────────────

header "Account Setup"
echo ""
echo "How many Claude Max accounts do you have?"
read -rp "Number of accounts [1-7]: " num_accounts

if [[ ! "$num_accounts" =~ ^[1-7]$ ]]; then
    num_accounts=1
fi

echo ""
echo "For each account, you'll:"
echo "  1. Enter the email"
echo "  2. Log in via browser (one-time)"
echo "  3. Credentials are saved automatically"
echo ""

for i in $(seq 1 "$num_accounts"); do
    header "Account $i of $num_accounts"
    read -rp "Email for account $i: " email

    # ccc login handles: config dir setup, browser login, credential copy, profile
    "$BIN_DIR/ccc" login "$i" || {
        warn "Login failed for $email — you can retry later with: ccc login $i"
        continue
    }

    # Fix email in profile (ccc login gets it from auth status, but user knows best)
    python3 -c "
import json
f = '$ACCOUNTS_DIR/profiles.json'
try:
    d = json.load(open(f))
except:
    d = {'accounts': {}}
d.setdefault('accounts', {})['$i'] = {'email': '$email', 'method': 'oauth'}
with open(f, 'w') as fh:
    json.dump(d, fh, indent=2)
" 2>/dev/null

    ok "Account $i ($email) configured"
    echo ""
done

# Set account 1 as current
echo "1" > "$ACCOUNTS_DIR/.current"

# ─── Done ─────────────────────────────────────────────────

header "Installation Complete"
echo ""
echo "  Accounts configured: $num_accounts"
echo "  Rotation engine:     $ACCOUNTS_DIR/rotation-engine.py"
echo "  CLI:                 $BIN_DIR/ccc"
echo "  /rotate command:     ~/.claude/commands/rotate.md"
echo ""
echo "Usage:"
echo "  ${BOLD}ccc quota${NC}            See all accounts with quota + priority"
echo "  ${BOLD}ccc swap 3${NC}           Manually switch to account 3"
echo "  ${BOLD}/rotate${NC}              Inside Claude Code: auto-pick best account"
echo ""
echo "  Auto-rotation happens automatically via the statusline."
echo "  When a rate limit hits, the next API call uses the best available account."
echo ""
warn "Restart any open Claude Code terminals to pick up the new settings."
