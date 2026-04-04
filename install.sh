#!/usr/bin/env bash
set -euo pipefail

# Claude Squad installer — multi-account rotation for Claude Code
# Install: curl -sSL https://raw.githubusercontent.com/terrene-foundation/claude-squad/main/install.sh | bash

REPO_URL="https://raw.githubusercontent.com/terrene-foundation/claude-squad/main"
ACCOUNTS_DIR="$HOME/.claude/accounts"
if [[ -d "$HOME/bin" ]] && echo "$PATH" | grep -q "$HOME/bin"; then
    BIN_DIR="$HOME/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

echo -e "\n${BOLD}Claude Squad — Multi-Account Rotation for Claude Code${NC}\n"

command -v claude &>/dev/null || { err "Claude Code not found."; exit 1; }
command -v python3 &>/dev/null || { err "Python 3 not found."; exit 1; }
command -v jq &>/dev/null || { err "jq not found. brew install jq"; exit 1; }

mkdir -p "$ACCOUNTS_DIR/credentials" "$BIN_DIR"
chmod 700 "$ACCOUNTS_DIR" "$ACCOUNTS_DIR/credentials"

# Install files — from local repo if available, otherwise download
if [[ -f "$(dirname "$0")/rotation-engine.py" ]]; then
    SRC="$(cd "$(dirname "$0")" && pwd)"
    cp "$SRC/rotation-engine.py" "$ACCOUNTS_DIR/rotation-engine.py"
    cp "$SRC/csq" "$BIN_DIR/csq"
    cp "$SRC/auto-rotate-hook.sh" "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    cp "$SRC/statusline-quota.sh" "$ACCOUNTS_DIR/statusline-quota.sh"
    mkdir -p "$HOME/.claude/commands"
    cp "$SRC/rotate.md" "$HOME/.claude/commands/rotate.md" 2>/dev/null || true
else
    curl -sfL "$REPO_URL/rotation-engine.py" -o "$ACCOUNTS_DIR/rotation-engine.py"
    curl -sfL "$REPO_URL/csq" -o "$BIN_DIR/csq"
    curl -sfL "$REPO_URL/auto-rotate-hook.sh" -o "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    curl -sfL "$REPO_URL/statusline-quota.sh" -o "$ACCOUNTS_DIR/statusline-quota.sh"
    mkdir -p "$HOME/.claude/commands"
    curl -sfL "$REPO_URL/rotate.md" -o "$HOME/.claude/commands/rotate.md" 2>/dev/null || true
fi

chmod +x "$ACCOUNTS_DIR/rotation-engine.py" "$BIN_DIR/csq" \
         "$ACCOUNTS_DIR/auto-rotate-hook.sh" "$ACCOUNTS_DIR/statusline-quota.sh"
ok "Files installed"

# Remove old 'cc' binary if it exists (renamed to csq)
rm -f "$BIN_DIR/cc" 2>/dev/null

# Create config dirs (1-7)
for n in 1 2 3 4 5 6 7; do
    mkdir -p "$ACCOUNTS_DIR/config-$n"
done
ok "Config dirs created"

# Patch settings.json — statusline + auto-rotate hook
SETTINGS_FILE="$HOME/.claude/settings.json"
[[ -f "$SETTINGS_FILE" ]] || echo '{}' > "$SETTINGS_FILE"
python3 -c "
import json
f = '$SETTINGS_FILE'
try:
    with open(f) as fh: s = json.load(fh)
except (FileNotFoundError, json.JSONDecodeError, ValueError): s = {}
changed = False

# Statusline
sl = s.get('statusLine', {})
if not sl or 'statusline' not in sl.get('command', ''):
    s['statusLine'] = {'type':'command','command':'bash ~/.claude/accounts/statusline-quota.sh'}
    changed = True

# Auto-rotate hook
hook_cmd = 'bash ~/.claude/accounts/auto-rotate-hook.sh'
uph = s.setdefault('hooks', {}).setdefault('UserPromptSubmit', [])
if not any(hook_cmd in str(entry) for entry in uph):
    uph.append({'matcher':'','hooks':[{'type':'command','command':hook_cmd}]})
    changed = True

if changed:
    with open(f,'w') as fh: json.dump(s, fh, indent=2)
" 2>/dev/null
ok "Settings configured (statusline + auto-rotate hook)"

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "$BIN_DIR not in PATH. Add to your shell profile:"
    echo "    export PATH=\"$BIN_DIR:\$PATH\""
fi

echo -e "\n${BOLD}Done.${NC} Now save your accounts:\n"
echo "  1. Start Claude:   claude"
echo "  2. Log in:          /login email@example.com"
echo "  3. Save it:         ! csq login 1"
echo "  4. Repeat for each account (slots 1-7)"
echo ""
echo "Daily use:"
echo "  csq run 1           Start CC on account 1 (isolated)"
echo "  csq run 3           Start CC on account 3 (separate terminal)"
echo "  csq status          Show all accounts + quota"
echo ""
echo "When rate limited:"
echo "  /rotate              Auto-switches (if started via csq run)"
echo "  csq suggest          Shows which account to switch to"
echo ""
