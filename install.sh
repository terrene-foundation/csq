#!/usr/bin/env bash
set -euo pipefail

# Claude Squad installer — multi-account rotation for Claude Code

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

echo -e "\n${BOLD}Claude Squad — Multi-Account Rotation${NC}\n"

command -v claude &>/dev/null || { err "Claude Code not found."; exit 1; }
command -v python3 &>/dev/null || { err "Python 3 not found."; exit 1; }
command -v jq &>/dev/null || { err "jq not found. brew install jq"; exit 1; }

mkdir -p "$ACCOUNTS_DIR/credentials" "$BIN_DIR"

if [[ -f "$(dirname "$0")/rotation-engine.py" ]]; then
    SRC="$(cd "$(dirname "$0")" && pwd)"
    cp "$SRC/rotation-engine.py" "$ACCOUNTS_DIR/rotation-engine.py"
    cp "$SRC/cc" "$BIN_DIR/cc"
    cp "$SRC/auto-rotate-hook.sh" "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    cp "$SRC/statusline-quota.sh" "$ACCOUNTS_DIR/statusline-quota.sh"
    cp "$SRC/rotate.md" "$HOME/.claude/commands/rotate.md" 2>/dev/null || true
else
    curl -sfL "$REPO_URL/rotation-engine.py" -o "$ACCOUNTS_DIR/rotation-engine.py"
    curl -sfL "$REPO_URL/cc" -o "$BIN_DIR/cc"
    curl -sfL "$REPO_URL/auto-rotate-hook.sh" -o "$ACCOUNTS_DIR/auto-rotate-hook.sh"
    curl -sfL "$REPO_URL/statusline-quota.sh" -o "$ACCOUNTS_DIR/statusline-quota.sh"
    curl -sfL "$REPO_URL/rotate.md" -o "$HOME/.claude/commands/rotate.md" 2>/dev/null || true
fi

chmod +x "$ACCOUNTS_DIR/rotation-engine.py" "$BIN_DIR/cc" \
         "$ACCOUNTS_DIR/auto-rotate-hook.sh" "$ACCOUNTS_DIR/statusline-quota.sh"
ok "Files installed"

# Patch settings.json
SETTINGS_FILE="$HOME/.claude/settings.json"
[[ -f "$SETTINGS_FILE" ]] || echo '{}' > "$SETTINGS_FILE"
python3 -c "
import json
f = '$SETTINGS_FILE'
try: s = json.load(open(f))
except: s = {}
changed = False
hook_cmd = 'bash ~/.claude/accounts/auto-rotate-hook.sh'
uph = s.setdefault('hooks', {}).setdefault('UserPromptSubmit', [])
if not any(hook_cmd in h.get('command','') for e in uph for h in e.get('hooks',[])):
    uph.append({'matcher':'','hooks':[{'type':'command','command':hook_cmd}]})
    changed = True
sl = s.get('statusLine', {})
if not sl or sl.get('command','') == 'bash ~/.claude/statusline-command.sh':
    s['statusLine'] = {'type':'command','command':'bash ~/.claude/accounts/statusline-quota.sh'}
    changed = True
if changed:
    with open(f,'w') as fh: json.dump(s, fh, indent=2)
" 2>/dev/null
ok "Settings configured"

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "$BIN_DIR not in PATH. Add: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo -e "\n${BOLD}Done.${NC} Now add your accounts:\n"
echo "  1. In any Claude terminal, /login to an account"
echo "  2. cc login 1    (saves it as slot 1)"
echo "  3. /login to next account"
echo "  4. cc login 2    (saves it as slot 2)"
echo "  5. ...repeat for more accounts"
echo ""
echo "When rate limited, /rotate auto-switches."
echo ""
