#!/usr/bin/env bash
# cc — Claude Code account manager
# Usage:
#   cc login <N>         Save current session's account as slot N
#   cc status            Show all accounts + quota
#   cc suggest           Suggest which account to /login to
#   cc help              Show this help

set -euo pipefail

ACCOUNTS_DIR="$HOME/.claude/accounts"
ENGINE="$ACCOUNTS_DIR/rotation-engine.py"

die() { echo "error: $*" >&2; exit 1; }

cmd_login() {
  local n="$1"
  [[ "$n" =~ ^[1-7]$ ]] || die "account must be 1-7, got: $n"

  # Get current email from active session
  local email
  email=$(claude auth status --json 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('email','unknown'))" 2>/dev/null \
    || echo "unknown")

  # Save credentials
  mkdir -p "$ACCOUNTS_DIR/credentials"
  local cred_file="$HOME/.claude/.credentials.json"
  if [[ -f "$cred_file" ]]; then
    cp "$cred_file" "$ACCOUNTS_DIR/credentials/${n}.json"
    chmod 600 "$ACCOUNTS_DIR/credentials/${n}.json"
  else
    echo "warning: no .credentials.json found — credentials are in keychain only" >&2
  fi

  # Save profile
  python3 -c "
import json
f = '$ACCOUNTS_DIR/profiles.json'
try:
    d = json.load(open(f))
except:
    d = {'accounts': {}}
d.setdefault('accounts', {})['$n'] = {'email': '$email', 'method': 'oauth'}
with open(f, 'w') as fh:
    json.dump(d, fh, indent=2)
" 2>/dev/null

  echo "Account $n saved ($email)."
}

main() {
  local cmd="${1:-help}"

  case "$cmd" in
    login)
      shift
      [[ $# -ge 1 ]] || die "usage: cc login <1-7>"
      cmd_login "$1"
      ;;
    status|ls|quota)
      python3 "$ENGINE" status
      ;;
    suggest)
      python3 "$ENGINE" suggest
      ;;
    help|-h|--help)
      cat <<'HELP'
cc — Claude Code account manager

  cc login <N>     Save current account as slot N
  cc status        Show all accounts + quota
  cc suggest       Suggest which account to /login to
  cc help          This message

Setup:
  1. /login to an account in Claude
  2. cc login 1    (saves it as slot 1)
  3. /login to another account
  4. cc login 2    (saves it as slot 2)

When rate limited, run /rotate for a suggestion.
HELP
      ;;
    *)
      die "unknown command: $cmd. Try: cc help"
      ;;
  esac
}

main "$@"
