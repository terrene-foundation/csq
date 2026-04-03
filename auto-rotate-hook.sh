#!/usr/bin/env bash
# Quota check hook — runs on UserPromptSubmit
# If exhausted, prints a suggestion to stderr (visible in CC output)
set -euo pipefail

ENGINE="$HOME/.claude/accounts/rotation-engine.py"
[[ -f "$ENGINE" ]] || exit 0

result=$(python3 "$ENGINE" check 2>/dev/null) || exit 0
exhausted=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('exhausted', False))" 2>/dev/null)

if [ "$exhausted" = "True" ]; then
  python3 "$ENGINE" suggest >&2
fi
