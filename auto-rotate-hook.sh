#!/usr/bin/env bash
# Auto-rotation hook — runs on UserPromptSubmit
set -euo pipefail

ENGINE="$HOME/.claude/accounts/rotation-engine.py"
[[ -f "$ENGINE" ]] || exit 0

result=$(python3 "$ENGINE" check 2>/dev/null) || exit 0
should=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('should_rotate', False))" 2>/dev/null)

if [ "$should" = "True" ]; then
  python3 "$ENGINE" auto-rotate 2>/dev/null
fi
