#!/usr/bin/env bash
# Auto-rotation hook — runs on UserPromptSubmit
# Fleet model: all terminals share one account. Swap benefits everyone.
set -euo pipefail

ROTATION_ENGINE="$HOME/.claude/accounts/rotation-engine.py"

# Check if rotation needed, rotate if so
result=$(python3 "$ROTATION_ENGINE" check 2>/dev/null) || exit 0
should_rotate=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('should_rotate', False))" 2>/dev/null)

if [ "$should_rotate" = "True" ]; then
  python3 "$ROTATION_ENGINE" auto-rotate 2>/dev/null
fi
