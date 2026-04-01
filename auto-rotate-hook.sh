#!/usr/bin/env bash
# Auto-rotation hook — runs on UserPromptSubmit
# Checks if a better account is available and swaps silently.
# Output goes to stderr (shown to user as hook feedback).

set -euo pipefail

ROTATION_ENGINE="$HOME/.claude/accounts/rotation-engine.py"

# Pass Claude Code PID (our parent) to disambiguate multi-terminal sessions
CLAUDE_PID="$PPID"

# Quick check — exits 0 (no output) if no rotation needed
result=$(python3 "$ROTATION_ENGINE" check --ppid "$CLAUDE_PID" 2>/dev/null) || exit 0

should_rotate=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('should_rotate', False))" 2>/dev/null)

if [ "$should_rotate" = "True" ]; then
  # Perform the rotation
  python3 "$ROTATION_ENGINE" auto-rotate --ppid "$CLAUDE_PID" 2>/dev/null
fi
