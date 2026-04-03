---
name: rotate
description: "Intelligent account rotation — auto-pick best Claude account based on quota"
---

# /rotate — Account Rotation

When the user runs /rotate, rotate to the best available account.

## Steps

1. Run:

   ```bash
   python3 ~/.claude/accounts/rotation-engine.py auto-rotate --force
   ```

2. Check the output:
   - If it says "Swapped to account N" — **rotation succeeded**. Say "Rotated." and resume your previous task.
   - If it says "All accounts exhausted" — say so and show the reset times.

**IMPORTANT**: On success, do NOT show status tables. Just continue working.
