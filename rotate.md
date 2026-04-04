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
   - If `CLAUDE_CONFIG_DIR` is set (started via `csq run`): the engine auto-swaps by refreshing the target account's token and writing to this terminal's keychain entry. CC picks up the new creds on its next API call.
     - If it says "Swapped to account N" — **rotation succeeded**. Say "Rotated to account N." and resume your previous task.
     - If it says "All accounts exhausted" — say so and show the reset times.
   - If `CLAUDE_CONFIG_DIR` is NOT set: the engine outputs JSON suggesting the best account.
     - Parse the JSON and tell the user to run `/login <email>` with the suggested account's email.

**IMPORTANT**: On success (auto-swap), do NOT show status tables. Just continue working.
