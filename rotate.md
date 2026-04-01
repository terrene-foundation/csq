---
name: rotate
description: "Intelligent account rotation — auto-pick best Claude account based on quota"
---

# /rotate — Account Rotation

When the user runs /rotate, perform intelligent account rotation.

The user calls this when they're rate-limited. The `--force` flag marks the current account as
exhausted so the engine picks an alternative even if quota data is stale.

## Steps

1. Run the rotation engine with `--force` (the user is asking because they're rate-limited):
   ```bash
   python3 ~/.claude/accounts/rotation-engine.py auto-rotate --force
   ```

2. If the auto-rotate prints `[auto-rotate] → account N (email) — reason`:
   - Confirm: "Rotated to account N (email). Next API call will use the new account."

3. If auto-rotate exits with no output (no alternatives available):
   - Show current quota status:
     ```bash
     python3 ~/.claude/accounts/rotation-engine.py status
     ```
   - Say: "No accounts available to rotate to — all are in cooldown. Show the reset times."

4. If the swap fails (no credentials extracted), tell the user:
   - "Account {N} has no stored credentials. Run `ccc login {N}` in a terminal."

5. If you suspect credential contamination (all accounts seem identical), run:
   ```bash
   python3 ~/.claude/accounts/rotation-engine.py verify
   ```
   And show the results.

## When to auto-suggest rotation

If you notice a rate limit error in the conversation (429, "rate limited", "usage limit"), proactively suggest: "You've hit a rate limit. Run /rotate to switch accounts."
