---
name: rotate
description: "Intelligent account rotation — auto-pick best Claude account based on quota"
---

# /rotate — Account Rotation

When the user runs /rotate, perform intelligent account rotation.

## Steps

1. Run the rotation engine check:
   ```bash
   python3 ~/.claude/accounts/rotation-engine.py check
   ```

2. Parse the JSON output. It has: `should_rotate`, `target`, `reason`, `target_email`.

3. If `should_rotate` is true:
   - Show: "Rotating to account {target} ({target_email}) — {reason}"
   - Execute the swap:
     ```bash
     python3 ~/.claude/accounts/rotation-engine.py swap {target}
     ```
   - After swap, confirm: "Done. Next API call will use the new account."

4. If `should_rotate` is false:
   - Show current quota status:
     ```bash
     python3 ~/.claude/accounts/rotation-engine.py status
     ```
   - Say: "No rotation needed — current account is optimal."

5. If the swap fails (no credentials extracted), tell the user:
   - "Account {N} has no stored credentials. Run these in a terminal:"
   - `ccc login {N}` then `ccc extract {N}`

## When to auto-suggest rotation

If you notice a rate limit error in the conversation (429, "rate limited", "usage limit"), proactively suggest: "You've hit a rate limit. Run /rotate to switch accounts."
