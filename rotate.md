---
name: rotate
description: "Intelligent account rotation — suggest best Claude account based on quota"
---

# /rotate — Account Rotation

When the user runs /rotate, suggest which account to switch to.

## Steps

1. Run:

   ```bash
   python3 ~/.claude/accounts/rotation-engine.py suggest
   ```

2. Show the output to the user. It will say which account to /login to.

3. If the user wants to switch, tell them: "Run /login and sign in as [email]"

4. After they /login, save the new credentials:
   ```bash
   cc login [N]
   ```
   (where N is the account number shown in the suggestion)
