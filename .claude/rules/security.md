---
name: security
description: Security rules — no hardcoded secrets, OAuth credential safety, keychain write guards, atomic file handling.
---

# Security Rules

Applies to all code in claude-squad, with particular attention to the OAuth credential flow, keychain writes, and atomic file handling in `rotation-engine.py` and `csq`.

## MUST Rules

### 1. No Hardcoded Secrets

Credentials, tokens, and keys come from the environment, `.env`, or the OAuth flow. Never committed literals.

```
BAD:  api_key = "sk-ant-..."
GOOD: api_key = os.environ["ANTHROPIC_API_KEY"]
```

**Why:** Hardcoded secrets end up in git history, CI logs, and error traces, making them permanently extractable even after deletion.

### 2. No Secrets in Logs or Error Messages

Access tokens, refresh tokens, and keychain payloads MUST NOT be logged. Print prefixes/suffixes only when diagnostics need them.

```
BAD:  print(f"token: {access_token}")
GOOD: print(f"token: {access_token[:8]}...{access_token[-4:]}")
```

**Why:** Log files are widely accessible (CI, monitoring, support staff) and rarely encrypted, turning every logged secret into a breach.

### 3. Input Validation on Account Numbers

Any value destined for `credentials/{N}.json`, config-dir path construction, or keychain service name MUST be validated via `_validate_account()` (range 1..MAX_ACCOUNTS, digits only).

**Why:** Unvalidated account numbers are a path-traversal and keychain-namespace-injection vector — one malformed value reaches the filesystem or keychain service and every other account becomes readable.

### 4. Atomic Writes for Credential Files

`.credentials.json`, `credentials/N.json`, and marker files (`.csq-account`, `.current-account`, `.quota-cursor`) MUST be written via `_atomic_replace` (temp file → `os.replace`).

**Why:** A partial write during a crash leaves the credential file truncated, which a running CC reads as "no credentials" and silently re-prompts the user to log in — losing the session.

### 5. File Permissions on Credential Files

After writing a credential file, call `_secure_file()` to set `0o600`. On Windows this is a no-op (handled by the filesystem ACL default).

**Why:** Default permissions on macOS/Linux are world-readable, meaning any other user or process on the machine can steal the credential file without escalation.

### 6. Fail-Closed on Keychain/Lock Contention

Keychain writes (`security add-generic-password`) and file locks can hang under concurrent load. Every call MUST use a 3-second timeout and fall through safely. Never block a statusline render on the keychain.

**Why:** A keychain hang blocks every CC render until the macOS security daemon responds, producing a visibly frozen UI that users mistake for a CC crash.

## MUST NOT Rules

### 1. No `shell=True` on User-Influenced Input

`subprocess.run([...])` with an array — never `shell=True` with string interpolation. Path components MUST NOT reach a shell.

**Why:** `shell=True` on user input is arbitrary command execution — any path containing shell metacharacters becomes an attack surface.

### 2. No `.env` or `credentials/` in Git

`.gitignore` MUST list `.env`, `credentials/`, `config-*/`, `.credentials.json`. If any were ever committed, history rewrite is required.

**Why:** Once committed, credentials persist in git history even after removal and are exposed to anyone with repo access.

### 3. No Global Keychain Writes Under User-Supplied Service Names

The keychain service name is derived from the hashed config dir path via `_keychain_service()`. Never accept a service name from CLI or env input directly.

**Why:** A user-supplied service name lets an attacker overwrite another account's keychain entry or read from a collision-namespace, bypassing per-account isolation.

## Cross-References

- `no-stubs.md` — no silent fallbacks that hide security errors
- `zero-tolerance.md` — pre-existing security issues must be fixed
