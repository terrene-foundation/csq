---
name: security
description: Security rules — no hardcoded secrets, OAuth credential safety, keychain write guards, atomic file handling.
---

# Security Rules

Applies to all code in claude-squad. The codebase is Rust (`csq-core/`, `csq-cli/`, `csq-desktop/`) with a legacy Python layer (`rotation-engine.py`, `csq`). OAuth credentials for multiple Claude Code accounts are the primary asset — a single mistake can burn refresh tokens, lock users out, or leak access tokens to other processes.

## MUST Rules

### 1. No Hardcoded Secrets

Credentials, tokens, and keys come from the environment, `.env`, or the OAuth flow. Never committed literals.

```rust
// DO NOT:
let api_key = "sk-ant-api03-...";

// DO:
let api_key = settings.get_api_key().ok_or("no API key")?;
```

**Why:** Hardcoded secrets end up in git history, CI logs, and error traces, making them permanently extractable even after deletion.

### 2. No Secrets in Logs or Error Messages

Access tokens, refresh tokens, and keychain payloads MUST NOT be logged. Use fixed-vocabulary log tags (not `%e` formatting of error bodies). All error formatting in OAuth-adjacent modules must pass through `error::redact_tokens`.

```rust
// DO NOT:
warn!("refresh failed: {e}");  // e may contain echoed tokens

// DO:
warn!(error_kind = "refresh_failed", "token refresh failed");

// DO NOT:
return Err(format!("exchange failed: {body}"));  // body may echo tokens

// DO:
return Err(format!("exchange failed: {}", redact_tokens(body)));
```

**Why:** Log files are widely accessible. Response bodies from OAuth endpoints can echo submitted tokens in error messages (observed: `invalid_grant` responses include refresh token prefix). See journals 0007, 0010.

### 3. Input Validation on Account Numbers

In Rust, all account values MUST use the `AccountNum` newtype (validated 1..MAX_ACCOUNTS). In Python, use `_validate_account()`. Raw `u16` should not reach filesystem paths or keychain operations without `AccountNum::try_from()`.

**Why:** Unvalidated account numbers are a path-traversal and keychain-namespace-injection vector.

### 4. Atomic Writes for Credential Files

All credential files MUST be written via `platform::fs::atomic_replace` (Rust) or `_atomic_replace` (Python): temp file → `secure_file()` → rename. Includes: `credentials/N.json`, `.credentials.json`, `quota.json`, marker files.

**Why:** A partial write during a crash leaves the credential file truncated, which a running CC reads as "no credentials."

### 5. File Permissions on Credential Files

After writing a credential file, call `platform::fs::secure_file()` to set `0o600`. On Windows this is a no-op.

**Why:** Default permissions on macOS/Linux are world-readable.

### 6. Fail-Closed on Keychain/Lock Contention

Keychain writes (now via `security-framework` native API on macOS) and file locks can hang under concurrent load. Every call MUST have a timeout path. Never block a statusline render on the keychain.

**Why:** A keychain hang blocks every CC render.

### 7. Daemon IPC: Three-Layer Security

The daemon Unix socket MUST be hardened at three layers (journal 0006):

1. **Socket file permissions**: umask `0o077` before `bind`, then explicit `chmod 0o600`
2. **Peer credential verification**: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) rejects different-UID connections
3. **Per-user socket directory**: `$XDG_RUNTIME_DIR` or `~/.claude/accounts/`

**Why:** The daemon handles OAuth tokens over IPC. Socket compromise = full credential theft.

### 8. Error-Chain Token Leakage Defense

Functions that format error messages near OAuth code MUST NOT include `{e}` or `{body}` directly. Two defense layers:

- **Structural**: `SecretString` wrappers prevent accidental Display
- **Redaction**: `error::redact_tokens()` catches `sk-ant-*` patterns and long hex strings

Note: authorization codes, PKCE verifiers, and state tokens have no stable prefix — they rely on structural defense only (journal 0010).

**Why:** `serde_json::Error::Display` and upstream response bodies can echo submitted tokens.

### 9. CRLF Validation on Hand-Rolled HTTP

Any `pub` function that interpolates strings into HTTP request lines MUST validate against `\r` and `\n` at runtime (not `debug_assert!`). Applies to `daemon::client` functions.

**Why:** CRLF injection in request lines allows arbitrary header injection (journal 0014 H3).

## MUST NOT Rules

### 1. No `shell=True` or Unsanitized Subprocess Args

Python: `subprocess.run([...])` with an array, never `shell=True`. Rust: no `Command::new("sh").arg("-c")` with interpolated paths.

**Why:** Shell metacharacters in paths = arbitrary command execution.

### 2. No `.env` or `credentials/` in Git

`.gitignore` MUST list `.env`, `credentials/`, `config-*/`, `.credentials.json`. If any were ever committed, history rewrite is required.

**Why:** Once committed, credentials persist in git history forever.

### 3. No Secrets on TCP Routes

The daemon's TCP listener (127.0.0.1:8420) serves exactly ONE route: `/oauth/callback`, authenticated by CSPRNG state token. ALL credential-handling routes MUST live on the Unix socket (journal 0011).

**Why:** TCP is reachable by any process on the machine. Unix socket + SO_PEERCRED restricts to same UID.

## Cross-References

- `no-stubs.md` — no silent fallbacks that hide security errors
- `zero-tolerance.md` — pre-existing security issues must be fixed
- Journal 0006 — daemon three-layer security
- Journal 0007 — error body echo leaks secrets
- Journal 0010 — redact_tokens scope boundary
- Journal 0011 — OAuth dual-listener security
- Journal 0014 — red team 3P polling findings
