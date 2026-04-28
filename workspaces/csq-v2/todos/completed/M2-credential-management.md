# M2: Credential Management

Priority: P0 (Launch Blocker)
Effort: 2.5 autonomous sessions
Dependencies: M1 (Platform Abstraction)
Phase: 1, Stream B

---

## M2-01: Build credential file load/save

`CredentialFile` struct per GAP-1 resolution. `load(path) -> Result<CredentialFile>`. `save(path, data)` using atomic write + secure permissions. Handles missing file, corrupt JSON, empty file.

- Scope: 2.1-2.2, GAP-1
- Complexity: Trivial
- Acceptance:
  - [x] Valid JSON loads correctly
  - [x] Missing file returns `CredentialError::NotFound`
  - [x] Corrupt file returns `CredentialError::Corrupt`
  - [x] Saved file has `0o600` permissions
  - [x] `#[serde(flatten)]` preserves unknown fields round-trip

## M2-02: Build account number validation

`AccountNum` newtype validation: `_validate_account()` equivalent. Range 1..999, digits only. Prevents path traversal and keychain namespace injection.

- Scope: 2.3
- Complexity: Trivial
- Acceptance:
  - [x] 1, 7, 999 → valid
  - [x] 0, -1, "abc", "../etc", 1000 → invalid

## M2-03: Build OAuth token refresh

`refresh_token(account, creds) -> Result<CredentialFile>`. POST to `platform.claude.com/v1/oauth/token` with `grant_type=refresh_token`. Merge response into existing payload (preserve `subscriptionType`, `rateLimitTier`, `scopes`, unknown fields). Atomic write to canonical.

- Scope: 2.4, GAP-1 (field preservation)
- Complexity: Complex
- Acceptance:
  - [x] Mock HTTP server: correct request body
  - [x] Response merged: accessToken/refreshToken/expiresAt updated, other fields preserved
  - [x] 401 response returns `OAuthError::Http`
  - [x] Parity: same request body format as v1.x

## M2-04: Build keychain service name derivation

`keychain_service(config_dir) -> String`. SHA256 of NFC-normalized path, first 8 hex chars. Format: `Claude Code-credentials-{hash}`.

- Scope: 2.5, GAP-2
- Complexity: Moderate
- Acceptance:
  - [x] `/Users/test/.claude/accounts/config-1` produces same hash as v1.x Python
  - [x] Verify against 5 known paths
  - [x] NFC normalization handles Unicode correctly

## M2-05: Build keychain write (macOS hex-encoded)

macOS: `security-framework` crate, hex-encode JSON before writing. Account parameter: `"credentials"`. 3-second timeout equivalent (best-effort, never blocks critical path).

- Scope: 2.6, GAP-2
- Complexity: Moderate
- Depends: M2-04
- Acceptance:
  - [x] macOS: keychain entry written, readable by `security find-generic-password`
  - [x] Hex-decoded payload matches original JSON
  - [x] Failure does not propagate (best-effort)

## M2-06: Build keychain write (Linux/Windows)

Linux: `keyring` crate with `libsecret` backend, store JSON directly. Windows: `keyring` crate with Windows Credential Manager, store JSON directly.

- Scope: 2.6, GAP-2
- Complexity: Moderate
- Depends: M2-04
- Acceptance:
  - [x] Linux: entry written if libsecret available, graceful fallback if not
  - [x] Windows: entry written to Credential Manager
  - [x] JSON round-trips correctly

## M2-07: Build credential capture (keychain read + file read)

Read credentials from macOS keychain (hex-decode JSON) or fall back to reading `config-N/.credentials.json`. This is the `csq login` post-login capture flow.

- Scope: 2.8-2.9
- Complexity: Complex (keychain read), Trivial (file read)
- Depends: M2-04
- Acceptance:
  - [x] macOS: hex-decoded JSON matches credential structure
  - [x] File fallback: reads .credentials.json when keychain fails
  - [x] Keychain timeout: does not block >3s

## M2-08: Build canonical save + config-dir mirror

Save to `credentials/N.json` (canonical) AND `config-N/.credentials.json` (live). Both atomic writes with secure permissions.

- Scope: 2.10-2.11
- Complexity: Moderate
- Depends: M2-01
- Acceptance:
  - [x] Both files written atomically
  - [x] Both have `0o600`
  - [x] Partial failure (canonical succeeds, live fails) is handled

## M2-09: Integration tests for credential management

Parity tests: keychain service name for known paths. Round-trip load/save. Concurrent access patterns. Refresh token merge verification.

- Scope: Phase 1 test strategy
- Complexity: Moderate
- Acceptance:
  - [x] > 90% line coverage on `credentials/`
  - [x] Keychain service name parity test passes
