---
name: testing
description: Test fixture rules — no time-bombs, no shared mutable state, mock fixtures must outlive the codebase
paths:
  - "**/tests/**"
  - "**/*test*.rs"
  - "**/*tests.rs"
  - "**/test_*.rs"
  - "**/*spec*.rs"
---

# Test Fixture Rules

Applies to all test files (Rust unit tests under `#[cfg(test)]`, integration tests under `tests/`, and any helper modules they import).

## MUST Rules

### 1. No Hard-Coded Wall-Clock Time-Bombs

Test fixtures MUST NOT embed timestamps that look like "today + N hours" or "this month + N days". Either use a far-future literal (year 2100+) or compute from `SystemTime::now() + Duration` at test construction time.

```rust
// DO — far-future literal that outlives the codebase
fn mock_zai_response() -> &'static [u8] {
    br#"{"data":{"limits":[{"nextResetTime":4102444800000}]}}"#
    //                                       ^^^^^^^^^^^^^^^ 2100-01-01 in ms
}

// DO — computed at test time
fn mock_response() -> Vec<u8> {
    let future = (SystemTime::now() + Duration::from_secs(365 * 86400))
        .duration_since(UNIX_EPOCH).unwrap().as_millis();
    format!(r#"{{"resets_at":{future}}}"#).into_bytes()
}

// DO NOT — looks plausible, becomes a time-bomb
fn mock_zai_response() -> &'static [u8] {
    br#"{"data":{"limits":[{"nextResetTime":1776025018977}]}}"#
    //                                       ^^^^^^^^^^^^^ 2026-04-12 — fails after this instant
}
```

**Why:** Two pre-existing test failures hit the image-cache guard session in 2026-04 because mocks pinned `nextResetTime` to "today + 4 hours". Once real time crossed that instant, `quota::clear_expired` nulled the windows on load and the assertion broke. The author who wrote those literals in early 2026 picked a date that _looked_ far enough but wasn't. This is the silent-decay shape of test failure — every `now()`-aware path becomes a time-bomb if mocked with a near-future literal.

**Audit checklist** when reviewing test changes:

- Search for `nextResetTime`, `end_time`, `weekly_end_time`, `expires_at`, `resets_at`, `created_at`
- Reject any value that decodes to a date within 5 years of when the test was written
- Required value if literal: `4102444800000` (2100-01-01 in ms) or `4102444800` (in s)
- Required comment: name the rationale so the next maintainer doesn't "tidy" it back

### 2. Test Mocks Must Round-Trip Through Production State

If a test feeds fixture data through a save → load cycle (e.g. `quota_state::save_state` → `quota_state::load_state`), the fixture must satisfy every invariant the production loader enforces. `clear_expired`, `validate_account`, `is_valid_session_name`, etc. all run on load — a fixture that's "internally correct" but can't survive the load path is a broken fixture.

```rust
// DO — fixture survives clear_expired
let window = UsageWindow {
    used_percentage: 50.0,
    resets_at: 4_102_444_800,  // year 2100, won't be cleared
};

// DO NOT — fixture nulled on first load
let window = UsageWindow {
    used_percentage: 50.0,
    resets_at: 1_000,  // 1970, clear_expired drops it
};
```

**Why:** Tests that round-trip through a loader implicitly depend on the loader's full invariant set. If the fixture violates any one of them, the test asserts on data that production code has already discarded.

### 3. Sign+Verify Tests Use a Test-Override Constant

When testing signature verification against a `pub const` public key (e.g. `RELEASE_PUBLIC_KEY_BYTES`), use `#[cfg(test)]` to override the constant with a deterministic test key. This lets tests sign with a known seed without needing the production private key in the test environment.

```rust
// DO — production gets the real key, tests get the seed-1 placeholder
#[cfg(not(test))]
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [/* foundation key */];

#[cfg(test)]
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [/* seed-1 derived */];

#[cfg(test)]
pub fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])  // matches the cfg(test) constant
}

// DO NOT — production constant in test, no way to sign in CI
pub const RELEASE_PUBLIC_KEY_BYTES: [u8; 32] = [/* foundation key */];
// tests can't sign because they don't have the foundation private key
```

**Why:** Production signing keys live ONLY in the release pipeline (e.g. GitHub Secrets), so test code can't sign with them. Without a `cfg(test)` override, sign+verify tests are forced to use mocked verifiers, which means the actual `verify_signature` code path goes untested.

### 4. Path-Sensitive Tests Use TempDir, Never `~/.claude`

Tests that write to filesystem paths MUST use `tempfile::TempDir`, never the user's real `~/.claude/` or `~/.claude/accounts/`. The CI runners share `$HOME` between test invocations and a test that writes to the real path leaves residue that contaminates the next run.

```rust
// DO
let dir = TempDir::new().unwrap();
let claude_home = dir.path().join(".claude");
std::fs::create_dir_all(&claude_home).unwrap();
sweep_dead_handles(dir.path(), Some(&claude_home));

// DO NOT
let claude_home = dirs::home_dir().unwrap().join(".claude");
sweep_dead_handles(&claude_home.join("accounts"), Some(&claude_home));
// pollutes the developer's real account state
```

**Why:** Tests that touch real `~/.claude/` corrupt the developer's running daemon state and (worse) leak credentials into test logs if a tracing call happens to format the live path. The csq daemon also sweeps `term-*` dirs every 60s — a test that creates a `term-99999` dir under the real base might get swept mid-test.

### 5. Mock Closures Match the Real Transport Shape

When injecting an HTTP closure (`HttpGetFn`, `HttpPostFn`), the mock signature MUST match the production type alias byte-for-byte. Drift between the mock and the real transport means the test passes against a different contract than the production code follows.

```rust
// DO — exactly matches csq_core::daemon::HttpGetFn
let http_get: HttpGetFn = Arc::new(
    |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
        Ok((200, br#"{"ok":true}"#.to_vec()))
    }
);

// DO NOT — drops the headers parameter, won't compile against the real type
let http_get = |_url: &str, _token: &str| Ok((200, vec![]));
```

**Why:** Type-checked transport injection is the entire point of the closure pattern. A mock that omits parameters or returns a different shape passes the test build but the type system never catches the contract drift, leaving a gap between what the test exercises and what production calls.

## SHOULD Rules

### 1. Round-Trip Tests Cover Both Directions

For every `save_*` / `load_*` pair, write a single test that does `save → load → assert equal`. This catches loader invariant violations and round-trip stability bugs in one place.

### 2. Property Tests for Validators

For non-trivial validators (`is_valid_session_name`, `is_valid_path_component`, etc.) write at least one property test covering the rejection alphabet — empty, max-length, every excluded character class.

### 3. Symlink Adversarial Tests Are Unix-Only

Tests that exercise symlink defenses MUST be `#[cfg(unix)]`. Windows has different symlink semantics (and often requires admin to create them) so the same test on Windows would either skip silently or report false negatives.

```rust
#[cfg(unix)]
#[test]
fn refuses_symlink_at_destination() {
    // ... std::os::unix::fs::symlink(...)
}
```

## Cross-References

- `rules/zero-tolerance.md` Rule 1 — pre-existing test failures must be fixed in-session, not deferred
- `rules/zero-tolerance.md` Rule 5 — redteam findings are resolved, not journaled as accepted
- `rules/no-stubs.md` — frontend mock data is a stub
- Journal 0038 — the time-bomb post-mortem and zero-residual-risk session
