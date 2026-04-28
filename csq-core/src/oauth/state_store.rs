//! Pending OAuth state tokens with TTL, bounded size, and single-
//! use semantics.
//!
//! # Threat model
//!
//! The `state` query parameter on the authorize URL is the
//! anti-CSRF token. When Anthropic redirects the browser back to
//! `http://127.0.0.1:{port}/oauth/callback?code=X&state=Y`, the
//! callback handler MUST verify that `Y` was issued by this daemon
//! before accepting the code. Otherwise a malicious page could
//! forge a callback and trick the daemon into exchanging an
//! attacker-chosen code.
//!
//! Each entry in the store also holds the [`CodeVerifier`] for the
//! login. PKCE requires the verifier to come back unchanged during
//! the code exchange — the verifier lives in the store for exactly
//! as long as the state does.
//!
//! # Invariants
//!
//! 1. **Single use** — [`OAuthStateStore::consume`] removes the
//!    entry before returning it. A second `consume` with the same
//!    state returns `StateMismatch`. Replay-protects callbacks.
//! 2. **TTL enforcement** — entries older than [`STATE_TTL`] are
//!    rejected at consume time with [`OAuthError::StateExpired`].
//!    Abandoned login attempts eventually vanish via
//!    [`OAuthStateStore::sweep_expired`] (called from a background
//!    task in M8.7b) or the next successful consume.
//! 3. **Bounded** — at most [`MAX_PENDING`] entries. A 101st insert
//!    evicts the oldest entry. This defends against a local
//!    attacker who spams `/api/login` (requires being the same UID
//!    as the daemon, so not a privilege boundary, but keeps the
//!    HashMap bounded regardless).
//! 4. **Not serializable** — `PendingState` is never persisted.
//!    Restarting the daemon invalidates all pending logins. This
//!    is the right default: an OAuth flow in progress across a
//!    daemon restart is already broken because the browser would
//!    try to POST to a dead callback listener.
//!
//! # Concurrency
//!
//! The store exposes a single `Arc<OAuthStateStore>` that daemon
//! subsystems clone cheaply. Internally it's a `Mutex<HashMap>` —
//! not `RwLock`, because `insert`, `consume`, and `sweep_expired`
//! all need write access, and read-only paths (like `len`) are not
//! on any hot path. A plain `std::sync::Mutex` is simpler than
//! `tokio::sync::Mutex` here: no lock is ever held across an
//! `await`.
//!
//! # Poison recovery (PR-B7, journal 0063 P2-3)
//!
//! `std::sync::Mutex` poisons when a holder panics. Prior to PR-B7
//! all `lock()` sites here called `.expect("...")`, which turns a
//! non-fatal poison into a process panic. None of the critical
//! sections do anything that can leave the map in a corrupt state
//! (inserts and removes on a HashMap are exception-safe at the Rust
//! level), so we can safely recover via `into_inner()`. The
//! `locked()` helper below centralises that recovery — every call
//! site uses it instead of `.lock().unwrap()` or `.lock().expect()`.
//! This matches the parking_lot-style "mutexes don't poison"
//! contract without adding a new dependency.

use crate::error::OAuthError;
use crate::oauth::pkce::CodeVerifier;
use crate::types::AccountNum;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum number of pending logins the store will hold.
///
/// Legitimate use never exceeds 1 (the user starts one login at a
/// time). 100 is a comfortable ceiling that still bounds worst-case
/// memory if a misbehaving UI (or an attacker on the same UID)
/// hammers `/api/login`.
///
/// # Eviction cost
///
/// [`OAuthStateStore::insert`] is **O(N)** when the store is at
/// capacity because it scans the entire HashMap to find the
/// oldest entry to evict. At MAX_PENDING=100 the scan is trivial
/// (100 comparisons under the mutex, <10µs). If this limit is
/// ever raised substantially, switch to an ordered secondary
/// index (e.g., `BTreeMap<Instant, String>`) so eviction stays
/// sublinear. Do not raise this constant above a few hundred
/// without making that change.
pub const MAX_PENDING: usize = 100;

/// TTL for a pending login state. After this much time the state
/// is considered expired and will be rejected on consume.
///
/// v1.x uses 10 minutes, motivated by the observation that a
/// normal OAuth flow takes well under 2 minutes but a user who
/// context-switches to approve an MFA challenge may take longer.
/// 10 minutes is generous without being unbounded.
///
/// # Clock semantics
///
/// TTL is measured via `Instant::elapsed()`, which reads
/// `CLOCK_MONOTONIC` on Linux and `mach_absolute_time` on macOS.
/// These clocks behave differently during system suspend:
///
/// - macOS: the clock pauses during sleep, so a pending login
///   that spans a sleep cycle may survive beyond 10 wall-clock
///   minutes.
/// - Linux: `CLOCK_MONOTONIC` behavior during suspend is kernel-
///   version dependent; modern kernels typically do not advance
///   it, matching macOS.
///
/// Neither behavior is dangerous — both paths still enforce the
/// TTL correctly against any new activity. A laptop that suspends
/// mid-login and wakes hours later will see the state as "still
/// fresh" on both platforms. The subsequent consume still cleans
/// up the entry exactly once (single-use). We consider this
/// acceptable because the threat model requires a local attacker
/// on the same UID to reach the state token at all.
pub const STATE_TTL: Duration = Duration::from_secs(600);

/// Length of the random state token in URL-safe base64 chars.
/// 32 bytes of entropy → 43 chars — overkill for CSRF but free.
const STATE_BYTES: usize = 32;

/// One pending login. Consumed (removed and returned) on callback.
///
/// # INVARIANT: every field must have a leak-safe `Debug` impl.
///
/// The `#[derive(Debug)]` below is safe today because
/// [`CodeVerifier`] has a manual `Debug` impl that prints
/// `[REDACTED]` and because `AccountNum` / `Instant` are
/// non-sensitive. If a future change adds a new field to this
/// struct, review its `Debug` output before merging. The
/// `pending_state_debug_does_not_leak_verifier` test catches
/// regressions in the existing field but will NOT catch a new
/// sensitive field slipping through the derive.
#[derive(Debug)]
pub struct PendingState {
    /// The PKCE verifier — held in secrecy-wrapped storage so it
    /// never leaks via `Debug` or log formatting.
    pub code_verifier: CodeVerifier,
    /// Which account slot this login is targeting. Encoded once at
    /// login-initiation time so the callback handler doesn't need
    /// to receive it as a query parameter.
    pub account: AccountNum,
    /// Wall-clock `Instant` at which this entry was created. Used
    /// for TTL checks and eviction ordering.
    pub created_at: Instant,
}

/// Bounded TTL map of pending OAuth login states.
pub struct OAuthStateStore {
    inner: Mutex<HashMap<String, PendingState>>,
    ttl: Duration,
    max_pending: usize,
}

impl Default for OAuthStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthStateStore {
    /// Creates a new empty store with production defaults
    /// ([`STATE_TTL`], [`MAX_PENDING`]).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: STATE_TTL,
            max_pending: MAX_PENDING,
        }
    }

    /// Creates a store with explicit TTL and cap. Tests use short
    /// TTLs to exercise the expiry path without sleeping.
    pub fn with_config(ttl: Duration, max_pending: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_pending,
        }
    }

    /// Generates a cryptographically-random state token, inserts
    /// the pending entry, and returns the state token for
    /// embedding in the authorize URL.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::StoreAtCapacity`] if the store already
    /// holds [`MAX_PENDING`] entries. UX-R1-L2: prior versions
    /// silently evicted the oldest entry to make room, but that
    /// converted a "concurrent legitimate login" into a "first
    /// login mysteriously fails on consume" silent drop. Failing
    /// fast at insert lets the orchestrator surface a clear error.
    /// In production the cap is 100 — a legitimate user never
    /// reaches it; an attacker hitting it cannot starve a user out
    /// of the OAuth flow because the cap drains via TTL within 10
    /// minutes.
    pub fn insert(
        &self,
        code_verifier: CodeVerifier,
        account: AccountNum,
    ) -> Result<String, OAuthError> {
        let state = random_state_token();
        let pending = PendingState {
            code_verifier,
            account,
            created_at: Instant::now(),
        };

        let mut guard = self.locked();
        if guard.len() >= self.max_pending {
            return Err(OAuthError::StoreAtCapacity {
                max_pending: self.max_pending,
            });
        }
        guard.insert(state.clone(), pending);
        Ok(state)
    }

    /// Consumes a pending login by state token.
    ///
    /// - Missing entry → [`OAuthError::StateMismatch`] (CSRF).
    /// - Expired entry → [`OAuthError::StateExpired`] (entry is
    ///   removed before returning so a retry returns CSRF, not
    ///   expired).
    /// - Fresh entry → `Ok(PendingState)`, entry removed.
    ///
    /// The entry is **always** removed on consume — there is no
    /// code path that leaves a consumed state in the store.
    pub fn consume(&self, state: &str) -> Result<PendingState, OAuthError> {
        let mut guard = self.locked();
        let pending = guard.remove(state).ok_or(OAuthError::StateMismatch)?;

        if pending.created_at.elapsed() > self.ttl {
            return Err(OAuthError::StateExpired {
                ttl_secs: self.ttl.as_secs(),
            });
        }
        Ok(pending)
    }

    /// Removes every entry whose age exceeds the TTL. Returns the
    /// number of entries removed. Called by a background sweep
    /// task in M8.7b; also callable from tests.
    pub fn sweep_expired(&self) -> usize {
        let mut guard = self.locked();
        let before = guard.len();
        let ttl = self.ttl;
        guard.retain(|_, v| v.created_at.elapsed() <= ttl);
        before - guard.len()
    }

    /// Returns the number of currently-pending entries. Primarily
    /// for tests and diagnostics — not on any hot path.
    pub fn len(&self) -> usize {
        self.locked().len()
    }

    /// Acquires the inner mutex with poison recovery.
    ///
    /// `std::sync::Mutex` poisons when a holder panics. The critical
    /// sections in this store (HashMap insert/remove/retain/len) are
    /// exception-safe — a panic can't leave the map in a corrupt
    /// state — so we recover via `into_inner()` instead of panicking
    /// ourselves. See module doc "Poison recovery" for the full
    /// rationale. Journal 0063 P2-3, PR-B7.
    ///
    /// # Why no `expect`
    ///
    /// REV-R1-L10: every public method of this store goes through
    /// `locked()` rather than calling `lock().expect()`. A panicking
    /// holder elsewhere in the process should not poison the OAuth
    /// flow — the worst case is a few stale pending entries the
    /// caller couldn't have done anything with anyway.
    fn locked(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingState>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns true if the store has no pending entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Generates a 32-byte URL-safe base64 state token.
fn random_state_token() -> String {
    let mut bytes = [0u8; STATE_BYTES];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG unavailable — cannot generate OAuth state token");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread;

    fn account(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn verifier(s: &str) -> CodeVerifier {
        CodeVerifier::new(s.to_string())
    }

    #[test]
    fn insert_stores_pending_entry() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("v1"), account(1)).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!state.is_empty());
    }

    #[test]
    fn state_tokens_are_unique() {
        let store = OAuthStateStore::new();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            let s = store.insert(verifier("v"), account(1)).unwrap();
            assert!(seen.insert(s), "duplicate state token");
        }
    }

    #[test]
    fn consume_returns_pending_and_removes_entry() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("v1"), account(7)).unwrap();

        let pending = store.consume(&state).expect("consume should succeed");
        assert_eq!(pending.account, account(7));
        assert_eq!(pending.code_verifier.expose_secret(), "v1");
        assert_eq!(store.len(), 0, "consumed entry must be removed");
    }

    #[test]
    fn consume_unknown_state_returns_state_mismatch() {
        let store = OAuthStateStore::new();
        let err = store.consume("not-a-real-state").unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch));
    }

    #[test]
    fn consume_is_single_use() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("v"), account(1)).unwrap();

        assert!(store.consume(&state).is_ok());
        // Second consume must NOT return the same entry (replay attack).
        let err = store.consume(&state).unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch));
    }

    #[test]
    fn expired_entry_is_rejected_and_removed() {
        let store = OAuthStateStore::with_config(Duration::from_millis(10), MAX_PENDING);
        let state = store.insert(verifier("v"), account(1)).unwrap();

        thread::sleep(Duration::from_millis(25));

        let err = store.consume(&state).unwrap_err();
        assert!(matches!(err, OAuthError::StateExpired { .. }));
        // Entry must be removed so a retry sees StateMismatch, not
        // the same StateExpired forever.
        assert_eq!(store.len(), 0);
        let second = store.consume(&state).unwrap_err();
        assert!(matches!(second, OAuthError::StateMismatch));
    }

    #[test]
    fn sweep_removes_expired_entries() {
        let store = OAuthStateStore::with_config(Duration::from_millis(10), MAX_PENDING);
        let _ = store.insert(verifier("v1"), account(1)).unwrap();
        let _ = store.insert(verifier("v2"), account(2)).unwrap();
        assert_eq!(store.len(), 2);

        thread::sleep(Duration::from_millis(25));

        let removed = store.sweep_expired();
        assert_eq!(removed, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn sweep_preserves_fresh_entries() {
        let store = OAuthStateStore::with_config(Duration::from_secs(60), MAX_PENDING);
        let _ = store.insert(verifier("v"), account(1)).unwrap();
        let removed = store.sweep_expired();
        assert_eq!(removed, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn insert_at_capacity_returns_error_not_evict() {
        // UX-R1-L2 regression. Prior to this fix, insert silently
        // evicted the oldest entry to make room. That converted a
        // "100 concurrent legitimate logins" scenario into a
        // mysterious StateMismatch on the user whose entry got
        // evicted out from under them. Failing fast at insert
        // surfaces a clear error the orchestrator can translate.
        let store = OAuthStateStore::with_config(Duration::from_secs(60), 3);
        let s1 = store.insert(verifier("v1"), account(1)).unwrap();
        // Ensure distinct created_at timestamps so the test is
        // deterministic about which entries survive.
        thread::sleep(Duration::from_millis(2));
        let s2 = store.insert(verifier("v2"), account(2)).unwrap();
        thread::sleep(Duration::from_millis(2));
        let s3 = store.insert(verifier("v3"), account(3)).unwrap();
        assert_eq!(store.len(), 3);

        thread::sleep(Duration::from_millis(2));
        // Fourth insert must FAIL — no eviction.
        let err = store.insert(verifier("v4"), account(4)).unwrap_err();
        assert!(
            matches!(err, OAuthError::StoreAtCapacity { max_pending: 3 }),
            "insert at capacity must return StoreAtCapacity, got {err:?}"
        );
        assert_eq!(store.len(), 3, "capacity must be held at 3");

        // All three original entries still consumable.
        assert!(store.consume(&s1).is_ok());
        assert!(store.consume(&s2).is_ok());
        assert!(store.consume(&s3).is_ok());
    }

    #[test]
    fn is_empty_reflects_store_state() {
        let store = OAuthStateStore::new();
        assert!(store.is_empty());
        let _ = store.insert(verifier("v"), account(1)).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn pending_state_debug_does_not_leak_verifier() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("secret-verifier-bytes"), account(1)).unwrap();
        let pending = store.consume(&state).unwrap();
        let dbg = format!("{pending:?}");
        assert!(
            !dbg.contains("secret-verifier-bytes"),
            "PendingState Debug leaked the verifier: {dbg}"
        );
    }

    #[test]
    fn store_recovers_from_poisoned_mutex() {
        // Regression guard for PR-B7 (journal 0063 P2-3). Prior to
        // PR-B7 every lock site called `.expect("state store lock
        // poisoned")`, which turned a non-fatal poison into a
        // process panic. The new `locked()` helper uses
        // `unwrap_or_else(|e| e.into_inner())` to recover.
        //
        // We simulate a poison by panicking inside a closure that
        // holds the lock, catching the panic on the outside, then
        // verifying the store still serves requests normally.
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::sync::Arc;

        let store = Arc::new(OAuthStateStore::new());

        // Seed one pending entry so we can assert state survives.
        let pre_state = store.insert(verifier("pre-poison"), account(1)).unwrap();
        assert_eq!(store.len(), 1);

        // Poison the mutex by panicking while holding it. We go
        // through the private `inner` field via a clone; no public
        // method panics while holding the lock, so we use the
        // internal API reachable from the test module.
        let store_clone = Arc::clone(&store);
        let _ = thread::spawn(move || {
            let _guard = store_clone.inner.lock().unwrap();
            panic!("deliberate panic to poison the mutex");
        })
        .join();

        // The mutex is now poisoned. `locked()` must recover.
        let res = catch_unwind(AssertUnwindSafe(|| {
            // All four public API paths must work after poison.
            let new_state = store.insert(verifier("post-poison"), account(2));
            let len = store.len();
            let consumed = store.consume(&pre_state);
            let swept = store.sweep_expired();
            (new_state, len, consumed, swept)
        }));

        let (new_state, len_after_insert, consumed, _swept) =
            res.expect("locked() must not panic on a poisoned mutex");

        let new_state_value = new_state.expect("insert worked after poison");
        assert!(!new_state_value.is_empty(), "insert returned a state token");
        assert_eq!(len_after_insert, 2, "both entries present after poison");
        assert!(consumed.is_ok(), "pre-poison entry consumable after poison");
    }
}
