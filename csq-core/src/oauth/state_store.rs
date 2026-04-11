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
    /// If the store is at capacity, the oldest entry is evicted
    /// before insertion to keep the size bounded. This never
    /// rejects a new login.
    pub fn insert(&self, code_verifier: CodeVerifier, account: AccountNum) -> String {
        let state = random_state_token();
        let pending = PendingState {
            code_verifier,
            account,
            created_at: Instant::now(),
        };

        let mut guard = self.inner.lock().expect("state store lock poisoned");
        if guard.len() >= self.max_pending {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(state.clone(), pending);
        state
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
        let mut guard = self.inner.lock().expect("state store lock poisoned");
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
        let mut guard = self.inner.lock().expect("state store lock poisoned");
        let before = guard.len();
        let ttl = self.ttl;
        guard.retain(|_, v| v.created_at.elapsed() <= ttl);
        before - guard.len()
    }

    /// Returns the number of currently-pending entries. Primarily
    /// for tests and diagnostics — not on any hot path.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("state store lock poisoned").len()
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
        let state = store.insert(verifier("v1"), account(1));
        assert_eq!(store.len(), 1);
        assert!(!state.is_empty());
    }

    #[test]
    fn state_tokens_are_unique() {
        let store = OAuthStateStore::new();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            let s = store.insert(verifier("v"), account(1));
            assert!(seen.insert(s), "duplicate state token");
        }
    }

    #[test]
    fn consume_returns_pending_and_removes_entry() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("v1"), account(7));

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
        let state = store.insert(verifier("v"), account(1));

        assert!(store.consume(&state).is_ok());
        // Second consume must NOT return the same entry (replay attack).
        let err = store.consume(&state).unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch));
    }

    #[test]
    fn expired_entry_is_rejected_and_removed() {
        let store = OAuthStateStore::with_config(Duration::from_millis(10), MAX_PENDING);
        let state = store.insert(verifier("v"), account(1));

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
        let _ = store.insert(verifier("v1"), account(1));
        let _ = store.insert(verifier("v2"), account(2));
        assert_eq!(store.len(), 2);

        thread::sleep(Duration::from_millis(25));

        let removed = store.sweep_expired();
        assert_eq!(removed, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn sweep_preserves_fresh_entries() {
        let store = OAuthStateStore::with_config(Duration::from_secs(60), MAX_PENDING);
        let _ = store.insert(verifier("v"), account(1));
        let removed = store.sweep_expired();
        assert_eq!(removed, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn insert_at_capacity_evicts_oldest() {
        let store = OAuthStateStore::with_config(Duration::from_secs(60), 3);
        let s1 = store.insert(verifier("v1"), account(1));
        // Ensure distinct created_at timestamps so "oldest" is well-defined.
        thread::sleep(Duration::from_millis(2));
        let s2 = store.insert(verifier("v2"), account(2));
        thread::sleep(Duration::from_millis(2));
        let s3 = store.insert(verifier("v3"), account(3));
        assert_eq!(store.len(), 3);

        thread::sleep(Duration::from_millis(2));
        // Fourth insert must evict s1.
        let _s4 = store.insert(verifier("v4"), account(4));
        assert_eq!(store.len(), 3, "capacity must be held at 3");

        // s1 is gone; s2, s3, s4 remain.
        let e1 = store.consume(&s1).unwrap_err();
        assert!(matches!(e1, OAuthError::StateMismatch));
        assert!(store.consume(&s2).is_ok());
        assert!(store.consume(&s3).is_ok());
    }

    #[test]
    fn is_empty_reflects_store_state() {
        let store = OAuthStateStore::new();
        assert!(store.is_empty());
        let _ = store.insert(verifier("v"), account(1));
        assert!(!store.is_empty());
    }

    #[test]
    fn pending_state_debug_does_not_leak_verifier() {
        let store = OAuthStateStore::new();
        let state = store.insert(verifier("secret-verifier-bytes"), account(1));
        let pending = store.consume(&state).unwrap();
        let dbg = format!("{pending:?}");
        assert!(
            !dbg.contains("secret-verifier-bytes"),
            "PendingState Debug leaked the verifier: {dbg}"
        );
    }
}
