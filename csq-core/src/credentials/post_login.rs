//! Post-`claude auth login` credential capture (keychain-commit race fix).
//!
//! After a successful `claude auth login`, CC commits the freshly minted OAuth
//! token to the macOS Keychain (service `Claude Code-credentials-{hash}`).
//! That keychain write can land a beat AFTER the subprocess exits, so a single
//! immediate [`keychain::read`] races it. The prior login read-back —
//! `keychain::read(dir).or_else(|| file::load(...).ok())` — lost that race
//! whenever the keychain wasn't committed yet and fell back to the STALE
//! `config-N/.credentials.json` on disk, persisting an already-expired token,
//! printing "credentials saved", and BLOCKING re-login recovery: the account
//! stayed Expired no matter how many times the user re-authed (a fresh token
//! sat unused in the keychain the whole time).
//!
//! [`read_fresh_after_login`] closes the race:
//!   1. reads BOTH the keychain and `.credentials.json` on each attempt,
//!   2. keeps whichever Anthropic credential is **login-fresh** — minted
//!      within [`MINT_WINDOW_MS`] of the expected CC access-token expiry
//!      (`now + CC_ACCESS_TOKEN_TTL_MS`). This is a bounded, zero-network
//!      liveness signal: a dead-but-later-expiry keychain token whose TTL
//!      is anomalously longer than the expected 5-hour CC TTL cannot be
//!      "login-fresh" by this definition, so a live `config-N` file token
//!      wins over it regardless of raw `expiresAt` ordering. When both
//!      candidates are login-fresh (the common case with standard CC tokens),
//!      the one with the higher `expiresAt` wins (preserving prior tie-break
//!      behaviour).
//!   3. returns as soon as the selected candidate is unexpired,
//!   4. otherwise retries with a short backoff (~2.2 s total) to let CC commit,
//!   5. returns `Err` if no unexpired credential ever appears — it NEVER
//!      silently saves a stale token and reports success.
//!
//! Both login paths (the CLI `csq login` and the desktop Add/Re-auth twin) call
//! this single helper, per `rules/account-terminal-separation.md` MUST Rule 5
//! (subscription metadata is carried verbatim in the captured credential) and
//! the CLI/desktop twin-parity discipline.
//!
//! Origin: 2026-06-20 — user hit "csq login N succeeds but the desktop card
//! still shows Expired"; the fresh token was stranded in the keychain while csq
//! saved the 35-day-old `.credentials.json`.
//!
//! Liveness fix origin: an internal ticket — selection by raw `expiresAt` alone is a
//! recency proxy, not a chain-liveness proof; a dead-but-anomalously-long-TTL
//! keychain token could beat a live file token.

use std::path::Path;
use std::time::Duration;

use super::{file, keychain, CredentialFile};

/// A credential expiring within this buffer (seconds) is treated as "not
/// fresh". A token CC just minted is hours out, so anything inside a minute is
/// a leftover stale credential, not the one the login produced.
const FRESH_BUFFER_SECS: u64 = 60;

/// Keychain-commit race budget: how many times to re-read before giving up.
/// `DEFAULT_ATTEMPTS * BACKOFF` ≈ 2.2 s, comfortably above the observed
/// keychain-commit lag while staying imperceptible on the success path (the
/// first read almost always wins, returning immediately).
const DEFAULT_ATTEMPTS: u32 = 12;
const BACKOFF: Duration = Duration::from_millis(200);

/// Expected Anthropic access-token TTL in milliseconds (5 hours = 18 000 s).
///
/// Derived directly from `crate::oauth::exchange::DEFAULT_EXPIRES_IN_SECS`
/// (the same value observed empirically from Anthropic's OAuth endpoint and
/// used as the exchange fallback). Single-sourcing guarantees these two never
/// silently diverge — if Anthropic changes the TTL, updating
/// `DEFAULT_EXPIRES_IN_SECS` in `exchange.rs` automatically updates the
/// freshness window here.
const CC_ACCESS_TOKEN_TTL_MS: u64 = crate::oauth::exchange::DEFAULT_EXPIRES_IN_SECS * 1_000;

/// Acceptable deviation from the expected expiry for a token to be considered
/// "login-fresh".
///
/// A token is login-fresh when:
///   `now + CC_ACCESS_TOKEN_TTL_MS - MINT_WINDOW_MS`
///   ≤ `expires_at_ms`
///   ≤ `now + CC_ACCESS_TOKEN_TTL_MS + MINT_WINDOW_MS`
///
/// The window is deliberately wide (±60 min) to buy TTL-drift tolerance.
/// Its sole job is separating "minted in THIS login" from
/// "anomalously-long-TTL prior-session token" — a task that needs only a
/// window much narrower than the gap between the standard TTL (5 h) and any
/// realistically anomalous TTL (e.g. 8 h). A ±60 min window centred on 5 h
/// still excludes an 8 h anomaly (|8 h − 5 h| = 3 h >> 60 min), so the
/// security invariant — "a dead token with an anomalously long TTL cannot
/// beat a standard-TTL live token" — is unchanged. Under the prior ±10 min
/// window, a >10 min drift in Anthropic's TTL would falsely exclude every
/// standard-TTL token minted in the current login.
const MINT_WINDOW_MS: u64 = 60 * 60 * 1_000; // 60 minutes

/// Why post-login credential capture failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshLoginError {
    /// No credential appeared in the keychain or `.credentials.json` at all.
    NoCredentials,
    /// Only an already-expired credential was readable across the full retry
    /// budget — CC's keychain write may not have committed, or keychain access
    /// was denied to csq.
    OnlyStale,
}

impl std::fmt::Display for FreshLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredentials => write!(
                f,
                "no credentials captured after login — keychain and \
                 .credentials.json both empty"
            ),
            Self::OnlyStale => write!(
                f,
                "login succeeded but only an expired credential was readable \
                 after retry — the credential write (the macOS Keychain, or \
                 .credentials.json on Linux/Windows) may not have committed in \
                 time, or access was denied to csq; retry the login. If it \
                 persists on macOS, open Keychain Access and confirm a \
                 'Claude Code-credentials-*' item exists for this account"
            ),
        }
    }
}

impl std::error::Error for FreshLoginError {}

/// Reads the credential CC wrote after a successful `claude auth login`,
/// preferring the freshest source and retrying to absorb the keychain-commit
/// race. See the module docs for the full rationale.
pub fn read_fresh_after_login(config_dir: &Path) -> Result<CredentialFile, FreshLoginError> {
    let file_path = config_dir.join(".credentials.json");
    read_fresh_after_login_with(
        || keychain::read(config_dir),
        || file::load(&file_path).ok(),
        DEFAULT_ATTEMPTS,
        |_attempt| std::thread::sleep(BACKOFF),
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        },
    )
}

/// Testable core: injected keychain + file readers, sleep hook, and `now_ms`
/// clock (closure injection per `rules/redteam-discipline.md` Rule 5 — the
/// real keychain, `thread::sleep`, and wall clock are not exercised in unit
/// tests).
///
/// ## Selection algorithm (an internal ticket liveness fix)
///
/// On each attempt:
/// 1. Read both sources; collect Anthropic-variant candidates only.
/// 2. For each candidate compute `is_login_fresh(expiresAt, now)`:
///    a token is login-fresh when its `expiresAt` falls within
///    `[now + CC_TTL - MINT_WINDOW, now + CC_TTL + MINT_WINDOW]`.
///    A token minted in THIS login has `expiresAt ≈ now + CC_TTL`.
///    A dead token from a prior session with an anomalously long TTL
///    (e.g. `expiresAt = now + 8h` while CC_TTL = 5h) falls outside
///    the window and cannot win over a login-fresh token.
/// 3. Replace `best` according to:
///    - A login-fresh candidate always beats a non-login-fresh `best`.
///    - Among two login-fresh candidates (the standard same-TTL case),
///      the one with the higher `expiresAt` wins (preserving prior
///      tie-break behaviour).
///    - Among two non-login-fresh candidates (fallback), higher `expiresAt`
///      wins.
/// 4. Return as soon as `best` is unexpired (`expiresAt > now + 60s`).
///    Otherwise retry; sleep between attempts (never after the last one).
///
/// `sleep` is called with the zero-based attempt index.
fn read_fresh_after_login_with<K, F, S, N>(
    mut read_keychain: K,
    mut read_file: F,
    attempts: u32,
    mut sleep: S,
    mut now_ms_fn: N,
) -> Result<CredentialFile, FreshLoginError>
where
    K: FnMut() -> Option<CredentialFile>,
    F: FnMut() -> Option<CredentialFile>,
    S: FnMut(u32),
    N: FnMut() -> u64,
{
    let mut best: Option<CredentialFile> = None;
    let mut saw_any = false;

    for attempt in 0..attempts {
        let now = now_ms_fn();
        for cand in [read_keychain(), read_file()].into_iter().flatten() {
            let Some(cand_exp) = anthropic_expiry(&cand) else {
                continue; // non-Anthropic candidate — not a login credential
            };
            saw_any = true;
            let cand_fresh = is_login_fresh(cand_exp, now);

            // Intentional design — prefer the token minted in THIS login over an
            // anomalously-longer-TTL competitor (an internal ticket).
            //
            // A candidate whose expiry is more than MINT_WINDOW_MS above the expected
            // `now + CC_ACCESS_TOKEN_TTL_MS` upper bound signals a stale or anomalous
            // token from a prior session, NOT a legitimately longer-lived token (a >5h
            // TTL is not an Anthropic-documented feature). In the rare case where BOTH
            // the just-minted token AND the anomalous token are simultaneously live,
            // this selection still prefers the just-minted one: the daemon refresher
            // renews credentials before expiry, so the marginally-shorter standard
            // TTL has no user-visible cost. The security invariant "a dead token can
            // never beat a live one" is preserved independently by `anthropic_is_live_at`
            // — selection order is only consulted while both candidates are unexpired.
            let replace = match &best {
                None => true,
                Some(prev) => {
                    let prev_exp = anthropic_expiry(prev)
                        .expect("best is always an Anthropic cred with a valid expiry");
                    let prev_fresh = is_login_fresh(prev_exp, now);
                    // Login-fresh beats non-login-fresh regardless of expiresAt.
                    // Within the same freshness class, higher expiresAt wins.
                    match (cand_fresh, prev_fresh) {
                        (true, false) => true,    // upgrade: login-fresh beats stale-class
                        (false, true) => false, // keep: don't replace login-fresh with stale-class
                        _ => cand_exp > prev_exp, // same class: later expiry wins
                    }
                }
            };

            if replace {
                best = Some(cand);
            }
        }

        // Return the moment the freshest candidate we've seen is unexpired.
        if best.as_ref().is_some_and(|c| anthropic_is_live_at(c, now)) {
            return Ok(best.expect("is_some_and confirmed Some"));
        }

        if attempt + 1 < attempts {
            sleep(attempt);
        }
    }

    Err(if saw_any {
        FreshLoginError::OnlyStale
    } else {
        FreshLoginError::NoCredentials
    })
}

/// Returns `true` if the token's `expiresAt` is within [`MINT_WINDOW_MS`] of
/// `now_ms + CC_ACCESS_TOKEN_TTL_MS`, indicating it was likely minted during
/// THIS login rather than being a surviving token from a prior session.
///
/// This is the bounded, zero-network liveness signal added by an internal ticket.
/// A dead token with an anomalously long TTL (e.g. `expiresAt = now + 8h`
/// when CC_TTL = 5h) falls outside the upper bound and cannot beat a
/// standard-TTL live token from this login.
///
/// Boundary: `[now + CC_TTL - MINT_WINDOW, now + CC_TTL + MINT_WINDOW]`
/// (inclusive on both ends, using saturating arithmetic to avoid overflow).
fn is_login_fresh(expires_at_ms: u64, now_ms: u64) -> bool {
    let expected_expiry = now_ms.saturating_add(CC_ACCESS_TOKEN_TTL_MS);
    let lower = expected_expiry.saturating_sub(MINT_WINDOW_MS);
    let upper = expected_expiry.saturating_add(MINT_WINDOW_MS);
    expires_at_ms >= lower && expires_at_ms <= upper
}

fn anthropic_expiry(cred: &CredentialFile) -> Option<u64> {
    cred.anthropic().map(|a| a.claude_ai_oauth.expires_at)
}

/// Returns `true` if the credential is "live" relative to `now_ms` — i.e. its
/// access token does not expire within the next [`FRESH_BUFFER_SECS`] seconds.
fn anthropic_is_live_at(cred: &CredentialFile, now_ms: u64) -> bool {
    cred.anthropic().is_some_and(|a| {
        let expiry_with_buffer_ms = now_ms.saturating_add(FRESH_BUFFER_SECS * 1_000);
        a.claude_ai_oauth.expires_at >= expiry_with_buffer_ms
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wall_now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Build an Anthropic credential with the given absolute expiry (ms epoch).
    fn anthropic_cred(expires_at_ms: u64) -> CredentialFile {
        let oauth = format!(
            r#"{{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":{expires_at_ms},"scopes":["user:inference"],"subscriptionType":"max"}}"#
        );
        let json = format!(r#"{{"claudeAiOauth":{oauth}}}"#);
        serde_json::from_str(&json).expect("parse anthropic cred fixture")
    }

    /// Fixed "now" used across deterministic tests — 2030-01-01 00:00:00 UTC in ms.
    /// Far enough from 0/u64::MAX to avoid saturating_add/sub boundary effects.
    const FIXED_NOW_MS: u64 = 1_893_456_000_000;

    /// Credential minted in THIS login: `expiresAt = FIXED_NOW_MS + CC_TTL`.
    fn login_fresh_cred() -> CredentialFile {
        anthropic_cred(FIXED_NOW_MS + CC_ACCESS_TOKEN_TTL_MS)
    }

    /// Credential with an anomalously long TTL (8 h > CC_TTL of 5 h) — the
    /// "dead-but-later-expiry" token described in an internal ticket.
    fn long_ttl_cred() -> CredentialFile {
        anthropic_cred(FIXED_NOW_MS + 8 * 3600 * 1_000)
    }

    /// Standard login-fresh credential using the real wall clock (for tests
    /// that do not inject a fixed clock).
    fn wall_fresh_cred() -> CredentialFile {
        anthropic_cred(wall_now_ms() + CC_ACCESS_TOKEN_TTL_MS)
    }

    fn stale_cred() -> CredentialFile {
        anthropic_cred(1000) // 1970 — long expired
    }

    fn no_sleep() -> impl FnMut(u32) {
        |_| {}
    }

    fn fixed_clock() -> impl FnMut() -> u64 {
        move || FIXED_NOW_MS
    }

    fn wall_clock() -> impl FnMut() -> u64 {
        || wall_now_ms()
    }

    // ── AC1: regression test — dead-but-later-expiry inversion case ──────────

    /// Exact scenario from an internal ticket: keychain has a dead token with an
    /// anomalously long TTL (expiresAt = now + 8h), file has the live token
    /// from this login (expiresAt = now + 5h = CC_TTL = login-fresh).
    ///
    /// The OLD code (max-expiresAt selection) picks the dead keychain token.
    /// The NEW code (login-fresh preference) picks the live file token.
    #[test]
    fn login_fresh_file_beats_dead_but_later_expiry_keychain() {
        // Arrange
        let dead_keychain = long_ttl_cred(); // expiresAt = now + 8h, NOT login-fresh
        let live_file = login_fresh_cred(); // expiresAt = now + 5h, login-fresh

        // Sanity-check: keychain's expiresAt IS later (the inversion precondition).
        assert!(
            anthropic_expiry(&dead_keychain).unwrap() > anthropic_expiry(&live_file).unwrap(),
            "fixture: keychain must have later expiresAt to reproduce the inversion"
        );
        assert!(
            !is_login_fresh(anthropic_expiry(&dead_keychain).unwrap(), FIXED_NOW_MS),
            "fixture: keychain token must NOT be login-fresh (long TTL)"
        );
        assert!(
            is_login_fresh(anthropic_expiry(&live_file).unwrap(), FIXED_NOW_MS),
            "fixture: file token MUST be login-fresh (standard TTL)"
        );

        // Act
        let got = read_fresh_after_login_with(
            || Some(dead_keychain.clone()),
            || Some(live_file.clone()),
            DEFAULT_ATTEMPTS,
            no_sleep(),
            fixed_clock(),
        )
        .expect("should capture the login-fresh file token");

        // Assert — the login-fresh file token MUST win.
        assert_eq!(
            anthropic_expiry(&got),
            anthropic_expiry(&live_file),
            "login-fresh file token must beat dead-but-later-expiry keychain token"
        );
    }

    // ── AC2 (structural): no unbounded keychain/network call ─────────────────
    //
    // The `now_ms_fn` closure in production calls `SystemTime::now()` — one
    // syscall, no I/O, no network, no keychain lookup beyond the existing
    // `read_keychain` invocation. The loop is bounded to `DEFAULT_ATTEMPTS`.
    // `is_login_fresh` and `anthropic_is_live_at` perform pure integer arithmetic
    // on already-loaded values — provably zero-network.

    // ── AC3: normal-case no-regression tests ─────────────────────────────────

    /// Original bug scenario: keychain has the fresh token, file is stale.
    #[test]
    fn prefers_fresh_keychain_over_stale_file() {
        let got = read_fresh_after_login_with(
            || Some(wall_fresh_cred()),
            || Some(stale_cred()),
            DEFAULT_ATTEMPTS,
            no_sleep(),
            wall_clock(),
        )
        .expect("should capture the fresh keychain token");
        assert!(
            anthropic_is_live_at(&got, wall_now_ms()),
            "selected token must be live"
        );
    }

    /// Keychain returns None for the first 2 attempts (CC hasn't committed),
    /// then the fresh token. The file is stale the whole time.
    #[test]
    fn retries_until_keychain_commits_then_returns_fresh() {
        let mut kc_calls = 0;
        let mut slept = 0;
        let got = read_fresh_after_login_with(
            || {
                kc_calls += 1;
                if kc_calls <= 2 {
                    None
                } else {
                    Some(wall_fresh_cred())
                }
            },
            || Some(stale_cred()),
            DEFAULT_ATTEMPTS,
            |_| slept += 1,
            wall_clock(),
        )
        .expect("should retry past the keychain-commit race");
        assert!(anthropic_is_live_at(&got, wall_now_ms()));
        assert_eq!(kc_calls, 3, "should have retried until keychain committed");
        assert_eq!(
            slept, 2,
            "should sleep once between each of the first 3 attempts"
        );
    }

    /// Both sources have standard CC TTL tokens (login-fresh).
    /// The one with the higher expiresAt must win (tie-break).
    #[test]
    fn prefers_later_expiry_when_both_login_fresh() {
        // Both within the MINT_WINDOW_MS of expected expiry.
        let later_exp = FIXED_NOW_MS + CC_ACCESS_TOKEN_TTL_MS + 30_000; // +30s above TTL
        let earlier_exp = FIXED_NOW_MS + CC_ACCESS_TOKEN_TTL_MS - 30_000; // -30s below TTL

        assert!(
            is_login_fresh(later_exp, FIXED_NOW_MS),
            "later must be login-fresh"
        );
        assert!(
            is_login_fresh(earlier_exp, FIXED_NOW_MS),
            "earlier must be login-fresh"
        );
        assert!(later_exp > earlier_exp);

        let got = read_fresh_after_login_with(
            || Some(anthropic_cred(later_exp)),
            || Some(anthropic_cred(earlier_exp)),
            DEFAULT_ATTEMPTS,
            no_sleep(),
            fixed_clock(),
        )
        .expect("fresh");
        assert_eq!(
            anthropic_expiry(&got),
            Some(later_exp),
            "higher expiresAt must win among login-fresh candidates"
        );
    }

    /// Linux path: no keychain, the fresh token is in the file.
    #[test]
    fn accepts_file_when_keychain_absent() {
        let got = read_fresh_after_login_with(
            || None,
            || Some(wall_fresh_cred()),
            DEFAULT_ATTEMPTS,
            no_sleep(),
            wall_clock(),
        )
        .expect("file fresh");
        assert!(anthropic_is_live_at(&got, wall_now_ms()));
    }

    /// Both sources only ever hold a stale token — never silently saves it.
    #[test]
    fn errors_only_stale_when_nothing_fresh_after_retries() {
        let mut slept = 0;
        let err = read_fresh_after_login_with(
            || Some(stale_cred()),
            || Some(stale_cred()),
            5,
            |_| slept += 1,
            wall_clock(),
        )
        .expect_err("must not return a stale credential");
        assert_eq!(err, FreshLoginError::OnlyStale);
        assert_eq!(slept, 4, "sleeps between attempts only (attempts-1)");
    }

    #[test]
    fn errors_no_credentials_when_both_empty() {
        let err = read_fresh_after_login_with(|| None, || None, 3, no_sleep(), wall_clock())
            .expect_err("none");
        assert_eq!(err, FreshLoginError::NoCredentials);
    }

    // ── Extra AC1: keychain IS login-fresh → correct winner ──────────────────

    /// When the keychain token IS login-fresh (normal case — CC just wrote it)
    /// with a higher expiresAt, it must win over a login-fresh file token.
    #[test]
    fn login_fresh_keychain_beats_login_fresh_file_with_lower_expiry() {
        let kc_exp = FIXED_NOW_MS + CC_ACCESS_TOKEN_TTL_MS + 5_000; // +5s over TTL
        let file_exp = FIXED_NOW_MS + CC_ACCESS_TOKEN_TTL_MS - 5_000; // -5s under TTL

        assert!(is_login_fresh(kc_exp, FIXED_NOW_MS));
        assert!(is_login_fresh(file_exp, FIXED_NOW_MS));
        assert!(kc_exp > file_exp);

        let got = read_fresh_after_login_with(
            || Some(anthropic_cred(kc_exp)),
            || Some(anthropic_cred(file_exp)),
            DEFAULT_ATTEMPTS,
            no_sleep(),
            fixed_clock(),
        )
        .expect("fresh");
        assert_eq!(
            anthropic_expiry(&got),
            Some(kc_exp),
            "login-fresh keychain wins when it has higher expiresAt"
        );
    }

    // ── is_login_fresh unit tests ─────────────────────────────────────────────

    #[test]
    fn is_login_fresh_boundary_cases() {
        let now = FIXED_NOW_MS;
        let expected = now + CC_ACCESS_TOKEN_TTL_MS;

        // Exact expected expiry → login-fresh.
        assert!(is_login_fresh(expected, now));

        // At window boundaries → still login-fresh.
        assert!(is_login_fresh(expected - MINT_WINDOW_MS, now));
        assert!(is_login_fresh(expected + MINT_WINDOW_MS, now));

        // One ms beyond the window → NOT login-fresh.
        assert!(!is_login_fresh(expected - MINT_WINDOW_MS - 1, now));
        assert!(!is_login_fresh(expected + MINT_WINDOW_MS + 1, now));

        // Anomalously long TTL (8h) → NOT login-fresh (the AC1 inversion token).
        assert!(!is_login_fresh(now + 8 * 3600 * 1_000, now));

        // Already-expired → NOT login-fresh.
        assert!(!is_login_fresh(1000, now));
    }
}
