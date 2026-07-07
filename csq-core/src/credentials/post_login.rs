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
//!   2. keeps whichever Anthropic credential has the LATER `expiresAt` — a
//!      stale file can never shadow a fresh keychain token, and on Linux (no
//!      keychain) the file still wins,
//!   3. returns as soon as the freshest candidate is unexpired,
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
    )
}

/// Testable core: injected keychain + file readers and a sleep hook (closure
/// injection per `rules/redteam-discipline.md` Rule 5 — the real keychain and
/// `thread::sleep` are not exercised in unit tests).
///
/// Each attempt reads both sources, keeps whichever Anthropic credential has
/// the later `expiresAt`, and returns as soon as that best candidate is
/// unexpired. Non-Anthropic candidates (e.g. a Codex `auth.json`) are ignored —
/// the `claude auth login` path is Anthropic-only. `sleep` is called between
/// attempts only (never after the last), with the zero-based attempt index.
fn read_fresh_after_login_with<K, F, S>(
    mut read_keychain: K,
    mut read_file: F,
    attempts: u32,
    mut sleep: S,
) -> Result<CredentialFile, FreshLoginError>
where
    K: FnMut() -> Option<CredentialFile>,
    F: FnMut() -> Option<CredentialFile>,
    S: FnMut(u32),
{
    let mut best: Option<CredentialFile> = None;
    let mut saw_any = false;

    for attempt in 0..attempts {
        for cand in [read_keychain(), read_file()].into_iter().flatten() {
            let Some(cand_exp) = anthropic_expiry(&cand) else {
                continue; // non-Anthropic candidate — not a login credential
            };
            saw_any = true;
            let best_exp = best.as_ref().and_then(anthropic_expiry);
            if best_exp.is_none_or(|b| cand_exp > b) {
                best = Some(cand);
            }
        }

        // Return the moment the freshest candidate we've seen is unexpired.
        if best.as_ref().is_some_and(anthropic_is_fresh) {
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

fn anthropic_expiry(cred: &CredentialFile) -> Option<u64> {
    cred.anthropic().map(|a| a.claude_ai_oauth.expires_at)
}

fn anthropic_is_fresh(cred: &CredentialFile) -> bool {
    cred.anthropic()
        .is_some_and(|a| !a.claude_ai_oauth.is_expired_within(FRESH_BUFFER_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Build an Anthropic credential with the given absolute expiry (ms epoch).
    fn anthropic(expires_at_ms: u64) -> CredentialFile {
        let oauth = format!(
            r#"{{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":{expires_at_ms},"scopes":["user:inference"],"subscriptionType":"max"}}"#
        );
        let json = format!(r#"{{"claudeAiOauth":{oauth}}}"#);
        serde_json::from_str(&json).expect("parse anthropic cred fixture")
    }

    fn fresh() -> CredentialFile {
        anthropic(now_ms() + 8 * 3600 * 1000) // +8h
    }
    fn stale() -> CredentialFile {
        anthropic(1000) // 1970
    }

    fn no_sleep() -> impl FnMut(u32) {
        |_| {}
    }

    #[test]
    fn prefers_fresh_keychain_over_stale_file() {
        // The bug scenario: keychain has the fresh token, the file is stale.
        // The old `keychain.or_else(file)` was fine HERE; the regression was
        // when the keychain read transiently failed (next test).
        let got = read_fresh_after_login_with(
            || Some(fresh()),
            || Some(stale()),
            DEFAULT_ATTEMPTS,
            no_sleep(),
        )
        .expect("should capture the fresh keychain token");
        assert!(anthropic_is_fresh(&got));
    }

    #[test]
    fn retries_until_keychain_commits_then_returns_fresh() {
        // Keychain returns None for the first 2 attempts (CC hasn't committed),
        // then the fresh token. The file is stale the whole time. The old code
        // would have returned the stale file on attempt 0; the fix retries.
        let mut kc_calls = 0;
        let mut slept = 0;
        let got = read_fresh_after_login_with(
            || {
                kc_calls += 1;
                if kc_calls <= 2 {
                    None
                } else {
                    Some(fresh())
                }
            },
            || Some(stale()),
            DEFAULT_ATTEMPTS,
            |_| slept += 1,
        )
        .expect("should retry past the keychain-commit race");
        assert!(anthropic_is_fresh(&got));
        assert_eq!(
            kc_calls, 3,
            "should have retried until the keychain committed"
        );
        assert_eq!(
            slept, 2,
            "should sleep once between each of the first 3 attempts"
        );
    }

    #[test]
    fn prefers_later_expiry_when_both_fresh() {
        let later = now_ms() + 10 * 3600 * 1000;
        let earlier = now_ms() + 5 * 3600 * 1000;
        let got = read_fresh_after_login_with(
            || Some(anthropic(later)),
            || Some(anthropic(earlier)),
            DEFAULT_ATTEMPTS,
            no_sleep(),
        )
        .expect("fresh");
        assert_eq!(anthropic_expiry(&got), Some(later));
    }

    #[test]
    fn accepts_file_when_keychain_absent() {
        // Linux path: no keychain, the fresh token is in the file.
        let got =
            read_fresh_after_login_with(|| None, || Some(fresh()), DEFAULT_ATTEMPTS, no_sleep())
                .expect("file fresh");
        assert!(anthropic_is_fresh(&got));
    }

    #[test]
    fn errors_only_stale_when_nothing_fresh_after_retries() {
        // Both sources only ever hold a stale token — never silently save it.
        let mut slept = 0;
        let err =
            read_fresh_after_login_with(|| Some(stale()), || Some(stale()), 5, |_| slept += 1)
                .expect_err("must not return a stale credential");
        assert_eq!(err, FreshLoginError::OnlyStale);
        assert_eq!(slept, 4, "sleeps between attempts only (attempts-1)");
    }

    #[test]
    fn errors_no_credentials_when_both_empty() {
        let err = read_fresh_after_login_with(|| None, || None, 3, no_sleep()).expect_err("none");
        assert_eq!(err, FreshLoginError::NoCredentials);
    }
}
