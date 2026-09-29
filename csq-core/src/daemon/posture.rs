//! Daemon refresh posture — leader (refreshes OAuth tokens) vs follower
//! (polls usage, serves IPC, but NEVER refreshes).
//!
//! # Why a posture exists
//!
//! Anthropic's OAuth refresh response carries a NEW `refresh_token` and
//! invalidates the one that was presented. Two hosts running csq against the
//! SAME accounts therefore fight: whichever daemon refreshes first strands the
//! other on a dead refresh token, which then fails with `error_kind="oauth"`,
//! enters the 10-minute cooldown, and 401s on its next usage poll. Measured on
//! 2026-09-12 across two hosts and 19 shared accounts: four slots hit within
//! ~2 hours, disjoint sets per host, and spreading.
//!
//! The mitigation that was reached for first — stopping the second host's
//! daemon outright — also loses that host's usage polling, IPC, handle-dir
//! sweep and keychain sync. Follower mode removes ONLY the refresh.
//!
//! # What follower mode does and does not disable
//!
//! Disabled: `broker_check` / `broker_codex_check` invocation from the
//! refresher tick. Those are the only two call sites in the daemon that
//! present a refresh token to an upstream OAuth endpoint, and therefore the
//! only two that can rotate one.
//!
//! NOT disabled: usage polling, IPC serving, the handle-dir sweep, keychain
//! sync, the audit outbox drains, the held-provenance sweep, and the keychain
//! custodian. The custodian is deliberately kept: it HARVESTS a token some
//! local CC session already minted and validates it with a read-only GET to
//! `/api/oauth/usage` — it never presents a refresh token, so it cannot
//! rotate one. On a follower it is the mechanism by which the host levels up
//! to a fresher token rather than going stale.
//!
//! # Why a persisted file and not an env var or a CLI flag
//!
//! A flag on `csq daemon start` is silently reverted: the LaunchAgent plist
//! is rewritten by the desktop app (`csq/src/cli/commands/daemon.rs::
//! build_launchd_plist`), so the next app launch drops any argv the operator
//! added. An `EnvironmentVariables` entry in the plist has the same defect for
//! the same reason. csq also carries almost no env knobs by convention
//! (`CSQ_AUDIT_VERIFY_LIMIT`, `CSQ_AUDIT_VERIFY_TIMEOUT_SECS`,
//! `CSQ_PACT_ALLOWED_PATHS` are the whole set), while it carries several
//! persisted per-base-dir JSON configs — `audit-sink.json`, `coc-trust.json`,
//! `rotation.json`. The posture follows that convention: a small JSON file at
//! `<base_dir>/daemon-posture.json`, which nothing in the desktop app rewrites.
//!
//! The file is re-read on every refresher tick rather than once at daemon
//! start, so an operator can flip a host between leader and follower without a
//! restart (and, on the incident path, without racing the desktop supervisor
//! that would otherwise respawn the daemon). One small read per 5-minute tick.
//!
//! # Fail direction
//!
//! - File ABSENT → [`DaemonPosture::Leader`](crate::daemon::posture::DaemonPosture::Leader).
//!   Every install that predates this module has no file, and must keep
//!   refreshing exactly as before.
//! - File present and parseable → whatever it says.
//! - File present but unreadable or unparseable →
//!   [`DaemonPosture::Follower`](crate::daemon::posture::DaemonPosture::Follower),
//!   loudly, via [`PostureSource::Unreadable`](crate::daemon::posture::PostureSource::Unreadable).
//!   The file's mere existence is
//!   evidence that an operator set a posture; the only reason to author it is
//!   to stop this host refreshing. Silently reverting to leader on a corrupt
//!   file re-creates the exact incident the file exists to prevent, and does so
//!   invisibly. Standing down is recoverable and is surfaced by `csq daemon
//!   status` and `csq doctor`; refreshing wrongly burns the other host's token.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// File name of the persisted posture config under `base_dir`.
pub const POSTURE_FILE_NAME: &str = "daemon-posture.json";

/// Whether this daemon may refresh OAuth tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DaemonPosture {
    /// Normal posture: this daemon refreshes tokens. The default.
    #[default]
    Leader,
    /// This daemon polls usage and serves IPC but never refreshes a token.
    /// Some other host is the leader for these accounts.
    Follower,
}

impl DaemonPosture {
    /// True when this posture forbids presenting a refresh token upstream.
    pub fn is_follower(self) -> bool {
        matches!(self, DaemonPosture::Follower)
    }

    /// Stable lowercase tag for logs, `csq daemon status` and `csq doctor`.
    pub fn as_str(self) -> &'static str {
        match self {
            DaemonPosture::Leader => "leader",
            DaemonPosture::Follower => "follower",
        }
    }
}

/// On-disk shape of `daemon-posture.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PostureConfig {
    /// The posture this host takes.
    pub role: DaemonPosture,
}

/// How the effective posture was arrived at. Carried alongside the posture so
/// operator surfaces can distinguish "leader because nobody configured
/// anything" from "follower because the config file is broken" — those need
/// different operator actions and must never render identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureSource {
    /// No `daemon-posture.json` on disk; the default applies.
    Default,
    /// Read and parsed from `daemon-posture.json`.
    File,
    /// `daemon-posture.json` exists but could not be read or parsed. The
    /// posture stood down to follower; the string is the reason, for the
    /// operator.
    Unreadable(String),
}

/// The effective posture plus how it was determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePosture {
    /// The posture the daemon must obey.
    pub posture: DaemonPosture,
    /// Provenance, for operator surfaces.
    pub source: PostureSource,
}

impl EffectivePosture {
    /// True when the posture forbids refreshes.
    pub fn is_follower(&self) -> bool {
        self.posture.is_follower()
    }
}

/// Errors from persisting a posture. Reads never error — they resolve to an
/// [`EffectivePosture`] with a [`PostureSource::Unreadable`] reason instead,
/// because a daemon tick has no caller to propagate to and must still decide.
#[derive(Debug, Error)]
pub enum PostureError {
    /// Filesystem failure while writing the config.
    #[error("daemon posture io: {message}")]
    Io {
        /// Human-readable context.
        message: String,
    },
    /// Serialisation failure.
    #[error("daemon posture json: {message}")]
    Json {
        /// Human-readable context.
        message: String,
    },
}

/// Path of the posture file under `base_dir`.
pub fn posture_path(base_dir: &Path) -> PathBuf {
    base_dir.join(POSTURE_FILE_NAME)
}

/// Resolve the effective posture for `base_dir`.
///
/// Never fails — see the fail-direction section in the module docs for why an
/// unreadable file resolves to [`DaemonPosture::Follower`] rather than to an
/// error or to the leader default.
pub fn load(base_dir: &Path) -> EffectivePosture {
    let path = posture_path(base_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return EffectivePosture {
                posture: DaemonPosture::Leader,
                source: PostureSource::Default,
            };
        }
        Err(e) => {
            return EffectivePosture {
                posture: DaemonPosture::Follower,
                source: PostureSource::Unreadable(format!("read {POSTURE_FILE_NAME}: {e}")),
            };
        }
    };
    match serde_json::from_str::<PostureConfig>(&raw) {
        Ok(cfg) => EffectivePosture {
            posture: cfg.role,
            source: PostureSource::File,
        },
        Err(e) => EffectivePosture {
            posture: DaemonPosture::Follower,
            // The payload is a two-field non-secret config, but serde's Display
            // echoes input bytes and this is a public error string; run it
            // through the shared redactor anyway (security.md MUST Rule 8's
            // defense-in-depth posture) rather than assuming the file's
            // contents.
            source: PostureSource::Unreadable(crate::error::redact_tokens(&format!(
                "parse {POSTURE_FILE_NAME}: {e}"
            ))),
        },
    }
}

/// Persist `posture` for `base_dir`, creating the file if absent.
///
/// Atomic + 0o600 per `rules/security.md` §4/§5, with tmp cleanup on every
/// failure branch (§5a). The payload is non-secret; the pattern is applied for
/// consistency with the other `base_dir` configs.
pub fn save(base_dir: &Path, posture: DaemonPosture) -> Result<(), PostureError> {
    let path = posture_path(base_dir);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PostureError::Io {
            message: format!("create parent dir for {POSTURE_FILE_NAME}: {e}"),
        })?;
    }

    let json = serde_json::to_string_pretty(&PostureConfig { role: posture }).map_err(|e| {
        PostureError::Json {
            message: format!("serialise {POSTURE_FILE_NAME}: {e}"),
        }
    })?;

    let tmp = unique_tmp_path(&path);

    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(PostureError::Io {
            message: format!("write tmp for {POSTURE_FILE_NAME}: {e}"),
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(PostureError::Io {
            message: format!("secure_file for {POSTURE_FILE_NAME}: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(PostureError::Io {
            message: format!("atomic_replace for {POSTURE_FILE_NAME}: {e}"),
        });
    }
    Ok(())
}

/// One slot whose stored OAuth access token has already expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredSlot {
    /// Slot number.
    pub slot: u16,
    /// `"anthropic"` or `"codex"`.
    pub surface: &'static str,
    /// Whole seconds the token has been expired for.
    pub expired_for_secs: u64,
}

/// Enumerate slots whose stored access token is ALREADY EXPIRED (not merely
/// inside the pre-expiry refresh window).
///
/// This is the operator-legibility half of follower mode: a follower that is
/// not being covered by any leader goes stale, and "stale" must be a stated
/// condition rather than a mysterious 401 later. Reported by `csq daemon
/// status` and `csq doctor` when the posture is follower.
///
/// Scope: Anthropic and Codex OAuth slots, which are the two surfaces the
/// refresher refreshes. Bearer-keyed third-party providers have no refresh
/// token, are unaffected by posture, and are not counted here. Slot ids come
/// from `discovery`, which is the same per-slot channel the refresher uses —
/// no new slot-id channel is introduced (`account-terminal-separation.md`
/// MUST Rule 1).
///
/// Best-effort: an unreadable credential file is skipped rather than reported
/// as expired, because "cannot read" and "expired" are different conditions
/// and this function must not conflate them.
pub fn expired_slots(base_dir: &Path, now_ms: u64) -> Vec<ExpiredSlot> {
    use crate::accounts::AccountSource;
    use crate::providers::catalog::Surface;

    let mut out = Vec::new();
    let mut accounts = crate::accounts::discovery::discover_anthropic(base_dir);
    accounts.extend(crate::accounts::discovery::discover_codex(base_dir));

    for info in accounts {
        if !info.has_credentials {
            continue;
        }
        let account = match crate::types::AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let uuid = crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get());
        let (surface, canonical) = match info.source {
            AccountSource::Anthropic => (
                "anthropic",
                match uuid {
                    Some(u) => crate::accounts::identity_store::credentials_path_for(base_dir, u),
                    None => crate::credentials::file::canonical_path(base_dir, account),
                },
            ),
            AccountSource::Codex => (
                "codex",
                match uuid {
                    Some(u) => {
                        crate::accounts::identity_store::credentials_codex_path_for(base_dir, u)
                    }
                    None => crate::credentials::file::canonical_path_for(
                        base_dir,
                        account,
                        Surface::Codex,
                    ),
                },
            ),
            _ => continue,
        };
        let creds = match crate::credentials::load(&canonical) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let expires_at_ms = match info.source {
            AccountSource::Anthropic => match creds.anthropic() {
                Some(a) => a.claude_ai_oauth.expires_at,
                None => continue,
            },
            AccountSource::Codex => match creds
                .codex()
                .and_then(|c| crate::http::codex::jwt_exp_secs(&c.tokens.access_token))
            {
                Some(exp_secs) => exp_secs.saturating_mul(1000),
                None => continue,
            },
            _ => continue,
        };
        if expires_at_ms != 0 && expires_at_ms < now_ms {
            out.push(ExpiredSlot {
                slot: info.id,
                surface,
                expired_for_secs: (now_ms - expires_at_ms) / 1000,
            });
        }
    }
    out.sort_by_key(|s| (s.slot, s.surface));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn absent_file_is_leader_by_default() {
        let tmp = TempDir::new().unwrap();
        let eff = load(tmp.path());
        assert_eq!(eff.posture, DaemonPosture::Leader);
        assert_eq!(eff.source, PostureSource::Default);
        assert!(!eff.is_follower());
    }

    #[test]
    fn saved_follower_round_trips() {
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), DaemonPosture::Follower).unwrap();
        let eff = load(tmp.path());
        assert_eq!(eff.posture, DaemonPosture::Follower);
        assert_eq!(eff.source, PostureSource::File);
    }

    #[test]
    fn saved_leader_round_trips() {
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), DaemonPosture::Follower).unwrap();
        save(tmp.path(), DaemonPosture::Leader).unwrap();
        let eff = load(tmp.path());
        assert_eq!(eff.posture, DaemonPosture::Leader);
        assert_eq!(eff.source, PostureSource::File);
    }

    #[test]
    fn unparseable_file_stands_down_to_follower_with_a_reason() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(posture_path(tmp.path()), "not json {").unwrap();
        let eff = load(tmp.path());
        assert_eq!(
            eff.posture,
            DaemonPosture::Follower,
            "a corrupt posture file must not silently revert to refreshing"
        );
        match eff.source {
            PostureSource::Unreadable(ref why) => {
                assert!(
                    why.contains(POSTURE_FILE_NAME),
                    "reason names the file: {why}"
                );
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn unknown_role_value_stands_down_to_follower() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(posture_path(tmp.path()), r#"{"role":"observer"}"#).unwrap();
        assert_eq!(load(tmp.path()).posture, DaemonPosture::Follower);
    }

    #[test]
    fn saved_file_is_owner_only() {
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), DaemonPosture::Follower).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(posture_path(tmp.path()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "posture file must be 0o600");
        }
    }

    #[test]
    fn expired_slots_is_empty_on_a_base_with_no_accounts() {
        let tmp = TempDir::new().unwrap();
        assert!(expired_slots(tmp.path(), 1_000_000_000_000).is_empty());
    }
}
