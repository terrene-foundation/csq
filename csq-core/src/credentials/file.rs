//! Credential file I/O — load, save, and canonical save with mirroring.

use super::mutex::AccountMutexTable;
use super::CredentialFile;
use crate::accounts::identity_store::{
    credentials_codex_path_for, credentials_path_for, is_identity_removed, settings_path_for,
    IdentityId,
};
use crate::accounts::profiles;
use crate::error::CredentialError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Loads a credential file from disk.
///
/// Returns `CredentialError::NotFound` if the file does not exist,
/// `CredentialError::Corrupt` if the JSON is invalid.
pub fn load(path: &Path) -> Result<CredentialFile, CredentialError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredentialError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            CredentialError::Io {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    if content.trim().is_empty() {
        return Err(CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "empty file".into(),
        });
    }

    serde_json::from_str(&content).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Saves a credential file to disk with atomic write + secure permissions.
pub fn save(path: &Path, creds: &CredentialFile) -> Result<(), CredentialError> {
    let json = serde_json::to_string_pretty(creds).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("serialization failed: {e}"),
    })?;

    // SEC-2.15 (unified, R2 M3): route the parent through the shared
    // fail-closed helper (0o700 at creation, symlink-refusing) instead of a
    // bare create_dir_all at the process umask.
    if let Some(parent) = path.parent() {
        crate::platform::fs::ensure_private_dir(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::other(format!("dir_secure_refused: {e}")),
        })?;
    }

    // Use a unique temp file name to prevent race conditions when
    // multiple callers save to the same path concurrently (per-PID
    // AND per-thread via atomic counter).
    let tmp = crate::platform::fs::unique_tmp_path(path);

    // Per security.md MUST Rule 5a: every failure branch after the tmp
    // write MUST best-effort `remove_file(&tmp)` before returning. Without
    // cleanup, an early `?` leaves an OAuth-token-bearing file at
    // umask-default (typically 0o644) until the next GC. Same B2 class
    // closed elsewhere in an internal journal entry
    //
    // `write_new_private` creates the tmp file at 0o600 AT CREATION
    // (`create_new` + `mode(0o600)`), so the separate `secure_file` step
    // this pipeline used to need is now redundant — there is no window
    // where the tmp file exists at umask-default mode.
    if let Err(e) = crate::platform::fs::write_new_private(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: std::io::Error::other(e.to_string()),
        });
    }

    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(e.to_string()),
        });
    }

    Ok(())
}

// ── M2-2: UUID-keyed credential write helpers ─────────────────────────────────

/// Resolves a slot number to its UUID identity using `profiles::resolve_slot_to_uuid`.
///
/// Returns `Some(uuid)` when the slot has a UUID mapping in `profiles.json`.
/// Returns `None` when the slot is unmapped (legacy layout, no `profiles.json`,
/// or daemon Pass 0 has not run yet). Absent UUID is a **graceful skip** — the
/// caller proceeds to legacy paths only; Pass 0 mints the UUID on next daemon start.
///
/// Never panics. Errors from I/O (e.g. missing `profiles.json`) are swallowed
/// and returned as `None`.
fn resolve_uuid_for_account(base_dir: &Path, account: AccountNum) -> Option<IdentityId> {
    profiles::resolve_slot_to_uuid(base_dir, account.get())
}

/// Preserves `subscription_type` and `rate_limit_tier` from an existing credential
/// file when the incoming credentials carry `None` for either field.
///
/// Anthropic's token endpoint does NOT return `subscription_type` or
/// `rate_limit_tier`; CC backfills them into the live credential file on its
/// first API call after a fresh login. Without this guard, a daemon refresh that
/// writes `subscription_type: None` silently destroys the user's Max tier, and CC
/// falls back to Sonnet with no error message (FM-1.1).
///
/// The UUID persistence helpers below call this guard for daemon refresh and
/// custodian adoption. Only the daemon custodian promotes CC-written live files
/// into canonical credentials (spec 02 INV-LIVE-CANON). Earlier live-file
/// promotion and fanout paths are retired.
///
/// Centralising the final write-side guard keeps UUID persistence consistent.
///
/// # Arguments
/// - `incoming`: the freshly-exchanged credential (may carry `None` for sub-fields)
/// - `existing_path`: path to an already-persisted credential from which to
///   backfill missing sub-fields. If the file is absent or unreadable, the
///   guard is a no-op (new account, nothing to preserve).
///
/// Returns the (possibly-augmented) credential to write.
fn preserve_subscription_metadata(
    incoming: &CredentialFile,
    existing_path: &Path,
) -> CredentialFile {
    let mut to_save = incoming.clone();

    // Only Anthropic-variant credentials carry subscription_type / rate_limit_tier.
    // Codex credentials do not have these fields; skip the guard silently.
    if to_save.anthropic().is_none() {
        return to_save;
    }

    let existing = match load(existing_path) {
        Ok(e) if e.anthropic().is_some() => e,
        Ok(_) => return to_save, // wrong variant (e.g. Codex file at path) — skip silently
        Err(CredentialError::NotFound { .. }) => return to_save, // new account, nothing to preserve
        Err(e) => {
            // Corrupt file at the UUID path — warn with fixed-vocabulary tag (security.md Rule 2)
            // and skip rather than clobbering subscription metadata with None.
            warn!(
                error_kind = "subscription_preserve_load_failed",
                path = %existing_path.display(),
                "preserve_subscription_metadata: existing UUID credential file unreadable; \
                 subscription metadata will not be backfilled"
            );
            let _ = e; // error already classified in the warn above
            return to_save;
        }
    };

    {
        let inner = to_save.expect_anthropic_mut();
        if inner.claude_ai_oauth.subscription_type.is_none() {
            inner.claude_ai_oauth.subscription_type = existing
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .clone();
        }
        if inner.claude_ai_oauth.rate_limit_tier.is_none() {
            inner.claude_ai_oauth.rate_limit_tier = existing
                .expect_anthropic()
                .claude_ai_oauth
                .rate_limit_tier
                .clone();
        }
    }

    to_save
}

/// Inner write function for UUID-keyed credentials — injectable for §5a testing.
///
/// **PRIMARY METHODOLOGICAL DIRECTIVE (from `redteam-discipline.md` Rule 5):**
/// Failure-branch tests MUST inject each of `write_fn`, `secure_fn`, `replace_fn`
/// independently. Do NOT use chmod tricks — they only cover the `write` branch.
/// Three distinct closure-injected tests, three distinct branches.
///
/// Per `rules/security.md` §5a: every failure branch after the tmp write MUST
/// `let _ = std::fs::remove_file(&tmp)` before returning. The tmp file carries
/// an OAuth-token-bearing payload; leaving it at umask-default (0o644) after
/// an early return is the §5a failure class.
///
/// All three closures use `std::io::Error` as the error type for uniformity:
/// - Production wraps `PlatformError` via `std::io::Error::other(e.to_string())`
/// - Tests inject `Err(std::io::Error::other("injected …"))` directly
fn write_uuid_credentials_inner<W, S, R>(
    tmp: &Path,
    final_path: &Path,
    bytes: &[u8],
    write_fn: W,
    secure_fn: S,
    replace_fn: R,
) -> Result<(), CredentialError>
where
    W: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&Path) -> std::io::Result<()>,
    R: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    if let Err(e) = write_fn(tmp, bytes) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: tmp.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = secure_fn(tmp) {
        let _ = std::fs::remove_file(tmp);
        // Report final_path (not tmp) — the caller cares which credential
        // file failed to secure, not the transient tmp name (LOW-3).
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = replace_fn(tmp, final_path) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    Ok(())
}

/// Writes credentials to the UUID-keyed path `identities/<UUID>/credentials.json`.
///
/// Called BEFORE the legacy `credentials/N.json` and `config-N/.credentials.json`
/// writes in [`save_canonical_for`], per SEC-2.7 write order: identity FIRST.
///
/// Applies [`preserve_subscription_metadata`] against the existing UUID-path file
/// before writing (closes FM-1.1 at the canonical site).
///
/// Returns `Ok(())` on success. On failure, the error is **propagated** — a UUID
/// write failure means we do NOT proceed to the legacy writes (fail-closed
/// per cross-phase constraint #4).
fn save_uuid_credentials(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let written = save_uuid_credentials_impl(base_dir, uuid, creds, false)?;
    // D237 ruling B: the token-history append happens AFTER the credential
    // write returns, so it is never inside a canonical critical section
    // this caller holds. The append has its own bounded lock; nesting it
    // inside the canonical lock was the same-budget-wait defect round 1
    // finding H1(a) named.
    super::token_history::record_write(base_dir, uuid, &written);
    Ok(())
}

/// Like [`save_uuid_credentials`] but REFUSES to create a missing
/// `identities/<UUID>/` (R2-M1): a writer that already proved the directory
/// exists must never resurrect one `csq logout` has since removed.
///
/// Test-only wrapper: production callers that hold the canonical lock use
/// [`save_uuid_credentials_prepared`] directly (they must append the token
/// history after releasing the lock — D237 ruling B).
#[cfg(test)]
fn save_uuid_credentials_existing_dir(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let written = save_uuid_credentials_impl(base_dir, uuid, creds, true)?;
    super::token_history::record_write(base_dir, uuid, &written);
    Ok(())
}

/// Writes `<base>/identities/<uuid>/credentials.json` and returns the EXACT
/// value written (after subscription-metadata preservation).
///
/// Returning the written value is what lets a caller that holds the
/// canonical lock append the token-history fingerprint after releasing it
/// (D237 ruling B) without re-reading the file.
fn save_uuid_credentials_impl(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
    require_existing_dir: bool,
) -> Result<CredentialFile, CredentialError> {
    let uuid_path = credentials_path_for(base_dir, uuid);
    // Subscription-metadata preservation guard (FM-1.1).
    let creds_to_write = preserve_subscription_metadata(creds, &uuid_path);
    save_uuid_credentials_prepared(base_dir, uuid, &creds_to_write, require_existing_dir)?;
    Ok(creds_to_write)
}

/// The write half of [`save_uuid_credentials_impl`], taking an ALREADY
/// preserved value.
///
/// The post-commit rescue protocol computes the value once and writes it
/// to BOTH the durable rescue record and (under the commit lock) this
/// canonical file, so the two can never diverge.
fn save_uuid_credentials_prepared(
    base_dir: &Path,
    uuid: IdentityId,
    creds_to_write: &CredentialFile,
    require_existing_dir: bool,
) -> Result<(), CredentialError> {
    let uuid_path = credentials_path_for(base_dir, uuid);

    // `keychain-fix-r11.md` D-5: refuse to write into an identity `csq
    // logout` has removed. The tombstone prevents a refresh, custodian adopt,
    // or login/store write from recreating a removed identity directory.
    // Check it BEFORE any I/O; live-file promotion belongs only to the
    // daemon custodian, not the retired backsync path.
    if is_identity_removed(base_dir, uuid) {
        return Err(CredentialError::IdentityRemoved {
            uuid: uuid.to_string(),
        });
    }

    let json =
        serde_json::to_string_pretty(creds_to_write).map_err(|e| CredentialError::Corrupt {
            path: uuid_path.clone(),
            reason: format!("serialization failed: {e}"),
        })?;

    // SEC-2.15 (unified, R1 M1) + R2 M2: under `require_existing_dir` the
    // precheck above refuses a logged-out identity, and the tighten below
    // NEVER creates — a directory removed between the precheck and this
    // call (orphan GC, logout) fails the write instead of being
    // resurrected around the credential. Fresh saves create via the shared
    // fail-closed helper (0o700 at creation, symlink-refusing).
    if let Some(parent) = uuid_path.parent() {
        if require_existing_dir {
            // Fail closed: a missing (logged-out) identity dir is never recreated.
            match std::fs::symlink_metadata(parent) {
                Ok(m) if m.is_dir() => {}
                _ => {
                    return Err(CredentialError::IdentityRemoved {
                        uuid: uuid.to_string(),
                    })
                }
            }
            pre_tighten_hook::run();
            match crate::accounts::identity_store::tighten_existing_identity_dir(base_dir, uuid) {
                Ok(()) => {}
                // R3 LOW 6: a directory removed between the precheck ABOVE
                // and this tighten surfaces as `NotFound` (the fs helper's
                // `missing_dir_refusal` carries that kind) — that is the same
                // logged-out state the precheck names, so report
                // `IdentityRemoved`, not corruption. Any other refusal is a
                // real secure failure.
                Err(crate::error::PlatformError::Io(e))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Err(CredentialError::IdentityRemoved {
                        uuid: uuid.to_string(),
                    })
                }
                Err(e) => {
                    return Err(CredentialError::Corrupt {
                        path: parent.to_path_buf(),
                        reason: format!("identity_dir_secure_refused: {e}"),
                    })
                }
            }
        } else {
            crate::accounts::identity_store::ensure_private_identity_dir(base_dir, uuid).map_err(
                |e| CredentialError::Corrupt {
                    path: parent.to_path_buf(),
                    reason: format!("identity_dir_secure_refused: {e}"),
                },
            )?;
        }
    }

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    // §5a: `write_new_private` creates the tmp file at 0o600 at creation,
    // so the paired `secure_file` closure below is now a redundant (but
    // harmless) re-chmod — kept as-is so the three-closure injectable
    // failure-branch test structure (`redteam-discipline.md` Rule 5) stays
    // unchanged for the `secure` and `replace` branches.
    write_uuid_credentials_inner(
        &tmp,
        &uuid_path,
        json.as_bytes(),
        |p, b| {
            crate::platform::fs::write_new_private(p, b)
                .map_err(|e| std::io::Error::other(e.to_string()))
        },
        |p| secure_file(p).map_err(|e| std::io::Error::other(e.to_string())),
        |t, f| atomic_replace(t, f).map_err(|e| std::io::Error::other(e.to_string())),
    )?;

    // `keychain-fix-r8.md` C-F1 (PRIMARY DIRECTIVE): every canonical-store
    // writer records the token it just wrote into this identity's bounded
    // history. The PUBLIC wrappers above (`save_uuid_credentials`,
    // `save_uuid_credentials_existing_dir`) do that append after this
    // function returns; callers that hold the canonical lock call THIS
    // function and append after dropping the guard (D237 ruling B), so no
    // credential critical section ever contains the history lock's own
    // bounded wait.
    Ok(())
}

// ── Post-commit rescue protocol (D237 C1) ────────────────────────────────────

/// Diagnostic reason stamped into a rescue record when the canonical lock
/// budget is the anticipated outcome.
const RESCUE_REASON_LOCK_TIMEOUT: &str = "post_commit_lock_timeout";

/// Diagnostic reason rewritten into a rescue record when the lock
/// acquisition ERRORED rather than expiring.
const RESCUE_REASON_LOCK_ERROR: &str = "post_commit_lock_error";

/// Writes the durable rescue record for a post-commit pair BEFORE the
/// canonical lock wait begins (ROOT ruling A).
///
/// Returns the record's own path, or `None` when the record could not be
/// written. A `None` return is LOGGED and does NOT abort the canonical
/// write: the record is the safety net for a delayed or killed writer, and
/// the in-place write is still the fast path.
///
/// `witness` carries the SOURCE/RESULT inputs adoption re-gates against
/// (D237 round-2 H-c); the record is written BEFORE any lock is taken.
fn write_post_commit_rescue(
    identity_dir: &Path,
    provider: &str,
    uuid: IdentityId,
    payload: &CredentialFile,
    witness: &crate::credentials::rescue::RescueWitness,
) -> Option<PathBuf> {
    let value = match serde_json::to_value(payload) {
        Ok(value) => value,
        Err(_) => {
            warn!(
                error_kind = "rescue_record_serialize_failed",
                provider,
                "post-commit pair could not be serialized for rescue; writing in place only"
            );
            return None;
        }
    };
    let written = crate::credentials::rescue::write_rescue_record(
        identity_dir,
        provider,
        &uuid.to_string(),
        RESCUE_REASON_LOCK_TIMEOUT,
        &value,
        witness,
    );
    match written {
        Ok(path) => Some(path),
        Err(error) => {
            warn!(
                error_kind = "rescue_record_write_failed",
                provider,
                reason = error.error_kind_tag(),
                "post-commit pair could not be rescued to disk; writing in place only"
            );
            None
        }
    }
}

/// Removes the CALLER'S OWN rescue record, never another writer's.
fn remove_own_rescue_record(record: Option<&Path>) {
    if let Some(path) = record {
        crate::credentials::rescue::remove_rescue_record(path);
    }
}

/// Acquires the canonical lock for a POST-COMMIT write under
/// [`crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET`].
///
/// On expiry or error the rescue record stays in place and the loud
/// fixed-vocabulary tag says the pair is deferred to adoption; the
/// returned refusal is the caller's signal that the canonical file was not
/// written. A post-commit caller MUST NOT treat that refusal as "the pair
/// was discarded" — check [`crate::credentials::rescue::rescue_record_pending`].
///
/// `rescue_record` is THIS writer's own record path: only it is
/// re-reasoned (never another writer's record).
fn acquire_post_commit_lock(
    provider: &str,
    canonical_lock: PathBuf,
    rescue_record: Option<&Path>,
) -> Result<crate::platform::lock::FileLockGuard, CredentialError> {
    use crate::credentials::rescue;
    match rescue::lock_credential_file_commit(&canonical_lock) {
        Ok(Some(guard)) => Ok(guard),
        Ok(None) => {
            warn!(
                error_kind = "credential_commit_lock_deferred",
                provider,
                budget_ms = rescue::CREDENTIAL_COMMIT_LOCK_BUDGET_MS,
                "post-commit pair is durably rescued; the canonical write is deferred to adoption"
            );
            Err(CredentialError::CanonicalLockRefused {
                path: canonical_lock,
                io_kind: std::io::ErrorKind::TimedOut,
            })
        }
        Err(error) => {
            if let Some(record) = rescue_record {
                let _ = rescue::mark_rescue_reason(record, RESCUE_REASON_LOCK_ERROR);
            }
            warn!(
                error_kind = "credential_commit_lock_error",
                provider,
                "post-commit canonical lock failed; the rescued pair is deferred to adoption"
            );
            Err(CredentialError::CanonicalLockRefused {
                path: canonical_lock,
                io_kind: rescue::platform_error_kind(&error),
            })
        }
    }
}

// ── End M2-2 helpers ──────────────────────────────────────────────────────────

// ── M4-1: Codex UUID-keyed credentials write (parity with M2-2) ───────────────

/// Inner write function for Codex UUID-keyed credentials — injectable for §5a testing.
///
/// **PRIMARY METHODOLOGICAL DIRECTIVE (from `redteam-discipline.md` Rule 5):**
/// Failure-branch tests MUST inject each of `write_fn`, `secure_fn`, `replace_fn`
/// independently. Do NOT use chmod tricks — they only cover the `write` branch.
/// Three distinct closure-injected tests, three distinct branches.
///
/// Per `rules/security.md` §5a: every failure branch after the tmp write MUST
/// `let _ = std::fs::remove_file(&tmp)` before returning. The tmp file carries
/// the Codex tokens payload (`access_token`, `refresh_token`, `id_token` — all
/// JWT-bearing secrets); leaving it at umask-default (0o644) after an early
/// return is the §5a failure class.
///
/// All three closures use `std::io::Error` as the error type for uniformity:
/// - Production wraps `PlatformError` via `std::io::Error::other(e.to_string())`
/// - Tests inject `Err(std::io::Error::other("injected …"))` directly
fn save_codex_canonical_for_uuid_inner<W, S, R>(
    tmp: &Path,
    final_path: &Path,
    bytes: &[u8],
    write_fn: W,
    secure_fn: S,
    replace_fn: R,
) -> Result<(), CredentialError>
where
    W: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&Path) -> std::io::Result<()>,
    R: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    if let Err(e) = write_fn(tmp, bytes) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: tmp.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = secure_fn(tmp) {
        let _ = std::fs::remove_file(tmp);
        // Report final_path (not tmp) — the caller cares which credential
        // file failed to secure, not the transient tmp name (LOW-3 parity
        // with `write_uuid_credentials_inner`).
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = replace_fn(tmp, final_path) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    Ok(())
}

/// Writes Codex credentials to the UUID-keyed path
/// `identities/<UUID>/credentials-codex.json` (parallel to
/// `save_uuid_credentials` for the Anthropic surface).
///
/// Called BEFORE the legacy `credentials/codex-<N>.json` write in
/// [`save_canonical_for`], per SEC-2.7 write order: identity FIRST.
///
/// Applies `preserve_subscription_metadata` against the existing UUID-path
/// file before writing — a no-op on Codex variants (Codex has no
/// `subscription_type` / `rate_limit_tier`), but the call site retains
/// structural parity with the Anthropic chokepoint and tolerates any future
/// preservation logic added to the helper for Codex.
///
/// Returns `Ok(())` on success. On failure, the error is **propagated** — a
/// UUID write failure means the caller does NOT proceed to the legacy write
/// (fail-closed per SEC-2.7).
///
/// # Security
///
/// §5a: the tmp file carries the Codex tokens payload (`access_token`,
/// `refresh_token`, `id_token` — JWT-bearing). Every failure branch in
/// `save_codex_canonical_for_uuid_inner` calls `remove_file(&tmp)` before
/// propagating.
pub fn save_codex_canonical_for_uuid(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    save_codex_canonical_for_uuid_checked(
        base_dir,
        uuid,
        creds,
        None,
        CanonicalWriteDurability::RefuseOnLockTimeout,
    )
    .map(|_| ())
}

/// Persist a refresh only if this original UUID still holds its captured source.
/// JSON value equality includes tokens, account fields and unknown extras; it
/// ignores serialization formatting, not credential or metadata changes.
/// `false` means a newer canonical won and remains untouched.
///
/// This is a POST-COMMIT write: Codex's refresh token is single-use, so the
/// pair handed in has already consumed the provider's grant. It therefore
/// runs the rescue protocol (D237 C1) — durable rescue record first, then
/// the canonical lock under
/// [`crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET`] — and a
/// lock that stays busy past that budget DEFERS the write instead of
/// discarding the pair.
pub fn save_codex_refresh_for_uuid(
    base_dir: &Path,
    uuid: IdentityId,
    expected_source: &CredentialFile,
    refreshed: &CredentialFile,
) -> Result<bool, CredentialError> {
    if expected_source.codex().is_none() || refreshed.codex().is_none() {
        return Err(CredentialError::Corrupt {
            path: credentials_codex_path_for(base_dir, uuid),
            reason: "codex_refresh_shape_refused".into(),
        });
    }
    save_codex_canonical_for_uuid_checked(
        base_dir,
        uuid,
        refreshed,
        Some(expected_source),
        CanonicalWriteDurability::RescueOnLockTimeout,
    )
}

/// Equality of the complete decoded Codex JSON, without cloning secret values.
/// Exhaustive destructuring forces a future persisted field to join this check.
pub(crate) fn codex_credentials_match(left: &CredentialFile, right: &CredentialFile) -> bool {
    let (Some(left), Some(right)) = (left.codex(), right.codex()) else {
        return false;
    };
    let super::CodexCredentialFile {
        auth_mode,
        openai_api_key,
        tokens,
        last_refresh,
        extra,
    } = left;
    let super::CodexTokensFile {
        account_id,
        access_token,
        refresh_token,
        id_token,
        extra: token_extra,
    } = tokens;
    auth_mode == &right.auth_mode
        && openai_api_key == &right.openai_api_key
        && last_refresh == &right.last_refresh
        && extra == &right.extra
        && account_id == &right.tokens.account_id
        && access_token == &right.tokens.access_token
        && refresh_token == &right.tokens.refresh_token
        && id_token == &right.tokens.id_token
        && token_extra == &right.tokens.extra
}

/// Which lock discipline a canonical credential write uses.
///
/// The split is the D237 round-1 ruling: a write that has consumed nothing
/// (`save_codex_canonical_for_uuid`'s mint / custodian path) keeps the
/// bounded 500 ms fail-closed refusal; a write that persists a consumed,
/// rotated grant must never discard it and therefore rescues first and
/// waits out the long post-commit budget.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CanonicalWriteDurability {
    /// PRE-COMMIT: bounded [`crate::platform::lock::lock_credential_file`].
    RefuseOnLockTimeout,
    /// POST-COMMIT: rescue record first, then the commit budget.
    RescueOnLockTimeout,
}

/// Serializes the expected Codex source for a rescue record.
///
/// A post-commit Codex write always has `expected_source`; a serialization
/// failure is reported and the record is skipped (the in-place write still
/// runs), never written with a witness adoption cannot evaluate.
fn codex_rescue_witness(
    expected_source: Option<&CredentialFile>,
) -> Option<crate::credentials::rescue::RescueWitness> {
    let expected = expected_source?;
    serde_json::to_value(expected)
        .ok()
        .map(|expected_source| crate::credentials::rescue::RescueWitness::Codex { expected_source })
}

fn save_codex_canonical_for_uuid_checked(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
    expected_source: Option<&CredentialFile>,
    durability: CanonicalWriteDurability,
) -> Result<bool, CredentialError> {
    let uuid_path = credentials_codex_path_for(base_dir, uuid);
    let parent = uuid_path
        .parent()
        .ok_or_else(|| CredentialError::IdentityDirectoryMissing {
            uuid: uuid.to_string(),
        })?;
    let require_existing_dir = || match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(CredentialError::IdentityDirectoryMissing {
                uuid: uuid.to_string(),
            })
        }
        _ => Err(CredentialError::Corrupt {
            path: parent.to_path_buf(),
            reason: "codex_identity_directory_refused".into(),
        }),
    };
    if is_identity_removed(base_dir, uuid) {
        return Err(CredentialError::IdentityRemoved {
            uuid: uuid.to_string(),
        });
    }
    // Mint owns directory creation. Share logout's Anthropic-named lock even
    // for Codex so a refresh cannot publish after the UUID has been removed.
    require_existing_dir()?;

    // Subscription-metadata preservation guard.
    //
    // For Codex variants this returns `creds` unchanged (the guard short-circuits
    // on `to_save.anthropic().is_none()`), but we invoke it for structural
    // parity with `save_uuid_credentials` so that any future preservation logic
    // added to the helper (e.g. preserving `last_refresh` for Codex) is
    // automatically picked up here without re-plumbing the call site.
    //
    // Computed BEFORE the lock: a post-commit write carries this exact value
    // in its rescue record, and the record is written before the lock wait
    // (ROOT ruling A), so both destinations must use one value.
    let creds_to_write = preserve_subscription_metadata(creds, &uuid_path);

    // D237 C1: a rotated Codex pair is POST-COMMIT — its single-use refresh
    // token is already consumed provider-side. Write the durable rescue
    // record FIRST, then wait on the canonical lock under the long commit
    // budget; on expiry the record stays for the next tick to adopt.
    //
    // D237 round-2 H-c: the record carries the EXACT expected source the
    // writer captured, so adoption can re-run
    // `codex_credentials_match(current, expected_source)` and discard a
    // record whose source no longer holds (a newer re-login).
    let rescue_record = if durability == CanonicalWriteDurability::RescueOnLockTimeout {
        match codex_rescue_witness(expected_source) {
            Some(witness) => {
                write_post_commit_rescue(parent, "codex", uuid, &creds_to_write, &witness)
            }
            None => {
                warn!(
                    error_kind = "rescue_record_witness_missing",
                    provider = "codex",
                    "codex post-commit pair has no serializable source witness; \
                     writing in place only"
                );
                None
            }
        }
    } else {
        None
    };

    let canonical_lock = credentials_path_for(base_dir, uuid).with_extension("lock");
    let _canonical = match durability {
        CanonicalWriteDurability::RescueOnLockTimeout => {
            acquire_post_commit_lock("codex", canonical_lock, rescue_record.as_deref())?
        }
        CanonicalWriteDurability::RefuseOnLockTimeout => {
            match crate::platform::lock::lock_credential_file(&canonical_lock) {
                Ok(Some(guard)) => guard,
                // Bounded acquisition expired: fail closed rather than write
                // without the lock. The caller surfaces
                // `credentials_canonical_lock_refused`.
                Ok(None) => {
                    return Err(CredentialError::CanonicalLockRefused {
                        path: canonical_lock,
                        io_kind: std::io::ErrorKind::TimedOut,
                    })
                }
                Err(error) => {
                    return Err(CredentialError::CanonicalLockRefused {
                        path: canonical_lock,
                        io_kind: match error {
                            crate::error::PlatformError::Io(source) => source.kind(),
                            crate::error::PlatformError::Win32 { code, .. } => {
                                std::io::Error::from_raw_os_error(code as i32).kind()
                            }
                            crate::error::PlatformError::LockContention { .. } => {
                                std::io::ErrorKind::WouldBlock
                            }
                            crate::error::PlatformError::LockTimeout { .. } => {
                                std::io::ErrorKind::TimedOut
                            }
                            _ => std::io::ErrorKind::Other,
                        },
                    })
                }
            }
        }
    };
    if is_identity_removed(base_dir, uuid) {
        // A deliberate logout outranks the rescue: discard it here rather
        // than leave a record that would keep readers from reporting
        // LOGIN-NEEDED for the removed identity. Only the post-commit
        // caller owns a record.
        remove_own_rescue_record(rescue_record.as_deref());
        return Err(CredentialError::IdentityRemoved {
            uuid: uuid.to_string(),
        });
    }
    if let Err(error) = require_existing_dir() {
        // The directory is gone or is not a directory. Adoption requires it
        // to exist, so a record left here would stay PENDING forever.
        remove_own_rescue_record(rescue_record.as_deref());
        return Err(error);
    }

    // R3 sec L-1 (codex arm): same in-lock re-read re-check as the Anthropic
    // arm. Only a POST-COMMIT refresh write defers here — a login/mint write
    // (no record of its own) supersedes pending records by design.
    // Defer only when this pair is durable in its own record; with no record,
    // skipping the write would discard the pair outright.
    if durability == CanonicalWriteDurability::RescueOnLockTimeout {
        if let Some(own) = rescue_record.as_deref() {
            if crate::credentials::rescue::has_other_rescue_record(parent, Some(own)) {
                warn!(
                    provider = "codex",
                    error_kind = "refresh_lineage_save_blocked_by_concurrent_rescue",
                    "rotated codex pair saved; a concurrent rescue record appeared before \
                     the in-lock re-read, so adoption decides which pair is provable"
                );
                return Ok(false);
            }
        }
    }
    if let Some(expected) = expected_source {
        let current = load(&uuid_path)?;
        if !codex_credentials_match(&current, expected) {
            // A newer canonical won this rotation. The pair stays rescued
            // until adoption proves it is superseded (freshness guard), so
            // remove the record here: it would only re-install a pair the
            // captured source no longer reflects.
            remove_own_rescue_record(rescue_record.as_deref());
            return Ok(false);
        }
    }

    let json =
        zeroize::Zeroizing::new(serde_json::to_string_pretty(&creds_to_write).map_err(|e| {
            CredentialError::Corrupt {
                path: uuid_path.clone(),
                reason: format!("serialization failed: {e}"),
            }
        })?);

    // SEC-2.15 (unified, R1 M1) + R2 M2: TIGHTEN-ONLY — the directory
    // already exists (`require_existing_dir` above), and a directory
    // removed between that precheck and this call must not be resurrected.
    // R3-fix-check LOW 5: a directory removed between the second
    // `require_existing_dir` and this tighten is the identity being GONE
    // (logout/orphan GC) — the same logged-out state the precheck maps to
    // `IdentityDirectoryMissing`, never the corruption shape.
    pre_tighten_hook::run();
    crate::accounts::identity_store::tighten_existing_identity_dir(base_dir, uuid).map_err(
        |e| {
            if let crate::error::PlatformError::Io(io) = &e {
                if io.kind() == std::io::ErrorKind::NotFound {
                    return CredentialError::IdentityDirectoryMissing {
                        uuid: uuid.to_string(),
                    };
                }
            }
            CredentialError::Corrupt {
                path: parent.to_path_buf(),
                reason: format!("identity_dir_secure_refused: {e}"),
            }
        },
    )?;

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    // §5a: `write_new_private` creates the tmp file at 0o600 at creation;
    // `secure_file` below is now a redundant (but harmless) re-chmod, kept
    // so the three-closure injectable failure-branch test structure stays
    // unchanged for the `secure` and `replace` branches.
    save_codex_canonical_for_uuid_inner(
        &tmp,
        &uuid_path,
        json.as_bytes(),
        |p, b| {
            crate::platform::fs::write_new_private(p, b)
                .map_err(|e| std::io::Error::other(e.to_string()))
        },
        |p| secure_file(p).map_err(|e| std::io::Error::other(e.to_string())),
        |t, f| atomic_replace(t, f).map_err(|e| std::io::Error::other(e.to_string())),
    )?;
    remove_own_rescue_record(rescue_record.as_deref());
    Ok(true)
}

// ── End M4-1 helpers ──────────────────────────────────────────────────────────

// ── M2-3 / M4-2: UUID-keyed settings.json write helpers ───────────────────────

/// Inner write function for UUID-keyed settings.json — injectable for §5a testing.
///
/// **PRIMARY METHODOLOGICAL DIRECTIVE (from `redteam-discipline.md` Rule 5):**
/// Failure-branch tests MUST inject each of `write_fn`, `secure_fn`, `replace_fn`
/// independently. Do NOT use chmod tricks — they only cover the `write` branch.
/// Three distinct closure-injected tests, three distinct branches.
///
/// Per `rules/security.md` §5a: every failure branch after the tmp write MUST
/// `let _ = std::fs::remove_file(&tmp)` before returning. The tmp file carries
/// a settings payload that may include `ANTHROPIC_AUTH_TOKEN` (3P key in env
/// block); leaving it at umask-default (0o644) after an early return is the
/// §5a failure class.
///
/// M4-2: renamed from `write_uuid_settings_inner` to `save_uuid_settings_inner`
/// for naming parity with the M4-1 / M2-2 chokepoints (`save_uuid_credentials`,
/// `save_codex_canonical_for_uuid`). Same shape — three injectable Fn closures.
pub(crate) fn save_uuid_settings_inner<W, S, R>(
    tmp: &Path,
    final_path: &Path,
    bytes: &[u8],
    write_fn: W,
    secure_fn: S,
    replace_fn: R,
) -> Result<(), CredentialError>
where
    W: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&Path) -> std::io::Result<()>,
    R: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    if let Err(e) = write_fn(tmp, bytes) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: tmp.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = secure_fn(tmp) {
        let _ = std::fs::remove_file(tmp);
        // Report final_path so the caller knows which settings file failed.
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    if let Err(e) = replace_fn(tmp, final_path) {
        let _ = std::fs::remove_file(tmp);
        return Err(CredentialError::Io {
            path: final_path.to_path_buf(),
            source: e,
        });
    }

    Ok(())
}

/// Writes raw settings bytes to the UUID-keyed path
/// `identities/<UUID>/settings.json`.
///
/// Called from:
/// 1. `commit_anthropic_login` / `finalize_verified_login` — seeds UUID settings from `config-<N>/settings.json` at
///    login time (same `ProfilesFileLock` window as identity.json write). Idempotent:
///    only writes when the UUID settings file is absent.
/// 2. Pass 0 catch-up in `startup_reconciler` — first-start back-fill of all
///    existing slots.
/// 3. `finalize_verified_login` (M4-2) — explicit pair after the login commit returns so
///    a freshly-bound 3P provider's settings overlay is mirrored into the UUID
///    path even when mint's idempotent seed skipped (UUID dir pre-existed).
/// 4. Codex `perform_with` (M4-2) — Codex slots that have a UUID mapping
///    (typically minted by daemon Pass 0 or prior Anthropic login on the same
///    slot) get a paired `{}` settings.json so handle-dir materialization sees
///    a consistent UUID-first layout.
///
/// `bytes` MUST be valid JSON (the caller serialises the settings object before
/// calling this). The raw bytes are written verbatim so byte-identity with the
/// source `config-<N>/settings.json` is guaranteed (needed by
/// `test_pass0_seeds_identities_settings_from_existing_config_n`).
///
/// Returns `Ok(())` on success or `Err(CredentialError)` on failure.
///
/// M4-2: renamed from `write_uuid_settings` to `save_uuid_settings` for naming
/// parity with the M4-1 / M2-2 chokepoints. The legacy alias `write_uuid_settings`
/// is preserved as a thin wrapper for backward compatibility with pre-M4-2
/// callsites in `daemon::identity_mint`, `daemon::startup_reconciler`, and
/// `cli::commands::models`.
///
/// # Security
///
/// §5a: the tmp file may carry `ANTHROPIC_AUTH_TOKEN` from the slot's 3P env
/// block. Every failure branch in `save_uuid_settings_inner` calls
/// `remove_file(&tmp)` before propagating.
pub fn save_uuid_settings(
    base_dir: &Path,
    uuid: IdentityId,
    bytes: &[u8],
) -> Result<(), CredentialError> {
    let uuid_path = settings_path_for(base_dir, uuid);

    // SEC-2.15 (unified, R1 M1): the shared fail-closed helper creates AND
    // secures `identities/` and `identities/<UUID>/` (0o700 at creation,
    // symlink-refusing); a no-op tighten when the dirs already exist.
    crate::accounts::identity_store::ensure_private_identity_dir(base_dir, uuid).map_err(|e| {
        CredentialError::Corrupt {
            path: uuid_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| uuid_path.clone()),
            reason: format!("identity_dir_secure_refused: {e}"),
        }
    })?;

    // H1 sibling: every writer of a slot settings file takes `<file>.lock`
    // (setkey/bind/unbind, the model switch, the Kimi migration), so a
    // read-modify-write elsewhere can never land a stale copy over this
    // write. Expiry refuses (fail closed). No caller holds this lock.
    let lock_path = uuid_path.with_extension("lock");
    let _lock = match crate::platform::lock::lock_credential_file(&lock_path) {
        Ok(Some(guard)) => guard,
        Ok(None) | Err(_) => {
            return Err(CredentialError::Corrupt {
                path: lock_path,
                reason: "settings_lock_unavailable".into(),
            })
        }
    };

    save_uuid_settings_lock_held(base_dir, uuid, bytes)
}

/// [`save_uuid_settings`] for a caller that ALREADY holds the destination's
/// `<file>.lock` (and created the identity dir via
/// `ensure_private_identity_dir`) — the startup catch-up, which must check
/// "absent" and write under one lock. Taking the lock again here would
/// self-deadlock (separate flock descriptors conflict). Same §5a contract.
pub(crate) fn save_uuid_settings_lock_held(
    base_dir: &Path,
    uuid: IdentityId,
    bytes: &[u8],
) -> Result<(), CredentialError> {
    let uuid_path = settings_path_for(base_dir, uuid);

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    // §5a: `write_new_private` creates the tmp file at 0o600 at creation;
    // `secure_file` below is now a redundant (but harmless) re-chmod, kept
    // so the three-closure injectable failure-branch test structure stays
    // unchanged for the `secure` and `replace` branches.
    save_uuid_settings_inner(
        &tmp,
        &uuid_path,
        bytes,
        |p, b| {
            crate::platform::fs::write_new_private(p, b)
                .map_err(|e| std::io::Error::other(e.to_string()))
        },
        |p| secure_file(p).map_err(|e| std::io::Error::other(e.to_string())),
        |t, f| atomic_replace(t, f).map_err(|e| std::io::Error::other(e.to_string())),
    )
}

/// Legacy alias for [`save_uuid_settings`] (M2-3 era name). Preserved as a
/// thin wrapper so pre-M4-2 callsites (daemon Pass 0, identity_mint hook,
/// models CLI) compile unchanged. New callsites SHOULD use
/// [`save_uuid_settings`] directly.
pub fn write_uuid_settings(
    base_dir: &Path,
    uuid: IdentityId,
    bytes: &[u8],
) -> Result<(), CredentialError> {
    save_uuid_settings(base_dir, uuid, bytes)
}

// ── End M2-3 / M4-2 helpers ───────────────────────────────────────────────────

/// Surface-dispatched canonical write.
///
/// Per spec 07 INV-P08 / INV-P09:
///
/// 1. Surface is derived from `creds.surface()` (PR-C2b) — no caller
///    surface parameter, so data shape and path shape cannot drift.
/// 2. Acquires the per-`(Surface, AccountNum)` write mutex from the
///    process-global [`AccountMutexTable`]. Serialises concurrent
///    writers within one process; cross-process serialisation is the
///    flock'd `refresh-lock` path in [`crate::refresh::check`].
/// 3. Delegates to the UUID-keyed writer for the resolved surface
///    (`save_uuid_credentials` / [`save_codex_canonical_for_uuid`]).
///    Each secures its tmp file to 0o600 via [`secure_file`] BEFORE
///    `atomic_replace` renames it over the target, so 0o600 is the mode
///    that lands on disk — `atomic_replace` overwrites the target's
///    inode, so a prior file's mode is neither inherited nor an
///    obstacle. The identity dir itself is restricted to 0o700
///    (`secure_dir`).
///
/// **M4-12: there is NO post-write 0o400 flip on this path.** The prior
/// step 4 (flip the Codex canonical to 0o400 after the write, cited as
/// the active INV-P08 guarantee) described the RETIRED numeric writer
/// and is no longer performed here for ANY surface — the inline
/// `M4-12` note in the body below records its removal, and two tests
/// pin the current behaviour:
/// `save_canonical_for_codex_uuid_path_at_0o600_with_uuid` and
/// `save_canonical_for_claude_code_leaves_uuid_path_at_0o600`. Codex
/// and Anthropic canonicals both land at 0o600.
///
/// This writer does not promote Claude Code live credentials. The daemon
/// custodian owns live-to-canonical promotion under spec 02 INV-LIVE-CANON;
/// explicit Anthropic login instead captures freshly authorized credentials and
/// publishes them through `accounts::anthropic_identity`. Numeric canonical
/// files remain read fallbacks only for pre-mapping installs. Logout uses
/// `live_path` to locate the permanent config directory for removal.
pub fn save_canonical_for(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let surface = creds.surface();
    if surface == Surface::ClaudeCode {
        return Err(crate::accounts::anthropic_identity::credential_refusal());
    }
    let slot_mutex = AccountMutexTable::global().get_or_insert(surface, account);
    let _guard = slot_mutex.lock().expect("per-account write mutex poisoned");

    // ── M2-2 / M4-1 / M4-12: UUID-keyed write (SEC-2.7 write order: identity FIRST) ──
    //
    // Resolve UUID once at section entry (cross-phase constraint #7: resolve-once).
    // M4-12: absent UUID is now a hard error — fail-closed (Finding 1.1 fix).
    // The daemon Pass 0 identity mint (M1-4) guarantees UUIDs exist for every
    // authenticated account before any credential write reaches this function.
    // If UUID is absent, something is structurally wrong; returning
    // CredentialError::NoCredentials forces visible failure instead of silently
    // writing nothing.
    //
    // - `Surface::ClaudeCode` writes `identities/<UUID>/credentials.json`
    //   (M2-2 chokepoint: `save_uuid_credentials`).
    // - `Surface::Codex` writes `identities/<UUID>/credentials-codex.json`
    //   (M4-1 chokepoint: `save_codex_canonical_for_uuid`; parity with M2-2).
    // - `Surface::Gemini` has no canonical credential file (key flows via
    //   `platform::secret::Vault`); explicitly skipped — no UUID check required.
    //
    // M4-12: numeric write path (`credentials/<N>.json`, `credentials/codex-<N>.json`,
    // `credentials/gemini-<N>.json`) fully retired. The `canonical_path_for` call
    // and the INV-P08 Codex 0o400 flip block have been removed. UUID-keyed
    // identity write is the ONLY write path.
    match surface {
        Surface::ClaudeCode => match resolve_uuid_for_account(base_dir, account) {
            Some(uuid) => save_uuid_credentials(base_dir, uuid, creds)?,
            None => return Err(CredentialError::NoCredentials(account.get())),
        },
        Surface::Codex => match resolve_uuid_for_account(base_dir, account) {
            Some(uuid) => save_codex_canonical_for_uuid(base_dir, uuid, creds)?,
            None => return Err(CredentialError::NoCredentials(account.get())),
        },
        Surface::Gemini | Surface::Kimi | Surface::Grok => {
            // Gemini + native-CLI surfaces (Kimi/Grok) store NO csq credential
            // file — Gemini keys flow via `platform::secret::Vault`; native
            // CLIs self-authenticate (creds under `~/.kimi-code/`,
            // `~/.grok/auth.json`). No UUID write path.
        }
    }
    // ── End UUID write (M4-12: numeric write fully retired) ───────────────────

    Ok(())
}

/// Only a proof for the exact candidate or a refresh of the captured pair can write.
#[derive(Clone, Copy)]
pub enum AnthropicWriteWitness<'a> {
    Profile(&'a crate::accounts::anthropic_identity::VerifiedAnthropicContext),
    /// Interim legacy authority is confined to this captured UUID, never an org index.
    LegacyOwnUuid(&'a crate::accounts::anthropic_identity::LegacyOwnUuidProof),
    RefreshLineage(&'a crate::accounts::anthropic_identity::RefreshLineageWitness),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedWriteOutcome {
    Written,
    NotFresher,
    BindingChanged,
}

pub fn save_anthropic_canonical_guarded(
    base: &Path,
    captured: &crate::accounts::anthropic_identity::CapturedBinding,
    candidate: &super::AnthropicCredentialFile,
    witness: AnthropicWriteWitness<'_>,
    min_expiry_exclusive: Option<u64>,
) -> Result<GuardedWriteOutcome, CredentialError> {
    if let AnthropicWriteWitness::RefreshLineage(proof) = witness {
        return save_anthropic_lineage_canonical(base, captured, candidate, proof);
    }
    let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base)
        .map_err(|_| crate::accounts::anthropic_identity::credential_refusal())?;
    save_anthropic_canonical_guarded_locked(
        &lock,
        base,
        captured,
        candidate,
        witness,
        min_expiry_exclusive,
    )
}

/// Caller holds profiles; this function acquires slot, canonical, then history locks.
pub fn save_anthropic_canonical_guarded_locked(
    lock: &crate::accounts::profiles_lock::ProfilesFileLock,
    base: &Path,
    captured: &crate::accounts::anthropic_identity::CapturedBinding,
    candidate: &super::AnthropicCredentialFile,
    witness: AnthropicWriteWitness<'_>,
    min_expiry_exclusive: Option<u64>,
) -> Result<GuardedWriteOutcome, CredentialError> {
    if let AnthropicWriteWitness::RefreshLineage(proof) = witness {
        return save_anthropic_lineage_canonical(base, captured, candidate, proof);
    }
    use crate::accounts::anthropic_identity::{
        self as ai, CredentialVersion, StoredAnthropicContext,
    };
    if !lock.protects(base) || !captured.belongs_to(base) {
        return Err(ai::credential_refusal());
    }
    let slot_mutex =
        AccountMutexTable::global().get_or_insert(Surface::ClaudeCode, captured.slot());
    let _slot_guard = slot_mutex.lock().map_err(|_| ai::credential_refusal())?;
    let path = credentials_path_for(base, captured.identity());
    if let AnthropicWriteWitness::LegacyOwnUuid(proof) = witness {
        if !matches!(captured.context(), StoredAnthropicContext::LegacyUnknown)
            || !proof.permits(base, captured, candidate)
        {
            return Err(ai::credential_refusal());
        }
        if !ai::binding_matches_locked(lock, base, captured)
            .map_err(|_| ai::credential_refusal())?
        {
            return Ok(GuardedWriteOutcome::BindingChanged);
        }
        // Existing migration directories can be 0755. Repair only the owner-
        // controlled original UUID after its interim authority is established.
        prepare_anthropic_refresh_directory(base, captured.identity())?;
    }
    require_identity_directory(&path, captured.identity())?;
    // Bounded acquisition; expiry refuses the write (fixed vocabulary).
    let _canonical = crate::platform::lock::lock_credential_file(&path.with_extension("lock"))
        .ok()
        .flatten()
        .ok_or_else(ai::credential_refusal)?;
    let candidate_version =
        CredentialVersion::for_credentials(candidate).map_err(|_| ai::credential_refusal())?;
    let current = ai::load_anthropic_canonical(&path).map_err(|_| ai::credential_refusal())?;
    let current = current.anthropic().ok_or_else(ai::credential_refusal)?;
    if !ai::binding_matches_locked(lock, base, captured).map_err(|_| ai::credential_refusal())? {
        return Ok(GuardedWriteOutcome::BindingChanged);
    }
    match witness {
        AnthropicWriteWitness::Profile(proof) => {
            if proof.credential_version() != candidate_version
                || captured.context() != &StoredAnthropicContext::Known(proof.context().clone())
            {
                return Err(ai::credential_refusal());
            }
            // Two identities must never hold one grant. A legacy identity has no index
            // row, so a verified context cannot rule out that its canonical holds this
            // very pair; only an affirmative "not held" permits the write.
            // A slot-bound legacy sibling with the same normalised email may hold the
            // pre-rotation pair of this very grant, which token equality cannot see.
            let held = ai::read_profiles_snapshot(base).and_then(|pf| {
                // Token comparison first: an unreadable sibling canonical keeps its own
                // error and warning. Only then the same-email rotation-lag check.
                if ai::candidate_pair_held_elsewhere(base, &pf, captured.identity(), candidate)? {
                    return Ok(true);
                }
                Ok(ai::legacy_sibling_shares_email(
                    base,
                    &pf,
                    captured.identity(),
                    proof.context(),
                ))
            });
            if held != Ok(false) {
                return Err(ai::credential_refusal());
            }
        }
        AnthropicWriteWitness::LegacyOwnUuid(proof) => {
            if !matches!(captured.context(), StoredAnthropicContext::LegacyUnknown)
                || !proof.permits(base, captured, candidate)
            {
                return Err(ai::credential_refusal());
            }
        }
        AnthropicWriteWitness::RefreshLineage(_) => return Err(ai::credential_refusal()),
    }
    if candidate.claude_ai_oauth.expires_at <= current.claude_ai_oauth.expires_at
        || min_expiry_exclusive
            .is_some_and(|minimum| candidate.claude_ai_oauth.expires_at <= minimum)
    {
        return Ok(GuardedWriteOutcome::NotFresher);
    }
    // PRE-COMMIT writer: the bounded 500 ms lock is correct here, because
    // refusing costs nothing and the next tick retries. Ruling B: write
    // under the lock, then release it BEFORE the token-history append (the
    // append has its own bounded lock and must never nest inside ours).
    let creds_to_write = CredentialFile::Anthropic(candidate.clone());
    let creds_to_write = preserve_subscription_metadata(&creds_to_write, &path);
    save_uuid_credentials_prepared(base, captured.identity(), &creds_to_write, false)?;
    drop(_canonical);
    super::token_history::record_write(base, captured.identity(), &creds_to_write);
    Ok(GuardedWriteOutcome::Written)
}

/// A rotating grant is durable identity custody, independent of any slot or profiles file.
fn save_anthropic_lineage_canonical(
    base: &Path,
    captured: &crate::accounts::anthropic_identity::CapturedBinding,
    candidate: &super::AnthropicCredentialFile,
    proof: &crate::accounts::anthropic_identity::RefreshLineageWitness,
) -> Result<GuardedWriteOutcome, CredentialError> {
    use crate::accounts::anthropic_identity::{self as ai, CredentialVersion};
    if !captured.belongs_to(base) {
        return Err(ai::credential_refusal());
    }
    prepare_anthropic_refresh_directory(base, captured.identity())?;
    let path = credentials_path_for(base, captured.identity());
    let identity_dir = path.parent().ok_or_else(ai::credential_refusal)?;
    // D237 C1: from the moment the provider answered the refresh, the new
    // pair exists only in memory and the old refresh token is dead. Rescue
    // FIRST (durable record before any lock wait), then take the canonical
    // lock under the long post-commit budget — never the 500 ms preflight
    // bound, whose expiry would discard the pair.
    let creds_to_write = CredentialFile::Anthropic(candidate.clone());
    let creds_to_write = preserve_subscription_metadata(&creds_to_write, &path);
    // D237 round-2 H-c: persist the captured source version, the result
    // version and the captured context, so adoption re-runs this writer's
    // exact gate (`proof.permits` + `refresh_context_matches`) instead of an
    // expiry-only comparison.
    let result_version =
        CredentialVersion::for_credentials(candidate).map_err(|_| ai::credential_refusal())?;
    let witness = crate::credentials::rescue::RescueWitness::Anthropic(
        ai::rescue_lineage_witness_refresh(captured, result_version),
    );
    let rescue_record = write_post_commit_rescue(
        identity_dir,
        "anthropic",
        captured.identity(),
        &creds_to_write,
        &witness,
    );
    let _canonical = acquire_post_commit_lock(
        "anthropic",
        path.with_extension("lock"),
        rescue_record.as_deref(),
    )?;
    // R3 sec L-1: re-check for a CONCURRENT record next to the in-lock
    // canonical re-read below. A record that appeared after the broker's
    // pre-flight gate means another writer rotated from the same source;
    // writing the canonical now would make that record's provenance
    // unverifiable. Defer to adoption — OUR record stays durable too, and
    // adoption decides which pair the canonical actually consumed.
    // Only defer when THIS pair is already durable in its own record: with
    // no record, skipping the write would discard the pair outright.
    if let Some(own) = rescue_record.as_deref() {
        if crate::credentials::rescue::has_other_rescue_record(identity_dir, Some(own)) {
            warn!(
                error_kind = "refresh_lineage_save_blocked_by_concurrent_rescue",
                "rotated pair saved; a concurrent rescue record appeared before the \
                 in-lock re-read, so adoption decides which pair is provable"
            );
            return Ok(GuardedWriteOutcome::NotFresher);
        }
    }
    // Policy gate. ANY refusal here deletes the rescue record: the pair was
    // refused for a custody/context reason and adoption MUST NOT bypass that
    // decision later by installing it from the record. Only a LOCK failure
    // (above) or an I/O failure of the canonical WRITE itself (below) keeps
    // the record.
    // A refusal adoption RE-DERIVES (identity removed, superseded source,
    // `proof.permits`, context mismatch) removes the record. A step that
    // could not READ its state decided nothing: the rotated pair's only
    // copy is retained for adoption, which re-runs this gate under the lock.
    enum GateFailure {
        Refused(CredentialError),
        Unreadable(CredentialError),
    }
    fn unreadable<E>(_: E) -> GateFailure {
        GateFailure::Unreadable(crate::accounts::anthropic_identity::credential_refusal())
    }
    let gate = (|| -> Result<GuardedWriteOutcome, GateFailure> {
        if is_identity_removed(base, captured.identity()) {
            return Err(GateFailure::Refused(ai::credential_refusal()));
        }
        let current = ai::load_anthropic_canonical(&path).map_err(unreadable)?;
        let current = current
            .anthropic()
            .ok_or_else(|| GateFailure::Unreadable(ai::credential_refusal()))?;
        let current_version = CredentialVersion::for_credentials(current).map_err(unreadable)?;
        if current_version != captured.credential_version() {
            // A newer canonical won this rotation; the rescued pair is
            // superseded, so it must not be re-installed.
            return Ok(GuardedWriteOutcome::BindingChanged);
        }
        if !proof.permits(captured.identity(), current_version, result_version) {
            return Err(GateFailure::Refused(ai::credential_refusal()));
        }
        if !ai::refresh_context_matches(base, captured).map_err(unreadable)? {
            return Err(GateFailure::Refused(ai::credential_refusal()));
        }
        Ok(GuardedWriteOutcome::Written)
    })();
    match gate {
        Ok(GuardedWriteOutcome::Written) => {}
        Ok(outcome) => {
            remove_own_rescue_record(rescue_record.as_deref());
            return Ok(outcome);
        }
        Err(GateFailure::Refused(error)) => {
            remove_own_rescue_record(rescue_record.as_deref());
            return Err(error);
        }
        Err(GateFailure::Unreadable(error)) => {
            warn!(
                error_kind = "refresh_lineage_gate_unreadable",
                "rotated pair's canonical state could not be read under the lock; the rescued \
                 pair is kept for adoption"
            );
            return Err(error);
        }
    }
    // Neither timestamp freshness nor slot custody can discard a rotated RT.
    save_uuid_credentials_prepared(base, captured.identity(), &creds_to_write, true)?;
    remove_own_rescue_record(rescue_record.as_deref());
    drop(_canonical);
    // Ruling B: the fingerprint append runs outside the canonical section.
    super::token_history::record_write(base, captured.identity(), &creds_to_write);
    Ok(GuardedWriteOutcome::Written)
}

/// Repair the existing owner-controlled identity directories before any rotating request.
pub(crate) fn prepare_anthropic_refresh_directory(
    base: &Path,
    identity: IdentityId,
) -> Result<(), CredentialError> {
    let refuse = crate::accounts::anthropic_identity::credential_refusal;
    let path = credentials_path_for(base, identity);
    let parent = path.parent().ok_or_else(refuse)?;
    for directory in [parent.parent().ok_or_else(refuse)?, parent] {
        let metadata = match std::fs::symlink_metadata(directory) {
            Ok(m) => m,
            // R3 LOW 6: missing == the logged-out state, never corruption.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(identity_dir_missing(identity))
            }
            Err(_) => return Err(refuse()),
        };
        if !metadata.is_dir() {
            return Err(refuse());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no memory or synchronization preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(refuse());
            }
        }
        // R2 M2: TIGHTEN-ONLY — the precheck above established the
        // directories exist; this must never recreate one removed in
        // between (orphan GC, logout).
        pre_tighten_hook::run();
        match crate::platform::fs::tighten_existing_private_dir(directory) {
            Ok(()) => {}
            // R3 LOW 6: removed between the precheck above and this tighten
            // (the fs helper's `missing_dir_refusal` carries NotFound).
            Err(crate::error::PlatformError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(identity_dir_missing(identity))
            }
            Err(_) => return Err(refuse()),
        }
    }
    require_identity_directory(&path, identity)
}

/// Test-only ordering hook (R3-fix-check LOW 6): fires between the
/// require-existing precheck and the tighten in the directory-prep paths,
/// so the removal-in-the-gap race can be exercised deterministically
/// instead of hoped for. Compiled to a no-op outside test/test-utils
/// builds (`rules/security.md` MUST Rule 1 feature-gate precedent).
#[cfg(any(test, feature = "test-utils"))]
mod pre_tighten_hook {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<fn()>> = const { RefCell::new(None) };
    }

    /// Invoke the installed hook, if any, on the CURRENT thread.
    pub(super) fn run() {
        HOOK.with(|h| {
            if let Some(f) = *h.borrow() {
                f();
            }
        });
    }

    /// Install (or clear) the hook for the CURRENT thread. Tests MUST clear
    /// it before returning — a leaked hook would fire in unrelated tests on
    /// the same thread (the guard pattern keeps that from surviving a
    /// failing assertion). `cfg(test)`-only: under a plain `test-utils`
    /// LIB build the module is active but nothing would call this, and the
    /// workspace lints deny dead code.
    #[cfg(test)]
    pub fn set(f: Option<fn()>) {
        HOOK.with(|h| *h.borrow_mut() = f);
    }
}
#[cfg(not(any(test, feature = "test-utils")))]
mod pre_tighten_hook {
    pub(super) fn run() {}
}

/// R3 LOW 6: the removed (logged-out) identity state — a distinct variant
/// from the generic `credential_refusal` corruption shape, so callers and
/// operators can tell "the identity is gone" (re-login) from "the store is
/// corrupt" (investigate).
fn identity_dir_missing(identity: IdentityId) -> CredentialError {
    CredentialError::IdentityDirectoryMissing {
        uuid: identity.to_string(),
    }
}

fn require_identity_directory(path: &Path, identity: IdentityId) -> Result<(), CredentialError> {
    check_identity_directory(path, identity).map_err(|refusal| match refusal {
        DirectoryRefusal::Unreadable(error) | DirectoryRefusal::Refused(error) => error,
    })
}

/// Why [`check_identity_directory`] refused.
enum DirectoryRefusal {
    /// A directory's metadata could not be READ (decides nothing).
    Unreadable(CredentialError),
    /// Missing (the logged-out identity), not a directory, or an unsafe
    /// owner or mode: a deliberate refusal.
    Refused(CredentialError),
}

fn check_identity_directory(path: &Path, identity: IdentityId) -> Result<(), DirectoryRefusal> {
    let refuse =
        || DirectoryRefusal::Refused(crate::accounts::anthropic_identity::credential_refusal());
    let parent = path.parent().ok_or_else(refuse)?;
    for directory in [parent, parent.parent().ok_or_else(refuse)?] {
        let metadata = match std::fs::symlink_metadata(directory) {
            Ok(m) => m,
            // R3 LOW 6: same mapping as the refresh path — a missing dir is
            // the logged-out identity, not corruption.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DirectoryRefusal::Refused(identity_dir_missing(identity)))
            }
            Err(_) => {
                return Err(DirectoryRefusal::Unreadable(
                    crate::accounts::anthropic_identity::credential_refusal(),
                ))
            }
        };
        if !metadata.is_dir() {
            return Err(refuse());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no memory or synchronization preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(refuse());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    // One-shot and thread-scoped: models a transient failure of the login
    // writer's own stored-context read (corr MED-1); no production knob.
    static WRITER_CONTEXT_READ_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn arm_writer_context_read_fault() {
    WRITER_CONTEXT_READ_FAULT.with(|armed| armed.set(true));
}

/// The login writer's stored-context read (one site, one test seam).
fn writer_stored_context(
    base: &Path,
    identity: IdentityId,
) -> Result<
    crate::accounts::anthropic_identity::StoredAnthropicContext,
    crate::accounts::anthropic_identity::IdentityError,
> {
    #[cfg(test)]
    if WRITER_CONTEXT_READ_FAULT.with(|armed| armed.replace(false)) {
        return Err(crate::accounts::anthropic_identity::IdentityError::Io);
    }
    crate::accounts::anthropic_identity::read_stored_anthropic_context(base, identity)
}

/// Writes a login grant's rescue record BEFORE the profiles lock is taken.
///
/// D237 round-2 corr N4 / security M4: the OAuth authorization-code exchange
/// has already consumed the grant when `commit_verified_login` runs, and the
/// profiles lock it is about to take can be held for the whole COMMIT-class
/// budget by another publication's canonical wait. Without this record a
/// profiles-lock timeout (or a crash while waiting) discards a consumed
/// grant that has no other durable copy.
///
/// Only a RE-LOGIN whose prior binding is Anthropic can be rescued here: the
/// slot is already bound to `prior.binding.identity`, so installing the
/// grant at that identity is exactly what the login would have done.
///
/// LIMIT (R3 security M4): a FIRST login — and a legacy install with no
/// identity directory or no Known context — has no identity directory to
/// write the record into, so this function protects NOTHING for it. The
/// grant becomes durable only when the publication's canonical write
/// completes; a profiles-lock timeout or a crash before that point still
/// discards it (the slot then needs a new login; no canonical credential is
/// corrupted). Spec 04 §4.2.1 states the same limit.
///
/// Returns the record's own path; the caller hands it to
/// [`save_anthropic_login_target_locked`] when the resolved target identity
/// is the same, and removes it otherwise.
/// A pre-lock login rescue record plus the WRITER-LIVENESS lock that keeps
/// adoption from installing a grant this publication may still refuse
/// (R3 sec M-A / corr L-7). The sidecar `<record>.json.writer` is held
/// exclusively for the record's whole life in this process; a crashed writer
/// releases it with the process, so a dead writer's record becomes adoptable.
pub(crate) struct PrelockRescue {
    pub path: PathBuf,
    pub writer_guard: crate::platform::lock::FileLockGuard,
}

/// Refuses a pre-lock record: best-effort tombstone and unlink, then the
/// writer guard drops and only THEN is its sidecar removed (corr L1).
///
/// The refusal does not depend on the cleanup: a pre-lock record is refused
/// by DEFAULT because no kept marker is ever written for it.
pub(crate) fn refuse_prelock_rescue(record: Option<PrelockRescue>) {
    let Some(PrelockRescue { path, writer_guard }) = record else {
        return;
    };
    crate::credentials::rescue::refuse_prelock_record(&path);
    drop(writer_guard);
    crate::credentials::rescue::remove_writer_sidecar(&path);
}

/// Keeps a pre-lock record for adoption: writes its kept marker, THEN drops
/// the writer guard (a record must never be adoptable-looking without its
/// marker). A marker that cannot be written leaves the record refused —
/// the accepted, safe-direction trade-off (see `mark_rescue_kept`).
pub(crate) fn keep_prelock_rescue(record: Option<PrelockRescue>) {
    let Some(PrelockRescue { path, writer_guard }) = record else {
        return;
    };
    crate::credentials::rescue::mark_rescue_kept(&path);
    drop(writer_guard);
}

/// Refuses a handed-in pre-lock record on a DELIBERATE refusal (R3 corr M-3,
/// the same rule as `PrelockLoginRescue`'s `keep`): the publication decided this
/// grant must not bind at this identity, so adoption must not install it
/// later. Read/IO-class failures RETAIN the record instead — adoption re-runs
/// every custody gate before installing.
fn discard_prelock_rescue(record: Option<PrelockRescue>) {
    refuse_prelock_rescue(record);
}

pub(crate) fn write_login_prelock_rescue(
    base: &Path,
    identity: IdentityId,
    candidate: &super::AnthropicCredentialFile,
    verified: &crate::accounts::anthropic_identity::VerifiedAnthropicContext,
) -> Option<PrelockRescue> {
    let path = credentials_path_for(base, identity);
    let identity_dir = path.parent()?;
    // A logged-out identity must never be resurrected by a rescue.
    if is_identity_removed(base, identity) {
        return None;
    }
    match std::fs::symlink_metadata(identity_dir) {
        Ok(metadata) if metadata.is_dir() => {}
        // No identity directory yet: nothing adoption could read.
        _ => return None,
    }
    let creds_to_write =
        preserve_subscription_metadata(&CredentialFile::Anthropic(candidate.clone()), &path);
    let witness = crate::accounts::anthropic_identity::rescue_lineage_witness_login(verified);
    let Ok(value) = serde_json::to_value(&creds_to_write) else {
        warn!(
            error_kind = "rescue_record_serialize_failed",
            provider = "anthropic",
            "pre-lock login grant could not be serialized for rescue"
        );
        return None;
    };
    // Liveness FIRST, adoption-visibility second (corr LOW-2): the sidecar is
    // created and locked BEFORE the record exists, so no adoption tick can
    // ever see this record without a live writer. The sidecar FILE is
    // created explicitly: on Windows the lock is a named mutex that creates
    // no file, and `rescue_writer_is_live` treats a missing sidecar as "no
    // live writer". (The orphan sweep leaves a LIVE sidecar alone.)
    let record = crate::credentials::rescue::new_prelock_rescue_record_path(identity_dir);
    let sidecar = record.with_extension("json.writer");
    let liveness = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&sidecar)
        .map_err(|_| ())
        .and_then(|_| crate::platform::lock::lock_file(&sidecar).map_err(|_| ()));
    let Ok(writer_guard) = liveness else {
        // Cannot prove the writer is live: write no record at all. The
        // post-lock writer still rescues the grant under its own record.
        warn!(
            error_kind = "rescue_prelock_liveness_unavailable",
            "pre-lock rescue skipped: its writer-liveness lock could not be taken"
        );
        crate::credentials::rescue::remove_writer_sidecar(&record);
        return None;
    };
    if let Err(error) = crate::credentials::rescue::write_prelock_rescue_record(
        &record,
        &identity.to_string(),
        RESCUE_REASON_LOCK_TIMEOUT,
        &value,
        &witness,
    ) {
        warn!(
            error_kind = "rescue_record_write_failed",
            provider = "anthropic",
            reason = error.error_kind_tag(),
            "pre-lock login grant could not be rescued to disk"
        );
        drop(writer_guard);
        crate::credentials::rescue::remove_writer_sidecar(&record);
        return None;
    }
    Some(PrelockRescue {
        path: record,
        writer_guard,
    })
}

/// Publication owner already validated the complete target metadata and prior slot.
pub(crate) fn save_anthropic_login_target_locked(
    lock: &crate::accounts::profiles_lock::ProfilesFileLock,
    base: &Path,
    slot: AccountNum,
    identity: IdentityId,
    candidate: &super::AnthropicCredentialFile,
    verified: &crate::accounts::anthropic_identity::VerifiedAnthropicContext,
    prelock_rescue: Option<PrelockRescue>,
) -> Result<(), CredentialError> {
    use crate::accounts::anthropic_identity::{
        self as ai, CredentialVersion, StoredAnthropicContext,
    };
    // Every exit below either KEEPS the handed pre-lock record (a read or
    // I/O failure decided nothing about the grant: `keep_prelock_rescue`
    // writes its kept marker) or REFUSES it (a deliberate decision). None
    // drops it implicitly (corr MED-1).
    let version_matches = CredentialVersion::for_credentials(candidate)
        .is_ok_and(|version| version == verified.credential_version());
    if !lock.protects(base) || !version_matches {
        // A deliberate refusal: the handed pre-lock record must not survive
        // for adoption to install a grant this publication refused.
        discard_prelock_rescue(prelock_rescue);
        return Err(ai::credential_refusal());
    }
    let stored = match writer_stored_context(base, identity) {
        Ok(stored) => stored,
        Err(_) => {
            // Read-class: keep; adoption re-runs this context check.
            keep_prelock_rescue(prelock_rescue);
            return Err(ai::credential_refusal());
        }
    };
    if stored != StoredAnthropicContext::Known(verified.context().clone()) {
        // A context MISMATCH is deliberate: refuse.
        discard_prelock_rescue(prelock_rescue);
        return Err(ai::credential_refusal());
    }
    // One grant, one identity. The caller holds the profiles lock (the lock order is
    // profiles, then settings, and nothing here takes either), so the sibling scan sees the
    // same `by_slot` the publication will commit. A login that really minted its pair can
    // never match a sibling; a reused config directory that handed back a pair another
    // identity still holds must not bind it to a second one. Only an affirmative "not
    // held" publishes: an unreadable sibling refuses too (its warning names the slot).
    match ai::read_profiles_snapshot(base).and_then(|pf| {
        ai::candidate_pair_holder_for_login(base, &pf, identity, &slot.to_string(), candidate)
    }) {
        Ok(None) => (),
        Ok(Some(holder)) => {
            // Deliberate refusal: the pair is another identity's grant.
            discard_prelock_rescue(prelock_rescue);
            return Err(ai::login_held_elsewhere_refusal(holder));
        }
        Err(ai::IdentityError::SiblingCustodyUnreadable { sibling }) => {
            // Read-class: KEEP the record; adoption re-gates (including this
            // holder scan) before installing.
            keep_prelock_rescue(prelock_rescue);
            return Err(ai::login_sibling_unreadable_refusal(sibling));
        }
        Err(_) => {
            // Read-class (profiles snapshot unreadable): keep, as above.
            keep_prelock_rescue(prelock_rescue);
            return Err(ai::credential_refusal());
        }
    }
    let slot_mutex = AccountMutexTable::global().get_or_insert(Surface::ClaudeCode, slot);
    let Ok(_slot_guard) = slot_mutex.lock() else {
        // A poisoned slot mutex says nothing about the grant: keep.
        keep_prelock_rescue(prelock_rescue);
        return Err(ai::credential_refusal());
    };
    let path = credentials_path_for(base, identity);
    let Some(identity_dir) = path.parent() else {
        discard_prelock_rescue(prelock_rescue);
        return Err(ai::credential_refusal());
    };
    match check_identity_directory(&path, identity) {
        Ok(()) => {}
        Err(DirectoryRefusal::Unreadable(error)) => {
            // Its metadata could not be read: keep; adoption re-checks.
            keep_prelock_rescue(prelock_rescue);
            return Err(error);
        }
        Err(DirectoryRefusal::Refused(error)) => {
            // Missing (logged out), not a directory, or unsafe owner/mode.
            discard_prelock_rescue(prelock_rescue);
            return Err(error);
        }
    }
    // D237 C1: the OAuth code exchange already consumed the login grant, so
    // this is a POST-COMMIT write. Rescue the pair before any lock wait, then
    // wait under the long commit budget instead of discarding the grant.
    let creds_to_write = CredentialFile::Anthropic(candidate.clone());
    let creds_to_write = preserve_subscription_metadata(&creds_to_write, &path);
    // D237 round-2 H-c: persist the verified result version and context so
    // adoption re-runs this writer's stored-context / freshness gate.
    // D237 round-2 corr N4 / sec M4: a re-login's caller writes the rescue
    // BEFORE it takes the profiles lock (the grant is consumed at the code
    // exchange); `prelock_rescue` is that record, and it is used only when
    // the caller proved it belongs to THIS identity.
    // The held guard keeps adoption out of this record until the publication
    // resolves; it drops at function exit, when a kept record becomes
    // adoptable (R3 sec M-A).
    let (rescue_record, writer_liveness) = match prelock_rescue {
        Some(handle) => (Some(handle.path), Some(handle.writer_guard)),
        None => {
            let witness = crate::credentials::rescue::RescueWitness::Anthropic(
                ai::rescue_lineage_witness_login(verified),
            );
            (
                write_post_commit_rescue(
                    identity_dir,
                    "anthropic",
                    identity,
                    &creds_to_write,
                    &witness,
                ),
                None,
            )
        }
    };
    // Hands a handed-over PRE-LOCK record back as KEPT (marker first, then
    // the guard drops). A post-lock record needs no marker.
    let keep_handed = |record: Option<PathBuf>,
                       guard: Option<crate::platform::lock::FileLockGuard>| {
        if let (Some(path), Some(writer_guard)) = (record, guard) {
            keep_prelock_rescue(Some(PrelockRescue { path, writer_guard }));
        }
    };
    let _canonical = match acquire_post_commit_lock(
        "anthropic",
        path.with_extension("lock"),
        rescue_record.as_deref(),
    ) {
        Ok(guard) => guard,
        Err(error) => {
            keep_handed(rescue_record, writer_liveness);
            return Err(error);
        }
    };
    // Policy gate. ANY refusal here refuses the rescue record durably
    // (corr M2): adoption cannot re-derive the read-class refusals, so it
    // must not later install a grant this publication refused. A failure of
    // the canonical write itself (below) keeps it.
    let gate = (|| -> Result<bool, CredentialError> {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let current =
                    ai::load_anthropic_canonical(&path).map_err(|_| ai::credential_refusal())?;
                let current = current.anthropic().ok_or_else(ai::credential_refusal)?;
                if CredentialVersion::for_credentials(current)
                    .map_err(|_| ai::credential_refusal())?
                    == verified.credential_version()
                {
                    // Already installed by a concurrent writer: nothing to adopt.
                    return Ok(true);
                }
                if candidate.claude_ai_oauth.expires_at <= current.claude_ai_oauth.expires_at {
                    // The existing canonical is at least as fresh as the
                    // incoming grant; keep it and refuse the older grant.
                    return Err(ai::credential_refusal());
                }
                Ok(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(ai::credential_refusal()),
        }
    })();
    match gate {
        Ok(true) => {
            remove_own_rescue_record(rescue_record.as_deref());
            drop(writer_liveness);
            if let Some(record) = rescue_record.as_deref() {
                super::rescue::clear_rescue_artifacts_if_gone(record);
            }
            // AlreadyInstalled: every older sibling record is superseded by
            // the canonical this login matches (R3 3b).
            super::rescue::quarantine_other_rescue_records(identity_dir, None);
            return Ok(());
        }
        Ok(false) => {}
        Err(error) => {
            match (rescue_record, writer_liveness) {
                (Some(path), Some(writer_guard)) => {
                    refuse_prelock_rescue(Some(PrelockRescue { path, writer_guard }));
                }
                (Some(path), None) => {
                    // Not durable at all is logged and flagged inside (the
                    // CLI prints the operator line); nothing more to do here.
                    if super::rescue::refuse_rescue_record(&path).is_err() {
                        warn!(
                            error_kind = "login_rescue_refusal_not_durable",
                            "login grant refused; its rescue record could not be discarded"
                        );
                    }
                }
                (None, _) => {}
            }
            return Err(error);
        }
    }
    if let Err(error) = save_uuid_credentials_prepared(base, identity, &creds_to_write, false) {
        keep_handed(rescue_record, writer_liveness);
        return Err(error);
    }
    remove_own_rescue_record(rescue_record.as_deref());
    drop(writer_liveness);
    if let Some(record) = rescue_record.as_deref() {
        super::rescue::clear_rescue_artifacts_if_gone(record);
    }
    // A successful login publication supersedes every older sibling record
    // for this identity (R3 3b); a re-login thus clears a blocked refresh.
    super::rescue::quarantine_other_rescue_records(identity_dir, None);
    drop(_canonical);
    // Ruling B: the fingerprint append runs outside the canonical section.
    super::token_history::record_write(base, identity, &creds_to_write);
    Ok(())
}

/// Returns the canonical credential file path for the
/// [`Surface::ClaudeCode`] surface: `{base_dir}/credentials/{N}.json`.
///
/// Thin wrapper over [`canonical_path_for`] preserving the pre-PR-C2a
/// 2-argument signature for existing Anthropic-only call sites.
///
/// **M4-12 (RN1-C)**: The numeric `credentials/<N>.json` path is retired
/// as a WRITE destination. This function is retained for existing READ
/// paths (doctor, run, refresh/check) that locate credential files on
/// disk for diagnostic or lock-coordination purposes. New code MUST NOT
/// use this as an Anthropic write target — use the captured-UUID guarded writer.
pub fn canonical_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    canonical_path_for(base_dir, account, Surface::ClaudeCode)
}

/// Surface-dispatched canonical credential file path.
///
/// | Surface     | Path                                       |
/// |-------------|--------------------------------------------|
/// | ClaudeCode  | `{base_dir}/credentials/{N}.json`          |
/// | Codex       | `{base_dir}/credentials/codex-{N}.json`    |
/// | Gemini      | `{base_dir}/credentials/gemini-{N}.json`*  |
///
/// The Codex path shape is fixed by spec 07 §7.2.2.
///
/// **Gemini caveat**: Gemini does NOT use a canonical credential
/// file. The API key flows through `platform::secret::Vault` and the
/// daemon refresher / credential writer skip the Gemini surface
/// entirely. The path is returned for API symmetry only — calling
/// `save` on it is a logic bug. PR-G2b will gate the writer call
/// sites; for PR-G1 the path exists so the dispatch chain compiles.
///
/// **M4-12 (RN1-C)**: The numeric paths are retired as WRITE
/// destinations. This function is retained for READ paths. New code
/// MUST NOT use this to construct write targets.
pub fn canonical_path_for(base_dir: &Path, account: AccountNum, surface: Surface) -> PathBuf {
    let filename = match surface {
        Surface::ClaudeCode => format!("{}.json", account),
        Surface::Codex => format!("codex-{}.json", account),
        Surface::Gemini => format!("gemini-{}.json", account),
        // Native-CLI binding markers (credential-less; see `providers::native`).
        Surface::Kimi => format!("kimi-{}.json", account),
        Surface::Grok => format!("grok-{}.json", account),
    };
    base_dir.join("credentials").join(filename)
}

/// Returns the live credential file path for the [`Surface::ClaudeCode`]
/// surface: `{base_dir}/config-{N}/.credentials.json`.
///
/// Thin wrapper over [`live_path_for`] preserving the pre-PR-C2a
/// 2-argument signature for existing Anthropic-only call sites.
pub fn live_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    live_path_for(base_dir, account, Surface::ClaudeCode)
}

/// Surface-dispatched live-mirror credential file path.
///
/// | Surface     | Path (inside `config-{N}/`)  |
/// |-------------|------------------------------|
/// | ClaudeCode  | `.credentials.json`          |
/// | Codex       | `codex-auth.json`            |
/// | Gemini      | `.gemini-creds.json`*        |
///
/// The Codex path shape is fixed by spec 07 §7.2.2.
///
/// **Gemini caveat**: same as [`canonical_path_for`] — Gemini does
/// not use a live mirror; the path is returned for API symmetry only.
pub fn live_path_for(base_dir: &Path, account: AccountNum, surface: Surface) -> PathBuf {
    let filename = match surface {
        Surface::ClaudeCode => ".credentials.json",
        Surface::Codex => "codex-auth.json",
        Surface::Gemini => ".gemini-creds.json",
        // Native-CLI surfaces have no live mirror (the vendor CLI owns its
        // creds); returned for API symmetry only — never written.
        Surface::Kimi => ".kimi-creds.json",
        Surface::Grok => ".grok-creds.json",
    };
    base_dir.join(format!("config-{}", account)).join(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn sample_creds() -> CredentialFile {
        CredentialFile::Anthropic(crate::credentials::AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test".into()),
                expires_at: 1775726524877,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn sample_codex_creds() -> CredentialFile {
        CredentialFile::Codex(crate::credentials::CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: crate::credentials::CodexTokensFile {
                account_id: Some("test-account-uuid".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.test-at.sig".into(),
                refresh_token: Some("rt_test".into()),
                id_token: Some("eyJhbGciOiJIUzI1NiJ9.test-id.sig".into()),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        })
    }

    // ── Migrated identity-authority fixtures (2026-10-10) ────────────────────
    //
    // The raw Anthropic canonical write authority (`save_canonical_for` on the
    // ClaudeCode surface) is retired: these Known-context fixtures write with
    // a captured identity and a verified exact-grant witness. These helpers reuse
    // the crate's fake-authenticated-commit primitives
    // (`commit_anthropic_login_with` + a fake `transport`), mirroring the
    // `anthropic_identity.rs` test fixtures.

    fn ai_slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn ai_context(org: u128) -> crate::accounts::anthropic_identity::AnthropicContext {
        crate::accounts::anthropic_identity::AnthropicContext::new(
            "same@test.invalid",
            uuid::Uuid::from_u128(10),
            uuid::Uuid::from_u128(org),
        )
        .unwrap()
    }

    fn ai_credential(tag: &str, expiry: u64, subscription: Option<&str>) -> CredentialFile {
        CredentialFile::Anthropic(crate::credentials::AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: AccessToken::new(format!("fake-access-{tag}")),
                refresh_token: RefreshToken::new(format!("fake-refresh-{tag}")),
                expires_at: expiry,
                scopes: vec![],
                subscription_type: subscription.map(str::to_owned),
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn ai_transport(
        expected: &CredentialFile,
        context: crate::accounts::anthropic_identity::AnthropicContext,
    ) -> crate::daemon::usage_poller::HttpGetFn {
        let expected_access = expected
            .anthropic()
            .unwrap()
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_owned();
        std::sync::Arc::new(move |url, access, headers| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(access, expected_access);
            assert_eq!(headers, &[("anthropic-beta", "oauth-2025-04-20")]);
            Ok((
                200,
                serde_json::to_vec(&serde_json::json!({
                    "account":{"uuid":context.account_uuid(),"email":context.email()},
                    "organization":{"uuid":context.organization_uuid()},
                }))
                .unwrap(),
            ))
        })
    }

    /// Fake authenticated commit: verifies `creds` against `ctx` via the fake
    /// transport, mints the typed Known identity, and writes the canonical —
    /// the only production door for an Anthropic canonical write.
    fn ai_commit(
        base: &Path,
        n: u16,
        creds: &CredentialFile,
        ctx: crate::accounts::anthropic_identity::AnthropicContext,
    ) -> IdentityId {
        let prior = crate::accounts::anthropic_identity::capture_login_prior(base, ai_slot(n))
            .expect("capture_login_prior");
        crate::accounts::anthropic_identity::commit_anthropic_login_with(
            base,
            ai_slot(n),
            creds,
            &ai_transport(creds, ctx),
            None,
            prior,
        )
        .expect("fake authenticated commit")
        .identity()
    }

    /// Exact-grant profile witness for `creds` under `ctx` (typed Known only).
    fn ai_proof(
        creds: &CredentialFile,
        ctx: crate::accounts::anthropic_identity::AnthropicContext,
    ) -> crate::accounts::anthropic_identity::VerifiedAnthropicContext {
        crate::accounts::anthropic_identity::verify_anthropic_context_with(
            creds.anthropic().unwrap(),
            &ai_transport(creds, ctx),
        )
        .expect("fake verified context")
    }

    fn ai_captured(base: &Path, n: u16) -> crate::accounts::anthropic_identity::CapturedBinding {
        crate::accounts::anthropic_identity::capture_anthropic_binding(base, ai_slot(n))
            .expect("capture_anthropic_binding")
    }

    fn ai_guarded(
        base: &Path,
        captured: &crate::accounts::anthropic_identity::CapturedBinding,
        candidate: &CredentialFile,
        ctx: crate::accounts::anthropic_identity::AnthropicContext,
        min_expiry_exclusive: Option<u64>,
    ) -> Result<GuardedWriteOutcome, CredentialError> {
        let proof = ai_proof(candidate, ctx);
        save_anthropic_canonical_guarded(
            base,
            captured,
            candidate.anthropic().unwrap(),
            AnthropicWriteWitness::Profile(&proof),
            min_expiry_exclusive,
        )
    }

    #[test]
    fn round_trip_load_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        let original = sample_creds();
        save(&path, &original).unwrap();

        let loaded = load(&path).unwrap();
        let a = loaded.anthropic().expect("sample is Anthropic");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test"
        );
        assert_eq!(a.claude_ai_oauth.expires_at, 1775726524877);
    }

    #[test]
    fn load_missing_file_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        match load(&path) {
            Err(CredentialError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn load_corrupt_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { .. }) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn load_empty_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(reason.contains("empty"), "reason: {reason}");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        save(&path, &sample_creds()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deep").join("creds.json");

        save(&path, &sample_creds()).unwrap();
        assert!(path.exists());
    }

    /// Regression: per security.md MUST Rule 5a (an internal journal entry B2 class),
    /// every failure branch in `save` after the tmp file would-be-write
    /// must best-effort `remove_file(&tmp)` before propagating. This test
    /// drives the atomic_replace failure branch by making the parent dir
    /// read-only, then asserts no `*.tmp.*` files remain.
    ///
    /// /redteam round 3 (2026-05-09) found `save` had been missed by the
    /// original B2 fix — same pattern as the cache_write test in coc/cache.rs.
    #[cfg(unix)]
    #[test]
    fn save_partial_failure_cleans_tmp_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        // Establish the file once so the parent dir is populated and
        // we know subsequent writes target an existing surface.
        save(&path, &sample_creds()).unwrap();

        // Make the parent dir read-only so the next save's
        // `std::fs::write(&tmp, ...)` fails (can't create a new file).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = save(&path, &sample_creds());

        // Restore permissions before any assertion so TempDir cleanup works.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "save must fail when parent dir is read-only"
        );

        // No .tmp.* files may remain — the cleanup branch must have run.
        let leaked: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "save leaked tmp files after failure: {leaked:?}"
        );
    }

    /// M4-12 acceptance test (RN1-C criterion 4):
    /// `save_canonical_for_does_not_write_numeric_credentials_n_json`.
    ///
    /// The numeric `credentials/<N>.json` write path is fully retired in M4-12.
    /// Without a UUID-provisioned identity, `save_canonical_for` MUST fail-closed
    /// (return `CredentialError::NoCredentials`) and MUST NOT write any file.
    #[test]
    fn save_canonical_for_does_not_write_numeric_credentials_n_json() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        // No UUID provisioned → must fail-closed (M4-12 Finding 1.1 fix).
        let result = save_canonical_for(dir.path(), account, &sample_creds());
        assert!(
            result.is_err(),
            "save_canonical_for MUST fail-closed when no UUID is provisioned (M4-12)"
        );

        // Numeric canonical MUST NOT be written (M4-12 numeric write retirement).
        assert!(
            !canonical_path(dir.path(), account).exists(),
            "credentials/N.json MUST NOT be written post-M4-12 numeric write retirement"
        );

        // Live mirror MUST NOT exist (M3-7 mirror retirement).
        assert!(
            !live_path(dir.path(), account).exists(),
            "config-N/.credentials.json mirror MUST NOT exist — retired in M3-7"
        );
    }

    #[test]
    fn canonical_and_live_paths_correct() {
        let base = Path::new("/home/user/.claude/accounts");
        let account = AccountNum::try_from(7u16).unwrap();

        assert_eq!(
            canonical_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/credentials/7.json")
        );
        assert_eq!(
            live_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/config-7/.credentials.json")
        );
    }

    #[test]
    fn flatten_preserves_unknown_fields() {
        let json = r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-t",
                "refreshToken": "sk-ant-ort01-t",
                "expiresAt": 1000,
                "scopes": [],
                "futureField": 42
            },
            "futureTopLevel": "hello"
        }"#;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rt.json");

        let creds: CredentialFile = serde_json::from_str(json).unwrap();
        save(&path, &creds).unwrap();

        let loaded = load(&path).unwrap();
        let reserialized = serde_json::to_value(&loaded).unwrap();

        assert_eq!(reserialized["futureTopLevel"], "hello");
        assert_eq!(reserialized["claudeAiOauth"]["futureField"], 42);
    }

    // ── PR-C2a tests: surface-param paths + mutex + mode-flip ──────────

    #[test]
    fn canonical_path_for_claude_code_matches_legacy() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(3u16).unwrap();
        assert_eq!(
            canonical_path_for(base, account, Surface::ClaudeCode),
            canonical_path(base, account)
        );
    }

    #[test]
    fn canonical_path_for_codex_prefixes_filename() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(3u16).unwrap();
        assert_eq!(
            canonical_path_for(base, account, Surface::Codex),
            PathBuf::from("/base/credentials/codex-3.json")
        );
    }

    #[test]
    fn live_path_for_claude_code_matches_legacy() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(4u16).unwrap();
        assert_eq!(
            live_path_for(base, account, Surface::ClaudeCode),
            live_path(base, account)
        );
    }

    #[test]
    fn live_path_for_codex_is_codex_auth_json() {
        let base = Path::new("/base");
        let account = AccountNum::try_from(4u16).unwrap();
        assert_eq!(
            live_path_for(base, account, Surface::Codex),
            PathBuf::from("/base/config-4/codex-auth.json")
        );
    }

    #[test]
    fn save_canonical_for_fails_closed_claude_code_without_uuid() {
        // M4-12: save_canonical wrapper deleted; save_canonical_for is the
        // only public write API. Without UUID, it MUST fail-closed for
        // Surface::ClaudeCode — neither numeric canonical nor live mirror written.
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        let result = save_canonical_for(dir.path(), account, &sample_creds());
        assert!(
            result.is_err(),
            "save_canonical_for MUST fail-closed without UUID (M4-12)"
        );
        assert!(
            !canonical_path(dir.path(), account).exists(),
            "numeric canonical MUST NOT be written post-M4-12"
        );
        assert!(
            !live_path(dir.path(), account).exists(),
            "M3-7: live mirror MUST NOT be written"
        );
        assert!(
            !canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "numeric canonical_path_for MUST NOT be written post-M4-12"
        );
        assert!(
            !live_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "M3-7: live mirror MUST NOT be written via surface-aware call"
        );
    }

    /// M4-12 acceptance test (RN1-C criterion 5):
    /// `save_canonical_for_does_not_write_numeric_credentials_codex_n_json`.
    ///
    /// The numeric `credentials/codex-<N>.json` write path is retired in M4-12.
    /// Without UUID, save_canonical_for fails-closed for Codex too.
    #[test]
    fn save_canonical_for_does_not_write_numeric_credentials_codex_n_json() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();

        // No UUID provisioned → must fail-closed (M4-12).
        let result = save_canonical_for(dir.path(), account, &sample_codex_creds());
        assert!(
            result.is_err(),
            "save_canonical_for MUST fail-closed for Codex without UUID (M4-12)"
        );

        // Numeric canonical MUST NOT be written.
        let canonical = canonical_path_for(dir.path(), account, Surface::Codex);
        let live = live_path_for(dir.path(), account, Surface::Codex);
        assert!(
            !canonical.exists(),
            "codex numeric canonical MUST NOT be written post-M4-12; path: {canonical:?}"
        );
        assert!(
            !live.exists(),
            "M3-7: codex live mirror MUST NOT be written; path: {live:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_claude_code_leaves_uuid_path_at_0o600() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use std::os::unix::fs::PermissionsExt;

        // Migrated: the raw Anthropic writer is retired; the first canonical
        // write lands through the fake authenticated commit (login target).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = ai_commit(
            base,
            2,
            &ai_credential("mode600", 1000, None),
            ai_context(20),
        );

        let uuid_path = uuid_creds_path(base, uuid);
        let mode = std::fs::metadata(&uuid_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "ClaudeCode UUID-keyed canonical must remain at 0o600 (no mode-flip)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_codex_fails_closed_without_uuid() {
        // M4-12: Codex 0o400 mode flip on numeric canonical is retired.
        // The UUID path written by save_codex_canonical_for_uuid stays at 0o600.
        // Without UUID, save_canonical_for must fail-closed.
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(8u16).unwrap();

        let result = save_canonical_for(dir.path(), account, &sample_codex_creds());
        assert!(
            result.is_err(),
            "save_canonical_for MUST fail-closed for Codex without UUID (M4-12)"
        );
        let canonical = canonical_path_for(dir.path(), account, Surface::Codex);
        assert!(
            !canonical.exists(),
            "numeric Codex canonical MUST NOT be written post-M4-12"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_canonical_for_codex_uuid_path_at_0o600_with_uuid() {
        // M4-12: Codex UUID-keyed path stays at 0o600 (not flipped to 0o400).
        // The 0o400 flip was on the numeric `credentials/codex-<N>.json` and
        // is retired along with the numeric write (Finding 1.1 / M4-12).
        use crate::accounts::identity_store::credentials_codex_path_for as uuid_codex_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::os::unix::fs::PermissionsExt;

        let dir = coexisting_fixture(9);
        let account = AccountNum::try_from(9u16).unwrap();
        let uuid = fixture_uuid_for_slot(9);

        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();
        let uuid_path = uuid_codex_path(dir.path(), uuid);
        let mode = std::fs::metadata(&uuid_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Codex UUID-keyed canonical must remain at 0o600 (mode-flip retired with numeric write)"
        );
    }

    #[test]
    fn save_canonical_for_concurrent_writers_produce_valid_file() {
        // Migrated: concurrent writers now enter through the guarded
        // exact-grant API. The mutex story is preserved — AccountMutexTable +
        // the canonical file lock serialize writers; every outcome is a clean
        // GuardedWriteOutcome and the final file must be well-formed (no torn
        // writes).
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let base = Arc::new(dir.path().to_path_buf());
        let account = ai_slot(11);
        let initial = ai_credential("conc-initial", 1000, None);
        ai_commit(&base, 11, &initial, ai_context(20));
        let candidate = ai_credential("conc-candidate", 2000, None);

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let base = Arc::clone(&base);
                let candidate = candidate.clone();
                thread::spawn(move || {
                    match crate::accounts::anthropic_identity::capture_anthropic_binding(
                        &base, account,
                    ) {
                        Ok(captured) => {
                            ai_guarded(&base, &captured, &candidate, ai_context(20), None)
                        }
                        Err(_) => Ok(GuardedWriteOutcome::BindingChanged),
                    }
                })
            })
            .collect();

        let mut written = 0usize;
        for h in handles {
            match h.join().unwrap().expect("guarded write must not error") {
                GuardedWriteOutcome::Written => written += 1,
                GuardedWriteOutcome::NotFresher | GuardedWriteOutcome::BindingChanged => {}
            }
        }
        assert!(
            written >= 1,
            "at least one concurrent writer must land the candidate"
        );

        let uuid_path = uuid_creds_path(&base, ai_captured(&base, 11).identity());
        // UUID-keyed file must be parseable JSON — no torn writes.
        let loaded = load(&uuid_path).expect("post-write UUID-keyed file must parse");
        let a = loaded.anthropic().expect("candidate is Anthropic");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "fake-access-conc-candidate"
        );
    }

    // ── PR-C2b tests: enum-variant-driven dispatch ─────────────────────

    #[test]
    fn save_canonical_for_dispatches_to_codex_when_variant_is_codex() {
        // M4-12: save_canonical_for derives write target from CredentialFile
        // variant (PR-C2b). With UUID provisioned, Codex variant writes to
        // UUID-keyed `identities/<UUID>/credentials-codex.json` — NOT to the
        // numeric codex-prefixed canonical (retired in M4-12).
        use crate::accounts::identity_store::credentials_codex_path_for as uuid_codex_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(12);
        let account = AccountNum::try_from(12u16).unwrap();
        let uuid = fixture_uuid_for_slot(12);

        save_canonical_for(dir.path(), account, &sample_codex_creds()).unwrap();

        // UUID-keyed Codex path MUST be written.
        assert!(
            uuid_codex_path(dir.path(), uuid).exists(),
            "Codex variant must write to UUID-keyed identities path"
        );
        // Numeric canonical path MUST NOT be written (M4-12).
        assert!(
            !canonical_path_for(dir.path(), account, Surface::Codex).exists(),
            "Codex variant MUST NOT write to numeric codex-prefixed canonical post-M4-12"
        );
        // ClaudeCode path MUST NOT be written.
        assert!(
            !canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "Codex variant MUST NOT write to ClaudeCode canonical"
        );
    }

    #[test]
    fn save_canonical_for_dispatches_to_anthropic_when_variant_is_anthropic() {
        // Migrated: the Anthropic write path (now the guarded exact-grant
        // commit) writes to UUID-keyed `identities/<UUID>/credentials.json` —
        // NOT to the numeric canonical and NOT to any Codex path.
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = ai_slot(13);
        let uuid = ai_commit(
            base,
            13,
            &ai_credential("dispatch", 1000, None),
            ai_context(20),
        );

        // UUID-keyed Anthropic path MUST be written.
        assert!(
            uuid_creds_path(base, uuid).exists(),
            "Anthropic variant must write to UUID-keyed identities path"
        );
        // Numeric canonical MUST NOT be written (M4-12).
        assert!(
            !canonical_path_for(base, account, Surface::ClaudeCode).exists(),
            "Anthropic variant MUST NOT write to numeric ClaudeCode canonical post-M4-12"
        );
        // Codex path MUST NOT be written.
        assert!(
            !canonical_path_for(base, account, Surface::Codex).exists(),
            "Anthropic variant MUST NOT write to Codex canonical"
        );
    }

    // ── M2-2 acceptance tests ────────────────────────────────────────────

    /// M4-12 / RN1-C acceptance test:
    /// `save_canonical_for` writes ONLY UUID-keyed credentials when UUID present.
    ///
    /// Under `coexisting_fixture(3)`, slot 2 → UUID mapping exists.
    /// After save:
    /// - `identities/<UUID>/credentials.json` MUST exist (UUID-keyed write)
    /// - `credentials/2.json` MUST NOT exist (numeric write retired in M4-12)
    /// - `config-<N>/.credentials.json` MUST NOT be written (M3-7 retirement)
    #[test]
    fn save_canonical_for_writes_uuid_credentials_when_uuid_present() {
        // Migrated: the guarded exact-grant update path writes ONLY the
        // UUID-keyed credentials and never touches the numeric canonical or
        // the live mirror (M3-7).
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = ai_slot(2);
        let initial = ai_credential("uuid-write-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));

        // Capture pre-update mtime of a mirror file so we can assert the
        // canonical write does NOT touch it (M3-7 mirror retirement).
        let live = live_path_for(base, account, Surface::ClaudeCode);
        std::fs::create_dir_all(live.parent().unwrap()).unwrap();
        std::fs::write(&live, b"{}").unwrap();
        let pre_mirror_mtime = std::fs::metadata(&live)
            .ok()
            .and_then(|m| m.modified().ok());
        // Sleep ~10ms so any post-write mtime would be observably newer.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Act: guarded exact-grant update (strictly fresher candidate).
        let candidate = ai_credential("uuid-write-candidate", 2000, None);
        let captured = ai_captured(base, 2);
        assert_eq!(
            ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap(),
            GuardedWriteOutcome::Written
        );

        // Assert: UUID-keyed path exists; numeric canonical NOT written; mirror untouched.
        let uuid_path = uuid_creds_path(base, uuid);
        let numeric_canonical = canonical_path_for(base, account, Surface::ClaudeCode);

        assert!(
            uuid_path.exists(),
            "identities/<UUID>/credentials.json must exist"
        );
        // M4-12: numeric write retired — credentials/N.json MUST NOT be written.
        assert!(
            !numeric_canonical.exists(),
            "credentials/2.json MUST NOT be written post-M4-12 numeric write retirement"
        );
        let post_mirror_mtime = std::fs::metadata(&live)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            pre_mirror_mtime, post_mirror_mtime,
            "M3-7: canonical writes MUST NOT touch config-N/.credentials.json mirror; \
             pre={pre_mirror_mtime:?} post={post_mirror_mtime:?}"
        );

        // Assert: UUID path carries the updated OAuth payload.
        let uuid_loaded = load(&uuid_path).unwrap();
        assert_eq!(
            uuid_loaded
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-uuid-write-candidate",
            "UUID path must carry the updated OAuth payload"
        );
    }

    // ── A2 (migrated): fresher-adopt guard — the TOCTOU semantics now live on
    //    the guarded exact-grant API (`save_anthropic_canonical_guarded`:
    //    Written / NotFresher). The old slot-only API was removed after all
    //    production callers migrated to captured identity authority. ─────────

    #[test]
    fn save_if_fresher_writes_when_strictly_fresher() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("fresher-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);

        let candidate = ai_credential("fresher-candidate", 2000, None);
        let outcome = ai_guarded(base, &captured, &candidate, ai_context(20), Some(1000)).unwrap();

        assert_eq!(
            outcome,
            GuardedWriteOutcome::Written,
            "strictly fresher candidate must be written"
        );
        let loaded = load(&uuid_creds_path(base, uuid)).unwrap();
        assert_eq!(loaded.expect_anthropic().claude_ai_oauth.expires_at, 2000);
    }

    #[test]
    fn save_if_fresher_refuses_when_store_already_fresher() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("stale-store", 2000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);

        // Candidate 1500 ≤ store 2000 → no write (TOCTOU: a concurrent login/refresh
        // wrote a fresher token between harvest and adopt; keep theirs).
        let candidate = ai_credential("stale-candidate", 1500, None);
        let outcome = ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap();

        assert_eq!(
            outcome,
            GuardedWriteOutcome::NotFresher,
            "candidate not fresher than store must be refused"
        );
        let loaded = load(&uuid_creds_path(base, uuid)).unwrap();
        assert_eq!(
            loaded.expect_anthropic().claude_ai_oauth.expires_at,
            2000,
            "store must be left unchanged"
        );
    }

    #[test]
    fn save_if_fresher_refuses_when_not_above_min_exclusive() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("min-initial", 1000, None);
        ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);

        // Candidate 1500, min_exclusive 1500 → 1500 ≤ 1500 → no write (pre-lock baseline).
        let candidate = ai_credential("min-candidate", 1500, None);
        let outcome = ai_guarded(base, &captured, &candidate, ai_context(20), Some(1500)).unwrap();

        assert_eq!(
            outcome,
            GuardedWriteOutcome::NotFresher,
            "candidate not strictly above min_exclusive must be refused"
        );
    }

    #[test]
    fn save_if_fresher_writes_when_store_absent() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("absent-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);
        // Simulate an absent store credential (no token yet for this account).
        let _ = std::fs::remove_file(uuid_creds_path(base, uuid));

        // The production writer for an absent target is the publication-owned
        // login-target path — the guarded API is an UPDATE door by design and
        // (correctly) refuses when there is no current canonical to verify
        // against.
        let candidate = ai_credential("absent-candidate", 1234, None);
        let proof = ai_proof(&candidate, ai_context(20));
        let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
        save_anthropic_login_target_locked(
            &lock,
            base,
            ai_slot(2),
            captured.identity(),
            candidate.anthropic().unwrap(),
            &proof,
            None,
        )
        .unwrap();

        let loaded = load(&uuid_creds_path(base, uuid)).unwrap();
        assert_eq!(loaded.expect_anthropic().claude_ai_oauth.expires_at, 1234);
    }

    /// R3 corr M-3 (post-hand-over arm): once the caller hands its pre-lock
    /// record to the publication, a DELIBERATE refusal must remove it —
    /// otherwise adoption installs a grant the publication refused.
    ///
    /// RED on the pre-fix hand-over code: the early refusal returned without
    /// touching the record, the handle dropped (releasing the writer lock),
    /// and `record_path.exists()` stayed true.
    #[test]
    fn login_publication_removes_its_prelock_record_on_a_deliberate_refusal() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("prelock-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let candidate = ai_credential("prelock-candidate", 2000, None);
        let proof = ai_proof(&candidate, ai_context(20));
        // The directory must exist for the pre-lock record to be written.
        assert!(uuid_creds_path(base, uuid).exists());

        let record = write_login_prelock_rescue(base, uuid, candidate.anthropic().unwrap(), &proof)
            .expect("the pre-lock record must be written for an existing identity");
        let record_path = record.path.clone();
        assert!(record_path.exists());

        // A lock on a DIFFERENT root: the first gate refuses this publication
        // deliberately (namespace mismatch), before any version check.
        let other = TempDir::new().unwrap();
        let foreign_lock =
            crate::accounts::profiles_lock::ProfilesFileLock::acquire(other.path()).unwrap();
        let result = save_anthropic_login_target_locked(
            &foreign_lock,
            base,
            ai_slot(2),
            uuid,
            candidate.anthropic().unwrap(),
            &proof,
            Some(record),
        );
        assert!(result.is_err(), "a foreign-root lock must be refused");
        assert!(
            !record_path.exists(),
            "a deliberate refusal must remove the handed pre-lock record"
        );
    }

    #[test]
    fn save_if_fresher_refuses_when_store_is_non_anthropic() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("nonanth-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);
        // Stage a NON-Anthropic (Codex-shaped) credential at the Anthropic store path.
        let p = uuid_creds_path(base, uuid);
        save(&p, &sample_codex_creds()).unwrap();

        // Fail-closed: a non-Anthropic store is NOT clobbered, even by a fresher token.
        let candidate = ai_credential("nonanth-candidate", 9999, None);
        let result = ai_guarded(base, &captured, &candidate, ai_context(20), None);

        assert!(
            result.is_err(),
            "non-Anthropic store must not be clobbered (fail-closed)"
        );
        assert!(
            load(&p).unwrap().codex().is_some(),
            "store still Codex-shaped"
        );
    }

    #[test]
    fn save_if_fresher_refuses_when_store_is_corrupt() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("corrupt-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);
        // Stage a corrupt (unparseable) store file.
        let p = uuid_creds_path(base, uuid);
        std::fs::write(&p, b"{ this is not valid json").unwrap();
        let corrupt_bytes = std::fs::read(&p).unwrap();

        // Fail-closed: an unreadable/corrupt store is NOT overwritten on doubt.
        let candidate = ai_credential("corrupt-candidate", 9999, None);
        let result = ai_guarded(base, &captured, &candidate, ai_context(20), None);

        assert!(
            result.is_err(),
            "corrupt store must not be overwritten (fail-closed)"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            corrupt_bytes,
            "corrupt store bytes must be left untouched"
        );
    }

    /// M4-12 / RN1-C acceptance test:
    /// `save_canonical_for` fails-CLOSED when UUID is absent (Finding 1.1 fix).
    ///
    /// Under `legacy_only_fixture(3)`, there is no `profiles.json` `by_slot`
    /// mapping. M4-12 converts the prior graceful-skip (which silently wrote
    /// nothing post-M4-12 after removing the numeric write) into a hard error.
    /// This prevents silent data loss when the UUID is not yet provisioned.
    #[test]
    fn save_canonical_for_fails_closed_when_uuid_absent_claude_code() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange
        let dir = legacy_only_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();

        // Act — MUST fail-closed (M4-12 Finding 1.1 fix)
        let result = save_canonical_for(base, account, &sample_creds());
        assert!(
            result.is_err(),
            "save_canonical_for MUST fail-closed when UUID is absent (M4-12)"
        );

        // Assert: numeric canonical NOT written; no identities dir created.
        assert!(
            !canonical_path_for(base, account, Surface::ClaudeCode).exists(),
            "credentials/N.json MUST NOT be written post-M4-12 numeric write retirement"
        );
        assert!(
            !base.join("identities").exists(),
            "identities/ must NOT be created when UUID is absent (fail-closed, not graceful skip)"
        );
    }

    /// Criterion 3: `save_canonical_for` preserves `subscription_type` on UUID path.
    ///
    /// This is THE regression test for FM-1.1 (Max-tier-loss bug):
    /// - First write: credentials carry `subscription_type: Some("max")`
    /// - Second write (simulated OAuth refresh): `subscription_type: None`
    /// - Assert: `identities/<UUID>/credentials.json` still carries `"max"`
    #[test]
    fn save_canonical_for_preserves_subscription_type_on_uuid_path() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("sub-initial", 1000, Some("max"));
        let uuid = ai_commit(base, 2, &initial, ai_context(20));

        // Verify: first write landed "max"
        let uuid_path = uuid_creds_path(base, uuid);
        let after_first = load(&uuid_path).unwrap();
        assert_eq!(
            after_first
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max"),
            "first write must persist subscription_type: max"
        );

        // Second write: simulate a fresh OAuth response — subscription_type is None
        // (Anthropic's token endpoint does not return subscription_type).
        // Strictly fresher (2000 > 1000) so the guarded write proceeds.
        let candidate = ai_credential("sub-refreshed", 2000, None);

        // Act: guarded exact-grant update (the one that must preserve subscription_type)
        let captured = ai_captured(base, 2);
        assert_eq!(
            ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap(),
            GuardedWriteOutcome::Written
        );

        // Assert: UUID path retains "max" even though second write had None
        let after_second = load(&uuid_path).unwrap();
        assert_eq!(
            after_second
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max"),
            "FM-1.1 regression: UUID path must preserve subscription_type: max \
             when OAuth refresh carries None"
        );
        // Also verify the refreshed access token DID land (we wrote something)
        assert_eq!(
            after_second
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-sub-refreshed",
            "access_token must be updated (proving the second write ran)"
        );
    }

    /// Criterion 4: concurrent UUID writers are serialized by `AccountMutexTable`.
    ///
    /// Two threads write for the same account → AccountMutexTable serializes;
    /// final files are valid (no torn write). The test does NOT assert which
    /// thread's data wins — only that the result is valid, complete JSON.
    #[test]
    fn save_canonical_for_concurrent_uuid_writers_serialized() {
        // Migrated: guarded exact-grant writers under concurrency. The test does
        // NOT assert which thread's grant wins — only that every outcome is a
        // clean GuardedWriteOutcome and the final file is valid, complete JSON.
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use std::sync::Arc;
        use std::thread;

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = Arc::new(dir.path().to_path_buf());
        let account = ai_slot(2);
        let initial = ai_credential("conc2-initial", 1000, None);
        ai_commit(&base, 2, &initial, ai_context(20));
        let candidate = ai_credential("conc2-candidate", 2000, None);

        // Act: 8 concurrent writers for the same account
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let base = Arc::clone(&base);
                let candidate = candidate.clone();
                thread::spawn(move || {
                    match crate::accounts::anthropic_identity::capture_anthropic_binding(
                        &base, account,
                    ) {
                        Ok(captured) => {
                            ai_guarded(&base, &captured, &candidate, ai_context(20), None)
                        }
                        Err(_) => Ok(GuardedWriteOutcome::BindingChanged),
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("concurrent write must not error");
        }

        // Assert: UUID path is parseable and carries the candidate (no torn write)
        let uuid_path = uuid_creds_path(&base, ai_captured(&base, 2).identity());
        let loaded = load(&uuid_path).expect("UUID path must parse after concurrent writes");
        assert_eq!(
            loaded
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-conc2-candidate",
            "UUID path must carry the candidate access_token after concurrent writes"
        );
    }

    /// Criterion 3b: fail-closed — if UUID write fails, legacy writes are aborted.
    ///
    /// Forces the UUID tmp write to fail by pre-creating the UUID credentials path
    /// as a DIRECTORY. `std::fs::write` on a directory path returns `EISDIR`,
    /// causing `write_uuid_credentials_inner` to return `Err` and
    /// `save_canonical_for` to abort before the legacy writes.
    ///
    /// This is the SEC-2.7 fail-closed invariant: identity write failure halts
    /// the entire operation; the legacy paths are NOT written as a fallback.
    #[test]
    fn save_canonical_for_uuid_write_fails_aborts_legacy_write() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;

        // Arrange: a committed identity, then obstruct the identity directory
        // by replacing it with a FILE. `require_identity_directory` (the
        // guarded pre-write check) refuses — and the retired legacy paths must
        // NOT be written as a fallback (SEC-2.7 fail-closed).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = ai_slot(2);
        let initial = ai_credential("abort-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);

        let uuid_path = uuid_creds_path(base, uuid);
        let identity_dir = uuid_path.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&identity_dir).unwrap();
        std::fs::write(&identity_dir, b"obstruction").unwrap();

        // Act: must fail — the identity store is obstructed
        let candidate = ai_credential("abort-candidate", 9999, None);
        let result = ai_guarded(base, &captured, &candidate, ai_context(20), None);

        // Assert: the call must have returned Err (fail-closed)
        assert!(
            result.is_err(),
            "fail-closed: a guarded write must return Err when the identity store is \
             obstructed; got Ok() — fail-closed invariant is broken"
        );

        // Assert: legacy canonical was NOT written (identity FIRST, abort on failure)
        assert!(
            !canonical_path_for(base, account, Surface::ClaudeCode).exists(),
            "fail-closed: credentials/2.json must NOT be written when the UUID write fails"
        );

        // UUID path (inside what is now a file-as-dir) cannot exist.
        assert!(
            !uuid_path.exists(),
            "fail-closed: identities/<UUID>/credentials.json must not exist after failed write"
        );
    }

    /// Unit test: `preserve_subscription_metadata` preserves `subscription_type`
    /// from an existing file when the incoming credentials have `None`.
    ///
    /// This tests the FM-1.1 guard in isolation — the helper function itself.
    #[test]
    fn preserve_subscription_metadata_preserves_existing_type() {
        // Arrange: write an existing credentials.json with subscription_type = Some("max")
        let dir = tempfile::TempDir::new().unwrap();
        let existing_path = dir.path().join("credentials.json");

        let existing = {
            let mut c = sample_creds();
            c.expect_anthropic_mut().claude_ai_oauth.subscription_type = Some("max".into());
            c.expect_anthropic_mut().claude_ai_oauth.rate_limit_tier = Some("h".into());
            c
        };
        save(&existing_path, &existing).unwrap();

        // Arrange: incoming credentials simulate a fresh OAuth response with None
        let incoming = {
            let mut c = sample_creds();
            c.expect_anthropic_mut().claude_ai_oauth.subscription_type = None;
            c.expect_anthropic_mut().claude_ai_oauth.rate_limit_tier = None;
            c
        };

        // Act
        let preserved = preserve_subscription_metadata(&incoming, &existing_path);

        // Assert: helper backfilled from existing file
        assert_eq!(
            preserved
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max"),
            "preserve_subscription_metadata must backfill subscription_type from existing file"
        );
        assert_eq!(
            preserved
                .expect_anthropic()
                .claude_ai_oauth
                .rate_limit_tier
                .as_deref(),
            Some("h"),
            "preserve_subscription_metadata must backfill rate_limit_tier from existing file"
        );
    }

    /// Unit test: `preserve_subscription_metadata` keeps the INCOMING value
    /// when both incoming and existing carry `subscription_type`.
    ///
    /// If the OAuth endpoint DID return a `subscription_type` (e.g. after a
    /// plan upgrade), the incoming value wins — we do NOT clobber it with the
    /// existing file's older value.
    #[test]
    fn preserve_subscription_metadata_keeps_incoming_when_both_present() {
        // Arrange: existing file has "standard"
        let dir = tempfile::TempDir::new().unwrap();
        let existing_path = dir.path().join("credentials.json");

        let existing = {
            let mut c = sample_creds();
            c.expect_anthropic_mut().claude_ai_oauth.subscription_type = Some("standard".into());
            c
        };
        save(&existing_path, &existing).unwrap();

        // Arrange: incoming has "max" (e.g. user just upgraded plan)
        let incoming = {
            let mut c = sample_creds();
            c.expect_anthropic_mut().claude_ai_oauth.subscription_type = Some("max".into());
            c
        };

        // Act
        let result = preserve_subscription_metadata(&incoming, &existing_path);

        // Assert: incoming value is preserved, NOT overwritten by existing "standard"
        assert_eq!(
            result
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max"),
            "preserve_subscription_metadata must keep incoming subscription_type when present"
        );
    }

    /// Criterion 5: `identities/<UUID>/credentials.json` has 0o600 permissions.
    #[cfg(unix)]
    #[test]
    fn save_canonical_for_uuid_path_at_0o600_post_secure_file() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use std::os::unix::fs::PermissionsExt;

        // Arrange: committed identity on the exact-grant door
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("file-mode-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));

        // Act: guarded exact-grant update (the production Anthropic write path)
        let captured = ai_captured(base, 2);
        let candidate = ai_credential("file-mode-candidate", 2000, None);
        assert_eq!(
            ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap(),
            GuardedWriteOutcome::Written
        );

        // Assert: UUID-path credentials.json is 0o600
        let uuid_path = uuid_creds_path(base, uuid);
        let mode = std::fs::metadata(&uuid_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "identities/<UUID>/credentials.json must be 0o600 after write"
        );
    }

    /// MED-1 regression: `identities/<UUID>/` directory is 0o700 after write.
    ///
    /// SEC-2.15 Phase 2 trust-boundary: the enclosing directory MUST be
    /// owner-only so other users cannot enumerate credential filenames inside,
    /// even though the credential file itself is 0o600.
    #[cfg(unix)]
    #[test]
    fn save_uuid_credentials_identity_dir_at_0o700() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use std::os::unix::fs::PermissionsExt;

        // Arrange: committed identity, then a guarded exact-grant update (the
        // production Anthropic write path)
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("dir-mode-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));

        let captured = ai_captured(base, 2);
        let candidate = ai_credential("dir-mode-candidate", 2000, None);
        assert_eq!(
            ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap(),
            GuardedWriteOutcome::Written
        );

        // Assert: identities/<UUID>/ directory is 0o700
        let uuid_path = uuid_creds_path(base, uuid);
        let uuid_dir = uuid_path.parent().unwrap();
        let mode = std::fs::metadata(uuid_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "MED-1: identities/<UUID>/ must be 0o700 after write; got 0o{mode:03o}"
        );
    }

    /// `keychain-fix-r11.md` D-5: `save_uuid_credentials` MUST refuse to
    /// recreate an identity dir `csq logout` removed — simulated here by
    /// writing the tombstone directly (`mark_identity_removed`), the exact
    /// state `logout_account` leaves behind, without needing a real
    /// concurrent race. A refresher tick or custodian adopt racing a genuine
    /// logout would otherwise silently resurrect the credential.
    ///
    /// RED: dropping the `is_identity_removed` check in
    /// `save_uuid_credentials` makes this assertion fail — the write
    /// succeeds and recreates the identity dir instead of refusing.
    #[cfg(unix)]
    #[test]
    fn save_uuid_credentials_refuses_a_removed_identity() {
        use crate::accounts::identity_store::{
            credentials_path_for as uuid_creds_path, mark_identity_removed,
        };

        // Branch A: identity dir INTACT, tombstoned — the guard must refuse
        // through the production guarded door before any I/O.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("removed-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let uuid_path = uuid_creds_path(base, uuid);
        let identity_dir = uuid_path.parent().unwrap().to_path_buf();
        let captured = ai_captured(base, 2);
        mark_identity_removed(base, uuid);
        assert!(identity_dir.exists(), "branch-A precondition: dir intact");

        let candidate = ai_credential("removed-candidate", 2000, None);
        let result = ai_guarded(base, &captured, &candidate, ai_context(20), None);
        assert!(
            matches!(result, Err(CredentialError::IdentityRemoved { .. })),
            "a canonical write for a removed identity must be refused, got {result:?}"
        );
        assert!(
            identity_dir.exists(),
            "branch A must not disturb the identity dir"
        );

        // Branch B: exactly what `logout_account` leaves behind — the identity
        // dir REMOVED, the tombstone written. The chokepoint must refuse and
        // must NOT recreate the dir (resurrecting a logged-out credential).
        let dir_b = TempDir::new().unwrap();
        let base_b = dir_b.path();
        let initial_b = ai_credential("removed-b-initial", 1000, None);
        let uuid_b = ai_commit(base_b, 2, &initial_b, ai_context(20));
        let uuid_path_b = uuid_creds_path(base_b, uuid_b);
        let identity_dir_b = uuid_path_b.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&identity_dir_b).unwrap();
        mark_identity_removed(base_b, uuid_b);
        assert!(!identity_dir_b.exists(), "branch-B precondition");

        let result_b = save_uuid_credentials(
            base_b,
            uuid_b,
            &ai_credential("removed-b-candidate", 5000, None),
        );
        assert!(
            matches!(result_b, Err(CredentialError::IdentityRemoved { .. })),
            "a write for a removed identity must be refused, got {result_b:?}"
        );
        assert!(
            !identity_dir_b.exists(),
            "the refusal must not recreate the identity dir — resurrecting a \
             logged-out credential"
        );
    }

    /// R2-M1: the lineage writer's non-creating write refuses to recreate a
    /// missing identity dir EVEN when no tombstone exists yet (logout order:
    /// the writer may observe the dir gone before the marker is visible).
    #[test]
    fn save_uuid_credentials_existing_dir_never_creates_the_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();
        let identity_dir = credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(!identity_dir.exists());
        let result =
            save_uuid_credentials_existing_dir(base, uuid, &ai_credential("no-dir", 5000, None));
        assert!(
            matches!(result, Err(CredentialError::IdentityRemoved { .. })),
            "got {result:?}"
        );
        assert!(!identity_dir.exists(), "must not recreate the identity dir");
    }

    /// Sibling of the refusal test: a FRESH login for the SAME uuid clears
    /// the tombstone (`clear_identity_removed_marker`), which is what
    /// the verified login commit (`accounts::anthropic_identity::commit_anthropic_login`) does under the profiles lock
    /// — after clearing, the canonical write proceeds normally.
    #[cfg(unix)]
    #[test]
    fn save_uuid_credentials_proceeds_after_tombstone_cleared() {
        use crate::accounts::identity_store::{
            clear_identity_removed_marker, credentials_path_for as uuid_creds_path,
            mark_identity_removed,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("cleared-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let uuid_path = uuid_creds_path(base, uuid);
        let identity_dir = uuid_path.parent().unwrap().to_path_buf();

        std::fs::remove_dir_all(&identity_dir).unwrap();
        mark_identity_removed(base, uuid);
        clear_identity_removed_marker(base, uuid);

        let candidate = ai_credential("cleared-candidate", 3000, None);
        let result = save_uuid_credentials(base, uuid, &candidate);

        assert!(
            result.is_ok(),
            "a cleared tombstone must unblock the canonical write, got {result:?}"
        );
        assert!(
            identity_dir.exists(),
            "the write must legitimately (re)create the identity dir once the \
             tombstone is cleared — a fresh login is not a resurrection"
        );
        assert!(
            uuid_path.exists(),
            "the credential file must be present after the unblocked write"
        );
    }

    /// `keychain-fix-r8.md` C-F1 (PRIMARY DIRECTIVE) — writer-level proof that
    /// `save_uuid_credentials` is a chokepoint for `token_history::record_write`:
    /// every canonical-store write appends the written token's fingerprint to
    /// `identities/<UUID>/token-history`. This is the assertion `decide_rule2_*`
    /// in `keychain.rs` depends on being true in production — those tests
    /// exercise the pure decision function directly against a hand-built
    /// history, so only THIS test proves the history is actually populated by
    /// the real write path rather than merely by test fixtures.
    #[test]
    fn save_canonical_for_appends_token_history() {
        use crate::credentials::token_history::{
            fingerprint_from_credential_file, read_history_for_slot,
        };

        // Arrange: a fake authenticated commit (the first canonical write)
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = ai_slot(2);
        let initial = ai_credential("hist-initial", 1000, None);
        ai_commit(base, 2, &initial, ai_context(20));

        // Act: a guarded exact-grant update (the second canonical write)
        let captured = ai_captured(base, 2);
        let candidate = ai_credential("hist-candidate", 2000, None);
        assert_eq!(
            ai_guarded(base, &captured, &candidate, ai_context(20), None).unwrap(),
            GuardedWriteOutcome::Written
        );

        // Assert: each canonical write appended the written token's fingerprint
        // (newest last).
        let history = read_history_for_slot(base, account);
        assert_eq!(
            history.len(),
            2,
            "each canonical write must append exactly one history entry"
        );
        let first_fp = fingerprint_from_credential_file(&initial)
            .expect("initial is Anthropic and has a refresh token");
        let second_fp = fingerprint_from_credential_file(&candidate)
            .expect("candidate is Anthropic and has a refresh token");
        assert_eq!(
            history[0], first_fp,
            "the first appended fingerprint must match the token actually written first"
        );
        assert_eq!(
            history[1], second_fp,
            "the second appended fingerprint must match the token actually written second"
        );
    }

    /// Criterion 6: §5a — tmp cleanup on `write` failure.
    ///
    /// Uses closure injection per PRIMARY METHODOLOGICAL DIRECTIVE in
    /// `redteam-discipline.md` Rule 5. The `write_fn` closure is injected
    /// to fail; `secure_fn` and `replace_fn` would succeed if reached.
    /// After the failure, no `*.tmp.*` file may remain under the parent dir.
    #[test]
    fn save_canonical_for_uuid_write_tmp_cleanup_on_write_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials.json");
        // Use a fixed tmp name (not the platform helper) so this test doesn't add
        // to the §5a audit count — this is test scaffolding, not a secret write site.
        let tmp = dir.path().join("credentials.json.test-tmp-write");

        let result = write_uuid_credentials_inner(
            &tmp,
            &final_path,
            b"{\"test\":1}",
            // write_fn: always fails
            |_p, _b| Err(std::io::Error::other("injected write failure")),
            // secure_fn: would succeed (never reached)
            |_p| Ok(()),
            // replace_fn: would succeed (never reached)
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected write failure must propagate as Err"
        );
        // Assert: tmp file was not left behind
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after write_fn failure; path: {tmp:?}"
        );
    }

    /// Criterion 7: §5a — tmp cleanup on `secure_file` failure.
    ///
    /// The `write_fn` succeeds (creating the tmp file), then `secure_fn` is
    /// injected to fail. After the failure, the tmp file must be removed.
    #[test]
    fn save_canonical_for_uuid_write_tmp_cleanup_on_secure_file_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials.json");
        // Fixed tmp name for the same reason as the write-failure test.
        let tmp = dir.path().join("credentials.json.test-tmp-secure");

        let result = write_uuid_credentials_inner(
            &tmp,
            &final_path,
            b"{\"test\":2}",
            // write_fn: succeeds (creates tmp file)
            |p, b| std::fs::write(p, b),
            // secure_fn: always fails
            |_p| Err(std::io::Error::other("injected secure_file failure")),
            // replace_fn: would succeed (never reached)
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected secure_fn failure must propagate as Err"
        );
        // Assert: tmp file was removed (§5a cleanup)
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after secure_fn failure; path: {tmp:?}"
        );
    }

    /// Criterion 8: §5a — tmp cleanup on `atomic_replace` failure.
    ///
    /// Both `write_fn` and `secure_fn` succeed. `replace_fn` is injected to
    /// fail. After the failure, the tmp file must be removed.
    #[test]
    fn save_canonical_for_uuid_write_tmp_cleanup_on_atomic_replace_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials.json");
        // Fixed tmp name for the same reason as the write-failure test.
        let tmp = dir.path().join("credentials.json.test-tmp-replace");

        let result = write_uuid_credentials_inner(
            &tmp,
            &final_path,
            b"{\"test\":3}",
            // write_fn: succeeds
            |p, b| std::fs::write(p, b),
            // secure_fn: succeeds (no-op — permissions are non-essential for this test)
            |_p| Ok(()),
            // replace_fn: always fails
            |_t, _f| Err(std::io::Error::other("injected atomic_replace failure")),
        );

        assert!(
            result.is_err(),
            "injected replace_fn failure must propagate as Err"
        );
        // Assert: tmp file was removed (§5a cleanup)
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after replace_fn failure; path: {tmp:?}"
        );
    }

    // ── M4-2 §5a closure-injection tests ─────────────────────────────────────
    //
    // These tests verify the partial-failure cleanup contract of
    // `save_uuid_settings_inner` (renamed from `write_uuid_settings_inner`
    // in M4-2). Three distinct closures, three distinct failure branches,
    // three distinct tests — same shape as M4-1's
    // `save_codex_canonical_for_uuid_cleans_tmp_on_*` triple.

    /// M4-2 Criterion: §5a — `save_uuid_settings_inner` cleans up tmp on write_fn failure.
    ///
    /// `write_fn` is injected to fail after creating the tmp file. After failure,
    /// the tmp file must be absent (§5a partial-failure cleanup).
    #[test]
    fn save_uuid_settings_cleans_tmp_on_write_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("settings.json");
        let tmp = dir.path().join("settings.json.test-tmp-write");

        let result = save_uuid_settings_inner(
            &tmp,
            &final_path,
            b"{\"key\":1}",
            // write_fn: creates tmp then fails
            |p, b| {
                std::fs::write(p, b)?; // actually writes the file first
                Err(std::io::Error::other("injected write_fn failure"))
            },
            // secure_fn: never reached
            |_p| Ok(()),
            // replace_fn: never reached
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected write_fn failure must propagate as Err"
        );
        // §5a: tmp must be gone
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after write_fn failure; path: {tmp:?}"
        );
    }

    /// M4-2 Criterion: §5a — `save_uuid_settings_inner` cleans up tmp on secure_fn failure.
    ///
    /// `write_fn` succeeds (tmp file exists). `secure_fn` fails. After failure,
    /// the tmp file must be absent (§5a partial-failure cleanup).
    #[test]
    fn save_uuid_settings_cleans_tmp_on_secure_file_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("settings.json");
        let tmp = dir.path().join("settings.json.test-tmp-secure");

        let result = save_uuid_settings_inner(
            &tmp,
            &final_path,
            b"{\"key\":2}",
            // write_fn: succeeds
            |p, b| std::fs::write(p, b),
            // secure_fn: fails
            |_p| Err(std::io::Error::other("injected secure_fn failure")),
            // replace_fn: never reached
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected secure_fn failure must propagate as Err"
        );
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after secure_fn failure; path: {tmp:?}"
        );
    }

    /// M4-2 Criterion: §5a — `save_uuid_settings_inner` cleans up tmp on replace_fn failure.
    ///
    /// `write_fn` and `secure_fn` succeed. `replace_fn` fails. After failure,
    /// the tmp file must be absent (§5a partial-failure cleanup).
    #[test]
    fn save_uuid_settings_cleans_tmp_on_atomic_replace_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("settings.json");
        let tmp = dir.path().join("settings.json.test-tmp-replace");

        let result = save_uuid_settings_inner(
            &tmp,
            &final_path,
            b"{\"key\":3}",
            // write_fn: succeeds
            |p, b| std::fs::write(p, b),
            // secure_fn: succeeds (no-op)
            |_p| Ok(()),
            // replace_fn: fails
            |_t, _f| Err(std::io::Error::other("injected replace_fn failure")),
        );

        assert!(
            result.is_err(),
            "injected replace_fn failure must propagate as Err"
        );
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after replace_fn failure; path: {tmp:?}"
        );
    }

    // ── M4-1 acceptance tests ────────────────────────────────────────────────

    /// M4-12 (RN1-C): when a UUID mapping exists for the slot,
    /// `save_canonical_for` with a Codex variant writes ONLY
    /// `identities/<UUID>/credentials-codex.json`.
    ///
    /// The numeric legacy path `credentials/codex-<N>.json` is
    /// fully retired as a write target (Finding 1.1 fix). Only the
    /// UUID-keyed identity path is written.
    ///
    /// (Previously this test was named `save_canonical_for_codex_writes_identity_path_first`
    /// and verified M4-1 dual-write; updated by RN1-C to verify single-write.)
    #[test]
    fn save_canonical_for_codex_writes_only_uuid_path_m4_12() {
        use crate::accounts::identity_store::credentials_codex_path_for as uuid_codex_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Act: Codex variant write through the surface-dispatch chokepoint.
        save_canonical_for(base, account, &sample_codex_creds()).unwrap();

        // Assert: UUID-keyed identity path exists.
        let uuid_path = uuid_codex_path(base, uuid);
        assert!(
            uuid_path.exists(),
            "M4-12: identities/<UUID>/credentials-codex.json must exist; path: {uuid_path:?}"
        );

        // Assert: M4-12 — numeric legacy canonical NOT written.
        let legacy = canonical_path_for(base, account, Surface::Codex);
        assert!(
            !legacy.exists(),
            "M4-12: credentials/codex-2.json (numeric path) must NOT be written post-M4-12"
        );

        // Assert: UUID-keyed file round-trips as Codex variant.
        let uuid_loaded = load(&uuid_path).unwrap();
        let uuid_codex = uuid_loaded
            .codex()
            .expect("UUID file must be Codex variant");
        assert_eq!(
            uuid_codex.tokens.access_token,
            sample_codex_creds().codex().unwrap().tokens.access_token,
            "UUID path must carry the expected access_token bytes"
        );
    }

    /// M4-1 Criterion (a)#2: identity-write failure aborts the legacy write
    /// (SEC-2.7 fail-closed). Forces the identity-write to fail by replacing
    /// `identities/<UUID>/` with a regular FILE — `create_dir_all` returns
    /// ENOTDIR on that path, propagating through `save_codex_canonical_for_uuid`.
    /// `save_canonical_for` MUST return Err and MUST NOT have written the
    /// legacy canonical.
    #[test]
    fn save_canonical_for_codex_uuid_failure_fails_closed() {
        use crate::accounts::identity_store::credentials_codex_path_for as uuid_codex_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Obstruct: replace identities/<UUID>/ with a regular file so
        // `create_dir_all(identities/<UUID>)` returns ENOTDIR.
        let identity_dir = base.join("identities").join(uuid.to_string());
        if identity_dir.exists() {
            std::fs::remove_dir_all(&identity_dir).unwrap();
        } else {
            std::fs::create_dir_all(base.join("identities")).unwrap();
        }
        std::fs::write(&identity_dir, b"obstruction").unwrap();

        // Act: identity-write must fail; legacy write must not run.
        let result = save_canonical_for(base, account, &sample_codex_creds());

        // Assert: fail-closed Err propagation.
        assert!(
            result.is_err(),
            "fail-closed: save_canonical_for must return Err when Codex UUID write fails"
        );

        // Assert: legacy canonical was NOT written (identity FIRST, abort on failure).
        assert!(
            !canonical_path_for(base, account, Surface::Codex).exists(),
            "fail-closed: credentials/codex-2.json must NOT be written when UUID write fails"
        );

        // Assert: UUID-keyed credentials-codex.json cannot exist either
        // (its parent is a file, not a dir).
        let uuid_path = uuid_codex_path(base, uuid);
        assert!(
            !uuid_path.exists(),
            "fail-closed: identities/<UUID>/credentials-codex.json must not exist after failed write"
        );
    }

    /// M4-12 (RN1-C): fail-closed when no UUID mapping exists (legacy layout).
    ///
    /// Pre-M4-12 (M4-1 Criterion a#3) this was a graceful-skip — the legacy
    /// `credentials/codex-<N>.json` was still written and `Ok(())` returned.
    /// Post-M4-12 (Finding 1.1 fix): absent UUID is a hard error. The daemon
    /// Pass 0 identity mint (M1-4) guarantees UUIDs exist for every
    /// authenticated account before any credential write reaches this function.
    /// Fail-closed surfaces the structural gap instead of silently writing nothing.
    #[test]
    fn save_canonical_for_codex_fails_closed_without_uuid_m4_12() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy-only layout — no profiles.json by_slot mapping.
        let dir = legacy_only_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();

        // Act: must fail-closed (Finding 1.1 fix).
        let result = save_canonical_for(base, account, &sample_codex_creds());
        assert!(
            result.is_err(),
            "M4-12: save_canonical_for must return Err when no UUID mapping exists for Codex"
        );

        // Assert: no legacy canonical written (fail-closed — no partial write).
        assert!(
            !canonical_path_for(base, account, Surface::Codex).exists(),
            "M4-12: credentials/codex-2.json must NOT be written when UUID absent"
        );

        // Assert: no identities/ dir created.
        assert!(
            !base.join("identities").exists(),
            "identities/ must NOT be created when UUID is absent"
        );
    }

    /// M4-1 Criterion (a)#4: subscription-metadata preservation at the new
    /// Codex UUID write site.
    ///
    /// Codex variants have no `subscription_type` / `rate_limit_tier`, so
    /// `preserve_subscription_metadata` is a no-op on the variant. The test
    /// exercises the structural call-site contract: `save_codex_canonical_for_uuid`
    /// invokes the preservation helper, which short-circuits on Codex variants
    /// without panicking, and the resulting on-disk file round-trips as a
    /// well-formed Codex credential with the incoming access_token preserved.
    ///
    /// This guards against a future regression that hooks
    /// `save_codex_canonical_for_uuid` directly to the inner writer, bypassing
    /// the `preserve_subscription_metadata` call site — at which point a
    /// future enhancement adding Codex-shape preservation (e.g. preserving
    /// `last_refresh` for downgrade safety) would silently land without
    /// effect.
    #[test]
    fn save_codex_canonical_for_uuid_preserves_subscription_type() {
        use crate::accounts::identity_store::credentials_codex_path_for as uuid_codex_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // First write: establishes the on-disk identity file.
        save_codex_canonical_for_uuid(base, uuid, &sample_codex_creds()).unwrap();

        // Verify first write landed as well-formed Codex variant.
        let uuid_path = uuid_codex_path(base, uuid);
        let first = load(&uuid_path).unwrap();
        assert!(
            first.codex().is_some(),
            "first write must persist as Codex variant"
        );
        assert_eq!(
            first.codex().unwrap().tokens.access_token,
            "eyJhbGciOiJIUzI1NiJ9.test-at.sig",
            "first write must persist incoming access_token"
        );

        // Second write: simulate a refresh — different access_token, same
        // variant. The preservation helper invokes (no-op for Codex), and
        // the new token must land.
        let refreshed = {
            let mut c = sample_codex_creds();
            c.codex_mut().unwrap().tokens.access_token =
                "eyJhbGciOiJIUzI1NiJ9.refreshed-at.sig".into();
            c
        };
        save_codex_canonical_for_uuid(base, uuid, &refreshed).unwrap();

        // Assert: refreshed access_token landed; file remains well-formed Codex.
        let second = load(&uuid_path).unwrap();
        let second_codex = second
            .codex()
            .expect("second write must persist as Codex variant");
        assert_eq!(
            second_codex.tokens.access_token, "eyJhbGciOiJIUzI1NiJ9.refreshed-at.sig",
            "refreshed access_token must be persisted (preservation guard must \
             not block the write of fresh tokens for Codex)"
        );
    }

    #[test]
    fn save_codex_canonical_for_uuid_refuses_tombstone_without_overwriting() {
        use crate::accounts::identity_store::mark_identity_removed;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);
        let initial = sample_codex_creds();
        save_codex_canonical_for_uuid(base, uuid, &initial).unwrap();
        let path = credentials_codex_path_for(base, uuid);
        let before = std::fs::read(&path).unwrap();
        let mut rotated = initial;
        rotated.codex_mut().unwrap().tokens.refresh_token = Some("fake-removed-refresh".into());
        mark_identity_removed(base, uuid);
        assert!(is_identity_removed(base, uuid));
        let result = save_codex_canonical_for_uuid(base, uuid, &rotated);
        assert!(
            matches!(result, Err(CredentialError::IdentityRemoved { .. })),
            "got {result:?}"
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    // Unix locks open a file; Windows named mutexes cannot be failed by this fixture.
    #[cfg(unix)]
    #[test]
    fn save_codex_canonical_lock_error_is_typed_and_preserves_credentials() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        let dir = coexisting_fixture(3);
        let uuid = fixture_uuid_for_slot(2);
        save_codex_canonical_for_uuid(dir.path(), uuid, &sample_codex_creds()).unwrap();
        let path = credentials_codex_path_for(dir.path(), uuid);
        let before = std::fs::read(&path).unwrap();
        let lock = credentials_path_for(dir.path(), uuid).with_extension("lock");
        if lock.exists() {
            std::fs::remove_file(&lock).unwrap();
        }
        std::fs::create_dir(&lock).unwrap();
        let expected_kind = match crate::platform::lock::lock_file(&lock).unwrap_err() {
            crate::error::PlatformError::Io(source) => source.kind(),
            error => panic!("directory fixture must fail the Unix file open: {error:?}"),
        };
        let error =
            save_codex_canonical_for_uuid(dir.path(), uuid, &sample_codex_creds()).unwrap_err();
        assert!(
            matches!(&error, CredentialError::CanonicalLockRefused { path, io_kind }
            if *path == lock && *io_kind == expected_kind),
            "lock I/O cause must remain typed: {error:?}"
        );
        assert_eq!(error.error_kind_tag(), "credentials_canonical_lock_refused");
        let message = error.redacted_message();
        assert!(message.contains("permissions and its parent directory"));
        assert!(!message.contains("corrupt"));
        assert!(!message.contains(&dir.path().display().to_string()));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    /// A wedged holder must not block the credential write forever: the
    /// bounded acquisition expires, the writer fails closed with the typed
    /// canonical-lock refusal, and the credential file is untouched.
    ///
    /// Unix-only for the same reason as the lock-error test above: Windows
    /// named mutexes are re-entrant per thread, so a same-thread holder is
    /// not contention there. The cross-fd bound itself is Unix/Linux/Windows
    /// covered by `lock_credential_file`'s unit test.
    #[cfg(unix)]
    #[test]
    fn save_codex_canonical_bounded_lock_expiry_fails_closed_without_writing() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        let dir = coexisting_fixture(3);
        let uuid = fixture_uuid_for_slot(2);
        save_codex_canonical_for_uuid(dir.path(), uuid, &sample_codex_creds()).unwrap();
        let path = credentials_codex_path_for(dir.path(), uuid);
        let before = std::fs::read(&path).unwrap();
        let lock = credentials_path_for(dir.path(), uuid).with_extension("lock");
        // RED against the old infinite wait: while this holder lives, the
        // unbounded writer blocks forever; the bounded one must expire.
        let held = crate::platform::lock::try_lock_file(&lock)
            .expect("try_lock_file")
            .expect("test must hold the canonical lock");
        let started = std::time::Instant::now();
        let error =
            save_codex_canonical_for_uuid(dir.path(), uuid, &sample_codex_creds()).unwrap_err();
        let elapsed = started.elapsed();
        // It must have waited out the derived budget floor (Unix sleeps one
        // delay less than the full Windows deadline), not skipped the lock
        // attempt.
        assert!(
            elapsed
                >= crate::platform::lock::CREDENTIAL_LOCK_BUDGET
                    - crate::platform::lock::CREDENTIAL_LOCK_DELAY,
            "bounded wait returned before the budget elapsed: {elapsed:?}"
        );
        // …and must return: only the retired unbounded wait violates this.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "bounded wait did not return promptly: {elapsed:?}"
        );
        assert!(
            matches!(&error, CredentialError::CanonicalLockRefused { path: refused, io_kind }
                if *refused == lock && *io_kind == std::io::ErrorKind::TimedOut),
            "expiry must surface the typed canonical-lock refusal: {error:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a refused write must leave the credential file byte-for-byte unchanged"
        );
        // No leaked guard: the lock is free again once the test's own holder
        // drops.
        drop(held);
        assert!(
            crate::platform::lock::try_lock_file(&lock)
                .unwrap()
                .is_some(),
            "the refused writer must not leak a lock guard"
        );
    }

    /// ROW 2 (Codex twin): a consumed, single-use Codex refresh whose
    /// canonical lock stays held past the commit budget MUST NOT be lost.
    ///
    /// RED mutation: delete the `write_post_commit_rescue` call in
    /// `save_codex_canonical_for_uuid_checked`'s post-commit arm — the
    /// rescue record is then absent and this row panics on its `expect`.
    #[test]
    fn post_commit_codex_refresh_rescues_pair_then_adopts() {
        use crate::credentials::rescue;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::time::Duration;
        let dir = coexisting_fixture(2);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(1);
        // R3 ruling 3(d) supersedes H-c row (3): an undecodable expiry is no
        // longer a refusal (exact source match decides). The fixture keeps
        // JWT-shaped tokens with a real `exp` claim so it also covers the
        // expiry-decoded path.
        let mut original = sample_codex_creds();
        if let Some(codex) = original.codex_mut() {
            codex.tokens.access_token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4OTM0NTYwMDB9.sig".into();
        }
        save_codex_canonical_for_uuid(base, uuid, &original).unwrap();
        let path = credentials_codex_path_for(base, uuid);
        let identity_dir = path.parent().unwrap().to_path_buf();
        let before = std::fs::read(&path).unwrap();

        let mut rotated = sample_codex_creds();
        if let Some(codex) = rotated.codex_mut() {
            codex.tokens.access_token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4OTM0NTk2MDB9.sig".into();
            codex.tokens.refresh_token = Some("rotated-refresh".into());
            codex.last_refresh = Some("2026-04-22T01:00:00Z".into());
        }

        let lock = credentials_path_for(base, uuid).with_extension("lock");
        let _holder = crate::accounts::profiles_lock::HeldOnOtherThread::hold({
            let lock = lock.clone();
            move || {
                crate::platform::lock::try_lock_file(&lock)
                    .expect("try_lock_file")
                    .expect("test must hold the canonical lock")
            }
        });
        let _budget = rescue::CommitBudgetOverrideGuard::install(Duration::from_millis(300));

        let error = save_codex_refresh_for_uuid(base, uuid, &original, &rotated).unwrap_err();
        assert!(
            matches!(error, CredentialError::CanonicalLockRefused { .. }),
            "expiry must surface the typed commit-lock refusal: {error:?}"
        );
        let pending = rescue::rescue_record_pending(&identity_dir)
            .expect("the rotated Codex pair must be durably rescued");
        assert_eq!(pending.provider, "codex");
        assert_eq!(pending.uuid, uuid.to_string());
        let rescued: CredentialFile = serde_json::from_value(pending.payload).unwrap();
        assert_eq!(
            rescued.codex().unwrap().tokens.access_token,
            "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4OTM0NTk2MDB9.sig"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a deferred save must leave the canonical untouched"
        );

        drop(_holder);
        assert!(rescue::adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = load(&path).unwrap();
        assert_eq!(
            installed.codex().unwrap().tokens.access_token,
            "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4OTM0NTk2MDB9.sig"
        );
        assert!(
            rescue::rescue_record_pending(&identity_dir).is_none(),
            "adoption must remove the rescue record"
        );
    }

    #[test]
    fn save_codex_canonical_for_uuid_never_recreates_removed_or_missing_directory() {
        use crate::accounts::identity_store::mark_identity_removed;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        for tombstone in [false, true] {
            let dir = coexisting_fixture(3);
            let base = dir.path();
            let uuid = fixture_uuid_for_slot(2);
            let path = credentials_codex_path_for(base, uuid);
            let parent = path.parent().unwrap();
            if tombstone {
                mark_identity_removed(base, uuid);
                assert!(is_identity_removed(base, uuid));
            }
            std::fs::remove_dir_all(parent).unwrap();
            let result = save_codex_canonical_for_uuid(base, uuid, &sample_codex_creds());
            if tombstone {
                assert!(
                    matches!(result, Err(CredentialError::IdentityRemoved { .. })),
                    "got {result:?}"
                );
            } else {
                let error = result.unwrap_err();
                assert!(matches!(
                    error,
                    CredentialError::IdentityDirectoryMissing { .. }
                ));
                assert_eq!(
                    error.error_kind_tag(),
                    "credentials_identity_directory_missing"
                );
                assert!(error.to_string().contains("directory is missing"));
            }
            assert!(
                !parent.exists(),
                "refusal must not resurrect the UUID directory"
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn codex_refresh_source_cas_includes_unknown_extras_and_preserves_winner() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        let dir = coexisting_fixture(3);
        let uuid = fixture_uuid_for_slot(2);
        let original = sample_codex_creds();
        save_codex_canonical_for_uuid(dir.path(), uuid, &original).unwrap();
        let mut winner = original.clone();
        winner
            .codex_mut()
            .unwrap()
            .extra
            .insert("new_login_context".into(), serde_json::json!("winner"));
        save_codex_canonical_for_uuid(dir.path(), uuid, &winner).unwrap();
        let path = credentials_codex_path_for(dir.path(), uuid);
        let winner_bytes = std::fs::read(&path).unwrap();
        let mut response = original.clone();
        response.codex_mut().unwrap().tokens.refresh_token = Some("fake-stale-response".into());
        assert!(!save_codex_refresh_for_uuid(dir.path(), uuid, &original, &response).unwrap());
        assert_eq!(std::fs::read(path).unwrap(), winner_bytes);
    }

    /// R3 sec L-1 (Anthropic arm): a rescue record from ANOTHER writer that
    /// appeared after the broker's pre-flight gate must be observed at THIS
    /// writer's in-lock re-read. The write defers to adoption; both records
    /// stay durable so adoption decides which pair the canonical consumed.
    ///
    /// RED on the pre-fix code: the guarded write ignored sibling records,
    /// returned `Written`, and made the other record's provenance
    /// unverifiable.
    #[test]
    fn guarded_write_defers_to_a_concurrent_rescue_record() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = ai_credential("concurrent-initial", 1000, None);
        let uuid = ai_commit(base, 2, &initial, ai_context(20));
        let captured = ai_captured(base, 2);
        let canonical = uuid_creds_path(base, uuid);
        let identity_dir = canonical.parent().unwrap().to_path_buf();

        // A record from ANOTHER writer (per-writer nonce), present before this
        // writer takes the canonical lock.
        let witness = crate::credentials::rescue::RescueWitness::Anthropic(
            crate::accounts::anthropic_identity::rescue_lineage_witness_refresh(
                &captured,
                captured.credential_version(),
            ),
        );
        let foreign = crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "concurrent_writer",
            &serde_json::json!({"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":9999999999999u64}}),
            &witness,
        )
        .unwrap();
        let before = std::fs::read(&canonical).unwrap();
        let records_before = std::fs::read_dir(&identity_dir).unwrap().count();

        let candidate = ai_credential("concurrent-candidate", 9999, None);
        // The concurrent-record re-check lives on the REFRESH-lineage write
        // arm (the post-commit path), so drive that arm directly.
        let result_version =
            crate::accounts::anthropic_identity::CredentialVersion::for_credentials(
                candidate.anthropic().unwrap(),
            )
            .unwrap();
        let proof = crate::accounts::anthropic_identity::RefreshLineageWitness::for_test(
            captured.identity(),
            captured.credential_version(),
            result_version,
        );
        let outcome = save_anthropic_canonical_guarded(
            base,
            &captured,
            candidate.anthropic().unwrap(),
            AnthropicWriteWitness::RefreshLineage(&proof),
            None,
        )
        .unwrap();

        assert_eq!(outcome, GuardedWriteOutcome::NotFresher);
        assert_eq!(
            std::fs::read(&canonical).unwrap(),
            before,
            "the canonical must not be written while a concurrent record can still prove itself"
        );
        assert!(
            foreign.exists(),
            "the other writer's record is kept for adoption"
        );
        assert!(
            std::fs::read_dir(&identity_dir).unwrap().count() > records_before,
            "this writer's own record must stay durable for adoption"
        );
    }

    /// R3 sec L-1 (codex arm): the same in-lock re-read re-check on the Codex
    /// post-commit refresh write.
    ///
    /// RED on the pre-fix code: the canonical was overwritten and `true`
    /// returned, making the concurrent record unprovable.
    #[test]
    fn codex_refresh_write_defers_to_a_concurrent_rescue_record() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        let dir = coexisting_fixture(3);
        let uuid = fixture_uuid_for_slot(2);
        let original = sample_codex_creds();
        save_codex_canonical_for_uuid(dir.path(), uuid, &original).unwrap();
        let path = credentials_codex_path_for(dir.path(), uuid);
        let identity_dir = path.parent().unwrap().to_path_buf();
        let foreign = crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "codex",
            &uuid.to_string(),
            "concurrent_writer",
            &serde_json::json!({"tokens":{"access_token":"a"}}),
            &crate::credentials::rescue::RescueWitness::Codex {
                expected_source: serde_json::json!({"tokens":{"access_token":"b"}}),
            },
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();

        let mut response = original.clone();
        response.codex_mut().unwrap().tokens.refresh_token = Some("fresh-response".into());
        assert!(
            !save_codex_refresh_for_uuid(dir.path(), uuid, &original, &response).unwrap(),
            "a concurrent rescue record defers the in-place write"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the codex canonical must be left untouched"
        );
        assert!(
            foreign.exists(),
            "the other writer's record is kept for adoption"
        );
    }

    /// M4-1 Criterion (a)#5a: §5a tmp cleanup on `write` failure.
    ///
    /// Uses closure injection per PRIMARY METHODOLOGICAL DIRECTIVE in
    /// `redteam-discipline.md` Rule 5. The `write_fn` closure is injected
    /// to fail; `secure_fn` and `replace_fn` would succeed if reached.
    /// After the failure, the tmp file must not remain.
    #[test]
    fn save_codex_canonical_for_uuid_cleans_tmp_on_write_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials-codex.json");
        // Fixed tmp name — this is test scaffolding, not a production secret
        // write site, so it does not contribute to the §5a audit count.
        let tmp = dir.path().join("credentials-codex.json.test-tmp-write");

        let result = save_codex_canonical_for_uuid_inner(
            &tmp,
            &final_path,
            b"{\"test\":1}",
            // write_fn: always fails
            |_p, _b| Err(std::io::Error::other("injected write failure")),
            // secure_fn: would succeed (never reached)
            |_p| Ok(()),
            // replace_fn: would succeed (never reached)
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected write failure must propagate as Err"
        );
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after write_fn failure; path: {tmp:?}"
        );
    }

    /// M4-1 Criterion (a)#5b: §5a tmp cleanup on `secure_file` failure.
    ///
    /// `write_fn` succeeds (creating the tmp file), then `secure_fn` is
    /// injected to fail. After the failure, the tmp file must be removed.
    #[test]
    fn save_codex_canonical_for_uuid_cleans_tmp_on_secure_file_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials-codex.json");
        let tmp = dir.path().join("credentials-codex.json.test-tmp-secure");

        let result = save_codex_canonical_for_uuid_inner(
            &tmp,
            &final_path,
            b"{\"test\":2}",
            // write_fn: succeeds (creates tmp file)
            |p, b| std::fs::write(p, b),
            // secure_fn: always fails
            |_p| Err(std::io::Error::other("injected secure_file failure")),
            // replace_fn: would succeed (never reached)
            |_t, _f| Ok(()),
        );

        assert!(
            result.is_err(),
            "injected secure_fn failure must propagate as Err"
        );
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after secure_fn failure; path: {tmp:?}"
        );
    }

    /// M4-1 Criterion (a)#5c: §5a tmp cleanup on `atomic_replace` failure.
    ///
    /// Both `write_fn` and `secure_fn` succeed. `replace_fn` is injected to
    /// fail. After the failure, the tmp file must be removed.
    #[test]
    fn save_codex_canonical_for_uuid_cleans_tmp_on_atomic_replace_failure() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let final_path = dir.path().join("credentials-codex.json");
        let tmp = dir.path().join("credentials-codex.json.test-tmp-replace");

        let result = save_codex_canonical_for_uuid_inner(
            &tmp,
            &final_path,
            b"{\"test\":3}",
            // write_fn: succeeds
            |p, b| std::fs::write(p, b),
            // secure_fn: succeeds (no-op)
            |_p| Ok(()),
            // replace_fn: always fails
            |_t, _f| Err(std::io::Error::other("injected atomic_replace failure")),
        );

        assert!(
            result.is_err(),
            "injected replace_fn failure must propagate as Err"
        );
        assert!(
            !tmp.exists(),
            "§5a: tmp file must not remain after replace_fn failure; path: {tmp:?}"
        );
    }

    /// R3 LOW 6/7 (caller level): `save_uuid_credentials_existing_dir` — the
    /// require-existing caller — on a REMOVED identity dir must return
    /// `IdentityRemoved` (the logged-out state), never recreate the
    /// directory, never report corruption. Reverting the precheck arm
    /// (file.rs:312-318) reds this; the helper-level test in
    /// `identity_store` stays green without it.
    #[test]
    fn save_existing_dir_refuses_removed_identity_dir_at_the_caller() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();

        let err = save_uuid_credentials_existing_dir(base, uuid, &sample_creds())
            .expect_err("a removed identity dir must refuse the write");

        assert!(
            matches!(err, CredentialError::IdentityRemoved { .. }),
            "the logged-out state must surface as IdentityRemoved, not corruption: {err:?}"
        );
        let uuid_dir = credentials_path_for(base, uuid);
        assert!(
            !uuid_dir.parent().unwrap().exists(),
            "the removed identity dir must NOT be recreated around the refusal"
        );
    }

    /// R3 LOW 6/7 (caller level): the refresh-path directory preparation on
    /// a REMOVED identity must refuse via `credential_refusal` — it is the
    /// same logged-out state, and the pre-refresh caller must not recreate
    /// the tree either.
    #[test]
    fn prepare_refresh_directory_refuses_removed_identity_at_the_caller() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();

        let err = prepare_anthropic_refresh_directory(base, uuid)
            .expect_err("a removed identity dir must refuse refresh preparation");

        assert!(
            matches!(err, CredentialError::IdentityDirectoryMissing { .. }),
            "the removed identity must surface as IdentityDirectoryMissing, not corruption: {err:?}"
        );
        assert!(
            !credentials_path_for(base, uuid).parent().unwrap().exists(),
            "the removed identity dir must NOT be recreated by refresh preparation"
        );
    }

    /// Test-only hook plumbing (R3-fix-check LOW 6): installs the
    /// pre-tighten hook and clears it on drop, so a failing assertion
    /// cannot leak it into sibling tests on the same thread.
    struct PreTightenHookGuard;

    impl PreTightenHookGuard {
        fn install(f: fn()) -> Self {
            super::pre_tighten_hook::set(Some(f));
            Self
        }
    }

    impl Drop for PreTightenHookGuard {
        fn drop(&mut self) {
            super::pre_tighten_hook::set(None);
        }
    }

    /// R3-fix-check LOW 6: the PREPARE tighten arm — the identity dir
    /// exists for the whole precheck loop, then disappears in the
    /// precheck→tighten gap of the SECOND loop iteration, so the round-3
    /// NotFound mapping on the TIGHTEN arm is what decides. Reverting that
    /// arm (or removing the hook call) reds this; the precheck-arm test
    /// above stays green without either.
    #[test]
    fn prepare_refresh_refuses_removed_in_the_tighten_gap() {
        use std::cell::{Cell, RefCell};
        thread_local! {
            static GAP_REMOVE: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
            static GAP_CALLS: Cell<u32> = const { Cell::new(0) };
        }
        fn hook() {
            GAP_CALLS.with(|c| {
                let n = c.get();
                c.set(n + 1);
                // First call is the identities root (no-op); the second is
                // the uuid dir, which vanishes in the stat→tighten gap.
                if n == 1 {
                    if let Some(p) = GAP_REMOVE.with(|r| r.borrow().clone()) {
                        let _ = std::fs::remove_dir_all(&p);
                    }
                }
            });
        }

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();
        let uuid_dir = credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&uuid_dir).unwrap();
        GAP_REMOVE.with(|r| *r.borrow_mut() = Some(uuid_dir.clone()));
        let _guard = PreTightenHookGuard::install(hook);

        let err = prepare_anthropic_refresh_directory(base, uuid)
            .expect_err("the tighten-gap removal must refuse");
        assert!(
            matches!(err, CredentialError::IdentityDirectoryMissing { .. }),
            "the tighten-arm mapping must fire (IdentityDirectoryMissing): {err:?}"
        );
        assert!(
            !uuid_dir.exists(),
            "the removed identity dir must NOT be recreated by the tighten"
        );
    }

    /// R3-fix-check LOW 6: the SAVE tighten arm — the identity dir exists
    /// at the precheck, then disappears in the precheck→tighten gap.
    /// Reverting the round-3 NotFound mapping on that arm (or removing the
    /// hook call before it) reds this.
    #[test]
    fn save_existing_dir_refuses_removed_in_the_tighten_gap() {
        use std::cell::RefCell;
        thread_local! {
            static GAP_REMOVE: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
        }
        fn hook() {
            if let Some(p) = GAP_REMOVE.with(|r| r.borrow_mut().take()) {
                let _ = std::fs::remove_dir_all(&p);
            }
        }

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();
        let uuid_dir = credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&uuid_dir).unwrap();
        GAP_REMOVE.with(|r| *r.borrow_mut() = Some(uuid_dir.clone()));
        let _guard = PreTightenHookGuard::install(hook);

        let err = save_uuid_credentials_existing_dir(base, uuid, &sample_creds())
            .expect_err("the tighten-gap removal must refuse the write");
        assert!(
            matches!(err, CredentialError::IdentityRemoved { .. }),
            "the save tighten arm must map NotFound to IdentityRemoved: {err:?}"
        );
        assert!(
            !uuid_dir.exists(),
            "the removed identity dir must NOT be recreated by the tighten"
        );
    }

    /// R3-fix-check LOW 5/6: the CODEX tighten arm — before the fix it
    /// mapped a removed-in-the-gap directory to `Corrupt`
    /// (`identity_dir_secure_refused`); it must report the logged-out
    /// state like every sibling path. Reverting the mapping reds this.
    #[test]
    fn codex_save_refuses_removed_in_the_tighten_gap() {
        use std::cell::RefCell;
        thread_local! {
            static GAP_REMOVE: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
        }
        fn hook() {
            if let Some(p) = GAP_REMOVE.with(|r| r.borrow_mut().take()) {
                let _ = std::fs::remove_dir_all(&p);
            }
        }

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();
        let uuid_dir = credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&uuid_dir).unwrap();
        GAP_REMOVE.with(|r| *r.borrow_mut() = Some(uuid_dir.clone()));
        let _guard = PreTightenHookGuard::install(hook);

        let err = save_codex_canonical_for_uuid(base, uuid, &sample_codex_creds())
            .expect_err("the tighten-gap removal must refuse the codex write");
        assert!(
            matches!(err, CredentialError::IdentityDirectoryMissing { .. }),
            "the codex tighten arm must map NotFound to IdentityDirectoryMissing: {err:?}"
        );
        assert!(
            !uuid_dir.exists(),
            "the removed identity dir must NOT be recreated by the tighten"
        );
    }
}
