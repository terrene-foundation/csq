//! Credential file I/O — load, save, and canonical save with mirroring.

use super::mutex::AccountMutexTable;
use super::CredentialFile;
use crate::accounts::identity_store::{
    credentials_codex_path_for, credentials_path_for, settings_path_for, IdentityId,
};
use crate::accounts::profiles;
use crate::error::CredentialError;
use crate::platform::fs::{atomic_replace, secure_dir, secure_file};
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

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
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
    // closed elsewhere in journal 0065.
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: e,
        });
    }

    // Set permissions on the temp file BEFORE rename so the credential
    // file is never world-readable at its final path.
    if let Err(e) = secure_file(&tmp) {
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
/// This is a shared helper used at both:
/// 1. The UUID-keyed write in `save_canonical_for` (M2-2 new site).
/// 2. The daemon refresher (existing guard in `broker/sync.rs` + `broker/fanout.rs`).
///
/// By centralising the guard here, both write sites use identical logic — no
/// "duplicated surface" failure mode where one site drifts.
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
    let uuid_path = credentials_path_for(base_dir, uuid);

    // Subscription-metadata preservation guard (FM-1.1).
    let creds_to_write = preserve_subscription_metadata(creds, &uuid_path);

    let json =
        serde_json::to_string_pretty(&creds_to_write).map_err(|e| CredentialError::Corrupt {
            path: uuid_path.clone(),
            reason: format!("serialization failed: {e}"),
        })?;

    // Ensure parent dir (identities/<UUID>/) exists and is 0o700 (SEC-2.15 MED-1).
    // `create_dir_all` uses umask-default (typically 0o755, world-enumerable);
    // `secure_dir` restricts it to owner-only so other users cannot list the
    // credential filename even though the file itself is 0o600.
    if let Some(parent) = uuid_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
        // Non-fatal: if the chmod fails on an already-existing dir owned by
        // another UID (shouldn't happen — the identity dir is per-user) we
        // tolerate it rather than aborting the credential write entirely.
        if let Err(e) = secure_dir(parent) {
            warn!(
                error_kind = "identity_dir_secure_failed",
                path = %parent.display(),
                "save_uuid_credentials: could not restrict identity dir to 0o700: {}",
                crate::error::redact_tokens(&e.to_string())
            );
        }
    }

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    write_uuid_credentials_inner(
        &tmp,
        &uuid_path,
        json.as_bytes(),
        |p, b| std::fs::write(p, b),
        |p| secure_file(p).map_err(|e| std::io::Error::other(e.to_string())),
        |t, f| atomic_replace(t, f).map_err(|e| std::io::Error::other(e.to_string())),
    )
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
/// [`save_uuid_credentials`] for the Anthropic surface).
///
/// Called BEFORE the legacy `credentials/codex-<N>.json` write in
/// [`save_canonical_for`], per SEC-2.7 write order: identity FIRST.
///
/// Applies [`preserve_subscription_metadata`] against the existing UUID-path
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
/// [`save_codex_canonical_for_uuid_inner`] calls `remove_file(&tmp)` before
/// propagating.
pub fn save_codex_canonical_for_uuid(
    base_dir: &Path,
    uuid: IdentityId,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let uuid_path = credentials_codex_path_for(base_dir, uuid);

    // Subscription-metadata preservation guard.
    //
    // For Codex variants this returns `creds` unchanged (the guard short-circuits
    // on `to_save.anthropic().is_none()`), but we invoke it for structural
    // parity with `save_uuid_credentials` so that any future preservation logic
    // added to the helper (e.g. preserving `last_refresh` for Codex) is
    // automatically picked up here without re-plumbing the call site.
    let creds_to_write = preserve_subscription_metadata(creds, &uuid_path);

    let json =
        serde_json::to_string_pretty(&creds_to_write).map_err(|e| CredentialError::Corrupt {
            path: uuid_path.clone(),
            reason: format!("serialization failed: {e}"),
        })?;

    // Ensure parent dir (identities/<UUID>/) exists and is 0o700 (SEC-2.15 MED-1).
    // `create_dir_all` uses umask-default (typically 0o755, world-enumerable);
    // `secure_dir` restricts it to owner-only so other users cannot list the
    // credential filename even though the file itself is 0o600. Idempotent on
    // a dir already created by `save_uuid_credentials` for the same UUID.
    if let Some(parent) = uuid_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
        if let Err(e) = secure_dir(parent) {
            warn!(
                error_kind = "identity_dir_secure_failed",
                path = %parent.display(),
                "save_codex_canonical_for_uuid: could not restrict identity dir to 0o700: {}",
                crate::error::redact_tokens(&e.to_string())
            );
        }
    }

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    save_codex_canonical_for_uuid_inner(
        &tmp,
        &uuid_path,
        json.as_bytes(),
        |p, b| std::fs::write(p, b),
        |p| secure_file(p).map_err(|e| std::io::Error::other(e.to_string())),
        |t, f| atomic_replace(t, f).map_err(|e| std::io::Error::other(e.to_string())),
    )
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
/// 1. `mint_for_login` — seeds UUID settings from `config-<N>/settings.json` at
///    login time (same `ProfilesFileLock` window as identity.json write). Idempotent:
///    only writes when the UUID settings file is absent.
/// 2. Pass 0 catch-up in `startup_reconciler` — first-start back-fill of all
///    existing slots.
/// 3. `finalize_login` (M4-2) — explicit pair after `mint_for_login` returns so
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
/// block. Every failure branch in [`save_uuid_settings_inner`] calls
/// `remove_file(&tmp)` before propagating.
pub fn save_uuid_settings(
    base_dir: &Path,
    uuid: IdentityId,
    bytes: &[u8],
) -> Result<(), CredentialError> {
    let uuid_path = settings_path_for(base_dir, uuid);

    // Ensure parent dir (identities/<UUID>/) exists and is 0o700.
    // `create_dir_all` is a no-op if the dir already exists (e.g. M2-2
    // already created it for credentials.json).  `secure_dir` is
    // idempotent on already-restricted dirs.
    if let Some(parent) = uuid_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
        if let Err(e) = secure_dir(parent) {
            warn!(
                error_kind = "identity_dir_secure_failed",
                path = %parent.display(),
                "save_uuid_settings: could not restrict identity dir to 0o700: {}",
                crate::error::redact_tokens(&e.to_string())
            );
        }
    }

    let tmp = crate::platform::fs::unique_tmp_path(&uuid_path);

    save_uuid_settings_inner(
        &tmp,
        &uuid_path,
        bytes,
        |p, b| std::fs::write(p, b),
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
/// 3. Writes the canonical file atomically (atomic_replace + 0o600
///    via [`secure_file`], identical to [`save`]).
/// 4. For [`Surface::Codex`] only, flips the canonical file to 0o400
///    after the write — the canonical Codex credential file lives at
///    0o400 outside narrow refresh windows per INV-P08. Anthropic
///    canonicals stay at 0o600 (unchanged behaviour).
///
/// **M3-7 retirement:** the prior step 5 (live-mirror write into
/// `config-<N>/.credentials.json`) is retired. Handle dirs read
/// credentials through their `.credentials.json` symlink which (post
/// M3-3/M3-4) resolves to `identities/<UUID>/credentials.json`. The
/// `config-N` mirror is no longer a credential reader for any
/// production code path. See the writer-surface retirement table in
/// `workspaces/account-slot-decoupling/02-plans/04-phase3-readiness.md`.
///
/// The 0o600-first-then-0o400 ordering matters on POSIX: `atomic_replace`
/// overwrites the target's inode, so the newly-written tmp file's mode
/// (set by [`secure_file`] before rename) is what lands on disk. A
/// prior-file-at-0o400 state is therefore not a writability obstacle.
/// The post-write flip to 0o400 is the active INV-P08 guarantee.
pub fn save_canonical_for(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let surface = creds.surface();
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
        Surface::Gemini => {
            // Gemini has no canonical credential file — key flows via
            // `platform::secret::Vault`. No UUID check required here.
        }
    }
    // ── End UUID write (M4-12: numeric write fully retired) ───────────────────

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
/// use this as a write target — call `save_canonical_for` instead.
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

    /// Regression: per security.md MUST Rule 5a (journal 0065 B2 class),
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
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::os::unix::fs::PermissionsExt;

        let dir = coexisting_fixture(3);
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        save_canonical_for(dir.path(), account, &sample_creds()).unwrap();

        let uuid_path = uuid_creds_path(dir.path(), uuid);
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
        // M4-12: save_canonical_for requires UUID provisioning. Use
        // coexisting_fixture to provide UUID for slot 11, then verify that
        // the per-account mutex serialises writers — all must succeed and the
        // final UUID-keyed file must be well-formed (no torn writes).
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::sync::Arc;
        use std::thread;

        let dir = coexisting_fixture(11);
        let uuid = fixture_uuid_for_slot(11);
        let account = AccountNum::try_from(11u16).unwrap();
        let base = Arc::new(dir.path().to_path_buf());

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let base = Arc::clone(&base);
                thread::spawn(move || save_canonical_for(&base, account, &sample_creds()))
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("write must succeed under mutex");
        }

        let uuid_path = uuid_creds_path(&base, uuid);
        // UUID-keyed file must be parseable JSON — no torn writes.
        let loaded = load(&uuid_path).expect("post-write UUID-keyed file must parse");
        let a = loaded.anthropic().expect("sample is Anthropic");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test"
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
        // M4-12: Anthropic variant writes to UUID-keyed
        // `identities/<UUID>/credentials.json` — NOT to the numeric canonical.
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(13);
        let account = AccountNum::try_from(13u16).unwrap();
        let uuid = fixture_uuid_for_slot(13);

        save_canonical_for(dir.path(), account, &sample_creds()).unwrap();

        // UUID-keyed Anthropic path MUST be written.
        assert!(
            uuid_creds_path(dir.path(), uuid).exists(),
            "Anthropic variant must write to UUID-keyed identities path"
        );
        // Numeric canonical MUST NOT be written (M4-12).
        assert!(
            !canonical_path_for(dir.path(), account, Surface::ClaudeCode).exists(),
            "Anthropic variant MUST NOT write to numeric ClaudeCode canonical post-M4-12"
        );
        // Codex path MUST NOT be written.
        assert!(
            !canonical_path_for(dir.path(), account, Surface::Codex).exists(),
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
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);
        let creds = sample_creds();

        // Capture pre-save mtime of the fixture-seeded mirror so we can assert
        // `save_canonical_for` does NOT touch it (M3-7 mirror retirement).
        let live = live_path_for(base, account, Surface::ClaudeCode);
        let pre_mirror_mtime = std::fs::metadata(&live)
            .ok()
            .and_then(|m| m.modified().ok());
        // Sleep ~10ms so any post-save mtime would be observably newer.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Act
        save_canonical_for(base, account, &creds).unwrap();

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
            "M3-7: save_canonical_for MUST NOT touch config-N/.credentials.json mirror; \
             pre={pre_mirror_mtime:?} post={post_mirror_mtime:?}"
        );

        // Assert: UUID path carries the correct OAuth payload.
        let uuid_loaded = load(&uuid_path).unwrap();
        assert_eq!(
            uuid_loaded
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-test",
            "UUID path must carry the OAuth payload"
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
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // First write: credentials WITH subscription_type = Some("max")
        let creds_with_max = sample_creds(); // sample_creds has Some("max")
        save_canonical_for(base, account, &creds_with_max).unwrap();

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
        // (Anthropic's token endpoint does not return subscription_type)
        let creds_fresh_oauth = {
            let mut c = creds_with_max.clone();
            c.expect_anthropic_mut().claude_ai_oauth.subscription_type = None;
            c.expect_anthropic_mut().claude_ai_oauth.rate_limit_tier = None;
            // Change the access token so the write is distinguishable
            c.expect_anthropic_mut().claude_ai_oauth.access_token =
                crate::types::AccessToken::new("sk-ant-oat01-refreshed".into());
            c
        };

        // Act: second write (the one that must preserve subscription_type)
        save_canonical_for(base, account, &creds_fresh_oauth).unwrap();

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
            "sk-ant-oat01-refreshed",
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
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::sync::Arc;
        use std::thread;

        // Arrange
        let dir = coexisting_fixture(3);
        let base = Arc::new(dir.path().to_path_buf());
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Act: 8 concurrent writers for the same account
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let base = Arc::clone(&base);
                thread::spawn(move || save_canonical_for(&base, account, &sample_creds()))
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("concurrent write must not error");
        }

        // Assert: UUID path is parseable (no torn write)
        let uuid_path = uuid_creds_path(&base, uuid);
        let loaded = load(&uuid_path).expect("UUID path must parse after concurrent writes");
        assert_eq!(
            loaded
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-test",
            "UUID path must carry correct access_token after concurrent writes"
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
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Pre-create the tmp path location as a DIRECTORY. The write will attempt
        // to create a tmp file next to `credentials.json`; the fact that
        // `credentials.json` itself is a dir means the parent dir exists and
        // our tmp file CAN be created (just in the same dir), so we must block
        // the tmp path specifically. We instead pre-create the UUID credentials
        // path as a dir — `unique_tmp_path` produces `credentials.json.tmp.PID.N`,
        // so we can't block the tmp name directly. Instead we block the entire
        // parent by making `identities/<uuid>/` a FILE (not a dir), so
        // `create_dir_all` on it will fail with ENOTDIR.
        //
        // Strategy: remove the identity dir (created by fixture) and replace it
        // with a FILE of the same name. `create_dir_all` on a path whose parent
        // component is a file returns ENOTDIR, causing save_uuid_credentials to fail.
        let identity_dir = base.join("identities").join(uuid.to_string());
        // The fixture creates identity.json but not the dir with exactly that name;
        // remove the dir and replace with a file.
        if identity_dir.exists() {
            std::fs::remove_dir_all(&identity_dir).unwrap();
        } else {
            // Ensure the identities/ root exists
            std::fs::create_dir_all(base.join("identities")).unwrap();
        }
        // Create a FILE at the path that would be the identity directory.
        // `create_dir_all("identities/<uuid>")` will now fail with ENOTDIR.
        std::fs::write(&identity_dir, b"obstruction").unwrap();

        // Act: must fail because create_dir_all for the UUID dir returns ENOTDIR
        let result = save_canonical_for(base, account, &sample_creds());

        // Assert: the call must have returned Err (fail-closed)
        assert!(
            result.is_err(),
            "fail-closed: save_canonical_for must return Err when UUID write fails; \
             got Ok() — fail-closed invariant is broken"
        );

        // Assert: legacy canonical was NOT written (identity FIRST, abort on failure)
        assert!(
            !canonical_path_for(base, account, Surface::ClaudeCode).exists(),
            "fail-closed: credentials/2.json must NOT be written when UUID write fails"
        );

        // UUID path (as a file inside what is now a file-as-dir) cannot exist.
        let uuid_path = uuid_creds_path(base, uuid);
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
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Act
        save_canonical_for(base, account, &sample_creds()).unwrap();

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
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let uuid = fixture_uuid_for_slot(2);

        // Act
        save_canonical_for(base, account, &sample_creds()).unwrap();

        // Assert: identities/<UUID>/ directory is 0o700
        let uuid_path = uuid_creds_path(base, uuid);
        let uuid_dir = uuid_path.parent().unwrap();
        let mode = std::fs::metadata(uuid_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "MED-1: identities/<UUID>/ must be 0o700 after write; got 0o{mode:03o}"
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
}
