//! Account logout / removal.
//!
//! Removes every trace of an account from the csq base directory:
//! the canonical credential file, the permanent `config-N` directory
//! (with its live credentials and markers), and the `profiles.json`
//! entry. Refuses if a live `claude` process is still bound to the
//! account through any handle dir.
//!
//! See `specs/02-csq-handle-dir-model.md` INV-01 — `config-N` is
//! permanent for the lifetime of an account. Logout ends that
//! lifetime, so removing the directory is correct (and required so
//! the slot becomes available again to the desktop Add Account flow).

use crate::accounts::identity_store::{identity_path, IdentityId};
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::accounts::{markers, profiles};
use crate::audit::op_emit;
use crate::audit::types::{
    AccountLogoutPayload, EventKind, EventPayload, OpOutcome, RedactedString,
};
use crate::credentials::file::{canonical_path_for, live_path};
use crate::platform::process::is_pid_alive;
use crate::platform::secret::open_default_vault;
use crate::providers::catalog::Surface;
use crate::providers::gemini::provisioning::{delete_api_key_from_vault, is_gemini_bound_slot};
use crate::providers::native;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

#[cfg(test)]
type LogoutOrderingHook = Box<dyn FnMut(&Path, IdentityId, bool)>;
#[cfg(test)]
thread_local! {
    static LOGOUT_ORDERING_HOOK: std::cell::RefCell<Option<LogoutOrderingHook>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_logout_ordering_hook(base: &Path, identity: IdentityId, before_profiles_save: bool) {
    LOGOUT_ORDERING_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(base, identity, before_profiles_save);
        }
    });
}

/// Every surface whose canonical credential file logout MUST sweep.
/// Adding a future surface (e.g. Bedrock) means landing a single line
/// here so logout cleanup remains exhaustive.
const ALL_SURFACES: [Surface; 5] = [
    Surface::ClaudeCode,
    Surface::Codex,
    Surface::Gemini,
    // Wave 3 native-CLI surfaces — their credential-less binding markers
    // (`credentials/{kimi,grok}-<N>.json`) MUST be swept on logout, else a
    // native slot is un-removable: `csq login` refuses (conflict guard) AND
    // `csq logout` reports "not configured", trapping the user (found by the
    // W3 user-path smoke; reconciler-cleanup-parity Rule 6).
    Surface::Kimi,
    Surface::Grok,
];

/// Summary of what was removed during a successful logout.
#[derive(Debug, Clone)]
pub struct LogoutSummary {
    pub account: AccountNum,
    pub canonical_removed: bool,
    pub config_dir_removed: bool,
    pub profiles_entry_removed: bool,
    pub quota_entry_removed: bool,
    /// `true` when logout dropped the last reference to the slot's identity
    /// UUID and removed the `identities/<UUID>/` directory at the source (the
    /// orphan-identity GC source-fix). `false` when the UUID is still
    /// referenced by another slot (shared identity) or no UUID resolved.
    pub identity_dir_removed: bool,
    /// `true` when logout dropped the last reference to the slot's identity
    /// UUID but the `identities/<UUID>/` directory — which holds the local
    /// copy of the credential — is STILL ON DISK at return: the identity's
    /// canonical credential lock could not be taken within
    /// `platform::lock::CREDENTIAL_LOCK_BUDGET` (or errored), or
    /// `remove_dir_all` failed. This is a refused delete, never a silent one:
    /// a fixed-vocabulary WARN (`error_kind = "logout_identity_dir_lock_busy"`
    /// / `"logout_identity_dir_lock_failed"` / `"logout_identity_dir_remove_failed"`)
    /// is emitted on each branch, and the identity tombstone (written before
    /// the delete attempt) already blocks writers. The orphan-identity GC
    /// (`accounts::orphan_identity_gc::prune_orphan_identities`) removes the
    /// directory on the next reconciler tick / daemon start. Callers MUST
    /// surface this plainly: the credential folder was NOT removed by this
    /// logout.
    pub identity_dir_pending_removal: bool,
    /// `true` when a native-CLI (Kimi/Grok) vendor home directory
    /// (`native-homes/<surface>-<N>/`) was removed for this slot (0135
    /// design lock, Wave C shard C3). `false` when the slot was never bound
    /// to a native surface, or its vendor home was already absent.
    pub native_home_removed: bool,
    /// `true` when a Gemini API-key OS-keychain vault entry was deleted for
    /// this slot. `false` when the slot was never Gemini-ApiKey-bound, or
    /// the caller already cleared the vault before calling
    /// `logout_account` (e.g. the desktop `remove_account` D7 pre-check —
    /// `is_gemini_bound_slot` reads the same marker this function removes,
    /// so a caller that unbinds first sees `false` here, correctly).
    pub gemini_vault_cleared: bool,
    /// `true` when the macOS keychain OAuth item was CONFIRMED cleared
    /// (deleted, or confirmed already absent) for at least one `term-*`
    /// handle dir bound to this slot at logout time — live or dead.
    /// `false` when: non-macOS (structural no-op), no handle dirs were
    /// bound to the slot, or the keychain mirror is disabled (test
    /// builds). Does NOT encode a per-dir failure to confirm — that is
    /// non-fatal and surfaced via a `WARN` log
    /// (`error_kind = "keychain_clear_unconfirmed"`), never silently
    /// dropped (`zero-tolerance.md` Rule 3). This is the third credential-
    /// resurrection source closed on the logout path — an internal ticket closed the
    /// file-level and Gemini-vault ones; current CC reads OAuth from the
    /// keychain FIRST, keyed by the handle dir's own path, which
    /// `logout_account` never touched before this field existed.
    pub keychain_cleared: bool,
    /// `true` when at least one UNCONFIRMED keychain clear could not be
    /// queued for automatic retry (the retry spool was at its cap or
    /// unwritable). Distinct from `keychain_cleared`: that field says the
    /// clear was not confirmed, this one says the automatic retry will NOT
    /// happen either — so the keychain item may survive this logout with no
    /// daemon sweep to remove it. Surfaced so the operator can act; the
    /// refusal itself is also logged at a fixed-vocabulary ERROR/WARN where
    /// it happens.
    pub keychain_retry_queue_failed: bool,
}

/// What the in-use scan found: live pids, and the NAMES of bound handle dirs whose pid
/// marker could not be read (possibly live — fail closed, but not a pid).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveHandleDirScan {
    pub pids: Vec<u32>,
    pub unreadable_dirs: Vec<String>,
}

impl LiveHandleDirScan {
    pub fn is_empty(&self) -> bool {
        self.pids.is_empty() && self.unreadable_dirs.is_empty()
    }
}

/// A handle dir name safe to put in an operator message: the `term-<…>` name only, never a
/// path. Anything outside `[A-Za-z0-9_-]` (or over 64 bytes) collapses to a placeholder.
fn display_dir_name(name: &str) -> String {
    if name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        name.to_string()
    } else {
        "term-?".to_string()
    }
}

/// Operator text for [`LogoutError::InUse`]; shared by the CLI and desktop renderers.
pub fn in_use_message(account: AccountNum, pids: &[u32], unreadable_dirs: &[String]) -> String {
    let mut parts = Vec::new();
    if !pids.is_empty() {
        parts.push(format!(
            "account {account} is in use by live claude process(es) {pids:?} — exit those terminals first, then retry"
        ));
    }
    if !unreadable_dirs.is_empty() {
        let names = unreadable_dirs.join(", ");
        let (noun, verb) = if unreadable_dirs.len() == 1 {
            ("handle dir", "has a pid marker")
        } else {
            ("handle dirs", "have pid markers")
        };
        parts.push(format!(
            "account {account}: {noun} {names} {verb} that cannot be read; inspect it and remove it if stale, then retry"
        ));
    }
    parts.join("; ")
}

/// Failure modes for [`logout_account`].
#[derive(Debug)]
pub enum LogoutError {
    /// The account is currently bound to one or more live `claude`
    /// processes via handle dirs. The user must exit those terminals
    /// before logging out — refusing to delete state from under a
    /// running process is the safest default.
    ///
    /// `unreadable_dirs` names (dir NAME only, never a path) each bound handle dir whose
    /// pid marker could not be read, so liveness cannot be ruled out. It is a separate
    /// field, not a sentinel pid, so no renderer can print it as a process id.
    InUse {
        account: AccountNum,
        pids: Vec<u32>,
        unreadable_dirs: Vec<String>,
    },
    /// No credential file or config dir exists for this account.
    /// Logout is a no-op against an empty slot.
    NotConfigured { account: AccountNum },
    /// A filesystem operation failed mid-removal.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A removal marker is a nonregular entry; never follow or replace it.
    NonregularTombstone { path: PathBuf },
    /// The identities namespace is not an actual directory; refuse aliases.
    UnsafeTombstoneNamespace { path: PathBuf },
    /// Loading or saving `profiles.json` failed.
    Profiles(crate::error::ConfigError),
    /// The Gemini API-key OS-keychain vault could not be opened, or the
    /// vault entry for this slot could not be deleted. Fails BEFORE the
    /// slot's other state is touched — proceeding would delete the
    /// binding marker while leaving a hard-to-find orphaned vault entry
    /// (`security.md` MUST-2/Rule 3: no raw error body, no silent
    /// fallback on a credential path). `error_kind` is a fixed-vocabulary
    /// tag from `SecretError::error_kind_tag()`.
    VaultUnavailable {
        account: AccountNum,
        error_kind: &'static str,
    },
}

impl std::fmt::Display for LogoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogoutError::InUse {
                account,
                pids,
                unreadable_dirs,
            } => f.write_str(&in_use_message(*account, pids, unreadable_dirs)),
            LogoutError::NotConfigured { account } => {
                write!(f, "account {} is not configured", account)
            }
            LogoutError::Io { path, source } => {
                write!(f, "filesystem error at {}: {}", path.display(), source)
            }
            LogoutError::NonregularTombstone { path } => write!(
                f,
                "identity_removal_marker_nonregular at {}: tombstone is not a regular file",
                path.display()
            ),
            LogoutError::UnsafeTombstoneNamespace { path } => write!(
                f,
                "identity_removal_namespace_nonregular at {}: identities namespace must be a directory, not an alias",
                path.display()
            ),
            LogoutError::Profiles(e) => write!(f, "profiles.json error: {}", e),
            LogoutError::VaultUnavailable {
                account,
                error_kind,
            } => write!(
                f,
                "account {}: gemini vault unavailable ({})",
                account, error_kind
            ),
        }
    }
}

impl std::error::Error for LogoutError {}

/// Removes account `account` from the csq base directory.
///
/// Steps (in order):
///  1. Verify the account is actually configured. Returns `NotConfigured`
///     if no canonical credential file exists for ANY surface
///     (`credentials/N.json` / `credentials/codex-N.json` /
///     `credentials/gemini-N.json`) AND `config-N/` is also absent.
///  2. Scan `term-*` handle dirs for any live process whose
///     `.csq-account` symlink resolves to `account`. If any exist,
///     return `InUse` listing the PIDs.
///  3. Delete each surface-shaped canonical file (best-effort if
///     absent) — see `ALL_SURFACES`. The pre-PR-fix code only
///     swept the ClaudeCode shape, so logging out a Codex or Gemini
///     slot left its credential file on disk and `discover_codex` /
///     `discover_gemini` continued to surface the slot to the
///     dashboard. Originating bug: this session, slot 12 (Codex)
///     surviving `csq logout 12`.
///  4. Delete the slot's native-CLI (Kimi/Grok) vendor home directory
///     (best-effort if absent) — see `remove_native_homes`. The vendor's
///     real credentials live there, not in the marker swept in step 3.
///  5. Delete `config-N/` recursively (best-effort if absent).
///  6. Remove the `account` entry from `profiles.json` (if present).
///
/// Daemon cache invalidation is the caller's responsibility — this
/// helper only touches on-disk state so tests do not need a daemon.
pub fn logout_account(base_dir: &Path, account: AccountNum) -> Result<LogoutSummary, LogoutError> {
    let live = live_path(base_dir, account);
    let config_dir = live
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| base_dir.join(format!("config-{}", account)));

    // `symlink_metadata` (not `.exists()`, which follows symlinks and is false
    // for a dangling link) so a slot whose ONLY binding is a dangling marker
    // symlink is still logout-able (recoverable) — matching the fail-toward-
    // present posture the `binding_guard::detect_bound_surface` union detector
    // uses, so "detected as bound → refuses new binds" and "logout-able" stay
    // consistent (redteam R2). The removal loop below uses `remove_file`, which
    // deletes a dangling symlink correctly.
    let any_canonical_exists = ALL_SURFACES
        .iter()
        .any(|s| std::fs::symlink_metadata(canonical_path_for(base_dir, account, *s)).is_ok());
    if !any_canonical_exists && !config_dir.exists() {
        // LogoutError::NotConfigured — pre-side-effect rejection: emit NO INTENT (WBS T5).
        return Err(LogoutError::NotConfigured { account });
    }

    let bound = scan_live_handle_dirs_for_account(base_dir, account);
    if !bound.is_empty() {
        // LogoutError::InUse — pre-side-effect rejection: emit NO INTENT (WBS T5).
        return Err(LogoutError::InUse {
            account,
            pids: bound.pids,
            unreadable_dirs: bound.unreadable_dirs,
        });
    }

    // M13b — emit INTENT BEFORE the first credential remove_file (F-LEDGER-02).
    // If the intent cannot be persisted this function returns LogoutError::Io
    // wrapping the audit error, and NO credential is deleted.
    // `orphaned_uuid` is unknown at intent time; carried as None and resolved
    // in the outcome record after remove_profiles_entry completes.
    let chain_id = op_emit::load_chain_id(base_dir);
    let correlation_id = op_emit::gen_correlation_id().map_err(|e| LogoutError::Io {
        path: base_dir.join("csq-runs"),
        source: std::io::Error::other(format!("audit correlation_id: {e}")),
    })?;
    let intent_payload = EventPayload::AccountLogout(AccountLogoutPayload {
        slot: account,
        orphaned_uuid: None, // unknown pre-side-effect; resolved in OUTCOME
    });
    // FIX-1: emit_intent now returns Ok(true)=emitted, Ok(false)=chain-broken
    // skip (proceed without audit), Err=fail-closed. Only Err aborts the logout.
    let intent_emitted = op_emit::emit_intent(
        base_dir,
        &chain_id,
        EventKind::AccountLogout,
        intent_payload,
        correlation_id.clone(),
    )
    .map_err(|e| LogoutError::Io {
        path: base_dir.join("csq-runs"),
        source: std::io::Error::other(format!(
            "audit intent record could not be persisted — logout aborted, \
             no credential file deleted: {e}"
        )),
    })?;

    // Gemini API-key vault cleanup. MUST run before the ALL_SURFACES sweep
    // below — that sweep deletes `credentials/gemini-<N>.json`, the ONLY
    // signal `is_gemini_bound_slot` / `delete_api_key_from_vault` have for
    // determining the slot's auth mode. This closes the CLI/desktop parity
    // gap directly in `logout_account` (rather than duplicating the
    // vault-clear sequence at each call site) so a future caller cannot
    // reintroduce it — csq has a documented history of CLI/desktop twin
    // drift (`account-terminal-separation.md`). A caller that already ran
    // its own pre-check (desktop `remove_account`'s D7 sequence: vault
    // delete + marker unbind BEFORE calling this function) has already
    // removed the marker, so `is_gemini_bound_slot` correctly reads
    // `false` here and this step is a no-op — safe to run unconditionally
    // from every caller. `security.md` MUST-2/Rule 3: fixed-vocabulary
    // `error_kind_tag()` only, never the raw `SecretError` body; failure
    // here aborts BEFORE any other state is touched — proceeding would
    // delete the binding marker while leaving an orphaned, hard-to-find
    // vault entry.
    let gemini_vault_cleared = if is_gemini_bound_slot(base_dir, account) {
        let vault = match open_default_vault() {
            Ok(v) => v,
            Err(e) => {
                emit_logout_outcome(
                    base_dir,
                    &chain_id,
                    correlation_id,
                    account,
                    None,
                    OpOutcome::Failed {
                        reason: logout_redact_reason("gemini vault unavailable"),
                    },
                    intent_emitted,
                );
                return Err(LogoutError::VaultUnavailable {
                    account,
                    error_kind: e.error_kind_tag(),
                });
            }
        };
        if let Err(e) = delete_api_key_from_vault(base_dir, account, vault.as_ref()) {
            emit_logout_outcome(
                base_dir,
                &chain_id,
                correlation_id,
                account,
                None,
                OpOutcome::Failed {
                    reason: logout_redact_reason("gemini vault delete failed"),
                },
                intent_emitted,
            );
            return Err(LogoutError::VaultUnavailable {
                account,
                error_kind: e.error_kind_tag(),
            });
        }
        true
    } else {
        false
    };

    // A4b — mirror the swap/auto-rotate keychain treatment on the terminal
    // logout path: the third credential-resurrection source (an internal ticket closed
    // the file-level and Gemini-vault ones). Current CC reads OAuth from
    // the per-handle-dir macOS keychain item FIRST — `logout_account`
    // never cleared it, so a handle dir (live or, more commonly at this
    // point, dead-but-not-yet-swept) still bound to this slot kept a
    // mirror of the credential that survived the slot's removal.
    //
    // MUST run HERE — before `config_dir` is removed below — because
    // `clear_bound_keychain_items` locates handle dirs via the marker
    // `bound_handle_dirs` reads THROUGH `config-N/.csq-account`, and
    // resolves a UUID-marker dir's account via `by_slot` (profiles.json),
    // both still intact at this point. Once either is gone, the handle
    // dirs bound to this slot cannot be found and their keychain items
    // become permanent orphans (see `clear_bound_keychain_items`'s doc for
    // the full fail-open rationale — it does not abort logout on a
    // locked/unreachable keychain).
    let keychain = clear_bound_keychain_items(base_dir, account);
    let keychain_cleared = keychain.any_confirmed;

    // SAFETY-ORDERING: credential files removed BEFORE ProfilesFileLock acquired (M9 + FM-9(c)). Crash here leaves an unidentifiable slot, never a falsely-identifiable one.
    // Sweep the canonical credential file for every surface. A slot
    // can carry exactly one binding so at most one of these exists,
    // but the loop is the only correctness guarantee — if a future
    // refactor lets a slot bind more than one surface, the sweep is
    // already exhaustive.
    let mut canonical_removed = false;
    for surface in ALL_SURFACES {
        let path = canonical_path_for(base_dir, account, surface);
        match std::fs::remove_file(&path) {
            Ok(()) => canonical_removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                // Partial failure → emit OUTCOME:Failed best-effort, then return error.
                emit_logout_outcome(
                    base_dir,
                    &chain_id,
                    correlation_id,
                    account,
                    None,
                    OpOutcome::Failed {
                        reason: logout_redact_reason(&format!("credential remove failed: {e}")),
                    },
                    intent_emitted,
                );
                return Err(LogoutError::Io { path, source: e });
            }
        }
    }

    // 0135 design lock, Wave C shard C3: native-CLI (Kimi/Grok) surfaces keep
    // their real vendor credentials OUTSIDE the credential-less marker just
    // swept above — in a per-slot vendor home at `native-homes/<surface>-<N>/`
    // (`providers::native::native_home_path`). Best-effort, non-fatal: a
    // removal failure is logged and the sweep continues (same discipline as
    // the rest of this pre-lock phase) — it must never block the credential
    // sweep, config-dir removal, or profiles cleanup that follow.
    let native_home_removed = remove_native_homes(base_dir, account);

    let config_dir_removed = match std::fs::remove_dir_all(&config_dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            emit_logout_outcome(
                base_dir,
                &chain_id,
                correlation_id,
                account,
                None,
                OpOutcome::Failed {
                    reason: logout_redact_reason(&format!("config dir remove failed: {e}")),
                },
                intent_emitted,
            );
            return Err(LogoutError::Io {
                path: config_dir,
                source: e,
            });
        }
    };

    // Clear the broker-failed sentinel. Removing the account RESOLVES the
    // condition the sentinel represents, definitively and permanently — there
    // is no longer an account to re-login — so this is a success boundary in
    // exactly the sense `sentinel-clearing-parity.md` MUST-1 means.
    //
    // Without it the sentinel outlives its slot and `csq doctor` reports
    // `✗ Account N: LOGIN-NEEDED (oauth) — run `csq login N`` forever, for a
    // slot with no profiles entry, no quota row, no config dir and no
    // credentials. Observed live on 2026-08-07: slot 7 was removed and the
    // stale `credentials/7.broker-failed` kept doctor at a hard FAIL, telling
    // the operator to log into an account they had deliberately deleted.
    //
    // Placed AFTER the credential sweep and config-dir removal, and BEFORE the
    // ProfilesFileLock: the sentinel is per-slot state under `credentials/`,
    // so it belongs with the other pre-lock filesystem cleanup. Best-effort by
    // design — `clear_broker_failed` swallows its own errors, and a sentinel
    // that cannot be removed must never block a logout that has already
    // deleted the credentials.
    crate::refresh::sentinel::clear_broker_failed(base_dir, account);

    // Acquire ProfilesFileLock before removing the profiles entry so that
    // by_slot, by_email, and by_slot_identity are updated atomically with the
    // accounts removal. This serializes against daemon Pass-0 and `csq login`
    // mint paths.
    //
    // M9 + FM-9 (c) ordering invariant: credential files (canonical_path_for
    // sweep above) and config_dir are deleted BEFORE this lock is acquired.
    // A crash between the credential sweep and the profiles update leaves the
    // slot unidentifiable (no credentials, no identity entry) — never falsely-
    // identifiable (stale by_slot_identity pointing at a recycled slot).
    let profiles_lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(e) => {
            emit_logout_outcome(
                base_dir,
                &chain_id,
                correlation_id,
                account,
                None,
                OpOutcome::Failed {
                    reason: logout_redact_reason(&format!("profiles lock: {e}")),
                },
                intent_emitted,
            );
            return Err(LogoutError::Profiles(e));
        }
    };
    let (profiles_entry_removed, orphaned_uuid) =
        match remove_profiles_entry(&profiles_lock, base_dir, account) {
            Ok(r) => r,
            Err(e) => {
                emit_logout_outcome(
                    base_dir,
                    &chain_id,
                    correlation_id,
                    account,
                    None,
                    OpOutcome::Failed {
                        reason: logout_redact_reason(&format!("profiles remove: {e}")),
                    },
                    intent_emitted,
                );
                return Err(e);
            }
        };
    drop(profiles_lock); // release before quota write (different lock)

    // Orphan-identity GC source-fix: when this logout dropped the LAST
    // reference to the slot's identity UUID (it is now in neither `by_slot`
    // nor `by_email`), delete the `identities/<UUID>/` dir so no orphan is
    // born. ORDERING (extends the M9 SAFETY-ORDERING invariant above): the
    // profiles map removal is durably saved BEFORE this delete, so a crash
    // here leaves an UNREFERENCED orphan dir (collected by
    // `orphan_identity_gc::prune_orphan_identities` on the next daemon start),
    // NEVER a `by_slot` row pointing at a deleted dir ("never
    // falsely-identifiable"). A shared UUID (another slot still references it)
    // yields `orphaned_uuid == None` → the dir is preserved for the sibling
    // slot. NotFound is treated as success (the GC pass may have raced).
    //
    // A lock that could NOT be taken is never bypassed on this destructive
    // path (guard-reader-writer-parity MUST-2): the tombstone written above
    // already blocks writers; the refusal is logged with a fixed-vocabulary
    // tag; and `LogoutSummary::identity_dir_pending_removal` tells the caller
    // the local credential folder is STILL ON DISK. The orphan GC collects it
    // on the next reconciler tick — the same claim the base code made, now
    // proven by `logout_lock_busy_leaves_dir_that_the_orphan_gc_then_collects`.
    let (identity_dir_removed, identity_dir_pending_removal) = match orphaned_uuid {
        Some(uuid) => remove_orphan_identity_dir(base_dir, uuid, account),
        None => (false, false),
    };

    let quota_entry_removed = remove_quota_entry(base_dir, account);

    // M13b — emit OUTCOME:Ok with the resolved orphaned_uuid.
    let outcome_orphaned_uuid = orphaned_uuid.map(|u| u.to_string());
    emit_logout_outcome(
        base_dir,
        &chain_id,
        correlation_id,
        account,
        outcome_orphaned_uuid.as_deref(),
        OpOutcome::Ok,
        intent_emitted,
    );

    Ok(LogoutSummary {
        account,
        canonical_removed,
        config_dir_removed,
        profiles_entry_removed,
        quota_entry_removed,
        identity_dir_removed,
        identity_dir_pending_removal,
        native_home_removed,
        gemini_vault_cleared,
        keychain_cleared,
        keychain_retry_queue_failed: keychain.retry_queue_failed,
    })
}

/// Deletes `identities/<uuid>/` for a slot that just dropped the last
/// reference to `uuid`, under that identity's canonical credential lock.
///
/// The lock MUST be held across the delete: the lineage writer takes the same
/// lock and re-checks the tombstone, so a refresh racing this logout either
/// finished its write before we took the lock (and is deleted with the dir) or
/// sees the tombstone and refuses to create a missing dir (R2-M1).
///
/// Returns `(removed, pending_removal)`:
///
/// - `(true, false)` — the directory was deleted under the lock.
/// - `(false, false)` — the directory was already absent (the orphan GC or a
///   concurrent logout won the race, or the identity never materialized).
/// - `(false, true)` — the directory — and with it the local copy of the
///   credential — is STILL ON DISK. The canonical lock could not be taken
///   within [`crate::platform::lock::CREDENTIAL_LOCK_BUDGET`] (`Ok(None)`),
///   locking failed (`Err`), or `remove_dir_all` failed. The refusal is never
///   silent: each branch logs a fixed-vocabulary `error_kind` (no `{e}` —
///   `PlatformError`'s Display carries the lock path; `security.md` MUST-2 /
///   `zero-tolerance.md` Rule 3), and the caller reports the pending cleanup
///   on [`LogoutSummary::identity_dir_pending_removal`]. The tombstone written
///   before this call blocks writers; `orphan_identity_gc` collects the dir on
///   the next reconciler tick.
fn remove_orphan_identity_dir(
    base_dir: &Path,
    uuid: IdentityId,
    account: AccountNum,
) -> (bool, bool) {
    let identity_dir = identity_path(base_dir, uuid);
    let canonical_lock = crate::accounts::identity_store::credentials_path_for(base_dir, uuid)
        .with_extension("lock");
    // The lock file lives inside the dir; only lock a dir that exists (the
    // lock call would otherwise fail, and must not create it). Bounded
    // acquisition: a wedged holder must not pin logout (the class and bound
    // are `platform::lock::lock_credential_file`'s).
    let guard = if identity_dir.is_dir() {
        match crate::platform::lock::lock_credential_file(&canonical_lock) {
            Ok(Some(guard)) => Some(guard),
            Ok(None) => {
                tracing::warn!(
                    error_kind = "logout_identity_dir_lock_busy",
                    account = account.get(),
                    budget_ms = crate::platform::lock::CREDENTIAL_LOCK_BUDGET_MS,
                    "logout: identity credential lock was still held at the bounded wait — \
                     the local credential folder was NOT removed (the identity tombstone \
                     blocks writers; the next orphan-identity GC removes it)"
                );
                None
            }
            Err(_) => {
                // Fixed tag only: `PlatformError`'s Display carries the lock
                // file path (`security.md` MUST-2).
                tracing::warn!(
                    error_kind = "logout_identity_dir_lock_failed",
                    account = account.get(),
                    "logout: could not lock the identity credential file — the local \
                     credential folder was NOT removed (the identity tombstone blocks \
                     writers; the next orphan-identity GC removes it)"
                );
                None
            }
        }
    } else {
        None
    };
    #[cfg(test)]
    run_logout_ordering_hook(base_dir, uuid, false);
    // An open lock file blocks directory removal on Windows.
    let locked = guard.is_some();
    #[cfg(windows)]
    drop(guard);
    let result = if identity_dir.is_dir() && !locked {
        (false, true)
    } else {
        match std::fs::remove_dir_all(&identity_dir) {
            Ok(()) => (true, false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, false),
            Err(_) => {
                // Best-effort, but never silent: the GC retries next tick.
                tracing::warn!(
                    error_kind = "logout_identity_dir_remove_failed",
                    account = account.get(),
                    "logout: identity credential folder removal failed — it was NOT \
                     removed (best-effort; the next orphan-identity GC retries)"
                );
                (false, true)
            }
        }
    };
    #[cfg(not(windows))]
    drop(guard);
    result
}

/// Removes the per-slot vendor home directories (0135 design lock —
/// `native-homes/<surface>-<N>/`) for every native-CLI surface (Kimi/Grok)
/// bound to `account`.
///
/// A native surface's REAL credentials live in this vendor-owned home, not
/// in csq's credential-less binding marker (already swept by the
/// `ALL_SURFACES` loop above), so it is a separate on-disk surface that
/// needs its own removal step. Gated on [`Surface::is_native_cli`] —
/// [`native::native_home_path`] is only meaningful for native surfaces;
/// calling it for `ClaudeCode`/`Codex`/`Gemini` would resolve a path that
/// was never written and is never expected to exist.
///
/// Best-effort and non-fatal: a removal failure is logged with a
/// fixed-vocabulary `error_kind` (`security.md` §2 — never `{e}` on a value
/// that can echo a full filesystem path) and does NOT abort the logout,
/// mirroring `remove_quota_entry`'s best-effort discipline.
///
/// Returns `true` iff at least one native vendor home was actually removed.
fn remove_native_homes(base_dir: &Path, account: AccountNum) -> bool {
    let mut removed_any = false;
    for surface in ALL_SURFACES {
        if !surface.is_native_cli() {
            continue;
        }
        let home = native::native_home_path(base_dir, account, surface);
        match std::fs::remove_dir_all(&home) {
            Ok(()) => removed_any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                tracing::warn!(
                    error_kind = "native_home_remove_failed",
                    account = account.get(),
                    surface = surface.as_str(),
                    "logout: native vendor home removal failed (non-fatal, sweep continues)"
                );
            }
        }
    }
    removed_any
}

/// Scrub home-directory paths from an error reason string before storing it
/// on the committed audit chain.
///
/// FIX-7: `io::Error` messages from `remove_file` / `remove_dir_all` can
/// contain the full filesystem path.
///
/// S-LOW-A / C-B5 (round 8b): was an independent, byte-identical copy of
/// the naive `raw.replace(&home, "<home>")` implementation — destructive
/// when `HOME` is `/` (replaces every path separator in `raw`) and blind to
/// an OS-canonicalized home path that differs from the literal `$HOME` env
/// var. Delegates to `op_emit::redact_reason`, which fixes both, so this
/// crate has exactly one home-directory-scrub implementation rather than
/// two drifting independently.
fn logout_redact_reason(raw: &str) -> RedactedString {
    crate::audit::op_emit::redact_reason(raw)
}

/// Emit an OUTCOME record for a logout operation. Best-effort — the side
/// effect has already run by the time this is called (the intent is either
/// resolved or becomes a visible orphan for `csq doctor`), so a write
/// failure here does NOT propagate as an error to the caller. It IS logged:
/// S-LOW-C (round 9), the same fixed-vocabulary `audit_outcome_emit_failed`
/// WARN `move_slot::emit_failed` uses, so a failed OUTCOME write is
/// observable rather than silently discarded.
fn emit_logout_outcome(
    base_dir: &Path,
    chain_id: &str,
    correlation_id: crate::audit::types::RecordId,
    account: AccountNum,
    orphaned_uuid: Option<&str>,
    result: OpOutcome,
    intent_emitted: bool,
) {
    // FIX-1: if the intent was skipped (chain broken), skip the outcome too —
    // there is no correlation_id on the chain to match against.
    if !intent_emitted {
        return;
    }
    let payload = EventPayload::AccountLogout(AccountLogoutPayload {
        slot: account,
        orphaned_uuid: orphaned_uuid.map(|s| s.to_owned()),
    });
    if let Err(e) = op_emit::emit_outcome(
        base_dir,
        chain_id,
        EventKind::AccountLogout,
        payload,
        correlation_id,
        result,
    ) {
        // S-LOW-C (round 9): best-effort audit trail — the logout already
        // ran by this point, so a WARN is correct, not a propagated error.
        // `e.fixed_tag()` is a fixed vocabulary (`security.md` MUST-2).
        tracing::warn!(
            error_kind = "audit_outcome_emit_failed",
            op = "logout",
            audit_error_kind = e.fixed_tag(),
            "logout: failed to emit AccountLogout OUTCOME record (op already \
             completed; audit trail incomplete — the INTENT is left as an \
             orphan for scan_orphan_intents)"
        );
    }
}

/// Removes the `account` entry from `quota.json` so a recycled slot
/// can't display the previous tenant's usage. Best-effort — failures
/// are logged but don't fail the logout, since the credential file
/// is already gone and the daemon will just write fresh data on the
/// next poll cycle.
///
/// `pub(crate)` (not module-private): also called from
/// `accounts::third_party::bind_provider_to_slot` when a slot's
/// provider changes (MED-2, an internal ticket redteam) — same hazard as
/// logout's recycled slot, one level up: a 3P rebind (e.g. MiniMax →
/// Kimi on the same slot) must not leave the PRIOR provider's
/// `quota.json` row rendering under the NEW provider's tag until the
/// new provider's own poll happens to overwrite it.
pub(crate) fn remove_quota_entry(base_dir: &Path, account: AccountNum) -> bool {
    use crate::quota::state as quota_state;

    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = match crate::platform::lock::lock_file(&lock_path) {
        Ok(g) => g,
        Err(_) => return false,
    };

    let mut quota = match quota_state::load_state_or_skip(base_dir) {
        Ok(q) => q,
        Err(_) => return false,
    };

    let key = account.get().to_string();
    if quota.accounts.remove(&key).is_none() {
        return false;
    }

    quota_state::save_state(base_dir, &quota).is_ok()
}

/// Returns the PIDs of any live `claude` processes whose handle dir
/// is currently bound to `account` via the `.csq-account` symlink.
///
/// Scans `base_dir/term-*` for symlinked markers; resolves each
/// `.csq-account` and checks both the marker value and the
/// `.live-pid` sentinel for liveness. Dead PIDs are ignored — those
/// handle dirs are stale and the next sweep tick will collect them.
/// Public re-export for `move_slot::move_account` which needs the
/// same in-use guard. Wraps the internal helper unchanged so future
/// changes flow to both call sites.
pub(crate) fn scan_live_handle_dirs_for_account_pub(
    base_dir: &Path,
    account: AccountNum,
) -> LiveHandleDirScan {
    scan_live_handle_dirs_for_account(base_dir, account)
}

fn scan_live_handle_dirs_for_account(base_dir: &Path, account: AccountNum) -> LiveHandleDirScan {
    let mut bound = LiveHandleDirScan::default();
    for path in bound_handle_dirs(base_dir, account) {
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        // Either marker, and an unreadable one counts as IN USE (reported by dir NAME):
        // this guard refuses a destructive logout, so "cannot read" fails closed.
        let fallback = name.strip_prefix("term-").and_then(|s| s.parse().ok());
        match markers::handle_dir_in_use(&path, fallback, is_pid_alive) {
            Some(markers::HandleDirInUse::Pid(pid)) => bound.pids.push(pid),
            Some(markers::HandleDirInUse::MarkerUnreadable) => {
                tracing::warn!(
                    error_kind = "logout_pid_marker_unreadable",
                    dir_name = %display_dir_name(&name),
                    "handle dir has an unreadable pid marker; treating it as in use"
                );
                bound.unreadable_dirs.push(display_dir_name(&name));
            }
            None => {}
        }
    }
    bound
}

/// Enumerate every `term-*` handle dir under `base_dir` whose `.csq-account`
/// marker currently resolves to `account` — numeric or UUID format —
/// REGARDLESS of whether the owning process is alive.
///
/// Shared by [`scan_live_handle_dirs_for_account`] (which filters this list
/// down to the live-PID subset for the in-use refusal guard) and
/// [`clear_bound_keychain_items`] (which needs every bound dir INCLUDING
/// dead ones — a keychain OAuth item persists independently of whether the
/// process that made CC write it is still running). A second,
/// independently-written bound-detection scan is exactly the drift this
/// factoring exists to prevent (`account-terminal-separation.md` MUST NOT
/// Rule 3: the marker is the sole identity authority).
///
/// Same fail-toward-ambiguous posture as the former in-use scan body: a
/// UUID marker whose slot has no `by_slot` mapping is treated as bound (we
/// cannot rule it out); an absent/unparseable marker is skipped (we cannot
/// attribute it to any account — see the original in-line rationale this
/// replaced, preserved in git history at the pre-refactor revision).
///
/// **The fail-toward-bound posture is asymmetric across the two callers
/// (security review 1386 L1) — over-inclusion is SAFE for one and
/// UNSAFE for the other.** For [`scan_live_handle_dirs_for_account`] (a
/// refusal guard) over-inclusion means "refuse to delete" — the safe
/// direction. For [`clear_bound_keychain_items`] (a destructive operation)
/// the same over-inclusion means "clear another account's keychain item".
/// The blast radius there is bounded: a dir with a live PID is already
/// caught by the in-use guard and refuses the whole logout before this scan
/// is even reached for the keychain step, so the collateral is limited to
/// DEAD or unparseable-PID dirs, whose keychain items are themselves stale
/// mirrors nothing else reads. Still, do not add a THIRD caller on the
/// strength of this function's name alone without re-checking which
/// direction over-inclusion is safe for it.
fn bound_handle_dirs(base_dir: &Path, account: AccountNum) -> Vec<PathBuf> {
    let mut bound = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return bound,
    };

    // Resolved once: `account`'s own identity UUID, if `profiles.json`
    // currently maps it via `by_slot`. Both `logout_account` callers of
    // this scanner (the in-use guard AND the keychain-clear step) run
    // BEFORE removing the profiles entry (SAFETY-ORDERING), so a modern
    // (post-A++) Anthropic OAuth slot resolves here under normal operation.
    // ONE profiles snapshot for BOTH the account's own UUID and the reverse
    // map. Two separate loads admit a torn view — load#1 says "this account
    // has no UUID" while load#2 attributes our UUID to another slot — which
    // is precisely the delete-under-a-live-session state below (redteam M4).
    let profiles_snapshot = profiles::load(&profiles::profiles_path(base_dir)).ok();

    // Resolved once: `account`'s own identity UUID, if `profiles.json`
    // currently maps it via `by_slot`. Both `logout_account` callers of
    // this scanner (the in-use guard AND the keychain-clear step) run
    // BEFORE removing the profiles entry (SAFETY-ORDERING), so a modern
    // (post-A++) Anthropic OAuth slot resolves here under normal operation.
    let account_uuid = profiles_snapshot
        .as_ref()
        .and_then(|pf| pf.by_slot.get(&account.get().to_string()).copied());

    // The UUID our OWN config dir's marker claims, if it holds one.
    //
    // Load-bearing when `account_uuid` is None (redteam C1). "Attributed to
    // another slot" does NOT imply "not ours": the retired email-only
    // `mint_for_login` REUSED `by_email[email]`, so a legacy install can still have two slots share one UUID,
    // and the codex partial-mint rollback (`profiles::remove_slot_mapping`,
    // called from `providers/codex/{login,desktop_login}.rs`) drops
    // `by_slot[N]` while leaving `config-N/` and its UUID marker intact.
    // Without this check, a live handle dir resolving into our own config dir
    // would be attributed to the sibling slot that still holds the UUID, and
    // logout would delete the directory out from under it.
    let own_marker_uuid =
        markers::read_identity_marker(&base_dir.join(format!("config-{}", account.get())))
            .and_then(|m| m.uuid);

    // UUID -> LOWEST owning slot. `min` matches `profiles::resolve_uuid_to_slot`
    // so the two resolvers cannot disagree on a UUID bound to several slots
    // (redteam L5); a plain `collect` would keep an arbitrary hash-order slot.
    let uuid_owner: std::collections::HashMap<_, u16> = profiles_snapshot
        .as_ref()
        .map(|pf| {
            let mut m = std::collections::HashMap::new();
            for (k, v) in &pf.by_slot {
                if let Ok(slot) = k.parse::<u16>() {
                    m.entry(*v)
                        .and_modify(|s: &mut u16| *s = (*s).min(slot))
                        .or_insert(slot);
                }
            }
            m
        })
        .unwrap_or_default();

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("term-") {
            continue;
        }
        // Read the account marker through the handle dir's symlink,
        // accepting BOTH the legacy numeric format and the M4-7 UUID
        // format (see `markers::read_identity_marker`'s doc comment).
        // `login::finalize_login` writes the marker as the slot's identity
        // UUID whenever `profiles::resolve_slot_to_uuid` resolves — the
        // normal state for every modern Anthropic OAuth slot — so a
        // numeric-only read here (the pre-fix `read_csq_account`) is blind
        // to every such slot and callers relying on this scan could never
        // see it.
        let marker = match markers::read_identity_marker(&path) {
            Some(m) => m,
            // Marker absent or unparseable — cannot attribute this handle
            // dir to any account, so it is skipped. A handle dir with a
            // genuinely live process AND a corrupted/never-written marker
            // is a distinct, much rarer failure mode (atomic_replace never
            // leaves a torn read; a fresh handle dir mid-provision race is
            // the realistic case) — fail-closing here would block logout
            // on unrelated, unbound handle dirs.
            None => continue,
        };
        let is_bound = match (marker.numeric, marker.uuid) {
            (Some(n), None) => n == account,
            (None, Some(u)) => match account_uuid {
                Some(slot_uuid) => u == slot_uuid,
                // `account` has no `by_slot` UUID. That is NOT automatically
                // ambiguous: if this dir's UUID maps to a KNOWN slot, the dir
                // is definitively that slot's and provably not ours.
                //
                // Only a UUID we cannot attribute to any slot is genuinely
                // ambiguous, and there we keep the fail-TOWARD-bound posture —
                // a destructive operation must not proceed on a comparison it
                // cannot make (`guard-reader-writer-parity.md` MUST-2).
                None => {
                    if own_marker_uuid == Some(u) {
                        // Our own config dir claims this UUID — it may be ours
                        // even though `by_slot` attributes it elsewhere.
                        true
                    } else {
                        // Attributable to some OTHER known slot -> definitively
                        // that slot's. Unattributable -> genuinely ambiguous, so
                        // keep the fail-TOWARD-bound posture: a destructive
                        // operation must not proceed on a comparison it cannot
                        // soundly make (`guard-reader-writer-parity.md` MUST-2).
                        !uuid_owner.contains_key(&u)
                    }
                }
            },
            // `read_identity_marker`'s contract guarantees exactly one
            // field is `Some` on every `Some(_)` return (see its doc
            // comment + the `m1_5_property_10k_random_strings_no_panic_no_fallback`
            // property test) — this arm is unreachable, but fails toward
            // bound rather than silently skipping on a classification it
            // cannot make.
            _ => true,
        };
        if is_bound {
            bound.push(path);
        }
    }

    bound
}

/// Clears the macOS keychain OAuth item for every handle dir bound to
/// `account` — live or dead — via [`bound_handle_dirs`], before the
/// credential/config-dir sweep in [`logout_account`] deletes the state that
/// scan needs to find them.
///
/// Closes the third credential-resurrection source on the logout path
/// (an internal ticket closed the file-level and Gemini-vault ones): current CC reads
/// OAuth from the per-handle-dir macOS keychain item FIRST, keyed by the
/// handle dir's own canonicalized path — a mirror `logout_account` never
/// touched before this existed. A DEAD bound handle dir (owning process
/// already exited, not yet reaped by
/// `session::handle_dir::sweep_dead_handles`, which itself does not clear
/// this item either) still carries a keychain entry CC wrote while it was
/// live; once `config_dir` is removed below, nothing can ever locate or
/// clear it again — it becomes a permanent orphan.
///
/// **Fail-open, unlike the Gemini vault step above — WITH a compensating
/// mechanism (security review 1386 H1).** At the moment this step runs, the
/// keychain item IS a mirror — the same credential also lives at
/// `identities/<UUID>/credentials.json` and `config-N/.credentials.json`.
/// But those file copies are deleted by THIS SAME `logout_account` call, a
/// few statements later — so on the `Err` branch below, the keychain item
/// can become the credential's ONLY surviving copy at function exit, not
/// "never the sole copy." Refusing the entire logout on a keychain timeout
/// is still the wrong trade (a locked/unreachable keychain is a common,
/// transient, RECOVERABLE operator condition — headless / SSH / tmux
/// session with no Aqua session, `security.md` §6 — refusing here would
/// trap an operator who most needs to remove a compromised or leaked slot;
/// unlike `csq swap` / `auto_rotate`'s v4 forced write — which correctly
/// refuses the SWITCH on the same condition, per `force_sync_account_changed`
/// — a logout has nothing left to protect by refusing: the file copies are
/// deleted either way, a few statements later). So
/// instead of accepting that residual as permanent, an unconfirmed clear is
/// queued via [`crate::credentials::keychain::record_pending_clear`] and
/// retried by the daemon's periodic sweep and `csq run`'s opportunistic
/// sweep (`keychain::sweep_pending_clears`) — see that module's queue docs.
/// Failures are NEVER silently dropped either way (`zero-tolerance.md` Rule
/// 3): each unconfirmed clear is logged at WARN with a fixed-vocabulary
/// `error_kind` (handle-dir NAME only, never an absolute path —
/// `security.md` MUST-2), and the aggregate result is reported on
/// `LogoutSummary::keychain_cleared` — plus
/// `LogoutSummary::keychain_retry_queue_failed` when an unconfirmed clear
/// could not even be queued for automatic retry (R3 sec M-D / corr L-3).
fn clear_bound_keychain_items(base_dir: &Path, account: AccountNum) -> KeychainClearOutcome {
    let mut outcome = KeychainClearOutcome::default();
    for path in bound_handle_dirs(base_dir, account) {
        let dir_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Security review 1386 M1: a canonicalize failure must NOT fall back to
        // the non-canonical `path` — that hashes to a DIFFERENT keychain service
        // name than the one CC actually uses (CC hashes the canonicalized
        // `CLAUDE_CONFIG_DIR`), so `clear_handle_dir_reporting` would delete
        // nothing, `security` would report "no such item" (a subprocess that ran
        // to completion), and this loop would wrongly record `any_confirmed =
        // true` for a dir whose REAL item was never touched. Matches
        // `sync_all_handle_dirs`'s existing disposition on the same failure
        // (count as skipped, never as a false "handled").
        let Ok(abs) = std::fs::canonicalize(&path) else {
            tracing::warn!(
                error_kind = "keychain_clear_canonicalize_failed",
                account = account.get(),
                dir = %dir_name,
                "logout: could not canonicalize this handle dir's path — its \
                 keychain item (if any) was NOT targeted for clearing (non-fatal — \
                 logout continues)"
            );
            continue;
        };
        let result = crate::credentials::keychain::clear_handle_dir_reporting(&abs);
        let (confirmed, needs_retry) = note_clear_result(result);
        let mut queued = true;
        if needs_retry {
            // Security review 1386 H1: the file-based copies of this
            // credential are deleted later in THIS SAME logout_account call
            // (ALL_SURFACES sweep, config_dir removal, identity dir removal),
            // so an item that could not be confirmed cleared here can become
            // the credential's ONLY surviving copy at function exit. Queue it
            // for retry by the daemon's periodic sweep and by `csq run`'s
            // opportunistic sweep, rather than leaving it a silent, permanent
            // orphan the moment `config_dir` disappears below.
            // `keychain-fix-r9.md` S-M-1/D-F2: `Logout` origin — the retry
            // repeats the SAME unconditional delete-by-service-name this
            // call just attempted (`clear_handle_dir_reporting`, above),
            // never decide+adopt. No candidate email or account-attribute
            // hint is needed for that disposition.
            queued = crate::credentials::keychain::record_pending_clear(
                base_dir,
                &crate::credentials::keychain::service_name(&abs),
                Some(account),
                crate::credentials::keychain::PendingClearOrigin::Logout,
                None,
                None,
            );
            // R3 sec M-D / corr L-3: a refused queue write is NOT "queued for
            // automatic retry". The item may survive this logout with nothing
            // left to retry it, so the refusal is both logged accurately and
            // carried on the summary for the operator.
            if queued {
                tracing::warn!(
                    error_kind = "keychain_clear_unconfirmed",
                    account = account.get(),
                    dir = %dir_name,
                    "logout: could not confirm the keychain OAuth item was cleared for \
                     this handle dir (non-fatal — keychain may be locked or unavailable; \
                     queued for automatic retry; logout continues)"
                );
            } else {
                tracing::warn!(
                    error_kind = "keychain_clear_unconfirmed_not_queued",
                    account = account.get(),
                    dir = %dir_name,
                    "logout: could not confirm the keychain OAuth item was cleared for \
                     this handle dir, and the automatic retry could NOT be queued \
                     (the retry spool is full or unwritable); the item may survive \
                     this logout — logout continues"
                );
            }
        }
        fold_clear_outcome(&mut outcome, confirmed, needs_retry, queued);
    }
    outcome
}

/// Fold ONE handle dir's outcome into the aggregate (R3 sec M-D / corr L-3).
///
/// `queued` is the durable-retry result: `false` means the unconfirmed clear
/// could NOT be persisted, so the keychain item may survive with no sweep to
/// retry it. The refusal is no longer log-only — it sets
/// [`KeychainClearOutcome::retry_queue_failed`], which [`LogoutSummary`]
/// carries to the CLI and IPC result.
fn fold_clear_outcome(
    outcome: &mut KeychainClearOutcome,
    confirmed: bool,
    needs_retry: bool,
    queued: bool,
) {
    if confirmed {
        outcome.any_confirmed = true;
    }
    if needs_retry && !queued {
        outcome.retry_queue_failed = true;
    }
}

/// What [`clear_bound_keychain_items`] reports: whether ANY bound handle
/// dir's keychain item was confirmed cleared, and whether any unconfirmed
/// clear could not even be QUEUED for automatic retry (R3 sec M-D / corr
/// L-3). Both are operator-visible through [`LogoutSummary`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct KeychainClearOutcome {
    any_confirmed: bool,
    retry_queue_failed: bool,
}

/// Pure decision for one handle dir's keychain-clear result: does
/// `any_confirmed` update, and does it need a WARN + retry queue entry?
/// Factored out (security review 1386 L2) so this branch is unit-testable
/// without touching a real keychain — `clear_handle_dir_reporting` itself
/// cannot be exercised meaningfully from a unit test
/// (`keychain_mirror_disabled()` is unconditionally `true` under
/// `cfg!(test)`, so it always returns `Ok(false)` there), but this decision
/// over a SYNTHETIC `Result` can be.
///
/// Returns `(confirmed, needs_retry)`: `Ok(true)` → `(true, false)`;
/// `Ok(false)` (structural no-op — non-macOS / disabled) → `(false,
/// false)`, never a failure; `Err(_)` → `(false, true)`, the WARN +
/// pending-clear-queue case.
fn note_clear_result(
    result: Result<bool, crate::credentials::keychain::KeychainClearUnconfirmed>,
) -> (bool, bool) {
    match result {
        Ok(true) => (true, false),
        Ok(false) => (false, false),
        Err(crate::credentials::keychain::KeychainClearUnconfirmed) => (false, true),
    }
}

/// Removes the `account` entry from `profiles.json`, including the
/// corresponding `by_slot`, `by_email`, and `by_slot_identity` entries.
///
/// # Lock precondition
///
/// The caller MUST hold `_lock` (a [`ProfilesFileLock`]) for `base_dir`
/// before calling this function. The type-witness parameter enforces this
/// at compile time — passing `&lock` makes the lock scope statically
/// visible at every callsite. Rationale: this performs a read-modify-write
/// cycle on `profiles.json`; the lock serializes against the daemon mint
/// paths and `csq login`.
///
/// # by_email conditional removal
///
/// When the removed slot had email `alice@x.com` (from `accounts[N].email`),
/// `by_email["alice@x.com"]` is only removed if no other `by_slot` entry
/// still references the same UUID — i.e. if no other slot shares that email
/// identity. This handles the M1-4 reuse-by-email path where two slots may
/// map to the same UUID.
///
/// # by_slot_identity removal (M9 — FM-9 (c))
///
/// `by_slot_identity[N]` is always removed unconditionally when present.
/// The entry is slot-scoped (not shared across slots like `by_email` UUIDs),
/// so there is no conditional guard needed. Omitting this removal would leave
/// a zombie identity entry: a recycled slot number would inherit the previous
/// tenant's identity label until the next daemon backfill overwrites it.
///
/// Returns true if an `accounts` entry was actually removed, false if the
/// file or entry was absent.
/// Removes the slot's `profiles.json` entries (`by_slot`, conditional
/// `by_email`, `by_slot_identity`, `accounts`).
///
/// Returns `(entry_removed, orphaned_uuid)` where `orphaned_uuid` is `Some(u)`
/// iff this removal dropped the LAST reference to UUID `u` — i.e. after the
/// removal `u` is in NEITHER `by_slot` NOR `by_email`. The caller deletes that
/// identity dir at the source. A shared UUID (still referenced by another
/// slot) yields `None`, preserving the sibling slot's credentials. This is the
/// same `by_slot ∪ by_email` reachability predicate the
/// `orphan_identity_gc::prune_orphan_identities` GC pass uses, applied at the
/// source so the GC has nothing to collect in the steady state.
fn remove_profiles_entry(
    lock: &ProfilesFileLock,
    base_dir: &Path,
    account: AccountNum,
) -> Result<(bool, Option<IdentityId>), LogoutError> {
    remove_profiles_entry_with(lock, base_dir, account, profiles::save)
}

fn remove_profiles_entry_with(
    lock: &ProfilesFileLock,
    base_dir: &Path,
    account: AccountNum,
    save: impl FnOnce(&Path, &profiles::ProfilesFile) -> Result<(), crate::error::ConfigError>,
) -> Result<(bool, Option<IdentityId>), LogoutError> {
    remove_profiles_entry_with_stat(lock, base_dir, account, save, |path| {
        std::fs::symlink_metadata(path)
    })
}

fn remove_profiles_entry_with_stat(
    lock: &ProfilesFileLock,
    base_dir: &Path,
    account: AccountNum,
    save: impl FnOnce(&Path, &profiles::ProfilesFile) -> Result<(), crate::error::ConfigError>,
    confirm_stat: impl FnOnce(&Path) -> std::io::Result<std::fs::Metadata>,
) -> Result<(bool, Option<IdentityId>), LogoutError> {
    remove_profiles_entry_with_marker(
        lock,
        base_dir,
        account,
        save,
        confirm_stat,
        crate::accounts::identity_store::mark_identity_removed_checked,
    )
}

fn remove_profiles_entry_with_marker(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    account: AccountNum,
    save: impl FnOnce(&Path, &profiles::ProfilesFile) -> Result<(), crate::error::ConfigError>,
    confirm_stat: impl FnOnce(&Path) -> std::io::Result<std::fs::Metadata>,
    mark: impl FnOnce(
        &Path,
        IdentityId,
    ) -> std::io::Result<crate::accounts::identity_store::RemovalMarker>,
) -> Result<(bool, Option<IdentityId>), LogoutError> {
    let path = profiles::profiles_path(base_dir);
    if !path.exists() {
        return Ok((false, None));
    }
    let mut file = profiles::load(&path).map_err(LogoutError::Profiles)?;
    let key = account.get().to_string();

    // Extract email and UUID before removing so we can clean by_email.
    //
    // M4-9 (release N affordance, an internal ticket Phase 4): the v1
    // `accounts[N].email` is empty-write in production, so the email
    // source-of-truth shifted to the `by_email` reverse-lookup. We
    // resolve it via the slot's UUID. If a populated `accounts[N]`
    // entry exists (user rename or v2.6.x downgrade re-save), it
    // takes precedence — but the by_email cleanup MUST use the OAuth
    // email keyed in `by_email`, not the rename label, so we resolve
    // both sources and use the by_email-keyed string for cleanup.
    let removed_uuid = file.by_slot.remove(&key);
    let removed_email: Option<String> = removed_uuid.and_then(|uuid| {
        file.by_email
            .iter()
            .find_map(|(e, u)| (*u == uuid).then_some(e.clone()))
    });
    // M4-13: accounts struct field removed; legacy email fallback now reads
    // from extra["accounts"] for pure-legacy fixtures with no by_slot mapping.
    let legacy_accounts = profiles::legacy_accounts_email_map(&file);
    let removed_email_legacy = legacy_accounts.get(&key).cloned();

    if let (Some(email), Some(uuid)) = (removed_email.as_ref(), removed_uuid) {
        // Only remove the by_email entry if no other by_slot entry still
        // references this UUID (i.e. no other slot shares the same email
        // identity via the M1-4 reuse path).
        let still_referenced = file.by_slot.values().any(|u| u == &uuid);
        if !still_referenced {
            // Remove from by_email only if it points to the same UUID we're
            // removing — guard against the case where a later login rewrote
            // by_email to a different UUID.
            if file.by_email.get(email).copied() == Some(uuid) {
                file.by_email.remove(email);
            }
        }
    } else if let Some(legacy_email) = removed_email_legacy.as_ref() {
        // Pure-legacy path: no by_slot/by_email maps to clean. The extra
        // remove below handles the cleanup; this branch exists so the
        // variable is not dead under the legacy fixture shape.
        let _ = legacy_email;
    }

    if let Some(uuid) = removed_uuid {
        if !file.by_slot.values().any(|other| *other == uuid) {
            // Remove only this exact local identity's context entries. A same
            // email belonging to another org/UUID remains reuse-eligible.
            file.anthropic_contexts
                .retain(|entry| entry.identity_uuid != uuid);
        }
    }
    // Increment the slot generation even when it becomes unbound: an ABA rebind
    // cannot revive an old HTTP capture.
    let generation = file
        .slot_binding_generations
        .entry(key.clone())
        .or_default();
    *generation = generation.checked_add(1).ok_or_else(|| {
        LogoutError::Profiles(crate::error::ConfigError::InvalidJson {
            path: path.clone(),
            reason: "slot_generation_exhausted".into(),
        })
    })?;

    // Review R2 L-R2-1: the slot's bounded binding history is cleared in
    // this same locked mutation. Logout tombstones only the identity that
    // logged out, never its predecessors — leaving `history[N]` in place
    // means a later `csq login N` as a NEW identity E still admits N's
    // earlier tenants' stored tokens (the reader admits unbound,
    // non-removed history members). Clearing it makes the vacated slot
    // admit nothing, so a stale foreign token in E's item takes the
    // harvest-first refusal.
    let _ = file.slot_binding_history.remove(&key);

    // Remove the legacy `accounts[key]` entry from extra if present.
    let accounts_had_entry = if let Some(accounts_val) = file.extra.get_mut("accounts") {
        if let Some(obj) = accounts_val.as_object_mut() {
            obj.remove(key.as_str()).is_some()
        } else {
            false
        }
    } else {
        false
    };
    // M9 — FM-9 (c): remove the non-OAuth identity-class label so a
    // recycled slot number cannot inherit the previous tenant's identity.
    // Unconditional — `by_slot_identity` is slot-scoped, not shared.
    file.by_slot_identity.remove(&key);

    // Orphan-identity GC source-fix: after all map removals, is the removed
    // UUID now fully unreferenced? (in neither by_slot nor by_email). If so,
    // it is a freshly-orphaned identity dir the caller deletes at the source.
    // This re-checks BOTH maps against the FINAL in-memory state rather than
    // reusing `still_referenced` (by_slot only) — a by_email straggler under a
    // different email key must still KEEP the dir (reuse-eligible).
    let orphaned_uuid = removed_uuid.filter(|u| {
        !file.by_slot.values().any(|x| x == u)
            && !file.by_email.values().any(|x| x == u)
            && !file
                .anthropic_contexts
                .iter()
                .any(|entry| entry.identity_uuid == *u)
    });

    let mut removal_marker = None;
    // Publish the last-reference tombstone while profiles authority is still
    // held, before an unbound row can become visible to legacy repair.
    if let Some(uuid) = orphaned_uuid {
        let marker = crate::accounts::identity_store::identity_removed_marker_path(base_dir, uuid);
        let witness = mark(base_dir, uuid).map_err(|source| {
            if source.kind() == std::io::ErrorKind::InvalidData {
                LogoutError::NonregularTombstone {
                    path: marker.clone(),
                }
            } else if source.kind() == std::io::ErrorKind::NotADirectory {
                LogoutError::UnsafeTombstoneNamespace {
                    path: crate::accounts::identity_store::identities_dir(base_dir),
                }
            } else {
                LogoutError::Io {
                    path: marker.clone(),
                    source,
                }
            }
        })?;
        // A writer's fail-closed "removed or unreadable" result is not proof
        // that logout has confirmed a regular marker before unlinking profiles.
        if !confirm_stat(&marker).is_ok_and(|metadata| metadata.is_file()) {
            witness.rollback_if_created();
            return Err(LogoutError::Io {
                path: marker,
                source: std::io::Error::other("identity removal tombstone could not be confirmed"),
            });
        }
        removal_marker = Some(witness);
        #[cfg(test)]
        run_logout_ordering_hook(base_dir, uuid, true);
    }
    if let Err(error) = save(&path, &file) {
        // Profiles still authorizes the old binding. Undo only the marker this
        // attempt created; never clear a previously removed identity's guard.
        if let Some(marker) = removal_marker {
            marker.rollback_if_created();
        }
        return Err(LogoutError::Profiles(error));
    }
    // Return true if EITHER channel had an entry to clean. Under M4-9
    // the post-mint normal case has by_slot[N] populated but
    // accounts[N] empty — that still counts as a successful removal.
    Ok((accounts_had_entry || removed_uuid.is_some(), orphaned_uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::profiles::{AccountProfile, ProfilesFile};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    fn account(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Minimal structured tracing capture for logout's fixed-vocabulary WARNs.
    /// Same shape as the crate's other capture fixtures: thread-local
    /// `set_default`/`with_default`, never a global subscriber, and it records
    /// only `error_kind` + `message` (no credentials, no paths asserted).
    #[derive(Clone, Debug, Default)]
    struct CapturedWarn {
        error_kind: Option<String>,
        message: Option<String>,
    }

    #[derive(Clone, Default)]
    struct WarnLog(std::sync::Arc<std::sync::Mutex<Vec<CapturedWarn>>>);

    impl WarnLog {
        fn error_kinds(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter_map(|event| event.error_kind.clone())
                .collect()
        }

        fn has_error_kind(&self, tag: &str) -> bool {
            self.0
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.error_kind.as_deref() == Some(tag))
        }
    }

    struct WarnVisitor<'a>(&'a mut CapturedWarn);

    impl tracing::field::Visit for WarnVisitor<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "error_kind" => self.0.error_kind = Some(value.to_owned()),
                "message" => self.0.message = Some(value.to_owned()),
                _ => {}
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" && self.0.message.is_none() {
                self.0.message = Some(format!("{value:?}"));
            }
        }
    }

    impl tracing::Subscriber for WarnLog {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::level_filters::LevelFilter::WARN
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::WARN)
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut captured = CapturedWarn::default();
            event.record(&mut WarnVisitor(&mut captured));
            self.0.lock().unwrap().push(captured);
        }
    }

    fn provision_account(base: &Path, n: u16) {
        let canonical_dir = base.join("credentials");
        fs::create_dir_all(&canonical_dir).unwrap();
        fs::write(canonical_dir.join(format!("{n}.json")), "{}").unwrap();

        let config_dir = base.join(format!("config-{n}"));
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join(".credentials.json"), "{}").unwrap();
        fs::write(config_dir.join(".csq-account"), n.to_string()).unwrap();
        fs::write(config_dir.join("settings.json"), "{}").unwrap();
    }

    fn write_profiles(base: &Path, accounts: &[(u16, &str)]) {
        let mut file = ProfilesFile::empty();
        for (n, email) in accounts {
            file.set_profile(
                *n,
                AccountProfile {
                    email: email.to_string(),
                    method: "oauth".into(),
                    extra: HashMap::new(),
                },
            );
        }
        profiles::save(&profiles::profiles_path(base), &file).unwrap();
    }

    fn write_quota_for(base: &Path, n: u16, pct_7d: f64) {
        use crate::quota::state as quota_state;
        use crate::quota::{AccountQuota, UsageWindow};
        let mut q = quota_state::load_state_salvage(base);
        q.set(
            n,
            AccountQuota {
                // resets_at deliberately in the year 2100 so
                // clear_expired() doesn't null the window mid-test.
                seven_day: Some(UsageWindow {
                    used_percentage: pct_7d,
                    resets_at: 4_102_444_800,
                }),
                ..Default::default()
            },
        );
        quota_state::save_state(base, &q).unwrap();
    }

    #[test]
    fn logout_removes_canonical_and_config_dir() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 3);

        let summary = logout_account(dir.path(), account(3)).unwrap();

        assert!(summary.canonical_removed);
        assert!(summary.config_dir_removed);
        assert!(!dir.path().join("credentials/3.json").exists());
        assert!(!dir.path().join("config-3").exists());
    }

    /// Review R2 L-R2-1: `csq logout N` clears the slot's bounded binding
    /// history in the same locked mutation that unbinds it. Logout
    /// tombstones only the identity that logged out, never its
    /// predecessors — without this clear, a later `csq login N` as a NEW
    /// identity E still admits N's earlier tenants' stored tokens (the
    /// reader admits unbound, non-removed history members).
    #[test]
    fn logout_clears_the_slots_binding_history() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "history@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        // The slot's earlier tenant, planted exactly as the rebind writer
        // records it.
        let prior = IdentityId::new_v4();
        let path = profiles::profiles_path(dir.path());
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        {
            let mut file = profiles::load(&path).unwrap();
            profiles::record_binding_displacement(&mut file, 1, prior);
            profiles::save(&path, &file).unwrap();
        }
        assert_eq!(
            profiles::load(&path).unwrap().slot_binding_history.get("1"),
            Some(&vec![prior]),
            "fixture precondition: the slot carries lineage before logout"
        );

        remove_profiles_entry(&lock, dir.path(), account(1)).unwrap();

        let after = profiles::load(&path).unwrap();
        assert!(!after.by_slot.contains_key("1"), "the slot is unbound");
        assert_eq!(
            after.slot_binding_history.get("1"),
            None,
            "logout must clear the slot's binding history (review R2 L-R2-1)"
        );
    }

    /// Removing an account RESOLVES the broker-failed condition permanently —
    /// there is no longer a slot to re-login — so logout is a clearing
    /// boundary under `sentinel-clearing-parity.md` MUST-1.
    ///
    /// Before this, the sentinel outlived its slot: `csq doctor` reported
    /// `✗ Account 7: LOGIN-NEEDED (oauth) — run `csq login 7`` for a slot with
    /// no profiles entry, no quota row, no config dir and no credentials.
    /// Observed live 2026-08-07 after the operator removed slot 7 — a hard
    /// FAIL on the health surface directing them to log into an account they
    /// had deliberately deleted.
    ///
    /// Non-vacuity: drop the `clear_broker_failed` call from `logout_account`
    /// and the second assertion fails with the sentinel still on disk.
    #[test]
    fn logout_clears_the_broker_failed_sentinel() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 7);
        // `.expect`, not a dropped Result: if the setter silently failed the
        // precondition assertion below would be the only thing standing
        // between this test and proving nothing.
        crate::refresh::sentinel::set_broker_failed(dir.path(), account(7), "oauth")
            .expect("set_broker_failed must succeed to arm this test");
        assert!(
            crate::refresh::sentinel::is_broker_failed(dir.path(), account(7)),
            "precondition: the sentinel must be set before logout, or this \
             test proves nothing"
        );

        logout_account(dir.path(), account(7)).unwrap();

        assert!(
            !crate::refresh::sentinel::is_broker_failed(dir.path(), account(7)),
            "a removed slot must not keep a broker-failed sentinel — it makes \
             `csq doctor` demand a login for an account that no longer exists"
        );
    }

    #[test]
    fn logout_removes_profiles_entry() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 5);
        write_profiles(dir.path(), &[(5, "alice@example.com")]);

        let summary = logout_account(dir.path(), account(5)).unwrap();
        assert!(summary.profiles_entry_removed);

        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(!reloaded.accounts_for_test().contains_key("5"));
    }

    /// Originating bug: `csq logout 12` on a Codex slot left
    /// `credentials/codex-12.json` on disk so `discover_codex` kept
    /// surfacing the slot to the desktop dashboard. Pinning the
    /// per-surface sweep at the test boundary so a future refactor
    /// cannot silently regress to the ClaudeCode-only shape.
    #[test]
    fn logout_removes_codex_canonical_credential_file() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        fs::create_dir_all(&creds).unwrap();
        fs::write(creds.join("codex-12.json"), "{}").unwrap();

        let summary = logout_account(dir.path(), account(12)).unwrap();
        assert!(summary.canonical_removed);
        assert!(!creds.join("codex-12.json").exists());
    }

    #[test]
    fn logout_removes_gemini_canonical_credential_file() {
        // Host-safety: the marker's presence makes `logout_account` reach
        // the new Gemini vault-clear step (`is_gemini_bound_slot` is a bare
        // `symlink_metadata` check on this exact path), which would
        // otherwise call `open_default_vault()` against the REAL platform
        // backend (macOS Keychain / Secret Service / DPAPI) — BLOCKED by
        // `security.md` MUST-6 / this repo's host-safe-test discipline
        // (`feedback_no_security_w_on_cc_keychain`). Pin the in-memory
        // backend for the duration of this test.
        let _env_guard = crate::platform::test_env::lock();
        let prev = std::env::var("CSQ_SECRET_BACKEND").ok();
        std::env::set_var("CSQ_SECRET_BACKEND", "in-memory");

        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        fs::create_dir_all(&creds).unwrap();
        fs::write(creds.join("gemini-13.json"), "{}").unwrap();

        let summary = logout_account(dir.path(), account(13)).unwrap();
        assert!(summary.canonical_removed);
        assert!(!creds.join("gemini-13.json").exists());

        match prev {
            Some(v) => std::env::set_var("CSQ_SECRET_BACKEND", v),
            None => std::env::remove_var("CSQ_SECRET_BACKEND"),
        }
    }

    /// D7/CLI-parity regression: a Gemini ApiKey-bound slot's OS-keychain
    /// vault entry previously survived `csq logout` (the CLI never called
    /// the vault-clear sequence the desktop `remove_account` D7 path used).
    /// `logout_account` now runs the vault-clear step itself, so BOTH
    /// surfaces get it for free. In-memory backend — see the host-safety
    /// note on `logout_removes_gemini_canonical_credential_file` above; a
    /// fresh `InMemoryVault` is created per `open_default_vault()` call
    /// (no cross-call persistence), so this proves the WIRING (the step
    /// runs, reports success, and is idempotent) rather than an literal
    /// before/after existence check on a pre-seeded secret — that finer
    /// grain is already covered by `providers::gemini::provisioning`'s own
    /// `delete_api_key_from_vault` unit tests, which control the `Vault`
    /// instance directly.
    #[test]
    fn logout_clears_gemini_api_key_vault_entry() {
        let _env_guard = crate::platform::test_env::lock();
        let prev = std::env::var("CSQ_SECRET_BACKEND").ok();
        std::env::set_var("CSQ_SECRET_BACKEND", "in-memory");

        let dir = TempDir::new().unwrap();
        let slot_n = 19u16;
        let creds = dir.path().join("credentials");
        fs::create_dir_all(&creds).unwrap();
        let binding = serde_json::json!({
            "v": 1,
            "auth": { "mode": "api_key" },
            "model_name": "auto",
            "created_unix_secs": 0_u64,
        });
        fs::write(
            creds.join(format!("gemini-{slot_n}.json")),
            binding.to_string(),
        )
        .unwrap();

        let result = logout_account(dir.path(), account(slot_n));

        match prev {
            Some(v) => std::env::set_var("CSQ_SECRET_BACKEND", v),
            None => std::env::remove_var("CSQ_SECRET_BACKEND"),
        }

        let summary = result.expect("logout of an ApiKey-bound Gemini slot must succeed");
        assert!(
            summary.gemini_vault_cleared,
            "an ApiKey-bound Gemini slot must report its vault entry cleared"
        );
        assert!(summary.canonical_removed);
        assert!(
            !creds.join(format!("gemini-{slot_n}.json")).exists(),
            "the binding marker must be gone — no residual signal that a \
             vault entry might still exist for this slot"
        );
    }

    /// A non-Gemini slot must never report `gemini_vault_cleared` and must
    /// never attempt to open the vault — `is_gemini_bound_slot` gates the
    /// whole step on the marker's presence.
    #[test]
    fn logout_non_gemini_slot_does_not_report_vault_cleared() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 15);

        let summary = logout_account(dir.path(), account(15)).unwrap();
        assert!(
            !summary.gemini_vault_cleared,
            "a plain ClaudeCode slot must report no gemini vault cleared"
        );
    }

    #[test]
    fn logout_removes_native_binding_marker() {
        // W3 user-path smoke found logout was blind to native markers,
        // trapping the slot (login refuses via conflict guard, logout said
        // "not configured"). ALL_SURFACES now includes Kimi/Grok.
        for (file, slot_n) in [("kimi-14.json", 14u16), ("grok-15.json", 15u16)] {
            let dir = TempDir::new().unwrap();
            let creds = dir.path().join("credentials");
            fs::create_dir_all(&creds).unwrap();
            fs::write(
                creds.join(file),
                r#"{"v":1,"surface":"kimi","created_unix_secs":0}"#,
            )
            .unwrap();
            let summary = logout_account(dir.path(), account(slot_n)).unwrap();
            assert!(summary.canonical_removed, "{file} should be swept");
            assert!(!creds.join(file).exists(), "{file} must be gone");
        }
    }

    /// redteam R2: a slot whose ONLY binding is a DANGLING native marker
    /// symlink is detected as bound by `binding_guard::detect_bound_surface`
    /// (which uses `symlink_metadata` → refuses new binds), so `logout` MUST
    /// also treat it as present (NOT `NotConfigured`) and remove it — else the
    /// slot is trapped: nothing can bind it and nothing can clear it.
    #[test]
    #[cfg(unix)]
    fn logout_removes_dangling_native_marker_symlink() {
        let dir = TempDir::new().unwrap();
        let slot_n = 18u16;
        let marker = native::marker_path(dir.path(), account(slot_n), Surface::Kimi);
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(dir.path().join("does-not-exist.json"), &marker).unwrap();
        assert!(!marker.exists(), "precondition: symlink target is absent");
        assert!(
            std::fs::symlink_metadata(&marker).is_ok(),
            "precondition: the dangling symlink itself is present"
        );

        let summary = logout_account(dir.path(), account(slot_n))
            .expect("dangling native marker slot must be logout-able, not NotConfigured");

        assert!(
            summary.canonical_removed,
            "the dangling marker must be swept"
        );
        assert!(
            std::fs::symlink_metadata(&marker).is_err(),
            "the dangling marker symlink must be gone"
        );
    }

    /// 0135 design lock, Wave C shard C3: a native slot's REAL vendor
    /// credentials live in `native-homes/<surface>-<N>/`, not in the
    /// credential-less marker — `logout_account` MUST remove BOTH.
    #[test]
    fn logout_removes_native_vendor_home_dir() {
        let dir = TempDir::new().unwrap();
        let slot_n = 16u16;

        native::write_binding(dir.path(), account(slot_n), Surface::Kimi).unwrap();
        let home = native::native_home_path(dir.path(), account(slot_n), Surface::Kimi);
        // Plant a fake vendor cred file at the real cred_relpath, mirroring
        // what the `kimi` binary would have written on a real login.
        let cred_path = home.join("credentials").join("kimi-code.json");
        fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        fs::write(&cred_path, r#"{"access_token":"fake"}"#).unwrap();

        let marker = native::marker_path(dir.path(), account(slot_n), Surface::Kimi);
        assert!(marker.exists(), "precondition: marker must exist");
        assert!(home.exists(), "precondition: vendor home must exist");

        let summary = logout_account(dir.path(), account(slot_n)).unwrap();

        assert!(
            summary.native_home_removed,
            "native_home_removed must be true when a vendor home was removed"
        );
        assert!(!marker.exists(), "binding marker must be gone");
        assert!(!home.exists(), "vendor home dir must be gone");
    }

    /// Logging out a NON-native slot MUST NOT error and MUST NOT create or
    /// touch any `native-homes/` dir — `remove_native_homes` is gated on
    /// `Surface::is_native_cli()` and only resolves paths for Kimi/Grok.
    #[test]
    fn logout_non_native_slot_does_not_touch_native_homes() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 17);

        let result = logout_account(dir.path(), account(17));
        assert!(result.is_ok(), "got: {result:?}");
        let summary = result.unwrap();
        assert!(
            !summary.native_home_removed,
            "a plain ClaudeCode slot must report no native home removed"
        );
        assert!(
            !dir.path().join("native-homes").exists(),
            "logout of a non-native slot must never create native-homes/"
        );
    }

    /// A slot that has ONLY a Codex credential file (no `config-N/`,
    /// no ClaudeCode `N.json`) MUST not be misclassified as
    /// `NotConfigured` — that would silently leave the credential file
    /// on disk and reproduce the original bug.
    #[test]
    fn logout_codex_only_slot_does_not_return_not_configured() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        fs::create_dir_all(&creds).unwrap();
        fs::write(creds.join("codex-14.json"), "{}").unwrap();

        let result = logout_account(dir.path(), account(14));
        assert!(result.is_ok(), "got: {result:?}");
    }

    #[test]
    fn logout_returns_not_configured_when_account_missing() {
        let dir = TempDir::new().unwrap();
        match logout_account(dir.path(), account(7)) {
            Err(LogoutError::NotConfigured { account: a }) => assert_eq!(a, account(7)),
            other => panic!("expected NotConfigured, got {other:?}"),
        }
    }

    #[test]
    fn logout_preserves_other_accounts() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        provision_account(dir.path(), 2);
        provision_account(dir.path(), 3);
        write_profiles(
            dir.path(),
            &[
                (1, "a@example.com"),
                (2, "b@example.com"),
                (3, "c@example.com"),
            ],
        );

        logout_account(dir.path(), account(2)).unwrap();

        assert!(dir.path().join("credentials/1.json").exists());
        assert!(dir.path().join("credentials/3.json").exists());
        assert!(dir.path().join("config-1").exists());
        assert!(dir.path().join("config-3").exists());
        assert!(!dir.path().join("credentials/2.json").exists());
        assert!(!dir.path().join("config-2").exists());

        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(reloaded.accounts_for_test().contains_key("1"));
        assert!(reloaded.accounts_for_test().contains_key("3"));
        assert!(!reloaded.accounts_for_test().contains_key("2"));
    }

    /// A handle dir named `term-<name_pid>` bound to account `n` via the real symlink.
    #[cfg(unix)]
    fn bound_term_dir(base: &Path, n: u16, name_pid: u32) -> PathBuf {
        let handle = base.join(format!("term-{name_pid}"));
        fs::create_dir_all(&handle).unwrap();
        std::os::unix::fs::symlink(
            base.join(format!("config-{n}")).join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        handle
    }

    /// `.live-pid` names a dead process; `.live-cc-pid` names THIS (live) process, the
    /// SIGKILLed-csq-parent shape. Logout must refuse.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_when_only_live_cc_pid_is_alive() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 4);
        let handle = bound_term_dir(dir.path(), 4, 999_999_031);
        fs::write(handle.join(".live-pid"), "999999032").unwrap();
        fs::write(handle.join(".live-cc-pid"), std::process::id().to_string()).unwrap();
        match logout_account(dir.path(), account(4)) {
            Err(LogoutError::InUse { pids, .. }) => {
                assert_eq!(pids, vec![std::process::id()])
            }
            other => panic!("expected InUse, got {other:?}"),
        }
        assert!(dir.path().join("config-4").exists());
    }

    /// Both markers dead: logout is NOT blocked by the new check (guards against
    /// over-refusal).
    #[cfg(unix)]
    #[test]
    fn logout_proceeds_when_both_markers_dead() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 4);
        let handle = bound_term_dir(dir.path(), 4, 999_999_033);
        fs::write(handle.join(".live-pid"), "999999034").unwrap();
        fs::write(handle.join(".live-cc-pid"), "999999035").unwrap();
        assert!(scan_live_handle_dirs_for_account(dir.path(), account(4)).is_empty());
    }

    /// An unreadable marker (a directory; an oversized file) counts as IN USE.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_when_pid_marker_unreadable() {
        for (marker, kind) in [
            (".live-cc-pid", "dir"),
            (".live-cc-pid", "oversized"),
            (".live-pid", "dir"),
            (".live-pid", "oversized"),
        ] {
            let dir = TempDir::new().unwrap();
            provision_account(dir.path(), 4);
            let handle = bound_term_dir(dir.path(), 4, 999_999_036);
            if marker == ".live-cc-pid" {
                fs::write(handle.join(".live-pid"), "999999037").unwrap();
            }
            let p = handle.join(marker);
            if kind == "dir" {
                fs::create_dir(&p).unwrap();
            } else {
                fs::write(&p, "9".repeat(4096)).unwrap();
            }
            match logout_account(dir.path(), account(4)) {
                Err(LogoutError::InUse {
                    pids,
                    unreadable_dirs,
                    ..
                }) => {
                    assert!(
                        pids.is_empty(),
                        "{marker} {kind}: no sentinel pid: {pids:?}"
                    );
                    assert_eq!(unreadable_dirs, vec!["term-999999036".to_string()]);
                }
                other => panic!("{marker} {kind}: expected InUse, got {other:?}"),
            }
            assert!(dir.path().join("config-4").exists(), "{marker} {kind}");
        }
    }

    #[test]
    fn in_use_message_names_unreadable_dir_never_pid_zero() {
        let a = account(4);
        let m = in_use_message(a, &[], &["term-1234".to_string()]);
        assert_eq!(
            m,
            "account 4: handle dir term-1234 has a pid marker that cannot be read; inspect it and remove it if stale, then retry"
        );
        assert!(!m.contains("[0]") && !m.contains("claude process"), "{m}");
        let e = LogoutError::InUse {
            account: a,
            pids: vec![77],
            unreadable_dirs: vec!["term-1".into(), "term-2".into()],
        };
        let m = e.to_string();
        assert!(
            m.contains("[77]") && m.contains("term-1, term-2") && m.contains("have pid markers"),
            "{m}"
        );
        assert!(!m.contains("[0"), "{m}");
    }

    #[test]
    fn display_dir_name_never_leaks_a_path() {
        assert_eq!(display_dir_name("term-12"), "term-12");
        assert_eq!(display_dir_name("term-/Users/x"), "term-?");
    }

    #[test]
    fn logout_refuses_when_handle_dir_alive() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 4);

        // Create a handle dir bound to account 4 with our own PID
        // (which is, by definition, alive).
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        // .csq-account symlink → ../config-4/.csq-account
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-4").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-4").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(4)) {
            Err(LogoutError::InUse {
                account: a, pids, ..
            }) => {
                assert_eq!(a, account(4));
                assert!(pids.contains(&my_pid), "expected my PID in {pids:?}");
            }
            other => panic!("expected InUse, got {other:?}"),
        }

        // State must be intact after a refused logout.
        assert!(dir.path().join("credentials/4.json").exists());
        assert!(dir.path().join("config-4").exists());
    }

    /// PRIMARY DEFECT regression: `login::finalize_login` writes the
    /// `.csq-account` marker as the slot's identity UUID whenever
    /// `profiles::resolve_slot_to_uuid` resolves — the normal state for
    /// every modern (post-A++) Anthropic OAuth slot. The pre-fix scanner
    /// read the marker with the NUMERIC-ONLY `markers::read_csq_account`,
    /// which returns `None` for a UUID marker and `continue`s past it, so
    /// `LogoutError::InUse` could never fire against a modern slot and
    /// `csq logout` deleted credentials out from under a live `claude`
    /// process. This test provisions the production UUID-marker shape
    /// (config dir marker = canonical UUID string, `by_slot[N]` = same
    /// UUID) with a live PID bound, and asserts the guard fires.
    #[test]
    fn logout_refuses_when_handle_dir_alive_with_uuid_marker() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let slot_n = 20u16;
        provision_account(dir.path(), slot_n);

        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(slot_n, "alice@x.com", uuid)]);
        // Overwrite the decimal marker `provision_account` wrote with the
        // UUID content — the M4-7 writer flip (`login::finalize_login`)
        // does exactly this whenever `resolve_slot_to_uuid` resolves.
        markers::write_csq_account(&dir.path().join(format!("config-{slot_n}")), uuid).unwrap();

        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path()
                .join(format!("config-{slot_n}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path()
                .join(format!("config-{slot_n}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(slot_n)) {
            Err(LogoutError::InUse {
                account: a, pids, ..
            }) => {
                assert_eq!(a, account(slot_n));
                assert!(pids.contains(&my_pid), "expected my PID in {pids:?}");
            }
            other => {
                panic!("expected InUse for a UUID-marker-bound live handle dir, got {other:?}")
            }
        }

        // State must be intact after a refused logout.
        assert!(dir
            .path()
            .join(format!("credentials/{slot_n}.json"))
            .exists());
        assert!(dir.path().join(format!("config-{slot_n}")).exists());
    }

    /// Ambiguous case: the handle dir carries a UUID marker, but the slot
    /// being logged out has NO `by_slot` UUID mapping at all (e.g. a
    /// corrupted or never-written profiles.json entry), so
    /// `resolve_slot_to_uuid` returns `None` and the scanner cannot rule
    /// OUT that this handle dir belongs to `account`. A destructive
    /// operation must fail TOWARD in-use on genuine ambiguity rather than
    /// silently proceeding.
    #[test]
    fn logout_refuses_when_uuid_marker_present_but_slot_has_no_by_slot_mapping() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let slot_n = 21u16;
        provision_account(dir.path(), slot_n);
        // Deliberately no profiles.json / by_slot entry for slot_n.

        let uuid = IdentityId::new_v4();
        markers::write_csq_account(&dir.path().join(format!("config-{slot_n}")), uuid).unwrap();

        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path()
                .join(format!("config-{slot_n}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path()
                .join(format!("config-{slot_n}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(slot_n)) {
            Err(LogoutError::InUse { account: a, .. }) => assert_eq!(a, account(slot_n)),
            other => panic!("expected InUse (fail-toward-ambiguous), got {other:?}"),
        }
    }

    /// REGRESSION (2026-08-28): a NON-OAuth slot — 3P bearer, native, or
    /// cloud-Claude — has no `by_slot` UUID at all (its profiles entry lives
    /// in `by_slot_identity`, which holds a LABEL like `apikey:claude-vertex`,
    /// not a UUID). `resolve_slot_to_uuid` therefore returns `None` for it,
    /// which is correct — but the scanner then treated EVERY UUID-markered
    /// live handle dir as bound, so such a slot could never be logged out
    /// while any OAuth session was alive.
    ///
    /// Observed on a real host: `csq logout 20` refused with 21 live PIDs,
    /// none of whose handle dirs resolved to `config-20`. Slots 13-20 were
    /// all un-logout-able.
    ///
    /// The ambiguity posture is preserved where it is genuine (see
    /// `logout_refuses_when_uuid_marker_present_but_slot_has_no_by_slot_mapping`
    /// and the unknown-UUID test below): a dir whose UUID maps to a KNOWN,
    /// DIFFERENT slot is not ambiguous — it is definitively not ours.
    #[test]
    fn logout_of_nonoauth_slot_ignores_dirs_owned_by_other_known_slots() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let oauth_slot = 4u16;
        let nonoauth_slot = 20u16;
        provision_account(dir.path(), oauth_slot);
        provision_account(dir.path(), nonoauth_slot);

        // Slot 4 is a normal OAuth slot WITH a by_slot UUID; slot 20 has none
        // (the production shape for a cloud-Claude / 3P / native slot).
        let uuid_4 = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(oauth_slot, "alice@x.com", uuid_4)]);
        markers::write_csq_account(&dir.path().join(format!("config-{oauth_slot}")), uuid_4)
            .unwrap();

        // A LIVE handle dir bound to slot 4 — not to slot 20.
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path()
                .join(format!("config-{oauth_slot}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path()
                .join(format!("config-{oauth_slot}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        // Logging out slot 20 must SUCCEED: the only live dir provably
        // belongs to slot 4.
        logout_account(dir.path(), account(nonoauth_slot)).expect(
            "logout of a non-OAuth slot must not be blocked by a live dir owned by another slot",
        );
        assert!(!dir.path().join(format!("config-{nonoauth_slot}")).exists());
        // Slot 4 untouched.
        assert!(dir.path().join(format!("config-{oauth_slot}")).exists());
    }

    /// REGRESSION (redteam C1): a slot can lose its `by_slot` entry while
    /// KEEPING its config dir and that dir's UUID marker — the codex
    /// partial-mint rollback (`profiles::remove_slot_mapping`) does exactly
    /// this — and a legacy install minted by the retired email-only `mint_for_login`
    /// (which REUSED `by_email[email]`) can have a sibling slot hold the same UUID.
    ///
    /// In that state the dir's UUID IS attributable (to the sibling), but the
    /// live handle dir resolves into OUR config dir. Treating "attributable
    /// elsewhere" as "not ours" would delete the directory out from under a
    /// running session — the exact failure the guard exists to prevent.
    #[test]
    fn logout_refuses_when_our_own_marker_uuid_is_attributed_to_a_sibling_slot() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sibling = 4u16;
        let target = 20u16;
        provision_account(dir.path(), sibling);
        provision_account(dir.path(), target);

        // One UUID, shared: `by_slot` maps it to the SIBLING only. The target
        // has no by_slot entry (rollback removed it) but its config dir marker
        // still carries the shared UUID.
        let shared = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(sibling, "alice@x.com", shared)]);
        markers::write_csq_account(&dir.path().join(format!("config-{sibling}")), shared).unwrap();
        markers::write_csq_account(&dir.path().join(format!("config-{target}")), shared).unwrap();

        // A LIVE handle dir resolving into the TARGET's config dir.
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path()
                .join(format!("config-{target}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path()
                .join(format!("config-{target}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(target)) {
            Err(LogoutError::InUse {
                account: a, pids, ..
            }) => {
                assert_eq!(a, account(target));
                assert!(pids.contains(&my_pid), "expected my PID in {pids:?}");
            }
            other => panic!(
                "expected InUse — a live dir in our own config dir must block logout even when \
                 by_slot attributes our marker UUID to a sibling slot; got {other:?}"
            ),
        }
        // The live session's directory must still be there.
        assert!(dir.path().join(format!("config-{target}")).exists());
        assert!(dir
            .path()
            .join(format!("credentials/{target}.json"))
            .exists());
    }

    /// The fail-closed half of the same arm: when the live dir's UUID maps to
    /// NO known slot, it stays ambiguous and logout must still refuse.
    #[test]
    fn logout_of_nonoauth_slot_still_refuses_on_unknown_uuid_dir() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let nonoauth_slot = 20u16;
        let stranger_slot = 7u16;
        provision_account(dir.path(), nonoauth_slot);
        provision_account(dir.path(), stranger_slot);

        // A UUID that appears in NO by_slot mapping at all.
        let orphan_uuid = IdentityId::new_v4();
        markers::write_csq_account(
            &dir.path().join(format!("config-{stranger_slot}")),
            orphan_uuid,
        )
        .unwrap();

        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path()
                .join(format!("config-{stranger_slot}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path()
                .join(format!("config-{stranger_slot}"))
                .join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(nonoauth_slot)) {
            Err(LogoutError::InUse { .. }) => {}
            other => panic!("expected InUse on an unattributable UUID dir, got {other:?}"),
        }
        assert!(dir.path().join(format!("config-{nonoauth_slot}")).exists());
    }

    /// Specificity check: a UUID-marker handle dir bound to a DIFFERENT
    /// slot's UUID must NOT block logout of `account` — the fix compares
    /// identities, it does not treat every UUID marker as a match.
    #[test]
    fn logout_ignores_uuid_marker_handle_dir_bound_to_different_slot() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 22);
        provision_account(dir.path(), 23);

        let uuid_22 = IdentityId::new_v4();
        let uuid_23 = IdentityId::new_v4();
        write_profiles_with_identity(
            dir.path(),
            &[(22, "a@x.com", uuid_22), (23, "b@x.com", uuid_23)],
        );
        markers::write_csq_account(&dir.path().join("config-22"), uuid_22).unwrap();
        markers::write_csq_account(&dir.path().join("config-23"), uuid_23).unwrap();

        // Handle dir bound to slot 23 with a live PID — must NOT block
        // logout of slot 22.
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-23").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-23").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        logout_account(dir.path(), account(22)).unwrap();
        assert!(!dir.path().join("config-22").exists());
        assert!(dir.path().join("config-23").exists());
    }

    #[test]
    fn logout_allows_when_handle_dir_dead() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 6);

        // Pick a PID above `/proc/sys/kernel/pid_max` (4_194_304 on Linux
        // default, 99999 on macOS) so it is never in use, but below
        // `i32::MAX` so it is not reinterpreted as -1 ("every process")
        // by kill(2). The earlier version spawned `true` and used the
        // reaped child's PID — this was flaky because Linux can reuse
        // a reaped PID within microseconds on a busy CI runner, at
        // which point `is_pid_alive` returned true and the test
        // panicked. The constant below bypasses the reuse race entirely.
        let dead_pid: u32 = 2_000_000_000;

        let handle = dir.path().join(format!("term-{dead_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-6").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-6").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), dead_pid.to_string()).unwrap();

        // Should succeed because the bound process is dead.
        let summary = logout_account(dir.path(), account(6)).unwrap();
        assert!(summary.config_dir_removed);
    }

    #[test]
    fn logout_ignores_unrelated_handle_dirs() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 8);
        provision_account(dir.path(), 9);

        // Handle dir bound to account 9 with our (live) PID — should
        // NOT block logout of account 8.
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-9").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-9").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        logout_account(dir.path(), account(8)).unwrap();
        assert!(!dir.path().join("config-8").exists());
        assert!(dir.path().join("config-9").exists());
    }

    #[test]
    fn logout_removes_quota_entry() {
        use crate::quota::state as quota_state;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 11);
        write_quota_for(dir.path(), 11, 87.5);

        let summary = logout_account(dir.path(), account(11)).unwrap();
        assert!(summary.quota_entry_removed);

        let q = quota_state::load_state(dir.path()).unwrap();
        assert!(
            q.get(11).is_none(),
            "quota entry must be cleared after logout — otherwise a recycled slot inherits the previous tenant's stale percentage"
        );
    }

    #[test]
    fn logout_quota_cleanup_does_not_touch_other_accounts() {
        use crate::quota::state as quota_state;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 12);
        provision_account(dir.path(), 13);
        write_quota_for(dir.path(), 12, 50.0);
        write_quota_for(dir.path(), 13, 75.0);

        logout_account(dir.path(), account(12)).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        assert!(q.get(12).is_none());
        let still = q.get(13).expect("account 13's quota must survive");
        assert_eq!(still.seven_day_pct(), 75.0);
    }

    #[test]
    fn logout_quota_cleanup_silent_when_no_entry() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 14);
        // No quota.json written for account 14 at all.

        let summary = logout_account(dir.path(), account(14)).unwrap();
        assert!(!summary.quota_entry_removed);
    }

    #[test]
    fn logout_no_profiles_file_is_fine() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        // Note: no profiles.json written.

        let summary = logout_account(dir.path(), account(1)).unwrap();
        assert!(!summary.profiles_entry_removed);
    }

    // ── R5-MED-1: by_slot and by_email maintenance on logout ─────────────

    /// Writes a combined ProfilesFile with both v1 `accounts` entries and
    /// M1-2 `by_slot`/`by_email` mappings in a single atomic save.
    fn write_profiles_with_identity(
        base: &Path,
        entries: &[(u16, &str, crate::accounts::identity_store::IdentityId)],
    ) {
        let mut file = ProfilesFile::empty();
        for (n, email, uuid) in entries {
            file.set_profile(
                *n,
                AccountProfile {
                    email: email.to_string(),
                    method: "oauth".into(),
                    extra: HashMap::new(),
                },
            );
            file.by_slot.insert(n.to_string(), *uuid);
            // by_email: last writer wins — in the reuse scenario all slots
            // point to the same UUID anyway.
            file.by_email.insert(email.to_string(), *uuid);
        }
        profiles::save(&profiles::profiles_path(base), &file).unwrap();
    }

    /// R5-MED-1: `logout_account` removes the `by_slot["N"]` entry AND the
    /// `by_email[email]` entry when no other slot still references the UUID.
    #[test]
    fn logout_removes_by_slot_entry() {
        use crate::accounts::identity_store::IdentityId;

        // Arrange: slot 1, alice@x.com, UUID_A
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);

        let uuid_a = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "alice@x.com", uuid_a)]);

        // Act
        let summary = logout_account(dir.path(), account(1)).unwrap();
        assert!(summary.profiles_entry_removed);

        // Assert: by_slot["1"] removed
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_slot.contains_key("1"),
            "by_slot[\"1\"] must be removed after logout"
        );
        // Assert: by_email["alice@x.com"] removed (no other slot references UUID_A)
        assert!(
            !reloaded.by_email.contains_key("alice@x.com"),
            "by_email[\"alice@x.com\"] must be removed after logout"
        );
        // Assert: accounts["1"] removed
        assert!(
            !reloaded.accounts_for_test().contains_key("1"),
            "accounts[\"1\"] must be removed after logout"
        );
    }

    /// R5-MED-1: When two slots share the same email (M1-4 reuse-by-email
    /// path), logging out slot 1 must NOT remove the `by_email` entry that
    /// slot 2 still relies on.
    #[test]
    fn logout_preserves_by_email_when_email_still_referenced() {
        use crate::accounts::identity_store::IdentityId;

        // Arrange: slot 1 and slot 2 both authenticated as alice@x.com;
        // the reuse-by-email path gives both slots UUID_A.
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        provision_account(dir.path(), 2);

        let uuid_a = IdentityId::new_v4();
        write_profiles_with_identity(
            dir.path(),
            &[
                (1, "alice@x.com", uuid_a),
                (2, "alice@x.com", uuid_a), // same UUID — reuse path
            ],
        );

        // Act: log out slot 1 only
        let summary = logout_account(dir.path(), account(1)).unwrap();
        assert!(summary.profiles_entry_removed);

        // Assert: by_slot["1"] removed
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_slot.contains_key("1"),
            "by_slot[\"1\"] must be removed"
        );

        // Assert: by_slot["2"] STILL points to UUID_A
        assert_eq!(
            reloaded.by_slot.get("2").copied(),
            Some(uuid_a),
            "by_slot[\"2\"] must still map to UUID_A"
        );

        // Assert: by_email["alice@x.com"] STILL present (slot 2 still uses it)
        assert_eq!(
            reloaded.by_email.get("alice@x.com").copied(),
            Some(uuid_a),
            "by_email[\"alice@x.com\"] must be preserved — slot 2 still references UUID_A"
        );

        // Assert: accounts["1"] removed, accounts["2"] intact
        assert!(!reloaded.accounts_for_test().contains_key("1"));
        assert!(reloaded.accounts_for_test().contains_key("2"));
    }

    /// R5-MED-1: `logout_account` acquires `ProfilesFileLock` before
    /// touching profiles.json. We verify this by holding the lock in a
    /// background thread and asserting that the foreground call blocks until
    /// the lock is released.
    #[test]
    fn logout_acquires_profiles_lock() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        write_profiles(dir.path(), &[(1, "user@x.com")]);

        // Shared flag: set to true when logout completes
        let completed = Arc::new(Mutex::new(false));
        let completed_bg = Arc::clone(&completed);

        let dir_path = dir.path().to_path_buf();

        // Hold the lock in a background thread for a short window
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = ProfilesFileLock::acquire(&dir_path).unwrap();
            tx_locked.send(()).unwrap();
            // Hold until signalled
            rx_release.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(_lock);
            *completed_bg.lock().unwrap() = true;
        });

        // Wait until background thread holds the lock
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("background thread must acquire lock");

        // Kick off logout in another thread (it will block on the lock)
        let dir_path2 = dir.path().to_path_buf();
        let logout_done = Arc::new(Mutex::new(false));
        let logout_done2 = Arc::clone(&logout_done);

        let logout_thread = std::thread::spawn(move || {
            // This will block until the background lock is released
            let _ = logout_account(&dir_path2, AccountNum::try_from(1u16).unwrap());
            *logout_done2.lock().unwrap() = true;
        });

        // Give the logout thread a moment to start and block
        std::thread::sleep(Duration::from_millis(50));

        // Verify it hasn't completed yet (still blocked on lock)
        assert!(
            !*logout_done.lock().unwrap(),
            "logout must not complete while ProfilesFileLock is held by another thread"
        );

        // Release the background lock
        tx_release.send(()).unwrap();

        // Wait for logout thread to finish
        logout_thread.join().expect("logout thread must not panic");

        // Verify logout completed after lock was released
        assert!(
            *logout_done.lock().unwrap(),
            "logout must complete after ProfilesFileLock is released"
        );
    }

    // ── M9: by_slot_identity removal on logout ────────────────────────────

    /// Writes a `ProfilesFile` whose `by_slot_identity` map is pre-populated,
    /// leaving `by_slot` / `by_email` / `accounts` empty. Used by the M9
    /// tests to focus on the non-OAuth identity channel without UUID noise.
    fn write_profiles_with_slot_identity(base: &Path, entries: &[(u16, &str)]) {
        let mut file = ProfilesFile::empty();
        for (n, label) in entries {
            file.by_slot_identity
                .insert(n.to_string(), label.to_string());
        }
        profiles::save(&profiles::profiles_path(base), &file).unwrap();
    }

    /// M9: `logout_account` removes `by_slot_identity["N"]` so a recycled
    /// slot number cannot inherit the previous tenant's identity label.
    #[test]
    fn logout_removes_by_slot_identity_entry() {
        // Arrange
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 9);
        write_profiles_with_slot_identity(dir.path(), &[(9, "apikey:mm")]);

        // Act
        let summary = logout_account(dir.path(), account(9)).unwrap();
        // profiles_entry_removed is false here because there was no
        // accounts[9] or by_slot[9] entry — that is expected for a pure
        // by_slot_identity fixture.
        let _ = summary;

        // Assert
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_slot_identity.contains_key("9"),
            "by_slot_identity[\"9\"] must be removed after logout — \
             leaving it would let a recycled slot inherit the previous tenant's identity"
        );
    }

    /// M9: logging out slot 9 MUST NOT touch `by_slot_identity` entries for
    /// other slots. Slot 11 survives intact.
    #[test]
    fn logout_preserves_by_slot_identity_for_other_slots() {
        // Arrange
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 9);
        write_profiles_with_slot_identity(dir.path(), &[(9, "apikey:mm"), (11, "apikey:ollama")]);

        // Act
        logout_account(dir.path(), account(9)).unwrap();

        // Assert: slot 9's entry is gone
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_slot_identity.contains_key("9"),
            "by_slot_identity[\"9\"] must be removed after logout"
        );
        // Assert: slot 11's entry is preserved
        assert_eq!(
            reloaded.by_slot_identity.get("11").map(String::as_str),
            Some("apikey:ollama"),
            "by_slot_identity[\"11\"] must survive logout of a different slot"
        );
    }

    /// M9 + FM-9 (c) ordering: `logout_account` deletes credential files and
    /// `config-N/` BEFORE acquiring `ProfilesFileLock` and calling
    /// `remove_profiles_entry`. This test provisions a full account with both
    /// a credential file and a `by_slot_identity` entry, calls `logout_account`,
    /// and asserts that BOTH the credential sweep (`canonical_removed`) and the
    /// profiles cleanup (entry gone) completed — proving the end-to-end path
    /// ran in the WBS-required order.
    ///
    /// Runtime invariant citation: the ordering is structural in
    /// `logout_account` (lines ~122-148: credential sweep; lines ~153+:
    /// `ProfilesFileLock::acquire` + `remove_profiles_entry`). A crash
    /// between the two phases leaves the slot unidentifiable (no creds, no
    /// identity entry), never falsely-identifiable.
    #[test]
    fn logout_deletes_settings_before_by_slot_identity() {
        // F-M-3 R1A: this is a true ordering test — it asserts BOTH the
        // runtime side-effects AND the structural-comment ordering invariant
        // in `logout_account`. A refactor that reverses the order
        // (`ProfilesFileLock::acquire` before the credential sweep) would
        // strip the SAFETY-ORDERING sentinel comment too, failing the
        // include_str! grep below.

        // Structural probe: assert the SAFETY-ORDERING sentinel sits at the
        // order-critical line in `logout_account`. The sentinel cites the
        // M9 + FM-9(c) invariant — credential files removed BEFORE the
        // profiles lock is acquired. Same shape as `audit/sweep.rs`'s
        // `audit_sweep_deleted_tag_is_in_source` test.
        let source = include_str!("logout.rs");
        assert!(
            source.contains(
                "SAFETY-ORDERING: credential files removed BEFORE ProfilesFileLock acquired"
            ),
            "logout.rs must contain the SAFETY-ORDERING sentinel pinning the M9 + FM-9(c) invariant"
        );

        // Arrange: full account with a by_slot_identity entry
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 9);
        // Also populate by_slot_identity so remove_profiles_entry has work to do.
        write_profiles_with_slot_identity(dir.path(), &[(9, "apikey:mm")]);

        // Act
        let summary = logout_account(dir.path(), account(9)).unwrap();

        // Assert: credential sweep ran (settings.json phase completed)
        assert!(
            summary.canonical_removed,
            "canonical credential file must be removed — \
             this confirms the settings.json sweep phase ran before profiles cleanup"
        );
        assert!(
            summary.config_dir_removed,
            "config-N dir must be removed as part of the pre-profiles sweep"
        );

        // Assert: by_slot_identity entry is gone (profiles cleanup phase completed)
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_slot_identity.contains_key("9"),
            "by_slot_identity[\"9\"] must be removed — confirms profiles cleanup ran \
             after (and only after) the credential sweep completed"
        );
    }

    // ── Orphan-identity GC source-fix ──────────────────────────────────────

    /// Plant an `identities/<uuid>/` dir with token-bearing credentials so the
    /// source-fix has a directory to delete.
    fn plant_identity_dir(base: &Path, uuid: IdentityId) {
        let id_dir = identity_path(base, uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(id_dir.join("credentials.json"), br#"{"x":1}"#).unwrap();
        std::fs::write(id_dir.join("identity.json"), br#"{"email":"a@b.com"}"#).unwrap();
    }

    /// AC-LOGOUT-1: logging out the LAST slot referencing a UUID deletes the
    /// `identities/<UUID>/` dir at the source (no orphan is born).
    #[test]
    fn logout_deletes_identity_dir_on_last_reference() {
        use crate::accounts::identity_store::IdentityId;
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "alice@x.com", uuid)]);
        plant_identity_dir(dir.path(), uuid);

        let summary = logout_account(dir.path(), account(1)).unwrap();

        assert!(
            summary.identity_dir_removed,
            "logout must delete the now-orphaned identity dir at the source"
        );
        assert!(
            !identity_path(dir.path(), uuid).exists(),
            "identities/<UUID>/ must be gone after last-reference logout"
        );
    }

    /// ROOT ruling D (D237 round 2; findings logout M2/M1 + sec M1): when the
    /// identity's canonical credential lock is still held past the bounded
    /// wait, logout REFUSES the delete (never deletes without the lock),
    /// emits the fixed-vocabulary `logout_identity_dir_lock_busy` warning,
    /// reports `identity_dir_pending_removal`, and leaves the credential
    /// folder on disk with the tombstone in place. The next orphan-identity
    /// GC pass then collects that leftover directory — the disposition the
    /// base code CLAIMED without proving.
    ///
    /// Non-vacuity (RED): the holder keeps the lock until the test has read
    /// logout's outcome, so a logout that WAITS for the lock is proven to have
    /// returned only after the holder released. A logout that (a) skips the
    /// fixed-vocabulary warning, (b) does not report the pending removal,
    /// (c) deletes without the lock, or (d) waits instead of refusing reds by
    /// ASSERTION (no hang: the holder's safety release is test-bounded).
    #[test]
    fn logout_lock_busy_leaves_dir_that_the_orphan_gc_then_collects() {
        use crate::accounts::identity_store::{
            credentials_path_for, is_identity_removed, IdentityId,
        };

        // Captured tracing is process-wide-filter-sensitive; share the crate
        // capture lock (see `crate::testing::TRACING_CAPTURE_LOCK`).
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        provision_account(&base, 1);
        provision_account(&base, 2);
        let going = IdentityId::new_v4();
        let staying = IdentityId::new_v4();
        write_profiles_with_identity(
            &base,
            &[
                (1, "gone@test.invalid", going),
                (2, "kept@test.invalid", staying),
            ],
        );
        plant_identity_dir(&base, going);
        plant_identity_dir(&base, staying);

        // Another writer holds the canonical credential lock for the identity
        // being logged out, and KEEPS holding it until the test has observed
        // logout's outcome. The hold is event-synchronised on purpose: the
        // product's bounded wait is COUNT-based (`CREDENTIAL_LOCK_ATTEMPTS` x
        // `CREDENTIAL_LOCK_DELAY`), not a wall-clock deadline, so a descheduled
        // waiter stretches it without bound. A fixed sleep here (the old
        // `budget + 1.5s`) races that stretch: on a loaded host the loop can
        // still be running past the release and then acquire a lock logout
        // should have refused. `test_guard` is the TEST's hang guard -- how far
        // scheduling may stretch a CORRECT logout before the holder releases and
        // a waiting implementation reds by assertion instead of hanging.
        // `logout_bound` is a derived BOUND on how long logout may wait: a raised
        // attempt count would extend the wait past it and red. The holder's safety
        // release is STRICTLY longer, so load can never release the holder while a
        // correct logout is still inside its bound (that would false-red and blame
        // the implementation).
        const SCHEDULING_STRETCH: u32 = 10;
        let logout_bound = crate::platform::lock::CREDENTIAL_LOCK_BUDGET * SCHEDULING_STRETCH;
        let holder_safety = logout_bound * 2;
        let lock_path = credentials_path_for(&base, going).with_extension("lock");
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let still_held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let still_held_bg = std::sync::Arc::clone(&still_held);
        let holder = std::thread::spawn(move || {
            let guard = crate::platform::lock::lock_file(&lock_path)
                .expect("holder takes the canonical credential lock");
            still_held_bg.store(true, std::sync::atomic::Ordering::SeqCst);
            held_tx.send(()).expect("signal held");
            // Released by the test once it has read logout's outcome; the
            // timeout only lets a WAITING implementation return and red.
            let _ = release_rx.recv_timeout(holder_safety);
            still_held_bg.store(false, std::sync::atomic::Ordering::SeqCst);
            drop(guard);
        });
        held_rx
            .recv_timeout(holder_safety)
            .expect("holder must acquire before logout runs");

        let log = WarnLog::default();
        let started = std::time::Instant::now();
        let result =
            tracing::subscriber::with_default(log.clone(), || logout_account(&base, account(1)));
        let elapsed = started.elapsed();
        // Read the holder's state BEFORE releasing it: a refusal must return
        // while the lock is genuinely held, within the derived bounded wait.
        let held_through_logout = still_held.load(std::sync::atomic::Ordering::SeqCst);
        let _ = release_tx.send(());
        holder.join().expect("holder thread must exit");

        let summary = result.expect("logout completes — the dir delete is deferred, not fatal");
        assert!(
            held_through_logout,
            "logout must return while the canonical lock is STILL held: a holder \
             that was released first let a waiting implementation pass"
        );
        assert!(
            elapsed < logout_bound,
            "logout must refuse within its derived bounded wait {logout_bound:?}; waited {elapsed:?}"
        );
        assert!(
            !summary.identity_dir_removed,
            "logout must NOT report the identity dir removed when it was refused"
        );
        assert!(
            summary.identity_dir_pending_removal,
            "logout must report the pending removal so callers can tell the operator \
             the local credential folder was NOT removed"
        );
        assert!(
            log.has_error_kind("logout_identity_dir_lock_busy"),
            "logout must emit the fixed-vocabulary expiry warning; captured: {:?}",
            log.error_kinds()
        );

        // The refusal is real: dir, credential copy, and tombstone all on disk;
        // the sibling identity (still bound) is untouched.
        assert!(
            identity_path(&base, going).is_dir(),
            "the refused delete must leave the identity dir on disk"
        );
        assert!(
            identity_path(&base, going)
                .join("credentials.json")
                .is_file(),
            "the local credential copy must still be on disk after the refusal"
        );
        assert!(
            is_identity_removed(&base, going),
            "the tombstone written before the delete attempt must remain"
        );
        assert!(identity_path(&base, staying).is_dir());

        // The next cleanup pass collects exactly the leftover dir: it is
        // unreferenced by both maps (the tombstone does not reference it),
        // the bound sibling is kept, and the tombstone survives the GC.
        let gc_lock = ProfilesFileLock::acquire(&base).expect("gc profiles lock");
        let report = crate::accounts::orphan_identity_gc::prune_orphan_identities(&gc_lock, &base)
            .expect("orphan-identity GC run");
        drop(gc_lock);
        assert_eq!(
            report.pruned_count, 1,
            "the next cleanup must collect the leftover identity dir"
        );
        assert!(
            !identity_path(&base, going).exists(),
            "the GC must remove the leftover credential folder"
        );
        assert!(
            identity_path(&base, staying).is_dir(),
            "the still-bound sibling identity must be kept"
        );
        assert!(
            is_identity_removed(&base, going),
            "the GC must not clear the tombstone"
        );
    }

    /// R2-M1: logout writes the tombstone BEFORE deleting, and deletes under
    /// `credentials.lock`. A concurrent writer holding that lock keeps the
    /// dir alive, but the tombstone is already visible to it.
    #[cfg(unix)]
    #[test]
    fn logout_tombstones_before_delete_and_deletes_under_canonical_lock() {
        use crate::accounts::identity_store::{credentials_path_for, is_identity_removed};
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "alice@x.com", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let lock_path = credentials_path_for(dir.path(), uuid).with_extension("lock");
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let base = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            LOGOUT_ORDERING_HOOK.with(|hook| {
                let mut before_save_calls = 0;
                *hook.borrow_mut() = Some(Box::new(move |base, identity, before_save| {
                    assert_eq!(identity, uuid);
                    assert!(is_identity_removed(base, uuid));
                    let profiles = profiles::load(&profiles::profiles_path(base)).unwrap();
                    if before_save {
                        assert_eq!(before_save_calls, 0, "before-save hook must run only once");
                        before_save_calls += 1;
                        assert_eq!(
                            profiles.by_slot.get("1"),
                            Some(&uuid),
                            "tombstone must precede the durable profiles unlink"
                        );
                    } else {
                        assert_eq!(
                            before_save_calls, 1,
                            "before-save hook must run exactly once before delete"
                        );
                        assert!(!profiles.by_slot.contains_key("1"));
                        assert!(
                            crate::platform::lock::try_lock_file(&lock_path)
                                .unwrap()
                                .is_none(),
                            "logout must hold the real canonical lock before deleting"
                        );
                        reached_tx.send(()).unwrap();
                        continue_rx
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap();
                    }
                }));
            });
            logout_account(&base, account(1))
        });
        reached_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(identity_path(dir.path(), uuid).exists());
        continue_tx.send(()).unwrap();
        let summary = handle.join().unwrap().unwrap();
        assert!(summary.identity_dir_removed);
        assert!(!identity_path(dir.path(), uuid).exists());
    }

    #[test]
    fn logout_tombstone_confirmation_stat_error_preserves_profiles() {
        for marker_state in [0, 1, 2] {
            let dir = TempDir::new().unwrap();
            provision_account(dir.path(), 1);
            let uuid = IdentityId::new_v4();
            write_profiles_with_identity(dir.path(), &[(1, "confirmation@test.invalid", uuid)]);
            plant_identity_dir(dir.path(), uuid);
            let marker =
                crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
            if marker_state == 1 {
                fs::write(&marker, b"preexisting nonsecret guard").unwrap();
            }
            let path = profiles::profiles_path(dir.path());
            let before = fs::read(&path).unwrap();
            let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
            let confirmed = std::cell::Cell::new(false);
            let saved = std::cell::Cell::new(false);
            let result = remove_profiles_entry_with_stat(
                &lock,
                dir.path(),
                account(1),
                |path, file| {
                    saved.set(true);
                    profiles::save(path, file)
                },
                |marker| {
                    assert_eq!(
                        marker,
                        crate::accounts::identity_store::identity_removed_marker_path(
                            dir.path(),
                            uuid
                        )
                    );
                    assert!(fs::symlink_metadata(marker).unwrap().is_file());
                    if marker_state == 2 {
                        fs::rename(marker, marker.with_extension("attempt-owned")).unwrap();
                        fs::write(marker, b"replacement nonsecret guard").unwrap();
                    }
                    confirmed.set(true);
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                },
            );
            assert!(confirmed.get(), "the confirmation stat must execute");
            assert!(matches!(result, Err(LogoutError::Io { .. })));
            assert!(
                !saved.get(),
                "an unconfirmed tombstone must not publish unlink"
            );
            assert_eq!(fs::read(path).unwrap(), before);
            assert!(identity_path(dir.path(), uuid).is_dir());
            if marker_state == 1 {
                assert_eq!(fs::read(marker).unwrap(), b"preexisting nonsecret guard");
            } else if marker_state == 2 {
                assert_eq!(fs::read(marker).unwrap(), b"replacement nonsecret guard");
            } else {
                assert_eq!(
                    fs::symlink_metadata(marker).unwrap_err().kind(),
                    std::io::ErrorKind::NotFound,
                    "confirmation failure must remove only this attempt's marker"
                );
            }
        }
    }

    #[test]
    fn logout_nonregular_tombstone_names_marker_and_preserves_profiles() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "nonregular@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let marker =
            crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
        fs::create_dir(&marker).unwrap();
        let path = profiles::profiles_path(dir.path());
        let before = fs::read(&path).unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let error = remove_profiles_entry(&lock, dir.path(), account(1)).unwrap_err();
        assert!(matches!(&error, LogoutError::NonregularTombstone { path } if *path == marker));
        assert!(error
            .to_string()
            .contains("identity_removal_marker_nonregular"));
        assert!(error
            .to_string()
            .contains("tombstone is not a regular file"));
        assert!(error.to_string().contains(&marker.display().to_string()));
        assert_eq!(fs::read(path).unwrap(), before);
        assert!(marker.is_dir());
        assert!(identity_path(dir.path(), uuid).is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn logout_hardlinked_tombstone_has_distinct_diagnostic_and_preserves_profiles() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "hardlink@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let marker =
            crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
        let target = dir.path().join("nonsecret-owned-target");
        fs::write(&target, b"must remain intact").unwrap();
        fs::hard_link(&target, &marker).unwrap();
        let before = fs::read(profiles::profiles_path(dir.path())).unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let error = remove_profiles_entry(&lock, dir.path(), account(1)).unwrap_err();
        assert!(
            matches!(&error, LogoutError::NonregularTombstone { path } if *path == marker),
            "hardlink must use distinct tombstone diagnostic"
        );
        assert!(error
            .to_string()
            .contains("identity_removal_marker_nonregular"));
        assert_eq!(fs::read(&target).unwrap(), b"must remain intact");
        assert_eq!(
            fs::read(profiles::profiles_path(dir.path())).unwrap(),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn logout_symlinked_namespace_has_distinct_diagnostic_and_preserves_profiles() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "namespace@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let namespace = crate::accounts::identity_store::identities_dir(dir.path());
        let real = dir.path().join("owned-real-identities");
        fs::rename(&namespace, &real).unwrap();
        std::os::unix::fs::symlink(&real, &namespace).unwrap();
        let before = fs::read(profiles::profiles_path(dir.path())).unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let error = remove_profiles_entry(&lock, dir.path(), account(1)).unwrap_err();
        assert!(
            matches!(&error, LogoutError::UnsafeTombstoneNamespace { path } if *path == namespace),
            "namespace alias must use distinct diagnostic"
        );
        assert!(error
            .to_string()
            .contains("identity_removal_namespace_nonregular"));
        assert!(error.to_string().contains(&namespace.display().to_string()));
        assert_eq!(
            fs::read(profiles::profiles_path(dir.path())).unwrap(),
            before
        );
        let marker =
            crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
        assert!(!real.join(marker.file_name().unwrap()).exists());
        assert!(real.join(uuid.to_string()).is_dir());
    }

    #[test]
    fn logout_marker_sync_failure_preserves_profiles_and_rolls_back_own_marker() {
        #[cfg(unix)]
        let stages = [false, true];
        #[cfg(not(unix))]
        let stages = [false];
        for directory_failure in stages {
            let dir = TempDir::new().unwrap();
            provision_account(dir.path(), 1);
            let uuid = IdentityId::new_v4();
            write_profiles_with_identity(dir.path(), &[(1, "sync-error@test.invalid", uuid)]);
            plant_identity_dir(dir.path(), uuid);
            let path = profiles::profiles_path(dir.path());
            let before = fs::read(&path).unwrap();
            let saved = std::cell::Cell::new(false);
            let sync_failed = std::cell::Cell::new(false);
            let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
            let result = remove_profiles_entry_with_marker(
                &lock,
                dir.path(),
                account(1),
                |path, file| {
                    saved.set(true);
                    profiles::save(path, file)
                },
                |path| fs::symlink_metadata(path),
                |base, id| {
                    crate::accounts::identity_store::mark_identity_removed_with_sync(
                        base,
                        id,
                        |file| {
                            if file.metadata()?.is_dir() == directory_failure {
                                sync_failed.set(true);
                                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                            } else {
                                file.sync_all()
                            }
                        },
                    )
                },
            );
            assert!(
                sync_failed.get(),
                "selected marker or directory sync must execute"
            );
            assert!(
                matches!(result, Err(LogoutError::Io { .. })),
                "sync failure must refuse profiles publication"
            );
            assert!(!saved.get());
            assert_eq!(fs::read(path).unwrap(), before);
            let marker =
                crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
            assert_eq!(
                fs::symlink_metadata(marker).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
            assert!(identity_path(dir.path(), uuid).is_dir());
        }
    }

    #[test]
    fn logout_preexisting_marker_survives_profiles_save_failure() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "save-error@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let marker =
            crate::accounts::identity_store::identity_removed_marker_path(dir.path(), uuid);
        fs::write(&marker, b"preexisting nonsecret guard").unwrap();
        let path = profiles::profiles_path(dir.path());
        let before = fs::read(&path).unwrap();
        let attempted = std::cell::Cell::new(false);
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let result = remove_profiles_entry_with(&lock, dir.path(), account(1), |path, _| {
            attempted.set(true);
            Err(crate::error::ConfigError::InvalidJson {
                path: path.to_path_buf(),
                reason: "fixture_save_refused".into(),
            })
        });
        assert!(attempted.get());
        assert!(matches!(result, Err(LogoutError::Profiles(_))));
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(
            fs::read(marker).unwrap(),
            b"preexisting nonsecret guard",
            "save failure must preserve a preexisting marker"
        );
        assert!(identity_path(dir.path(), uuid).is_dir());
    }

    #[test]
    fn logout_failed_profiles_save_does_not_tombstone_a_still_bound_identity() {
        use crate::accounts::identity_store::is_identity_removed;
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(dir.path(), &[(1, "logout-failure@test.invalid", uuid)]);
        plant_identity_dir(dir.path(), uuid);
        let before = fs::read(profiles::profiles_path(dir.path())).unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let result = remove_profiles_entry_with(&lock, dir.path(), account(1), |path, _| {
            assert!(
                is_identity_removed(dir.path(), uuid),
                "marker exists before attempted unlink"
            );
            Err(crate::error::ConfigError::InvalidJson {
                path: path.to_path_buf(),
                reason: "fixture_profiles_save_refused".into(),
            })
        });
        assert!(matches!(result, Err(LogoutError::Profiles(_))));
        assert_eq!(
            fs::read(profiles::profiles_path(dir.path())).unwrap(),
            before
        );
        assert!(
            !is_identity_removed(dir.path(), uuid),
            "failed unlink must restore bound identity write authority"
        );
        assert!(identity_path(dir.path(), uuid).exists());
    }

    /// AC-LOGOUT-2: a UUID shared by two slots (M1-4 reuse-by-email) MUST NOT
    /// have its identity dir deleted when only ONE slot logs out — the sibling
    /// slot still reads those credentials.
    #[test]
    fn logout_keeps_identity_dir_when_uuid_shared() {
        use crate::accounts::identity_store::IdentityId;
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        provision_account(dir.path(), 2);
        let uuid = IdentityId::new_v4();
        write_profiles_with_identity(
            dir.path(),
            &[(1, "alice@x.com", uuid), (2, "alice@x.com", uuid)],
        );
        plant_identity_dir(dir.path(), uuid);

        let summary = logout_account(dir.path(), account(1)).unwrap();

        assert!(
            !summary.identity_dir_removed,
            "shared UUID: logout of one slot must NOT delete the dir"
        );
        assert!(
            identity_path(dir.path(), uuid).exists(),
            "sibling slot 2 still references the UUID — dir MUST remain"
        );
        // And slot 2 still resolves to the UUID.
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert_eq!(reloaded.by_slot.get("2").copied(), Some(uuid));
    }

    /// AC-LOGOUT-3: ordering invariant — the profiles map removal is durably
    /// saved BEFORE the identity-dir delete, so a crash leaves an unreferenced
    /// orphan (collected by the GC pass), never a `by_slot` row pointing at a
    /// deleted dir. Same source-grep shape as
    /// `logout_deletes_settings_before_by_slot_identity`.
    #[test]
    fn logout_identity_dir_delete_ordering_is_pinned_in_source() {
        let source = include_str!("logout.rs");
        assert!(
            source.contains("profiles map removal is durably saved BEFORE this delete"),
            "logout.rs must pin the map-removal-before-dir-delete ordering invariant"
        );
    }

    /// Redteam MED-1: a Codex slot minted via the REAL `mint_for_codex_login`
    /// path is correctly orphaned + deleted on last-reference logout — proves
    /// the source-fix's `orphaned_uuid` computation works against the real
    /// `by_slot` + `by_email["codex:slot-N"]` shape the mint writes, not a
    /// hand-rolled fixture (per `feedback_test_fixtures_mirror_real_csq_state`).
    #[test]
    fn logout_deletes_identity_dir_for_real_minted_codex_slot() {
        use crate::accounts::identity_store::IdentityId;
        use crate::daemon::identity_mint::mint_for_codex_login;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 12);
        let uuid: IdentityId = {
            let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
            mint_for_codex_login(&lock, dir.path(), 12, Some("acct-hint")).unwrap()
        };
        // Identity dir exists from the mint; plant the codex creds too.
        std::fs::write(
            identity_path(dir.path(), uuid).join("credentials-codex.json"),
            br#"{"tokens":{"access_token":"x"}}"#,
        )
        .unwrap();

        let summary = logout_account(dir.path(), account(12)).unwrap();

        assert!(
            summary.identity_dir_removed,
            "real-minted Codex slot's identity dir must be deleted on last-reference logout"
        );
        assert!(!identity_path(dir.path(), uuid).exists());
        // by_email["codex:slot-12"]-class key must be cleaned.
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            !reloaded.by_email.values().any(|u| *u == uuid),
            "no by_email entry may still reference the logged-out Codex UUID"
        );
        assert!(!reloaded.by_slot.values().any(|u| *u == uuid));
    }

    /// Redteam LOW-3: a UUID referenced by `by_email` under a DIFFERENT email
    /// key than the logged-out slot's must KEEP the identity dir (reuse-eligible
    /// straggler) — parity with the GC's `dir_kept_when_referenced_by_email_only`.
    #[test]
    fn logout_keeps_identity_dir_when_by_email_straggler_under_other_key() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        let uuid = IdentityId::new_v4();

        // Slot 1 → uuid via by_slot, but by_email carries the SAME uuid under a
        // different key ("other@x.com") — a reuse straggler. logout of slot 1
        // removes by_slot[1] and (because the slot's own email key differs) the
        // straggler key remains → uuid still in by_email → dir KEPT.
        let mut file = ProfilesFile::empty();
        file.set_profile(
            1,
            AccountProfile {
                email: "alice@x.com".to_string(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        file.by_slot.insert("1".into(), uuid);
        file.by_email.insert("alice@x.com".into(), uuid);
        file.by_email.insert("other@x.com".into(), uuid); // straggler under other key
        profiles::save(&profiles::profiles_path(dir.path()), &file).unwrap();
        plant_identity_dir(dir.path(), uuid);

        let summary = logout_account(dir.path(), account(1)).unwrap();

        assert!(
            !summary.identity_dir_removed,
            "a by_email straggler under another key must KEEP the dir (reuse-eligible)"
        );
        assert!(identity_path(dir.path(), uuid).exists());
        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(
            reloaded.by_email.values().any(|u| *u == uuid),
            "the straggler by_email entry must still reference the UUID"
        );
    }

    // ── M13b-T5 — audit-trail tests for logout_account ───────────────────────

    /// AC-C1 + AC-C2 (logout): INTENT seq N < OUTCOME seq N+1; they share
    /// the same correlation_id; the chain verifies after both records land.
    #[test]
    fn logout_audit_intent_before_outcome_chain_verifies() {
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline so this test
        // cannot race a concurrent enterprise-edition test (testing.md Rule 6 /
        // test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 3);
        let base = dir.path();

        logout_account(base, account(3)).expect("logout must succeed");

        // The committed chain must have at least 2 records (INTENT + OUTCOME).
        let verify_result = crate::audit::verify::verify_chain(
            base,
            &crate::audit::verify::VerifyConfig::default(),
            None,
        );
        assert!(
            verify_result.is_ok(),
            "chain must verify after logout: {verify_result:?}"
        );
        let summary = verify_result.unwrap();
        assert!(
            summary.verified_count >= 2,
            "at least 2 records (intent + outcome) must be on-chain after logout"
        );

        // Scan for orphan intents — there should be none (OUTCOME resolved intent).
        let orphans =
            crate::audit::intent_scan::scan_orphan_intents(base).expect("orphan scan must succeed");
        assert!(
            orphans.is_empty(),
            "no orphan intents after a successful logout: {orphans:?}"
        );
    }

    /// AC-C3 / AC-L1 (logout): when `csq-runs/` is read-only, `logout_account`
    /// returns an error AND no credential file is deleted (fail-closed on the
    /// most destructive op).
    #[cfg(unix)]
    #[test]
    fn logout_fail_closed_when_intent_unpersistable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 5);
        let base = dir.path();

        // Make csq-runs/ read-only so the intent write fails.
        let runs_dir = base.join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        let result = logout_account(base, account(5));

        // Restore so TempDir cleanup doesn't fail.
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        assert!(
            result.is_err(),
            "logout must fail when intent cannot be persisted"
        );
        // Critical AC-L1: credential file MUST still exist (fail-closed).
        assert!(
            base.join("credentials/5.json").exists(),
            "credential file must NOT be deleted when intent emit fails (fail-closed)"
        );
        assert!(
            base.join("config-5").exists(),
            "config dir must NOT be deleted when intent emit fails (fail-closed)"
        );
    }

    /// AC-C5 (logout): a crash between INTENT and OUTCOME (simulated by
    /// manually writing an intent without an outcome) leaves an orphan that
    /// `scan_orphan_intents` detects.
    #[test]
    fn logout_crash_between_intent_and_outcome_produces_detectable_orphan() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Write a dangling INTENT with no OUTCOME.
        let chain_id = crate::audit::op_emit::load_chain_id(base);
        let correlation_id = crate::audit::op_emit::gen_correlation_id().unwrap();
        crate::audit::op_emit::emit_intent(
            base,
            &chain_id,
            crate::audit::types::EventKind::AccountLogout,
            crate::audit::types::EventPayload::AccountLogout(
                crate::audit::types::AccountLogoutPayload {
                    slot: account(7),
                    orphaned_uuid: None,
                },
            ),
            correlation_id,
        )
        .expect("intent write must succeed");

        // No OUTCOME written — simulates crash-between.
        let orphans =
            crate::audit::intent_scan::scan_orphan_intents(base).expect("orphan scan must succeed");
        assert!(
            !orphans.is_empty(),
            "orphan intent (no outcome) must be detectable by scan_orphan_intents"
        );
        // orphans[0].kind is a String (serde JSON value of the EventKind)
        assert!(
            orphans[0].kind.contains("account_logout"),
            "orphan kind must be account_logout, got: {}",
            orphans[0].kind
        );
    }

    /// AC-C7 (logout): pre-side-effect rejections (NotConfigured, InUse) emit
    /// NO intent record on the chain.
    #[test]
    fn logout_pre_rejection_emits_no_intent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // NotConfigured rejection: no account on disk.
        let _ = logout_account(base, account(9));

        // Chain must have zero records (no intent emitted for pre-rejection).
        let runs_dir = base.join("csq-runs");
        if runs_dir.exists() {
            let files: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
                .collect();
            assert!(
                files.is_empty(),
                "NotConfigured rejection must emit no audit record: {files:?}"
            );
        }
    }

    /// Round-3 FIX-1: when the `.chain-broken` sentinel is set, `logout_account`
    /// MUST succeed (degrade-not-fail-closed) AND emit zero audit records.
    /// Credentials MUST be deleted — the op proceeds without an audit trail.
    #[test]
    fn logout_proceeds_skips_audit_when_chain_broken() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        provision_account(base, 4);

        // Set the .chain-broken sentinel to simulate a broken chain.
        crate::audit::set_chain_broken(base, "chain_broken_test");

        // Logout MUST succeed even though the chain is broken.
        let result = logout_account(base, account(4));
        assert!(
            result.is_ok(),
            "logout must SUCCEED (degrade) when chain is broken, got: {result:?}"
        );

        // Credentials MUST be deleted — op proceeded despite no audit trail.
        assert!(
            !base.join("credentials/4.json").exists(),
            "credential file must be deleted even when chain is broken"
        );
        assert!(
            !base.join("config-4").exists(),
            "config dir must be deleted even when chain is broken"
        );

        // Zero audit records must be on the chain (intent skipped → no orphan,
        // no outcome).
        let runs_dir = base.join("csq-runs");
        if runs_dir.exists() {
            let files: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
                .collect();
            assert!(
                files.is_empty(),
                "no audit records must be written when chain is broken: {files:?}"
            );
        }
    }

    // ── A4b — keychain-clear on logout (third resurrection source) ──────────

    /// The core mechanism `clear_bound_keychain_items` relies on:
    /// `bound_handle_dirs` finds a handle dir bound to the slot even when its
    /// owning process is DEAD, while `scan_live_handle_dirs_for_account`
    /// (the in-use refusal guard) correctly excludes that same dir. This is
    /// exactly the divergence the keychain-clear step needs — a dead-but-
    /// not-yet-swept handle dir still carries a keychain OAuth item CC wrote
    /// while it was live, and `sweep_dead_handles` never clears it either
    /// (grepped: no `keychain` reference in `session::handle_dir.rs`), so if
    /// `logout_account` only looked at LIVE handle dirs (as the in-use guard
    /// does), a dead one's keychain item would survive the slot's removal.
    ///
    /// Non-vacuity: this test was run against a version of `bound_handle_dirs`
    /// with the `is_pid_alive` filter re-added (matching the OLD
    /// `scan_live_handle_dirs_for_account` body) and FAILED at the first
    /// assertion (`bound` was empty) — confirming the test actually
    /// discriminates between "sees dead dirs" and "doesn't."
    #[test]
    fn bound_handle_dirs_includes_dead_dir_scan_live_excludes_it() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 24);

        // Same technique as `logout_allows_when_handle_dir_dead`: a PID
        // value guaranteed dead and never reinterpreted as -1 by kill(2).
        let dead_pid: u32 = 2_000_000_001;
        let handle = dir.path().join(format!("term-{dead_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-24").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-24").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), dead_pid.to_string()).unwrap();

        let bound = bound_handle_dirs(dir.path(), account(24));
        assert_eq!(
            bound,
            vec![handle.clone()],
            "a dead-but-bound handle dir must still be found — its keychain \
             item cannot be cleared if it is never enumerated"
        );

        let live_pids = scan_live_handle_dirs_for_account_pub(dir.path(), account(24));
        assert!(
            live_pids.is_empty(),
            "the in-use guard must NOT see this dir (dead PID) — precondition \
             for the divergence this test pins"
        );
    }

    /// End-to-end wiring: `logout_account` calls the keychain-clear step
    /// (reaching a bound, dead handle dir) without erroring or panicking,
    /// and reports the outcome on `LogoutSummary.keychain_cleared` rather
    /// than a silent no-signal default. `keychain_mirror_disabled()` is
    /// unconditionally `true` under `cfg!(test)` (host-safety — never shells
    /// `security` from a unit test, matching the existing Gemini-vault
    /// tests' rationale), so `clear_handle_dir_reporting` short-circuits to
    /// `Ok(false)` for every dir and `keychain_cleared` is deterministically
    /// `false` here — this test pins that TEST-MODE contract and proves the
    /// step is reached (a panic or an `Io`/other error from this path would
    /// fail the `.unwrap()` below), not the real macOS behavior.
    #[test]
    fn logout_reaches_keychain_clear_step_for_dead_bound_handle_dir() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 25);

        let dead_pid: u32 = 2_000_000_002;
        let handle = dir.path().join(format!("term-{dead_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-25").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-25").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), dead_pid.to_string()).unwrap();

        let summary = logout_account(dir.path(), account(25))
            .expect("logout must succeed with a dead bound handle dir present");
        assert!(
            !summary.keychain_cleared,
            "keychain mirror is disabled under cfg!(test) — the step must \
             report false, never silently omit the field or panic"
        );
        assert!(summary.config_dir_removed);
    }

    /// A slot with no handle dirs at all (the common case) must not error
    /// and must report `keychain_cleared == false` — nothing was bound, so
    /// nothing was cleared.
    #[test]
    fn logout_no_handle_dirs_reports_keychain_cleared_false() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 26);

        let summary = logout_account(dir.path(), account(26)).unwrap();
        assert!(!summary.keychain_cleared);
    }

    // ── security review 1386 ─────────────────────────────────────────────

    /// `note_clear_result` (L2): all three outcomes of
    /// `clear_handle_dir_reporting`'s `Result` shape, exercised directly —
    /// no keychain involved, so this is real coverage of the `Err` branch
    /// that `clear_bound_keychain_items`'s own tests structurally cannot
    /// reach (`keychain_mirror_disabled()` is unconditionally true under
    /// `cfg!(test)`, so `logout_account` never observes `Err` in-process).
    #[test]
    fn note_clear_result_covers_all_three_outcomes() {
        use crate::credentials::keychain::KeychainClearUnconfirmed;

        assert_eq!(note_clear_result(Ok(true)), (true, false));
        assert_eq!(note_clear_result(Ok(false)), (false, false));
        assert_eq!(
            note_clear_result(Err(KeychainClearUnconfirmed)),
            (false, true)
        );
    }

    /// R3 sec M-D / corr L-3: an unconfirmed clear whose durable retry could
    /// NOT be queued must raise `retry_queue_failed` on the aggregate — the
    /// field `LogoutSummary` carries to the CLI and IPC result. A queued
    /// retry, a confirmed clear, and a structural no-op must NOT raise it.
    ///
    /// RED mutation: drop the `needs_retry && !queued` branch — the first
    /// assertion below fails.
    #[test]
    fn fold_clear_outcome_reports_only_an_unqueued_retry() {
        let mut unqueued = KeychainClearOutcome::default();
        fold_clear_outcome(&mut unqueued, false, true, false);
        assert!(
            unqueued.retry_queue_failed,
            "a refused retry queue must be operator-visible"
        );
        assert!(!unqueued.any_confirmed);

        let mut queued = KeychainClearOutcome::default();
        fold_clear_outcome(&mut queued, false, true, true);
        assert!(!queued.retry_queue_failed, "a queued retry is fine");

        let mut confirmed = KeychainClearOutcome::default();
        fold_clear_outcome(&mut confirmed, true, false, true);
        assert!(confirmed.any_confirmed && !confirmed.retry_queue_failed);

        let mut noop = KeychainClearOutcome::default();
        fold_clear_outcome(&mut noop, false, false, false);
        assert!(
            !noop.any_confirmed && !noop.retry_queue_failed,
            "a structural no-op (non-macOS / disabled) is not a failure"
        );
    }

    /// M1: a handle dir whose path cannot be canonicalized must be SKIPPED
    /// (WARN + `continue`), never fall back to the non-canonical path — that
    /// would hash to a keychain service name CC never uses and let
    /// `clear_bound_keychain_items` record a false "confirmed" for a dir
    /// whose real item was never touched. This test cannot force
    /// `canonicalize` to fail directly (its failure modes — a symlink loop,
    /// a component removed mid-syscall — are not reproducible from a
    /// TempDir), so it pins the OTHER half of the M1 fix instead: a bound
    /// dir whose path DOES canonicalize successfully must still complete
    /// the keychain step and let `logout_account` succeed (no regression
    /// from the `let Ok(abs) = ... else { continue }` restructuring).
    #[test]
    fn logout_succeeds_when_bound_dir_canonicalizes_normally() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 27);

        let dead_pid: u32 = 2_000_000_003;
        let handle = dir.path().join(format!("term-{dead_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-27").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-27").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), dead_pid.to_string()).unwrap();

        // `TempDir`'s path is always canonicalize-able, so this exercises
        // the `Ok(abs)` arm end-to-end.
        assert!(std::fs::canonicalize(&handle).is_ok());
        let summary = logout_account(dir.path(), account(27)).unwrap();
        assert!(summary.config_dir_removed);
    }
    #[test]
    fn logout_org_identity_regression_same_email_foreign_org_context_is_preserved() {
        let dir = TempDir::new().unwrap();
        let source = IdentityId::new_v4();
        let sibling = IdentityId::new_v4();
        let mut profiles = profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".into(), source);
        profiles.by_slot.insert("2".into(), sibling);
        profiles
            .by_email
            .insert("same@example.test".into(), sibling);
        for (id, org) in [
            (source, "22222222-2222-4222-8222-222222222222"),
            (sibling, "33333333-3333-4333-8333-333333333333"),
        ] {
            profiles.anthropic_contexts.push(
                crate::accounts::anthropic_identity::AnthropicContextEntry {
                    email: "same@example.test".into(),
                    account_uuid: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                        .unwrap(),
                    organization_uuid: uuid::Uuid::parse_str(org).unwrap(),
                    identity_uuid: id,
                    extra: Default::default(),
                },
            );
        }
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        remove_profiles_entry(&lock, dir.path(), account(1)).unwrap();
        let actual = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(!actual.by_slot.contains_key("1"));
        assert_eq!(actual.by_slot.get("2"), Some(&sibling));
        assert_eq!(actual.by_email.get("same@example.test"), Some(&sibling));
        assert_eq!(actual.anthropic_contexts.len(), 1);
        assert_eq!(actual.anthropic_contexts[0].identity_uuid, sibling);
        assert_eq!(actual.slot_binding_generations.get("1"), Some(&1));
    }
}
