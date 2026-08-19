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
}

/// Failure modes for [`logout_account`].
#[derive(Debug)]
pub enum LogoutError {
    /// The account is currently bound to one or more live `claude`
    /// processes via handle dirs. The user must exit those terminals
    /// before logging out — refusing to delete state from under a
    /// running process is the safest default.
    InUse { account: AccountNum, pids: Vec<u32> },
    /// No credential file or config dir exists for this account.
    /// Logout is a no-op against an empty slot.
    NotConfigured { account: AccountNum },
    /// A filesystem operation failed mid-removal.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
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
            LogoutError::InUse { account, pids } => write!(
                f,
                "account {} is in use by live claude process(es): {:?} — exit those terminals first",
                account, pids
            ),
            LogoutError::NotConfigured { account } => {
                write!(f, "account {} is not configured", account)
            }
            LogoutError::Io { path, source } => {
                write!(f, "filesystem error at {}: {}", path.display(), source)
            }
            LogoutError::Profiles(e) => write!(f, "profiles.json error: {}", e),
            LogoutError::VaultUnavailable { account, error_kind } => write!(
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
///     absent) — see [`ALL_SURFACES`]. The pre-PR-fix code only
///     swept the ClaudeCode shape, so logging out a Codex or Gemini
///     slot left its credential file on disk and `discover_codex` /
///     `discover_gemini` continued to surface the slot to the
///     dashboard. Originating bug: this session, slot 12 (Codex)
///     surviving `csq logout 12`.
///  4. Delete the slot's native-CLI (Kimi/Grok) vendor home directory
///     (best-effort if absent) — see [`remove_native_homes`]. The vendor's
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

    let bound_pids = scan_live_handle_dirs_for_account(base_dir, account);
    if !bound_pids.is_empty() {
        // LogoutError::InUse — pre-side-effect rejection: emit NO INTENT (WBS T5).
        return Err(LogoutError::InUse {
            account,
            pids: bound_pids,
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
                let _ = emit_logout_outcome(
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
            let _ = emit_logout_outcome(
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
    let keychain_cleared = clear_bound_keychain_items(base_dir, account);

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
                let _ = emit_logout_outcome(
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
            let _ = emit_logout_outcome(
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
            let _ = emit_logout_outcome(
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
                let _ = emit_logout_outcome(
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
    let identity_dir_removed = match orphaned_uuid {
        Some(uuid) => match std::fs::remove_dir_all(identity_path(base_dir, uuid)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => false, // best-effort; the GC pass collects it next start
        },
        None => false,
    };

    let quota_entry_removed = remove_quota_entry(base_dir, account);

    // M13b — emit OUTCOME:Ok with the resolved orphaned_uuid.
    let outcome_orphaned_uuid = orphaned_uuid.map(|u| u.to_string());
    let _ = emit_logout_outcome(
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
        native_home_removed,
        gemini_vault_cleared,
        keychain_cleared,
    })
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
/// contain the full filesystem path. Replacing `$HOME` with `<home>` prevents
/// the user's username from appearing in exported audit bundles.
fn logout_redact_reason(raw: &str) -> RedactedString {
    let home = std::env::var("HOME").unwrap_or_default();
    let scrubbed = if !home.is_empty() {
        raw.replace(&home, "<home>")
    } else {
        raw.to_string()
    };
    RedactedString::from_untrusted(scrubbed)
}

/// Emit an OUTCOME record for a logout operation. Best-effort — errors are
/// silently discarded (the side effect has already run; the intent is either
/// resolved or becomes a visible orphan for `csq doctor`).
fn emit_logout_outcome(
    base_dir: &Path,
    chain_id: &str,
    correlation_id: crate::audit::types::RecordId,
    account: AccountNum,
    orphaned_uuid: Option<&str>,
    result: OpOutcome,
    intent_emitted: bool,
) -> Result<(), crate::audit::persist::AuditV2Error> {
    // FIX-1: if the intent was skipped (chain broken), skip the outcome too —
    // there is no correlation_id on the chain to match against.
    if !intent_emitted {
        return Ok(());
    }
    let payload = EventPayload::AccountLogout(AccountLogoutPayload {
        slot: account,
        orphaned_uuid: orphaned_uuid.map(|s| s.to_owned()),
    });
    op_emit::emit_outcome(
        base_dir,
        chain_id,
        EventKind::AccountLogout,
        payload,
        correlation_id,
        result,
    )
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

    let mut quota = match quota_state::load_state(base_dir) {
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
) -> Vec<u32> {
    scan_live_handle_dirs_for_account(base_dir, account)
}

fn scan_live_handle_dirs_for_account(base_dir: &Path, account: AccountNum) -> Vec<u32> {
    let mut bound = Vec::new();
    for path in bound_handle_dirs(base_dir, account) {
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let pid = markers::read_live_pid(&path)
            .or_else(|| name.strip_prefix("term-").and_then(|s| s.parse().ok()));
        let Some(pid) = pid else { continue };
        if is_pid_alive(pid) {
            bound.push(pid);
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
    let account_uuid = profiles::resolve_slot_to_uuid(base_dir, account.get());

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
                // `account` has no by_slot UUID mapping, so we cannot rule
                // OUT that this handle dir belongs to it. Destructive
                // operation: fail TOWARD in-use/bound on ambiguity rather
                // than silently proceeding on a comparison we cannot make.
                None => true,
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
/// session with no Aqua session, `security.md` §6 — and every EXISTING
/// caller of `keychain::clear_handle_dir`, `csq swap` / `auto_rotate`, is
/// already fire-and-forget for the same reason; refusing would trap an
/// operator who most needs to remove a compromised or leaked slot). So
/// instead of accepting that residual as permanent, an unconfirmed clear is
/// queued via [`crate::credentials::keychain::record_pending_clear`] and
/// retried by the daemon's periodic sweep and `csq run`'s opportunistic
/// sweep (`keychain::sweep_pending_clears`) — see that module's queue docs.
/// Failures are NEVER silently dropped either way (`zero-tolerance.md` Rule
/// 3): each unconfirmed clear is logged at WARN with a fixed-vocabulary
/// `error_kind` (handle-dir NAME only, never an absolute path —
/// `security.md` MUST-2), and the aggregate result is reported on
/// `LogoutSummary::keychain_cleared`.
fn clear_bound_keychain_items(base_dir: &Path, account: AccountNum) -> bool {
    let mut any_confirmed = false;
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
        if confirmed {
            any_confirmed = true;
        }
        if needs_retry {
            tracing::warn!(
                error_kind = "keychain_clear_unconfirmed",
                account = account.get(),
                dir = %dir_name,
                "logout: could not confirm the keychain OAuth item was cleared for \
                 this handle dir (non-fatal — keychain may be locked or unavailable; \
                 queued for automatic retry; logout continues)"
            );
            // Security review 1386 H1: the file-based copies of this
            // credential are deleted later in THIS SAME logout_account call
            // (ALL_SURFACES sweep, config_dir removal, identity dir removal),
            // so an item that could not be confirmed cleared here can become
            // the credential's ONLY surviving copy at function exit. Queue it
            // for retry by the daemon's periodic sweep and by `csq run`'s
            // opportunistic sweep, rather than leaving it a silent, permanent
            // orphan the moment `config_dir` disappears below.
            crate::credentials::keychain::record_pending_clear(
                base_dir,
                &crate::credentials::keychain::service_name(&abs),
            );
        }
    }
    any_confirmed
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
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    account: AccountNum,
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
        !file.by_slot.values().any(|x| x == u) && !file.by_email.values().any(|x| x == u)
    });

    profiles::save(&path, &file).map_err(LogoutError::Profiles)?;
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
            Err(LogoutError::InUse { account: a, pids }) => {
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
            Err(LogoutError::InUse { account: a, pids }) => {
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
}
