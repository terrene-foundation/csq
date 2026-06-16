//! profiles.json management — maps account numbers to email/method pairs.
//!
//! # Schema versioning
//!
//! `profiles.json` carries two schema generations simultaneously during A++
//! Phase 1 through Phase 3 coexistence:
//!
//! - **v1 (v2.6.x shape):** `{ "accounts": { "1": { email, method } } }`
//!   plus unknown top-level keys round-tripped via `#[serde(flatten)] extra`.
//! - **v2 (v2.7.x shape, Phase 1 M1-2):** adds top-level `by_slot` and
//!   `by_email` maps alongside the existing `accounts` field.
//!
//! The `#[serde(flatten)] extra` hatch at the `ProfilesFile` level is the
//! forward-compat mechanism: a v2.6.x csq reader that deserializes the merged
//! v2.7.x file loses `by_slot` and `by_email` into `extra`. When that v2.6.x
//! csq re-saves the file, serde re-emits `extra` verbatim so the UUID
//! maps survive the round-trip. This is the v2.6.x↔v2.7.x round-trip
//! regression tested in `flatten_preserves_unknown_fields_and_v2_keys`.
//!
//! **Shadow authority in Phase 1:** `by_slot` and `by_email` are written but
//! no production reader routes through them yet. Phase 2 activates the reader
//! switchover at `csq-core/src/usage/account_id.rs:37`.

use crate::accounts::identity_store::{self, IdentityId};
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Reads `oauthAccount.emailAddress` from a credential JSON file.
///
/// Used internally to source the OAuth email from the authenticated credential
/// record rather than from the `by_email` map (which could be polluted if a
/// rename label happened to equal another slot's OAuth email — the C2 class
/// of cross-contamination from journal 0029).
fn read_oauth_email_from_cred(cred_path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(cred_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let email = json
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())?;
    if email.is_empty() {
        None
    } else {
        Some(email.to_string())
    }
}

/// Top-level profiles file. Maps account numbers (as strings) to profiles.
///
/// The two fields (`by_slot`, `by_email`) are A++ Phase 1 additions.
/// They are additive: an absent key deserializes to an empty map.
///
/// **M4-13 (release N+1, 2026-05-26):** the v1 `accounts` field has been
/// REMOVED. On-disk files that still carry `accounts: {...}` from earlier
/// releases have their payload absorbed by the `#[serde(flatten)] extra`
/// hatch — no parse error, and the key is round-tripped through `extra`
/// until the `prune_redundant_accounts_entries` reconciler pass (which runs
/// on every daemon start) removes the `accounts` key from `extra` once the
/// field's content is fully recovered through other channels.
///
/// **Merge contract:** top-level fields defined by this struct are serialized
/// explicitly; the `extra` hatch captures everything else. A v2.6.x csq that
/// round-trips a v2.7.x file preserves `by_slot` and `by_email` via `extra`
/// because it does not comprehend those keys as named fields. Likewise,
/// a v2.12.x (or older) on-disk file carrying `accounts: {...}` is absorbed
/// into `extra` on first load by this build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesFile {
    /// A++ Phase 1: slot number (as string, e.g. `"1"`) → UUID identity.
    /// Shadow authority — written in Phase 1; read in Phase 2+.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_slot: HashMap<String, IdentityId>,

    /// A++ Phase 1: email address → UUID identity.
    /// Shadow authority — written in Phase 1; read in Phase 2+.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_email: HashMap<String, IdentityId>,

    /// RN1-D2 (A1 label channel): slot number (as string) → user-chosen
    /// display label. Written by `set_slot_label` (the `rename_account`
    /// flow, post-D3). Read by `get_email` (D3 changes resolution order
    /// to check this FIRST before `accounts[N].email`).
    ///
    /// Slot-keyed (not UUID-keyed) so that `csq move FROM TO` can
    /// swap entries alongside `by_slot` via `swap_slot_mapping` (D4).
    ///
    /// Absent for slots that have never been renamed — `get_email` falls
    /// through to `accounts[N].email` then `by_slot→by_email`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_slot_label: HashMap<String, String>,

    /// Identity-class labels for non-OAuth slots (3P API keys, Codex).
    /// Slot number (as string, e.g. "9") → identity label literal:
    ///   "apikey:<provider_id>"    for 3P API-key slots
    ///   "codex-<N>/<id-prefix>"   for Codex OAuth slots
    ///   "gemini-<N>/<id>"         reserved for future Gemini integration
    /// Distinct from `by_slot_label` (user rename) so backfill + rename
    /// do not collide.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_slot_identity: HashMap<String, String>,

    /// Forward-compat: preserve unknown top-level keys.
    ///
    /// This hatch is the structural mechanism for two round-trip contracts:
    /// 1. v2.6.x↔v2.7.x: a v2.6.x reader captures `by_slot`/`by_email`
    ///    here and re-emits them verbatim on save.
    /// 2. M4-13 (release N+1): on-disk files carrying the now-deleted
    ///    `accounts: {...}` field have its payload absorbed here so no
    ///    parse error occurs; the `prune_redundant_accounts_entries`
    ///    reconciler pass removes the `accounts` key from `extra` once the
    ///    content is information-recoverable through other channels.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ProfilesFile {
    /// Returns an empty profiles file with all maps initialized.
    pub fn empty() -> Self {
        Self {
            by_slot: HashMap::new(),
            by_email: HashMap::new(),
            by_slot_label: HashMap::new(),
            by_slot_identity: HashMap::new(),
            extra: HashMap::new(),
        }
    }

    /// Gets the email (or user-chosen display label) for a given account
    /// number, or `None` if not found.
    ///
    /// Resolution order (M4-13, release N+1 — `accounts` field removed):
    ///
    /// - **Step 1** `by_slot_label[N]` — user-chosen rename label (A1
    ///   channel, written by `set_slot_label` / the `rename_account` flow).
    ///   Checked FIRST so renames take effect immediately. Step 1 wins
    ///   over step 1b — a user rename always takes precedence over a
    ///   backfilled identity.
    /// - **Step 1b** `by_slot_identity[N]` — non-OAuth identity-class label
    ///   written by the daemon backfill reconciler (M6),
    ///   `bind_provider_to_slot` (M7), and Codex `finalize_login` (M8).
    ///   Distinct from step 1 so backfill + rename do not collide.
    ///   Step 1b is checked after the rename channel so a user rename wins.
    /// - **Step 2** `by_slot[N] → UUID → reverse-search by_email` — fallback
    ///   for OAuth slots that have never been renamed and have reached
    ///   daemon Pass 0 / `mint_for_login`.
    ///
    /// (The former Step 2 `accounts[N].email` compat seam was removed in
    /// M4-13 / release N+1. The `prune_redundant_accounts_entries`
    /// reconciler pass ensures any residual `accounts` key in `extra` is
    /// cleaned up on upgraded hosts.)
    pub fn get_email(&self, account: u16) -> Option<&str> {
        let slot_key = account.to_string();
        // Step 1: by_slot_label (RN1-D3 A1 label channel — checked first).
        if let Some(label) = self.by_slot_label.get(&slot_key).map(|l| l.as_str()) {
            return Some(label);
        }
        // Step 1.5: by_slot_identity (non-OAuth identity-class label).
        // Distinct from step 1 (by_slot_label = user rename) so a backfilled
        // identity does not conflict with a user-chosen rename. Step 1 is
        // checked first so a rename always wins over a backfilled label.
        if let Some(label) = self.by_slot_identity.get(&slot_key).map(|s| s.as_str()) {
            return Some(label);
        }
        // Step 2: identity layer fallback for un-renamed OAuth slots.
        // (Former Step 2 `accounts[N].email` removed in M4-13.)
        let uuid = self.by_slot.get(&slot_key).copied()?;
        self.by_email
            .iter()
            .find_map(|(e, u)| (*u == uuid).then_some(e.as_str()))
    }

    /// Sets or updates a v1-style account profile entry in `extra["accounts"]`.
    ///
    /// **Test/fixture use only.** Production writers MUST NOT call this method.
    /// This is retained so tests can simulate a v2.6.x-populated shape and
    /// assert that v2.13.x+ readers tolerate residual `accounts: {…}` payloads
    /// via the `#[serde(flatten)] extra` hatch.
    ///
    /// Writing directly into `extra` rather than a dedicated struct field keeps
    /// test fixtures faithful to the on-disk representation a real v2.12.x host
    /// would have produced.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_profile(&mut self, account: u16, profile: AccountProfile) {
        let entry = self
            .extra
            .entry("accounts".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(obj) = entry.as_object_mut() {
            let mut slot_obj = serde_json::Map::new();
            slot_obj.insert(
                "email".to_string(),
                serde_json::Value::String(profile.email),
            );
            slot_obj.insert(
                "method".to_string(),
                serde_json::Value::String(profile.method),
            );
            obj.insert(account.to_string(), serde_json::Value::Object(slot_obj));
        }
    }

    /// Returns the legacy v1 `accounts` map as a `HashMap<String, AccountProfile>`.
    ///
    /// **Test/fixture use only.** Production readers MUST NOT call this method.
    /// Returns an empty map when the `accounts` key is absent from `extra`
    /// (normal case on freshly-initialized hosts or after pruning).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn accounts_for_test(&self) -> std::collections::HashMap<String, AccountProfile> {
        let Some(accounts_val) = self.extra.get("accounts") else {
            return std::collections::HashMap::new();
        };
        let Some(obj) = accounts_val.as_object() else {
            return std::collections::HashMap::new();
        };
        obj.iter()
            .map(|(k, v)| {
                let email = v
                    .get("email")
                    .and_then(|e| e.as_str())
                    .unwrap_or("")
                    .to_string();
                let method = v
                    .get("method")
                    .and_then(|e| e.as_str())
                    .unwrap_or("")
                    .to_string();
                (
                    k.clone(),
                    AccountProfile {
                        email,
                        method,
                        extra: HashMap::new(),
                    },
                )
            })
            .collect()
    }

    /// Gets a v1-style account profile from `extra["accounts"]`, if present.
    ///
    /// **Test/fixture use only.** Production readers MUST NOT call this method.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn get_profile(&self, account: u16) -> Option<AccountProfile> {
        let accounts_val = self.extra.get("accounts")?;
        let obj = accounts_val.as_object()?;
        let entry = obj.get(&account.to_string())?;
        let email = entry
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let method = entry
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Some(AccountProfile {
            email,
            method,
            extra: HashMap::new(),
        })
    }
}

/// Profile entry for a single account.
///
/// **Test/fixture use only (M4-13).** This struct is retained only to allow
/// test fixtures to simulate the v2.6.x on-disk shape and verify that the
/// `#[serde(flatten)] extra` hatch round-trips residual `accounts: {…}`
/// payloads transparently. Production code MUST NOT construct this type;
/// use `by_slot_label`, `by_slot_identity`, or `by_email` instead.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    /// Email address (or identity label for 3P accounts).
    pub email: String,
    /// Authentication method. Known values: "oauth", "api_key".
    pub method: String,

    /// Forward-compat: preserve unknown fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Loads profiles.json from disk. Returns an empty ProfilesFile if
/// the file doesn't exist (not an error — profiles are optional).
pub fn load(path: &Path) -> Result<ProfilesFile, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.trim().is_empty() {
                return Ok(ProfilesFile::empty());
            }
            serde_json::from_str(&content).map_err(|e| ConfigError::InvalidJson {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProfilesFile::empty()),
        Err(e) => Err(ConfigError::InvalidJson {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

/// Saves profiles.json to disk with atomic write.
///
/// The write pipeline follows security.md MUST Rule 5a and MUST Rule 5:
/// every failure branch removes the tmp file before propagating the error,
/// because profiles.json carries email PII + provider metadata.
/// The `secure_file` step propagates failure (fail-closed) — a permission
/// failure leaves the token-bearing tmp at umask default; the only safe
/// response is to remove the tmp and surface the error. Mirrors the
/// fail-closed posture in `third_party::bind_provider_to_slot`.
pub fn save(path: &Path, profiles: &ProfilesFile) -> Result<(), ConfigError> {
    let json = serde_json::to_string_pretty(profiles).map_err(|e| ConfigError::InvalidJson {
        path: path.to_path_buf(),
        reason: format!("serialization: {e}"),
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(path);
    // §5a cleanup: profiles.json carries email + method + provider PII.
    // Partial-failure leaves PII-bearing tmp at umask 0o644.
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp,
            reason: format!("write: {e}"),
        });
    }

    // SECURITY: propagate (not `.ok()`) — a silent permission failure would
    // publish the PII-bearing tmp at umask default, potentially world-readable.
    // Fail closed. §5a: remove tmp before propagating on any failure.
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("secure_file: {e}"),
        });
    }

    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: path.to_path_buf(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(())
}

/// Returns the path to profiles.json within a base directory.
pub fn profiles_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("profiles.json")
}

/// Updates the display label for an account by writing to `by_slot_label`.
///
/// **RN1-D3:** The rename channel migrated from `profiles.accounts` to the
/// A1 `by_slot_label` map. `get_email`'s resolution order (D3) checks
/// `by_slot_label` FIRST, so a write here is immediately visible to every
/// reader. The legacy `profiles.accounts` channel is no longer written by
/// this function.
///
/// The desktop `Rename account` action
/// (`csq/src/desktop/commands/mod.rs::rename_account`) routes here.
///
/// # Lock
///
/// This function acquires the exclusive [`ProfilesFileLock`] for `base_dir`
/// as its first action and holds it across the entire `load → mutate → save`
/// cycle. Without the lock, two concurrent `rename_account` actions (or a
/// rename racing the daemon Pass-0 mint) would both load the same
/// `profiles.json`, apply independent edits, and whichever saved last would
/// silently drop the other's update. The lock is released on function return.
///
/// Because `update_email` is a self-contained, single-operation writer (called
/// only from the `rename_account` Tauri command — one user action with no
/// surrounding multi-step lock window), it acquires the lock internally rather
/// than taking a `_lock` type-witness parameter. The type-witness pattern is
/// reserved for callers like `move_account` that hold a wider lock window
/// across multiple mutations.
pub fn update_email(
    base_dir: &Path,
    account: crate::types::AccountNum,
    new_label: &str,
) -> Result<(), ConfigError> {
    let lock = ProfilesFileLock::acquire(base_dir)?;
    set_slot_label(&lock, base_dir, account.get(), new_label)
}

/// Resolves a slot number to its UUID identity.
///
/// Returns `Some(uuid)` if `by_slot[slot.to_string()]` is present in the
/// loaded profiles. Returns `None` if the slot is not in `by_slot` or if
/// profiles.json is missing. Never returns a silent fallback — absent key
/// means `None`.
///
/// **Phase 1:** This function exists as the path helper for the anchor at
/// `csq-core/src/usage/account_id.rs:37`. Phase 2 activates that callsite.
pub fn resolve_slot_to_uuid(base_dir: &Path, slot: u16) -> Option<IdentityId> {
    let path = profiles_path(base_dir);
    let profiles = load(&path).ok()?;
    profiles.by_slot.get(&slot.to_string()).copied()
}

/// Resolves a UUID identity back to its slot number — the inverse of
/// [`resolve_slot_to_uuid`].
///
/// This is the missing reverse resolver that lets the statusline / snapshot
/// path map a UUID `.csq-account` marker (the Phase-4 content for Anthropic
/// OAuth slots) back to a numeric slot. Without it, a UUID marker has no
/// numeric channel and the (drift-prone) `.current-account` cache became
/// load-bearing — the root cause of the `csq swap N` → wrong-slot bug
/// (workspace `slot-attribution-consistency`).
///
/// Only `by_slot` (slot→UUID, Anthropic OAuth) is searched. `by_slot_identity`
/// holds human-readable labels (`"codex-8/3bf322e8"`, `"apikey:mm"`), NOT
/// UUIDs, so it cannot be reverse-searched by UUID — and codex/gemini/3P slots
/// carry NUMERIC `.csq-account` markers anyway (resolved directly by the
/// caller), so they never reach this function.
///
/// **Determinism:** `by_slot` is normally injective (one UUID per slot). If a
/// UUID is (anomalously) bound to multiple slots, the LOWEST slot number is
/// returned so the result is stable across `HashMap` iteration order. The
/// caller that knows the candidate slot (e.g. from the handle dir's
/// `.csq-account` symlink target) should prefer validating
/// `resolve_slot_to_uuid(slot) == uuid` instead.
///
/// **No-silent-fallback** (`account-terminal-separation.md` MUST NOT Rule 3):
/// returns `None` when profiles.json is missing/unreadable or the UUID is not
/// present in `by_slot`. Never invents a slot.
pub fn resolve_uuid_to_slot(base_dir: &Path, uuid: IdentityId) -> Option<crate::types::AccountNum> {
    let path = profiles_path(base_dir);
    let profiles = load(&path).ok()?;
    profiles
        .by_slot
        .iter()
        .filter(|(_, v)| **v == uuid)
        .filter_map(|(k, _)| k.parse::<u16>().ok())
        .min()
        .and_then(|slot| crate::types::AccountNum::try_from(slot).ok())
}

/// Enumerates every `config-N` whose `.current-account` cache holds a slot id
/// ≠ N — the stale-cache drift the `csq swap N → wrong slot` bug rode on.
/// `.current-account` absent is NOT drift (a valid state). Returns
/// `(slot, cached)` pairs sorted by slot ascending for deterministic ordering.
///
/// This is the SINGLE drift predicate shared by `csq doctor`
/// (`audit_coexistence`, which takes the first) and `csq repair`
/// (`scan_attribution`, which repairs all) so the two surfaces cannot drift
/// apart (`reconciler-cleanup-parity.md` Rule 4 — one keep-set across
/// consumers). Workspace slot-attribution-consistency.
pub fn current_account_drifts(base_dir: &Path) -> Vec<(u16, u16)> {
    let mut slots: Vec<u16> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(base_dir) {
        for entry in rd.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Some(rest) = name.strip_prefix("config-") {
                    if let Ok(n) = rest.parse::<u16>() {
                        // Bound to the valid AccountNum range (1..=MAX_ACCOUNTS)
                        // so the drift predicate is coherent with the type
                        // system — `config-1000`+ are not valid slots and must
                        // not surface as drift (R3 rust-specialist LOW-1).
                        if (1..=crate::types::MAX_ACCOUNTS).contains(&n) {
                            slots.push(n);
                        }
                    }
                }
            }
        }
    }
    slots.sort_unstable();
    slots
        .into_iter()
        .filter_map(|n| {
            let cfg = base_dir.join(format!("config-{n}"));
            match crate::accounts::markers::read_current_account(&cfg) {
                Some(c) if c.get() != n => Some((n, c.get())),
                _ => None,
            }
        })
        .collect()
}

/// Resolves an email address to its UUID identity.
///
/// Returns `Some(uuid)` if `by_email[email]` is present in the loaded
/// profiles. Returns `None` if the email is not in `by_email` or if
/// profiles.json is missing. Never returns a silent fallback.
pub fn resolve_email_to_uuid(base_dir: &Path, email: &str) -> Option<IdentityId> {
    let path = profiles_path(base_dir);
    let profiles = load(&path).ok()?;
    profiles.by_email.get(email).copied()
}

/// Writes a slot→UUID and email→UUID mapping into profiles.json.
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// before calling this function. The `_lock` parameter is a type-witness that
/// enforces this at compile time — passing `&lock` makes the lock scope
/// statically visible at every callsite. The parameter is not used in the
/// function body; it exists solely to enforce the precondition.
///
/// Rationale: this function performs a read-modify-write cycle
/// (`load → mutate → save`). Without the lock, two concurrent OS processes
/// (the daemon Pass 0 and `csq login N`) can both load the same file, apply
/// different edits, and whichever saves last silently drops the other's update.
/// The lock serializes all writers.
///
/// If `by_slot` already contains an entry for `slot`, it is overwritten.
/// If `by_email` already contains an entry for `email`, it is overwritten.
/// All other fields and `extra` are preserved unchanged.
///
/// The write follows the §5a-compliant pipeline in `save()`.
pub fn add_identity_mapping(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    email: &str,
    uuid: IdentityId,
) -> Result<(), ConfigError> {
    let path = profiles_path(base_dir);
    let mut profiles = load(&path)?;
    profiles.by_slot.insert(slot.to_string(), uuid);
    profiles.by_email.insert(email.to_string(), uuid);
    save(&path, &profiles)
}

/// Removes the `by_slot[slot]` entry from `profiles.json`.
///
/// Used for partial-mint rollback (CRIT-2): when `mint_for_codex_login`
/// succeeds (writes `by_slot[N] = UUID`) but `save_canonical_for` then
/// fails, the slot is left in a partial-mint state. Rolling back
/// `by_slot[slot]` lets the next `csq run N` / re-login retry cleanly.
///
/// # Idempotency contract
///
/// `by_email[synthetic_key]` is intentionally **preserved** on rollback so
/// that a retry reuses the same UUID (no churn) — the `by_email` entry is
/// the UUID reservation; removing it would cause a fresh UUID on retry and
/// violate idempotency.
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// before calling this function. The `_lock` parameter is a type-witness that
/// enforces this at compile time — the same pattern as `add_identity_mapping`.
///
/// # Return value
///
/// Returns `Ok(())` whether or not the slot key was present (idempotent).
/// Callers that invoke this on a best-effort basis should log on `Err` but
/// propagate the original error rather than this one.
pub fn remove_slot_mapping(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
) -> Result<(), ConfigError> {
    let path = profiles_path(base_dir);
    if !path.exists() {
        // Nothing to remove — idempotent no-op.
        return Ok(());
    }
    let mut profiles = load(&path)?;
    let slot_key = slot.to_string();
    if profiles.by_slot.remove(&slot_key).is_none() {
        // Already absent — idempotent no-op, no disk write.
        return Ok(());
    }
    save(&path, &profiles)
}

// NOTE: a `prune_orphan_slot_and_email` mutation primitive (remove `by_slot[N]`
// + its paired `by_email` entry) was prototyped here and REMOVED (2026-06-01)
// together with the `csq repair` orphan-prune. It was built on the false
// premise that a slot in both `by_slot` and `by_slot_identity` is an orphan —
// that is the normal codex-slot shape, and pruning `by_slot[N]` breaks the
// codex slot. See memory `discovery_by_slot_holds_codex_identities`.

/// Writes a user-chosen display label for a slot into `profiles.json`.
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// before calling this function. The `_lock` parameter is a type-witness that
/// enforces this at compile time — the same pattern as `add_identity_mapping`.
///
/// # Behaviour
///
/// If `by_slot_label` already contains an entry for `slot`, it is overwritten.
/// All other fields are preserved unchanged. An empty label is stored verbatim —
/// the caller (`rename_account` Tauri command) is responsible for rejecting
/// empty labels before calling this function (D3 adds that validation).
///
/// # §5a compliance
///
/// Labels are user-visible strings, not secrets. The `save()` helper already
/// performs §5a-compliant atomic write + `secure_file`. No additional cleanup
/// is needed at this layer.
pub fn set_slot_label(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    label: &str,
) -> Result<(), ConfigError> {
    let path = profiles_path(base_dir);
    let mut profiles = load(&path)?;
    profiles
        .by_slot_label
        .insert(slot.to_string(), label.to_string());
    save(&path, &profiles)
}

/// Sets the identity-class label for a slot in `by_slot_identity`.
///
/// Used by the daemon backfill reconciler (M6), `bind_provider_to_slot`
/// (M7), and Codex `finalize_login` (M8) to record the non-OAuth
/// identity for a slot. Distinct from [`set_slot_label`] (user rename
/// channel) — the two write separate fields and `get_email`'s step 1
/// always wins over step 1.5.
///
/// # Idempotency
///
/// If `by_slot_identity[slot]` already equals `label`, the function
/// skips the save entirely (no disk I/O, no fsync). This preserves
/// mtime for downstream watchers and avoids redundant atomic writes
/// during reconciler passes.
///
/// # Lock precondition
///
/// The caller MUST hold the exclusive [`ProfilesFileLock`] for
/// `base_dir`. The `_lock` parameter is a compile-time type-witness.
pub fn set_slot_identity(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    label: &str,
) -> Result<(), ConfigError> {
    let path = profiles_path(base_dir);
    let mut profiles = load(&path)?;
    let slot_key = slot.to_string();
    // Idempotency: skip save when current value already matches.
    if profiles.by_slot_identity.get(&slot_key).map(|s| s.as_str()) == Some(label) {
        return Ok(());
    }
    profiles
        .by_slot_identity
        .insert(slot_key, label.to_string());
    save(&path, &profiles)
}

/// Compile-time signature pin — ensures the type-witness `_lock` argument
/// and argument types of `set_slot_identity` cannot be silently changed by
/// a refactor.
const _SET_SLOT_IDENTITY_SIG: fn(&ProfilesFileLock, &Path, u16, &str) -> Result<(), ConfigError> =
    set_slot_identity;

/// Removes the identity-class label for a slot from `by_slot_identity`,
/// if present.
///
/// Used by `finalize_login` after `unbind_provider_from_slot` when a
/// slot is transitioning from a non-OAuth identity (3P API-key, Codex)
/// to an Anthropic OAuth identity.  Without this cleanup `get_email`'s
/// step 1.5 would return the stale `"apikey:<provider>"` label instead
/// of the OAuth email resolved via step 3 (F-H-1 fix).
///
/// Idempotent: if `by_slot_identity[slot]` is absent the function
/// returns `Ok(())` without touching disk.
///
/// # Lock precondition
///
/// The caller MUST hold the exclusive [`ProfilesFileLock`] for
/// `base_dir`. The `_lock` parameter is a compile-time type-witness.
pub fn clear_slot_identity(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
) -> Result<(), ConfigError> {
    let path = profiles_path(base_dir);
    if !path.exists() {
        return Ok(());
    }
    let mut profiles = load(&path)?;
    let slot_key = slot.to_string();
    if profiles.by_slot_identity.remove(&slot_key).is_none() {
        // Already absent — idempotent no-op, no disk write.
        return Ok(());
    }
    save(&path, &profiles)
}

/// Compile-time signature pin — ensures the type-witness `_lock` argument
/// and argument types of `clear_slot_identity` cannot be silently changed.
const _CLEAR_SLOT_IDENTITY_SIG: fn(&ProfilesFileLock, &Path, u16) -> Result<(), ConfigError> =
    clear_slot_identity;

/// Swaps the `by_slot` entries for two slot numbers in `profiles.json`.
///
/// After `csq move FROM TO`, the on-disk `config-FROM/` directory has been
/// renamed to `config-TO/`. The slot→UUID mapping in `by_slot` must follow:
/// the identity that was addressable at `by_slot[FROM]` is now addressable at
/// `by_slot[TO]`, and vice-versa.
///
/// `by_email` is intentionally **not** updated — email→UUID is slot-independent.
///
/// # Return value
///
/// Returns `Ok(true)` when at least one of `by_slot[a]` or `by_slot[b]` was
/// present and the swap was performed (file written). Returns `Ok(false)` when
/// `profiles.json` is absent OR neither slot has a `by_slot` entry
/// (legacy-only / unprovisioned fixture), after emitting an `info!` log.
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// before calling this function. The `_lock` parameter is a type-witness that
/// enforces this at compile time. This function is called from
/// `accounts::move_slot::move_account` under the SAME lock window as
/// `move_profiles_entry`, satisfying SEC-2.3.
///
/// **This is the single source of truth for `by_slot` swaps.** The private
/// `swap_by_slot_mapping` that previously existed in `move_slot.rs` has been
/// deleted (MED-1 fix). All callers use this public function.
///
/// The write follows the §5a-compliant pipeline in `save()`.
///
/// # Compile-time signature pin
///
/// The `const _` assertion below ensures the function's type does not silently
/// change (e.g., drop the `_lock` type-witness arg) during refactoring:
/// ```text
/// const _: fn(&ProfilesFileLock, &Path, u16, u16) -> Result<bool, ConfigError>
///     = swap_slot_mapping;
/// ```
pub fn swap_slot_mapping(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    a: u16,
    b: u16,
) -> Result<bool, ConfigError> {
    let path = profiles_path(base_dir);
    if !path.exists() {
        tracing::info!(
            slot_a = a,
            slot_b = b,
            "swap_slot_mapping: profiles.json absent — no-op"
        );
        return Ok(false);
    }
    let mut pf = load(&path)?;
    let key_a = a.to_string();
    let key_b = b.to_string();

    // Compute all six removals upfront so the early-return check is
    // authoritative across ALL three maps.  The old check tested only
    // `by_slot`, which incorrectly no-op'd `csq move` for non-OAuth
    // slots (3P API-key, Codex) that have `by_slot_identity` but no
    // `by_slot` UUID (F-C-1 regression fix).
    let uuid_a = pf.by_slot.remove(&key_a);
    let uuid_b = pf.by_slot.remove(&key_b);
    let label_a = pf.by_slot_label.remove(&key_a);
    let label_b = pf.by_slot_label.remove(&key_b);
    let identity_a = pf.by_slot_identity.remove(&key_a);
    let identity_b = pf.by_slot_identity.remove(&key_b);

    // Only no-op when ALL six values are absent: nothing to swap in any map.
    if uuid_a.is_none()
        && uuid_b.is_none()
        && label_a.is_none()
        && label_b.is_none()
        && identity_a.is_none()
        && identity_b.is_none()
    {
        tracing::info!(
            slot_a = a,
            slot_b = b,
            "swap_slot_mapping: neither slot has any by_slot/by_slot_label/by_slot_identity entry — no-op"
        );
        return Ok(false);
    }

    if let Some(u) = uuid_a {
        pf.by_slot.insert(key_b.clone(), u);
    }
    if let Some(u) = uuid_b {
        pf.by_slot.insert(key_a.clone(), u);
    }

    // RN1-D4: also swap by_slot_label entries so a user-chosen rename
    // label follows the slot identity through `csq move FROM TO`.
    if let Some(l) = label_a {
        pf.by_slot_label.insert(key_b.clone(), l);
    }
    if let Some(l) = label_b {
        pf.by_slot_label.insert(key_a.clone(), l);
    }

    // M4-by_slot_identity: also swap by_slot_identity entries so a
    // backfilled non-OAuth identity follows the slot through `csq move
    // FROM TO`. Same shape as by_slot_label swap above.
    if let Some(l) = identity_a {
        pf.by_slot_identity.insert(key_b, l);
    }
    if let Some(l) = identity_b {
        pf.by_slot_identity.insert(key_a, l);
    }

    save(&path, &pf)?;
    Ok(true)
}

/// Compile-time signature pin — ensures the type-witness `_lock` argument
/// and return type of `swap_slot_mapping` cannot be silently dropped by
/// a refactor (LOW-2 fix, redteam round 1).
const _SWAP_SLOT_MAPPING_SIG: fn(&ProfilesFileLock, &Path, u16, u16) -> Result<bool, ConfigError> =
    swap_slot_mapping;

// ─── RN1-D5a label relocation ────────────────────────────────────────────────

/// Outcome of a single slot's label relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotRelocationOutcome {
    /// `accounts[N].email` was a renamed label (differs from OAuth email)
    /// → copied to `by_slot_label[N]`.
    Relocated { slot: u16, label: String },
    /// `accounts[N].email` was the OAuth email (no rename) → skipped.
    SkippedOauthEmail { slot: u16 },
    /// Slot has an `accounts[N]` entry but no `by_slot` mapping → no OAuth
    /// email to compare; entry is skipped (may be a legacy 3P slot or an
    /// unprovisioned slot).
    SkippedNoUuid { slot: u16 },
    /// Slot has no `accounts[N]` entry → nothing to relocate.
    NoAccountEntry { slot: u16 },
    /// `accounts[N].email` exists (user-chosen rename label) but there is NO
    /// `by_slot[N]` UUID entry — the slot was never minted via Pass-0. The
    /// label cannot be relocated to `by_slot_label` because there is no UUID
    /// to anchor the identity.
    ///
    /// This is the data-loss class flagged by WBS RN1-D5: when RN1-F removes
    /// the `accounts` field, this label will be silently dropped. The user
    /// MUST log in again (`csq login N`) so Pass-0 mints a UUID, then re-run
    /// the daemon so the relocation pass fires again.
    UnrecoverableNoBySlot { slot: u16, accounts_email: String },
}

/// Report returned by [`relocate_labels_to_by_slot_label`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelocationReport {
    /// Total slots examined (those with a `by_slot` UUID mapping).
    pub slots_examined: usize,
    /// Slots whose label was relocated from `accounts[N].email` to
    /// `by_slot_label[N]`.
    pub slots_relocated: usize,
    /// Slots where `accounts[N].email` matched the OAuth email (no rename
    /// needed → skipped).
    pub slots_skipped_oauth_email: usize,
    /// Slots where no `by_slot` UUID mapping existed (cannot determine
    /// whether the label is a rename → skipped conservatively).
    pub slots_skipped_no_uuid: usize,
    /// Slots with `accounts[N].email` (a user rename label) but NO
    /// `by_slot[N]` UUID — the slot was never Pass-0 minted. These labels
    /// CANNOT be relocated; they will be silently dropped when RN1-F removes
    /// the `accounts` field. Surface via `csq doctor` (WBS RN1-D5 warning).
    pub slots_unrecoverable_no_by_slot: usize,
    /// Per-slot outcome records for diagnostics.
    pub outcomes: Vec<SlotRelocationOutcome>,
}

/// One-time migration: copies user-chosen rename labels from the legacy
/// `profiles.accounts[N].email` channel into the new `by_slot_label[N]` A1
/// channel.
///
/// # What counts as a rename label?
///
/// A slot's `accounts[N].email` is considered a rename label (and therefore
/// relocated) when:
/// - `by_slot[N]` has a UUID mapping (so the OAuth email is derivable), AND
/// - The OAuth email from `oauth_email_for_slot(N)` differs from
///   `accounts[N].email`.
///
/// When the two values are equal, `accounts[N].email` is the bare OAuth email
/// written by a pre-RN1-D3 `update_email` call (which happened on login
/// instead of on rename). Those entries are left as-is — the `get_email`
/// fallback chain will surface them from `accounts[N]` already.
///
/// # Idempotency
///
/// The function is safe to call multiple times. If `by_slot_label[N]` already
/// has a value, it is NOT overwritten — the existing rename label takes
/// precedence. This ensures a user's label survives if they renamed their
/// account after the daemon ran a relocation pass.
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// before calling this function. The `_lock` parameter is a type-witness that
/// enforces this at compile time.
pub fn relocate_labels_to_by_slot_label(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
) -> Result<RelocationReport, ConfigError> {
    let path = profiles_path(base_dir);
    let mut pf = load(&path)?;
    let mut report = RelocationReport::default();

    // Collect slot numbers that have a `by_slot` UUID mapping — those are
    // the Anthropic OAuth slots that Pass-0 provisioned.
    let by_slot_keys: Vec<String> = pf.by_slot.keys().cloned().collect();
    report.slots_examined = by_slot_keys.len();

    let mut dirty = false;

    for key in &by_slot_keys {
        let slot: u16 = match key.parse() {
            Ok(n) => n,
            Err(_) => continue, // malformed key — skip
        };

        // C2 fix: source OAuth email from the credential file, NOT from
        // `by_email` reverse-lookup. If `by_email` is polluted (rename label
        // matching another slot's email), the reverse lookup returns the
        // polluted value and relocate_labels would misclassify the entry.
        let uuid = match pf.by_slot.get(key).copied() {
            Some(u) => u,
            None => {
                // by_slot entry was in keys() but vanished — race condition,
                // skip defensively.
                report.slots_skipped_no_uuid += 1;
                report
                    .outcomes
                    .push(SlotRelocationOutcome::SkippedNoUuid { slot });
                continue;
            }
        };
        let cred_path = identity_store::credentials_path_for(base_dir, uuid);
        let oauth_email = match read_oauth_email_from_cred(&cred_path) {
            Some(e) => e,
            None => {
                // No credential file or no emailAddress — cannot determine OAuth
                // email for comparison; skip this slot (conservative).
                report.slots_skipped_no_uuid += 1;
                report
                    .outcomes
                    .push(SlotRelocationOutcome::SkippedNoUuid { slot });
                continue;
            }
        };

        // M4-13: accounts field removed; legacy content lives in extra["accounts"].
        let legacy_accounts = legacy_accounts_email_map(&pf);
        let accounts_email = legacy_accounts.get(key).cloned();
        let Some(accounts_email) = accounts_email else {
            // No accounts[N] entry in extra — nothing to relocate for this slot.
            report
                .outcomes
                .push(SlotRelocationOutcome::NoAccountEntry { slot });
            continue;
        };

        // M4-13 /redteam R1 MED-1: skip empty-email entries. `legacy_accounts_email_map`
        // returns "" for `accounts[N]` entries whose `email` field is missing/null/non-string
        // (defensive parse; the v1 contract required a string but on-disk files can drift).
        // Without this guard, the bare-empty-string would `!= oauth_email`, fall through
        // the comparison branch, and be inserted into `by_slot_label[N]` — polluting the
        // rename channel so `get_email` step 1 returns Some("") for the slot (blank UI label).
        // The empty entry will be removed by the immediately-following `prune_redundant_accounts_entries`
        // pass via its arm-1 (`email.trim().is_empty()` → removable).
        if accounts_email.is_empty() {
            report
                .outcomes
                .push(SlotRelocationOutcome::NoAccountEntry { slot });
            continue;
        }

        if accounts_email == oauth_email {
            // accounts[N].email IS the OAuth email — not a user rename.
            report.slots_skipped_oauth_email += 1;
            report
                .outcomes
                .push(SlotRelocationOutcome::SkippedOauthEmail { slot });
            continue;
        }

        // accounts[N].email differs from OAuth email → it's a user rename label.
        // Copy to by_slot_label[N] unless the user has already set a label
        // there (preserve later renames over earlier ones).
        if !pf.by_slot_label.contains_key(key) {
            pf.by_slot_label.insert(key.clone(), accounts_email.clone());
            dirty = true;
        }
        report.slots_relocated += 1;
        report.outcomes.push(SlotRelocationOutcome::Relocated {
            slot,
            label: accounts_email,
        });
    }

    if dirty {
        save(&path, &pf)?;
    }

    // ── Second pass: detect unrecoverable labels ──────────────────────────────
    //
    // Iterate `accounts` entries that are NOT covered by `by_slot_keys` (i.e.
    // the slot was never UUID-minted by Pass-0). For each such slot that has a
    // non-empty `email` value, we cannot determine whether the email is a user
    // rename label or the bare OAuth email — but we CAN determine that NO
    // relocation is possible because there is no `by_slot[N]` anchor.
    //
    // We surface these as `UnrecoverableNoBySlot` outcomes so `csq doctor` can
    // warn the operator by name rather than silently drop the label when RN1-F
    // removes the `accounts` field.
    //
    // This pass is read-only — no `dirty` flip, no `save` call.
    // M4-13: read legacy accounts from extra rather than struct field.
    let legacy_accounts_full = legacy_accounts_email_map(&pf);
    let by_slot_key_set: std::collections::HashSet<&String> = by_slot_keys.iter().collect();
    for (key, email) in &legacy_accounts_full {
        if by_slot_key_set.contains(key) {
            // Covered by the first pass — not unrecoverable.
            continue;
        }
        if email.is_empty() {
            continue;
        }
        let Ok(slot) = key.parse::<u16>() else {
            continue; // malformed key — skip
        };
        report.slots_unrecoverable_no_by_slot += 1;
        report
            .outcomes
            .push(SlotRelocationOutcome::UnrecoverableNoBySlot {
                slot,
                accounts_email: email.clone(),
            });
    }

    Ok(report)
}

/// Report returned by [`prune_redundant_accounts_entries`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccountsPruneReport {
    /// `accounts[N]` entries removed because their information is fully
    /// recoverable from another channel (see fn docs for the predicate).
    pub pruned: usize,
    /// Entries deliberately kept because removal would change
    /// `get_email(N)` — the genuinely-unrecoverable set (no `by_slot`,
    /// non-empty label, no `by_slot_label`). These correctly keep the
    /// WINDOW-CLOSE P1 gate OPEN until the user re-logs in (RN1-D R2
    /// `mint_for_login` captures them then).
    pub kept_unrecoverable: usize,
    /// `accounts[N]` entries removed specifically via arm-4
    /// (by_slot_identity match). Subset of `pruned` — every arm-4
    /// hit also increments `pruned`. Reported separately so the
    /// daemon's structured log can attribute prunes to channels.
    pub pruned_by_identity_channel: usize,
}

/// RN1-D R3: idempotent reconciler pass that empties `profiles.json::accounts`
/// of every entry whose removal is **information-preserving**, bringing
/// already-populated maps to the same `accounts: {}` target shape M4-9 made
/// new writes produce. This closes the WINDOW-CLOSE P1 gate gap: before this
/// pass, nothing pre-RN1-F emptied existing entries, so
/// `detect_v1_accounts_field` (`accounts.len() > 0`) could never clear on an
/// upgraded host and RN1-F was structurally unreachable.
///
/// # Removal predicate (per entry `N`)
///
/// `get_email(N)` resolution order is `by_slot_label[N]` → `accounts[N].email`
/// → `by_slot[N]→UUID→by_email`. Removing `accounts[N]` is information-
/// preserving — `get_email(N)` is unchanged — iff ANY of:
///
/// 1. `accounts[N].email` is empty (nothing to lose); OR
/// 2. `by_slot_label[N]` is present (step 1 wins regardless of step 2 —
///    a genuine rename already relocated by [`relocate_labels_to_by_slot_label`]
///    or captured by `mint_for_login`); OR
/// 3. `by_slot[N]` resolves a UUID whose credential file's
///    `oauthAccount.emailAddress` equals `accounts[N].email` (the entry is
///    the bare OAuth email — step 3 yields the identical value).
///
/// Otherwise the entry is a genuine user rename label with NO recovery
/// channel (`UnrecoverableNoBySlot`): it is **kept**. Keeping it correctly
/// holds WINDOW-CLOSE P1 OPEN — there is real un-relocated data; the gate is
/// doing its job, not gapped.
///
/// # Idempotency
///
/// Pure function of on-disk state. A second run is a no-op (every removable
/// entry is already gone; the kept set is stable). NOT sentinel-gated — it
/// runs every reconcile so a host that later resolves an unrecoverable entry
/// (via `csq login N`) gets it pruned on the next daemon start.
///
/// # Lock precondition
///
/// Caller MUST hold the exclusive [`ProfilesFileLock`]; `_lock` is the
/// compile-time type-witness (same pattern as the relocation pass). MUST run
/// AFTER [`relocate_labels_to_by_slot_label`] so genuine renames are already
/// in `by_slot_label` before the predicate evaluates removability.
pub fn prune_redundant_accounts_entries(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
) -> Result<AccountsPruneReport, ConfigError> {
    let path = profiles_path(base_dir);
    let mut pf = load(&path)?;
    let mut report = AccountsPruneReport::default();

    // M4-13: accounts field removed from struct; legacy content is in
    // extra["accounts"] as a serde_json::Value. Parse once up front.
    let legacy_accounts = legacy_accounts_email_map(&pf);
    let keys: Vec<String> = legacy_accounts.keys().cloned().collect();

    // If there are no legacy entries in extra, nothing to do.
    if keys.is_empty() {
        return Ok(report);
    }

    let mut removable: Vec<String> = Vec::new();

    for key in &keys {
        let email = match legacy_accounts.get(key) {
            Some(e) => e.clone(),
            None => continue,
        };

        // CORRECTNESS INVARIANT (closes the relocation→prune two-lock
        // concern): every arm below is evaluated against `pf`, the snapshot
        // this function loaded UNDER ITS OWN `_lock`. Safety is a property of
        // THIS snapshot, never of the earlier relocation pass's state — so an
        // external writer acting in the gap between relocation's lock-release
        // and this pass's lock-acquire cannot induce a false-prune: whatever
        // it wrote is either visible here (and re-judged by the live arms) or
        // not yet committed (and untouched). The predicate is "removing
        // accounts[N] from extra leaves `get_email(N)` unchanged".

        // (1) empty email — nothing to lose.
        if email.trim().is_empty() {
            removable.push(key.clone());
            continue;
        }
        // (2) by_slot_label[N] present — `get_email` step 1 returns it
        //     UNCONDITIONALLY, so the legacy accounts value is already dead
        //     code for this slot. Pruning it is information-preserving.
        if pf.by_slot_label.contains_key(key) {
            removable.push(key.clone());
            continue;
        }
        // (4) by_slot_identity[N] equals accounts[N].email — the M4-9
        //     identity channel mirrors what `get_email` step 1.5 would
        //     return after this entry is removed. Information-preserving
        //     by the same proof as arm 3. Divergent labels are KEPT so
        //     schema drift is visible to `csq doctor`.
        if let Some(identity) = pf.by_slot_identity.get(key) {
            if identity == &email {
                removable.push(key.clone());
                report.pruned_by_identity_channel += 1;
                continue;
            }
        }
        // (3) bare OAuth email — equals what `get_email` step 2 (now step 2,
        //     the by_email fallback) would return. Mirror get_email step 2
        //     verbatim: by_slot[N] → uuid → reverse-search by_email.
        if let Some(uuid) = pf.by_slot.get(key).copied() {
            let step2 = pf
                .by_email
                .iter()
                .find_map(|(e, u)| (*u == uuid).then_some(e.as_str()));
            if step2 == Some(email.as_str()) {
                removable.push(key.clone());
                continue;
            }
        }
        // Otherwise: genuine rename, no recovery channel — KEEP.
        report.kept_unrecoverable += 1;
    }

    if !removable.is_empty() {
        // Mutate extra["accounts"] in-place: remove the pruned keys from the
        // JSON object. If all keys are pruned, remove the "accounts" key from
        // extra entirely so future loads see a clean file.
        let all_pruned = removable.len() == keys.len();
        if all_pruned {
            pf.extra.remove("accounts");
        } else if let Some(accounts_val) = pf.extra.get_mut("accounts") {
            if let Some(obj) = accounts_val.as_object_mut() {
                for key in &removable {
                    obj.remove(key.as_str());
                }
            }
        }
        report.pruned = removable.len();
        save(&path, &pf)?;
    }

    Ok(report)
}

/// Extracts the legacy v1 `accounts` map from `pf.extra["accounts"]`.
///
/// On-disk files written before M4-13 carry `accounts: {"N": {email, method}}`.
/// After M4-13 the struct field is removed; the key is absorbed into `extra`
/// on deserialization. This helper parses that `extra` entry into a
/// `HashMap<String, String>` of slot_key → email, suitable for the
/// relocation and prune passes. Returns an empty map when the key is absent
/// or unparseable (e.g. on fresh installs or already-pruned hosts).
pub fn legacy_accounts_email_map(pf: &ProfilesFile) -> HashMap<String, String> {
    let Some(accounts_val) = pf.extra.get("accounts") else {
        return HashMap::new();
    };
    let Some(obj) = accounts_val.as_object() else {
        return HashMap::new();
    };
    obj.iter()
        .map(|(k, v)| {
            let email = v
                .get("email")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            (k.clone(), email)
        })
        .collect()
}

/// Path of the one-shot label-relocation sentinel file in the accounts base dir.
///
/// When this file exists, the label-relocation pass (RN1-D5b) has already
/// run and will not run again on subsequent daemon starts.
pub fn label_relocation_sentinel_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("label-channel-migrated")
}

/// One slot whose rename label cannot be migrated to the A1 channel because
/// the slot was never UUID-minted (no `by_slot[N]` entry in `profiles.json`).
///
/// Returned by [`unrecoverable_label_slots`] for surfacing in `csq doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecoverableSlot {
    /// Slot number (e.g. `3`).
    pub slot: u16,
    /// The value in `accounts[N].email` — a user-chosen rename label that
    /// cannot be distinguished from a bare OAuth email without a UUID anchor.
    pub accounts_email: String,
}

/// Read-only diagnostic: list slots whose `accounts[N].email` entry will be
/// silently dropped when RN1-F removes the `accounts` field, because the slot
/// has no `by_slot[N]` UUID and therefore cannot have its label relocated.
///
/// Returns an empty `Vec` when `profiles.json` is absent or unparseable —
/// diagnostic non-fatal fallback (doctor must emit a report even when
/// individual checks fail).
///
/// This function is **read-only** — it does not write `profiles.json` or any
/// sentinel file. It is safe to call from `csq doctor` without holding any lock.
///
/// # When to call
///
/// `csq doctor` calls this ONLY when the `label-channel-migrated` sentinel
/// exists — before the sentinel, users are pre-migration and the warning would
/// be noise (no relocation pass has run yet). After the sentinel, unprovisioned
/// slots that still have `accounts[N].email` entries are the ones whose labels
/// will be lost when the `accounts` field is removed in RN1-F.
pub fn unrecoverable_label_slots(base_dir: &Path) -> Vec<UnrecoverableSlot> {
    let path = profiles_path(base_dir);
    let pf = match load(&path) {
        Ok(pf) => pf,
        Err(_) => return Vec::new(),
    };

    // M4-13: accounts field removed from struct; read from extra["accounts"].
    let legacy_accounts = legacy_accounts_email_map(&pf);

    // Build the set of slot keys that have a `by_slot` UUID entry.
    let provisioned_keys: std::collections::HashSet<&String> = pf.by_slot.keys().collect();

    let mut result: Vec<UnrecoverableSlot> = legacy_accounts
        .iter()
        .filter(|(key, email)| {
            // Only flag slots that:
            // 1. Are NOT in by_slot (no UUID minted)
            // 2. Have a non-empty email (there is something to lose)
            !provisioned_keys.contains(key) && !email.is_empty()
        })
        .filter_map(|(key, email)| {
            let slot: u16 = key.parse().ok()?;
            Some(UnrecoverableSlot {
                slot,
                accounts_email: email.clone(),
            })
        })
        .collect();

    // Sort by slot number so the output is deterministic.
    result.sort_by_key(|s| s.slot);
    result
}

// ─── Coexistence audit types ─────────────────────────────────────────────────

/// Describes the operational state of the A++ identity store relative to the
/// legacy `config-N/` layout (M1-8 diagnostic surface, schema_version 3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CoexistenceState {
    /// Only `config-N/` directories exist; no `identities/` dirs and no
    /// `store-version` sentinel. This is the pre-Phase-1 shape or a fresh
    /// install where the daemon has not yet run its Pass 0 mint.
    LegacyOnly,
    /// Both `config-N/` dirs AND `identities/<UUID>/` dirs exist with
    /// the `store-version` sentinel present. Normal post-Pass-0 shape.
    Coexisting,
    /// Only `identities/<UUID>/` dirs exist; no `config-N/` dirs and the
    /// sentinel is present. This is the post-Phase-4 shape; not expected
    /// in Phase 1.
    IdentityOnly,
}

/// Describes the consistency between the `profiles.json` A++ maps and the
/// on-disk `config-N/` + `identities/<UUID>/` directory layout.
/// A single account-store consistency issue. `audit_coexistence` returns a
/// `Vec<ConsistencyState>` — an empty vec is the consistent signal (there is
/// deliberately no `Consistent` variant: `[Consistent]` would be incoherent
/// and a single-issue field re-creates the unmask treadmill this list shape
/// exists to end). See `workspaces/doctor-consistency-audit/journal/0001`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum ConsistencyState {
    /// `profiles.json::by_slot` is non-empty while the layout is `LegacyOnly`
    /// (no `store-version` sentinel, no `identities/<UUID>/` dirs) — a
    /// half-written state. Only emitted from the `LegacyOnly` branch.
    SlotCountMismatch { legacy: usize, identity: usize },
    /// An `identities/<UUID>/` directory exists whose UUID is NOT in
    /// `profiles.json::by_slot` — i.e. the identity has no live slot binding.
    /// `by_email` is deliberately NOT consulted: it is a lookup index that is
    /// not pruned in lockstep with `by_slot`, so a stale `by_email` entry
    /// would mask a genuine orphan (round-1 redteam HIGH-1). Returns the
    /// FIRST such UUID found (diagnostic, not exhaustive; Phase 4 GC owns
    /// bulk removal).
    OrphanIdentity {
        uuid: crate::accounts::identity_store::IdentityId,
    },
    /// A `config-N/` directory exists whose slot number is NOT in
    /// `profiles.json::by_slot`.  Returns the FIRST such slot found.
    OrphanLegacySlot { slot: u16 },
    /// An identity exists in `profiles.json::by_slot` but its UUID-keyed
    /// `identities/<UUID>/credentials.json` is absent.
    ///
    /// Added in M2-6 scaffold (Wave 1); detection fires after M2-2 ships so
    /// the file can actually exist.  Returns the FIRST affected UUID found.
    MissingCredentialsAtUuidPath {
        uuid: crate::accounts::identity_store::IdentityId,
    },
    /// An identity exists in `profiles.json::by_slot` but its UUID-keyed
    /// `identities/<UUID>/settings.json` is absent.
    ///
    /// Added in M2-6 scaffold (Wave 1); detection fires after M2-3 ships.
    /// Returns the FIRST affected UUID found.
    MissingSettingsAtUuidPath {
        uuid: crate::accounts::identity_store::IdentityId,
    },
    /// `config-N/.current-account` holds a slot id ≠ N (and ≠ absent) — a
    /// stale fast-path cache. Under the handle-dir model `config-N` is slot
    /// N's permanent canonical dir, so its `.current-account` MUST be N or
    /// absent. A foreign value (a pre-handle-dir-migration leftover, or a
    /// value left by a binder that did not refresh the cache) makes
    /// `csq swap N` surface `cached` in the statusline instead of N.
    /// `snapshot_account` self-heals this lazily; this surfaces it for
    /// `csq repair`. Returns the FIRST drifted slot found. (Workspace
    /// slot-attribution-consistency, M5/H3.)
    CurrentAccountDrift { slot: u16, cached: u16 },
    // NOTE: a `DualMapSlot` variant (slot present in both `by_slot` and
    // `by_slot_identity`) was prototyped and REMOVED (2026-06-01). That is the
    // NORMAL representation of a codex slot — codex login mints both — not an
    // inconsistency. See memory `discovery_by_slot_holds_codex_identities`.
}

/// Diagnostic report about the A++ identity-store coexistence shape for a
/// given accounts base directory.  Produced by [`audit_coexistence`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentityStoreReport {
    /// Which of the three layout states the directory is currently in.
    pub state: CoexistenceState,
    /// `schema_version` parsed from `store-version`; `0` when the sentinel is
    /// absent (i.e. state is `LegacyOnly`).
    pub store_version: u32,
    /// Number of `identities/<UUID>/` directories found.
    pub identity_count: usize,
    /// Number of `config-N/` directories found.
    pub profile_slot_count: usize,
    /// Detected consistency issues between `profiles.json` and the on-disk
    /// layout — one entry per issue KIND (the first instance of each kind;
    /// `audit_coexistence` uses `find`, not collect-all, to keep the list
    /// bounded). An EMPTY vec means consistent. Because every kind is
    /// surfaced together, fixing one stale predicate can no longer hide a
    /// different one — the cross-predicate "unmask treadmill" is closed. (A
    /// second instance of the SAME kind still surfaces only after the first
    /// is resolved; that is an accepted, bounded trade-off.)
    pub consistency: Vec<ConsistencyState>,
}

/// Checks whether a named file inside an identity directory exists and is a
/// **regular file** (not a symlink).
///
/// This is the single SEC-2.6 chokepoint for all UUID-keyed identity file
/// existence checks in `audit_coexistence`.  Using `symlink_metadata` instead
/// of `metadata` ensures a dangling or escaping symlink is treated as absent.
///
/// Returns `true` only when the path resolves to a regular (non-symlink) file.
fn identity_file_exists(
    base: &Path,
    uuid: crate::accounts::identity_store::IdentityId,
    filename: &str,
) -> bool {
    use crate::accounts::identity_store::identity_path;
    let file_path = identity_path(base, uuid).join(filename);
    // symlink_metadata does NOT follow symlinks — a symlink (even a valid one)
    // is not a regular file and returns false here.
    match std::fs::symlink_metadata(&file_path) {
        Ok(meta) => meta.file_type().is_file(),
        Err(_) => false,
    }
}

/// Audits the A++ identity-store coexistence shape in `base_dir`.
///
/// Reads:
/// - `profiles.json` — for `by_slot` and `by_email` maps.
/// - `identities/<UUID>/` directories — for identity count.
/// - `store-version` sentinel — for schema version.
/// - `config-N/` directories — for legacy slot count.
///
/// All reads are performed under a [`ProfilesFileLock`] because this is a
/// multi-file consistency check: holding the lock prevents a concurrent
/// `add_identity_mapping` call from updating `profiles.json` between reading
/// it and reading the `identities/` directory, which would create a spurious
/// `OrphanIdentity` false-positive.
///
/// Returns `Err` only when the `profiles.json` read-lock cannot be acquired
/// (rare, indicative of a broken file system).  Missing files (e.g. absent
/// `store-version` or absent `identities/` dir) are treated as the legitimate
/// `LegacyOnly` state, not as errors.
/// Returns `true` when slot `n` is **recovery-backed** by ANY identity
/// channel — i.e. it is a MODERN, identity-store-known account, NOT a
/// pre-identity-store ("pure-legacy") footprint. A slot is recovery-backed
/// when ANY of the following holds:
///
///   (a) `pf.by_slot[n]`          — OAuth UUID map (Anthropic).
///   (b) `pf.by_slot_identity[n]` — 3P API-key / Codex / Gemini recovery
///       label (post-backfill or post-synchronous-write).
///   (c) a **regular-file** `credentials/gemini-<n>.json` binding marker —
///       closes the narrow Gemini window between a provision whose
///       synchronous identity write failed and the next daemon backfill
///       that re-derives `by_slot_identity[n]` (FM-8). Symlinks are
///       rejected (via `symlink_metadata().is_file()`) to match
///       `discover_gemini`'s hardened walk, which never derives
///       `by_slot_identity` for a symlinked marker — treating a symlink as
///       "bound" would suppress an orphan flag for a slot the backfill will
///       never identity-back.
///
/// This is the single authoritative "is this slot modern?" predicate.
/// `audit_coexistence`'s `OrphanLegacySlot` check, `csq doctor`'s
/// `detect_decimal_marker`, and the `legacy_count` terminal heuristic all
/// call it so their keep-sets cannot drift apart (per
/// `reconciler-cleanup-parity.md` Rule 4: enumerate the producer's real
/// channels; the reachable set is the UNION of every channel).
///
/// A slot failing all three is a genuine orphan / pre-migration footprint
/// (e.g. `config-N/` with credentials but no map entry and no marker).
pub fn is_slot_recovery_backed(base_dir: &Path, pf: &ProfilesFile, n: u16) -> bool {
    let key = n.to_string();
    if pf.by_slot.contains_key(&key) || pf.by_slot_identity.contains_key(&key) {
        return true;
    }
    std::fs::symlink_metadata(
        base_dir
            .join("credentials")
            .join(format!("gemini-{n}.json")),
    )
    .map(|m| m.file_type().is_file())
    .unwrap_or(false)
}

pub fn audit_coexistence(base: &Path) -> Result<IdentityStoreReport, crate::error::ConfigError> {
    use crate::accounts::identity_store::IdentityId;
    use std::collections::HashSet;
    use std::str::FromStr;

    // Acquire the profiles lock for a consistent multi-file snapshot.
    let _lock = ProfilesFileLock::acquire(base)?;

    // ── Load profiles.json ───────────────────────────────────────────────────
    let pf = load(&profiles_path(base))?;
    let by_slot_count = pf.by_slot.len();
    // The OrphanIdentity check flags an `identities/<UUID>/` dir whose UUID
    // has no LIVE slot binding. `by_slot` is the live-binding map; `by_email`
    // is only a lookup index and is NOT pruned in lockstep with `by_slot` (a
    // logout can clear `by_slot[N]` yet leave a `by_email[email] → UUID`
    // entry behind). Unioning `by_email` into this set would let a stale
    // index entry MASK a genuine orphan — so the referenced-set is `by_slot`
    // ONLY. (Round-1 redteam HIGH-1: the `OrphanIdentity` variant doc
    // previously read "by_slot or by_email" — the doc was wrong, the
    // by_slot-only code was right; the doc is corrected to match.)
    let by_uuid_set: HashSet<IdentityId> = pf.by_slot.values().copied().collect();

    // ── Count config-N/ dirs ─────────────────────────────────────────────────
    let mut config_slots: Vec<u16> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(base) {
        for entry in rd.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if let Some(rest) = name.strip_prefix("config-") {
                if let Ok(n) = rest.parse::<u16>() {
                    if n >= 1 {
                        config_slots.push(n);
                    }
                }
            }
        }
    }
    let config_slot_count = config_slots.len();

    // ── Count identities/<UUID>/ dirs ────────────────────────────────────────
    let identities_dir = base.join("identities");
    let mut identity_uuids: Vec<IdentityId> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&identities_dir) {
        for entry in rd.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if let Ok(id) = IdentityId::from_str(&name) {
                // Only count directories
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    identity_uuids.push(id);
                }
            }
        }
    }
    let identity_count = identity_uuids.len();

    // ── Read store-version sentinel ──────────────────────────────────────────
    let sv_path = crate::accounts::identity_store::store_version_path(base);
    let store_version: u32 = if sv_path.exists() {
        std::fs::read_to_string(&sv_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("schema").and_then(|n| n.as_u64()))
            .map(|n| n as u32)
            .unwrap_or(1)
    } else {
        0
    };

    let sentinel_present = sv_path.exists();

    // ── Classify CoexistenceState ────────────────────────────────────────────
    let state = if config_slot_count > 0 && identity_count > 0 && sentinel_present {
        CoexistenceState::Coexisting
    } else if config_slot_count == 0 && identity_count > 0 && sentinel_present {
        CoexistenceState::IdentityOnly
    } else {
        // LegacyOnly — either no identities, or sentinel absent (fresh install /
        // daemon not yet run Pass 0)
        CoexistenceState::LegacyOnly
    };

    // ── Classify ConsistencyState ────────────────────────────────────────────
    //
    // Collect one entry per detected issue KIND into a Vec rather than
    // returning on the first — `csq doctor` surfaces every kind at once, so
    // fixing one stale predicate can no longer hide a different one (the
    // cross-predicate "unmask treadmill" — doctor-consistency-audit journal
    // 0001). Each check still uses `find` (first instance of its kind) to
    // keep the list bounded; an empty Vec means consistent.
    let mut consistency: Vec<ConsistencyState> = match &state {
        CoexistenceState::LegacyOnly => {
            // In LegacyOnly state, by_slot MUST be empty — Pass-0 identity
            // mint writes by_slot, the identity dirs, AND the store-version
            // sentinel together. A populated by_slot with no sentinel / no
            // identity dirs is a half-written state.
            if by_slot_count == 0 {
                Vec::new()
            } else {
                vec![ConsistencyState::SlotCountMismatch {
                    legacy: config_slot_count,
                    identity: by_slot_count,
                }]
            }
        }
        CoexistenceState::Coexisting | CoexistenceState::IdentityOnly => {
            let mut issues: Vec<ConsistencyState> = Vec::new();

            // Issue — orphan identity dir (UUID in identities/ but not in
            // by_slot or by_email). One-per-kind: the first orphan found.
            if let Some(uuid) = identity_uuids
                .iter()
                .copied()
                .find(|id| !by_uuid_set.contains(id))
            {
                issues.push(ConsistencyState::OrphanIdentity { uuid });
            }

            // Issue — orphan legacy slot (config-N/ but no recovery
            // channel). FM-1 (journal 0001 D4): the original predicate
            // tested ONLY `by_slot` (the OAuth UUID map), so every
            // non-OAuth slot (3P API-key, Codex, Gemini) was a false
            // `OrphanLegacySlot` candidate even after PR #500 shipped the
            // `by_slot_identity` recovery channel — a pre-existing PR #500
            // defect (verified on the maintainer host: slots 9/11/12/14
            // carry `by_slot_identity` yet were orphan-flagged). A slot is
            // recovery-backed (NOT an orphan) when ANY holds:
            //   (a) `by_slot[N]`            — OAuth UUID (original).
            //   (b) `by_slot_identity[N]`   — 3P/Codex/Gemini recovery
            //       label (post-backfill / post-synchronous-write).
            //   (c) a `credentials/gemini-<N>.json` binding marker —
            //       closes the narrow Gemini window between a provision
            //       whose synchronous identity write failed and the next
            //       daemon backfill that re-derives it (FM-8). 3P/Codex
            //       have no such window: M7/M8 write `by_slot_identity`
            //       synchronously in the same lock as the bind, so (b)
            //       fully covers them. A genuine orphan (no by_slot, no
            //       by_slot_identity, no binding — e.g. slot 10) stays
            //       correctly flagged → owned by slot-10-orphan-investigation.
            // A slot is an orphan when it is NOT recovery-backed by any
            // identity channel. The three-way predicate (by_slot ∪
            // by_slot_identity ∪ regular-file gemini-<N>.json marker) lives
            // in `is_slot_recovery_backed` so this audit, `csq doctor`'s
            // `detect_decimal_marker`, and the `legacy_count` terminal
            // heuristic share ONE keep-set (reconciler-cleanup-parity Rule
            // 4 — channels cannot drift apart across consumers).
            let orphan_slot = config_slots
                .iter()
                .copied()
                .find(|&n| !is_slot_recovery_backed(base, &pf, n));

            if let Some(slot) = orphan_slot {
                issues.push(ConsistencyState::OrphanLegacySlot { slot });
            }

            // ── Phase 2 UUID-path checks ────────────────────────────────────
            //
            // These iterate over `by_slot` mappings (not the identity_uuids
            // collected from disk) so only *mapped* identities are checked —
            // orphan dirs are handled by the OrphanIdentity check above.

            // Issue — missing UUID-keyed credentials.json.
            // Codex-only-aware: skip slots that are codex-only. These slots
            // have no Anthropic OAuth and legitimately lack `credentials.json`
            // at the identity path (their creds live at `credentials-codex.json`);
            // surfacing `MissingCredentialsAtUuidPath` for them is a false alarm.
            // Detection is identity-store-aware (per account-terminal-separation.md
            // MUST Rule 4): `identity.json` provider=codex is the canonical
            // post-A++ signal, with the legacy `credentials/codex-<N>.json`
            // marker as a pre-A++ fallback — a post-A++ slot whose legacy mirror
            // was retired (host slot 8) has no marker but is still codex-only.
            // Parity with `phase4_gate_check`'s Check-3 binding guard and
            // `discover_anthropic`'s codex-skip.
            if let Some(uuid) = pf.by_slot.iter().find_map(|(slot_str, &uuid)| {
                let is_codex_only = match slot_str.parse::<u16>() {
                    Ok(n) => identity_store::is_codex_only_slot(base, n, uuid),
                    Err(_) => false,
                };
                if is_codex_only {
                    return None;
                }
                if identity_file_exists(base, uuid, "credentials.json") {
                    None
                } else {
                    Some(uuid)
                }
            }) {
                issues.push(ConsistencyState::MissingCredentialsAtUuidPath { uuid });
            }

            // Issue — missing UUID-keyed settings.json.
            // Codex-only-aware, mirroring the MissingCredentials skip above:
            // a Codex slot's `settings.json` pairing is non-fatal — the codex
            // login path logs a WARN and proceeds if `save_uuid_settings`
            // fails (providers/codex/login.rs) — so its absence MUST NOT trip
            // a persistent doctor INCONSISTENT verdict. Without this skip the
            // sibling check re-introduces the exact false-INCONSISTENT class
            // the MissingCredentials skip closed, one credential file over.
            if let Some(uuid) = pf.by_slot.iter().find_map(|(slot_str, &uuid)| {
                let is_codex_only = match slot_str.parse::<u16>() {
                    Ok(n) => identity_store::is_codex_only_slot(base, n, uuid),
                    Err(_) => false,
                };
                if is_codex_only {
                    return None;
                }
                if identity_file_exists(base, uuid, "settings.json") {
                    None
                } else {
                    Some(uuid)
                }
            }) {
                issues.push(ConsistencyState::MissingSettingsAtUuidPath { uuid });
            }

            // The former count-based `SlotCountMismatch` check here (comparing
            // `config_slot_count` vs `by_slot_count` vs `identity_count`) is
            // removed: `config_slot_count` counts non-OAuth `config-N/` dirs
            // too, so it tripped on every multi-slot host, AND both its
            // comparisons are fully redundant with the per-slot
            // OrphanIdentity / OrphanLegacySlot / Missing* checks above.
            // See workspaces/doctor-consistency-audit/01-analysis predicate 5.

            // (A `DualMapSlot` check — slot in both by_slot and by_slot_identity
            // — was prototyped and REMOVED: that is the NORMAL codex-slot shape,
            // not an inconsistency. See ConsistencyState's note + memory
            // discovery_by_slot_holds_codex_identities.)

            issues
        }
    };

    // Issue — CurrentAccountDrift: config-N/.current-account ≠ N. Detected for
    // ALL coexistence states (it depends only on config-N enumeration +
    // read_current_account, NOT on the identity store) — a LegacyOnly host
    // (pre-Pass-0, numeric markers) can drift exactly like a Coexisting one, so
    // restricting this to the Coexisting|IdentityOnly arm left `csq doctor`
    // blind while `csq repair` saw it (R1 deep-analyst HIGH-2). One-per-kind:
    // first drifted slot (the shared predicate returns them slot-ascending);
    // repair consumes the full list. Single keep-set, no consumer drift.
    if let Some(&(slot, cached)) = current_account_drifts(base).first() {
        consistency.push(ConsistencyState::CurrentAccountDrift { slot, cached });
    }

    Ok(IdentityStoreReport {
        state,
        store_version,
        identity_count,
        profile_slot_count: config_slot_count,
        consistency,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::identity_store::IdentityId;
    use crate::accounts::profiles_lock::ProfilesFileLock;
    use tempfile::TempDir;

    #[test]
    fn round_trip_profiles() {
        // M4-13: get_email no longer reads extra["accounts"]. This test now
        // verifies round-trip persistence of the extra["accounts"] data via
        // accounts_for_test(), and that get_email returns None for slots only in
        // the legacy accounts map (no by_slot/by_slot_label/by_slot_identity).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "user@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles.set_profile(
            8,
            AccountProfile {
                email: "other@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        save(&path, &profiles).unwrap();
        let loaded = load(&path).unwrap();

        // Legacy data round-trips through extra["accounts"].
        let accounts = loaded.accounts_for_test();
        assert_eq!(
            accounts.get("1").map(|p| p.email.as_str()),
            Some("user@example.com")
        );
        assert_eq!(
            accounts.get("8").map(|p| p.email.as_str()),
            Some("other@example.com")
        );
        // M4-13: get_email no longer consults extra["accounts"] — returns None.
        assert_eq!(
            loaded.get_email(1),
            None,
            "M4-13: get_email skips extra[accounts]"
        );
        assert_eq!(loaded.get_email(99), None);
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        let profiles = load(&path).unwrap();
        assert!(profiles.accounts_for_test().is_empty());
    }

    /// `ProfilesFile::empty()` initializes every map to an empty state.
    ///
    /// This test enumerates all fields so that adding a new map field without
    /// extending `empty()` causes a compile error (struct literal exhaustiveness)
    /// rather than a silent default-initialization miss.
    #[test]
    fn empty_returns_all_maps_initialized() {
        let pf = ProfilesFile::empty();
        assert!(
            pf.accounts_for_test().is_empty(),
            "accounts must be empty (via extra)"
        );
        assert!(pf.by_slot.is_empty(), "by_slot must be empty");
        assert!(pf.by_email.is_empty(), "by_email must be empty");
        assert!(pf.by_slot_label.is_empty(), "by_slot_label must be empty");
        assert!(
            pf.by_slot_identity.is_empty(),
            "by_slot_identity must be empty"
        );
        assert!(pf.extra.is_empty(), "extra must be empty");
    }

    /// Extends the original `flatten_preserves_unknown_fields` test with
    /// the v2.6.x↔v2.7.x round-trip regression:
    ///
    /// 1. Write merged v2.7.x shape (with `by_slot` + `by_email`).
    /// 2. Read via a shadow v2.6.x-equivalent struct (no `by_slot`/`by_email`
    ///    named fields — they fall into `extra`).
    /// 3. Re-save via the v2.6.x-equivalent struct.
    /// 4. Read back via the v2.7.x `ProfilesFile` — assert `by_slot` and
    ///    `by_email` survived via `extra` round-trip.
    ///
    /// This is the CRITICAL regression: getting the merge contract wrong
    /// cascades into Phases 2-4.
    #[test]
    fn flatten_preserves_unknown_fields_and_v2_keys() {
        // v2.6.x-equivalent reader: only knows about `accounts` + `extra`.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct ProfilesFileV26 {
            #[serde(default)]
            accounts: HashMap<String, serde_json::Value>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        // Step 1: Write the merged v2.7.x shape.
        let uuid1 = IdentityId::new_v4();
        let uuid2 = IdentityId::new_v4();

        let mut v27 = ProfilesFile::empty();
        v27.set_profile(
            1,
            AccountProfile {
                email: "alice@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        v27.by_slot.insert("1".into(), uuid1);
        v27.by_email.insert("alice@example.com".into(), uuid2);
        // Inject an extra top-level field that both versions should preserve.
        v27.extra.insert(
            "topLevelExtra".into(),
            serde_json::Value::String("preserved".into()),
        );
        save(&path, &v27).unwrap();

        // Step 2: Read as a v2.6.x-equivalent reader.
        let content = std::fs::read_to_string(&path).unwrap();
        let v26: ProfilesFileV26 = serde_json::from_str(&content).unwrap();

        // `by_slot` and `by_email` land in `extra` (not named fields).
        assert!(
            v26.extra.contains_key("by_slot"),
            "v2.6.x reader must capture by_slot in extra; extra keys: {:?}",
            v26.extra.keys().collect::<Vec<_>>()
        );
        assert!(
            v26.extra.contains_key("by_email"),
            "v2.6.x reader must capture by_email in extra"
        );
        assert_eq!(v26.extra["topLevelExtra"], "preserved");

        // Step 3: Re-save via the v2.6.x-equivalent struct.
        let re_saved = serde_json::to_string_pretty(&v26).unwrap();
        std::fs::write(&path, re_saved.as_bytes()).unwrap();

        // Step 4: Re-read via v2.7.x — assert UUIDs survived.
        let reloaded = load(&path).unwrap();
        assert_eq!(
            reloaded.by_slot.get("1").copied(),
            Some(uuid1),
            "by_slot must survive v2.7.x→v2.6.x→v2.7.x round-trip"
        );
        assert_eq!(
            reloaded.by_email.get("alice@example.com").copied(),
            Some(uuid2),
            "by_email must survive v2.7.x→v2.6.x→v2.7.x round-trip"
        );
        // The original `accounts` field must survive in extra (M4-13: get_email
        // no longer reads from extra["accounts"]; verify via accounts_for_test).
        assert_eq!(
            reloaded
                .accounts_for_test()
                .get("1")
                .map(|p| p.email.as_str()),
            Some("alice@example.com"),
            "extra[accounts][1].email must survive the downgrade round-trip"
        );
        // The non-A++ extra key must also survive.
        assert_eq!(
            reloaded.extra.get("topLevelExtra").and_then(|v| v.as_str()),
            Some("preserved")
        );
    }

    /// M4-13 regression: a pre-M4-13 on-disk file that has a top-level
    /// `accounts` key is loaded successfully — the key is absorbed into
    /// `ProfilesFile::extra` via `#[serde(flatten)]`.
    ///
    /// This is the backward-compat hatch. Pre-M4-13 writers emitted:
    /// ```json
    /// { "accounts": { "1": { "email": "alice@example.com", "method": "oauth" } } }
    /// ```
    /// Post-M4-13 readers must not fail, must not silently discard the data,
    /// and must expose it through `legacy_accounts_email_map`.
    #[test]
    fn profiles_load_tolerates_v1_accounts_field_via_flatten() {
        // Arrange — write a raw JSON file that looks like a pre-M4-13 profiles.json.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");
        let raw = serde_json::json!({
            "accounts": {
                "1": { "email": "alice@example.com", "method": "oauth" },
                "2": { "email": "bob@example.com",   "method": "oauth" }
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        // Act — load with the M4-13 ProfilesFile reader.
        let pf = load(&path).unwrap();

        // Assert — the accounts data survived via extra["accounts"].
        assert!(
            pf.extra.contains_key("accounts"),
            "pre-M4-13 accounts key must be absorbed into extra via flatten"
        );

        let email_map = legacy_accounts_email_map(&pf);
        assert_eq!(
            email_map.get("1").map(|s| s.as_str()),
            Some("alice@example.com"),
            "legacy_accounts_email_map must expose slot 1 email from extra"
        );
        assert_eq!(
            email_map.get("2").map(|s| s.as_str()),
            Some("bob@example.com"),
            "legacy_accounts_email_map must expose slot 2 email from extra"
        );

        // The new-style fields start empty — nothing was injected by the old file.
        assert!(
            pf.by_slot.is_empty(),
            "by_slot must be empty on a pre-M4-13 file"
        );
        assert!(
            pf.by_email.is_empty(),
            "by_email must be empty on a pre-M4-13 file"
        );
    }

    /// M4-13 /redteam R1 MED-1 regression: `relocate_labels_to_by_slot_label`
    /// MUST NOT insert an empty string into `by_slot_label[N]` when the
    /// pre-M4-13 `accounts[N]` entry has a missing or non-string `email` field.
    ///
    /// `legacy_accounts_email_map` returns "" for malformed entries (defensive
    /// parse — the v1 contract required a string but on-disk files can drift).
    /// Without the in-pass empty-string guard, the relocator would fall through
    /// the `accounts_email == oauth_email` check (empty != real OAuth email)
    /// and insert "" into `by_slot_label[N]`, polluting the rename channel so
    /// `get_email` step 1 returns `Some("")` for the slot (blank UI label).
    #[test]
    fn relocate_labels_skips_empty_email_accounts_entries() {
        // Arrange: slot 1 has a UUID + OAuth email "alice@example.com" in its
        // credential file, but the pre-M4-13 on-disk profiles.json contains a
        // malformed `accounts[1]` entry with NO `email` field. The defensive
        // `legacy_accounts_email_map` returns "" for such entries.
        //
        // Pre-fix: the relocator's `accounts_email != oauth_email` check passes
        // (empty != real email), so it inserts "" into by_slot_label[1] —
        // polluting the rename channel.
        //
        // Post-fix: the in-pass `if accounts_email.is_empty()` guard skips the
        // entry and emits a NoAccountEntry outcome.
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("alice@example.com".into(), uuid);
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Create the identity credential file so relocate can read oauth_email.
        let cred_path = identity_store::credentials_path_for(dir.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            br#"{"oauthAccount":{"emailAddress":"alice@example.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Inject a malformed `accounts[1]` payload into extra — no `email` key.
        // This simulates a pre-M4-13 on-disk file whose v1 contract was violated
        // (e.g. truncated write, hand-edit). `legacy_accounts_email_map` returns
        // ("1", "") for this shape; the in-pass guard MUST skip it.
        let path = profiles_path(dir.path());
        let mut profiles_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        profiles_json["accounts"] = serde_json::json!({
            "1": { "method": "oauth" }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&profiles_json).unwrap()).unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = relocate_labels_to_by_slot_label(&lock, dir.path()).unwrap();
        drop(lock);

        // Assert — the relocator did NOT pollute by_slot_label.
        let after = load(&path).unwrap();
        assert!(
            !after.by_slot_label.contains_key("1"),
            "empty-email accounts entry must NOT pollute by_slot_label \
             (slot 1 contains: {:?})",
            after.by_slot_label.get("1")
        );

        // Assert — the relocator reported slot 1 as NoAccountEntry (the empty-email
        // outcome path is the same as the missing-entry path: both unactionable).
        let has_no_entry = report
            .outcomes
            .iter()
            .any(|o| matches!(o, SlotRelocationOutcome::NoAccountEntry { slot } if *slot == 1));
        assert!(
            has_no_entry,
            "relocator must report slot 1 as NoAccountEntry when email is empty \
             (outcomes: {:?})",
            report.outcomes
        );

        // Assert — the relocator did NOT touch extra["accounts"]; the entry is still
        // present (per `rules/reconciler-cleanup-parity.md` Rule 2: the prune pass
        // owns deletion of legacy `accounts` entries — the relocator must NOT also
        // delete them, otherwise the pass-ordering contract is broken).
        // Tightens the test's invariant surface per /redteam R2 rust-specialist LOW-1.
        let entry_still_present = after
            .extra
            .get("accounts")
            .and_then(|a| a.get("1"))
            .is_some();
        assert!(
            entry_still_present,
            "relocator must NOT delete extra[accounts][1]; \
             prune_redundant_accounts_entries owns that deletion"
        );
    }

    /// M4-13 regression: when a pre-M4-13 `accounts` payload is absorbed via
    /// `extra`, a `save` + `load` round-trip preserves that payload intact.
    ///
    /// The flattened `accounts` key must survive a write → read cycle so that
    /// any reconciler pass that needs to read the legacy map still sees it after
    /// a daemon restart (which re-saves profiles.json).
    #[test]
    fn profiles_round_trip_preserves_v1_accounts_via_extra() {
        // Arrange — build a ProfilesFile that has both new-style A++ fields
        // and a legacy accounts payload in extra.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        // New-style A++ fields.
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("alice@example.com".into(), uuid);
        // Legacy accounts payload injected into extra (simulates a migrated host
        // that still has the old entry before prune_redundant_accounts_entries runs).
        pf.set_profile(
            1,
            AccountProfile {
                email: "alice@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // Act — save, then reload.
        save(&path, &pf).unwrap();
        let reloaded = load(&path).unwrap();

        // Assert — new-style fields survived.
        assert_eq!(
            reloaded.by_slot.get("1").copied(),
            Some(uuid),
            "by_slot must survive round-trip"
        );
        assert_eq!(
            reloaded.by_email.get("alice@example.com").copied(),
            Some(uuid),
            "by_email must survive round-trip"
        );

        // Legacy accounts entry survived via extra.
        let email_map = legacy_accounts_email_map(&reloaded);
        assert_eq!(
            email_map.get("1").map(|s| s.as_str()),
            Some("alice@example.com"),
            "extra[accounts][1].email must survive save+load round-trip"
        );
    }

    /// The merged shape (accounts + by_slot + by_email) survives a full
    /// `save` + `load` cycle with all three maps intact.
    #[test]
    fn round_trip_merged_shape_all_three_maps() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        let uuid = IdentityId::new_v4();
        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "test@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles.by_slot.insert("1".into(), uuid);
        profiles.by_email.insert("test@example.com".into(), uuid);

        save(&path, &profiles).unwrap();
        let loaded = load(&path).unwrap();

        // accounts preserved
        assert_eq!(loaded.get_email(1), Some("test@example.com"));
        // by_slot preserved
        assert_eq!(loaded.by_slot.get("1").copied(), Some(uuid));
        // by_email preserved
        assert_eq!(loaded.by_email.get("test@example.com").copied(), Some(uuid));
    }

    #[test]
    fn set_profile_preserves_others() {
        // M4-13: set_profile writes into extra["accounts"]; get_email no longer
        // reads from it. This test verifies the persistence via accounts_for_test.
        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "a@a.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles.set_profile(
            2,
            AccountProfile {
                email: "b@b.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // Update account 1, account 2 should be preserved
        profiles.set_profile(
            1,
            AccountProfile {
                email: "updated@a.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        let accounts = profiles.accounts_for_test();
        assert_eq!(
            accounts.get("1").map(|p| p.email.as_str()),
            Some("updated@a.com")
        );
        assert_eq!(accounts.get("2").map(|p| p.email.as_str()), Some("b@b.com"));
    }

    /// `resolve_slot_to_uuid` returns `Some(uuid)` iff `by_slot["N"]` is present.
    /// Returns `None` for absent slots — NO silent fallback.
    #[test]
    fn resolve_slot_to_uuid_present_and_absent() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();

        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("3".into(), uuid);
        save(&profiles_path(dir.path()), &profiles).unwrap();

        // Present slot returns the UUID.
        assert_eq!(resolve_slot_to_uuid(dir.path(), 3), Some(uuid));
        // Absent slot returns None — no silent default.
        assert_eq!(resolve_slot_to_uuid(dir.path(), 1), None);
        assert_eq!(resolve_slot_to_uuid(dir.path(), 99), None);
    }

    /// `resolve_uuid_to_slot` is the inverse of `resolve_slot_to_uuid`:
    /// `Some(slot)` iff some `by_slot["slot"] == uuid`, else `None`.
    #[test]
    fn resolve_uuid_to_slot_present_and_absent() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let other = IdentityId::new_v4();

        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("7".into(), uuid);
        save(&profiles_path(dir.path()), &profiles).unwrap();

        // Present UUID reverse-resolves to its slot.
        assert_eq!(
            resolve_uuid_to_slot(dir.path(), uuid),
            Some(crate::types::AccountNum::try_from(7u16).unwrap())
        );
        // A UUID not in by_slot → None (no silent fallback).
        assert_eq!(resolve_uuid_to_slot(dir.path(), other), None);
    }

    /// Missing profiles.json → None, never a panic or invented slot.
    #[test]
    fn resolve_uuid_to_slot_none_on_missing_profiles() {
        let dir = TempDir::new().unwrap();
        assert_eq!(resolve_uuid_to_slot(dir.path(), IdentityId::new_v4()), None);
    }

    /// Determinism: a UUID bound to multiple slots returns the LOWEST slot
    /// regardless of HashMap iteration order. (Anomalous input; the resolver
    /// must still be stable.)
    #[test]
    fn resolve_uuid_to_slot_returns_lowest_slot_on_duplicate() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();

        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("8".into(), uuid);
        profiles.by_slot.insert("2".into(), uuid);
        profiles.by_slot.insert("5".into(), uuid);
        save(&profiles_path(dir.path()), &profiles).unwrap();

        assert_eq!(
            resolve_uuid_to_slot(dir.path(), uuid),
            Some(crate::types::AccountNum::try_from(2u16).unwrap()),
            "lowest matching slot must win for stability"
        );
    }

    /// `resolve_email_to_uuid` returns `Some(uuid)` iff `by_email[email]` is present.
    #[test]
    fn resolve_email_to_uuid_present_and_absent() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();

        let mut profiles = ProfilesFile::empty();
        profiles.by_email.insert("alice@x.com".into(), uuid);
        save(&profiles_path(dir.path()), &profiles).unwrap();

        // Present email returns the UUID.
        assert_eq!(resolve_email_to_uuid(dir.path(), "alice@x.com"), Some(uuid));
        // Absent email returns None.
        assert_eq!(resolve_email_to_uuid(dir.path(), "bob@x.com"), None);
        assert_eq!(resolve_email_to_uuid(dir.path(), ""), None);
    }

    /// `add_identity_mapping` writes both by_slot and by_email, and the
    /// mapping survives a load round-trip. Also verifies that pre-existing
    /// `extra["accounts"]` entries are preserved (M4-13: via accounts_for_test).
    #[test]
    fn add_identity_mapping_persists_and_preserves_accounts() {
        let dir = TempDir::new().unwrap();

        // Pre-populate with an existing account profile.
        let mut initial = ProfilesFile::empty();
        initial.set_profile(
            2,
            AccountProfile {
                email: "bob@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &initial).unwrap();

        let uuid = IdentityId::new_v4();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        add_identity_mapping(&lock, dir.path(), 1, "alice@example.com", uuid).unwrap();

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot.get("1").copied(),
            Some(uuid),
            "by_slot[1] must be the minted UUID"
        );
        assert_eq!(
            loaded.by_email.get("alice@example.com").copied(),
            Some(uuid),
            "by_email[alice@example.com] must be the minted UUID"
        );
        // Pre-existing extra["accounts"] entry must survive (M4-13: get_email no longer
        // reads from this channel; verify via accounts_for_test).
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("2")
                .map(|p| p.email.as_str()),
            Some("bob@example.com"),
            "extra[accounts][2].email must survive add_identity_mapping round-trip"
        );
    }

    /// Property test: 1000 randomized merged-shape values round-trip
    /// byte-equivalently through `save` + `load`.
    ///
    /// Uses `serde_json::Value` comparison (canonical JSON-equivalent).
    #[test]
    fn property_1000_merged_shapes_round_trip() {
        let dir = TempDir::new().unwrap();

        for i in 0u16..1000 {
            let path = dir.path().join(format!("profiles_{i}.json"));

            let uuid_slot = IdentityId::new_v4();
            let uuid_email = IdentityId::new_v4();

            let mut profiles = ProfilesFile::empty();
            profiles.set_profile(
                i % 10 + 1,
                AccountProfile {
                    email: format!("user{i}@example.com"),
                    method: "oauth".into(),
                    extra: HashMap::new(),
                },
            );
            profiles
                .by_slot
                .insert(((i % 10) + 1).to_string(), uuid_slot);
            profiles
                .by_email
                .insert(format!("user{i}@example.com"), uuid_email);

            save(&path, &profiles).unwrap();
            let loaded = load(&path).unwrap();

            // Serialize both to serde_json::Value for canonical comparison.
            let original_val = serde_json::to_value(&profiles).unwrap();
            let loaded_val = serde_json::to_value(&loaded).unwrap();
            assert_eq!(
                original_val, loaded_val,
                "merged-shape round-trip failed at iteration {i}"
            );
        }
    }

    /// §5a regression (security.md MUST Rule 5a, journal 0065 B2,
    /// /redteam round 3 2026-05-09): when `save` fails after the tmp
    /// file would have been created (parent dir read-only → write
    /// fails), no `.tmp.` file must remain on disk.
    #[cfg(unix)]
    #[test]
    fn save_partial_failure_cleans_tmp_file() {
        // Arrange: write a valid profiles.json so the parent dir exists.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");
        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "user@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&path, &profiles).unwrap();

        // Act + Assert: read-only parent → write fails → no tmp leak.
        crate::platform::fs::assert_no_tmp_leak_on_readonly_parent(dir.path(), || {
            save(&path, &profiles)
        });
    }

    // ─── M1 round-trip test ──────────────────────────────────────────────────

    /// M1 regression: `by_slot_identity` survives a v2.7.x → v2.6.x → v2.7.x
    /// round-trip via the `#[serde(flatten)] extra` hatch.
    ///
    /// Steps:
    /// 1. Write a v2.7.x-shape `ProfilesFile` with `by_slot_identity` populated.
    /// 2. Read via a v2.6.x-equivalent struct (only knows `accounts` + `extra`).
    /// 3. Assert `extra` contains the `"by_slot_identity"` key.
    /// 4. Re-save via the v2.6.x struct; re-load via v2.7.x; assert the entry
    ///    survived.
    ///
    /// This mirrors `flatten_preserves_unknown_fields_and_v2_keys` (line 1328)
    /// for the new field.
    #[test]
    fn flatten_preserves_by_slot_identity_through_v2_6_downgrade() {
        // v2.6.x-equivalent reader: only knows about `accounts` + `extra`.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct ProfilesFileV26 {
            #[serde(default)]
            accounts: HashMap<String, serde_json::Value>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        // Step 1: Write the v2.7.x shape with by_slot_identity populated.
        let mut v27 = ProfilesFile::empty();
        v27.by_slot_identity.insert("9".into(), "apikey:mm".into());
        save(&path, &v27).unwrap();

        // Step 2: Read as a v2.6.x-equivalent reader.
        let content = std::fs::read_to_string(&path).unwrap();
        let v26: ProfilesFileV26 = serde_json::from_str(&content).unwrap();

        // Step 3: `by_slot_identity` must land in `extra` (not a named field).
        assert!(
            v26.extra.contains_key("by_slot_identity"),
            "v2.6.x reader must capture by_slot_identity in extra; extra keys: {:?}",
            v26.extra.keys().collect::<Vec<_>>()
        );

        // Step 4: Re-save via the v2.6.x-equivalent struct; re-load via v2.7.x.
        let re_saved = serde_json::to_string_pretty(&v26).unwrap();
        std::fs::write(&path, re_saved.as_bytes()).unwrap();

        let reloaded = load(&path).unwrap();
        assert_eq!(
            reloaded.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity must survive v2.7.x→v2.6.x→v2.7.x round-trip"
        );
    }

    // ─── M10 security regression test ─────────────────────────────────────────

    /// M10 regression: `save` returns `Err` when `secure_file` fails (fail-closed
    /// posture), AND leaves no `.tmp.` artifact on disk (§5a compliance).
    ///
    /// Uses the read-only parent directory technique: on Unix, making the parent
    /// directory read-only prevents both `write` AND any rename/chmod operations,
    /// which forces `secure_file` to fail on some platforms. However, since
    /// `write` fails first under a read-only parent, this test primarily validates
    /// the §5a no-tmp-leak guarantee end-to-end (covering both the `write` and
    /// `secure_file` failure paths structurally). The fail-closed `secure_file`
    /// change is additionally validated by the code inspection: the `.ok()` is
    /// gone and replaced with fail-closed propagation.
    ///
    /// The canonical §5a regression fixture is
    /// `crate::platform::fs::assert_no_tmp_leak_on_readonly_parent`.
    #[cfg(unix)]
    #[test]
    fn save_propagates_secure_file_failure() {
        // Arrange: write a valid profiles.json so the parent dir exists.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");
        let mut profiles = ProfilesFile::empty();
        profiles
            .by_slot_identity
            .insert("9".into(), "apikey:mm".into());
        save(&path, &profiles).unwrap();

        // Act + Assert: read-only parent → `save` returns Err, no tmp leak.
        crate::platform::fs::assert_no_tmp_leak_on_readonly_parent(dir.path(), || {
            save(&path, &profiles)
        });
    }

    // ─── RN1-D2 / D3 / D4 tests ──────────────────────────────────────────────

    /// D2: `set_slot_label` requires a `ProfilesFileLock` type-witness —
    /// this test confirms the function signature accepts `&ProfilesFileLock`
    /// and that the write persists through a save+load round-trip.
    ///
    /// The type-witness pattern is compile-time enforcement: the function
    /// cannot be called without holding the lock. This test proves both the
    /// calling convention and the persistence behaviour.
    #[test]
    fn set_slot_label_acquires_profiles_file_lock() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();

        // Act: type-witness `&lock` satisfies the compile-time precondition.
        set_slot_label(&lock, dir.path(), 3, "My Label").unwrap();

        // Assert: label persists through a fresh load.
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("3").map(|s| s.as_str()),
            Some("My Label"),
            "label must be persisted in by_slot_label[3]"
        );
        // Unrelated slots must not be affected.
        assert!(
            !loaded.by_slot_label.contains_key("1"),
            "by_slot_label[1] must remain absent"
        );
    }

    /// M4-13: `get_email` uses a 2-step resolution (by_slot_label FIRST,
    /// then by_slot → UUID → by_email). Step 2 (accounts[N].email) was REMOVED.
    ///
    /// When all channels have a value for slot 1, the `by_slot_label` value wins.
    #[test]
    fn get_email_resolves_by_slot_label_first_then_by_email() {
        // Arrange: populate all active channels for slot 1 with distinct values.
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        // Step 2 channel (by_slot → UUID → by_email): OAuth email.
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("oauth@example.com".into(), uuid);
        // Residual legacy entry in extra["accounts"] (no longer consulted).
        pf.set_profile(
            1,
            AccountProfile {
                email: "legacy@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        // Step 1 channel (by_slot_label): user rename label — should win.
        pf.by_slot_label
            .insert("1".into(), "Renamed Display".into());

        // Act
        let result = pf.get_email(1);

        // Assert: by_slot_label wins (step 1).
        assert_eq!(
            result,
            Some("Renamed Display"),
            "get_email must return by_slot_label value (step 1) when populated"
        );

        // M4-13: without by_slot_label, extra[accounts] is NOT consulted.
        // by_email wins via the by_slot → UUID → by_email chain (step 2).
        let mut pf2 = ProfilesFile::empty();
        pf2.by_slot.insert("1".into(), uuid);
        pf2.by_email.insert("oauth@example.com".into(), uuid);
        pf2.set_profile(
            1,
            AccountProfile {
                email: "legacy@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        assert_eq!(
            pf2.get_email(1),
            Some("oauth@example.com"),
            "M4-13: without by_slot_label, by_email wins — extra[accounts] NOT consulted"
        );

        // And: without any label channel, by_slot→by_email is the canonical step 2.
        let mut pf3 = ProfilesFile::empty();
        pf3.by_slot.insert("1".into(), uuid);
        pf3.by_email.insert("oauth@example.com".into(), uuid);
        assert_eq!(
            pf3.get_email(1),
            Some("oauth@example.com"),
            "by_slot→by_email must resolve when neither label channel is populated"
        );
    }

    /// D3: `update_email` now delegates to `set_slot_label`, writing to
    /// `by_slot_label` instead of `accounts[N].email`.
    ///
    /// After a call to `update_email`, the label MUST be in `by_slot_label`
    /// and `get_email` MUST return it (resolution order D3). The legacy
    /// `accounts[N].email` field MUST NOT be written.
    #[test]
    fn update_email_writes_to_by_slot_label_not_accounts() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let account_num = crate::types::AccountNum::try_from(2_u16).unwrap();

        // Act
        update_email(dir.path(), account_num, "New Label").unwrap();

        // Assert: by_slot_label has the label.
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("2").map(|s| s.as_str()),
            Some("New Label"),
            "update_email must write to by_slot_label[2]"
        );
        // The legacy accounts field must NOT have been written by update_email.
        assert!(
            !loaded.accounts_for_test().contains_key("2"),
            "update_email must NOT write to accounts[N] in RN1-D3"
        );
        // get_email must return the new label via by_slot_label resolution.
        assert_eq!(
            loaded.get_email(2),
            Some("New Label"),
            "get_email must resolve the new label from by_slot_label"
        );
    }

    /// D4: `swap_slot_mapping` swaps `by_slot_label` entries alongside
    /// `by_slot` entries when `csq move FROM TO` is executed.
    ///
    /// After a swap, the label that was associated with slot A must now be
    /// associated with slot B, and vice-versa.
    #[test]
    fn swap_slot_mapping_swaps_by_slot_label_on_move() {
        // Arrange: two slots with UUIDs and labels.
        let dir = TempDir::new().unwrap();
        let uuid_a = IdentityId::new_v4();
        let uuid_b = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("2".into(), uuid_a);
        pf.by_slot.insert("5".into(), uuid_b);
        pf.by_slot_label
            .insert("2".into(), "Label for slot 2".into());
        pf.by_slot_label
            .insert("5".into(), "Label for slot 5".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act: swap slots 2 and 5.
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let swapped = swap_slot_mapping(&lock, dir.path(), 2, 5).unwrap();

        // Assert: swap was performed.
        assert!(
            swapped,
            "swap_slot_mapping must return true when both slots have entries"
        );

        let loaded = load(&profiles_path(dir.path())).unwrap();
        // UUIDs must have swapped.
        assert_eq!(
            loaded.by_slot.get("2").copied(),
            Some(uuid_b),
            "by_slot[2] must now hold uuid_b after swap"
        );
        assert_eq!(
            loaded.by_slot.get("5").copied(),
            Some(uuid_a),
            "by_slot[5] must now hold uuid_a after swap"
        );
        // Labels must have swapped alongside the UUIDs.
        assert_eq!(
            loaded.by_slot_label.get("2").map(|s| s.as_str()),
            Some("Label for slot 5"),
            "by_slot_label[2] must now hold the label that was at slot 5"
        );
        assert_eq!(
            loaded.by_slot_label.get("5").map(|s| s.as_str()),
            Some("Label for slot 2"),
            "by_slot_label[5] must now hold the label that was at slot 2"
        );
    }

    /// D4 edge case: `swap_slot_mapping` handles slots where only ONE side has
    /// a label — the label follows its slot after the swap, and the other slot
    /// has no label.
    #[test]
    fn swap_slot_mapping_handles_asymmetric_labels() {
        // Arrange: slot 1 has a label, slot 3 does not.
        let dir = TempDir::new().unwrap();
        let uuid_1 = IdentityId::new_v4();
        let uuid_3 = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid_1);
        pf.by_slot.insert("3".into(), uuid_3);
        pf.by_slot_label
            .insert("1".into(), "Only slot 1 has a label".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        swap_slot_mapping(&lock, dir.path(), 1, 3).unwrap();

        // Assert: the label moved to slot 3; slot 1 now has no label.
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("3").map(|s| s.as_str()),
            Some("Only slot 1 has a label"),
            "label must follow its slot after swap"
        );
        assert!(
            !loaded.by_slot_label.contains_key("1"),
            "slot 1 must have no label after the swap (it had none before the swap at slot 3)"
        );
    }

    /// D2 round-trip: `by_slot_label` field survives a `save` + `load` cycle,
    /// including through the v2.6.x flatten-extra round-trip contract.
    ///
    /// A v2.6.x reader (no `by_slot_label` named field) captures it in `extra`
    /// and re-emits it verbatim on save; the v2.7.x reader restores it.
    #[test]
    fn by_slot_label_round_trips_v26x_via_flatten_extra() {
        // v2.6.x-equivalent reader (no by_slot_label field).
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct ProfilesFileV26 {
            #[serde(default)]
            accounts: HashMap<String, serde_json::Value>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        // Step 1: Write a v2.7.x+ file with by_slot_label populated.
        let mut pf = ProfilesFile::empty();
        pf.by_slot_label
            .insert("4".into(), "Renamed Account 4".into());
        save(&path, &pf).unwrap();

        // Step 2: Read as a v2.6.x-equivalent reader — by_slot_label lands in extra.
        let content = std::fs::read_to_string(&path).unwrap();
        let v26: ProfilesFileV26 = serde_json::from_str(&content).unwrap();
        assert!(
            v26.extra.contains_key("by_slot_label"),
            "v2.6.x reader must capture by_slot_label in extra"
        );

        // Step 3: Re-save via the v2.6.x-equivalent struct.
        let re_saved = serde_json::to_string_pretty(&v26).unwrap();
        std::fs::write(&path, re_saved.as_bytes()).unwrap();

        // Step 4: Re-read via v2.7.x — assert by_slot_label survived.
        let reloaded = load(&path).unwrap();
        assert_eq!(
            reloaded.by_slot_label.get("4").map(|s| s.as_str()),
            Some("Renamed Account 4"),
            "by_slot_label must survive v2.7.x→v2.6.x→v2.7.x round-trip"
        );
    }

    // ─── RN1-D5a label relocation tests ──────────────────────────────────────

    /// D5a: `relocate_labels_to_by_slot_label` copies a rename label from
    /// `accounts[N].email` to `by_slot_label[N]` when it differs from the
    /// OAuth email sourced from the identity credential file.
    #[test]
    fn relocate_labels_copies_renamed_label_not_oauth_email() {
        // Arrange: slot 3 has a UUID, OAuth email "oauth@x.com" in its
        // identity credential file, but accounts[3].email is "My Work Account"
        // (a user rename label).
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("3".into(), uuid);
        pf.by_email.insert("oauth@x.com".into(), uuid);
        pf.set_profile(
            3,
            AccountProfile {
                email: "My Work Account".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();
        // Create the identity credential file so relocate_labels_to_by_slot_label
        // can read the OAuth email from it (C2 fix: no longer uses by_email lookup).
        let cred_path = identity_store::credentials_path_for(dir.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            br#"{"oauthAccount":{"emailAddress":"oauth@x.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = relocate_labels_to_by_slot_label(&lock, dir.path()).unwrap();

        // Assert: slot 3 was relocated.
        assert_eq!(report.slots_examined, 1);
        assert_eq!(report.slots_relocated, 1);
        assert_eq!(report.slots_skipped_oauth_email, 0);

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("3").map(|s| s.as_str()),
            Some("My Work Account"),
            "rename label must be relocated to by_slot_label[3]"
        );
    }

    /// D5a: slots where `accounts[N].email` equals the OAuth email are skipped
    /// (they are not user renames — they are the pre-RN1-D3 login-time writes).
    #[test]
    fn relocate_labels_skips_slot_when_accounts_email_matches_oauth_email() {
        // Arrange: slot 1 has accounts[1].email == OAuth email (no rename).
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("real@x.com".into(), uuid);
        pf.set_profile(
            1,
            AccountProfile {
                email: "real@x.com".into(), // same as OAuth email
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();
        // Create the identity credential file so relocate_labels_to_by_slot_label
        // can read the OAuth email from it (C2 fix: no longer uses by_email lookup).
        let cred_path = identity_store::credentials_path_for(dir.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            br#"{"oauthAccount":{"emailAddress":"real@x.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = relocate_labels_to_by_slot_label(&lock, dir.path()).unwrap();

        // Assert: slot 1 was skipped.
        assert_eq!(report.slots_skipped_oauth_email, 1);
        assert_eq!(report.slots_relocated, 0);

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            !loaded.by_slot_label.contains_key("1"),
            "by_slot_label[1] must remain absent when accounts email equals OAuth email"
        );
    }

    /// D5a: `relocate_labels_to_by_slot_label` is idempotent — running it twice
    /// does not overwrite an existing `by_slot_label[N]` value.
    #[test]
    fn relocate_labels_is_idempotent_preserves_later_rename() {
        // Arrange: slot 2 has a rename label in accounts[2], BUT by_slot_label[2]
        // already has a value (user renamed again after an earlier relocation).
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("2".into(), uuid);
        pf.by_email.insert("oauth@x.com".into(), uuid);
        pf.set_profile(
            2,
            AccountProfile {
                email: "Old Rename".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        // by_slot_label already has a newer rename.
        pf.by_slot_label.insert("2".into(), "Newer Rename".into());
        save(&profiles_path(dir.path()), &pf).unwrap();
        // Create the identity credential file so relocate_labels_to_by_slot_label
        // can read the OAuth email from it (C2 fix: no longer uses by_email lookup).
        let cred_path = identity_store::credentials_path_for(dir.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            br#"{"oauthAccount":{"emailAddress":"oauth@x.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Act: run relocation — should not overwrite the existing by_slot_label entry.
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = relocate_labels_to_by_slot_label(&lock, dir.path()).unwrap();

        // slots_relocated counts 1 because accounts[2].email ≠ OAuth email,
        // but the existing by_slot_label entry is NOT overwritten.
        assert_eq!(report.slots_relocated, 1);

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("2").map(|s| s.as_str()),
            Some("Newer Rename"),
            "existing by_slot_label must not be overwritten by relocation"
        );
    }

    // ─── RN1-D R3 prune_redundant_accounts_entries tests ────────────────────

    /// RN1-D R3: an entry whose genuine rename was already relocated into
    /// `by_slot_label[N]` is information-recoverable → pruned.
    #[test]
    fn prune_removes_entry_covered_by_by_slot_label() {
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            3,
            AccountProfile {
                email: "My Work Account".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        pf.by_slot_label
            .insert("3".into(), "My Work Account".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned, 1);
        assert_eq!(report.kept_unrecoverable, 0);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            loaded.accounts_for_test().is_empty(),
            "by_slot_label-covered entry must be pruned; accounts: {:?}",
            loaded.accounts_for_test()
        );
        assert_eq!(
            loaded.by_slot_label.get("3").map(|s| s.as_str()),
            Some("My Work Account"),
            "the relocated label must be preserved in by_slot_label"
        );
    }

    /// RN1-D R3: a bare-OAuth-email entry (by_slot resolves a UUID whose
    /// credential email == accounts[N].email) is recoverable via
    /// `by_slot[N]→by_email` → pruned.
    #[test]
    fn prune_removes_bare_oauth_email_entry() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("real@x.com".into(), uuid);
        pf.set_profile(
            1,
            AccountProfile {
                email: "real@x.com".into(), // == OAuth email, not a rename
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        // REAL-HOST SHAPE: NO identity credential file is created. On a
        // daemon-refreshed host the UUID-keyed credentials.json lacks
        // `oauthAccount.emailAddress` (CC backfills it only on first API
        // call). Arm 3 MUST resolve via by_email reverse-lookup (mirroring
        // get_email step 3), independent of the cred file. A cred-file
        // predicate would silently never fire here — the bug journal 0064
        // round-2 fixed; this test is the anti-fixture-masking regression.
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned, 1,
            "bare OAuth email must be pruned via by_email reverse-lookup \
             even with NO credential file (real daemon-refreshed host)"
        );
        assert_eq!(report.kept_unrecoverable, 0);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            loaded.accounts_for_test().is_empty(),
            "bare OAuth email entry pruned"
        );
    }

    /// RN1-D R3 (arm-3 safety): `by_slot[N]` present but the by_email
    /// reverse-lookup yields a DIFFERENT value than `accounts[N].email`
    /// (a genuine rename that was never relocated, e.g. relocation skipped
    /// because the cred file lacked emailAddress). `get_email` step 3 would
    /// change the observable → entry MUST be kept, not pruned.
    #[test]
    fn prune_keeps_when_by_email_reverse_differs_from_accounts_email() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("2".into(), uuid);
        pf.by_email.insert("oauth@x.com".into(), uuid); // step 3 → "oauth@x.com"
        pf.set_profile(
            2,
            AccountProfile {
                email: "My Custom Rename".into(), // ≠ step 3 → genuine rename
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned, 0, "genuine rename MUST NOT be pruned");
        assert_eq!(report.kept_unrecoverable, 1);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("2")
                .map(|p| p.email.as_str()),
            Some("My Custom Rename"),
            "rename ≠ by_email-reverse → get_email would change → KEEP"
        );
    }

    /// RN1-D R3: an empty-email entry has nothing to lose → pruned.
    #[test]
    fn prune_removes_empty_email_entry() {
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            5,
            AccountProfile {
                email: "".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned, 1);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(loaded.accounts_for_test().is_empty());
    }

    /// RN1-D R3 (the safety invariant): a genuine rename with NO recovery
    /// channel — no `by_slot[N]`, no `by_slot_label[N]`, non-empty label —
    /// MUST be kept. Pruning it would silently destroy the label (the exact
    /// data-loss the WINDOW-CLOSE gate exists to prevent). Keeping it
    /// correctly holds P1 OPEN until `csq login N` (RN1-D R2) captures it.
    #[test]
    fn prune_keeps_unrecoverable_rename_entry() {
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            7,
            AccountProfile {
                email: "Irreplaceable Label".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        // No by_slot[7], no by_slot_label[7], non-empty email.
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned, 0);
        assert_eq!(report.kept_unrecoverable, 1);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("7")
                .map(|p| p.email.as_str()),
            Some("Irreplaceable Label"),
            "unrecoverable rename label MUST be kept (no recovery channel)"
        );
    }

    /// RN1-D R3: idempotent — a second run prunes nothing more and the
    /// kept-unrecoverable set is stable.
    #[test]
    fn prune_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            1,
            AccountProfile {
                email: "".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        pf.set_profile(
            7,
            AccountProfile {
                email: "Keep Me".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let r1 = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();
        assert_eq!(r1.pruned, 1);
        assert_eq!(r1.kept_unrecoverable, 1);
        let r2 = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();
        assert_eq!(r2.pruned, 0, "second run must prune nothing (idempotent)");
        assert_eq!(r2.kept_unrecoverable, 1, "kept set is stable");
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(loaded.accounts_for_test().len(), 1);
        assert!(loaded.accounts_for_test().contains_key("7"));
    }

    // ─── M1-8 audit_coexistence tests ────────────────────────────────────────

    /// M1-8: legacy-only fixture (3 slots) returns LegacyOnly + Consistent.
    ///
    /// A fresh install where the daemon Pass 0 has never run: only `config-N/`
    /// dirs exist, no `identities/`, no `store-version`, `profiles.json` has
    /// empty `by_slot`.  `LegacyOnly` + `Consistent` is the expected shape.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_returns_legacy_only_on_fresh_install() {
        // Arrange: legacy-only fixture with 3 slots.
        let dir = crate::testing::identity_fixtures::legacy_only_fixture(3);

        // Act
        let report = audit_coexistence(dir.path()).expect("audit_coexistence must succeed");

        // Assert: state is LegacyOnly (no identities, no sentinel).
        assert_eq!(
            report.state,
            CoexistenceState::LegacyOnly,
            "expected LegacyOnly state on fresh install"
        );
        // 3 config-N dirs found.
        assert_eq!(
            report.profile_slot_count, 3,
            "expected 3 legacy config-N dirs"
        );
        // No identity dirs.
        assert_eq!(report.identity_count, 0, "expected 0 identity dirs");
        // store_version = 0 (sentinel absent).
        assert_eq!(
            report.store_version, 0,
            "expected store_version 0 — no sentinel"
        );
        // Consistency is Consistent (by_slot is also empty).
        assert!(
            report.consistency.is_empty(),
            "expected Consistent (empty vec) — empty by_slot matches 0 identity dirs"
        );
    }

    /// M1-8: coexisting fixture (3 slots) returns Coexisting + Consistent.
    ///
    /// After the daemon Pass 0 has run: `config-N/` dirs and `identities/<UUID>/`
    /// dirs both exist with consistent slot↔UUID mapping and a sentinel.
    ///
    /// Updated for M2-6 scaffold: the test now also seeds `credentials.json`
    /// and `settings.json` under every UUID path so that the Phase 2
    /// presence-checks (MissingCredentialsAtUuidPath, MissingSettingsAtUuidPath)
    /// do not fire and the result remains `Consistent`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_returns_coexisting_after_pass0() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture with 3 slots.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Seed UUID-keyed credentials.json + settings.json for every slot so
        // the M2-6 presence-checks pass.
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        // Act
        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        // Assert: state is Coexisting.
        assert_eq!(
            report.state,
            CoexistenceState::Coexisting,
            "expected Coexisting state with both layouts present"
        );
        assert_eq!(
            report.profile_slot_count, 3,
            "expected 3 legacy config-N dirs"
        );
        assert_eq!(report.identity_count, 3, "expected 3 identity dirs");
        assert!(report.store_version >= 1, "store_version must be >= 1");
        assert!(
            report.consistency.is_empty(),
            "expected Consistent (empty vec) — all slots have matching identity dirs and UUID files"
        );
    }

    /// slot-attribution-consistency M5: `CurrentAccountDrift` fires when a
    /// `config-N/.current-account` holds a slot id ≠ N (the reported bug's
    /// on-disk shape). Absent `.current-account` is NOT drift.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_current_account_drift() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        // config-2/.current-account = "8" — stale (foreign slot id).
        std::fs::write(base.join("config-2").join(".current-account"), "8").unwrap();

        let report = audit_coexistence(base).expect("audit must succeed");
        assert!(
            report.consistency.iter().any(|c| matches!(
                c,
                ConsistencyState::CurrentAccountDrift { slot: 2, cached: 8 }
            )),
            "expected CurrentAccountDrift(slot=2, cached=8), got {:?}",
            report.consistency
        );
    }

    /// HIGH-2 regression (R1 deep-analyst): CurrentAccountDrift MUST also be
    /// detected on a LegacyOnly host (no identities/, no sentinel — the brief's
    /// numeric-marker slots classify here). Before the hoist the drift check
    /// only ran in the Coexisting|IdentityOnly arm, so `csq doctor` was blind
    /// while `csq repair` saw it.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_current_account_drift_on_legacy_only() {
        let dir = crate::testing::identity_fixtures::legacy_only_fixture(3);
        let base = dir.path();
        std::fs::write(base.join("config-2").join(".current-account"), "9").unwrap();

        let report = audit_coexistence(base).expect("audit must succeed");
        assert_eq!(
            report.state,
            CoexistenceState::LegacyOnly,
            "fixture must be LegacyOnly for this regression"
        );
        assert!(
            report.consistency.iter().any(|c| matches!(
                c,
                ConsistencyState::CurrentAccountDrift { slot: 2, cached: 9 }
            )),
            "LegacyOnly drift must be detected, got {:?}",
            report.consistency
        );
    }

    /// A slot present in BOTH `by_slot` and `by_slot_identity` is the NORMAL
    /// codex-slot representation (codex login mints both), NOT an inconsistency.
    /// `audit_coexistence` MUST NOT flag it. Regression guard for the removed
    /// `DualMapSlot` false-positive (memory
    /// discovery_by_slot_holds_codex_identities).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_does_not_flag_codex_dual_map_slot() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();
        let mut pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }
        // Slot 2 in by_slot AND by_slot_identity — the normal codex shape.
        pf.by_slot_identity
            .insert("2".into(), "codex-2/deadbeef".into());
        save(&profiles_path(base), &pf).unwrap();

        let report = audit_coexistence(base).expect("audit must succeed");
        assert!(
            report.consistency.is_empty(),
            "a codex dual-map slot must NOT be flagged as inconsistent, got {:?}",
            report.consistency
        );
    }

    /// M1-8: OrphanIdentity detected when an `identities/<UUID>/` dir exists
    /// but its UUID is not in `profiles.json::by_slot` or `by_email`.
    ///
    /// Setup: coexisting_fixture(3) → remove ONLY by_slot["1"] from
    /// profiles.json while keeping `identities/<UUID-1>/` on disk AND the
    /// stale `by_email` entry for that UUID. The UUID for slot 1 is
    /// deterministic via `fixture_uuid_for_slot(1)`.
    ///
    /// Round-1 redteam HIGH-1 regression guard: the stale `by_email` entry
    /// is deliberately KEPT. `OrphanIdentity` keys on `by_slot` only — a
    /// `by_email` entry is a lookup index, not a live binding, and must NOT
    /// suppress the orphan flag. If the audit ever re-unions `by_email` into
    /// the referenced-set, this test fails.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_orphan_identity() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture, then remove ONLY the by_slot mapping
        // for slot 1 — leaving the by_email entry for its UUID in place.
        let dir = coexisting_fixture(3);
        let path = profiles_path(dir.path());

        let mut pf = load(&path).unwrap();
        let uuid1 = fixture_uuid_for_slot(1);
        pf.by_slot.remove("1");
        // by_email[<slot-1 email>] → uuid1 is INTENTIONALLY left in place —
        // it is the stale-index condition the orphan check must see through.
        assert!(
            pf.by_email.values().any(|v| *v == uuid1),
            "fixture precondition: a stale by_email entry for uuid1 must remain"
        );
        save(&path, &pf).unwrap();

        // Act
        let report = audit_coexistence(dir.path()).expect("audit_coexistence must succeed");

        // Assert: OrphanIdentity is detected.
        let orphan = report.consistency.iter().find_map(|c| {
            if let ConsistencyState::OrphanIdentity { uuid } = c {
                Some(*uuid)
            } else {
                None
            }
        });
        match orphan {
            Some(uuid) => {
                assert_eq!(uuid, uuid1, "expected the UUID for slot 1 to be the orphan");
            }
            None => panic!(
                "expected OrphanIdentity, got {:?}\n\
                 identities_dir={:?}",
                report.consistency,
                dir.path().join("identities")
            ),
        }
    }

    /// M1-8: OrphanLegacySlot detected when a `config-N/` dir exists but
    /// its slot number is not in `profiles.json::by_slot`.
    ///
    /// Setup: coexisting_fixture(3) → create `config-4/` without adding a
    /// matching `by_slot["4"]` entry.
    ///
    /// Updated for M2-6 scaffold: seeds UUID credentials.json + settings.json
    /// for slots 1–3 so the new Missing* checks do not fire before the orphan
    /// detection; the OrphanLegacySlot check runs at step 2 in the audit
    /// order, which is before the M2-6 checks at step 3+.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_orphan_legacy_slot() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture, then create config-4/ with no by_slot entry.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let extra_config = base.join("config-4");
        std::fs::create_dir_all(&extra_config).unwrap();
        // Write a stub .credentials.json so the dir is non-empty (matching
        // the real on-disk shape that discover_anthropic expects).
        std::fs::write(extra_config.join(".credentials.json"), r#"{"stub":true}"#).unwrap();
        // profiles.json::by_slot["4"] is intentionally absent.
        // The OrphanLegacySlot check (step 2) fires before the M2-6 Missing*
        // checks (step 3+), so no UUID file seeding is necessary here.

        // Act
        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        // Assert: OrphanLegacySlot(4) is detected.
        let orphan_slot = report.consistency.iter().find_map(|c| {
            if let ConsistencyState::OrphanLegacySlot { slot } = c {
                Some(*slot)
            } else {
                None
            }
        });
        match orphan_slot {
            Some(slot) => {
                assert_eq!(slot, 4, "expected slot 4 to be the orphan legacy slot");
            }
            None => panic!("expected OrphanLegacySlot, got {:?}", report.consistency),
        }
    }

    /// G4/AC-7 (FM-1, journal 0001 D4): a `config-N/` slot with a
    /// `by_slot_identity[N]` entry (3P/Codex/Gemini recovery channel) OR
    /// #578: direct contract test for the canonical `is_slot_recovery_backed`
    /// predicate shared by `audit_coexistence`, `detect_decimal_marker`, and
    /// the `csq doctor` `legacy_count` heuristic. Covers all three channels
    /// + the symlink-rejection rule + the genuine-orphan case.
    #[test]
    fn is_slot_recovery_backed_covers_all_channels() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("credentials")).unwrap();

        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert(
            "1".into(),
            "00000000-0000-0000-0000-000000000001"
                .parse()
                .expect("valid UUID"),
        );
        pf.by_slot_identity.insert("2".into(), "apikey:mm".into());

        // (a) by_slot member → recovery-backed.
        assert!(is_slot_recovery_backed(base, &pf, 1));
        // (b) by_slot_identity member → recovery-backed.
        assert!(is_slot_recovery_backed(base, &pf, 2));

        // (c) regular-file gemini marker → recovery-backed.
        std::fs::write(base.join("credentials").join("gemini-3.json"), "{}").unwrap();
        assert!(is_slot_recovery_backed(base, &pf, 3));

        // Symlinked gemini marker is REJECTED (matches discover_gemini's
        // hardened walk — a symlink is never identity-backed). Unix-only:
        // the symlink-rejection path uses `symlink_metadata().is_file()`,
        // and creating a symlink to exercise it needs the unix API. The
        // cross-platform channel + orphan assertions above/below run on all
        // platforms.
        #[cfg(unix)]
        {
            let real = base.join("credentials").join("gemini-3.json");
            std::os::unix::fs::symlink(&real, base.join("credentials").join("gemini-4.json"))
                .unwrap();
            assert!(
                !is_slot_recovery_backed(base, &pf, 4),
                "a SYMLINKED gemini marker must NOT count as recovery-backed (#578)"
            );
        }

        // Genuine orphan — no map entry, no marker.
        assert!(!is_slot_recovery_backed(base, &pf, 9));
    }

    /// a `credentials/gemini-N.json` binding marker is NOT a false
    /// `OrphanLegacySlot`. This is the pre-existing PR #500 defect fix —
    /// verified on the maintainer host where slots 9/11/12/14 carry
    /// `by_slot_identity` yet were orphan-flagged because the predicate
    /// tested only `by_slot`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_excludes_by_slot_identity_and_gemini_marker_slots() {
        use crate::testing::identity_fixtures::{
            coexisting_fixture, gemini_binding_state, GeminiFixtureMode,
        };

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // config-4: recovery-backed via by_slot_identity (no by_slot).
        std::fs::create_dir_all(base.join("config-4")).unwrap();
        std::fs::write(
            base.join("config-4").join(".credentials.json"),
            r#"{"stub":true}"#,
        )
        .unwrap();
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_identity(&lock, base, 4, "apikey:mm").unwrap();
        }
        // config-5: recovery-backed via Gemini binding marker only
        // (no by_slot, no by_slot_identity — the pre-backfill window).
        gemini_binding_state(base, 5, GeminiFixtureMode::ApiKey, true).unwrap();

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        assert!(
            !report
                .consistency
                .iter()
                .any(|c| { matches!(c, ConsistencyState::OrphanLegacySlot { slot: 4 | 5 }) }),
            "slots 4 (by_slot_identity) and 5 (gemini marker) must NOT be \
             false OrphanLegacySlot; got {:?}",
            report.consistency
        );
    }

    /// G4/AC-7: a GENUINE orphan (config-N with no by_slot, no
    /// by_slot_identity, no binding marker — e.g. the maintainer host's
    /// slot 10) is STILL correctly flagged even when recovery-backed
    /// siblings exist. The predicate fix must not over-suppress.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_still_flags_genuine_orphan_with_recovery_backed_siblings() {
        use crate::testing::identity_fixtures::{
            coexisting_fixture, gemini_binding_state, GeminiFixtureMode,
        };

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Recovery-backed siblings (must be skipped by the predicate).
        std::fs::create_dir_all(base.join("config-4")).unwrap();
        std::fs::write(
            base.join("config-4").join(".credentials.json"),
            r#"{"stub":true}"#,
        )
        .unwrap();
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_identity(&lock, base, 4, "codex-4/abc").unwrap();
        }
        gemini_binding_state(base, 5, GeminiFixtureMode::VertexSa, true).unwrap();

        // Genuine orphan: config-6 with nothing recovery-backed.
        std::fs::create_dir_all(base.join("config-6")).unwrap();
        std::fs::write(
            base.join("config-6").join(".credentials.json"),
            r#"{"stub":true}"#,
        )
        .unwrap();

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");
        let orphan_slot = report.consistency.iter().find_map(|c| {
            if let ConsistencyState::OrphanLegacySlot { slot } = c {
                Some(*slot)
            } else {
                None
            }
        });
        match orphan_slot {
            Some(slot) => assert_eq!(
                slot, 6,
                "the genuine orphan (6) must be flagged, not a recovery-backed sibling"
            ),
            None => panic!("expected OrphanLegacySlot(6), got {:?}", report.consistency),
        }
    }

    /// Round-1 redteam MED regression: a SYMLINK at
    /// `credentials/gemini-N.json` must NOT suppress the
    /// `OrphanLegacySlot` flag. `discover_gemini` rejects symlinked
    /// markers (so the backfill never writes `by_slot_identity[N]` for
    /// them); the audit predicate must be symmetric — a symlink is not a
    /// valid binding, so the slot is genuinely a recovery-less orphan.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn audit_coexistence_symlinked_gemini_marker_does_not_suppress_orphan() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();

        // config-4 with a SYMLINK marker (points anywhere; even a real
        // file — discover_gemini rejects ALL symlinks). No by_slot, no
        // by_slot_identity.
        std::fs::create_dir_all(base.join("config-4")).unwrap();
        std::fs::write(
            base.join("config-4").join(".credentials.json"),
            r#"{"stub":true}"#,
        )
        .unwrap();
        let real = creds.join("gemini-real.json");
        std::fs::write(
            &real,
            r#"{"v":1,"auth":{"mode":"api_key"},"model_name":"auto","created_unix_secs":0}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, creds.join("gemini-4.json")).unwrap();

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");
        let orphan_slot = report.consistency.iter().find_map(|c| {
            if let ConsistencyState::OrphanLegacySlot { slot } = c {
                Some(*slot)
            } else {
                None
            }
        });
        match orphan_slot {
            Some(slot) => assert_eq!(
                slot, 4,
                "a symlinked gemini marker must NOT suppress the orphan flag \
                 (symmetric with discover_gemini's symlink rejection)"
            ),
            None => panic!("expected OrphanLegacySlot(4), got {:?}", report.consistency),
        }
    }

    /// AC-6: `get_email(N)` resolves a Gemini slot via step 1.5
    /// (`by_slot_identity`) when no `by_slot_label` rename exists; a
    /// rename (step 1) still wins.
    #[test]
    fn get_email_resolves_gemini_identity_then_rename_wins() {
        let mut pf = ProfilesFile::empty();
        pf.by_slot_identity
            .insert("13".into(), "gemini-13/codeassist".into());
        assert_eq!(
            pf.get_email(13),
            Some("gemini-13/codeassist"),
            "step 1.5 must resolve the Gemini identity literal"
        );
        pf.by_slot_label.insert("13".into(), "My Gemini".into());
        assert_eq!(
            pf.get_email(13),
            Some("My Gemini"),
            "a by_slot_label rename (step 1) must win over by_slot_identity (step 1.5)"
        );
    }

    // ─── M2-6 scaffold tests ─────────────────────────────────────────────────

    /// M2-6 criterion 1: audit detects missing `credentials.json` at UUID path.
    ///
    /// Fixture: `coexisting_fixture(3)` has NO `identities/<UUID>/credentials.json`
    /// files (Wave 1 Phase 1 baseline).  At least one slot must produce
    /// `MissingCredentialsAtUuidPath`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_missing_uuid_credentials() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: Phase 1 coexisting fixture — no UUID-keyed credentials files.
        let dir = coexisting_fixture(3);

        // Act
        let report = audit_coexistence(dir.path()).expect("audit_coexistence must succeed");

        // Assert: at least one MissingCredentialsAtUuidPath variant is emitted.
        // The audit returns the FIRST missing UUID, so we check the variant kind
        // rather than a specific UUID (iteration order may vary).
        assert!(
            report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::MissingCredentialsAtUuidPath { .. })),
            "expected MissingCredentialsAtUuidPath, got {:?}; \
             coexisting_fixture has no UUID-keyed credentials files in Phase 1",
            report.consistency
        );
    }

    /// M2-6 criterion 2: audit detects missing `settings.json` at UUID path.
    ///
    /// Fixture: `coexisting_fixture(3)` seeded with `credentials.json` for all
    /// slots (so criterion-1 check passes through), but no `settings.json`.
    /// At least one slot must produce `MissingSettingsAtUuidPath`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_detects_missing_uuid_settings() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture, seed credentials.json for all UUIDs
        // (so the MissingCredentials check passes through), but leave
        // settings.json absent.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            // settings.json intentionally NOT written
        }

        // Act
        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        // Assert: at least one MissingSettingsAtUuidPath variant is emitted.
        assert!(
            report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::MissingSettingsAtUuidPath { .. })),
            "expected MissingSettingsAtUuidPath, got {:?}; \
             settings.json was intentionally absent for all UUID paths",
            report.consistency
        );
    }

    /// M2-6 criterion 3: audit returns Consistent when all UUID-keyed files
    /// (credentials.json + settings.json) are present for every slot.
    ///
    /// This simulates the post-Phase-2 steady state.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_consistent_on_steady_state() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture, then seed credentials.json + settings.json
        // under every UUID directory so all Phase 2 checks pass.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        // Act
        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        // Assert: no Missing* variants.
        assert!(
            report.consistency.is_empty(),
            "expected Consistent (empty vec) when all UUID-path files are present; got {:?}",
            report.consistency
        );
        assert_eq!(
            report.state,
            CoexistenceState::Coexisting,
            "fixture must be in Coexisting state"
        );
    }

    /// RC1 regression guard (doctor-consistency-audit): `audit_coexistence`
    /// surfaces MULTIPLE issues at once. A host with both an orphan legacy
    /// slot AND a missing UUID-keyed credentials file reports BOTH in the
    /// consistency list — proving the list shape ended the single-issue
    /// unmask treadmill (a single-`ConsistencyState` field would have
    /// returned only the first).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_surfaces_multiple_issues_at_once() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Issue A — config-4/ with no recovery channel → OrphanLegacySlot(4).
        std::fs::create_dir_all(base.join("config-4")).unwrap();
        std::fs::write(
            base.join("config-4").join(".credentials.json"),
            r#"{"stub":true}"#,
        )
        .unwrap();

        // Issue B — seed settings.json (so MissingSettings does NOT fire) but
        // NOT credentials.json → MissingCredentialsAtUuidPath.
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        assert!(
            report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::OrphanLegacySlot { slot: 4 })),
            "OrphanLegacySlot(4) must be in the list; got {:?}",
            report.consistency
        );
        assert!(
            report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::MissingCredentialsAtUuidPath { .. })),
            "MissingCredentialsAtUuidPath must be in the list; got {:?}",
            report.consistency
        );
        assert_eq!(
            report.consistency.len(),
            2,
            "exactly two issues — one OrphanLegacySlot + one MissingCredentials; got {:?}",
            report.consistency
        );
        // Collection-order stability: OrphanLegacySlot is pushed before the
        // Missing* checks, so it occupies index 0. doctor renders the list
        // in this order (collection order, not a severity ranking).
        assert!(
            matches!(
                report.consistency[0],
                ConsistencyState::OrphanLegacySlot { .. }
            ),
            "OrphanLegacySlot must be collected before MissingCredentials; got {:?}",
            report.consistency
        );
    }

    /// **2026-05-25 post-A++ codex-only regression (host slot 8)** — a Codex
    /// slot minted post-A++ records its codex-ness ONLY in the identity store
    /// (`identity.json` provider=codex + `credentials-codex.json`); its legacy
    /// `credentials/codex-<N>.json` mirror was retired. The pre-fix
    /// legacy-marker-only skip missed it, so `audit_coexistence` emitted a
    /// false `MissingCredentialsAtUuidPath` (the host's persistent doctor
    /// INCONSISTENT verdict). This pins the identity-store-aware skip for BOTH
    /// sibling UUID-path checks: a codex-only slot with NO legacy marker and NO
    /// Anthropic `credentials.json`/`settings.json` produces NEITHER
    /// `MissingCredentialsAtUuidPath` NOR `MissingSettingsAtUuidPath` (R1 deep-
    /// analyst MED: the settings sibling re-introduced the same class one file
    /// over — codex settings pairing is non-fatal by design).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_skips_post_aplusplus_codex_only_slot() {
        use crate::accounts::identity_store::{
            credentials_codex_path_for, credentials_path_for, identity_path, settings_path_for,
            IdentityId,
        };
        use crate::testing::identity_fixtures::coexisting_fixture;

        // One healthy Anthropic slot (seed UUID-path creds + settings so it
        // does NOT itself fire Missing* — isolates the codex assertion).
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let anthropic_uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        std::fs::write(credentials_path_for(base, anthropic_uuid), b"{}").unwrap();
        std::fs::write(settings_path_for(base, anthropic_uuid), b"{}").unwrap();

        // Add a post-A++ codex-only slot 8: provider=codex + credentials-codex
        // present, NO Anthropic credentials.json, NO settings.json, NO legacy
        // mirror. The MISSING settings.json is deliberate — pins the sibling
        // MissingSettings skip too.
        let codex_uuid = IdentityId::new_v4();
        let mut pf = load(&profiles_path(base)).unwrap();
        pf.by_slot.insert("8".to_string(), codex_uuid);
        save(&profiles_path(base), &pf).unwrap();
        let id_dir = identity_path(base, codex_uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(
            id_dir.join("identity.json"),
            br#"{"email":"codex:abc","provider":"codex","created_at":"t","key_id":null}"#,
        )
        .unwrap();
        std::fs::write(credentials_codex_path_for(base, codex_uuid), b"{}").unwrap();

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        assert!(
            !report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::MissingCredentialsAtUuidPath { .. })),
            "post-A++ codex-only slot 8 (no legacy mirror) must NOT produce \
             MissingCredentialsAtUuidPath; got {:?}",
            report.consistency
        );
        assert!(
            !report
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::MissingSettingsAtUuidPath { .. })),
            "post-A++ codex-only slot 8 (no settings.json) must NOT produce \
             MissingSettingsAtUuidPath — codex settings pairing is non-fatal; got {:?}",
            report.consistency
        );
    }

    /// RC2 regression guard (doctor-consistency-audit): a healthy host with
    /// BOTH OAuth slots AND a non-OAuth (`by_slot_identity`) slot reports an
    /// EMPTY consistency list. The retired count-based `SlotCountMismatch`
    /// would have false-flagged this — `config_slot_count` (4) counted the
    /// non-OAuth `config-9/` dir while `by_slot_count` was 3.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_consistent_with_non_oauth_slot() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // 3 OAuth slots, fully consistent — seed UUID credentials + settings.
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = crate::accounts::identity_store::identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        // A non-OAuth slot: config-9/ recovery-backed by `by_slot_identity`.
        std::fs::create_dir_all(base.join("config-9")).unwrap();
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_identity(&lock, base, 9, "apikey:zai").unwrap();
        }

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        assert!(
            report.consistency.is_empty(),
            "a healthy host with OAuth + non-OAuth slots must report an empty \
             consistency list — the retired count check false-flagged this; got {:?}",
            report.consistency
        );
    }

    /// Round-1 redteam LOW-1 regression guard (doctor-consistency-audit): the
    /// LegacyOnly-branch `SlotCountMismatch` — a populated `by_slot` in a
    /// LegacyOnly layout (no `store-version` sentinel, no `identities/` dir)
    /// — is a genuine half-written state and the ONLY `SlotCountMismatch`
    /// emission the audit retains. Exercises it through `audit_coexistence`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn audit_coexistence_legacy_only_with_populated_by_slot_flags_mismatch() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // A profiles.json carrying a by_slot entry, but NO store-version
        // sentinel and NO identities/ dir → LegacyOnly state, non-empty
        // by_slot.
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".to_string(), IdentityId::new_v4());
        save(&profiles_path(base), &pf).unwrap();

        let report = audit_coexistence(base).expect("audit_coexistence must succeed");

        assert_eq!(
            report.state,
            CoexistenceState::LegacyOnly,
            "no sentinel + no identity dirs ⇒ LegacyOnly"
        );
        assert_eq!(
            report.consistency,
            vec![ConsistencyState::SlotCountMismatch {
                legacy: 0,
                identity: 1,
            }],
            "a populated by_slot in LegacyOnly is a half-written state — must be flagged"
        );
    }

    /// M2-6 criterion 4: serde round-trip for the UUID-path Missing*
    /// ConsistencyState variants.
    #[test]
    fn consistency_state_serialize_includes_new_variants() {
        use crate::accounts::identity_store::IdentityId;

        let uuid = IdentityId::new_v4();

        // MissingCredentialsAtUuidPath round-trip
        {
            let v = ConsistencyState::MissingCredentialsAtUuidPath { uuid };
            let json = serde_json::to_string(&v).expect("serialize MissingCredentialsAtUuidPath");
            let decoded: ConsistencyState =
                serde_json::from_str(&json).expect("deserialize MissingCredentialsAtUuidPath");
            assert_eq!(v, decoded, "MissingCredentialsAtUuidPath must round-trip");
            // The serde tag must be present in the JSON.
            assert!(
                json.contains("MissingCredentialsAtUuidPath"),
                "JSON tag must include variant name; got: {json}"
            );
        }

        // MissingSettingsAtUuidPath round-trip
        {
            let v = ConsistencyState::MissingSettingsAtUuidPath { uuid };
            let json = serde_json::to_string(&v).expect("serialize MissingSettingsAtUuidPath");
            let decoded: ConsistencyState =
                serde_json::from_str(&json).expect("deserialize MissingSettingsAtUuidPath");
            assert_eq!(v, decoded, "MissingSettingsAtUuidPath must round-trip");
            assert!(
                json.contains("MissingSettingsAtUuidPath"),
                "JSON tag must include variant name; got: {json}"
            );
        }
    }

    // ─── M4-9 (release N affordance, issue #292 Phase 4) ─────────────────────
    //
    // The v1 `profiles.accounts` field is empty-write in production. The
    // tests below cover:
    //   - v2.6.x ↔ v2.7.x DOWNGRADE round-trip preserves Phase 4 fields.
    //   - `get_email` resolves OAuth slots via `by_slot → UUID → by_email`
    //     reverse-lookup when `accounts[N]` is empty.
    //   - `get_email` prefers `accounts[N]` when populated (user rename
    //     or v2.6.x downgrade re-save).

    /// M4-9 (a): v2.6.x downgrade compat round-trip preserves the Phase 4
    /// fields (`by_slot`, `by_email`) when a v2.6.x csq writes back a
    /// file that originated as a release-N empty-accounts shape.
    ///
    /// This extends `flatten_preserves_unknown_fields_and_v2_keys` to the
    /// post-M4-9 state where the v2.7.x writer emits `accounts: {}` and
    /// the v2.6.x reader populates accounts with its own emails before
    /// writing back. The Phase 4 maps MUST survive the round trip via the
    /// `#[serde(flatten)] extra` hatch.
    #[test]
    fn v26x_downgrade_round_trip_preserves_phase4_fields() {
        // v2.6.x-equivalent reader: knows `accounts` + `extra`, NOT
        // `by_slot` / `by_email`.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct ProfilesFileV26 {
            #[serde(default)]
            accounts: HashMap<String, serde_json::Value>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        // Step 1: write the release-N (post-M4-9) shape — empty
        // `accounts`, populated `by_slot` + `by_email`.
        let uuid_a = IdentityId::new_v4();
        let uuid_b = IdentityId::new_v4();
        let mut v27 = ProfilesFile::empty();
        v27.by_slot.insert("1".into(), uuid_a);
        v27.by_slot.insert("2".into(), uuid_b);
        v27.by_email.insert("alice@example.com".into(), uuid_a);
        v27.by_email.insert("bob@example.com".into(), uuid_b);
        save(&path, &v27).unwrap();

        // M4-13 sanity: the file on disk MUST NOT contain an `accounts` key.
        // Pre-M4-9: accounts was written as a populated map.
        // M4-9: accounts was written as `accounts: {}` (empty affordance).
        // M4-13: accounts key is ABSENT — the serde-flatten hatch absorbs any
        //        residual `accounts` from older on-disk files, but new writes
        //        omit it entirely.
        let raw = std::fs::read_to_string(&path).unwrap();
        let raw_val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(
            raw_val.get("accounts").is_none(),
            "M4-13: release-N writer MUST NOT emit an `accounts` key; \
             the field is absent from ProfilesFile. Raw: {raw}"
        );

        // Step 2: a v2.6.x csq reads the file. by_slot + by_email land in
        // its `extra` hatch (it doesn't know those keys as named fields).
        let v26: ProfilesFileV26 = serde_json::from_str(&raw).unwrap();
        assert!(
            v26.extra.contains_key("by_slot"),
            "v2.6.x reader MUST capture by_slot in extra so it survives the round-trip"
        );
        assert!(
            v26.extra.contains_key("by_email"),
            "v2.6.x reader MUST capture by_email in extra"
        );
        assert!(
            v26.accounts.is_empty(),
            "v2.6.x reader observes accounts as empty under M4-9"
        );

        // Step 3: simulate the v2.6.x csq doing its own login on a third
        // slot and writing back. v2.6.x DOES populate `accounts[N]` per
        // its own contract. The Phase 4 maps in `extra` must round-trip
        // verbatim.
        let mut v26_mut = v26;
        v26_mut.accounts.insert(
            "3".into(),
            serde_json::json!({
                "email": "carol@example.com",
                "method": "oauth"
            }),
        );
        let v26_serialized = serde_json::to_string_pretty(&v26_mut).unwrap();
        std::fs::write(&path, v26_serialized.as_bytes()).unwrap();

        // Step 4: a release-N csq re-reads. Phase 4 maps MUST be intact;
        // the v2.6.x-written accounts[3] entry MUST also be visible.
        let reloaded = load(&path).unwrap();
        assert_eq!(
            reloaded.by_slot.get("1").copied(),
            Some(uuid_a),
            "by_slot[1] MUST survive the v2.7→v2.6→v2.7 downgrade round-trip"
        );
        assert_eq!(
            reloaded.by_slot.get("2").copied(),
            Some(uuid_b),
            "by_slot[2] MUST survive the v2.7→v2.6→v2.7 downgrade round-trip"
        );
        assert_eq!(
            reloaded.by_email.get("alice@example.com").copied(),
            Some(uuid_a),
            "by_email[alice] MUST survive the downgrade round-trip"
        );
        assert_eq!(
            reloaded.by_email.get("bob@example.com").copied(),
            Some(uuid_b),
            "by_email[bob] MUST survive the downgrade round-trip"
        );
        assert_eq!(
            reloaded
                .accounts_for_test()
                .get("3")
                .map(|p| p.email.as_str()),
            Some("carol@example.com"),
            "v2.6.x-written accounts[3] MUST be readable post-downgrade"
        );
    }

    /// M4-9: `get_email` resolves an OAuth slot's email via the
    /// `by_slot → UUID → by_email` reverse-lookup when `accounts[N]`
    /// is empty (the normal post-M4-9 state).
    #[test]
    fn get_email_resolves_via_by_email_reverse_when_accounts_empty() {
        let uuid = IdentityId::new_v4();
        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("1".into(), uuid);
        profiles.by_email.insert("alice@example.com".into(), uuid);
        // accounts intentionally empty — this is the post-M4-9 normal case.

        assert_eq!(
            profiles.get_email(1),
            Some("alice@example.com"),
            "get_email MUST resolve via by_slot→UUID→by_email when accounts is empty"
        );
        assert_eq!(
            profiles.get_email(99),
            None,
            "get_email MUST return None for slots with neither accounts nor by_slot entry"
        );
    }

    /// M4-13: `get_email` step 2 (accounts[N].email) was REMOVED. The desktop
    /// `update_email` rename now writes to `by_slot_label`, not `accounts[N]`.
    /// When `by_slot_label` is absent but `by_slot → UUID → by_email` resolves,
    /// `get_email` returns the OAuth email from `by_email` (step 2 post-M4-13).
    #[test]
    fn get_email_falls_back_to_by_email_after_m4_13_accounts_step_removed() {
        let uuid = IdentityId::new_v4();
        let mut profiles = ProfilesFile::empty();
        // OAuth flow populated: by_slot + by_email carry the original OAuth email.
        profiles.by_slot.insert("1".into(), uuid);
        profiles.by_email.insert("alice@example.com".into(), uuid);
        // Simulate a residual accounts entry (legacy on-disk — no longer consulted).
        profiles.set_profile(
            1,
            AccountProfile {
                email: "Acme Inc.".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // M4-13: step 2 removed; by_email wins.
        assert_eq!(
            profiles.get_email(1),
            Some("alice@example.com"),
            "M4-13: get_email MUST NOT consult extra[accounts][N]; by_email wins"
        );
    }

    /// RN1-A: `update_email` acquires `ProfilesFileLock` before its
    /// `load → mutate → save` cycle, serializing concurrent renames.
    ///
    /// Proved by holding the lock in a background thread, asserting the
    /// `update_email` call blocks, releasing the lock, and then confirming
    /// the update landed AND a pre-existing slot-1 entry was not lost.
    #[test]
    fn update_email_acquires_profiles_file_lock() {
        use std::time::Duration;

        // Arrange: create a profiles.json with a pre-existing slot-1 entry.
        let dir = TempDir::new().unwrap();
        {
            let mut initial = ProfilesFile::empty();
            initial.set_profile(
                1,
                AccountProfile {
                    email: "slot1@example.com".into(),
                    method: "oauth".into(),
                    extra: HashMap::new(),
                },
            );
            save(&profiles_path(dir.path()), &initial).unwrap();
        }

        let account2 = crate::types::AccountNum::try_from(2u16).unwrap();
        let dir_path = dir.path().to_path_buf();

        // Hold the ProfilesFileLock in a background thread.
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = ProfilesFileLock::acquire(&dir_path).unwrap();
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(5)).unwrap();
            // Lock is released when _lock drops at end of this scope.
        });

        // Wait until background thread holds the lock.
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("background thread must acquire lock");

        // Kick off update_email in another thread — it must block on the lock.
        // Signal-based handoff (not a sleep grace period): the update thread
        // signals `tx_attempting` immediately before the update_email call and
        // `tx_completed` immediately after it returns. Once `rx_attempting`
        // fires, the ONLY work between it and `tx_completed` is update_email's
        // own lock-acquire+load+save — so a `tx_completed` timeout while the
        // background thread holds the lock is a *structural* proof of blocking,
        // not a timing artifact. The residual gap (the `tx_attempting.send`
        // returning vs. the flock syscall being entered) is sub-millisecond and
        // independent of CI scheduling load (the thread is already running).
        let dir_path2 = dir.path().to_path_buf();
        let (tx_attempting, rx_attempting) = std::sync::mpsc::channel::<()>();
        let (tx_completed, rx_completed) = std::sync::mpsc::channel::<()>();
        let update_thread = std::thread::spawn(move || {
            tx_attempting.send(()).unwrap();
            update_email(&dir_path2, account2, "renamed@example.com").unwrap();
            tx_completed.send(()).unwrap();
        });

        // The update thread is alive and about to enter update_email.
        rx_attempting
            .recv_timeout(Duration::from_secs(2))
            .expect("update thread must reach the update_email call");

        // Assert: update_email cannot complete while the lock is held
        // externally. 500ms is a confidence window, not a race window — the
        // thread has already signaled it is at the call site, so the only
        // thing that can delay completion is the held lock.
        assert!(
            matches!(
                rx_completed.recv_timeout(Duration::from_millis(500)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "update_email must block while ProfilesFileLock is held by another thread"
        );

        // Release the background lock.
        tx_release.send(()).unwrap();

        // Assert: update_email completes after the lock is released.
        rx_completed
            .recv_timeout(Duration::from_secs(5))
            .expect("update_email must complete after ProfilesFileLock is released");
        update_thread.join().expect("update thread must not panic");

        // Assert: slot-2 rename landed.
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.get_email(2),
            Some("renamed@example.com"),
            "slot-2 rename must persist after lock released"
        );

        // Assert: pre-existing slot-1 extra["accounts"] entry was NOT lost (no lost-update).
        // M4-13: get_email no longer reads from extra["accounts"]; check via accounts_for_test.
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("1")
                .map(|p| p.email.as_str()),
            Some("slot1@example.com"),
            "slot-1 entry must survive concurrent update_email on slot 2"
        );
    }

    // ── RN1-D1 / Finding-3d C2 fix tests ───────────────────────────────────

    /// RN1-D1 (Finding-3d, C2 fix): `oauth_email_for_slot` has been retired.
    /// This test is a structural grep-audit: it asserts that no production
    /// callsite of `oauth_email_for_slot` remains outside test code.
    ///
    /// If this test description changes, update the acceptance-criteria mapping
    /// in the milestone task file.
    #[test]
    fn oauth_email_for_slot_retired() {
        // Structural invariant: `oauth_email_for_slot` no longer exists as a
        // production function. Any appearance in non-test Rust source is a
        // re-introduction of the C2 circular dependency (by_email → oauth_email
        // → write to by_email). The orchestrator grep audit verifies this
        // externally; this test documents the intent and serves as a named AC.
        //
        // The grep command to verify (run from repo root):
        //   grep -rn 'oauth_email_for_slot' --include='*.rs' csq-core/src \
        //     | grep -v '#\[cfg(test)\]' | grep -v '// '
        // Expected output: 0 lines.
        //
        // This test always passes (it is a documentation + naming anchor, not
        // a runtime assertion). The orchestrator grep is the runtime check.
        // Body intentionally empty — the test name + doc comment are the
        // named-AC anchor; an `assert!(true, …)` would trip
        // `clippy::assertions_on_constants`.
    }

    /// M4-13 (formerly RN1-D1 Finding-3d): `get_email` step 2 (accounts[N].email)
    /// was REMOVED in M4-13. With `by_slot_label` absent and only
    /// `by_slot[N] → UUID → by_email[oauth_email]` available, `get_email`
    /// now returns the canonical OAuth email from `by_email`. The v1
    /// rename label in `extra["accounts"]` is no longer consulted.
    #[test]
    fn get_email_falls_through_to_by_email_when_accounts_removed_m4_13() {
        // Arrange: slot 1 has a residual accounts entry (stored via extra["accounts"])
        // and a by_slot → by_email chain.
        let uuid = IdentityId::new_v4();
        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("1".into(), uuid);
        profiles
            .by_email
            .insert("real@oauth.example.com".into(), uuid);
        // Simulate residual v1 on-disk entry via the test helper.
        profiles.set_profile(
            1,
            AccountProfile {
                email: "My Custom Label".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // Act: get_email uses the 2-step resolution (M4-13): by_slot_label → by_slot→UUID→by_email.
        let label = profiles.get_email(1);

        // Assert: M4-13 drops step 2; by_email wins over extra["accounts"].email.
        assert_eq!(
            label,
            Some("real@oauth.example.com"),
            "M4-13: get_email MUST NOT consult extra[accounts][N].email; by_email wins"
        );
    }

    // ─── M2 — get_email step 1.5 tests ───────────────────────────────────────

    /// M2: `get_email` returns the `by_slot_identity` value (step 1.5) when
    /// no `by_slot_label` entry (step 1) is present.
    ///
    /// The only populated channel is `by_slot_identity["9"] = "apikey:mm"`.
    /// Step 1 is absent, so step 1.5 wins.
    #[test]
    fn get_email_resolves_by_slot_identity_when_no_rename_label() {
        // Arrange: only by_slot_identity populated for slot 9.
        let mut pf = ProfilesFile::empty();
        pf.by_slot_identity.insert("9".into(), "apikey:mm".into());

        // Act
        let result = pf.get_email(9);

        // Assert: step 1.5 wins.
        assert_eq!(
            result,
            Some("apikey:mm"),
            "get_email must return by_slot_identity value when by_slot_label is absent"
        );
        // Unrelated slots return None.
        assert_eq!(pf.get_email(1), None, "unrelated slot must return None");
    }

    /// M2: `get_email` returns `by_slot_label` (step 1) even when
    /// `by_slot_identity` (step 1.5) is ALSO populated for the same slot.
    ///
    /// Step 1 (user rename) always wins over step 1.5 (backfilled identity).
    #[test]
    fn get_email_prefers_by_slot_label_over_by_slot_identity() {
        // Arrange: both channels populated for slot 9.
        let mut pf = ProfilesFile::empty();
        pf.by_slot_label.insert("9".into(), "my-mm".into());
        pf.by_slot_identity.insert("9".into(), "apikey:mm".into());

        // Act
        let result = pf.get_email(9);

        // Assert: step 1 (by_slot_label) wins.
        assert_eq!(
            result,
            Some("my-mm"),
            "by_slot_label must win over by_slot_identity when both are populated"
        );
    }

    /// M4-13: `get_email` step 2 (accounts[N].email) was REMOVED. When only
    /// `extra["accounts"]` is populated (no step-1, step-1.5, or by_slot chain),
    /// `get_email` returns None — the legacy entry is no longer consulted.
    #[test]
    fn get_email_returns_none_when_only_extra_accounts_populated_m4_13() {
        // Arrange: only extra["accounts"][N] via set_profile; no step-1, step-1.5,
        // or by_slot→by_email chain.
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            3,
            AccountProfile {
                email: "old@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // Act
        let result = pf.get_email(3);

        // Assert: M4-13 drops step 2; no by_slot chain → None.
        assert_eq!(
            result,
            None,
            "M4-13: get_email MUST NOT consult extra[accounts][N].email; no recovery channel → None"
        );
    }

    // ─── M3 — set_slot_identity tests ────────────────────────────────────────

    /// M3: `set_slot_identity` writes `by_slot_identity[9]` and preserves all
    /// other fields (accounts, by_slot, by_slot_label for slot 5) unchanged.
    #[test]
    fn set_slot_identity_persists_and_preserves_others() {
        // Arrange: existing file with slot 5 populated in multiple channels.
        let dir = TempDir::new().unwrap();
        let uuid_5 = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("5".into(), uuid_5);
        pf.by_slot_label.insert("5".into(), "Slot 5 Label".into());
        pf.set_profile(
            5,
            AccountProfile {
                email: "slot5@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act: write identity for slot 9 — unrelated to slot 5.
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        set_slot_identity(&lock, dir.path(), 9, "apikey:mm").unwrap();

        // Assert: by_slot_identity[9] is persisted.
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be persisted"
        );
        // Slot 5 fields are preserved unchanged.
        assert_eq!(
            loaded.by_slot.get("5").copied(),
            Some(uuid_5),
            "by_slot[5] must be preserved"
        );
        assert_eq!(
            loaded.by_slot_label.get("5").map(|s| s.as_str()),
            Some("Slot 5 Label"),
            "by_slot_label[5] must be preserved"
        );
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("5")
                .map(|p| p.email.as_str()),
            Some("slot5@example.com"),
            "accounts[5].email must be preserved in extra (M4-13)"
        );
    }

    /// M3: `set_slot_identity` is idempotent — calling it twice with the
    /// same value does not change the file on the second call (mtime/bytes
    /// unchanged via byte-comparison).
    #[test]
    fn set_slot_identity_is_idempotent_no_mtime_change() {
        // Arrange: write initial value.
        let dir = TempDir::new().unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        set_slot_identity(&lock, dir.path(), 9, "apikey:mm").unwrap();

        // Capture the file bytes after the first write.
        let path = profiles_path(dir.path());
        let bytes_after_first = std::fs::read(&path).unwrap();

        // Act: call again with the same value.
        set_slot_identity(&lock, dir.path(), 9, "apikey:mm").unwrap();

        // Assert: file bytes are unchanged (idempotent — no new write).
        let bytes_after_second = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes_after_first, bytes_after_second,
            "set_slot_identity must not rewrite the file when the value is unchanged"
        );
    }

    // ─── M4 — swap_slot_mapping by_slot_identity tests ───────────────────────

    /// M4: `swap_slot_mapping` swaps `by_slot_identity` entries alongside
    /// `by_slot` and `by_slot_label` entries when `csq move FROM TO` is
    /// executed.
    #[test]
    fn swap_slot_mapping_swaps_by_slot_identity_on_move() {
        // Arrange: two slots with UUIDs, labels, and identity entries.
        let dir = TempDir::new().unwrap();
        let uuid_3 = IdentityId::new_v4();
        let uuid_7 = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("3".into(), uuid_3);
        pf.by_slot.insert("7".into(), uuid_7);
        pf.by_slot_identity.insert("3".into(), "apikey:mm".into());
        pf.by_slot_identity
            .insert("7".into(), "codex-7/fixture-prefix".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act: swap slots 3 and 7.
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let swapped = swap_slot_mapping(&lock, dir.path(), 3, 7).unwrap();

        // Assert: swap was performed.
        assert!(swapped, "swap_slot_mapping must return true");

        let loaded = load(&profiles_path(dir.path())).unwrap();
        // by_slot_identity must have swapped.
        assert_eq!(
            loaded.by_slot_identity.get("3").map(|s| s.as_str()),
            Some("codex-7/fixture-prefix"),
            "by_slot_identity[3] must now hold the identity that was at slot 7"
        );
        assert_eq!(
            loaded.by_slot_identity.get("7").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[7] must now hold the identity that was at slot 3"
        );
        // UUIDs must have swapped too.
        assert_eq!(
            loaded.by_slot.get("3").copied(),
            Some(uuid_7),
            "by_slot[3] must hold uuid_7 after swap"
        );
        assert_eq!(
            loaded.by_slot.get("7").copied(),
            Some(uuid_3),
            "by_slot[7] must hold uuid_3 after swap"
        );
    }

    // ─── F-C-1 regression tests ──────────────────────────────────────────────

    /// F-C-1 regression: `swap_slot_mapping` MUST swap `by_slot_identity`
    /// even when NEITHER slot has a `by_slot` UUID (the default state for
    /// 3P API-key and Codex slots).  The old early-return on
    /// `uuid_a.is_none() && uuid_b.is_none()` silently dropped the swap.
    ///
    /// Fixture: ONLY `by_slot_identity` populated — NO `by_slot` entries.
    /// This is the exact production shape for non-OAuth slots.
    #[test]
    fn swap_slot_mapping_swaps_non_oauth_only_no_by_slot_uuid() {
        // Arrange: two non-OAuth slots with by_slot_identity but NO by_slot UUID.
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot_identity.insert("9".into(), "apikey:mm".into());
        pf.by_slot_identity
            .insert("14".into(), "apikey:ollama".into());
        // Deliberately NO entries in pf.by_slot — this is the non-OAuth slot shape.
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act: swap slots 9 and 14.
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let result = swap_slot_mapping(&lock, dir.path(), 9, 14).unwrap();

        // Assert: returns Ok(true) — NOT the early-return Ok(false).
        assert!(
            result,
            "F-C-1: swap_slot_mapping must return true for non-OAuth slots \
             that have by_slot_identity but no by_slot UUID"
        );

        let loaded = load(&profiles_path(dir.path())).unwrap();

        // by_slot_identity must have swapped.
        assert_eq!(
            loaded.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:ollama"),
            "F-C-1: by_slot_identity[9] must now hold the identity that was at slot 14"
        );
        assert_eq!(
            loaded.by_slot_identity.get("14").map(|s| s.as_str()),
            Some("apikey:mm"),
            "F-C-1: by_slot_identity[14] must now hold the identity that was at slot 9"
        );

        // by_slot must remain empty (no UUIDs were added).
        assert!(
            loaded.by_slot.is_empty(),
            "F-C-1: by_slot must remain empty — no UUIDs exist for non-OAuth slots"
        );
    }

    /// F-C-1 parallel: `swap_slot_mapping` MUST swap `by_slot_label`
    /// even when NEITHER slot has a `by_slot` UUID (pre-existing class-1
    /// bug newly relevant for non-OAuth user renames).
    ///
    /// Fixture: ONLY `by_slot_label` populated — NO `by_slot` entries.
    #[test]
    fn swap_slot_mapping_swaps_by_slot_label_only_no_by_slot_uuid() {
        // Arrange: two slots with labels but no UUIDs.
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot_label.insert("3".into(), "Work".into());
        pf.by_slot_label.insert("7".into(), "Personal".into());
        // No by_slot entries.
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let result = swap_slot_mapping(&lock, dir.path(), 3, 7).unwrap();

        // Assert: returns Ok(true).
        assert!(
            result,
            "swap_slot_mapping must return true when only by_slot_label entries exist"
        );

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("3").map(|s| s.as_str()),
            Some("Personal"),
            "by_slot_label[3] must hold the label that was at slot 7"
        );
        assert_eq!(
            loaded.by_slot_label.get("7").map(|s| s.as_str()),
            Some("Work"),
            "by_slot_label[7] must hold the label that was at slot 3"
        );
        assert!(loaded.by_slot.is_empty(), "by_slot must remain empty");
    }

    // ─── M5 — prune arm-4 tests ───────────────────────────────────────────────

    /// M5 arm-4: an `accounts[N]` entry whose email equals `by_slot_identity[N]`
    /// is information-recoverable via step 1.5 → pruned.
    #[test]
    fn prune_removes_entry_covered_by_by_slot_identity() {
        // Arrange: accounts["9"].email == by_slot_identity["9"] = "apikey:mm".
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            9,
            AccountProfile {
                email: "apikey:mm".into(),
                method: "api_key".into(),
                extra: HashMap::new(),
            },
        );
        pf.by_slot_identity.insert("9".into(), "apikey:mm".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        // Assert: entry pruned via arm 4.
        assert_eq!(report.pruned, 1, "arm-4 covered entry must be pruned");
        assert_eq!(report.pruned_by_identity_channel, 1);
        assert_eq!(report.kept_unrecoverable, 0);
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            !loaded.accounts_for_test().contains_key("9"),
            "accounts[9] must be removed after arm-4 prune"
        );
        // by_slot_identity is preserved.
        assert_eq!(
            loaded.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be preserved after prune"
        );
    }

    /// M5 arm-4 safety: when `by_slot_identity[N]` and `accounts[N].email`
    /// DIVERGE, the entry MUST be kept (information would be lost if pruned).
    #[test]
    fn prune_keeps_entry_when_by_slot_identity_diverges() {
        // Arrange: accounts["9"].email = "apikey:mm" but
        //          by_slot_identity["9"] = "apikey:zai" — divergent labels.
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            9,
            AccountProfile {
                email: "apikey:mm".into(),
                method: "api_key".into(),
                extra: HashMap::new(),
            },
        );
        pf.by_slot_identity.insert("9".into(), "apikey:zai".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        // Act
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();

        // Assert: entry is kept (divergent identity → information-lossy to prune).
        assert_eq!(
            report.pruned, 0,
            "divergent-identity entry MUST NOT be pruned"
        );
        assert_eq!(report.pruned_by_identity_channel, 0);
        assert_eq!(
            report.kept_unrecoverable, 1,
            "divergent entry must be counted as kept_unrecoverable"
        );
        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            loaded.accounts_for_test().contains_key("9"),
            "accounts[9] must be preserved when by_slot_identity diverges"
        );
    }

    /// M5 arm-4 idempotency: a second prune run is a no-op after the first
    /// run already removed the arm-4 covered entry.
    #[test]
    fn prune_arm_4_is_idempotent() {
        // Arrange: same as prune_removes_entry_covered_by_by_slot_identity.
        let dir = TempDir::new().unwrap();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            9,
            AccountProfile {
                email: "apikey:mm".into(),
                method: "api_key".into(),
                extra: HashMap::new(),
            },
        );
        pf.by_slot_identity.insert("9".into(), "apikey:mm".into());
        save(&profiles_path(dir.path()), &pf).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();

        // First run: prunes the entry.
        let r1 = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();
        assert_eq!(r1.pruned, 1);
        assert_eq!(r1.pruned_by_identity_channel, 1);

        // Second run: accounts is already empty — no-op.
        let r2 = prune_redundant_accounts_entries(&lock, dir.path()).unwrap();
        assert_eq!(
            r2.pruned, 0,
            "second prune run must be a no-op (idempotent)"
        );
        assert_eq!(r2.pruned_by_identity_channel, 0);

        let loaded = load(&profiles_path(dir.path())).unwrap();
        assert!(
            loaded.accounts_for_test().is_empty(),
            "accounts map must be empty after two prune runs"
        );
    }
}
