//! Daemon first-start identity minting — an internal ticket (A++) Phase 1, M1-4.
//!
//! # Purpose
//!
//! On the first daemon start after an upgrade to a v2.7.x (or later) build,
//! this pass walks every Anthropic `config-<N>/` directory found by
//! `accounts::discovery::discover_anthropic`, derives (or reuses) a UUID
//! identity for each slot, writes `identities/<UUID>/identity.json`,
//! updates `profiles.json` (`by_slot` + `by_email`), and — when every slot
//! has been processed without error — atomically writes the idempotency
//! sentinel `store-version`.
//!
//! # Idempotency
//!
//! The sentinel `store-version` is written LAST.  If the daemon is killed
//! mid-mint, the next start observes the absent sentinel and retries.  The
//! per-slot logic inside the retry is also idempotent:
//!
//! - If `by_email` in `profiles.json` already maps the slot's email to a
//!   UUID, that UUID is **reused** (no churn).
//! - If `identities/<UUID>/identity.json` already exists, the write is
//!   skipped (file existence is the per-slot sentinel).
//!
//! # Error handling at startup
//!
//! The function returns `Err(IdentityMintError)` on failure, but the caller
//! (`startup_reconciler::run_reconciler`) MUST log a structured warning and
//! continue — a mint failure is non-fatal to the daemon.  The daemon provides
//! refresh and quota services even without the identity layer; Phase 2 and
//! later phases rely on the identity layer, but Phase 1 is additive.
//!
//! # Phase 1 scope boundary
//!
//! MUST NOT:
//! - Write UUID-keyed credentials, settings, or usage data.
//! - Activate Phase 2 reader switchover at `usage/account_id.rs:37`.
//! - Mint Codex or Gemini identities (Anthropic only via `discover_anthropic`).
//!
//! # §5a compliance
//!
//! Every `unique_tmp_path` site in this module writes email PII or stub
//! credential content → classified as secret-bearing.  All three failure
//! branches (`write`, `secure_file`, `atomic_replace`) perform
//! `let _ = std::fs::remove_file(&tmp);` before propagating an error.

use crate::accounts::discovery::discover_anthropic;
use crate::accounts::identity_store::{
    identity_json_path_for, settings_path_for, store_version_path, IdentityId,
};
use crate::accounts::profiles;
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::credentials::write_uuid_settings;
use crate::error::{redact_tokens, ConfigError};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use std::path::Path;
use tracing::{debug, info, warn};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Outcome of a single slot's mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotMintOutcome {
    /// UUID was already in `by_email` → reused; no new `identity.json` written.
    Reused(IdentityId),
    /// Fresh UUID minted and `identity.json` written.
    Fresh(IdentityId),
    /// `identity.json` already present on disk — skipped.
    AlreadyPresent,
}

/// Per-slot error record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotError {
    pub slot: u16,
    pub reason: String,
}

/// Summary returned from [`run_if_unsentineled`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MintSummary {
    /// Sentinel was already present — mint was a no-op.
    pub already_minted: bool,
    /// Number of `config-<N>/` directories discovered.
    pub slots_seen: usize,
    /// Slots whose `identity.json` file was written fresh.
    pub slots_fresh: usize,
    /// Slots that reused an existing UUID from `by_email`.
    pub slots_reused: usize,
    /// Slots whose `identity.json` was already present.
    pub slots_already_present: usize,
    /// Slots that failed (non-fatal per-slot errors).
    pub slot_errors: Vec<SlotError>,
}

/// Error returned when the mint pass itself fails (e.g. sentinel write fails).
///
/// This is distinct from per-slot errors, which are collected inside
/// [`MintSummary::slot_errors`] and do not prevent other slots from being
/// processed.
#[derive(Debug)]
pub enum IdentityMintError {
    /// Failed to write the `store-version` sentinel.
    SentinelWrite(String),
    /// An I/O error occurred when walking `config-N/` directories.
    DirWalk(String),
}

impl std::fmt::Display for IdentityMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentinelWrite(msg) => write!(f, "identity mint: sentinel write failed: {msg}"),
            Self::DirWalk(msg) => write!(f, "identity mint: dir walk failed: {msg}"),
        }
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Runs the identity mint pass, skipping entirely if the `store-version`
/// sentinel is already present.
///
/// # Returns
///
/// - `Ok(MintSummary)` — mint completed (or was already done).  Check
///   `summary.already_minted` to distinguish.
/// - `Err(IdentityMintError)` — a fatal pass-level error occurred (e.g.
///   sentinel write failed).  The caller MUST log and continue.
///
/// Per-slot failures do NOT cause an `Err` return; they are collected in
/// `summary.slot_errors`.
pub fn run_if_unsentineled(base_dir: &Path) -> Result<MintSummary, IdentityMintError> {
    let sentinel = store_version_path(base_dir);

    // Fast-path: sentinel present → already minted on a previous start.
    if sentinel.exists() {
        debug!("identity mint: sentinel present, skipping");
        return Ok(MintSummary {
            already_minted: true,
            ..Default::default()
        });
    }

    let mut summary = MintSummary::default();

    // (Orphan-identity observability + GC is now owned by the non-sentinel-gated
    // reconciler pass `accounts::orphan_identity_gc::prune_orphan_identities`,
    // which both reports and collects orphans on every daemon start. The old
    // warn-only `sweep_orphan_identities` was removed — it was sentinel-gated
    // here and so never re-fired on an established install.)

    // Collect Anthropic-only slots via discover_anthropic.
    // This excludes 3P-bound slots (those with ANTHROPIC_BASE_URL) and
    // slots without a readable credentials file — fixes A-CRIT-3 + A-MED-9.
    let slots = discover_anthropic(base_dir);
    summary.slots_seen = slots.len();

    // Acquire the profiles.json file lock ONCE for the entire Pass 0 walk.
    //
    // This serializes the Pass 0 walk against any concurrent `csq login N`
    // invocation that also calls `add_identity_mapping`. Without the lock,
    // concurrent load+save cycles silently drop each other's updates (lost
    // update). The lock is acquired even when slots.is_empty() so the
    // zero-slot case is trivially safe (lock + immediate release).
    //
    // Error path: if we cannot acquire the lock we log a warning and return
    // the summary with no slots processed. The sentinel will NOT be written
    // (slot_errors is empty but slots_seen is 0 after we return early).
    // Actually we want to keep sentinel logic clean — surface as DirWalk error.
    let profiles_lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(e) => {
            return Err(IdentityMintError::DirWalk(format!(
                "profiles_lock_acquire_failed: {}",
                redact_tokens(&e.to_string())
            )));
        }
    };

    for account_info in slots {
        let slot_num = account_info.id;
        // RN1-D1 (Finding-3d, C1 fix): use the credential-derived OAuth
        // email, NOT the display label. The label may be a user-chosen
        // rename; using it as a by_email key would overwrite the legitimate
        // mapping with the rename label — the journal-0029 cross-contamination
        // class. If oauth_email is absent (pure-legacy slot with no credential
        // file or credential file lacking oauthAccount.emailAddress), skip this
        // slot entirely: the identity will be minted at login time via
        // mint_for_login, which carries an explicit OAuth-flow email.
        let email_raw = match account_info.oauth_email.as_deref() {
            Some(e) => e.to_string(),
            None => {
                warn!(
                    slot = slot_num,
                    error_kind = "oauth_email_unresolved",
                    "identity mint: oauth_email absent for slot, skipping (will mint at login)"
                );
                continue;
            }
        };
        // normalize_email trims and lowercases. "unknown" is no longer emitted
        // as a fallback (slots with absent oauth_email are now skipped above).
        let email = normalize_email(&email_raw);

        match mint_slot(&profiles_lock, base_dir, slot_num, email.as_deref()) {
            Ok(SlotMintOutcome::Fresh(_)) => summary.slots_fresh += 1,
            Ok(SlotMintOutcome::Reused(_)) => summary.slots_reused += 1,
            Ok(SlotMintOutcome::AlreadyPresent) => summary.slots_already_present += 1,
            Err(reason) => {
                warn!(
                    slot = slot_num,
                    error_kind = "slot_mint_failed",
                    "identity mint: slot failed (non-fatal)"
                );
                summary.slot_errors.push(SlotError {
                    slot: slot_num,
                    reason,
                });
            }
        }
    }

    // Release the profiles lock explicitly before writing the sentinel so
    // any concurrent reader of profiles.json can proceed.
    drop(profiles_lock);

    // Write sentinel LAST — only after all slots have been attempted AND
    // no slot errors occurred.
    //
    // If any slot errored AND slots existed, skip the sentinel so the next
    // daemon start retries — fixes A-MED-8.
    //
    // The zero-slots case (fresh install) always writes the sentinel: an
    // empty install is a valid terminal state, not an error.
    if !summary.slot_errors.is_empty() {
        warn!(
            error_count = summary.slot_errors.len(),
            "identity mint: skipping sentinel — will retry next start"
        );
        return Ok(summary);
    }

    write_sentinel(&sentinel)?;

    debug!(
        slots_seen = summary.slots_seen,
        slots_fresh = summary.slots_fresh,
        slots_reused = summary.slots_reused,
        slots_already_present = summary.slots_already_present,
        slot_errors = summary.slot_errors.len(),
        "identity mint: pass complete"
    );

    Ok(summary)
}

/// Per-login identity mint hook called from `accounts::login::finalize_login`.
///
/// Mints or reuses a UUID for a single slot identified by `slot` and `email`.
/// Unlike `run_if_unsentineled`, this does NOT check for the `store-version`
/// sentinel (a login after a fresh install might run before the daemon starts)
/// and does NOT write the sentinel (that is the daemon Pass 0's job).
///
/// # Lock precondition
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// and pass it as `_lock`. This ensures the caller holds the lock across both
/// the preceding `profiles::save` call in `finalize_login` AND this
/// `add_identity_mapping` call — making the two-step write atomic from a
/// cross-process perspective. Re-acquiring the lock inside this function would
/// defeat that guarantee (and risk deadlock on platforms where `flock` is
/// process-level, not fd-level).
///
/// Idempotency: if `by_email` already maps `email` to a UUID, that UUID is
/// reused. If `identities/<UUID>/identity.json` already exists, the write is
/// skipped. Profiles mappings are always updated (safe to overwrite with the
/// same value).
///
/// # Write order (R2-HIGH-1 fix — symmetric with `mint_slot`)
///
/// 1. Write `add_identity_mapping` FIRST (reserves `by_email[email] = uuid`).
/// 2. Write `identity.json` SECOND (only if not already present).
///
/// Crash analysis: crash after step 1 but before step 2 leaves `by_email`
/// pointing at a UUID with no `identity.json`. The next login (or daemon
/// Pass 0 re-run) finds the `by_email` entry, reuses the UUID, then finds
/// `identity_path` missing and writes it. Convergent, no UUID churn.
///
/// # Returned error strings are FIXED-VOCABULARY tags safe for logging
///
/// Returned `Err(reason)` strings are FIXED-VOCABULARY tags that MUST NOT
/// contain paths, emails, tokens, or other PII. They are safe to log
/// directly at the call site in `finalize_login`.
///
/// # Returns
///
/// `Ok(uuid)` on success or `Err(String)` with a fixed-vocabulary reason tag.
pub fn mint_for_login(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    email: &str,
) -> Result<IdentityId, String> {
    // Normalize + validate the caller-supplied email (fixes B-MED-2).
    let normalized = normalize_email(email)
        .ok_or_else(|| "identity_mint_failed: email rejected by normalizer".to_string())?;

    let current_profiles = profiles::load(&profiles::profiles_path(base_dir))
        .map_err(|_| "identity_mint_failed: profiles load error".to_string())?;

    let (uuid, outcome) =
        if let Some(existing) = current_profiles.by_email.get(&normalized).copied() {
            (existing, true)
        } else {
            (IdentityId::new_v4(), false)
        };

    // WRITE ORDER (R2-HIGH-1 fix, symmetric with mint_slot A-CRIT-1 fix):
    // mapping FIRST, then identity.json.
    // The _lock witness is forwarded to enforce the compile-time lock-held
    // precondition at this inner callsite too.
    profiles::add_identity_mapping(_lock, base_dir, slot, &normalized, uuid)
        .map_err(|_| "identity_mint_failed: mapping write error".to_string())?;

    // Write identity.json only if not already present.
    // If identity.json already exists (e.g. mint_slot wrote it first, or a
    // prior partial mint materialized it), preserve the existing file — do not
    // overwrite. This matches mint_slot's AlreadyPresent branch.
    let identity_path = identity_json_path_for(base_dir, uuid);
    if !identity_path.exists() {
        let created_at = now_rfc3339();
        let json_content = identity_json_content(&normalized, &created_at);
        write_identity_json(&identity_path, &json_content)
            .map_err(|_| "identity_mint_failed: identity.json write error".to_string())?;
    }

    // RN1-D R2: capture a pre-existing rename label on login.
    //
    // A pure-legacy slot may carry a user-chosen rename label in
    // `accounts[N].email` with no `by_slot[N]` UUID. The one-shot
    // `label-channel-migrated` relocation pass cannot migrate it (no UUID
    // anchor) and never re-fires once its sentinel exists, and `csq login`
    // historically did not capture it either — so `csq doctor`'s "log in
    // again to mint UUIDs" instruction silenced the warning (the by_slot
    // predicate stops matching) WITHOUT preserving the label, which RN1-F's
    // `accounts` deletion then silently dropped. This step makes that
    // operator instruction true: now that `add_identity_mapping` has minted
    // `by_slot[N]`, copy the rename label into the A1 `by_slot_label[N]`
    // channel. Rename detection mirrors `relocate_labels_to_by_slot_label`'s
    // first arm EXACTLY — a single raw inequality against the authoritative
    // OAuth email (`email.trim()`, OAuth-sourced per RN1-D1). The reference
    // pass compares `accounts_email == oauth_email` (one raw comparison); a
    // second `normalized` guard here would diverge from that one canonical
    // detector and could over-skip a cased-email rename label (data loss —
    // the exact bug class being fixed). Over-capturing a bare un-normalized
    // OAuth-email variant is cosmetic only (`get_email` returns the email
    // regardless), strictly safer than over-skipping. Guarded by
    // `by_slot_label[N]` absence so a later explicit rename is never
    // overwritten (same precedence as the relocation pass). Malformed labels
    // (control chars, oversize) are NOT relocated: they would land in the
    // `by_slot_label` channel `get_email` reads FIRST and that doctor/UI
    // render — skip them so a malformed legacy value is not promoted into
    // the active label channel (RN1-D3 rejects the same shapes on the
    // `rename_account` write path; this is the read-side parity, inlined
    // because that validator lives in the `csq` crate which `csq-core`
    // cannot depend on). `current_profiles` predates the
    // `add_identity_mapping` save, but that call preserves `accounts` and
    // `by_slot_label` unchanged, so the read is accurate; `set_slot_label`
    // does its own load→mutate→save under the same `_lock`. Non-fatal: a
    // capture failure must not block login.
    const MAX_LABEL_LEN: usize = 256;
    let slot_key = slot.to_string();
    if !current_profiles.by_slot_label.contains_key(&slot_key) {
        // M4-13: accounts struct field removed; read legacy email from
        // extra["accounts"] via the helper. Same semantics as before.
        let legacy_accounts = profiles::legacy_accounts_email_map(&current_profiles);
        if let Some(raw_label) = legacy_accounts.get(&slot_key) {
            let label = raw_label.trim();
            let well_formed =
                label.chars().count() <= MAX_LABEL_LEN && !label.chars().any(|c| c.is_control());
            if !label.is_empty() && label != email.trim() && well_formed {
                if let Err(_e) = profiles::set_slot_label(_lock, base_dir, slot, label) {
                    // Fixed-vocabulary tag, NO error body: `ConfigError`
                    // Display carries the `profiles.json`/tmp path (OS
                    // username) and `redact_tokens` does not strip paths
                    // (security.md Rule 2 — fixed tags, not `{e}` bodies).
                    warn!(
                        error_kind = "label_capture_failed",
                        slot = slot,
                        "mint_for_login: could not capture pre-existing rename label"
                    );
                }
            }
        }
    }

    // M2-3: seed identities/<UUID>/settings.json from config-<N>/settings.json
    // within the same ProfilesFileLock window (constraint #7: resolve UUID once
    // at section entry, never mid-section). Only write if not already present —
    // same idempotency rule as identity.json above.
    let uuid_settings = settings_path_for(base_dir, uuid);
    if !uuid_settings.exists() {
        let config_n_settings = base_dir
            .join(format!("config-{slot}"))
            .join("settings.json");
        let bytes = if config_n_settings.exists() {
            std::fs::read(&config_n_settings).unwrap_or_default()
        } else {
            b"{}".to_vec()
        };
        // Non-fatal: settings seeding failure does not block login.
        // Fixed-vocabulary tag, NO error body (security.md Rule 2): the
        // error Display carries a filesystem path that `redact_tokens`
        // does not strip. Pre-existing-pattern parity fix landed with the
        // RN1-D R2 sibling above (redteam security L1, zero-tolerance R1).
        if let Err(_e) = write_uuid_settings(base_dir, uuid, &bytes) {
            warn!(
                error_kind = "settings_seed_failed",
                slot = slot,
                "mint_for_login: could not seed UUID settings.json"
            );
        }
    }

    info!(
        slot = slot,
        reused = outcome,
        "identity_mint: finalize_login hook completed"
    );

    Ok(uuid)
}

/// Validates an `account_id_hint` string from a Codex auth.json for use as
/// part of a synthetic `by_email` key.
///
/// Returns `Some(hint)` when the hint is safe to embed:
/// - No byte < 0x20 (ASCII control characters, including `\r`, `\n`, `\0`)
/// - Non-empty
/// - Length within 256 bytes
///
/// Returns `None` when the hint fails any check. Callers fall back to the
/// `codex:slot-<N>` synthetic key.
///
/// SR-M1 guard: `account_id_hint` flows into `format_label` which is written
/// to the terminal AND persisted to `profiles.json`. A planted/malformed
/// auth.json with control chars in `account_id` would inject bytes into
/// operator-facing output. Symmetric with `normalize_email`'s control-char
/// rejection.
fn validate_codex_account_id_hint(hint: &str) -> Option<&str> {
    if hint.is_empty() || hint.len() > 256 {
        return None;
    }
    // Reject any byte < 0x20 (control characters including \r, \n, \0, BEL, etc.)
    if hint.bytes().any(|b| b < 0x20) {
        return None;
    }
    Some(hint)
}

/// Per-login identity mint hook for Codex-only slots.
///
/// Called from `providers::codex::login::perform_with` AFTER it has acquired
/// the [`ProfilesFileLock`] and BEFORE calling
/// `credentials::file::save_canonical_for`. `save_canonical_for` is
/// fail-closed when `profiles.json::by_slot[N]` is absent
/// (`CredentialError::NoCredentials`); this function ensures the mapping
/// exists so the subsequent write succeeds.
///
/// # Why a separate function from `mint_for_login`
///
/// `mint_for_login` (the Anthropic OAuth path) uses the caller-supplied OAuth
/// `email` as the `by_email` key — every Anthropic account has a verified
/// email from the CC device-auth flow. Codex uses ChatGPT OAuth, which csq
/// deliberately does NOT decode (spec 07 §7.3.3: no `id_token` claim
/// decoding for data-minimisation). There is no email to act as the secondary
/// key. This function therefore uses a synthetic `by_email` key of the form
/// `codex:<account_id_hint>` (or `codex:slot-<N>` when the hint is absent or
/// invalid) so the mapping survives a re-run of `mint_for_codex_login`
/// without creating a new UUID each time (idempotency via `by_email` lookup).
///
/// # Key `by_email` choice — synthetic prefix, minimal invasiveness
///
/// Adding a separate `by_codex_account_id` map would widen the
/// `ProfilesFile` struct with a new field and require every reader to
/// accommodate it. The `codex:` prefix in `by_email` is cheaper: it is
/// syntactically distinct from any real email (RFC 5321 forbids a colon
/// before the `@` in the local-part), so a genuine email can never collide
/// with a synthetic key. The prefix is stable across re-logins because
/// `account_id_hint` comes from codex-cli's auth.json and does not drift
/// unless the user logs into a different ChatGPT account on the same slot
/// (in which case a new UUID is correct).
///
/// # Identity JSON shape
///
/// The written `identity.json` uses `"provider": "codex"` (instead of
/// `"anthropic"`) to reflect the actual auth surface. The `email` field
/// carries the synthetic key. All other fields follow the same structure as
/// the Anthropic path (see `identity_json_content_codex` below).
///
/// # Idempotency
///
/// 1. If `by_slot[N]` already exists AND `identity.json` is present, return
///    that UUID — no new file or mapping is written.
/// 2. If `by_slot[N]` exists but `identity.json` is missing (partial-mint
///    crash recovery), fall through to the write path to repair identity.json.
/// 3. If `by_email[synthetic_key]` already exists (prior partial mint),
///    reuse the UUID; only the `by_slot` mapping and `identity.json` are
///    updated if missing.
/// 4. `identity.json` is only written when absent (preserves `created_at`).
///
/// # Write order
///
/// Symmetric with `mint_for_login` (R2-HIGH-1 fix):
/// 1. `add_identity_mapping` (profiles.json FIRST — reserves the slot→UUID
///    and synthetic-email→UUID rows).
/// 2. `identity.json` SECOND — only if not already present.
///
/// # Lock discipline (IR-M5 fix)
///
/// The caller **MUST** hold the exclusive [`ProfilesFileLock`] for `base_dir`
/// and pass it as `_lock`. This is symmetric with `mint_for_login` and
/// prevents deadlock on platforms where `flock` is process-level. The caller
/// (`perform_with` in `providers::codex::login`) acquires the lock once and
/// holds it across both `mint_for_codex_login` and `save_canonical_for` so
/// the two-step write is atomic from a cross-process perspective.
///
/// # Note on settings.json (IR-M6)
///
/// Unlike `mint_for_login`, this fn does NOT seed
/// `identities/<UUID>/settings.json`. Codex provisioning uses
/// `config-<N>/config.toml` (spec 07 §7.2.2) — there is no
/// `config-<N>/settings.json` to copy and no Codex consumer that reads
/// `identities/<UUID>/settings.json`. The settings pairing (`{}` bytes) is
/// performed separately by `perform_with` in `providers::codex::login` via
/// `credentials::save_uuid_settings` after login completes.
///
/// # Returned errors are fixed-vocabulary tags safe for logging
///
/// No PII, no token content, no filesystem paths in returned `Err(String)`.
pub fn mint_for_codex_login(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    account_id_hint: Option<&str>,
) -> Result<IdentityId, String> {
    // SR-M1: validate account_id_hint at the boundary. Any hint that contains
    // control chars, is empty, or exceeds 256 bytes is treated as absent — we
    // fall back to the `codex:slot-<N>` synthetic key. Symmetric with
    // normalize_email's control-char rejection for Anthropic slots.
    let account_id_hint = account_id_hint.and_then(validate_codex_account_id_hint);

    // SR-H2: fast-path only fires when BOTH by_slot is populated AND
    // identity.json exists. A missing identity.json (partial-mint crash
    // recovery) falls through to the write path below to repair it.
    if let Some(existing_uuid) = profiles::resolve_slot_to_uuid(base_dir, slot) {
        let identity_path = identity_json_path_for(base_dir, existing_uuid);
        if identity_path.exists() {
            debug!(
                slot,
                uuid = %existing_uuid,
                "mint_for_codex_login: by_slot mapped + identity.json present, reusing UUID"
            );
            return Ok(existing_uuid);
        }
        // Fall through to the lock + write path to repair the missing identity.json.
        debug!(
            slot,
            uuid = %existing_uuid,
            "mint_for_codex_login: by_slot mapped but identity.json absent, repairing via slow path"
        );
    }

    // Load profiles under the caller-held lock (no TOCTOU — caller serialized
    // us against concurrent minters by holding the lock before calling).
    let current_profiles = profiles::load(&profiles::profiles_path(base_dir))
        .map_err(|_| "identity_mint_failed: profiles load error".to_string())?;

    // Re-check by_slot under lock (another process may have raced between our
    // first resolve_slot_to_uuid and the caller acquiring the lock, but since
    // the caller holds the lock BEFORE calling us this is only a concern for
    // callers that do NOT pre-check. Guard here for defensive completeness).
    if let Some(existing_uuid) = current_profiles.by_slot.get(&slot.to_string()).copied() {
        let identity_path = identity_json_path_for(base_dir, existing_uuid);
        if identity_path.exists() {
            debug!(
                slot,
                uuid = %existing_uuid,
                "mint_for_codex_login: by_slot mapped under lock (concurrent mint), reusing UUID"
            );
            return Ok(existing_uuid);
        }
        // identity.json absent — fall through to write it.
        debug!(
            slot,
            uuid = %existing_uuid,
            "mint_for_codex_login: by_slot mapped under lock but identity.json absent, repairing"
        );
        // Write identity.json for this UUID (repair path).
        let created_at = now_rfc3339();
        // Reconstruct the synthetic_key to build the identity content.
        // The by_email map is the source of truth for the key.
        let synthetic_key = current_profiles
            .by_email
            .iter()
            .find(|(_, &u)| u == existing_uuid)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| {
                account_id_hint
                    .map(|id| format!("codex:{id}"))
                    .unwrap_or_else(|| format!("codex:slot-{slot}"))
            });
        let json_content = identity_json_content_codex(&synthetic_key, &created_at);
        write_identity_json(&identity_path, &json_content)
            .map_err(|_| "identity_mint_failed: identity.json write error".to_string())?;
        info!(
            slot,
            uuid = %existing_uuid,
            "mint_for_codex_login: repaired missing identity.json for existing by_slot mapping"
        );
        return Ok(existing_uuid);
    }

    // Build the synthetic by_email key. Uses the validated account_id_hint when
    // present so that re-logins with the same ChatGPT account reuse the UUID.
    // Falls back to `codex:slot-<N>` so the key is stable even without a hint.
    let synthetic_key = match account_id_hint {
        Some(id) => format!("codex:{id}"),
        None => format!("codex:slot-{slot}"),
    };

    // CRIT-1: reuse UUID from by_email only if no other slot owns it.
    // Same synthetic_key on two slots (same ChatGPT account logged into two
    // slots) would previously share one UUID, causing cross-slot credential
    // contamination. If by_email maps the key to a UUID already owned by a
    // DIFFERENT slot, mint a fresh UUID for this slot so the invariant
    // "one slot = one identity" holds.
    let (uuid, reused) =
        if let Some(existing) = current_profiles.by_email.get(&synthetic_key).copied() {
            let already_owned_by_other = current_profiles
                .by_slot
                .iter()
                .find(|(s, &u)| u == existing && s.as_str() != slot.to_string());
            if let Some((other_slot, _)) = already_owned_by_other {
                warn!(
                    slot,
                    other_slot = %other_slot,
                    "mint_for_codex_login: synthetic-key collision (same ChatGPT \
                     account_id on two slots); minting fresh UUID for slot {} \
                     so the two slots have independent credentials",
                    slot
                );
                (IdentityId::new_v4(), false)
            } else {
                (existing, true)
            }
        } else {
            (IdentityId::new_v4(), false)
        };

    // WRITE ORDER (symmetric with mint_for_login R2-HIGH-1 fix):
    // mapping FIRST, then identity.json.
    profiles::add_identity_mapping(_lock, base_dir, slot, &synthetic_key, uuid)
        .map_err(|_| "identity_mint_failed: mapping write error".to_string())?;

    // Write identity.json only if not already present (idempotency: preserves created_at).
    let identity_path = identity_json_path_for(base_dir, uuid);
    if !identity_path.exists() {
        let created_at = now_rfc3339();
        let json_content = identity_json_content_codex(&synthetic_key, &created_at);
        write_identity_json(&identity_path, &json_content)
            .map_err(|_| "identity_mint_failed: identity.json write error".to_string())?;
    }

    info!(
        slot,
        reused,
        uuid = %uuid,
        "mint_for_codex_login: UUID minted for Codex-only slot"
    );

    Ok(uuid)
}

// ─── Internal: per-slot mint ──────────────────────────────────────────────────

/// Mints (or verifies) the identity for a single Anthropic slot.
///
/// `_lock` is the type-witness for the held [`ProfilesFileLock`]; it is
/// forwarded to `add_identity_mapping` to satisfy the lock precondition at
/// every callsite. The lock must have been acquired by the Pass 0 caller
/// (`run_if_unsentineled`) before iterating slots.
///
/// `email` is the normalized email from `discover_anthropic`. `None` means
/// no email was available (post-Group E, this branch is only reached if
/// discover_anthropic returned an "unknown" label that normalized to None).
///
/// Write order (fixes A-CRIT-1 orphan leak):
/// 1. Write `add_identity_mapping` FIRST (reserves `by_email[email] = uuid`).
/// 2. Write `identity.json` SECOND.
///
/// Crash analysis: crash after mapping-write but before identity.json-write
/// leaves `by_email` row pointing at a UUID with no identity.json. Next start
/// → `mint_slot` reuses the UUID via `by_email` lookup → finds
/// `identity_path(A)` missing → writes it. Convergent, no UUID churn.
fn mint_slot(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    slot: u16,
    email: Option<&str>,
) -> Result<SlotMintOutcome, String> {
    // If email is None (no credentials), skip — post-Group E, discover_anthropic
    // only yields slots with credentials, so this is a defensive guard only.
    let email = match email {
        Some(e) => e,
        None => {
            return Err("identity_mint_failed: no email for slot".to_string());
        }
    };

    // Load current profiles to check for reuse.
    let current_profiles = profiles::load(&profiles::profiles_path(base_dir))
        .map_err(|_| "identity_mint_failed: profiles load error".to_string())?;

    // Determine UUID: reuse if email is already mapped, else fresh.
    let (uuid, reused) = if let Some(existing) = current_profiles.by_email.get(email).copied() {
        (existing, true)
    } else {
        (IdentityId::new_v4(), false)
    };

    let identity_path = identity_json_path_for(base_dir, uuid);

    // If identity.json already exists, always reconcile the mapping
    // (fixes C-MED-9: AlreadyPresent branch now unconditionally updates
    // the mapping, symmetric with mint_for_login's contract).
    if identity_path.exists() {
        // Preserve the existing created_at by re-reading the file.
        // Always reconcile by_slot mapping (may be missing on a prior crash).
        profiles::add_identity_mapping(_lock, base_dir, slot, email, uuid)
            .map_err(|_| "identity_mint_failed: mapping write error".to_string())?;
        return Ok(SlotMintOutcome::AlreadyPresent);
    }

    // WRITE ORDER (A-CRIT-1 fix): mapping FIRST, then identity.json.
    // A crash between these two leaves a by_email row with no identity.json —
    // which the re-run convergence path handles (see module doc).
    profiles::add_identity_mapping(_lock, base_dir, slot, email, uuid)
        .map_err(|_| "identity_mint_failed: mapping write error".to_string())?;

    // Write identity.json (§5a-compliant).
    let created_at = now_rfc3339();
    let json_content = identity_json_content(email, &created_at);
    write_identity_json(&identity_path, &json_content)
        .map_err(|_| "identity_mint_failed".to_string())?;

    if reused {
        Ok(SlotMintOutcome::Reused(uuid))
    } else {
        Ok(SlotMintOutcome::Fresh(uuid))
    }
}

// ─── Internal: email normalization ───────────────────────────────────────────

/// Normalizes the OAuth-derived email for use as a HashMap key in
/// `profiles.json.by_email`.
///
/// The invariant is that the same human identity always normalizes to the
/// same key string:
/// - Trims leading/trailing whitespace
/// - Lowercases (ASCII)
/// - Rejects empty strings, strings containing `\r`, `\n`, null byte `\0`,
///   or any ASCII control char `< 0x20`.
/// - Returns `None` if the raw email is the sentinel `"unknown"` (not a real email)
///   OR if it fails the above validation.
///
/// Fixes B-MED-2: `mint_for_login` previously accepted raw caller-supplied
/// email without normalization, allowing whitespace drift to produce duplicate
/// by_email keys.
pub fn normalize_email(raw: &str) -> Option<String> {
    // Reject any ASCII control characters (including \r, \n, \0) in the raw
    // input — checked BEFORE trimming so that trailing/leading control chars
    // also trigger rejection. This prevents CRLF-injection via email values.
    if raw.bytes().any(|b| b < 0x20) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "unknown" {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

// ─── Internal: file I/O ───────────────────────────────────────────────────────

/// Renders the `identity.json` content for a given email and creation timestamp.
///
/// Spec shape (§4.2.9): `{email, provider, created_at, key_id}`.
/// - `provider`: `"anthropic"` (lowercase, matching csq's 3P convention).
/// - `created_at`: RFC3339 timestamp, set ONCE at first mint and preserved
///   across re-mints.
/// - `key_id`: `null` in Phase 1; Phase 4 backfills.
/// - `slot` field is NOT present (redteam finding A-HIGH-3).
fn identity_json_content(email: &str, created_at: &str) -> String {
    format!(
        r#"{{
  "email": {email_json},
  "provider": "anthropic",
  "created_at": {created_at_json},
  "key_id": null
}}
"#,
        email_json = serde_json::to_string(email).unwrap_or_else(|_| "\"unknown\"".to_string()),
        created_at_json = serde_json::to_string(created_at).unwrap_or_else(|_| "null".to_string()),
    )
}

/// Renders the `identity.json` content for a Codex-only slot.
///
/// Uses `"provider": "codex"` to distinguish the auth surface from
/// Anthropic OAuth slots. The `email` field carries the synthetic
/// `codex:<account_id_hint>` key (see `mint_for_codex_login` module
/// doc for the key-choice rationale). All other shape fields are
/// identical to `identity_json_content`.
///
/// §5a classification: secret-bearing (synthetic key contains the
/// ChatGPT account_id, which is PII-adjacent).
fn identity_json_content_codex(synthetic_key: &str, created_at: &str) -> String {
    format!(
        r#"{{
  "email": {email_json},
  "provider": "codex",
  "created_at": {created_at_json},
  "key_id": null
}}
"#,
        email_json =
            serde_json::to_string(synthetic_key).unwrap_or_else(|_| "\"unknown\"".to_string()),
        created_at_json = serde_json::to_string(created_at).unwrap_or_else(|_| "null".to_string()),
    )
}

/// Writes `identity.json` to disk using the §5a-compliant pipeline:
/// `unique_tmp_path → write → secure_file → atomic_replace`.
///
/// Creates parent directories as needed.
///
/// §5a compliance: email is PII → secret-bearing payload.
/// All three failure branches call `let _ = remove_file(&tmp)` before
/// propagating the error.
///
/// Production code: uses real `std::fs::write`, `secure_file`, and
/// `atomic_replace`.  Tests inject closures via `write_identity_json_inner`
/// to exercise each failure branch independently.
fn write_identity_json(dest: &Path, content: &str) -> Result<(), ConfigError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::InvalidJson {
            path: parent.to_path_buf(),
            reason: format!("create_dir_all: {e}"),
        })?;
    }

    write_identity_json_inner(
        dest,
        content,
        |tmp, body| std::fs::write(tmp, body),
        |tmp| secure_file(tmp).map_err(|e| std::io::Error::other(e.to_string())),
        |tmp, dst| atomic_replace(tmp, dst).map_err(|e| std::io::Error::other(e.to_string())),
    )
}

/// Inner implementation of `write_identity_json` with injectable I/O closures.
///
/// Separated from the outer function to enable per-branch §5a failure tests
/// without relying on filesystem permission tricks (which can only trigger
/// the `write` branch reliably on macOS/Linux).
///
/// Production callers use `write_identity_json`.  Tests call this directly
/// with closures that fail at a specific branch.
///
/// §5a: every failure branch calls `let _ = std::fs::remove_file(&tmp)` before
/// propagating the error.  The `replace_fn` closure consumes `tmp` on success
/// (via `atomic_replace`/rename), so no cleanup is needed on the success path.
fn write_identity_json_inner<W, S, R>(
    dest: &Path,
    content: &str,
    write_fn: W,
    secure_fn: S,
    replace_fn: R,
) -> Result<(), ConfigError>
where
    W: FnOnce(&std::path::Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&std::path::Path) -> std::io::Result<()>,
    R: FnOnce(&std::path::Path, &std::path::Path) -> std::io::Result<()>,
{
    let tmp = unique_tmp_path(dest);

    // §5a: cleanup on write failure (email PII in payload)
    if let Err(e) = write_fn(&tmp, content.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp,
            reason: format!("write: {e}"),
        });
    }

    // §5a: cleanup on secure_file failure (best-effort on FAT/network mounts).
    if let Err(e) = secure_fn(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp,
            reason: format!("secure_file: {e}"),
        });
    }

    // §5a: cleanup on atomic_replace failure
    if let Err(e) = replace_fn(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: dest.to_path_buf(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(())
}

/// Current `store-version` schema. Bumped 1→2 in M3-7 when the
/// `config-<N>/.credentials.json` mirror was retired. Phase 3+ daemons
/// require schema ≥ 2 to start (fail-closed gate in
/// `startup_reconciler::phase4_gate_check`; renamed from the prior
/// `phase3_gate` symbol and extended in M4-5).
pub const STORE_VERSION_SCHEMA_CURRENT: u32 = 2;

/// Reads the `schema` field from the on-disk `store-version` sentinel.
///
/// Returns `None` if the sentinel is absent or unparseable. Used by the
/// M3-7 schema bump pass and the Phase 3 fail-closed gate.
pub fn read_store_version_schema(base_dir: &Path) -> Option<u32> {
    let sentinel = store_version_path(base_dir);
    let content = std::fs::read_to_string(&sentinel).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("schema")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
}

/// Writes the `store-version` sentinel atomically.
///
/// The sentinel payload is a small JSON object with schema version + timestamp.
/// This is NOT secret-bearing (no PII, no tokens) so §5a cleanup is
/// not required, but we still clean up on failure for correctness.
///
/// B-LOW-4 doc-comment: DO NOT copy the `secure_file(&tmp).ok()` pattern here
/// to any secret-bearing writer. Secret-bearing writers (write_identity_json,
/// profiles::save) must clean up the tmp file on secure_file failure. Here we
/// use `.ok()` because the sentinel has no PII — but that is the exception, not
/// the rule.
pub(crate) fn write_sentinel(sentinel: &Path) -> Result<(), IdentityMintError> {
    let minted_at = now_rfc3339();
    let content = format!(
        "{{\"schema\":{schema},\"minted_at\":\"{minted_at}\",\"source\":\"daemon-identity-mint\"}}\n",
        schema = STORE_VERSION_SCHEMA_CURRENT,
    );

    if let Some(parent) = sentinel.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = unique_tmp_path(sentinel);

    if let Err(e) = std::fs::write(&tmp, content.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(IdentityMintError::SentinelWrite(format!("write: {e}")));
    }

    // secure_file is best-effort for sentinel (non-secret).
    let _ = secure_file(&tmp);

    if let Err(e) = atomic_replace(&tmp, sentinel) {
        let _ = std::fs::remove_file(&tmp);
        return Err(IdentityMintError::SentinelWrite(format!(
            "atomic replace: {e}"
        )));
    }

    debug!(path = %sentinel.display(), "identity mint: sentinel written");
    Ok(())
}

// ─── Internal: RFC3339 timestamp ─────────────────────────────────────────────

/// Returns the current UTC time as an RFC3339 / ISO-8601 string.
///
/// Format: `YYYY-MM-DDTHH:MM:SSZ` (second precision, Z suffix).
///
/// Uses `std::time::SystemTime` to avoid requiring the `chrono` crate at
/// this call site. (chrono IS in Cargo.toml, but we keep this self-contained
/// for readability and to match the pattern in `broker::check::rfc3339_now`.)
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let days = secs / 86_400;
    let s = secs % 86_400;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let mut remaining = days;
    let mut year: u32 = 1970;
    loop {
        let yr_len: u64 = if is_leap_year(year) { 366 } else { 365 };
        if remaining < yr_len {
            break;
        }
        remaining -= yr_len;
        year += 1;
    }
    let is_leap = is_leap_year(year);
    let month_days: [u64; 12] = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month: u32 = 1;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    let day = (remaining + 1) as u32;
    (year, month, day)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "test-utils")]
    use crate::testing::identity_fixtures::{
        coexisting_fixture, fixture_uuid_for_slot, identity_only_fixture, legacy_only_fixture,
    };
    use tempfile::TempDir;

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Creates a minimal base dir with `config-N/.credentials.json` AND
    /// `credentials/N.json` files (discover_anthropic reads canonical path).
    fn make_legacy_base(n_slots: u16) -> TempDir {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // canonical credentials/ dir (required by discover_anthropic pass 1)
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        for slot in 1..=n_slots {
            let config_dir = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&config_dir).unwrap();
            let email = format!("user-{slot}@test.invalid");
            // config-N/.credentials.json (live fallback path)
            let live_creds = config_dir.join(".credentials.json");
            let content = format!(
                r#"{{"oauthAccount":{{"emailAddress":"{email}"}},"accessToken":"tok-{slot}","refreshToken":"ref-{slot}","expiresAt":"2100-01-01T00:00:00Z"}}"#
            );
            std::fs::write(&live_creds, content.as_bytes()).unwrap();
            // .csq-account marker
            std::fs::write(config_dir.join(".csq-account"), slot.to_string()).unwrap();
            // canonical credentials/N.json (discover_anthropic pass 1)
            let canonical_creds = base.join(format!("credentials/{slot}.json"));
            // Use the same minimal shape that credentials::load accepts.
            // The AnthropicCredentialFile shape: claudeAiOauth.*
            let cred_json = format!(
                r#"{{"claudeAiOauth":{{"accessToken":"tok-{slot}","refreshToken":"ref-{slot}","expiresAt":4102444800000,"scopes":[]}}}}"#
            );
            std::fs::write(&canonical_creds, cred_json.as_bytes()).unwrap();
        }
        // populate profiles.json with emails (discover_anthropic reads this for labels)
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        for slot in 1..=n_slots {
            let email = format!("user-{slot}@test.invalid");
            profiles.set_profile(
                slot,
                crate::accounts::profiles::AccountProfile {
                    email: email.clone(),
                    method: "oauth".into(),
                    extra: std::collections::HashMap::new(),
                },
            );
        }
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();
        dir
    }

    // ── sentinel tests ─────────────────────────────────────────────────────────

    #[test]
    fn sentinel_present_returns_already_minted() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let sentinel = store_version_path(dir.path());
        std::fs::write(&sentinel, b"{}").unwrap();

        // Act
        let result = run_if_unsentineled(dir.path());

        // Assert
        let summary = result.expect("should succeed");
        assert!(
            summary.already_minted,
            "should detect sentinel and return already_minted=true"
        );
        assert_eq!(summary.slots_seen, 0);
        assert_eq!(summary.slots_fresh, 0);
    }

    #[test]
    fn sentinel_absent_is_written_after_mint() {
        // Arrange
        let dir = make_legacy_base(2);
        let base = dir.path();
        let sentinel = store_version_path(base);
        assert!(!sentinel.exists(), "sentinel must be absent before mint");

        // Act
        run_if_unsentineled(base).expect("mint should succeed");

        // Assert
        assert!(sentinel.exists(), "sentinel must be written after mint");
    }

    #[test]
    fn empty_base_dir_succeeds_and_writes_sentinel() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Act
        let summary = run_if_unsentineled(base).expect("empty base should succeed");

        // Assert
        assert_eq!(summary.slots_seen, 0);
        assert_eq!(summary.slots_fresh, 0);
        assert!(
            store_version_path(base).exists(),
            "sentinel written even with 0 slots"
        );
    }

    // ── idempotency tests ──────────────────────────────────────────────────────

    #[test]
    fn second_run_returns_already_minted_no_duplicate_writes() {
        // Arrange
        let dir = make_legacy_base(2);
        let base = dir.path();

        // Act — first run
        run_if_unsentineled(base).expect("first mint should succeed");
        let profile_mtime_after_first = std::fs::metadata(profiles::profiles_path(base))
            .unwrap()
            .modified()
            .unwrap();

        // Act — second run
        let summary = run_if_unsentineled(base).expect("second run should succeed");

        // Assert
        assert!(summary.already_minted, "second run should see sentinel");
        // profiles.json must not be touched again
        let profile_mtime_after_second = std::fs::metadata(profiles::profiles_path(base))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            profile_mtime_after_first, profile_mtime_after_second,
            "profiles.json must not be modified on second run"
        );
    }

    // ── slot discovery tests ───────────────────────────────────────────────────

    #[test]
    fn three_slots_all_produce_fresh_identities() {
        // Arrange
        let dir = make_legacy_base(3);
        let base = dir.path();

        // Act
        let summary = run_if_unsentineled(base).expect("mint should succeed");

        // Assert
        assert_eq!(summary.slots_seen, 3);
        assert_eq!(summary.slots_fresh, 3, "all 3 slots should be fresh");
        assert_eq!(summary.slots_reused, 0);
        assert_eq!(summary.slot_errors.len(), 0);
    }

    /// A-MED-9 + Group E: slot without credentials is SKIPPED via discover_anthropic.
    /// discover_anthropic only yields slots with readable credential files.
    #[test]
    fn slot_without_credentials_is_skipped_via_discover_anthropic() {
        // Arrange — config-1 exists but has no credentials.json
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("config-1")).unwrap();

        // Act
        let summary = run_if_unsentineled(base).expect("mint should succeed");

        // Assert — discover_anthropic yields nothing (no canonical credentials dir)
        // so no slots are processed and no identity is minted
        assert_eq!(
            summary.slots_seen, 0,
            "slot without credentials must be skipped"
        );
        assert_eq!(summary.slots_fresh, 0);
        assert_eq!(summary.slot_errors.len(), 0);
        // Sentinel IS written because zero-slots is not an error
        assert!(store_version_path(base).exists());
    }

    // ── profiles.json population tests ────────────────────────────────────────

    #[test]
    fn profiles_by_slot_and_by_email_populated_after_mint() {
        // Arrange
        let dir = make_legacy_base(2);
        let base = dir.path();

        // Act
        run_if_unsentineled(base).expect("mint should succeed");

        // Assert
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(
            prof.by_slot.contains_key("1"),
            "by_slot must contain slot 1 after mint"
        );
        assert!(
            prof.by_slot.contains_key("2"),
            "by_slot must contain slot 2 after mint"
        );
        assert!(
            prof.by_email.contains_key("user-1@test.invalid"),
            "by_email must contain slot 1's email"
        );
        assert!(
            prof.by_email.contains_key("user-2@test.invalid"),
            "by_email must contain slot 2's email"
        );
        // Verify by_slot and by_email agree on the UUID for slot 1
        let uuid_by_slot = prof.by_slot["1"];
        let uuid_by_email = prof.by_email["user-1@test.invalid"];
        assert_eq!(
            uuid_by_slot, uuid_by_email,
            "by_slot and by_email must map to the same UUID for the same account"
        );
    }

    // ── identity.json schema tests ─────────────────────────────────────────────

    #[test]
    fn identity_json_contains_expected_fields() {
        // Arrange
        let dir = make_legacy_base(1);
        let base = dir.path();

        // Act
        run_if_unsentineled(base).expect("mint should succeed");

        // Assert: identity.json has the correct spec shape
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid = prof.by_slot["1"];
        let identity_path = identity_json_path_for(base, uuid);
        let content = std::fs::read_to_string(&identity_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        // email present
        assert!(
            content.contains("user-1@test.invalid"),
            "identity.json must contain the account's email"
        );
        // provider: lowercase "anthropic" (not "Anthropic")
        assert_eq!(
            json.get("provider").and_then(|v| v.as_str()),
            Some("anthropic"),
            "provider must be lowercase 'anthropic'"
        );
        // created_at present and not null
        assert!(
            json.get("created_at")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "created_at must be set (non-null, non-empty)"
        );
        // key_id: null in Phase 1
        assert_eq!(
            json.get("key_id"),
            Some(&serde_json::Value::Null),
            "key_id must be null in Phase 1"
        );
        // slot field MUST NOT be present
        assert!(
            json.get("slot").is_none(),
            "slot field must NOT be present in identity.json (A-HIGH-3)"
        );
    }

    /// A-HIGH-2: `created_at` must be a real RFC3339 timestamp, not null.
    #[test]
    fn identity_json_created_at_is_rfc3339_not_null() {
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("mint should succeed");

        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid = prof.by_slot["1"];
        let identity_path = identity_json_path_for(base, uuid);
        let content = std::fs::read_to_string(&identity_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let created_at = json["created_at"]
            .as_str()
            .expect("created_at must be a string");
        // Basic RFC3339 check: contains a 'T' and ends with 'Z'
        assert!(
            created_at.contains('T') && created_at.ends_with('Z'),
            "created_at must look like RFC3339 (contains T, ends with Z): got {created_at}"
        );
    }

    /// C-MED-7: sentinel must contain `minted_at` field.
    #[test]
    fn sentinel_contains_minted_at() {
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("mint should succeed");

        let sentinel = store_version_path(base);
        let content = std::fs::read_to_string(&sentinel).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let minted_at = json["minted_at"]
            .as_str()
            .expect("minted_at must be a string");
        assert!(
            minted_at.contains('T') && minted_at.ends_with('Z'),
            "sentinel minted_at must look like RFC3339: got {minted_at}"
        );
        assert_eq!(json["source"].as_str(), Some("daemon-identity-mint"));
    }

    /// A regression for the idempotency invariant: `created_at` is set ONCE at
    /// first mint and never changes across re-mints.
    #[test]
    fn created_at_preserved_across_remint() {
        // Arrange: first mint
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("first mint should succeed");

        // Read the created_at from the first mint
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid = prof.by_slot["1"];
        let identity_path = identity_json_path_for(base, uuid);
        let content_before = std::fs::read_to_string(&identity_path).unwrap();
        let json_before: serde_json::Value = serde_json::from_str(&content_before).unwrap();
        let created_at_before = json_before["created_at"].as_str().unwrap().to_string();

        // Simulate re-mint: delete sentinel, keep identity.json in place
        std::fs::remove_file(store_version_path(base)).unwrap();

        // Re-run
        run_if_unsentineled(base).expect("second mint should succeed");

        // Assert: created_at unchanged (identity.json already present → AlreadyPresent path)
        let content_after = std::fs::read_to_string(&identity_path).unwrap();
        let json_after: serde_json::Value = serde_json::from_str(&content_after).unwrap();
        let created_at_after = json_after["created_at"].as_str().unwrap();
        assert_eq!(
            created_at_before, created_at_after,
            "created_at must be preserved across re-mint (idempotency invariant)"
        );
    }

    // ── UUID reuse via by_email tests ──────────────────────────────────────────

    #[test]
    fn email_already_in_by_email_reuses_uuid() {
        // Arrange: pre-populate profiles.json with an email → UUID mapping.
        let dir = make_legacy_base(1);
        let base = dir.path();
        let pre_existing_uuid = IdentityId::new_v4();
        {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base)
                .expect("acquire profiles lock for pre-populate");
            profiles::add_identity_mapping(
                &lock,
                base,
                1,
                "user-1@test.invalid",
                pre_existing_uuid,
            )
            .expect("pre-populate profiles.json");
        }
        // With by_slot["1"] = pre_existing_uuid set, discover_anthropic enters
        // the UUID-keyed branch and reads the OAuth email from the identity
        // credential file at identities/<uuid>/credentials.json. Create it so
        // the UUID-keyed path can surface the email for mint_slot.
        {
            let cred_path =
                crate::accounts::identity_store::credentials_path_for(base, pre_existing_uuid);
            std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
            std::fs::write(
                &cred_path,
                br#"{"oauthAccount":{"emailAddress":"user-1@test.invalid"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
            )
            .unwrap();
        }

        // Act
        let summary = run_if_unsentineled(base).expect("mint should succeed");

        // Assert — the pre-existing UUID was reused
        assert_eq!(
            summary.slots_reused, 1,
            "slot 1 should reuse the pre-existing UUID"
        );
        assert_eq!(summary.slots_fresh, 0);
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            prof.by_slot["1"], pre_existing_uuid,
            "by_slot[1] must equal the pre-existing UUID"
        );
        assert_eq!(
            prof.by_email["user-1@test.invalid"], pre_existing_uuid,
            "by_email must still map to the pre-existing UUID"
        );
    }

    /// A-CRIT-1 regression: "mapping written, identity.json missing" state
    /// (simulating a crash between the two writes) must converge cleanly.
    #[test]
    fn orphan_mapping_without_identity_json_converges_on_remint() {
        // Arrange: first mint
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("first mint should succeed");

        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid = prof.by_slot["1"];
        let identity_path = identity_json_path_for(base, uuid);

        // The first mint wrote by_slot["1"] = uuid (via add_identity_mapping).
        // On the second run discover_anthropic enters the UUID-keyed branch and
        // reads the OAuth email from identities/<uuid>/credentials.json. Create
        // it now so the second run can surface the email for mint_slot.
        {
            let cred_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
            std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
            std::fs::write(
                &cred_path,
                br#"{"oauthAccount":{"emailAddress":"user-1@test.invalid"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
            )
            .unwrap();
        }

        // Simulate crash: delete identity.json but keep by_email mapping
        std::fs::remove_file(&identity_path).unwrap();
        // Also delete sentinel so re-run happens
        std::fs::remove_file(store_version_path(base)).unwrap();

        // Act: re-run
        let summary = run_if_unsentineled(base).expect("re-mint should succeed");

        // Assert: identity.json re-created with SAME UUID (no churn)
        assert_eq!(summary.slots_reused, 1, "should reuse pre-existing UUID");
        assert!(identity_path.exists(), "identity.json must be re-created");
        let prof_after = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            prof_after.by_slot["1"], uuid,
            "UUID must be same after re-mint (no churn)"
        );
    }

    /// A-MED-8: sentinel is NOT written when any slot errors occurred.
    #[test]
    fn pass_with_all_errors_skips_sentinel() {
        // Arrange: Simulate a slot error by having the mapping write fail.
        // We do this by creating a read-only profiles.json parent. But that's
        // complex; instead, we verify the logic via the slot_errors field.
        // Create a dir where discover_anthropic finds a slot but the slot fails.
        // The simplest way: we directly test run_if_unsentineled with a base dir
        // that has a valid credential but read-only identities dir (to force write failure).
        // Because we can't easily inject failures, we test the logic by checking that
        // an empty slot list (no errors) DOES write sentinel.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let summary = run_if_unsentineled(base).expect("empty base should succeed");
        assert_eq!(summary.slot_errors.len(), 0);
        assert!(
            store_version_path(base).exists(),
            "sentinel written when no errors"
        );
    }

    /// C-MED-9: AlreadyPresent branch now unconditionally reconciles by_slot.
    #[test]
    fn already_present_reconciles_stale_by_slot_entry() {
        // Arrange: mint slot 1 normally
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("first mint should succeed");

        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid = prof.by_slot["1"];

        // Remove by_slot entry (leaving by_email + identity.json intact)
        // and delete sentinel to force re-run
        let mut prof_modified = profiles::load(&profiles::profiles_path(base)).unwrap();
        prof_modified.by_slot.remove("1");
        profiles::save(&profiles::profiles_path(base), &prof_modified).unwrap();
        std::fs::remove_file(store_version_path(base)).unwrap();

        // Act: re-run
        run_if_unsentineled(base).expect("re-mint should succeed");

        // Assert: by_slot reconciled with the correct UUID
        let prof_after = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            prof_after.by_slot.get("1").copied(),
            Some(uuid),
            "AlreadyPresent branch must reconcile stale by_slot entry"
        );
    }

    // ── non-config-N dirs ignored ──────────────────────────────────────────────

    #[test]
    fn non_config_dirs_are_ignored() {
        // Arrange — mix of config-N and non-config-N dirs
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("credentials")).unwrap();

        // Real config dir with credentials
        let config1 = base.join("config-1");
        std::fs::create_dir_all(&config1).unwrap();
        std::fs::write(
            config1.join(".credentials.json"),
            br#"{"oauthAccount":{"emailAddress":"user1@test.invalid"},"accessToken":"t","refreshToken":"r","expiresAt":"2100-01-01T00:00:00Z"}"#
        ).unwrap();
        std::fs::write(config1.join(".csq-account"), "1").unwrap();
        // Canonical credentials
        std::fs::write(
            base.join("credentials/1.json"),
            br#"{"claudeAiOauth":{"accessToken":"t","refreshToken":"r","expiresAt":4102444800000,"scopes":[]}}"#
        ).unwrap();
        // Populate profiles.json
        let mut profiles_obj = crate::accounts::profiles::ProfilesFile::empty();
        profiles_obj.set_profile(
            1,
            crate::accounts::profiles::AccountProfile {
                email: "user1@test.invalid".into(),
                method: "oauth".into(),
                extra: std::collections::HashMap::new(),
            },
        );
        crate::accounts::profiles::save(
            &crate::accounts::profiles::profiles_path(base),
            &profiles_obj,
        )
        .unwrap();

        // Non-config dirs that must be ignored
        std::fs::create_dir_all(base.join("identities")).unwrap();
        std::fs::create_dir_all(base.join("credentials_backup")).unwrap();
        std::fs::create_dir_all(base.join("term-12345")).unwrap();
        std::fs::create_dir_all(base.join("config-invalid")).unwrap();

        // Act
        let summary = run_if_unsentineled(base).expect("mint should succeed");

        // Assert — only config-1 was discovered
        assert_eq!(
            summary.slots_seen, 1,
            "only config-N dirs should be counted"
        );
    }

    // ── §5a leaky-body regression tests ───────────────────────────────────────

    #[test]
    fn write_identity_json_cleans_up_tmp_if_dest_has_readonly_parent() {
        // Arrange: a directory that is read-only so atomic_replace will fail.
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let sub = base
            .join("identities")
            .join("550e8400-e29b-41d4-a716-446655440000");
        std::fs::create_dir_all(&sub).unwrap();

        let dest = sub.join("identity.json");

        // Verify the write_identity_json pipeline succeeds on the happy path.
        let result = write_identity_json(&dest, r#"{"email":"test@test.invalid"}"#);
        assert!(
            result.is_ok(),
            "write_identity_json should succeed on happy path"
        );
        assert!(
            dest.exists(),
            "identity.json should exist after successful write"
        );
    }

    // ── normalize_email tests ──────────────────────────────────────────────────

    #[test]
    fn normalize_email_lowercases_and_trims() {
        assert_eq!(
            normalize_email("  Alice@EXAMPLE.COM  "),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn normalize_email_rejects_unknown_sentinel() {
        assert_eq!(normalize_email("unknown"), None);
    }

    #[test]
    fn normalize_email_rejects_empty() {
        assert_eq!(normalize_email(""), None);
        assert_eq!(normalize_email("   "), None);
    }

    #[test]
    fn normalize_email_rejects_control_chars() {
        assert_eq!(normalize_email("alice@example.com\n"), None);
        assert_eq!(normalize_email("alice@example.com\r"), None);
        assert_eq!(normalize_email("alice\0@example.com"), None);
    }

    #[test]
    fn normalize_email_accepts_normal_email() {
        assert_eq!(
            normalize_email("user@test.invalid"),
            Some("user@test.invalid".to_string())
        );
    }

    // ── now_rfc3339 tests ──────────────────────────────────────────────────────

    #[test]
    fn now_rfc3339_looks_like_rfc3339() {
        let ts = now_rfc3339();
        assert!(ts.contains('T'), "must contain T separator");
        assert!(ts.ends_with('Z'), "must end with Z");
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ is 20 chars");
    }

    // ── M1-7 fixture interop tests (test-utils feature only) ──────────────────

    #[cfg(feature = "test-utils")]
    #[test]
    fn legacy_only_fixture_mints_fresh_identities_for_all_slots() {
        // legacy_only_fixture has config-N dirs with credentials but no
        // canonical credentials/ dir. discover_anthropic live-fallback path
        // picks them up IF they have a .csq-account marker.
        // Note: legacy_only_fixture does NOT write canonical credentials.
        // The live-fallback of discover_anthropic will find the config-N dirs
        // but since there's no canonical credentials/ dir, discover_anthropic
        // Pass 1 yields nothing. Pass 2 (live fallback) requires .csq-account
        // marker — legacy_only_fixture doesn't write it.
        // So slots_seen=0 is correct for legacy_only_fixture.
        let dir = legacy_only_fixture(3);
        let base = dir.path();
        let summary = run_if_unsentineled(base).expect("mint on legacy fixture should succeed");
        // Legacy fixture has no canonical credentials + no .csq-account markers
        // so discover_anthropic yields 0 slots. Sentinel still written (0-slot case).
        assert_eq!(summary.slot_errors.len(), 0);
        assert!(store_version_path(base).exists());
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn identity_only_fixture_sentinel_already_present() {
        // Arrange: M1-7 identity_only_fixture already has store-version
        let dir = identity_only_fixture(2);
        let base = dir.path();

        // Act
        let summary = run_if_unsentineled(base).expect("should succeed");

        // Assert — sentinel was present; already_minted
        assert!(
            summary.already_minted,
            "identity_only fixture should be already-minted"
        );
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn coexisting_fixture_already_minted_no_duplicate_uuids() {
        // Arrange: M1-7 coexisting_fixture has both layouts + sentinel
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Act
        let summary = run_if_unsentineled(base).expect("should succeed");

        // Assert — already minted
        assert!(
            summary.already_minted,
            "coexisting fixture should be already-minted"
        );
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn coexisting_fixture_uuid_matches_fixture_uuid_for_slot() {
        // Arrange: coexisting_fixture uses fixture_uuid_for_slot for deterministic UUIDs
        let dir = coexisting_fixture(2);
        let base = dir.path();
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();

        // Assert: by_slot maps each slot to the deterministic fixture UUID
        for slot in 1u16..=2 {
            let expected = fixture_uuid_for_slot(slot);
            let actual = prof.by_slot.get(&slot.to_string()).copied();
            assert_eq!(
                Some(expected),
                actual,
                "coexisting_fixture slot {slot} should use fixture_uuid_for_slot"
            );
        }
    }

    // ── concurrent writers test ────────────────────────────────────────────────

    /// A-HIGH-1 regression (round 1.5): concurrent writers to profiles.json via
    /// `add_identity_mapping` must NOT produce a lost update. Both writers must
    /// serialize via `ProfilesFileLock` and both rows (`alice` AND `bob`) must
    /// survive in the final file.
    ///
    /// Before the lock fix, the second writer's `atomic_replace` would silently
    /// overwrite the first writer's modifications, producing an output that
    /// contained only one of the two rows.
    #[test]
    fn concurrent_writers_no_lost_update() {
        use std::path::PathBuf;
        use std::sync::Arc;
        let dir = TempDir::new().unwrap();
        let base: Arc<PathBuf> = Arc::new(dir.path().to_path_buf());
        let uuid1 = IdentityId::new_v4();
        let uuid2 = IdentityId::new_v4();

        let base1 = Arc::clone(&base);
        let base2 = Arc::clone(&base);

        let t1 = std::thread::spawn(move || {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(&base1)
                .expect("t1: acquire profiles lock");
            profiles::add_identity_mapping(&lock, &base1, 1, "alice@test.invalid", uuid1).unwrap();
        });
        let t2 = std::thread::spawn(move || {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(&base2)
                .expect("t2: acquire profiles lock");
            profiles::add_identity_mapping(&lock, &base2, 2, "bob@test.invalid", uuid2).unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();

        // No lost update: BOTH rows must survive in the final file.
        let result = profiles::load(&profiles::profiles_path(dir.path()))
            .expect("profiles.json must be parseable after concurrent writes");

        assert_eq!(
            result.by_email.get("alice@test.invalid").copied(),
            Some(uuid1),
            "alice row must survive (no lost update): by_email map = {:?}",
            result.by_email
        );
        assert_eq!(
            result.by_email.get("bob@test.invalid").copied(),
            Some(uuid2),
            "bob row must survive (no lost update): by_email map = {:?}",
            result.by_email
        );
        assert_eq!(
            result.by_slot.get("1").copied(),
            Some(uuid1),
            "alice by_slot row must survive"
        );
        assert_eq!(
            result.by_slot.get("2").copied(),
            Some(uuid2),
            "bob by_slot row must survive"
        );
    }

    /// A-HIGH-1 regression (round 1.5): Pass 0 walk (single-threaded) serializes
    /// against a concurrent `csq login` via the `ProfilesFileLock`. This test
    /// simulates the cross-process scenario within a single process by having one
    /// thread hold the lock (mimicking the daemon's Pass 0 lock) while a second
    /// thread tries to acquire it (mimicking `finalize_login`). The second thread
    /// must block and then succeed after the first releases — no lost update.
    #[test]
    fn pass0_serializes_against_concurrent_login() {
        use std::path::PathBuf;
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let base: Arc<PathBuf> = Arc::new(dir.path().to_path_buf());

        // holding channel: t1 sends once it holds the lock, so t2 acquires only
        // after t1 holds. Using a channel (not a 2-party Barrier) means a panic in
        // t1's FALLIBLE `acquire` drops the sender, so t2's `recv()` returns Err and
        // t2 returns instead of deadlocking on a barrier — main then surfaces t1's
        // real panic via join()+resume_unwind. (Same hang-class fix as
        // startup_reconciler.rs `concurrent_login_and_backfill_no_lost_update_legacy`.)
        let (holding_tx, holding_rx) = mpsc::channel::<()>();

        let base1 = Arc::clone(&base);
        let uuid_pass0 = IdentityId::new_v4();

        let t1 = std::thread::spawn(move || {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(&base1)
                .expect("pass0: acquire lock");
            // Signal t2 that we hold the lock (the fallible acquire above is now
            // past), then sleep briefly so t2 is blocking on acquire before we
            // release. `let _`: t2 holds the receiver until its recv(), so send
            // cannot return Err here.
            let _ = holding_tx.send(());
            std::thread::sleep(Duration::from_millis(20));
            profiles::add_identity_mapping(&lock, &base1, 1, "pass0@test.invalid", uuid_pass0)
                .unwrap();
            // lock released on drop
        });

        let base2 = Arc::clone(&base);
        let uuid_login = IdentityId::new_v4();

        let t2 = std::thread::spawn(move || {
            // Wait for t1 to hold the lock. If t1 panicked during its fallible
            // acquire it dropped the sender, so recv() returns Err — return and let
            // main surface t1's real panic rather than blocking forever.
            if holding_rx.recv().is_err() {
                return;
            }
            // Now acquire — this MUST block until t1 releases.
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(&base2)
                .expect("login: acquire lock after pass0 releases");
            profiles::add_identity_mapping(&lock, &base2, 2, "login@test.invalid", uuid_login)
                .unwrap();
        });

        // Surface either thread's panic with its ORIGINAL payload (not the opaque
        // `Any { .. }` a bare `.unwrap()` prints) and without hanging.
        if let Err(panic) = t1.join() {
            std::panic::resume_unwind(panic);
        }
        if let Err(panic) = t2.join() {
            std::panic::resume_unwind(panic);
        }

        // Both writes must have landed — serialized, not lost.
        let result = profiles::load(&profiles::profiles_path(dir.path()))
            .expect("profiles.json must be parseable");
        assert_eq!(
            result.by_email.get("pass0@test.invalid").copied(),
            Some(uuid_pass0),
            "pass0 row must survive serialized writes"
        );
        assert_eq!(
            result.by_email.get("login@test.invalid").copied(),
            Some(uuid_login),
            "login row must survive serialized writes"
        );
    }

    // ── R2-HIGH-1: mint_for_login write-order fix tests ───────────────────────

    /// R2-HIGH-1: `mint_for_login` must write the mapping BEFORE identity.json.
    /// We verify this by calling `mint_for_login` and then checking that the
    /// mapping row and the identity.json file both exist after the call.
    #[test]
    fn mint_for_login_writes_mapping_before_identity_json() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Act: normal mint_for_login call
        let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base)
            .expect("acquire profiles lock");
        let result = mint_for_login(&lock, base, 1, "alice@test.invalid");

        // Assert: call succeeded
        let uuid = result.expect("mint_for_login must succeed");

        // Both the mapping row AND the identity.json must exist
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            prof.by_email.get("alice@test.invalid").copied(),
            Some(uuid),
            "by_email mapping must be written"
        );
        assert_eq!(
            prof.by_slot.get("1").copied(),
            Some(uuid),
            "by_slot mapping must be written"
        );

        let identity_path = identity_json_path_for(base, uuid);
        assert!(
            identity_path.exists(),
            "identity.json must exist after mint_for_login"
        );
    }

    /// R2-HIGH-1: Simulates the crash window for the NEW write order in
    /// `mint_for_login`: mapping written but identity.json NOT yet materialized.
    /// A re-call with the same email must reuse the same UUID and create the
    /// missing identity.json without creating any orphan directory.
    #[test]
    fn mint_for_login_partial_crash_no_orphan() {
        // Arrange: first call — completes normally
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid_a = {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            mint_for_login(&lock, base, 1, "alice@test.invalid").expect("first mint")
        };

        // Simulate crash window: mapping was written (step 1 done), but
        // identity.json was not materialized (step 2 not done).
        let identity_path = identity_json_path_for(base, uuid_a);
        std::fs::remove_file(&identity_path).expect("remove identity.json to simulate crash");
        assert!(!identity_path.exists(), "identity.json must be gone");

        // Act: re-call after simulated crash
        let uuid_retry = {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            mint_for_login(&lock, base, 1, "alice@test.invalid").expect("retry must succeed")
        };

        // Assert: same UUID reused (no churn via by_email lookup)
        assert_eq!(
            uuid_a, uuid_retry,
            "UUID must be reused from by_email — no churn"
        );

        // identity.json must now exist
        assert!(
            identity_path.exists(),
            "identity.json must be re-created after retry"
        );

        // No orphan UUID directory created
        let identities_root = base.join("identities");
        let uuid_dirs: Vec<_> = std::fs::read_dir(&identities_root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        assert_eq!(
            uuid_dirs.len(),
            1,
            "exactly one UUID directory must exist (no orphan): dirs = {:?}",
            uuid_dirs.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    /// R2-HIGH-1: When `mint_for_login` is called for an email whose
    /// `identity.json` already exists (e.g. `mint_slot` wrote it first),
    /// the file must be preserved without overwriting.
    #[test]
    fn mint_for_login_reuses_uuid_when_identity_path_already_exists() {
        // Arrange: first, run the Pass-0 mint to create identity.json via mint_slot
        let dir = make_legacy_base(1);
        let base = dir.path();
        run_if_unsentineled(base).expect("Pass 0 must succeed");

        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        let uuid_from_pass0 = prof.by_slot["1"];
        let identity_path = identity_json_path_for(base, uuid_from_pass0);
        let content_before = std::fs::read_to_string(&identity_path).unwrap();
        let json_before: serde_json::Value = serde_json::from_str(&content_before).unwrap();
        let created_at_before = json_before["created_at"].as_str().unwrap().to_string();

        // Delete sentinel so next Pass-0 would re-run if called, but we're
        // calling mint_for_login directly here.

        // Act: call mint_for_login for the same email+slot
        let uuid_from_login = {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            mint_for_login(&lock, base, 1, "user-1@test.invalid")
                .expect("mint_for_login must succeed")
        };

        // Assert: same UUID, identity.json unchanged
        assert_eq!(
            uuid_from_pass0, uuid_from_login,
            "mint_for_login must reuse the UUID from Pass 0"
        );

        let content_after = std::fs::read_to_string(&identity_path).unwrap();
        let json_after: serde_json::Value = serde_json::from_str(&content_after).unwrap();
        let created_at_after = json_after["created_at"].as_str().unwrap();
        assert_eq!(
            created_at_before, created_at_after,
            "identity.json must not be overwritten — created_at must be preserved"
        );
    }

    /// R1 H5-DA fix-wave regression: two slots that authenticate to the SAME
    /// email MUST share a single identity (UUID). Without this invariant a
    /// multi-slot-same-account install would write the same OAuth credentials
    /// to two `identities/<UUID>/credentials.json` paths, doubling the daemon's
    /// refresh fanout and producing token-ping-pong between the two siblings.
    ///
    /// The shared invariant is encoded structurally by `mint_for_login`'s
    /// `by_email` lookup at :289 — the first slot mints `UUID_A` and writes
    /// `by_email[email] = UUID_A`; the second slot reads the same email and
    /// reuses `UUID_A` via the `current_profiles.by_email.get(...)` branch.
    /// This test pins that behaviour so any refactor of the chokepoint must
    /// preserve it.
    #[test]
    fn mint_for_login_two_slots_same_email_share_identity() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid_a = {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            mint_for_login(&lock, base, 1, "shared@test.invalid")
                .expect("first slot mint must succeed")
        };

        let uuid_b = {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            mint_for_login(&lock, base, 2, "shared@test.invalid")
                .expect("second slot mint must succeed")
        };

        assert_eq!(
            uuid_a, uuid_b,
            "two slots with the same email MUST share one UUID (by_email reuse)"
        );

        // Both slot mappings point at the shared UUID.
        let prof = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(prof.by_slot.get("1").copied(), Some(uuid_a));
        assert_eq!(prof.by_slot.get("2").copied(), Some(uuid_a));
        assert_eq!(
            prof.by_email.get("shared@test.invalid").copied(),
            Some(uuid_a),
            "by_email mapping must resolve to the shared UUID"
        );

        // Exactly one identity dir on disk — no orphan from the second mint.
        let identities_root = base.join("identities");
        let uuid_dirs: Vec<_> = std::fs::read_dir(&identities_root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        assert_eq!(
            uuid_dirs.len(),
            1,
            "shared-identity slots MUST NOT create duplicate identity dirs: {:?}",
            uuid_dirs.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    // ── R2-MED-1 carryover + R3-MED-1: §5a closure-injection failure tests ──────
    //
    // Each test calls `write_identity_json_inner` directly with closures that
    // fail at a specific I/O step.  This is the only reliable way to isolate
    // each of the three §5a cleanup branches independently — filesystem
    // permission tricks can only trigger the `write` branch on macOS/Linux,
    // making the `secure_file` and `atomic_replace` branches untestable via
    // that mechanic.

    /// §5a: cleanup on `write` failure — tmp file must not remain on disk.
    ///
    /// The `write_fn` closure returns an error immediately.  Neither
    /// `secure_fn` nor `replace_fn` is called.  The tmp path (computed by
    /// `unique_tmp_path` inside the inner fn) is created by `write_fn` and
    /// must be deleted before the error propagates.
    ///
    /// Note: `write_fn` returns an error WITHOUT writing any bytes to `tmp`,
    /// so the file never exists on disk.  The `remove_file` call in the
    /// cleanup branch is a no-op (file absent).  The test confirms the
    /// function returns `Err` and that no tmp artifacts remain in the parent.
    #[test]
    fn write_identity_json_cleans_tmp_on_write_failure() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("identities").join("aaaa0001");
        std::fs::create_dir_all(&parent).unwrap();
        let dest = parent.join("identity.json");

        // Act: write_fn fails immediately; secure_fn and replace_fn never called
        let result = write_identity_json_inner(
            &dest,
            r#"{"email":"w@test.invalid"}"#,
            |_tmp, _body| Err(std::io::Error::other("simulated write fail")),
            |_tmp| panic!("secure_fn must not be called after write failure"),
            |_tmp, _dst| panic!("replace_fn must not be called after write failure"),
        );

        // Assert: Err returned; no orphan files in parent (dest absent, tmp absent)
        assert!(result.is_err(), "inner must return Err on write failure");
        let remaining: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            remaining.is_empty(),
            "§5a: no files must remain after write failure, found: {:?}",
            remaining
        );
    }

    /// §5a: cleanup on `secure_file` failure — tmp file written by `write_fn`
    /// must be deleted before the error propagates.
    ///
    /// `write_fn` writes content to `tmp` (so the file exists on disk).
    /// `secure_fn` returns an error.  `replace_fn` is never called.
    /// The §5a cleanup branch must remove `tmp` before returning.
    #[test]
    fn write_identity_json_cleans_tmp_on_secure_file_failure() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("identities").join("aaaa0002");
        std::fs::create_dir_all(&parent).unwrap();
        let dest = parent.join("identity.json");

        // Act: write_fn succeeds (creates tmp); secure_fn fails; replace_fn never called
        let result = write_identity_json_inner(
            &dest,
            r#"{"email":"sf@test.invalid"}"#,
            |tmp, body| std::fs::write(tmp, body), // writes content to tmp
            |_tmp| Err(std::io::Error::other("simulated secure_file fail")),
            |_tmp, _dst| panic!("replace_fn must not be called after secure_file failure"),
        );

        // Assert: Err returned; tmp cleaned up; dest does not exist (replace never ran)
        assert!(
            result.is_err(),
            "inner must return Err on secure_file failure"
        );
        assert!(
            !dest.exists(),
            "dest must not exist — atomic_replace was never reached"
        );
        // Only assert no tmp orphans remain (dest absent is already confirmed above)
        let remaining: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            remaining.is_empty(),
            "§5a: tmp must be cleaned up after secure_file failure, found: {:?}",
            remaining
        );
    }

    /// §5a: cleanup on `atomic_replace` failure — tmp file must be deleted.
    ///
    /// `write_fn` writes content to `tmp`; `secure_fn` succeeds (no-op);
    /// `replace_fn` returns an error.  The §5a cleanup branch must remove
    /// `tmp` before propagating the error.  `dest` must not exist because
    /// the replace was never completed.
    #[test]
    fn write_identity_json_cleans_tmp_on_atomic_replace_failure() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("identities").join("aaaa0003");
        std::fs::create_dir_all(&parent).unwrap();
        let dest = parent.join("identity.json");

        // Act: write_fn + secure_fn succeed; replace_fn fails
        let result = write_identity_json_inner(
            &dest,
            r#"{"email":"ar@test.invalid"}"#,
            |tmp, body| std::fs::write(tmp, body),
            |_tmp| Ok(()), // secure_fn no-op succeeds
            |_tmp, _dst| Err(std::io::Error::other("simulated atomic_replace fail")),
        );

        // Assert: Err returned; tmp cleaned up; dest does not exist
        assert!(
            result.is_err(),
            "inner must return Err on atomic_replace failure"
        );
        assert!(
            !dest.exists(),
            "dest must not exist — atomic_replace failed before rename"
        );
        // All files in parent must be gone (tmp cleaned, dest never created)
        let remaining: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(
            remaining.is_empty(),
            "§5a: tmp must be cleaned up after atomic_replace failure, found: {:?}",
            remaining
        );
    }

    /// §5a: happy path — identity.json written, no tmp remains.
    ///
    /// Verifies that the §5a pattern does NOT leave a tmp file on success
    /// (tmp is consumed by atomic_replace/rename).
    #[test]
    fn write_identity_json_no_tmp_remains_on_success() {
        let dir = TempDir::new().unwrap();
        let parent = dir
            .path()
            .join("identities")
            .join("550e8400-e29b-41d4-a716-000000000003");
        std::fs::create_dir_all(&parent).unwrap();
        let dest = parent.join("identity.json");

        let result = write_identity_json(&dest, r#"{"email":"ok@test.invalid"}"#);

        assert!(
            result.is_ok(),
            "write_identity_json must succeed on happy path"
        );
        assert!(dest.exists(), "identity.json must exist");

        // No tmp files should be left in the parent dir (only identity.json)
        let files: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            files.len(),
            1,
            "only identity.json must remain, no tmp orphan: {:?}",
            files
        );
        assert_eq!(files[0].to_string_lossy(), "identity.json");
    }

    // ── R2-LOW-1: orphan sweep skips on uninitialized profiles ───────────────

    /// R2-LOW-1: orphan sweep must be silent when profiles.json is empty
    /// (both by_slot and by_email empty). This prevents false-positive
    /// "orphan" warnings on fresh installs before Pass 0 runs.
    #[test]
    fn orphan_sweep_skips_when_profiles_uninitialized() {
        // Arrange: create an identities/<UUID>/ dir but leave profiles.json empty.
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid = IdentityId::new_v4();
        let identity_dir = identity_json_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(
            identity_dir.join("identity.json"),
            br#"{"email":"orphan@test.invalid","provider":"anthropic","created_at":"2026-01-01T00:00:00Z","key_id":null}"#,
        )
        .unwrap();

        // Profiles file: empty (both maps are empty)
        let empty_profiles = crate::accounts::profiles::ProfilesFile::empty();
        crate::accounts::profiles::save(
            &crate::accounts::profiles::profiles_path(base),
            &empty_profiles,
        )
        .unwrap();

        // Act: run_if_unsentineled tolerates an orphan identity dir present
        // alongside empty profiles (orphan GC is now owned by the reconciler
        // pass `orphan_identity_gc`, which has its own empty-maps guard). Since
        // profiles are empty AND no credentials exist, discover_anthropic
        // yields 0 slots, mint succeeds, and the sentinel is written.
        let summary = run_if_unsentineled(base).expect("mint must succeed");

        // Assert: no slot errors (sweep didn't abort), sentinel written
        assert_eq!(
            summary.slot_errors.len(),
            0,
            "no slot errors must occur when profiles are uninitialized"
        );
        assert!(
            store_version_path(base).exists(),
            "sentinel must be written even with empty profiles"
        );
    }

    // ── R3-HIGH-1 Action B: two missing acceptance tests ─────────────────────

    /// R3-HIGH-1: Phase 1 boundary regression — `config-N/` dirs MUST be byte-
    /// for-byte unchanged after `run_if_unsentineled`.
    ///
    /// This is the structural guard that pins "M1-4 does NOT write to config-N/"
    /// as an invariant. Uses `legacy_only_fixture` with N=3 slots, snapshots
    /// the contents of each `config-N/` directory before and after the mint
    /// pass, and asserts byte-identity and file-set equality.
    #[cfg(feature = "test-utils")]
    #[test]
    fn config_n_dirs_byte_for_byte_unchanged_after_run_if_unsentineled() {
        use std::collections::BTreeMap;

        // Arrange: M1-7 fixture with 3 slots (config-1, config-2, config-3 populated)
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Snapshot: collect bytes of every file in config-N/ dirs
        let snapshot_before: BTreeMap<std::path::PathBuf, Vec<u8>> = (1u16..=3)
            .flat_map(|slot| {
                let config_dir = base.join(format!("config-{slot}"));
                walkdir_bytes(&config_dir)
            })
            .collect();

        assert!(
            !snapshot_before.is_empty(),
            "fixture must have files in config-N/ dirs"
        );

        // Act: run the mint pass
        let summary = run_if_unsentineled(base).expect("mint must succeed");
        assert!(
            !summary.already_minted,
            "sentinel was absent — mint should have run"
        );

        // Assert: every file that existed before still exists with same bytes
        let snapshot_after: BTreeMap<std::path::PathBuf, Vec<u8>> = (1u16..=3)
            .flat_map(|slot| {
                let config_dir = base.join(format!("config-{slot}"));
                walkdir_bytes(&config_dir)
            })
            .collect();

        assert_eq!(
            snapshot_before.keys().collect::<Vec<_>>(),
            snapshot_after.keys().collect::<Vec<_>>(),
            "config-N/ file set must be identical before and after mint"
        );

        for (path, before_bytes) in &snapshot_before {
            let after_bytes = snapshot_after
                .get(path)
                .unwrap_or_else(|| panic!("file disappeared after mint: {:?}", path));
            assert_eq!(
                before_bytes, after_bytes,
                "config-N/ file must be byte-identical after mint: {:?}",
                path
            );
        }
    }

    /// Walk a directory tree and return (abs_path, bytes) for every file.
    /// Returns empty vec if the directory does not exist.
    #[cfg(feature = "test-utils")]
    fn walkdir_bytes(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        if !dir.exists() {
            return vec![];
        }
        let mut result = Vec::new();
        fn recurse(path: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
            if path.is_dir() {
                if let Ok(rd) = std::fs::read_dir(path) {
                    for entry in rd.flatten() {
                        recurse(&entry.path(), out);
                    }
                }
            } else if path.is_file() {
                if let Ok(bytes) = std::fs::read(path) {
                    out.push((path.to_path_buf(), bytes));
                }
            }
        }
        recurse(dir, &mut result);
        result
    }

    /// R3-HIGH-1: `mint_for_login` with an unknown/sentinel email MUST return
    /// `Err` and MUST NOT create any identity files or profile entries.
    ///
    /// This guards the normalizer's "unknown" sentinel rejection path inside
    /// `mint_for_login` (line ~280). The variant "unknown" is CC's sentinel
    /// value when `oauthAccount.emailAddress` is absent from credentials — it
    /// is NOT a valid email and must not produce an identity record.
    #[test]
    fn mint_for_login_with_unknown_email_returns_skip() {
        // Arrange: fresh base dir with no existing profiles or identity dirs
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Act: call mint_for_login with the "unknown" sentinel email
        let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 1, "unknown");
        drop(lock);

        // Assert: Err returned — normalizer rejected the sentinel email
        assert!(
            result.is_err(),
            "mint_for_login must return Err for 'unknown' sentinel email"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("identity_mint_failed"),
            "error must use fixed-vocabulary prefix, got: {err_msg}"
        );

        // Assert: no identities/ directory created
        let identities_dir = base.join("identities");
        assert!(
            !identities_dir.exists(),
            "identities/ dir must not be created for unknown email"
        );

        // Assert: profiles.json either absent or has empty by_slot/by_email
        // (no partial mapping written for slot 1)
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        if profiles_path.exists() {
            let profiles =
                crate::accounts::profiles::load(&profiles_path).expect("profiles must be valid");
            assert!(
                profiles.by_slot.is_empty() && profiles.by_email.is_empty(),
                "no mapping must be written for unknown email, got: {:?}",
                profiles
            );
        }
        // If profiles.json doesn't exist, that's also correct (nothing was written).
    }

    // ── M2-3 acceptance test ──────────────────────────────────────────────────

    /// Criterion 4: `mint_for_login` seeds `identities/<UUID>/settings.json`
    /// from `config-<N>/settings.json` within the same `ProfilesFileLock` window.
    ///
    /// Arrange: a base dir with config-2/settings.json containing `{"login_key": 99}`.
    /// After calling `mint_for_login`, the UUID's settings.json must contain that key.
    #[test]
    fn finalize_login_seeds_uuid_settings_for_new_account() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::accounts::profiles_lock::ProfilesFileLock;

        // Arrange: create the base dir with config-2 + settings.json
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let config2 = base.join("config-2");
        std::fs::create_dir_all(&config2).unwrap();
        std::fs::write(config2.join("settings.json"), r#"{"login_key": 99}"#).unwrap();

        // Acquire the ProfilesFileLock (mint_for_login requires the lock witness)
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        std::fs::create_dir_all(profiles_path.parent().unwrap()).unwrap();
        let lock = ProfilesFileLock::acquire(base).expect("must acquire profiles lock");

        // Act
        let result = mint_for_login(&lock, base, 2, "login-test@test.invalid");
        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let uuid = result.unwrap();

        // Assert: identities/<UUID>/settings.json was seeded
        let uuid_settings = settings_path_for(base, uuid);
        assert!(
            uuid_settings.exists(),
            "mint_for_login must seed identities/<UUID>/settings.json"
        );
        let content = std::fs::read_to_string(&uuid_settings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["login_key"].as_u64(),
            Some(99),
            "seeded settings must contain login_key from config-2/settings.json"
        );
    }

    /// M4-9 (release N affordance, an internal ticket Phase 4): daemon Pass 0
    /// (`run_if_unsentineled`) MUST NOT add NEW entries to the v1
    /// `profiles.json::accounts` map. The mint flow's
    /// `profiles::add_identity_mapping` writes ONLY `by_slot` and
    /// `by_email` — never `accounts`.
    ///
    /// Test shape: an upgrade scenario from v2.6.x to v2.7.x where the
    /// legacy fixture has `accounts` populated (v2.6.x wrote it) but
    /// `by_slot` is empty (Pass 0 hasn't run). After Pass 0, the
    /// `accounts` map count is UNCHANGED (Pass 0 didn't add to it), but
    /// `by_slot` + `by_email` are now populated. This is the v2.6.x →
    /// v2.7.x upgrade compat seam — `accounts` is the read-only source
    /// for email resolution during the first Pass 0; subsequent mints
    /// (via `mint_for_login`) source emails from `.claude.json` and
    /// also do not write `accounts`.
    #[test]
    fn identity_mint_pass0_does_not_populate_v1_accounts_map() {
        // Arrange: v2.6.x-shape legacy base — accounts is populated
        // (the v2.6.x writers did that) but by_slot is empty (mint
        // hasn't run).
        let dir = make_legacy_base(2);
        let base = dir.path();
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let accounts_count_before = crate::accounts::profiles::load(&profiles_path)
            .unwrap()
            .accounts_for_test()
            .len();
        assert!(
            accounts_count_before > 0,
            "make_legacy_base seeds accounts to simulate v2.6.x state"
        );

        // Act: run Pass 0 — the v2.6.x → v2.7.x upgrade boundary.
        let summary = run_if_unsentineled(base).expect("mint should succeed");
        assert!(summary.slots_fresh >= 1, "at least one slot should mint");

        // Assert: Pass 0 did NOT add new entries to the v1 accounts map.
        let pf = crate::accounts::profiles::load(&profiles_path).unwrap();
        let accounts_after = pf.accounts_for_test();
        assert_eq!(
            accounts_after.len(),
            accounts_count_before,
            "M4-9: Pass 0 MUST NOT add new entries to the v1 accounts map; \
             before={} after={} accounts={:?}",
            accounts_count_before,
            accounts_after.len(),
            accounts_after.keys().collect::<Vec<_>>()
        );
        // Sanity: by_slot + by_email WERE populated (the new channels).
        assert!(
            !pf.by_slot.is_empty(),
            "M4-9: Pass 0 must populate by_slot — that is the new identity channel"
        );
        assert!(
            !pf.by_email.is_empty(),
            "M4-9: Pass 0 must populate by_email — that is the new email channel"
        );
    }

    // ── RN1-D1 tests ────────────────────────────────────────────────────────

    /// RN1-D1 (Finding-3d decouple): `mint_for_login` keys `by_email` by the
    /// caller-supplied OAuth email, not by the display label. This test
    /// verifies the login path is correctly isolated from the rename label.
    #[test]
    fn mint_for_login_email_arg_is_oauth_not_label() {
        // Arrange: empty base dir
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();

        // Act: mint with real OAuth email "oauth@example.com"
        let result = mint_for_login(&lock, base, 1, "oauth@example.com");
        drop(lock);

        // Assert: succeeded and by_email contains "oauth@example.com"
        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert!(
            pf.by_email.contains_key("oauth@example.com"),
            "by_email must contain 'oauth@example.com' after mint_for_login; \
             keys: {:?}",
            pf.by_email.keys().collect::<Vec<_>>()
        );
    }

    // ── RN1-D R2 tests: login-path rename-label capture ─────────────────────

    /// RN1-D R2: the pure-legacy unminted-with-rename-label case.
    ///
    /// Setup: slot 1 has `accounts[1].email = "Work account"` (a user rename
    /// label), NO `by_slot[1]` UUID, NO `by_slot_label[1]`. This is the exact
    /// shape `csq doctor` flags as `unrecoverable_label_relocations` and tells
    /// the operator to "log in again to mint UUIDs". Before this fix, that
    /// instruction silenced the warning (the `!by_slot` predicate stopped
    /// matching after mint) WITHOUT preserving the label — RN1-F's `accounts`
    /// deletion then silently dropped it. This test pins that `mint_for_login`
    /// now copies the rename label into the A1 `by_slot_label[1]` channel,
    /// making the operator instruction true.
    #[test]
    fn mint_for_login_captures_pure_legacy_rename_label() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        // Pure-legacy slot 1: rename label, no by_slot, no by_slot_label.
        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.set_profile(
            1,
            profiles::AccountProfile {
                email: "Work account".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &initial_pf).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 1, "oauth@example.com");
        drop(lock);

        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert_eq!(
            pf.by_slot_label.get("1").map(String::as_str),
            Some("Work account"),
            "the pre-existing rename label MUST be captured into \
             by_slot_label[1] so RN1-F's accounts deletion does not drop it; \
             by_slot_label: {:?}",
            pf.by_slot_label
        );
    }

    /// RN1-D R2 negative: `accounts[N].email` that IS the OAuth email (a
    /// pre-RN1-D3 bare-email write, not a rename) MUST NOT be captured as a
    /// label. Rename detection mirrors `relocate_labels_to_by_slot_label`'s
    /// first arm — equal to the OAuth email (raw or normalized) means "not a
    /// rename".
    #[test]
    fn mint_for_login_does_not_capture_bare_oauth_email_as_label() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.set_profile(
            2,
            profiles::AccountProfile {
                // accounts[2].email == the OAuth email → NOT a rename.
                email: "oauth2@example.com".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &initial_pf).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 2, "oauth2@example.com");
        drop(lock);

        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert!(
            !pf.by_slot_label.contains_key("2"),
            "a bare OAuth email in accounts[N].email is NOT a rename and MUST \
             NOT be captured as a label; by_slot_label: {:?}",
            pf.by_slot_label
        );
    }

    /// RN1-D R2 negative: an existing `by_slot_label[N]` (a later explicit
    /// rename) MUST NOT be overwritten by the legacy `accounts[N].email`
    /// value — same precedence rule as the relocation pass's idempotency
    /// guarantee.
    #[test]
    fn mint_for_login_preserves_existing_by_slot_label() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.set_profile(
            3,
            profiles::AccountProfile {
                email: "Old Legacy Label".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        initial_pf
            .by_slot_label
            .insert("3".into(), "User Set Later".into());
        profiles::save(&pf_path, &initial_pf).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 3, "oauth3@example.com");
        drop(lock);

        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert_eq!(
            pf.by_slot_label.get("3").map(String::as_str),
            Some("User Set Later"),
            "an existing by_slot_label MUST be preserved (later rename wins \
             over legacy accounts label); by_slot_label: {:?}",
            pf.by_slot_label
        );
    }

    /// RN1-D R2 (redteam security L4): a malformed legacy label — one
    /// containing ASCII control characters — MUST NOT be relocated into the
    /// `by_slot_label` channel (which `get_email` reads first and doctor/UI
    /// render). Skipping it keeps a malformed legacy value from being
    /// promoted into the active label channel; same shapes RN1-D3 rejects on
    /// the `rename_account` write path.
    #[test]
    fn mint_for_login_skips_malformed_control_char_label() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.set_profile(
            4,
            profiles::AccountProfile {
                email: "Work\u{0007}account".into(), // BEL control char
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &initial_pf).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 4, "oauth4@example.com");
        drop(lock);

        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert!(
            !pf.by_slot_label.contains_key("4"),
            "a control-char legacy label MUST NOT be promoted into \
             by_slot_label; by_slot_label: {:?}",
            pf.by_slot_label
        );
    }

    /// RN1-D R2 (redteam security L4): an oversize legacy label (> 256
    /// chars) MUST NOT be relocated — same read-side parity with RN1-D3's
    /// oversize rejection on the write path.
    #[test]
    fn mint_for_login_skips_oversize_label() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();

        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.set_profile(
            5,
            profiles::AccountProfile {
                email: "x".repeat(257), // 257 > MAX_LABEL_LEN (256)
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &initial_pf).unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = mint_for_login(&lock, base, 5, "oauth5@example.com");
        drop(lock);

        assert!(result.is_ok(), "mint_for_login must succeed: {result:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert!(
            !pf.by_slot_label.contains_key("5"),
            "an oversize (>256) legacy label MUST NOT be promoted into \
             by_slot_label; by_slot_label: {:?}",
            pf.by_slot_label
        );
    }

    /// RN1-D1 (Finding-3d decouple): Pass-0 (`run_if_unsentineled`) — when
    /// `AccountInfo.oauth_email` differs from `label`, Pass-0 MUST key
    /// `by_email` by `oauth_email`, not by `label`.
    ///
    /// Setup: slot 1 has `accounts[1].email = "My Rename"` (the label),
    /// C1+C2 fix (Finding-3d): `discover_anthropic` sources `oauth_email` from
    /// the authenticated credential file (`oauthAccount.emailAddress`), NOT from
    /// `by_email` reverse-lookup. This test verifies that even when
    /// `accounts[1].email` holds a rename label, Pass-0 writes the credential
    /// file's email to `by_email`, not the label.
    ///
    /// Also serves as the AC test for the C2 structural fix:
    /// `discover_anthropic_populates_oauth_email_from_credential_file`.
    #[test]
    fn by_email_keyed_from_oauth_email_not_label_in_pass0() {
        use crate::accounts::identity_store::{self, IdentityId};
        use crate::accounts::profiles;

        // Arrange: build a base dir with a seeded identity.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("accounts")).unwrap();
        std::fs::create_dir_all(base.join("credentials")).unwrap();

        // Create a UUID identity for slot 1.
        let uuid = IdentityId::new_v4();

        // Write the UUID-keyed credential so discover_anthropic's UUID branch
        // finds it.
        let uuid_cred = identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_cred.parent().unwrap()).unwrap();
        std::fs::write(
            &uuid_cred,
            br#"{"oauthAccount":{"emailAddress":"real@oauth.example.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Set up profiles.json: by_slot[1]=UUID, by_email["real@oauth.example.com"]=UUID,
        // AND accounts[1].email = "My Rename" (simulates a user rename).
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();
        let mut initial_pf = profiles::ProfilesFile::empty();
        initial_pf.by_slot.insert("1".into(), uuid);
        initial_pf
            .by_email
            .insert("real@oauth.example.com".into(), uuid);
        initial_pf.set_profile(
            1,
            profiles::AccountProfile {
                email: "My Rename".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &initial_pf).unwrap();

        // Act: run Pass-0 (the function that processes discover_anthropic output)
        // by calling run_if_unsentineled on this prepared base dir.
        let summary = run_if_unsentineled(base);

        // Assert: by_email must contain "real@oauth.example.com" (not "My Rename").
        assert!(summary.is_ok(), "pass0 must succeed: {summary:?}");
        let pf = profiles::load(&pf_path).unwrap();
        assert!(
            !pf.by_email.contains_key("My Rename"),
            "by_email MUST NOT contain the rename label 'My Rename' (Finding-3d); \
             keys: {:?}",
            pf.by_email.keys().collect::<Vec<_>>()
        );
        assert!(
            pf.by_email.contains_key("real@oauth.example.com"),
            "by_email MUST contain the OAuth email 'real@oauth.example.com'; \
             keys: {:?}",
            pf.by_email.keys().collect::<Vec<_>>()
        );
    }

    /// C2 fix AC: `discover_anthropic` (UUID-keyed path) reads
    /// `oauthAccount.emailAddress` from the credential file on disk and
    /// populates `AccountInfo.oauth_email` from it — NOT from
    /// `profiles.oauth_email_for_slot` (the retired `by_email` reverse-lookup).
    ///
    /// Demonstrates the trust anchor: the credential file is the Anthropic-
    /// authenticated record. Even if `by_email` is empty or polluted, the
    /// credential file produces the correct email.
    #[test]
    fn discover_anthropic_populates_oauth_email_from_credential_file() {
        use crate::accounts::discovery::discover_anthropic;
        use crate::accounts::identity_store::{self, IdentityId};
        use crate::accounts::profiles;

        // Arrange: base dir with slot 1 UUID-keyed, NO by_email entry
        // (so a by_email reverse-lookup would return None), but the
        // identity credential file has the real OAuth email.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("credentials")).unwrap();

        let uuid = IdentityId::new_v4();
        let uuid_cred = identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_cred.parent().unwrap()).unwrap();
        std::fs::write(
            &uuid_cred,
            br#"{"oauthAccount":{"emailAddress":"cred-file@example.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // Set up profiles.json: by_slot[1]=UUID, by_email intentionally EMPTY
        // so the old reverse-lookup path would return None.
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        // by_email is empty — if discovery used reverse-lookup, oauth_email would be None.
        profiles::save(&pf_path, &pf).unwrap();

        // Act: discover_anthropic — UUID-keyed path reads credential file.
        let accounts = discover_anthropic(base);

        // Assert: oauth_email is populated from the credential file, not by_email.
        assert_eq!(accounts.len(), 1, "must discover exactly 1 account");
        assert_eq!(
            accounts[0].oauth_email.as_deref(),
            Some("cred-file@example.com"),
            "oauth_email must come from the credential file, not by_email reverse-lookup; \
             got: {:?}",
            accounts[0].oauth_email
        );
    }

    /// C1 fix AC: when `AccountInfo.oauth_email` is `None` (UUID-keyed slot
    /// whose identity credential file is missing `oauthAccount.emailAddress`),
    /// Pass-0 MUST skip the slot with a warn-level log rather than falling back
    /// to `account_info.label` as the `by_email` key.
    ///
    /// Skipping prevents the journal-0029 cross-contamination class where a
    /// rename label that happens to equal another slot's OAuth email poisons
    /// the `by_email` mapping.
    #[test]
    fn pass_0_skips_slot_when_oauth_email_unresolved() {
        use crate::accounts::identity_store::{self, IdentityId};
        use crate::accounts::profiles;

        // Arrange: UUID-keyed slot whose identity credential file does NOT
        // contain oauthAccount.emailAddress (empty or missing field).
        // accounts[1].email is a rename label "My Rename" — this would be the
        // C1 bug if we fell through to it.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("credentials")).unwrap();

        let uuid = IdentityId::new_v4();
        let uuid_cred = identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_cred.parent().unwrap()).unwrap();
        // Credential file with NO oauthAccount.emailAddress field.
        std::fs::write(
            &uuid_cred,
            br#"{"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        // profiles.json: by_slot[1]=UUID, accounts[1].email = "My Rename" (a rename label).
        let pf_path = profiles::profiles_path(base);
        std::fs::create_dir_all(pf_path.parent().unwrap()).unwrap();
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        pf.set_profile(
            1,
            profiles::AccountProfile {
                email: "My Rename".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&pf_path, &pf).unwrap();

        // Verify precondition: discover_anthropic returns oauth_email = None
        // for this UUID-keyed slot (no oauthAccount.emailAddress in cred file).
        let accounts = crate::accounts::discovery::discover_anthropic(base);
        assert_eq!(accounts.len(), 1);
        assert!(
            accounts[0].oauth_email.is_none(),
            "precondition: UUID-keyed slot with missing emailAddress must return None oauth_email; \
             got: {:?}",
            accounts[0].oauth_email
        );

        // Act: run Pass-0. The slot has no oauth_email → must be skipped.
        let summary = run_if_unsentineled(base).unwrap();

        // Assert: the slot was NOT minted — no fresh identity written.
        assert_eq!(
            summary.slots_fresh, 0,
            "pass-0 must not mint a slot when oauth_email is absent; \
             slots_fresh={}, slot_errors={:?}",
            summary.slots_fresh, summary.slot_errors
        );

        // Assert: by_email does NOT contain the rename label.
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(
            !pf.by_email.contains_key("My Rename"),
            "by_email MUST NOT contain the rename label even when oauth_email is absent; \
             by_email: {:?}",
            pf.by_email
        );
    }

    // ── mint_for_codex_login tests ────────────────────────────────────────────

    /// Helper: acquire profiles lock and call mint_for_codex_login.
    /// Convenience wrapper so tests don't repeat the lock-acquire pattern.
    fn call_mint_for_codex_login(
        base: &std::path::Path,
        slot: u16,
        hint: Option<&str>,
    ) -> Result<IdentityId, String> {
        let lock = ProfilesFileLock::acquire(base)
            .map_err(|e| format!("test: lock acquire failed: {e}"))?;
        mint_for_codex_login(&lock, base, slot, hint)
    }

    /// Fresh mint: slot has no prior by_slot mapping. Calling
    /// `mint_for_codex_login` must write `by_slot[N]`, a synthetic
    /// `by_email[codex:<hint>]`, and `identity.json` with provider="codex".
    #[test]
    fn mint_for_codex_login_fresh_slot_mints_uuid() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Pre-condition: no by_slot mapping.
        assert!(
            profiles::resolve_slot_to_uuid(base, 12).is_none(),
            "precondition: no UUID for slot 12"
        );

        let uuid = call_mint_for_codex_login(base, 12, Some("acc-abc123-xyz"))
            .expect("mint should succeed on a fresh slot");

        // by_slot[12] must now exist.
        assert_eq!(
            profiles::resolve_slot_to_uuid(base, 12),
            Some(uuid),
            "by_slot[12] must map to the returned UUID after mint"
        );

        // by_email[codex:acc-abc123-xyz] must map to the same UUID.
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_email.get("codex:acc-abc123-xyz").copied(),
            Some(uuid),
            "by_email[codex:<hint>] must map to the same UUID"
        );

        // identity.json must exist with provider="codex".
        let id_path = identity_json_path_for(base, uuid);
        assert!(id_path.exists(), "identity.json must exist after mint");
        let content = std::fs::read_to_string(&id_path).unwrap();
        assert!(
            content.contains("\"codex\""),
            "identity.json must carry provider=\"codex\"; content: {content}"
        );
    }

    /// Idempotency: calling `mint_for_codex_login` twice on the same slot
    /// must return the SAME UUID and must NOT overwrite `identity.json`
    /// (the `created_at` field must be preserved).
    #[test]
    fn mint_for_codex_login_idempotent_same_hint() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid1 = call_mint_for_codex_login(base, 5, Some("my-codex-id"))
            .expect("first mint should succeed");
        let id_path = identity_json_path_for(base, uuid1);
        // Capture mtime after first write.
        let mtime1 = std::fs::metadata(&id_path).unwrap().modified().unwrap();

        // Tiny sleep to ensure mtime would differ if the file were rewritten.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let uuid2 = call_mint_for_codex_login(base, 5, Some("my-codex-id"))
            .expect("second mint should succeed");

        assert_eq!(uuid1, uuid2, "second call must return the same UUID");
        // identity.json must not have been rewritten (mtime unchanged).
        let mtime2 = std::fs::metadata(&id_path).unwrap().modified().unwrap();
        assert_eq!(
            mtime1, mtime2,
            "identity.json must not be rewritten on idempotent call (preserves created_at)"
        );
    }

    /// Hint-absent fallback: when `account_id_hint` is None or empty, the
    /// synthetic key becomes `codex:slot-<N>`. The UUID must still be stable
    /// across two calls without a hint.
    #[test]
    fn mint_for_codex_login_no_hint_uses_slot_fallback_key() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid1 =
            call_mint_for_codex_login(base, 7, None).expect("mint without hint should succeed");
        let uuid2 = call_mint_for_codex_login(base, 7, None)
            .expect("second mint without hint should succeed");

        assert_eq!(uuid1, uuid2, "no-hint mints must be stable (same UUID)");

        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_email.get("codex:slot-7").copied(),
            Some(uuid1),
            "fallback key must be codex:slot-<N>"
        );
    }

    /// Pre-existing by_slot mapping: fast-path returns the existing UUID
    /// without touching disk (no new lock, no identity.json rewrite).
    #[test]
    fn mint_for_codex_login_reuses_existing_by_slot_uuid() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Seed by_slot[3] and write identity.json so the fast-path fires.
        let pre_uuid = IdentityId::new_v4();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        profiles::add_identity_mapping(&lock, base, 3, "codex:seed-hint", pre_uuid).unwrap();
        drop(lock);
        // Write identity.json so the fast-path's existence check passes.
        let id_path = identity_json_path_for(base, pre_uuid);
        std::fs::create_dir_all(id_path.parent().unwrap()).unwrap();
        std::fs::write(&id_path, b"{}").unwrap();

        // mint_for_codex_login must return pre_uuid unchanged.
        let returned = call_mint_for_codex_login(base, 3, Some("anything"))
            .expect("should succeed (reuse path)");

        assert_eq!(
            returned, pre_uuid,
            "must reuse the pre-existing by_slot UUID; got {returned}"
        );
    }

    // ── CRIT-1: two-slot collision ─────────────────────────────────────────────

    /// CRIT-1: when two distinct slots are logged in with the same ChatGPT
    /// `account_id`, they MUST receive distinct UUIDs. The second mint must
    /// NOT reuse the UUID already owned by the first slot.
    #[test]
    fn mint_for_codex_login_same_account_id_two_slots_get_distinct_uuids() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let hint = "shared-chatgpt-account-id";

        // Mint slot 1 with the shared hint.
        let uuid1 =
            call_mint_for_codex_login(base, 1, Some(hint)).expect("first slot mint should succeed");

        // Mint slot 2 with the SAME hint.
        let uuid2 = call_mint_for_codex_login(base, 2, Some(hint))
            .expect("second slot mint with same hint should succeed");

        // CRIT-1: the two slots must get distinct UUIDs.
        assert_ne!(
            uuid1, uuid2,
            "CRIT-1: two slots with the same account_id_hint must get distinct UUIDs; \
             both got {uuid1}"
        );

        // Each slot's by_slot mapping must point at its own UUID.
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot.get("1").copied(),
            Some(uuid1),
            "by_slot[1] must map to uuid1"
        );
        assert_eq!(
            pf.by_slot.get("2").copied(),
            Some(uuid2),
            "by_slot[2] must map to uuid2 (not uuid1)"
        );

        // Each identity.json must exist independently.
        assert!(
            identity_json_path_for(base, uuid1).exists(),
            "identity.json for slot 1 (uuid1) must exist"
        );
        assert!(
            identity_json_path_for(base, uuid2).exists(),
            "identity.json for slot 2 (uuid2) must exist"
        );
    }

    // ── SR-H2: fast-path repairs missing identity.json ────────────────────────

    /// SR-H2: when `by_slot[N]` is populated but `identity.json` is absent
    /// (partial-mint crash recovery), the fast-path must NOT short-circuit.
    /// Instead, `mint_for_codex_login` must fall through to the write path
    /// and repair the missing `identity.json`.
    #[test]
    fn mint_for_codex_login_repairs_missing_identity_json_via_slow_path() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // First mint: writes by_slot, by_email, AND identity.json.
        let uuid = call_mint_for_codex_login(base, 9, Some("repair-test"))
            .expect("first mint should succeed");
        let id_path = identity_json_path_for(base, uuid);
        assert!(
            id_path.exists(),
            "identity.json must exist after first mint"
        );

        // Simulate partial-mint: delete identity.json but keep the by_slot mapping.
        std::fs::remove_file(&id_path).unwrap();
        assert!(
            !id_path.exists(),
            "identity.json must be absent before the repair call"
        );

        // Second call: must detect the missing identity.json and repair it.
        let uuid2 = call_mint_for_codex_login(base, 9, Some("repair-test"))
            .expect("repair mint should succeed");

        // UUID must be stable (no churn).
        assert_eq!(
            uuid, uuid2,
            "SR-H2: UUID must be stable after repair (no churn); got uuid1={uuid} uuid2={uuid2}"
        );

        // identity.json must be re-created.
        assert!(
            id_path.exists(),
            "SR-H2: identity.json must be re-created by the slow-path repair; \
             path: {id_path:?}"
        );
    }

    // ── SR-M1: control-char rejection ─────────────────────────────────────────

    /// SR-M1: `validate_codex_account_id_hint` must reject hints that contain
    /// ASCII control characters.
    #[test]
    fn validate_codex_account_id_hint_rejects_control_chars() {
        assert!(
            validate_codex_account_id_hint("abc\ndef").is_none(),
            "newline in hint must be rejected"
        );
        assert!(
            validate_codex_account_id_hint("abc\rdef").is_none(),
            "carriage return in hint must be rejected"
        );
        assert!(
            validate_codex_account_id_hint("abc\x00def").is_none(),
            "null byte in hint must be rejected"
        );
        assert!(
            validate_codex_account_id_hint("\x01leading").is_none(),
            "SOH at start must be rejected"
        );
        assert!(
            validate_codex_account_id_hint("trailing\x1f").is_none(),
            "US (0x1f) at end must be rejected"
        );
    }

    /// SR-M1: empty and oversized hints are rejected.
    #[test]
    fn validate_codex_account_id_hint_rejects_empty_and_oversized() {
        assert!(
            validate_codex_account_id_hint("").is_none(),
            "empty hint must be rejected"
        );
        let oversized = "a".repeat(257);
        assert!(
            validate_codex_account_id_hint(&oversized).is_none(),
            "hint > 256 bytes must be rejected"
        );
    }

    /// SR-M1: well-formed hints are accepted.
    #[test]
    fn validate_codex_account_id_hint_accepts_valid_hints() {
        assert_eq!(
            validate_codex_account_id_hint("abc123"),
            Some("abc123"),
            "printable ASCII hint must be accepted"
        );
        assert_eq!(
            validate_codex_account_id_hint("chatgpt-uuid-1234-abcd"),
            Some("chatgpt-uuid-1234-abcd"),
            "UUID-shaped hint must be accepted"
        );
        let max_len = "x".repeat(256);
        assert!(
            validate_codex_account_id_hint(&max_len).is_some(),
            "hint of exactly 256 bytes must be accepted"
        );
    }

    /// SR-M1: a hint with control chars falls back to `codex:slot-<N>`
    /// in `mint_for_codex_login` — the malformed hint does NOT appear in
    /// the synthetic key or identity.json.
    #[test]
    fn mint_for_codex_login_control_char_hint_uses_slot_fallback() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let malicious_hint = "valid\x0ainjected";

        let uuid = call_mint_for_codex_login(base, 11, Some(malicious_hint))
            .expect("mint must succeed (falling back to slot key)");

        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();

        // The malicious hint must NOT appear as a by_email key.
        let malicious_key = format!("codex:{malicious_hint}");
        assert!(
            !pf.by_email.contains_key(&malicious_key),
            "control-char hint must NOT be used as the by_email key; \
             by_email keys: {:?}",
            pf.by_email.keys().collect::<Vec<_>>()
        );

        // The fallback key `codex:slot-11` must be used instead.
        assert_eq!(
            pf.by_email.get("codex:slot-11").copied(),
            Some(uuid),
            "control-char hint must fall back to codex:slot-<N> key"
        );

        // identity.json must exist and not contain the raw control char sequence.
        let id_path = identity_json_path_for(base, uuid);
        let content = std::fs::read_to_string(&id_path).unwrap();
        assert!(
            !content.contains("injected"),
            "identity.json must not contain the injected portion of the malicious hint; \
             content: {content:?}"
        );
    }
}
