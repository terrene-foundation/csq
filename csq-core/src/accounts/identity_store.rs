//! Identity-keyed account storage primitives — an internal ticket (A++) Phase 1.
//!
//! This module is the entry surface for the A++ migration to identity-keyed
//! account paths. In Phase 1 it is **additive**: no production reader
//! consumes [`identity_path`] yet — readers stay on slot-keyed `config-N/`
//! paths through Phase 1. The module exists so that:
//!
//! 1. The [`IdentityId`] newtype is the canonical type for "which account"
//!    once Phase 2 wires the readers.
//! 2. Path helpers ([`identity_path`], [`identity_json_path_for`],
//!    [`store_version_path`]) chokepoint all identity-store path
//!    construction so there is no inline `format!("identities/{uuid}")`
//!    drift class.
//! 3. The daemon's first-start mint flow (M1-4, lands later) materializes
//!    `identities/<UUID>/identity.json` via these helpers.
//!
//! See `internal-design-docs`
//! and `an internal journal entry`
//! for the design context.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;

/// Identity for an account. Wraps a UUID v4.
///
/// Serializes as a canonical hyphenated UUID string (e.g.
/// `550e8400-e29b-41d4-a716-446655440000`). Deserialization rejects any
/// string that does not parse as a UUID — there is no `Default` fallback,
/// so a corrupted identity file fails loud instead of silently materializing
/// the nil UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(Uuid);

impl IdentityId {
    /// Generates a new random (v4) identity.
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Renders as the canonical hyphenated lowercase form. Stable across
    /// process invocations and platform.
    pub fn to_canonical_string(&self) -> String {
        self.0.as_hyphenated().to_string()
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_hyphenated())
    }
}

impl FromStr for IdentityId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

impl From<Uuid> for IdentityId {
    /// Wraps a `Uuid` as an `IdentityId`.
    ///
    /// Used by the test fixture surface (`crate::testing::identity_fixtures`)
    /// to construct deterministic identities from seeded byte arrays via
    /// `Uuid::from_bytes`. Not intended for production use.
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Returns `<base>/identities/`.
///
/// `base` is the csq accounts root — typically `~/.claude/accounts/`.
pub fn identities_dir(base: &Path) -> PathBuf {
    base.join("identities")
}

/// Returns `<base>/identities/<uuid>/`.
pub fn identity_path(base: &Path, id: IdentityId) -> PathBuf {
    identities_dir(base).join(id.to_canonical_string())
}

/// Returns `<base>/identities/<uuid>/identity.json`.
///
/// `identity.json` carries the **immutable** side of an account in Phase 1:
/// email, provider, created_at, key_id. Mutable state (credentials,
/// settings, usage) stays slot-keyed through Phase 1 — see an internal journal entry D4.
pub fn identity_json_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("identity.json")
}

/// Returns `<base>/identities/<uuid>/credentials.json`.
///
/// Phase 2 adds this as the canonical write site for OAuth tokens.  In Phase 1
/// this path may not exist; callers MUST treat its absence as a graceful skip.
pub fn credentials_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("credentials.json")
}

/// Returns `<base>/identities/<uuid>/settings.json`.
///
/// Phase 2 materialises this from `config-<N>/settings.json` on first start
/// and from `csq login` for new accounts.  In Phase 1 this path may not exist.
pub fn settings_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("settings.json")
}

/// Returns `<base>/identities/<uuid>/usage.ndjson`.
///
/// Phase 2 (M2-5) routes usage ledger writes through this path when a UUID
/// is available for the slot. Legacy fallback (`usage-{slot}.ndjson`) remains
/// in [`crate::usage::ledger::ledger_path`] for slots without a UUID mapping.
pub fn usage_ledger_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("usage.ndjson")
}

/// Returns `<base>/identities/<uuid>/token-history`.
///
/// Bounded per-identity history of the SHA-256 fingerprints (never the raw
/// tokens themselves) of every Anthropic refresh token this identity's
/// canonical store has held — see `crate::credentials::token_history`
/// (`pub(crate)`, so not linkable from this public doc). Absence means "no
/// history recorded yet" (a fresh identity, or one minted before this file
/// existed), which callers MUST treat as a graceful, non-fatal empty history
/// rather than an error.
pub fn token_history_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("token-history")
}

/// `keychain-fix-r11.md` D-5: returns `<base>/identities/<uuid>.removed` — a
/// TOMBSTONE for a logged-out identity, deliberately a SIBLING of
/// `identities/<uuid>/` (never inside it), so it SURVIVES `logout_account`'s
/// `remove_dir_all` of the identity dir itself.
///
/// **The gap this closes.** `credentials::file::save_uuid_credentials` is
/// the single canonical-store chokepoint for the refresher, backsync, the
/// custodian's adopt path, AND login — and it unconditionally
/// `create_dir_all`s the identity dir if absent, because a FRESH login
/// legitimately needs that on first provisioning. `logout_account` removes
/// the identity dir with no lock shared with any of those writers, so a
/// refresher tick (or backsync, or an in-flight adopt) racing a logout can
/// silently RECREATE the just-removed identity dir and write a token into
/// it — resurrecting a credential the operator just logged out. Absent vs.
/// removed are indistinguishable to `create_dir_all` alone; this tombstone
/// is the third state a writer can check for. `is_identity_removed`/
/// `mark_identity_removed`/`clear_identity_removed_marker` are the
/// read/write/clear primitives; `logout_account` writes the marker in the
/// SAME step it removes the dir, `save_uuid_credentials` refuses to write
/// (fail closed) when it is present, and a fresh authorization event for
/// that SAME uuid (`daemon::identity_mint::mint_for_login`) clears it —
/// a legitimate new login supersedes a stale removal.
pub fn identity_removed_marker_path(base: &Path, id: IdentityId) -> PathBuf {
    identities_dir(base).join(format!("{}.removed", id.to_canonical_string()))
}

/// `true` iff `id` was logged out and no subsequent login has cleared the
/// tombstone. Absence of the marker file (including any read error — a
/// missing `identities/` dir, permission failure) reads as "not removed",
/// which is the correct default for a fresh identity that was never logged
/// out at all.
pub fn is_identity_removed(base: &Path, id: IdentityId) -> bool {
    identity_removed_marker_path(base, id).is_file()
}

/// Writes the tombstone for `id`. Best-effort (`security.md` Rule 3: logged,
/// never fatal to the logout it is part of) — the marker holds no secret, so
/// a plain empty-file create is sufficient; no atomic-replace ceremony is
/// needed for a file whose only meaningful state is "exists or not".
pub fn mark_identity_removed(base: &Path, id: IdentityId) {
    let path = identity_removed_marker_path(base, id);
    if let Err(e) = std::fs::write(&path, b"") {
        tracing::warn!(
            error_kind = "identity_removed_marker_write_failed",
            "logout: could not write the identity-removed tombstone for this \
             uuid; a concurrent writer racing this logout could resurrect \
             the credential: {}",
            crate::error::redact_tokens(&e.to_string())
        );
    }
}

/// Clears `id`'s tombstone, if any — called by a fresh authorization event
/// for the SAME uuid, which supersedes a stale removal. Best-effort:
/// `remove_file`'s `NotFound` is the common case (nothing to clear) and any
/// other failure is logged, non-fatal (never blocks the login it is part
/// of).
pub fn clear_identity_removed_marker(base: &Path, id: IdentityId) {
    let path = identity_removed_marker_path(base, id);
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                error_kind = "identity_removed_marker_clear_failed",
                "login: could not clear a prior identity-removed tombstone \
                 for this uuid (non-fatal): {}",
                crate::error::redact_tokens(&e.to_string())
            );
        }
    }
}

/// Returns `<base>/store-version`.
///
/// The store-version sentinel is the Phase 1 idempotency marker: presence
/// means a prior daemon start has minted identities for every legacy
/// `config-N/` it discovered. Subsequent daemon starts observe the sentinel
/// and skip re-mint.
pub fn store_version_path(base: &Path) -> PathBuf {
    base.join("store-version")
}

/// Resolved paths for a given account number, routing through the identity
/// store when a UUID is available and falling back to `config-N/` when not.
///
/// This struct is the chokepoint for all per-account path construction in
/// Phase 3. Consumers (M3-3 `create_handle_dir`, M3-4 `repoint_handle_dir`)
/// call [`account_to_identity_paths`] once and build their symlink targets
/// from the returned fields.
///
/// # Marker source path
///
/// `marker_source_path` is **always** `config-N/.csq-account` regardless of
/// whether a UUID was resolved.  This is a deliberate, load-bearing constant
/// per:
///
/// - an internal journal entry OQ #2 resolution (Option A): markers stay at `config-N/`
///   through Phase 4 per cross-phase constraint #3.
/// - `rules/account-terminal-separation.md` MUST NOT Rule 3: "The
///   `.csq-account` marker is the SOLE authority for 'which account is this
///   session using.'"  Handle-dir `.csq-account` symlinks continue to resolve
///   to `config-<current>/.csq-account` until Phase 4 emits UUID-keyed
///   markers.
///
/// Changing this constant before the Phase 4 marker-writer migration would
/// break `scan_live_handle_dirs_for_account_pub` (M3-6) and the entire
/// terminal-attribution chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPaths {
    /// Path to the OAuth credentials file for the ClaudeCode surface.
    ///
    /// Identity-keyed: `<base>/identities/<UUID>/credentials.json`
    /// Legacy: `<base>/config-<N>/.credentials.json`
    pub credentials_path: std::path::PathBuf,

    /// Path to the per-account settings file.
    ///
    /// Identity-keyed: `<base>/identities/<UUID>/settings.json`
    /// Legacy: `<base>/config-<N>/settings.json`
    pub settings_path: std::path::PathBuf,

    /// Path to the `.csq-account` marker file.
    ///
    /// **Always** `<base>/config-<N>/.csq-account`, regardless of
    /// `is_identity_keyed`.  See struct-level doc comment for rationale
    /// (an internal journal entry OQ #2 + cross-phase constraint #3).
    pub marker_source_path: std::path::PathBuf,

    /// `true` when the slot had a UUID in `profiles.json::by_slot` and the
    /// identity-keyed paths were returned.  `false` for legacy-only installs
    /// or any slot that has not yet been through the A++ mint pass.
    pub is_identity_keyed: bool,
}

/// The credential file a forced keychain write (`csq swap` A1,
/// `daemon::auto_rotate` A1) must read the NEW account's token from —
/// resolved through [`account_to_identity_paths`], the SAME chokepoint
/// [`crate::session::handle_dir::repoint_handle_dir`] uses to pick its
/// post-repoint symlink target (M3-4/M3-7). Never source this token from a
/// hardcoded `config-{N}/.credentials.json` guess instead — M3-7 retired
/// csq's own writer to that legacy path for any UUID-keyed slot, so a stale
/// or absent config-N copy would silently mirror the WRONG (or no) token
/// into the keychain for such a slot (`guard-reader-writer-parity.md`
/// MUST-1: this reader must recognise every form a writer — here,
/// `repoint_handle_dir` — targets).
///
/// UUID-keyed slot -> `identities/<UUID>/credentials.json`; legacy slot (no
/// `profiles.json` mapping) -> `config-<N>/.credentials.json`, which CC's
/// own `claude auth login` subprocess still writes directly (M3-7 retired
/// only csq's writers, not CC's).
pub fn credential_file_for_slot_write(base: &Path, account: crate::types::AccountNum) -> PathBuf {
    account_to_identity_paths(base, account).credentials_path
}

/// F5: the raw `.credentials.json` content of the account being switched
/// TO, read through [`credential_file_for_slot_write`] — the SAME resolver
/// `repoint_handle_dir` uses to pick its post-repoint symlink target.
///
/// `csq swap`'s same-surface ClaudeCode route and `daemon::auto_rotate`'s
/// tick both need exactly this before a v4 forced keychain write (A1); both
/// used to inline `std::fs::read_to_string(credential_file_for_slot_write(..))
/// .ok()` independently, which is the shape `guard-reader-writer-parity.md`
/// MUST-1 warns against — two readers of the same state that can silently
/// drift apart (e.g. one forgetting the identity-aware resolver and falling
/// back to a hardcoded `config-{N}/.credentials.json` guess). One function,
/// used by both, makes that drift a compile-time impossibility.
///
/// Outcome of reading an account's own canonical credential file for a
/// forced keychain write / reconcile decision (H1). `read_to_string(..).ok()`
/// alone cannot distinguish "the file does not exist / cannot be read" from
/// "the file exists but holds no live Anthropic token" (a 3P/Codex-only
/// slot, or one whose token has expired) — both used to fold into the same
/// `None`, which is fine for a caller that only asks "is there a token to
/// write" (every EXISTING caller — see [`TargetToken::as_valid_str`]) but is
/// exactly the distinction `reconcile_keychain_to_marker`'s rule 4 fallback
/// needs when deciding whether the marker account's OWN canonical token can
/// be trusted at all before it is used to overwrite X.
/// Deliberately does NOT `#[derive(Debug)]` (`credential-type-hygiene.md`
/// Rule 1): `Valid` carries the raw credential JSON, which contains a live
/// OAuth access+refresh token pair. The manual impl below redacts it; see
/// `target_token_debug_redacts_valid`.
#[derive(Clone, PartialEq, Eq)]
pub enum TargetToken {
    /// The file was read and its content is a live (non-expired) Anthropic
    /// `claudeAiOauth` token.
    Valid(String),
    /// The file was read, but its content is not a live Anthropic token —
    /// missing `claudeAiOauth` entirely (e.g. a 3P/Codex-only slot) or one
    /// whose `expiresAt` has already passed.
    ExpiredOrInvalid,
    /// The file itself could not be read (absent, permissions, non-UTF-8).
    Unreadable,
}

impl std::fmt::Debug for TargetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetToken::Valid(_) => f.debug_tuple("Valid").field(&"[REDACTED]").finish(),
            TargetToken::ExpiredOrInvalid => write!(f, "ExpiredOrInvalid"),
            TargetToken::Unreadable => write!(f, "Unreadable"),
        }
    }
}

impl TargetToken {
    /// The raw JSON when [`TargetToken::Valid`], else `None` — the view
    /// every pre-H1 caller needs: they only ever asked "is there a token to
    /// write", never the unreadable/expired distinction.
    pub fn as_valid_str(&self) -> Option<&str> {
        match self {
            TargetToken::Valid(s) => Some(s.as_str()),
            TargetToken::ExpiredOrInvalid | TargetToken::Unreadable => None,
        }
    }
}

/// Returns [`TargetToken::Unreadable`] when the file cannot be read (absent,
/// permissions, non-UTF-8); [`TargetToken::ExpiredOrInvalid`] when it reads
/// but is not a live Anthropic token; [`TargetToken::Valid`] otherwise.
///
/// `keychain-fix-r8.md` C-F2 (doc correction — `doc-property-claims.md`
/// MUST-1: the prior wording here asserted a property this function's own
/// only variable-latency caller does not have): the previous sentence
/// claimed every caller only needs [`TargetToken::as_valid_str`] because
/// `force_sync_account_changed`'s `None` arm "already re-validates
/// expiry/shape on its own, so folding `ExpiredOrInvalid` and `Unreadable`
/// into `None` there changes nothing" — that is FALSE for
/// `daemon::auto_rotate::tick`, which reads this AFTER acquiring a lock that
/// can wait up to ~20s: a target selected as `Valid` before the lock can
/// become `ExpiredOrInvalid`/`Unreadable` by the time the tick reads it
/// here, and `force_sync_account_changed_with_executor` treats a `None`
/// credentials string identically to "the target is POSITIVELY
/// non-Anthropic" (`crate::credentials::keychain::Intended::Strip`'s own
/// contract) — collapsing the two is exactly what that function's
/// `Intended::Strip` doc says must never happen. `tick` MUST (and does, as
/// of C-F2) check `matches!(target_creds, TargetToken::Valid(_))` itself
/// and refuse the rotation rather than let an untrustworthy-but-Anthropic
/// target reach `Intended::Strip`.
pub fn target_token_for_forced_write(base: &Path, target: crate::types::AccountNum) -> TargetToken {
    let raw = match std::fs::read_to_string(credential_file_for_slot_write(base, target)) {
        Ok(s) => s,
        Err(_) => return TargetToken::Unreadable,
    };
    match crate::credentials::keychain::anthropic_expiry_ms(&raw) {
        Some(ms) if ms > crate::credentials::keychain::now_ms() => TargetToken::Valid(raw),
        _ => TargetToken::ExpiredOrInvalid,
    }
}

/// Resolves an account number to its canonical identity paths.
///
/// # Resolution logic
///
/// 1. Calls [`crate::accounts::profiles::resolve_slot_to_uuid`] (Phase 1
///    anchor; Phase 2 activated the write side; Phase 3 wires this as the
///    path chokepoint for M3-3/M3-4 consumers).
/// 2. When `resolve_slot_to_uuid` returns `Some(uuid)`:
///    - `credentials_path` → `<base>/identities/<UUID>/credentials.json`
///      (via [`credentials_path_for`])
///    - `settings_path` → `<base>/identities/<UUID>/settings.json`
///      (via [`settings_path_for`])
///    - `is_identity_keyed` = `true`
/// 3. When `resolve_slot_to_uuid` returns `None` (no `profiles.json`,
///    missing slot, or parse error):
///    - `credentials_path` → `<base>/config-<N>/.credentials.json`
///    - `settings_path` → `<base>/config-<N>/settings.json`
///    - `is_identity_keyed` = `false`
/// 4. **In both cases**, `marker_source_path` is hardcoded to
///    `<base>/config-<N>/.csq-account`.  See [`IdentityPaths`] doc for the
///    cross-phase constraint rationale (an internal journal entry OQ #2 + cross-phase
///    constraint #3 from `rules/account-terminal-separation.md` MUST NOT
///    Rule 3).
///
/// # No-panic contract
///
/// Missing or malformed `profiles.json` silently returns legacy-keyed paths.
/// The function does not panic; errors at the file layer are absorbed by
/// [`crate::accounts::profiles::resolve_slot_to_uuid`]'s `Option` return.
pub fn account_to_identity_paths(base: &Path, account: crate::types::AccountNum) -> IdentityPaths {
    let slot = account.get();
    let config_dir = base.join(format!("config-{slot}"));

    // marker_source_path: HARDCODED to config-N/.csq-account per an internal journal entry
    // OQ #2 (Option A — markers stay at config-N/ through Phase 4) and
    // cross-phase constraint #3 (rules/account-terminal-separation.md MUST NOT
    // Rule 3).  Do NOT route this through the identity path even when
    // is_identity_keyed is true.
    let marker_source_path = config_dir.join(".csq-account");

    match crate::accounts::profiles::resolve_slot_to_uuid(base, slot) {
        Some(uuid) => IdentityPaths {
            credentials_path: credentials_path_for(base, uuid),
            settings_path: settings_path_for(base, uuid),
            marker_source_path,
            is_identity_keyed: true,
        },
        None => IdentityPaths {
            credentials_path: config_dir.join(".credentials.json"),
            settings_path: config_dir.join("settings.json"),
            marker_source_path,
            is_identity_keyed: false,
        },
    }
}

/// Returns `<base>/identities/<uuid>/credentials-codex.json`.
///
/// Phase 3 ADDS this as the canonical UUID-keyed path for the Codex surface
/// (parallel to [`credentials_path_for`] for ClaudeCode).  Per an internal journal entry
/// OQ #3, Phase 3 retargets Codex handle-dir symlinks to this path; the
/// legacy `credentials/codex-N.json` canonical is RETAINED through Phase 4
/// for downgrade safety.
pub fn credentials_codex_path_for(base: &Path, id: IdentityId) -> PathBuf {
    identity_path(base, id).join("credentials-codex.json")
}

/// Reads the `provider` field from `identities/<UUID>/identity.json`.
///
/// `identity.json` is written by the daemon mint flow as a string-built JSON
/// object `{email, provider, created_at, key_id}` (see
/// [`crate::daemon::identity_mint`]). `provider` is `"anthropic"` for OAuth
/// slots and `"codex"` for Codex-only slots minted via the `csq login N
/// --provider codex` path. This is the **authoritative post-A++ signal** for a
/// slot's auth surface — it survives legacy-mirror retirement, unlike the
/// `credentials/codex-<N>.json` marker.
///
/// Returns `None` if the file is absent, unreadable, or unparseable, or if the
/// `provider` field is missing/non-string. Callers MUST treat `None` as "fall
/// back to the legacy on-disk marker", never as "assume a provider".
pub fn read_identity_provider(base: &Path, id: IdentityId) -> Option<String> {
    let path = identity_json_path_for(base, id);
    let bytes = std::fs::read(&path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("provider")?.as_str().map(str::to_owned)
}

/// Reads the `email` field from `identities/<uuid>/identity.json` — the account's
/// authenticated OAuth email captured at mint (write-once per
/// [`crate::daemon::identity_mint`]). For an Anthropic identity this is the same
/// OAuth email CC writes to a handle dir's `.claude.json` `oauthAccount.emailAddress`.
///
/// This is the **wrong-account adopt anchor** for the daemon keychain custodian
/// (`crate::daemon::custodian`): a harvested keychain token is account-anonymous
/// (the opaque `sk-ant-oat01-` access token and the `claudeAiOauth` payload carry
/// NO account identity), so the custodian compares the candidate session's
/// CC-recorded account (`.claude.json` email) against THIS value before adopting
/// the token into the account-global store.
///
/// Returns `None` if the file is absent, unreadable, unparseable, or the `email`
/// field is missing / empty / non-string. Callers MUST treat `None` as "cannot
/// confirm identity → do not adopt" (fail-closed), never as a match.
pub fn read_identity_email(base: &Path, id: IdentityId) -> Option<String> {
    let path = identity_json_path_for(base, id);
    let bytes = std::fs::read(&path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let email = json.get("email")?.as_str()?;
    if email.is_empty() {
        None
    } else {
        Some(email.to_owned())
    }
}

/// Returns `true` when `slot` (mapped to `uuid` in `profiles.json::by_slot`) is
/// a **Codex-only** slot — Codex-bound with no Anthropic credential surface.
///
/// Such a slot legitimately lacks an Anthropic `credentials.json` at its
/// identity path: its credentials live at [`credentials_codex_path_for`]. Both
/// the daemon's Anthropic enumerator ([`crate::accounts::discovery::discover_anthropic`])
/// and the doctor consistency audit ([`crate::accounts::profiles`]'s
/// `MissingCredentialsAtUuidPath` check) MUST skip these slots, otherwise they
/// surface a false "broken Anthropic account" / INCONSISTENT verdict and the
/// daemon emits a spurious "phase4_gate should have caught this" WARN on every
/// poll.
///
/// Identity-store-aware (per `account-terminal-separation.md` MUST Rule 4):
/// - **Codex-bound** ⇐ `identity.json` `provider == "codex"` (canonical
///   post-A++ signal) OR `credentials-codex.json` exists at the identity path
///   (write-order-independent signal: the codex mint writes `identity.json`
///   first then the credential, but consulting the credential file too closes
///   the mid-migration window AND the corrupt-`identity.json` sub-case) OR
///   legacy `credentials/codex-<N>.json` exists (pre-A++ fallback for installs
///   whose `identity.json` predates the provider field).
/// - **Anthropic-bound** ⇐ legacy `credentials/<N>.json` exists OR
///   `identity.json` `provider == "anthropic"` OR an Anthropic
///   `credentials.json` exists at the identity path.
///
/// A slot is Codex-only iff it is Codex-bound and NOT Anthropic-bound. A slot
/// with a genuinely missing Anthropic `credentials.json` (provider anthropic,
/// no Codex binding) is NOT Codex-only — it stays flaggable so the doctor's
/// real `MissingCredentialsAtUuidPath` alarm is preserved.
pub fn is_codex_only_slot(base: &Path, slot: u16, uuid: IdentityId) -> bool {
    let creds_dir = base.join("credentials");
    let legacy_codex = creds_dir.join(format!("codex-{slot}.json")).exists();
    let legacy_anthropic = creds_dir.join(format!("{slot}.json")).exists();
    let provider = read_identity_provider(base, uuid);
    let codex_creds_at_uuid = credentials_codex_path_for(base, uuid).exists();
    let anthropic_creds_at_uuid = credentials_path_for(base, uuid).exists();

    let codex_bound = provider.as_deref() == Some("codex") || codex_creds_at_uuid || legacy_codex;
    let anthropic_bound =
        legacy_anthropic || provider.as_deref() == Some("anthropic") || anthropic_creds_at_uuid;

    codex_bound && !anthropic_bound
}

/// True iff `slot` is bound to an **Anthropic OAuth** account, resolving the
/// binding through the identity store (per `account-terminal-separation.md`
/// MUST Rule 4) — NOT the M4-12-retired legacy `credentials/<N>.json` mirror
/// alone.
///
/// Post-M4-12 the numeric write path is retired: a slot logged in on a current
/// build has NO `credentials/<N>.json`; its Anthropic binding lives only in
/// `profiles.json::by_slot` → `identities/<UUID>/`. A detection site that stats
/// the legacy mirror alone (the pre-fix `csq setkey` guard) is therefore blind
/// to every post-A++ Anthropic login — the same detection-site-drift class the
/// M4-12 mirror retirement introduced (`reconciler-cleanup-parity.md` Rule 6).
///
/// Anthropic-bound ⇐ legacy `credentials/<N>.json` exists (pre-A++ fallback) OR
/// the slot's `by_slot` identity has `provider == "anthropic"` OR an Anthropic
/// `credentials.json` exists at that identity's path. Fail-toward-unbound only
/// when there is genuinely no legacy mirror AND no `by_slot` mapping.
pub fn is_anthropic_bound_slot(base: &Path, slot: crate::types::AccountNum) -> bool {
    let n = slot.get();
    // `symlink_metadata` (not `.exists()`): a dangling legacy-mirror symlink is
    // treated as bound so the guard fails toward refusing the clobber (the
    // PR-C3b security posture the legacy `is_codex_bound_slot` established).
    if std::fs::symlink_metadata(base.join("credentials").join(format!("{n}.json"))).is_ok() {
        return true;
    }
    match crate::accounts::profiles::resolve_slot_to_uuid(base, n) {
        Some(uuid) => {
            read_identity_provider(base, uuid).as_deref() == Some("anthropic")
                || credentials_path_for(base, uuid).exists()
        }
        None => false,
    }
}

/// True iff `slot` is bound to a **Codex** account, resolving through the
/// identity store — the identity-store-aware sibling of
/// [`is_anthropic_bound_slot`] and the correct successor to the legacy
/// [`crate::providers::codex::provisioning::is_codex_bound_slot`] marker
/// predicate.
///
/// `is_codex_bound_slot` stats `credentials/codex-<N>.json`, which M4-12
/// retired as a WRITE target: a Codex slot logged in on a current build has no
/// such file (its credentials live at [`credentials_codex_path_for`]), so the
/// legacy predicate returns `false` for a live Codex slot. This predicate keys
/// on the identity store instead, with the legacy marker retained only as a
/// pre-A++ fallback.
///
/// Codex-bound ⇐ legacy `credentials/codex-<N>.json` exists (pre-A++ fallback)
/// OR the slot's `by_slot` identity has `provider == "codex"` OR a Codex
/// `credentials-codex.json` exists at that identity's path.
pub fn is_codex_bound_slot_identity_aware(base: &Path, slot: crate::types::AccountNum) -> bool {
    let n = slot.get();
    // `symlink_metadata` (not `.exists()`): dangling legacy marker → treated as
    // bound (fail-toward-refuse), matching the legacy `is_codex_bound_slot`
    // PR-C3b posture.
    if std::fs::symlink_metadata(base.join("credentials").join(format!("codex-{n}.json"))).is_ok() {
        return true;
    }
    match crate::accounts::profiles::resolve_slot_to_uuid(base, n) {
        Some(uuid) => {
            read_identity_provider(base, uuid).as_deref() == Some("codex")
                || credentials_codex_path_for(base, uuid).exists()
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;

    /// S-LOW-1 / `credential-type-hygiene.md` Rule 1: `TargetToken::Valid`
    /// carries a live `.credentials.json` payload. Its manual `Debug` MUST
    /// print a placeholder and MUST NOT print the token bytes; the
    /// non-`Valid` variants print their plain names unchanged.
    #[test]
    fn target_token_debug_redacts_valid() {
        let valid = TargetToken::Valid(
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOTREALTOKu9x","refreshToken":"sk-ant-ort01-NOTREALTOKu9x","expiresAt":4102444800000}}"#
                .to_string(),
        );
        let debug = format!("{valid:?}");
        assert!(
            debug.contains("REDACTED"),
            "Debug output must contain a redaction placeholder: {debug}"
        );
        assert!(
            !debug.contains("NOTREALTOKu9x"),
            "Debug output must NOT contain the token bytes: {debug}"
        );
        assert_eq!(
            format!("{:?}", TargetToken::ExpiredOrInvalid),
            "ExpiredOrInvalid"
        );
        assert_eq!(format!("{:?}", TargetToken::Unreadable), "Unreadable");
    }

    #[test]
    fn new_v4_is_unique_across_1000_invocations() {
        let mut seen = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let id = IdentityId::new_v4();
            assert!(seen.insert(id), "duplicate IdentityId from new_v4");
        }
    }

    #[test]
    fn display_and_to_canonical_string_match() {
        let id = IdentityId::new_v4();
        assert_eq!(format!("{id}"), id.to_canonical_string());
    }

    #[test]
    fn canonical_string_is_lowercase_hyphenated() {
        let id = IdentityId::new_v4();
        let s = id.to_canonical_string();
        assert_eq!(
            s.len(),
            36,
            "canonical UUID-v4 is 36 chars including hyphens"
        );
        assert!(s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        // Hyphen positions are fixed in the canonical form.
        let hyphens: Vec<usize> = s
            .char_indices()
            .filter_map(|(i, c)| (c == '-').then_some(i))
            .collect();
        assert_eq!(hyphens, vec![8, 13, 18, 23]);
    }

    #[test]
    fn from_str_rejects_garbage_no_silent_default() {
        for bad in [
            "",
            "not-a-uuid",
            "0",
            "1",
            "abc",
            "00000000-0000-0000-0000-00000000000",   // 35 chars
            "00000000-0000-0000-0000-0000000000000", // 37 chars
            "zz000000-0000-0000-0000-000000000000",  // non-hex
        ] {
            assert!(
                IdentityId::from_str(bad).is_err(),
                "expected from_str({bad:?}) to fail, got Ok — no silent fallback allowed"
            );
        }
    }

    #[test]
    fn from_str_accepts_canonical_and_round_trips() {
        let original = IdentityId::new_v4();
        let canonical = original.to_canonical_string();
        let parsed = IdentityId::from_str(&canonical).expect("canonical string round-trips");
        assert_eq!(parsed, original);
    }

    #[test]
    fn serde_round_trips_as_canonical_string() {
        let id = IdentityId::new_v4();
        let json = serde_json::to_string(&id).expect("serialize");
        // serde_json emits the UUID inside quotes.
        let expected = format!("\"{}\"", id.to_canonical_string());
        assert_eq!(json, expected);
        let decoded: IdentityId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, id);
    }

    #[test]
    fn serde_rejects_garbage_no_silent_default() {
        for bad in [
            "\"\"",
            "\"not-a-uuid\"",
            "\"0\"",
            "null",
            "0",
            "false",
            "{}",
        ] {
            let result: Result<IdentityId, _> = serde_json::from_str(bad);
            assert!(
                result.is_err(),
                "expected deserializing {bad:?} to fail, got Ok — no silent default allowed"
            );
        }
    }

    #[test]
    fn identities_dir_appends_identities_segment() {
        let base = PathBuf::from("/tmp/accounts");
        assert_eq!(
            identities_dir(&base),
            PathBuf::from("/tmp/accounts/identities")
        );
    }

    #[test]
    fn identity_path_returns_base_identities_uuid_dir() {
        let base = PathBuf::from("/tmp/accounts");
        let id = IdentityId::from_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            identity_path(&base, id),
            PathBuf::from("/tmp/accounts/identities/550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn identity_json_path_for_returns_identity_json_inside_uuid_dir() {
        let base = PathBuf::from("/tmp/accounts");
        let id = IdentityId::from_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            identity_json_path_for(&base, id),
            PathBuf::from(
                "/tmp/accounts/identities/550e8400-e29b-41d4-a716-446655440000/identity.json"
            )
        );
    }

    // ── Finding #1 (kc-v4 correctness review): the forced-write token
    // source MUST resolve through the SAME identity-aware path
    // `repoint_handle_dir` targets, not a hardcoded `config-N/.credentials.json`
    // guess — M3-7 retired csq's own writer to that legacy path for any
    // UUID-keyed slot, so it can be stale or absent entirely while the
    // identity file is the live, correct token.
    #[test]
    fn credential_file_for_slot_write_uses_identity_path_when_config_n_is_absent() {
        // Arrange: a UUID-mapped slot whose config-N/.credentials.json does
        // not exist at all (simulating M3-7's retired legacy writer), while
        // identities/<UUID>/credentials.json holds the live token.
        let dir = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = dir.path();
        let slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // Remove the legacy config-N copy the fixture wrote, and write a
        // DISTINCT, distinguishable token at the identity path.
        std::fs::remove_file(base.join("config-1").join(".credentials.json"))
            .expect("remove legacy config-N credentials");
        let identity_creds_path = credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        std::fs::write(
            &identity_creds_path,
            r#"{"claudeAiOauth":{"accessToken":"IDENTITY-LIVE-TOKEN"}}"#,
        )
        .expect("write identity credentials");

        // Act
        let resolved = credential_file_for_slot_write(base, slot);
        let resolved_content = std::fs::read_to_string(&resolved);

        // Assert: the resolver targets the identity path (not the absent
        // config-N path), and its content is the live identity token.
        assert_eq!(resolved, identity_creds_path);
        assert_eq!(
            resolved_content.unwrap(),
            r#"{"claudeAiOauth":{"accessToken":"IDENTITY-LIVE-TOKEN"}}"#
        );
    }

    // ── Finding #1 continued: config-N present but STALE (an old snapshot),
    // identity path is still what MUST be read.
    #[test]
    fn credential_file_for_slot_write_uses_identity_path_over_stale_config_n() {
        let dir = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = dir.path();
        let slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // config-N/.credentials.json is left as the fixture's STALE stub;
        // identities/<UUID>/credentials.json gets a distinguishable fresh token.
        let identity_creds_path = credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        std::fs::write(
            &identity_creds_path,
            r#"{"claudeAiOauth":{"accessToken":"IDENTITY-FRESH-TOKEN"}}"#,
        )
        .expect("write identity credentials");

        let resolved = credential_file_for_slot_write(base, slot);
        let resolved_content = std::fs::read_to_string(&resolved).unwrap();

        assert_eq!(resolved, identity_creds_path);
        assert!(resolved_content.contains("IDENTITY-FRESH-TOKEN"));
        assert!(!resolved_content.contains("stub-access-token-1"));
    }

    /// F5: `target_token_for_forced_write` MUST return the fresh
    /// identity-keyed token, not the stale `config-N` copy sitting right
    /// next to it — the exact scenario `csq swap`'s and `auto_rotate`'s v4
    /// forced write both need before a keychain write. This test goes RED
    /// if the function is ever changed to read `config-N/.credentials.json`
    /// directly instead of going through the shared resolver.
    #[test]
    fn target_token_for_forced_write_prefers_fresh_identity_over_stale_config_n() {
        let dir = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = dir.path();
        let slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // config-N/.credentials.json is left as the fixture's STALE stub
        // (contains "stub-access-token-1"); identities/<UUID>/credentials.json
        // gets a distinguishable fresh token.
        let identity_creds_path = credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        let far_future = crate::credentials::keychain::now_ms() + 365 * 24 * 60 * 60 * 1000;
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"FORCED-WRITE-FRESH-TOKEN","expiresAt":{far_future}}}}}"#
            ),
        )
        .expect("write identity credentials");

        let token = target_token_for_forced_write(base, slot)
            .as_valid_str()
            .expect("target_token_for_forced_write must read the identity-keyed file as Valid")
            .to_string();

        assert!(
            token.contains("FORCED-WRITE-FRESH-TOKEN"),
            "must return the fresh identity token, got: {token}"
        );
        assert!(
            !token.contains("stub-access-token-1"),
            "must NOT return the stale config-N stub, got: {token}"
        );
    }

    /// H1: `target_token_for_forced_write` MUST distinguish "the file could
    /// not be read at all" from "the file was read but is not a live
    /// Anthropic token" — the pre-H1 `read_to_string(..).ok()` folded both
    /// into the same `None`, and `reconcile_keychain_to_marker`'s rule 4
    /// fallback needs to say "this file cannot be trusted", which requires
    /// telling the two apart.
    ///
    /// RED proof (quoted in the PR/journal): with the classification
    /// collapsed back to `raw.contains("claudeAiOauth")` alone (no expiry
    /// check, no distinct `Unreadable` case — the pre-H1 shape), this test
    /// fails on the EXPIRED case:
    ///   assertion `left == right` failed
    ///     left: ExpiredOrInvalid
    ///    right: Valid("{\"claudeAiOauth\":{\"accessToken\":\"EXPIRED-TOKEN\",\"expiresAt\":1}}")
    #[test]
    fn target_token_for_forced_write_distinguishes_unreadable_from_expired_invalid_from_valid() {
        let dir = crate::testing::identity_fixtures::coexisting_fixture(3);
        let base = dir.path();
        let far_future = crate::credentials::keychain::now_ms() + 365 * 24 * 60 * 60 * 1000;

        // Slot 1: a live, non-expired token -> Valid.
        let slot1 = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let path1 = credentials_path_for(base, uuid1);
        std::fs::create_dir_all(path1.parent().unwrap()).unwrap();
        std::fs::write(
            &path1,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"LIVE-TOKEN","refreshToken":"LIVE-REFRESH","expiresAt":{far_future}}}}}"#
            ),
        )
        .unwrap();

        // Slot 2: present but EXPIRED -> ExpiredOrInvalid, never Valid.
        let slot2 = crate::types::AccountNum::try_from(2u16).unwrap();
        let uuid2 = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let path2 = credentials_path_for(base, uuid2);
        std::fs::create_dir_all(path2.parent().unwrap()).unwrap();
        std::fs::write(
            &path2,
            r#"{"claudeAiOauth":{"accessToken":"EXPIRED-TOKEN","refreshToken":"EXPIRED-REFRESH","expiresAt":1}}"#,
        )
        .unwrap();

        // Slot 3: present but no `claudeAiOauth` at all (a 3P/Codex-only
        // slot) -> ExpiredOrInvalid, never Valid, never a crash.
        let slot3 = crate::types::AccountNum::try_from(3u16).unwrap();
        let uuid3 = crate::testing::identity_fixtures::fixture_uuid_for_slot(3);
        let path3 = credentials_path_for(base, uuid3);
        std::fs::create_dir_all(path3.parent().unwrap()).unwrap();
        std::fs::write(&path3, r#"{"tokens":{"access_token":"codex-only"}}"#).unwrap();

        assert!(matches!(
            target_token_for_forced_write(base, slot1),
            TargetToken::Valid(_)
        ));
        assert_eq!(
            target_token_for_forced_write(base, slot2),
            TargetToken::ExpiredOrInvalid
        );
        assert_eq!(
            target_token_for_forced_write(base, slot3),
            TargetToken::ExpiredOrInvalid
        );

        // A slot whose file does not exist at all -> Unreadable, distinct
        // from both of the above.
        let slot4 = crate::types::AccountNum::try_from(4u16).unwrap();
        assert_eq!(
            target_token_for_forced_write(base, slot4),
            TargetToken::Unreadable
        );
    }

    #[test]
    fn store_version_path_is_at_base_root() {
        let base = PathBuf::from("/tmp/accounts");
        assert_eq!(
            store_version_path(&base),
            PathBuf::from("/tmp/accounts/store-version")
        );
    }

    #[test]
    fn identity_path_is_deterministic_for_same_id() {
        let base = PathBuf::from("/tmp/accounts");
        let id = IdentityId::new_v4();
        assert_eq!(identity_path(&base, id), identity_path(&base, id));
    }

    // ── M3-1 acceptance tests ────────────────────────────────────────────

    /// AC1: coexisting fixture slot 2 resolves to identity-keyed paths.
    ///
    /// With a coexisting fixture (both `config-N/` and `identities/<UUID>/`),
    /// `account_to_identity_paths` MUST return paths under `identities/<UUID>/`
    /// and set `is_identity_keyed = true`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn account_to_identity_paths_returns_identity_keyed_under_coexisting_fixture() {
        // Arrange
        let dir = crate::testing::identity_fixtures::coexisting_fixture(3);
        let base = dir.path();
        let account = crate::types::AccountNum::try_from(2u16).unwrap();
        let expected_uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);

        // Act
        let paths = account_to_identity_paths(base, account);

        // Assert: credentials and settings under identities/<UUID>/
        assert!(
            paths
                .credentials_path
                .to_string_lossy()
                .contains("identities"),
            "credentials_path must contain 'identities', got: {:?}",
            paths.credentials_path
        );
        assert!(
            paths
                .credentials_path
                .to_string_lossy()
                .contains(&expected_uuid.to_canonical_string()),
            "credentials_path must contain the UUID for slot 2"
        );
        assert!(
            paths.credentials_path.ends_with("credentials.json"),
            "credentials_path must end with credentials.json"
        );

        assert!(
            paths.settings_path.to_string_lossy().contains("identities"),
            "settings_path must contain 'identities', got: {:?}",
            paths.settings_path
        );
        assert!(
            paths.settings_path.ends_with("settings.json"),
            "settings_path must end with settings.json"
        );

        // Assert: marker stays at config-2/.csq-account (OQ #2 Option A)
        assert!(
            paths
                .marker_source_path
                .to_string_lossy()
                .contains("config-2"),
            "marker_source_path must contain 'config-2', got: {:?}",
            paths.marker_source_path
        );
        assert!(
            paths.marker_source_path.ends_with(".csq-account"),
            "marker_source_path must end with .csq-account"
        );

        // Assert: is_identity_keyed flag
        assert!(
            paths.is_identity_keyed,
            "is_identity_keyed must be true for coexisting fixture"
        );
    }

    /// AC2: legacy-only fixture slot 2 resolves to config-N/-keyed paths.
    ///
    /// With a legacy-only fixture (no `profiles.json` UUID mapping),
    /// `account_to_identity_paths` MUST return all paths under `config-2/`
    /// and set `is_identity_keyed = false`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn account_to_identity_paths_returns_legacy_keyed_under_legacy_only_fixture() {
        // Arrange
        let dir = crate::testing::identity_fixtures::legacy_only_fixture(3);
        let base = dir.path();
        let account = crate::types::AccountNum::try_from(2u16).unwrap();

        // Act
        let paths = account_to_identity_paths(base, account);

        // Assert: all three paths route under config-2/
        assert!(
            paths
                .credentials_path
                .to_string_lossy()
                .contains("config-2"),
            "credentials_path must contain 'config-2', got: {:?}",
            paths.credentials_path
        );
        assert!(
            paths.settings_path.to_string_lossy().contains("config-2"),
            "settings_path must contain 'config-2', got: {:?}",
            paths.settings_path
        );
        assert!(
            paths
                .marker_source_path
                .to_string_lossy()
                .contains("config-2"),
            "marker_source_path must contain 'config-2', got: {:?}",
            paths.marker_source_path
        );

        // Assert: is_identity_keyed flag
        assert!(
            !paths.is_identity_keyed,
            "is_identity_keyed must be false for legacy-only fixture"
        );
    }

    /// AC3: fresh TempDir with no profiles.json returns legacy-keyed paths
    /// without panic.
    ///
    /// The no-panic contract: when `profiles.json` is absent, the function
    /// silently falls back to `config-N/` paths.
    #[test]
    fn account_to_identity_paths_no_panic_on_missing_profiles_json() {
        // Arrange: fresh tmpdir with no files at all
        let dir = tempfile::TempDir::new().expect("TempDir::new");
        let base = dir.path();
        let account = crate::types::AccountNum::try_from(1u16).unwrap();

        // Act: must not panic
        let paths = account_to_identity_paths(base, account);

        // Assert: legacy-keyed paths returned
        assert!(
            paths
                .credentials_path
                .to_string_lossy()
                .contains("config-1"),
            "credentials_path must fall back to config-1/, got: {:?}",
            paths.credentials_path
        );
        assert!(!paths.is_identity_keyed, "is_identity_keyed must be false");
    }

    /// AC4: `credentials_codex_path_for` returns the expected path shape.
    #[test]
    fn credentials_codex_path_for_under_identity_dir() {
        // Arrange
        use std::str::FromStr;
        let base = PathBuf::from("/tmp/accounts");
        let id = IdentityId::from_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        // Act
        let path = credentials_codex_path_for(&base, id);

        // Assert: exact path equality
        assert_eq!(
            path,
            PathBuf::from(
                "/tmp/accounts/identities/550e8400-e29b-41d4-a716-446655440000/credentials-codex.json"
            )
        );
    }

    /// AC5: `is_identity_keyed` flag matches UUID resolution for both layouts.
    ///
    /// Discriminant test: coexisting fixture → `true`; legacy-only → `false`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn identity_paths_is_identity_keyed_flag_matches_uuid_resolution() {
        // Arrange
        let coex_dir = crate::testing::identity_fixtures::coexisting_fixture(2);
        let leg_dir = crate::testing::identity_fixtures::legacy_only_fixture(2);
        let account = crate::types::AccountNum::try_from(1u16).unwrap();

        // Act + Assert: coexisting → is_identity_keyed == true
        let coex_paths = account_to_identity_paths(coex_dir.path(), account);
        assert!(
            coex_paths.is_identity_keyed,
            "coexisting fixture slot must be identity-keyed"
        );

        // Act + Assert: legacy-only → is_identity_keyed == false
        let leg_paths = account_to_identity_paths(leg_dir.path(), account);
        assert!(
            !leg_paths.is_identity_keyed,
            "legacy-only fixture slot must not be identity-keyed"
        );
    }

    /// AC6: SEC-3-C1 path-traversal regression.
    ///
    /// A `profiles.json` containing `by_slot["1"] = "../../etc/passwd"` (a
    /// raw non-UUID string) MUST cause `profiles::load` to return `Err`.
    /// The structural defense is `IdentityId`'s `serde(transparent)` +
    /// `Uuid::parse_str` rejection — the malicious string is not a valid UUID
    /// and therefore cannot deserialize into `IdentityId`.
    ///
    /// This test is the security-reviewer SEC-3-C1 regression specified in
    /// `02-plans/04-phase3-readiness.md` § M3-1 acceptance criteria.
    #[test]
    fn by_slot_rejects_path_traversal_uuid_strings() {
        // Arrange: construct profiles.json with a path-traversal string in
        // by_slot["1"].  We write raw JSON — NOT via serde — so the malicious
        // string bypasses any Rust-side validation.
        let dir = tempfile::TempDir::new().expect("TempDir::new");
        let profiles_path = dir.path().join("profiles.json");
        let hostile_json = r#"{
            "accounts": {},
            "by_slot": {"1": "../../etc/passwd"},
            "by_email": {}
        }"#;
        std::fs::write(&profiles_path, hostile_json).expect("write hostile profiles.json");

        // Act: load must fail — serde rejects "../../etc/passwd" as an
        // IdentityId because Uuid::parse_str("../../etc/passwd") returns Err.
        let result = crate::accounts::profiles::load(&profiles_path);

        // Assert
        assert!(
            result.is_err(),
            "profiles::load must return Err when by_slot contains a non-UUID string; \
             got Ok — path-traversal defense would be broken"
        );
    }

    /// Helper: write an `identity.json` with the given provider for `uuid`.
    fn write_identity_provider(base: &Path, uuid: IdentityId, provider: &str) {
        let dir = identity_path(base, uuid);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("identity.json"),
            format!(r#"{{"email":"x","provider":"{provider}","created_at":"t","key_id":null}}"#),
        )
        .unwrap();
    }

    #[test]
    fn read_identity_provider_returns_codex_for_codex_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "codex");
        assert_eq!(
            read_identity_provider(dir.path(), uuid).as_deref(),
            Some("codex")
        );
    }

    #[test]
    fn read_identity_provider_returns_none_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        assert_eq!(read_identity_provider(dir.path(), uuid), None);
    }

    /// Helper: write an `identity.json` carrying the given email for `uuid`.
    fn write_identity_email(base: &Path, uuid: IdentityId, email: &str) {
        let dir = identity_path(base, uuid);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("identity.json"),
            format!(
                r#"{{"email":{},"provider":"anthropic","created_at":"t","key_id":null}}"#,
                serde_json::to_string(email).unwrap()
            ),
        )
        .unwrap();
    }

    // read_identity_email is the custodian's wrong-account anchor — its
    // fail-closed contract (empty/absent/unparseable → None) is load-bearing.
    #[test]
    fn read_identity_email_returns_email_when_present() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_email(dir.path(), uuid, "user@example.com");
        assert_eq!(
            read_identity_email(dir.path(), uuid).as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn read_identity_email_returns_none_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        assert_eq!(read_identity_email(dir.path(), uuid), None);
    }

    /// Helper: map `slot` → `uuid` in `profiles.json::by_slot` (the current,
    /// non-legacy binding channel — the one a real host uses).
    fn write_by_slot(base: &Path, slot: &str, uuid: IdentityId) {
        use crate::accounts::profiles::{save, ProfilesFile};
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        save(&crate::accounts::profiles::profiles_path(base), &pf).unwrap();
    }

    fn acc(n: u16) -> crate::types::AccountNum {
        crate::types::AccountNum::try_from(n).unwrap()
    }

    // ── is_anthropic_bound_slot — the M4-12 detection-site-drift regression ──

    #[test]
    fn is_anthropic_bound_slot_true_via_identity_store_no_legacy_mirror() {
        // The real-host shape: by_slot → identity(provider=anthropic) +
        // identities/<uuid>/credentials.json, and NO legacy credentials/<N>.json.
        // The pre-fix guard (legacy-mirror stat only) returned false here — the
        // exact blindness this predicate fixes.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "anthropic");
        std::fs::write(credentials_path_for(dir.path(), uuid), b"{}").unwrap();
        write_by_slot(dir.path(), "3", uuid);

        assert!(
            !dir.path().join("credentials/3.json").exists(),
            "precondition: no legacy mirror (post-M4-12 host shape)"
        );
        assert!(
            is_anthropic_bound_slot(dir.path(), acc(3)),
            "identity-store anthropic binding must be detected without a legacy mirror"
        );
    }

    #[test]
    fn is_anthropic_bound_slot_true_via_legacy_mirror_fallback() {
        // Pre-A++ hosts may still carry the legacy mirror; keep detecting it.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(dir.path().join("credentials/2.json"), b"{}").unwrap();
        assert!(is_anthropic_bound_slot(dir.path(), acc(2)));
    }

    #[test]
    fn is_anthropic_bound_slot_false_for_unbound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!is_anthropic_bound_slot(dir.path(), acc(5)));
    }

    #[test]
    fn is_anthropic_bound_slot_false_for_codex_only_slot() {
        // A codex slot (by_slot → provider=codex) is NOT anthropic-bound: a 3P
        // rebind guard must not misclassify it as Claude.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "codex");
        std::fs::write(credentials_codex_path_for(dir.path(), uuid), b"{}").unwrap();
        write_by_slot(dir.path(), "9", uuid);
        assert!(!is_anthropic_bound_slot(dir.path(), acc(9)));
    }

    // ── is_codex_bound_slot_identity_aware — sibling M4-12 drift regression ──

    #[test]
    fn is_codex_bound_slot_identity_aware_true_without_legacy_marker() {
        // Real-host slot-9 shape: by_slot → identity(provider=codex) +
        // credentials-codex.json, NO legacy credentials/codex-9.json. The legacy
        // `providers::codex::provisioning::is_codex_bound_slot` returns false here.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "codex");
        std::fs::write(credentials_codex_path_for(dir.path(), uuid), b"{}").unwrap();
        write_by_slot(dir.path(), "9", uuid);

        assert!(
            !dir.path().join("credentials/codex-9.json").exists(),
            "precondition: no legacy codex marker (post-M4-12 host shape)"
        );
        assert!(is_codex_bound_slot_identity_aware(dir.path(), acc(9)));
    }

    #[test]
    fn is_codex_bound_slot_identity_aware_true_via_legacy_marker_fallback() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(dir.path().join("credentials/codex-4.json"), b"{}").unwrap();
        assert!(is_codex_bound_slot_identity_aware(dir.path(), acc(4)));
    }

    #[test]
    fn is_codex_bound_slot_identity_aware_false_for_anthropic_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "anthropic");
        std::fs::write(credentials_path_for(dir.path(), uuid), b"{}").unwrap();
        write_by_slot(dir.path(), "3", uuid);
        assert!(!is_codex_bound_slot_identity_aware(dir.path(), acc(3)));
    }

    #[test]
    fn read_identity_email_returns_none_when_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_email(dir.path(), uuid, "");
        assert_eq!(read_identity_email(dir.path(), uuid), None);
    }

    #[test]
    fn read_identity_email_returns_none_on_unparseable() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let d = identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("identity.json"), b"{not json").unwrap();
        assert_eq!(read_identity_email(dir.path(), uuid), None);
    }

    /// Post-A++ Codex slot: `identity.json` provider=codex, NO legacy
    /// `credentials/codex-<N>.json` mirror (cleaned up by legacy-mirror
    /// retirement), no Anthropic `credentials.json`. This is the slot-8
    /// host-reproduced shape that fired the spurious WARN every poll.
    #[test]
    fn is_codex_only_true_for_post_aplusplus_codex_slot_without_legacy_mirror() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "codex");
        // Codex creds present at the identity path; Anthropic creds absent.
        std::fs::write(credentials_codex_path_for(dir.path(), uuid), b"{}").unwrap();
        assert!(
            is_codex_only_slot(dir.path(), 8, uuid),
            "post-A++ codex slot (provider=codex, no legacy mirror) must be codex-only"
        );
    }

    /// R3 NIT: the `codex_creds_at_uuid` signal alone (no `identity.json` at
    /// all → provider=None, no legacy marker) must classify codex-only. Pins
    /// the corrupt-/absent-identity.json sub-case the R1 hardening closed —
    /// without the credentials-codex.json term this would mis-classify and
    /// re-trip the spurious Anthropic WARN.
    #[test]
    fn is_codex_only_true_when_only_codex_creds_present_no_identity_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        std::fs::create_dir_all(identity_path(dir.path(), uuid)).unwrap();
        std::fs::write(credentials_codex_path_for(dir.path(), uuid), b"{}").unwrap();
        assert!(
            is_codex_only_slot(dir.path(), 8, uuid),
            "codex-only via credentials-codex.json alone (no identity.json, no \
             legacy marker) must be codex-only"
        );
    }

    /// Pre-A++ Codex slot: no `identity.json` (provider=None), legacy
    /// `credentials/codex-<N>.json` present, no Anthropic legacy mirror.
    /// The legacy-marker fallback must still classify it codex-only.
    #[test]
    fn is_codex_only_true_for_legacy_codex_marker_without_identity_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-12.json"), b"{}").unwrap();
        assert!(
            is_codex_only_slot(dir.path(), 12, uuid),
            "legacy codex marker without identity.json must remain codex-only"
        );
    }

    /// Genuine Anthropic slot missing `credentials.json`: provider=anthropic,
    /// no Codex binding. MUST NOT be classified codex-only — the doctor's real
    /// MissingCredentialsAtUuidPath alarm must still fire.
    #[test]
    fn is_codex_only_false_for_anthropic_slot_missing_credentials() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        write_identity_provider(dir.path(), uuid, "anthropic");
        assert!(
            !is_codex_only_slot(dir.path(), 3, uuid),
            "anthropic slot with missing creds must stay flaggable, not codex-only"
        );
    }

    /// Dual-bound slot: both legacy `credentials/codex-<N>.json` and
    /// `credentials/<N>.json` present. Anthropic binding wins — NOT codex-only.
    #[test]
    fn is_codex_only_false_for_dual_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-1.json"), b"{}").unwrap();
        std::fs::write(creds.join("1.json"), b"{}").unwrap();
        assert!(
            !is_codex_only_slot(dir.path(), 1, uuid),
            "dual-bound slot must enumerate as Anthropic, not codex-only"
        );
    }
}
