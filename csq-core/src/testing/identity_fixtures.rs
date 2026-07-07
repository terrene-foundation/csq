//! Dual-layout identity fixture surface for M1-7 (an internal ticket A++ Phase 1)
//! and M12 anti-fixture-masking helpers (non-OAuth slot identity workspace).
//!
//! # Overview
//!
//! Provides deterministic on-disk fixture shapes that any test (including
//! M1-4's acceptance tests and redteam round) can consume:
//!
//! - [`legacy_only_fixture`] — `config-1`…`config-N` with stub credentials;
//!   no `identities/`, no `store-version`, no `profiles.json` A++ fields.
//! - [`identity_only_fixture`] — N `identities/<UUID>/identity.json` files,
//!   populated `profiles.json` (`by_slot` + `by_email`), and `store-version`;
//!   no `config-N/` directories.
//! - [`coexisting_fixture`] — both layouts with consistent slot↔UUID mapping.
//! - [`daemon_refreshed_only_state`] — **M12** non-OAuth slot helper that
//!   materializes ONLY the files a real daemon-refreshed host has for a 3P
//!   API-key or Codex OAuth slot. Structurally refuses to write
//!   `oauthAccount.emailAddress` or `credentials/<N>.json` for 3P slots.
//! - [`legacy_pre_m4_9_state`] — **M12** pre-M4-9 shape for backward-compat
//!   tests; requires a `*_legacy_*` test name to make the intent explicit.
//!
//! All fixture-returning functions return a [`tempfile::TempDir`] whose
//! `path()` is the base directory (the parent of `config-N/`, `identities/`,
//! `profiles.json`, `store-version`). The `TempDir` cleans up on `Drop`.
//!
//! # Fixture-masking defence (M12)
//!
//! The `daemon_refreshed_only_state` / `legacy_pre_m4_9_state` split
//! closes the failure mode described in
//! `internal-design-docs`
//! Finding 1 and in
//! `internal-design-docs`
//! FM-1:
//!
//! > Synthetic fixtures that construct the recovery channel WITH companion
//! > state a real daemon-refreshed host does not have (e.g.
//! > `oauthAccount.emailAddress` in a non-OAuth credentials file) cause
//! > tests to pass green while the SUT silently resolves identity from the
//! > wrong channel.  On a real host `get_email(N)` returns `None` for the
//! > slot the test asserted as `Some("apikey:ollama")`.
//!
//! `daemon_refreshed_only_state` is the structural defence: its API has NO
//! parameter that could introduce `oauthAccount.emailAddress` or a
//! `credentials/<N>.json` payload for a non-OAuth slot.  Tests that
//! explicitly need the pre-M4-9 shape MUST use `legacy_pre_m4_9_state` and
//! name themselves `*_legacy_*`.
//!
//! # Determinism
//!
//! UUIDs are **reproducible** across runs for the same slot index. The
//! canonical approach is `uuid::Uuid::from_bytes([…])` seeded with a
//! deterministic 16-byte array keyed by slot index:
//!
//! ```text
//! bytes[0..2]  = slot as big-endian u16
//! bytes[2..16] = fixed sentinel bytes
//! ```
//!
//! This produces a byte-stable mapping `slot → UUID` so tests asserting UUID
//! equality across two invocations are stable by construction.
//!
//! # Security (§5a compliance)
//!
//! Every file write uses the `unique_tmp_path → write → secure_file →
//! atomic_replace` cluster from `csq-core/src/platform/fs.rs`, with explicit
//! cleanup (`let _ = std::fs::remove_file(&tmp);`) on every failure branch,
//! as mandated by `rules/security.md` §5a. Fixture content carries stub email
//! PII and stub credential shapes, so it falls under the §5a scope per the
//! rule's payload classification table (email PII = secret-bearing).
//!
//! See `rules/security.md` §5a audit primitive: run
//! `grep -rn 'unique_tmp_path' --include='*.rs' csq-core csq-cli csq-desktop`
//! and classify every hit.

use crate::accounts::identity_store::{
    credentials_codex_path_for, identity_json_path_for, store_version_path, IdentityId,
};
use crate::accounts::profiles::{self, AccountProfile, ProfilesFile};
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::types::AccountNum;
use std::io;
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;

// ─── Deterministic UUID derivation ──────────────────────────────────────────

/// Derives a deterministic `IdentityId` for a given slot index.
///
/// The encoding is:
/// ```text
/// bytes[0..2]  = slot as big-endian u16
/// bytes[2..16] = FIXTURE_SEED (14 fixed sentinel bytes)
/// ```
///
/// This is stable across process invocations: two calls with the same `slot`
/// always produce the same UUID. It is NOT intended for production use.
pub fn fixture_uuid_for_slot(slot: u16) -> IdentityId {
    const FIXTURE_SEED: [u8; 14] = [
        0xC5, 0xA1, 0x7E, 0x3F, 0xB8, 0x42, 0xD9, 0x11, 0xAE, 0x60, 0xF3, 0x02, 0x88, 0x5D,
    ];
    let slot_bytes = slot.to_be_bytes();
    let mut bytes = [0u8; 16];
    bytes[0] = slot_bytes[0];
    bytes[1] = slot_bytes[1];
    bytes[2..16].copy_from_slice(&FIXTURE_SEED);
    IdentityId::from(Uuid::from_bytes(bytes))
}

// ─── M12: NonOauthKind ───────────────────────────────────────────────────────

/// Classification of non-OAuth slot kind for the daemon-refreshed-only fixture.
///
/// Used by [`daemon_refreshed_only_state`] to determine the exact on-disk shape
/// to materialize for a non-OAuth slot. Each variant maps to a specific
/// provider whose `bind_provider_to_slot` or Codex `finalize_login` path
/// produces a recognizable `by_slot_identity` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonOauthKind {
    /// 3P API-key slot bound to MiniMax (label literal: `"apikey:mm"`).
    ApiKeyMm,
    /// 3P API-key slot bound to Z.AI (label literal: `"apikey:zai"`).
    ApiKeyZai,
    /// 3P API-key slot bound to DeepSeek (label literal: `"apikey:deepseek"`).
    ApiKeyDeepseek,
    /// 3P API-key slot bound to Ollama (label literal: `"apikey:ollama"`).
    ApiKeyOllama,
    /// Codex OAuth slot (label literal: `"codex-<N>/fx<slot:08x>"` where the
    /// id-prefix is deterministic for fixture reproducibility).
    ///
    /// The label shape `codex-N/fx<hex>` is produced by `format_label` in
    /// `providers::codex::login` when given an `account_id` whose first
    /// hyphen-delimited segment is `"fx<slot:08x>"`.  The fixture writes
    /// `tokens.account_id = "fx{slot:08x}-fixture"` so the prefix round-trips
    /// correctly without encoding a real JWT.
    CodexOauth,
}

impl NonOauthKind {
    /// Returns the `by_slot_identity` label literal this kind produces.
    ///
    /// For `CodexOauth`, the slot number is injected at call time.  The label
    /// mirrors what the daemon's backfill reconciler (M6) will write after
    /// inspecting the slot's on-disk state.
    pub fn identity_label(self, slot: u16) -> String {
        match self {
            NonOauthKind::ApiKeyMm => "apikey:mm".to_string(),
            NonOauthKind::ApiKeyZai => "apikey:zai".to_string(),
            NonOauthKind::ApiKeyDeepseek => "apikey:deepseek".to_string(),
            NonOauthKind::ApiKeyOllama => "apikey:ollama".to_string(),
            // format_label(account, Some("fx{:08x}-fixture")) takes the first
            // hyphen-split segment → "fx{slot:08x}", producing
            // "codex-{slot}/fx{slot:08x}".
            NonOauthKind::CodexOauth => format!("codex-{slot}/fx{slot:08x}"),
        }
    }

    /// Returns the `ANTHROPIC_BASE_URL` value used by the daemon's
    /// `provider_from_base_url` classification for 3P kinds.
    ///
    /// URL strings are sourced from
    /// `csq-core/src/providers/catalog.rs` `PROVIDERS` array
    /// `default_base_url` fields (verified 2026-05-18):
    ///   - MiniMax:  `https://api.minimax.io/anthropic`
    ///   - Z.AI:     `https://api.z.ai/api/anthropic`
    ///   - DeepSeek: `https://api.deepseek.com/anthropic`
    ///   - Ollama:   `http://localhost:11434`
    ///
    /// Returns `None` for `CodexOauth` (Codex does not use the 3P proxy URL;
    /// its identity comes from `credentials-codex.json::tokens.account_id`).
    pub fn anthropic_base_url(self) -> Option<&'static str> {
        match self {
            NonOauthKind::ApiKeyMm => Some("https://api.minimax.io/anthropic"),
            NonOauthKind::ApiKeyZai => Some("https://api.z.ai/api/anthropic"),
            NonOauthKind::ApiKeyDeepseek => Some("https://api.deepseek.com/anthropic"),
            NonOauthKind::ApiKeyOllama => Some("http://localhost:11434"),
            NonOauthKind::CodexOauth => None,
        }
    }
}

// ─── M12 helpers ─────────────────────────────────────────────────────────────

/// Converts a [`ConfigError`] to an [`io::Error`] with `ErrorKind::Other`.
///
/// Used to bridge `write_secure`'s `Result<(), ConfigError>` return type to
/// the `io::Result<()>` demanded by the M12 public API.
fn config_err_to_io(e: ConfigError) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

/// Stub `settings.json` content for a 3P API-key slot.
///
/// Writes only the minimal `env` block that `provider_from_base_url` and
/// `discover_per_slot_third_party` need to classify the slot.  No
/// `oauthAccount.emailAddress`, no `credentials/<N>.json`.
///
/// The `ANTHROPIC_AUTH_TOKEN` is a recognisable stub (`"stub-apikey-{slot}"`);
/// it is never exercised by unit tests (no real HTTP calls are made).
fn stub_3p_settings_json(slot: u16, base_url: &str) -> String {
    // Use a placeholder model string that passes the non-empty check.
    // The exact model value is not significant for M12 fixture purposes.
    let stub_model = format!("fixture-model-{slot}");
    format!(
        r#"{{
  "env": {{
    "ANTHROPIC_BASE_URL": "{base_url}",
    "ANTHROPIC_AUTH_TOKEN": "stub-apikey-{slot}",
    "ANTHROPIC_MODEL": "{stub_model}"
  }}
}}
"#
    )
}

/// Stub `identities/<UUID>/credentials-codex.json` content for a Codex slot.
///
/// The `tokens.account_id` value is `"fx{slot:08x}-fixture"`. When
/// `format_label` (providers::codex::login) splits on `-`, it takes the first
/// segment `"fx{slot:08x}"` as the prefix, producing the label
/// `"codex-{slot}/fx{slot:08x}"`.  This matches [`NonOauthKind::CodexOauth`]'s
/// `identity_label` output exactly.
///
/// Note: `id_token` is kept as an opaque stub (not a real JWT). The M12 fixture
/// is consumed by reconciler tests that only inspect `tokens.account_id` (via
/// the daemon's label-derivation path), not by JWT-decode callers.  Spec 07
/// §7.3.3 explicitly forbids decoding `id_token` for data-minimisation reasons;
/// the fixture honours that by never embedding a decodable payload.
fn stub_codex_credentials_json(slot: u16) -> String {
    format!(
        r#"{{
  "auth_mode": "chatgpt",
  "OPENAI_API_KEY": null,
  "tokens": {{
    "account_id": "fx{slot:08x}-fixture",
    "access_token": "stub-codex-at-{slot}",
    "refresh_token": "stub-codex-rt-{slot}",
    "id_token": "stub-id-token-opaque"
  }},
  "last_refresh": "{FIXTURE_TIMESTAMP}"
}}
"#
    )
}

// ─── Stub credential content ─────────────────────────────────────────────────

/// Fixed ISO-8601 timestamp used throughout fixtures (avoids time-bomb issues).
///
/// Using a far-future value per `feedback_no_test_timebombs`: 2100-01-01T00:00:00Z
/// as a Unix epoch is 4102444800.
const FIXTURE_TIMESTAMP: &str = "2100-01-01T00:00:00Z";

/// Stub email address for a given slot. Format: `fixture-slot-<N>@test.invalid`.
fn stub_email(slot: u16) -> String {
    format!("fixture-slot-{slot}@test.invalid")
}

/// Minimal stub `.credentials.json` content that satisfies the shape
/// `accounts::discovery::discover_anthropic` reads.
///
/// Shape (subset; omits fields not needed by M1-4's reader):
/// ```json
/// {
///   "oauthAccount": {
///     "emailAddress": "fixture-slot-N@test.invalid"
///   },
///   "accessToken": "stub-access-token",
///   "refreshToken": "stub-refresh-token",
///   "expiresAt": "2100-01-01T00:00:00Z"
/// }
/// ```
fn stub_credentials_json(slot: u16) -> String {
    let email = stub_email(slot);
    format!(
        r#"{{
  "oauthAccount": {{
    "emailAddress": "{email}"
  }},
  "accessToken": "stub-access-token-{slot}",
  "refreshToken": "stub-refresh-token-{slot}",
  "expiresAt": "{FIXTURE_TIMESTAMP}"
}}
"#
    )
}

/// Minimal `identity.json` content for the identity-only and coexisting layouts.
fn stub_identity_json(slot: u16) -> String {
    let email = stub_email(slot);
    format!(
        r#"{{
  "email": "{email}",
  "provider": "anthropic",
  "created_at": "{FIXTURE_TIMESTAMP}",
  "key_id": null
}}
"#
    )
}

/// `store-version` sentinel content.
fn store_version_json() -> String {
    format!(
        r#"{{
  "schema": 1,
  "minted_at": "{FIXTURE_TIMESTAMP}",
  "source": "test-fixture"
}}
"#
    )
}

// ─── §5a-compliant file writer ────────────────────────────────────────────────

/// Writes `content` to `dest` using the §5a-compliant pipeline:
/// `unique_tmp_path → write → secure_file → atomic_replace`,
/// with explicit tmp cleanup on every failure branch.
///
/// This matches the pattern in `profiles::save` and satisfies the
/// `rules/security.md` §5a audit primitive.
fn write_secure(dest: &Path, content: &str) -> Result<(), ConfigError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::InvalidJson {
            path: parent.to_path_buf(),
            reason: format!("create_dir_all: {e}"),
        })?;
    }

    let tmp = unique_tmp_path(dest);

    // §5a: cleanup on write failure
    if let Err(e) = std::fs::write(&tmp, content.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp,
            reason: format!("write: {e}"),
        });
    }

    // §5a: cleanup on secure_file failure (best-effort; some filesystems
    // cannot honor 0o600). We treat secure_file failure as fatal here to
    // ensure the §5a partial-failure test exercises the cleanup path.
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp,
            reason: format!("secure_file: {e}"),
        });
    }

    // §5a: cleanup on atomic_replace failure
    if let Err(e) = atomic_replace(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: dest.to_path_buf(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(())
}

// ─── Public fixture API ───────────────────────────────────────────────────────

/// Creates a **legacy-only** fixture: `config-1` … `config-N` directories,
/// each containing a `.credentials.json` stub.
///
/// No `identities/` directory, no `store-version` file, no `profiles.json`
/// A++ fields (`by_slot`/`by_email`). This is the state of a csq install
/// that has never run an A++-aware daemon.
///
/// The returned [`TempDir`]'s `path()` is the base directory (the parent of
/// the `config-N/` dirs). Cleanup happens on `Drop`.
///
/// # Panics
///
/// Panics if any filesystem operation fails — fixture setup failures should
/// never be silently swallowed in tests.
pub fn legacy_only_fixture(n_accounts: u16) -> TempDir {
    let dir = TempDir::new().expect("fixture: TempDir::new");
    let base = dir.path();

    for slot in 1..=n_accounts {
        let config_dir = base.join(format!("config-{slot}"));
        let creds_path = config_dir.join(".credentials.json");
        write_secure(&creds_path, &stub_credentials_json(slot))
            .unwrap_or_else(|e| panic!("fixture: write_secure credentials slot {slot}: {e:?}"));
    }

    dir
}

/// Creates an **identity-only** fixture: N `identities/<UUID>/identity.json`
/// files, a `profiles.json` with populated `by_slot` and `by_email` maps,
/// and a `store-version` sentinel.
///
/// No `config-N/` directories. This is the state of a post-Phase-4 csq
/// install where the legacy slot layout has been fully retired.
///
/// UUIDs are deterministic: `fixture_uuid_for_slot(slot)` produces the same
/// UUID for the same slot across invocations.
///
/// The returned [`TempDir`]'s `path()` is the base directory. Cleanup on `Drop`.
///
/// # Panics
///
/// Panics on filesystem failure.
pub fn identity_only_fixture(n_accounts: u16) -> TempDir {
    let dir = TempDir::new().expect("fixture: TempDir::new");
    let base = dir.path();

    let mut profiles = ProfilesFile::empty();

    for slot in 1..=n_accounts {
        let uuid = fixture_uuid_for_slot(slot);
        let email = stub_email(slot);

        // Write identities/<uuid>/identity.json
        let identity_dest = identity_json_path_for(base, uuid);
        write_secure(&identity_dest, &stub_identity_json(slot))
            .unwrap_or_else(|e| panic!("fixture: write_secure identity slot {slot}: {e:?}"));

        // Populate by_slot and by_email
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.by_email.insert(email, uuid);
    }

    // Write profiles.json
    let profiles_path = profiles::profiles_path(base);
    profiles::save(&profiles_path, &profiles)
        .unwrap_or_else(|e| panic!("fixture: profiles::save: {e:?}"));

    // Write store-version sentinel
    let sv_path = store_version_path(base);
    write_secure(&sv_path, &store_version_json())
        .unwrap_or_else(|e| panic!("fixture: write_secure store-version: {e:?}"));

    dir
}

/// Creates a **coexisting** fixture: both the legacy `config-N/` layout AND
/// the A++ `identities/<UUID>/` layout, with consistent slot↔UUID mapping.
///
/// This is the state of a csq install during Phase 1–3 of the A++ migration:
/// the daemon has run its first-start mint pass and both layouts are present.
///
/// The same deterministic UUIDs as [`identity_only_fixture`] are used, so
/// `profiles.json.by_slot["N"]` maps to the same UUID that
/// `identities/<by_slot["N"]>/identity.json` declares.
///
/// The returned [`TempDir`]'s `path()` is the base directory. Cleanup on `Drop`.
///
/// # Panics
///
/// Panics on filesystem failure.
pub fn coexisting_fixture(n_accounts: u16) -> TempDir {
    let dir = TempDir::new().expect("fixture: TempDir::new");
    let base = dir.path();

    let mut profiles = ProfilesFile::empty();

    for slot in 1..=n_accounts {
        let uuid = fixture_uuid_for_slot(slot);
        let email = stub_email(slot);

        // ── Legacy side: config-N/.credentials.json ──────────────────────
        let config_dir = base.join(format!("config-{slot}"));
        let creds_path = config_dir.join(".credentials.json");
        write_secure(&creds_path, &stub_credentials_json(slot))
            .unwrap_or_else(|e| panic!("fixture: write_secure credentials slot {slot}: {e:?}"));

        // ── Identity side: identities/<uuid>/identity.json ────────────────
        let identity_dest = identity_json_path_for(base, uuid);
        write_secure(&identity_dest, &stub_identity_json(slot))
            .unwrap_or_else(|e| panic!("fixture: write_secure identity slot {slot}: {e:?}"));

        // Populate profiles maps (consistent with identity side)
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.by_email.insert(email, uuid);

        // Populate the v1 accounts map so the fixture is also valid against
        // the legacy reader (M1-4 reads config-N, but a populated accounts
        // map keeps doctor + other readers happy).
        profiles.set_profile(
            slot,
            AccountProfile {
                email: stub_email(slot),
                method: "oauth".to_string(),
                extra: std::collections::HashMap::new(),
            },
        );
    }

    // Write profiles.json
    let profiles_path = profiles::profiles_path(base);
    profiles::save(&profiles_path, &profiles)
        .unwrap_or_else(|e| panic!("fixture: profiles::save: {e:?}"));

    // Write store-version sentinel
    let sv_path = store_version_path(base);
    write_secure(&sv_path, &store_version_json())
        .unwrap_or_else(|e| panic!("fixture: write_secure store-version: {e:?}"));

    dir
}

/// Creates a **Partial-Pass-0** fixture: a coexisting layout where the slots
/// in `failed_slots` have a UUID in `profiles.json::by_slot` and an optional
/// identity directory, but NO `identities/<UUID>/credentials.json` and NO
/// `identities/<UUID>/identity.json`.  The identity directory itself exists
/// (models the race window where the daemon minted the dir but has not yet
/// seeded the credential files).  All other slots get a full coexisting setup.
///
/// This models the Partial-Pass-0 state defined in an internal journal entry (OQ #2): the
/// daemon has resolved the UUID and created the identity directory but has not
/// yet written `credentials.json` into it.  The `config-N/.credentials.json`
/// legacy file DOES exist for the failed slots (it was not deleted — coexisting
/// layout preservation invariant).
///
/// The returned [`TempDir`]'s `path()` is the base directory. Cleanup on `Drop`.
///
/// # Panics
///
/// Panics on filesystem failure.
pub fn partial_pass_0_fixture(n_accounts: u16, failed_slots: &[u16]) -> TempDir {
    use crate::accounts::identity_store::identity_path;
    use std::collections::HashSet;

    let dir = TempDir::new().expect("fixture: TempDir::new");
    let base = dir.path();

    let failed: HashSet<u16> = failed_slots.iter().copied().collect();
    let mut profiles = ProfilesFile::empty();

    for slot in 1..=n_accounts {
        let uuid = fixture_uuid_for_slot(slot);
        let email = stub_email(slot);

        // ── Legacy side: config-N/.credentials.json — present for ALL slots ──
        let config_dir = base.join(format!("config-{slot}"));
        let creds_path = config_dir.join(".credentials.json");
        write_secure(&creds_path, &stub_credentials_json(slot))
            .unwrap_or_else(|e| panic!("fixture: write_secure credentials slot {slot}: {e:?}"));

        // ── Identity side ─────────────────────────────────────────────────────
        if failed.contains(&slot) {
            // Partial-Pass-0: UUID is registered in profiles but the identity
            // directory exists without credential files.
            let id_dir = identity_path(base, uuid);
            std::fs::create_dir_all(&id_dir).unwrap_or_else(|e| {
                panic!("fixture: create_dir_all identity dir slot {slot}: {e}")
            });
            // credentials.json and identity.json are intentionally NOT written.
        } else {
            // Full coexisting: identity.json present.
            let identity_dest = identity_json_path_for(base, uuid);
            write_secure(&identity_dest, &stub_identity_json(slot))
                .unwrap_or_else(|e| panic!("fixture: write_secure identity slot {slot}: {e:?}"));
        }

        // UUID is registered for all slots (including failed) — that's what
        // makes it Partial-Pass-0: the UUID is known but the files aren't seeded.
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.by_email.insert(email.clone(), uuid);
        profiles.set_profile(
            slot,
            AccountProfile {
                email,
                method: "oauth".to_string(),
                extra: std::collections::HashMap::new(),
            },
        );
    }

    // Write profiles.json
    let profiles_path = profiles::profiles_path(base);
    profiles::save(&profiles_path, &profiles)
        .unwrap_or_else(|e| panic!("fixture: profiles::save: {e:?}"));

    // Write store-version sentinel
    let sv_path = store_version_path(base);
    write_secure(&sv_path, &store_version_json())
        .unwrap_or_else(|e| panic!("fixture: write_secure store-version: {e:?}"));

    dir
}

// ─── M12: Anti-fixture-masking public API ────────────────────────────────────

/// Materializes daemon-refresh-only on-disk state for a non-OAuth slot.
///
/// This fixture **structurally refuses** to write `oauthAccount.emailAddress`,
/// `credentials/<N>.json` (for 3P slots), or `accounts[N]` in `profiles.json`.
/// No parameter exposes those fields — a test that needs the pre-M4-9 shape
/// MUST use the separate [`legacy_pre_m4_9_state`] helper (and name itself
/// `*_legacy_*` for intent visibility).  This split is the structural defence
/// against the fixture-masking failure mode documented in
/// `internal-design-docs` Finding 1 and
/// `internal-design-docs`
/// FM-1.
///
/// # What it writes
///
/// **3P kinds** (`ApiKeyMm` / `ApiKeyZai` / `ApiKeyDeepseek` / `ApiKeyOllama`):
///   - `<base>/config-<slot>/settings.json` with an `env` block containing
///     `ANTHROPIC_BASE_URL` set to the kind's classified URL (the daemon's
///     `provider_from_base_url` will classify this back to the matching
///     `apikey:<id>` identity) and a stub `ANTHROPIC_AUTH_TOKEN`.
///   - `<base>/config-<slot>/.csq-account` marker with the legacy decimal slot
///     id (3P slots use the legacy marker format per `bind_provider_to_slot`).
///
/// **`CodexOauth`**:
///   - `<base>/identities/<UUID>/credentials-codex.json` with a stub
///     `tokens.account_id` value `"fx{slot:08x}-fixture"` whose first
///     hyphen-split segment (`"fx{slot:08x}"`) produces the deterministic label
///     `"codex-{slot}/fx{slot:08x}"` via the daemon's `format_label`.
///   - `<base>/config-<slot>/.csq-account` marker (legacy decimal).
///
/// # What it does NOT write
///
/// - NO `<base>/config-<slot>/.credentials.json` (the Anthropic OAuth cred file).
/// - NO `oauthAccount.emailAddress` payload in ANY file.
/// - NO `accounts[<slot>]` row in `profiles.json`.
/// - NO `by_slot_identity[<slot>]` entry (the test is verifying that the
///   reconciler PRODUCES this entry from the signals above).
///
/// This shape models a daemon-refreshed-only host: the slot was bound via
/// `csq bind <slot> <provider>` (3P) or `csq login <slot> --codex` (Codex)
/// AFTER M4-9 landed, so the v1 `accounts[N]` row is never populated.
///
/// # Origin
///
/// an internal journal entry Finding 1 + FM-1. See module doc-comment for full context.
pub fn daemon_refreshed_only_state(base: &Path, slot: u16, kind: NonOauthKind) -> io::Result<()> {
    let config_dir = base.join(format!("config-{slot}"));
    std::fs::create_dir_all(&config_dir)?;

    match kind {
        NonOauthKind::CodexOauth => {
            // Write identities/<UUID>/credentials-codex.json.
            let uuid = fixture_uuid_for_slot(slot);
            let cred_path = credentials_codex_path_for(base, uuid);
            write_secure(&cred_path, &stub_codex_credentials_json(slot))
                .map_err(config_err_to_io)?;
        }
        _ => {
            // 3P kind: write config-<slot>/settings.json.
            let base_url = kind
                .anthropic_base_url()
                .expect("non-Codex NonOauthKind always has a base URL");
            let settings_path = config_dir.join("settings.json");
            write_secure(&settings_path, &stub_3p_settings_json(slot, base_url))
                .map_err(config_err_to_io)?;
        }
    }

    // Write the legacy decimal .csq-account marker for all kinds.
    // (3P slots always use the legacy decimal marker per bind_provider_to_slot;
    // Codex slots use it here too because the fixture does not set up the full
    // UUID-keyed by_slot mapping that would trigger the UUID marker path.)
    let account_num = AccountNum::try_from(slot).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("slot {slot} out of AccountNum range: {e:?}"),
        )
    })?;
    crate::accounts::markers::write_csq_account_legacy(&config_dir, account_num)
        .map_err(|e| io::Error::other(format!("{e:?}")))?;

    Ok(())
}

/// Materializes the **pre-M4-9** on-disk shape with populated
/// `accounts[<slot>].email = legacy_email`.
///
/// Tests that need this shape (typically tests verifying backward-compat
/// behaviour on a v2.6.x-upgraded host) MUST name themselves `*_legacy_*`
/// to make the fixture intent explicit.  Calling this helper in a test that
/// is supposed to verify modern (post-M4-9) behaviour MASKS the fixture-bug
/// class described in an internal journal entry Finding 1 and FM-1.
///
/// Use [`daemon_refreshed_only_state`] for any test that verifies modern
/// daemon-refreshed-host behaviour.
///
/// # What it writes
///
/// Everything [`daemon_refreshed_only_state`] writes, PLUS:
///   - `<base>/profiles.json` with `accounts[<slot>] = { email: legacy_email,
///     method: "api_key" (3P) or "oauth" (Codex) }`.
pub fn legacy_pre_m4_9_state(
    base: &Path,
    slot: u16,
    kind: NonOauthKind,
    legacy_email: &str,
) -> io::Result<()> {
    // First materialize the daemon-refreshed-only layer.
    daemon_refreshed_only_state(base, slot, kind)?;

    // Then add the legacy accounts[N] row.
    let profiles_path = profiles::profiles_path(base);
    let mut pf = if profiles_path.exists() {
        profiles::load(&profiles_path).map_err(|e| io::Error::other(format!("{e:?}")))?
    } else {
        ProfilesFile::empty()
    };

    let method = match kind {
        NonOauthKind::CodexOauth => "oauth",
        _ => "api_key",
    };

    pf.set_profile(
        slot,
        AccountProfile {
            email: legacy_email.to_string(),
            method: method.to_string(),
            extra: std::collections::HashMap::new(),
        },
    );

    profiles::save(&profiles_path, &pf).map_err(|e| io::Error::other(format!("{e:?}")))?;

    Ok(())
}

/// Gemini auth mode selector for [`gemini_binding_state`] — kept separate
/// from [`NonOauthKind`] because Gemini's identity is derived from the
/// binding marker's `AuthMode`, NOT from an `accounts[N].email` /
/// `ANTHROPIC_BASE_URL` signal. The mode-class literal each produces is
/// the same one `gemini_identity_label` emits (FM-3a single producer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiFixtureMode {
    /// AI Studio API key → `gemini-<N>/apikey`.
    ApiKey,
    /// Vertex SA (synthetic absolute path; not validated by the fixture) →
    /// `gemini-<N>/vertex`.
    VertexSa,
    /// Code Assist OAuth → `gemini-<N>/codeassist`.
    CodeAssistOAuth,
}

impl GeminiFixtureMode {
    /// The expected `by_slot_identity[slot]` literal for this mode — the
    /// SAME value `provisioning::gemini_identity_label` produces. Tests
    /// assert against this so a divergence between the fixture's
    /// expectation and the SUT's producer is caught (FM-3a).
    pub fn expected_label(&self, slot: u16) -> String {
        let seg = match self {
            GeminiFixtureMode::ApiKey => "apikey",
            GeminiFixtureMode::VertexSa => "vertex",
            GeminiFixtureMode::CodeAssistOAuth => "codeassist",
        };
        format!("gemini-{slot}/{seg}")
    }
}

/// Materializes the on-disk shape of a Gemini-bound slot: a
/// `credentials/gemini-<slot>.json` binding marker (written through the
/// production `write_binding` path so the schema/permissions are real),
/// and — when `with_config_dir` — an empty `config-<slot>/` directory.
///
/// # Why `with_config_dir` is a parameter (FM-9 anti-masking)
///
/// `audit_coexistence`'s `OrphanLegacySlot` arm only considers a slot a
/// candidate when a `config-<slot>/` dir EXISTS (it scans `config-*`).
/// A fixture that writes only the binding marker (no `config-<slot>/`)
/// would make any "slot N no longer OrphanLegacySlot" assertion pass
/// green REGARDLESS of the G4 predicate fix — the slot was never a
/// candidate in that fixture. The real maintainer host HAS `config-13/`
/// (verified in an internal journal entry D4). A test asserting the G4 fix MUST pass
/// `with_config_dir = true` so the slot is a genuine orphan candidate
/// that the predicate must actively exclude. This is the structural
/// defense for the journal-0065-Finding-1 fixture-masking class.
pub fn gemini_binding_state(
    base: &Path,
    slot: u16,
    mode: GeminiFixtureMode,
    with_config_dir: bool,
) -> io::Result<()> {
    use crate::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};

    let account_num = AccountNum::try_from(slot).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("slot {slot} out of AccountNum range: {e:?}"),
        )
    })?;

    let auth = match mode {
        GeminiFixtureMode::ApiKey => AuthMode::ApiKey,
        GeminiFixtureMode::VertexSa => AuthMode::VertexSa {
            // Synthetic absolute path — the fixture does NOT validate or
            // read it (the writer never reads the SA JSON; the identity
            // literal is mode-class only — an internal journal entry Finding 1 class).
            path: std::path::PathBuf::from(format!("/nonexistent/fixture-sa-{slot}.json")),
        },
        GeminiFixtureMode::CodeAssistOAuth => AuthMode::CodeAssistOAuth,
    };

    let binding = GeminiBinding::new(auth, "auto");
    write_binding(base, account_num, &binding).map_err(|e| io::Error::other(format!("{e:?}")))?;

    if with_config_dir {
        std::fs::create_dir_all(base.join(format!("config-{slot}")))?;
    }

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::profiles;
    use std::fs;

    // ── legacy_only_fixture ──────────────────────────────────────────────

    #[test]
    fn legacy_only_has_config_dirs_and_no_identity_layout() {
        // Arrange + Act
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Assert: config-1, config-2, config-3 each have .credentials.json
        for slot in 1u16..=3 {
            let creds = base
                .join(format!("config-{slot}"))
                .join(".credentials.json");
            assert!(creds.exists(), "config-{slot}/.credentials.json must exist");
            let content = fs::read_to_string(&creds).unwrap();
            assert!(
                content.contains(&format!("fixture-slot-{slot}@test.invalid")),
                "slot {slot} credentials must contain stub email"
            );
        }

        // Assert: no identities/ dir
        assert!(
            !base.join("identities").exists(),
            "legacy-only fixture must not have identities/"
        );

        // Assert: no store-version
        assert!(
            !store_version_path(base).exists(),
            "legacy-only fixture must not have store-version"
        );

        // Assert: no profiles.json with by_slot/by_email
        // (profiles.json may not exist at all, or if it does it must not have by_slot)
        let profiles_path = profiles::profiles_path(base);
        if profiles_path.exists() {
            let pf = profiles::load(&profiles_path).unwrap();
            assert!(
                pf.by_slot.is_empty(),
                "legacy-only profiles.json must not have by_slot"
            );
            assert!(
                pf.by_email.is_empty(),
                "legacy-only profiles.json must not have by_email"
            );
        }
    }

    // ── identity_only_fixture ────────────────────────────────────────────

    #[test]
    fn identity_only_has_identity_layout_and_no_config_dirs() {
        // Arrange + Act
        let dir = identity_only_fixture(3);
        let base = dir.path();

        // Assert: no config-N/ directories
        for slot in 1u16..=3 {
            assert!(
                !base.join(format!("config-{slot}")).exists(),
                "identity-only fixture must not have config-{slot}/"
            );
        }

        // Assert: 3 identities/<uuid>/identity.json files
        for slot in 1u16..=3 {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_path = identity_json_path_for(base, uuid);
            assert!(
                identity_path.exists(),
                "identities/{uuid}/identity.json must exist for slot {slot}"
            );
        }

        // Assert: store-version exists
        assert!(
            store_version_path(base).exists(),
            "identity-only fixture must have store-version"
        );

        // Assert: profiles.json with populated by_slot and by_email
        let profiles_path = profiles::profiles_path(base);
        assert!(profiles_path.exists(), "profiles.json must exist");
        let pf = profiles::load(&profiles_path).unwrap();
        assert_eq!(pf.by_slot.len(), 3, "by_slot must have 3 entries");
        assert_eq!(pf.by_email.len(), 3, "by_email must have 3 entries");
    }

    #[test]
    fn identity_only_profiles_round_trip_through_load_save() {
        // Arrange
        let dir = identity_only_fixture(3);
        let base = dir.path();
        let profiles_path = profiles::profiles_path(base);

        // Act: load the profiles.json that the fixture wrote
        let pf = profiles::load(&profiles_path).unwrap();

        // Assert: by_slot entries resolve to the expected UUIDs
        for slot in 1u16..=3 {
            let expected_uuid = fixture_uuid_for_slot(slot);
            let actual_uuid = pf.by_slot.get(&slot.to_string()).copied();
            assert_eq!(
                actual_uuid,
                Some(expected_uuid),
                "by_slot[{slot}] must be the deterministic fixture UUID"
            );

            // Assert: by_email is the reverse lookup
            let email = stub_email(slot);
            let email_uuid = pf.by_email.get(&email).copied();
            assert_eq!(
                email_uuid,
                Some(expected_uuid),
                "by_email[{email}] must match by_slot[{slot}]"
            );
        }

        // Act: save + reload (round-trip test)
        profiles::save(&profiles_path, &pf).unwrap();
        let reloaded = profiles::load(&profiles_path).unwrap();
        assert_eq!(pf.by_slot, reloaded.by_slot, "by_slot survives round-trip");
        assert_eq!(
            pf.by_email, reloaded.by_email,
            "by_email survives round-trip"
        );
    }

    // ── coexisting_fixture ───────────────────────────────────────────────

    #[test]
    fn coexisting_has_both_layouts() {
        // Arrange + Act
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Assert: legacy config-N/ side
        for slot in 1u16..=3 {
            let creds = base
                .join(format!("config-{slot}"))
                .join(".credentials.json");
            assert!(
                creds.exists(),
                "config-{slot}/.credentials.json must exist in coexisting fixture"
            );
        }

        // Assert: identity side
        for slot in 1u16..=3 {
            let uuid = fixture_uuid_for_slot(slot);
            let identity = identity_json_path_for(base, uuid);
            assert!(
                identity.exists(),
                "identities/{uuid}/identity.json must exist for slot {slot}"
            );
        }

        // Assert: store-version
        assert!(
            store_version_path(base).exists(),
            "coexisting fixture must have store-version"
        );

        // Assert: profiles.json
        assert!(
            profiles::profiles_path(base).exists(),
            "coexisting fixture must have profiles.json"
        );
    }

    #[test]
    fn coexisting_slot_uuid_mapping_is_consistent() {
        // Arrange + Act
        let dir = coexisting_fixture(3);
        let base = dir.path();

        let profiles_path = profiles::profiles_path(base);
        let pf = profiles::load(&profiles_path).unwrap();

        // Assert: for each slot N, by_slot["N"] maps to the UUID that
        // identities/<by_slot["N"]>/identity.json declares (consistent mapping).
        for slot in 1u16..=3 {
            let uuid = pf
                .by_slot
                .get(&slot.to_string())
                .copied()
                .unwrap_or_else(|| panic!("by_slot must contain slot {slot}"));

            // The identity.json file at that UUID must exist
            let identity_path = identity_json_path_for(base, uuid);
            assert!(
                identity_path.exists(),
                "identities/{uuid}/identity.json (from by_slot[{slot}]) must exist"
            );

            // The identity.json email must match the by_email reverse lookup
            let email = stub_email(slot);
            let email_uuid = pf
                .by_email
                .get(&email)
                .copied()
                .unwrap_or_else(|| panic!("by_email must contain email {email}"));
            assert_eq!(
                uuid, email_uuid,
                "by_slot[{slot}] and by_email[{email}] must map to the same UUID"
            );

            // The identity.json content must reference the same email
            let identity_content = fs::read_to_string(&identity_path).unwrap();
            assert!(
                identity_content.contains(&email),
                "identity.json for slot {slot} must contain email {email}"
            );
        }
    }

    // ── Determinism tests ────────────────────────────────────────────────

    #[test]
    fn legacy_only_is_byte_identical_across_two_invocations() {
        // Two invocations of legacy_only_fixture(3) must produce byte-identical
        // .credentials.json content (modulo the TempDir's randomized parent path).
        let dir1 = legacy_only_fixture(3);
        let dir2 = legacy_only_fixture(3);

        for slot in 1u16..=3 {
            let content1 = fs::read_to_string(
                dir1.path()
                    .join(format!("config-{slot}"))
                    .join(".credentials.json"),
            )
            .unwrap();
            let content2 = fs::read_to_string(
                dir2.path()
                    .join(format!("config-{slot}"))
                    .join(".credentials.json"),
            )
            .unwrap();
            assert_eq!(
                content1, content2,
                "slot {slot} credentials must be byte-identical across invocations"
            );
        }
    }

    #[test]
    fn identity_only_uuids_are_deterministic_across_two_invocations() {
        // Two invocations of identity_only_fixture(3) must produce the same
        // UUIDs (deterministic seeding).
        let dir1 = identity_only_fixture(3);
        let dir2 = identity_only_fixture(3);

        let pf1 = profiles::load(&profiles::profiles_path(dir1.path())).unwrap();
        let pf2 = profiles::load(&profiles::profiles_path(dir2.path())).unwrap();

        assert_eq!(
            pf1.by_slot, pf2.by_slot,
            "by_slot UUIDs must be identical across two invocations"
        );
        assert_eq!(
            pf1.by_email, pf2.by_email,
            "by_email UUIDs must be identical across two invocations"
        );
    }

    #[test]
    fn coexisting_uuids_are_deterministic_across_two_invocations() {
        let dir1 = coexisting_fixture(3);
        let dir2 = coexisting_fixture(3);

        let pf1 = profiles::load(&profiles::profiles_path(dir1.path())).unwrap();
        let pf2 = profiles::load(&profiles::profiles_path(dir2.path())).unwrap();

        assert_eq!(pf1.by_slot, pf2.by_slot, "by_slot must be deterministic");
        assert_eq!(pf1.by_email, pf2.by_email, "by_email must be deterministic");
    }

    #[test]
    fn fixture_uuid_for_slot_is_stable() {
        // The same slot always produces the same UUID.
        for slot in 1u16..=5 {
            let u1 = fixture_uuid_for_slot(slot);
            let u2 = fixture_uuid_for_slot(slot);
            assert_eq!(u1, u2, "UUID for slot {slot} must be deterministic");
        }
    }

    #[test]
    fn fixture_uuid_for_slot_is_unique_across_slots() {
        // Different slots produce different UUIDs.
        let mut seen = std::collections::HashSet::new();
        for slot in 1u16..=20 {
            let uuid = fixture_uuid_for_slot(slot);
            assert!(seen.insert(uuid), "slot {slot} produced a duplicate UUID");
        }
    }

    // ── §5a partial-failure cleanup test ────────────────────────────────

    /// §5a regression: when `write_secure` fails after attempting to write
    /// (parent dir read-only), no `.tmp.` file must remain on disk.
    ///
    /// This exercises the `let _ = std::fs::remove_file(&tmp)` cleanup on
    /// the `write` failure branch. The helper
    /// `platform::fs::assert_no_tmp_leak_on_readonly_parent` is the
    /// canonical §5a regression fixture.
    #[cfg(unix)]
    #[test]
    fn write_secure_partial_failure_cleans_tmp_file() {
        use crate::platform::fs::assert_no_tmp_leak_on_readonly_parent;

        let outer = TempDir::new().unwrap();
        let locked_dir = outer.path().join("locked");
        std::fs::create_dir_all(&locked_dir).unwrap();

        // Write a placeholder so the file exists (write_secure needs a parent).
        let dest = locked_dir.join("test.json");
        std::fs::write(&dest, b"{}").unwrap();

        // Drive write_secure with read-only parent and assert no tmp leak.
        assert_no_tmp_leak_on_readonly_parent(&locked_dir, || write_secure(&dest, "{\"x\":1}"));
    }

    // ── R5-MED-2: fixture provider casing parity ─────────────────────────

    /// R5-MED-2 parity guard: `stub_identity_json` must use lowercase
    /// `"anthropic"` for the `"provider"` field, matching the production
    /// identity-mint path in `daemon/identity_mint.rs`.
    ///
    /// If this test fails after a refactor of `stub_identity_json`, the fixture
    /// will silently diverge from production and tests that parse provider
    /// values will pass against a casing that real code never emits.
    #[test]
    fn fixture_provider_matches_production_casing() {
        // Arrange: generate the stub JSON for any slot (casing is slot-independent)
        let json = stub_identity_json(1);

        // Assert: "provider" field is lowercase "anthropic"
        assert!(
            json.contains(r#""provider": "anthropic""#),
            "stub_identity_json must use lowercase \"anthropic\" for \"provider\"; \
             production identity-mint emits lowercase; got:\n{json}"
        );
        // Assert: NOT uppercase "Anthropic"
        assert!(
            !json.contains(r#""provider": "Anthropic""#),
            "stub_identity_json must NOT use uppercase \"Anthropic\" for \"provider\"; \
             got:\n{json}"
        );
    }

    // ── External consumer smoke test ─────────────────────────────────────

    /// Smoke test exercising the public API the way an external crate consumer
    /// (M1-4 tests, coc-eval) would call it: construct each fixture and verify
    /// the top-level invariants without access to private helpers.
    ///
    /// This mirrors what `csq/tests/identity_fixtures_smoke.rs` would do.
    #[test]
    fn external_consumer_smoke() {
        // legacy_only: config dirs present, no identity layout
        {
            let dir = legacy_only_fixture(2);
            let base = dir.path();
            assert!(base.join("config-1").join(".credentials.json").exists());
            assert!(base.join("config-2").join(".credentials.json").exists());
            assert!(!base.join("identities").exists());
            assert!(!store_version_path(base).exists());
        }

        // identity_only: identity layout present, no config dirs
        {
            let dir = identity_only_fixture(2);
            let base = dir.path();
            assert!(!base.join("config-1").exists());
            assert!(store_version_path(base).exists());
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert_eq!(pf.by_slot.len(), 2);
        }

        // coexisting: both layouts present
        {
            let dir = coexisting_fixture(2);
            let base = dir.path();
            assert!(base.join("config-1").join(".credentials.json").exists());
            assert!(store_version_path(base).exists());
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert_eq!(pf.by_slot.len(), 2);
            // UUID in by_slot must match the identity file on disk
            let uuid = pf.by_slot["1"];
            assert!(identity_json_path_for(base, uuid).exists());
        }
    }

    // ── M12: daemon_refreshed_only_state tests ───────────────────────────

    /// M12 acceptance test 1: `daemon_refreshed_only_state` for a 3P kind
    /// writes EXACTLY `settings.json` + `.csq-account` and does NOT write
    /// `.credentials.json`, `credentials/`, or `profiles.json::accounts[N]`.
    ///
    /// Origin: an internal journal entry Finding 1 + FM-1.
    #[test]
    fn daemon_refreshed_only_state_writes_settings_and_marker_only() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot: u16 = 5;
        let kind = NonOauthKind::ApiKeyMm;

        // Act
        daemon_refreshed_only_state(base, slot, kind).unwrap();

        // Assert: settings.json was written with the correct ANTHROPIC_BASE_URL
        let settings_path = base.join(format!("config-{slot}")).join("settings.json");
        assert!(
            settings_path.exists(),
            "settings.json must be written for 3P kind"
        );
        let settings_content = fs::read_to_string(&settings_path).unwrap();
        assert!(
            settings_content.contains("https://api.minimax.io/anthropic"),
            "settings.json must contain the MiniMax ANTHROPIC_BASE_URL; got:\n{settings_content}"
        );

        // Assert: .csq-account marker was written
        let marker_path = base.join(format!("config-{slot}")).join(".csq-account");
        assert!(marker_path.exists(), ".csq-account marker must be written");
        let marker_content = fs::read_to_string(&marker_path).unwrap();
        assert_eq!(
            marker_content.trim(),
            slot.to_string(),
            ".csq-account must contain the decimal slot id"
        );

        // Assert: no .credentials.json (the Anthropic OAuth credential file)
        let creds_path = base
            .join(format!("config-{slot}"))
            .join(".credentials.json");
        assert!(
            !creds_path.exists(),
            ".credentials.json MUST NOT be written for a 3P slot"
        );

        // Assert: no credentials/ subdirectory
        let creds_dir = base.join("credentials");
        assert!(
            !creds_dir.exists(),
            "credentials/ directory MUST NOT be created for a 3P slot"
        );

        // Assert: profiles.json does not exist OR accounts map is empty for this slot
        let profiles_path = profiles::profiles_path(base);
        if profiles_path.exists() {
            let pf = profiles::load(&profiles_path).unwrap();
            assert!(
                !pf.accounts_for_test().contains_key(&slot.to_string()),
                "profiles.json accounts[{slot}] MUST NOT be populated by daemon_refreshed_only_state"
            );
        }

        // Assert: identity_label returns the expected string
        assert_eq!(
            kind.identity_label(slot),
            "apikey:mm",
            "identity_label for ApiKeyMm must be \"apikey:mm\""
        );
    }

    /// M12 acceptance test 2: `daemon_refreshed_only_state` never writes
    /// `.credentials.json` or `oauthAccount.emailAddress` for ANY `NonOauthKind`
    /// variant.  For `CodexOauth`, only the Codex credential file is written.
    ///
    /// Structural defence: the function signature has no parameter that could
    /// introduce `oauthAccount.emailAddress` — this test verifies the invariant
    /// at the filesystem level across all five variants.
    ///
    /// Origin: an internal journal entry Finding 1 + FM-1.
    #[test]
    fn daemon_refreshed_only_state_refuses_to_write_credentials() {
        let all_kinds = [
            NonOauthKind::ApiKeyMm,
            NonOauthKind::ApiKeyZai,
            NonOauthKind::ApiKeyDeepseek,
            NonOauthKind::ApiKeyOllama,
            NonOauthKind::CodexOauth,
        ];

        for kind in all_kinds {
            // Arrange: fresh base dir per variant
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let slot: u16 = 3;

            // Act
            daemon_refreshed_only_state(base, slot, kind).unwrap();

            let variant_name = format!("{kind:?}");

            // Assert: Anthropic OAuth .credentials.json MUST NOT exist for any kind
            let anthropic_creds = base
                .join(format!("config-{slot}"))
                .join(".credentials.json");
            assert!(
                !anthropic_creds.exists(),
                "{variant_name}: .credentials.json (Anthropic OAuth) MUST NOT be written"
            );

            // Assert: no oauthAccount.emailAddress in any file under base.
            // We do a recursive walk and check every .json file's content.
            let found_email_address = walk_json_files_for_string(base, "oauthAccount");
            assert!(
                !found_email_address,
                "{variant_name}: 'oauthAccount' MUST NOT appear in any file written by daemon_refreshed_only_state"
            );

            // Assert: for CodexOauth, the Codex credential file IS present;
            // for 3P kinds, neither credentials/ dir nor any N.json exists.
            match kind {
                NonOauthKind::CodexOauth => {
                    let uuid = fixture_uuid_for_slot(slot);
                    let codex_cred = credentials_codex_path_for(base, uuid);
                    assert!(
                        codex_cred.exists(),
                        "CodexOauth: identities/<UUID>/credentials-codex.json must exist"
                    );
                    // Verify the account_id produces the expected label prefix.
                    let content = fs::read_to_string(&codex_cred).unwrap();
                    let expected_prefix = format!("fx{slot:08x}");
                    assert!(
                        content.contains(&expected_prefix),
                        "CodexOauth credentials-codex.json must contain account_id prefix \
                         {expected_prefix}; got:\n{content}"
                    );
                }
                _ => {
                    // No credentials/ dir should exist for 3P kinds.
                    let creds_dir = base.join("credentials");
                    assert!(
                        !creds_dir.exists(),
                        "{variant_name}: credentials/ directory MUST NOT be created"
                    );
                }
            }
        }
    }

    // ── M12: NonOauthKind helpers ────────────────────────────────────────

    /// Verifies `identity_label` returns the expected string for each variant.
    #[test]
    fn non_oauth_kind_identity_label_matches_expected() {
        assert_eq!(NonOauthKind::ApiKeyMm.identity_label(1), "apikey:mm");
        assert_eq!(NonOauthKind::ApiKeyZai.identity_label(1), "apikey:zai");
        assert_eq!(
            NonOauthKind::ApiKeyDeepseek.identity_label(1),
            "apikey:deepseek"
        );
        assert_eq!(
            NonOauthKind::ApiKeyOllama.identity_label(1),
            "apikey:ollama"
        );
        // Codex label encodes the slot number.
        assert_eq!(
            NonOauthKind::CodexOauth.identity_label(9),
            "codex-9/fx00000009"
        );
        assert_eq!(
            NonOauthKind::CodexOauth.identity_label(255),
            "codex-255/fx000000ff"
        );
    }

    /// Verifies `anthropic_base_url` returns the canonical URL from the catalog.
    #[test]
    fn non_oauth_kind_anthropic_base_url_matches_catalog() {
        // Sourced from csq-core/src/providers/catalog.rs PROVIDERS array.
        assert_eq!(
            NonOauthKind::ApiKeyMm.anthropic_base_url(),
            Some("https://api.minimax.io/anthropic")
        );
        assert_eq!(
            NonOauthKind::ApiKeyZai.anthropic_base_url(),
            Some("https://api.z.ai/api/anthropic")
        );
        assert_eq!(
            NonOauthKind::ApiKeyDeepseek.anthropic_base_url(),
            Some("https://api.deepseek.com/anthropic")
        );
        assert_eq!(
            NonOauthKind::ApiKeyOllama.anthropic_base_url(),
            Some("http://localhost:11434")
        );
        assert_eq!(NonOauthKind::CodexOauth.anthropic_base_url(), None);
    }

    // ── M12 test helper ──────────────────────────────────────────────────

    /// Recursively walks all `.json` files under `root` and returns `true`
    /// if any contains `needle`.
    ///
    /// Used by `daemon_refreshed_only_state_refuses_to_write_credentials` to
    /// assert the absence of `oauthAccount.emailAddress` across all written
    /// files — a structural check that cannot be spoofed by renaming a file.
    fn walk_json_files_for_string(root: &Path, needle: &str) -> bool {
        let Ok(entries) = fs::read_dir(root) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if walk_json_files_for_string(&path, needle) {
                    return true;
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains(needle) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
