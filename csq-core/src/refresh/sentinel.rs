//! Per-slot lifecycle sentinels: the LOGIN-NEEDED flag persistence.
//!
//! Phase 4 M4-6 (an internal ticket): migrated from `broker::fanout` to
//! `refresh::sentinel`. The module's surviving responsibility is the
//! per-slot failure marker (`credentials/{N}.broker-failed`).
//!
//! # What the marker MEANS
//!
//! The file is the sticky per-slot **LOGIN-NEEDED** state, despite its
//! historical `broker-failed` name. A slot is marked only when a refresh
//! failure proves the credential can never recover without a fresh
//! interactive login ([`reason_means_login_needed`]): an allowlisted OAuth
//! rejection of the grant (`invalid_grant`, `unauthorized_client`) or one of
//! OpenAI's own re-login codes (`token_expired`, `refresh_token_reused`,
//! `token_invalidated`), plus a Codex canonical that has no refresh token at
//! all.
//!
//! Every other refresh failure — a transport error, an unparseable body, an
//! allowlisted-but-retryable category such as `invalid_scope` or
//! `invalid_request`, a 429, a local lock/IO fault — is a RETRYABLE COOLDOWN:
//! the daemon backs off and retries, and NO sentinel is written. Marking a
//! slot login-needed for those told operators to re-authenticate healthy
//! accounts and made `csq run` refuse a slot a retry would have healed.
//!
//! Because a marked slot is by definition not recoverable without a login,
//! the state is STICKY across daemon ticks: readers must not expire it on
//! age (the statusline is read-only — `account-terminal-separation.md`
//! MUST-2 — so rendering never deletes it).
//!
//! # Reading the marker — THREE states, never two
//!
//! Field hosts already hold markers written by the PRE-classification
//! writer, which marked ANY refresh failure (transient ones included) with a
//! generic `error_kind_tag` value (`"oauth"`, `"credential"`, `"platform"`,
//! `"daemon"`, `"config"`, `"other"`, `"broker_refresh_failed"`,
//! `"broker_token_invalid"`), or by the pre-v2.1 writer as a zero-byte file.
//! Existence is therefore NOT a login demand. Every production reader MUST
//! use [`login_needed_state`]:
//!
//! 1. reason in [`LOGIN_NEEDED_REASONS`] → [`LoginNeededState::LoginNeeded`];
//! 2. marker present, reason anything else (generic tag, unrecognised future
//!    tag, empty, or unreadable) → [`LoginNeededState::Unknown`], surfaced as
//!    [`REFRESH_FAILING_CAUSE_NOT_RECORDED`] — never healthy, never
//!    login-needed;
//! 3. no marker → [`LoginNeededState::Healthy`].
//!
//! `login_needed_marker_present` is a derived existence predicate for tests
//! and cleanup paths only; it must never be read as "needs login".
//!
//! Historical note: `fan_out_credentials` was retired in M3-7 — handle
//! dirs read credentials through their identity-keyed symlinks
//! (M3-3/M3-4), so the daemon's `save_canonical_for` write IS the only
//! credential write needed. `config-N/.credentials.json` is no longer
//! materialised. The retired symbol is gone with the M4-6 rename.
//!
//! **`scan_config_dirs` removed (`guard-reader-writer-parity.md` sweep):**
//! this module's docstring previously claimed a `scan_config_dirs` helper
//! was "used by the desktop swap command to find the live config-N for an
//! account". That was false — a repo-wide grep found zero production
//! callers (only its own `#[cfg(test)]` module referenced it), and it
//! carried the SAME narrow-marker-reader defect as the three live sites
//! this sweep fixed (`markers::read_csq_account`, numeric-only, silently
//! dropping every UUID-marker `config-*` dir from its scan). Genuinely dead
//! code with the class-defining bug pre-baked is deleted rather than fixed,
//! so it cannot be re-wired blind by a future caller.

use crate::error::CredentialError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

// `fan_out_credentials` retired in M3-7 and the symbol is gone in
// M4-6. Handle dirs symlink `.credentials.json` to
// `identities/<UUID>/credentials.json` (M3-3/M3-4 retarget); the
// daemon's `save_canonical_for` write IS the only credential write
// needed, and CC re-stats the symlink before every API call
// (spec 01 §1.4).

// ── Login-needed sentinel ─────────────────────────────────────────────

/// Returns the path to the login-needed flag file.
///
/// The `{N}.broker-failed` filename is RETIRED-VOCABULARY-BUT-CURRENT: every
/// shipped csq version writes it and every reader (including the desktop)
/// reads it, so renaming it would silently orphan existing markers and force
/// a two-name reader. The name is historical; the MEANING is login-needed
/// (see the module docs).
fn broker_failed_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account))
}

/// Whether `reason` is one of the fixed-vocabulary tags that mean "only a
/// fresh login can recover this slot".
///
/// This is the SINGLE gate for [`set_broker_failed`]'s production callers:
/// a tag outside this set must never write the sentinel, because the
/// sentinel drives `csq run`'s launch refusal and the operator's
/// "run `csq login N`" instruction. The Anthropic half delegates to
/// [`crate::error::login_needed_category`] (the same predicate
/// `error_kind_tag` produces tags from); the Codex half is OpenAI's own
/// re-login codes.
///
/// `invalid_request` and `invalid_scope` are deliberately ABSENT — see
/// [`crate::error::login_needed_category`] for why a retryable OAuth
/// category must not demand a login.
pub fn reason_means_login_needed(reason: &str) -> bool {
    crate::error::login_needed_category(reason)
        || matches!(
            reason,
            "codex_token_expired" | "codex_refresh_reused" | "codex_token_invalidated"
        )
}

/// The fixed vocabulary of reason tags that mean "only a fresh login can
/// recover this slot", as `&'static str` so a reader can carry the tag
/// without borrowing marker bytes.
pub const LOGIN_NEEDED_REASONS: &[&str] = &[
    "invalid_grant",
    "unauthorized_client",
    "codex_token_expired",
    "codex_refresh_reused",
    "codex_token_invalidated",
];

/// The reader cap for the marker file, in bytes.
///
/// Derived from the writer's cap: [`set_broker_failed`] stores at most 256
/// `char`s, and a UTF-8 `char` is at most 4 bytes, so 1024 bytes is the
/// largest legitimate marker. A larger file is not a marker this build can
/// classify; the bounded reader rejects it instead of allocating whatever a
/// foreign or corrupt file happens to hold.
pub const SENTINEL_MAX_BYTES: u64 = 1024;

/// Maps marker contents to the fixed login-needed tag, or `None` when the
/// reason is not in the vocabulary.
///
/// The returned string is a slice of [`LOGIN_NEEDED_REASONS`], never of the
/// marker file. A marker's contents are attacker-influenceable only through a
/// local same-user write, but the pointer discipline is shared with the
/// OAuth allowlist for the same reason: no upstream/local text is ever
/// carried forward as a tag.
pub fn login_needed_tag(reason: &str) -> Option<&'static str> {
    LOGIN_NEEDED_REASONS
        .iter()
        .copied()
        .find(|tag| *tag == reason)
}

/// The operator phrase every surface prints for a marker whose cause this
/// build cannot classify.
///
/// A marker written by the PRE-classification writer (generic `error_kind_tag`
/// values such as `"oauth"`, `"credential"`, `"platform"`, `"daemon"`,
/// `"config"`, `"other"`, `"broker_refresh_failed"`, `"broker_token_invalid"`),
/// a pre-v2.1 zero-byte marker, an unreadable marker and an unrecognised
/// future tag all land here. That writer marked ANY refresh failure, transient
/// ones included, so such a marker is NOT evidence the grant is dead: the
/// state is UNKNOWN — never healthy, never login-needed.
pub const REFRESH_FAILING_CAUSE_NOT_RECORDED: &str = "refresh failing, cause not recorded";

/// The operator phrase every surface prints when the `credentials/` directory
/// itself cannot be enumerated, so the per-slot lists are UNDETERMINED rather
/// than empty.
///
/// Fixed vocabulary, no path and no credential material. A surface that
/// printed nothing here would read as "all clear" — the fail-open this
/// phrase exists to prevent.
pub const SENTINEL_SCAN_UNDETERMINED: &str =
    "login state undetermined — cannot read credentials directory";

/// The three states of the per-slot login-needed sentinel.
///
/// This is the ONLY accessor production readers may use
/// (`guard-reader-writer-parity.md` MUST-1): a marker is either a classified
/// login demand, an unclassifiable refresh failure, or absent. Existence
/// alone is NOT "needs login" — the pre-classification writer marked every
/// failure with a generic tag, so a bare existence check would demand a
/// login for slots whose credential is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginNeededState {
    /// No marker: the slot has no recorded login-needed or refresh-failure
    /// condition.
    Healthy,
    /// Marker present with a tag from [`LOGIN_NEEDED_REASONS`]: only a fresh
    /// login can recover the slot.
    LoginNeeded { reason: &'static str },
    /// Marker present, cause not classifiable (legacy generic tag, zero-byte
    /// pre-v2.1 marker, unrecognised future tag, or unreadable file).
    /// Surfaced as [`REFRESH_FAILING_CAUSE_NOT_RECORDED`]; NOT a login
    /// demand and NOT healthy.
    Unknown,
}

impl LoginNeededState {
    /// Whether this state demands a fresh login.
    pub fn is_login_needed(self) -> bool {
        matches!(self, LoginNeededState::LoginNeeded { .. })
    }

    /// Whether a sentinel file exists at all (login-needed OR unknown).
    ///
    /// Deliberately NOT named "failed" or "needs login": callers that gate an
    /// operator action must match the three states, not collapse them.
    pub fn has_marker(self) -> bool {
        !matches!(self, LoginNeededState::Healthy)
    }
}

/// Classifies the slot's sentinel file.
///
/// Read-only: no credential read, no keychain read, no network, no deletion.
/// The marker is opened through
/// [`crate::platform::fs::read_private_regular_nofollow_bounded`]: no symlink
/// following (`O_NOFOLLOW`), non-blocking open (`O_NONBLOCK`, so a FIFO cannot
/// hang an operator surface), a regular-file requirement, the private-file
/// ownership/mode check, and a [`SENTINEL_MAX_BYTES`] read cap. A symlink, a
/// FIFO, an oversized file, a foreign-owned file or an I/O refusal is
/// UNKNOWN — never healthy (silence must not read as "all clear") and never
/// login-needed (no demand without a recorded cause).
pub fn login_needed_state(base_dir: &Path, account: AccountNum) -> LoginNeededState {
    let path = broker_failed_path(base_dir, account);
    let bytes =
        match crate::platform::fs::read_private_regular_nofollow_bounded(&path, SENTINEL_MAX_BYTES)
        {
            // The bounded reader maps a genuinely missing file to `None`;
            // a symlink (dangling or not) fails O_NOFOLLOW and takes the
            // `Err` arm below, so link presence is never read as absence.
            Ok(None) => return LoginNeededState::Healthy,
            Ok(Some(bytes)) => bytes,
            // Symlink, FIFO, directory, oversized file, foreign-owned file,
            // permission/IO refusal: the marker may exist but its cause
            // cannot be read safely. UNKNOWN (fail toward surfacing, never
            // toward "healthy").
            Err(_) => return LoginNeededState::Unknown,
        };
    let reason = String::from_utf8_lossy(&bytes).trim().to_string();
    match login_needed_tag(&reason) {
        Some(reason) => LoginNeededState::LoginNeeded { reason },
        None => {
            // LEGACY-SENTINEL-UNKNOWN
            // RETIRE AFTER 2027-01-31, or once no pre-classification marker
            // remains on any host — whichever is later. This arm carries the
            // legacy forms (generic `error_kind_tag` values written by the
            // writer that marked EVERY refresh failure, and the pre-v2.1
            // zero-byte marker) as well as any unrecognised future tag; only
            // the legacy half is retire-able. Retirement marker:
            // LEGACY-SENTINEL-UNKNOWN.
            LoginNeededState::Unknown
        }
    }
}

/// Whether a sentinel file exists for the slot (login-needed or unknown).
///
/// Thin derived predicate over [`login_needed_state`]; the three-state
/// accessor remains the authority. Do NOT read this as "needs login".
pub fn login_needed_marker_present(base_dir: &Path, account: AccountNum) -> bool {
    login_needed_state(base_dir, account).has_marker()
}

/// The one operator-facing line every surface prints for a login-needed slot.
///
/// Used by `csq status`, `csq doctor` and the statusline so the three
/// surfaces cannot drift, and so the required phrase itself is testable in
/// one place. Fixed vocabulary only: an account number and an action — no
/// reason tag, no credential material, no upstream text. Reading it requires
/// no credential and no keychain access (`diagnostic-surface-parity.md`
/// MUST NOT 4).
pub fn login_needed_line(account: AccountNum) -> String {
    format!("login needed — run csq login {account}")
}

/// The one operator-facing line every surface prints for an UNKNOWN marker.
///
/// The phrase is [`REFRESH_FAILING_CAUSE_NOT_RECORDED`] verbatim; the slot is
/// prefixed by the multi-slot surfaces (status, doctor) so two unknown slots
/// cannot render as one indistinguishable line. The statusline prints the
/// bare phrase (its own slot is implicit).
pub fn refresh_failing_line(account: AccountNum) -> String {
    format!("slot {account}: {REFRESH_FAILING_CAUSE_NOT_RECORDED}")
}

/// The result of one `credentials/` enumeration.
///
/// `readable = false` means the directory (or one of its entries) could not be
/// read: the slot lists are UNDETERMINED, not empty, and every surface must print
/// [`SENTINEL_SCAN_UNDETERMINED`] rather than reading as "all clear".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelScan {
    /// False when `credentials/` exists but could not be enumerated. A
    /// missing directory is readable-and-empty: a fresh base has no slots and
    /// no failures.
    pub readable: bool,
    /// Every enumerated marker and its classification, ascending.
    pub states: Vec<(AccountNum, LoginNeededState)>,
}

impl SentinelScan {
    /// `(slot, classified reason)` for LOGIN-NEEDED slots only.
    ///
    /// The reason is the `&'static str` from [`LOGIN_NEEDED_REASONS`], never
    /// bytes re-read from the marker: a surface that serialises this can only
    /// ever emit the fixed vocabulary.
    pub fn login_needed(&self) -> impl Iterator<Item = (AccountNum, &'static str)> + '_ {
        self.states
            .iter()
            .filter_map(|(account, state)| match state {
                LoginNeededState::LoginNeeded { reason } => Some((*account, *reason)),
                LoginNeededState::Healthy | LoginNeededState::Unknown => None,
            })
    }

    /// Slots in the LOGIN-NEEDED state only (case 1 of the three-state model).
    pub fn login_needed_slots(&self) -> Vec<AccountNum> {
        self.login_needed().map(|(account, _)| account).collect()
    }

    /// Slots whose marker exists but whose cause is not classifiable (case 2).
    ///
    /// Surfaced as [`REFRESH_FAILING_CAUSE_NOT_RECORDED`] by every operator
    /// surface. Never login-needed, never healthy.
    pub fn refresh_failing_slots(&self) -> Vec<AccountNum> {
        self.states
            .iter()
            .filter(|(_, state)| matches!(state, LoginNeededState::Unknown))
            .map(|(account, _)| *account)
            .collect()
    }
}

/// Enumerates `credentials/` once and classifies every marker.
///
/// The ONE enumerator the multi-slot operator surfaces use (`csq status` and
/// `csq doctor`), so they cannot disagree about which slots need a login and
/// which are merely failing with an unrecorded cause — and so they can both
/// distinguish "no markers" from "could not read the directory". The
/// statusline renders one terminal's own slot and probes it directly with
/// [`login_needed_state`]; only its UNKNOWN path consults this scan to tell a
/// legacy marker from an unreadable directory.
///
/// Scans `credentials/` for `*.broker-failed` files with a numeric stem — the
/// representation [`set_broker_failed`] writes and every shipped csq version
/// has written — and ignores every other entry.
///
/// Read-only by contract: nothing is deleted and no credential file is
/// opened, so this never needs the keychain (`diagnostic-surface-parity.md`
/// MUST NOT 4). A directory that cannot be read is reported through
/// [`SentinelScan::readable`] rather than collapsing to an empty list.
pub fn sentinel_scan(base_dir: &Path) -> SentinelScan {
    let entries = match std::fs::read_dir(base_dir.join("credentials")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A listing: probe a child so `credentials` itself is an ancestor checked
            // (Windows reports a file-shaped `credentials` as NotFound).
            let readable = crate::platform::fs::confirm_absent(
                &base_dir.join("credentials").join("0.broker-failed"),
            )
            .is_ok();
            return SentinelScan {
                readable,
                states: Vec::new(),
            };
        }
        Err(_) => {
            return SentinelScan {
                readable: false,
                states: Vec::new(),
            };
        }
    };
    scan_entry_names(
        base_dir,
        entries.map(|entry| entry.map(|entry| entry.file_name())),
    )
}

/// The scan over directory entry names. An entry the directory iterator could not
/// yield (`Err`) makes the scan UNREADABLE: dropping it would hide a possible
/// `.broker-failed` marker while reporting `readable: true`. Split from
/// [`sentinel_scan`] so the `Err` entry can be injected in a test (a `DirEntry`
/// cannot be constructed).
fn scan_entry_names(
    base_dir: &Path,
    entries: impl Iterator<Item = std::io::Result<std::ffi::OsString>>,
) -> SentinelScan {
    let mut states = Vec::new();
    let mut readable = true;
    for entry in entries {
        let Ok(name) = entry else {
            readable = false;
            continue;
        };
        let Ok(name) = name.into_string() else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".broker-failed") else {
            continue;
        };
        let Ok(id) = stem.parse::<u16>() else {
            continue;
        };
        // A stem outside the valid slot range cannot be a live slot; it is
        // ignored rather than surfaced as a login demand for a slot the
        // operator cannot address.
        let Ok(account) = AccountNum::try_from(id) else {
            continue;
        };
        states.push((account, login_needed_state(base_dir, account)));
    }
    states.sort_unstable_by_key(|(account, _)| account.get());
    states.dedup_by_key(|(account, _)| *account);
    SentinelScan { readable, states }
}

/// Sets the login-needed flag for the given account with a fixed-vocabulary
/// reason tag (`"invalid_grant"`, `"unauthorized_client"`,
/// `"codex_token_expired"`, …).
///
/// The reason is stored as the file contents so `csq doctor` can surface WHY
/// the slot needs a login without log archaeology.
///
/// ### Only permanent conditions may call this
///
/// Production callers MUST gate on [`reason_means_login_needed`]. A
/// retryable failure (transport, 429, `invalid_scope`, a local lock fault)
/// that writes this file makes `csq run` refuse a slot a retry would heal and
/// tells the operator to re-authenticate a healthy account.
///
/// Every path that CLEARS the flag is enumerated on
/// [`clear_broker_failed`]; a new setter without a registered clearer is a
/// `sentinel-clearing-parity.md` violation.
///
/// ### Atomic, private write
///
/// `rules/security.md` §4/§5/§5a: the flag is written through the
/// target-taking private-temp factory and published by rename while the
/// creator retains the writer — a torn write would either lose the state
/// (silently un-marking a dead slot) or leave a zero-byte file, and the
/// pre-fix plain `std::fs::write` created the file with the process umask
/// (0644 under the common 022), exposing the slot's auth state to other
/// local users.
///
/// ### Security
///
/// The `reason` argument is caller-controlled and MUST be a fixed-vocabulary
/// tag that never contains raw error messages — token leakage risk. See
/// `error::error_kind_tag` in csq-core for the canonical enum of safe
/// reason strings.
pub fn set_broker_failed(
    base_dir: &Path,
    account: AccountNum,
    reason: &str,
) -> Result<(), CredentialError> {
    let path = broker_failed_path(base_dir, account);
    if let Some(parent) = path.parent() {
        // SEC-2.15 (unified, R1 M1): the flag file lives in credentials/ —
        // create AND secure that dir fail-closed via the shared helper
        // (was a silent `.ok()` best-effort).
        crate::platform::fs::ensure_private_dir(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::other(format!("credentials_dir_refused: {e}")),
        })?;
    }
    // Cap at 256 bytes so a stray bug that shoves a full error
    // string in here can never bloat the flag file.
    let payload: String = reason.chars().take(256).collect();
    let write_path = path.clone();
    let writer = crate::platform::fs::write_private_tmp_synced_retained(&path, payload.as_bytes())
        .map_err(|e| CredentialError::Io {
            path: write_path,
            source: std::io::Error::other(format!("login_needed_write_failed: {e}")),
        })?;
    writer.replace(&path).map_err(|e| CredentialError::Io {
        path,
        source: std::io::Error::other(format!("login_needed_publish_failed: {e}")),
    })
}

/// Reads the login-needed reason tag, or `None` if the flag is not set or the
/// file cannot be read safely.
///
/// Diagnostic only. Operator surfaces no longer re-read the marker for a slot
/// they already classified: `csq doctor` uses the `&'static str` carried by
/// [`SentinelScan::login_needed`], so unclassified file bytes can never reach
/// a serialised surface (`csq doctor --json`). This accessor remains for
/// tests and for callers that need the raw (still fixed-vocabulary) reason;
/// it uses the same bounded, no-follow, regular-file reader as
/// [`login_needed_state`].
///
/// Contents are diagnostic, never the state: readers must never narrow
/// acceptance to the tags this build's writer emits
/// (`guard-reader-writer-parity.md` MUST-1) — a newer writer's tag, an older
/// build's `"network"`/`"oauth"` tag, and the pre-v2.1 zero-byte format are
/// all recognised.
///
/// Empty-file markers from the pre-v2.1 format are mapped to `Some("")` so
/// callers can still detect the flag but know the reason is unknown.
pub fn read_broker_failed_reason(base_dir: &Path, account: AccountNum) -> Option<String> {
    let path = broker_failed_path(base_dir, account);
    crate::platform::fs::read_private_regular_nofollow_bounded(&path, SENTINEL_MAX_BYTES)
        .ok()
        .flatten()
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
}

/// Clears the login-needed flag for `account`.
///
/// Per `.claude/rules/sentinel-clearing-parity.md` MUST Rule 2, every
/// success boundary that resolves the condition MUST call this function.
/// The enumeration below names every current caller; new success boundaries
/// that should clear the flag MUST be added BOTH here AND at the callsite
/// (paired update, never one without the other). [`set_broker_failed`] names
/// this function as the sole clearer.
///
/// **Current callers (12 sites — keep this list current):**
///
/// 1. `refresh::check::broker_check` early-return Valid path
///    (`csq-core/src/refresh/check.rs:89`) — daemon-tick observed that
///    the Anthropic access token is healthy; any stale flag is obsolete.
/// 2. `refresh::check::broker_check` post-lock Valid path (line 126) —
///    sibling process refreshed between our read and lock acquisition;
///    creds are healthy by the time we observe them under the lock.
/// 3. `refresh::check::do_refresh` Ok branch (line 134) — symmetric
///    setter pair for the Anthropic refresh path: a successful refresh
///    supersedes any prior failure.
/// 4. `refresh::check::broker_codex_check` early-return Valid (line 279)
///    — Codex sibling of (1).
/// 5. `refresh::check::broker_codex_check` post-lock Valid (line 308) —
///    Codex sibling of (2).
/// 6. `refresh::check::broker_codex_check` Refreshed-Ok (line 425) —
///    Codex symmetric setter pair sibling of (3); a successful Codex
///    refresh supersedes any prior failure.
/// 7. `providers::codex::login::perform_with` post-`save_canonical_for`
///    (`csq-core/src/providers/codex/login.rs:484`) — `csq login N
///    --provider codex` minted a fresh chain into the identity store;
///    prior broker_failed flag is obsolete.
/// 8. `providers::codex::desktop_login::*` post-`save_canonical_for`
///    (`csq-core/src/providers/codex/desktop_login.rs:268`) — desktop
///    counterpart to (7).
/// 9. `accounts::login::finalize_login`
///    (`csq-core/src/accounts/login.rs`) — Anthropic OAuth login
///    success; the rule's first instance (predates `sentinel-clearing-
///    parity.md`).
/// 10. `daemon::custodian::reconcile_account` adopt-success
///     (`csq-core/src/daemon/custodian.rs`) — the custodian adopted a
///     server-confirmed-live+owned token into the store; any prior
///     broker_failed flag is obsolete.
/// 11. `cli::commands::repair::apply_contaminated_heal`
///     (`csq/src/cli/commands/repair.rs`) — `csq repair
///     --heal-contaminated --apply` cleared a slot's
///     cross-account-contaminated store token (an internal ticket heal); the flag
///     from that dead token is now obsolete. `sentinel-clearing-parity.md`
///     Rule 1 names `csq repair --apply` as a resolution boundary.
/// 12. `accounts::logout::logout_account` post-credential-sweep
///     (`csq-core/src/accounts/logout.rs`) — the account is GONE, which
///     resolves the condition permanently rather than transiently: there
///     is no longer a slot to re-login. Without this the sentinel
///     outlives its slot and `csq doctor` reports a hard
///     `✗ LOGIN-NEEDED — run `csq login N`` for a slot with no profiles
///     entry, no quota row, no config dir and no credentials. Observed
///     live 2026-08-07 on a removed slot 7.
///
/// **Audit primitive (per `sentinel-clearing-parity.md` Rule 1):**
///
/// ```bash
/// grep -rEn 'clear_broker_failed' csq-core/src csq/src --include='*.rs' \
///   | grep -v test | grep -v '/sentinel.rs'
/// ```
///
/// The executable calls this returns are the enumeration above: eleven
/// invocations across nine files, two of which (broker_check's early-return
/// and post-lock Valid paths) share `clear_broker_failed_for_current`. The
/// grep also surfaces that helper's definition and a comment in
/// `accounts::logout` — classify hits, never count them (`tooling-self-
/// verification.md` Rule 5). A hit outside the enumeration is either a new
/// caller that MUST be added to this docstring (paired-update discipline) or
/// an unauthorized site to investigate.
///
/// **Fail-safe:** silently ignores remove errors (the sentinel may not
/// exist; ENOENT is the steady state). Errors other than ENOENT also
/// drop silently — this function is best-effort cleanup; persistent
/// clearing failures surface via the broker_failed flag itself staying
/// stale, which the Rule 1 audit catches structurally.
pub fn clear_broker_failed(base_dir: &Path, account: AccountNum) {
    let path = broker_failed_path(base_dir, account);
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;

    use crate::credentials;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn setup_config_dir(base: &Path, n: u16) -> PathBuf {
        let dir = base.join(format!("config-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let account = AccountNum::try_from(n).unwrap();
        markers::write_csq_account_legacy(&dir, account).unwrap();
        dir
    }

    /// Classify on a worker thread with a timeout so a blocking regression
    /// (a FIFO open without `O_NONBLOCK`, an unbounded read of `/dev/zero`)
    /// fails the test instead of hanging the suite.
    #[cfg(unix)]
    fn classify_with_timeout(base: &Path, account: AccountNum) -> LoginNeededState {
        let (tx, rx) = std::sync::mpsc::channel();
        let base = base.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(login_needed_state(&base, account));
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("sentinel classification blocked (FIFO or unbounded read)")
    }

    /// M3-7 acceptance test #9 (WBS line 266), preserved across the
    /// M4-6 broker→refresh rename:
    /// `broker_fanout_does_not_write_config_n_credentials_json`.
    ///
    /// `fan_out_credentials` is retired. After a daemon-driven token
    /// refresh, no refresh module function writes to `config-<N>/.credentials.json`.
    /// We assert the behaviour at the broker_check level: run a successful
    /// refresh (via the broker_check entry) and confirm the fixture-seeded
    /// config-N mirror is untouched (mtime stable).
    #[test]
    fn broker_fanout_does_not_write_config_n_credentials_json() {
        use crate::credentials::file as cred_file;
        use crate::refresh::check::broker_check;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();
        let config = setup_config_dir(dir.path(), 9);

        // Seed canonical with expiring credentials so broker_check fires.
        // M4-12: save_canonical is retired; write directly to the numeric
        // canonical read path that broker_check reads via file::canonical_path.
        let mut expiring = make_creds("at-expiring", "rt-9");
        expiring.expect_anthropic_mut().claude_ai_oauth.expires_at = 1000; // far in the past
        let canonical_path = cred_file::canonical_path(dir.path(), account);
        std::fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
        credentials::save(&canonical_path, &expiring).unwrap();

        // Seed live mirror with old content; we assert it stays untouched.
        let live_path = config.join(".credentials.json");
        credentials::save(&live_path, &make_creds("at-mirror-seed", "rt-9")).unwrap();
        let pre_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Run broker_check with a stubbed http_post that returns a fresh token.
        let mock = |_url: &str, _body: &str| -> Result<Vec<u8>, String> {
            Ok(br#"{
                "access_token":"at-refreshed",
                "refresh_token":"rt-9-new",
                "expires_in":3600
            }"#
            .to_vec())
        };
        let _ = broker_check(dir.path(), account, mock);

        // Assert: live mirror's mtime is unchanged → broker did not fan out.
        let post_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            pre_mtime, post_mtime,
            "M3-7: broker fanout retired; config-N/.credentials.json mirror MUST NOT \
             be written by broker_check; pre={pre_mtime:?} post={post_mtime:?}"
        );
    }

    #[test]
    fn broker_failed_flag_lifecycle() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        assert!(!login_needed_marker_present(dir.path(), account));

        set_broker_failed(dir.path(), account, "network").unwrap();
        assert!(login_needed_marker_present(dir.path(), account));
        assert_eq!(
            read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("network")
        );

        clear_broker_failed(dir.path(), account);
        assert!(!login_needed_marker_present(dir.path(), account));
        assert_eq!(read_broker_failed_reason(dir.path(), account), None);
    }

    #[test]
    fn broker_failed_reason_is_truncated_at_256_bytes() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();
        let huge = "a".repeat(10_000);
        set_broker_failed(dir.path(), account, &huge).unwrap();
        let read = read_broker_failed_reason(dir.path(), account).unwrap();
        assert!(
            read.len() <= 256,
            "reason must cap at 256 bytes to protect the flag file size"
        );
    }

    /// M4-6 acceptance test: the broker-failed sentinel API has been
    /// migrated from the legacy fanout module path to
    /// `csq_core::refresh::sentinel`. This test exists to pin the new
    /// module path — if a future refactor moves the API again the
    /// orchestrator grep (`crate::refresh::sentinel::set_broker_failed`)
    /// will fail to compile and surface the drift.
    #[test]
    fn set_broker_failed_writes_under_refresh_module() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(7u16).unwrap();

        // Exercise the API via its post-rename path. `super::` resolves
        // to `crate::refresh::sentinel` after M4-6 — the test fails to
        // compile if the module rename regresses.
        super::set_broker_failed(dir.path(), account, "m4_6_pin").unwrap();
        assert!(super::login_needed_marker_present(dir.path(), account));
        assert_eq!(
            super::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("m4_6_pin")
        );

        // Flag file lives under credentials/N.broker-failed regardless
        // of the parent module — verify on-disk layout is unchanged.
        let flag = dir
            .path()
            .join("credentials")
            .join(format!("{}.broker-failed", account));
        assert!(
            flag.exists(),
            "broker-failed flag must persist under credentials/{{N}}.broker-failed \
             after the broker→refresh rename (M4-6); got missing at {flag:?}"
        );

        super::clear_broker_failed(dir.path(), account);
        assert!(!super::login_needed_marker_present(dir.path(), account));
    }

    #[test]
    fn broker_failed_empty_file_reads_as_empty_reason() {
        // Pre-v2.1 broker-failed files were zero-byte markers.
        // `read_broker_failed_reason` should treat them as
        // `Some("")` so the flag-existence check stays the same
        // but the reason is just "unknown".
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("6.broker-failed"), b"").unwrap();
        assert_eq!(
            read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("")
        );
        assert!(login_needed_marker_present(dir.path(), account));
    }

    /// The shared operator message is the ONE string `csq status`,
    /// `csq doctor` and the statusline print, so it is pinned here rather
    /// than three times in three crates. The em dash and the `csq login N`
    /// action are part of the operator contract.
    #[test]
    fn login_needed_line_is_the_shared_operator_message() {
        assert_eq!(
            login_needed_line(AccountNum::try_from(3u16).unwrap()),
            "login needed — run csq login 3"
        );
    }

    /// The permanence classification is fixed vocabulary: a provider
    /// rejection of the GRANT is login-needed; everything else — including
    /// `invalid_request` and `invalid_scope`, the two categories that have
    /// historically caused mass false re-login demands — is retryable.
    #[test]
    fn reason_means_login_needed_is_the_fixed_permanent_vocabulary() {
        for permanent in [
            "invalid_grant",
            "unauthorized_client",
            "codex_token_expired",
            "codex_refresh_reused",
            "codex_token_invalidated",
        ] {
            assert!(
                reason_means_login_needed(permanent),
                "{permanent} means only a fresh login recovers the slot"
            );
        }
        for retryable in [
            "invalid_request",
            "invalid_scope",
            "unsupported_grant_type",
            "authorization_pending",
            "slow_down",
            "access_denied",
            "expired_token",
            "oauth",
            "credential",
            "network",
            "rate_limit",
            "codex_refresh_transport_outcome_unknown",
            "credentials_canonical_lock_refused",
            "broker_refresh_failed",
            "broker_token_invalid",
        ] {
            assert!(
                !reason_means_login_needed(retryable),
                "{retryable} is a retryable cooldown, never a login demand"
            );
        }
    }

    /// `rules/security.md` §4/§5/§5a: the persisted marker is created 0600
    /// through the private-temp factory and published by rename, leaving no
    /// staging file behind. The pre-fix `std::fs::write` created the file
    /// with the process umask — 0644 under the common 022 — so this
    /// assertion REDs on the old shape.
    #[cfg(unix)]
    #[test]
    fn sentinel_file_is_private_and_leaves_no_temp_behind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(8u16).unwrap();
        set_broker_failed(dir.path(), account, "invalid_grant").unwrap();

        let flag = dir.path().join("credentials").join("8.broker-failed");
        let mode = std::fs::metadata(&flag).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sentinel must be owner-only, got {mode:o}");

        let stray: Vec<String> = std::fs::read_dir(dir.path().join("credentials"))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "8.broker-failed")
            .collect();
        assert!(
            stray.is_empty(),
            "the private-temp writer must not leave a staging file behind: {stray:?}"
        );
    }

    /// Reader parity (`guard-reader-writer-parity.md` MUST-1): every tag the
    /// production setters emit is recognised by the enumerator and read back
    /// verbatim, and the enumerator ignores unrelated entries. Also pins the
    /// one-shot scanner both `csq status` and `csq doctor` use.
    #[test]
    fn login_needed_slots_recognises_every_writer_form() {
        let dir = TempDir::new().unwrap();
        let tags = [
            (7u16, "invalid_grant"),
            (2, "unauthorized_client"),
            (11, "codex_token_expired"),
            (4, "codex_refresh_reused"),
            (9, "codex_token_invalidated"),
        ];
        for (slot, tag) in tags {
            set_broker_failed(dir.path(), AccountNum::try_from(slot).unwrap(), tag).unwrap();
        }
        // Legacy/foreign shapes the reader must tolerate without mistaking
        // them for slots: an empty pre-v2.1 marker and junk entries. The
        // zero-byte marker is a MARKER, but its cause is unrecorded — it must
        // land in the UNKNOWN list, never the login-needed list.
        std::fs::write(dir.path().join("credentials").join("5.broker-failed"), b"").unwrap();
        std::fs::write(dir.path().join("credentials").join("notes.txt"), b"x").unwrap();
        std::fs::write(
            dir.path().join("credentials").join("999999.broker-failed"),
            b"out-of-range",
        )
        .unwrap();

        let slots: Vec<u16> = sentinel_scan(dir.path())
            .login_needed_slots()
            .into_iter()
            .map(|account| account.get())
            .collect();
        assert_eq!(
            slots,
            vec![2, 4, 7, 9, 11],
            "only the classified login-needed tags are slots; the zero-byte \
             legacy marker and junk/out-of-range stems are not"
        );
        for (slot, tag) in tags {
            assert_eq!(
                read_broker_failed_reason(dir.path(), AccountNum::try_from(slot).unwrap())
                    .as_deref(),
                Some(tag),
                "the enumerated slot's reason must round-trip"
            );
        }
        assert_eq!(
            read_broker_failed_reason(dir.path(), AccountNum::try_from(5u16).unwrap()).as_deref(),
            Some(""),
            "a zero-byte legacy marker still reads back as an empty reason"
        );
        assert_eq!(
            sentinel_scan(dir.path()).refresh_failing_slots(),
            vec![AccountNum::try_from(5u16).unwrap()],
            "the zero-byte legacy marker is UNKNOWN, not login-needed"
        );
        assert!(
            login_needed_marker_present(dir.path(), AccountNum::try_from(5u16).unwrap()),
            "UNKNOWN is not healthy: the marker still exists"
        );
    }

    /// The three-state classification over the LEGACY forms a field host can
    /// hold. Each is UNKNOWN — never healthy (silence would hide a real
    /// failure) and never login-needed (the pre-classification writer marked
    /// transient failures too, so the marker is not evidence the grant is
    /// dead). Removing the `Unknown` arm of [`login_needed_state`] REDs this.
    #[test]
    fn legacy_and_unrecognised_markers_are_unknown_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let cases: [(u16, &str, Option<&[u8]>); 9] = [
            (1, "canonical generic oauth", Some(b"oauth")),
            (2, "credential", Some(b"credential")),
            (3, "platform", Some(b"platform")),
            (4, "daemon", Some(b"daemon")),
            (5, "config", Some(b"config")),
            (6, "other", Some(b"other")),
            (7, "broker_refresh_failed", Some(b"broker_refresh_failed")),
            (8, "broker_token_invalid", Some(b"broker_token_invalid")),
            (9, "zero-byte pre-v2.1", Some(b"")),
        ];
        for (slot, name, content) in cases {
            std::fs::write(
                creds.join(format!("{slot}.broker-failed")),
                content.unwrap(),
            )
            .unwrap();
            let account = AccountNum::try_from(slot).unwrap();
            assert_eq!(
                login_needed_state(dir.path(), account),
                LoginNeededState::Unknown,
                "{name}: a pre-classification marker is UNKNOWN"
            );
            assert!(
                !sentinel_scan(dir.path())
                    .login_needed_slots()
                    .contains(&account),
                "{name}: UNKNOWN must never be enumerated as login-needed"
            );
            assert!(
                sentinel_scan(dir.path())
                    .refresh_failing_slots()
                    .contains(&account),
                "{name}: UNKNOWN must be enumerated as refresh-failing"
            );
        }

        // An unrecognised FUTURE tag takes the same arm (that half is not
        // retire-able): a newer writer's vocabulary must not be guessed at.
        let future = AccountNum::try_from(20u16).unwrap();
        std::fs::write(creds.join("20.broker-failed"), b"some_future_tag").unwrap();
        assert_eq!(
            login_needed_state(dir.path(), future),
            LoginNeededState::Unknown
        );
        assert!(!sentinel_scan(dir.path())
            .login_needed_slots()
            .contains(&future));
        assert!(sentinel_scan(dir.path())
            .refresh_failing_slots()
            .contains(&future));
        assert!(
            read_broker_failed_reason(dir.path(), future).is_some(),
            "reading must not delete or hide the marker"
        );
        assert!(creds.join("20.broker-failed").exists());
        assert!(
            creds.join("1.broker-failed").exists(),
            "no reader may delete a legacy marker"
        );
    }

    /// An UNREADABLE marker (here: a directory occupying the marker path —
    /// deterministic EISDIR, unlike a permission bit that a root CI user
    /// ignores) is UNKNOWN. It must not read as healthy, and must not demand
    /// a login for an account nobody can address.
    #[test]
    fn unreadable_marker_is_unknown_not_healthy() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(30u16).unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::create_dir(creds.join("30.broker-failed")).unwrap();

        assert_eq!(
            login_needed_state(dir.path(), account),
            LoginNeededState::Unknown,
            "an unreadable marker is UNKNOWN, never Healthy"
        );
        assert!(!login_needed_state(dir.path(), account).is_login_needed());
        assert!(sentinel_scan(dir.path())
            .refresh_failing_slots()
            .contains(&account));
    }

    /// A login-needed slot is permanently unresolvable without a login, so
    /// the state must NOT expire on age — the retired statusline helper
    /// deleted the marker after 24h, which silently dropped the demand for a
    /// dead credential. RED if any staleness filter returns for this marker.
    #[test]
    fn aged_login_needed_marker_stays_sticky() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(12u16).unwrap();
        set_broker_failed(dir.path(), account, "invalid_grant").unwrap();
        let flag = dir.path().join("credentials").join("12.broker-failed");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 24 * 3600);
        let file = std::fs::File::options().write(true).open(&flag).unwrap();
        file.set_modified(old).unwrap();
        drop(file);

        assert!(
            login_needed_marker_present(dir.path(), account),
            "an aged marker is still login-needed"
        );
        assert_eq!(
            sentinel_scan(dir.path()).login_needed_slots(),
            vec![account],
            "the enumerator must not filter by age"
        );
        assert!(flag.exists(), "no reader may delete the marker");
    }

    /// Availability: the marker reader must not follow a symlink. A symlink
    /// whose target would classify as login-needed is UNKNOWN, and reading it
    /// deletes nothing. The plain `std::fs::read` this replaced follows the
    /// link and classifies it `LoginNeeded` — the discriminating mutation.
    #[cfg(unix)]
    #[test]
    fn symlink_sentinel_is_unknown_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"invalid_grant").unwrap();
        std::os::unix::fs::symlink(&target, creds.join("40.broker-failed")).unwrap();
        let account = AccountNum::try_from(40u16).unwrap();

        assert_eq!(
            login_needed_state(dir.path(), account),
            LoginNeededState::Unknown,
            "a symlink marker is UNKNOWN, never a login demand"
        );
        assert!(!sentinel_scan(dir.path())
            .login_needed_slots()
            .contains(&account));
        assert!(sentinel_scan(dir.path())
            .refresh_failing_slots()
            .contains(&account));
        assert_eq!(
            read_broker_failed_reason(dir.path(), account),
            None,
            "the diagnostic reader must refuse the same symlink"
        );
        assert!(
            creds.join("40.broker-failed").is_symlink(),
            "reading must not delete or replace the link"
        );
    }

    /// The 1024-byte read cap wins over a valid-looking leading tag: a file
    /// larger than [`SENTINEL_MAX_BYTES`] is UNKNOWN, never login-needed.
    /// `std::fs::read` + `trim()` would classify this file `invalid_grant`.
    #[test]
    fn oversized_sentinel_is_unknown_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let mut payload = b"invalid_grant".to_vec();
        payload.extend(vec![b' '; 2000]);
        std::fs::write(creds.join("41.broker-failed"), &payload).unwrap();
        let account = AccountNum::try_from(41u16).unwrap();

        assert_eq!(
            login_needed_state(dir.path(), account),
            LoginNeededState::Unknown,
            "an oversized marker is UNKNOWN; the read cap wins over its leading tag"
        );
        assert!(!sentinel_scan(dir.path())
            .login_needed_slots()
            .contains(&account));
        assert!(sentinel_scan(dir.path())
            .refresh_failing_slots()
            .contains(&account));
        assert!(creds.join("41.broker-failed").exists());
    }

    /// A FIFO at the marker path must not block a statusline/render read:
    /// `O_NONBLOCK` plus the regular-file requirement classify it UNKNOWN.
    #[cfg(unix)]
    #[test]
    fn fifo_sentinel_is_unknown_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let fifo = creds.join("42.broker-failed");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo has no memory preconditions; `c_path` is a
        // NUL-terminated C string borrowed for the duration of the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        let account = AccountNum::try_from(42u16).unwrap();

        assert_eq!(
            classify_with_timeout(dir.path(), account),
            LoginNeededState::Unknown,
            "a FIFO marker is UNKNOWN and must not block the read"
        );
        assert!(!sentinel_scan(dir.path())
            .login_needed_slots()
            .contains(&account));
        assert!(sentinel_scan(dir.path())
            .refresh_failing_slots()
            .contains(&account));
    }

    /// `/dev/zero` is the unbounded-symlink case: following it would read
    /// forever (or exhaust memory). The no-follow reader classifies UNKNOWN
    /// without opening the target.
    #[cfg(unix)]
    #[test]
    fn dev_zero_symlink_is_unknown_without_reading_forever() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::os::unix::fs::symlink("/dev/zero", creds.join("43.broker-failed")).unwrap();
        let account = AccountNum::try_from(43u16).unwrap();

        assert_eq!(
            classify_with_timeout(dir.path(), account),
            LoginNeededState::Unknown
        );
        assert!(!sentinel_scan(dir.path())
            .login_needed_slots()
            .contains(&account));
    }

    /// A directory that cannot be enumerated is an UNDETERMINED scan, not an
    /// empty one: no surface may read it as all-clear. `credentials` as a
    /// regular file is a deterministic ENOTDIR on every platform.
    #[test]
    fn unreadable_credentials_directory_is_an_undetermined_scan() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("credentials"), b"not a directory").unwrap();

        let scan = sentinel_scan(dir.path());
        assert!(
            !scan.readable,
            "an unenumerable credentials path must be flagged, not read as empty"
        );
        assert!(scan.states.is_empty());
        assert!(scan.login_needed_slots().is_empty());
        assert!(scan.refresh_failing_slots().is_empty());
    }

    /// The base directory itself is a regular file, so `credentials` lies under a
    /// non-directory. Unix reports ENOTDIR from `read_dir`; Windows reports NotFound
    /// (`ERROR_PATH_NOT_FOUND`), which `confirm_absent` must refuse. DISCRIMINATES ONLY
    /// ON WINDOWS (unix passes before and after the fix, asserting parity).
    #[test]
    fn credentials_under_a_regular_file_base_is_an_undetermined_scan() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base-is-a-file");
        std::fs::write(&base, b"not a directory").unwrap();

        let scan = sentinel_scan(&base);
        assert!(
            !scan.readable,
            "a non-directory base must be flagged, not read as an empty credentials dir"
        );
        assert!(scan.states.is_empty());
    }

    /// An entry the directory iterator fails to yield makes the scan UNREADABLE, while the
    /// readable entries around it are still classified; a clean iterator stays readable.
    #[test]
    fn an_unyieldable_directory_entry_makes_the_scan_unreadable() {
        use std::ffi::OsString;
        let dir = TempDir::new().unwrap();
        let broken = || -> std::io::Result<OsString> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        };
        let scan = scan_entry_names(
            dir.path(),
            vec![Ok(OsString::from("unrelated.txt")), broken()].into_iter(),
        );
        assert!(
            !scan.readable,
            "a dropped Err entry must not report readable"
        );
        let scan = scan_entry_names(
            dir.path(),
            vec![Ok(OsString::from("unrelated.txt"))].into_iter(),
        );
        assert!(scan.readable);
    }

    /// A missing `credentials` directory under a real base is genuine absence on every
    /// platform: readable, no sentinels.
    #[test]
    fn missing_credentials_directory_under_a_real_base_is_readable_and_empty() {
        let dir = TempDir::new().unwrap();
        let scan = sentinel_scan(dir.path());
        assert!(scan.readable);
        assert!(scan.states.is_empty());
    }
}
