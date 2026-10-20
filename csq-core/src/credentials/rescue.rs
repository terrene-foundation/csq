//! Durable post-commit rescue records for rotated OAuth pairs.
//!
//! # Why this module exists
//!
//! A refresh has two halves. The FIRST half is PRE-COMMIT: directory
//! preparation, preflight reads, a lock probe. Refusing there costs
//! nothing — the next tick retries and no provider state has moved. The
//! SECOND half starts the moment the provider answers a refresh (or an
//! authorization-code exchange): the refresh token it consumed is already
//! rotated server-side, so from that instant the NEW pair exists ONLY in
//! this process's memory. A failed save after that point is permanent
//! token loss, and for Codex (whose refresh token is single-use,
//! openai/codex#10332) it is terminal — the account drops to LOGIN-NEEDED.
//!
//! `platform::lock::lock_credential_file`'s bounded 500 ms budget is
//! correct for the PRE-COMMIT half (`review-check-discipline.md` D237
//! round-1 finding C1 / security H1). Applying it to the post-commit half
//! is what loses tokens: a live holder doing ordinary local work (a small
//! JSON `atomic_replace` with fsync, an O(accounts) sibling scan) can hold
//! the canonical lock longer than 500 ms on a loaded filesystem, and the
//! writer then throws the pair away.
//!
//! # The protocol (ROOT ruling A, extended by D237 round-2 H-c)
//!
//! Every POST-COMMIT canonical write:
//!
//! 1. FIRST writes a durable rescue record
//!    (`<identity_dir>/rescue-<nonce>.json`, mode 0600) holding the exact
//!    credential JSON that is about to be written. The write is durable
//!    before the lock wait begins, so a crash during the wait loses nothing.
//!    ONE FILE PER WRITER: the nonce is CSPRNG-derived, so two writers never
//!    share a slot and a writer only ever deletes its OWN record.
//! 2. THEN takes the canonical lock under
//!    [`CREDENTIAL_COMMIT_LOCK_BUDGET`] (30 s), a long bound derived from
//!    the composed worst case of the holder sections that remain after
//!    D237's ruling B (see that constant's doc).
//! 3. On success it writes the canonical credential and removes its record.
//! 4. On expiry or lock error the record STAYS, a loud fixed-vocabulary
//!    log line is emitted (`credential_commit_lock_deferred` /
//!    `credential_commit_lock_error`), and the next refresher tick or
//!    daemon start ADOPTS it through [`adopt_rescue_record`].
//!
//! # Adoption re-runs the writer's source gate (D237 round-2 H-c)
//!
//! A record is a canonical WRITE proposal, so adoption is a canonical
//! writer. Every v2 record therefore carries the SOURCE and RESULT witness
//! the writer already had:
//!
//! - Anthropic refresh lineage: the captured source `CredentialVersion`,
//!   the result version, the captured context, and the captured legacy
//!   email — enough to re-run `proof.permits` and
//!   `refresh_context_matches` under the lock.
//! - Anthropic login: the verified result version and context — enough to
//!   re-run the login writer's "stored context matches / incoming grant is
//!   fresher than the canonical" gate.
//! - Codex: the exact expected source fingerprint, so
//!   `codex_credentials_match(current, expected_source)` is re-evaluated.
//!
//! If the current canonical no longer matches the recorded source (a newer
//! re-login or refresh landed), the record is DISCARDED as superseded
//! (`rescue_record_superseded`) and the canonical is never reverted. An
//! undecodable Codex expiry is NOT a refusal: the writer never decoded it
//! either, so adoption is no stricter than the writer — the exact
//! `codex_credentials_match` decides (R3 ruling 3(d)).
//!
//! A v1 record (`csq.rescue.v1`, or any v2 record without a witness) has no
//! source witness and cannot be re-gated, so it is discarded as superseded
//! with the same fixed tag — a backwards-compatible READ, never a
//! witness-free install.
//!
//! # The record's `reason` field
//!
//! It is diagnostic only, never a correctness input. Because the record is
//! written before the lock outcome is known, it is first stamped with the
//! anticipated `post_commit_lock_timeout`; an actual lock ERROR rewrites it
//! with `post_commit_lock_error`. A process that dies mid-wait leaves the
//! anticipated value, which is exactly why adoption keys on the record's
//! PRESENCE, never on its reason.
//!
//! # Secret handling
//!
//! The payload is live OAuth material. The record is written with
//! `crate::platform::fs::write_new_private` (mode 0600 at creation),
//! `secure_file`, then `atomic_replace`, and every failure branch removes
//! the temp file (`rules/security.md` §5a). No log line or error carries
//! token text: errors carry paths and fixed `error_kind` tags only.
//!
//! # Reader hardening (D237 round-2 security M1)
//!
//! The record is read on every refresher tick, from `probe`, from the usage
//! poller and from post-login. `read_rescue_bytes` therefore stats with
//! `symlink_metadata`, accepts ONLY a regular file, caps the size at
//! [`RESCUE_RECORD_MAX_BYTES`], and on unix opens with `O_NOFOLLOW |
//! O_NONBLOCK` so a planted FIFO, device symlink or oversized file is
//! treated as PENDING-unparseable WITHOUT being read — it can never wedge
//! the daemon.

use crate::accounts::anthropic_identity as ai;
use crate::accounts::identity_store::{self, IdentityId};
use crate::error::CredentialError;
use crate::platform::lock::{self, FileLockGuard};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

/// Schema marker for a rescue record this module wrote.
///
/// v2 added the SOURCE/RESULT witness (`anthropic_witness` /
/// `codex_expected_source`); adoption re-runs the writer's gate from it.
pub const RESCUE_SCHEMA: &str = "csq.rescue.v2";

/// Schema of a login publication's PRE-LOCK record (sec L-4). It is refused
/// by DEFAULT: readers act on it only once its publication wrote the
/// `<record>.json.kept` marker. A distinct value, so every reader that
/// predates the default (and would re-gate it) sees an UNKNOWN schema and
/// quarantines it instead of installing it.
pub const RESCUE_SCHEMA_PRELOCK: &str = "csq.rescue.v2.prelock";

/// The pre-witness schema. A v1 record has NO source witness, so adoption
/// cannot re-run the writer's gate; it is discarded as superseded with the
/// fixed `rescue_record_superseded` tag (backwards-compatible READ only).
pub const RESCUE_SCHEMA_V1: &str = "csq.rescue.v1";

/// Schema marker for a record that exists but could not be parsed.
///
/// Such a record is PENDING, never absent (fail-closed): readers must not
/// conclude "login needed" while it exists, and adoption reports it
/// instead of deleting it.
pub const RESCUE_SCHEMA_UNPARSEABLE: &str = "csq.rescue.unparseable";

/// Legacy single-slot file name. Still READ (a pre-v2 install could have
/// left one) and used by tests that plant an unparseable record.
pub const RESCUE_RECORD_FILE: &str = "rescue-credential.json";

/// Prefix and suffix of a per-writer rescue record name.
const RESCUE_RECORD_PREFIX: &str = "rescue-";
const RESCUE_RECORD_SUFFIX: &str = ".json";

/// Maximum size of a rescue record this module will read.
///
/// POLICY cap, not a measurement: a real record is one credential JSON
/// (well under 8 KiB). 64 KiB leaves ample headroom while bounding a
/// planted file or `/dev/zero` symlink to one bounded read.
pub const RESCUE_RECORD_MAX_BYTES: u64 = 64 * 1024;

/// Maximum rescue records one identity directory may hold (R3 sec L-4).
///
/// POLICY cap, not a measurement: a healthy identity has at most one record
/// per concurrent writer, and adoption/quarantine removes them on the next
/// tick. A directory above this cap is not a credential state this protocol
/// produced — enumeration FAILS CLOSED (the gate blocks, status reports
/// UNKNOWN) instead of scanning an unbounded directory on every tick.
pub const RESCUE_RECORD_MAX_PER_IDENTITY: usize = 32;

/// Named policy allowance for ONE bounded local-I/O section in a
/// credential critical section.
///
/// This is a POLICY CAP on bounded local work, never a measurement. It
/// covers one `serialize + atomic_replace + fsync` of a small JSON file
/// (or one O(accounts) sibling scan of small canonical reads) on a loaded
/// local filesystem. No network call, no subprocess, and no nested wait
/// on a same-budget lock belongs inside such a section — ruling B moved
/// the token-history append out of it for exactly that reason.
pub const CREDENTIAL_COMMIT_IO_ALLOWANCE: Duration = Duration::from_secs(5);

/// Per-transaction worst-case wait for a POST-COMMIT canonical lock.
///
/// DERIVATION, never a measurement. It composes the sections that can
/// still hold the canonical lock after this wave, each capped by
/// [`CREDENTIAL_COMMIT_IO_ALLOWANCE`]:
///
/// | Section                                                        | Allowances |
/// | -------------------------------------------------------------- | ---------- |
/// | holder: canonical serialize + `atomic_replace` + fsync          | 1          |
/// | holder: sibling canonical reads, O(accounts) small files        | 1          |
/// | waiter: its own serialize + `atomic_replace` + fsync            | 1          |
/// | second live waiter drained ahead of this one                    | 2          |
/// | retry room for a scheduling stall at the OS level               | 1          |
///
/// Six allowances = 30 s. Deliberately much larger than the 500 ms
/// PRE-COMMIT budget: a post-commit writer that gives up has CONSUMED a
/// single-use refresh token, so waiting is always cheaper than losing it.
/// Ruling B removed the nested token-history wait from this section and
/// nothing here performs network I/O or waits on user input.
pub const CREDENTIAL_COMMIT_LOCK_BUDGET: Duration =
    CREDENTIAL_COMMIT_IO_ALLOWANCE.saturating_mul(6);

/// [`CREDENTIAL_COMMIT_LOCK_BUDGET`] in whole milliseconds, for
/// fixed-vocabulary error text.
pub const CREDENTIAL_COMMIT_LOCK_BUDGET_MS: u64 = CREDENTIAL_COMMIT_LOCK_BUDGET.as_millis() as u64;

/// Delay between lock-acquisition attempts inside
/// [`CREDENTIAL_COMMIT_LOCK_BUDGET`].
const CREDENTIAL_COMMIT_LOCK_DELAY: Duration = Duration::from_millis(10);

/// Attempts derive from the TWO Durations, never from a literal: the
/// bound and the retry cadence are declared above and the count is their
/// quotient.
const CREDENTIAL_COMMIT_LOCK_ATTEMPTS: u32 =
    (CREDENTIAL_COMMIT_LOCK_BUDGET.as_millis() / CREDENTIAL_COMMIT_LOCK_DELAY.as_millis()) as u32;

/// Test-only override of the commit budget, so rows can exercise the
/// expiry branch without a 30-second wall-clock wait.
///
/// Thread-local (the `pre_tighten_hook` precedent): the holder runs on
/// another thread, the writer under test on this one. Only the BUDGET is
/// overridable — the retry delay and the derived attempt count stay the
/// production shape, and production builds compile this module away.
#[cfg(any(test, feature = "test-utils"))]
mod commit_budget_override {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        static BUDGET: Cell<Option<Duration>> = const { Cell::new(None) };
    }

    pub(super) fn get() -> Option<Duration> {
        BUDGET.with(Cell::get)
    }

    /// Installs (or clears) the override for the CURRENT thread. Tests MUST
    /// clear it before returning; [`OverrideGuard`] does that even on a
    /// failing assertion.
    #[cfg(test)]
    pub fn set(budget: Option<Duration>) {
        BUDGET.with(|slot| slot.set(budget));
    }

    /// RAII override: restores the production budget on drop.
    #[cfg(test)]
    pub struct OverrideGuard;

    #[cfg(test)]
    impl OverrideGuard {
        #[must_use]
        pub fn install(budget: Duration) -> Self {
            set(Some(budget));
            OverrideGuard
        }
    }

    #[cfg(test)]
    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            set(None);
        }
    }
}

#[cfg(test)]
pub use commit_budget_override::OverrideGuard as CommitBudgetOverrideGuard;

/// The (attempts, delay) shape the commit lock uses on this thread.
fn commit_lock_shape() -> (u32, Duration) {
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(budget) = commit_budget_override::get() {
        return (
            (budget.as_millis() / CREDENTIAL_COMMIT_LOCK_DELAY.as_millis()).max(1) as u32,
            CREDENTIAL_COMMIT_LOCK_DELAY,
        );
    }
    (
        CREDENTIAL_COMMIT_LOCK_ATTEMPTS,
        CREDENTIAL_COMMIT_LOCK_DELAY,
    )
}

/// Acquires the canonical credential lock under
/// [`CREDENTIAL_COMMIT_LOCK_BUDGET`].
///
/// `Ok(None)` means the budget expired while another process held the
/// lock. A post-commit caller MUST NOT discard on it: the rescue record it
/// wrote first is the durable copy, and adoption installs it later.
pub fn lock_credential_file_commit(
    path: &Path,
) -> Result<Option<FileLockGuard>, crate::error::PlatformError> {
    let (attempts, delay) = commit_lock_shape();
    lock::try_lock_file_bounded(path, attempts, delay)
}

/// The provider-specific SOURCE/RESULT witness a rescue record carries.
///
/// See the module docs: adoption re-runs the same gate the in-place writer
/// runs, using exactly these values.
#[derive(Clone)]
pub enum RescueWitness {
    /// A refresh-lineage or login-grant witness from `anthropic_identity`.
    Anthropic(ai::RescueLineageWitness),
    /// The exact Codex canonical the refreshing writer captured before HTTP.
    Codex { expected_source: serde_json::Value },
}

/// REDACTING `Debug` (R3 sec L-2). The witness's codex arm holds the exact
/// canonical — tokens included — and the anthropic arm carries context PII;
/// a derived Debug printed both. Only the non-secret lineage fields print.
impl std::fmt::Debug for RescueWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RescueWitness::Anthropic(witness) => f
                .debug_struct("Anthropic")
                .field("kind", &witness.kind)
                .field("source_version", &witness.source_version)
                .field("result_version", &witness.result_version)
                .finish_non_exhaustive(),
            RescueWitness::Codex { .. } => f.write_str("Codex { expected_source: <redacted> }"),
        }
    }
}

/// One durable post-commit rescue record.
///
/// Field order and names are the cross-shard contract (ROOT ruling A):
/// other shards parse this shape to wire adoption, so an added field must
/// be optional and appended, and these names never change.
#[derive(Clone, Serialize, Deserialize)]
pub struct RescueRecord {
    /// Always [`RESCUE_SCHEMA`] for a record this module wrote.
    pub schema: String,
    /// `"anthropic"` or `"codex"` — selects the canonical destination.
    pub provider: String,
    /// Canonical hyphenated lowercase UUID whose identity owns the pair.
    pub uuid: String,
    /// Milliseconds since the Unix epoch, for operator forensics and
    /// freshest-writer tie-breaks only.
    pub written_at_ms: u128,
    /// `post_commit_lock_timeout` | `post_commit_lock_error` (diagnostic).
    pub reason: String,
    /// The exact canonical credential JSON that would have been written.
    pub payload: serde_json::Value,
    /// v2: the Anthropic source/result witness. Absent on a v1 record and
    /// on a Codex record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic_witness: Option<ai::RescueLineageWitness>,
    /// v2: the exact Codex canonical the writer captured before HTTP.
    /// Absent on a v1 record and on an Anthropic record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_expected_source: Option<serde_json::Value>,
}

/// REDACTING `Debug` (R3 sec L-2): `payload` and `codex_expected_source` hold
/// the rescued credential JSON (access and refresh tokens). Only the
/// diagnostic fields print.
impl std::fmt::Debug for RescueRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RescueRecord")
            .field("schema", &self.schema)
            .field("provider", &self.provider)
            .field("uuid", &self.uuid)
            .field("written_at_ms", &self.written_at_ms)
            .field("reason", &self.reason)
            .field("payload", &"<redacted>")
            .field("anthropic_witness", &self.anthropic_witness)
            .field(
                "codex_expected_source",
                &self.codex_expected_source.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RescueRecord {
    /// Fail-closed placeholder for a record that exists but could not be
    /// read or parsed. [`rescue_record_pending`] returns it so callers
    /// treat the state as PENDING; [`adopt_rescue_record`] reports it and
    /// never deletes it.
    fn unparseable() -> Self {
        RescueRecord {
            schema: RESCUE_SCHEMA_UNPARSEABLE.to_string(),
            provider: "unknown".to_string(),
            uuid: String::new(),
            written_at_ms: 0,
            reason: "rescue_record_unparseable".to_string(),
            payload: serde_json::Value::Null,
            anthropic_witness: None,
            codex_expected_source: None,
        }
    }

    /// Whether this is a login publication's PRE-LOCK record
    /// ([`RESCUE_SCHEMA_PRELOCK`]): refused by default until kept.
    pub fn is_prelock(&self) -> bool {
        self.schema == RESCUE_SCHEMA_PRELOCK
    }

    /// Whether this is an Anthropic LOGIN-witness record (a re-login grant).
    fn is_login_grant(&self) -> bool {
        self.provider == "anthropic"
            && self
                .anthropic_witness
                .as_ref()
                .is_some_and(|witness| witness.kind == ai::RescueWitnessKind::Login)
    }

    /// Whether this module's v2 readers understand the record's schema
    /// ([`RESCUE_SCHEMA`] or [`RESCUE_SCHEMA_PRELOCK`]).
    fn has_current_schema(&self) -> bool {
        self.schema == RESCUE_SCHEMA || self.is_prelock()
    }

    /// Whether this placeholder stands for an unreadable record.
    pub fn is_unparseable(&self) -> bool {
        self.schema == RESCUE_SCHEMA_UNPARSEABLE
    }

    /// Whether the record carries a SOURCE witness adoption can re-gate.
    fn has_witness(&self) -> bool {
        self.anthropic_witness.is_some() || self.codex_expected_source.is_some()
    }

    /// Whether adoption resolves this record without a human.
    ///
    /// Classified from the record ALONE, from the same fields adoption
    /// reads before it touches the canonical lock:
    ///
    /// - unreadable/unparseable, an unknown schema, a `uuid` that does not
    ///   match the identity directory, or an unparseable provider payload is
    ///   REFUSED by adoption on every tick (`rescue_record_unreadable` /
    ///   `rescue_uuid_mismatch`), so only a fresh sign-in can clear it. An
    ///   undecodable Codex EXPIRY is NOT in this class (R3 ruling 3(d): the
    ///   exact source match decides, as it does for the writer);
    /// - a v1 / witness-less record is discarded as superseded (also with
    ///   no user action), so it counts as self-resolving;
    /// - an intact v2 record with a witness either installs or is
    ///   discarded as superseded on a later tick.
    ///
    /// A live-canonical refusal (unreadable canonical, source gate
    /// unreadable) is NOT classified here: it can clear on a later tick
    /// without a human and is not a property of the record.
    fn is_self_resolving(&self, base_dir: &Path, id: IdentityId, identity_uuid: &str) -> bool {
        if self.is_unparseable() {
            return false;
        }
        if self.schema == RESCUE_SCHEMA_V1 {
            return true;
        }
        if !self.has_current_schema() {
            return false;
        }
        if !self.has_witness() {
            return true;
        }
        if self.uuid != identity_uuid {
            return false;
        }
        let Ok(payload) =
            serde_json::from_value::<crate::credentials::CredentialFile>(self.payload.clone())
        else {
            return false;
        };
        let target = match self.provider.as_str() {
            "anthropic" => identity_store::credentials_path_for(base_dir, id),
            "codex" => identity_store::credentials_codex_path_for(base_dir, id),
            _ => return false,
        };
        let current = match crate::credentials::load(&target) {
            Ok(current) => Some(current),
            Err(CredentialError::NotFound { .. }) => None,
            // R3 3(c): an unreadable canonical can never be re-gated by a
            // later tick without a human — Unadoptable, not "retries".
            Err(_) => return false,
        };
        match self.provider.as_str() {
            "anthropic" => {
                let Some(witness) = self.anthropic_witness.as_ref() else {
                    return false;
                };
                let Some(payload) = payload.anthropic() else {
                    return false;
                };
                let current = match current.as_ref() {
                    Some(current) => match current.anthropic() {
                        Some(current) => Some(current),
                        None => return false,
                    },
                    None => None,
                };
                // R3 3(c): the gate's own refusals (undecodable versions,
                // unreadable stored context, a newer store schema) are
                // classified Unadoptable; Install and Superseded (including a
                // no-canonical login whose context no longer matches)
                // resolve without a human.
                ai::rescue_source_gate(base_dir, id, witness, current, payload).is_ok()
            }
            "codex" => {
                // R3 3(c): a witness that cannot be decoded is unadoptable; an
                // undecodable EXPIRY is not a refusal (3d — exact match decides).
                self.codex_expected_source
                    .as_ref()
                    .and_then(|expected| {
                        serde_json::from_value::<crate::credentials::CredentialFile>(
                            expected.clone(),
                        )
                        .ok()
                    })
                    .is_some()
                    && payload.codex().is_some()
            }
            _ => false,
        }
    }
}

/// Operator-surface classification of a pending rescue record.
///
/// A record's PRESENCE is still the fail-closed pending signal (see
/// [`rescue_record_pending`]); this only says WHO can clear it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RescuePendingState {
    /// Adoption resolves it on a later refresher tick with no user action:
    /// it either installs the rescued pair or discards the record as
    /// superseded. A refresh blocked in this state is TRANSIENT.
    Adoptable,
    /// Adoption can never install this record (unreadable, unparseable,
    /// unknown schema, uuid mismatch, unparseable payload): the saved login
    /// is lost until the user signs in again for the account. An undecodable
    /// Codex expiry is not this class — it installs (or is superseded) by
    /// exact source match.
    Unadoptable,
    /// The rescue state could not be DETERMINED at all: `profiles.json` is
    /// unreadable and the identities directory could not be scanned either.
    /// Emitted as exactly ONE row so the operator sees a fail-closed
    /// diagnostic instead of silence; it is never a claim that a record
    /// exists or is absent.
    Unknown,
}

impl RescuePendingState {
    /// Stable wire/tag spelling shared by status, doctor and the desktop.
    pub fn tag(self) -> &'static str {
        match self {
            RescuePendingState::Adoptable => "adoptable",
            RescuePendingState::Unadoptable => "unadoptable",
            RescuePendingState::Unknown => "unknown",
        }
    }

    /// Fixed-vocabulary operator text. Never a path, never secret material.
    pub fn message(self) -> &'static str {
        match self {
            RescuePendingState::Adoptable => {
                "saved login restoration pending; the next refresh tick retries it automatically"
            }
            RescuePendingState::Unadoptable => {
                "a saved login could not be restored; sign in again for this account"
            }
            RescuePendingState::Unknown => "rescue status unknown: profiles unreadable",
        }
    }
}

/// One slot — or, when `profiles.json` cannot supply the mapping, one
/// identity — whose identity has a pending rescue record.
///
/// Emitted by [`pending_rescues`] for the operator surfaces (`csq status`,
/// `csq doctor`, the desktop account row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRescue {
    /// Numeric slot bound to the identity in `profiles.json::by_slot`.
    ///
    /// `None` when no mapping is available: the row was enumerated by
    /// scanning `<base>/identities/` because `profiles.json` is unreadable
    /// (the fallback), or the state itself is [`RescuePendingState::Unknown`].
    pub slot: Option<u16>,
    /// Display label from the profiles file; empty when none is recorded.
    pub label: String,
    /// Who can clear the pending record (or that this is undetermined).
    pub state: RescuePendingState,
    /// Canonical identity UUID when the row was found by scanning the
    /// identities directory. Additive: absent on slot-keyed rows, where
    /// `slot` + `label` already identify the account.
    pub identity_uuid: Option<String>,
}

impl PendingRescue {
    /// The `csq status` line body for this row: fixed vocabulary, no path,
    /// no secret material.
    pub fn status_line(&self) -> String {
        if self.state == RescuePendingState::Unknown {
            // The fixed message IS the whole row: there is no subject to
            // name, and inventing one would misattribute the diagnostic.
            return self.state.message().to_string();
        }
        match self.slot {
            Some(slot) => format!("slot {}: {}", slot, self.state.message()),
            None => {
                let identity = self.identity_uuid.as_deref().unwrap_or("unknown");
                format!("identity {identity}: {}", self.state.message())
            }
        }
    }

    /// The ONE row emitted when neither `profiles.json` nor the identities
    /// directory can be read. Never a path, never secret material.
    fn unknown() -> Self {
        PendingRescue {
            slot: None,
            label: String::new(),
            state: RescuePendingState::Unknown,
            identity_uuid: None,
        }
    }
}

/// Serializes a [`PendingRescue`] with two ADDITIVE operator fields so the
/// desktop renders the SAME fixed-vocabulary text as `csq status` and
/// `csq doctor` instead of re-deriving it:
///
/// - `message`: [`RescuePendingState::message`] for this row;
/// - `status_line`: [`PendingRescue::status_line`], the complete status row.
///
/// `slot` keeps its existing wire meaning (`3`, not wrapped); it is `null`
/// only for the new no-slot rows. `identity_uuid` is omitted when absent, so
/// a slot-keyed row's JSON is shape-identical to a pre-fallback build.
impl Serialize for PendingRescue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("slot", &self.slot)?;
        map.serialize_entry("label", &self.label)?;
        map.serialize_entry("state", &self.state)?;
        if let Some(uuid) = &self.identity_uuid {
            map.serialize_entry("identity_uuid", uuid)?;
        }
        map.serialize_entry("message", self.state.message())?;
        map.serialize_entry("status_line", &self.status_line())?;
        map.end()
    }
}

/// Returns the LEGACY `<identity_dir>/rescue-credential.json` path.
///
/// New writers use a per-writer `rescue-<nonce>.json` name; this path is
/// still enumerated (a pre-v2 install may have left one) and is the
/// fixture path for "a record exists but is unreadable".
pub fn rescue_record_path(identity_dir: &Path) -> PathBuf {
    identity_dir.join(RESCUE_RECORD_FILE)
}

/// Returns a FRESH per-writer record path.
///
/// The nonce is CSPRNG-backed (`uuid::Uuid::new_v4` is `getrandom`), so
/// two writers can never collide and each deletes only its own record.
fn new_rescue_record_path(identity_dir: &Path) -> PathBuf {
    identity_dir.join(format!(
        "{RESCUE_RECORD_PREFIX}{}{RESCUE_RECORD_SUFFIX}",
        uuid::Uuid::new_v4().simple()
    ))
}

/// Returns the identity directory that owns `uuid` under `base_dir`.
fn identity_dir_for(base_dir: &Path, uuid: IdentityId) -> PathBuf {
    identity_store::credentials_path_for(base_dir, uuid)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| base_dir.join("identities").join(uuid.to_canonical_string()))
}

fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
}

/// Writes a durable rescue record for a post-commit credential write.
///
/// MUST be called BEFORE the canonical lock wait begins: the record is the
/// durable copy of a pair the provider has already rotated, so it has to
/// exist before the writer can be delayed or killed.
///
/// `payload` is the exact canonical credential JSON that would have been
/// written (the caller computes it once and uses the same value for both
/// the record and the in-place write). `witness` is the SOURCE/RESULT
/// witness adoption re-gates against.
///
/// Returns the record's path; the caller removes ONLY this path on the
/// paths that own it (never another writer's record).
///
/// §5a: the temp file carries live OAuth material; every failure branch
/// removes it before returning.
pub fn write_rescue_record(
    identity_dir: &Path,
    provider: &str,
    uuid: &str,
    reason: &str,
    payload: &serde_json::Value,
    witness: &RescueWitness,
) -> Result<PathBuf, CredentialError> {
    write_rescue_record_as(identity_dir, provider, uuid, reason, payload, witness)
}

/// A fresh path for a login publication's PRE-LOCK record. The caller
/// creates and locks the record's writer sidecar BEFORE the record exists
/// (corr LOW-2), then writes it with [`write_prelock_rescue_record`].
pub(crate) fn new_prelock_rescue_record_path(identity_dir: &Path) -> PathBuf {
    new_rescue_record_path(identity_dir)
}

/// Writes a login publication's PRE-LOCK record ([`RESCUE_SCHEMA_PRELOCK`])
/// at `path` (from [`new_prelock_rescue_record_path`]), under §5a.
pub(crate) fn write_prelock_rescue_record(
    path: &Path,
    uuid: &str,
    reason: &str,
    payload: &serde_json::Value,
    witness: &ai::RescueLineageWitness,
) -> Result<(), CredentialError> {
    let record = RescueRecord {
        schema: RESCUE_SCHEMA_PRELOCK.to_string(),
        provider: "anthropic".to_string(),
        uuid: uuid.to_string(),
        written_at_ms: now_unix_ms(),
        reason: reason.to_string(),
        payload: payload.clone(),
        anthropic_witness: Some(witness.clone()),
        codex_expected_source: None,
    };
    write_record_to(path, &record)
}

fn write_rescue_record_as(
    identity_dir: &Path,
    provider: &str,
    uuid: &str,
    reason: &str,
    payload: &serde_json::Value,
    witness: &RescueWitness,
) -> Result<PathBuf, CredentialError> {
    let path = new_rescue_record_path(identity_dir);
    let record = RescueRecord {
        schema: RESCUE_SCHEMA.to_string(),
        provider: provider.to_string(),
        uuid: uuid.to_string(),
        written_at_ms: now_unix_ms(),
        reason: reason.to_string(),
        payload: payload.clone(),
        anthropic_witness: match witness {
            RescueWitness::Anthropic(witness) => Some(witness.clone()),
            RescueWitness::Codex { .. } => None,
        },
        codex_expected_source: match witness {
            RescueWitness::Codex { expected_source } => Some(expected_source.clone()),
            RescueWitness::Anthropic(_) => None,
        },
    };
    write_record_to(&path, &record)?;
    Ok(path)
}

/// Serializes `record` and installs it at `path` under the §5a discipline.
fn write_record_to(path: &Path, record: &RescueRecord) -> Result<(), CredentialError> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(record).map_err(|error| {
        CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("rescue_record_serialize_failed: {error}"),
        }
    })?);
    let tmp = crate::platform::fs::unique_tmp_path(path);
    if let Err(error) = crate::platform::fs::write_new_private(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: std::io::Error::other(error.to_string()),
        });
    }
    if let Err(error) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(error.to_string()),
        });
    }
    if let Err(error) = crate::platform::fs::atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(error.to_string()),
        });
    }
    Ok(())
}

/// Reads a rescue record file with the hardened reader.
///
/// `Ok(None)` means the path is definitely absent. Any `Err` means the
/// entry is IRREGULAR (not a regular file, a symlink, oversized, or an I/O
/// failure); callers treat that as PENDING-unparseable WITHOUT reading it.
#[cfg(unix)]
fn read_rescue_bytes(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rescue_record_irregular",
        ));
    }
    if metadata.len() > RESCUE_RECORD_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rescue_record_oversized",
        ));
    }
    // O_NOFOLLOW rejects a symlink planted between the stat above and this
    // open; O_NONBLOCK makes a FIFO (which the stat already rejected) or an
    // odd pipe-like object return immediately instead of blocking a read.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    // Re-check on the OPEN descriptor: the path could have been swapped
    // between the stat and the open.
    let opened = file.metadata()?;
    if !opened.file_type().is_file() || opened.len() > RESCUE_RECORD_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rescue_record_irregular",
        ));
    }
    let mut bytes = Vec::new();
    file.take(RESCUE_RECORD_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > RESCUE_RECORD_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rescue_record_oversized",
        ));
    }
    Ok(Some(bytes))
}

/// Non-Unix reader. LIMIT (R3 sec L-4): Windows has no `O_NOFOLLOW` and no
/// `O_NONBLOCK`, so a path swapped between the `symlink_metadata` above and
/// the `File::open` below is followed for THIS read, and a FIFO swapped in
/// could block the open. The exposure is bounded: every read is capped by
/// `take(RESCUE_RECORD_MAX_BYTES + 1)`, the per-identity record count is
/// capped by [`RESCUE_RECORD_MAX_PER_IDENTITY`], and callers run this from
/// the daemon's refresh/adoption paths (not a render path). A swapped target
/// can at worst yield bytes that fail `RescueRecord` deserialization, which
/// is reported as an unparseable PENDING record.
#[cfg(not(unix))]
fn read_rescue_bytes(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rescue_record_irregular",
        ));
    }
    if metadata.len() > RESCUE_RECORD_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rescue_record_oversized",
        ));
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(RESCUE_RECORD_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > RESCUE_RECORD_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rescue_record_oversized",
        ));
    }
    Ok(Some(bytes))
}

/// Parses one record path. `None` only when the path is absent; an
/// irregular or unparseable entry yields the fail-closed placeholder.
fn read_record_at(path: &Path) -> Option<RescueRecord> {
    match read_rescue_bytes(path) {
        Ok(None) => None,
        Ok(Some(bytes)) => Some(
            serde_json::from_slice::<RescueRecord>(&bytes)
                .unwrap_or_else(|_| RescueRecord::unparseable()),
        ),
        Err(_) => Some(RescueRecord::unparseable()),
    }
}

/// Every rescue record name in `identity_dir`, sorted by file name.
///
/// A single directory read; the filter accepts the legacy name and every
/// per-writer `rescue-<nonce>.json`. A MISSING directory is an empty scan
/// (the identity was removed); any other read error is returned so the
/// fallback enumerator can fail closed to the explicit UNKNOWN row instead
/// of reading an unreadable identity as "no records".
fn rescue_record_paths_checked(identity_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(identity_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == RESCUE_RECORD_FILE
            || (name.starts_with(RESCUE_RECORD_PREFIX) && name.ends_with(RESCUE_RECORD_SUFFIX))
        {
            paths.push(entry.path());
            // R3 sec L-4: bound the scan; callers fail CLOSED on this error
            // (the gate blocks, status reports UNKNOWN) rather than treating
            // an over-full directory as a credential state.
            if paths.len() > RESCUE_RECORD_MAX_PER_IDENTITY {
                return Err(std::io::Error::other("rescue_record_cap_exceeded"));
            }
        }
    }
    paths.sort();
    Ok(paths)
}

/// True when a rescue record OTHER than `own` is present in `identity_dir`.
///
/// Post-commit writers call this UNDER the canonical lock, next to their
/// in-lock canonical re-read (R3 sec L-1): a record that appeared after the
/// broker's pre-flight gate means another writer rotated from the same
/// source. Writing the canonical then would make that record's provenance
/// unverifiable, so the writer defers — its OWN record stays durable and
/// adoption decides which pair is provable.
///
/// Fail closed: an unreadable directory may hide a record, so it answers
/// `true` (the caller defers rather than overwrites).
pub(crate) fn has_other_rescue_record(identity_dir: &Path, own: Option<&Path>) -> bool {
    match rescue_record_paths_checked(identity_dir) {
        Ok(paths) => paths.iter().any(|path| Some(path.as_path()) != own),
        Err(_) => true,
    }
}

/// [`rescue_record_paths_checked`] with read errors flattened to an empty
/// scan. Render paths (`csq status`/`csq doctor`) keep their existing
/// best-effort behaviour; only the fallback enumerator needs the distinction.
fn rescue_record_paths(identity_dir: &Path) -> Vec<PathBuf> {
    rescue_record_paths_checked(identity_dir).unwrap_or_default()
}

/// Every record present in `identity_dir`, with its path; distinguishes an
/// UNREADABLE directory (the unchecked sibling was retired when every caller
/// moved to the checked form — R3 sec M-B / corr L-2).
///
/// An irregular or unparseable entry appears as the fail-closed
/// placeholder, never as an absence.
fn rescue_records_checked(identity_dir: &Path) -> std::io::Result<Vec<(PathBuf, RescueRecord)>> {
    Ok(rescue_record_paths_checked(identity_dir)?
        .into_iter()
        .filter_map(|path| read_record_at(&path).map(|record| (path, record)))
        .collect())
}

/// Classifies a non-empty record set for one identity.
///
/// Every record self-resolving (adoption installs or discards it without a
/// human) is [`RescuePendingState::Adoptable`]; any other record keeps the
/// identity [`RescuePendingState::Unadoptable`].
fn classify_records(
    records: &[(PathBuf, RescueRecord)],
    base_dir: &Path,
    id: IdentityId,
    identity_uuid: &str,
) -> RescuePendingState {
    // A tombstoned record resolves without a human (adoption quarantines
    // it); one whose tombstone cannot be read stays pending (adoption
    // defers it) — the same disposition adoption applies.
    if records
        .iter()
        .all(|(path, record)| match refusal_mark(path, record) {
            // A LIVE publication still owns its record (adoption defers it,
            // as `rescue_blocks_refresh` blocks on it): it resolves without a
            // human, so it is pending restoration — never "refused".
            _ if rescue_writer_is_live(path) => true,
            RefusalMark::Refused => true,
            RefusalMark::Unknown => false,
            RefusalMark::Absent => record.is_self_resolving(base_dir, id, identity_uuid),
        })
    {
        RescuePendingState::Adoptable
    } else {
        RescuePendingState::Unadoptable
    }
}

/// Reads a pending rescue record in `identity_dir`, if any.
///
/// `Some(_)` means a rescue is PENDING. An unreadable directory or an
/// unparseable record is PENDING too — fail-closed: it is reported, never
/// ignored (adoption quarantines an unparseable record, never installs it).
/// `None` only when no record is definitely present.
pub fn rescue_record_pending(identity_dir: &Path) -> Option<RescueRecord> {
    match rescue_records_checked(identity_dir) {
        Ok(records) => records
            .into_iter()
            .map(|(_, record)| record)
            .max_by_key(|record| record.written_at_ms),
        // An unreadable directory cannot prove absence: fail closed as pending
        // (R3 sec M-B). The placeholder is reported and never deleted.
        Err(_) => Some(RescueRecord::unparseable()),
    }
}

/// Subdirectory that holds records no reader may act on any more.
const RESCUE_QUARANTINE_DIR: &str = "quarantine";

/// Moves a record that can never install into `<identity_dir>/quarantine/`.
///
/// Quarantine, never delete (R3 corr M-1 / sec M-C): the bytes remain for
/// forensics, the name leaves the pending set, and a later re-login has
/// nothing to clear. Best effort — a failed move leaves the record in place,
/// which the gate predicate treats as non-blocking anyway.
fn quarantine_rescue_record(path: &Path) {
    let Some(dir) = path.parent() else { return };
    let quarantine = dir.join(RESCUE_QUARANTINE_DIR);
    if let Err(error) = std::fs::create_dir_all(&quarantine) {
        warn!(
            error_kind = "rescue_quarantine_failed",
            reason = format!("{}", error.kind()),
            "rescue record could not be quarantined; left in place (non-blocking)"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700));
    }
    let Some(name) = path.file_name() else { return };
    match std::fs::rename(path, quarantine.join(name)) {
        Ok(()) => {
            warn!(
                error_kind = "rescue_record_quarantined",
                "rescue record can never install against the current canonical; quarantined"
            );
            // The record left the pending set: its refusal tombstone has
            // nothing left to guard. A LIVE writer's sidecar stays with it.
            remove_refusal_artifact(&path.with_extension(RESCUE_REFUSED_EXTENSION));
            remove_refusal_artifact(&path.with_extension(RESCUE_KEPT_EXTENSION));
            if !rescue_writer_is_live(path) {
                remove_refusal_artifact(&path.with_extension(RESCUE_WRITER_EXTENSION));
            }
        }
        Err(error) => warn!(
            error_kind = "rescue_quarantine_failed",
            reason = format!("{}", error.kind()),
            "rescue record could not be quarantined; left in place (non-blocking)"
        ),
    }
}

/// Whether a record's WRITER is still alive (R3 sec M-A / corr L-7).
///
/// A pre-lock login rescue holds `<record>.json.writer` exclusively for its
/// whole life; a crashed writer releases it with the process. No sidecar at
/// all means the record was written under the canonical lock (or by an older
/// version) and is not provisional. An unreadable sidecar fails CLOSED.
fn rescue_writer_is_live(path: &Path) -> bool {
    let sidecar = path.with_extension(RESCUE_WRITER_EXTENSION);
    if std::fs::metadata(&sidecar).is_err() {
        return false;
    }
    match crate::platform::lock::try_lock_file(&sidecar) {
        // Some(guard) means WE took it: the writer released it (it is dead).
        Ok(Some(_guard)) => false,
        Ok(None) => true,
        Err(_) => true,
    }
}

/// Quarantine every rescue record in `identity_dir` except `keep`.
///
/// A successful login publication — or an AlreadyInstalled verdict — proves
/// every OLDER sibling record was superseded by it, so none may keep blocking
/// refresh (R3 corr M-1 / 3b). Records whose writer is still live are left
/// for the next tick. Best effort: a failed directory read leaves everything
/// in place (the gate predicate still classifies them).
pub(crate) fn quarantine_other_rescue_records(identity_dir: &Path, keep: Option<&Path>) {
    let Ok(paths) = rescue_record_paths_checked(identity_dir) else {
        return;
    };
    for path in paths {
        if keep.is_some_and(|keep| keep == path.as_path()) {
            continue;
        }
        if rescue_writer_is_live(&path) {
            continue;
        }
        quarantine_rescue_record(&path);
    }
}

/// Whether any rescue record still blocks refresh for `uuid`.
///
/// A record blocks only while it can still prove the CURRENT canonical was
/// consumed by a post-commit write: its witness source equals the canonical
/// as it is now, or a canonical-less identity holds a login record that
/// would install. A record the current canonical cannot satisfy proves
/// nothing about today's canonical (a re-login or another writer replaced
/// it) and must not block refresh forever (R3 corr M-1 / sec M-C); a record
/// that cannot be parsed or verified is likewise unadoptable, and a re-login
/// clears it through quarantine. Unreadable state fails CLOSED.
pub fn rescue_blocks_refresh(base_dir: &Path, uuid: IdentityId) -> bool {
    let identity_dir = identity_dir_for(base_dir, uuid);
    let records = match rescue_records_checked(&identity_dir) {
        Ok(records) => records,
        Err(_) => return true,
    };
    let canonical_uuid = uuid.to_canonical_string();
    for (path, record) in &records {
        // A record whose writer is still publishing is never adoptable, and
        // its grant may still be refused: block while the writer is live.
        if rescue_writer_is_live(path) {
            return true;
        }
        // Adoption's disposition: a refused record is quarantined (never
        // blocks); an unreadable tombstone state keeps it pending (blocks).
        match refusal_mark(path, record) {
            RefusalMark::Absent => {}
            RefusalMark::Refused => continue,
            RefusalMark::Unknown => return true,
        }
        if record.is_unparseable() || !record.has_current_schema() {
            continue;
        }
        if record.uuid != canonical_uuid {
            continue;
        }
        let target = match record.provider.as_str() {
            "anthropic" => identity_store::credentials_path_for(base_dir, uuid),
            "codex" => identity_store::credentials_codex_path_for(base_dir, uuid),
            _ => continue,
        };
        let current = match crate::credentials::load(&target) {
            Ok(current) => Some(current),
            Err(CredentialError::NotFound { .. }) => None,
            // Cannot prove the source; fail closed.
            Err(_) => return true,
        };
        let installs = match (record.provider.as_str(), current.as_ref()) {
            ("anthropic", None) => {
                let Some(witness) = record.anthropic_witness.as_ref() else {
                    continue;
                };
                if witness.kind != ai::RescueWitnessKind::Login {
                    continue;
                }
                // Adoption re-runs the writer's context gate; an unreadable
                // payload or gate leaves the record pending, so it blocks.
                let Some(payload) = serde_json::from_value::<crate::credentials::CredentialFile>(
                    record.payload.clone(),
                )
                .ok()
                .and_then(|payload| payload.anthropic().cloned()) else {
                    return true;
                };
                match ai::rescue_source_gate(base_dir, uuid, witness, None, &payload) {
                    Ok(ai::RescueGate::Install) => true,
                    Ok(_) => false,
                    Err(_) => return true,
                }
            }
            ("anthropic", Some(current)) => {
                let (Some(witness), Some(current)) =
                    (record.anthropic_witness.as_ref(), current.anthropic())
                else {
                    continue;
                };
                ai::CredentialVersion::for_credentials(current)
                    .ok()
                    .is_some_and(|version| version == witness.source_version)
            }
            ("codex", None) => false,
            ("codex", Some(current)) => record
                .codex_expected_source
                .as_ref()
                .and_then(|expected| {
                    serde_json::from_value::<crate::credentials::CredentialFile>(expected.clone())
                        .ok()
                })
                .is_some_and(|expected| super::file::codex_credentials_match(current, &expected)),
            _ => false,
        };
        if installs {
            return true;
        }
    }
    false
}

/// The pending rescue disposition for `uuid` under `base_dir`, or `None`
/// when no record is definitely present.
///
/// Read-only and lock-free: it never adopts and never mutates the record.
/// It reports [`RescuePendingState::Unadoptable`] while any listed record
/// cannot self-resolve; an unparseable record is quarantined by the next
/// adoption pass and never installed, and an unreadable identity directory
/// is [`RescuePendingState::Unknown`], never a fabricated disposition.
pub fn rescue_pending_state(base_dir: &Path, uuid: IdentityId) -> Option<RescuePendingState> {
    let identity_dir = identity_dir_for(base_dir, uuid);
    match rescue_records_checked(&identity_dir) {
        Ok(records) if records.is_empty() => None,
        Ok(records) => Some(classify_records(
            &records,
            base_dir,
            uuid,
            &uuid.to_canonical_string(),
        )),
        // UNKNOWN: an unreadable directory is never "no record" and never a
        // fabricated Adoptable/Unadoptable (R3 sec M-B / corr L-2).
        Err(_) => Some(RescuePendingState::Unknown),
    }
}

/// Every slot whose identity has a pending rescue record, sorted by slot.
///
/// The operator surfaces (`csq status`, `csq doctor`, the desktop account
/// row) read this so all three agree on the state via the SAME accessor.
/// Read-only: an adoption attempt belongs to the refresh tick, never a
/// render path.
///
/// # Fallback when `profiles.json` is unreadable
///
/// The slot→identity mapping lives ONLY in `profiles.json::by_slot`. When
/// that file cannot be read, returning an empty list would turn a real
/// pending rescue into SILENCE — exactly the fail-open this function
/// exists to prevent. It therefore scans `<base>/identities/` directly and
/// emits one row per identity directory holding a rescue record, labelled
/// by its canonical UUID ([`PendingRescue::identity_uuid`], `slot: None`).
///
/// If even that scan cannot run (the identities directory is unreadable or
/// absent, an entry cannot be inspected, or an identity directory read
/// fails), it emits exactly ONE [`RescuePendingState::Unknown`] row carrying
/// the fixed message `rescue status unknown: profiles unreadable` — never an
/// empty list. A readable scan that finds no records still returns an empty
/// list: "profiles unreadable" is not evidence that a record exists.
pub fn pending_rescues(base_dir: &Path) -> Vec<PendingRescue> {
    match crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base_dir)) {
        Ok(profiles) => {
            let mut pending: Vec<PendingRescue> = profiles
                .by_slot
                .iter()
                .filter_map(|(slot, uuid)| {
                    let slot: u16 = slot.parse().ok()?;
                    let state = rescue_pending_state(base_dir, *uuid)?;
                    Some(PendingRescue {
                        slot: Some(slot),
                        label: profiles.get_email(slot).unwrap_or_default().to_string(),
                        state,
                        identity_uuid: None,
                    })
                })
                .collect();
            pending.sort_by_key(|entry| entry.slot);
            pending
        }
        Err(_) => pending_rescues_from_identities(base_dir),
    }
}

/// The `profiles.json`-unreadable fallback enumerator.
///
/// Walks `<base>/identities/`, skips every non-directory or non-UUID entry
/// (including the `<uuid>.removed` tombstones, which are siblings), and
/// classifies each identity that holds records. Directory entries are
/// inspected with `DirEntry::file_type`, which does not follow symlinks, so
/// a planted symlink is skipped rather than traversed.
fn pending_rescues_from_identities(base_dir: &Path) -> Vec<PendingRescue> {
    let entries = match std::fs::read_dir(identity_store::identities_dir(base_dir)) {
        Ok(entries) => entries,
        // Absent or unreadable: the scan cannot establish "no records", so
        // report the undetermined state rather than an empty list.
        Err(_) => return vec![PendingRescue::unknown()],
    };
    let mut pending = Vec::new();
    for entry in entries {
        let scan = (move || -> std::io::Result<Option<PendingRescue>> {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Ok(None);
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Ok(None);
            };
            let Ok(uuid) = name.parse::<IdentityId>() else {
                return Ok(None);
            };
            let identity_dir = identity_store::identity_path(base_dir, uuid);
            let records = rescue_records_checked(&identity_dir)?;
            if records.is_empty() {
                return Ok(None);
            }
            let canonical = uuid.to_canonical_string();
            let state = classify_records(&records, base_dir, uuid, &canonical);
            Ok(Some(PendingRescue {
                slot: None,
                label: String::new(),
                state,
                identity_uuid: Some(canonical),
            }))
        })();
        match scan {
            Ok(Some(row)) => pending.push(row),
            Ok(None) => {}
            // An entry we could not inspect, or an identity directory we
            // could not read, means the scan is not exhaustive: fail closed
            // to the ONE explicit UNKNOWN row.
            Err(_) => return vec![PendingRescue::unknown()],
        }
    }
    pending.sort_by(|left, right| left.identity_uuid.cmp(&right.identity_uuid));
    pending
}

/// Rewrites a pending record's diagnostic `reason` (best effort).
///
/// Used when the lock outcome is known after the record was written with
/// the anticipated timeout reason. Operates on the CALLER'S OWN record
/// path only; a missing record is a no-op (another process may already
/// have adopted it).
pub(crate) fn mark_rescue_reason(record_path: &Path, reason: &str) -> Result<(), CredentialError> {
    let Some(mut record) = read_record_at(record_path) else {
        return Ok(());
    };
    if record.is_unparseable() {
        return Ok(());
    }
    record.reason = reason.to_string();
    write_record_to(record_path, &record)
}

/// Test-only fault seams for the rescue refusal path (modelled on
/// `anthropic_identity`'s `PROFILES_LOAD_FAULT`).
///
/// Thread-local and RAII-armed: a publication under test runs on the test's
/// own thread, and the guard disarms on drop even when an assertion fails.
/// Compiled into test builds only — production has no knob here.
#[cfg(test)]
pub(crate) mod refusal_faults {
    use std::cell::Cell;

    use super::MarkerStage;

    thread_local! {
        static UNLINK: Cell<bool> = const { Cell::new(false) };
        static MARKER_WRITE: Cell<Option<MarkerStage>> = const { Cell::new(None) };
        static MARKER_READ: Cell<bool> = const { Cell::new(false) };
        static TOMBSTONE_ONLY: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn unlink_armed() -> bool {
        UNLINK.with(Cell::get)
    }

    pub(super) fn marker_write_armed() -> Option<MarkerStage> {
        MARKER_WRITE.with(Cell::get)
    }

    pub(super) fn tombstone_only() -> bool {
        TOMBSTONE_ONLY.with(Cell::get)
    }

    pub(super) fn marker_read_armed() -> bool {
        MARKER_READ.with(Cell::get)
    }

    /// While held, every rescue-record unlink on this thread fails with
    /// `PermissionDenied`, modelling a read-only remount or a Windows sharing
    /// violation.
    #[must_use]
    pub(crate) struct UnlinkFault;

    impl UnlinkFault {
        pub(crate) fn arm() -> Self {
            UNLINK.with(|armed| armed.set(true));
            UnlinkFault
        }
    }

    impl Drop for UnlinkFault {
        fn drop(&mut self) {
            UNLINK.with(|armed| armed.set(false));
        }
    }

    /// While held, every marker write (refusal tombstone or kept marker) on
    /// this thread fails at `stage` (after the temp file exists, for
    /// `Secure` and `Replace`).
    #[must_use]
    pub(crate) struct MarkerWriteFault;

    impl MarkerWriteFault {
        pub(crate) fn arm(stage: MarkerStage) -> Self {
            MARKER_WRITE.with(|armed| armed.set(Some(stage)));
            MarkerWriteFault
        }

        /// As [`Self::arm`], but only the refusal TOMBSTONE fails; a kept
        /// marker still writes (so a mutation that keeps a record is not
        /// masked by this fault).
        pub(crate) fn arm_tombstone_only(stage: MarkerStage) -> Self {
            TOMBSTONE_ONLY.with(|only| only.set(true));
            Self::arm(stage)
        }
    }

    impl Drop for MarkerWriteFault {
        fn drop(&mut self) {
            MARKER_WRITE.with(|armed| armed.set(None));
            TOMBSTONE_ONLY.with(|only| only.set(false));
        }
    }

    /// While held, every marker presence probe on this thread fails with
    /// `PermissionDenied`, so the marker state is UNKNOWN.
    #[must_use]
    pub(crate) struct MarkerReadFault;

    impl MarkerReadFault {
        pub(crate) fn arm() -> Self {
            MARKER_READ.with(|armed| armed.set(true));
            MarkerReadFault
        }
    }

    impl Drop for MarkerReadFault {
        fn drop(&mut self) {
            MARKER_READ.with(|armed| armed.set(false));
        }
    }
}

/// Unlinks one rescue record (the single unlink site, so the test seam
/// covers every caller).
fn unlink_rescue_record(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if refusal_faults::unlink_armed() {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    std::fs::remove_file(path)
}

/// Extension of a record's refusal tombstone: `<record>.json.refused`.
///
/// None of the three marker names below matches the record filter
/// (`rescue-*.json`), so a marker is never itself read as a record.
const RESCUE_REFUSED_EXTENSION: &str = "json.refused";

/// Extension of a pre-lock record's KEPT marker: `<record>.json.kept`.
const RESCUE_KEPT_EXTENSION: &str = "json.kept";

/// Extension of a pre-lock record's writer-liveness sidecar.
const RESCUE_WRITER_EXTENSION: &str = "json.writer";

/// Fixed, non-secret marker bodies (a marker's PRESENCE is the signal).
const REFUSAL_TOMBSTONE_BYTES: &[u8] = b"{\"schema\":\"csq.rescue.refused.v1\"}\n";
const KEPT_MARKER_BYTES: &[u8] = b"{\"schema\":\"csq.rescue.kept.v1\"}\n";

/// The three steps of the §5a marker write (a test seam names one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkerStage {
    /// `write_new_private` of the temp file.
    Write,
    /// `secure_file` on the temp file.
    Secure,
    /// `atomic_replace` of the temp file onto the marker.
    Replace,
}

/// Whether a test armed a marker-write failure at `stage` (always false in
/// production).
fn marker_write_fault(stage: MarkerStage, marker: &Path) -> bool {
    #[cfg(test)]
    if refusal_faults::marker_write_armed() == Some(stage)
        && (!refusal_faults::tombstone_only()
            || marker.to_string_lossy().ends_with(".json.refused"))
    {
        return true;
    }
    let _ = (stage, marker);
    false
}

/// Whether a record may be acted on, as far as its markers say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusalMark {
    /// Not refused: the record is re-gated as usual.
    Absent,
    /// Refused: a tombstone (or anything at its name) exists, or the record
    /// is a pre-lock record with no kept marker. Never install; quarantine.
    Refused,
    /// A marker's presence cannot be read: never install, never discard —
    /// the record stays pending.
    Unknown,
}

/// Whether `marker` exists. Any entry at the name counts (fail-safe toward
/// refusal for a tombstone); an unreadable state is an error.
fn marker_present(marker: &Path) -> std::io::Result<bool> {
    #[cfg(test)]
    if refusal_faults::marker_read_armed() {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    match std::fs::symlink_metadata(marker) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// The ONE refusal classifier every reader uses (adoption,
/// [`rescue_blocks_refresh`], the pending-state classifier).
///
/// Refusal is the DEFAULT for a pre-lock record: it is adoptable only once
/// its publication wrote the kept marker (every keep path does, before the
/// writer guard drops). A pre-lock record with no kept marker — a deliberate
/// refusal whose unlink failed, or a publication that crashed — is refused.
fn refusal_mark(path: &Path, record: &RescueRecord) -> RefusalMark {
    match marker_present(&path.with_extension(RESCUE_REFUSED_EXTENSION)) {
        Ok(true) => return RefusalMark::Refused,
        Ok(false) => {}
        Err(_) => return RefusalMark::Unknown,
    }
    if !record.is_prelock() {
        return RefusalMark::Absent;
    }
    match marker_present(&path.with_extension(RESCUE_KEPT_EXTENSION)) {
        Ok(true) => RefusalMark::Absent,
        Ok(false) => RefusalMark::Refused,
        Err(_) => RefusalMark::Unknown,
    }
}

/// Writes a fixed-body marker under §5a: a `unique_tmp_path` temp file
/// created 0o600 by `write_new_private`, re-secured, then atomically
/// renamed; the temp file is removed on EVERY failure branch.
fn write_marker(marker: &Path, bytes: &[u8]) -> Result<(), CredentialError> {
    let tmp = crate::platform::fs::unique_tmp_path(marker);
    let failed = |stage: &str| CredentialError::Io {
        path: marker.to_path_buf(),
        source: std::io::Error::other(format!("rescue_marker_{stage}_failed")),
    };
    if marker_write_fault(MarkerStage::Write, marker)
        || crate::platform::fs::write_new_private(&tmp, bytes).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed("write"));
    }
    if marker_write_fault(MarkerStage::Secure, marker)
        || crate::platform::fs::secure_file(&tmp).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed("secure"));
    }
    if marker_write_fault(MarkerStage::Replace, marker)
        || crate::platform::fs::atomic_replace(&tmp, marker).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed("replace"));
    }
    Ok(())
}

/// Removes a marker or writer sidecar (best effort, logged).
fn remove_refusal_artifact(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warn!(
            error_kind = "rescue_refusal_artifact_remove_failed",
            io_kind = ?error.kind(),
            "a rescue record's marker or writer sidecar could not be removed"
        ),
    }
}

/// Removes the markers and writer sidecar of a record that has left
/// `record`'s path (no-op while the record is still there).
pub(crate) fn clear_rescue_artifacts_if_gone(record: &Path) {
    if matches!(std::fs::symlink_metadata(record),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        remove_refusal_artifact(&record.with_extension(RESCUE_REFUSED_EXTENSION));
        remove_refusal_artifact(&record.with_extension(RESCUE_KEPT_EXTENSION));
        remove_refusal_artifact(&record.with_extension(RESCUE_WRITER_EXTENSION));
    }
}

/// Removes a pre-lock record's writer sidecar. Call it AFTER the writer
/// guard drops: a sidecar is never unlinked while its lock is held.
pub(crate) fn remove_writer_sidecar(record: &Path) {
    remove_refusal_artifact(&record.with_extension(RESCUE_WRITER_EXTENSION));
}

/// Sweeps markers and sidecars whose record is gone (sec LOW-2): a crash
/// between a record's unlink and its artifact cleanup leaves them behind.
///
/// A sidecar whose writer still holds its lock is left alone. A record is
/// always created BEFORE any of its artifacts, so an artifact without a
/// record is an orphan. The caller has established that `identity_dir` is a
/// real directory. Best effort: an unreadable directory is reported by the
/// record scan that follows, which fails closed.
fn sweep_orphan_rescue_artifacts(identity_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(identity_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(record) = orphan_artifact_record(identity_dir, name) else {
            continue;
        };
        let gone = matches!(std::fs::symlink_metadata(&record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        if !gone {
            continue;
        }
        // sec L-3: a non-regular entry (a planted symlink, a directory) is
        // unlinked directly and NEVER probed: the liveness probe opens with
        // create and would follow a symlink to create its target.
        let regular = entry.file_type().is_ok_and(|kind| kind.is_file());
        if regular && name.ends_with(RESCUE_WRITER_EXTENSION) && rescue_writer_is_live(&record) {
            continue;
        }
        remove_refusal_artifact(&entry.path());
    }
}

/// The record an artifact belongs to, when `name` is one of a record's
/// artifacts: `<record>.json.{refused,kept,writer}`, or a marker's §5a temp
/// file `<record>.json.tmp.<pid>.<n>` (corr LOW-3; `unique_tmp_path` swaps
/// the marker's last extension). `None` for anything else, records included.
fn orphan_artifact_record(identity_dir: &Path, name: &str) -> Option<PathBuf> {
    if !name.starts_with(RESCUE_RECORD_PREFIX) {
        return None;
    }
    for extension in [
        RESCUE_REFUSED_EXTENSION,
        RESCUE_KEPT_EXTENSION,
        RESCUE_WRITER_EXTENSION,
    ] {
        if let Some(stem) = name
            .strip_suffix(extension)
            .and_then(|stem| stem.strip_suffix('.'))
        {
            return Some(identity_dir.join(format!("{stem}.json")));
        }
    }
    let (stem, tail) = name.split_once(".json.tmp.")?;
    let (pid, counter) = tail.split_once('.')?;
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    (numeric(pid) && numeric(counter)).then(|| identity_dir.join(format!("{stem}.json")))
}

/// Set when a refusal could not be made durable at all; `csq login` reads
/// it once to tell the operator (process-local, never persisted).
static REFUSAL_NOT_DURABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether a refusal in this process could not be made durable since the
/// last call (clears the flag). `csq login` prints a fixed operator line
/// when it is set.
pub fn take_refusal_not_durable() -> bool {
    REFUSAL_NOT_DURABLE.swap(false, std::sync::atomic::Ordering::SeqCst)
}

/// The ONE fixed operator line every login surface shows when a refusal
/// could not be made durable (no path, token or payload).
pub const REFUSAL_NOT_DURABLE_NOTICE: &str = "login refused; run csq doctor";

/// [`REFUSAL_NOT_DURABLE_NOTICE`] when [`take_refusal_not_durable`] reports
/// a non-durable refusal since the last call (clears the flag).
pub fn take_refusal_not_durable_notice() -> Option<&'static str> {
    take_refusal_not_durable().then_some(REFUSAL_NOT_DURABLE_NOTICE)
}

/// Best-effort tombstone, then unlink; on a successful unlink the tombstone
/// is removed again. Returns whether the tombstone landed and the unlink
/// failure, if any.
fn tombstone_then_unlink(path: &Path) -> (bool, Option<std::io::Error>) {
    let tombstone = path.with_extension(RESCUE_REFUSED_EXTENSION);
    let marked = write_marker(&tombstone, REFUSAL_TOMBSTONE_BYTES).is_ok();
    if !marked {
        warn!(
            error_kind = "rescue_refusal_tombstone_failed",
            "refusal tombstone for a rescue record could not be written; unlinking the record"
        );
    }
    match unlink_rescue_record(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return (marked, Some(error)),
    }
    remove_refusal_artifact(&tombstone);
    (marked, None)
}

/// Durably refuses ONE post-lock rescue record (one written under the
/// canonical lock, which has no kept-marker default).
///
/// Order: write the `<record>.json.refused` tombstone (§5a), unlink the
/// record, then remove the tombstone once the record is gone. Every reader
/// treats a tombstoned record as refused. `Ok(())` means the refusal is
/// durable: the record is gone, or its tombstone is on disk.
///
/// # Errors
///
/// When the tombstone write AND the unlink both fail, nothing on disk records
/// the refusal: returns `Err`, logs `rescue_refusal_not_durable`, and sets
/// the flag [`take_refusal_not_durable`] reports.
pub(crate) fn refuse_rescue_record(path: &Path) -> Result<(), CredentialError> {
    match tombstone_then_unlink(path) {
        (_, None) => Ok(()),
        (true, Some(error)) => {
            warn!(
                error_kind = "rescue_record_remove_failed",
                io_kind = ?error.kind(),
                "refused rescue record could not be removed; its tombstone keeps it from \
                 being installed and adoption quarantines it"
            );
            Ok(())
        }
        (false, Some(error)) => {
            warn!(
                error_kind = "rescue_refusal_not_durable",
                io_kind = ?error.kind(),
                "refused rescue record could neither be tombstoned nor removed"
            );
            REFUSAL_NOT_DURABLE.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(CredentialError::Io {
                path: path.to_path_buf(),
                source: error,
            })
        }
    }
}

/// Refuses ONE pre-lock record.
///
/// A pre-lock record is refused by DEFAULT: no kept marker was written, so
/// every reader quarantines it once its writer is gone, whatever this
/// cleanup manages. The tombstone and unlink only tidy up, so a failure of
/// both is logged and the refusal still holds. The writer sidecar is NOT
/// touched here; the caller removes it after dropping the writer guard.
pub(crate) fn refuse_prelock_record(path: &Path) {
    if let (_, Some(error)) = tombstone_then_unlink(path) {
        warn!(
            error_kind = "rescue_record_remove_failed",
            io_kind = ?error.kind(),
            "refused pre-lock rescue record could not be removed; it has no kept marker, \
             so adoption quarantines it"
        );
    }
}

/// Marks a pre-lock record KEPT: its publication could not place the grant
/// for a read/IO-class reason and leaves it to adoption.
///
/// MUST run before the writer guard drops. Accepted trade-off (ROOT): if the
/// marker cannot be written — or the process dies before it is — the record
/// stays refused by default and the fresh login grant is lost. The previous
/// canonical is untouched and the user signs in again; that is the safe
/// direction.
pub(crate) fn mark_rescue_kept(path: &Path) {
    if write_marker(
        &path.with_extension(RESCUE_KEPT_EXTENSION),
        KEPT_MARKER_BYTES,
    )
    .is_err()
    {
        warn!(
            error_kind = "rescue_kept_marker_failed",
            "kept marker for a pre-lock rescue record could not be written; the record \
             will be quarantined and the login must be repeated"
        );
    }
}

/// Removes ONE rescue record file after its pair was INSTALLED.
///
/// Best effort by design: if the removal fails the record REMAINS, and the
/// next adoption re-gates it: the canonical already holds its result
/// (AlreadyInstalled), or the gate supersedes it.
///
/// Refusals: a refusal that adoption RE-DERIVES (identity removed, a
/// superseded source, `proof.permits`, a context or freshness mismatch) may
/// use this best-effort unlink. A refusal adoption cannot re-derive MUST go
/// through `refuse_rescue_record` (or `refuse_prelock_record`).
///
/// Takes the exact path: a writer MUST only ever remove its own record.
pub fn remove_rescue_record(path: &Path) {
    match unlink_rescue_record(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warn!(
            error_kind = "rescue_record_remove_failed",
            io_kind = ?error.kind(),
            "rescue record could not be removed after the canonical write; \
             the next adoption will clean it up"
        ),
    }
}

fn remove_all_rescue_records(identity_dir: &Path) {
    for path in rescue_record_paths(identity_dir) {
        remove_rescue_record(&path);
        clear_rescue_artifacts_if_gone(&path);
    }
}

/// How long adoption may wait for the canonical lock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdoptionBudget {
    /// POST-COMMIT class: wait the full [`CREDENTIAL_COMMIT_LOCK_BUDGET`].
    /// Correct for the refresher tick, which is where a rotated pair must
    /// land.
    Commit,
    /// NON-BLOCKING: one attempt with no wait. Correct for render/CLI and
    /// async-runtime paths (`probe`, the usage poller), which must never
    /// stall on a 30 s canonical wait; a refused adoption leaves the record
    /// PENDING and those readers already report a rescue-pending state.
    NonBlocking,
}

/// Adopts every pending rescue record for `uuid`, installing the terminal
/// pair of each writer's source chain.
///
/// Returns `Ok(true)` when this call installed at least one canonical
/// credential from a record; `Ok(false)` when there was nothing to do (no
/// record, or every record was already installed / superseded).
///
/// Refusals NEVER delete an unreadable record: it is reported
/// (`error_kind = "rescue_record_unreadable"`) and stays PENDING.
/// The identity tombstone is different: a logged-out identity must not be
/// resurrected, so its records are discarded with a fixed log tag.
pub fn adopt_rescue_record(base_dir: &Path, uuid: &str) -> Result<bool, CredentialError> {
    adopt_rescue_record_with(base_dir, uuid, AdoptionBudget::Commit)
}

/// [`adopt_rescue_record`] with a bounded, non-blocking lock attempt.
pub fn adopt_rescue_record_nonblocking(
    base_dir: &Path,
    uuid: &str,
) -> Result<bool, CredentialError> {
    adopt_rescue_record_with(base_dir, uuid, AdoptionBudget::NonBlocking)
}

fn adopt_rescue_record_with(
    base_dir: &Path,
    uuid: &str,
    budget: AdoptionBudget,
) -> Result<bool, CredentialError> {
    let id: IdentityId = uuid.parse().map_err(|_| CredentialError::Corrupt {
        path: base_dir.to_path_buf(),
        reason: "rescue_uuid_invalid".to_string(),
    })?;
    let identity_dir = identity_dir_for(base_dir, id);
    // sec LOW-2: reap markers and sidecars a crash orphaned. Only inside a
    // REAL directory, so a symlinked identity path is never followed.
    if std::fs::symlink_metadata(&identity_dir).is_ok_and(|metadata| metadata.is_dir()) {
        sweep_orphan_rescue_artifacts(&identity_dir);
    }
    // A directory read that fails is NOT "no records": the gate, the pending
    // state and adoption itself must all fail CLOSED (R3 sec M-B / corr L-2).
    match rescue_record_paths_checked(&identity_dir) {
        Ok(paths) if paths.is_empty() => return Ok(false),
        Ok(_) => {}
        Err(error) => {
            warn!(
                error_kind = "rescue_dir_unreadable",
                "rescue directory could not be read; adoption refuses with the record state UNKNOWN"
            );
            return Err(CredentialError::Corrupt {
                path: identity_dir,
                reason: format!("rescue_dir_unreadable: {}", error.kind()),
            });
        }
    }
    if identity_store::is_identity_removed(base_dir, id) {
        // Deliberate logout wins: the tombstone says this identity must not
        // be resurrected, so its rescued pair is discarded, not installed.
        warn!(
            error_kind = "rescue_record_discarded_identity_removed",
            "rescue record discarded: the identity was logged out after the pair was rescued"
        );
        remove_all_rescue_records(&identity_dir);
        return Ok(false);
    }

    // sec L-1: a LOGIN record's holder check (one grant, one identity) must
    // be serialized against every publication's holder check, which runs
    // under the profiles lock. Take it NON-BLOCKING, in the publication's
    // order (profiles, then canonical), only when a login record may be
    // present; never wait for it on a tick or render path. Unreadable state
    // counts as "may be present". Without it, login records stay pending.
    let login_record_present = rescue_records_checked(&identity_dir)
        .map(|records| records.iter().any(|(_, record)| record.is_login_grant()))
        .unwrap_or(true);
    let profiles_guard = if login_record_present {
        match crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(base_dir) {
            Ok(Some(guard)) => Some(guard),
            Ok(None) | Err(_) => None,
        }
    } else {
        None
    };
    // Every canonical writer uses the Anthropic-named lock file, Codex
    // included (a Codex refresh must not publish after logout), so adoption
    // takes the same lock regardless of provider.
    let lock_path = identity_store::credentials_path_for(base_dir, id).with_extension("lock");
    let guard = match budget {
        AdoptionBudget::Commit => lock_credential_file_commit(&lock_path),
        AdoptionBudget::NonBlocking => lock::try_lock_file_bounded(&lock_path, 1, Duration::ZERO),
    };
    let guard = match guard {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            warn!(
                error_kind = "rescue_adopt_lock_deferred",
                "rescue adoption deferred: the canonical lock is held past the adoption budget"
            );
            return Err(CredentialError::CanonicalLockRefused {
                path: lock_path,
                io_kind: std::io::ErrorKind::TimedOut,
            });
        }
        Err(error) => {
            return Err(CredentialError::CanonicalLockRefused {
                path: lock_path,
                io_kind: platform_error_kind(&error),
            })
        }
    };

    // Re-read under the lock: another process may have adopted already, and
    // a `csq logout` that ran while we waited must win.
    if identity_store::is_identity_removed(base_dir, id) {
        warn!(
            error_kind = "rescue_record_discarded_identity_removed",
            "rescue record discarded: the identity was logged out while adoption waited for the lock"
        );
        remove_all_rescue_records(&identity_dir);
        return Ok(false);
    }
    // Custody (R3 corr M-2): a symlinked `identities/<uuid>` would let the
    // canonical be renamed into the symlink target. This check must run UNDER
    // the lock and BEFORE the first load(&target), so no read or write can
    // follow the link; a non-directory or a refused tighten is a refusal, and
    // the record stays pending (never discarded as a logged-out identity).
    match std::fs::symlink_metadata(&identity_dir) {
        Ok(metadata) if metadata.is_dir() => {}
        _ => {
            warn!(
                error_kind = "identity_dir_not_a_directory",
                "rescue adoption refused: the identity directory is absent or not a real directory"
            );
            return Err(CredentialError::Corrupt {
                path: identity_dir,
                reason: "identity_dir_not_a_directory".to_string(),
            });
        }
    }
    if let Err(error) = crate::accounts::identity_store::tighten_existing_identity_dir(base_dir, id)
    {
        warn!(
            error_kind = "identity_dir_secure_refused",
            "rescue adoption refused: the identity directory could not be tightened"
        );
        return Err(CredentialError::Corrupt {
            path: identity_dir,
            reason: format!("identity_dir_secure_refused: {error}"),
        });
    }
    let mut records = match rescue_records_checked(&identity_dir) {
        Ok(records) => records,
        Err(error) => {
            return Err(CredentialError::Corrupt {
                path: identity_dir,
                reason: format!("rescue_dir_unreadable: {}", error.kind()),
            })
        }
    };
    if records.is_empty() {
        return Ok(false);
    }
    if records.iter().any(|(_, record)| record.is_unparseable()) {
        // An unparseable record can never install. It is quarantined (kept for
        // forensics) so it stops blocking refresh; the rest of the set still
        // adopts on this tick (R3 corr M-1).
        warn!(
            error_kind = "rescue_record_unreadable",
            "a rescue record exists but cannot be parsed; quarantined"
        );
        for (path, record) in records.iter().filter(|(_, record)| record.is_unparseable()) {
            quarantine_rescue_record(path);
            let _ = record;
        }
        records.retain(|(_, record)| !record.is_unparseable());
        if records.is_empty() {
            return Ok(false);
        }
    }

    // v1 / witness-less records cannot be re-gated. Discard them as
    // superseded (fixed tag) — never install them witness-free.
    let mut usable = Vec::with_capacity(records.len());
    for (path, record) in records.drain(..) {
        // Provisional: the writer still holds its liveness lock. Leave the
        // record pending; the next tick after the writer exits adopts it or
        // quarantines it (R3 sec M-A).
        if rescue_writer_is_live(&path) {
            warn!(
                error_kind = "rescue_adopt_deferred_provisional",
                "rescue record belongs to a live login writer; adoption deferred"
            );
            continue;
        }
        // A record its publication refused is never installed, even when the
        // refusal's unlink failed (the tombstone outlives it).
        match refusal_mark(&path, &record) {
            RefusalMark::Absent => {}
            RefusalMark::Refused => {
                warn!(
                    error_kind = "rescue_record_refused",
                    "rescue record was refused by its publication; quarantined"
                );
                quarantine_rescue_record(&path);
                continue;
            }
            RefusalMark::Unknown => {
                warn!(
                    error_kind = "rescue_refusal_state_unreadable",
                    "rescue record's refusal state cannot be read; adoption deferred"
                );
                continue;
            }
        }
        if record.schema == RESCUE_SCHEMA_V1 || !record.has_witness() {
            warn!(
                error_kind = "rescue_record_superseded",
                reason = "no_source_witness",
                "rescue record carries no source witness and cannot be re-gated; quarantined"
            );
            quarantine_rescue_record(&path);
            continue;
        }
        if !record.has_current_schema() {
            warn!(
                error_kind = "rescue_record_unreadable",
                reason = "rescue_record_schema_unknown",
                "rescue record has an unknown schema; quarantined"
            );
            quarantine_rescue_record(&path);
            continue;
        }
        if record.is_login_grant() && profiles_guard.is_none() {
            warn!(
                error_kind = "rescue_adopt_profiles_deferred",
                "login rescue record left pending: the profiles store is busy, so its \
                 one-grant-one-identity check cannot be serialized this tick"
            );
            continue;
        }
        if record.uuid != uuid {
            // A record naming another identity can never apply here; keep the
            // bytes under quarantine rather than refusing the whole identity.
            warn!(
                error_kind = "rescue_record_quarantined",
                reason = "rescue_uuid_mismatch",
                "rescue record names a different identity; quarantined"
            );
            quarantine_rescue_record(&path);
            continue;
        }
        usable.push((path, record));
    }

    let mut adopted = false;
    let mut last_installed: Option<crate::credentials::CredentialFile> = None;
    for provider in ["anthropic", "codex"] {
        loop {
            let target = match provider {
                "anthropic" => identity_store::credentials_path_for(base_dir, id),
                _ => identity_store::credentials_codex_path_for(base_dir, id),
            };
            let current = match crate::credentials::load(&target) {
                Ok(current) => Some(current),
                Err(CredentialError::NotFound { .. }) => None,
                Err(_) => {
                    // Cannot prove the source; never install over an
                    // unreadable canonical. The record stays PENDING.
                    warn!(
                        error_kind = "rescue_current_canonical_unreadable",
                        provider,
                        "current canonical is unreadable; adoption refuses and leaves the record pending"
                    );
                    return Err(CredentialError::Corrupt {
                        path: target,
                        reason: "rescue_current_canonical_unreadable".to_string(),
                    });
                }
            };

            // Chain resolution: only a record whose SOURCE matches the
            // CURRENT canonical may install. A successor record whose source
            // is an earlier record's RESULT waits for the next iteration.
            let mut chosen: Option<usize> = None;
            let mut already_installed: Vec<usize> = Vec::new();
            for (index, (path, record)) in usable.iter().enumerate() {
                if record.provider != provider {
                    continue;
                }
                match evaluate_record(base_dir, id, path, provider, record, current.as_ref())? {
                    RecordVerdict::Install => {
                        let fresher = chosen
                            .map(|existing| usable[existing].1.written_at_ms < record.written_at_ms)
                            .unwrap_or(true);
                        if fresher {
                            chosen = Some(index);
                        }
                    }
                    RecordVerdict::AlreadyInstalled => already_installed.push(index),
                    RecordVerdict::Superseded => {}
                }
            }

            // Remove the chosen record and the already-installed leftovers
            // in ONE descending pass. Removing a lower index first would
            // shift the chosen index (both are indices into `usable`), which
            // is exactly the kind of stale-offset bug this ordering rules
            // out.
            let mut removals = already_installed;
            if let Some(index) = chosen {
                removals.push(index);
            }
            removals.sort_unstable();
            let mut chosen_entry = None;
            for index in removals.into_iter().rev() {
                let entry = usable.remove(index);
                if Some(index) == chosen {
                    chosen_entry = Some(entry);
                } else {
                    warn!(
                        error_kind = "rescue_record_superseded",
                        reason = "already_installed",
                        provider,
                        "rescue record already installed by a concurrent writer; quarantined"
                    );
                    quarantine_rescue_record(&entry.0);
                }
            }

            let Some((path, record)) = chosen_entry else {
                break;
            };
            let parsed = payload_of(&path, provider, &record)?;
            let json = serde_json::to_string_pretty(&parsed).map_err(|error| {
                CredentialError::Corrupt {
                    path: target.clone(),
                    reason: format!("serialization failed: {error}"),
                }
            })?;
            write_canonical_private(&target, json.as_bytes())?;
            remove_rescue_record(&path);
            clear_rescue_artifacts_if_gone(&path);
            adopted = true;
            last_installed = Some(parsed);
        }

        // No remaining record of this provider can be chained from the
        // current canonical: each is superseded (a newer canonical won, or
        // its predecessor was never installed).
        let mut index = usable.len();
        while index > 0 {
            index -= 1;
            if usable[index].1.provider != provider {
                continue;
            }
            let (path, _) = usable.remove(index);
            warn!(
                error_kind = "rescue_record_superseded",
                reason = "no_chain_match",
                provider,
                "rescue record is not on the current source chain; quarantined"
            );
            quarantine_rescue_record(&path);
        }
    }

    drop(guard);
    drop(profiles_guard);

    // Ruling B parity: the fingerprint append runs OUTSIDE the canonical
    // section, exactly like the canonical writer's post-lock append.
    if let Some(installed) = last_installed {
        super::token_history::record_write(base_dir, id, &installed);
    }
    Ok(adopted)
}

/// One record's disposition against the CURRENT canonical.
enum RecordVerdict {
    /// The writer's gate passes; this record's payload should be installed.
    Install,
    /// The canonical already holds this record's result.
    AlreadyInstalled,
    /// The writer's gate refuses / the source no longer matches.
    Superseded,
}

fn payload_of(
    path: &Path,
    provider: &str,
    record: &RescueRecord,
) -> Result<crate::credentials::CredentialFile, CredentialError> {
    let parsed: crate::credentials::CredentialFile = serde_json::from_value(record.payload.clone())
        .map_err(|_| CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "rescue_payload_unreadable".to_string(),
        })?;
    let shape_matches = match provider {
        "anthropic" => parsed.anthropic().is_some(),
        "codex" => parsed.codex().is_some(),
        _ => false,
    };
    if !shape_matches {
        return Err(CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "rescue_provider_mismatch".to_string(),
        });
    }
    Ok(parsed)
}

/// Re-runs the in-place writer's gate for one record (D237 round-2 H-c).
fn evaluate_record(
    base_dir: &Path,
    id: IdentityId,
    path: &Path,
    provider: &str,
    record: &RescueRecord,
    current: Option<&crate::credentials::CredentialFile>,
) -> Result<RecordVerdict, CredentialError> {
    let parsed = payload_of(path, provider, record)?;
    match provider {
        "anthropic" => {
            let witness =
                record
                    .anthropic_witness
                    .as_ref()
                    .ok_or_else(|| CredentialError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "rescue_witness_missing".to_string(),
                    })?;
            let payload = parsed.anthropic().ok_or_else(|| CredentialError::Corrupt {
                path: path.to_path_buf(),
                reason: "rescue_provider_mismatch".to_string(),
            })?;
            // Writer parity: with no canonical, the gate still runs the login
            // writer's stored-context and store-schema checks (a refresh
            // lineage, which needs its captured source, is superseded).
            let current = match current {
                Some(current) => {
                    Some(
                        current
                            .anthropic()
                            .ok_or_else(|| CredentialError::Corrupt {
                                path: path.to_path_buf(),
                                reason: "rescue_provider_mismatch".to_string(),
                            })?,
                    )
                }
                None => None,
            };
            match ai::rescue_source_gate(base_dir, id, witness, current, payload) {
                Ok(ai::RescueGate::Install) => Ok(RecordVerdict::Install),
                Ok(ai::RescueGate::AlreadyInstalled) => Ok(RecordVerdict::AlreadyInstalled),
                Ok(ai::RescueGate::Superseded) => Ok(RecordVerdict::Superseded),
                Err(_) if ai::rescue_store_schema_refused(base_dir) => {
                    warn!(
                        error_kind = "rescue_adopt_store_schema_refused",
                        provider,
                        "rescue adoption refused: the store schema is unreadable or newer than \
                         this binary; record left pending"
                    );
                    Err(CredentialError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "rescue_adopt_store_schema_refused".to_string(),
                    })
                }
                Err(_) => {
                    warn!(
                        error_kind = "rescue_source_gate_unreadable",
                        provider,
                        "adoption could not re-run the writer's custody gate; record left pending"
                    );
                    Err(CredentialError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "rescue_source_gate_unreadable".to_string(),
                    })
                }
            }
        }
        "codex" => {
            let expected_value =
                record
                    .codex_expected_source
                    .as_ref()
                    .ok_or_else(|| CredentialError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "rescue_witness_missing".to_string(),
                    })?;
            let expected: crate::credentials::CredentialFile =
                serde_json::from_value(expected_value.clone()).map_err(|_| {
                    CredentialError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "rescue_witness_unreadable".to_string(),
                    }
                })?;
            let Some(current) = current else {
                // The captured source is gone; a Codex record never installs
                // without proving it.
                return Ok(RecordVerdict::Superseded);
            };
            // Writer parity (R3 sec M-D / corr L-3): adoption is no stricter
            // than the writer — the EXACT source match decides. An undecodable
            // expiry is not a refusal; the same bytes the writer installed
            // must adopt, and anything else is superseded.
            if super::file::codex_credentials_match(current, &expected) {
                Ok(RecordVerdict::Install)
            } else if super::file::codex_credentials_match(current, &parsed) {
                Ok(RecordVerdict::AlreadyInstalled)
            } else {
                Ok(RecordVerdict::Superseded)
            }
        }
        _ => Err(CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "rescue_provider_mismatch".to_string(),
        }),
    }
}

/// Writes canonical credential bytes atomically, owner-only.
///
/// Mirrors `file.rs`'s §5a discipline: `write_new_private` creates the temp
/// file at 0o600, `secure_file` re-asserts the mode, `atomic_replace`
/// commits, and every failure branch removes the temp file.
fn write_canonical_private(path: &Path, bytes: &[u8]) -> Result<(), CredentialError> {
    let tmp = crate::platform::fs::unique_tmp_path(path);
    if let Err(error) = crate::platform::fs::write_new_private(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: std::io::Error::other(error.to_string()),
        });
    }
    if let Err(error) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(error.to_string()),
        });
    }
    if let Err(error) = crate::platform::fs::atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(error.to_string()),
        });
    }
    Ok(())
}

pub(crate) fn platform_error_kind(error: &crate::error::PlatformError) -> std::io::ErrorKind {
    match error {
        crate::error::PlatformError::Io(source) => source.kind(),
        crate::error::PlatformError::Win32 { code, .. } => {
            std::io::Error::from_raw_os_error(*code as i32).kind()
        }
        crate::error::PlatformError::LockContention { .. } => std::io::ErrorKind::WouldBlock,
        crate::error::PlatformError::LockTimeout { .. } => std::io::ErrorKind::TimedOut,
        _ => std::io::ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::anthropic_identity::{RescueKnownContext, RescueWitnessKind};
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};

    /// R3 sec L-4: an identity directory holding more records than the
    /// policy cap is not a state this protocol produces. Enumeration FAILS
    /// CLOSED — the refresh gate blocks and the status row is UNKNOWN —
    /// instead of scanning an unbounded directory on every tick.
    ///
    /// RED on the pre-fix code: every file was enumerated and the gate
    /// answered from an over-full directory.
    #[test]
    fn over_cap_records_fail_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(31);
        let identity_dir = crate::accounts::identity_store::identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        for index in 0..=RESCUE_RECORD_MAX_PER_IDENTITY {
            std::fs::write(
                identity_dir.join(format!(
                    "{RESCUE_RECORD_PREFIX}{index}{RESCUE_RECORD_SUFFIX}"
                )),
                b"{}",
            )
            .unwrap();
        }

        assert!(
            rescue_record_paths_checked(&identity_dir).is_err(),
            "the enumeration must refuse an over-cap directory"
        );
        assert!(
            rescue_blocks_refresh(dir.path(), uuid),
            "the refresh gate must fail closed"
        );
        assert_eq!(
            rescue_pending_state(dir.path(), uuid),
            Some(RescuePendingState::Unknown),
            "the status surface must report UNKNOWN, never a fabricated state"
        );
    }

    /// R3 corr M-2: a symlinked `identities/<uuid>` would let adoption follow
    /// the link and operate on a directory outside the identity tree. The
    /// custody check runs UNDER the canonical lock and BEFORE any load or
    /// write, so a non-directory (a symlink included) refuses and nothing is
    /// written through the link.
    ///
    /// Unix-only: the mechanism is a filesystem symlink. RED mutation: neuter
    /// the custody match (`_ => {}`) -> adoption no longer returns the
    /// `identity_dir_not_a_directory` refusal this test requires.
    #[cfg(unix)]
    #[test]
    fn symlinked_identity_dir_refuses_adoption_without_following_the_link() {
        let base = tempfile::TempDir::new().unwrap();
        let decoy = tempfile::TempDir::new().unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(32);
        let identity_dir = crate::accounts::identity_store::identity_path(base.path(), uuid);
        std::fs::create_dir_all(identity_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(decoy.path(), &identity_dir).unwrap();
        // A record visible through the link keeps adoption from stopping at
        // the empty-scan gate, so it reaches the custody check.
        std::fs::write(rescue_record_path(decoy.path()), b"not json").unwrap();

        let error = adopt_rescue_record(base.path(), &uuid.to_string())
            .expect_err("a symlinked identity directory must refuse adoption");
        assert!(
            format!("{error:?}").contains("identity_dir_not_a_directory"),
            "the refusal must name the custody refusal; got {error:?}"
        );
        assert!(
            !decoy.path().join("credentials.json").exists(),
            "nothing may be written through the identity symlink"
        );
    }

    /// R3 sec M-B: a directory read that fails is NOT "no records". Adoption
    /// must refuse with the record state UNKNOWN, and the refresh gate must
    /// fail closed instead of reporting a definite absence.
    ///
    /// Unix-only: the mechanism is `chmod 0o000`. RED mutation: route the
    /// read error to `Ok(false)` -> adoption reports "nothing to adopt" and
    /// `expect_err` fails.
    #[cfg(unix)]
    #[test]
    fn unreadable_identity_dir_refuses_adoption_and_reports_unknown() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            // SAFETY: geteuid takes no arguments, dereferences no pointers and
            // cannot fail; the block carries no invariant for the caller.

            // root bypasses the read bit; the mechanism cannot run as root.
            return;
        }
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(33);
        let identity_dir = crate::accounts::identity_store::identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        std::fs::set_permissions(&identity_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Observe every result, then restore the mode BEFORE asserting so a
        // failed assertion cannot leave an unremovable directory behind.
        let adoption = adopt_rescue_record(dir.path(), &uuid.to_string());
        let state = rescue_pending_state(dir.path(), uuid);
        let gate_blocks = rescue_blocks_refresh(dir.path(), uuid);
        std::fs::set_permissions(&identity_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let error = adoption.expect_err("an unreadable identity directory must refuse adoption");
        assert!(
            format!("{error:?}").contains("rescue_dir_unreadable"),
            "the refusal must name the unreadable directory; got {error:?}"
        );
        assert_eq!(
            state,
            Some(RescuePendingState::Unknown),
            "the status surface must report UNKNOWN, never a definite absence"
        );
        assert!(gate_blocks, "the refresh gate must fail closed");
    }

    /// R3 corr M-1 / sec M-C: a record whose witness source does NOT match the
    /// current canonical proves nothing about it (a re-login or another
    /// writer replaced the canonical) and must NOT block refresh forever. A
    /// record that DOES prove the current canonical was consumed must block.
    ///
    /// RED mutation: make `rescue_blocks_refresh` return `true` on presence
    /// (skip the installs evaluation) -> the first assertion fails.
    #[test]
    fn superseded_record_does_not_block_refresh() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(34);
        let canonical = identity_store::credentials_path_for(base, uuid);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();

        // Current canonical: a pair the record's source is NOT.
        let current = anthropic_cred("current-at", "current-rt", 300);
        crate::credentials::save(&canonical, &current).unwrap();
        let source = anthropic_cred("stale-src-at", "stale-src-rt", 100);
        let result = anthropic_cred("rescued-at", "rescued-rt", 200);
        let witness = RescueWitness::Anthropic(refresh_witness(&source, &result));
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&result).unwrap(),
            &witness,
        )
        .unwrap();

        assert!(
            !rescue_blocks_refresh(base, uuid),
            "a superseded record must not block refresh"
        );

        // Control: the same record DOES block while it still proves the
        // current canonical was consumed.
        crate::credentials::save(&canonical, &source).unwrap();
        assert!(
            rescue_blocks_refresh(base, uuid),
            "a provable record must block refresh"
        );
    }

    /// R3 ruling 3(b): a successful re-login proves every OLDER sibling record
    /// was superseded, so publication quarantines them (never deletes), while
    /// a sibling whose WRITER is still live is left for the next tick.
    ///
    /// RED mutation: make `quarantine_other_rescue_records` a no-op -> the
    /// second record stays in the pending set and the quarantined-path
    /// assertion fails.
    #[test]
    fn login_publication_quarantines_dead_siblings_and_keeps_a_live_writer() {
        let dir = TempDir::new().unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(35);
        let identity_dir = crate::accounts::identity_store::identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();

        let dead = rescue_record_path(&identity_dir);
        std::fs::write(&dead, b"not json").unwrap();
        let live = identity_dir.join(format!("{RESCUE_RECORD_PREFIX}live{RESCUE_RECORD_SUFFIX}"));
        std::fs::write(&live, b"not json").unwrap();
        // Hold the writer sidecar the way a live login writer would; the
        // sibling is provisional and must survive this pass. The file is
        // created explicitly (Windows locks create no file) and the lock is
        // held on another thread (Windows locks are re-entrant per thread).
        let sidecar = live.with_extension("json.writer");
        std::fs::write(&sidecar, b"").unwrap();
        let _writer_guard = crate::platform::lock::HeldOnOtherThread::hold(&sidecar);

        quarantine_other_rescue_records(&identity_dir, None);

        assert!(
            !dead.exists(),
            "a dead sibling record is moved out of the pending set"
        );
        assert!(
            identity_dir
                .join(RESCUE_QUARANTINE_DIR)
                .join(dead.file_name().unwrap())
                .is_file(),
            "the sibling is QUARANTINED, never deleted"
        );
        assert!(
            live.is_file(),
            "a sibling whose writer is still live is left for the next tick"
        );
    }

    /// R3 sec L-2, RED on the pre-fix code: the derived Debug printed the
    /// payload (tokens) for both the record and the codex witness. The
    /// assertions below fail there because the secret strings appear verbatim.
    #[test]
    fn r3_sec_l2_debug_never_prints_credential_material() {
        let record = RescueRecord {
            schema: RESCUE_SCHEMA.to_string(),
            provider: "anthropic".to_string(),
            uuid: "00000000-0000-4000-8000-000000000001".to_string(),
            written_at_ms: 1,
            reason: "post_commit_lock_timeout".to_string(),
            payload: serde_json::json!({"claudeAiOauth": {"accessToken": "sk-ant-SECRET-PAYLOAD"}}),
            anthropic_witness: None,
            codex_expected_source: Some(
                serde_json::json!({"tokens": {"accessToken": "SECRET-CANONICAL"}}),
            ),
        };
        let rendered = format!("{record:?}");
        assert!(
            !rendered.contains("SECRET-PAYLOAD"),
            "payload tokens never print: {rendered}"
        );
        assert!(
            !rendered.contains("SECRET-CANONICAL"),
            "the codex source canonical never prints: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "redaction is visible: {rendered}"
        );

        let witness = RescueWitness::Codex {
            expected_source: serde_json::json!({"tokens": {"accessToken": "SECRET-WITNESS"}}),
        };
        assert!(
            !format!("{witness:?}").contains("SECRET-WITNESS"),
            "the codex witness never prints its canonical"
        );
    }

    use tempfile::TempDir;

    fn anthropic_cred(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: std::collections::HashMap::new(),
            },
            extra: std::collections::HashMap::new(),
        })
    }

    fn context(email: &str) -> RescueKnownContext {
        RescueKnownContext {
            email: email.to_string(),
            account_uuid: uuid::Uuid::from_u128(0x1234),
            organization_uuid: uuid::Uuid::from_u128(0x5678),
        }
    }

    fn refresh_witness(
        source: &CredentialFile,
        result: &CredentialFile,
    ) -> ai::RescueLineageWitness {
        ai::RescueLineageWitness {
            kind: RescueWitnessKind::Refresh,
            source_version: ai::CredentialVersion::for_credentials(source.anthropic().unwrap())
                .unwrap(),
            result_version: ai::CredentialVersion::for_credentials(result.anthropic().unwrap())
                .unwrap(),
            context: Some(context("rescued@example.test")),
            legacy_email: None,
        }
    }

    /// Seeds the identity directory the production writer creates: owner-only
    /// dirs, a Known identity.json matching `ctx`, and the canonical pair.
    fn seed_canonical(
        base: &Path,
        uuid: IdentityId,
        creds: &CredentialFile,
        ctx: &RescueKnownContext,
    ) -> PathBuf {
        let canonical = identity_store::credentials_path_for(base, uuid);
        let dir = canonical.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
        crate::platform::fs::secure_dir(dir).unwrap();
        let identity_json = dir.join("identity.json");
        std::fs::write(
            &identity_json,
            serde_json::to_vec(&serde_json::json!({
                "email": ctx.email, "provider": "anthropic",
                "created_at": "2026-01-01T00:00:00Z", "key_id": null,
                "account_uuid": ctx.account_uuid, "organization_uuid": ctx.organization_uuid
            }))
            .unwrap(),
        )
        .unwrap();
        crate::platform::fs::secure_file(&identity_json).unwrap();
        crate::credentials::save(&canonical, creds).unwrap();
        canonical
    }

    #[test]
    fn record_round_trips_and_is_pending() {
        let dir = TempDir::new().unwrap();
        let identity_dir = dir.path().join("identities").join("u-1");
        std::fs::create_dir_all(&identity_dir).unwrap();
        assert!(rescue_record_pending(&identity_dir).is_none());
        let payload = serde_json::to_value(anthropic_cred("a", "r", 42)).unwrap();
        let witness = RescueWitness::Anthropic(ai::RescueLineageWitness {
            kind: RescueWitnessKind::Refresh,
            source_version: ai::CredentialVersion::for_credentials(
                anthropic_cred("old-a", "old-r", 1).anthropic().unwrap(),
            )
            .unwrap(),
            result_version: ai::CredentialVersion::for_credentials(
                anthropic_cred("a", "r", 42).anthropic().unwrap(),
            )
            .unwrap(),
            context: Some(context("rescued@example.test")),
            legacy_email: None,
        });
        let path = write_rescue_record(
            &identity_dir,
            "anthropic",
            "u-1",
            "post_commit_lock_timeout",
            &payload,
            &witness,
        )
        .unwrap();
        assert!(path.starts_with(&identity_dir));
        assert_eq!(path, rescue_record_paths(&identity_dir)[0]);
        assert_ne!(
            path,
            rescue_record_path(&identity_dir),
            "new writers use a per-writer name, never the shared legacy slot"
        );
        let pending = rescue_record_pending(&identity_dir).expect("pending");
        assert!(!pending.is_unparseable());
        assert_eq!(pending.schema, RESCUE_SCHEMA);
        assert_eq!(pending.provider, "anthropic");
        assert_eq!(pending.uuid, "u-1");
        assert_eq!(pending.reason, "post_commit_lock_timeout");
        assert_eq!(pending.payload, payload);
        assert!(pending.anthropic_witness.is_some());
        // §5a: the record is owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        remove_rescue_record(&path);
        assert!(rescue_record_pending(&identity_dir).is_none());
    }

    /// D237 round-2 N3: two writers each leave their OWN record. Removing one
    /// must never delete the other's.
    #[test]
    fn per_writer_records_survive_independently() {
        let dir = TempDir::new().unwrap();
        let identity_dir = dir.path().join("identities").join("u-2");
        std::fs::create_dir_all(&identity_dir).unwrap();
        let payload = serde_json::to_value(anthropic_cred("a", "r", 42)).unwrap();
        let witness = RescueWitness::Anthropic(ai::RescueLineageWitness {
            kind: RescueWitnessKind::Refresh,
            source_version: ai::CredentialVersion::for_credentials(
                anthropic_cred("old-a", "old-r", 1).anthropic().unwrap(),
            )
            .unwrap(),
            result_version: ai::CredentialVersion::for_credentials(
                anthropic_cred("a", "r", 42).anthropic().unwrap(),
            )
            .unwrap(),
            context: Some(context("rescued@example.test")),
            legacy_email: None,
        });
        let first = write_rescue_record(
            &identity_dir,
            "anthropic",
            "u-2",
            "post_commit_lock_timeout",
            &payload,
            &witness,
        )
        .unwrap();
        let second = write_rescue_record(
            &identity_dir,
            "anthropic",
            "u-2",
            "post_commit_lock_timeout",
            &payload,
            &witness,
        )
        .unwrap();
        assert_ne!(first, second, "per-writer names must not collide");
        assert_eq!(rescue_record_paths(&identity_dir).len(), 2);

        remove_rescue_record(&first);
        assert_eq!(
            rescue_record_paths(&identity_dir),
            vec![second],
            "a writer's removal must never delete another writer's record"
        );
    }

    #[test]
    fn unparseable_record_is_pending_not_absent() {
        let dir = TempDir::new().unwrap();
        let identity_dir = dir.path().join("identities").join("u-3");
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        let pending = rescue_record_pending(&identity_dir).expect("unparseable is pending");
        assert!(pending.is_unparseable());
    }

    /// Security M1: a FIFO planted at the record path must be treated as
    /// PENDING-unparseable immediately — never read, never a hang.
    #[cfg(unix)]
    #[test]
    fn fifo_record_is_pending_without_blocking() {
        let dir = TempDir::new().unwrap();
        let identity_dir = dir.path().join("identities").join("u-4");
        std::fs::create_dir_all(&identity_dir).unwrap();
        let fifo = rescue_record_path(&identity_dir);
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "test setup: mkfifo must succeed");

        let started = std::time::Instant::now();
        let pending = rescue_record_pending(&identity_dir).expect("fifo is pending");
        let elapsed = started.elapsed();
        assert!(pending.is_unparseable());
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "an irregular record must not block a reader: {elapsed:?}"
        );
        // The adoption path classifies it as unreadable and leaves it.
        assert!(
            adopt_rescue_record(dir.path(), "u-4").is_err()
                || rescue_record_pending(&identity_dir).is_some()
        );
    }

    /// Security M1: a symlink to `/dev/zero` must not be followed or read.
    #[cfg(unix)]
    #[test]
    fn dev_zero_symlink_record_is_pending_without_blocking() {
        let dir = TempDir::new().unwrap();
        let identity_dir = dir.path().join("identities").join("u-5");
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::os::unix::fs::symlink("/dev/zero", rescue_record_path(&identity_dir)).unwrap();

        let started = std::time::Instant::now();
        let pending = rescue_record_pending(&identity_dir).expect("symlink is pending");
        assert!(pending.is_unparseable());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    /// The commit budget is derived from the named policy allowance and the
    /// retry cadence is derived from the budget — never a bare literal.
    #[test]
    fn commit_budget_and_attempts_are_derived() {
        assert_eq!(
            CREDENTIAL_COMMIT_LOCK_BUDGET,
            CREDENTIAL_COMMIT_IO_ALLOWANCE * 6
        );
        assert_eq!(CREDENTIAL_COMMIT_LOCK_BUDGET_MS, 30_000);
        assert_eq!(
            CREDENTIAL_COMMIT_LOCK_ATTEMPTS,
            (CREDENTIAL_COMMIT_LOCK_BUDGET.as_millis() / CREDENTIAL_COMMIT_LOCK_DELAY.as_millis())
                as u32
        );
        assert_eq!(CREDENTIAL_COMMIT_LOCK_ATTEMPTS, 3_000);
    }

    /// Adoption installs the payload when the current canonical IS the
    /// record's captured source, and removes the record.
    #[test]
    fn adopt_installs_payload_and_removes_record() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(1);
        let ctx = context("rescued@example.test");
        let old = anthropic_cred("old-at", "old-rt", 100);
        let canonical = seed_canonical(base, uuid, &old, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let new = anthropic_cred("new-at", "new-rt", 200);
        let witness = RescueWitness::Anthropic(refresh_witness(&old, &new));
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&new).unwrap(),
            &witness,
        )
        .unwrap();
        assert!(adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "new-at"
        );
        assert!(rescue_record_pending(&identity_dir).is_none());
        // A second adoption is a no-op.
        assert!(!adopt_rescue_record(base, &uuid.to_string()).unwrap());
    }

    /// D237 round-2 H-c row (1): rotation → rescue → a NEWER re-login lands →
    /// adoption DISCARDS the record and keeps the re-login.
    #[test]
    fn adopt_discards_a_record_whose_source_no_longer_matches() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(1);
        let ctx = context("rescued@example.test");
        let old = anthropic_cred("old-at", "old-rt", 100);
        let new = anthropic_cred("rescued-at", "rescued-rt", 900);
        let relogin = anthropic_cred("relogin-at", "relogin-rt", 500);
        let canonical = seed_canonical(base, uuid, &relogin, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let witness = RescueWitness::Anthropic(refresh_witness(&old, &new));
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&new).unwrap(),
            &witness,
        )
        .unwrap();

        assert!(!adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "relogin-at",
            "a rescue must never revert a newer re-login"
        );
        assert!(rescue_record_pending(&identity_dir).is_none());
    }

    /// H-c: a planted far-future record whose source does not match the
    /// canonical is refused (discarded) — never installed.
    #[test]
    fn planted_far_future_record_with_wrong_source_is_not_installed() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);
        let ctx = context("rescued@example.test");
        let planted_source = anthropic_cred("planted-src-at", "planted-src-rt", 1);
        let canonical_pair = anthropic_cred("current-at", "current-rt", 100);
        let planted_result = anthropic_cred("planted-at", "planted-rt", u64::MAX);
        let canonical = seed_canonical(base, uuid, &canonical_pair, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let witness = RescueWitness::Anthropic(refresh_witness(&planted_source, &planted_result));
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&planted_result).unwrap(),
            &witness,
        )
        .unwrap();

        assert!(!adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "current-at"
        );
        assert!(rescue_record_pending(&identity_dir).is_none());
    }

    /// H-c: a v1 record carries no witness and is discarded as superseded.
    #[test]
    fn v1_record_is_discarded_as_superseded() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(3);
        let ctx = context("rescued@example.test");
        let canonical_pair = anthropic_cred("current-at", "current-rt", 100);
        let canonical = seed_canonical(base, uuid, &canonical_pair, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let legacy = format!(
            r#"{{"schema":"{RESCUE_SCHEMA_V1}","provider":"anthropic","uuid":"{uuid}","written_at_ms":1,"reason":"post_commit_lock_timeout","payload":{}}}"#,
            serde_json::to_string(&anthropic_cred("v1-at", "v1-rt", u64::MAX)).unwrap()
        );
        std::fs::write(rescue_record_path(&identity_dir), legacy).unwrap();

        assert!(!adopt_rescue_record(base, &uuid.to_string()).unwrap());
        assert!(rescue_record_pending(&identity_dir).is_none());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "current-at"
        );
    }

    /// R3 ruling 3(d), superseding H-c row (3): an undecodable access-token
    /// expiry (non-JWT) is NOT a refusal — the writer never decoded it
    /// either, so adoption must be no stricter than the writer. The EXACT
    /// `codex_credentials_match(current, expected_source)` decides: a
    /// matching source installs the rescued pair.
    ///
    /// RED on the pre-fix code: the undecodable-exp refusal arm returned Err
    /// without installing, so the access-token assertion below fails.
    #[test]
    fn codex_record_with_undecodable_expiry_installs_on_an_exact_source_match() {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(5);
        let codex = |access: &str, refresh: &str| {
            CredentialFile::Codex(CodexCredentialFile {
                auth_mode: Some("chatgpt".into()),
                openai_api_key: None,
                tokens: CodexTokensFile {
                    account_id: Some("acct".into()),
                    access_token: access.into(),
                    refresh_token: Some(refresh.into()),
                    id_token: None,
                    extra: Default::default(),
                },
                last_refresh: None,
                extra: Default::default(),
            })
        };
        let current = codex("not-a-jwt", "rt-current");
        let target = identity_store::credentials_codex_path_for(base, uuid);
        let identity_dir = target.parent().unwrap();
        std::fs::create_dir_all(identity_dir).unwrap();
        crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
        crate::platform::fs::secure_dir(identity_dir).unwrap();
        crate::credentials::save(&target, &current).unwrap();

        let payload = codex("also-not-a-jwt", "rt-rescued");
        let witness = RescueWitness::Codex {
            expected_source: serde_json::to_value(&current).unwrap(),
        };
        write_rescue_record(
            identity_dir,
            "codex",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&payload).unwrap(),
            &witness,
        )
        .unwrap();

        assert!(
            adopt_rescue_record(base, &uuid.to_string()).unwrap(),
            "an exact source match installs even when the expiry is undecodable"
        );
        let installed = crate::credentials::load(&target).unwrap();
        assert_eq!(
            installed.codex().unwrap().tokens.access_token,
            "also-not-a-jwt",
            "the rescued pair is installed over the matched source"
        );
        assert_eq!(
            installed.codex().unwrap().tokens.refresh_token.as_deref(),
            Some("rt-rescued")
        );
        assert!(
            rescue_record_pending(identity_dir).is_none(),
            "an installed record is removed"
        );
    }

    /// Regression: an ALREADY-INSTALLED leftover record sorted before the
    /// chosen installable record must not shift the chosen index (both are
    /// indices into the same vector). The old removal order panicked here.
    #[test]
    fn already_installed_record_before_the_chosen_one_does_not_shift_the_index() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(6);
        let ctx = context("rescued@example.test");
        let older = anthropic_cred("older-at", "older-rt", 50);
        let current = anthropic_cred("current-at", "current-rt", 100);
        let new = anthropic_cred("new-at", "new-rt", 200);
        let canonical = seed_canonical(base, uuid, &current, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();

        let write_at = |name: &str, payload: &CredentialFile, witness: &RescueWitness| {
            let record = RescueRecord {
                schema: RESCUE_SCHEMA.to_string(),
                provider: "anthropic".to_string(),
                uuid: uuid.to_string(),
                written_at_ms: 1,
                reason: "post_commit_lock_timeout".to_string(),
                payload: serde_json::to_value(payload).unwrap(),
                anthropic_witness: match witness {
                    RescueWitness::Anthropic(w) => Some(w.clone()),
                    RescueWitness::Codex { .. } => None,
                },
                codex_expected_source: None,
            };
            let path = identity_dir.join(name);
            write_record_to(&path, &record).unwrap();
            path
        };
        // `rescue-aa…` sorts FIRST and is already installed (source old,
        // result == the canonical).
        let already = write_at(
            "rescue-aa-already.json",
            &current,
            &RescueWitness::Anthropic(refresh_witness(&older, &current)),
        );
        // `rescue-zz…` sorts SECOND and is the installable record.
        let installable = write_at(
            "rescue-zz-install.json",
            &new,
            &RescueWitness::Anthropic(refresh_witness(&current, &new)),
        );

        assert!(adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "new-at"
        );
        assert!(!already.exists(), "the already-installed record is removed");
        assert!(!installable.exists(), "the adopted record is removed");
    }

    /// H-c chain: two rescues A→B form a source chain. Adoption installs the
    /// TERMINAL pair (B), not the intermediate A.
    #[test]
    fn adoption_follows_the_source_chain_to_the_terminal_pair() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(4);
        let ctx = context("rescued@example.test");
        let v0 = anthropic_cred("v0-at", "v0-rt", 100);
        let v1 = anthropic_cred("v1-at", "v1-rt", 200);
        let v2 = anthropic_cred("v2-at", "v2-rt", 300);
        let canonical = seed_canonical(base, uuid, &v0, &ctx);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let w1 = RescueWitness::Anthropic(refresh_witness(&v0, &v1));
        let w2 = RescueWitness::Anthropic(refresh_witness(&v1, &v2));
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&v1).unwrap(),
            &w1,
        )
        .unwrap();
        write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&v2).unwrap(),
            &w2,
        )
        .unwrap();

        assert!(adopt_rescue_record(base, &uuid.to_string()).unwrap());
        let installed = crate::credentials::load(&canonical).unwrap();
        assert_eq!(
            installed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "v2-at",
            "adoption must follow the source chain to the terminal pair"
        );
        assert!(rescue_record_pending(&identity_dir).is_none());
    }

    /// Operator surfaces must agree on WHO can clear a pending record: an
    /// unparseable record is UNADOPTABLE (sign-in required), while an intact
    /// v2 record is ADOPTABLE (the blocked tick is transient).
    ///
    /// RED mutation: make `is_self_resolving` ignore `is_unparseable` (always
    /// `true` for the placeholder) — the `Unadoptable` assertion fails.
    #[test]
    fn pending_state_distinguishes_unadoptable_from_transient() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(7);
        let identity_dir = identity_store::credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();

        // No record → no pending state at all.
        assert_eq!(rescue_pending_state(base, uuid), None);

        // An intact v2 record with a witness is adoptable, and its message
        // never asks the user to sign in.
        let source = anthropic_cred("src-at", "src-rt", 100);
        let result = anthropic_cred("new-at", "new-rt", 200);
        let witness = RescueWitness::Anthropic(refresh_witness(&source, &result));
        let path = write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&result).unwrap(),
            &witness,
        )
        .unwrap();
        assert_eq!(
            rescue_pending_state(base, uuid),
            Some(RescuePendingState::Adoptable)
        );
        assert!(
            !RescuePendingState::Adoptable
                .message()
                .contains("sign in again"),
            "a transient block must not demand a sign-in"
        );
        remove_rescue_record(&path);

        // An unparseable record can never be adopted: the user must sign in.
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        assert_eq!(
            rescue_pending_state(base, uuid),
            Some(RescuePendingState::Unadoptable)
        );
        assert_eq!(
            RescuePendingState::Unadoptable.message(),
            "a saved login could not be restored; sign in again for this account"
        );
        assert_eq!(
            PendingRescue {
                slot: Some(7),
                label: String::new(),
                state: RescuePendingState::Unadoptable,
                identity_uuid: None,
            }
            .status_line(),
            "slot 7: a saved login could not be restored; sign in again for this account"
        );
    }

    /// Fallback enumeration: when `profiles.json` cannot be read, the slot
    /// mapping is gone but the rescue RECORD is not. `pending_rescues` must
    /// still enumerate `<base>/identities/<uuid>/` and surface the identity,
    /// labelled by its canonical UUID (`slot: None`).
    ///
    /// RED mutation: make the `profiles::load` error arm return
    /// `Vec::new()` (the pre-fix behaviour) — this test fails with zero rows.
    #[test]
    fn unreadable_profiles_falls_back_to_identity_scan() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(9);
        let identity_dir = identity_store::identity_path(base, uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        // profiles.json exists but cannot be parsed: the slot mapping is
        // unreadable, NOT absent (an absent file loads as an empty map).
        std::fs::write(crate::accounts::profiles::profiles_path(base), b"not json").unwrap();

        let rows = pending_rescues(base);
        assert_eq!(
            rows.len(),
            1,
            "the rescued identity must be visible: {rows:?}"
        );
        let canonical = uuid.to_canonical_string();
        assert_eq!(rows[0].slot, None, "no slot mapping is available");
        assert_eq!(rows[0].identity_uuid.as_deref(), Some(canonical.as_str()));
        assert_eq!(rows[0].state, RescuePendingState::Unadoptable);
        assert_eq!(
            rows[0].status_line(),
            format!(
                "identity {uuid}: a saved login could not be restored; sign in again for this account"
            )
        );
    }

    /// Fallback scan skips non-identity entries (tombstones, stray files,
    /// non-UUID directories) rather than treating them as identities.
    #[test]
    fn identity_scan_skips_non_identity_entries() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let identities = identity_store::identities_dir(base);
        std::fs::create_dir_all(&identities).unwrap();
        // A tombstone sibling, a stray file, and a non-UUID directory.
        std::fs::write(identities.join("deadbeef.removed"), b"").unwrap();
        std::fs::write(identities.join("notes.txt"), b"").unwrap();
        std::fs::create_dir_all(identities.join("not-a-uuid")).unwrap();
        // One real identity holding a record.
        let uuid = fixture_uuid_for_slot(10);
        let identity_dir = identity_store::identity_path(base, uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        std::fs::write(crate::accounts::profiles::profiles_path(base), b"not json").unwrap();

        let rows = pending_rescues(base);
        assert_eq!(rows.len(), 1, "only the UUID identity counts: {rows:?}");
        let canonical = uuid.to_canonical_string();
        assert_eq!(rows[0].identity_uuid.as_deref(), Some(canonical.as_str()));
    }

    /// The explicit UNKNOWN row: `profiles.json` unreadable AND the
    /// identities directory cannot be scanned (here: absent). Silence would
    /// be indistinguishable from "no rescue pending", so exactly ONE fixed
    /// row is emitted instead.
    ///
    /// RED mutation: return `Vec::new()` from the identities-scan failure
    /// arm — this test fails with zero rows.
    #[test]
    fn unreadable_profiles_and_missing_identities_reports_unknown() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::write(crate::accounts::profiles::profiles_path(base), b"not json").unwrap();
        assert!(
            !identity_store::identities_dir(base).exists(),
            "test setup: the identities directory must be absent"
        );

        let rows = pending_rescues(base);
        assert_eq!(rows.len(), 1, "exactly one UNKNOWN row: {rows:?}");
        assert_eq!(rows[0].state, RescuePendingState::Unknown);
        assert_eq!(rows[0].slot, None);
        assert_eq!(rows[0].identity_uuid, None);
        assert_eq!(
            rows[0].status_line(),
            "rescue status unknown: profiles unreadable"
        );
    }

    /// A READABLE identities scan that finds no records is still an empty
    /// list — the UNKNOWN row is for an undetermined state, not a blanket
    /// warning whenever profiles is broken.
    #[test]
    fn unreadable_profiles_with_empty_identity_tree_is_silent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(identity_store::identities_dir(base)).unwrap();
        std::fs::write(crate::accounts::profiles::profiles_path(base), b"not json").unwrap();
        assert!(pending_rescues(base).is_empty());
    }

    /// A readable `profiles.json` keeps the slot-keyed shape unchanged, and
    /// the additive wire fields carry the shared message.
    #[test]
    fn readable_profiles_keeps_slot_keyed_rows() {
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(11);
        let identity_dir = identity_store::identity_path(base, uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(rescue_record_path(&identity_dir), b"not json").unwrap();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("11".to_string(), uuid);
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();

        let rows = pending_rescues(base);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].slot, Some(11));
        assert_eq!(rows[0].identity_uuid, None);
        assert_eq!(
            rows[0].status_line(),
            "slot 11: a saved login could not be restored; sign in again for this account"
        );

        let json = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(json["slot"], 11, "slot keeps its numeric wire meaning");
        assert_eq!(json["state"], "unadoptable");
        assert_eq!(
            json["message"],
            "a saved login could not be restored; sign in again for this account"
        );
        assert_eq!(
            json["status_line"],
            "slot 11: a saved login could not be restored; sign in again for this account"
        );
        assert!(
            json.get("identity_uuid").is_none(),
            "additive field omitted at None"
        );
    }

    /// The UNKNOWN row serializes with the fixed message and a null slot —
    /// the desktop payload state, no paths and no secrets.
    #[test]
    fn unknown_row_serializes_fixed_message() {
        let json = serde_json::to_value(PendingRescue::unknown()).unwrap();
        assert!(json["slot"].is_null());
        assert_eq!(json["state"], "unknown");
        assert_eq!(
            json["message"],
            "rescue status unknown: profiles unreadable"
        );
        assert_eq!(
            json["status_line"],
            "rescue status unknown: profiles unreadable"
        );
        assert!(json.get("identity_uuid").is_none());
    }
}
