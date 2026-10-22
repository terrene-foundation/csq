//! Orphan sweep for `Claude Code-credentials-<8hex>` keychain items.
//!
//! CC keys its keychain item on the SHA-256 of the canonical `CLAUDE_CONFIG_DIR`
//! path ([`super::service_name`]). Every `csq run` terminal has its own
//! `term-<pid>` dir, so every terminal that ever logged in left one item behind
//! unless the dead-handle reaper cleared it on the way out. The reaper's clear
//! only runs for a `term-*` dir it still SEES whose `.credentials.json` is an
//! Anthropic login, and a keep-and-retry outcome goes into a 200-entry queue
//! that evicts under pressure; a dir removed any other way (crash, manual `rm`,
//! a sweep that raced a kill) is never visited, and nothing ever enumerated the
//! keychain to find what the dir-driven path missed. Items accumulated until
//! the login keychain held thousands and every keychain write timed out.
//!
//! # What this sweep may touch
//!
//! Only an item whose service name is the hash of a path csq itself mints:
//! `<canonical accounts dir>/term-<pid>` ([`minted_service_name`]). That path is
//! built through [`super::canonicalize_for_keychain_sync`] and
//! [`crate::session::handle_dir::term_handle_dir_name`], the two functions the
//! writer uses, so the sweep recognises exactly the forms csq writes. An item
//! for any other config dir (a benchmark `coc-env`, a manual `CLAUDE_CONFIG_DIR`,
//! another tool) is FOREIGN: it is counted and never read, never deleted.
//!
//! # When it deletes (every condition, no other path)
//!
//! 1. the item is csq-minted ([`MintedIndex`]) AND attested by the mint ledger
//!    ([`crate::session::term_mint::MintLedger`]): one of the pids its hash
//!    maps to is a pid csq recorded minting a `term-<pid>` for. An unreadable
//!    ledger makes the whole cycle UNDETERMINED (nothing deleted);
//! 2. its handle dir is provably gone, checked again immediately before the
//!    delete ([`precheck`]);
//! 3. the pid in `term-<pid>` is held by no process, sampled before the read
//!    and again immediately before the delete ([`PidProbe`]). A removed handle
//!    dir leaves no recorded start time to compare a new holder against, so ANY
//!    holder of the pid (the original terminal still running, or an unrelated
//!    process that reused the pid) keeps the item for this cycle; and no live
//!    process runs as the terminal: none names `CLAUDE_CONFIG_DIR=<accounts>/term-<pid>`,
//!    none is in its process group, none DESCENDS from its launcher, decided per
//!    terminal from unique ids recorded in the mint ledger (`sessions::macos::holders`
//!    carries the rule, its proof and its one assumption: a process not FORKED (transitively)
//!    from the launcher carries the terminal's dir only by a manual act or by a broker that
//!    replays a stored or client environment: `export`, `tmux -e`, `launchctl setenv`,
//!    `sudo VAR=`, `at`, an sshd `AcceptEnv`, `open --env`). A launcher the
//!    ledger holds no identity for keeps its terminal; a launcher minted in an earlier boot
//!    session has no live descendant;
//! 4. the payload holds nothing but `claudeAiOauth`: no sibling key at all
//!    (`mcpOAuth`, anything unknown), by the SAME predicate the dead-handle
//!    reaper uses (`extract_sibling_object`). csq keeps no other copy of a
//!    sibling, and the reaper deliberately leaves a siblings-only item behind
//!    ([`OrphanVerdict::KeepSiblings`]);
//! 5. that `claudeAiOauth` carries no login (both tokens empty) or its refresh
//!    token is byte-equal to a canonical `identities/<uuid>/credentials.json`
//!    ([`CanonicalRefreshTokens`]), so a copy of the login survives elsewhere
//!    ([`classify_orphan`]).
//!
//! 6. the sweep holds the term mint lock ([`crate::session::term_mint`]) from
//!    that final dir check through the delete, so a terminal minted meanwhile
//!    either is seen by the check or waits for the delete. A busy or
//!    unavailable lock keeps the item for this cycle;
//! 7. immediately before the delete, the pid list is read again and every process forked
//!    since the fresh scan joins its creation lineage (`TerminalHolders::arrivals`), so a
//!    process that appeared after the scan listed the table, whose creator then exited, is
//!    still placed by its creator's unique id;
//! 8. immediately before the delete, `killpg(N, 0)` finds no process group `N`
//!    (`process_group_state`, macOS only): a group that exists (or that the kernel will not
//!    answer for) keeps the item, which also covers a process that joined the
//!    group after the scan listed the table. An unreaped zombie in the group, or a member
//!    this user may not signal, answers like a live one: the item is kept until it is gone.
//!    That is the fail-safe direction (the leak of one lingering refresh-token copy
//!    continues), not a fault.
//!
//! Everything else, an unreadable item included, is KEPT. Access-token expiry is
//! never a reason to delete: the refresh token inside an expired access token is
//! usually still the only valid copy of a login.
//!
//! # Destructive call sites
//!
//! There is exactly one: the `KeychainExecutor::delete` call in `examine`
//! (macOS only). Everything above it is a read or a pure decision.

use super::{RawContentClassification, SecretJson};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use zeroize::Zeroizing;

/// Service-name prefix of every per-dir CC item.
pub const ORPHAN_SERVICE_PREFIX: &str = "Claude Code-credentials-";

/// Highest pid whose `term-<pid>` form the sweep treats as csq-minted: XNU's
/// `PID_MAX`. The bound is a recognition limit, not a safety argument: a
/// `term-<pid>` item above it is simply not recognised, so it is FOREIGN, never
/// read and never deleted. The cost of a wrong bound is a leaked item, never a
/// deleted one.
pub const MACOS_PID_MAX: u32 = 99_999;

/// Most orphan items examined (one `find` plus at most one `delete` each) per tick.
pub const ORPHAN_BATCH_MAX: usize = 40;

/// Wall-clock ceiling for one tick's batch; checked between items, so a
/// locked or slow keychain stops the batch after the item in flight.
pub const ORPHAN_TICK_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// How old the worklist may get before the keychain is enumerated again. A
/// worklist older than this is never trusted: it is rebuilt, or (when the
/// rebuild cannot complete) dropped.
pub const ORPHAN_REENUMERATE_SECS: u64 = 600;

/// Status file under the accounts dir, written by the sweep and read by
/// `csq doctor`. Counts only; no service names, accounts or token bytes.
pub const ORPHAN_STATUS_FILENAME: &str = "keychain-orphan-sweep.json";

/// Largest status file `csq doctor` will read; the file is a few hundred bytes.
const STATUS_MAX_BYTES: u64 = 64 * 1024;

/// Largest canonical credentials file read for a refresh-token comparison.
const CANONICAL_MAX_BYTES: u64 = 1024 * 1024;

/// `true` for exactly `Claude Code-credentials-` plus 8 lowercase hex digits
/// (what [`super::service_name`] emits). The unsuffixed default item and any
/// other service never match.
pub fn is_suffixed_service(svc: &str) -> bool {
    svc.strip_prefix(ORPHAN_SERVICE_PREFIX).is_some_and(|hex| {
        hex.len() == 8 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Why a cycle could not be decided. A cycle with a reason deletes NOTHING; the
/// token is the only thing published (fixed vocabulary, never an error body).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndeterminedReason {
    /// `dump-keychain` did not return inside the standard 5s
    /// `KEYCHAIN_OP_TIMEOUT`, the keychain was locked, or `security` could not
    /// start. The bounded runner reports all three the same way (`None`).
    EnumerationUnavailable,
    /// `dump-keychain` ran but its output was not fully captured.
    EnumerationIncomplete,
    /// `dump-keychain` exited non-zero.
    EnumerationFailed,
    /// The executor cannot enumerate at all.
    EnumerationUnsupported,
    /// The accounts dir could not be canonicalised, so no csq-minted path form
    /// can be computed.
    AccountsDirUnresolved,
    /// The mint ledger exists but is not a well-formed ledger, so which pids
    /// csq minted cannot be established.
    MintLedgerUnreadable,
}

impl UndeterminedReason {
    /// The fixed reason token (what the status file and doctor show).
    pub fn token(self) -> &'static str {
        match self {
            Self::EnumerationUnavailable => "enumeration_unavailable",
            Self::EnumerationIncomplete => "enumeration_incomplete",
            Self::EnumerationFailed => "enumeration_failed",
            Self::EnumerationUnsupported => "enumeration_unsupported",
            Self::AccountsDirUnresolved => "accounts_dir_unresolved",
            Self::MintLedgerUnreadable => "mint_ledger_unreadable",
        }
    }
}

/// What one `delete-generic-password` call did.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// `security` exited 0: this call removed the item.
    Deleted,
    /// `security` exited 44 (`errSecItemNotFound`): there was no such item, so
    /// this call removed nothing (something else already had).
    NotFound,
    /// Any other outcome: the item may still exist.
    Failed,
}

/// Classify a finished `delete-generic-password` by its exit code: only 0 is a
/// delete this sweep performed; 44 is "already gone"; everything else (a signal,
/// another code) is a failure.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn delete_outcome_of(output: &std::process::Output) -> DeleteOutcome {
    match output.status.code() {
        Some(0) => DeleteOutcome::Deleted,
        Some(super::SECURITY_ITEM_NOT_FOUND) => DeleteOutcome::NotFound,
        _ => DeleteOutcome::Failed,
    }
}

/// One item's identifying attributes (never a secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainItemRef {
    pub service: String,
    pub account: String,
}

/// Result of parsing a `dump-keychain` listing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DumpScan {
    /// Distinct `(service, account)` pairs of suffixed CC items.
    pub items: Vec<KeychainItemRef>,
    /// Pairs listed more than once. A `delete` by `(service, account)` removes
    /// an arbitrary one of them, so the one classified may not be the one
    /// deleted: these are never deleted (same stance as
    /// `drain_duplicate_cc_items`).
    pub ambiguous: HashSet<(String, String)>,
    /// Suffixed items whose account attribute could not be read as plain text;
    /// they cannot be targeted exactly and are kept.
    pub unresolved: usize,
}

/// Extract the quoted text of a `"<attr>"<blob>="…"` line, or `None` for any
/// other shape (`<NULL>`, hex-encoded blob, embedded quote or backslash).
fn blob_text<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix('"')?.strip_prefix(attr)?;
    let rest = rest.strip_prefix("\"<blob>=\"")?;
    let text = rest.strip_suffix('"')?;
    (!text.contains(['"', '\\'])).then_some(text)
}

/// Parse `security dump-keychain` (no `-d`) output. A record runs from its
/// `keychain:`/`class:` header to the next one; the `acct` attribute precedes
/// `svce` inside it.
pub fn parse_dump(text: &str) -> DumpScan {
    let mut scan = DumpScan::default();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut acct: Option<String> = None;
    let mut svce: Option<String> = None;

    let mut flush = |acct: &mut Option<String>, svce: &mut Option<String>| {
        if let Some(service) = svce.take().filter(|s| is_suffixed_service(s)) {
            match acct.take() {
                Some(account) => {
                    let pair = (service.clone(), account.clone());
                    if seen.insert(pair.clone()) {
                        scan.items.push(KeychainItemRef { service, account });
                    } else {
                        scan.ambiguous.insert(pair);
                    }
                }
                None => scan.unresolved += 1,
            }
        }
        *acct = None;
    };

    for line in text.lines() {
        if line.starts_with("keychain: ") || line.starts_with("class: ") {
            flush(&mut acct, &mut svce);
        } else if let Some(t) = blob_text(line, "acct") {
            acct = Some(t.to_string());
        } else if let Some(t) = blob_text(line, "svce") {
            svce = Some(t.to_string());
        }
    }
    flush(&mut acct, &mut svce);
    scan
}

// ── csq-minted path forms ────────────────────────────────────────────────

/// The service name of the item csq writes for the terminal `term-<pid>` under
/// `canonical_base`. `canonical_base` MUST come from
/// [`super::canonicalize_for_keychain_sync`]: the writer canonicalises the
/// handle dir (which exists then), and a plain dir under a canonical base
/// canonicalises to `<canonical base>/<name>`.
pub fn minted_service_name(canonical_base: &Path, pid: u32) -> String {
    super::service_name(&canonical_base.join(crate::session::handle_dir::term_handle_dir_name(pid)))
}

/// The 32-bit hash of a suffixed service name (its 8 hex digits).
fn service_hash(service: &str) -> Option<u32> {
    if !is_suffixed_service(service) {
        return None;
    }
    u32::from_str_radix(service.strip_prefix(ORPHAN_SERVICE_PREFIX)?, 16).ok()
}

/// Reverse index from a service-name hash to the `term-<pid>` pids that produce
/// it. The hash is 32 bits and there are ~10^5 pids, so a collision between two
/// pids is likely to exist; an item matching a colliding hash is attributed to
/// ALL of its pids and every one of them must pass the delete conditions.
#[derive(Debug, Default)]
pub struct MintedIndex {
    first: HashMap<u32, u32>,
    more: HashMap<u32, Vec<u32>>,
}

impl MintedIndex {
    /// Index every pid csq could have minted a `term-<pid>` dir for under
    /// `canonical_base`.
    pub fn build(canonical_base: &Path) -> Self {
        Self::build_with(|pid| minted_service_name(canonical_base, pid))
    }

    /// [`Self::build`] with an injected name function (tests inject collisions).
    pub fn build_with(name_of: impl Fn(u32) -> String) -> Self {
        let mut index = Self::default();
        for pid in 1..=MACOS_PID_MAX {
            let Some(hash) = service_hash(&name_of(pid)) else {
                continue;
            };
            match index.first.entry(hash) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(pid);
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    index.more.entry(hash).or_default().push(pid);
                }
            }
        }
        index
    }

    /// Every pid whose `term-<pid>` form hashes to `service`, or `None` when the
    /// service is not a csq-minted form (a FOREIGN item).
    pub fn pids_for(&self, service: &str) -> Option<Vec<u32>> {
        let hash = service_hash(service)?;
        let first = *self.first.get(&hash)?;
        let mut pids = vec![first];
        if let Some(more) = self.more.get(&hash) {
            pids.extend_from_slice(more);
        }
        Some(pids)
    }
}

// ── liveness evidence: handle dir and pid ────────────────────────────────

/// What the filesystem says about `term-<pid>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirState {
    /// The accounts dir is readable and holds no `term-<pid>` entry.
    Gone,
    /// Something is at the path (dir, file or symlink).
    Exists,
    /// The answer could not be established (unreadable or missing accounts dir,
    /// any error other than "no such entry").
    Unknown,
}

/// Is `<canonical_base>/term-<pid>` provably gone? "Not found" alone is not
/// enough: a missing or replaced accounts dir also reports every child as not
/// found, so the accounts dir itself must be a readable directory.
pub fn dir_state(canonical_base: &Path, pid: u32) -> DirState {
    if !std::fs::metadata(canonical_base).is_ok_and(|m| m.is_dir()) {
        return DirState::Unknown;
    }
    let path = canonical_base.join(crate::session::handle_dir::term_handle_dir_name(pid));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => DirState::Exists,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirState::Gone,
        Err(_) => DirState::Unknown,
    }
}

/// Who holds a pid right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidOccupant {
    /// No process holds the pid (`kill(pid, 0)` reported ESRCH).
    Absent,
    /// A process holds the pid (`kill(pid, 0)` succeeded, or reported EPERM).
    Present,
    /// The pid could not be classified (an unexpected errno, or a value that
    /// must never reach `kill`).
    Unknown,
}

/// Source of [`PidOccupant`] samples. A trait so tests script reuse.
pub trait PidProbe {
    fn occupant(&self, pid: u32) -> PidOccupant;
}

/// The production probe: `kill(pid, 0)`.
#[cfg(unix)]
pub struct OsPidProbe;

#[cfg(unix)]
impl PidProbe for OsPidProbe {
    fn occupant(&self, pid: u32) -> PidOccupant {
        // `kill(0, _)` signals the caller's process group and `kill(-1, _)`
        // every process the caller may signal. Neither is a pid; refuse them
        // (and anything that wraps negative) before the syscall.
        if pid == 0 || pid > i32::MAX as u32 {
            return PidOccupant::Unknown;
        }
        // SAFETY: `kill` with signal 0 performs only the existence/permission
        // check and has no memory effects.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return PidOccupant::Present;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => PidOccupant::Absent,
            // The process exists; we may not signal it.
            Some(libc::EPERM) => PidOccupant::Present,
            _ => PidOccupant::Unknown,
        }
    }
}

/// The verdict of the liveness evidence for one candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precheck {
    /// Every pid's dir is provably gone and no process holds any of them.
    Clear,
    /// A `term-<pid>` dir exists: the item is live.
    DirExists,
    /// A process holds the pid (the original owner, or a reuse of the pid by a
    /// process that may be about to mint `term-<pid>` again).
    PidInUse,
    /// The evidence could not be established.
    Unknown,
}

/// Evidence that the terminal(s) behind a candidate are gone. EVERY pid the
/// service hash maps to must pass both the dir check and the pid sample.
pub fn precheck(canonical_base: &Path, pids: &[u32], probe: &dyn PidProbe) -> Precheck {
    if pids.is_empty() {
        return Precheck::Unknown;
    }
    for &pid in pids {
        match dir_state(canonical_base, pid) {
            DirState::Gone => {}
            DirState::Exists => return Precheck::DirExists,
            DirState::Unknown => return Precheck::Unknown,
        }
    }
    for &pid in pids {
        match probe.occupant(pid) {
            PidOccupant::Absent => {}
            PidOccupant::Present => return Precheck::PidInUse,
            PidOccupant::Unknown => return Precheck::Unknown,
        }
    }
    Precheck::Clear
}

// ── what the item holds ──────────────────────────────────────────────────

/// The refresh tokens of every canonical `identities/<uuid>/credentials.json`.
/// An item's login is only "not the last copy" if its refresh token is one of
/// these, byte for byte.
#[derive(Default)]
pub struct CanonicalRefreshTokens {
    tokens: Vec<Zeroizing<String>>,
}

impl CanonicalRefreshTokens {
    /// Build from explicit tokens (empty strings are not tokens and are dropped).
    pub fn from_tokens<I: IntoIterator<Item = String>>(tokens: I) -> Self {
        Self {
            tokens: tokens
                .into_iter()
                .filter(|t| !t.is_empty())
                .map(Zeroizing::new)
                .collect(),
        }
    }

    /// `true` when `token` is non-empty and byte-equal to a canonical one.
    pub fn contains(&self, token: &str) -> bool {
        !token.is_empty() && self.tokens.iter().any(|t| t.as_str() == token)
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Load the canonical refresh tokens: each `profiles.json::by_slot` uuid's
/// `identities/<uuid>/credentials.json` (the path
/// [`crate::accounts::identity_store::credentials_path_for`] writes). A missing,
/// unreadable, symlinked or oversized file contributes nothing, so any doubt
/// shrinks the set and can only turn a delete into a keep. The legacy
/// `config-<N>/.credentials.json` is deliberately NOT read: the delete rule
/// names the canonical identity file.
pub fn load_canonical_refresh_tokens(base_dir: &Path) -> CanonicalRefreshTokens {
    let Ok(profiles) =
        crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base_dir))
    else {
        return CanonicalRefreshTokens::default();
    };
    let mut seen = HashSet::new();
    let mut tokens = Vec::new();
    for id in profiles.by_slot.values() {
        if !seen.insert(*id) {
            continue;
        }
        let path = crate::accounts::identity_store::credentials_path_for(base_dir, *id);
        let Some(raw) = super::read_bounded_sentinel(&path, CANONICAL_MAX_BYTES) else {
            continue;
        };
        let raw = Zeroizing::new(raw);
        let Ok(value) = serde_json::from_str::<SecretJson>(&raw) else {
            continue;
        };
        if let Some(token) = value
            .get("claudeAiOauth")
            .and_then(|o| o.get("refreshToken"))
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
        {
            tokens.push(token.to_owned());
        }
    }
    CanonicalRefreshTokens::from_tokens(tokens)
}

/// What to do with one orphan item, given what its content is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanVerdict {
    /// The item is already gone.
    Gone,
    /// The item holds nothing but a `claudeAiOauth` with no login in it: the
    /// key is absent from an empty object, or both tokens are empty.
    DeleteNoLogin,
    /// Its refresh token is byte-equal to a canonical one: the login survives.
    DeleteCopyExists,
    /// A login whose refresh token (or lone access token) csq holds no
    /// canonical copy of: possibly the only copy.
    KeepSoleCopy,
    /// A top-level key other than `claudeAiOauth` is present (`mcpOAuth`, an
    /// unknown key): csq keeps no other copy of it, and the dead-handle
    /// reaper keeps such an item on purpose. Kept whatever `claudeAiOauth`
    /// holds.
    KeepSiblings,
    /// The read did not complete cleanly.
    KeepUnreadable,
    /// A `claudeAiOauth` whose tokens cannot be read as strings, or a payload
    /// that is not a JSON object.
    KeepMalformed,
}

impl OrphanVerdict {
    pub fn deletes(self) -> bool {
        matches!(self, Self::DeleteNoLogin | Self::DeleteCopyExists)
    }
}

/// Pure delete/keep decision for an orphan item's content. Everything not
/// positively proven safe is kept, and the access token's expiry is not an
/// input.
pub fn classify_orphan(
    x: &RawContentClassification,
    canonical: &CanonicalRefreshTokens,
) -> OrphanVerdict {
    match x {
        RawContentClassification::Absent => OrphanVerdict::Gone,
        RawContentClassification::Unreadable(_) => OrphanVerdict::KeepUnreadable,
        RawContentClassification::Content(raw) => classify_content(raw, canonical),
    }
}

fn classify_content(raw: &str, canonical: &CanonicalRefreshTokens) -> OrphanVerdict {
    let Ok(value) = serde_json::from_str::<SecretJson>(raw) else {
        return OrphanVerdict::KeepMalformed;
    };
    let Some(object) = value.as_object() else {
        return OrphanVerdict::KeepMalformed;
    };
    // Siblings first, and by the reaper's own predicate (not a reimplementation
    // of it): an item with any key besides `claudeAiOauth` is never deleted.
    if !super::extract_sibling_object(raw).is_empty() {
        return OrphanVerdict::KeepSiblings;
    }
    let Some(oauth) = object.get("claudeAiOauth") else {
        return OrphanVerdict::DeleteNoLogin;
    };
    let (Some(access), Some(refresh)) = (
        oauth.get("accessToken").and_then(|t| t.as_str()),
        oauth.get("refreshToken").and_then(|t| t.as_str()),
    ) else {
        return OrphanVerdict::KeepMalformed;
    };
    if refresh.is_empty() {
        // The shape CC leaves after a failed refresh (both empty) holds no
        // login. An access token with no refresh token is a live credential
        // csq cannot re-derive: keep it.
        return if access.is_empty() {
            OrphanVerdict::DeleteNoLogin
        } else {
            OrphanVerdict::KeepSoleCopy
        };
    }
    if canonical.contains(refresh) {
        OrphanVerdict::DeleteCopyExists
    } else {
        OrphanVerdict::KeepSoleCopy
    }
}

// ── status published for `csq doctor` ────────────────────────────────────

/// Counts the sweep publishes for `csq doctor`, `csq status` and the desktop
/// (all through [`read_diagnostic`]). `deleted_total` is cumulative since the
/// daemon started; the rest describe the latest successful enumeration and the
/// ticks since (`counts_stale` says when an undetermined cycle has since made
/// them out of date).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanSweepStatus {
    pub checked_at_unix_secs: u64,
    /// Suffixed `Claude Code-credentials-*` items at the last enumeration.
    pub keychain_items: usize,
    /// Of those, items that are NOT a csq-minted `term-<pid>` form. Never read,
    /// never deleted.
    pub foreign_items: usize,
    /// csq-minted items whose `term-<pid>` dir was gone at enumeration.
    pub orphan_candidates: usize,
    /// Candidates still queued for examination.
    pub pending: usize,
    /// Items this sweep's `security delete` removed (exit 0), since the daemon
    /// started. A delete that found no item (exit 44) is NOT counted here; it is
    /// `already_gone`.
    pub deleted_total: usize,
    /// Kept because the item holds a login csq has no canonical copy of.
    pub kept_sole_copy: usize,
    /// Kept because the item holds a key besides `claudeAiOauth` (`mcpOAuth`,
    /// an unknown key), of which csq keeps no other copy. Informational: the
    /// dead-handle reaper leaves such items on purpose.
    #[serde(default)]
    pub kept_siblings: usize,
    /// Kept because a live process still runs as the terminal: one holds the pid of
    /// `term-<pid>` (the launcher, or a reuse of the pid), or one carries
    /// `CLAUDE_CONFIG_DIR=<accounts>/term-<pid>` (a Claude Code that outlived its
    /// launcher), seen by the pre-lock checks.
    pub kept_pid_in_use: usize,
    /// Kept because the dir or the pid came back, a process took the terminal's
    /// config dir (the holder scan repeated under the lock), or the item's bytes changed
    /// (a login rotated by a live Claude Code), AFTER the item was first read
    /// and every other delete condition had held, caught by the final check and
    /// the re-read just before the delete. EXCLUDES a dir that reappeared before the read
    /// (`dir_reappeared`), a pid already held before the read
    /// (`kept_pid_in_use`), an item that vanished (`already_gone`) and a busy
    /// mint lock (`kept_mint_busy`).
    #[serde(alias = "kept_revived")]
    pub kept_revived_after_read: usize,
    /// A candidate whose `term-<pid>` dir came back between the enumeration and
    /// the first check (a terminal was started): it is live, not an orphan.
    #[serde(default)]
    pub dir_reappeared: usize,
    /// A candidate that was no longer in the keychain when read, or whose
    /// delete found no item (exit 44): nothing left to clean.
    #[serde(default)]
    pub already_gone: usize,
    /// Kept because a terminal was being minted (or another sweep ran) and held
    /// the term mint lock when the sweep tried to take it for its final check.
    #[serde(default)]
    pub kept_mint_busy: usize,
    /// csq-form items (hash of a `term-<pid>` path, dir gone) whose pid csq has
    /// no record of minting: not attested by the mint ledger, so never read or
    /// deleted. Includes every item minted before the ledger existed.
    #[serde(default)]
    pub unattested_items: usize,
    /// Kept because the sweep could not rule out a live process still running as the
    /// terminal: the process table could not be read whole (a same-uid process whose
    /// environment, or any live process whose unique id, could not be read, an unreadable table, a scan that ran
    /// out of time), a process forked after the terminal's launcher has a creator that
    /// died, or csq recorded nothing about the launcher. Fail-closed and persistent while
    /// the condition lasts, so it is its own count: `process_table_unknown` says which and
    /// the diagnostic says what to do, which `kept_other` could not.
    #[serde(default)]
    pub kept_process_table_unknown: usize,
    /// Kept for an unreadable/malformed read, a duplicate pair, an unreadable
    /// account attribute, unestablished evidence, or a failed delete.
    pub kept_other: usize,
    /// Why the last cycle could not be decided (it deleted nothing), if so.
    pub undetermined: Option<UndeterminedReason>,
    /// `true` while `undetermined` is set: every count above (except
    /// `deleted_total`) is from the last SUCCESSFUL enumeration, not the latest
    /// cycle.
    #[serde(default)]
    pub counts_stale: bool,
    /// When the current run of undetermined cycles began (unix secs); `None`
    /// when the last cycle was determined.
    #[serde(default)]
    pub undetermined_since_unix_secs: Option<u64>,
    /// Why the sweep's process scan last could not rule a gone terminal out (it kept
    /// the items and will retry), or `None` while scans read whole. Cleared by a whole
    /// scan, by an enumeration that finds nothing to clean, and by a cycle that drained
    /// without needing a scan, so it never outlives the condition it reports.
    #[serde(default)]
    pub process_table_unknown: Option<ProcessTableUnknown>,
    /// When the current run of unknown scans began (unix secs); `None` while
    /// `process_table_unknown` is `None`. Ages into "needs action" like
    /// `undetermined_since_unix_secs` does.
    #[serde(default)]
    pub process_table_unknown_since_unix_secs: Option<u64>,
}

/// Why the process scan could not rule a gone terminal out. Fixed vocabulary: it names a
/// cause and nothing about any process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTableUnknown {
    /// The list of running processes itself could not be read (or lacked this process, or
    /// could not be read again just before a delete).
    TableUnreadable,
    /// Some same-uid process's environment or unique id could not be read, or the table
    /// contradicted itself.
    ProcessUnreadable,
    /// The scan ran out of its time budget before every process was read.
    ScanIncomplete,
    /// A process forked after the terminal's launcher has a creator that died, so it may
    /// descend from the launcher (a daemon that outlived its parent): the sweep cannot tell.
    /// Per terminal; other terminals are decided.
    #[serde(alias = "env_withheld")]
    LineageBroken,
    /// csq recorded nothing usable about the terminal's launcher (an item minted by an older
    /// build, or one whose launcher id could not be read), so no process can be ruled out.
    LauncherUnrecorded,
    /// The kernel could not say whether the terminal's process group still exists.
    ProcessGroupUnknown,
}

impl ProcessTableUnknown {
    /// The token the operator signal carries.
    pub fn token(self) -> &'static str {
        match self {
            Self::TableUnreadable => "table_unreadable",
            Self::ProcessUnreadable => "process_unreadable",
            Self::ScanIncomplete => "scan_incomplete",
            Self::LineageBroken => "lineage_broken",
            Self::LauncherUnrecorded => "launcher_unrecorded",
            Self::ProcessGroupUnknown => "process_group_unknown",
        }
    }

    /// The one wording of the cause, shared by every surface (fixed strings).
    pub fn describe(self) -> &'static str {
        match self {
            Self::TableUnreadable => "the list of running processes could not be read",
            Self::ProcessUnreadable => "some process's environment or identity could not be read",
            Self::ScanIncomplete => "the scan ran out of time",
            Self::LineageBroken => {
                "a process started after the terminal may have been started by it, and its \
                 parent is gone"
            }
            Self::LauncherUnrecorded => {
                "csq recorded nothing about the process that started the terminal"
            }
            Self::ProcessGroupUnknown => {
                "the system could not say whether the terminal's process group still exists"
            }
        }
    }

    /// What the operator can do about it, in one sentence (the aged "needs action" signal
    /// appends it).
    pub fn remedy(self) -> &'static str {
        match self {
            Self::TableUnreadable | Self::ProcessUnreadable | Self::ScanIncomplete => {
                "if it persists, restart the csq daemon (csq daemon stop, then csq daemon start); a \
                 Mac that is short of memory or busy can leave a scan unfinished"
            }
            Self::LineageBroken => {
                "restart the Mac, or quit the long-running background processes started from \
                 terminals that are now closed (each one keeps this cleanup waiting)"
            }
            Self::LauncherUnrecorded => {
                "restart the Mac once: terminals started before this version of csq cannot be \
                 identified, and their items are cleaned up after a restart"
            }
            Self::ProcessGroupUnknown => {
                "if it persists, restart the csq daemon (csq daemon stop, then csq daemon start)"
            }
        }
    }
}

/// How long cycles must stay undetermined before the diagnostic says the
/// operator has to act (30 minutes: three re-enumeration intervals).
pub const ORPHAN_NEEDS_ACTION_SECS: u64 = 3 * ORPHAN_REENUMERATE_SECS;

/// Why the status file could not be read. Fixed vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusReadError {
    /// The path exists but cannot be read as a regular file.
    Unreadable,
    /// The file is larger than any status this sweep writes.
    Oversized,
    /// The file is not a status document.
    Corrupt,
}

impl StatusReadError {
    pub fn token(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Oversized => "oversized",
            Self::Corrupt => "corrupt",
        }
    }
}

/// Read the status the daemon last published. `Ok(None)` only when no status
/// file exists (never published); a file that exists and cannot be read is an
/// explicit error, never "never published".
pub fn read_status(base_dir: &Path) -> Result<Option<OrphanSweepStatus>, StatusReadError> {
    let path = base_dir.join(ORPHAN_STATUS_FILENAME);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StatusReadError::Unreadable),
    };
    if !meta.is_file() {
        return Err(StatusReadError::Unreadable);
    }
    if meta.len() > STATUS_MAX_BYTES {
        return Err(StatusReadError::Oversized);
    }
    let raw = std::fs::read_to_string(&path).map_err(|_| StatusReadError::Unreadable)?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|_| StatusReadError::Corrupt)
}

/// Publish `status`; a failure is logged with a fixed tag, never fatal.
pub fn write_status(base_dir: &Path, status: &OrphanSweepStatus) {
    let target = base_dir.join(ORPHAN_STATUS_FILENAME);
    let tmp = crate::platform::fs::unique_tmp_path(&target);
    let result = serde_json::to_vec(status)
        .map_err(|e| e.to_string())
        .and_then(|bytes| std::fs::write(&tmp, bytes).map_err(|e| e.to_string()))
        .and_then(|()| {
            crate::platform::fs::atomic_replace(&tmp, &target).map_err(|e| e.to_string())
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "keychain_orphan_status_write_failed",
            "orphan sweep: could not publish its status file (non-fatal)"
        );
    }
}

// ── the one diagnostic accessor ──────────────────────────────────────────

/// How serious a published status is. `Info` is for outcomes that need nothing
/// from the operator (items kept on purpose); `NeedsAction` is a sweep that has
/// been unable to run for [`ORPHAN_NEEDS_ACTION_SECS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Ok,
    Info,
    Warn,
    NeedsAction,
}

/// What `csq status`, `csq doctor` and the desktop show about the orphan sweep.
/// ALL THREE obtain it from [`read_diagnostic`] and render [`Self::summary`] and
/// [`Self::level`]; none reads the status file or words the counts itself, so
/// the surfaces cannot disagree (`diagnostic-surface-parity.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanDiagnostic {
    /// The published counts; `None` when never published or unreadable.
    pub status: Option<OrphanSweepStatus>,
    /// Why a status file that EXISTS could not be read (never "never published").
    pub error: Option<&'static str>,
    /// Seconds between the sweep's last report (`checked_at_unix_secs`) and the
    /// moment this diagnostic was read; `None` when no status was read. Computed
    /// ONCE, by [`read_diagnostic_at`], so every surface ages the same report
    /// identically; [`Self::level`] and [`Self::summary`] never read a clock.
    pub age_secs: Option<u64>,
}

/// How old the sweep's last report may be before the diagnostic stops showing
/// it as current: three re-enumeration intervals (30 minutes), the same span
/// that turns a run of undetermined cycles into "needs action". A daemon that
/// stopped publishing would otherwise leave its last level on screen forever.
pub const ORPHAN_STALE_SECS: u64 = 3 * ORPHAN_REENUMERATE_SECS;

/// Read the sweep's published state for display. THE accessor: `csq status`,
/// `csq doctor` and the desktop all call this one, so they age the report
/// identically. The clock is read here and nowhere else; see
/// [`read_diagnostic_at`] for the injected-clock form.
pub fn read_diagnostic(base_dir: &Path) -> OrphanDiagnostic {
    // A clock that cannot be read ages the report to "stale", the safe display.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs());
    read_diagnostic_at(base_dir, now_secs)
}

/// [`read_diagnostic`] with `now_secs` (unix seconds) passed in, because
/// csq-core has no injectable clock.
pub fn read_diagnostic_at(base_dir: &Path, now_secs: u64) -> OrphanDiagnostic {
    match read_status(base_dir) {
        Ok(status) => OrphanDiagnostic {
            age_secs: status
                .as_ref()
                .map(|s| now_secs.saturating_sub(s.checked_at_unix_secs)),
            status,
            error: None,
        },
        Err(e) => OrphanDiagnostic {
            status: None,
            error: Some(e.token()),
            age_secs: None,
        },
    }
}

/// The wire shape of a diagnostic: what the desktop sends and `csq status
/// --json` embeds. Counts and fixed tokens only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrphanDiagnosticView {
    pub level: DiagnosticLevel,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<OrphanSweepStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
}

impl OrphanDiagnostic {
    /// `true` when the last report is older than [`ORPHAN_STALE_SECS`]: the
    /// sweep has stopped publishing, so its counts and level are unknown.
    fn is_stale(&self) -> bool {
        self.age_secs.is_some_and(|age| age > ORPHAN_STALE_SECS)
    }

    /// `None` only when nothing was ever published and nothing is wrong. A
    /// report past [`ORPHAN_STALE_SECS`] never reads better than `Warn`.
    pub fn level(&self) -> Option<DiagnosticLevel> {
        let level = self.published_level()?;
        Some(
            if self.is_stale() && level != DiagnosticLevel::NeedsAction {
                DiagnosticLevel::Warn
            } else {
                level
            },
        )
    }

    fn published_level(&self) -> Option<DiagnosticLevel> {
        if self.error.is_some() {
            return Some(DiagnosticLevel::Warn);
        }
        let s = self.status.as_ref()?;
        if let Some(since) = s
            .undetermined_since_unix_secs
            .filter(|_| s.undetermined.is_some())
        {
            if s.checked_at_unix_secs.saturating_sub(since) >= ORPHAN_NEEDS_ACTION_SECS {
                return Some(DiagnosticLevel::NeedsAction);
            }
            return Some(DiagnosticLevel::Warn);
        }
        if s.undetermined.is_some() {
            return Some(DiagnosticLevel::Warn);
        }
        if s.process_table_unknown.is_some() {
            // A sweep that cannot tell whether a live process still runs as a gone terminal
            // pauses cleanup, and a pause that persists is the operator's to look at.
            return Some(match s.process_table_unknown_since_unix_secs {
                Some(since)
                    if s.checked_at_unix_secs.saturating_sub(since) >= ORPHAN_NEEDS_ACTION_SECS =>
                {
                    DiagnosticLevel::NeedsAction
                }
                _ => DiagnosticLevel::Warn,
            });
        }
        if s.orphan_candidates == 0 {
            return Some(if s.unattested_items > 0 {
                DiagnosticLevel::Info
            } else {
                DiagnosticLevel::Ok
            });
        }
        let actionable = s.pending
            + s.kept_sole_copy
            + s.kept_pid_in_use
            + s.kept_revived_after_read
            + s.kept_mint_busy
            + s.kept_process_table_unknown
            + s.kept_other;
        Some(if actionable > 0 {
            DiagnosticLevel::Warn
        } else {
            DiagnosticLevel::Info
        })
    }

    /// The one wording of the counts (no glyph; each surface adds its own).
    pub fn summary(&self) -> Option<String> {
        let text = self.published_summary()?;
        Some(match self.age_secs.filter(|_| self.is_stale()) {
            Some(age) => format!(
                "stale: the sweep last reported {} min ago, so these counts may be out of date \
                 (is the daemon running?). Last report: {text}",
                age / 60
            ),
            None => text,
        })
    }

    fn published_summary(&self) -> Option<String> {
        if let Some(error) = self.error {
            return Some(format!(
                "the sweep's status file ({ORPHAN_STATUS_FILENAME}) is {error}; its counts are unknown"
            ));
        }
        let s = self.status.as_ref()?;
        let counts = |s: &OrphanSweepStatus| {
            format!(
                "{} of {} per-terminal items belong to gone csq terminals ({} still queued, \
                 {} deleted since the daemon started, {} kept as possibly the only copy of a login, \
                 {} kept because a live process still runs as the terminal, \
                 {} kept because the terminal reappeared \
                 or the item changed after the read, {} kept because a terminal was being created, \
                 {} kept because the sweep could not rule out a live process still running as the \
                 terminal ({}), so cleanup of these items is paused until it can, \
                 {} kept for other reasons, {} already gone, {} reappeared before the read; \
                 info: {} kept because they hold non-login data such as MCP logins, \
                 {} not recorded as minted by csq and left alone)",
                s.orphan_candidates,
                s.keychain_items,
                s.pending,
                s.deleted_total,
                s.kept_sole_copy,
                s.kept_pid_in_use,
                s.kept_revived_after_read,
                s.kept_mint_busy,
                s.kept_process_table_unknown,
                s.process_table_unknown
                    .map_or("the cause was not recorded", ProcessTableUnknown::describe),
                s.kept_other,
                s.already_gone,
                s.dir_reappeared,
                s.kept_siblings,
                s.unattested_items
            )
        };
        if let Some(reason) = s.undetermined {
            let head = if self.level() == Some(DiagnosticLevel::NeedsAction) {
                let mins = s
                    .undetermined_since_unix_secs
                    .map_or(0, |t| s.checked_at_unix_secs.saturating_sub(t) / 60);
                format!(
                    "needs action: the keychain could not be enumerated ({}) for {mins} min, \
                     so orphaned items are NOT being cleaned up (nothing was deleted); \
                     check that the login keychain is unlocked and not oversized",
                    reason.token()
                )
            } else {
                format!(
                    "last cycle undetermined ({}); nothing was deleted, the sweep retries",
                    reason.token()
                )
            };
            return Some(if s.keychain_items == 0 && s.orphan_candidates == 0 {
                head
            } else {
                format!(
                    "{head}. Counts below are STALE (from the last successful enumeration): {}",
                    counts(s)
                )
            });
        }
        if let Some(cause) = s.process_table_unknown {
            return Some(if self.level() == Some(DiagnosticLevel::NeedsAction) {
                let mins = s
                    .process_table_unknown_since_unix_secs
                    .map_or(0, |t| s.checked_at_unix_secs.saturating_sub(t) / 60);
                format!(
                    "needs action: the sweep has not been able to tell whether a live process \
                     still runs as a gone terminal for {mins} min ({}), so orphaned items are \
                     NOT being cleaned up (nothing was deleted on their account). To resume: \
                     {}. Counts: {}",
                    cause.describe(),
                    cause.remedy(),
                    counts(s)
                )
            } else {
                format!(
                    "cleanup is paused: the sweep cannot tell whether a live process still runs \
                     as a gone terminal ({}). Counts: {}",
                    cause.describe(),
                    counts(s)
                )
            });
        }
        if s.orphan_candidates == 0 {
            return Some(format!(
                "none ({} per-terminal items, {} not minted by csq and never touched, \
                 {} csq-form items not recorded as minted by csq and left alone)",
                s.keychain_items, s.foreign_items, s.unattested_items
            ));
        }
        Some(counts(s))
    }

    /// The wire view, or `None` when there is nothing to show.
    pub fn view(&self) -> Option<OrphanDiagnosticView> {
        Some(OrphanDiagnosticView {
            level: self.level()?,
            summary: self.summary()?,
            status: self.status.clone(),
            error: self.error,
        })
    }
}

// ── the sweep ────────────────────────────────────────────────────────────

/// A csq-minted orphan awaiting examination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub item: KeychainItemRef,
    /// Every pid whose `term-<pid>` form hashes to the item's service.
    pub pids: Vec<u32>,
}

/// Worklist and counters carried between ticks by the daemon loop.
#[derive(Default)]
pub struct OrphanSweepState {
    pub pending: std::collections::VecDeque<Candidate>,
    pub ambiguous: HashSet<(String, String)>,
    /// The canonical accounts dir the worklist was computed under. A worklist
    /// is only valid for the base it was built for.
    pub enumerated_base: Option<std::path::PathBuf>,
    pub last_enumerated_unix_secs: Option<u64>,
    pub status: OrphanSweepStatus,
    /// `true` once a process scan ran in the current enumeration cycle. A cycle that
    /// drains without one never needed the table, so a stale `process_table_unknown`
    /// is cleared (see `track_process_table`, macOS only).
    pub scanned_this_cycle: bool,
}

#[cfg(target_os = "macos")]
use super::{KeychainExecutor, SecurityCliExecutor};

/// Run one bounded orphan-sweep tick against the real keychain. A structural
/// no-op under tests and wherever the keychain mirror is disabled.
#[cfg(target_os = "macos")]
pub fn sweep_orphans(base_dir: &Path, state: &mut OrphanSweepState) {
    if super::keychain_mirror_disabled() {
        return;
    }
    sweep_orphans_with(
        &SweepDeps {
            exec: &SecurityCliExecutor,
            probe: &OsPidProbe,
            holders: &OsTerminalHolders::new(),
            load_canonical: &load_canonical_refresh_tokens,
            boot_now: crate::session::term_mint::current_boot(),
            now_secs: super::pending_clears_now_secs(),
            batch_max: ORPHAN_BATCH_MAX,
            budget: ORPHAN_TICK_BUDGET,
        },
        base_dir,
        state,
    );
}

/// Non-macOS: CC keeps no OS-keychain item, so there is nothing to sweep.
#[cfg(not(target_os = "macos"))]
pub fn sweep_orphans(_base_dir: &Path, _state: &mut OrphanSweepState) {}

/// Whether a LIVE process still runs as one of a candidate's terminals.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalHolder {
    /// No process was launched with `CLAUDE_CONFIG_DIR=<accounts>/term-<pid>`, is in that
    /// terminal's process group, or descends from its launcher, on a table read whole.
    None,
    /// A live process still runs as that terminal (a Claude Code child that
    /// outlived its launcher, whose dir was then removed by hand).
    Held,
    /// The table could not be read whole, or this terminal's launcher cannot be told from
    /// a process it may have started (`ProcessTableUnknown` says which): unknown.
    Unknown,
}

/// Which process scan a holder question wants.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    /// The scan shared by every candidate of this tick (taken at most once).
    Tick,
    /// A new scan, taken now: used under the mint lock, just before the delete, so a
    /// process that appeared after the tick scan is still seen.
    Fresh,
}

/// The sweep's second liveness witness. The pid rule keys on the dir-name pid
/// (the launcher); a Claude Code child can outlive a dead launcher, and nothing
/// recorded inside the removed dir (`.live-cc-pid`) survives its removal. A process
/// that still carries the terminal's config dir, sits in its process group, or descends
/// from its launcher is the only evidence left.
#[cfg(target_os = "macos")]
pub(crate) trait TerminalHolders {
    fn holder(&self, canonical_base: &Path, term: &Terminal<'_>, scan: Scan) -> TerminalHolder;

    /// What the scans taken through this instance (one tick) found out about the table,
    /// for the operator signal and its aging. [`ScanOutcome::Unknown`] if ANY scan could
    /// not say.
    fn outcome(&self) -> ScanOutcome;

    /// Whether a process group named by one of `pids` exists right now, asked of the
    /// kernel immediately before the delete. [`TerminalHolder::Held`] when one does
    /// (or the kernel will not say it does not), [`TerminalHolder::Unknown`] when the
    /// answer cannot be told, [`TerminalHolder::None`] only when every group is gone.
    fn group_alive(&self, pids: &[u32]) -> TerminalHolder;

    /// The pid list read AGAIN, immediately before the delete: any process forked since the
    /// last fresh scan joins its lineage, so a process that appeared after the scan listed the
    /// table (and whose creator then exited) is still placed by its creator's unique id.
    fn arrivals(&self, canonical_base: &Path, term: &Terminal<'_>) -> TerminalHolder;
}

/// What the sweep knows about one candidate for the holder question: its pids, and for each
/// pid csq minted, how that launcher is told from the processes of a scan.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Terminal<'a> {
    pub pids: &'a [u32],
    /// One entry per pid of `pids` csq minted (a candidate is attested by at least one).
    pub launchers: Vec<(u32, crate::session::term_mint::LauncherBasis)>,
}

#[cfg(target_os = "macos")]
impl<'a> Terminal<'a> {
    /// The terminal of `pids` as `ledger` records it, in the boot session `boot_now`.
    pub(crate) fn of(
        pids: &'a [u32],
        ledger: &crate::session::term_mint::MintLedger,
        boot_now: Option<crate::session::term_mint::BootId>,
    ) -> Self {
        Self {
            pids,
            launchers: ledger
                .attested(pids)
                .into_iter()
                .map(|(pid, record)| (pid, record.basis(boot_now)))
                .collect(),
        }
    }
}

/// What a tick's process scans found out about the table.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// No scan was taken this tick: nothing reached the holder question.
    NotScanned,
    /// Every scan read the table whole, and every terminal asked about was decided.
    Whole,
    /// A scan could not rule a terminal out, and why.
    Unknown(UnknownReason),
}

/// The production witness: its OWN process scan (`sessions::macos::holders`), not the
/// session-display listing, whose tty and argv0 filters would hide a detached or
/// differently-named Claude Code. One instance serves one tick, so its cached scan is
/// the tick's single scan.
#[cfg(target_os = "macos")]
pub(crate) struct OsTerminalHolders {
    scanner: fn(std::time::Duration) -> Option<crate::sessions::macos::holders::ProcessEnvScan>,
    relister: fn(
        &crate::sessions::macos::holders::ProcessEnvScan,
    ) -> Option<crate::sessions::macos::holders::ProcessEnvScan>,
    /// `killpg(pgrp, 0)`: the errno, or `Ok` when the group exists.
    group_probe: fn(i32) -> Result<(), i32>,
    tick: std::cell::RefCell<Option<Option<crate::sessions::macos::holders::ProcessEnvScan>>>,
    /// The most recent fresh scan, which [`TerminalHolders::arrivals`] extends.
    fresh: std::cell::RefCell<Option<crate::sessions::macos::holders::ProcessEnvScan>>,
    outcome: std::cell::Cell<ScanOutcome>,
}

#[cfg(target_os = "macos")]
impl OsTerminalHolders {
    pub(crate) fn new() -> Self {
        Self::with_scanner(crate::sessions::macos::holders::scan_process_env)
    }

    /// The scan is injectable so a test can count and script it.
    pub(crate) fn with_scanner(
        scanner: fn(std::time::Duration) -> Option<crate::sessions::macos::holders::ProcessEnvScan>,
    ) -> Self {
        Self::with_kernel(
            scanner,
            crate::sessions::macos::holders::relist_process_env,
            kill_group_probe,
        )
    }

    /// Every kernel read injectable: the scan, the re-list that extends it and `killpg`.
    pub(crate) fn with_kernel(
        scanner: fn(std::time::Duration) -> Option<crate::sessions::macos::holders::ProcessEnvScan>,
        relister: fn(
            &crate::sessions::macos::holders::ProcessEnvScan,
        ) -> Option<crate::sessions::macos::holders::ProcessEnvScan>,
        group_probe: fn(i32) -> Result<(), i32>,
    ) -> Self {
        Self {
            scanner,
            relister,
            group_probe,
            tick: std::cell::RefCell::new(None),
            fresh: std::cell::RefCell::new(None),
            outcome: std::cell::Cell::new(ScanOutcome::NotScanned),
        }
    }

    /// Fold one question's cause into the tick's outcome: the first that could not say stays.
    fn record(&self, why: Option<UnknownReason>) {
        let seen = match why {
            Some(why) => ScanOutcome::Unknown(why),
            None => ScanOutcome::Whole,
        };
        let merged = match (self.outcome.get(), seen) {
            (ScanOutcome::Unknown(first), _) => ScanOutcome::Unknown(first),
            (_, seen) => seen,
        };
        self.outcome.set(merged);
    }

    /// Judge `term` against `table`, record why it could not be decided (or that the table
    /// itself could not be read whole, whatever this terminal's verdict), and map it.
    fn decide(
        &self,
        table: Option<&crate::sessions::macos::holders::ProcessEnvScan>,
        canonical_base: &Path,
        term: &Terminal<'_>,
    ) -> (TerminalHolder, Judgement) {
        let judgement = match table {
            Some(table) => judge(table, canonical_base, term),
            None => Judgement::Unknown(UnknownReason::of(ProcessTableUnknown::TableUnreadable, 0)),
        };
        let global = unknown_reason(table);
        self.record(match &judgement {
            Judgement::Unknown(why) => Some(*why),
            _ => global,
        });
        let holder = match judgement {
            Judgement::Held => TerminalHolder::Held,
            Judgement::Unknown(_) => TerminalHolder::Unknown,
            Judgement::Clear => TerminalHolder::None,
        };
        (holder, judgement)
    }
}

#[cfg(target_os = "macos")]
impl TerminalHolders for OsTerminalHolders {
    fn holder(&self, canonical_base: &Path, term: &Terminal<'_>, scan: Scan) -> TerminalHolder {
        use crate::sessions::macos::holders::SCAN_BUDGET;
        match scan {
            Scan::Tick => {
                let mut cached = self.tick.borrow_mut();
                let table = cached.get_or_insert_with(|| (self.scanner)(SCAN_BUDGET));
                self.decide(table.as_ref(), canonical_base, term).0
            }
            Scan::Fresh => {
                let table = (self.scanner)(SCAN_BUDGET);
                let (holder, _) = self.decide(table.as_ref(), canonical_base, term);
                *self.fresh.borrow_mut() = table;
                holder
            }
        }
    }

    fn outcome(&self) -> ScanOutcome {
        self.outcome.get()
    }

    fn group_alive(&self, pids: &[u32]) -> TerminalHolder {
        let state = process_group_state(pids, &self.group_probe);
        if state == TerminalHolder::Unknown {
            self.record(Some(UnknownReason::of(
                ProcessTableUnknown::ProcessGroupUnknown,
                0,
            )));
        }
        state
    }

    fn arrivals(&self, canonical_base: &Path, term: &Terminal<'_>) -> TerminalHolder {
        let extended = self
            .fresh
            .borrow()
            .as_ref()
            .and_then(|scan| (self.relister)(scan));
        self.decide(extended.as_ref(), canonical_base, term).0
    }
}

/// `killpg(pgrp, 0)`: `Ok` when the group exists and may be signalled, the errno otherwise.
/// Signal 0 delivers nothing.
#[cfg(target_os = "macos")]
fn kill_group_probe(pgrp: i32) -> Result<(), i32> {
    // SAFETY: killpg with signal 0 only checks that the group exists and may be signalled;
    // it takes two integers and touches no memory.
    if unsafe { libc::killpg(pgrp, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    }
}

/// Whether any process group named by `pids` exists, from `killpg(pgrp, 0)` over `probe`:
/// success or `EPERM` (the group exists; a member we may not signal, or a zombie-only
/// group, answers `EPERM`) is [`TerminalHolder::Held`]; `ESRCH` is no such group; ANY other
/// errno, and a pid that is not a valid process-group id, is [`TerminalHolder::Unknown`].
/// `Held` outranks `Unknown`, which outranks `None`: every outcome but `None` keeps.
///
/// This closes the window between the scan's pid list and the delete: a member that forked
/// into the group and exited, or a process that joined it, after the list was read.
#[cfg(target_os = "macos")]
pub(crate) fn process_group_state(
    pids: &[u32],
    probe: &dyn Fn(i32) -> Result<(), i32>,
) -> TerminalHolder {
    let mut state = TerminalHolder::None;
    for &pid in pids {
        // pid 0 would name this process's OWN group, and a pid above i32::MAX names none.
        let verdict = match i32::try_from(pid).ok().filter(|p| *p > 0) {
            None => TerminalHolder::Unknown,
            Some(pgrp) => match probe(pgrp) {
                Ok(()) => TerminalHolder::Held,
                Err(e) if e == libc::EPERM => TerminalHolder::Held,
                Err(e) if e == libc::ESRCH => TerminalHolder::None,
                Err(_) => TerminalHolder::Unknown,
            },
        };
        match verdict {
            TerminalHolder::Held => return TerminalHolder::Held,
            TerminalHolder::Unknown => state = TerminalHolder::Unknown,
            TerminalHolder::None => {}
        }
    }
    state
}

/// Why a process scan cannot rule a terminal out, as FIXED vocabulary plus a count: the
/// operator signal (a `warn!`) carries these and nothing else. A count of processes is
/// the most it says about them: never a pid, a path, an argv element or an environment
/// value.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnknownReason {
    /// `TableUnreadable` (the pid table itself, or a list lacking this process),
    /// `ProcessUnreadable` (a same-uid process whose environment, or any live process whose
    /// unique id, could not be read, or a table that contradicts itself), `ScanIncomplete` (the budget ran out),
    /// `LineageBroken` / `LauncherUnrecorded` (this terminal only) or `ProcessGroupUnknown`.
    pub cause: ProcessTableUnknown,
    /// How many processes (or launchers) stand in the way; `0` when the cause is not a count.
    pub blocking: usize,
}

#[cfg(target_os = "macos")]
impl UnknownReason {
    pub(crate) fn token(&self) -> &'static str {
        self.cause.token()
    }

    pub(crate) fn of(cause: ProcessTableUnknown, blocking: usize) -> Self {
        Self { cause, blocking }
    }
}

/// `None` when the table was read whole; otherwise why it cannot rule any terminal out.
/// A per-terminal reason (lineage, launcher) is not a property of the table.
#[cfg(target_os = "macos")]
pub(crate) fn unknown_reason(
    table: Option<&crate::sessions::macos::holders::ProcessEnvScan>,
) -> Option<UnknownReason> {
    let Some(table) = table else {
        return Some(UnknownReason::of(ProcessTableUnknown::TableUnreadable, 0));
    };
    if table.unreadable == 0 && table.complete && !table.damaged {
        return None;
    }
    let cause = if table.unreadable > 0 || table.damaged {
        ProcessTableUnknown::ProcessUnreadable
    } else {
        ProcessTableUnknown::ScanIncomplete
    };
    Some(UnknownReason::of(cause, table.unreadable))
}

/// What a tick's [`ScanOutcome`] did to the published unknown state: the operator signal
/// fires on a change, not on every tick that repeats it.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableTransition {
    Unchanged,
    /// Scans could not say, and the last published state said they could.
    Entered(UnknownReason),
    /// Scans still cannot say, for a different cause.
    Changed(UnknownReason),
    /// Scans read whole again.
    Recovered,
}

/// Fold one tick's scan outcome into the published state and say whether it is a
/// transition. A tick that took no scan changes nothing here: the state is decided by
/// scans (or by [`settle_process_table`] when a cycle needed none).
#[cfg(target_os = "macos")]
pub(crate) fn track_process_table(
    state: &mut OrphanSweepState,
    outcome: ScanOutcome,
    now_secs: u64,
) -> TableTransition {
    match outcome {
        ScanOutcome::NotScanned => TableTransition::Unchanged,
        ScanOutcome::Whole => {
            state.scanned_this_cycle = true;
            clear_process_table(&mut state.status)
        }
        ScanOutcome::Unknown(why) => {
            state.scanned_this_cycle = true;
            let previous = state.status.process_table_unknown.replace(why.cause);
            state
                .status
                .process_table_unknown_since_unix_secs
                .get_or_insert(now_secs);
            match previous {
                None => TableTransition::Entered(why),
                Some(p) if p != why.cause => TableTransition::Changed(why),
                Some(_) => TableTransition::Unchanged,
            }
        }
    }
}

/// A cycle that drained without needing a scan, or found nothing to clean, has no table
/// to be unable to read: a stale unknown state is cleared rather than left to age into
/// "needs action".
#[cfg(target_os = "macos")]
fn settle_process_table(state: &mut OrphanSweepState) -> TableTransition {
    if state.pending.is_empty() && !state.scanned_this_cycle {
        clear_process_table(&mut state.status)
    } else {
        TableTransition::Unchanged
    }
}

#[cfg(target_os = "macos")]
fn clear_process_table(status: &mut OrphanSweepStatus) -> TableTransition {
    status.process_table_unknown_since_unix_secs = None;
    match status.process_table_unknown.take() {
        Some(_) => TableTransition::Recovered,
        None => TableTransition::Unchanged,
    }
}

/// Log a transition. Fixed vocabulary and counts only (security.md MUST-2).
#[cfg(target_os = "macos")]
fn log_table_transition(transition: TableTransition) {
    match transition {
        TableTransition::Unchanged => {}
        TableTransition::Entered(why) | TableTransition::Changed(why) => tracing::warn!(
            error_kind = "keychain_orphan_process_table_unknown",
            reason = why.token(),
            blocking_processes = why.blocking,
            "orphan sweep: the process table could not be read whole; \
             items are kept until it can"
        ),
        TableTransition::Recovered => tracing::info!(
            event = "keychain_orphan_process_table_readable",
            "orphan sweep: the process table reads whole again; cleanup resumes"
        ),
    }
}

/// What one scan says about one terminal.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judgement {
    /// A live process runs as the terminal.
    Held,
    /// The scan cannot say, and why.
    Unknown(UnknownReason),
    /// Nothing runs as the terminal, on a table read whole.
    Clear,
}

/// `a == b` ignoring case (Unicode lowercase of the lossy form). Used for a path the
/// volume may treat as case-insensitive: any case-only difference counts as the same,
/// which keeps the item (the cheap direction).
#[cfg(target_os = "macos")]
fn same_ignoring_case(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

/// `true` when `config_dir` is `<canonical_base>/term-<pid>` for one of `pids`.
/// A parent that cannot be resolved while the leaf name matches counts as a
/// match (fail closed: the dir may be a spelling of the accounts dir). The leaf and
/// the resolved parent compare case-insensitively: APFS is case-insensitive by
/// default, so `Term-<pid>` or a re-cased accounts path names the same directory.
#[cfg(target_os = "macos")]
fn config_dir_is_a_term_dir(config_dir: &Path, canonical_base: &Path, pids: &[u32]) -> bool {
    let Some(name) = config_dir.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_lowercase();
    if !pids
        .iter()
        .any(|&pid| name == crate::session::handle_dir::term_handle_dir_name(pid).to_lowercase())
    {
        return false;
    }
    // A bare `term-<pid>` has an empty parent, which does not resolve: a match.
    config_dir
        .parent()
        .unwrap_or(Path::new(""))
        .canonicalize()
        .map(|c| same_ignoring_case(&c, canonical_base))
        .unwrap_or(true)
}

/// Decide from one process scan. A live same-uid process in the terminal's process group
/// (its pid is the group id the launcher led), whatever its image or environment, a process
/// naming the terminal's config dir, and a process that DESCENDS from the terminal's
/// launcher, are `Held`. Otherwise `Clear` only when the table was read whole and every
/// launcher is accounted for; anything else is `Unknown`.
///
/// Descent (`sessions::macos::holders`) is per terminal: a dead creator above one launcher's
/// id is unknown for THAT terminal, while a terminal whose launcher is newer than the
/// creator is decided on the same scan. A launcher csq recorded nothing about
/// (`LauncherUnrecorded`) cannot be ruled out. A launcher minted in an EARLIER boot session
/// has no live descendant. A scan that is incomplete, unreadable or damaged is unknown for
/// every terminal.
///
/// The group witness covers what the environment cannot: a shell or script under `/bin` or
/// `/usr/bin` whose environment macOS withholds but which will start the next `claude` on
/// `term-N`. A group outlives its leader and survives reparenting, so the dead launcher's
/// descendants stay in it unless they started a session of their own.
#[cfg(target_os = "macos")]
pub(crate) fn judge(
    scan: &crate::sessions::macos::holders::ProcessEnvScan,
    canonical_base: &Path,
    term: &Terminal<'_>,
) -> Judgement {
    use crate::session::term_mint::LauncherBasis;
    use crate::sessions::macos::holders::Descent;
    if term
        .pids
        .iter()
        .any(|pid| scan.process_groups.contains(pid))
    {
        return Judgement::Held;
    }
    if scan
        .config_dirs
        .iter()
        .any(|d| config_dir_is_a_term_dir(d, canonical_base, term.pids))
    {
        return Judgement::Held;
    }
    // A damaged table proves nothing either way, a Held that rests on it included.
    if !scan.damaged {
        for (_, basis) in &term.launchers {
            if let LauncherBasis::SameBoot { uniqueid } = basis {
                if scan.descent(*uniqueid) == Descent::Descendant {
                    return Judgement::Held;
                }
            }
        }
    }
    if let Some(why) = unknown_reason(Some(scan)) {
        return Judgement::Unknown(why);
    }
    if term.launchers.is_empty() {
        // Attested by the ledger yet no launcher to account for: nothing to rule out with.
        return Judgement::Unknown(UnknownReason::of(
            ProcessTableUnknown::LauncherUnrecorded,
            1,
        ));
    }
    let mut unknown: Option<UnknownReason> = None;
    for (_, basis) in &term.launchers {
        let why = match basis {
            LauncherBasis::PreviousBoot => continue,
            LauncherBasis::Unrecorded => {
                UnknownReason::of(ProcessTableUnknown::LauncherUnrecorded, 1)
            }
            LauncherBasis::SameBoot { uniqueid } => {
                match scan.descent(*uniqueid) {
                    Descent::Not => continue,
                    // (returned above)
                    Descent::Descendant => return Judgement::Held,
                    Descent::Unknown { processes } => {
                        UnknownReason::of(ProcessTableUnknown::LineageBroken, processes)
                    }
                }
            }
        };
        unknown.get_or_insert(why);
    }
    unknown.map_or(Judgement::Clear, Judgement::Unknown)
}

/// [`judge`] as the plain answer the sweep acts on (the tests' view of it).
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn holder_from_scan(
    scan: &crate::sessions::macos::holders::ProcessEnvScan,
    canonical_base: &Path,
    term: &Terminal<'_>,
) -> TerminalHolder {
    match judge(scan, canonical_base, term) {
        Judgement::Held => TerminalHolder::Held,
        Judgement::Unknown(_) => TerminalHolder::Unknown,
        Judgement::Clear => TerminalHolder::None,
    }
}

/// Everything a tick reads from outside the state, injectable for tests.
#[cfg(target_os = "macos")]
pub(crate) struct SweepDeps<'a> {
    pub exec: &'a dyn KeychainExecutor,
    pub probe: &'a dyn PidProbe,
    pub holders: &'a dyn TerminalHolders,
    pub load_canonical: &'a dyn Fn(&Path) -> CanonicalRefreshTokens,
    /// The boot session this sweep runs in; `None` when it cannot be read (every launcher is
    /// then unrecorded: kept).
    pub boot_now: Option<crate::session::term_mint::BootId>,
    pub now_secs: u64,
    pub batch_max: usize,
    pub budget: std::time::Duration,
}

/// `dump-keychain` through the standard bounded runner (the 5s
/// `KEYCHAIN_OP_TIMEOUT`; there is no longer bound and no interactive scope).
/// Anything short of a complete, successful listing is a reason, never a
/// partial listing treated as the whole keychain.
#[cfg(target_os = "macos")]
pub(crate) fn dump_keychain(
    run: super::SecurityRunner<'_>,
) -> Result<DumpScan, UndeterminedReason> {
    let bo = run(&["dump-keychain"], None).ok_or(UndeterminedReason::EnumerationUnavailable)?;
    let bo = super::SecretOutput::new(bo);
    if !bo.stdout_complete {
        return Err(UndeterminedReason::EnumerationIncomplete);
    }
    if !bo.output.status.success() {
        return Err(UndeterminedReason::EnumerationFailed);
    }
    Ok(parse_dump(&String::from_utf8_lossy(&bo.output.stdout)))
}

/// One tick: refresh the worklist when it is stale, then examine at most
/// `batch_max` items inside `budget`. A cycle that cannot enumerate publishes
/// its reason, drops the worklist and deletes nothing.
#[cfg(target_os = "macos")]
pub(crate) fn sweep_orphans_with(
    deps: &SweepDeps<'_>,
    base_dir: &Path,
    state: &mut OrphanSweepState,
) {
    let started = std::time::Instant::now();
    let now_secs = deps.now_secs;
    state.status.checked_at_unix_secs = now_secs;

    let (canonical_base, resolved) = super::canonicalize_for_keychain_sync(base_dir);
    if !resolved {
        undetermine(base_dir, state, UndeterminedReason::AccountsDirUnresolved);
        return;
    }
    // Which pids csq minted. Read every tick (it only grows): an unreadable
    // ledger means attestation cannot be established, so nothing is deleted.
    let ledger = match crate::session::term_mint::read_ledger(&canonical_base) {
        Ok(ledger) => ledger,
        Err(_) => {
            state.pending.clear();
            state.last_enumerated_unix_secs = None;
            undetermine(base_dir, state, UndeterminedReason::MintLedgerUnreadable);
            return;
        }
    };
    if state.enumerated_base.as_deref() != Some(canonical_base.as_path()) {
        // A worklist is only valid for the base whose paths were hashed.
        state.pending.clear();
        state.last_enumerated_unix_secs = None;
    }
    let due = state
        .last_enumerated_unix_secs
        .is_none_or(|t| now_secs.saturating_sub(t) >= ORPHAN_REENUMERATE_SECS);
    if due {
        match enumerate(deps.exec, &canonical_base, &ledger) {
            Ok(found) => {
                state.status.keychain_items = found.total;
                state.status.foreign_items = found.foreign;
                state.status.orphan_candidates = found.candidates.len();
                state.status.undetermined = None;
                state.status.kept_other = found.unresolved;
                state.status.kept_sole_copy = 0;
                state.status.kept_siblings = 0;
                state.status.kept_pid_in_use = 0;
                state.status.kept_revived_after_read = 0;
                state.status.kept_mint_busy = 0;
                state.status.kept_process_table_unknown = 0;
                state.status.dir_reappeared = 0;
                state.status.unattested_items = found.unattested;
                state.status.already_gone = 0;
                state.status.counts_stale = false;
                state.status.undetermined_since_unix_secs = None;
                state.ambiguous = found.ambiguous;
                state.pending = found.candidates.into();
                state.enumerated_base = Some(canonical_base.clone());
                state.last_enumerated_unix_secs = Some(now_secs);
                state.scanned_this_cycle = false;
            }
            Err(reason) => {
                // UNDETERMINED: the worklist is stale and cannot be refreshed,
                // so it is dropped, not drained.
                state.pending.clear();
                state.last_enumerated_unix_secs = Some(now_secs);
                undetermine(base_dir, state, reason);
                return;
            }
        }
    }

    let mut examined = 0;
    while examined < deps.batch_max && started.elapsed() < deps.budget {
        let Some(candidate) = state.pending.pop_front() else {
            break;
        };
        examined += 1;
        examine(deps, base_dir, &canonical_base, &ledger, state, candidate);
    }

    let transition = match track_process_table(state, deps.holders.outcome(), now_secs) {
        TableTransition::Unchanged => settle_process_table(state),
        seen => seen,
    };
    log_table_transition(transition);
    state.status.pending = state.pending.len();
    write_status(base_dir, &state.status);
}

/// Publish an UNDETERMINED cycle: the reason, no pending work, no deletes.
#[cfg(target_os = "macos")]
fn undetermine(base_dir: &Path, state: &mut OrphanSweepState, reason: UndeterminedReason) {
    tracing::warn!(
        error_kind = "keychain_orphan_sweep_undetermined",
        reason = reason.token(),
        "orphan sweep: cycle undetermined; nothing was deleted"
    );
    state.status.undetermined = Some(reason);
    state.status.counts_stale = true;
    state
        .status
        .undetermined_since_unix_secs
        .get_or_insert(state.status.checked_at_unix_secs);
    state.status.pending = state.pending.len();
    write_status(base_dir, &state.status);
}

#[cfg(target_os = "macos")]
struct Enumeration {
    total: usize,
    foreign: usize,
    unresolved: usize,
    unattested: usize,
    candidates: Vec<Candidate>,
    ambiguous: HashSet<(String, String)>,
}

/// Enumerate, then keep only csq-minted items whose `term-<pid>` dir is gone.
#[cfg(target_os = "macos")]
fn enumerate(
    exec: &dyn KeychainExecutor,
    canonical_base: &Path,
    ledger: &crate::session::term_mint::MintLedger,
) -> Result<Enumeration, UndeterminedReason> {
    let scan = exec.list_cc_credential_items()?;
    let minted = MintedIndex::build(canonical_base);
    let mut found = Enumeration {
        total: scan.items.len(),
        foreign: 0,
        unresolved: scan.unresolved,
        unattested: 0,
        candidates: Vec::new(),
        ambiguous: scan.ambiguous,
    };
    for item in scan.items {
        let Some(pids) = minted.pids_for(&item.service) else {
            found.foreign += 1;
            continue;
        };
        if pids
            .iter()
            .all(|&pid| dir_state(canonical_base, pid) == DirState::Gone)
        {
            // Hash-matched and gone: a candidate only when csq recorded minting
            // one of its pids. Otherwise it may be a foreign item that merely
            // collides with a minted-form hash (or predate the ledger): never
            // read, never deleted.
            if ledger.contains_any(&pids) {
                found.candidates.push(Candidate { item, pids });
            } else {
                found.unattested += 1;
            }
        }
    }
    Ok(found)
}

/// Re-check the evidence, read the item, and delete it only on a deleting
/// verdict that survives a fresh canonical read and a final evidence check.
#[cfg(target_os = "macos")]
fn examine(
    deps: &SweepDeps<'_>,
    base_dir: &Path,
    canonical_base: &Path,
    ledger: &crate::session::term_mint::MintLedger,
    state: &mut OrphanSweepState,
    candidate: Candidate,
) {
    let item = &candidate.item;
    // Re-checked against the ledger read at the start of THIS tick.
    if !ledger.contains_any(&candidate.pids) {
        state.status.unattested_items += 1;
        return;
    }
    if state
        .ambiguous
        .contains(&(item.service.clone(), item.account.clone()))
    {
        state.status.kept_other += 1;
        return;
    }
    match precheck(canonical_base, &candidate.pids, deps.probe) {
        Precheck::Clear => {}
        // A dir that reappeared since the enumeration is a live terminal.
        Precheck::DirExists => {
            state.status.dir_reappeared += 1;
            return;
        }
        Precheck::PidInUse => {
            state.status.kept_pid_in_use += 1;
            return;
        }
        Precheck::Unknown => {
            state.status.kept_other += 1;
            return;
        }
    }

    let term = Terminal::of(&candidate.pids, ledger, deps.boot_now);
    let x = deps.exec.find(&item.service, &item.account);
    let verdict = classify_orphan(&x, &(deps.load_canonical)(base_dir));
    if !verdict.deletes() {
        count_non_delete(state, verdict);
        return;
    }
    // A Claude Code child can outlive its dead launcher; the pid rule above
    // only sees the launcher's pid. Keep the item while any live process still
    // runs as this terminal, and when the process table cannot say.
    match deps.holders.holder(canonical_base, &term, Scan::Tick) {
        TerminalHolder::None => {}
        TerminalHolder::Held => {
            state.status.kept_pid_in_use += 1;
            return;
        }
        TerminalHolder::Unknown => {
            state.status.kept_process_table_unknown += 1;
            return;
        }
    }
    // Immediately before the delete: the canonical copy must STILL be there (a
    // logout may have removed it since the read above), and the dir and the pid
    // must STILL be gone (a terminal may have taken the pid and minted
    // `term-<pid>` while the item was being read).
    let again = classify_orphan(&x, &(deps.load_canonical)(base_dir));
    if !again.deletes() {
        count_non_delete(state, again);
        return;
    }
    // The term mint lock is taken FIRST and held to the end of this fn: a
    // creator waits for the delete instead of minting between the check and the
    // delete. It is a leaf lock (nothing else is taken while it is held, and it
    // is never taken under a swap or keychain write lock); busy or unavailable
    // keeps the item.
    let _mint = match crate::session::term_mint::try_acquire_for_sweep(base_dir) {
        crate::session::term_mint::SweepLock::Held(guard) => guard,
        crate::session::term_mint::SweepLock::Busy
        | crate::session::term_mint::SweepLock::Unavailable => {
            state.status.kept_mint_busy += 1;
            return;
        }
    };
    match precheck(canonical_base, &candidate.pids, deps.probe) {
        Precheck::Clear => {}
        Precheck::DirExists | Precheck::PidInUse => {
            state.status.kept_revived_after_read += 1;
            return;
        }
        Precheck::Unknown => {
            state.status.kept_other += 1;
            return;
        }
    }
    // Re-read the item under the lock, immediately before the delete (one more
    // bounded `find`, `KEYCHAIN_OP_TIMEOUT`). The verdict above classified the
    // bytes read BEFORE the lock; a Claude Code child that rotated its refresh
    // token since then holds the only copy of the new one in this item, and
    // the lock serialises csq creators, not that writer. Anything but
    // byte-equal content keeps the item.
    let reread = deps.exec.find(&item.service, &item.account);
    if !same_item_content(&x, &reread) {
        if matches!(reread, RawContentClassification::Absent) {
            state.status.already_gone += 1;
        } else {
            // Counted with the other "changed after the read" keeps.
            state.status.kept_revived_after_read += 1;
        }
        return;
    }
    // Repeated under the lock, immediately before the delete (D237 sec-M1): a process
    // that started after the tick scan is not covered by the mint lock (it serialises
    // csq creators only, not a hand-set `CLAUDE_CONFIG_DIR=…/term-N claude` or a
    // child of a surviving process), and an unchanged item still re-reads byte-equal.
    // The scan's budget (`SCAN_BUDGET`) is part of the constants the creators' 13s wait is sized
    // against; one kernel read is not individually timed (see `MINT_WAIT_DELAY`).
    match deps.holders.holder(canonical_base, &term, Scan::Fresh) {
        TerminalHolder::None => {}
        TerminalHolder::Held => {
            // Not held at the first check, held now: it came back after the read.
            state.status.kept_revived_after_read += 1;
            return;
        }
        TerminalHolder::Unknown => {
            state.status.kept_process_table_unknown += 1;
            return;
        }
    }
    // The scan's pid list is a snapshot: a process may have been forked since, and its
    // creator may already have exited. The pid list is read again and each process the scan
    // has not seen joins the lineage, so it is placed by its creator's unique id (S3).
    match deps.holders.arrivals(canonical_base, &term) {
        TerminalHolder::None => {}
        TerminalHolder::Held => {
            state.status.kept_revived_after_read += 1;
            return;
        }
        TerminalHolder::Unknown => {
            state.status.kept_process_table_unknown += 1;
            return;
        }
    }
    // A member may also have forked into the terminal's group, or joined it, since.
    // `killpg(N, 0)` asks the kernel NOW, immediately before the delete (R3-2).
    match deps.holders.group_alive(&candidate.pids) {
        TerminalHolder::None => {}
        TerminalHolder::Held => {
            state.status.kept_revived_after_read += 1;
            return;
        }
        TerminalHolder::Unknown => {
            state.status.kept_process_table_unknown += 1;
            return;
        }
    }
    // THE destructive call of the sweep.
    match deps.exec.delete_reporting(&item.service, &item.account) {
        outcome @ (DeleteOutcome::Deleted | DeleteOutcome::NotFound) => {
            if outcome == DeleteOutcome::Deleted {
                state.status.deleted_total += 1;
            } else {
                // Nothing was there to delete (exit 44): not a delete this
                // sweep made.
                state.status.already_gone += 1;
            }
            // The item is gone either way: the ledger bit has done its job.
            // Still under the lock, which `forget_mint` requires as proof.
            if crate::session::term_mint::forget_mint(canonical_base, &candidate.pids, &_mint)
                .is_err()
            {
                tracing::warn!(
                    error_kind = "term_mint_ledger_prune_failed",
                    "orphan sweep: could not prune the mint ledger; the bit stays set"
                );
            }
        }
        DeleteOutcome::Failed => state.status.kept_other += 1,
    }
}

#[cfg(target_os = "macos")]
/// `true` only when both reads are a successful read of the SAME bytes. An
/// unreadable read, or a read that differs, is "not the same item".
pub(crate) fn same_item_content(
    before: &RawContentClassification,
    after: &RawContentClassification,
) -> bool {
    match (before, after) {
        (RawContentClassification::Content(a), RawContentClassification::Content(b)) => {
            a.as_str() == b.as_str()
        }
        _ => false,
    }
}

/// Count a verdict that does not delete, by its own kind.
#[cfg(target_os = "macos")]
fn count_non_delete(state: &mut OrphanSweepState, verdict: OrphanVerdict) {
    match verdict {
        OrphanVerdict::Gone => state.status.already_gone += 1,
        OrphanVerdict::KeepSoleCopy => state.status.kept_sole_copy += 1,
        OrphanVerdict::KeepSiblings => state.status.kept_siblings += 1,
        OrphanVerdict::KeepUnreadable | OrphanVerdict::KeepMalformed => {
            state.status.kept_other += 1;
        }
        // Callers pass only non-deleting verdicts; a deleting one reaching here
        // would be a logic error, and counting it kept is the safe direction.
        OrphanVerdict::DeleteNoLogin | OrphanVerdict::DeleteCopyExists => {
            state.status.kept_other += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(access: &str, refresh: &str, expires_at: u64) -> String {
        serde_json::json!({"claudeAiOauth": {
            "accessToken": access, "refreshToken": refresh, "expiresAt": expires_at
        }})
        .to_string()
    }

    fn content(raw: &str) -> RawContentClassification {
        RawContentClassification::Content(Zeroizing::new(raw.to_string()))
    }

    fn canonical_of(tokens: &[&str]) -> CanonicalRefreshTokens {
        CanonicalRefreshTokens::from_tokens(tokens.iter().map(|t| t.to_string()))
    }

    // ── parse_dump ────────────────────────────────────────────────────

    const DUMP: &str = r#"keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="Claude Code-credentials-aaaaaaaa"
    "acct"<blob>="esperie"
    "svce"<blob>="Claude Code-credentials-aaaaaaaa"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="esperie"
    "svce"<blob>="Claude Code-credentials"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="esperie"
    "svce"<blob>="Claude Code-credentials-bbbbbbbb"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="esperie"
    "svce"<blob>="Claude Code-credentials-bbbbbbbb"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=<NULL>
    "svce"<blob>="Claude Code-credentials-cccccccc"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=0x6162  "ab"
    "svce"<blob>="Claude Code-credentials-dddddddd"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="someone"
    "svce"<blob>="Other Service"
keychain: "/Users/u/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="late"
    "svce"<blob>="Claude Code-credentials-eeeeeeee"
"#;

    /// RED against a parser that keeps the unsuffixed default item, counts a
    /// duplicate pair once as deletable, or reads an unreadable account.
    #[test]
    fn parse_dump_keeps_only_plain_suffixed_items_and_flags_duplicates() {
        let scan = parse_dump(DUMP);
        let got: Vec<(&str, &str)> = scan
            .items
            .iter()
            .map(|i| (i.service.as_str(), i.account.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("Claude Code-credentials-aaaaaaaa", "esperie"),
                ("Claude Code-credentials-bbbbbbbb", "esperie"),
                ("Claude Code-credentials-eeeeeeee", "late"),
            ]
        );
        assert!(scan.ambiguous.contains(&(
            "Claude Code-credentials-bbbbbbbb".to_string(),
            "esperie".to_string()
        )));
        assert_eq!(scan.ambiguous.len(), 1);
        // `<NULL>` and the hex-encoded blob are both unreadable accounts.
        assert_eq!(scan.unresolved, 2);
    }

    #[test]
    fn suffixed_service_requires_exactly_eight_lowercase_hex() {
        assert!(is_suffixed_service("Claude Code-credentials-0123abcd"));
        for bad in [
            "Claude Code-credentials",
            "Claude Code-credentials-0123abc",
            "Claude Code-credentials-0123abcde",
            "Claude Code-credentials-0123ABCD",
            "Claude Code-credentials-0123abcg",
            "Other-credentials-0123abcd",
        ] {
            assert!(!is_suffixed_service(bad), "{bad:?}");
        }
    }

    #[test]
    fn reason_tokens_are_fixed_and_match_their_serialised_form() {
        for (reason, token) in [
            (
                UndeterminedReason::EnumerationUnavailable,
                "enumeration_unavailable",
            ),
            (
                UndeterminedReason::EnumerationIncomplete,
                "enumeration_incomplete",
            ),
            (UndeterminedReason::EnumerationFailed, "enumeration_failed"),
            (
                UndeterminedReason::EnumerationUnsupported,
                "enumeration_unsupported",
            ),
            (
                UndeterminedReason::AccountsDirUnresolved,
                "accounts_dir_unresolved",
            ),
            (
                UndeterminedReason::MintLedgerUnreadable,
                "mint_ledger_unreadable",
            ),
        ] {
            assert_eq!(reason.token(), token);
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{token}\"")
            );
        }
    }

    // ── csq-minted path forms ─────────────────────────────────────────

    /// The sweep must hash the path the WRITER hashes: the canonicalised handle
    /// dir. On macOS the temp dir lives under the `/var` -> `/private/var`
    /// symlink, so a raw spelling would hash to a different service. RED
    /// against a sweep that hashes `base.join("term-N")` without canonicalising.
    #[test]
    fn minted_service_name_equals_the_service_the_writer_derives() {
        let tmp = tempfile::tempdir().unwrap();
        let term = tmp
            .path()
            .join(crate::session::handle_dir::term_handle_dir_name(4242));
        std::fs::create_dir(&term).unwrap();

        // Writer side, exactly as `create_handle_dir_named` derives it.
        let (term_abs, ok) = super::super::canonicalize_for_keychain_sync(&term);
        assert!(ok);
        let written = super::super::service_name(&term_abs);

        // Sweep side: the dir is gone, so only the base can be canonicalised.
        let (base_abs, ok) = super::super::canonicalize_for_keychain_sync(tmp.path());
        assert!(ok);
        std::fs::remove_dir(&term).unwrap();
        assert_eq!(minted_service_name(&base_abs, 4242), written);

        if tmp.path() != base_abs {
            assert_ne!(
                minted_service_name(tmp.path(), 4242),
                written,
                "a non-canonical spelling hashes elsewhere: the canonical base is load-bearing"
            );
        }
    }

    #[test]
    fn minted_index_attributes_only_minted_forms_and_all_colliding_pids() {
        let base = Path::new("/x/accounts");
        let index = MintedIndex::build(base);
        let svc = minted_service_name(base, 1234);
        assert!(index.pids_for(&svc).unwrap().contains(&1234));
        // A foreign path's service, the unsuffixed default item, junk: none minted.
        let foreign = super::super::service_name(Path::new("/elsewhere/coc-env/term-1234"));
        assert_eq!(index.pids_for(&foreign), None);
        assert_eq!(index.pids_for("Claude Code-credentials"), None);
        assert_eq!(index.pids_for("not a service"), None);

        // A forced collision attributes the service to BOTH pids.
        let colliding = MintedIndex::build_with(|pid| {
            if pid == 7 || pid == 9 {
                "Claude Code-credentials-0000abcd".to_string()
            } else {
                format!("Claude Code-credentials-{:08x}", pid + 0x1000_0000)
            }
        });
        let mut pids = colliding
            .pids_for("Claude Code-credentials-0000abcd")
            .unwrap();
        pids.sort_unstable();
        assert_eq!(pids, vec![7, 9]);
    }

    // ── liveness evidence ─────────────────────────────────────────────

    struct ScriptedProbe {
        /// pid -> successive samples; the last repeats.
        script: std::cell::RefCell<HashMap<u32, Vec<PidOccupant>>>,
    }

    impl ScriptedProbe {
        fn new(script: &[(u32, Vec<PidOccupant>)]) -> Self {
            Self {
                script: std::cell::RefCell::new(script.iter().cloned().collect()),
            }
        }
        fn all_absent() -> Self {
            Self::new(&[])
        }
    }

    impl PidProbe for ScriptedProbe {
        fn occupant(&self, pid: u32) -> PidOccupant {
            let mut script = self.script.borrow_mut();
            match script.get_mut(&pid) {
                Some(samples) if samples.len() > 1 => samples.remove(0),
                Some(samples) => samples[0],
                None => PidOccupant::Absent,
            }
        }
    }

    #[test]
    fn dir_state_separates_gone_exists_and_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert_eq!(dir_state(base, 11), DirState::Gone);
        std::fs::create_dir(base.join("term-11")).unwrap();
        assert_eq!(dir_state(base, 11), DirState::Exists);
        // A regular file at the path is also "something is there".
        std::fs::write(base.join("term-12"), b"x").unwrap();
        assert_eq!(dir_state(base, 12), DirState::Exists);
        // A missing accounts dir would report every child "not found": unknown.
        assert_eq!(dir_state(&base.join("missing"), 11), DirState::Unknown);
    }

    #[test]
    fn precheck_requires_every_pid_gone_and_unoccupied() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let free = ScriptedProbe::all_absent();
        assert_eq!(precheck(base, &[5], &free), Precheck::Clear);
        assert_eq!(precheck(base, &[], &free), Precheck::Unknown);
        // Any one of several colliding pids having a dir keeps the item.
        std::fs::create_dir(base.join("term-9")).unwrap();
        assert_eq!(precheck(base, &[5, 9], &free), Precheck::DirExists);
        // A reused pid (some other process, with its own start time) keeps it.
        let reused = ScriptedProbe::new(&[(5, vec![PidOccupant::Present])]);
        assert_eq!(precheck(base, &[5], &reused), Precheck::PidInUse);
        let unknown = ScriptedProbe::new(&[(5, vec![PidOccupant::Unknown])]);
        assert_eq!(precheck(base, &[5], &unknown), Precheck::Unknown);
        assert_eq!(
            precheck(&base.join("missing"), &[5], &free),
            Precheck::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn os_pid_probe_reports_present_absent_and_refuses_non_pids() {
        let probe = OsPidProbe;
        assert_eq!(probe.occupant(std::process::id()), PidOccupant::Present);
        // Above any pid either platform issues.
        assert_eq!(probe.occupant(999_999_999), PidOccupant::Absent);
        // `kill(0, _)` and `kill(-1, _)` are not pids and must never be sent.
        assert_eq!(probe.occupant(0), PidOccupant::Unknown);
        assert_eq!(probe.occupant(u32::MAX), PidOccupant::Unknown);
    }

    // ── classify_orphan ───────────────────────────────────────────────

    const LONG_DEAD: u64 = 1_000; // an access token expired long ago

    /// Only an item whose sole content is an emptied `claudeAiOauth` (or an
    /// empty object) is deleted as "no login".
    #[test]
    fn classify_deletes_only_items_that_hold_nothing_but_an_empty_login() {
        let emptied = content(&login("", "", 0));
        let empty_object = content("{}");
        let canonical = canonical_of(&[]);
        assert_eq!(
            classify_orphan(&emptied, &canonical),
            OrphanVerdict::DeleteNoLogin
        );
        assert_eq!(
            classify_orphan(&empty_object, &canonical),
            OrphanVerdict::DeleteNoLogin
        );
    }

    /// RED against a classifier that looks only at `claudeAiOauth`: csq keeps
    /// no other copy of an MCP server's login, and the reaper deliberately
    /// leaves a siblings-only item behind, so the sweep must not delete it.
    /// Covers the three shapes: an MCP-only item, a canonical-match login that
    /// also carries `mcpOAuth`, and an unknown top-level key.
    #[test]
    fn classify_keeps_every_item_that_holds_a_sibling_key() {
        let canonical = canonical_of(&["ref-canonical"]);
        let mcp_only = content(r#"{"mcpOAuth":{"srv":{"accessToken":"m"}}}"#);
        let canonical_match_with_mcp = content(
            r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"ref-canonical","expiresAt":1},
                "mcpOAuth":{"srv":{"accessToken":"m"}}}"#,
        );
        let emptied_with_mcp = content(
            r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0},
                "mcpOAuth":{"srv":{"accessToken":"m"}}}"#,
        );
        let unknown_key =
            content(r#"{"claudeAiOauth":{"accessToken":"","refreshToken":""},"future":1}"#);
        let unknown_only = content(r#"{"somethingNew":{"x":1}}"#);
        for (name, item) in [
            ("mcp-only", &mcp_only),
            ("canonical-match + mcpOAuth", &canonical_match_with_mcp),
            ("emptied login + mcpOAuth", &emptied_with_mcp),
            ("unknown key beside an emptied login", &unknown_key),
            ("unknown key only", &unknown_only),
        ] {
            assert_eq!(
                classify_orphan(item, &canonical),
                OrphanVerdict::KeepSiblings,
                "{name}"
            );
            assert!(!OrphanVerdict::KeepSiblings.deletes());
        }
    }

    #[test]
    fn classify_deletes_a_refresh_token_byte_equal_to_a_canonical_one_even_if_expired() {
        let canonical = canonical_of(&["ref-canonical"]);
        // Expiry is not an input: expired and unexpired alike have a copy.
        for expires in [LONG_DEAD, u64::MAX / 2] {
            let raw = login("access-x", "ref-canonical", expires);
            assert_eq!(
                classify_orphan(&content(&raw), &canonical),
                OrphanVerdict::DeleteCopyExists
            );
        }
    }

    /// RED against a classifier that deletes on access-token expiry (the
    /// retired `DeleteExpired`) or that matches a refresh token by prefix.
    #[test]
    fn classify_keeps_a_live_refresh_token_csq_holds_no_canonical_copy_of() {
        let canonical = canonical_of(&["ref-canonical"]);
        let expired = content(&login("a", "ref-other", LONG_DEAD));
        assert_eq!(
            classify_orphan(&expired, &canonical),
            OrphanVerdict::KeepSoleCopy
        );
        let prefix = content(&login("a", "ref-canonic", LONG_DEAD));
        assert_eq!(
            classify_orphan(&prefix, &canonical),
            OrphanVerdict::KeepSoleCopy
        );
        // No canonical copy at all (no profiles, unreadable file): keep.
        assert_eq!(
            classify_orphan(&expired, &canonical_of(&[])),
            OrphanVerdict::KeepSoleCopy
        );
    }

    #[test]
    fn classify_keeps_an_access_token_with_no_refresh_token() {
        let access_only = content(&login("live-access", "", LONG_DEAD));
        assert_eq!(
            classify_orphan(&access_only, &canonical_of(&["x"])),
            OrphanVerdict::KeepSoleCopy
        );
    }

    #[test]
    fn classify_keeps_what_it_cannot_read_and_reports_gone_for_absent() {
        let canonical = canonical_of(&["r"]);
        let unreadable =
            RawContentClassification::Unreadable(super::super::UnreadableKind::Transient);
        assert_eq!(
            classify_orphan(&unreadable, &canonical),
            OrphanVerdict::KeepUnreadable
        );
        for malformed in [
            r#"{"claudeAiOauth":{"accessToken":"a"}}"#,
            r#"{"claudeAiOauth":null}"#,
            r#"{"claudeAiOauth":{"accessToken":1,"refreshToken":2}}"#,
            r#"["not","an","object"]"#,
            "not json",
        ] {
            assert_eq!(
                classify_orphan(&content(malformed), &canonical),
                OrphanVerdict::KeepMalformed,
                "{malformed}"
            );
        }
        assert_eq!(
            classify_orphan(&RawContentClassification::Absent, &canonical),
            OrphanVerdict::Gone
        );
    }

    // ── canonical refresh tokens ──────────────────────────────────────

    fn write_canonical(base: &Path, slot: u16, raw: &str) {
        let id = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot);
        let path = crate::accounts::identity_store::credentials_path_for(base, id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, raw).unwrap();
    }

    /// Reads the identity-keyed canonical file whatever its access-token expiry,
    /// and nothing else: the legacy `config-N` copy is not a canonical source.
    #[test]
    fn canonical_tokens_come_from_identity_files_only() {
        let dir = crate::testing::identity_fixtures::coexisting_fixture(2);
        let base = dir.path();
        write_canonical(base, 1, &login("expired", "ref-slot-1", LONG_DEAD));
        // Slot 2 has only the legacy config-2 copy (the fixture's): not read.
        std::fs::write(
            base.join("config-2").join(".credentials.json"),
            login("a", "ref-legacy-only", u64::MAX / 2),
        )
        .unwrap();
        let tokens = load_canonical_refresh_tokens(base);
        assert!(tokens.contains("ref-slot-1"));
        assert!(!tokens.contains("ref-legacy-only"));
        assert!(!tokens.contains(""));
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn canonical_tokens_are_empty_without_profiles_or_for_a_symlinked_file() {
        let empty = tempfile::tempdir().unwrap();
        assert!(load_canonical_refresh_tokens(empty.path()).is_empty());

        let dir = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = dir.path();
        write_canonical(base, 1, &login("a", "ref-real", 5));
        #[cfg(unix)]
        {
            let id = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
            let path = crate::accounts::identity_store::credentials_path_for(base, id);
            let real = base.join("real-creds");
            std::fs::rename(&path, &real).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
            assert!(
                load_canonical_refresh_tokens(base).is_empty(),
                "a symlinked canonical file is not followed"
            );
        }
    }

    // ── status file ───────────────────────────────────────────────────

    #[test]
    fn status_round_trips_and_a_missing_file_is_never_published() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(read_status(base.path()), Ok(None));
        let status = OrphanSweepStatus {
            checked_at_unix_secs: 7,
            keychain_items: 5,
            foreign_items: 1,
            orphan_candidates: 3,
            pending: 2,
            deleted_total: 1,
            kept_sole_copy: 1,
            kept_siblings: 6,
            kept_pid_in_use: 2,
            kept_revived_after_read: 3,
            kept_mint_busy: 7,
            kept_process_table_unknown: 11,
            dir_reappeared: 8,
            already_gone: 9,
            unattested_items: 10,
            kept_other: 4,
            undetermined: Some(UndeterminedReason::EnumerationUnavailable),
            counts_stale: true,
            undetermined_since_unix_secs: Some(5),
            process_table_unknown: Some(ProcessTableUnknown::LineageBroken),
            process_table_unknown_since_unix_secs: Some(6),
        };
        write_status(base.path(), &status);
        assert_eq!(read_status(base.path()), Ok(Some(status)));
    }

    /// RED against a reader that folds a corrupt file into "never published".
    #[test]
    fn a_corrupt_oversized_or_non_file_status_is_an_explicit_error() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join(ORPHAN_STATUS_FILENAME);
        std::fs::write(&path, b"{\"checked_at_unix_secs\":").unwrap();
        assert_eq!(read_status(base.path()), Err(StatusReadError::Corrupt));
        // Parses as JSON but is not a status.
        std::fs::write(&path, b"{}").unwrap();
        assert_eq!(read_status(base.path()), Err(StatusReadError::Corrupt));
        std::fs::write(&path, vec![b' '; (STATUS_MAX_BYTES + 1) as usize]).unwrap();
        assert_eq!(read_status(base.path()), Err(StatusReadError::Oversized));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(read_status(base.path()), Err(StatusReadError::Unreadable));
    }

    // ── delete outcome ────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn delete_outcome_separates_deleted_not_found_and_failed() {
        use std::os::unix::process::ExitStatusExt;
        let out = |raw: i32| std::process::Output {
            status: std::process::ExitStatus::from_raw(raw),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert_eq!(delete_outcome_of(&out(0)), DeleteOutcome::Deleted);
        assert_eq!(
            delete_outcome_of(&out(44 << 8)),
            DeleteOutcome::NotFound,
            "exit 44 is errSecItemNotFound"
        );
        assert_eq!(delete_outcome_of(&out(1 << 8)), DeleteOutcome::Failed);
        assert_eq!(delete_outcome_of(&out(45 << 8)), DeleteOutcome::Failed);
        // Killed by SIGKILL: no exit code at all.
        assert_eq!(delete_outcome_of(&out(9)), DeleteOutcome::Failed);
    }

    // ── the diagnostic accessor ───────────────────────────────────────

    fn diag(status: OrphanSweepStatus) -> OrphanDiagnostic {
        OrphanDiagnostic {
            status: Some(status),
            error: None,
            age_secs: Some(0),
        }
    }

    /// An old status file that says `kept_revived` still reads (renamed field).
    #[test]
    fn a_status_file_with_the_old_kept_revived_name_still_reads() {
        let base = tempfile::tempdir().unwrap();
        let mut value = serde_json::to_value(OrphanSweepStatus::default()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("kept_revived_after_read");
        object.insert("kept_revived".into(), 9.into());
        std::fs::write(base.path().join(ORPHAN_STATUS_FILENAME), value.to_string()).unwrap();
        assert_eq!(
            read_status(base.path())
                .unwrap()
                .unwrap()
                .kept_revived_after_read,
            9
        );
    }

    #[test]
    fn the_diagnostic_levels_follow_the_published_state() {
        let none = read_diagnostic(tempfile::tempdir().unwrap().path());
        assert_eq!(none.level(), None);
        assert_eq!(none.summary(), None);
        assert!(none.view().is_none());

        let clean = diag(OrphanSweepStatus {
            keychain_items: 7,
            foreign_items: 3,
            ..Default::default()
        });
        assert_eq!(clean.level(), Some(DiagnosticLevel::Ok));
        assert!(clean
            .summary()
            .unwrap()
            .starts_with("none (7 per-terminal items, 3 not minted"));

        // Siblings-only leftovers are INFO, not a warning.
        let siblings_only = diag(OrphanSweepStatus {
            keychain_items: 5,
            orphan_candidates: 2,
            kept_siblings: 2,
            ..Default::default()
        });
        assert_eq!(siblings_only.level(), Some(DiagnosticLevel::Info));

        // Anything the operator may care about is a warning.
        for status in [
            OrphanSweepStatus {
                orphan_candidates: 1,
                pending: 1,
                ..Default::default()
            },
            OrphanSweepStatus {
                orphan_candidates: 1,
                kept_sole_copy: 1,
                ..Default::default()
            },
            OrphanSweepStatus {
                orphan_candidates: 1,
                kept_other: 1,
                ..Default::default()
            },
            OrphanSweepStatus {
                orphan_candidates: 1,
                kept_mint_busy: 1,
                ..Default::default()
            },
            // Nothing is being cleaned up while the table cannot be read whole: the
            // operator must be able to see that, so it is never INFO.
            OrphanSweepStatus {
                orphan_candidates: 1,
                kept_process_table_unknown: 1,
                ..Default::default()
            },
        ] {
            assert_eq!(diag(status).level(), Some(DiagnosticLevel::Warn));
        }
        let unknown = diag(OrphanSweepStatus {
            orphan_candidates: 2,
            kept_process_table_unknown: 2,
            process_table_unknown: Some(ProcessTableUnknown::ProcessUnreadable),
            ..Default::default()
        });
        assert!(
            unknown
                .summary()
                .unwrap()
                .contains("2 kept because the sweep could not rule out a live process"),
            "{:?}",
            unknown.summary()
        );
        // The cause is in the sentence, so an operator can act on it (corr N4).
        assert!(
            unknown
                .summary()
                .unwrap()
                .contains("some process's environment or identity could not be read"),
            "{:?}",
            unknown.summary()
        );

        let err = OrphanDiagnostic {
            status: None,
            error: Some("corrupt"),
            age_secs: None,
        };
        assert_eq!(err.level(), Some(DiagnosticLevel::Warn));
        assert!(err.summary().unwrap().contains("corrupt"));
    }

    /// Persistent undetermined => NEEDS ACTION; a fresh one is a warning. The
    /// threshold is the enforced constant, and the text marks counts stale and
    /// includes kept_other and kept_siblings.
    #[test]
    fn a_persistently_undetermined_sweep_needs_action_and_marks_counts_stale() {
        let base = OrphanSweepStatus {
            checked_at_unix_secs: 10_000,
            keychain_items: 4,
            orphan_candidates: 2,
            kept_other: 3,
            kept_siblings: 5,
            undetermined: Some(UndeterminedReason::EnumerationUnavailable),
            counts_stale: true,
            ..Default::default()
        };
        let fresh = diag(OrphanSweepStatus {
            undetermined_since_unix_secs: Some(10_000 - (ORPHAN_NEEDS_ACTION_SECS - 1)),
            ..base.clone()
        });
        assert_eq!(fresh.level(), Some(DiagnosticLevel::Warn));
        let persistent = diag(OrphanSweepStatus {
            undetermined_since_unix_secs: Some(10_000 - ORPHAN_NEEDS_ACTION_SECS),
            ..base
        });
        assert_eq!(persistent.level(), Some(DiagnosticLevel::NeedsAction));
        let text = persistent.summary().unwrap();
        for part in [
            "needs action",
            "enumeration_unavailable",
            "30 min",
            "STALE",
            "3 kept for other reasons",
            "5 kept because they hold non-login data",
        ] {
            assert!(text.contains(part), "{part:?} missing from {text}");
        }
        let json = serde_json::to_value(persistent.view().unwrap()).unwrap();
        assert_eq!(json["level"], "needs_action");
        assert_eq!(json["status"]["counts_stale"], true);
    }

    /// F4: the report ages against an injected `now`. A report within the bound
    /// reads as published; one past it is `Warn` with a stale summary; a
    /// needs-action report is not softened. RED on a `level()` that never
    /// compared `checked_at_unix_secs` with now (it stayed `Ok` forever).
    #[test]
    fn a_report_older_than_the_bound_reads_stale_not_ok() {
        let base = tempfile::tempdir().unwrap();
        let t = 5_000_000u64;
        write_status(
            base.path(),
            &OrphanSweepStatus {
                checked_at_unix_secs: t,
                ..OrphanSweepStatus::default()
            },
        );
        let fresh = read_diagnostic_at(base.path(), t + ORPHAN_STALE_SECS);
        assert_eq!(fresh.age_secs, Some(ORPHAN_STALE_SECS));
        assert_eq!(fresh.level(), Some(DiagnosticLevel::Ok));
        assert!(!fresh.summary().unwrap().contains("stale"));
        let stale = read_diagnostic_at(base.path(), t + ORPHAN_STALE_SECS + 1);
        assert_eq!(stale.level(), Some(DiagnosticLevel::Warn));
        let text = stale.summary().unwrap();
        assert!(
            text.starts_with("stale: the sweep last reported 30 min ago"),
            "{text}"
        );
        let view = serde_json::to_value(stale.view().unwrap()).unwrap();
        assert_eq!(view["level"], "warn");
        // A clock behind the report (skew) ages to zero, never underflows.
        assert_eq!(read_diagnostic_at(base.path(), t - 9).age_secs, Some(0));
        // A needs-action report keeps its level when stale.
        write_status(
            base.path(),
            &OrphanSweepStatus {
                checked_at_unix_secs: t + ORPHAN_NEEDS_ACTION_SECS,
                undetermined: Some(UndeterminedReason::EnumerationFailed),
                undetermined_since_unix_secs: Some(t),
                counts_stale: true,
                ..OrphanSweepStatus::default()
            },
        );
        let na = read_diagnostic_at(base.path(), t + 10 * ORPHAN_STALE_SECS);
        assert_eq!(na.level(), Some(DiagnosticLevel::NeedsAction));
    }

    // ── sweep driver (macOS: KeychainExecutor is macOS-only) ─────────

    #[cfg(target_os = "macos")]
    mod driver {
        use super::*;
        use crate::error::PlatformError;
        use std::cell::RefCell;
        use std::path::PathBuf;

        const ACCT: &str = "esperie";
        const NOW_SECS: u64 = 2_000_000_000;
        const LONG: std::time::Duration = std::time::Duration::from_secs(3600);
        /// A pid no test dir uses and no live process holds.
        const DEAD_PID: u32 = 54_321;
        /// The boot session the sweep tests run in, and the next one (a restart).
        const BOOT: crate::session::term_mint::BootId = [0xB1; 16];
        const NEXT_BOOT: crate::session::term_mint::BootId = [0xB2; 16];

        /// A terminal whose launchers are all from an earlier boot: env and group decide.
        fn env_term(pids: &[u32]) -> Terminal<'_> {
            Terminal {
                pids,
                launchers: pids
                    .iter()
                    .map(|&pid| (pid, crate::session::term_mint::LauncherBasis::PreviousBoot))
                    .collect(),
            }
        }

        /// A terminal with one launcher minted in this boot with unique id `uniqueid`.
        fn term_of(pids: &[u32], uniqueid: u64) -> Terminal<'_> {
            Terminal {
                pids,
                launchers: vec![(
                    pids[0],
                    crate::session::term_mint::LauncherBasis::SameBoot { uniqueid },
                )],
            }
        }

        struct Fake {
            /// `(service, content)`; the account is always `ACCT`.
            items: RefCell<Vec<(String, RawContentClassification)>>,
            list: RefCell<Result<DumpScan, UndeterminedReason>>,
            finds: RefCell<Vec<String>>,
            deletes: RefCell<Vec<String>>,
            delete_ok: bool,
            /// `delete` finds no item (exit 44) instead of removing one.
            delete_not_found: bool,
            /// Runs inside `find`, after the item is read: simulates the world
            /// changing between the read and the delete.
            on_find: RefCell<Option<Box<dyn FnMut()>>>,
            /// Runs inside `delete`, before the item is removed: the window the
            /// sweep holds the term mint lock across.
            on_delete: RefCell<Option<Box<dyn FnMut()>>>,
            /// Successive `find` results returned BEFORE the stored item is
            /// consulted: a read that changes between two reads of one item.
            scripted_reads: RefCell<std::collections::VecDeque<RawContentClassification>>,
        }

        impl KeychainExecutor for Fake {
            fn find(&self, svc: &str, _account: &str) -> RawContentClassification {
                self.finds.borrow_mut().push(svc.to_string());
                if let Some(next) = self.scripted_reads.borrow_mut().pop_front() {
                    return next;
                }
                let found = self
                    .items
                    .borrow()
                    .iter()
                    .find(|(s, _)| s == svc)
                    .map(|(_, c)| c.clone())
                    .unwrap_or(RawContentClassification::Absent);
                if let Some(hook) = self.on_find.borrow_mut().as_mut() {
                    hook();
                }
                found
            }
            fn add(&self, _: &str, _: &str, _: &str) -> Result<(), PlatformError> {
                panic!("the orphan sweep never writes");
            }
            fn delete(&self, svc: &str, _account: &str) -> bool {
                if let Some(hook) = self.on_delete.borrow_mut().as_mut() {
                    hook();
                }
                self.deletes.borrow_mut().push(svc.to_string());
                if self.delete_ok {
                    self.items.borrow_mut().retain(|(s, _)| s != svc);
                }
                self.delete_ok
            }
            fn delete_reporting(&self, svc: &str, account: &str) -> DeleteOutcome {
                if self.delete_not_found {
                    self.deletes.borrow_mut().push(svc.to_string());
                    return DeleteOutcome::NotFound;
                }
                if self.delete(svc, account) {
                    DeleteOutcome::Deleted
                } else {
                    DeleteOutcome::Failed
                }
            }
            fn list_cc_credential_items(&self) -> Result<DumpScan, UndeterminedReason> {
                match &*self.list.borrow() {
                    Ok(scan) => Ok(DumpScan {
                        items: scan.items.clone(),
                        ambiguous: scan.ambiguous.clone(),
                        unresolved: scan.unresolved,
                    }),
                    Err(reason) => Err(*reason),
                }
            }
        }

        fn fake(items: Vec<(String, RawContentClassification)>) -> Fake {
            let scan = DumpScan {
                items: items
                    .iter()
                    .map(|(s, _)| KeychainItemRef {
                        service: s.clone(),
                        account: ACCT.to_string(),
                    })
                    .collect(),
                ..DumpScan::default()
            };
            Fake {
                items: RefCell::new(items),
                list: RefCell::new(Ok(scan)),
                finds: RefCell::default(),
                deletes: RefCell::default(),
                delete_ok: true,
                delete_not_found: false,
                on_find: RefCell::default(),
                on_delete: RefCell::default(),
                scripted_reads: RefCell::default(),
            }
        }

        /// The service csq mints for `term-<pid>` under `base`, and a ledger
        /// entry for `pid` (as `create_handle_dir_named` records when it mints).
        fn minted(base: &Path, pid: u32) -> String {
            let guard = crate::session::term_mint::acquire_for_mint(base).unwrap();
            crate::session::term_mint::record_mint(base, pid, None, &guard).unwrap();
            drop(guard);
            minted_service_only(base, pid)
        }

        /// [`minted`] with the launcher identity the creator would have recorded.
        fn minted_as(
            base: &Path,
            pid: u32,
            launcher: Option<(u64, crate::session::term_mint::BootId)>,
        ) -> String {
            let guard = crate::session::term_mint::acquire_for_mint(base).unwrap();
            crate::session::term_mint::record_mint(base, pid, launcher, &guard).unwrap();
            drop(guard);
            minted_service_only(base, pid)
        }

        /// The same service name WITHOUT a ledger entry: a csq-form item csq has
        /// no record of minting.
        fn minted_service_only(base: &Path, pid: u32) -> String {
            let (abs, ok) = super::super::super::canonicalize_for_keychain_sync(base);
            assert!(ok);
            minted_service_name(&abs, pid)
        }

        fn no_canonical(_: &Path) -> CanonicalRefreshTokens {
            CanonicalRefreshTokens::default()
        }

        /// A scripted second witness: the same verdict on every call.
        struct FixedHolders(TerminalHolder);
        impl TerminalHolders for FixedHolders {
            fn holder(&self, _: &Path, _: &Terminal<'_>, _: Scan) -> TerminalHolder {
                self.0
            }
            fn outcome(&self) -> ScanOutcome {
                ScanOutcome::NotScanned
            }
            fn group_alive(&self, _: &[u32]) -> TerminalHolder {
                TerminalHolder::None
            }
            fn arrivals(&self, _: &Path, _: &Terminal<'_>) -> TerminalHolder {
                TerminalHolder::None
            }
        }

        /// A scripted witness for the delete-edge and operator-signal tests: the tick and
        /// fresh scans, the `killpg` verdict and the table outcome each answer as scripted.
        struct ScriptedHolders {
            group: TerminalHolder,
            outcome: std::cell::Cell<ScanOutcome>,
            group_asked: std::cell::Cell<u32>,
            /// The verdict of the re-list before the delete, and how often it was asked.
            arrivals: TerminalHolder,
            arrivals_asked: std::cell::Cell<u32>,
            /// The verdict of the fresh scan under the lock.
            fresh: TerminalHolder,
        }
        impl ScriptedHolders {
            fn new(group: TerminalHolder, outcome: ScanOutcome) -> Self {
                Self {
                    group,
                    outcome: std::cell::Cell::new(outcome),
                    group_asked: std::cell::Cell::new(0),
                    arrivals: TerminalHolder::None,
                    arrivals_asked: std::cell::Cell::new(0),
                    fresh: TerminalHolder::None,
                }
            }
        }
        impl TerminalHolders for ScriptedHolders {
            fn holder(&self, _: &Path, _: &Terminal<'_>, scan: Scan) -> TerminalHolder {
                match scan {
                    Scan::Tick => TerminalHolder::None,
                    Scan::Fresh => self.fresh,
                }
            }
            fn outcome(&self) -> ScanOutcome {
                self.outcome.get()
            }
            fn group_alive(&self, _: &[u32]) -> TerminalHolder {
                self.group_asked.set(self.group_asked.get() + 1);
                self.group
            }
            fn arrivals(&self, _: &Path, _: &Terminal<'_>) -> TerminalHolder {
                self.arrivals_asked.set(self.arrivals_asked.get() + 1);
                self.arrivals
            }
        }

        struct Harness<'a> {
            exec: &'a Fake,
            probe: &'a dyn PidProbe,
            holders: &'a dyn TerminalHolders,
            canonical: &'a dyn Fn(&Path) -> CanonicalRefreshTokens,
            batch: usize,
            budget: std::time::Duration,
            now_secs: u64,
            boot_now: Option<crate::session::term_mint::BootId>,
        }

        impl<'a> Harness<'a> {
            fn new(exec: &'a Fake, probe: &'a dyn PidProbe) -> Self {
                Self {
                    exec,
                    probe,
                    holders: &FixedHolders(TerminalHolder::None),
                    canonical: &no_canonical,
                    batch: 40,
                    budget: LONG,
                    now_secs: NOW_SECS,
                    boot_now: Some(BOOT),
                }
            }
            fn run(&self, base: &Path, state: &mut OrphanSweepState) {
                sweep_orphans_with(
                    &SweepDeps {
                        exec: self.exec,
                        probe: self.probe,
                        holders: self.holders,
                        load_canonical: self.canonical,
                        boot_now: self.boot_now,
                        now_secs: self.now_secs,
                        batch_max: self.batch,
                        budget: self.budget,
                    },
                    base,
                    state,
                );
            }
        }

        /// RED against a sweep that considers items csq did not mint: an item
        /// for a FOREIGN config dir (a bench `coc-env`, a manual run) with an
        /// emptied payload, i.e. one every other rule would delete, must be
        /// neither read nor deleted.
        #[test]
        fn an_item_from_a_foreign_config_dir_survives() {
            let base = tempfile::tempdir().unwrap();
            let foreign =
                super::super::super::service_name(Path::new("/Users/u/coc-env/run-1/config-dir"));
            let foreign_term = super::super::super::service_name(Path::new(
                "/Users/u/elsewhere/accounts/term-54321",
            ));
            let exec = fake(vec![
                (foreign.clone(), content(&login("", "", 0))),
                (foreign_term.clone(), content(&login("", "", 0))),
            ]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(
                exec.finds.borrow().is_empty(),
                "a foreign item is never read"
            );
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.foreign_items, 2);
            assert_eq!(st.status.orphan_candidates, 0);
        }

        /// RED against a sweep that deletes on access-token expiry: the item's
        /// access token expired long ago but its refresh token is live and is
        /// NOT the canonical one, so it may be the only copy of that login.
        #[test]
        fn an_access_expired_item_with_a_live_non_canonical_refresh_token_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(
                svc,
                content(&login("old", "ref-live-elsewhere", LONG_DEAD)),
            )]);
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            let canonical = |_: &Path| canonical_of(&["ref-canonical"]);
            h.canonical = &canonical;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 1, "the item was examined");
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_sole_copy, 1);
        }

        /// RED against a sweep with no pid check: `term-54321` is gone but a
        /// process now holds pid 54321 (a reused pid, so a different pid-start
        /// than the terminal that wrote the item), so a new terminal may mint
        /// `term-54321` again.
        #[test]
        fn a_reused_term_pid_with_a_different_pid_start_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::new(&[(DEAD_PID, vec![PidOccupant::Present])]);
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty(), "not even read");
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_pid_in_use, 1);
        }

        /// RED against a sweep that trusts the dir-name pid alone: the launcher
        /// `term-54321` is dead and its dir was removed by hand, but a Claude
        /// Code child was launched with that config dir and is still alive, so its item
        /// must survive.
        #[test]
        fn an_item_whose_claude_child_outlived_the_launcher_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let holders = FixedHolders(TerminalHolder::Held);
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert!(
                exec.deletes.borrow().is_empty(),
                "a live child's item was deleted"
            );
            assert_eq!(st.status.kept_pid_in_use, 1);
            assert_eq!(st.status.deleted_total, 0);
        }

        /// A process table that cannot be read whole is not evidence of absence.
        #[test]
        fn an_item_is_kept_when_the_process_table_cannot_say() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let holders = FixedHolders(TerminalHolder::Unknown);
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_process_table_unknown, 1);
            assert_eq!(st.status.kept_other, 0);
        }

        /// RED against `unwrap_or(false)` on an unresolvable parent, and against a
        /// bare name (empty parent) that is not a match: the dir may be a spelling of
        /// the accounts dir, so the leaf name decides and the item is kept.
        #[test]
        fn an_unresolvable_or_empty_parent_with_the_term_leaf_still_holds() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            let leaf = format!("term-{DEAD_PID}");
            let gone = base.join("no-such-dir").join(&leaf);
            assert_eq!(
                holder_from_scan(&scan_of(vec![gone]), &base, &env_term(&pids)),
                TerminalHolder::Held,
                "unresolvable parent"
            );
            assert_eq!(
                holder_from_scan(
                    &scan_of(vec![PathBuf::from(&leaf)]),
                    &base,
                    &env_term(&pids)
                ),
                TerminalHolder::Held,
                "empty parent"
            );
            // And a resolvable parent that is NOT the accounts dir is not a holder.
            let elsewhere = tempfile::tempdir().unwrap();
            assert_eq!(
                holder_from_scan(
                    &scan_of(vec![elsewhere.path().canonicalize().unwrap().join(&leaf)]),
                    &base,
                    &env_term(&pids)
                ),
                TerminalHolder::None
            );
        }

        static SCANS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn counted_scan(
            _: std::time::Duration,
        ) -> Option<crate::sessions::macos::holders::ProcessEnvScan> {
            SCANS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(crate::sessions::macos::holders::ProcessEnvScan {
                complete: true,
                ..Default::default()
            })
        }
        fn unreadable_table(
            _: std::time::Duration,
        ) -> Option<crate::sessions::macos::holders::ProcessEnvScan> {
            None
        }

        /// One tick scan serves every candidate (corr L7); a fresh scan under the
        /// lock is a new read; a process table that cannot be read at all is
        /// Unknown on both paths, never None.
        #[test]
        fn the_production_witness_scans_once_per_tick_and_maps_an_unreadable_table_to_unknown() {
            let base = Path::new("/nonexistent-accounts");
            let pids = [DEAD_PID];
            let holders = OsTerminalHolders::with_scanner(counted_scan);
            let before = SCANS.load(std::sync::atomic::Ordering::SeqCst);
            for _ in 0..5 {
                assert_eq!(
                    holders.holder(base, &env_term(&pids), Scan::Tick),
                    TerminalHolder::None
                );
            }
            assert_eq!(SCANS.load(std::sync::atomic::Ordering::SeqCst), before + 1);
            assert_eq!(
                holders.holder(base, &env_term(&pids), Scan::Fresh),
                TerminalHolder::None
            );
            assert_eq!(SCANS.load(std::sync::atomic::Ordering::SeqCst), before + 2);

            let blind = OsTerminalHolders::with_scanner(unreadable_table);
            assert_eq!(
                blind.holder(base, &env_term(&pids), Scan::Tick),
                TerminalHolder::Unknown
            );
            assert_eq!(
                blind.holder(base, &env_term(&pids), Scan::Fresh),
                TerminalHolder::Unknown
            );
        }

        /// A witness that answers per scan kind: the tick scan and the scan under
        /// the lock can disagree (a process that appeared in between).
        struct PerScanHolders {
            tick: TerminalHolder,
            fresh: TerminalHolder,
        }
        impl TerminalHolders for PerScanHolders {
            fn holder(&self, _: &Path, _: &Terminal<'_>, scan: Scan) -> TerminalHolder {
                match scan {
                    Scan::Tick => self.tick,
                    Scan::Fresh => self.fresh,
                }
            }
            fn outcome(&self) -> ScanOutcome {
                ScanOutcome::NotScanned
            }
            fn group_alive(&self, _: &[u32]) -> TerminalHolder {
                TerminalHolder::None
            }
            fn arrivals(&self, _: &Path, _: &Terminal<'_>) -> TerminalHolder {
                TerminalHolder::None
            }
        }

        /// RED against a sweep whose only holder check precedes the lock: the
        /// terminal is free at the tick scan and held by the scan under the lock.
        /// The item was read (and re-read) and every other condition held, yet it
        /// survives.
        #[test]
        fn a_holder_that_appears_between_the_first_check_and_the_lock_keeps_the_item() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let holders = PerScanHolders {
                tick: TerminalHolder::None,
                fresh: TerminalHolder::Held,
            };
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 2, "read and re-read both ran");
            assert!(
                exec.deletes.borrow().is_empty(),
                "a holder seen under the lock did not stop the delete"
            );
            assert_eq!(st.status.kept_revived_after_read, 1);
            assert_eq!(st.status.deleted_total, 0);
        }

        /// The scan under the lock that cannot say keeps the item too.
        #[test]
        fn a_process_table_that_cannot_say_under_the_lock_keeps_the_item() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let holders = PerScanHolders {
                tick: TerminalHolder::None,
                fresh: TerminalHolder::Unknown,
            };
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_process_table_unknown, 1);
            assert_eq!(st.status.kept_other, 0);
        }

        // ── R3-2: killpg immediately before the delete ──────────────────────

        /// `killpg(pgrp, 0)`: a group that exists, or that the kernel will not answer for
        /// (`EPERM`), holds; `ESRCH` is no group; anything else, and a pid that cannot be a
        /// group id, is unknown. Held outranks unknown.
        #[test]
        fn a_process_group_is_held_on_success_or_eperm_and_unknown_on_any_other_errno() {
            let probe = |pgrp: i32| match pgrp {
                11 => Err(libc::ESRCH),
                12 => Err(libc::EPERM),
                13 => Ok(()),
                14 => Err(libc::EINVAL),
                other => panic!("probed a group the table did not expect: {other}"),
            };
            let state = |pids: &[u32]| process_group_state(pids, &probe);
            assert_eq!(state(&[11]), TerminalHolder::None, "ESRCH");
            assert_eq!(state(&[12]), TerminalHolder::Held, "EPERM");
            assert_eq!(state(&[13]), TerminalHolder::Held, "success");
            assert_eq!(state(&[14]), TerminalHolder::Unknown, "other errno");
            assert_eq!(state(&[11, 14]), TerminalHolder::Unknown);
            assert_eq!(
                state(&[14, 12]),
                TerminalHolder::Held,
                "held outranks unknown"
            );
            assert_eq!(state(&[11, 13]), TerminalHolder::Held, "any pid's group");
            // pid 0 would be this process's OWN group; above i32::MAX names none: never probed.
            assert_eq!(state(&[0]), TerminalHolder::Unknown);
            assert_eq!(state(&[u32::MAX]), TerminalHolder::Unknown);
            assert_eq!(state(&[]), TerminalHolder::None, "no pids, no group");
        }

        /// The real `killpg`: this process's own group exists; a group id above the kernel's
        /// `PID_MAX` does not.
        #[test]
        fn the_real_killpg_probe_sees_a_group_that_exists_and_one_that_does_not() {
            // SAFETY: getpgrp has no preconditions and cannot fail.
            let own = unsafe { libc::getpgrp() };
            assert_eq!(kill_group_probe(own), Ok(()));
            assert_eq!(kill_group_probe(2_000_000_000), Err(libc::ESRCH));
            assert_eq!(
                process_group_state(&[2_000_000_000], &kill_group_probe),
                TerminalHolder::None
            );
        }

        /// RED against a sweep that deletes on the scan alone (D237 R3-2): the scan listed no
        /// member of the terminal's group (its only member forked and exited between the list
        /// and the read), yet the kernel says the group exists right before the delete. The
        /// item is kept and counted as revived after the read; an unanswerable `killpg` keeps
        /// it as unknown; only "no such group" lets the delete run.
        #[test]
        fn a_group_that_exists_right_before_the_delete_keeps_the_item() {
            for (group, revived, unknown, deleted) in [
                (TerminalHolder::Held, 1, 0, 0),
                (TerminalHolder::Unknown, 0, 1, 0),
                (TerminalHolder::None, 0, 0, 1),
            ] {
                let base = tempfile::tempdir().unwrap();
                let svc = minted(base.path(), DEAD_PID);
                let exec = fake(vec![(svc, content(&login("", "", 0)))]);
                let probe = ScriptedProbe::all_absent();
                let holders = ScriptedHolders::new(group, ScanOutcome::NotScanned);
                let mut h = Harness::new(&exec, &probe);
                h.holders = &holders;
                let mut st = OrphanSweepState::default();
                h.run(base.path(), &mut st);
                assert_eq!(holders.group_asked.get(), 1, "{group:?}: asked once");
                assert_eq!(exec.deletes.borrow().len(), deleted, "{group:?}");
                assert_eq!(st.status.kept_revived_after_read, revived, "{group:?}");
                assert_eq!(st.status.kept_process_table_unknown, unknown, "{group:?}");
                assert_eq!(st.status.deleted_total, deleted, "{group:?}");
            }
        }

        /// RED against a sweep that deletes on the scan alone (S3): a process forked after the
        /// scan listed the table, whose creator then exited, is found by the pid list read
        /// again right before the delete. Held keeps (counted as revived after the read);
        /// unknown keeps (counted as the table not being readable whole); only a clean re-list
        /// lets the delete run, and it runs before `killpg`.
        #[test]
        fn a_process_forked_after_the_scan_keeps_the_item() {
            for (arrivals, revived, unknown, deleted, group_asked) in [
                (TerminalHolder::Held, 1, 0, 0, 0),
                (TerminalHolder::Unknown, 0, 1, 0, 0),
                (TerminalHolder::None, 0, 0, 1, 1),
            ] {
                let base = tempfile::tempdir().unwrap();
                let svc = minted(base.path(), DEAD_PID);
                let exec = fake(vec![(svc, content(&login("", "", 0)))]);
                let probe = ScriptedProbe::all_absent();
                let mut holders =
                    ScriptedHolders::new(TerminalHolder::None, ScanOutcome::NotScanned);
                holders.arrivals = arrivals;
                let mut h = Harness::new(&exec, &probe);
                h.holders = &holders;
                let mut st = OrphanSweepState::default();
                h.run(base.path(), &mut st);
                assert_eq!(holders.arrivals_asked.get(), 1, "{arrivals:?}: asked once");
                assert_eq!(holders.group_asked.get(), group_asked, "{arrivals:?}");
                assert_eq!(exec.deletes.borrow().len(), deleted, "{arrivals:?}");
                assert_eq!(st.status.kept_revived_after_read, revived, "{arrivals:?}");
                assert_eq!(
                    st.status.kept_process_table_unknown, unknown,
                    "{arrivals:?}"
                );
            }
        }

        // ── the production witness over scripted kernel reads ───────────────

        use crate::sessions::macos::holders::ProcessEnvScan;

        /// launchd, a readable process (800) and a tool shell (900) whose creator (777) is
        /// dead: the closed-terminal orphan.
        fn orphan_table(_: std::time::Duration) -> Option<ProcessEnvScan> {
            let mut scan = ProcessEnvScan {
                complete: true,
                ..Default::default()
            };
            for (pid, id, creator) in [(1u32, 1u64, 0u64), (800, 800, 1), (900, 900, 777)] {
                scan.lineage.insert(id, creator);
                scan.by_pid.insert(pid, id);
                scan.listed.insert(pid);
            }
            scan.max_id = 900;
            Some(scan)
        }
        /// launchd and one readable process: nothing with a dead creator.
        fn quiet_table(_: std::time::Duration) -> Option<ProcessEnvScan> {
            let mut scan = ProcessEnvScan {
                complete: true,
                ..Default::default()
            };
            for (pid, id, creator) in [(1u32, 1u64, 0u64), (800, 800, 1)] {
                scan.lineage.insert(id, creator);
                scan.by_pid.insert(pid, id);
                scan.listed.insert(pid);
            }
            scan.max_id = 800;
            Some(scan)
        }
        fn same_table(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
            Some(scan.clone())
        }
        fn no_group(_: i32) -> Result<(), i32> {
            Err(libc::ESRCH)
        }

        /// RED against a GLOBAL unknown (correctness HIGH-1): one orphan with a dead creator
        /// pinned every terminal on the host. Now it pins the terminals it could descend
        /// from and no others: the terminal whose launcher is newer than the dead creator is
        /// cleaned up on the same scan, and the cause is recorded for the one that is kept.
        #[test]
        fn a_dead_creator_orphan_pins_only_the_terminals_it_could_descend_from() {
            let base = tempfile::tempdir().unwrap();
            let older = minted_as(base.path(), DEAD_PID, Some((500, BOOT)));
            let newer = minted_as(base.path(), DEAD_PID + 1, Some((850, BOOT)));
            let exec = fake(vec![
                (older, content(&login("", "", 0))),
                (newer, content(&login("", "", 0))),
            ]);
            let probe = ScriptedProbe::all_absent();
            let holders = OsTerminalHolders::with_kernel(orphan_table, same_table, no_group);
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 1, "the newer terminal only");
            assert_eq!(st.status.deleted_total, 1);
            assert_eq!(st.status.kept_process_table_unknown, 1);
            assert_eq!(
                st.status.process_table_unknown,
                Some(ProcessTableUnknown::LineageBroken)
            );
            // What stays is the OLDER terminal's item; the newer one's ledger bit is gone.
            let ledger = crate::session::term_mint::read_ledger(base.path()).unwrap();
            assert!(ledger.contains(DEAD_PID) && !ledger.contains(DEAD_PID + 1));
        }

        /// The scan is not a snapshot (D237 R2, correctness HIGH-A / security R2-1). A listed
        /// descendant `G0` (id 900) forks `G1` and exits before its own read, so the scan
        /// neither holds it nor sees `G1`. The item is kept this cycle (the re-list finds `G1`,
        /// whose creator is dead); a later cycle meets `G2`, forked by the dead `G1`. No cycle
        /// may delete, and nothing a cycle leaves behind may make the next one decide
        /// differently. RED against a sweep that records, from a "clean" scan, how far its
        /// claim reaches (the withdrawn descent-free latch): that record read `G2` as forked
        /// after a proof which never saw `G1`, and deleted while `G2` ran.
        #[test]
        fn a_descendant_that_forks_and_vanishes_between_two_scans_never_yields_a_delete() {
            /// Launcher 500 is dead. `G0` (pid 4000) was listed and gone before its read.
            fn first_scan(_: std::time::Duration) -> Option<ProcessEnvScan> {
                let mut scan = ProcessEnvScan {
                    complete: true,
                    ..Default::default()
                };
                for (pid, id, creator) in [(1u32, 1u64, 0u64), (800, 800, 1)] {
                    scan.lineage.insert(id, creator);
                    scan.by_pid.insert(pid, id);
                    scan.listed.insert(pid);
                }
                scan.listed.insert(4000);
                scan.max_id = 800;
                Some(scan)
            }
            /// The re-list finds `G1` (id 1700), forked by the vanished `G0` (id 900).
            fn first_relist(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
                use crate::sessions::macos::{Probe, Uniq};
                Some(scan.with_arrivals(&[4001], &|_| {
                    Probe::Got(Uniq {
                        uniqueid: 1700,
                        puniqueid: 900,
                    })
                }))
            }
            /// Later: `G1` is gone too, and `G2` (id 2000) runs, forked by the dead `G1`.
            fn second_scan(_: std::time::Duration) -> Option<ProcessEnvScan> {
                let mut scan = ProcessEnvScan {
                    complete: true,
                    ..Default::default()
                };
                for (pid, id, creator) in [(1u32, 1u64, 0u64), (800, 800, 1), (4002, 2000, 1700)] {
                    scan.lineage.insert(id, creator);
                    scan.by_pid.insert(pid, id);
                    scan.listed.insert(pid);
                }
                scan.max_id = 2000;
                Some(scan)
            }
            let base = tempfile::tempdir().unwrap();
            let svc = minted_as(base.path(), DEAD_PID, Some((500, BOOT)));
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            type Scanner = fn(std::time::Duration) -> Option<ProcessEnvScan>;
            type Relister = fn(&ProcessEnvScan) -> Option<ProcessEnvScan>;
            let cycles: [(u32, Scanner, Relister); 2] =
                [(1, first_scan, first_relist), (2, second_scan, same_table)];
            for (cycle, scan, relist) in cycles {
                let holders = OsTerminalHolders::with_kernel(scan, relist, no_group);
                let mut h = Harness::new(&exec, &probe);
                h.holders = &holders;
                let mut st = OrphanSweepState::default();
                h.run(base.path(), &mut st);
                assert!(exec.deletes.borrow().is_empty(), "cycle {cycle}: no delete");
                assert_eq!(st.status.deleted_total, 0, "cycle {cycle}");
                assert_eq!(
                    st.status.kept_process_table_unknown, 1,
                    "cycle {cycle}: kept because the lineage cannot rule the terminal out"
                );
                assert_eq!(
                    st.status.process_table_unknown,
                    Some(ProcessTableUnknown::LineageBroken),
                    "cycle {cycle}"
                );
            }
        }

        /// Legacy entries are unknown PER TERMINAL (guard-reader-writer-parity MUST-5): a
        /// ledger bit csq has no launcher id for keeps its own terminal and no other, with the
        /// cause named, until the Mac restarts; after a restart its launcher (and everything
        /// it started) is gone and the terminal is decided on environment and group alone.
        #[test]
        fn a_bit_without_a_launcher_id_keeps_only_its_own_terminal_until_a_restart() {
            let base = tempfile::tempdir().unwrap();
            let legacy = minted_as(base.path(), DEAD_PID, Some((0, BOOT)));
            let recorded = minted_as(base.path(), DEAD_PID + 1, Some((850, BOOT)));
            let exec = fake(vec![
                (legacy, content(&login("", "", 0))),
                (recorded, content(&login("", "", 0))),
            ]);
            let probe = ScriptedProbe::all_absent();
            let holders = OsTerminalHolders::with_kernel(quiet_table, same_table, no_group);
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 1, "only the recorded terminal");
            assert_eq!(st.status.kept_process_table_unknown, 1);
            assert_eq!(
                st.status.process_table_unknown,
                Some(ProcessTableUnknown::LauncherUnrecorded)
            );

            // After a restart the legacy launcher belongs to an earlier boot session.
            let holders = OsTerminalHolders::with_kernel(quiet_table, same_table, no_group);
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            h.boot_now = Some(NEXT_BOOT);
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 2, "now the legacy one too");
            assert_eq!(st.status.process_table_unknown, None);
        }

        /// The re-list through the production witness: a process forked since the scan by the
        /// launcher itself holds the terminal; one forked by a process the scan has, whose chain ends at launchd, is unknown (an arrival is opaque);
        /// one with a dead creator is unknown with the lineage cause; a re-list that cannot
        /// read the table, or no fresh scan to extend, is unknown.
        #[test]
        fn the_re_list_extends_the_fresh_scan_with_what_was_forked_since() {
            fn forked_by_launcher(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
                use crate::sessions::macos::{Probe, Uniq};
                Some(scan.with_arrivals(&[4242], &|_| {
                    Probe::Got(Uniq {
                        uniqueid: 1700,
                        puniqueid: 500,
                    })
                }))
            }
            fn forked_by_old_process(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
                use crate::sessions::macos::{Probe, Uniq};
                Some(scan.with_arrivals(&[4242], &|_| {
                    Probe::Got(Uniq {
                        uniqueid: 1700,
                        puniqueid: 800,
                    })
                }))
            }
            fn forked_by_dead(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
                use crate::sessions::macos::{Probe, Uniq};
                Some(scan.with_arrivals(&[4242], &|_| {
                    Probe::Got(Uniq {
                        uniqueid: 1700,
                        puniqueid: 1650,
                    })
                }))
            }
            fn cannot_list(_: &ProcessEnvScan) -> Option<ProcessEnvScan> {
                None
            }
            let base = Path::new("/nonexistent-accounts");
            let pids = [DEAD_PID];
            let me = term_of(&pids, 500);
            let ask = |relister: fn(&ProcessEnvScan) -> Option<ProcessEnvScan>, fresh: bool| {
                let holders = OsTerminalHolders::with_kernel(quiet_table, relister, no_group);
                if fresh {
                    assert_eq!(
                        holders.holder(base, &me, Scan::Fresh),
                        TerminalHolder::None,
                        "the fresh scan itself is clear"
                    );
                }
                (holders.arrivals(base, &me), holders.outcome())
            };
            assert_eq!(ask(forked_by_launcher, true).0, TerminalHolder::Held);
            // An arrival is never read, so it is opaque: its chain (800, forked by launchd)
            // ends at launchd and cannot clear it, as the kernel may have rewritten a link.
            assert_eq!(ask(forked_by_old_process, true).0, TerminalHolder::Unknown);
            let (verdict, outcome) = ask(forked_by_dead, true);
            assert_eq!(verdict, TerminalHolder::Unknown);
            assert_eq!(
                outcome,
                ScanOutcome::Unknown(UnknownReason::of(ProcessTableUnknown::LineageBroken, 1))
            );
            let (verdict, outcome) = ask(cannot_list, true);
            assert_eq!(verdict, TerminalHolder::Unknown);
            assert_eq!(
                outcome,
                ScanOutcome::Unknown(UnknownReason::of(ProcessTableUnknown::TableUnreadable, 0))
            );
            // No fresh scan to extend: unknown, never "nothing new".
            assert_eq!(ask(same_table, false).0, TerminalHolder::Unknown);
        }

        /// S4: a `killpg` the kernel will not answer keeps the item AND says why. RED against
        /// a witness whose group check records nothing (the summary then reads "the cause was
        /// not recorded"). Pid 0 names no group the sweep may ask about.
        #[test]
        fn an_unanswerable_killpg_records_its_cause() {
            let holders = OsTerminalHolders::with_kernel(orphan_table, same_table, no_group);
            assert_eq!(holders.group_alive(&[DEAD_PID]), TerminalHolder::None);
            assert_eq!(holders.outcome(), ScanOutcome::NotScanned, "control: none");
            assert_eq!(holders.group_alive(&[0]), TerminalHolder::Unknown);
            assert_eq!(
                holders.outcome(),
                ScanOutcome::Unknown(UnknownReason::of(
                    ProcessTableUnknown::ProcessGroupUnknown,
                    0
                ))
            );
        }

        // ── D: the unknown state ages and its signal is latched ─────────────

        fn reason(cause: ProcessTableUnknown) -> UnknownReason {
            UnknownReason::of(cause, 2)
        }

        /// The transition is a pure function of the previous published state and the tick's
        /// outcome, so the warn is logged when it changes and not on every tick. RED against
        /// a signal that fires per scan: the repeated unknown tick is `Unchanged`.
        #[test]
        fn the_operator_signal_fires_on_a_transition_not_on_every_tick() {
            use ProcessTableUnknown::{LineageBroken, ScanIncomplete};
            let mut st = OrphanSweepState::default();
            let mut step = |outcome, now| track_process_table(&mut st, outcome, now);
            assert_eq!(
                step(ScanOutcome::NotScanned, 10),
                TableTransition::Unchanged
            );
            let env = reason(LineageBroken);
            assert_eq!(
                step(ScanOutcome::Unknown(env), 20),
                TableTransition::Entered(env)
            );
            assert_eq!(
                step(ScanOutcome::Unknown(env), 30),
                TableTransition::Unchanged,
                "the same reason again: no new signal"
            );
            assert_eq!(
                step(ScanOutcome::NotScanned, 40),
                TableTransition::Unchanged
            );
            let late = reason(ScanIncomplete);
            assert_eq!(
                step(ScanOutcome::Unknown(late), 50),
                TableTransition::Changed(late),
                "a different reason is a transition"
            );
            assert_eq!(step(ScanOutcome::Whole, 60), TableTransition::Recovered);
            assert_eq!(step(ScanOutcome::Whole, 70), TableTransition::Unchanged);
            assert_eq!(st.status.process_table_unknown, None);
            assert_eq!(st.status.process_table_unknown_since_unix_secs, None);
        }

        /// The since-timestamp is the first unknown tick of the run, not the latest, so it
        /// ages: RED against a state that restamps on every unknown tick (never reaches the
        /// threshold). It survives re-enumeration, reaches "needs action" after the same
        /// threshold `undetermined` uses (not a second earlier), and a whole scan clears it.
        #[test]
        fn an_unknown_table_ages_into_needs_action_and_a_whole_scan_clears_it() {
            let base = tempfile::tempdir().unwrap();
            let exec = fake(vec![]);
            let probe = ScriptedProbe::all_absent();
            let holders = ScriptedHolders::new(
                TerminalHolder::None,
                ScanOutcome::Unknown(reason(ProcessTableUnknown::LineageBroken)),
            );
            let mut h = Harness::new(&exec, &probe);
            h.holders = &holders;
            let mut st = OrphanSweepState::default();
            let level_at = |st: &OrphanSweepState, now| {
                write_status(base.path(), &st.status);
                let diag = read_diagnostic_at(base.path(), now);
                (diag.level(), diag.summary().unwrap())
            };

            h.now_secs = NOW_SECS;
            h.run(base.path(), &mut st);
            assert_eq!(
                st.status.process_table_unknown,
                Some(ProcessTableUnknown::LineageBroken)
            );
            assert_eq!(
                st.status.process_table_unknown_since_unix_secs,
                Some(NOW_SECS)
            );
            let (level, text) = level_at(&st, NOW_SECS);
            assert_eq!(level, Some(DiagnosticLevel::Warn));
            assert!(text.starts_with("cleanup is paused"), "{text}");

            // Ticks across several enumerations keep the ORIGINAL start.
            for step in 1..3 {
                h.now_secs = NOW_SECS + step * ORPHAN_REENUMERATE_SECS;
                h.run(base.path(), &mut st);
            }
            assert_eq!(
                st.status.process_table_unknown_since_unix_secs,
                Some(NOW_SECS)
            );
            assert_eq!(level_at(&st, h.now_secs).0, Some(DiagnosticLevel::Warn));

            h.now_secs = NOW_SECS + ORPHAN_NEEDS_ACTION_SECS;
            h.run(base.path(), &mut st);
            let (level, text) = level_at(&st, h.now_secs);
            assert_eq!(level, Some(DiagnosticLevel::NeedsAction), "{text}");
            assert!(text.starts_with("needs action"), "{text}");
            assert!(text.contains("30 min"), "{text}");
            assert!(
                text.contains(ProcessTableUnknown::LineageBroken.describe()),
                "{text}"
            );

            holders.outcome.set(ScanOutcome::Whole);
            h.now_secs += 1;
            h.run(base.path(), &mut st);
            assert_eq!(st.status.process_table_unknown, None);
            let (level, _) = level_at(&st, h.now_secs);
            assert_eq!(level, Some(DiagnosticLevel::Ok));
        }

        /// A cycle that drained without needing a scan has no table to be unable to read: a
        /// stale unknown state is cleared. Control: while candidates are still pending the
        /// state is NOT cleared, so this is not a blanket reset.
        #[test]
        fn a_drained_cycle_that_needed_no_scan_clears_a_stale_unknown_state() {
            let stale = |st: &mut OrphanSweepState| {
                st.status.process_table_unknown = Some(ProcessTableUnknown::ScanIncomplete);
                st.status.process_table_unknown_since_unix_secs = Some(1);
            };
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            // Control: nothing is examined (batch 0), the candidate is still queued.
            h.batch = 0;
            let mut pending = OrphanSweepState::default();
            stale(&mut pending);
            h.run(base.path(), &mut pending);
            assert_eq!(pending.pending.len(), 1);
            assert_eq!(
                pending.status.process_table_unknown,
                Some(ProcessTableUnknown::ScanIncomplete),
                "work is still queued: the state stands"
            );
            // Drained without a scan: the candidate is a sole copy and never reaches the scan.
            let exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("live", "sole", u64::MAX / 2)),
            )]);
            let h = Harness::new(&exec, &probe);
            let mut drained = OrphanSweepState::default();
            stale(&mut drained);
            h.run(base.path(), &mut drained);
            assert!(drained.pending.is_empty());
            assert_eq!(drained.status.kept_sole_copy, 1, "no scan was needed");
            assert_eq!(drained.status.process_table_unknown, None);
            assert_eq!(drained.status.process_table_unknown_since_unix_secs, None);
        }

        /// The production witness reports what its scans found: nothing before one, whole
        /// after a whole one, and the first unknown stays against a later whole scan.
        #[test]
        fn the_production_witness_reports_the_outcome_of_its_scans() {
            fn incomplete(
                _: std::time::Duration,
            ) -> Option<crate::sessions::macos::holders::ProcessEnvScan> {
                Some(crate::sessions::macos::holders::ProcessEnvScan {
                    complete: false,
                    ..Default::default()
                })
            }
            let base = Path::new("/nonexistent-accounts");
            let pids = [DEAD_PID];
            let whole = OsTerminalHolders::with_scanner(counted_scan);
            assert_eq!(whole.outcome(), ScanOutcome::NotScanned);
            whole.holder(base, &env_term(&pids), Scan::Tick);
            assert_eq!(whole.outcome(), ScanOutcome::Whole);

            let blind = OsTerminalHolders::with_scanner(unreadable_table);
            blind.holder(base, &env_term(&pids), Scan::Tick);
            assert_eq!(
                blind.outcome(),
                ScanOutcome::Unknown(reason_of(ProcessTableUnknown::TableUnreadable))
            );

            let slow = OsTerminalHolders::with_scanner(incomplete);
            slow.holder(base, &env_term(&pids), Scan::Fresh);
            let ScanOutcome::Unknown(why) = slow.outcome() else {
                panic!("an incomplete scan is unknown");
            };
            assert_eq!(why.cause, ProcessTableUnknown::ScanIncomplete);
        }

        fn reason_of(cause: ProcessTableUnknown) -> UnknownReason {
            UnknownReason::of(cause, 0)
        }

        // ── E: the summary says which kind of unknown it is ─────────────────

        /// A pid table that could not be read says so; it does not name an environment or a
        /// timeout that never happened (R3-4). Each cause has its own fixed sentence, and
        /// a status with no recorded cause says that.
        #[test]
        fn the_summary_names_the_cause_that_applies() {
            let text = |cause: Option<ProcessTableUnknown>| {
                let status = OrphanSweepStatus {
                    keychain_items: 3,
                    orphan_candidates: 1,
                    kept_process_table_unknown: 1,
                    process_table_unknown: cause,
                    ..Default::default()
                };
                OrphanDiagnostic {
                    status: Some(status),
                    error: None,
                    age_secs: Some(0),
                }
                .summary()
                .unwrap()
            };
            let table = text(Some(ProcessTableUnknown::TableUnreadable));
            assert!(
                table.contains("the list of running processes could not be read"),
                "{table}"
            );
            assert!(!table.contains("environment"), "{table}");
            assert!(!table.contains("ran out of time"), "{table}");
            let lineage = text(Some(ProcessTableUnknown::LineageBroken));
            assert!(
                lineage
                    .contains("a process started after the terminal may have been started by it"),
                "{lineage}"
            );
            assert!(!lineage.contains("list of running processes"), "{lineage}");
            let launcher = text(Some(ProcessTableUnknown::LauncherUnrecorded));
            assert!(
                launcher
                    .contains("csq recorded nothing about the process that started the terminal"),
                "{launcher}"
            );
            let group = text(Some(ProcessTableUnknown::ProcessGroupUnknown));
            assert!(group.contains("process group still exists"), "{group}");
            let other = text(Some(ProcessTableUnknown::ProcessUnreadable));
            assert!(
                other.contains("some process's environment or identity could not be read"),
                "{other}"
            );
            let late = text(Some(ProcessTableUnknown::ScanIncomplete));
            assert!(late.contains("the scan ran out of time"), "{late}");
            assert!(!late.contains("environment"), "{late}");
            assert!(
                text(None).contains("the cause was not recorded"),
                "an old status file says its cause was not recorded"
            );
        }

        fn scan_of(dirs: Vec<PathBuf>) -> crate::sessions::macos::holders::ProcessEnvScan {
            crate::sessions::macos::holders::ProcessEnvScan {
                config_dirs: dirs,
                complete: true,
                ..Default::default()
            }
        }

        /// RED against an exact-case leaf compare: on a case-insensitive volume
        /// `Term-<pid>` is the same directory, so a case-only difference holds.
        #[test]
        fn a_case_only_difference_in_the_leaf_still_holds_the_terminal() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            for leaf in [format!("TERM-{DEAD_PID}"), format!("Term-{DEAD_PID}")] {
                assert_eq!(
                    holder_from_scan(&scan_of(vec![base.join(&leaf)]), &base, &env_term(&pids)),
                    TerminalHolder::Held,
                    "{leaf}"
                );
            }
            // A different pid is still not a holder, whatever the case.
            let other = base.join(format!("TERM-{}", DEAD_PID + 1));
            assert_eq!(
                holder_from_scan(&scan_of(vec![other]), &base, &env_term(&pids)),
                TerminalHolder::None
            );
        }

        /// The parent compare ignores case too: a re-cased spelling of the accounts
        /// dir that resolves is the same dir on a case-insensitive volume.
        #[test]
        fn the_parent_comparison_ignores_case() {
            let a = Path::new("/Users/X/.claude/accounts");
            assert!(same_ignoring_case(
                a,
                Path::new("/users/x/.CLAUDE/Accounts")
            ));
            assert!(!same_ignoring_case(
                a,
                Path::new("/users/x/.claude/accounts2")
            ));
        }

        /// A relative value joined onto the process's own cwd (what the scan
        /// stores) lands on the term dir through `..`; the same value from a cwd
        /// elsewhere does not.
        #[test]
        fn a_relative_value_resolved_on_its_cwd_holds_only_when_it_lands_on_the_term_dir() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let work = base.join("work");
            std::fs::create_dir(&work).unwrap();
            let pids = [DEAD_PID];
            let rel = format!("../term-{DEAD_PID}");
            assert_eq!(
                holder_from_scan(&scan_of(vec![work.join(&rel)]), &base, &env_term(&pids)),
                TerminalHolder::Held
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let there = elsewhere.path().canonicalize().unwrap().join("w");
            std::fs::create_dir(&there).unwrap();
            assert_eq!(
                holder_from_scan(&scan_of(vec![there.join(&rel)]), &base, &env_term(&pids)),
                TerminalHolder::None
            );
        }

        /// The production witness over a scan: only a process on THIS accounts
        /// dir's `term-<pid>` for a candidate pid holds it, and anything the scan
        /// cannot say is Unknown, never None.
        #[test]
        fn holder_from_scan_separates_held_none_and_unknown() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            let term = base.join(format!("term-{DEAD_PID}"));
            let other_pid = base.join(format!("term-{}", DEAD_PID + 1));
            let elsewhere = tempfile::tempdir().unwrap();
            let same_name_elsewhere = elsewhere.path().join(format!("term-{DEAD_PID}"));

            assert_eq!(
                holder_from_scan(&scan_of(vec![term.clone()]), &base, &env_term(&pids)),
                TerminalHolder::Held
            );
            let none = scan_of(vec![other_pid, same_name_elsewhere, base.join("config-3")]);
            assert_eq!(
                holder_from_scan(&none, &base, &env_term(&pids)),
                TerminalHolder::None
            );

            let mut unreadable = scan_of(Vec::new());
            unreadable.unreadable = 1;
            assert_eq!(
                holder_from_scan(&unreadable, &base, &env_term(&pids)),
                TerminalHolder::Unknown
            );
            let mut incomplete = scan_of(Vec::new());
            incomplete.complete = false;
            assert_eq!(
                holder_from_scan(&incomplete, &base, &env_term(&pids)),
                TerminalHolder::Unknown
            );
            // A found holder wins over an unreadable sibling.
            let mut both = scan_of(vec![term]);
            both.unreadable = 2;
            assert_eq!(
                holder_from_scan(&both, &base, &env_term(&pids)),
                TerminalHolder::Held
            );
        }

        /// KERN_PROCARGS2 bytes for a withheld environment: argc, exec path, argv, no env.
        fn withheld_env(exec: &str, argv: &[&str]) -> Vec<u8> {
            let mut b = u32::try_from(argv.len()).unwrap().to_ne_bytes().to_vec();
            b.extend_from_slice(exec.as_bytes());
            b.extend_from_slice(&[0, 0, 0]);
            for a in argv {
                b.extend_from_slice(a.as_bytes());
                b.push(0);
            }
            b.extend_from_slice(&[0, 0]);
            b
        }

        /// A KERN_PROCARGS2 block with a readable environment.
        fn readable_env(exec: &str, env: &[&str]) -> Vec<u8> {
            let mut b = 1u32.to_ne_bytes().to_vec();
            b.extend_from_slice(exec.as_bytes());
            b.extend_from_slice(&[0, 0, 0]);
            b.extend_from_slice(b"x\0");
            for e in env {
                b.extend_from_slice(e.as_bytes());
                b.push(0);
            }
            b.extend_from_slice(&[0, 0]);
            b
        }

        /// The scan of a withheld `/bin/sh` (pid 900, unique id 900) in process group `group`,
        /// created by the process with unique id `creator`. The table also holds a readable
        /// `claude`-like process (pid 800, unique id 800, created by launchd) and launchd
        /// (pid 1, unique id 1, root), so `creator` can be 800 (alive), 1 (launchd-born) or
        /// anything else (dead).
        fn shell_scan(group: u32, creator: u64) -> crate::sessions::macos::holders::ProcessEnvScan {
            use crate::sessions::macos::holders::{scan_via, HolderReads};
            use crate::sessions::macos::{BsdFacts, Probe, Uniq};
            let mut args = |pid: u32| {
                if pid == 900 {
                    Probe::Got(withheld_env("/bin/sh", &["sh"]))
                } else {
                    Probe::Got(readable_env("/Users/u/bin/claude", &["PATH=/usr/bin"]))
                }
            };
            let mut reads = HolderReads {
                bsd: &|pid| {
                    Probe::Got(BsdFacts {
                        pid,
                        uid: if pid == 1 { 0 } else { 501 },
                        start: 1_790_000_000,
                        tdev: crate::sessions::macos::NODEV,
                        claude_named: false,
                        codex_named: false,
                        zombie: false,
                        pgid: if pid == 900 { group } else { 1 },
                    })
                },
                args: &mut args,
                uniq: &|pid| {
                    Probe::Got(Uniq {
                        uniqueid: u64::from(pid),
                        puniqueid: match pid {
                            900 => creator,
                            800 => 1,
                            _ => 0,
                        },
                    })
                },
                cwd: &|_| None,
            };
            scan_via(
                &[900, 800, 1],
                501,
                std::time::Instant::now() + std::time::Duration::from_secs(60),
                &mut reads,
            )
        }

        /// RED against a holder check that reads environments only (D237 R2 sec N1): a
        /// `/bin/sh` still in the dead launcher's process group, its environment withheld,
        /// can start the next `claude` on `term-N`. It holds the item through its group,
        /// whatever its image or environment; a shell in another group does not.
        #[test]
        fn a_system_binary_in_the_terminals_process_group_holds_the_item() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            // The shell was started by launchd and names no config dir, so neither the
            // environment nor its lineage holds the item: only the group can.
            let in_group = shell_scan(DEAD_PID, 1);
            assert!(
                in_group.complete && in_group.unreadable == 0 && in_group.config_dirs.is_empty(),
                "the shell inherited nothing: only its group can hold the item"
            );
            assert_eq!(
                holder_from_scan(&in_group, &base, &term_of(&pids, 500)),
                TerminalHolder::Held
            );
            assert_eq!(
                holder_from_scan(&shell_scan(DEAD_PID + 1, 400), &base, &term_of(&pids, 500)),
                TerminalHolder::None,
                "control: the same shell in another group, forked before the launcher, holds nothing"
            );
        }

        /// RED against the blanket system-image exception (D237 R3 F1), against a walk of the
        /// current parent, and against an attribution through the nearest readable ancestor: a
        /// Claude Code tool shell leads a process group of its own (measured: `/bin/zsh` pgid
        /// == its pid), so the group witness cannot see it, and macOS withholds its
        /// environment. It holds the terminal when it DESCENDS from the terminal's launcher
        /// (unique id 500, dead): forked by it directly, or through a chain of live links.
        /// A shell forked before the launcher, or by launchd, holds nothing (the sweep is not
        /// inert); one whose dead creator is above the launcher's id is unknown for THIS
        /// terminal and decided for a newer one on the same scan.
        #[test]
        fn a_withheld_tool_shell_holds_the_terminal_it_descends_from() {
            use crate::session::term_mint::LauncherBasis;
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            let me = term_of(&pids, 500);
            // Its own group (900), not the terminal's: the group witness is silent.
            let held = shell_scan(900, 500);
            assert!(!held.process_groups.contains(&DEAD_PID));
            assert_eq!(holder_from_scan(&held, &base, &me), TerminalHolder::Held);
            assert_eq!(
                holder_from_scan(&shell_scan(900, 400), &base, &me),
                TerminalHolder::None,
                "forked by something older than the launcher"
            );
            // The kernel sometimes rewrites a reparented process's creator id to launchd's,
            // so a hidden-env same-uid shell above the launcher's id that reads launchd as
            // its creator may be the launcher's orphan: keep.
            assert_eq!(
                holder_from_scan(&shell_scan(900, 1), &base, &me),
                TerminalHolder::Unknown,
                "creator reads launchd and the environment is hidden: it may be an orphan"
            );
            assert_eq!(
                holder_from_scan(&shell_scan(900, 800), &base, &me),
                TerminalHolder::Unknown,
                "hidden leaf behind a live readable link that launchd forked: the creator id \
                 may have been rewritten at either link"
            );
            let broken = shell_scan(900, 777);
            assert_eq!(
                holder_from_scan(&broken, &base, &me),
                TerminalHolder::Unknown,
                "creator dead and above the launcher's id: it may descend, keep"
            );
            assert_eq!(
                holder_from_scan(&broken, &base, &term_of(&pids, 850)),
                TerminalHolder::None,
                "the same scan, a terminal whose launcher is newer than that creator: decided"
            );
            assert_eq!(
                judge(&broken, &base, &me),
                Judgement::Unknown(UnknownReason::of(ProcessTableUnknown::LineageBroken, 1))
            );
            // A launcher minted in an earlier boot has no live descendant, whatever the ids.
            assert_eq!(
                holder_from_scan(&held, &base, &env_term(&pids)),
                TerminalHolder::None
            );
            // Nothing recorded about the launcher: no process can be ruled out.
            let unrecorded = Terminal {
                pids: &pids,
                launchers: vec![(DEAD_PID, LauncherBasis::Unrecorded)],
            };
            assert_eq!(
                judge(&shell_scan(900, 1), &base, &unrecorded),
                Judgement::Unknown(UnknownReason::of(
                    ProcessTableUnknown::LauncherUnrecorded,
                    1
                ))
            );
            // Held outranks Unknown: one launcher held, another unrecorded.
            let both = Terminal {
                pids: &pids,
                launchers: vec![
                    (DEAD_PID, LauncherBasis::Unrecorded),
                    (DEAD_PID + 1, LauncherBasis::SameBoot { uniqueid: 500 }),
                ],
            };
            assert_eq!(holder_from_scan(&held, &base, &both), TerminalHolder::Held);
        }

        /// A scan that cannot be relied on is unknown for EVERY terminal, descent or not; a
        /// damaged table is not trusted to say "held" or "clear" by descent.
        #[test]
        fn an_unreliable_scan_is_unknown_for_every_terminal() {
            use crate::sessions::macos::holders::ProcessEnvScan;
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let pids = [DEAD_PID];
            let me = term_of(&pids, 500);
            let unknown = |scan: &ProcessEnvScan, cause: ProcessTableUnknown| {
                assert_eq!(
                    judge(scan, &base, &me),
                    Judgement::Unknown(UnknownReason::of(cause, scan.unreadable)),
                    "{scan:?}"
                );
            };
            let mut whole = shell_scan(900, 400);
            assert_eq!(judge(&whole, &base, &me), Judgement::Clear, "control");
            whole.unreadable = 2;
            unknown(&whole, ProcessTableUnknown::ProcessUnreadable);
            let mut slow = shell_scan(900, 400);
            slow.complete = false;
            unknown(&slow, ProcessTableUnknown::ScanIncomplete);
            let mut damaged = shell_scan(900, 500);
            damaged.damaged = true;
            unknown(&damaged, ProcessTableUnknown::ProcessUnreadable);
        }

        /// The operator signal names WHY the sweep keeps items, in fixed vocabulary and
        /// counts. A whole table has no reason; the pid table itself unreadable, another
        /// unreadable process (or a table that contradicts itself) and a budget overrun each
        /// have their own token. None of it can carry a pid, a path or a value: the type
        /// holds a token and one count.
        #[test]
        fn the_unknown_reason_is_a_fixed_token_and_a_count() {
            use crate::sessions::macos::holders::ProcessEnvScan;
            let whole = ProcessEnvScan {
                complete: true,
                ..Default::default()
            };
            assert_eq!(unknown_reason(Some(&whole)), None);
            let reason = |scan: ProcessEnvScan| unknown_reason(Some(&scan)).unwrap();
            assert_eq!(unknown_reason(None).unwrap().token(), "table_unreadable");
            let other = reason(ProcessEnvScan {
                unreadable: 3,
                complete: true,
                ..Default::default()
            });
            assert_eq!((other.token(), other.blocking), ("process_unreadable", 3));
            let damaged = reason(ProcessEnvScan {
                damaged: true,
                complete: true,
                ..Default::default()
            });
            assert_eq!(
                (damaged.token(), damaged.blocking),
                ("process_unreadable", 0)
            );
            let late = reason(ProcessEnvScan {
                complete: false,
                ..Default::default()
            });
            assert_eq!((late.token(), late.blocking), ("scan_incomplete", 0));
            // The per-terminal causes are never a property of the table.
            for cause in [
                ProcessTableUnknown::LineageBroken,
                ProcessTableUnknown::LauncherUnrecorded,
                ProcessTableUnknown::ProcessGroupUnknown,
            ] {
                assert!(!cause.token().is_empty());
                assert!(
                    !cause.remedy().is_empty() && !cause.describe().is_empty(),
                    "{cause:?}"
                );
            }
        }

        /// RED against a sweep whose only pid sample precedes the read: the pid
        /// is free at the first sample and taken at the second.
        #[test]
        fn a_pid_taken_between_the_read_and_the_delete_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe =
                ScriptedProbe::new(&[(DEAD_PID, vec![PidOccupant::Absent, PidOccupant::Present])]);
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 1);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_revived_after_read, 1);
        }

        /// RED against a sweep with no check immediately before the delete: a
        /// terminal mints `term-54321` WHILE the item is being read.
        #[test]
        fn a_dir_created_between_the_read_and_the_delete_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let term = base
                .path()
                .join(crate::session::handle_dir::term_handle_dir_name(DEAD_PID));
            *exec.on_find.borrow_mut() = Some(Box::new(move || {
                std::fs::create_dir(&term).unwrap();
            }));
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 1);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_revived_after_read, 1);
        }

        /// The canonical copy disappearing between the read and the delete (a
        /// logout) turns a "copy exists" delete into a keep.
        #[test]
        fn a_canonical_copy_removed_before_the_delete_keeps_the_item() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(
                svc,
                content(&login("a", "ref-canonical", LONG_DEAD)),
            )]);
            let probe = ScriptedProbe::all_absent();
            let calls = std::cell::Cell::new(0);
            let canonical = |_: &Path| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    canonical_of(&["ref-canonical"])
                } else {
                    canonical_of(&[])
                }
            };
            let mut h = Harness::new(&exec, &probe);
            h.canonical = &canonical;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_sole_copy, 1);
        }

        /// The positive paths: csq-minted, dir gone, pid free, and either no
        /// login or a refresh token byte-equal to the canonical one.
        #[test]
        fn a_provably_dead_minted_item_with_a_copy_elsewhere_is_deleted() {
            let base = tempfile::tempdir().unwrap();
            let with_copy = minted(base.path(), 11_111);
            let no_login = minted(base.path(), 22_222);
            let exec = fake(vec![
                (
                    with_copy.clone(),
                    content(&login("x", "ref-canonical", LONG_DEAD)),
                ),
                (no_login.clone(), content(&login("", "", 0))),
            ]);
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            let canonical = |_: &Path| canonical_of(&["ref-canonical"]);
            h.canonical = &canonical;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            let mut deleted = exec.deletes.borrow().clone();
            deleted.sort();
            let mut expected = vec![with_copy, no_login];
            expected.sort();
            assert_eq!(deleted, expected);
            assert_eq!(st.status.deleted_total, 2);
            assert_eq!(st.status.orphan_candidates, 2);
            assert_eq!(
                read_status(base.path()).unwrap().unwrap().deleted_total,
                2,
                "published for doctor"
            );
        }

        /// RED against a sweep that deletes an item holding sibling keys. Every
        /// other delete condition holds for each item (csq-minted, dir gone, pid
        /// free; the first is an MCP-only item, the second a canonical-match
        /// login that also carries `mcpOAuth`, the third an emptied login with an
        /// unknown key), so only the sibling check keeps them.
        #[test]
        fn an_item_holding_sibling_keys_survives_and_is_counted() {
            let base = tempfile::tempdir().unwrap();
            let mcp_only = minted(base.path(), 11_111);
            let matching = minted(base.path(), 22_222);
            let unknown = minted(base.path(), 33_333);
            let exec = fake(vec![
                (
                    mcp_only,
                    content(r#"{"mcpOAuth":{"srv":{"accessToken":"m"}}}"#),
                ),
                (
                    matching,
                    content(
                        r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"ref-canonical","expiresAt":1},"mcpOAuth":{"s":{"accessToken":"m"}}}"#,
                    ),
                ),
                (
                    unknown,
                    content(r#"{"claudeAiOauth":{"accessToken":"","refreshToken":""},"future":1}"#),
                ),
            ]);
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            let canonical = |_: &Path| canonical_of(&["ref-canonical"]);
            h.canonical = &canonical;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 3, "all three were examined");
            assert!(
                exec.deletes.borrow().is_empty(),
                "no sibling item is deleted"
            );
            assert_eq!(st.status.kept_siblings, 3);
            assert_eq!(st.status.deleted_total, 0);
            assert_eq!(read_status(base.path()).unwrap().unwrap().kept_siblings, 3);
        }

        /// RED against a sweep that does not take the term mint lock: a creator
        /// (or another sweep) holds it, so the sweep must keep the item instead
        /// of running its final check and delete unserialised.
        #[test]
        fn a_busy_mint_lock_keeps_the_item() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            // Held by ANOTHER thread, as a creator in another process would.
            let (held_tx, held_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let lock_base = base.path().to_path_buf();
            let holder = std::thread::spawn(move || {
                let _guard = crate::session::term_mint::acquire_for_mint(&lock_base).unwrap();
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            held_rx.recv().unwrap();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_mint_busy, 1);
            assert_eq!(st.status.deleted_total, 0);
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            // Once the lock is free the very next tick deletes it.
            st.pending.clear();
            st.last_enumerated_unix_secs = None;
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 1);
            assert_eq!(st.status.kept_mint_busy, 0, "a fresh enumeration resets it");
        }

        /// The race the lock closes: a terminal is minted WHILE the sweep's
        /// delete runs. RED against a sweep that does not hold the lock across
        /// the delete (the creator is not held out), and against a creator that
        /// does not take it (same symptom). The creator must wait for the
        /// delete, mint afterwards, and its dir must then protect its item.
        #[test]
        fn a_terminal_minted_during_the_delete_window_waits_for_the_delete() {
            let base = tempfile::tempdir().unwrap();
            let home = tempfile::tempdir().unwrap();
            let config = base.path().join("config-1");
            std::fs::create_dir_all(&config).unwrap();
            for f in [
                ".csq-account",
                ".credentials.json",
                "settings.json",
                ".claude.json",
            ] {
                std::fs::write(config.join(f), if f == ".csq-account" { "1" } else { "{}" })
                    .unwrap();
            }
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc.clone(), content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let term = base
                .path()
                .join(crate::session::handle_dir::term_handle_dir_name(DEAD_PID));
            let creator: std::rc::Rc<RefCell<Option<std::thread::JoinHandle<bool>>>> =
                std::rc::Rc::default();
            let hook_creator = std::rc::Rc::clone(&creator);
            let (hook_base, hook_home, hook_term) = (
                base.path().to_path_buf(),
                home.path().to_path_buf(),
                term.clone(),
            );
            *exec.on_delete.borrow_mut() = Some(Box::new(move || {
                let (b, h) = (hook_base.clone(), hook_home.clone());
                *hook_creator.borrow_mut() = Some(std::thread::spawn(move || {
                    let account = crate::types::AccountNum::try_from(1u16).unwrap();
                    crate::session::create_handle_dir(&b, &h, account, DEAD_PID).is_ok()
                }));
                // The creator is running; give it every chance to mint.
                std::thread::sleep(std::time::Duration::from_millis(500));
                assert!(
                    !hook_term.exists(),
                    "a terminal was minted while the sweep held the term mint lock"
                );
            }));
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(st.status.deleted_total, 1, "the sweep's delete ran");
            let minted_ok = creator
                .borrow_mut()
                .take()
                .expect("hook ran")
                .join()
                .unwrap();
            assert!(
                minted_ok,
                "the waiting creator mints once the sweep is done"
            );
            assert!(term.is_dir());

            // The new terminal's item (written after its mint) is protected by
            // its dir on the next sweep.
            exec.items
                .borrow_mut()
                .push((svc.clone(), content(&login("", "", 0))));
            st.pending.clear();
            st.last_enumerated_unix_secs = None;
            exec.deletes.borrow_mut().clear();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
        }

        /// S2-1: the item is re-read under the lock and must be byte-equal to the
        /// bytes that were classified. Here the second read returns a ROTATED
        /// login (a live Claude Code wrote a new refresh token after the first
        /// read), which is the only copy of that token: it must survive. RED on
        /// the previous sweep, which classified the first read and deleted.
        #[test]
        fn an_item_rotated_after_the_classifying_read_survives_the_delete() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            exec.scripted_reads.borrow_mut().extend([
                content(&login("", "", 0)),
                content(&login(
                    "rotated-access",
                    "rotated-refresh",
                    4_102_444_800_000,
                )),
            ]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(
                exec.deletes.borrow().is_empty(),
                "a rotated item was deleted"
            );
            assert_eq!(exec.finds.borrow().len(), 2, "classify read + re-read");
            assert_eq!(st.status.kept_revived_after_read, 1);
            assert_eq!(st.status.deleted_total, 0);
            assert!(
                crate::session::term_mint::read_ledger(base.path())
                    .unwrap()
                    .contains(DEAD_PID),
                "a kept item keeps its ledger bit"
            );
        }

        /// The re-read that finds the item already gone is `already_gone`, not a
        /// delete and not a keep.
        #[test]
        fn an_item_that_vanishes_before_the_re_read_is_counted_gone() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            exec.scripted_reads
                .borrow_mut()
                .extend([content(&login("", "", 0)), RawContentClassification::Absent]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.already_gone, 1);
        }

        /// S2-3: once the sweep's delete returns Deleted or NotFound the pid's
        /// ledger bit is cleared, so the ledger does not accumulate every pid ever
        /// launched. RED on the previous sweep, which never cleared a bit.
        #[test]
        fn the_ledger_bit_is_cleared_after_a_delete_and_after_a_not_found() {
            for not_found in [false, true] {
                let base = tempfile::tempdir().unwrap();
                let svc = minted(base.path(), DEAD_PID);
                let other = minted(base.path(), DEAD_PID + 1);
                let mut exec = fake(vec![(svc, content(&login("", "", 0)))]);
                exec.delete_not_found = not_found;
                let probe = ScriptedProbe::all_absent();
                let mut st = OrphanSweepState::default();
                Harness::new(&exec, &probe).run(base.path(), &mut st);
                assert_eq!(exec.deletes.borrow().len(), 1, "not_found={not_found}");
                let ledger = crate::session::term_mint::read_ledger(base.path()).unwrap();
                assert!(!ledger.contains(DEAD_PID), "not_found={not_found}");
                assert!(
                    ledger.contains(DEAD_PID + 1),
                    "another pid's bit is untouched ({other})"
                );
            }
        }

        /// F3: the lock must be HELD at the final check, not taken after it. The
        /// probe is called by `precheck` (once before the lock, once for the final
        /// check); each call records whether another thread can take the lock.
        /// RED against a sweep that takes the lock after the final `precheck`:
        /// the final sample would read "free".
        #[test]
        fn the_mint_lock_is_held_at_the_final_check() {
            struct LockWitness {
                base: std::path::PathBuf,
                held_at_call: RefCell<Vec<bool>>,
            }
            impl PidProbe for LockWitness {
                fn occupant(&self, _pid: u32) -> PidOccupant {
                    let base = self.base.clone();
                    let held = std::thread::spawn(move || {
                        matches!(
                            crate::session::term_mint::try_acquire_for_sweep(&base),
                            crate::session::term_mint::SweepLock::Busy
                        )
                    })
                    .join()
                    .unwrap();
                    self.held_at_call.borrow_mut().push(held);
                    PidOccupant::Absent
                }
            }
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = LockWitness {
                base: base.path().to_path_buf(),
                held_at_call: RefCell::default(),
            };
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(st.status.deleted_total, 1);
            assert_eq!(
                *probe.held_at_call.borrow(),
                vec![false, true],
                "first check is before the lock; the final check is under it"
            );
        }

        /// The creator's wait is sized against the SUM of the constants the sweep holds
        /// the lock for: its item re-read and its `security delete` (each the enforced
        /// `KEYCHAIN_OP_TIMEOUT` plus `MIN_POST_EXIT_GRACE`) and its fresh scan's budget.
        /// This asserts the sum of constants, not the hold: the dir check, the pid probe,
        /// the ledger write and one kernel read are not individually timed.
        #[test]
        fn the_mint_wait_exceeds_the_sum_of_the_constants_the_sweep_holds_the_lock_for() {
            let sum = 2
                * (super::super::super::KEYCHAIN_OP_TIMEOUT
                    + super::super::super::MIN_POST_EXIT_GRACE)
                + crate::sessions::macos::holders::SCAN_BUDGET;
            let wait = crate::session::term_mint::MINT_WAIT_DELAY
                * crate::session::term_mint::MINT_WAIT_ATTEMPTS;
            assert!(
                wait >= sum + std::time::Duration::from_secs(2),
                "wait {wait:?} vs the sum of the sweep's lock-hold constants {sum:?}"
            );
        }

        /// L2: RED against a sweep that treats every hash match as csq-minted. An
        /// item in csq's service-name form whose pid csq never recorded minting
        /// (a foreign item colliding with the hash, or one predating the ledger)
        /// is neither read nor deleted, even though every other condition holds.
        #[test]
        fn an_item_csq_has_no_ledger_record_of_survives_unread() {
            let base = tempfile::tempdir().unwrap();
            let attested = minted(base.path(), 11_111);
            let unattested = minted_service_only(base.path(), 22_222);
            let exec = fake(vec![
                (attested.clone(), content(&login("", "", 0))),
                (unattested, content(&login("", "", 0))),
            ]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            // The attested item is read twice (classify, then the re-read under
            // the mint lock); the unattested one is never read.
            assert_eq!(
                *exec.finds.borrow(),
                vec![attested.clone(), attested.clone()],
                "only the attested one is read"
            );
            assert_eq!(*exec.deletes.borrow(), vec![attested]);
            assert_eq!(st.status.unattested_items, 1);
            assert_eq!(st.status.orphan_candidates, 1);
        }

        /// An unreadable ledger fails CLOSED: the cycle is undetermined with the
        /// fixed token and a stale worklist of otherwise deletable items is
        /// dropped, nothing is read or deleted. RED against a sweep that treats
        /// a corrupt ledger as empty-and-fine or as "attest everything".
        #[test]
        fn an_unreadable_mint_ledger_deletes_nothing() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(base.path(), &mut st);
            assert_eq!(st.pending.len(), 1, "a deletable worklist exists");
            std::fs::write(crate::session::term_mint::ledger_path(base.path()), b"junk").unwrap();
            h.batch = 40;
            h.run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty());
            assert!(exec.deletes.borrow().is_empty());
            assert!(st.pending.is_empty(), "the worklist is dropped");
            assert_eq!(
                st.status.undetermined,
                Some(UndeterminedReason::MintLedgerUnreadable)
            );
            assert!(st.status.counts_stale);
            // Repaired: the next tick enumerates again (the entry is lost, so the
            // item is merely unattested: a leak, never a delete).
            std::fs::remove_file(crate::session::term_mint::ledger_path(base.path())).unwrap();
            h.run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.undetermined, None);
            assert_eq!(st.status.unattested_items, 1);
        }

        /// L1: a live Claude Code whose `term-<pid>` dir was removed by hand
        /// keeps its item through the live-pid rule, using the REAL pid probe.
        /// The csq process that named the dir (here: this test process) still
        /// holds its pid, so the item is not even read. RED against a sweep that
        /// decides from the dir alone.
        ///
        /// Limit (stated, not hidden): the rule keys on the pid in the dir NAME.
        /// A Claude Code child that outlives a dead csq supervisor (SIGKILL) is
        /// invisible to it once the dir is also gone.
        #[cfg(unix)]
        #[test]
        fn a_live_terminal_whose_dir_was_removed_by_hand_keeps_its_item() {
            let base = tempfile::tempdir().unwrap();
            let live_pid = std::process::id();
            let svc = minted(base.path(), live_pid);
            let term = base
                .path()
                .join(crate::session::handle_dir::term_handle_dir_name(live_pid));
            std::fs::create_dir(&term).unwrap();
            std::fs::remove_dir_all(&term).unwrap(); // the hand removal
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &OsPidProbe).run(base.path(), &mut st);
            assert_eq!(
                st.status.orphan_candidates, 1,
                "the dir is gone, so it is a candidate"
            );
            assert!(exec.finds.borrow().is_empty(), "not even read");
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_pid_in_use, 1);
        }

        /// RED against a sweep that deletes an item it cannot read.
        #[test]
        fn an_unreadable_item_survives() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(
                svc,
                RawContentClassification::Unreadable(
                    super::super::super::UnreadableKind::Transient,
                ),
            )]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(exec.finds.borrow().len(), 1);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_other, 1);
        }

        /// RED against a sweep that proceeds when the enumeration did not
        /// complete. The state carries a stale worklist of provably deletable
        /// items; the refresh that would validate it times out, so the cycle is
        /// UNDETERMINED: nothing is read, nothing deleted, the reason is
        /// published, and the stale worklist is dropped.
        #[test]
        fn an_enumeration_timeout_is_undetermined_and_deletes_nothing() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc.clone(), content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            // Tick 1 enumerates; batch 0 leaves the worklist pending.
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(base.path(), &mut st);
            assert_eq!(st.pending.len(), 1);
            // Tick 2, past the worklist's age: the listing now times out.
            *exec.list.borrow_mut() = Err(UndeterminedReason::EnumerationUnavailable);
            let mut h = Harness::new(&exec, &probe);
            h.now_secs = NOW_SECS + ORPHAN_REENUMERATE_SECS;
            h.run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty());
            assert!(exec.deletes.borrow().is_empty());
            assert!(st.pending.is_empty(), "a stale worklist is dropped");
            let published = read_status(base.path()).unwrap().unwrap();
            assert_eq!(
                published.undetermined,
                Some(UndeterminedReason::EnumerationUnavailable)
            );
            assert_eq!(published.deleted_total, 0);
        }

        /// The real executor maps every way `dump-keychain` can fail to a
        /// distinct fixed reason, and a runner that timed out (`None`) to
        /// UNAVAILABLE, never to an empty listing.
        #[test]
        fn dump_keychain_maps_each_failure_to_a_fixed_reason() {
            use std::os::unix::process::ExitStatusExt;
            let out = |code: i32, stdout: &str, complete: bool| {
                Some(super::super::super::BoundedOutput {
                    output: std::process::Output {
                        status: std::process::ExitStatus::from_raw((code & 0xff) << 8),
                        stdout: stdout.as_bytes().to_vec(),
                        stderr: Vec::new(),
                    },
                    stdout_complete: complete,
                    stderr_complete: true,
                })
            };
            let seen_args = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
            let run = |result: Option<super::super::super::BoundedOutput>| {
                let cell = RefCell::new(Some(result));
                let seen = std::rc::Rc::clone(&seen_args);
                move |args: &[&str], stdin: Option<Vec<u8>>| {
                    assert!(stdin.is_none());
                    seen.borrow_mut().extend(args.iter().map(|a| a.to_string()));
                    cell.borrow_mut().take().unwrap()
                }
            };
            assert_eq!(
                dump_keychain(&run(None)).unwrap_err(),
                UndeterminedReason::EnumerationUnavailable
            );
            assert_eq!(
                dump_keychain(&run(out(0, DUMP, false))).unwrap_err(),
                UndeterminedReason::EnumerationIncomplete
            );
            assert_eq!(
                dump_keychain(&run(out(1, "", true))).unwrap_err(),
                UndeterminedReason::EnumerationFailed
            );
            let scan = dump_keychain(&run(out(0, DUMP, true))).unwrap();
            assert_eq!(scan.items.len(), 3);
            // Metadata only: never `-d` (which would print secrets).
            assert!(seen_args.borrow().iter().all(|a| a == "dump-keychain"));
        }

        /// The standard 5s bound is the only bound: the enumeration goes through
        /// `run_security_bounded`, whose timeout outside an interactive scope is
        /// `KEYCHAIN_OP_TIMEOUT`.
        #[test]
        fn the_enumeration_bound_is_the_standard_five_seconds() {
            assert_eq!(
                super::super::super::KEYCHAIN_OP_TIMEOUT,
                std::time::Duration::from_secs(5)
            );
            assert_eq!(
                super::super::super::security_op_timeout(false),
                super::super::super::KEYCHAIN_OP_TIMEOUT
            );
        }

        /// RED against a sweep without the live-dir filter: the item's dir
        /// exists, so it must be neither read nor deleted even though empty.
        #[test]
        fn never_touches_an_item_whose_dir_exists() {
            let base = tempfile::tempdir().unwrap();
            let live_svc = minted(base.path(), DEAD_PID);
            std::fs::create_dir(
                base.path()
                    .join(crate::session::handle_dir::term_handle_dir_name(DEAD_PID)),
            )
            .unwrap();
            let exec = fake(vec![(live_svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty());
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.keychain_items, 1);
            assert_eq!(st.status.orphan_candidates, 0);
        }

        /// A dir that appears AFTER the enumeration makes its item live: the
        /// per-item re-check, not the enumeration filter, must catch it.
        #[test]
        fn a_dir_created_after_enumeration_protects_its_item() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(base.path(), &mut st);
            assert_eq!(st.pending.len(), 1);
            std::fs::create_dir(
                base.path()
                    .join(crate::session::handle_dir::term_handle_dir_name(DEAD_PID)),
            )
            .unwrap();
            h.batch = 40;
            h.run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty());
            assert!(exec.deletes.borrow().is_empty());
        }

        /// RED against a sweep with no per-tick cap: 5 orphans, cap 2.
        #[test]
        fn examines_at_most_the_batch_per_tick_then_drains_over_ticks() {
            let base = tempfile::tempdir().unwrap();
            let exec = fake(
                (1..=5)
                    .map(|n| (minted(base.path(), 30_000 + n), content(&login("", "", 0))))
                    .collect(),
            );
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 2;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 2);
            assert_eq!(st.status.pending, 3);
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 4);
            h.run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 5);
            assert_eq!(st.status.pending, 0);
        }

        /// RED against a sweep that ignores the wall-clock budget.
        #[test]
        fn an_exhausted_budget_examines_nothing() {
            let base = tempfile::tempdir().unwrap();
            let exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("", "", 0)),
            )]);
            let probe = ScriptedProbe::all_absent();
            let mut h = Harness::new(&exec, &probe);
            h.budget = std::time::Duration::ZERO;
            let mut st = OrphanSweepState::default();
            h.run(base.path(), &mut st);
            assert!(exec.finds.borrow().is_empty());
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.pending, 1);
        }

        /// RED against a sweep that deletes a pair the listing shows twice.
        #[test]
        fn never_deletes_a_duplicated_pair() {
            let base = tempfile::tempdir().unwrap();
            let svc = minted(base.path(), DEAD_PID);
            let exec = fake(vec![(svc.clone(), content(&login("", "", 0)))]);
            exec.list
                .borrow_mut()
                .as_mut()
                .unwrap()
                .ambiguous
                .insert((svc, ACCT.to_string()));
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.kept_other, 1);
        }

        /// RED against a sweep that, when the accounts dir cannot be resolved,
        /// hashes some other base and treats items as orphans.
        #[test]
        fn an_unresolvable_accounts_dir_is_undetermined_and_deletes_nothing() {
            let base = tempfile::tempdir().unwrap();
            let missing = base.path().join("missing");
            let exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("", "", 0)),
            )]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(&missing, &mut st);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(
                st.status.undetermined,
                Some(UndeterminedReason::AccountsDirUnresolved)
            );
        }

        /// A worklist built for one accounts dir is never drained under another.
        #[test]
        fn a_worklist_is_dropped_when_the_accounts_dir_changes() {
            let first = tempfile::tempdir().unwrap();
            let second = tempfile::tempdir().unwrap();
            let svc = minted(first.path(), DEAD_PID);
            let exec = fake(vec![(svc, content(&login("", "", 0)))]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(first.path(), &mut st);
            assert_eq!(st.pending.len(), 1);
            h.batch = 40;
            h.run(second.path(), &mut st);
            // Re-enumerated under `second`: the item is foreign there.
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(st.status.foreign_items, 1);
        }

        /// RED against a sweep that counts exit 44 as a delete: the item was
        /// already gone, so this call removed nothing and `deleted_total` stays 0.
        #[test]
        fn a_delete_that_finds_no_item_is_already_gone_not_deleted() {
            let base = tempfile::tempdir().unwrap();
            let mut exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("", "", 0)),
            )]);
            exec.delete_not_found = true;
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(exec.deletes.borrow().len(), 1, "the delete was attempted");
            assert_eq!(st.status.deleted_total, 0);
            assert_eq!(st.status.already_gone, 1);
            assert_eq!(st.status.kept_other, 0);
        }

        /// 4b: a dir that reappeared before the read, and an item that is no
        /// longer in the keychain when read, are each counted (not dropped).
        #[test]
        fn a_reappeared_dir_and_a_vanished_item_are_counted() {
            let base = tempfile::tempdir().unwrap();
            let revived = minted(base.path(), 11_111);
            let vanished = minted(base.path(), 22_222);
            let exec = fake(vec![(revived, content(&login("", "", 0)))]);
            // `vanished` is listed by the enumeration but absent when read.
            exec.list
                .borrow_mut()
                .as_mut()
                .unwrap()
                .items
                .push(KeychainItemRef {
                    service: vanished,
                    account: ACCT.to_string(),
                });
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(base.path(), &mut st);
            assert_eq!(st.pending.len(), 2);
            std::fs::create_dir(
                base.path()
                    .join(crate::session::handle_dir::term_handle_dir_name(11_111)),
            )
            .unwrap();
            h.batch = 40;
            h.run(base.path(), &mut st);
            assert_eq!(st.status.dir_reappeared, 1);
            assert_eq!(st.status.already_gone, 1);
            assert!(exec.deletes.borrow().is_empty());
            assert_eq!(
                st.status.kept_revived_after_read, 0,
                "neither is a post-read revival"
            );
        }

        /// While a cycle is undetermined the counts are marked stale and the
        /// start of the run is recorded; the next determined enumeration clears
        /// both. RED against a sweep that leaves old counts unmarked.
        #[test]
        fn undetermined_cycles_mark_counts_stale_until_the_next_enumeration() {
            let base = tempfile::tempdir().unwrap();
            let exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("", "", 0)),
            )]);
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            let mut h = Harness::new(&exec, &probe);
            h.batch = 0;
            h.run(base.path(), &mut st);
            assert!(!st.status.counts_stale);
            *exec.list.borrow_mut() = Err(UndeterminedReason::EnumerationUnavailable);
            h.now_secs = NOW_SECS + ORPHAN_REENUMERATE_SECS;
            h.run(base.path(), &mut st);
            assert!(st.status.counts_stale);
            assert_eq!(
                st.status.undetermined_since_unix_secs,
                Some(NOW_SECS + ORPHAN_REENUMERATE_SECS)
            );
            // A second undetermined cycle keeps the ORIGINAL start.
            h.now_secs = NOW_SECS + 2 * ORPHAN_REENUMERATE_SECS;
            h.run(base.path(), &mut st);
            assert_eq!(
                st.status.undetermined_since_unix_secs,
                Some(NOW_SECS + ORPHAN_REENUMERATE_SECS)
            );
            assert_eq!(
                st.status.keychain_items, 1,
                "old counts are kept, marked stale"
            );
            // The listing recovers.
            *exec.list.borrow_mut() = Ok(DumpScan::default());
            h.now_secs = NOW_SECS + 3 * ORPHAN_REENUMERATE_SECS;
            h.run(base.path(), &mut st);
            assert!(!st.status.counts_stale);
            assert_eq!(st.status.undetermined_since_unix_secs, None);
            assert_eq!(st.status.undetermined, None);
        }

        /// A delete that does not confirm is not counted as deleted.
        #[test]
        fn an_unconfirmed_delete_is_not_counted() {
            let base = tempfile::tempdir().unwrap();
            let mut exec = fake(vec![(
                minted(base.path(), DEAD_PID),
                content(&login("", "", 0)),
            )]);
            exec.delete_ok = false;
            let probe = ScriptedProbe::all_absent();
            let mut st = OrphanSweepState::default();
            Harness::new(&exec, &probe).run(base.path(), &mut st);
            assert_eq!(st.status.deleted_total, 0);
            assert_eq!(st.status.kept_other, 1);
        }

        /// The default executor cannot enumerate: refuse, never guess.
        #[test]
        fn an_executor_without_enumeration_refuses() {
            struct Bare;
            impl KeychainExecutor for Bare {
                fn find(&self, _: &str, _: &str) -> RawContentClassification {
                    RawContentClassification::Absent
                }
                fn add(&self, _: &str, _: &str, _: &str) -> Result<(), PlatformError> {
                    Ok(())
                }
                fn delete(&self, _: &str, _: &str) -> bool {
                    panic!("must not delete without an enumeration");
                }
            }
            assert_eq!(
                Bare.list_cc_credential_items().unwrap_err(),
                UndeterminedReason::EnumerationUnsupported
            );
        }
    }
}
