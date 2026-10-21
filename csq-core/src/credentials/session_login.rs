//! Token-free daemon snapshot projection. Diagnostics never read credentials.
use super::{keychain, token_history};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginState {
    Current,
    Superseded,
    Unproven,
    KeychainUnavailable,
    KeychainAbsent,
    Undetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginReason {
    Current,
    Superseded,
    OrderUnproven,
    KeychainUnavailable,
    KeychainAbsent,
    MalformedOauth,
    HandleInconsistent,
    MarkerUnresolved,
    CanonicalUnavailable,
    CanonicalChanged,
    HistoryChanged,
    OwnerVerifiedChanged,
    OwnerChanged,
    LockTimeout,
    LockFailed,
    SweepBudget,
    KeychainDisabled,
    SnapshotUnavailable,
    NotInSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginRemedy {
    KeychainSync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginEvidence {
    pub state: LoginState,
    pub reason: LoginReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<LoginRemedy>,
}
impl LoginEvidence {
    fn new(state: LoginState, reason: LoginReason) -> Self {
        Self {
            state,
            reason,
            remedy: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLogin {
    pub handle_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountNum>,
    pub evidence: LoginEvidence,
}
impl SessionLogin {
    /// Fail closed on contradictory/corrupt rows before trusting a snapshot.
    pub(crate) fn is_valid(&self) -> bool {
        self.handle_pid > 0
            && (self.account.is_some() || self.evidence.state == LoginState::Undetermined)
            && (self.evidence.remedy.is_none() || self.evidence.state == LoginState::Superseded)
            && match self.evidence.state {
                LoginState::Current => self.evidence.reason == LoginReason::Current,
                LoginState::Superseded => self.evidence.reason == LoginReason::Superseded,
                LoginState::Unproven => self.evidence.reason == LoginReason::OrderUnproven,
                LoginState::KeychainUnavailable => {
                    self.evidence.reason == LoginReason::KeychainUnavailable
                }
                LoginState::KeychainAbsent => self.evidence.reason == LoginReason::KeychainAbsent,
                LoginState::Undetermined => !matches!(
                    self.evidence.reason,
                    LoginReason::Current | LoginReason::Superseded | LoginReason::OrderUnproven
                ),
            }
    }
    pub(crate) fn from_evidence(
        pid: u32,
        account: Option<AccountNum>,
        evidence: LoginEvidence,
    ) -> Self {
        Self {
            handle_pid: pid,
            account,
            evidence,
        }
    }
    pub(crate) fn undetermined(pid: u32, account: Option<AccountNum>, reason: LoginReason) -> Self {
        Self::from_evidence(
            pid,
            account,
            LoginEvidence::new(LoginState::Undetermined, reason),
        )
    }
}

/// Pure producer adapter. B calls this with the ORIGINAL classified keychain
/// read under its handle lock; no parsing into an owned credential type,
/// reserialization, keychain call, canonical read, or secret cache here.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn classify_login(
    current: &keychain::RawContentClassification,
    canonical: &str,
    history: &[token_history::Fingerprint],
    owner_verified: &[token_history::Fingerprint],
) -> LoginEvidence {
    use keychain::{RawContentClassification as Raw, WriteDecision as Decision};
    let raw = match current {
        Raw::Absent => {
            return LoginEvidence::new(LoginState::KeychainAbsent, LoginReason::KeychainAbsent)
        }
        Raw::Unreadable(_) => {
            return LoginEvidence::new(
                LoginState::KeychainUnavailable,
                LoginReason::KeychainUnavailable,
            )
        }
        Raw::Content(raw) => raw,
    };
    let known = keychain::KnownTokens {
        marker_account_canonical: Some(canonical),
        marker_account_history: history,
        marker_account_owner_verified: owner_verified,
        ..Default::default()
    };
    let decision =
        keychain::decide_cc_keychain_write(current, &known, keychain::Intended::Token(canonical));
    if matches!(decision, Decision::Unknown(_)) {
        return LoginEvidence::new(LoginState::Undetermined, LoginReason::MalformedOauth);
    }
    let Some(canonical_fp) = token_history::fingerprint_from_raw_json(canonical) else {
        return LoginEvidence::new(LoginState::Undetermined, LoginReason::CanonicalUnavailable);
    };
    let Some(current_fp) = token_history::fingerprint_from_raw_json(raw) else {
        return LoginEvidence::new(LoginState::Undetermined, LoginReason::MalformedOauth);
    };
    if matches!(decision, Decision::NoWrite) {
        return LoginEvidence::new(LoginState::Current, LoginReason::Current);
    }
    // Both LAST occurrences are required; neither expiry nor owner recognition
    // alone proves that this login preceded this canonical account refresh.
    if !matches!((history.iter().rposition(|fp| *fp == current_fp),
        history.iter().rposition(|fp| *fp == canonical_fp)),
        (Some(old), Some(new)) if old < new)
    {
        return LoginEvidence::new(LoginState::Unproven, LoginReason::OrderUnproven);
    }
    LoginEvidence {
        state: LoginState::Superseded,
        reason: LoginReason::Superseded,
        remedy: matches!(decision, Decision::Write(_)).then_some(LoginRemedy::KeychainSync),
    }
}

#[derive(Debug)]
pub struct LoginDiagnostics {
    pub session_logins: Vec<SessionLogin>,
    pub sessions_undetermined: bool,
    pub snapshot_age_secs: Option<u64>,
    pub keychain_mirror: Option<keychain::MirrorSyncStatus>,
}

/// Read the token-free snapshot, bounded non-secret PID markers, and local
/// filesystem metadata only. No credential contents or keychain access.
pub fn read_diagnostics(base: &Path) -> LoginDiagnostics {
    let live = observe_handles(base, crate::platform::process::is_pid_alive);
    project_snapshot(
        keychain::read_mirror_sync_observation(base),
        keychain::now_ms(),
        live,
        |handle, row, stamp| check_metadata(base, handle, row, stamp),
        cfg!(target_os = "macos"),
    )
}

/// Scope of Claude Code's OAuth keychain mirror, derived without reading secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MirrorApplicability {
    ClaudeOAuth,
    NotApplicable,
    Unknown,
}

pub(crate) fn mirror_applicability(base: &Path, handle: &Path) -> MirrorApplicability {
    use crate::accounts::{binding_guard, identity_store, markers, profiles};
    use MirrorApplicability::{ClaudeOAuth, NotApplicable, Unknown};
    let Ok(root) = std::fs::canonicalize(base) else {
        return Unknown;
    };
    let profile = profiles::profiles_path(&root);
    if std::fs::symlink_metadata(&profile).is_ok() && local_metadata(&root, &profile).is_err() {
        return Unknown;
    }
    let Ok(profile_data) = profiles::load(&profile) else {
        return Unknown;
    };
    // Validate the marker's local target before the canonical marker reader
    // follows it; an arbitrary symlink must not turn a diagnostic into a read
    // outside this accounts root.
    let Ok(marker_text) = std::fs::read_link(handle.join(".csq-account")) else {
        return Unknown;
    };
    // Leading ../ in a relative canonical link is supported. A parent after
    // a named component can cancel a directory symlink and escape containment.
    let mut named_component = false;
    if marker_text.components().any(|component| match component {
        Component::Normal(_) => {
            named_component = true;
            false
        }
        Component::ParentDir => named_component,
        _ => false,
    }) {
        return Unknown;
    }
    let Some(mut marker_target) = normalize(&if marker_text.is_absolute() {
        marker_text
    } else {
        handle.join(marker_text)
    }) else {
        return Unknown;
    };
    if let Some(alias) = normalize(base) {
        if let Ok(relative) = marker_target.strip_prefix(alias) {
            marker_target = root.join(relative);
        }
    }
    // The directory resolver appends .csq-account: reject other basenames
    // before it can read a different, unvalidated sibling marker.
    if marker_target.file_name() != Some(std::ffi::OsStr::new(".csq-account")) {
        return Unknown;
    }
    if local_metadata(&root, &marker_target).is_err() {
        return Unknown;
    }
    let Some(account) = marker_target
        .parent()
        .and_then(|parent| markers::resolve_marker_to_slot(&root, parent))
    else {
        return Unknown;
    };
    let config = root.join(format!("config-{account}"));
    // A marker resolving to a number is insufficient to license an exclusion:
    // it must be this slot's canonical marker link, not a copied/foreign marker.
    if marker_target != config.join(".csq-account") {
        return Unknown;
    }
    let uuid = profile_data
        .by_slot
        .get(&account.get().to_string())
        .copied();
    if let Some(uuid) = uuid {
        // Check both canonical credential nodes without following links or
        // reading bytes: absence is distinct from dangling/unreadable metadata.
        for path in [
            identity_store::credentials_path_for(&root, uuid),
            identity_store::credentials_codex_path_for(&root, uuid),
        ] {
            if local_file_presence(&root, &path).is_err() {
                return Unknown;
            }
        }
        let identity = identity_store::identity_json_path_for(&root, uuid);
        if std::fs::symlink_metadata(&identity).is_ok() && local_metadata(&root, &identity).is_err()
        {
            return Unknown;
        }
    }
    let present = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    };
    if present(&root.join("credentials").join(format!("{account}.json"))).is_none() {
        return Unknown;
    }
    // Canonical Anthropic identity survives a missing credential or handle link.
    // Legacy live credentials remain a binding signal before UUID migration.
    let oauth = binding_guard::oauth_slot_evidence(&root, account);
    if oauth.anthropic || present(&config.join(".credentials.json")) != Some(false) {
        return ClaudeOAuth;
    }
    // Mixed evidence and incomplete swaps cannot become false exemptions.
    for name in [
        ".credentials.json",
        ".credentials.json.swap-tmp",
        ".csq-account.swap-tmp",
        "auth.json.swap-tmp",
        "config.toml.swap-tmp",
    ] {
        if present(&handle.join(name)) != Some(false) {
            return Unknown;
        }
    }
    let codex_only = uuid.map_or_else(
        || oauth.codex,
        |id| identity_store::is_codex_only_slot(&root, account.get(), id),
    );
    if codex_only {
        // Codex link integrity belongs to Codex diagnostics. A canonical
        // Codex-only binding does not acquire a Claude mirror when auth breaks.
        return NotApplicable;
    }
    // A UUID mapping without a proven OAuth surface is an incomplete identity,
    // not permission to revive a stale pre-UUID API-key classification.
    if uuid.is_some() {
        return Unknown;
    }
    let api_key = profile_data
        .by_slot_identity
        .get(&account.get().to_string())
        .and_then(|label| label.strip_prefix("apikey:"))
        .and_then(crate::providers::catalog::get_provider)
        .is_some_and(|provider| {
            provider.surface == crate::providers::catalog::Surface::ClaudeCode
                && provider.id != "claude"
        });
    if api_key
        && present(&handle.join("auth.json")) == Some(false)
        && present(&handle.join("config.toml")) == Some(false)
    {
        NotApplicable
    } else {
        Unknown
    }
}

// Enumeration and row bounds, not a filesystem wall-clock guarantee.
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_LIVE_HANDLES: usize = 256;
#[derive(Default)]
struct LiveHandles {
    // None means the owner is ambiguous/unreadable, never a measured account.
    handles: BTreeMap<u32, Option<PathBuf>>,
    undetermined: bool,
    not_applicable: BTreeSet<u32>,
}

fn dirname_pid(handle: &Path) -> Option<u32> {
    handle
        .file_name()?
        .to_str()?
        .strip_prefix("term-")?
        .parse()
        .ok()
        .filter(|p| *p > 0)
}

fn observe_handles(base: &Path, alive: impl Fn(u32) -> bool) -> LiveHandles {
    let Ok(entries) = std::fs::read_dir(base) else {
        return LiveHandles {
            undetermined: true,
            ..Default::default()
        };
    };
    let mut not_applicable = BTreeSet::new();
    let mut live = collect_handles(
        entries.map(|entry| entry.map(|entry| entry.path())),
        |path| {
            if !std::fs::symlink_metadata(path).map_err(|_| ())?.is_dir() {
                return Err(());
            }
            let pid = crate::accounts::markers::read_live_pid_checked(path)
                .map_err(|_| ())?
                .or_else(|| dirname_pid(path))
                .filter(|pid| *pid > 0)
                .ok_or(())?;
            if alive(pid) {
                if mirror_applicability(base, path) == MirrorApplicability::NotApplicable {
                    not_applicable.insert(pid);
                    return Ok(None);
                }
                Ok(Some(pid))
            } else {
                Ok(None)
            }
        },
    );
    // A duplicate PID with mixed scopes remains ambiguous, never excluded.
    for pid in &not_applicable {
        if let Some(handle) = live.handles.get_mut(pid) {
            *handle = None;
            live.undetermined = true;
        }
    }
    not_applicable.retain(|pid| !live.handles.contains_key(pid));
    live.not_applicable = not_applicable;
    live
}

fn collect_handles(
    entries: impl Iterator<Item = std::io::Result<PathBuf>>,
    mut inspect: impl FnMut(&Path) -> Result<Option<u32>, ()>,
) -> LiveHandles {
    let mut live = LiveHandles::default();
    let mut terms = 0;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            live.undetermined = true;
            break;
        }
        let path = match entry {
            Ok(path) => path,
            Err(_) => {
                live.undetermined = true;
                continue;
            }
        };
        if !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("term-"))
        {
            continue;
        }
        let (pid, handle) = match inspect(&path) {
            Ok(Some(pid)) => (pid, Some(path.clone())),
            Ok(None) => continue,
            Err(()) => {
                live.undetermined = true;
                let Some(pid) = dirname_pid(&path) else {
                    continue;
                };
                (pid, None)
            }
        };
        terms += 1;
        if terms > MAX_LIVE_HANDLES {
            live.undetermined = true;
            break;
        }
        if live.handles.insert(pid, handle).is_some() {
            live.handles.insert(pid, None);
            live.undetermined = true;
        }
    }
    live
}

// Normalize text before any target metadata access; no canonicalization of a
// caller-controlled symlink target. Only the configured accounts root is resolved.
fn normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            Component::CurDir => (),
            component => result.push(component.as_os_str()),
        }
    }
    Some(result)
}

fn unchanged(metadata: &std::fs::Metadata, stamp: u64) -> Result<(), ()> {
    let observed = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(stamp))
        .ok_or(())?;
    if metadata.modified().map_err(|_| ())? > observed {
        Err(())
    } else {
        Ok(())
    }
}

/// Tri-state canonical credential metadata; no symlink traversal or file read.
fn local_file_presence(base: &Path, path: &Path) -> Result<bool, ()> {
    let relative = path.strip_prefix(base).map_err(|_| ())?;
    let mut cursor = base.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(Component::Normal(component)) = components.next() {
        cursor.push(component);
        let metadata = match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(()),
        };
        if components.peek().is_none() {
            return metadata.is_file().then_some(true).ok_or(());
        }
        if !metadata.is_dir() {
            return Err(());
        }
    }
    Err(())
}

/// Walk only validated local components, rejecting symlink directories/files.
/// This is an observation, not a handle lock or a concurrent-mutation guarantee.
fn local_metadata(base: &Path, path: &Path) -> Result<std::fs::Metadata, ()> {
    let relative = path.strip_prefix(base).map_err(|_| ())?;
    let mut cursor = base.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(Component::Normal(component)) = components.next() {
        cursor.push(component);
        let metadata = std::fs::symlink_metadata(&cursor).map_err(|_| ())?;
        if components.peek().is_none() {
            return metadata.is_file().then_some(metadata).ok_or(());
        }
        if !metadata.is_dir() {
            return Err(());
        }
    }
    Err(())
}

fn check_metadata(
    base: &Path,
    handle: &Path,
    row: &SessionLogin,
    stamp: u64,
) -> Result<(), LoginReason> {
    use crate::accounts::{identity_store, profiles};
    // The producer's ACCOUNT_BOUND_ITEMS transaction leaves these names while
    // repointing. Inspect names/metadata only, never their contents or targets.
    for name in [
        ".credentials.json",
        ".csq-account",
        ".current-account",
        ".quota-cursor",
    ] {
        match std::fs::symlink_metadata(handle.join(format!("{name}.swap-tmp"))) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(LoginReason::OwnerChanged),
        }
    }
    let account = row.account.ok_or(LoginReason::MarkerUnresolved)?;
    let root = std::fs::canonicalize(base).map_err(|_| LoginReason::OwnerChanged)?;
    let alias = normalize(base).ok_or(LoginReason::OwnerChanged)?;
    let legacy = super::file::live_path(&root, account);
    let marker = legacy.with_file_name(".csq-account");
    let target = |name: &str| -> Result<PathBuf, LoginReason> {
        let link = handle.join(name);
        let metadata = std::fs::symlink_metadata(&link).map_err(|_| LoginReason::OwnerChanged)?;
        if !metadata.file_type().is_symlink() || unchanged(&metadata, stamp).is_err() {
            return Err(LoginReason::OwnerChanged);
        }
        let text = std::fs::read_link(link).map_err(|_| LoginReason::OwnerChanged)?;
        if text.as_os_str().len() > 4096 {
            return Err(LoginReason::OwnerChanged);
        }
        let path = normalize(&if text.is_absolute() {
            text
        } else {
            handle.join(text)
        })
        .ok_or(LoginReason::OwnerChanged)?;
        if let Ok(relative) = path.strip_prefix(&alias) {
            Ok(root.join(relative))
        } else if path.starts_with(&root) {
            Ok(path)
        } else {
            Err(LoginReason::OwnerChanged)
        }
    };
    if target(".csq-account")? != marker {
        return Err(LoginReason::OwnerChanged);
    }
    let credential = target(".credentials.json")?;
    let uuid_channel = credential != legacy;
    if uuid_channel {
        let id = credential
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<identity_store::IdentityId>().ok())
            .ok_or(LoginReason::OwnerChanged)?;
        if credential != identity_store::credentials_path_for(&root, id) {
            return Err(LoginReason::OwnerChanged);
        }
    }
    let metadata =
        local_metadata(&root, &credential).map_err(|_| LoginReason::CanonicalUnavailable)?;
    unchanged(&metadata, stamp).map_err(|_| LoginReason::CanonicalChanged)?;
    let metadata = local_metadata(&root, &marker).map_err(|_| LoginReason::MarkerUnresolved)?;
    unchanged(&metadata, stamp).map_err(|_| LoginReason::OwnerChanged)?;
    // A UUID row relies on the producer's profile resolution; unchanged profile
    // metadata preserves that observation without re-reading profile/marker data.
    let profile = profiles::profiles_path(&root);
    match std::fs::symlink_metadata(&profile) {
        Ok(metadata) if metadata.is_file() => {
            unchanged(&metadata, stamp).map_err(|_| LoginReason::OwnerChanged)
        }
        Err(error) if !uuid_channel && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(LoginReason::OwnerChanged),
    }?;
    // Recheck the same producer owner channel after metadata observation. An
    // unreadable marker never becomes a directory-name fallback here either.
    let owner = crate::accounts::markers::read_live_pid_checked(handle)
        .map_err(|_| LoginReason::OwnerChanged)?
        .or_else(|| dirname_pid(handle));
    if owner == Some(row.handle_pid) && std::fs::symlink_metadata(handle).is_ok_and(|m| m.is_dir())
    {
        Ok(())
    } else {
        Err(LoginReason::OwnerChanged)
    }
}

fn project_snapshot(
    status: Option<keychain::MirrorSyncStatus>,
    now: u64,
    live: LiveHandles,
    mut check: impl FnMut(&Path, &SessionLogin, u64) -> Result<(), LoginReason>,
    include_disabled: bool,
) -> LoginDiagnostics {
    let mut report = LoginDiagnostics {
        session_logins: Vec::new(),
        sessions_undetermined: true,
        snapshot_age_secs: None,
        keychain_mirror: None,
    };
    let mut seen = BTreeSet::new();
    if let Some(mut status) = status.filter(|s| {
        s.updated_at_unix_ms > 0
            && s.updated_at_unix_ms <= now
            && s.sessions.iter().all(SessionLogin::is_valid)
    }) {
        report.snapshot_age_secs = Some((now - status.updated_at_unix_ms) / 1000);
        report.sessions_undetermined = status.sessions_undetermined || live.undetermined;
        for mut row in status.sessions.drain(..) {
            if live.not_applicable.contains(&row.handle_pid) {
                continue;
            }
            if !seen.insert(row.handle_pid) {
                report.sessions_undetermined = true;
                continue;
            }
            if !include_disabled && row.evidence.reason == LoginReason::KeychainDisabled {
                report.sessions_undetermined = true;
                continue;
            }
            let checked = match live.handles.get(&row.handle_pid) {
                Some(Some(handle)) if row.account.is_some() => {
                    check(handle, &row, status.updated_at_unix_ms)
                }
                Some(Some(_)) => Ok(()),
                _ => Err(LoginReason::OwnerChanged),
            };
            if let Err(reason) = checked {
                row = SessionLogin::undetermined(row.handle_pid, None, reason);
            }
            report.session_logins.push(row);
        }
        report.keychain_mirror = Some(status);
    }
    for (pid, handle) in live.handles {
        if seen.contains(&pid) {
            continue;
        }
        report.session_logins.push(SessionLogin::undetermined(
            pid,
            None,
            if handle.is_some() {
                LoginReason::NotInSnapshot
            } else {
                LoginReason::OwnerChanged
            },
        ));
        report.sessions_undetermined = true;
    }
    report.sessions_undetermined |= report.session_logins.iter().any(|row| {
        matches!(
            row.evidence.state,
            LoginState::Undetermined | LoginState::KeychainUnavailable | LoginState::Unproven
        )
    });
    if let Some(status) = &mut report.keychain_mirror {
        status.sessions = report.session_logins.clone();
        status.sessions_undetermined = report.sessions_undetermined;
    }
    report
}

/// Fixed-vocabulary, path-free display of stored evidence; never an assertion
/// about a process's currently cached token. Unknown observations are visible.
pub fn finding_line(login: &SessionLogin) -> Option<String> {
    let message = match login.evidence.state {
        LoginState::Current => return None,
        LoginState::Superseded => "session holds a superseded login",
        LoginState::Unproven => "session keychain login order is unproven",
        LoginState::KeychainUnavailable => "session keychain login could not be read",
        LoginState::KeychainAbsent => "session keychain login is absent",
        LoginState::Undetermined => "session login evidence is unknown",
    };
    let account = login
        .account
        .map(|a| format!(" account {a}"))
        .unwrap_or_default();
    let remedy = match login.evidence.remedy {
        Some(LoginRemedy::KeychainSync) => " — run `csq keychain-sync`",
        None => "",
    };
    Some(format!(
        "Session {}{account}: {message} (daemon snapshot, reason={:?}){remedy}",
        login.handle_pid, login.evidence.reason
    ))
}

/// Both CLI text surfaces use the same persisted-snapshot age and unknown flag.
pub fn snapshot_line(
    status: Option<&keychain::MirrorSyncStatus>,
    age: Option<u64>,
    unknown: bool,
) -> String {
    let age = age
        .map(|seconds| format!("{seconds}s"))
        .unwrap_or_else(|| "unknown".into());
    match status {
        Some(status) => format!("Keychain mirror last persisted sweep: age={age} pending={} failed={} lock_timed_out={} lock_failed={} sessions_undetermined={unknown}",
            status.pending, status.failed, status.lock_timed_out, status.lock_failed),
        None => format!("Keychain mirror evidence: unknown (snapshot age={age}, sessions_undetermined=true)"),
    }
}

#[cfg(all(test, unix))]
fn verified_mirror_fixture_login(
    base: &Path,
    slot: AccountNum,
    email: &str,
) -> crate::accounts::anthropic_identity::CommittedAnthropicLogin {
    use crate::accounts::anthropic_identity as ai;
    let credential: crate::credentials::CredentialFile = serde_json::from_str(
        r#"{"claudeAiOauth":{"accessToken":"synthetic-at","refreshToken":"synthetic-rt","expiresAt":4102444800000}}"#,
    ).unwrap();
    let email = email.to_owned();
    let profile: crate::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(move |url, token, _| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(token, "synthetic-at");
            Ok((
                200,
                serde_json::to_vec(&serde_json::json!({
                    "account": {"email": email, "uuid": "11111111-1111-4111-8111-111111111111"},
                    "organization": {"uuid": "22222222-2222-4222-8222-222222222222"}
                }))
                .unwrap(),
            ))
        });
    let prior = ai::capture_login_prior(base, slot).unwrap();
    ai::commit_anthropic_login_with(base, slot, &credential, &profile, None, prior).unwrap()
}

#[cfg(all(test, unix))]
pub(crate) fn mirror_applicability_fixture(kind: &str) -> (tempfile::TempDir, PathBuf) {
    use crate::accounts::{identity_store, markers, profiles_lock::ProfilesFileLock};
    let base = tempfile::tempdir().unwrap();
    let root = base.path().to_path_buf();
    let account = AccountNum::try_from(1u16).unwrap();
    let config = root.join("config-1");
    std::fs::create_dir_all(&config).unwrap();
    let home = root.join("isolated-claude-home");
    std::fs::create_dir(&home).unwrap();
    let write_config = |dir: &Path, body: &str| {
        let target = dir.join("config.toml");
        let tmp = crate::platform::fs::unique_tmp_path(&target);
        let result = (|| {
            std::fs::write(&tmp, body)?;
            crate::platform::fs::secure_file(&tmp)?;
            crate::platform::fs::atomic_replace(&tmp, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.unwrap();
    };
    if kind == "api_key" {
        crate::accounts::third_party::bind_provider_to_slot(
            &root,
            "mm",
            account,
            Some("SYNTHETIC-API-KEY-ONLY"),
            None,
        )
        .unwrap();
    } else {
        let uuid = if kind.starts_with("codex") {
            let lock = ProfilesFileLock::acquire(&root).unwrap();
            crate::daemon::identity_mint::mint_for_codex_login(
                &lock,
                &root,
                1,
                Some("synthetic-codex-account"),
            )
            .unwrap()
        } else {
            let committed = verified_mirror_fixture_login(&root, account, "synthetic@test.invalid");
            let identity = committed.identity();
            crate::accounts::login::finalize_verified_login(&root, account, committed).unwrap();
            identity
        };
        markers::write_csq_account(&config, uuid).unwrap();
        let path = if kind.starts_with("codex") {
            write_config(&config, "cli_auth_credentials_store = \"file\"\n");
            identity_store::credentials_codex_path_for(&root, uuid)
        } else {
            identity_store::credentials_path_for(&root, uuid)
        };
        if kind.starts_with("codex") {
            std::fs::write(path, r#"{"claudeAiOauth":{"accessToken":"synthetic-at","refreshToken":"synthetic-rt","expiresAt":4102444800000}}"#).unwrap();
        }
    }
    let pid = std::process::id();
    let name = format!("term-{pid}");
    let handle = if kind.starts_with("codex") {
        crate::session::handle_dir::create_handle_dir_codex_named(&root, account, pid, &name)
    } else {
        crate::session::handle_dir::create_handle_dir_named(&root, &home, account, pid, &name)
    }
    .unwrap();
    if matches!(kind, "broken_claude" | "masquerading_claude") {
        std::fs::remove_file(handle.join(".credentials.json")).unwrap();
    }
    if kind == "masquerading_claude" {
        std::fs::write(
            handle.join("auth.json"),
            "opaque synthetic Codex-shaped file",
        )
        .unwrap();
        write_config(&handle, "opaque synthetic config");
    }
    if kind == "wrong_claude" {
        std::fs::remove_file(handle.join(".credentials.json")).unwrap();
        std::os::unix::fs::symlink(
            root.join("config-2/.credentials.json"),
            handle.join(".credentials.json"),
        )
        .unwrap();
    }
    if kind == "codex_dangling_anthropic" {
        let uuid = crate::accounts::profiles::resolve_slot_to_uuid(&root, 1).unwrap();
        std::os::unix::fs::symlink(
            root.join("absent-synthetic-credentials"),
            identity_store::credentials_path_for(&root, uuid),
        )
        .unwrap();
    }
    if kind == "codex_bad_profiles_legacy" {
        std::fs::create_dir_all(root.join("credentials")).unwrap();
        std::fs::write(
            root.join("credentials/codex-1.json"),
            "opaque synthetic credentials",
        )
        .unwrap();
        markers::write_csq_account_legacy(&config, account).unwrap();
        std::fs::write(root.join("profiles.json"), "{invalid synthetic profiles").unwrap();
    }
    if kind == "codex_broken" {
        std::fs::remove_file(handle.join("auth.json")).unwrap();
        std::fs::remove_file(handle.join("config.toml")).unwrap();
    }
    (base, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keychain::RawContentClassification as Raw;

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_reader_excludes_minted_codex_and_api_key() {
        let _env = crate::platform::test_env::lock();
        for kind in ["codex", "codex_broken", "api_key"] {
            let (base, handle) = mirror_applicability_fixture(kind);
            let stored = keychain::MirrorSyncStatus {
                updated_at_unix_ms: keychain::now_ms(),
                sessions: vec![SessionLogin::from_evidence(
                    std::process::id(),
                    Some(AccountNum::try_from(1u16).unwrap()),
                    LoginEvidence::new(LoginState::Current, LoginReason::Current),
                )],
                ..Default::default()
            };
            std::fs::write(
                base.path().join(".keychain-mirror-sync.json"),
                serde_json::to_vec(&stored).unwrap(),
            )
            .unwrap();
            let report = read_diagnostics(base.path());
            assert!(
                report.session_logins.is_empty(),
                "{kind}: {:?}",
                report.session_logins
            );
            assert!(!report.sessions_undetermined, "{kind}");
            let historical = keychain::MirrorSyncStatus {
                updated_at_unix_ms: keychain::now_ms(),
                sessions: vec![SessionLogin::undetermined(
                    std::process::id(),
                    None,
                    LoginReason::HandleInconsistent,
                )],
                sessions_undetermined: true,
                ..Default::default()
            };
            std::fs::write(
                base.path().join(".keychain-mirror-sync.json"),
                serde_json::to_vec(&historical).unwrap(),
            )
            .unwrap();
            let historical = read_diagnostics(base.path());
            assert!(historical.session_logins.is_empty());
            assert!(
                historical.sessions_undetermined,
                "unattributed historical uncertainty"
            );
            assert!(
                observe_handles(base.path(), |_| true).handles.is_empty(),
                "{handle:?}"
            );
        }
    }

    fn raw(token: &str, expiry: u64) -> String {
        serde_json::json!({"claudeAiOauth":{"accessToken":"fixture-access",
            "refreshToken":token,"expiresAt":expiry,"scopes":[]}})
        .to_string()
    }
    fn fp(raw: &str) -> token_history::Fingerprint {
        token_history::fingerprint_from_raw_json(raw).unwrap()
    }
    fn row(state: LoginState) -> SessionLogin {
        SessionLogin::from_evidence(
            45678,
            Some(AccountNum::try_from(1u16).unwrap()),
            LoginEvidence::new(state, LoginReason::Current),
        )
    }
    fn snapshot(now: u64) -> keychain::MirrorSyncStatus {
        keychain::MirrorSyncStatus {
            updated_at_unix_ms: now,
            sessions: vec![row(LoginState::Current)],
            ..Default::default()
        }
    }
    #[cfg(unix)]
    #[test]
    fn mirror_applicability_review_relative_canonical_markers_keep_scope() {
        let _env = crate::platform::test_env::lock();
        for kind in ["api_key", "codex", "claude"] {
            let (base, handle) = mirror_applicability_fixture(kind);
            let expected = mirror_applicability(base.path(), &handle);
            std::fs::remove_file(handle.join(".csq-account")).unwrap();
            std::os::unix::fs::symlink("../config-1/.csq-account", handle.join(".csq-account"))
                .unwrap();
            assert_eq!(
                mirror_applicability(base.path(), &handle),
                expected,
                "{kind}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_oauth_signals_preserve_claude_and_legacy_codex_scope() {
        let _env = crate::platform::test_env::lock();
        let account = AccountNum::try_from(1u16).unwrap();
        for kind in [
            "claude",
            "broken_claude",
            "wrong_claude",
            "masquerading_claude",
        ] {
            let (base, handle) = mirror_applicability_fixture(kind);
            std::fs::create_dir_all(base.path().join("credentials")).unwrap();
            std::fs::write(base.path().join("credentials/codex-1.json"), "synthetic").unwrap();
            let oauth = crate::accounts::binding_guard::oauth_slot_evidence(base.path(), account);
            assert!(oauth.anthropic && oauth.codex, "{kind}");
            assert_eq!(
                mirror_applicability(base.path(), &handle),
                MirrorApplicability::ClaudeOAuth,
                "{kind}"
            );
        }
        let (base, handle) = mirror_applicability_fixture("codex");
        std::fs::create_dir_all(base.path().join("credentials")).unwrap();
        std::fs::write(base.path().join("credentials/codex-1.json"), "synthetic").unwrap();
        crate::accounts::markers::write_csq_account_legacy(&base.path().join("config-1"), account)
            .unwrap();
        std::fs::remove_file(base.path().join("profiles.json")).unwrap();
        let oauth = crate::accounts::binding_guard::oauth_slot_evidence(base.path(), account);
        assert!(!oauth.anthropic && oauth.codex);
        assert_eq!(
            mirror_applicability(base.path(), &handle),
            MirrorApplicability::NotApplicable
        );
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_review_negative_metadata_stays_unknown() {
        let _env = crate::platform::test_env::lock();
        for kind in ["codex_dangling_anthropic", "codex_bad_profiles_legacy"] {
            let (base, handle) = mirror_applicability_fixture(kind);
            assert_eq!(
                mirror_applicability(base.path(), &handle),
                MirrorApplicability::Unknown,
                "{kind}"
            );
            assert_eq!(observe_handles(base.path(), |_| true).handles.len(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_review_malformed_profiles_are_unknown() {
        let _env = crate::platform::test_env::lock();
        let (base, handle) = mirror_applicability_fixture("codex_bad_profiles_legacy");
        assert_eq!(
            mirror_applicability(base.path(), &handle),
            MirrorApplicability::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_review_parent_traversal_never_reads_foreign_canary() {
        assert_foreign_marker_not_read(false);
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_review_alternate_basename_never_reads_foreign_canary() {
        assert_foreign_marker_not_read(true);
    }

    #[cfg(unix)]
    fn assert_foreign_marker_not_read(alternate_basename: bool) {
        use std::io::Write;
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let _env = crate::platform::test_env::lock();
        let (base, handle) = mirror_applicability_fixture("api_key");
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("child")).unwrap();
        std::fs::create_dir(outside.path().join("config-1")).unwrap();
        let fifo = outside.path().join("config-1/.csq-account");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is NUL-terminated and lives across this private FIFO creation.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        std::fs::remove_file(handle.join(".csq-account")).unwrap();
        if alternate_basename {
            let config = base.path().join("config-1");
            std::fs::write(config.join("ordinary"), "opaque local fixture").unwrap();
            std::fs::remove_file(config.join(".csq-account")).unwrap();
            std::os::unix::fs::symlink(&fifo, config.join(".csq-account")).unwrap();
            std::os::unix::fs::symlink(config.join("ordinary"), handle.join(".csq-account"))
                .unwrap();
        } else {
            std::os::unix::fs::symlink(outside.path().join("child"), base.path().join("escape"))
                .unwrap();
            std::os::unix::fs::symlink(
                base.path().join("escape/../config-1/.csq-account"),
                handle.join(".csq-account"),
            )
            .unwrap();
        }
        let root = base.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker =
            std::thread::spawn(move || tx.send(mirror_applicability(&root, &handle)).unwrap());
        // Env custody is done: `mirror_applicability` reads no process env
        // (it is driven entirely by the two explicit paths), and nothing
        // below reads env either. Release the shared lock rather than hold
        // it across the wait bound.
        drop(_env);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut foreign_read = false;
        let result = loop {
            if let Ok(result) = rx.try_recv() {
                break result;
            }
            // A nonblocking FIFO writer succeeds only after a reader opened the
            // canary. Feed a synthetic marker to unblock the regressed reader.
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
            {
                Ok(mut writer) => {
                    foreign_read = true;
                    writer.write_all(b"1\n").unwrap();
                    drop(writer);
                    break rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap();
                }
                Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ENXIO)),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "classifier did not return"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        worker.join().unwrap();
        assert!(!foreign_read, "classifier opened the foreign canary");
        assert_eq!(result, MirrorApplicability::Unknown);
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_mixed_surface_pid_is_ambiguous() {
        let _env = crate::platform::test_env::lock();
        let (base, _) = mirror_applicability_fixture("api_key");
        let account = AccountNum::try_from(2u16).unwrap();
        let config = base.path().join("config-2");
        std::fs::create_dir(&config).unwrap();
        let committed =
            verified_mirror_fixture_login(base.path(), account, "second-synthetic@test.invalid");
        let uuid = committed.identity();
        crate::accounts::login::finalize_verified_login(base.path(), account, committed).unwrap();
        crate::accounts::markers::write_csq_account(&config, uuid).unwrap();
        let pid = std::process::id();
        crate::session::handle_dir::create_handle_dir_named(
            base.path(),
            &base.path().join("isolated-claude-home"),
            account,
            pid,
            &format!("term-{}", pid + 1),
        )
        .unwrap();
        let live = observe_handles(base.path(), |_| true);
        assert_eq!(live.handles.get(&pid), Some(&None));
        assert!(live.undetermined);
        let stored = keychain::MirrorSyncStatus {
            updated_at_unix_ms: keychain::now_ms(),
            sessions: vec![SessionLogin::from_evidence(
                pid,
                Some(account),
                LoginEvidence::new(LoginState::Current, LoginReason::Current),
            )],
            ..Default::default()
        };
        let report = project_snapshot(
            Some(stored),
            keychain::now_ms(),
            live,
            |_, _, _| panic!("ambiguous owner must not be attributed"),
            true,
        );
        assert!(report.sessions_undetermined);
        assert_eq!(report.session_logins[0].account, None);
        assert_eq!(
            report.session_logins[0].evidence.reason,
            LoginReason::OwnerChanged
        );
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_partial_uuid_cannot_use_stale_api_key_label() {
        let _env = crate::platform::test_env::lock();
        for missing in [true, false] {
            let (base, handle) = mirror_applicability_fixture("api_key");
            // Retain the stale API-key label/settings after verified publication.
            // A surviving canonical OAuth file is still a real Claude surface;
            // the deliberately partial state below removes it as well as metadata.
            let committed = verified_mirror_fixture_login(
                base.path(),
                AccountNum::try_from(1u16).unwrap(),
                "partial-synthetic@test.invalid",
            );
            let uuid = committed.identity();
            assert_eq!(
                mirror_applicability(base.path(), &handle),
                MirrorApplicability::ClaudeOAuth,
                "the genuine canonical grant is an OAuth surface before corruption"
            );
            std::fs::remove_file(crate::accounts::identity_store::credentials_path_for(
                base.path(),
                uuid,
            ))
            .unwrap();
            let identity =
                crate::accounts::identity_store::identity_json_path_for(base.path(), uuid);
            if missing {
                std::fs::remove_file(identity).unwrap();
            } else {
                std::fs::write(identity, r#"{"provider":null}"#).unwrap();
            }
            assert_eq!(
                mirror_applicability(base.path(), &handle),
                MirrorApplicability::Unknown
            );
            assert_eq!(observe_handles(base.path(), |_| true).handles.len(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mirror_applicability_ambiguous_files_and_api_key_mixed_evidence_stay_unknown() {
        let _env = crate::platform::test_env::lock();
        let (base, handle) = mirror_applicability_fixture("api_key");
        std::fs::write(handle.join(".credentials.json.swap-tmp"), "opaque").unwrap();
        assert_eq!(
            mirror_applicability(base.path(), &handle),
            MirrorApplicability::Unknown
        );
        let live = observe_handles(base.path(), |_| true);
        assert_eq!(live.handles.len(), 1);
        std::fs::remove_file(handle.join(".credentials.json.swap-tmp")).unwrap();
        std::fs::remove_file(base.path().join("profiles.json")).unwrap();
        std::fs::write(handle.join("auth.json"), "opaque Codex-shaped file").unwrap();
        assert_eq!(
            mirror_applicability(base.path(), &handle),
            MirrorApplicability::Unknown
        );
        assert_eq!(observe_handles(base.path(), |_| true).handles.len(), 1);
    }

    #[test]
    fn session_login_superseded_raw_policy_has_exact_fix() {
        let old = raw("fixture-old", u64::MAX - 1);
        let current = raw("fixture-current", u64::MAX);
        let ev = classify_login(
            &Raw::Content(old.clone().into()),
            &current,
            &[fp(&old), fp(&current)],
            &[],
        );
        assert_eq!(ev.state, LoginState::Superseded);
        assert_eq!(ev.remedy, Some(LoginRemedy::KeychainSync));
        assert!(finding_line(&SessionLogin::from_evidence(1, None, ev))
            .unwrap()
            .contains("run `csq keychain-sync`"));
    }
    #[test]
    fn session_login_current_foreign_unknown_rollback_and_duplicate_history() {
        let old = raw("fixture-old", 1);
        let current = raw("fixture-current", 2);
        let foreign = raw("fixture-foreign", 0);
        let h = [fp(&old), fp(&current)];
        assert_eq!(
            classify_login(&Raw::Content(current.clone().into()), &current, &h, &[]).state,
            LoginState::Current
        );
        for (seen, canonical, history) in [
            (&foreign, &current, h.as_slice()),
            (&old, &current, &[]),
            (&current, &old, h.as_slice()),
            (&old, &current, &[fp(&old), fp(&current), fp(&old)]),
        ] {
            let ev = classify_login(&Raw::Content(seen.clone().into()), canonical, history, &[]);
            assert_eq!(ev.state, LoginState::Unproven);
            assert_eq!(ev.remedy, None);
        }
    }
    #[test]
    fn session_login_original_malformed_content_is_not_reserialized_into_repair() {
        let current = raw("fixture-current", u64::MAX);
        let malformed=Raw::Content(r#"{"claudeAiOauth":{"refreshToken":"fixture-old","accessToken":false},"sibling":true}"#.to_owned().into());
        let ev = classify_login(&malformed, &current, &[], &[]);
        assert_eq!(ev.state, LoginState::Undetermined);
        assert_eq!(ev.remedy, None);
    }
    #[test]
    fn session_login_owner_verified_recognition_never_proves_order_alone() {
        let old = raw("fixture-old", u64::MAX);
        let current = raw("fixture-current", u64::MAX - 1);
        let h = [fp(&old), fp(&current)];
        let x = Raw::Content(old.clone().into());
        assert_eq!(classify_login(&x, &current, &h, &[]).remedy, None);
        assert_eq!(
            classify_login(&x, &current, &h, &[fp(&old)]).remedy,
            Some(LoginRemedy::KeychainSync)
        );
        assert_eq!(
            classify_login(&x, &current, &[], &[fp(&old)]).state,
            LoginState::Unproven
        );
    }
    #[test]
    fn session_login_absent_unavailable_and_malformed_are_distinct() {
        let current = raw("fixture-current", u64::MAX);
        assert_eq!(
            classify_login(&Raw::Absent, &current, &[], &[]).state,
            LoginState::KeychainAbsent
        );
        assert_eq!(
            classify_login(
                &Raw::Unreadable(keychain::UnreadableKind::Transient),
                &current,
                &[],
                &[]
            )
            .state,
            LoginState::KeychainUnavailable
        );
    }
    fn live(pids: &[u32]) -> LiveHandles {
        LiveHandles {
            handles: pids
                .iter()
                .map(|pid| (*pid, Some(PathBuf::from(format!("term-{pid}")))))
                .collect(),
            undetermined: false,
            not_applicable: BTreeSet::new(),
        }
    }
    fn project(
        status: Option<keychain::MirrorSyncStatus>,
        now: u64,
        live: LiveHandles,
    ) -> LoginDiagnostics {
        project_snapshot(status, now, live, |_, _, _| Ok(()), true)
    }
    #[test]
    fn session_login_missing_snapshot_and_new_sessions_are_unknown() {
        let r = project(None, 1, live(&[45678]));
        assert!(r.sessions_undetermined);
        assert!(r.keychain_mirror.is_none());
        assert_eq!(
            r.session_logins[0].evidence.reason,
            LoginReason::NotInSnapshot
        );
        let r = project(Some(snapshot(1)), 1, live(&[45678, 45679]));
        assert_eq!(r.session_logins.len(), 2);
        assert_eq!(
            r.session_logins[1].evidence.reason,
            LoginReason::NotInSnapshot
        );
        assert!(r.sessions_undetermined);
        assert_eq!(r.keychain_mirror.unwrap().sessions, r.session_logins);
    }
    #[test]
    fn session_login_unchanged_old_snapshot_retains_evidence_and_age() {
        let r = project(Some(snapshot(1)), 2_000_000, live(&[45678]));
        assert!(!r.sessions_undetermined);
        assert_eq!(r.session_logins[0].evidence.state, LoginState::Current);
        assert_eq!(r.snapshot_age_secs, Some(1999));
        assert!(r.keychain_mirror.is_some());
    }
    #[test]
    fn session_login_future_zero_and_contradictory_snapshots_are_unknown() {
        let mut contradictory = snapshot(1);
        contradictory.sessions[0].evidence.reason = LoginReason::OwnerChanged;
        for s in [snapshot(2), snapshot(0), contradictory] {
            let r = project(Some(s), 1, live(&[45678]));
            assert!(r.sessions_undetermined);
            assert!(r.keychain_mirror.is_none());
            assert_eq!(
                r.session_logins[0].evidence.reason,
                LoginReason::NotInSnapshot
            );
        }
    }
    #[test]
    fn session_login_unknown_rows_stay_visible_and_dead_owners_lose_attribution() {
        let mut s = snapshot(1);
        s.sessions.push(SessionLogin::undetermined(
            45679,
            None,
            LoginReason::MarkerUnresolved,
        ));
        let r = project(Some(s), 1001, live(&[45679]));
        assert_eq!(r.snapshot_age_secs, Some(1));
        assert_eq!(r.session_logins.len(), 2);
        assert!(r.sessions_undetermined);
        assert_eq!(
            r.session_logins[0].evidence.reason,
            LoginReason::OwnerChanged
        );
        assert!(r.session_logins[0].account.is_none());
        assert_eq!(
            r.session_logins[1].evidence.reason,
            LoginReason::MarkerUnresolved
        );
    }
    #[test]
    fn session_login_changed_metadata_removes_remedy_in_both_views() {
        let mut s = snapshot(1);
        s.sessions[0].evidence = LoginEvidence {
            state: LoginState::Superseded,
            reason: LoginReason::Superseded,
            remedy: Some(LoginRemedy::KeychainSync),
        };
        let r = project_snapshot(
            Some(s),
            1,
            live(&[45678]),
            |_, _, _| Err(LoginReason::CanonicalChanged),
            true,
        );
        assert!(r.sessions_undetermined);
        let row = &r.session_logins[0];
        assert!(row.account.is_none());
        assert!(row.evidence.remedy.is_none());
        assert_eq!(row.evidence.reason, LoginReason::CanonicalChanged);
        assert_eq!(
            r.keychain_mirror.as_ref().unwrap().sessions,
            r.session_logins
        );
    }
    #[test]
    fn session_login_disabled_platform_omits_rows_but_keeps_unknown() {
        let mut s = snapshot(1);
        s.sessions[0] = SessionLogin::undetermined(45678, None, LoginReason::KeychainDisabled);
        let r = project_snapshot(
            Some(s),
            1,
            live(&[45678]),
            |_, _, _| panic!("disabled row must not probe"),
            false,
        );
        assert!(r.sessions_undetermined);
        assert!(r.session_logins.is_empty());
        assert!(r.keychain_mirror.unwrap().sessions.is_empty());
    }
    #[test]
    fn session_login_collector_errors_caps_and_duplicate_owners_are_unknown() {
        let error = std::io::Error::other("fixture unreadable entry");
        let r = collect_handles([Err(error)].into_iter(), |_| panic!("no path"));
        assert!(r.undetermined);
        let entries = (0..=MAX_DIRECTORY_ENTRIES).map(|i| Ok(PathBuf::from(format!("config-{i}"))));
        assert!(collect_handles(entries, |_| panic!("not a handle")).undetermined);
        let entries = (1..=MAX_LIVE_HANDLES + 1).map(|i| Ok(PathBuf::from(format!("term-{i}"))));
        assert!(collect_handles(entries, |path| Ok(dirname_pid(path))).undetermined);
        let entries = ["term-1", "term-2"].map(|p| Ok(PathBuf::from(p)));
        let r = collect_handles(entries.into_iter(), |_| Ok(Some(45678)));
        assert!(r.undetermined);
        assert_eq!(r.handles.get(&45678), Some(&None));
        let r = project(Some(snapshot(1)), 1, r);
        assert!(r.sessions_undetermined);
        assert_eq!(
            r.session_logins[0].evidence.reason,
            LoginReason::OwnerChanged
        );
    }
    #[test]
    fn session_login_snapshot_reader_missing_and_corrupt_are_unknown() {
        let base = tempfile::tempdir().unwrap();
        assert!(read_diagnostics(base.path()).sessions_undetermined);
        std::fs::write(base.path().join(".keychain-mirror-sync.json"), b"malformed").unwrap();
        assert!(read_diagnostics(base.path()).sessions_undetermined);
        assert!(observe_handles(&base.path().join("absent"), |_| true).undetermined);
    }

    #[cfg(unix)]
    fn set_mtime(path: &Path, stamp: u64) {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_millis(stamp);
        if std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_symlink()
        {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let times = [libc::timespec {
                tv_sec: (stamp / 1000) as _,
                tv_nsec: ((stamp % 1000) * 1_000_000) as _,
            }; 2];
            // SAFETY: valid NUL-terminated temp fixture path and two timespecs;
            // AT_SYMLINK_NOFOLLOW updates only the fixture link itself.
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0
            );
        } else {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(time))
                .unwrap();
        }
    }
    #[cfg(unix)]
    struct MetadataFixture {
        base: tempfile::TempDir,
        handle: PathBuf,
        credential: PathBuf,
        marker: PathBuf,
        stamp: u64,
        row: SessionLogin,
    }
    #[cfg(unix)]
    impl MetadataFixture {
        fn new(uuid: bool) -> Self {
            let base = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(base.path()).unwrap();
            let handle = root.join("term-1");
            let slot = root.join("config-1");
            std::fs::create_dir(&handle).unwrap();
            std::fs::create_dir(&slot).unwrap();
            let marker = slot.join(".csq-account");
            // Numeric and UUID marker bytes share this producer path. Neither
            // marker nor credential contents are interpreted by the reader.
            let id = "550e8400-e29b-41d4-a716-446655440000";
            std::fs::write(&marker, if uuid { id } else { "1" }).unwrap();
            let credential = if uuid {
                let dir = root.join("identities").join(id);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(root.join("profiles.json"), b"opaque fixture; never parsed")
                    .unwrap();
                dir.join("credentials.json")
            } else {
                slot.join(".credentials.json")
            };
            std::fs::write(&credential, b"opaque fixture; never parsed").unwrap();
            std::os::unix::fs::symlink(&credential, handle.join(".credentials.json")).unwrap();
            std::os::unix::fs::symlink(&marker, handle.join(".csq-account")).unwrap();
            let mut row = row(LoginState::Current);
            row.handle_pid = std::process::id();
            std::fs::write(handle.join(".live-pid"), row.handle_pid.to_string()).unwrap();
            let stamp = keychain::now_ms() - 1_000_000;
            for path in [
                &credential,
                &marker,
                &handle.join(".credentials.json"),
                &handle.join(".csq-account"),
            ] {
                set_mtime(path, stamp);
            }
            if uuid {
                set_mtime(&root.join("profiles.json"), stamp);
            }
            Self {
                base,
                handle,
                credential,
                marker,
                stamp,
                row,
            }
        }
        fn checked(&self) -> Result<(), LoginReason> {
            check_metadata(self.base.path(), &self.handle, &self.row, self.stamp)
        }
        fn report(&self) -> LoginDiagnostics {
            let stored = keychain::MirrorSyncStatus {
                updated_at_unix_ms: self.stamp,
                sessions: vec![self.row.clone()],
                ..Default::default()
            };
            std::fs::write(
                self.base.path().join(".keychain-mirror-sync.json"),
                serde_json::to_vec(&stored).unwrap(),
            )
            .unwrap();
            read_diagnostics(self.base.path())
        }
    }
    #[cfg(unix)]
    #[test]
    fn session_login_local_legacy_and_uuid_old_snapshots_use_actual_pid_marker() {
        for uuid in [false, true] {
            let fixture = MetadataFixture::new(uuid);
            assert_eq!(fixture.checked(), Ok(()));
            let r = fixture.report();
            assert!(!r.sessions_undetermined);
            assert!(r.snapshot_age_secs.unwrap() >= 1000);
            assert_eq!(r.session_logins, vec![fixture.row.clone()]);
            assert!(observe_handles(fixture.base.path(), |_| false)
                .handles
                .is_empty());
            assert!(observe_handles(fixture.base.path(), |_| true)
                .handles
                .contains_key(&std::process::id()));
        }
    }
    #[cfg(unix)]
    #[test]
    fn session_login_changed_local_metadata_fails_closed_without_secret_reads() {
        for name in [
            "credential",
            "marker",
            "credential_link",
            "marker_link",
            "profile",
        ] {
            let fixture = MetadataFixture::new(true);
            let path = match name {
                "credential" => fixture.credential.clone(),
                "marker" => fixture.marker.clone(),
                "credential_link" => fixture.handle.join(".credentials.json"),
                "marker_link" => fixture.handle.join(".csq-account"),
                _ => fixture.base.path().join("profiles.json"),
            };
            set_mtime(&path, fixture.stamp + 1);
            let reason = if name == "credential" {
                LoginReason::CanonicalChanged
            } else {
                LoginReason::OwnerChanged
            };
            assert_eq!(fixture.checked(), Err(reason), "{name}");
            let r = fixture.report();
            assert!(r.sessions_undetermined);
            assert_eq!(r.session_logins[0].evidence.reason, reason);
            assert!(r.session_logins[0].account.is_none());
        }
    }
    #[cfg(unix)]
    #[test]
    fn session_login_same_millisecond_later_write_is_changed() {
        let fixture = MetadataFixture::new(false);
        let time = std::time::UNIX_EPOCH
            + std::time::Duration::from_millis(fixture.stamp)
            + std::time::Duration::from_micros(1);
        std::fs::File::options()
            .write(true)
            .open(&fixture.credential)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(time))
            .unwrap();
        assert_eq!(fixture.checked(), Err(LoginReason::CanonicalChanged));
        assert_eq!(
            fixture.report().session_logins[0].evidence.reason,
            LoginReason::CanonicalChanged
        );
    }
    #[cfg(unix)]
    #[test]
    fn session_login_external_swapped_missing_and_symlinked_targets_are_unknown() {
        let fixture = MetadataFixture::new(false);
        let link = fixture.handle.join(".credentials.json");
        std::fs::remove_file(&link).unwrap();
        // An external missing target must be refused before target inspection.
        std::os::unix::fs::symlink("/outside/fixture-credential", &link).unwrap();
        set_mtime(&link, fixture.stamp);
        assert_eq!(fixture.checked(), Err(LoginReason::OwnerChanged));
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&fixture.credential, &link).unwrap();
        set_mtime(&link, fixture.stamp);
        std::fs::write(fixture.handle.join(".csq-account.swap-tmp"), b"fixture").unwrap();
        assert_eq!(fixture.checked(), Err(LoginReason::OwnerChanged));
        std::fs::remove_file(fixture.handle.join(".csq-account.swap-tmp")).unwrap();
        std::fs::remove_file(&fixture.credential).unwrap();
        assert_eq!(fixture.checked(), Err(LoginReason::CanonicalUnavailable));
        std::os::unix::fs::symlink("/outside/fixture", &fixture.credential).unwrap();
        assert_eq!(fixture.checked(), Err(LoginReason::CanonicalUnavailable));
    }
    #[cfg(unix)]
    #[test]
    fn session_login_pid_marker_unreadable_never_uses_live_dirname_fallback() {
        let fixture = MetadataFixture::new(false);
        let pidfile = fixture.handle.join(".live-pid");
        for bytes in [b"invalid".as_slice(), b"0", &[b'1'; 65]] {
            std::fs::write(&pidfile, bytes).unwrap();
            let live = observe_handles(fixture.base.path(), |_| true);
            assert!(live.undetermined);
            assert_eq!(live.handles.get(&1), Some(&None));
            assert_eq!(fixture.checked(), Err(LoginReason::OwnerChanged));
            assert!(fixture.report().sessions_undetermined);
        }
        std::fs::remove_file(&pidfile).unwrap();
        std::os::unix::fs::symlink(&fixture.marker, &pidfile).unwrap();
        assert!(observe_handles(fixture.base.path(), |_| true).undetermined);
        std::fs::remove_file(&pidfile).unwrap();
        // Absent marker is the producer's legitimate directory-PID fallback.
        let live = observe_handles(fixture.base.path(), |_| true);
        assert!(!live.undetermined);
        assert!(live.handles.get(&1).unwrap().is_some());
    }
    #[test]
    fn session_login_persisted_rows_accept_no_arbitrary_reason_or_secret_fields() {
        let mut json = serde_json::to_value(row(LoginState::Current)).unwrap();
        json["evidence"]["reason"] = serde_json::json!("fixture-token");
        assert!(serde_json::from_value::<SessionLogin>(json).is_err());
        let mut json = serde_json::to_value(row(LoginState::Current)).unwrap();
        json["token"] = serde_json::json!("fixture-secret");
        assert!(serde_json::from_value::<SessionLogin>(json).is_err());
    }
}
