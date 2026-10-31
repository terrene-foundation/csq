//! Account login helpers shared between csq-cli and csq-desktop.
//!
//! - [`find_claude_binary`] locates the `claude` CLI from BOTH the
//!   inherited `$PATH` and a fixed list of well-known install
//!   directories. The well-known list matters because Finder-launched
//!   macOS apps (the desktop bundle) inherit only a minimal `PATH`
//!   (`/usr/bin:/bin:/usr/sbin:/sbin`) — the user's shell-installed
//!   `claude` (typically in `/usr/local/bin`, `/opt/homebrew/bin`, or
//!   `~/.npm-global/bin`) is invisible to plain `Command::new("claude")`.
//!   The desktop's `start_claude_login` Tauri command was disabled in
//!   alpha.5 (per an internal journal entry §2) precisely because of this PATH gap.
//!
//! - [`read_email_from_claude_json`] reads the OAuth account email
//!   that CC writes to `<config_dir>/.claude.json` after a successful
//!   `claude auth login`. Both `csq login N` and the desktop Add
//!   Account modal may use this as display or expected-context metadata; the
//!   exact incoming grant must independently verify its account and organization
//!   before publishing any `profiles.json` identity binding.
//!
//! - [`finalize_verified_login`] consumes an exact-grant commit receipt, writes
//!   its identity marker under a custody lock, and queues asynchronous mirroring.

use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::accounts::{markers, profiles};
use crate::credentials;
#[cfg(test)]
use crate::credentials::file as cred_file;
use crate::error::ConfigError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Returns the absolute path to the `claude` CLI binary, if
/// installed and executable.
///
/// Search order:
///  1. Walk `$PATH` (matches the legacy `which_claude` behaviour).
///  2. Walk a fixed list of well-known install directories that
///     survive a Finder launch (i.e. don't depend on the shell rc).
///  3. Walk `$HOME/<sub>` for common per-user install layouts
///     (`.local/bin`, `.npm-global/bin`, `.bun/bin`, `.cargo/bin`).
///
/// Returns `None` if no executable `claude` is found anywhere.
///
/// # Per-spawn resolution (R3/B87)
///
/// This function MUST NOT cache its result at startup or across
/// invocations. Every call must probe the filesystem fresh so that
/// `CSQ_BENCH_MODE=1` runs (which inject a temporary binary via
/// `CLAUDE_PATH`) always see the current value of `$PATH` at the
/// moment of the probe. Any `static` or `OnceLock` cache would
/// silently lock in the binary path from the first call and break
/// bench-mode PATH injection. This is the authoritative per-spawn
/// resolution site; no other site may cache the result.
pub fn find_claude_binary() -> Option<PathBuf> {
    // 1. $PATH walk.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if let Some(p) = check_dir(&dir) {
                return Some(p);
            }
        }
    }

    // 2. System-wide well-known locations.
    for sys_dir in SYSTEM_WIDE_DIRS {
        if let Some(p) = check_dir(Path::new(sys_dir)) {
            return Some(p);
        }
    }

    // 3. Per-user well-known locations under $HOME.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_SUBDIRS {
            if let Some(p) = check_dir(&home.join(sub)) {
                return Some(p);
            }
        }
    }

    None
}

/// Reads the OAuth account email out of `<config_dir>/.claude.json`.
///
/// CC writes `oauthAccount.emailAddress` to its local `.claude.json`
/// during `claude auth login`. This is a file-only read with no
/// subprocess. It supplies display metadata, never verified ownership authority.
/// It avoids the status-query timing window of
/// `claude auth status --json`, which has a documented timing
/// window where stdout can lack `email` if csq runs it too soon
/// after auth completes (see an internal journal entry §1).
///
/// Returns `None` if the file is missing, malformed, or has no
/// non-empty `emailAddress` field. Callers should fall back to
/// `"unknown"` for display only. Identity publication still requires the complete
/// expected context and exact-grant profile verification.
pub fn read_email_from_claude_json(config_dir: &Path) -> Option<String> {
    let path = config_dir.join(".claude.json");
    let content = std::fs::read_to_string(&path).ok()?;
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

/// Evidence from this login's canonical transition; never persisted or caller-constructed.
#[cfg(target_os = "macos")]
pub struct LoginMirrorContext {
    base: PathBuf,
    account: AccountNum,
    identity: crate::accounts::identity_store::IdentityId,
    prior: crate::credentials::token_history::Fingerprint,
    incoming: [u8; 32],
    expires: std::time::Instant,
    custody: Option<crate::accounts::anthropic_identity::CapturedBinding>,
}

#[cfg(not(target_os = "macos"))]
pub struct LoginMirrorContext;

/// Capture exact pre-write evidence for the selected target, without reading a live account.
pub(crate) fn prepare_verified_login_mirror(
    base: &Path,
    account: AccountNum,
    identity: crate::accounts::identity_store::IdentityId,
    credential: &credentials::CredentialFile,
) -> Option<LoginMirrorContext> {
    #[cfg(target_os = "macos")]
    {
        let prior = read_login_canonical(base, identity)?;
        login_raw_version(&prior)?;
        Some(LoginMirrorContext {
            base: std::fs::canonicalize(base).ok()?,
            account,
            identity,
            prior: crate::credentials::token_history::fingerprint_from_raw_json(&prior)?,
            incoming: login_credential_version(credential)?,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(600),
            custody: None,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (base, account, identity, credential);
        None
    }
}

/// Remedy for a damaged organization record. It never names `csq login`: login refuses on
/// the same record, so that advice would send the operator in a circle.
const INDEX_DAMAGED_REMEDY: &str = "profiles.json holds a damaged organization record that may belong to this account; restore a trusted profiles.json backup and do not hand-edit it, because signing in again cannot clear a damaged record";

/// The one outcome vocabulary for a verified-login commit that did not land.
///
/// The daemon (`/api/oauth/exchange`), the CLI (`csq login`) and the desktop
/// (login / paste-code / race) all map `IdentityError` through THIS type, so
/// every surface reports the same fixed `error_kind` and the same operator
/// message. A busy profiles store is a retry, never an identity refusal; a
/// publication failure after another identity's canonical credentials were
/// advanced is named explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginCommitOutcome {
    /// Staging/publishing failed with an I/O fault; nothing observable advanced.
    PublicationFailed,
    /// The existing target's canonical credentials were advanced, then the
    /// remaining publication failed.
    TargetAdvancedPublicationFailed,
    /// The slot's login authority moved while the login ran.
    IdentityChanged,
    /// The profiles store was held by another operation; retry.
    Busy,
    /// The grant's organization identity could not be confirmed.
    Refused,
    /// The committed receipt was refused at finalization.
    FinalizationRefused,
    /// A damaged organization record in profiles.json may belong to this account.
    /// Logging in again cannot clear it, so it has its own tag and remedy.
    IndexDamaged,
}

impl LoginCommitOutcome {
    /// Map a commit failure.
    pub fn from_identity_error(error: &crate::accounts::anthropic_identity::IdentityError) -> Self {
        use crate::accounts::anthropic_identity::IdentityError as E;
        match error {
            E::Io => Self::PublicationFailed,
            E::TargetAdvancedPublicationFailed => Self::TargetAdvancedPublicationFailed,
            E::BindingChanged => Self::IdentityChanged,
            E::BindingBusy => Self::Busy,
            E::DamagedContextIndexRow => Self::IndexDamaged,
            // Explicit: both are identity refusals whose remedy text lives in
            // `describe_error` (they name a slot), not the generic one.
            E::SiblingCustodyUnreadable { .. } | E::LoginCredentialHeldElsewhere { .. } => {
                Self::Refused
            }
            _ => Self::Refused,
        }
    }

    /// Fixed-vocabulary tag; also the daemon's `error_kind` log field.
    pub fn error_kind(self) -> &'static str {
        match self {
            Self::PublicationFailed => "oauth_login_publication_failed",
            Self::TargetAdvancedPublicationFailed => {
                "oauth_login_target_advanced_publication_failed"
            }
            Self::IdentityChanged => "oauth_identity_changed",
            Self::Busy => "oauth_identity_busy",
            Self::Refused => "oauth_identity_refused",
            Self::FinalizationRefused => "oauth_identity_finalization_refused",
            Self::IndexDamaged => "oauth_identity_index_damaged",
        }
    }

    /// Inverse of [`Self::error_kind`]; an unknown tag is a publication failure.
    pub fn from_error_kind(kind: &str) -> Self {
        [
            Self::TargetAdvancedPublicationFailed,
            Self::IdentityChanged,
            Self::Busy,
            Self::Refused,
            Self::FinalizationRefused,
            Self::IndexDamaged,
        ]
        .into_iter()
        .find(|outcome| outcome.error_kind() == kind)
        .unwrap_or(Self::PublicationFailed)
    }

    /// Operator-facing text; carries no token, body or path.
    pub fn message(self) -> &'static str {
        match self {
            Self::PublicationFailed => "credential publication failed",
            Self::TargetAdvancedPublicationFailed => {
                "login stopped after this slot's existing credentials were advanced; run the login again to finish"
            }
            Self::IdentityChanged => "login authority changed; start login again",
            Self::Busy => "another csq operation holds the profiles store; retry the login in a moment",
            Self::Refused => "organization identity could not be confirmed; login refused",
            Self::FinalizationRefused => "verified login finalization refused; start login again",
            Self::IndexDamaged => INDEX_DAMAGED_REMEDY,
        }
    }

    /// `"<message> (<error_kind>)"` — the one line every surface shows.
    ///
    /// Preserve specific fixed-text remedies rather than sending every refusal
    /// back to a login that cannot repair the broken local authority.
    pub fn describe_error(error: &crate::accounts::anthropic_identity::IdentityError) -> String {
        use crate::accounts::anthropic_identity::IdentityError as E;
        let outcome = Self::from_identity_error(error);
        let message = match error {
            E::BoundIdentityMetadataMissing { account } => format!(
                "identity.json is missing for this slot; run `csq logout {account}` then `csq login {account}` to replace the broken slot binding"
            ),
            E::InvalidMetadata => "identity metadata was refused; run `csq logout N` then `csq login N`; do not hand-edit identity metadata or profiles.json".to_owned(),
            E::LegacyEmailUnparseable => "the recorded legacy email cannot be verified; run `csq login N` to authenticate the affected slot".to_owned(),
            E::UnsafePermissions => "identity.json or credentials.json has unsafe permissions; restore private permissions only after confirming no other user modified the file, or run `csq logout N` then `csq login N`".to_owned(),
            E::MultipleLinks => "identity.json or credentials.json has extra hard links; remove the extra links after confirming the file contents, or run `csq logout N` then `csq login N`".to_owned(),
            E::SnapshotChanged => "the file changed while it was read; retry the operation".to_owned(),
            E::ProfilesUnsafePermissions => "profiles.json has unsafe permissions; run chmod 600 on profiles.json after confirming no other user modified it; if its provenance is untrusted, restore a trusted backup".to_owned(),
            E::ProfilesMultipleLinks => "profiles.json has extra hard links; remove the extra links after confirming its contents; otherwise restore a trusted backup".to_owned(),
            E::ProfilesSnapshotChanged => "profiles.json kept changing while it was read; retry the operation".to_owned(),
            E::ProfilesReadRefused => "profiles.json could not be safely read; restore a trusted backup; do not hand-edit identity metadata or profiles.json".to_owned(),
            E::DamagedContextIndexRow => INDEX_DAMAGED_REMEDY.to_owned(),
            E::SharedLegacyIdentity => "this legacy identity is shared by several slots or its organization is already held by another identity; authenticate each affected slot with `csq login` and its own slot number so each one is verified individually".to_owned(),
            E::SiblingCustodyUnreadable { sibling } => match sibling.account() {
                Some(slot) => format!(
                    "slot {slot}'s stored identity is unreadable; run `csq login {slot}` or `csq logout {slot}` to replace it (the slot being logged in is unaffected)"
                ),
                None => "another slot's stored identity is unreadable; run `csq login <slot>` or `csq logout <slot>` for that slot to replace it (the slot being logged in is unaffected)".to_owned(),
            },
            E::LoginCredentialHeldElsewhere { holder } => match holder.account() {
                Some(slot) => format!(
                    "this login produced a credential that slot {slot} already holds; run `csq login N` again so a fresh credential is issued, or `csq logout {slot}` if slot {slot} is the one that is stale"
                ),
                None => "this login produced a credential that another slot already holds; run `csq login N` again so a fresh credential is issued".to_owned(),
            },
            _ => outcome.message().to_owned(),
        };
        format!("{message} ({})", outcome.error_kind())
    }

    /// Account-aware commit wording shared by CLI and desktop. A new login
    /// helps only the transient/changed-authority outcomes, not every refusal.
    /// [`Self::describe_error_for_account`] for a FAILED login commit, plus
    /// the fixed operator line when the commit's refusal could not be made
    /// durable (corr LOW-1: every login surface shows the same line as the
    /// CLI). Reads and clears the process flag.
    pub fn describe_commit_failure_for_account(
        error: &crate::accounts::anthropic_identity::IdentityError,
        account: AccountNum,
    ) -> String {
        let text = Self::describe_error_for_account(error, account);
        match crate::credentials::rescue::take_refusal_not_durable_notice() {
            Some(notice) => format!("{text}; {notice}"),
            None => text,
        }
    }

    pub fn describe_error_for_account(
        error: &crate::accounts::anthropic_identity::IdentityError,
        account: AccountNum,
    ) -> String {
        let outcome = Self::from_identity_error(error);
        let text = Self::describe_error(error)
            .replace("csq logout N", &format!("csq logout {account}"))
            .replace("csq login N", &format!("csq login {account}"));
        if matches!(
            outcome,
            Self::IdentityChanged | Self::Busy | Self::TargetAdvancedPublicationFailed
        ) {
            let suffix = format!(" ({})", outcome.error_kind());
            let message = match outcome {
                Self::IdentityChanged => "login authority changed",
                Self::Busy => "another csq operation holds the profiles store",
                _ => text.strip_suffix(&suffix).unwrap_or(&text),
            };
            format!("{message}; run `csq login {account}` again{suffix}")
        } else {
            text
        }
    }

    /// Message for a failure BEFORE any login ran (the `capture_login_prior`
    /// snapshot). Nothing was published, so the commit-time wording of
    /// [`Self::describe_error`] ("credential publication failed") would be
    /// wrong. Contention uses the shared retry message; other failures retain
    /// their specific identity text, like the CLI surface shows.
    pub fn describe_prior_capture_error(
        error: &crate::accounts::anthropic_identity::IdentityError,
    ) -> String {
        if matches!(
            error,
            crate::accounts::anthropic_identity::IdentityError::BindingBusy
        ) {
            Self::describe_error(error)
        } else {
            error.to_string()
        }
    }
}

/// Finish only the identity committed by the exact verified grant. Never remint or reseed.
pub fn finalize_verified_login(
    base: &Path,
    account: AccountNum,
    committed: crate::accounts::anthropic_identity::CommittedAnthropicLogin,
) -> Result<String, ConfigError> {
    use crate::accounts::anthropic_identity::{self as ai, StoredAnthropicContext};
    let refused = || ConfigError::InvalidJson {
        path: profiles::profiles_path(base),
        reason: "anthropic_identity_finalization_refused".into(),
    };
    if committed.binding().slot() != account {
        return Err(refused());
    }
    let lock = ProfilesFileLock::acquire(base)?;
    if !committed
        .independent_matches_locked(&lock, base)
        .map_err(|_| refused())?
    {
        return Err(refused());
    }
    let (binding, mirror, fingerprint) = committed.into_parts();
    #[cfg(target_os = "macos")]
    let mirror =
        mirror.and_then(|mut mirror| mirror.bind_committed_custody(&binding).then_some(mirror));
    if !ai::binding_custody_matches_locked(&lock, base, &binding).map_err(|_| refused())? {
        return Err(refused());
    }
    let email = match binding.context() {
        StoredAnthropicContext::Known(context) => context.email().to_owned(),
        _ => return Err(refused()),
    };
    let stale = crate::accounts::binding_guard::detect_stale_marker_binding(base, account);
    crate::accounts::third_party::unbind_provider_from_slot(base, account)?;
    profiles::clear_slot_identity(&lock, base, account.get())?;
    let config = base.join(format!("config-{}", account.get()));
    // Fresh vendor grants are isolated outside config-N. Publish the canonical
    // home only now, after the sealed receipt and binding have been validated.
    crate::platform::fs::ensure_private_dir(&config).map_err(|_| refused())?;
    markers::write_csq_account(&config, binding.identity()).map_err(|_| refused())?;
    let settings = config.join("settings.json");
    if let Ok(bytes) = std::fs::read(&settings) {
        credentials::save_uuid_settings(base, binding.identity(), &bytes).map_err(|_| refused())?;
    }
    if let Some(surface) = stale {
        crate::accounts::binding_guard::clear_detected_marker_binding(base, account, surface);
    }
    if ai::capture_anthropic_binding_locked(&lock, base, account)
        .map_err(|_| refused())?
        .credential_version()
        == binding.credential_version()
    {
        crate::credentials::token_history::start_new_segment(base, binding.identity(), fingerprint);
    }
    // Sentinel cleanup belongs to the custody window too: a later provider
    // winner must not have its newly written failure cleared by this receipt.
    crate::refresh::sentinel::clear_broker_failed(base, account);
    // F5/L3: a re-bound slot no longer shares the grant that suppressed its refresh. It ends
    // THIS slot's suppression only (no other slot's login releases anything), and it runs
    // INSIDE the receipt's profiles lock, so the startup audit (which also runs inside that
    // lock) cannot read the old grant and re-apply a verdict after this clear.
    crate::accounts::refresh_token_audit::clear_on_login_locked(&lock, base, account.get());
    drop(lock);
    crate::credentials::keychain::queue_login_mirror(base, account, mirror);
    Ok(email)
}

// Bind the precise access/refresh pair and expiry without retaining credential bytes.
#[cfg(target_os = "macos")]
fn login_grant_version(access: &str, refresh: &str, expiry: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for token in [access, refresh] {
        hash.update((token.len() as u64).to_be_bytes());
        hash.update(token.as_bytes());
    }
    hash.update(expiry.to_be_bytes());
    hash.finalize().into()
}

#[cfg(target_os = "macos")]
fn login_credential_version(credential: &credentials::CredentialFile) -> Option<[u8; 32]> {
    let oauth = &credential.anthropic()?.claude_ai_oauth;
    Some(login_grant_version(
        oauth.access_token.expose_secret(),
        oauth.refresh_token.expose_secret(),
        oauth.expires_at,
    ))
}

#[cfg(target_os = "macos")]
fn login_raw_version(raw: &str) -> Option<[u8; 32]> {
    crate::credentials::keychain::inspect_secret_json(raw, |value| {
        let oauth = value.get("claudeAiOauth")?;
        Some(login_grant_version(
            oauth.get("accessToken")?.as_str()?,
            oauth.get("refreshToken")?.as_str()?,
            oauth.get("expiresAt")?.as_u64()?,
        ))
    })
    .flatten()
}

// Hold each canonical namespace component; reject aliases, nonregular/private
// files and oversized payloads. Partial reads and decode failures zeroize too.
#[cfg(target_os = "macos")]
fn read_login_canonical(
    base: &Path,
    identity: crate::accounts::identity_store::IdentityId,
) -> Option<zeroize::Zeroizing<String>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let root = std::fs::canonicalize(base).ok()?;
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .ok()?;
    for name in ["identities".to_string(), identity.to_canonical_string()] {
        let name = std::ffi::CString::new(name).ok()?;
        // The parent descriptor stays held while opening its direct child.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        // Successful openat transfers sole descriptor ownership to File.
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"credentials.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().ok()?;
    const MAX_BYTES: u64 = 65_536;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > MAX_BYTES
    {
        return None;
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    crate::credentials::keychain::zeroizing_utf8(bytes).ok()
}

#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    static TEST_LOGIN_MIRROR_CLOCK: std::cell::RefCell<Option<std::collections::VecDeque<std::time::Instant>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(target_os = "macos")]
impl LoginMirrorContext {
    /// Bind only an opaque captured publication authority, never a synthesized epoch.
    /// The finalizer calls this while its original profiles lock is still held.
    pub(crate) fn bind_committed_custody(
        &mut self,
        binding: &crate::accounts::anthropic_identity::CapturedBinding,
    ) -> bool {
        use crate::accounts::anthropic_identity::StoredAnthropicContext;
        if self.custody.is_some()
            || !binding.belongs_to(&self.base)
            || binding.slot() != self.account
            || binding.identity() != self.identity
            || !matches!(binding.context(), StoredAnthropicContext::Known(_))
        {
            return false;
        }
        self.custody = Some(binding.clone());
        true
    }

    // Queue callers may hold their mutex: bounded file reads only, no lock acquire.
    fn custody_snapshot_matches(&self, base: &Path) -> bool {
        use crate::accounts::anthropic_identity as ai;
        let Some(binding) = self.custody.as_ref() else {
            return false;
        };
        let ai::StoredAnthropicContext::Known(context) = binding.context() else {
            return false;
        };
        let pf = match ai::read_profiles_snapshot(base) {
            Ok(pf) => pf,
            Err(_) => {
                tracing::warn!(
                    error_kind = "login_custody_snapshot_unreadable",
                    account = self.account.get(),
                    "login custody check failed closed: profiles snapshot unreadable"
                );
                return false;
            }
        };
        let stored = match ai::read_stored_anthropic_context(base, self.identity) {
            Ok(stored) => stored,
            Err(_) => {
                tracing::warn!(
                    error_kind = "login_custody_context_unreadable",
                    account = self.account.get(),
                    "login custody check failed closed: stored context unreadable"
                );
                return false;
            }
        };
        pf.by_slot.get(&self.account.to_string()).copied() == Some(self.identity)
            && pf
                .slot_binding_generations
                .get(&self.account.to_string())
                .copied()
                .unwrap_or(0)
                == binding.generation()
            && stored == *binding.context()
            && ai::validate_target_index(&pf, Some(self.identity), Some(context), true).is_ok()
    }

    /// Recheck the ORIGINAL witness custody inside the actual apply authority lock.
    /// No lock is acquired here; canonical incoming digest and deadline remain required.
    pub(crate) fn prior_for_locked(
        &self,
        lock: &ProfilesFileLock,
        base: &Path,
        account: AccountNum,
        target: &str,
    ) -> Option<crate::credentials::token_history::Fingerprint> {
        let binding = self.custody.as_ref()?;
        if !crate::accounts::anthropic_identity::binding_custody_matches_locked(lock, base, binding)
            .ok()?
        {
            return None;
        }
        self.prior_for(base, account, target)
    }

    pub(crate) fn current_for(&self, base: &Path, account: AccountNum) -> bool {
        !self.expired()
            && read_login_canonical(base, self.identity)
                .is_some_and(|current| self.prior_for(base, account, &current).is_some())
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.expires = std::time::Instant::now();
    }

    #[cfg(test)]
    pub(crate) fn cross_deadline_during_read_for_test(&self) {
        TEST_LOGIN_MIRROR_CLOCK.with(|clock| {
            *clock.borrow_mut() = Some(
                [
                    self.expires - std::time::Duration::from_secs(1),
                    self.expires,
                ]
                .into(),
            );
        });
    }

    #[cfg(test)]
    pub(crate) fn clear_clock_for_test() {
        TEST_LOGIN_MIRROR_CLOCK.with(|clock| *clock.borrow_mut() = None);
    }

    fn expired(&self) -> bool {
        #[cfg(test)]
        if let Some(now) = TEST_LOGIN_MIRROR_CLOCK.with(|clock| {
            clock
                .borrow_mut()
                .as_mut()
                .and_then(|times| times.pop_front())
        }) {
            return now >= self.expires;
        }
        std::time::Instant::now() >= self.expires
    }

    // Called inside the existing handle lock against the policy's actual target.
    pub(crate) fn prior_for(
        &self,
        base: &Path,
        account: AccountNum,
        target: &str,
    ) -> Option<crate::credentials::token_history::Fingerprint> {
        if account != self.account
            || self.expired()
            || std::fs::canonicalize(base).ok().as_deref() != Some(self.base.as_path())
            || !self.custody_snapshot_matches(base)
        {
            return None;
        }
        let current = read_login_canonical(base, self.identity)?;
        (login_raw_version(&current) == Some(self.incoming)
            && login_raw_version(target) == Some(self.incoming)
            && !self.expired())
        .then_some(self.prior)
    }
}

/// System-wide install directories searched after `$PATH`.
///
/// Order is deliberate: Homebrew on Apple Silicon (`/opt/homebrew/bin`)
/// is checked before Intel Homebrew / manual installs (`/usr/local/bin`)
/// because Apple Silicon machines often have BOTH and the user wants
/// the modern one.
const SYSTEM_WIDE_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

/// Per-user install subdirectories, joined to `$HOME`.
const PER_USER_SUBDIRS: &[&str] = &[
    ".local/bin",
    ".npm-global/bin",
    ".bun/bin",
    ".cargo/bin",
    ".volta/bin",
    "n/bin",
];

/// If `dir/claude` (or `dir/claude.exe` on Windows) is an executable
/// regular file, returns its path. Otherwise returns `None`.
fn check_dir(dir: &Path) -> Option<PathBuf> {
    check_dir_named(dir, "claude")
}

/// Generalized form of [`check_dir`] for arbitrary CLI binary names.
/// Used by [`find_cli_binary`] to share the search infrastructure
/// across `claude`, `codex`, and any future first-party CLI shellouts.
pub(crate) fn check_dir_named(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if is_executable_file(&candidate) {
        return Some(candidate);
    }
    #[cfg(windows)]
    {
        let exe = dir.join(format!("{name}.exe"));
        if is_executable_file(&exe) {
            return Some(exe);
        }
    }
    None
}

/// Generalized binary locator. Same search order as
/// [`find_claude_binary`] (`$PATH` → SYSTEM_WIDE_DIRS → per-user
/// HOME-relative dirs) but parameterized by binary name. Used for
/// `codex` (the OpenAI CLI) and any future first-party CLI csq
/// shells out to from the Tauri-launched desktop bundle, where the
/// Finder PATH is `/usr/bin:/bin:/usr/sbin:/sbin` and Homebrew /
/// per-user installs are otherwise invisible.
pub fn find_cli_binary(name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if let Some(p) = check_dir_named(&dir, name) {
                return Some(p);
            }
        }
    }
    for sys_dir in SYSTEM_WIDE_DIRS {
        if let Some(p) = check_dir_named(Path::new(sys_dir), name) {
            return Some(p);
        }
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_SUBDIRS {
            if let Some(p) = check_dir_named(&home.join(sub), name) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_env::with_in_memory_secret_backend;
    use std::fs;
    use tempfile::TempDir;

    /// Explicit fake canonical/history staging; never an authorization API.
    fn stage_fixture_canonical(
        base: &Path,
        account: AccountNum,
        credential: &credentials::CredentialFile,
    ) -> Result<(), crate::error::CredentialError> {
        let identity = profiles::resolve_slot_to_uuid(base, account.get())
            .ok_or(crate::error::CredentialError::NoCredentials(account.get()))?;
        credentials::file::save(
            &crate::accounts::identity_store::credentials_path_for(base, identity),
            credential,
        )?;
        crate::credentials::token_history::record_write(base, identity, credential);
        Ok(())
    }

    // Full-context synthetic fixture setup. This is not a legacy upgrade path.
    // The transport proves the precise incoming token; only production commit
    // and receipt finalization perform the operation under test.
    fn fixture_verified_commit(
        base: &Path,
        account: AccountNum,
    ) -> Result<crate::accounts::anthropic_identity::CommittedAnthropicLogin, ConfigError> {
        use crate::accounts::anthropic_identity as ai;
        let config = base.join(format!("config-{}", account.get()));
        let refused = || ConfigError::InvalidJson {
            path: config.clone(),
            reason: "fixture_verified_login_refused".into(),
        };
        let email = read_email_from_claude_json(&config).ok_or_else(refused)?;
        let credential =
            credentials::load(&config.join(".credentials.json")).map_err(|_| refused())?;
        let context = ai::AnthropicContext::new(
            &email,
            uuid::Uuid::from_u128(101),
            uuid::Uuid::from_u128(202),
        )
        .map_err(|_| refused())?;
        if let Some(identity) = profiles::resolve_slot_to_uuid(base, account.get()) {
            // coexisting_fixture models the older migration layout and creates
            // directories at ordinary umask modes. These successful-login tests
            // explicitly stage a private Known identity, not a production legacy
            // upgrade or a bypass of the writer's private-directory requirement.
            for directory in [
                crate::accounts::identity_store::identities_dir(base),
                crate::accounts::identity_store::identity_path(base, identity),
            ] {
                crate::platform::fs::secure_dir(&directory).map_err(|_| refused())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                        0o700
                    );
                }
            }
            // Existing-success fixtures are explicitly known-context identities.
            let metadata_path =
                crate::accounts::identity_store::identity_json_path_for(base, identity);
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&fs::read(&metadata_path).map_err(|_| refused())?)
                    .map_err(|_| refused())?;
            metadata["email"] = serde_json::json!(context.email());
            metadata["account_uuid"] = serde_json::json!(context.account_uuid());
            metadata["organization_uuid"] = serde_json::json!(context.organization_uuid());
            fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap())
                .map_err(|_| refused())?;
            crate::platform::fs::secure_file(&metadata_path).map_err(|_| refused())?;
            let mut pf = profiles::load(&profiles::profiles_path(base))?;
            pf.anthropic_contexts
                .retain(|entry| entry.identity_uuid != identity);
            pf.anthropic_contexts.push(ai::AnthropicContextEntry {
                email: context.email().into(),
                account_uuid: context.account_uuid(),
                organization_uuid: context.organization_uuid(),
                identity_uuid: identity,
                extra: Default::default(),
            });
            profiles::save(&profiles::profiles_path(base), &pf)?;
        }
        let token = credential
            .anthropic()
            .ok_or_else(refused)?
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_owned();
        let http: crate::daemon::usage_poller::HttpGetFn = std::sync::Arc::new(
            move |url, bearer, _| {
                assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
                assert_eq!(bearer, token, "must prove the exact incoming fixture grant");
                Ok((200, serde_json::to_vec(&serde_json::json!({"account":{"uuid":context.account_uuid(),"email":context.email()},"organization":{"uuid":context.organization_uuid()}})).unwrap()))
            },
        );
        let prior = ai::capture_login_prior(base, account).map_err(|_| refused())?;
        ai::commit_anthropic_login_with(base, account, &credential, &http, None, prior)
            .map_err(|_| refused())
    }
    fn fixture_verified_finalize(base: &Path, account: AccountNum) -> Result<String, ConfigError> {
        with_in_memory_secret_backend(|| {
            let committed = fixture_verified_commit(base, account)?;
            finalize_verified_login(base, account, committed)
        })
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_finds_executable_claude() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        make_executable(&claude);

        let found = check_dir(dir.path()).expect("should find claude");
        assert_eq!(found, claude);
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_skips_non_executable() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        // Mode 0o644 — readable but not executable.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&claude).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&claude, perms).unwrap();

        assert!(check_dir(dir.path()).is_none());
    }

    #[test]
    fn check_dir_returns_none_for_missing_dir() {
        let missing = Path::new("/definitely/not/a/real/path/12345abcde");
        assert!(check_dir(missing).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn find_claude_binary_picks_up_path_entry() {
        // Override $PATH and $HOME to point at an isolated tempdir
        // so the assertion is hermetic regardless of what's installed
        // on the test machine.
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh").unwrap();
        make_executable(&claude);

        // Cross-module env-var mutex (`crate::platform::test_env`)
        // serializes against any other test mutating PATH / HOME
        // concurrently. PATH especially is read transitively by many
        // libraries, so a parallel set_var elsewhere can flip what
        // `find_claude_binary` sees mid-call.
        let _shared_env_guard = crate::platform::test_env::lock();

        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("PATH", dir.path());
        // Point HOME at an empty dir so the per-user fallbacks miss.
        let empty_home = TempDir::new().unwrap();
        std::env::set_var("HOME", empty_home.path());

        let found = find_claude_binary();

        // Restore env before asserting so a panic doesn't poison
        // sibling tests.
        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(found, Some(claude));
    }

    /// Regression for the live-discovered Codex spawn bug: the
    /// Finder-launched desktop bundle inherits `PATH=/usr/bin:/bin`
    /// and cannot find Homebrew-installed `codex` via bare
    /// `Command::new("codex")`. `find_cli_binary("codex")` MUST find
    /// it via the same SYSTEM_WIDE_DIRS / PER_USER_SUBDIRS fallback
    /// search Claude uses.
    #[cfg(unix)]
    #[test]
    fn find_cli_binary_finds_codex_in_path() {
        let dir = TempDir::new().unwrap();
        let codex = dir.path().join("codex");
        fs::write(&codex, "#!/bin/sh").unwrap();
        make_executable(&codex);

        let _shared_env_guard = crate::platform::test_env::lock();

        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("PATH", dir.path());
        let empty_home = TempDir::new().unwrap();
        std::env::set_var("HOME", empty_home.path());

        let found = find_cli_binary("codex");

        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(found, Some(codex));
    }

    /// HIGH-2 regression: `finalize_login` seeds `identities/<UUID>/credentials.json`
    /// when the UUID is present in profiles.json (i.e. Pass 0 has already run).
    ///
    /// Uses `coexisting_fixture(1)` which provides:
    /// - `config-1/.credentials.json` (live creds CC would have written)
    /// - `profiles.json` with `by_slot["1"] = fixture_uuid_for_slot(1)`
    /// - `identities/<uuid>/identity.json` (Pass 0 already ran)
    ///
    /// After `finalize_login`, `identities/<UUID>/credentials.json` MUST exist
    /// with bytes identical to what was in `config-1/.credentials.json`.
    #[test]
    fn finalize_login_seeds_uuid_credentials_when_uuid_present() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: fixture with live creds + profiles UUID mapping
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        // Write .claude.json with the fixture email so the fixture UUID stays the
        // slot's binding (no new UUID is minted).
        // This keeps the test hermetic — fixture_uuid_for_slot(1) stays canonical.
        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        // fixture email for slot 1 is "fixture-slot-1@test.invalid" (see identity_fixtures.rs)
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Overwrite live creds with csq CredentialFile JSON (the fixture writes CC's
        // native format which credentials::load cannot parse; this replaces it).
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-seed-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-seed-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Also write the marker so the config dir is fully set up.
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Act
        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: identities/<UUID>/credentials.json exists
        let uuid_creds = uuid_creds_path(base, uuid);
        assert!(
            uuid_creds.exists(),
            "HIGH-2: identities/<UUID>/credentials.json must be seeded by finalize_login; \
             path: {uuid_creds:?}"
        );

        // Assert: UUID credentials carry the same access_token as live creds
        let live_creds =
            credentials::load(&cred_file::live_path(base, account)).expect("live creds present");
        let seeded_creds = credentials::load(&uuid_creds).expect("UUID creds readable");
        assert_eq!(
            live_creds
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            seeded_creds
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "HIGH-2: UUID credentials must carry the same access_token as live creds"
        );
    }

    /// `keychain-fix-r10.md` T-d: `finalize_login` must actually invoke
    /// `token_history::start_new_segment` — proven end to end (no mock;
    /// `start_new_segment` is not an injectable seam) by pre-seeding the
    /// identity's history with an OLD grant's fingerprint before login, then
    /// asserting it is GONE afterward and only the fresh grant's fingerprint
    /// remains. If `finalize_login` never called `start_new_segment`, the
    /// old fingerprint would still be present (this call's own
    /// `save_canonical_for` → `record_write` path only APPENDS, it never
    /// clears).
    ///
    /// RED: commenting out `finalize_login`'s `start_new_segment` call makes
    /// this assertion fail — the old grant's fingerprint survives alongside
    /// the new one instead of being cleared.
    #[test]
    fn finalize_login_starts_a_new_token_history_segment() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        let old_refresh_token = "sk-ant-ort01-OLD-GRANT";
        let old_fp = crate::credentials::token_history::fingerprint_from_raw_json(&format!(
            r#"{{"claudeAiOauth":{{"accessToken":"a","refreshToken":"{old_refresh_token}"}}}}"#
        ))
        .unwrap();
        // Pre-seed the identity's history with the OLD grant, as though a
        // prior login/refresh had recorded it — requires the identity dir to
        // already exist (S-N-2), so plant it first.
        let identity_creds_path = uuid_creds_path(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        crate::credentials::token_history::append_history(base, uuid, old_fp);
        assert!(
            crate::credentials::token_history::read_history(base, uuid).contains(&old_fp),
            "test precondition: the old grant must be recorded before login"
        );

        let new_grant = crate::credentials::CredentialFile::Anthropic(
            crate::credentials::AnthropicCredentialFile {
                claude_ai_oauth: crate::credentials::OAuthPayload {
                    access_token: crate::types::AccessToken::new("sk-ant-oat01-new-grant".into()),
                    refresh_token: crate::types::RefreshToken::new("sk-ant-ort01-new-grant".into()),
                    expires_at: 4102444800000,
                    scopes: vec!["user:inference".into()],
                    subscription_type: Some("max".into()),
                    rate_limit_tier: None,
                    extra: std::collections::HashMap::new(),
                },
                extra: std::collections::HashMap::new(),
            },
        );
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(&live_creds_path, &new_grant).unwrap();
        // Every REAL production caller calls `save_canonical_for` (via
        // `read_fresh_after_login`) BEFORE `finalize_login` — this is what
        // actually seeds `identities/<UUID>/credentials.json`, which is the
        // file `finalize_login`'s own `start_new_segment` call reads to
        // compute the fingerprint it starts the new segment at. Skipping
        // this step (as an earlier draft of this test did) leaves that file
        // absent, so `finalize_login`'s `std::fs::read_to_string` fails and
        // the whole `start_new_segment` call is silently never reached —
        // not a bug in `finalize_login`, but an unrealistic test fixture.
        stage_fixture_canonical(base, account, &new_grant).unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        let history = crate::credentials::token_history::read_history(base, uuid);
        assert!(
            !history.contains(&old_fp),
            "the OLD grant's fingerprint must be cleared by a new segment start, got {history:?}"
        );
        let new_fp = crate::credentials::token_history::fingerprint_from_raw_json(
            r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"sk-ant-ort01-new-grant"}}"#,
        )
        .unwrap();
        assert!(
            history.contains(&new_fp),
            "the fresh grant's fingerprint must be present, got {history:?}"
        );
    }

    // Real login producer ordering: canonical save, history reset, then sweep.
    // The injected executor exercises write policy without any host Keychain call.
    #[cfg(target_os = "macos")]
    #[test]
    fn finalize_login_delivers_new_grant_after_history_reset() {
        login_mirror_case("fresh");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_canonical_change_during_keychain_read() {
        login_mirror_case("canonical_changed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_refresh_change_during_keychain_read() {
        login_mirror_case("refresh_changed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_expiry_change_during_keychain_read() {
        login_mirror_case("expiry_changed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_with_unreadable_prior_retains_safe_refusal() {
        login_mirror_case("unreadable_prior");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_with_incomplete_prior_retains_safe_refusal() {
        login_mirror_case("incomplete_prior");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_uuid_rebind_during_keychain_read() {
        login_mirror_case("uuid_rebound");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_symlinked_prior_canonical() {
        login_mirror_case("symlink_prior");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_symlinked_current_canonical() {
        login_mirror_case("symlink_current");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_context_from_another_root() {
        login_mirror_case("other_root");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_without_prior_canonical_retains_safe_refusal() {
        login_mirror_case("missing_prior");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_unrelated_foreign_grant() {
        login_mirror_case("foreign");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_different_account_prior() {
        login_mirror_case("other_account");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_expired_context() {
        login_mirror_case("expired");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refuses_deadline_crossing_during_canonical_recheck() {
        login_mirror_case("cross_deadline");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_refresh_context_takes_precedence() {
        login_mirror_case("refreshed_precedence");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_context_is_not_reused_by_later_sweep() {
        login_mirror_case("later_sweep");
    }

    #[cfg(target_os = "macos")]
    fn stage_known_mirror_fixture(
        base: &Path,
        identity: crate::accounts::identity_store::IdentityId,
        email: &str,
        credential: &credentials::CredentialFile,
    ) {
        use crate::accounts::anthropic_identity as ai;
        let context = ai::AnthropicContext::new(
            email,
            uuid::Uuid::from_u128(101),
            uuid::Uuid::from_u128(202),
        )
        .unwrap();
        let path = crate::accounts::identity_store::identity_json_path_for(base, identity);
        let metadata = serde_json::json!({"provider":"anthropic","email":context.email(),"account_uuid":context.account_uuid(),"organization_uuid":context.organization_uuid(),"created_at":"fixture"});
        fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        crate::platform::fs::secure_file(&path).unwrap();
        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        pf.anthropic_contexts
            .retain(|entry| entry.identity_uuid != identity);
        pf.anthropic_contexts.push(ai::AnthropicContextEntry {
            email: context.email().into(),
            account_uuid: context.account_uuid(),
            organization_uuid: context.organization_uuid(),
            identity_uuid: identity,
            extra: Default::default(),
        });
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        credentials::file::save(
            &crate::accounts::identity_store::credentials_path_for(base, identity),
            credential,
        )
        .unwrap();
        crate::credentials::token_history::record_write(base, identity, credential);
        // No old-token owner proof: the transient witness must be the sole authorization channel.
    }

    /// Records the `error_kind` field of every event emitted inside `run`.
    #[cfg(target_os = "macos")]
    fn capture_error_kinds<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
        use std::sync::{Arc, Mutex};
        struct Kinds(Arc<Mutex<Vec<String>>>);
        struct Visit<'a>(&'a Mutex<Vec<String>>);
        impl tracing::field::Visit for Visit<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "error_kind" {
                    self.0.lock().unwrap().push(value.to_owned());
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        impl tracing::Subscriber for Kinds {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                event.record(&mut Visit(&self.0));
            }
        }
        let _guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(Kinds(Arc::clone(&seen)), || {
            tracing::callsite::rebuild_interest_cache();
            run()
        });
        let kinds = seen.lock().unwrap().clone();
        (out, kinds)
    }

    #[test]
    fn login_commit_outcome_maps_busy_and_target_advanced_distinctly() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::BindingBusy),
            LoginCommitOutcome::Busy
        );
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::TargetAdvancedPublicationFailed),
            LoginCommitOutcome::TargetAdvancedPublicationFailed
        );
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::BindingChanged),
            LoginCommitOutcome::IdentityChanged
        );
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::Io),
            LoginCommitOutcome::PublicationFailed
        );
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::ProfileRefused),
            LoginCommitOutcome::Refused
        );
        let all = [
            LoginCommitOutcome::PublicationFailed,
            LoginCommitOutcome::TargetAdvancedPublicationFailed,
            LoginCommitOutcome::IdentityChanged,
            LoginCommitOutcome::Busy,
            LoginCommitOutcome::Refused,
            LoginCommitOutcome::FinalizationRefused,
            LoginCommitOutcome::IndexDamaged,
        ];
        for outcome in all {
            assert_eq!(
                LoginCommitOutcome::from_error_kind(outcome.error_kind()),
                outcome
            );
        }
        assert!(LoginCommitOutcome::describe_error_for_account(
            &E::BindingBusy,
            AccountNum::try_from(7u16).unwrap()
        )
        .contains("run `csq login 7` again"));
        assert!(!LoginCommitOutcome::TargetAdvancedPublicationFailed
            .message()
            .contains("could not be confirmed"));
        assert!(
            !LoginCommitOutcome::describe_error(&E::BindingBusy).contains("anthropic_identity_")
        );
    }

    #[test]
    fn prior_capture_busy_is_retryable_and_other_errors_keep_identity_remedies() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        assert_eq!(
            LoginCommitOutcome::describe_prior_capture_error(&E::BindingBusy),
            "another csq operation holds the profiles store; retry the login in a moment (oauth_identity_busy)"
        );
        for error in [E::Io, E::ProfilesReadRefused, E::InvalidMetadata] {
            assert_eq!(
                LoginCommitOutcome::describe_prior_capture_error(&error),
                error.to_string()
            );
        }
    }

    /// A damaged organization record is refused with its own tag and remedy. `csq login`
    /// refuses on the same record, so no surface (error text, message, per-account text)
    /// may tell the operator to run it; the healthy shared-identity remedy still may.
    #[test]
    fn damaged_index_row_has_its_own_kind_and_a_remedy_that_never_says_csq_login() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        let account = AccountNum::try_from(7u16).unwrap();
        let damaged = [
            LoginCommitOutcome::describe_error(&E::DamagedContextIndexRow),
            LoginCommitOutcome::describe_error_for_account(&E::DamagedContextIndexRow, account),
            LoginCommitOutcome::IndexDamaged.message().to_owned(),
            E::DamagedContextIndexRow.to_string(),
        ];
        for text in &damaged {
            assert!(!text.contains("csq login"), "got: {text}");
            assert!(!text.contains("start login again"), "got: {text}");
            assert!(
                text.contains("restore a trusted profiles.json backup"),
                "got: {text}"
            );
        }
        assert!(
            damaged[0].ends_with("(oauth_identity_index_damaged)"),
            "got: {}",
            damaged[0]
        );
        assert_eq!(
            LoginCommitOutcome::from_identity_error(&E::DamagedContextIndexRow).error_kind(),
            "oauth_identity_index_damaged"
        );
        // Control: the healthy shared-identity refusal keeps its own kind and its remedy.
        let shared = LoginCommitOutcome::describe_error(&E::SharedLegacyIdentity);
        assert!(shared.contains("`csq login`") && shared.ends_with("(oauth_identity_refused)"));
    }

    /// N-3: refusals with their own remedy keep it instead of collapsing to
    /// the generic "organization identity could not be confirmed".
    #[test]
    fn describe_error_carries_each_refusal_remedy() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        let shared = LoginCommitOutcome::describe_error(&E::SharedLegacyIdentity);
        assert!(
            shared.contains("each affected slot with `csq login` and its own slot number"),
            "got: {shared}"
        );
        assert!(shared.contains("shared by several slots"), "got: {shared}");
        let meta = LoginCommitOutcome::describe_error(&E::InvalidMetadata);
        assert!(meta.contains("csq logout N"), "got: {meta}");
        assert!(meta.contains("then `csq login N`"), "got: {meta}");
        assert!(meta.contains("do not hand-edit"), "got: {meta}");
        for text in [&shared, &meta] {
            assert!(!text.contains("could not be confirmed"), "got: {text}");
            assert!(!text.contains("anthropic_identity_"), "got: {text}");
            assert!(text.ends_with("(oauth_identity_refused)"), "got: {text}");
        }
        // Negative control: other refusals keep the generic text.
        assert!(LoginCommitOutcome::describe_error(&E::InvalidContext)
            .contains("could not be confirmed"));
    }

    #[test]
    fn org_identity_r3d_describe_error_preserves_specific_remedies() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        for (error, required) in [
            (
                E::BoundIdentityMetadataMissing { account: 7 },
                vec!["identity.json", "csq logout 7", "csq login 7"],
            ),
            (
                E::LegacyEmailUnparseable,
                vec!["legacy email", "csq login N"],
            ),
            (
                E::UnsafePermissions,
                vec![
                    "identity.json",
                    "credentials.json",
                    "after confirming no other user modified",
                    "csq logout N",
                ],
            ),
            (
                E::MultipleLinks,
                vec!["identity.json", "hard links", "csq logout N"],
            ),
            (E::SnapshotChanged, vec!["retry"]),
            (
                E::ProfilesUnsafePermissions,
                vec![
                    "chmod 600 on profiles.json",
                    "after confirming no other user modified it",
                    "trusted backup",
                ],
            ),
            (
                E::ProfilesMultipleLinks,
                vec!["profiles.json", "hard links"],
            ),
            (E::ProfilesSnapshotChanged, vec!["profiles.json", "retry"]),
            (
                E::ProfilesReadRefused,
                vec!["profiles.json", "trusted backup", "do not hand-edit"],
            ),
        ] {
            let text = LoginCommitOutcome::describe_error(&error);
            for needle in required {
                assert!(text.contains(needle), "missing {needle}: {text}");
            }
            assert!(!text.contains("could not be confirmed"), "{text}");
            assert!(!text.contains("anthropic_identity_"), "{text}");
            assert!(!text.contains("run the login again"), "{text}");
        }
    }

    #[test]
    fn org_identity_r3d_account_remedies_only_retry_supported_outcomes() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        let account = AccountNum::try_from(7u16).unwrap();
        for error in [
            E::BindingChanged,
            E::BindingBusy,
            E::TargetAdvancedPublicationFailed,
        ] {
            let text = LoginCommitOutcome::describe_error_for_account(&error, account);
            assert!(text.contains("run `csq login 7` again"), "{text}");
            if matches!(error, E::BindingChanged | E::BindingBusy) {
                assert!(!text.contains("start login again"), "{text}");
                assert!(!text.contains("retry the login in a moment"), "{text}");
            }
            assert!(
                text.ends_with(&format!(
                    "({})",
                    LoginCommitOutcome::from_identity_error(&error).error_kind()
                )),
                "{text}"
            );
        }
        for error in [
            E::InvalidMetadata,
            E::LegacyEmailUnparseable,
            E::BoundIdentityMetadataMissing { account: 7 },
            E::UnsafePermissions,
            E::MultipleLinks,
            E::SnapshotChanged,
            E::ProfilesUnsafePermissions,
            E::ProfilesMultipleLinks,
            E::ProfilesSnapshotChanged,
            E::ProfilesReadRefused,
            E::SharedLegacyIdentity,
            E::InvalidContext,
            E::Io,
            E::ProfileRefused,
        ] {
            let text = LoginCommitOutcome::describe_error_for_account(&error, account);
            assert!(!text.contains("run `csq login 7` again"), "{text}");
            assert!(!text.contains("csq login N"), "{text}");
            assert!(!text.contains("csq logout N"), "{text}");
        }
        let text = LoginCommitOutcome::describe_error_for_account(&E::InvalidMetadata, account);
        assert!(text.contains("`csq logout 7` then `csq login 7`"), "{text}");
        assert!(text.contains("do not hand-edit"), "{text}");
        let unsafe_profiles =
            LoginCommitOutcome::describe_error_for_account(&E::ProfilesUnsafePermissions, account);
        assert!(
            unsafe_profiles.contains("trusted backup"),
            "{unsafe_profiles}"
        );
        assert!(!unsafe_profiles.contains("csq logout"), "{unsafe_profiles}");
    }

    /// r4 F2/L2: the two slot-naming refusals show the slot and the remedy on every
    /// surface; the kind stays the refusal tag and no secret-bearing text appears.
    #[test]
    fn describe_error_names_the_slot_for_custody_and_held_elsewhere() {
        use crate::accounts::anthropic_identity::{IdentityError as E, SlotKey};
        let account = AccountNum::try_from(4u16).unwrap();
        let sibling = E::SiblingCustodyUnreadable {
            sibling: SlotKey::from_key("2"),
        };
        assert_eq!(
            LoginCommitOutcome::describe_error(&sibling),
            "slot 2's stored identity is unreadable; run `csq login 2` or `csq logout 2` to replace it (the slot being logged in is unaffected) (oauth_identity_refused)"
        );
        let held = E::LoginCredentialHeldElsewhere {
            holder: SlotKey::from_key("2"),
        };
        assert_eq!(
            LoginCommitOutcome::describe_error_for_account(&held, account),
            "this login produced a credential that slot 2 already holds; run `csq login 4` again so a fresh credential is issued, or `csq logout 2` if slot 2 is the one that is stale (oauth_identity_refused)"
        );
        // A key that is not a canonical account number never reaches the text.
        for key in ["evil\nkey", "+2", "02", "0", ""] {
            let text = LoginCommitOutcome::describe_error(&E::SiblingCustodyUnreadable {
                sibling: SlotKey::from_key(key),
            });
            assert!(text.starts_with("another slot's stored identity"), "{text}");
            assert!(!text.contains("evil"), "{text}");
            let text = LoginCommitOutcome::describe_error(&E::LoginCredentialHeldElsewhere {
                holder: SlotKey::from_key(key),
            });
            assert!(text.contains("another slot already holds"), "{text}");
        }
        for error in [sibling, held] {
            assert_eq!(
                LoginCommitOutcome::from_identity_error(&error),
                LoginCommitOutcome::Refused
            );
            let text = LoginCommitOutcome::describe_error(&error);
            assert!(!text.contains("could not be confirmed"), "{text}");
            assert!(!text.contains("anthropic_identity_"), "{text}");
        }
    }

    /// N-3: a pre-login capture failure is not a "publication" failure.
    #[test]
    fn describe_prior_capture_error_is_not_a_publication_failure() {
        use crate::accounts::anthropic_identity::IdentityError as E;
        let io = LoginCommitOutcome::describe_prior_capture_error(&E::Io);
        assert_eq!(io, E::Io.to_string());
        assert!(!io.contains("credential publication failed"), "got: {io}");
        assert!(
            LoginCommitOutcome::describe_error(&E::Io).contains("credential publication failed")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_custody_snapshot_failure_warns_with_error_kind() {
        with_in_memory_secret_backend(|| {
            use crate::accounts::anthropic_identity as ai;
            use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
            let dir = coexisting_fixture(2);
            let base = dir.path();
            let account = AccountNum::try_from(1u16).unwrap();
            let identity = fixture_uuid_for_slot(1);
            let config = base.join("config-1");
            let raw = r#"{"claudeAiOauth":{"accessToken":"snap-at","refreshToken":"snap-rt","expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max"}}"#;
            fs::write(config.join(".credentials.json"), raw).unwrap();
            let old = credentials::load(&config.join(".credentials.json")).unwrap();
            stage_known_mirror_fixture(base, identity, "snap@test.invalid", &old);
            fs::write(
                config.join(".claude.json"),
                r#"{"oauthAccount":{"emailAddress":"snap@test.invalid"}}"#,
            )
            .unwrap();
            let incoming = raw
                .replace("snap-at", "snap-new")
                .replace("4102444800000", "4102444800001");
            fs::write(config.join(".credentials.json"), &incoming).unwrap();
            let receipt = fixture_verified_commit(base, account).unwrap();
            let (binding, mirror, _) = receipt.into_parts();
            let mut witness = mirror.expect("verified commit retains a witness");
            {
                let lock = ProfilesFileLock::acquire(base).unwrap();
                assert!(ai::binding_custody_matches_locked(&lock, base, &binding).unwrap());
                assert!(witness.bind_committed_custody(&binding));
            }
            let (healthy, kinds) = capture_error_kinds(|| witness.custody_snapshot_matches(base));
            assert!(healthy);
            assert!(kinds.is_empty(), "{kinds:?}");
            let profiles_path = profiles::profiles_path(base);
            fs::remove_file(&profiles_path).unwrap();
            fs::create_dir(&profiles_path).unwrap();
            let (matched, kinds) = capture_error_kinds(|| witness.custody_snapshot_matches(base));
            assert!(!matched);
            assert!(
                kinds
                    .iter()
                    .any(|k| k == "login_custody_snapshot_unreadable"),
                "{kinds:?}"
            );
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_mirror_original_custody_rejects_aba_context_drift_and_canonical_advance() {
        with_in_memory_secret_backend(|| {
            use crate::accounts::{anthropic_identity as ai, identity_store};
            use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
            for case in ["same_grant", "aba", "context_drift", "canonical_advance"] {
                let dir = coexisting_fixture(2);
                let base = dir.path();
                let account = AccountNum::try_from(1u16).unwrap();
                let identity = fixture_uuid_for_slot(1);
                let config = base.join("config-1");
                let old_raw = r#"{"claudeAiOauth":{"accessToken":"custody-old-at","refreshToken":"custody-old-rt","expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max"}}"#;
                fs::write(config.join(".credentials.json"), old_raw).unwrap();
                let old = credentials::load(&config.join(".credentials.json")).unwrap();
                stage_known_mirror_fixture(base, identity, "custody@test.invalid", &old);
                fs::write(
                    config.join(".claude.json"),
                    r#"{"oauthAccount":{"emailAddress":"custody@test.invalid"}}"#,
                )
                .unwrap();
                let incoming = old_raw
                    .replace("custody-old", "custody-new")
                    .replace("4102444800000", "4102444800001");
                fs::write(config.join(".credentials.json"), &incoming).unwrap();
                let receipt = fixture_verified_commit(base, account).unwrap();
                let (binding, mirror, _) = receipt.into_parts();
                let mut first = mirror.expect("actual verified commit retains original witness");
                {
                    let lock = ProfilesFileLock::acquire(base).unwrap();
                    assert!(ai::binding_custody_matches_locked(&lock, base, &binding).unwrap());
                    assert!(first.bind_committed_custody(&binding));
                }
                let repeated = fixture_verified_commit(base, account).unwrap();
                let (same_binding, mirror, _) = repeated.into_parts();
                let mut second = mirror.unwrap();
                assert_eq!(same_binding.generation(), binding.generation());
                {
                    let lock = ProfilesFileLock::acquire(base).unwrap();
                    assert!(
                        ai::binding_custody_matches_locked(&lock, base, &same_binding).unwrap()
                    );
                    assert!(second.bind_committed_custody(&same_binding));
                    assert_eq!(
                        first.prior_for_locked(&lock, base, account, &incoming),
                        token_history_fingerprint(old_raw)
                    );
                    assert_eq!(
                        second.prior_for_locked(&lock, base, account, &incoming),
                        token_history_fingerprint(&incoming)
                    );
                }
                assert!(first.current_for(base, account));
                let canonical = identity_store::credentials_path_for(base, identity);
                let before = fs::read(&canonical).unwrap();
                match case {
                    "aba" => {
                        let lock = ProfilesFileLock::acquire(base).unwrap();
                        assert!(profiles::swap_slot_mapping(&lock, base, 1, 2).unwrap());
                        assert!(profiles::swap_slot_mapping(&lock, base, 1, 2).unwrap());
                        assert_eq!(profiles::resolve_slot_to_uuid(base, 1), Some(identity));
                        let current =
                            ai::capture_anthropic_binding_locked(&lock, base, account).unwrap();
                        assert!(current.generation() > binding.generation());
                        assert!(
                            !first.bind_committed_custody(&current),
                            "old witness custody is immutable across ABA"
                        );
                        assert_eq!(fs::read(&canonical).unwrap(), before);
                    }
                    "context_drift" => {
                        let _lock = ProfilesFileLock::acquire(base).unwrap();
                        let path = identity_store::identity_json_path_for(base, identity);
                        let mut metadata: serde_json::Value =
                            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                        metadata["organization_uuid"] =
                            serde_json::json!(uuid::Uuid::from_u128(303));
                        fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
                        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
                        pf.anthropic_contexts
                            .iter_mut()
                            .find(|entry| entry.identity_uuid == identity)
                            .unwrap()
                            .organization_uuid = uuid::Uuid::from_u128(303);
                        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
                        assert_eq!(fs::read(&canonical).unwrap(), before);
                    }
                    "canonical_advance" => {
                        let changed = incoming
                            .replace("custody-new-at", "custody-next-at")
                            .replace("4102444800001", "4102444800002");
                        fs::write(&canonical, changed).unwrap();
                    }
                    "same_grant" => (),
                    _ => unreachable!(),
                }
                let lock = ProfilesFileLock::acquire(base).unwrap();
                if case == "same_grant" {
                    assert!(first.current_for(base, account));
                    assert_eq!(
                        first.prior_for_locked(&lock, base, account, &incoming),
                        token_history_fingerprint(old_raw)
                    );
                } else {
                    assert!(
                        !first.current_for(base, account),
                        "original witness must refuse {case}"
                    );
                    assert!(first.prior_for(base, account, &incoming).is_none());
                    assert!(first
                        .prior_for_locked(&lock, base, account, &incoming)
                        .is_none());
                }
            }
        });
    }

    #[cfg(target_os = "macos")]
    fn token_history_fingerprint(
        raw: &str,
    ) -> Option<crate::credentials::token_history::Fingerprint> {
        crate::credentials::token_history::fingerprint_from_raw_json(raw)
    }

    #[cfg(target_os = "macos")]
    fn login_mirror_case(case: &str) {
        with_in_memory_secret_backend(|| {
            use crate::credentials::keychain::{
                clear_test_keychain_executor, set_test_keychain_executor, KeychainExecutor,
                RawContentClassification, ScriptedKeychainExecutor,
            };
            use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
            use std::os::unix::fs::{symlink, PermissionsExt};
            use std::rc::Rc;
            struct ResetExecutor;
            impl Drop for ResetExecutor {
                fn drop(&mut self) {
                    clear_test_keychain_executor();
                }
            }
            struct ResetClock(Option<std::collections::VecDeque<std::time::Instant>>);
            impl Drop for ResetClock {
                fn drop(&mut self) {
                    TEST_LOGIN_MIRROR_CLOCK.with(|clock| {
                        clock.replace(self.0.take());
                    });
                }
            }
            struct MutatingExecutor {
                inner: Rc<ScriptedKeychainExecutor>,
                after_find: std::cell::RefCell<Option<Box<dyn FnOnce()>>>,
            }
            impl KeychainExecutor for MutatingExecutor {
                fn find(&self, service: &str, account: &str) -> RawContentClassification {
                    let value = self.inner.find(service, account);
                    if let Some(change) = self.after_find.borrow_mut().take() {
                        change();
                    }
                    value
                }
                fn add(
                    &self,
                    service: &str,
                    account: &str,
                    payload: &str,
                ) -> Result<(), crate::error::PlatformError> {
                    self.inner.add(service, account, payload)
                }
                fn delete(&self, service: &str, account: &str) -> bool {
                    self.inner.delete(service, account)
                }
            }
            let dir = coexisting_fixture(2);
            let base = dir.path();
            let account = AccountNum::try_from(1u16).unwrap();
            let uuid = fixture_uuid_for_slot(1);
            let config = base.join("config-1");
            fs::write(
                config.join(".claude.json"),
                r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
            )
            .unwrap();
            // Year 2100 keeps both fixture grants valid for the real mirror policy.
            let old_raw = r#"{"claudeAiOauth":{"accessToken":"fixture-old-at","refreshToken":"fixture-old-rt","expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max"}}"#;
            fs::write(config.join(".credentials.json"), old_raw).unwrap();
            let old = credentials::load(&config.join(".credentials.json")).unwrap();
            stage_known_mirror_fixture(base, uuid, "fixture-slot-1@test.invalid", &old);
            crate::credentials::file::save(
                &crate::accounts::identity_store::credentials_path_for(base, uuid),
                &old,
            )
            .unwrap();
            crate::credentials::token_history::record_write(base, uuid, &old);
            let old_fp =
                crate::credentials::token_history::fingerprint_from_raw_json(old_raw).unwrap();
            assert!(crate::credentials::token_history::read_history(base, uuid).contains(&old_fp));
            let handle = base.join(format!("term-{}", std::process::id()));
            fs::create_dir(&handle).unwrap();
            crate::accounts::markers::write_csq_account(&config, uuid).unwrap();
            symlink(
                crate::accounts::identity_store::credentials_path_for(base, uuid),
                handle.join(".credentials.json"),
            )
            .unwrap();
            symlink(config.join(".csq-account"), handle.join(".csq-account")).unwrap();
            fs::write(handle.join(".live-pid"), std::process::id().to_string()).unwrap();
            assert!(crate::session::handle_dir::handle_dir_symlinks_are_consistent(base, &handle));
            let foreign_raw = old_raw
                .replace("fixture-old-at", "fixture-foreign-at")
                .replace("fixture-old-rt", "fixture-foreign-rt");
            let exec = Rc::new(ScriptedKeychainExecutor::scripted(
                RawContentClassification::Content(
                    if matches!(case, "symlink_prior" | "foreign" | "other_account") {
                        foreign_raw.clone().into()
                    } else {
                        old_raw.to_string().into()
                    },
                ),
            ));
            let _reset = ResetExecutor;
            let new_raw = old_raw
                .replace("fixture-old-at", "fixture-new-at")
                .replace("fixture-old-rt", "fixture-new-rt");
            fs::write(config.join(".credentials.json"), &new_raw).unwrap();
            let new = credentials::load(&config.join(".credentials.json")).unwrap();
            if case == "missing_prior" {
                fs::remove_file(crate::accounts::identity_store::credentials_path_for(
                    base, uuid,
                ))
                .unwrap();
            }
            if case == "unreadable_prior" {
                fs::write(
                    crate::accounts::identity_store::credentials_path_for(base, uuid),
                    "invalid-fixture-json",
                )
                .unwrap();
            }
            if case == "incomplete_prior" {
                fs::write(
                    crate::accounts::identity_store::credentials_path_for(base, uuid),
                    r#"{"claudeAiOauth":{"refreshToken":"fixture-old-rt"}}"#,
                )
                .unwrap();
            }
            let foreign_path = base.join("foreign-grant.json");
            if case == "symlink_prior" {
                std::fs::write(&foreign_path, &foreign_raw).unwrap();
                std::fs::set_permissions(&foreign_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                let path = crate::accounts::identity_store::credentials_path_for(base, uuid);
                std::fs::remove_file(&path).unwrap();
                symlink(&foreign_path, &path).unwrap();
            }
            let mut context = prepare_verified_login_mirror(base, account, uuid, &new);
            let canonical = crate::accounts::identity_store::credentials_path_for(base, uuid);
            // Explicit fixture setup includes deliberate malformed/symlink inputs; no production write bypass.
            if std::fs::symlink_metadata(&canonical).is_ok_and(|m| m.file_type().is_symlink()) {
                std::fs::remove_file(&canonical).unwrap();
            }
            crate::credentials::file::save(&canonical, &new).unwrap();
            if !matches!(case, "symlink_prior" | "incomplete_prior") {
                assert_eq!(
                    context.is_some(),
                    !matches!(case, "missing_prior" | "unreadable_prior")
                );
            }
            let other_root = (case == "other_root").then(|| coexisting_fixture(1));
            if let Some(other) = other_root.as_ref() {
                stage_known_mirror_fixture(other.path(), uuid, "fixture-slot-1@test.invalid", &old);
                crate::credentials::file::save(
                    &crate::accounts::identity_store::credentials_path_for(other.path(), uuid),
                    &old,
                )
                .unwrap();
                context = prepare_verified_login_mirror(other.path(), account, uuid, &new);
                crate::credentials::file::save(
                    &crate::accounts::identity_store::credentials_path_for(other.path(), uuid),
                    &new,
                )
                .unwrap();
            }
            if case == "other_account" {
                let other = AccountNum::try_from(2u16).unwrap();
                let metadata_path = profiles::profiles_path(base);
                let mut metadata = profiles::load(&metadata_path).unwrap();
                metadata.by_slot.insert("2".into(), uuid);
                profiles::save(&metadata_path, &metadata).unwrap();
                assert_eq!(
                    profiles::resolve_slot_to_uuid(base, other.get()),
                    Some(uuid)
                );
                let path = config.join(".credentials.json");
                fs::write(&path, &foreign_raw).unwrap();
                let prior = credentials::load(&path).unwrap();
                crate::credentials::file::save(
                    &crate::accounts::identity_store::credentials_path_for(base, uuid),
                    &prior,
                )
                .unwrap();
                context = prepare_verified_login_mirror(base, other, uuid, &new);
                crate::credentials::file::save(
                    &crate::accounts::identity_store::credentials_path_for(base, uuid),
                    &new,
                )
                .unwrap();
                fs::write(&path, &new_raw).unwrap();
            }
            if let Some(context) = context.as_mut() {
                let binding = crate::accounts::anthropic_identity::capture_anthropic_binding(
                    &context.base,
                    context.account,
                )
                .unwrap();
                assert!(context.bind_committed_custody(&binding));
            }
            if case == "expired" {
                context.as_mut().unwrap().expires = std::time::Instant::now();
            }
            let base_owned = base.to_path_buf();
            let changed = match case {
                "refresh_changed" => new_raw.replace("fixture-new-rt", "fixture-changed-rt"),
                "expiry_changed" => new_raw.replace("4102444800000", "4102444800001"),
                _ => new_raw.replace("fixture-new-at", "fixture-changed-at"),
            };
            let current_raw = new_raw.clone();
            let after_find: Option<Box<dyn FnOnce()>> = match case {
                "canonical_changed" | "refresh_changed" | "expiry_changed" => {
                    Some(Box::new(move || {
                        let path = crate::accounts::identity_store::credentials_path_for(
                            &base_owned,
                            uuid,
                        );
                        fs::write(path, changed).unwrap();
                    }))
                }
                "symlink_current" => Some(Box::new(move || {
                    let foreign = base_owned.join("foreign-current.json");
                    std::fs::write(&foreign, &current_raw).unwrap();
                    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    let path =
                        crate::accounts::identity_store::credentials_path_for(&base_owned, uuid);
                    std::fs::remove_file(&path).unwrap();
                    symlink(&foreign, path).unwrap();
                })),
                "uuid_rebound" => Some(Box::new(move || {
                    let path = profiles::profiles_path(&base_owned);
                    let mut metadata = profiles::load(&path).unwrap();
                    metadata
                        .by_slot
                        .insert("1".into(), fixture_uuid_for_slot(2));
                    profiles::save(&path, &metadata).unwrap();
                })),
                _ => None,
            };
            set_test_keychain_executor(Rc::new(MutatingExecutor {
                inner: exec.clone(),
                after_find: std::cell::RefCell::new(after_find),
            }));
            // Only the witness clock is scripted: early eligibility succeeds, then
            // the final probe occurs after the held reread and grant digests.
            let _clock = (case == "cross_deadline").then(|| {
                let deadline = context.as_ref().unwrap().expires;
                let early = deadline - std::time::Duration::from_secs(1);
                ResetClock(TEST_LOGIN_MIRROR_CLOCK.with(|clock| {
                    clock.replace(Some(std::collections::VecDeque::from([early, deadline])))
                }))
            });
            // Exercise synchronous mirror policy directly; verified finalization now queues delivery.
            crate::credentials::token_history::start_new_segment(
                base,
                uuid,
                crate::credentials::token_history::fingerprint_from_raw_json(&new_raw).unwrap(),
            );
            if case == "refreshed_precedence" {
                let map = std::collections::HashMap::from([(
                    account,
                    crate::credentials::token_history::fingerprint_from_raw_json(&foreign_raw)
                        .unwrap(),
                )]);
                crate::credentials::keychain::sync_all_handle_dirs_context(
                    base,
                    &map,
                    context.as_ref(),
                );
            } else {
                crate::credentials::keychain::sync_all_handle_dirs_context(
                    base,
                    &std::collections::HashMap::new(),
                    context.as_ref(),
                );
            }
            if case == "symlink_prior" {
                assert!(
                    std::fs::read_to_string(&foreign_path).unwrap() == foreign_raw,
                    "canonical save must preserve the symlink target bytes"
                );
            }
            let history = crate::credentials::token_history::read_history(base, uuid);
            assert!(
                !history.contains(&old_fp),
                "login must still discard the old grant history"
            );
            assert!(
                exec.calls().iter().any(|(verb, _, _)| *verb == "find"),
                "the real sweep must reach its injected executor"
            );
            if matches!(case, "fresh" | "later_sweep") {
                let written = exec
                    .last_add_payload()
                    .expect("login must deliver the new grant");
                let written_fp =
                    crate::credentials::token_history::fingerprint_from_raw_json(&written).unwrap();
                let new_fp =
                    crate::credentials::token_history::fingerprint_from_raw_json(&new_raw).unwrap();
                assert_eq!(written_fp, new_fp, "mirror must carry the fresh grant");
                assert!(history.contains(&new_fp));
                if case == "later_sweep" {
                    let later = Rc::new(ScriptedKeychainExecutor::scripted(
                        RawContentClassification::Content(old_raw.to_string().into()),
                    ));
                    set_test_keychain_executor(later.clone());
                    crate::credentials::keychain::sync_all_handle_dirs(
                        base,
                        &std::collections::HashMap::new(),
                    );
                    assert!(later.calls().iter().any(|(verb, _, _)| *verb == "find"));
                    assert!(
                        later
                            .calls()
                            .iter()
                            .all(|(verb, _, _)| *verb != "add" && *verb != "delete"),
                        "consumed login context must not authorize a later sweep"
                    );
                }
            } else {
                assert!(
                    exec.calls()
                        .iter()
                        .all(|(verb, _, _)| *verb != "add" && *verb != "delete"),
                    "a mismatched or absent witness must grant no mirror write"
                );
                if case == "cross_deadline" {
                    assert!(
                        TEST_LOGIN_MIRROR_CLOCK.with(|clock| {
                            clock
                                .borrow()
                                .as_ref()
                                .is_some_and(|times| times.is_empty())
                        }),
                        "both early and final witness clock probes must execute"
                    );
                }
            }
        });
    }

    /// An exact-token profile proof permits a same-context new login grant; TTL alone grants no authority.
    #[test]
    fn finalize_login_fresher_config_n_advances_store() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        fn anthropic_creds(access: &str, expires_at: u64) -> crate::credentials::CredentialFile {
            crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(access.into()),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "sk-ant-ort01-{access}"
                        )),
                        expires_at,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            )
        }

        const OLD_EXPIRY: u64 = 2000000000000; // 2033
        const NEWER_EXPIRY: u64 = 4102444800000; // 2100 (> OLD)

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);
        let config_dir = base.join("config-1");
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Store holds an OLDER token; config-N holds a strictly NEWER token.
        stage_fixture_canonical(
            base,
            account,
            &anthropic_creds("sk-ant-oat01-OLD", OLD_EXPIRY),
        )
        .expect("pre-seed older store token");
        credentials::save(
            &cred_file::live_path(base, account),
            &anthropic_creds("sk-ant-oat01-NEWER", NEWER_EXPIRY),
        )
        .unwrap();

        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {result:?}");

        let store = credentials::load(&uuid_creds_path(base, uuid)).expect("store readable");
        assert_eq!(
            store
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-NEWER",
            "a strictly-fresher config-N MUST advance the store (monotonic-up)"
        );
        assert_eq!(
            store.expect_anthropic().claude_ai_oauth.expires_at,
            NEWER_EXPIRY,
            "store expiry must advance to the fresher config-N value"
        );
    }

    /// M4-2 Criterion: `finalize_login` writes `identities/<UUID>/settings.json`
    /// byte-equivalent to `config-<N>/settings.json`.
    ///
    /// The pair-write in `finalize_login` (post-`commit_anthropic_login`) reads the
    /// legacy `config-<N>/settings.json` and writes the same bytes verbatim to
    /// `identities/<UUID>/settings.json`. The two paths must be byte-equivalent
    /// during the M4-2 → M4-5 transition window (spec 02 §2.3.3) so
    /// `materialize_handle_settings` reads identical content regardless of which
    /// overlay-source branch it takes.
    ///
    /// Arrange:
    /// - `coexisting_fixture(1)` — live creds + profiles UUID mapping
    /// - Write a sentinel `config-1/settings.json` with a 3P-style env block
    ///   (`ANTHROPIC_BASE_URL` + a recognizable model name)
    /// - Pre-write `identities/<UUID>/settings.json` with STALE bytes (different
    ///   model) to verify the pair-write OVERWRITES the stale UUID copy
    ///
    /// Assert: after `finalize_login`, `identities/<UUID>/settings.json` has
    /// bytes identical to `config-1/settings.json`.
    #[test]
    fn finalize_login_writes_uuid_settings_byte_equivalent_to_legacy() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        // Set up the config-1 marker + .claude.json so finalize_login's
        // the verified commit keeps the fixture UUID.
        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Live creds (so finalize_login's credential seed step doesn't bail).
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-FAKETEST-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-FAKETEST-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Write the LEGACY settings.json with a recognizable sentinel.
        //
        // CRITICAL: the bytes MUST NOT trigger `unbind_provider_from_slot`
        // (which `finalize_login` runs as its FIRST step). Unbind rewrites
        // `config-N/settings.json` if any 3P provider markers are present
        // (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, etc.) — that rewrite
        // changes the bytes BEFORE the pair-write reads them. We avoid those
        // markers and use a plain user-custom key under `env` so unbind is a
        // no-op and the legacy bytes round-trip verbatim into the UUID pair.
        let legacy_settings = config_dir.join("settings.json");
        let legacy_bytes = br#"{"plain_user_key":"m42-pair-source","other_field":42}"#;
        fs::write(&legacy_settings, legacy_bytes).unwrap();

        // Pre-write a STALE UUID settings file so we can verify the pair-write
        // OVERWRITES it (not just "absent → write" idempotency).
        std::fs::create_dir_all(settings_path_for(base, uuid).parent().unwrap()).unwrap();
        fs::write(
            settings_path_for(base, uuid),
            br#"{"env":{"CLAUDE_MODEL":"STALE-pre-finalize"}}"#,
        )
        .unwrap();

        // Act
        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: UUID settings.json now byte-equivalent to legacy.
        let uuid_settings = settings_path_for(base, uuid);
        assert!(
            uuid_settings.exists(),
            "M4-2: identities/<UUID>/settings.json must exist after finalize_login; path: {uuid_settings:?}"
        );
        let written_uuid_bytes = std::fs::read(&uuid_settings).expect("UUID settings readable");
        assert_eq!(
            written_uuid_bytes.as_slice(),
            legacy_bytes.as_slice(),
            "M4-2: identities/<UUID>/settings.json must be byte-equivalent to \
             config-N/settings.json after finalize_login; UUID bytes: {written_uuid_bytes:?}"
        );
    }

    /// M4-7 acceptance: `finalize_login` writes UUID content to
    /// `config-<N>/.csq-account` when `profiles.json::by_slot` carries a
    /// mapping for the slot. `commit_anthropic_login` runs before `finalize_verified_login`
    /// and (re)uses the fixture UUID via the by_email lookup, so the
    /// post-mint marker write surfaces `Some(uuid)` and emits the
    /// canonical UUID-v4 string. Filename `.csq-account` is unchanged
    /// per OQ #3.
    #[test]
    fn finalize_login_writes_uuid_to_csq_account_marker() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture seeds profiles.json with the
        // by_email entry for slot 1; the verified commit
        // keeps the fixture UUID so the
        // by_slot mapping resolves after the lock release.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Live creds so the credential-seed step does not bail.
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-FAKETESTer-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-FAKETESTer-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Act
        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: UUID accessor returns the fixture UUID.
        assert_eq!(
            crate::accounts::markers::read_csq_account_uuid(&config_dir),
            Some(uuid),
            "M4-7: .csq-account must contain the canonical UUID after finalize_login \
             when by_slot maps; got {:?}",
            crate::accounts::markers::read_identity_marker(&config_dir)
        );
        // The numeric reader (M1-5 contract) returns None for UUID-content.
        assert_eq!(
            crate::accounts::markers::read_csq_account(&config_dir),
            None,
            "M4-7: numeric reader must reject UUID-content markers"
        );
    }

    /// M4-9 (release N affordance, an internal ticket Phase 4):
    /// `finalize_login` MUST NOT populate the v1
    /// `profiles.json::accounts[N]` map. After login, the map is `{}`.
    /// The slot's email is carried by `by_email` (written by
    /// `commit_anthropic_login`), and `ProfilesFile::get_email(N)` resolves it
    /// via the `by_slot → UUID → by_email` reverse-lookup fallback.
    #[test]
    fn finalize_login_does_not_populate_v1_accounts_map() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture seeds by_slot/by_email already.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");

        // Write .claude.json so finalize_login can resolve the email.
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Overwrite live creds with valid csq-shaped CredentialFile JSON.
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-m4-9-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-m4-9-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Wipe any accounts[N] entry the fixture might have set so the
        // assertion measures finalize_login's own behavior.
        {
            use crate::accounts::profiles;
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
            // M4-13: accounts field removed; clear via extra["accounts"] mutation.
            if let Some(accounts_val) = pf.extra.get_mut("accounts") {
                if let Some(obj) = accounts_val.as_object_mut() {
                    obj.clear();
                }
            }
            profiles::save(&path, &pf).unwrap();
        }

        // Act
        let result = fixture_verified_finalize(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {result:?}");

        // Assert: profiles.json::accounts is still empty.
        let path = crate::accounts::profiles::profiles_path(base);
        let pf = crate::accounts::profiles::load(&path).unwrap();
        let accounts_in_extra = pf.extra.get("accounts").and_then(|v| v.as_object());
        assert!(
            accounts_in_extra.is_none() || accounts_in_extra.is_some_and(|m| m.is_empty()),
            "M4-9/M4-13: finalize_login MUST NOT populate the v1 accounts map; \
             extra[accounts]: {:?}",
            pf.extra.get("accounts")
        );

        // Assert: the email survives — by_email carries it, and
        // get_email's reverse-lookup retrieves it.
        assert_eq!(
            pf.get_email(account.get()),
            Some("fixture-slot-1@test.invalid"),
            "M4-9: get_email MUST resolve the email via by_email reverse-lookup"
        );
    }

    /// F-H-1 regression: `finalize_login` MUST clear a stale
    /// `by_slot_identity[N]` entry left from a prior non-OAuth (3P
    /// API-key) binding when the user subsequently logs in with
    /// Anthropic OAuth on the same slot.
    ///
    /// Sequence under test:
    ///   1. Slot 5 has `by_slot_identity["5"] = "apikey:mm"` (prior bind).
    ///   2. User runs `csq login 5` (Anthropic OAuth) → `finalize_login`.
    ///   3. After login, `by_slot_identity["5"]` MUST be absent so that
    ///      `get_email(5)` returns the OAuth email via step 3 (by_email),
    ///      not `"apikey:mm"` via the stale step 1.5.
    #[test]
    fn finalize_login_clears_stale_by_slot_identity_after_3p_to_oauth_transition() {
        use crate::accounts::profiles;
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture seeds by_slot/by_email for slot 1.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");

        // Simulate a prior 3P bind by writing by_slot_identity["1"] = "apikey:mm".
        {
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
            pf.by_slot_identity.insert("1".into(), "apikey:mm".into());
            profiles::save(&path, &pf).unwrap();
        }

        // Verify pre-condition: stale identity exists.
        {
            let path = profiles::profiles_path(base);
            let pf = profiles::load(&path).unwrap();
            assert_eq!(
                pf.by_slot_identity.get("1").map(|s| s.as_str()),
                Some("apikey:mm"),
                "pre: by_slot_identity[1] must be 'apikey:mm' before finalize_login"
            );
        }

        // Write .claude.json so finalize_login can resolve the OAuth email.
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Write live creds so save_canonical_for can seed the UUID path.
        credentials::save(
            &config_dir.join(".credentials.json"),
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-fh1-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-fh1-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Act: perform Anthropic OAuth finalize on the same slot.
        let result = fixture_verified_finalize(base, account);
        assert!(
            result.is_ok(),
            "finalize_login must succeed on 3P→OAuth transition: {result:?}"
        );

        // Assert: by_slot_identity["1"] is now absent.
        let path = profiles::profiles_path(base);
        let pf = profiles::load(&path).unwrap();
        assert!(
            !pf.by_slot_identity.contains_key("1"),
            "F-H-1: by_slot_identity[1] must be absent after OAuth login \
             on a previously 3P-bound slot; got: {:?}",
            pf.by_slot_identity.get("1")
        );
    }

    /// GH an internal ticket: `csq login N` (Anthropic) onto a slot previously bound
    /// ONLY to Gemini (no prior Anthropic/Codex identity — additive binds
    /// already refuse onto an OAuth-bound slot, so this is the only reachable
    /// pre-state) must clear the stale Gemini marker so the slot does not
    /// carry two bindings afterward.
    ///
    /// PRODUCTION ORDERING (an internal ticket regression — was a false pass here
    /// before the fix): every production caller
    /// (`csq/src/cli/commands/login.rs::handle_direct_post_subprocess`, and
    /// the desktop login twins) calls `commit_anthropic_login` BEFORE
    /// `finalize_verified_login` ever runs (an internal ticket),
    /// which mints `by_slot[account]` for the fresh Anthropic identity ahead
    /// of the marker-cleanup call inside `finalize_login`. The prior version
    /// of this test called `finalize_login` directly against a base with NO
    /// `by_slot` mapping at all — a state no production caller ever
    /// produces — which is why it passed against the precedence-masked
    /// detector `detect_stale_marker_binding` used to delegate to. Mint
    /// FIRST here, exactly as production does, so this test actually
    /// exercises the reachable pre-state.
    #[test]
    fn finalize_login_clears_stale_gemini_marker() {
        use crate::providers::gemini::provisioning::{
            is_gemini_bound_slot, write_binding as gemini_write, AuthMode, GeminiBinding,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");
        fs::create_dir_all(&config_dir).unwrap();

        gemini_write(base, account, &GeminiBinding::new(AuthMode::ApiKey, "auto")).unwrap();
        assert!(
            is_gemini_bound_slot(base, account),
            "pre: slot must be Gemini-bound before the OAuth login"
        );

        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let anthropic_creds = crate::credentials::CredentialFile::Anthropic(
            crate::credentials::AnthropicCredentialFile {
                claude_ai_oauth: crate::credentials::OAuthPayload {
                    access_token: crate::types::AccessToken::new("sk-ant-oat01-fh1-test".into()),
                    refresh_token: crate::types::RefreshToken::new("sk-ant-ort01-fh1-test".into()),
                    expires_at: 4102444800000,
                    scopes: vec!["user:inference".into()],
                    subscription_type: Some("max".into()),
                    rate_limit_tier: None,
                    extra: std::collections::HashMap::new(),
                },
                extra: std::collections::HashMap::new(),
            },
        );
        credentials::save(&config_dir.join(".credentials.json"), &anthropic_creds).unwrap();

        // PRODUCTION ORDERING: mint the slot's identity UUID, then write the
        // canonical UUID-keyed credential — exactly what
        // `handle_direct_post_subprocess` does — BEFORE `finalize_login` runs.
        let committed = fixture_verified_commit(base, account).expect("exact grant verified");

        // Pin the vault backend: `clear_detected_marker_binding` deletes the
        // Gemini vault entry BEFORE the marker and is fail-closed on any
        // vault-step failure, so an ambient-resolved vault makes this test
        // platform-dependent — GREEN on macOS/Windows (their vaults always
        // open) and RED on a bus-less Linux CI runner, where the marker is
        // deliberately left in place. See
        // `platform::test_env::with_in_memory_secret_backend`.
        let result =
            with_in_memory_secret_backend(|| finalize_verified_login(base, account, committed));
        assert!(
            result.is_ok(),
            "finalize_login must succeed on Gemini→OAuth transition: {result:?}"
        );
        assert!(
            !is_gemini_bound_slot(base, account),
            "the stale Gemini marker must be removed after finalize_login \
             (production ordering: identity already minted before finalize_login runs)"
        );
    }

    /// Security review regression (GH an internal ticket): a `finalize_login` that
    /// FAILS after the stale-marker DETECTION point must NOT have deleted the
    /// prior Gemini binding. Before the capture/act split, cleanup ran
    /// immediately at the detection point — deleting the marker even when the
    /// rest of `finalize_login` (the profiles lock, the mint, the profile
    /// save) subsequently failed, leaving the slot with NEITHER the new
    /// Anthropic identity (never minted) NOR the old Gemini binding (already
    /// gone). This forces exactly that failure — `.profiles.lock` pre-created
    /// as a DIRECTORY makes `ProfilesFileLock::acquire`'s `OpenOptions::write`
    /// fail deterministically (EISDIR) — and asserts the Gemini marker
    /// SURVIVES.
    // UNIX-ONLY FIXTURE, not a unix-only property. The failure this test needs
    // is injected by creating `.profiles.lock` as a DIRECTORY, so that
    // `ProfilesFileLock::acquire`'s `OpenOptions::write(true).open(path)` fails
    // EISDIR. Windows does not share those semantics — the open does not fail
    // the same way, so `finalize_login` SUCCEEDS and the fixture never creates
    // the condition under test (CI: `Rust tests (windows-latest)`, 4 tests, all
    // on the `result.is_err()` assertion).
    //
    // The behaviour being pinned — a login that fails must not destroy a
    // binding it never replaced — is platform-independent and lives in
    // ordinary control flow. Only the failure INJECTION is Unix-specific, so
    // the test is gated rather than weakened into something that passes
    // everywhere by asserting less.
    #[cfg(unix)]
    #[test]
    fn finalize_login_failure_preserves_prior_gemini_binding() {
        use crate::providers::gemini::provisioning::{
            is_gemini_bound_slot, write_binding as gemini_write, AuthMode, GeminiBinding,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");
        fs::create_dir_all(&config_dir).unwrap();

        gemini_write(base, account, &GeminiBinding::new(AuthMode::ApiKey, "auto")).unwrap();
        assert!(
            is_gemini_bound_slot(base, account),
            "pre: slot must be Gemini-bound before the OAuth login attempt"
        );

        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        credentials::save(
            &config_dir.join(".credentials.json"),
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-fh1-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-fh1-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        let committed =
            fixture_verified_commit(base, account).expect("verified receipt precedes lock failure");
        // Force ProfilesFileLock::acquire to fail: it opens `.profiles.lock`
        // with `OpenOptions::write(true)`, which errors EISDIR against a
        // directory. This is the exact failure point security review named
        // ("the very next fallible step is ProfilesFileLock::acquire").
        fs::remove_file(base.join(".profiles.lock")).unwrap();
        fs::create_dir_all(base.join(".profiles.lock")).unwrap();

        // Pinned for the same reason as the sibling cleanup test, and for one
        // more: with an ambient vault that cannot open, the cleanup is blocked
        // by the environment rather than by the capture/act split, so the
        // survival assertion would hold even if that split regressed. Pinning
        // an always-available backend keeps this test discriminating.
        let result =
            with_in_memory_secret_backend(|| finalize_verified_login(base, account, committed));
        assert!(
            result.is_err(),
            "finalize_login must fail when the profiles lock cannot be acquired: {result:?}"
        );
        assert!(
            is_gemini_bound_slot(base, account),
            "the Gemini marker must SURVIVE a finalize_login that fails after \
             the detect point — a failed login must not destroy a binding it \
             never actually replaced"
        );
    }

    /// GH an internal ticket (security review, round 3). Sibling of the Gemini test
    /// above, for the THIRD-PARTY binding — and the more expensive variant.
    ///
    /// `unbind_provider_from_slot` removes `ANTHROPIC_AUTH_TOKEN` from
    /// `config-<N>/settings.json`, and that token IS the operator's 3P API
    /// key. While the unbind ran BEFORE `ProfilesFileLock::acquire`, a login
    /// that failed on the lock left the slot with neither a new OAuth identity
    /// nor its previous key — the operator had to go find and re-enter it.
    /// A credential-less marker is recoverable by re-binding; a discarded API
    /// key is not.
    ///
    /// Non-vacuity: moving the unbind back above the lock acquisition reds
    /// this test — the token is gone by the time `finalize_login` returns Err.
    // UNIX-ONLY FIXTURE, not a unix-only property. The failure this test needs
    // is injected by creating `.profiles.lock` as a DIRECTORY, so that
    // `ProfilesFileLock::acquire`'s `OpenOptions::write(true).open(path)` fails
    // EISDIR. Windows does not share those semantics — the open does not fail
    // the same way, so `finalize_login` SUCCEEDS and the fixture never creates
    // the condition under test (CI: `Rust tests (windows-latest)`, 4 tests, all
    // on the `result.is_err()` assertion).
    //
    // The behaviour being pinned — a login that fails must not destroy a
    // binding it never replaced — is platform-independent and lives in
    // ordinary control flow. Only the failure INJECTION is Unix-specific, so
    // the test is gated rather than weakened into something that passes
    // everywhere by asserting less.
    #[cfg(unix)]
    #[test]
    fn finalize_login_failure_preserves_prior_third_party_key() {
        use crate::accounts::third_party::bind_provider_to_slot;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");
        fs::create_dir_all(&config_dir).unwrap();

        // Arrange: slot 1 is bound to a 3P provider with a real-shaped key.
        bind_provider_to_slot(base, "mm", account, Some("sk-test-minimax-round3"), None).unwrap();
        let settings_path = config_dir.join("settings.json");
        let before = fs::read_to_string(&settings_path).unwrap();
        assert!(
            before.contains("ANTHROPIC_AUTH_TOKEN"),
            "pre: the 3P binding must carry an auth token before the login attempt"
        );

        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        credentials::save(
            &config_dir.join(".credentials.json"),
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new("sk-ant-oat01-r3-test".into()),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-r3-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        let committed =
            fixture_verified_commit(base, account).expect("verified receipt precedes lock failure");
        // Act: force the same EISDIR failure at `ProfilesFileLock::acquire`.
        // Unlike the Gemini fixture, `bind_provider_to_slot` has already taken
        // the profiles lock, so `.profiles.lock` exists as a regular FILE —
        // `create_dir_all` would fail EEXIST against it. Remove it first.
        let lock_path = base.join(".profiles.lock");
        let _ = fs::remove_file(&lock_path);
        fs::create_dir_all(&lock_path).unwrap();
        let result = finalize_verified_login(base, account, committed);

        // Assert: the login failed AND the operator's key survived it.
        assert!(
            result.is_err(),
            "finalize_login must fail when the profiles lock cannot be acquired: {result:?}"
        );
        let after = fs::read_to_string(&settings_path).unwrap();
        assert_eq!(
            before, after,
            "failed receipt finalization must preserve every settings byte"
        );
        assert!(
            after.contains("ANTHROPIC_AUTH_TOKEN"),
            "the 3P API key must SURVIVE a finalize_login that fails — a login \
             that replaced nothing must not discard the operator's key. \
             settings.json after the failed login: {after}"
        );
    }

    /// GH an internal ticket: `csq login N` (Anthropic) onto a slot previously bound
    /// ONLY to a native CLI (Kimi/Grok) must clear the stale native marker so
    /// the slot does not carry two bindings afterward.
    ///
    /// PRODUCTION ORDERING (an internal ticket regression — see the Gemini test above
    /// for the full rationale): mint the identity + save the canonical
    /// credential BEFORE `finalize_login`, exactly as
    /// `handle_direct_post_subprocess` does, so this test exercises the
    /// state production actually reaches rather than an unreachable
    /// empty-`by_slot` fixture.
    #[test]
    fn finalize_login_clears_stale_native_marker() {
        use crate::providers::catalog::Surface;
        use crate::providers::native;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");
        fs::create_dir_all(&config_dir).unwrap();

        native::write_binding(base, account, Surface::Kimi).unwrap();
        assert!(native::marker_exists(base, account, Surface::Kimi));

        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let anthropic_creds = crate::credentials::CredentialFile::Anthropic(
            crate::credentials::AnthropicCredentialFile {
                claude_ai_oauth: crate::credentials::OAuthPayload {
                    access_token: crate::types::AccessToken::new("sk-ant-oat01-fh1-test".into()),
                    refresh_token: crate::types::RefreshToken::new("sk-ant-ort01-fh1-test".into()),
                    expires_at: 4102444800000,
                    scopes: vec!["user:inference".into()],
                    subscription_type: Some("max".into()),
                    rate_limit_tier: None,
                    extra: std::collections::HashMap::new(),
                },
                extra: std::collections::HashMap::new(),
            },
        );
        credentials::save(&config_dir.join(".credentials.json"), &anthropic_creds).unwrap();

        // PRODUCTION ORDERING: mint, then save canonical — BEFORE finalize_login.
        let committed = fixture_verified_commit(base, account).expect("exact grant verified");

        let result = finalize_verified_login(base, account, committed);
        assert!(
            result.is_ok(),
            "finalize_login must succeed on native→OAuth transition: {result:?}"
        );
        assert!(
            !native::marker_exists(base, account, Surface::Kimi),
            "the stale native marker must be removed after finalize_login \
             (production ordering: identity already minted before finalize_login runs)"
        );
    }

    /// Fresh verified login publishes a full context and UUID; legacy email indexing remains unchanged.
    #[test]
    fn verified_login_mints_uuid_when_absent_on_fresh_install() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(3u16).unwrap();

        // Fresh install: config-3 carries the email CC wrote; no profiles.json.
        let config_dir = base.join("config-3");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fresh-slot-3@test.invalid"}}"#,
        )
        .unwrap();

        assert!(
            profiles::resolve_slot_to_uuid(base, 3).is_none(),
            "pre-condition: slot 3 must have no UUID before mint"
        );

        let credential: credentials::CredentialFile = serde_json::from_value(serde_json::json!({"claudeAiOauth":{"accessToken":"fixture-verified-at","refreshToken":"fixture-verified-rt","expiresAt":4102444800000u64,"scopes":[]}})).unwrap();
        credentials::save(&config_dir.join(".credentials.json"), &credential).unwrap();
        fixture_verified_finalize(base, account).expect("verified fresh login must succeed");

        let uuid = profiles::resolve_slot_to_uuid(base, 3)
            .expect("slot 3 must resolve to a minted UUID after verified login");
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(
            pf.by_email.is_empty(),
            "legacy email index is not new ownership authority"
        );
        assert!(
            pf.anthropic_contexts
                .iter()
                .any(|entry| entry.identity_uuid == uuid
                    && entry.email == "fresh-slot-3@test.invalid")
        );
    }

    /// The exact grants' verified native contexts distinguish equal-email orgs.
    #[test]
    fn org_identity_regression_same_email_distinct_native_contexts_get_distinct_uuids() {
        use crate::accounts::anthropic_identity as ai;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let email = "same-user@test.invalid";
        for slot in [1u16, 2u16] {
            let account_uuid = uuid::Uuid::from_u128(u128::from(slot) + 100);
            let organization_uuid = uuid::Uuid::from_u128(u128::from(slot) + 200);
            let config = base.join(format!("config-{slot}"));
            fs::create_dir_all(&config).unwrap();
            let native = serde_json::json!({"oauthAccount": {"emailAddress":email,"accountUuid":account_uuid,"organizationUuid":organization_uuid}});
            fs::write(
                config.join(".claude.json"),
                serde_json::to_vec(&native).unwrap(),
            )
            .unwrap();
            crate::platform::fs::secure_file(&config.join(".claude.json")).unwrap();
            let expected = ai::read_native_expectation(&config).unwrap();
            let credential = crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(format!("fake-access-{slot}")),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "fake-refresh-{slot}"
                        )),
                        expires_at: 4102444800000,
                        scopes: vec![],
                        subscription_type: None,
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            );
            let transport: crate::daemon::usage_poller::HttpGetFn = std::sync::Arc::new(
                move |url, bearer, _| {
                    assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
                    assert_eq!(bearer, format!("fake-access-{slot}"));
                    Ok((200, serde_json::to_vec(&serde_json::json!({"account":{"uuid":account_uuid,"email":email},"organization":{"uuid":organization_uuid}})).unwrap()))
                },
            );
            let account = AccountNum::try_from(slot).unwrap();
            let prior = ai::capture_login_prior(base, account).unwrap();
            let committed = ai::commit_anthropic_login_with(
                base,
                account,
                &credential,
                &transport,
                Some(&expected),
                prior,
            )
            .unwrap();
            assert_eq!(
                finalize_verified_login(base, account, committed).unwrap(),
                email
            );
        }
        assert_ne!(profiles::resolve_slot_to_uuid(base, 1).unwrap(), profiles::resolve_slot_to_uuid(base, 2).unwrap(),
            "different verified account/organization contexts must not share a credential identity merely because their emails match");
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.anthropic_contexts.len(), 2);
        assert!(pf.by_email.is_empty(), "fresh context publication must preserve the legacy index without creating ownership claims");
    }

    /// Repeated verified login to the same full context preserves the identity UUID.
    #[test]
    fn verified_login_reuses_uuid_for_same_context() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let config_dir = base.join("config-2");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"idem-slot-2@test.invalid"}}"#,
        )
        .unwrap();

        let credential: credentials::CredentialFile = serde_json::from_value(serde_json::json!({"claudeAiOauth":{"accessToken":"fixture-verified-at","refreshToken":"fixture-verified-rt","expiresAt":4102444800000u64,"scopes":[]}})).unwrap();
        credentials::save(&config_dir.join(".credentials.json"), &credential).unwrap();
        fixture_verified_finalize(base, account).expect("first verified login must succeed");
        let first = profiles::resolve_slot_to_uuid(base, 2).unwrap();
        fixture_verified_finalize(base, account)
            .expect("same-context verified login must reuse UUID");
        let second = profiles::resolve_slot_to_uuid(base, 2).unwrap();
        assert_eq!(first, second, "UUID must not churn across repeat calls");
    }
}
