//! One quarantine for unpublished Claude and Codex grants. Actual child custody
//! retains the shared grant. No PID/group census is authority to remove a grant.
use crate::error::PlatformError;
use crate::platform::{fs, lock};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum LaunchState {
    Created,
    Spawning,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    version: u8,
    pid: u32,
    birth: Option<u64>,
    state: LaunchState,
}

/// Which durability step of a lease write failed.
///
/// Deliberately a fixed vocabulary: a quarantine error may name the STEP and
/// the io class, and nothing else — no path, no file content, nothing from the
/// credential payload (`security.md` §2/§8). What a caller DECIDES is
/// unchanged; only what a reader can learn from the failure improves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseStep {
    Write,
    Rename,
    // Windows cannot open a directory as a File, so the step is never
    // constructed there; the tag vocabulary still names it on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    DirFsync,
}

impl LeaseStep {
    /// `o_excl_create` is the write step's own exclusivity failure, reported
    /// apart from an ordinary write/fsync failure: "someone else's file is
    /// already there" and "the disk refused the bytes" send a reader to
    /// different places, and `write_new_private` documents the distinction.
    fn tag(self, error: &PlatformError) -> &'static str {
        match self {
            LeaseStep::Write => match error {
                PlatformError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    "o_excl_create"
                }
                _ => "write",
            },
            // `rename(2)` replaces an existing target, so EEXIST here comes from
            // the EXDEV fallback's staging file (the cross-filesystem path in
            // `atomic_replace_unix`), not from an ordinary same-fs rename. A
            // reader chasing this needs to know the rename took that branch.
            LeaseStep::Rename => match error {
                PlatformError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    "rename_eexist"
                }
                _ => "rename",
            },
            LeaseStep::DirFsync => "dir_fsync",
        }
    }

    /// `kind`/`errno` come from the io error when there is one, and a Win32
    /// failure carries its numeric `code` as the errno — a number only, never
    /// the message. Every other `PlatformError` variant carries a path or
    /// free-text, so it is reported only as its class.
    fn detail(self, error: &PlatformError) -> String {
        let (kind, errno) = platform_io_class(error).unwrap_or_else(non_io_class);
        format!(
            "lease_step={} kind={} errno={}",
            self.tag(error),
            kind,
            errno
        )
    }
}

/// `kind`/`errno` of an io error: the `ErrorKind` name and the raw OS errno
/// (`-1` when there is none). Never the io error's message, which can carry a
/// path.
fn io_class(error: &std::io::Error) -> (String, i64) {
    (
        format!("{:?}", error.kind()),
        error.raw_os_error().map_or(-1, i64::from),
    )
}

/// The io-carrying `PlatformError` variants; a Win32 failure carries its
/// numeric `code` as the errno, never its message.
fn platform_io_class(error: &PlatformError) -> Option<(String, i64)> {
    match error {
        PlatformError::Io(e) => Some(io_class(e)),
        PlatformError::Win32 { code, .. } => Some(("win32".to_string(), i64::from(*code))),
        _ => None,
    }
}

fn non_io_class() -> (String, i64) {
    ("non_io".to_string(), -1)
}

/// `kind`/`errno` of a pre-lease step's failure. Lock contention and lock
/// timeout keep their own kinds, so "another owner holds it" and "the wait
/// ran out" stay distinguishable from an ordinary failure once the
/// path-bearing `PlatformError` text is gone.
fn pre_lease_class(error: &anyhow::Error) -> (String, i64) {
    if let Some(platform) = error.downcast_ref::<PlatformError>() {
        return match platform {
            PlatformError::LockContention { .. } => ("lock_contention".to_string(), -1),
            PlatformError::LockTimeout { .. } => ("lock_timeout".to_string(), -1),
            other => platform_io_class(other).unwrap_or_else(non_io_class),
        };
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        return io_class(io);
    }
    non_io_class()
}

/// A pre-lease step's refusal, in the same fixed vocabulary as a failed first
/// lease write: the step, the class, the errno — nothing from the error's text.
fn pre_lease_refused((step, error): (PreLeaseStep, anyhow::Error)) -> anyhow::Error {
    let (kind, errno) = pre_lease_class(&error);
    anyhow!(lease_creation_refused(&format!(
        "step={} kind={} errno={}",
        step.tag(),
        kind,
        errno
    )))
}

/// The refusal `VendorLoginGrant::new` reports when its FIRST lease write
/// fails. Deliberately neither a quarantine message nor path-bearing: nothing
/// is quarantined (no grant was ever published, and the caller drops the
/// grant), and this text reaches the desktop frontend, which redacts tokens
/// but does not strip paths — an absolute grant home carries the user name.
fn lease_creation_refused(detail: &str) -> String {
    format!("vendor_grant_lease_refused ({detail})")
}

// Test-only fault injection for the FIRST lease write. Without it a test can
// only call `lease_creation_refused` directly — which pins the helper, not what
// `new` returns, so reverting `new`'s mapping would leave the assertion green.
// This drives the real path instead. `#[cfg(test)]` throughout, so no shipped
// build contains the flag or the branch. (Plain comments, not `///`: rustdoc
// does not document macro invocations, and `-D warnings` refuses the doc block.)
#[cfg(test)]
thread_local! {
    static FAIL_LEASE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn arm_lease_write_fault() {
    FAIL_LEASE_WRITE.with(|armed| armed.set(true));
}

/// One-shot: the injection disarms itself as it fires, so a stray arm cannot
/// leak a failure into a later test on the same thread.
#[cfg(test)]
fn lease_write_fault_armed() -> bool {
    FAIL_LEASE_WRITE.with(|armed| armed.replace(false))
}

/// A step `VendorLoginGrant::new` runs BEFORE its first lease write. Each
/// one's failure is reported through `PreLeaseStep::run`, the single funnel
/// the real result and the test fault both pass through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PreLeaseStep {
    Canonicalize,
    SweepCanonicalize,
    SweepTighten,
    SweepReadDir,
    SweepRemove,
    Create,
    OwnerLock,
}

impl PreLeaseStep {
    fn tag(self) -> &'static str {
        match self {
            PreLeaseStep::Canonicalize => "canonicalize",
            PreLeaseStep::SweepCanonicalize => "sweep_canonicalize",
            PreLeaseStep::SweepTighten => "sweep_tighten",
            PreLeaseStep::SweepReadDir => "sweep_read_dir",
            PreLeaseStep::SweepRemove => "sweep_remove",
            PreLeaseStep::Create => "create",
            PreLeaseStep::OwnerLock => "owner_lock",
        }
    }
    /// Runs `op` as this step. Under test, an armed fault for this step
    /// replaces the operation's result, so the fault travels the same
    /// reporting path a real failure does.
    fn run<T, E: Into<anyhow::Error>>(
        self,
        #[cfg_attr(not(test), allow(unused_variables))] path: &Path,
        op: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, (PreLeaseStep, anyhow::Error)> {
        #[cfg(test)]
        if let Some(error) = take_pre_lease_fault(self, path) {
            return Err((self, error));
        }
        op().map_err(|e| (self, e.into()))
    }
}

// Test-only fault injection for the pre-lease steps of `new`, same shape and
// rationale as `FAIL_LEASE_WRITE`: a one-shot that drives the REAL `new` path
// so reverting its mapping reddens the test. The builder receives the path the
// step was operating on, so the injected error can carry it the way a
// `PlatformError::LockContention` does.
#[cfg(test)]
type FaultBuilder = fn(&Path) -> anyhow::Error;

#[cfg(test)]
thread_local! {
    static PRE_LEASE_FAULT: std::cell::Cell<Option<(PreLeaseStep, FaultBuilder)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn arm_pre_lease_fault(step: PreLeaseStep, build: FaultBuilder) {
    PRE_LEASE_FAULT.with(|armed| armed.set(Some((step, build))));
}

#[cfg(test)]
fn take_pre_lease_fault(step: PreLeaseStep, path: &Path) -> Option<anyhow::Error> {
    PRE_LEASE_FAULT.with(|armed| match armed.get() {
        Some((armed_step, build)) if armed_step == step => {
            armed.set(None);
            Some(build(path))
        }
        _ => None,
    })
}

// Test-only: makes `new` find its owner lock already held, through the real
// lock, so the `Ok(None)` branch is driven rather than simulated.
#[cfg(test)]
thread_local! {
    static OWNER_LOCK_HELD_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn take_owner_lock_held_fault() -> bool {
    OWNER_LOCK_HELD_FAULT.with(|armed| armed.replace(false))
}

/// The base-relative marker [`VendorLoginGrant::quarantine_message`] names
/// the accounts base with, instead of its absolute path.
const QUARANTINE_BASE_MARKER: &str = "<csq-base>";

/// Rewrites every quarantine location in `text` (one message, or an error
/// chain that embeds one) to name the real accounts `base`.
///
/// For the operator's OWN terminal ONLY — the CLI's single error exit. The
/// desktop renderer must keep the base-relative form (an internal ticket): an absolute
/// base names the OS user, and the renderer is a trust boundary the
/// operator's terminal is not.
pub fn quarantine_text_for_terminal(text: &str, base: &Path) -> String {
    rewrite_quarantine_locations(text, |id| {
        base.join(".login-grants").join(id).display().to_string()
    })
}

/// Replaces each `vendor_login_quarantined: <csq-base>/.login-grants/<id>`
/// with `vendor_login_quarantined: <locate(id)>`. `<id>` runs to `;`,
/// whitespace or the end and must be a well-formed grant id
/// (`grant-` + UUID characters); any other token keeps the renderer form.
/// The whole location comes from `locate`, so its separators are the
/// platform's own, never the renderer form's `/`.
fn rewrite_quarantine_locations(text: &str, locate: impl Fn(&str) -> String) -> String {
    let head = format!("vendor_login_quarantined: {QUARANTINE_BASE_MARKER}/.login-grants/");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&head) {
        out.push_str(&rest[..at]);
        let after = &rest[at + head.len()..];
        let end = after
            .find(|c: char| c == ';' || c.is_whitespace())
            .unwrap_or(after.len());
        let id = &after[..end];
        let well_formed = id.strip_prefix("grant-").is_some_and(|uuid| {
            !uuid.is_empty() && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        });
        if well_formed {
            out.push_str("vendor_login_quarantined: ");
            out.push_str(&locate(id));
        } else {
            out.push_str(&head);
            out.push_str(id);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

pub struct VendorLoginGrant {
    home: PathBuf,
    /// `grant-<uuid>`: the home's own directory name, kept so the
    /// quarantine location can be rendered without the absolute path.
    name: String,
    lease: Lease,
    /// Held by a dedicated thread, never by whoever drops the grant last: on
    /// Windows the underlying guard is `!Send` (Q6 — a named mutex releases
    /// only from its acquiring thread), and the grant travels between the
    /// login worker and its readers. The handle is `Send`; the holder drops
    /// the guard on the thread that took it.
    _owner: lock::OwnerThreadLock,
    cleaned: bool,
}

impl VendorLoginGrant {
    /// Every refusal before the lease is written is either a fixed literal
    /// or `vendor_grant_lease_refused (step=… kind=… errno=…)`: this text
    /// reaches a desktop frontend that redacts tokens but does not strip
    /// paths, and an absolute grant home carries the user name (an internal ticket).
    pub fn new(base: &Path) -> Result<Self> {
        fs::ensure_private_dir_root(base)
            .map_err(|_| anyhow!("vendor grant preparation refused"))?;
        let root = PreLeaseStep::Canonicalize
            .run(base, || std::fs::canonicalize(base))
            .map_err(pre_lease_refused)?
            .join(".login-grants");
        fs::ensure_private_dir(&root).map_err(|_| anyhow!("vendor grant preparation refused"))?;
        Self::sweep_steps(base, owner_gone).map_err(pre_lease_refused)?;
        let name = format!("grant-{}", uuid::Uuid::new_v4());
        let home = root.join(&name);
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        PreLeaseStep::Create
            .run(&home, || builder.create(&home))
            .map_err(pre_lease_refused)?;
        let owner_lock = home.join("owner.lock");
        let owner = PreLeaseStep::OwnerLock
            .run(&owner_lock, || {
                // Test-only: hold the owner lock first, so the real second
                // hold below reports it as held (`Ok(None)`).
                #[cfg(test)]
                let _held = take_owner_lock_held_fault()
                    .then(|| lock::hold_file_on_owner_thread(&owner_lock));
                lock::hold_file_on_owner_thread(&owner_lock)
            })
            .map_err(pre_lease_refused)?
            .ok_or_else(|| anyhow!(lease_creation_refused("step=owner_lock kind=held errno=-1")))?;
        let lease = Lease {
            version: 1,
            pid: std::process::id(),
            birth: crate::sessions::ancestor_start(std::process::id()),
            state: LaunchState::Created,
        };
        let grant = Self {
            home,
            name,
            lease,
            _owner: owner,
            cleaned: false,
        };
        // A creation refusal is NOT a quarantine: no grant was ever published,
        // and `Drop` still removes the home. The text must therefore carry no
        // absolute path — it reaches a frontend that redacts tokens only.
        grant
            .persist_lease()
            .map_err(|e| anyhow!(lease_creation_refused(&e.to_string())))?;
        Ok(grant)
    }
    pub fn config_dir(&self) -> &Path {
        &self.home
    }
    /// Names the quarantined grant RELATIVE to the accounts base, never by
    /// its absolute path: this text reaches the desktop renderer (Claude and
    /// Codex) and the CLI, and an absolute grant home names the OS user —
    /// including when the base is a symlink to a tree outside `$HOME`, where
    /// no home redaction can catch it (an internal ticket R2-1). The grant id stays: it
    /// is how an operator finds the quarantine under their base.
    pub fn quarantine_message(&self) -> String {
        format!(
            "vendor_login_quarantined: {QUARANTINE_BASE_MARKER}/.login-grants/{}",
            self.name
        )
    }
    /// Returns the failing step's DETAIL only — no prefix and no path. Each
    /// caller owns the framing, because the same failure means two different
    /// things: `begin_launch`/`mark_completed` prepend the quarantine message
    /// (a grant WAS published), while `new` must not claim a quarantine at all
    /// and must not put a path in front of a frontend that strips tokens.
    fn persist_lease(&self) -> Result<()> {
        #[cfg(test)]
        if lease_write_fault_armed() {
            return Err(anyhow!(
                "{}",
                LeaseStep::Write.detail(&PlatformError::from(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied
                )))
            ));
        }
        let path = self.home.join("lease.json");
        let tmp = fs::unique_tmp_path(&path);
        let bytes = serde_json::to_vec(&self.lease).map_err(|_| {
            // serde's Display can echo field names, so only the fixed tag.
            anyhow!("lease_step=serialize kind=non_io errno=-1")
        })?;
        fs::write_new_private_synced(&tmp, &bytes)
            .map_err(|e| anyhow!(LeaseStep::Write.detail(&e)))?;
        fs::atomic_replace(&tmp, &path).map_err(|e| anyhow!(LeaseStep::Rename.detail(&e)))?;
        #[cfg(unix)]
        std::fs::File::open(&self.home)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| anyhow!(LeaseStep::DirFsync.detail(&PlatformError::from(e))))?;
        Ok(())
    }
    /// Durable BEFORE actual spawn. A crash anywhere after this fence is unknown
    /// until the owner records actual group/readers completion. No PID shortcut.
    pub fn begin_launch(&mut self) -> Result<()> {
        if self.lease.state != LaunchState::Created {
            return Err(anyhow!(self.quarantine_message()));
        }
        self.lease.state = LaunchState::Spawning;
        // A grant HAS been published by this point, so the quarantine framing
        // is correct — and the cause is appended rather than mapped away,
        // which is what made every quarantine report identical.
        self.persist_lease()
            .map_err(|e| anyhow!("{} ({e})", self.quarantine_message()))
    }
    /// Only the actual owner may call this after direct-child reap and captured reader EOF/join.
    pub fn mark_completed(&mut self) -> Result<()> {
        self.lease.state = LaunchState::Complete;
        self.persist_lease()
            .map_err(|e| anyhow!("{} ({e})", self.quarantine_message()))
    }
    pub fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        if self.lease.state == LaunchState::Spawning {
            return Err(anyhow!(self.quarantine_message()));
        }
        crate::credentials::keychain::clear_login_grant_home(&self.home)
            .map_err(|_| anyhow!("{}; cleanup unconfirmed", self.quarantine_message()))?;
        std::fs::remove_dir_all(&self.home)
            .map_err(|_| anyhow!("{}; cleanup unconfirmed", self.quarantine_message()))?;
        self.cleaned = true;
        Ok(())
    }
    /// Read only the known slot config, and select strictly benign key/value pairs.
    /// No auth, sessions, history, env, provider, MCP, or unknown table is copied.
    pub fn prepare_codex(&self, base: &Path, account: crate::types::AccountNum) -> Result<()> {
        let config = base.join(format!("config-{account}"));
        match std::fs::symlink_metadata(&config) {
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
                return Err(anyhow!("Codex login config refused"));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => (),
        }
        let source = config.join("config.toml");
        let bytes = fs::read_private_regular_nofollow_bounded(&source, 1024 * 1024)?;
        let mut output = toml::value::Table::new();
        if let Some(bytes) = bytes {
            let bytes = zeroize::Zeroizing::new(bytes);
            let text =
                std::str::from_utf8(&bytes).map_err(|_| anyhow!("Codex login config refused"))?;
            let mut parsed: toml::Value =
                toml::from_str(text).map_err(|_| anyhow!("Codex login config refused"))?;
            if let Some(value) = parsed.get("model").and_then(toml::Value::as_str) {
                if value.len() <= 128
                    && !value.is_empty()
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                {
                    output.insert("model".into(), toml::Value::String(value.into()));
                }
            }
            if let Some(value) = parsed
                .get("model_reasoning_effort")
                .and_then(toml::Value::as_str)
            {
                if ["none", "minimal", "low", "medium", "high", "xhigh"].contains(&value) {
                    output.insert(
                        "model_reasoning_effort".into(),
                        toml::Value::String(value.into()),
                    );
                }
            }
            wipe_toml(&mut parsed);
        }
        output.insert(
            "cli_auth_credentials_store".into(),
            toml::Value::String("file".into()),
        );
        let text = toml::to_string(&output).map_err(|_| anyhow!("Codex login config refused"))?;
        fs::write_new_private_synced(&self.home.join("config.toml"), text.as_bytes())?;
        Ok(())
    }
    /// Safe orphans only: never-launched or positively completed + exact owner
    /// gone + lease available. Spawning/malformed/unreadable/unknown is KEEP.
    ///
    /// Each failure is tagged by the step that produced it, and `new` (its
    /// only caller) reports it in the fixed path-free vocabulary. There is
    /// deliberately no public plain-error entry point: a raw sweep error can
    /// carry a path, and a caller that forwarded one to the desktop would
    /// reopen an internal ticket.
    fn sweep_steps(
        base: &Path,
        gone: impl Fn(&Lease) -> bool,
    ) -> std::result::Result<(), (PreLeaseStep, anyhow::Error)> {
        let root = PreLeaseStep::SweepCanonicalize
            .run(base, || std::fs::canonicalize(base))?
            .join(".login-grants");
        if root.exists() {
            PreLeaseStep::SweepTighten.run(&root, || fs::tighten_existing_private_dir(&root))?;
        }
        let entries = match PreLeaseStep::SweepReadDir.run(&root, || std::fs::read_dir(&root)) {
            Ok(entries) => entries,
            Err((_, e))
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(())
            }
            Err(tagged) => return Err(tagged),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let home = entry.path();
            let valid_name = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_prefix("grant-"))
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .is_some();
            if !valid_name || entry.file_type().map_or(true, |kind| !kind.is_dir()) {
                continue;
            }
            if fs::tighten_existing_private_dir(&home).is_err() {
                continue;
            }
            let bytes =
                match fs::read_private_regular_nofollow_bounded(&home.join("lease.json"), 4096) {
                    Ok(Some(bytes)) => bytes,
                    _ => continue,
                };
            let lease: Lease = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if lease.version != 1 || lease.state == LaunchState::Spawning || !gone(&lease) {
                continue;
            }
            let _lease = match lock::try_lock_file_bounded_nofollow(
                &home.join("owner.lock"),
                1,
                std::time::Duration::ZERO,
            ) {
                Ok(Some(guard)) => guard,
                _ => continue,
            };
            if crate::credentials::keychain::clear_login_grant_home(&home).is_ok() {
                PreLeaseStep::SweepRemove.run(&home, || std::fs::remove_dir_all(&home))?;
            }
        }
        Ok(())
    }
}
fn wipe_toml(value: &mut toml::Value) {
    use zeroize::Zeroize;
    match value {
        toml::Value::String(s) => s.zeroize(),
        toml::Value::Array(a) => {
            for v in a {
                wipe_toml(v);
            }
        }
        toml::Value::Table(t) => {
            for (_, v) in t {
                wipe_toml(v);
            }
        }
        _ => (),
    }
}
fn owner_gone(lease: &Lease) -> bool {
    let Some(saved) = lease.birth else {
        return false;
    };
    if let Some(current) = crate::sessions::ancestor_start(lease.pid) {
        return current != saved;
    }
    #[cfg(unix)]
    {
        if lease.pid == 0 || lease.pid > i32::MAX as u32 {
            return false;
        }
        // Only typed ESRCH is absence; EPERM and all unknowns keep the grant.
        let missing = unsafe { libc::kill(lease.pid as i32, 0) == -1 };
        missing && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        false
    } // No typed Windows absence instrument here: conservative KEEP.
}
impl Drop for VendorLoginGrant {
    fn drop(&mut self) {
        if !self.cleaned && self.cleanup().is_err() {
            tracing::error!(error_kind = "vendor_login_quarantined", quarantine = %self.home.display(),
                "unpublished grant retained; cleanup not confirmed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orphan(base: &Path, state: LaunchState) -> PathBuf {
        let mut grant = VendorLoginGrant::new(base).unwrap();
        let home = grant.config_dir().to_owned();
        grant.lease.state = state;
        grant.persist_lease().unwrap();
        // Model abrupt owner death: retain files but release its kernel lease.
        grant.cleaned = true;
        drop(grant);
        home
    }

    /// The defect this guards: every lease-write failure used to collapse into
    /// the bare quarantine message, so a captured bundle could not say WHICH
    /// step failed. The refusal must be unchanged; the cause must now be named.
    ///
    /// Root-proof by construction: rename(2) of a file onto an existing
    /// directory is refused regardless of uid or permission bits.
    #[test]
    #[cfg(unix)]
    fn lease_rename_failure_names_the_step_and_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut grant = VendorLoginGrant::new(dir.path()).unwrap();
        let path = grant.config_dir().join("lease.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = grant.mark_completed();
        grant.cleaned = true;
        let text = error
            .expect_err("renaming a lease onto a directory must refuse")
            .to_string();
        assert!(
            text.starts_with("vendor_login_quarantined: "),
            "the quarantine decision text changed: {text}"
        );
        assert!(
            text.contains("lease_step=rename"),
            "step tag missing: {text}"
        );
    }

    /// The step vocabulary is fixed on purpose: a reader must be able to tell
    /// an exclusivity loss from a broken write from a broken directory fsync,
    /// and NO path may ride along in the detail.
    #[test]
    #[cfg(unix)]
    fn lease_step_detail_is_a_fixed_vocabulary_and_never_carries_a_path() {
        let io = |errno: i32| PlatformError::Io(std::io::Error::from_raw_os_error(errno));
        assert_eq!(
            LeaseStep::Write.tag(&io(libc::EEXIST)),
            "o_excl_create",
            "EEXIST is the O_EXCL create losing its race, not a plain write"
        );
        assert_eq!(LeaseStep::Write.tag(&io(libc::EACCES)), "write");
        assert_eq!(LeaseStep::Rename.tag(&io(libc::EISDIR)), "rename");
        // rename(2) replaces an existing target, so EEXIST means the EXDEV
        // fallback's staging file, and it is named apart for that reason.
        assert_eq!(LeaseStep::Rename.tag(&io(libc::EEXIST)), "rename_eexist");
        assert_eq!(LeaseStep::DirFsync.tag(&io(libc::EINVAL)), "dir_fsync");
        let detail = LeaseStep::DirFsync.detail(&io(libc::EINVAL));
        assert_eq!(detail, "lease_step=dir_fsync kind=InvalidInput errno=22");
        // A Win32 failure carries its numeric code as the errno, never its
        // message.
        let win32 = PlatformError::Win32 {
            code: 5,
            message: "Access is denied. /some/path".to_string(),
        };
        assert_eq!(
            LeaseStep::Write.detail(&win32),
            "lease_step=write kind=win32 errno=5"
        );
        // A non-io variant carries a path in its Display; the detail must not.
        let contention = PlatformError::LockContention {
            path: PathBuf::from("/some/grant/home/owner.lock"),
        };
        let detail = LeaseStep::Write.detail(&contention);
        assert_eq!(detail, "lease_step=write kind=non_io errno=-1");
        assert!(
            !detail.contains("/some/grant/home"),
            "a path rode along in the lease detail: {detail}"
        );
    }

    /// `new` must not claim a quarantine and must not carry a path. Nothing was
    /// published, `Drop` still removes the home, and the text reaches a
    /// frontend that redacts tokens but does not strip paths — an absolute
    /// grant home carries the user name.
    ///
    /// This drives the REAL path, through the test-only fault hook. An earlier
    /// version called `lease_creation_refused` directly, which pinned the
    /// helper rather than what `new` returns — reverting `new`'s mapping left
    /// it green (R2 finding, D237 5d: a vacuous pin on a trust boundary).
    #[test]
    fn new_refusal_is_path_free_and_not_a_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        arm_lease_write_fault();
        let error = match VendorLoginGrant::new(dir.path()) {
            Ok(_) => panic!("the armed write fault must refuse the grant"),
            Err(error) => error,
        };
        let text = error.to_string();
        assert!(
            text.starts_with("vendor_grant_lease_refused ("),
            "the creation refusal lost its prefix: {text}"
        );
        assert!(
            !text.contains("vendor_login_quarantined"),
            "a creation refusal must not claim a quarantine: {text}"
        );
        let dir_text = dir.path().display().to_string();
        assert!(
            !text.contains(&dir_text),
            "the grant's directory reached the refusal: {text}"
        );
        assert!(
            !text.contains('/') && !text.contains('\\'),
            "a path reached the creation refusal: {text}"
        );
    }

    /// Drives `new` with a fault armed at `step` whose error carries the path
    /// the step was operating on, and returns the refusal text.
    fn pre_lease_refusal(dir: &Path, step: PreLeaseStep, build: FaultBuilder) -> String {
        arm_pre_lease_fault(step, build);
        let text = match VendorLoginGrant::new(dir) {
            Ok(_) => panic!("the armed {step:?} fault must refuse the grant"),
            Err(error) => format!("{error:#}"),
        };
        // A fault that never fired would leave the cell armed; `new` failing
        // for another reason would then be read as this step's refusal.
        assert!(
            PRE_LEASE_FAULT.with(|armed| armed.get().is_none()),
            "the {step:?} fault was never reached"
        );
        text
    }

    fn io_with_path(path: &Path) -> anyhow::Error {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("denied: {}", path.display()),
        )
        .into()
    }

    fn platform_io_with_path(path: &Path) -> anyhow::Error {
        PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("denied: {}", path.display()),
        ))
        .into()
    }

    fn contention(path: &Path) -> anyhow::Error {
        PlatformError::LockContention {
            path: path.to_path_buf(),
        }
        .into()
    }

    fn timeout(path: &Path) -> anyhow::Error {
        PlatformError::LockTimeout {
            path: path.to_path_buf(),
            timeout_ms: 1,
        }
        .into()
    }

    fn assert_path_free_refusal(dir: &Path, text: &str, expected: &str) {
        assert!(
            text.starts_with("vendor_grant_lease_refused ("),
            "the pre-lease refusal is not in the fixed vocabulary: {text}"
        );
        assert!(
            text.contains(expected),
            "expected `{expected}` in the refusal: {text}"
        );
        assert!(
            !text.contains("vendor_login_quarantined"),
            "a pre-lease refusal must not claim a quarantine: {text}"
        );
        let dir_text = dir.display().to_string();
        assert!(
            !text.contains(&dir_text),
            "the base path reached the refusal: {text}"
        );
        assert!(
            !text.contains('/') && !text.contains('\\'),
            "a path reached the refusal: {text}"
        );
    }

    #[test]
    fn new_canonicalize_refusal_is_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::Canonicalize, io_with_path);
        assert_path_free_refusal(
            dir.path(),
            &text,
            "step=canonicalize kind=PermissionDenied errno=-1",
        );
    }

    #[test]
    fn new_sweep_canonicalize_refusal_is_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::SweepCanonicalize, io_with_path);
        assert_path_free_refusal(dir.path(), &text, "step=sweep_canonicalize kind=");
    }

    #[test]
    fn new_sweep_tighten_refusal_is_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(
            dir.path(),
            PreLeaseStep::SweepTighten,
            platform_io_with_path,
        );
        assert_path_free_refusal(
            dir.path(),
            &text,
            "step=sweep_tighten kind=PermissionDenied",
        );
    }

    #[test]
    fn new_sweep_read_dir_refusal_is_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::SweepReadDir, io_with_path);
        assert_path_free_refusal(dir.path(), &text, "step=sweep_read_dir kind=");
    }

    #[test]
    fn new_create_refusal_is_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::Create, io_with_path);
        assert_path_free_refusal(dir.path(), &text, "step=create kind=PermissionDenied");
    }

    /// Lock contention and lock timeout stay distinguishable from each other
    /// and from an ordinary failure, by `kind`, without the lock's path.
    #[test]
    fn new_owner_lock_contention_refusal_is_path_free_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::OwnerLock, contention);
        assert_path_free_refusal(
            dir.path(),
            &text,
            "step=owner_lock kind=lock_contention errno=-1",
        );
    }

    #[test]
    fn new_owner_lock_timeout_refusal_is_path_free_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let text = pre_lease_refusal(dir.path(), PreLeaseStep::OwnerLock, timeout);
        assert_path_free_refusal(
            dir.path(),
            &text,
            "step=owner_lock kind=lock_timeout errno=-1",
        );
    }

    #[test]
    fn terminal_quarantine_text_is_native_separated_throughout() {
        let id = "grant-8d23c0de-1111-4222-8333-444455556666";
        let renderer = format!("vendor_login_quarantined: <csq-base>/.login-grants/{id}");
        // Separator-explicit: on Linux CI this is the only way to see `\`.
        let win = rewrite_quarantine_locations(&format!("e: {renderer}; next"), |id| {
            format!("C:\\b\\.login-grants\\{id}")
        });
        assert_eq!(
            win,
            format!("e: vendor_login_quarantined: C:\\b\\.login-grants\\{id}; next")
        );
        assert!(!win.contains('/'), "a renderer-form '/' survived: {win}");
        // Native path: exact equality with Path::join on this platform.
        let base = Path::new("base-dir");
        assert_eq!(
            quarantine_text_for_terminal(&renderer, base),
            format!(
                "vendor_login_quarantined: {}",
                base.join(".login-grants").join(id).display()
            )
        );
        // A malformed id keeps the renderer form (fail-safe).
        for bad in ["../x", "grant-", "grant-zz", "other"] {
            let m = format!("vendor_login_quarantined: <csq-base>/.login-grants/{bad}");
            assert_eq!(quarantine_text_for_terminal(&m, base), m);
        }
    }

    /// an internal ticket R2-1: the quarantine location must never be absolute. A base
    /// that is a symlink to another tree (a dotfile manager, another
    /// volume) canonicalizes OUTSIDE `$HOME`, where no home redaction can
    /// catch it; rendering it relative to the accounts base makes the
    /// message safe for every caller, Claude and Codex alike.
    #[test]
    #[cfg(unix)]
    fn quarantine_message_is_relative_to_the_accounts_base() {
        let outside = tempfile::tempdir().unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let base = link_parent.path().join("accounts");
        std::os::unix::fs::symlink(outside.path(), &base).unwrap();
        let grant = VendorLoginGrant::new(&base).unwrap();
        let text = grant.quarantine_message();
        let id = grant
            .config_dir()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(id.starts_with("grant-"), "unexpected grant dir name: {id}");
        assert_eq!(
            text,
            format!("vendor_login_quarantined: <csq-base>/.login-grants/{id}"),
            "the quarantine location must be relative to the accounts base"
        );
        let canonical = std::fs::canonicalize(outside.path()).unwrap();
        for needle in [outside.path(), canonical.as_path(), link_parent.path()] {
            assert!(
                !text.contains(&needle.display().to_string()),
                "an absolute path reached the quarantine message: {text}"
            );
        }
    }

    /// A held owner lock (the real second hold returns `Ok(None)`) is a
    /// refusal in the same vocabulary, distinct from contention and timeout.
    #[test]
    fn new_owner_lock_held_refusal_is_path_free_and_named() {
        let dir = tempfile::tempdir().unwrap();
        OWNER_LOCK_HELD_FAULT.with(|armed| armed.set(true));
        let text = match VendorLoginGrant::new(dir.path()) {
            Ok(_) => panic!("a held owner lock must refuse the grant"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            OWNER_LOCK_HELD_FAULT.with(|armed| !armed.get()),
            "the held-lock fault was never reached"
        );
        assert_path_free_refusal(dir.path(), &text, "step=owner_lock kind=held errno=-1");
    }

    /// A refused tmp-file create (the write step) is also named. Skipped as
    /// root: with uid 0 the permission bits do not refuse the create, so the
    /// fixture would prove nothing rather than fail.
    #[test]
    #[cfg(unix)]
    fn lease_write_failure_names_the_step_and_still_refuses() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions and does not touch memory.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIP lease_write_failure_names_the_step_and_still_refuses: uid 0");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut grant = VendorLoginGrant::new(dir.path()).unwrap();
        let home = grant.config_dir().to_owned();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).unwrap();
        let error = grant.begin_launch();
        // Restore before asserting so the tempdir is always removable.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        grant.cleaned = true;
        let text = error
            .expect_err("a read-only grant home must refuse the lease write")
            .to_string();
        assert!(
            text.starts_with("vendor_login_quarantined: "),
            "the quarantine decision text changed: {text}"
        );
        assert!(
            text.contains("lease_step=write"),
            "step tag missing: {text}"
        );
        assert!(
            text.contains("kind=PermissionDenied"),
            "io class missing: {text}"
        );
    }

    #[test]
    fn sweep_removes_only_safe_orphan_and_keeps_spawning_or_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let created = orphan(dir.path(), LaunchState::Created);
        let completed = orphan(dir.path(), LaunchState::Complete);
        let spawning = orphan(dir.path(), LaunchState::Spawning);
        VendorLoginGrant::sweep_steps(dir.path(), |_| false).unwrap();
        assert!(created.exists() && completed.exists() && spawning.exists());
        VendorLoginGrant::sweep_steps(dir.path(), |_| true).unwrap();
        assert!(!created.exists());
        assert!(!completed.exists());
        assert!(spawning.exists());
    }

    #[cfg(unix)]
    #[test]
    fn live_kernel_lease_keeps_grant_even_when_probe_claims_gone() {
        let dir = tempfile::tempdir().unwrap();
        let mut grant = VendorLoginGrant::new(dir.path()).unwrap();
        let home = grant.config_dir().to_owned();
        VendorLoginGrant::sweep_steps(dir.path(), |_| true).unwrap();
        assert!(home.exists());
        grant.cleanup().unwrap();
    }

    #[test]
    fn launch_fence_keeps_grant_until_actual_completion_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut grant = VendorLoginGrant::new(dir.path()).unwrap();
        grant.begin_launch().unwrap();
        let home = grant.config_dir().to_owned();
        assert!(grant.cleanup().is_err());
        let lease: Lease =
            serde_json::from_slice(&std::fs::read(home.join("lease.json")).unwrap()).unwrap();
        assert!(lease.state == LaunchState::Spawning);
        grant.mark_completed().unwrap();
        grant.cleanup().unwrap();
        assert!(!home.exists());
    }

    #[test]
    fn codex_config_forces_file_and_copies_only_benign_keys_without_mutating_source() {
        for old_store in ["auto", "keyring", "file"] {
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("config-2");
            std::fs::create_dir(&config).unwrap();
            let source = format!(
                r#"model = "synthetic-model"
model_reasoning_effort = "high"
cli_auth_credentials_store = "{old_store}"
unknown = "synthetic-unknown"
[mcp_servers.private.env]
API_KEY = "synthetic-nested-secret"
[model_providers.private]
http_headers = {{ Authorization = "synthetic-auth-secret" }}
"#
            );
            std::fs::write(config.join("config.toml"), &source).unwrap(); // CI-ALLOW-fs-write-config-toml
            let mut grant = VendorLoginGrant::new(dir.path()).unwrap();
            grant
                .prepare_codex(dir.path(), crate::types::AccountNum::try_from(2).unwrap())
                .unwrap();
            let private = std::fs::read_to_string(grant.config_dir().join("config.toml")).unwrap();
            let parsed: toml::Value = toml::from_str(&private).unwrap();
            assert_eq!(parsed.as_table().unwrap().len(), 3);
            assert_eq!(
                parsed.get("model").and_then(toml::Value::as_str),
                Some("synthetic-model")
            );
            assert_eq!(
                parsed
                    .get("model_reasoning_effort")
                    .and_then(toml::Value::as_str),
                Some("high")
            );
            assert_eq!(
                parsed
                    .get("cli_auth_credentials_store")
                    .and_then(toml::Value::as_str),
                Some("file")
            );
            assert!(!private.contains("synthetic-nested-secret"));
            assert!(!private.contains("synthetic-auth-secret"));
            assert!(!private.contains("unknown"));
            assert_eq!(
                std::fs::read_to_string(config.join("config.toml")).unwrap(),
                source
            );
            grant.cleanup().unwrap();
        }
    }

    #[test]
    fn private_unique_grants_cleanup_without_changing_prior_slot() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("config-2");
        std::fs::create_dir(&canonical).unwrap();
        let prior = canonical.join(".credentials.json");
        std::fs::write(&prior, b"synthetic-prior").unwrap();
        let mut a = VendorLoginGrant::new(dir.path()).unwrap();
        let mut b = VendorLoginGrant::new(dir.path()).unwrap();
        assert_ne!(a.config_dir(), b.config_dir());
        assert_eq!(
            std::fs::canonicalize(a.config_dir()).unwrap(),
            a.config_dir()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(a.config_dir())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::write(a.config_dir().join(".credentials.json"), b"synthetic-new").unwrap();
        let home = a.config_dir().to_owned();
        a.cleanup().unwrap();
        assert!(!home.exists());
        assert_eq!(std::fs::read(prior).unwrap(), b"synthetic-prior");
        assert!(b.config_dir().exists());
        b.cleanup().unwrap();
    }

    /// The grant travels between the login worker and its readers, so the
    /// handle must be `Send` on every target — that is the whole point of the
    /// holder thread on Windows (Q6's guard is `!Send`).
    #[test]
    fn grant_and_owner_handle_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VendorLoginGrant>();
        assert_send::<lock::OwnerThreadLock>();
    }

    #[test]
    fn released_owner_lock_can_be_reacquired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.lock");
        let first = lock::hold_file_on_owner_thread(&path)
            .unwrap()
            .expect("uncontended owner lock");
        drop(first);
        let second = lock::hold_file_on_owner_thread(&path)
            .unwrap()
            .expect("lock available again after release");
        drop(second);
    }

    #[test]
    fn dropping_the_handle_without_an_explicit_release_still_releases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.lock");
        // No release call exists by design: Dropping the handle IS the release,
        // and that path must work on the holder thread.
        drop(lock::hold_file_on_owner_thread(&path).unwrap().unwrap());
        assert!(lock::hold_file_on_owner_thread(&path).unwrap().is_some());
    }

    #[test]
    fn second_owner_lock_while_one_is_held_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.lock");
        let held = lock::hold_file_on_owner_thread(&path)
            .unwrap()
            .expect("first owner lock");
        assert!(
            lock::hold_file_on_owner_thread(&path).unwrap().is_none(),
            "a second owner lock must refuse while one is held"
        );
        drop(held);
        assert!(
            lock::hold_file_on_owner_thread(&path).unwrap().is_some(),
            "the lock is acquirable again once released"
        );
    }
}
