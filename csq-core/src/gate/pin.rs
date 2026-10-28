//! Session-private hash integrity pin. Admission returns exact immutable bytes;
//! reopening the repository path for execution would discard this proof.
pub use super::policy::{PinError, VerificationFailure};
use super::registry::{self, Dependency, Event, FailurePolicy, HookRow, Registry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const MANIFEST_FILE: &str = ".claude/hook-registry.json";
pub const MAX_HOOK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityPolicy {
    Hash,
    RequireSignature,
}
impl IntegrityPolicy {
    /// Signature enforcement is not downgraded to a content hash while the
    /// approved signature verifier is unavailable on this pure-Rust seam.
    pub fn check_supported(self) -> Result<(), PinError> {
        match self {
            Self::Hash => Ok(()),
            Self::RequireSignature => Err(PinError::SignatureUnavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RowAdmissionError {
    #[error("hook source cannot be read safely")]
    Unreadable,
    #[error("hook source path is invalid")]
    InvalidPath,
    #[error("hook source hash differs")]
    HashMismatch,
    #[error("hook source exceeds admission limit")]
    Limit,
    #[error("hook source admission deadline expired")]
    Deadline,
}

#[derive(Debug)]
pub struct VerifiedBytes {
    source_path: PathBuf,
    bytes: Box<[u8]>,
    dependencies: BTreeMap<String, VerifiedDependency>,
}
#[derive(Debug)]
pub struct VerifiedDependency {
    source_path: PathBuf,
    bytes: Box<[u8]>,
}
impl VerifiedDependency {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }
}
impl VerifiedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Informational module-resolution filename, not an instruction to reopen it.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }
    /// Declared transitive closure keyed by repo-relative path. Consumers must
    /// resolve local modules from these retained bytes, never reopen source paths.
    pub fn dependencies(&self) -> &BTreeMap<String, VerifiedDependency> {
        &self.dependencies
    }
}
#[derive(Debug)]
pub struct VerifiedRow {
    pub row: HookRow,
    pub admission: Result<VerifiedBytes, RowAdmissionError>,
}
#[derive(Debug)]
pub struct VerifiedRegistry {
    pub registry: Registry,
    pub rows: Vec<VerifiedRow>,
    /// Every declared runtime entry and its closure, admitted before any row.
    pub runtimes: Vec<VerifiedBytes>,
}

/// Grade-i integrity only. Signed grade-ii attestation is a separate verifier;
/// a deployment requiring it must not treat this hash pin as signature proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    schema_version: u32,
    repo: PathBuf,
    repo_identity: Option<(u64, u64)>,
    manifest_sha256: String,
    content_sha256: String,
    source_sha: String,
    version: String,
    event_policies: BTreeMap<Event, FailurePolicy>,
}
impl Pin {
    /// Explicit operator activation binds a separately reviewed raw digest.
    /// All declared rows must be admitted, including continue-class rows; this
    /// command is not permission to silently omit an unreviewed missing hook.
    pub fn capture_operator_bound(
        repo: &Path,
        expected_manifest_sha256: &str,
        integrity: IntegrityPolicy,
    ) -> Result<Self, PinError> {
        integrity.check_supported()?;
        if !registry::valid_digest(expected_manifest_sha256) {
            return Err(PinError::TrustUnset);
        }
        let pin = Self::capture_operator(repo)?;
        if pin.manifest_sha256 != expected_manifest_sha256 {
            return Err(PinError::Mismatch);
        }
        if pin
            .verify(repo)?
            .rows
            .iter()
            .any(|row| row.admission.is_err())
        {
            return Err(PinError::Incomplete);
        }
        Ok(pin)
    }

    /// Expected raw manifest digest. Reading this field is not verification;
    /// diagnostic callers expose it only after `verify` accepts the subject.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Explicit operator-authorized pin creation; never call implicitly at launch.
    pub fn capture_operator(repo: &Path) -> Result<Self, PinError> {
        let repo = repo.canonicalize().map_err(|_| PinError::UnsafePath)?;
        let repo_identity = root_identity(&repo)?;
        let bytes = read_contained(&repo, MANIFEST_FILE, registry::MAX_MANIFEST_BYTES)
            .map_err(|_| PinError::Io)?;
        let registry = Registry::parse(&bytes)?;
        for runtime in &registry.runtimes {
            let expected = runtime
                .entry_sha256
                .as_deref()
                .ok_or(PinError::RuntimeAdmission(RowAdmissionError::HashMismatch))?;
            digest_closure(&repo, &runtime.entry, expected, &runtime.deps)
                .map_err(PinError::RuntimeAdmission)?;
        }
        // Stream every row at launch; only selected-event dispatch retains bytes.
        // A continue-class incomplete row remains pinned to the declared digest
        // and will be skipped by that same policy on subsequent dispatch.
        for row in &registry.hooks {
            let admission = digest_closure(&repo, &row.file, &row.file_sha256, &row.deps);
            if admission.is_err() && row.on_incomplete == FailurePolicy::Deny {
                return Err(PinError::Incomplete);
            }
        }
        if root_identity(&repo)? != repo_identity {
            return Err(PinError::Mismatch);
        }
        Ok(Self {
            schema_version: 2,
            repo,
            repo_identity,
            manifest_sha256: registry::sha256(&bytes),
            event_policies: super::policy::event_policies(&registry),
            content_sha256: registry.content_sha256,
            source_sha: registry.source_sha,
            version: registry.version,
        })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, PinError> {
        serde_json::to_vec(self).map_err(|_| PinError::InvalidPin)
    }
    /// Parent exists and belongs to the caller; this module does not select a session.
    /// Pin is outside the repository, private at creation, fsynced and atomically replaced.
    /// Unix only until a verified private DACL writer/reader is available.
    pub fn write_private(&self, path: &Path) -> Result<(), PinError> {
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(PinError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            self.write_private_with_tmp(path, crate::platform::fs::unique_tmp_path)
        }
    }
    #[cfg(unix)]
    fn write_private_with_tmp(
        &self,
        path: &Path,
        make_tmp: impl FnOnce(&Path) -> PathBuf,
    ) -> Result<(), PinError> {
        let (parent, name) = private_parent(path)?;
        if parent.starts_with(&self.repo) {
            return Err(PinError::UnsafePath);
        }
        let path = parent.join(name);
        let tmp = make_tmp(&path);
        let bytes = self.to_bytes()?;
        // A create_new collision grants no cleanup authority. This helper
        // already removes its own incomplete file on write/fsync failure.
        crate::platform::fs::write_new_private_synced(&tmp, &bytes).map_err(|_| PinError::Io)?;
        let result = crate::platform::fs::atomic_replace(&tmp, &path).map_err(|_| PinError::Io);
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
    pub fn read_private(path: &Path) -> Result<Self, PinError> {
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(PinError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let (parent, name) = private_parent(path)?;
            let mut file = open_contained(&parent, &name).map_err(|_| PinError::Io)?;
            validate_private_file(&file)?;
            let bytes =
                read_bounded(&mut file, registry::MAX_MANIFEST_BYTES).map_err(|_| PinError::Io)?;
            let pin: Self = serde_json::from_value(registry::strict_json(&bytes)?)
                .map_err(|_| PinError::InvalidPin)?;
            if pin.schema_version != 2
                || !pin.repo.is_absolute()
                || parent.starts_with(&pin.repo)
                || !registry::valid_digest(&pin.manifest_sha256)
                || !registry::valid_digest(&pin.content_sha256)
                || Event::ALL
                    .iter()
                    .any(|event| !pin.event_policies.contains_key(event))
            {
                return Err(PinError::InvalidPin);
            }
            Ok(pin)
        }
    }
    pub fn load_verify(path: &Path, repo: &Path) -> Result<VerifiedRegistry, PinError> {
        Self::read_private(path)?.verify(repo)
    }
    pub fn load_verify_until(
        path: &Path,
        repo: &Path,
        event: Event,
        deadline: Instant,
    ) -> Result<VerifiedRegistry, VerificationFailure> {
        if Instant::now() >= deadline {
            return Err(VerificationFailure {
                error: PinError::Deadline,
                policy: FailurePolicy::Deny,
            });
        }
        let pin = Self::read_private(path).map_err(|error| VerificationFailure {
            error,
            policy: FailurePolicy::Deny,
        })?;
        // A private pin authenticates its own subject, not an arbitrary caller's
        // repository. Its continue policy is usable only after binding that subject.
        pin.authenticate_repo(repo)
            .map_err(|error| VerificationFailure {
                error,
                policy: FailurePolicy::Deny,
            })?;
        pin.verify_until(repo, event, deadline).map_err(|error| {
            super::policy::verification_failure(&pin, repo, event, error, deadline)
        })
    }
    pub fn fallback_policy(&self, event: Event) -> FailurePolicy {
        self.event_policies
            .get(&event)
            .copied()
            .unwrap_or(FailurePolicy::Deny)
    }
    pub fn verify_until(
        &self,
        repo: &Path,
        event: Event,
        deadline: Instant,
    ) -> Result<VerifiedRegistry, PinError> {
        self.verify_selected(repo, Some(event), Some(deadline))
    }
    pub fn verify(&self, repo: &Path) -> Result<VerifiedRegistry, PinError> {
        self.verify_selected(repo, None, None)
    }
    pub(super) fn authenticate_repo(&self, repo: &Path) -> Result<PathBuf, PinError> {
        let repo = repo.canonicalize().map_err(|_| PinError::UnsafePath)?;
        if repo != self.repo || root_identity(&repo)? != self.repo_identity {
            return Err(PinError::Mismatch);
        }
        Ok(repo)
    }
    /// A stored continue value is usable only while its current subject,
    /// manifest bytes, metadata and derived policy still validate together.
    pub(super) fn validated_fallback_policy(
        &self,
        repo: &Path,
        event: Event,
        deadline: Instant,
    ) -> Result<FailurePolicy, PinError> {
        if Instant::now() >= deadline {
            return Err(PinError::Deadline);
        }
        let repo = self.authenticate_repo(repo)?;
        if Instant::now() >= deadline {
            return Err(PinError::Deadline);
        }
        let registry = self.validated_registry(&repo)?;
        if Instant::now() >= deadline {
            return Err(PinError::Deadline);
        }
        let policy = super::policy::event_policies(&registry)[&event];
        if policy == FailurePolicy::Continue {
            let mut remaining = MAX_SNAPSHOT_BYTES;
            admit_runtimes(&repo, &registry, &mut remaining, Some(deadline))?;
        }
        if Instant::now() >= deadline {
            return Err(PinError::Deadline);
        }
        self.authenticate_repo(&repo)?;
        if Instant::now() >= deadline {
            return Err(PinError::Deadline);
        }
        Ok(policy)
    }
    fn validated_registry(&self, repo: &Path) -> Result<Registry, PinError> {
        let bytes = read_contained(repo, MANIFEST_FILE, registry::MAX_MANIFEST_BYTES)
            .map_err(|_| PinError::Io)?;
        if registry::sha256(&bytes) != self.manifest_sha256 {
            return Err(PinError::Mismatch);
        }
        let registry = Registry::parse(&bytes)?;
        if self.event_policies != super::policy::event_policies(&registry) {
            return Err(PinError::InvalidPin);
        }
        if registry.content_sha256 != self.content_sha256
            || registry.version != self.version
            || registry.source_sha != self.source_sha
        {
            return Err(PinError::Mismatch);
        }
        Ok(registry)
    }
    fn verify_selected(
        &self,
        repo: &Path,
        event: Option<Event>,
        deadline: Option<Instant>,
    ) -> Result<VerifiedRegistry, PinError> {
        let repo = self.authenticate_repo(repo)?;
        let registry = self.validated_registry(&repo)?;
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(PinError::Deadline);
        }
        let mut remaining = MAX_SNAPSHOT_BYTES;
        let runtimes = admit_runtimes(&repo, &registry, &mut remaining, deadline)?;
        let rows = registry
            .hooks
            .iter()
            .filter(|row| event.is_none_or(|event| row.event == event))
            .map(|row| {
                let admission = admit_closure(
                    &repo,
                    &row.file,
                    &row.file_sha256,
                    &row.deps,
                    &mut remaining,
                    deadline,
                );
                VerifiedRow {
                    row: row.clone(),
                    admission,
                }
            })
            .collect();
        if root_identity(&repo)? != self.repo_identity {
            return Err(PinError::Mismatch);
        }
        Ok(VerifiedRegistry {
            registry,
            rows,
            runtimes,
        })
    }
}

fn admit_runtimes(
    root: &Path,
    registry: &Registry,
    remaining: &mut usize,
    deadline: Option<Instant>,
) -> Result<Vec<VerifiedBytes>, PinError> {
    registry
        .runtimes
        .iter()
        .map(|runtime| {
            let expected = runtime
                .entry_sha256
                .as_deref()
                .ok_or(PinError::RuntimeAdmission(RowAdmissionError::HashMismatch))?;
            admit_closure(
                root,
                &runtime.entry,
                expected,
                &runtime.deps,
                remaining,
                deadline,
            )
            .map_err(PinError::RuntimeAdmission)
        })
        .collect()
}

fn validate_closure(entry: &str, deps: &[Dependency]) -> Result<(), RowAdmissionError> {
    if !registry::valid_relative_file(entry) {
        return Err(RowAdmissionError::InvalidPath);
    }
    let mut paths = std::collections::BTreeSet::new();
    for dep in deps {
        if !registry::valid_relative_file(&dep.path) || dep.path == entry {
            return Err(RowAdmissionError::InvalidPath);
        }
        if !paths.insert(&dep.path) || !registry::valid_digest(&dep.sha256) {
            return Err(RowAdmissionError::HashMismatch);
        }
    }
    Ok(())
}

fn digest_closure(
    root: &Path,
    entry: &str,
    expected: &str,
    deps: &[Dependency],
) -> Result<(), RowAdmissionError> {
    validate_closure(entry, deps)?;
    for (path, digest) in std::iter::once((entry, expected)).chain(
        deps.iter()
            .map(|dep| (dep.path.as_str(), dep.sha256.as_str())),
    ) {
        if digest_contained(root, path)? != digest {
            return Err(RowAdmissionError::HashMismatch);
        }
    }
    Ok(())
}

fn admit_closure(
    root: &Path,
    entry: &str,
    expected: &str,
    deps: &[Dependency],
    remaining: &mut usize,
    deadline: Option<Instant>,
) -> Result<VerifiedBytes, RowAdmissionError> {
    validate_closure(entry, deps)?;
    let mut read = |path: &str, digest: &str| -> Result<Box<[u8]>, RowAdmissionError> {
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(RowAdmissionError::Deadline);
        }
        let bytes = read_contained(root, path, (*remaining).min(MAX_HOOK_BYTES))?;
        *remaining -= bytes.len();
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(RowAdmissionError::Deadline);
        }
        if registry::sha256(&bytes) != digest {
            return Err(RowAdmissionError::HashMismatch);
        }
        Ok(bytes.into_boxed_slice())
    };
    let bytes = read(entry, expected)?;
    let dependencies = deps
        .iter()
        .map(|dep| {
            Ok((
                dep.path.clone(),
                VerifiedDependency {
                    source_path: root.join(&dep.path),
                    bytes: read(&dep.path, &dep.sha256)?,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, RowAdmissionError>>()?;
    Ok(VerifiedBytes {
        source_path: root.join(entry),
        bytes,
        dependencies,
    })
}

fn root_identity(root: &Path) -> Result<Option<(u64, u64)>, PinError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| PinError::UnsafePath)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PinError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some((metadata.dev(), metadata.ino())))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}
#[cfg(unix)]
fn private_parent(path: &Path) -> Result<(PathBuf, String), PinError> {
    let parent = path.parent().ok_or(PinError::UnsafePath)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PinError::UnsafePath)?;
    if !registry::valid_relative_file(name) || name.contains('/') {
        return Err(PinError::UnsafePath);
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| PinError::UnsafePath)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PinError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(PinError::UnsafePath);
        }
    }
    Ok((
        parent.canonicalize().map_err(|_| PinError::UnsafePath)?,
        name.to_owned(),
    ))
}
#[cfg(unix)]
fn validate_private_file(file: &File) -> Result<(), PinError> {
    let metadata = file.metadata().map_err(|_| PinError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PinError::InvalidPin);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(PinError::UnsafePath);
        }
    }
    Ok(())
}
pub(super) fn read_bounded(file: &mut File, limit: usize) -> Result<Vec<u8>, RowAdmissionError> {
    if !file
        .metadata()
        .map_err(|_| RowAdmissionError::Unreadable)?
        .is_file()
    {
        return Err(RowAdmissionError::InvalidPath);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RowAdmissionError::Unreadable)?;
    if bytes.len() > limit {
        return Err(RowAdmissionError::Limit);
    }
    Ok(bytes)
}
fn read_contained(root: &Path, relative: &str, limit: usize) -> Result<Vec<u8>, RowAdmissionError> {
    if !registry::valid_relative_file(relative) {
        return Err(RowAdmissionError::InvalidPath);
    }
    let mut file = open_contained(root, relative).map_err(|_| RowAdmissionError::Unreadable)?;
    read_bounded(&mut file, limit)
}
fn digest_contained(root: &Path, relative: &str) -> Result<String, RowAdmissionError> {
    let mut file = open_contained(root, relative).map_err(|_| RowAdmissionError::Unreadable)?;
    if !file
        .metadata()
        .map_err(|_| RowAdmissionError::Unreadable)?
        .is_file()
    {
        return Err(RowAdmissionError::InvalidPath);
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut read = 0usize;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| RowAdmissionError::Unreadable)?;
        if n == 0 {
            return Ok(hex::encode(hash.finalize()));
        }
        read += n;
        if read > MAX_HOOK_BYTES {
            return Err(RowAdmissionError::Limit);
        }
        hash.update(&buf[..n]);
    }
}

#[cfg(unix)]
pub(super) fn open_contained(root: &Path, relative: &str) -> io::Result<File> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    };
    let mut dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let parts: Vec<_> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let name =
            std::ffi::CString::new(part.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if last {
                libc::O_NONBLOCK
            } else {
                libc::O_DIRECTORY
            };
        // SAFETY: live directory FD and NUL-terminated component; each suffix hop
        // is opened relative to its owned predecessor without following symlinks.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: new descriptor is transferred exactly once to this File.
        let file = unsafe { File::from_raw_fd(fd) };
        if last {
            return Ok(file);
        }
        dir = file;
    }
    Err(io::ErrorKind::InvalidInput.into())
}
#[cfg(windows)]
pub(super) fn open_contained(root: &Path, relative: &str) -> io::Result<File> {
    use std::os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    if !registry::valid_relative_file(relative)
        || !root.is_absolute()
        || root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Check the supplied root and its ancestors before resolving it: canonicalize
    // alone would erase a junction/symlink that must remain a refusal. Resolve
    // once so ordinary and verbatim Windows paths share the same comparison form.
    for ancestor in root.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_attributes() & 0x400 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let root = root.canonicalize()?;
    if !fs::metadata(&root)?.is_dir() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut probe = root.clone();
    for part in relative.split('/') {
        probe.push(part);
        if fs::symlink_metadata(&probe)?.file_attributes() & 0x400 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let canonical = probe.canonicalize()?;
    if !canonical.starts_with(&root) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(probe)?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut buf = vec![0u16; 32768];
    // SAFETY: live file handle and correctly sized writable UTF-16 buffer.
    let n = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
            file.as_raw_handle() as _,
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
        )
    };
    if n == 0 || n as usize >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    let opened = PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize]));
    if opened != canonical || !opened.starts_with(&root) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(file)
}
#[cfg(not(any(unix, windows)))]
pub(super) fn open_contained(_root: &Path, _relative: &str) -> io::Result<File> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::super::registry::tests::{fixture as registry_fixture, sealed};
    use super::*;
    use serde_json::json;
    const RUNTIME_BYTES: &[u8] = b"trusted runtime fixture";
    fn fixture(bytes: &[u8]) -> serde_json::Value {
        let mut value = registry_fixture(bytes);
        value["runtimes"] = json!([{"entry":".claude/hooks/runtime.js",
            "entry_sha256": registry::sha256(RUNTIME_BYTES), "deps":[]}]);
        value
    }
    fn setup(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let handle = temp.path().join("handle");
        fs::create_dir_all(repo.join(".claude/hooks")).unwrap();
        fs::create_dir(&handle).unwrap();
        fs::write(repo.join(".claude/hooks/guard.js"), bytes).unwrap();
        fs::write(repo.join(".claude/hooks/runtime.js"), RUNTIME_BYTES).unwrap();
        fs::write(repo.join(MANIFEST_FILE), sealed(fixture(bytes))).unwrap();
        (temp, repo, handle.join(".csq-hook-registry-pin.json"))
    }

    #[cfg(windows)]
    #[test]
    fn contained_read_accepts_plain_and_verbatim_roots() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/settings.json"), b"{\"ratio\":1.5}").unwrap();
        for supplied in [&root, &root.canonicalize().unwrap()] {
            let mut file = open_contained(supplied, "nested/settings.json").unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"{\"ratio\":1.5}");
        }
        for invalid in [
            "../outside.json",
            "nested/../settings.json",
            "nested\\settings.json",
        ] {
            assert!(open_contained(&root, invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn contained_read_refuses_junction_root_ancestor_and_suffix() {
        let _env = crate::platform::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/settings.json"), b"{}").unwrap();
        let junction = |alias: &Path, target: &Path| {
            let mut command = std::process::Command::new("cmd.exe");
            command
                .env_clear()
                .env("HOME", temp.path())
                .env("USERPROFILE", temp.path());
            for key in [
                "PATH",
                "SYSTEMROOT",
                "SystemRoot",
                "WINDIR",
                "ComSpec",
                "TEMP",
                "TMP",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            let output = command
                .args(["/d", "/c", "mklink", "/J"])
                .arg(alias)
                .arg(target)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "junction fixture: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let root_alias = temp.path().join("root-alias");
        junction(&root_alias, &root);
        let suffix_alias = root.join("suffix-alias");
        junction(&suffix_alias, &root.join("nested"));
        for (supplied, relative) in [
            (&root_alias, "nested/settings.json"),
            (&root_alias.join("nested"), "settings.json"),
            (&root, "suffix-alias/settings.json"),
        ] {
            assert_eq!(
                open_contained(supplied, relative).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn reviewed_operator_pin_binds_private_state_to_exact_manifest() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, repo, path) = setup(b"hook");
        let expected = registry::sha256(&fs::read(repo.join(MANIFEST_FILE)).unwrap());
        let pin = Pin::capture_operator_bound(&repo, &expected, IntegrityPolicy::Hash).unwrap();
        pin.write_private(&path).unwrap();
        let verified = Pin::load_verify(&path, &repo).unwrap();
        assert_eq!(verified.rows.len(), 1);
        assert!(verified.rows[0].admission.is_ok());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            Pin::read_private(&path).unwrap().manifest_sha256(),
            expected
        );
        fs::write(repo.join(MANIFEST_FILE), sealed(fixture(b"replacement"))).unwrap();
        assert!(matches!(
            Pin::load_verify(&path, &repo),
            Err(PinError::Mismatch)
        ));
    }

    #[test]
    fn operator_activation_without_reviewed_anchor_or_with_wrong_digest_refuses() {
        let (_temp, repo, _path) = setup(b"hook");
        for unset in ["", "not-a-digest", &"a".repeat(63)] {
            assert!(matches!(
                Pin::capture_operator_bound(&repo, unset, IntegrityPolicy::Hash),
                Err(PinError::TrustUnset)
            ));
        }
        assert!(matches!(
            Pin::capture_operator_bound(&repo, &"a".repeat(64), IntegrityPolicy::Hash),
            Err(PinError::Mismatch)
        ));
    }

    #[test]
    fn reviewed_operator_activation_refuses_missing_continue_row() {
        let (_temp, repo, _path) = setup(b"hook");
        let mut value = fixture(b"hook");
        value["hooks"][0]["on_incomplete"] = json!("continue");
        value["hooks"][0]["contract"]["protocol"]["severity"] = json!("advise");
        let bytes = sealed(value);
        fs::write(repo.join(MANIFEST_FILE), &bytes).unwrap();
        fs::remove_file(repo.join(".claude/hooks/guard.js")).unwrap();
        // The low-level capture preserves ordinary continue-class dispatch
        // semantics; explicit operator activation demands complete admission.
        assert!(Pin::capture_operator(&repo).is_ok());
        assert!(matches!(
            Pin::capture_operator_bound(&repo, &registry::sha256(&bytes), IntegrityPolicy::Hash),
            Err(PinError::Incomplete)
        ));
    }

    #[test]
    fn signed_operator_activation_never_downgrades_to_reviewed_hash() {
        let (_temp, repo, _path) = setup(b"hook");
        let expected = registry::sha256(&fs::read(repo.join(MANIFEST_FILE)).unwrap());
        assert!(matches!(
            Pin::capture_operator_bound(&repo, &expected, IntegrityPolicy::RequireSignature),
            Err(PinError::SignatureUnavailable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_pin_temp_collision_preserves_foreign_regular_file() {
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        let foreign = path.with_file_name("foreign.tmp");
        fs::write(&foreign, b"foreign bytes remain owned by their creator").unwrap();
        assert!(pin
            .write_private_with_tmp(&path, |_| foreign.clone())
            .is_err());
        assert!(!path.exists());
        assert_eq!(
            fs::read(&foreign).unwrap(),
            b"foreign bytes remain owned by their creator"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_pin_temp_collision_preserves_foreign_symlink() {
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        let target = path.with_file_name("foreign-target");
        fs::write(&target, b"foreign target unchanged").unwrap();
        let foreign = path.with_file_name("foreign-link.tmp");
        std::os::unix::fs::symlink(&target, &foreign).unwrap();
        assert!(pin
            .write_private_with_tmp(&path, |_| foreign.clone())
            .is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_link(&foreign).unwrap(), target);
        assert_eq!(fs::read(&target).unwrap(), b"foreign target unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn syntactically_valid_policy_tamper_refuses_verification_and_continue_fallback() {
        let (_temp, repo, path) = setup(b"hook");
        Pin::capture_operator(&repo)
            .unwrap()
            .write_private(&path)
            .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["event_policies"]["PreToolUse"] = "continue".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let pin = Pin::read_private(&path).unwrap();
        assert_eq!(
            pin.fallback_policy(Event::PreToolUse),
            FailurePolicy::Continue
        );
        assert!(matches!(pin.verify(&repo), Err(PinError::InvalidPin)));
        assert!(matches!(
            Pin::load_verify_until(
                &path,
                &repo,
                Event::PreToolUse,
                Instant::now() + std::time::Duration::from_secs(5)
            ),
            Err(VerificationFailure {
                error: PinError::InvalidPin,
                policy: FailurePolicy::Deny
            })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn policy_tamper_composed_with_metadata_or_manifest_failure_cannot_continue() {
        for fault in ["version", "changed-manifest", "missing-manifest"] {
            let (_temp, repo, path) = setup(b"hook");
            Pin::capture_operator(&repo)
                .unwrap()
                .write_private(&path)
                .unwrap();
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["event_policies"]["PreToolUse"] = "continue".into();
            if fault == "version" {
                value["version"] = "1.9.0".into();
            }
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            if fault == "changed-manifest" {
                fs::write(repo.join(MANIFEST_FILE), b"changed").unwrap();
            } else if fault == "missing-manifest" {
                fs::remove_file(repo.join(MANIFEST_FILE)).unwrap();
            }
            let failure = Pin::load_verify_until(
                &path,
                &repo,
                Event::PreToolUse,
                Instant::now() + std::time::Duration::from_secs(5),
            )
            .unwrap_err();
            assert_eq!(failure.policy, FailurePolicy::Deny, "{fault}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn closures_retain_exact_bytes_and_refuse_row_dependency_tamper() {
        let (_temp, repo, path) = setup(b"hook");
        fs::create_dir(repo.join(".claude/hooks/lib")).unwrap();
        let dep_path = ".claude/hooks/lib/shared.js";
        fs::write(repo.join(dep_path), b"dependency").unwrap();
        let mut value = fixture(b"hook");
        let deps = json!([{"path":dep_path,"sha256":registry::sha256(b"dependency")}]);
        value["hooks"][0]["deps"] = deps.clone();
        value["runtimes"][0]["deps"] = deps;
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        let pin = Pin::capture_operator(&repo).unwrap();
        pin.write_private(&path).unwrap();
        let admitted = pin.verify(&repo).unwrap();
        fs::write(repo.join(dep_path), b"replacement").unwrap();
        assert_eq!(
            admitted.rows[0].admission.as_ref().unwrap().dependencies()[dep_path].as_bytes(),
            b"dependency"
        );
        assert_eq!(
            admitted.runtimes[0].dependencies()[dep_path].as_bytes(),
            b"dependency"
        );
        let failure = Pin::load_verify_until(
            &path,
            &repo,
            Event::Stop,
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(matches!(
            failure.error,
            PinError::RuntimeAdmission(RowAdmissionError::HashMismatch)
        ));
        assert_eq!(failure.policy, FailurePolicy::Deny);
        let mut value = fixture(b"hook");
        value["hooks"][0]["deps"] =
            json!([{"path":dep_path,"sha256":registry::sha256(b"replacement")}]);
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        let pin = Pin::capture_operator(&repo).unwrap();
        fs::remove_file(repo.join(dep_path)).unwrap();
        assert_eq!(
            pin.verify(&repo).unwrap().rows[0]
                .admission
                .as_ref()
                .unwrap_err(),
            &RowAdmissionError::Unreadable
        );
    }

    #[test]
    fn runtime_entry_requires_hash_and_all_events_verify_runtime_bytes() {
        let (_temp, repo, _path) = setup(b"hook");
        let mut value = fixture(b"hook");
        value["runtimes"][0]
            .as_object_mut()
            .unwrap()
            .remove("entry_sha256");
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        assert!(matches!(
            Pin::capture_operator(&repo),
            Err(PinError::RuntimeAdmission(RowAdmissionError::HashMismatch))
        ));
        fs::write(repo.join(MANIFEST_FILE), sealed(fixture(b"hook"))).unwrap();
        let pin = Pin::capture_operator(&repo).unwrap();
        fs::write(repo.join(".claude/hooks/runtime.js"), b"changed").unwrap();
        for event in Event::ALL {
            assert!(matches!(
                pin.verify_until(
                    &repo,
                    event,
                    Instant::now() + std::time::Duration::from_secs(5)
                ),
                Err(PinError::RuntimeAdmission(RowAdmissionError::HashMismatch))
            ));
        }
    }

    #[test]
    fn dependency_traversal_duplicates_and_symlinks_refuse_admission() {
        let (_temp, repo, _path) = setup(b"hook");
        for paths in [
            vec!["../outside.js"],
            vec!["/outside.js"],
            vec![".claude/hooks/guard.js"],
            vec![".claude/hooks/runtime.js", ".claude/hooks/runtime.js"],
        ] {
            let mut value = fixture(b"hook");
            value["hooks"][0]["deps"] = json!(paths
                .into_iter()
                .map(|path| json!({"path":path,"sha256":registry::sha256(RUNTIME_BYTES)}))
                .collect::<Vec<_>>());
            fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
            assert!(Pin::capture_operator(&repo).is_err());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("runtime.js", repo.join(".claude/hooks/dependency.js"))
                .unwrap();
            let mut value = fixture(b"hook");
            value["hooks"][0]["deps"] = json!([{"path":".claude/hooks/dependency.js",
                "sha256":registry::sha256(RUNTIME_BYTES)}]);
            fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
            assert!(matches!(
                Pin::capture_operator(&repo),
                Err(PinError::Incomplete)
            ));
        }
    }

    #[test]
    fn runtime_closure_shares_the_aggregate_snapshot_bound() {
        let (_temp, repo, _path) = setup(b"hook");
        let bytes = vec![b'x'; MAX_HOOK_BYTES];
        let mut value = fixture(b"hook");
        value["runtimes"] = json!((0..=MAX_SNAPSHOT_BYTES / MAX_HOOK_BYTES)
            .map(|index| {
                let entry = format!(".claude/hooks/runtime-{index}.js");
                fs::write(repo.join(&entry), &bytes).unwrap();
                json!({"entry":entry,"entry_sha256":registry::sha256(&bytes),"deps":[]})
            })
            .collect::<Vec<_>>());
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        assert!(matches!(
            Pin::capture_operator(&repo).unwrap().verify(&repo),
            Err(PinError::RuntimeAdmission(RowAdmissionError::Limit))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn expired_deadline_cannot_continue_before_runtime_admission() {
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        pin.write_private(&path).unwrap();
        assert_eq!(pin.fallback_policy(Event::Stop), FailurePolicy::Continue);
        fs::write(repo.join(".claude/hooks/runtime.js"), b"changed runtime").unwrap();
        assert!(matches!(
            Pin::load_verify_until(&path, &repo, Event::Stop, Instant::now()),
            Err(VerificationFailure {
                error: PinError::Deadline,
                policy: FailurePolicy::Deny
            })
        ));
        let error = pin
            .verify_until(&repo, Event::Stop, Instant::now())
            .unwrap_err();
        assert!(matches!(error, PinError::Deadline));
        let failure = super::super::policy::verification_failure(
            &pin,
            &repo,
            Event::Stop,
            error,
            Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(failure.policy, FailurePolicy::Deny);
    }

    #[cfg(unix)]
    #[test]
    fn generic_failure_cannot_continue_after_the_shared_deadline() {
        let (_temp, repo, _path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        assert_eq!(pin.fallback_policy(Event::Stop), FailurePolicy::Continue);
        let failure = super::super::policy::verification_failure(
            &pin,
            &repo,
            Event::Stop,
            PinError::Io,
            Instant::now(),
        );
        assert_eq!(failure.policy, FailurePolicy::Deny);
        assert!(matches!(failure.error, PinError::Io));
        let failure = super::super::policy::verification_failure(
            &pin,
            &repo,
            Event::Stop,
            PinError::Io,
            Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(failure.policy, FailurePolicy::Continue);
    }

    #[cfg(unix)]
    #[test]
    fn production_pin_roundtrip_keeps_immutable_admitted_bytes() {
        let (_temp, repo, path) = setup(b"original hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        pin.write_private(&path).unwrap();
        let admitted = Pin::load_verify_until(
            &path,
            &repo,
            Event::PreToolUse,
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(admitted.rows.len(), 1);
        let source = admitted.rows[0].admission.as_ref().unwrap();
        fs::write(repo.join(".claude/hooks/guard.js"), b"replacement hook").unwrap();
        assert_eq!(source.as_bytes(), b"original hook");
        assert!(matches!(
            pin.verify(&repo).unwrap().rows[0].admission,
            Err(RowAdmissionError::HashMismatch)
        ));
    }
    #[test]
    fn continue_row_failure_remains_a_row_result_and_deny_pin_refuses() {
        let (_temp, repo, _path) = setup(b"hook");
        fs::remove_file(repo.join(".claude/hooks/guard.js")).unwrap();
        assert!(matches!(
            Pin::capture_operator(&repo),
            Err(PinError::Incomplete)
        ));
        let mut value = fixture(b"hook");
        value["hooks"][0]["on_incomplete"] = json!("continue");
        value["hooks"][0]["contract"]["protocol"]["severity"] = json!("advise");
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        let pin = Pin::capture_operator(&repo).unwrap();
        let verified = pin.verify(&repo).unwrap();
        assert_eq!(verified.rows[0].row.on_incomplete, FailurePolicy::Continue);
        assert_eq!(
            verified.rows[0].admission.as_ref().unwrap_err(),
            &RowAdmissionError::Unreadable
        );
    }
    #[cfg(unix)]
    #[test]
    fn changed_manifest_wrong_repo_and_expired_deadline_refuse() {
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        pin.write_private(&path).unwrap();
        assert!(matches!(
            Pin::load_verify_until(&path, &repo, Event::PreToolUse, Instant::now()),
            Err(VerificationFailure {
                error: PinError::Deadline,
                policy: FailurePolicy::Deny
            })
        ));
        assert!(pin.verify(path.parent().unwrap()).is_err());
        let mut bytes = fs::read(repo.join(MANIFEST_FILE)).unwrap();
        bytes.push(b'\n');
        fs::write(repo.join(MANIFEST_FILE), bytes).unwrap();
        assert!(matches!(pin.verify(&repo), Err(PinError::Mismatch)));
        assert!(matches!(
            pin.write_private(&repo.join("pin.json")),
            Err(PinError::UnsafePath)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn selected_event_does_not_reopen_unrelated_hook_files() {
        let (_temp, repo, path) = setup(b"hook");
        let mut value = fixture(b"hook");
        let mut other = value["hooks"][0].clone();
        other["id"] = "other-event".into();
        other["event"] = "PostToolUse".into();
        other["contract"]["protocol"]["kind"] = "context-injection".into();
        other["on_incomplete"] = "continue".into();
        other["file"] = ".claude/hooks/other.js".into();
        value["hooks"].as_array_mut().unwrap().push(other);
        fs::write(repo.join(".claude/hooks/other.js"), b"hook").unwrap();
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        Pin::capture_operator(&repo)
            .unwrap()
            .write_private(&path)
            .unwrap();
        fs::remove_file(repo.join(".claude/hooks/other.js")).unwrap();
        let admitted = Pin::load_verify_until(
            &path,
            &repo,
            Event::PreToolUse,
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(admitted.rows.len(), 1);
        assert!(admitted.rows[0].admission.is_ok());
    }
    #[test]
    fn aggregate_snapshot_budget_marks_later_rows_incomplete() {
        let bytes = vec![b'x'; MAX_HOOK_BYTES];
        let (_temp, repo, _path) = setup(&bytes);
        let mut value = fixture(&bytes);
        let first = value["hooks"][0].clone();
        for index in 1..=MAX_SNAPSHOT_BYTES / MAX_HOOK_BYTES {
            let mut row = first.clone();
            row["file"] = format!(".claude/hooks/row-{index}.js").into();
            row["order"] = (index + 10).into();
            fs::write(repo.join(row["file"].as_str().unwrap()), &bytes).unwrap();
            value["hooks"].as_array_mut().unwrap().push(row);
        }
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        let admitted = Pin::capture_operator(&repo).unwrap().verify(&repo).unwrap();
        let retained: usize = admitted
            .rows
            .iter()
            .filter_map(|r| r.admission.as_ref().ok())
            .map(|bytes| bytes.as_bytes().len())
            .sum();
        assert_eq!(retained, MAX_SNAPSHOT_BYTES - MAX_HOOK_BYTES);
        assert!(retained + admitted.runtimes[0].as_bytes().len() <= MAX_SNAPSHOT_BYTES);
        assert_eq!(
            admitted
                .rows
                .last()
                .unwrap()
                .admission
                .as_ref()
                .unwrap_err(),
            &RowAdmissionError::Limit
        );
        assert_eq!(
            admitted.rows.last().unwrap().row.on_incomplete,
            FailurePolicy::Deny
        );
    }
    #[test]
    fn required_signature_cannot_downgrade_to_hash_grade() {
        assert!(IntegrityPolicy::Hash.check_supported().is_ok());
        assert!(matches!(
            IntegrityPolicy::RequireSignature.check_supported(),
            Err(PinError::SignatureUnavailable)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn unverifiable_manifest_or_missing_pin_denies_and_validated_policy_can_continue() {
        let (_temp, repo, path) = setup(b"hook");
        let mut value = fixture(b"hook");
        value["hooks"][0]["event"] = "PostToolUse".into();
        value["hooks"][0]["contract"]["protocol"]["kind"] = "context-injection".into();
        value["hooks"][0]["on_incomplete"] = "deny".into();
        fs::write(repo.join(MANIFEST_FILE), sealed(value)).unwrap();
        Pin::capture_operator(&repo)
            .unwrap()
            .write_private(&path)
            .unwrap();
        fs::write(repo.join(MANIFEST_FILE), b"malformed manifest").unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let denial =
            Pin::load_verify_until(&path, &repo, Event::PostToolUse, deadline).unwrap_err();
        assert_eq!(denial.policy, FailurePolicy::Deny);
        let skip = Pin::load_verify_until(&path, &repo, Event::Stop, deadline).unwrap_err();
        assert_eq!(skip.policy, FailurePolicy::Deny);
        fs::write(repo.join(MANIFEST_FILE), sealed(fixture(b"hook"))).unwrap();
        let valid_pin = Pin::capture_operator(&repo).unwrap();
        let valid_failure = super::super::policy::verification_failure(
            &valid_pin,
            &repo,
            Event::Stop,
            PinError::Io,
            Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(valid_failure.policy, FailurePolicy::Continue);
        fs::write(repo.join(".claude/hooks/runtime.js"), b"changed runtime").unwrap();
        let changed_runtime = super::super::policy::verification_failure(
            &valid_pin,
            &repo,
            Event::Stop,
            PinError::Io,
            Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(changed_runtime.policy, FailurePolicy::Deny);
        fs::remove_file(&path).unwrap();
        let unavailable = Pin::load_verify_until(&path, &repo, Event::Stop, deadline).unwrap_err();
        assert_eq!(unavailable.policy, FailurePolicy::Deny);
    }
    #[cfg(unix)]
    #[test]
    fn foreign_or_replaced_repository_cannot_borrow_continue_policy() {
        let (temp, repo, path) = setup(b"hook");
        Pin::capture_operator(&repo)
            .unwrap()
            .write_private(&path)
            .unwrap();
        let foreign = temp.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        assert!(matches!(
            Pin::load_verify_until(&path, &foreign, Event::Stop, deadline),
            Err(VerificationFailure {
                error: PinError::Mismatch,
                policy: FailurePolicy::Deny
            })
        ));
        fs::rename(&repo, temp.path().join("old-repo")).unwrap();
        fs::create_dir(&repo).unwrap();
        assert!(matches!(
            Pin::load_verify_until(&path, &repo, Event::Stop, deadline),
            Err(VerificationFailure {
                error: PinError::Mismatch,
                policy: FailurePolicy::Deny
            })
        ));
        fs::remove_dir(&repo).unwrap();
        assert!(matches!(
            Pin::load_verify_until(&path, &repo, Event::Stop, deadline),
            Err(VerificationFailure {
                policy: FailurePolicy::Deny,
                ..
            })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn fallback_reauthenticates_subject_after_verification_failure() {
        let (temp, repo, _path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        assert_eq!(pin.fallback_policy(Event::Stop), FailurePolicy::Continue);
        pin.authenticate_repo(&repo).unwrap();
        fs::rename(&repo, temp.path().join("old-repo")).unwrap();
        fs::create_dir(&repo).unwrap();
        // Invoke the exact post-verification error mapper after initial authentication
        // and an actual inode replacement, rather than depending on thread timing.
        let failure = super::super::policy::verification_failure(
            &pin,
            &repo,
            Event::Stop,
            PinError::Mismatch,
            Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(failure.policy, FailurePolicy::Deny);
    }
    #[cfg(unix)]
    #[test]
    fn nofollow_pin_and_hook_admission_refuse_links_and_fifo() {
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        };
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        pin.write_private(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Pin::read_private(&path),
            Err(PinError::UnsafePath)
        ));
        let original_pin = path.with_file_name("original-pin.json");
        pin.write_private(&original_pin).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(original_pin, &path).unwrap();
        assert!(Pin::read_private(&path).is_err());
        let hook = repo.join(".claude/hooks/guard.js");
        let same_hook = path.parent().unwrap().join("same-hook.js");
        fs::write(&same_hook, b"hook").unwrap();
        fs::remove_file(&hook).unwrap();
        symlink(same_hook, &hook).unwrap();
        assert!(pin.verify(&repo).unwrap().rows[0].admission.is_err());
        fs::remove_file(&hook).unwrap();
        let name = std::ffi::CString::new(hook.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated fixture path and ordinary FIFO permissions.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(
            pin.verify(&repo).unwrap().rows[0]
                .admission
                .as_ref()
                .unwrap_err(),
            &RowAdmissionError::InvalidPath
        );
    }
    #[cfg(unix)]
    #[test]
    fn parent_symlink_and_replaced_repository_identity_refuse() {
        use std::os::unix::fs::symlink;
        let (temp, repo, _path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        fs::rename(repo.join(".claude/hooks"), repo.join(".claude/renamed")).unwrap();
        symlink(repo.join(".claude/renamed"), repo.join(".claude/hooks")).unwrap();
        assert!(matches!(
            pin.verify(&repo),
            Err(PinError::RuntimeAdmission(RowAdmissionError::Unreadable))
        ));
        fs::rename(&repo, temp.path().join("old-repo")).unwrap();
        fs::create_dir(&repo).unwrap();
        assert!(matches!(pin.verify(&repo), Err(PinError::Mismatch)));
    }
    #[cfg(windows)]
    #[test]
    fn windows_private_pin_activation_explicitly_refuses() {
        let (_temp, repo, path) = setup(b"hook");
        let pin = Pin::capture_operator(&repo).unwrap();
        assert!(matches!(
            pin.write_private(&path),
            Err(PinError::UnsupportedPlatform)
        ));
        assert!(matches!(
            Pin::read_private(&path),
            Err(PinError::UnsupportedPlatform)
        ));
        let failure = Pin::load_verify_until(
            &path,
            &repo,
            Event::Stop,
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(matches!(failure.error, PinError::UnsupportedPlatform));
        assert_eq!(failure.policy, FailurePolicy::Deny);
    }
}
