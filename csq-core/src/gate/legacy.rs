//! Loom legacy-adapter package admission and bounded Node execution.
//!
//! The package manifest is a second integrity boundary: the hook registry pins
//! rows, while this manifest pins the immutable runtime that is allowed to
//! execute them.  No Node process is started until every listed file and every
//! lexical runtime-closure pin has been checked against the supplied checkout.
//! Dynamic module specifiers remain a reviewer concern; the manifest's empty
//! `gaps` field is therefore required but is not treated as proof of a complete
//! dynamic closure.

use super::dispatch::{RowFailure, RowOutput, RowRequest, RowRunner, MAX_ROW_OUTPUT_BYTES};
use super::pin::VerifiedBytes;
use super::registry::{self, Event, Pool};
use super::runtime_mapping::RuntimePoolBinding;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_PACKAGE_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PACKAGE_FILES: usize = 512;
pub const MAX_RUNTIME_CLOSURE_FILES: usize = 512;
pub const CRASH_DEMOTION_THRESHOLD: usize = 3;
pub const CRASH_DEMOTION_WINDOW: Duration = Duration::from_secs(30 * 60);
const MAX_DEMOTION_LEDGER_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePin {
    pub path: String,
    pub sha256: String,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosure {
    pub entry_points: Vec<String>,
    pub reached_files: usize,
    pub gaps: Vec<String>,
    pub method: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageVerification {
    pub pins: Vec<PackagePin>,
    pub runtime_closure: RuntimeClosure,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub package: String,
    pub version: String,
    pub proposed_path: String,
    pub invocation: String,
    pub commit_sha: String,
    pub commit_sha_convention: String,
    pub head_at_generation: String,
    pub runtime_clean_at_generation: bool,
    pub file_count: usize,
    pub files: Vec<PackageFile>,
    pub verification: PackageVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    #[error("package manifest is unreadable")]
    Io,
    #[error("package manifest is malformed")]
    Malformed,
    #[error("package manifest exceeds admission limits")]
    Limit,
    #[error("package manifest contains an invalid path")]
    InvalidPath,
    #[error("package manifest contains an invalid digest")]
    InvalidDigest,
    #[error("package manifest file count is inconsistent")]
    FileCount,
    #[error("package manifest contains a duplicate path")]
    DuplicatePath,
    #[error("package manifest runtime closure is incomplete")]
    RuntimeClosure,
    #[error("package file is missing")]
    MissingFile,
    #[error("package file digest differs")]
    HashMismatch,
    #[error("package file is not a regular non-symlink file")]
    UnsafeFile,
    #[error("legacy adapter activation requires Windows Job Object cleanup")]
    UnsupportedPlatform,
    #[error("runtime base directory is not trusted: {0}")]
    UnsafeRuntimeBase(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    root: PathBuf,
    manifest_sha256: String,
    manifest: PackageManifest,
    files: BTreeMap<String, PackageFile>,
    /// Bytes retained at admission. Runtime execution uses a private copy of
    /// these bytes and never reopens the repository path as authority.
    verified_bytes: BTreeMap<String, Box<[u8]>>,
    materialized: BTreeMap<String, PathBuf>,
    materialized_bytes: BTreeMap<String, Box<[u8]>>,
    /// Runtime entry roots admitted by the materializer. This is narrower
    /// than the complete closure, which also contains dependency files.
    materialized_runtime_union: BTreeSet<String>,
}

impl VerifiedPackage {
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    fn canonical_relative(&self, path: &Path) -> Option<String> {
        let canonical = path.canonicalize().ok()?;
        // Manifest keys are POSIX paths even when canonical filesystem paths
        // use Windows separators. Convert only the confined normal components;
        // a blanket string replacement could admit an invalid Unix filename.
        let relative = canonical.strip_prefix(&self.root).ok()?;
        let parts: Option<Vec<_>> = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(part) => part.to_str(),
                _ => None,
            })
            .collect();
        let key = parts?.join("/");
        validate_relative(&key).ok()?;
        Some(key)
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.canonical_relative(path)
            .is_some_and(|relative| self.files.contains_key(&relative))
    }

    /// Bind an independently admitted pin closure to this package's retained
    /// bytes.  Path membership and a child-reported digest are insufficient:
    /// two independently valid authorities may name the same path with
    /// different bytes.  Every entry and declared dependency must match before
    /// a package runtime can execute.
    pub fn bind_verified_bytes(&self, admitted: &VerifiedBytes) -> Result<(), PackageError> {
        let check = |path: &Path, bytes: &[u8]| {
            let relative = self
                .canonical_relative(path)
                .ok_or(PackageError::HashMismatch)?;
            let package_file = self
                .files
                .get(&relative)
                .ok_or(PackageError::HashMismatch)?;
            let retained = self
                .verified_bytes
                .get(&relative)
                .ok_or(PackageError::HashMismatch)?;
            if package_file.bytes != bytes.len() as u64
                || package_file.sha256 != digest(bytes)
                || retained.as_ref() != bytes
                || package_file.bytes != retained.len() as u64
                || package_file.sha256 != digest(retained)
            {
                return Err(PackageError::HashMismatch);
            }
            Ok(())
        };
        check(admitted.source_path(), admitted.as_bytes())?;
        for dependency in admitted.dependencies().values() {
            check(dependency.source_path(), dependency.as_bytes())?;
        }
        Ok(())
    }

    fn is_runtime_entry(&self, path: &Path) -> bool {
        self.canonical_relative(path).is_some_and(|relative| {
            self.manifest
                .verification
                .pins
                .iter()
                .any(|pin| pin.source == "runtime_closure" && pin.path == relative)
        })
    }

    /// Verify the complete package before constructing a process runner.
    pub fn verify(manifest_path: &Path, repo_root: &Path) -> Result<Self, PackageError> {
        let manifest_bytes = read_admission_file(manifest_path, MAX_PACKAGE_MANIFEST_BYTES)
            .map_err(|error| match error {
                PackageError::MissingFile | PackageError::UnsafeFile => PackageError::Io,
                other => other,
            })?;
        let value = registry::strict_json(&manifest_bytes).map_err(|_| PackageError::Malformed)?;
        let manifest: PackageManifest =
            serde_json::from_value(value).map_err(|_| PackageError::Malformed)?;
        if manifest.files.len() > MAX_PACKAGE_FILES
            || manifest.verification.pins.len() > MAX_PACKAGE_FILES
            || manifest.verification.runtime_closure.entry_points.len() > MAX_RUNTIME_CLOSURE_FILES
            || manifest.verification.runtime_closure.reached_files > MAX_RUNTIME_CLOSURE_FILES
        {
            return Err(PackageError::Limit);
        }
        if manifest.file_count != manifest.files.len() {
            return Err(PackageError::FileCount);
        }
        if !manifest.verification.runtime_closure.gaps.is_empty()
            || manifest.verification.runtime_closure.reached_files == 0
            || manifest.verification.runtime_closure.method.is_empty()
        {
            return Err(PackageError::RuntimeClosure);
        }
        let root = repo_root.canonicalize().map_err(|_| PackageError::Io)?;
        let manifest_parent = manifest_path.parent().ok_or(PackageError::Io)?;
        // The manifest may live in the immutable runtime directory, but a
        // package always verifies source paths relative to the repository root.
        if !manifest_parent.exists() {
            return Err(PackageError::Io);
        }
        let mut files = BTreeMap::new();
        let mut verified_bytes = BTreeMap::new();
        for file in &manifest.files {
            validate_relative(&file.path)?;
            validate_digest(&file.sha256)?;
            if files.insert(file.path.clone(), file.clone()).is_some() {
                return Err(PackageError::DuplicatePath);
            }
            let bytes = read_package_file(&root, &file.path)?;
            if bytes.len() as u64 != file.bytes || digest(&bytes) != file.sha256 {
                return Err(PackageError::HashMismatch);
            }
            verified_bytes.insert(file.path.clone(), bytes.into_boxed_slice());
        }
        let mut pins = BTreeMap::new();
        for pin in &manifest.verification.pins {
            validate_relative(&pin.path)?;
            validate_digest(&pin.sha256)?;
            if pins.insert(pin.path.clone(), pin).is_some() {
                return Err(PackageError::DuplicatePath);
            }
            // A runtime pin that names a package file must bind to the exact
            // bytes already retained in `verified_bytes`. Reopening the path
            // here would create two independent reads (A and B): a swap
            // between them could make the manifest appear internally
            // consistent while the runner executes a different byte set.
            let matches_pin = if let Some(bytes) = verified_bytes.get(&pin.path) {
                digest(bytes) == pin.sha256
            } else {
                let bytes = read_package_file(&root, &pin.path)?;
                digest(&bytes) == pin.sha256
            };
            if !matches_pin {
                return Err(PackageError::HashMismatch);
            }
        }
        let closure_pins: BTreeSet<_> = manifest
            .verification
            .pins
            .iter()
            .filter(|pin| pin.source == "runtime_closure")
            .map(|pin| pin.path.as_str())
            .collect();
        let entry_points: BTreeSet<_> = manifest
            .verification
            .runtime_closure
            .entry_points
            .iter()
            .map(String::as_str)
            .collect();
        if closure_pins.len() != manifest.verification.runtime_closure.reached_files
            || entry_points.len() != manifest.verification.runtime_closure.reached_files
            || entry_points.len() != manifest.verification.runtime_closure.entry_points.len()
            || manifest
                .verification
                .runtime_closure
                .entry_points
                .iter()
                .any(|entry| !closure_pins.contains(entry.as_str()))
        {
            return Err(PackageError::RuntimeClosure);
        }
        for path in closure_pins {
            if !files.contains_key(path) {
                return Err(PackageError::RuntimeClosure);
            }
        }
        let manifest_sha256 = digest(&manifest_bytes);
        Ok(Self {
            root,
            manifest_sha256,
            manifest,
            files,
            verified_bytes,
            materialized: BTreeMap::new(),
            materialized_bytes: BTreeMap::new(),
            materialized_runtime_union: BTreeSet::new(),
        })
    }

    /// Bind the manifest's one runtime union to immutable materialized bytes.
    /// The caller supplies the source-to-destination map produced by the
    /// materializer; no basename or proposed-path guess is accepted.
    pub fn verify_materialized(
        mut self,
        mappings: BTreeMap<String, PathBuf>,
        runtime_union: &[String],
    ) -> Result<Self, PackageError> {
        let closure: BTreeSet<_> = self
            .manifest
            .verification
            .pins
            .iter()
            .filter(|pin| pin.source == "runtime_closure")
            .map(|pin| pin.path.as_str())
            .collect();
        let admitted_union: BTreeSet<_> = runtime_union.iter().map(String::as_str).collect();
        if runtime_union.is_empty()
            || admitted_union.len() != runtime_union.len()
            || admitted_union.iter().any(|path| !closure.contains(path))
            || mappings.len() != closure.len()
            || closure.iter().any(|path| !mappings.contains_key(*path))
        {
            return Err(PackageError::RuntimeClosure);
        }
        let mut materialized_bytes = BTreeMap::new();
        for source in &closure {
            let destination = mappings.get(*source).ok_or(PackageError::RuntimeClosure)?;
            let package_file = self
                .files
                .get(*source)
                .ok_or(PackageError::RuntimeClosure)?;
            let pin = self
                .manifest
                .verification
                .pins
                .iter()
                .find(|pin| pin.source == "runtime_closure" && pin.path == *source)
                .ok_or(PackageError::RuntimeClosure)?;
            // Keep the materializer's B-side read bound to both declarations.
            // Admission already proved A (the cached package bytes) equals
            // the pin, and this check prevents a future caller from silently
            // changing that invariant while bypassing the admission path.
            if package_file.sha256 != pin.sha256 {
                return Err(PackageError::HashMismatch);
            }
            let bytes = read_materialized_file(destination)?;
            if bytes.len() as u64 != package_file.bytes
                || digest(&bytes) != package_file.sha256
                || digest(&bytes) != pin.sha256
            {
                return Err(PackageError::HashMismatch);
            }
            materialized_bytes.insert((*source).to_owned(), bytes.into_boxed_slice());
        }
        self.materialized = mappings;
        self.materialized_bytes = materialized_bytes;
        self.materialized_runtime_union = runtime_union.iter().cloned().collect();
        Ok(self)
    }

    pub fn materialized_path(&self, source: &str) -> Option<&Path> {
        self.materialized.get(source).map(PathBuf::as_path)
    }

    fn private_runtime(
        &self,
        bytes: &BTreeMap<String, Box<[u8]>>,
    ) -> Result<RuntimeMaterialization, PackageError> {
        RuntimeMaterialization::create(bytes)
    }

    /// The registry emitter supplies one union of dispatcher, adapter, and
    /// package runtime paths. Reject any executed path outside that union.
    pub fn verify_runtime_union(&self, runtime_union: &[String]) -> Result<(), PackageError> {
        let closure: BTreeSet<_> = self
            .manifest
            .verification
            .pins
            .iter()
            .filter(|pin| pin.source == "runtime_closure")
            .map(|pin| pin.path.as_str())
            .collect();
        let requested_union: BTreeSet<_> = runtime_union.iter().map(String::as_str).collect();
        if runtime_union.is_empty()
            || requested_union.len() != runtime_union.len()
            || requested_union.iter().any(|path| !closure.contains(path))
            || requested_union
                != self
                    .materialized_runtime_union
                    .iter()
                    .map(String::as_str)
                    .collect()
        {
            return Err(PackageError::RuntimeClosure);
        }
        Ok(())
    }
}

/// Private copy of admitted runtime bytes. A replacement in the repository or
/// in the caller's materialization cannot change the source executed by Node.
struct RuntimeMaterialization {
    root: PathBuf,
}

/// A directory builder whose mode (0o700) is applied at creation, so the directory never
/// exists with a wider mode than the umask leaves it.
#[cfg(unix)]
fn private_dir_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn private_dir_builder() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

/// Create one directory that only this user can enter: the mode is applied AT creation
/// (the umask can only remove bits from it), so there is no window with a wider mode, and
/// the result is checked on the object that was created. An existing path, a symlink, a
/// foreign owner, or any group/other bit refuses (fail closed).
fn make_private_dir(path: &Path) -> Result<(), PackageError> {
    private_dir_builder()
        .create(path)
        .map_err(|_| PackageError::Io)?;
    check_private_dir(path)
}

/// The directory at `path` is a real directory (not a symlink), owned by this user, with no
/// group or other permission bit.
fn check_private_dir(path: &Path) -> Result<(), PackageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).map_err(|_| PackageError::Io)?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if !meta.file_type().is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(PackageError::Io);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Close a file and report the result. `File`'s drop discards a close error, and on
/// network or FUSE filesystems close is where a deferred write error surfaces; with the
/// fsync gone (it ran inside the hook deadline) this is the check that a torn copy is
/// never executed.
fn close_checked(file: File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        // SAFETY: `into_raw_fd` transferred ownership of a live descriptor; it is closed
        // exactly once here.
        if unsafe { libc::close(fd) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        drop(file);
        Ok(())
    }
}

/// Write one runtime file into the private tree: each missing parent is created here, by
/// this call, as a private directory (`created` records them); a parent that already
/// exists and was not created by this call refuses instead of being adopted.
fn write_private_runtime_file(
    root: &Path,
    relative: &str,
    content: &[u8],
    created: &mut BTreeSet<PathBuf>,
    close: impl FnOnce(File) -> std::io::Result<()>,
) -> Result<(), PackageError> {
    use std::path::Component;
    let relative_path = Path::new(relative);
    let mut parts = Vec::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(part) => parts.push(part),
            _ => return Err(PackageError::Io),
        }
    }
    let (file_name, parents) = parts.split_last().ok_or(PackageError::Io)?;
    let mut dir = root.to_path_buf();
    for part in parents {
        dir.push(part);
        if !created.contains(&dir) {
            make_private_dir(&dir)?;
            created.insert(dir.clone());
        }
    }
    let destination = dir.join(file_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    let mut file = options.open(&destination).map_err(|_| PackageError::Io)?;
    // No fsync: this copy lives for one invocation and `Drop` removes it, so a crash
    // discards it rather than recovering it. The child reads it through the page
    // cache, which is coherent with this write. Syncing every file here ran inside
    // the hook's deadline, so on a slow-fsync disk N files cost N * fsync latency
    // before the child could start and the row timed out.
    file.write_all(content).map_err(|_| PackageError::Io)?;
    close(file).map_err(|_| PackageError::Io)?;
    #[cfg(unix)]
    // Mode restriction is defense in depth only: a child or loader
    // with a permitted rewrite path can still alter a private copy.
    // Fresh materialization on every call protects cross-call
    // authority; same-child lazy-load immutability needs a loader
    // proof at the activation boundary.
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))
        .map_err(|_| PackageError::Io)?;
    Ok(())
}

impl RuntimeMaterialization {
    fn create(bytes: &BTreeMap<String, Box<[u8]>>) -> Result<Self, PackageError> {
        Self::create_in(&gate_runtime_base()?, bytes)
    }

    /// `create` under an explicit base (tests pass their own; production passes
    /// [`gate_runtime_base`]). On unix the base and every ancestor are held to the shared
    /// directory-trust policy (owner, mode, and an extended ACL granting entry changes:
    /// macOS ACL or Linux NFSv4 ACL; other Unix refuses), and the base itself must be private to this user (a shared sticky
    /// directory such as `/tmp` is refused), before anything is created under it. The gate
    /// base is held to the ANCESTOR ACL rule only, never the leaf private-store rule
    /// (`platform::fs::private_directory_acl_refusal`): the threat is planting, and the tree
    /// holds no secrets (only manifest-pinned, sha256-verified package sources read from the
    /// repository, plus a constant `package.json`; see `write_private_runtime_file`), so a
    /// non-owner read grant exposes nothing. Another
    /// user who can create entries beside the tree can plant a `package.json` or
    /// `node_modules` that the runtime resolves from. Windows makes no owner or DACL check;
    /// its base sits under the user profile (see [`gate_runtime_base`]) and relies on that
    /// directory's inherited per-user ACL.
    fn create_in(base: &Path, bytes: &BTreeMap<String, Box<[u8]>>) -> Result<Self, PackageError> {
        if bytes.is_empty() {
            return Err(PackageError::RuntimeClosure);
        }
        #[cfg(unix)]
        let base = crate::platform::fs::check_trusted_directory_chain(base)
            .map_err(PackageError::UnsafeRuntimeBase)?;
        #[cfg(unix)]
        require_private_base(&base).map_err(PackageError::UnsafeRuntimeBase)?;
        #[cfg(not(unix))]
        let base = base.to_path_buf();
        let pid = std::process::id();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let mut root = None;
        for attempt in 0..32u32 {
            let candidate = base.join(format!("csq-loom-runtime-{pid}-{stamp}-{attempt}"));
            match private_dir_builder().create(&candidate) {
                Ok(()) => {
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(PackageError::Io),
            }
        }
        let root = root.ok_or(PackageError::Io)?;
        // Owned from here on, so every early return below removes the partial tree.
        let materialization = Self { root };
        // The root was created with mode 0o700 (the umask can only remove bits); verify what
        // is on disk before anything is placed in it. No chmod follows: a chmod by path
        // follows symlinks and would only widen what the creation mode already fixed.
        check_private_dir(&materialization.root)?;
        let mut created = BTreeSet::new();
        // The runtime resolves "type" from the nearest package.json above each script. The
        // tree's own root file stops that walk here, so no package.json outside the private
        // tree (an ancestor's, or one planted beside it) can change how our scripts load.
        if !bytes.contains_key("package.json") {
            write_private_runtime_file(
                &materialization.root,
                "package.json",
                RUNTIME_ROOT_PACKAGE_JSON,
                &mut created,
                close_checked,
            )?;
        }
        for (relative, content) in bytes {
            write_private_runtime_file(
                &materialization.root,
                relative,
                content,
                &mut created,
                close_checked,
            )?;
        }
        Ok(materialization)
    }

    fn entry(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

/// A row cannot run because its runtime tree could not be built. The row outcome stays
/// `Incomplete`, but the reason is no longer discarded: the typed, path-free diagnostic code
/// (the same vocabulary `csq gate status` reports) is logged, and the status report names
/// an unusable base before any row runs ([`runtime_base_preflight`]).
fn runtime_unavailable(error: &PackageError) -> RowFailure {
    tracing::warn!(
        event = "gate_runtime_unavailable",
        diagnostic = ?super::status::AdapterDiagnostic::from_package(error),
        "gate runtime tree could not be built"
    );
    RowFailure::Incomplete
}

/// Whether a runtime base exists that a tree can be built in, by the same chooser a row uses
/// (creating the private base directory if it is missing). `csq gate status` reports a
/// refusal here as `ManifestUnsafeRuntimeBase` instead of every row failing as incomplete.
pub(super) fn runtime_base_preflight() -> Result<(), PackageError> {
    gate_runtime_base().map(|_| ())
}

/// Written at the root of every runtime tree unless the package ships its own.
const RUNTIME_ROOT_PACKAGE_JSON: &[u8] = b"{\"type\":\"commonjs\"}\n";

/// Where the runtime trees are built: a directory only this user can enter, never a shared
/// one. `$XDG_RUNTIME_DIR/csq-gate` when that exists, else `gate-runtime` under the csq
/// state directory (`CSQ_BASE_DIR`, or `~/.claude/accounts`). On Windows the second form is
/// used, inheriting the user-profile ACL; no DACL check is made there.
fn gate_runtime_base() -> Result<PathBuf, PackageError> {
    #[cfg(unix)]
    let xdg = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    #[cfg(not(unix))]
    let xdg: Option<PathBuf> = None;
    choose_runtime_base(xdg.as_deref(), gate_state_root().as_deref())
}

#[cfg(not(test))]
fn gate_state_root() -> Option<PathBuf> {
    std::env::var_os("CSQ_BASE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            crate::platform::home::home_dir().map(|home| home.join(".claude").join("accounts"))
        })
}

/// Unit tests never write under the real home: one per-process temporary state root.
#[cfg(test)]
fn gate_state_root() -> Option<PathBuf> {
    static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let root = ROOT.get_or_init(|| tempfile::tempdir().expect("test state root"));
    Some(root.path().join("state"))
}

/// The pure chooser behind [`gate_runtime_base`]: the first candidate that can be made
/// private and passes the trust checks wins; when none does, every refusal is reported.
fn choose_runtime_base(xdg: Option<&Path>, state: Option<&Path>) -> Result<PathBuf, PackageError> {
    let mut refusals = Vec::new();
    if let Some(xdg) = xdg {
        // An absolute, already existing directory only: this never creates the XDG parent.
        if xdg.is_absolute() && xdg.is_dir() {
            match private_base(&xdg.join("csq-gate")) {
                Ok(base) => return Ok(base),
                Err(reason) => refusals.push(reason),
            }
        } else {
            refusals.push(format!(
                "XDG_RUNTIME_DIR {} is not an existing absolute directory",
                xdg.display()
            ));
        }
    }
    match state {
        Some(state) => match private_base(&state.join("gate-runtime")) {
            Ok(base) => return Ok(base),
            Err(reason) => refusals.push(reason),
        },
        None => refusals.push("no csq state directory is available".to_string()),
    }
    Err(PackageError::UnsafeRuntimeBase(refusals.join("; ")))
}

/// Create `dir` private (mode 0o700) if needed and require it, and every ancestor, to pass
/// the trust policy. Returns the canonical path.
fn private_base(dir: &Path) -> Result<PathBuf, String> {
    crate::platform::fs::ensure_private_dir(dir)
        .map_err(|e| format!("directory {} cannot be made private: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        let canonical = crate::platform::fs::check_trusted_directory_chain(dir)?;
        require_private_base(&canonical)?;
        Ok(canonical)
    }
    #[cfg(not(unix))]
    Ok(dir.to_path_buf())
}

/// The base itself (not only its ancestors) is a real directory owned by this user with no
/// group or other permission bit, so no other user can create entries beside our trees.
#[cfg(unix)]
fn require_private_base(base: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(base)
        .map_err(|e| format!("directory {} cannot be inspected: {e}", base.display()))?;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !meta.file_type().is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(format!(
            "directory {} refused: the runtime base must be private to this user (owner {}, mode {:o})",
            base.display(),
            meta.uid(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

impl Drop for RuntimeMaterialization {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn validate_relative(path: &str) -> Result<(), PackageError> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(PackageError::InvalidPath);
    }
    Ok(())
}

fn validate_digest(hash: &str) -> Result<(), PackageError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PackageError::InvalidDigest);
    }
    Ok(())
}

fn read_package_file(root: &Path, relative: &str) -> Result<Vec<u8>, PackageError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| PackageError::MissingFile)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PackageError::UnsafeFile);
    }
    let canonical = path.canonicalize().map_err(|_| PackageError::MissingFile)?;
    if !canonical.starts_with(root) {
        return Err(PackageError::UnsafeFile);
    }
    read_admission_file(&canonical, MAX_PACKAGE_FILE_BYTES)
}

fn read_materialized_file(path: &Path) -> Result<Vec<u8>, PackageError> {
    read_admission_file(path, MAX_PACKAGE_FILE_BYTES)
}

/// Read an admission-bound file without allocating from an untrusted length
/// or blocking on a named pipe. The initial metadata check gives a fast
/// rejection for oversized regular files; the no-follow, nonblocking open and
/// second metadata check close the FIFO/symlink race before any bytes are read.
fn read_admission_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, PackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PackageError::MissingFile)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PackageError::UnsafeFile);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(PackageError::Limit);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|_| PackageError::MissingFile)?;
    let opened = file.metadata().map_err(|_| PackageError::MissingFile)?;
    if !opened.is_file() {
        return Err(PackageError::UnsafeFile);
    }
    if opened.len() > max_bytes as u64 {
        return Err(PackageError::Limit);
    }

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PackageError::MissingFile)?;
    if bytes.len() > max_bytes {
        return Err(PackageError::Limit);
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Session values that may cross into a legacy Node process. The process never
/// inherits the caller's environment wholesale.
#[derive(Debug, Clone, Default)]
pub struct NodeEnvironment {
    pub claude_config_dir: Option<String>,
    pub codex_home: Option<String>,
    pub session_id: Option<String>,
    pub handle_dir: Option<String>,
    pub path: Option<String>,
    pub home: Option<String>,
    pub tmpdir: Option<String>,
}

impl NodeEnvironment {
    fn apply(&self, command: &mut Command, project_dir: &Path) {
        command.env_clear().env("CLAUDE_PROJECT_DIR", project_dir);
        for (name, value) in [
            ("CLAUDE_CONFIG_DIR", self.claude_config_dir.as_ref()),
            ("CODEX_HOME", self.codex_home.as_ref()),
            ("CSQ_SESSION_ID", self.session_id.as_ref()),
            ("CSQ_HANDLE_DIR", self.handle_dir.as_ref()),
            ("PATH", self.path.as_ref()),
            ("HOME", self.home.as_ref()),
            ("TMPDIR", self.tmpdir.as_ref()),
        ] {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Pool,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    #[error("runtime package is not admitted")]
    PackageNotAdmitted,
    #[error("node subprocess could not be started")]
    Spawn,
    #[error("node subprocess output is incomplete")]
    Incomplete,
    #[error("node subprocess timed out")]
    Timeout,
}

#[derive(Debug, Clone)]
struct FaultWindow {
    first: Instant,
    crashes: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedFault {
    crashes: usize,
    demoted_at_ms: u128,
    /// Start of the crash window.  `demoted_at_ms` is retained as the
    /// last-update timestamp for compatibility with the original sidecar
    /// shape; old records use it as their window start.
    #[serde(default)]
    window_started_at_ms: Option<u128>,
}

/// One durable demotion event. The ledger is newline-delimited so each
/// demotion remains an event-level record rather than a periodically rewritten
/// summary that can erase history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedDemotion {
    row_id: String,
    crashes: usize,
    demoted_at_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DemotionLedgerError {
    #[error("demotion ledger could not read its existing records: {0}")]
    Read(String),
    #[error("demotion ledger could not write its temporary record: {0}")]
    Write(String),
    #[error("demotion ledger temporary record could not be fsynced: {0}")]
    SyncTemp(String),
    #[error("demotion ledger could not atomically install its record: {0}")]
    Rename(String),
    #[error("demotion ledger parent directory could not be fsynced: {0}")]
    SyncParent(String),
    #[error("demotion ledger record could not be encoded")]
    Encode,
    #[error("demotion ledger contains malformed records")]
    Malformed,
    #[error("demotion ledger exceeds its bounded capacity")]
    Capacity,
}

/// Own only a newly-created private temporary file. A collision never grants
/// cleanup authority, and installation disarms removal of a reused old path.
struct DemotionTemp {
    path: PathBuf,
    file: Option<File>,
    installed: bool,
}

impl DemotionTemp {
    fn create(parent: &Path) -> Result<Self, DemotionLedgerError> {
        for _ in 0..16 {
            let path = parent.join(format!(".gate-demotion-{}.tmp", uuid::Uuid::new_v4()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        installed: false,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    return Err(DemotionLedgerError::Write(
                        "temporary file unavailable".into(),
                    ))
                }
            }
        }
        Err(DemotionLedgerError::Write("temporary collisions".into()))
    }
}

impl Drop for DemotionTemp {
    fn drop(&mut self) {
        self.file.take();
        if !self.installed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Bounded subprocess runner for a single admitted row. It also tracks the
/// repo-pool crash ledger: after three crashes inside thirty minutes the row is
/// marked process-mode and surfaced through `demoted_rows`. Process mode keeps
/// the same stdin/output protocol, so verdict identity does not change.
pub struct NodeRowRunner {
    package: VerifiedPackage,
    node: PathBuf,
    environment: NodeEnvironment,
    faults: HashMap<String, FaultWindow>,
    demoted: BTreeSet<String>,
    fault_ledger: Option<PathBuf>,
    fault_state: Option<PathBuf>,
    ledger_unavailable: bool,
    child_started: Cell<bool>,
    /// Set before pipe-drain validation for an exit-2 pool refusal, so an
    /// empty/plain or incomplete refusal cannot become continuable execution.
    protocol_refusal: Cell<bool>,
}

impl NodeRowRunner {
    pub fn new(package: VerifiedPackage) -> Self {
        Self {
            package,
            node: PathBuf::from("node"),
            environment: NodeEnvironment::default(),
            faults: HashMap::new(),
            demoted: BTreeSet::new(),
            fault_ledger: None,
            fault_state: None,
            ledger_unavailable: false,
            child_started: Cell::new(false),
            protocol_refusal: Cell::new(false),
        }
    }

    pub fn with_node(mut self, node: impl Into<PathBuf>) -> Self {
        self.node = node.into();
        self
    }

    pub fn with_environment(mut self, environment: NodeEnvironment) -> Self {
        self.environment = environment;
        self
    }

    /// Persist demotion state in the repository's operator-visible status
    /// location. Unreadable state or failed durability denies a row rather than
    /// silently forgetting a demotion or advertising unpersisted state.
    pub fn with_fault_ledger(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let state = path.with_extension("faults");
        match read_demotion_ledger(&path).and_then(|bytes| load_demotion_rows(&bytes)) {
            Ok(rows) => self.demoted.extend(rows),
            Err(_) => self.ledger_unavailable = true,
        }
        match read_fault_state(&state) {
            Ok(rows) => {
                let now = now_millis();
                for (row_id, fault) in rows {
                    let started = fault.window_started_at_ms.unwrap_or(fault.demoted_at_ms);
                    let age = now.saturating_sub(started);
                    if age > CRASH_DEMOTION_WINDOW.as_millis() {
                        continue;
                    }
                    self.faults.insert(
                        row_id,
                        FaultWindow {
                            first: Instant::now()
                                .checked_sub(Duration::from_millis(age as u64))
                                .unwrap_or_else(Instant::now),
                            crashes: fault.crashes,
                        },
                    );
                }
            }
            Err(_) => self.ledger_unavailable = true,
        }
        self.fault_ledger = Some(path);
        self.fault_state = Some(state);
        self
    }

    pub fn demoted_rows(&self) -> impl Iterator<Item = &str> {
        self.demoted.iter().map(String::as_str)
    }

    pub fn execution_mode(&self, row_id: &str, pool: Pool) -> ExecutionMode {
        if pool == Pool::Repo && self.demoted.contains(row_id) {
            ExecutionMode::Process
        } else {
            ExecutionMode::Pool
        }
    }

    /// Validate durable pool state before the caller starts its first child.
    /// This is separate from `execution_mode`: a corrupt or unreadable ledger
    /// must not be mistaken for an empty ledger with all rows still poolable.
    pub fn preflight_ledger(&self) -> Result<(), RowFailure> {
        let Some(path) = &self.fault_ledger else {
            return Ok(());
        };
        read_demotion_ledger(path)
            .and_then(|bytes| load_demotion_rows(&bytes))
            .map_err(|_| RowFailure::DemotionLedger)?;
        read_fault_state(&path.with_extension("faults")).map_err(|_| RowFailure::DemotionLedger)?;
        Ok(())
    }

    fn note_crash(&mut self, row_id: &str) -> Result<(), DemotionLedgerError> {
        if self.ledger_unavailable {
            return Err(DemotionLedgerError::Read("state unavailable".into()));
        }
        let now = Instant::now();
        let crashes = {
            let window = self.faults.entry(row_id.to_owned()).or_insert(FaultWindow {
                first: now,
                crashes: 0,
            });
            if now.duration_since(window.first) > CRASH_DEMOTION_WINDOW {
                window.first = now;
                window.crashes = 0;
            }
            let crashes = next_fault_count(window.crashes)?;
            window.crashes = crashes;
            crashes
        };
        let crashes = if self.fault_state.is_some() {
            self.persist_fault_state(row_id)?
        } else {
            crashes
        };
        if let Some(window) = self.faults.get_mut(row_id) {
            window.crashes = crashes;
        }
        if crashes >= CRASH_DEMOTION_THRESHOLD && !self.demoted.contains(row_id) {
            // The in-memory mode changes only after the event is durable. A
            // failed write therefore cannot silently advertise a demotion that
            // would disappear on restart.
            self.persist_demotion(row_id, crashes)?;
            self.demoted.insert(row_id.to_owned());
        }
        Ok(())
    }

    pub fn demotion_status(&self) -> Vec<String> {
        self.demoted.iter().cloned().collect()
    }

    fn persist_demotion(&self, row_id: &str, crashes: usize) -> Result<(), DemotionLedgerError> {
        self.persist_demotion_with_hooks(row_id, crashes, |file| file.sync_all(), sync_directory)
    }

    fn persist_fault_state(&self, row_id: &str) -> Result<usize, DemotionLedgerError> {
        let Some(path) = &self.fault_state else {
            return Ok(0);
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| DemotionLedgerError::Read("parent unavailable".into()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(DemotionLedgerError::Read(
                "parent is not a directory".into(),
            ));
        }
        let lock_name = format!(
            ".{}.faults-lock",
            path.file_name()
                .ok_or(DemotionLedgerError::Malformed)?
                .to_string_lossy()
        );
        let _lock = crate::sessions::directives::acquire_gate_ledger_lock_as(
            "demotion fault window",
            &parent.join(lock_name),
        )
        .map_err(|_| DemotionLedgerError::Write("lock unavailable".into()))?;
        let mut state = read_fault_state(path)?;
        let now = now_millis();
        let (previous, window_started_at_ms) = state.get(row_id).map_or((0, now), |fault| {
            let started = fault.window_started_at_ms.unwrap_or(fault.demoted_at_ms);
            if now.saturating_sub(started) > CRASH_DEMOTION_WINDOW.as_millis() {
                (0, now)
            } else {
                (fault.crashes, started)
            }
        });
        let crashes = next_fault_count(previous)?;
        state.insert(
            row_id.to_owned(),
            PersistedFault {
                crashes,
                demoted_at_ms: now,
                window_started_at_ms: Some(window_started_at_ms),
            },
        );
        let bytes = serde_json::to_vec(&state).map_err(|_| DemotionLedgerError::Encode)?;
        if bytes.len() as u64 > MAX_DEMOTION_LEDGER_BYTES {
            return Err(DemotionLedgerError::Capacity);
        }
        let mut tmp = DemotionTemp::create(parent)?;
        let file = tmp
            .file
            .as_mut()
            .ok_or_else(|| DemotionLedgerError::Write("temporary handle unavailable".into()))?;
        file.write_all(&bytes)
            .map_err(|_| DemotionLedgerError::Write("write failed".into()))?;
        file.sync_all()
            .map_err(|_| DemotionLedgerError::SyncTemp("fsync failed".into()))?;
        tmp.file.take();
        fs::rename(&tmp.path, path)
            .map_err(|_| DemotionLedgerError::Rename("replace failed".into()))?;
        tmp.installed = true;
        sync_directory(parent)
            .map_err(|_| DemotionLedgerError::SyncParent("fsync failed".into()))?;
        Ok(crashes)
    }

    fn persist_demotion_with_hooks<FS, FD>(
        &self,
        row_id: &str,
        crashes: usize,
        sync_temp: FS,
        sync_parent: FD,
    ) -> Result<(), DemotionLedgerError>
    where
        FS: Fn(&File) -> std::io::Result<()>,
        FD: Fn(&Path) -> std::io::Result<()>,
    {
        let Some(path) = &self.fault_ledger else {
            return Ok(());
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| DemotionLedgerError::Read("parent unavailable".into()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(DemotionLedgerError::Read(
                "parent is not a directory".into(),
            ));
        }
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(path.file_name().ok_or(DemotionLedgerError::Malformed)?);
        lock_name.push(".demotion-lock");
        let _lock = crate::sessions::directives::acquire_gate_ledger_lock_as(
            "demotion ledger",
            &parent.join(lock_name),
        )
        .map_err(|_| DemotionLedgerError::Write("lock unavailable".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let event = PersistedDemotion {
            row_id: row_id.to_owned(),
            crashes,
            demoted_at_ms: now,
        };
        let event_bytes = serde_json::to_vec(&event).map_err(|_| DemotionLedgerError::Encode)?;
        let mut bytes = normalize_demotion_ledger(&read_demotion_ledger(path)?)?;
        bytes.extend_from_slice(&event_bytes);
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_DEMOTION_LEDGER_BYTES {
            return Err(DemotionLedgerError::Capacity);
        }
        let mut tmp = DemotionTemp::create(parent)?;
        let file = tmp
            .file
            .as_mut()
            .ok_or_else(|| DemotionLedgerError::Write("temporary handle unavailable".into()))?;
        file.write_all(&bytes)
            .map_err(|_| DemotionLedgerError::Write("write failed".into()))?;
        sync_temp(file).map_err(|_| DemotionLedgerError::SyncTemp("fsync failed".into()))?;
        tmp.file.take();
        fs::rename(&tmp.path, path)
            .map_err(|_| DemotionLedgerError::Rename("replace failed".into()))?;
        tmp.installed = true;
        // An install followed by a failed directory fsync is uncertain durability:
        // retain its bytes, but do not acknowledge the demotion or permit this row.
        sync_parent(parent).map_err(|_| DemotionLedgerError::SyncParent("fsync failed".into()))?;
        Ok(())
    }

    fn run_process(
        &self,
        source: &Path,
        args: &[String],
        payload: &[u8],
        cwd: &Path,
        deadline: Instant,
        require_json: bool,
    ) -> Result<RowOutput, RowFailure> {
        self.child_started.set(false);
        self.protocol_refusal.set(false);
        if Instant::now() >= deadline {
            return Err(RowFailure::Timeout);
        }
        #[cfg(unix)]
        if !child_wait_policy_safe() {
            return Err(RowFailure::Crash);
        }
        let mut command = Command::new(&self.node);
        command
            .arg(source)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Each pool child is its own process group. This lets a timeout kill
        // descendants too; otherwise a hostile hook can keep the pipe open
        // after its direct Node process is gone.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        self.environment.apply(&mut command, cwd);
        let mut child = command.spawn().map_err(|_| RowFailure::Crash)?;
        self.child_started.set(true);
        let stdin = child.stdin.take();
        let payload = payload.to_vec();
        let (writer_done_tx, writer_done_rx) = mpsc::channel();
        let _writer = match thread::Builder::new()
            .name("csq-legacy-stdin-writer".into())
            .spawn(move || {
                if let Some(mut stdin) = stdin {
                    let _ = stdin.write_all(&payload);
                }
                let _ = writer_done_tx.send(());
            }) {
            Ok(writer) => writer,
            Err(_) => {
                terminate_child(child, deadline);
                return Err(RowFailure::Crash);
            }
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_child(child, deadline);
            return Err(RowFailure::Crash);
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(child, deadline);
            return Err(RowFailure::Crash);
        };
        let (stdout_done_tx, stdout_done_rx) = mpsc::channel();
        let (stderr_done_tx, stderr_done_rx) = mpsc::channel();
        let _stdout_reader = match thread::Builder::new()
            .name("csq-legacy-stdout-reader".into())
            .spawn(move || {
                let result = read_bounded_pipe(stdout);
                let _ = stdout_done_tx.send(result);
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_child(child, deadline);
                return Err(RowFailure::Crash);
            }
        };
        let _stderr_reader = match thread::Builder::new()
            .name("csq-legacy-stderr-reader".into())
            .spawn(move || {
                let result = read_bounded_pipe(stderr);
                let _ = stderr_done_tx.send(result);
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_child(child, deadline);
                return Err(RowFailure::Crash);
            }
        };
        // Keep the PIDs observed below the direct child.  A descendant can
        // call setsid(2), leave the private process group, and then keep the
        // pipe open after its parent exits.  On supported Unix hosts the
        // bounded process-tree walk lets cleanup kill those descendants while
        // they still belong to this invocation.
        #[cfg(unix)]
        let mut descendants = BTreeSet::new();
        let status = loop {
            match poll_child_exit(&mut child) {
                Ok(Some(status)) => {
                    // The leader is now reaped: its reusable PID must never
                    // seed another process-tree discovery. Only identities
                    // observed while it was still owned remain authorized.
                    #[cfg(unix)]
                    kill_descendants(&descendants);
                    break Ok(status);
                }
                Ok(None) if Instant::now() >= deadline => {
                    #[cfg(unix)]
                    {
                        descendants.extend(process_descendants(child.id()));
                        kill_descendants(&descendants);
                    }
                    kill_process_group(&child);
                    #[cfg(not(unix))]
                    let _ = child.kill();
                    break Err(RowFailure::Timeout);
                }
                Ok(None) => {
                    #[cfg(unix)]
                    descendants.extend(process_descendants(child.id()));
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break Err(RowFailure::Crash),
            }
        };
        let status = match status {
            Ok(status) => status,
            Err(failure) => {
                // `Child::wait` is deliberately not used here: a process
                // that ignored SIGKILL (or a platform cleanup race) must not
                // turn the invocation's deadline into an unbounded wait.
                // Reap it in a detached helper when the same deadline has
                // already elapsed.
                if matches!(failure, RowFailure::Crash) {
                    // A `try_wait` error does not prove that the child is
                    // gone. Kill it before handing ownership to the bounded
                    // reaper, otherwise a setup/OS error can leak a live
                    // subprocess beyond the request.
                    terminate_child(child, deadline);
                } else {
                    reap_child_until_deadline(child, deadline);
                }
                return Err(failure);
            }
        };
        // A process that has no conventional exit code was terminated by a
        // signal. Classify that as a crash before considering its output: a
        // signaled row must enter the repo-pool crash ledger and count toward
        // process-mode demotion. Waiting for a pipe holder here could otherwise
        // turn the same signal into an incomplete result.
        if status.code().is_none() {
            return Err(RowFailure::Crash);
        }
        // Exit 2 is the adapter's explicit refusal status. Record this before
        // draining the pipes: empty/plain output, or a detached holder that
        // prevents a complete drain, must remain a trust-boundary refusal.
        if require_json && status.code() == Some(2) {
            self.protocol_refusal.set(true);
        }
        // Every completion channel uses the original invocation deadline.
        // Dropping the handles instead of joining them is intentional: a
        // detached descendant may retain a pipe forever, and JoinHandle::join
        // would make that unbounded. The reader/writer owns no authority or
        // mutable state after sending its result, so detaching is safe here.
        let _ = writer_done_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let stdout = stdout_done_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Err(()));
        let stderr = stderr_done_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Err(()));
        let (stdout, stderr) = match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => (stdout, stderr),
            _ => return Err(RowFailure::Incomplete),
        };
        let exit_code = status.code().unwrap_or(1);
        if stdout.len().saturating_add(stderr.len()) > MAX_ROW_OUTPUT_BYTES {
            return Err(RowFailure::Incomplete);
        }
        let has_json_reply = single_json_object(&stdout);
        if (exit_code != 0 && exit_code != 2 && !has_json_reply)
            || (require_json && !has_json_reply)
        {
            return Err(RowFailure::Incomplete);
        }
        Ok(RowOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Bind the row admission to the package admission before any child is
    /// started.  `VerifiedBytes::source_path` is only a lexical module name;
    /// its retained bytes and every retained dependency must match the package
    /// snapshot that this runner will materialize.
    fn admitted_relative(&self, source: &VerifiedBytes) -> Result<String, RowFailure> {
        let relative = source
            .source_path()
            .strip_prefix(&self.package.root)
            .ok()
            .and_then(|path| path.to_str())
            .ok_or(RowFailure::Incomplete)?;
        validate_relative(relative).map_err(|_| RowFailure::Incomplete)?;
        self.package_entry_matches(relative, source.as_bytes())?;
        for (declared, dependency) in source.dependencies() {
            validate_relative(declared).map_err(|_| RowFailure::Incomplete)?;
            let dependency_relative = dependency
                .source_path()
                .strip_prefix(&self.package.root)
                .ok()
                .and_then(|path| path.to_str())
                .ok_or(RowFailure::Incomplete)?;
            if dependency_relative != declared {
                return Err(RowFailure::Incomplete);
            }
            self.package_entry_matches(declared, dependency.as_bytes())?;
        }
        Ok(relative.to_owned())
    }

    fn package_entry_matches(&self, relative: &str, admitted: &[u8]) -> Result<(), RowFailure> {
        let package_file = self
            .package
            .files
            .get(relative)
            .ok_or(RowFailure::Incomplete)?;
        let package_bytes = self
            .package
            .verified_bytes
            .get(relative)
            .ok_or(RowFailure::Incomplete)?;
        if package_file.bytes != package_bytes.len() as u64
            || digest(package_bytes) != package_file.sha256
            || package_bytes.len() != admitted.len()
            || digest(admitted) != package_file.sha256
            || package_bytes.as_ref() != admitted
        {
            return Err(RowFailure::Incomplete);
        }
        Ok(())
    }
}

fn read_demotion_ledger(path: &Path) -> Result<Vec<u8>, DemotionLedgerError> {
    crate::sessions::directives::read_regular_bounded_as(
        "demotion ledger",
        path,
        MAX_DEMOTION_LEDGER_BYTES,
    )
    .map(|text| text.unwrap_or_default().into_bytes())
    .map_err(|_| DemotionLedgerError::Read("bounded regular read refused".into()))
}

fn read_fault_state(path: &Path) -> Result<BTreeMap<String, PersistedFault>, DemotionLedgerError> {
    let bytes = read_demotion_ledger(path)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(BTreeMap::new());
    }
    let value = registry::strict_json(&bytes).map_err(|_| DemotionLedgerError::Malformed)?;
    let state: BTreeMap<String, PersistedFault> =
        serde_json::from_value(value).map_err(|_| DemotionLedgerError::Malformed)?;
    if state
        .values()
        .any(|fault: &PersistedFault| fault.crashes == usize::MAX)
    {
        return Err(DemotionLedgerError::Malformed);
    }
    Ok(state)
}

/// Keep the maximum counter representable as an input state, but refuse the
/// next increment before it can wrap or serialize an unprocessable state.
fn next_fault_count(current: usize) -> Result<usize, DemotionLedgerError> {
    current
        .checked_add(1)
        .filter(|next| *next < usize::MAX)
        .ok_or(DemotionLedgerError::Malformed)
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn load_demotion_rows(bytes: &[u8]) -> Result<BTreeSet<String>, DemotionLedgerError> {
    let mut rows = BTreeSet::new();
    let normalized = normalize_demotion_ledger(bytes)?;
    rows.extend(
        parse_demotion_events(&normalized)?
            .into_iter()
            .map(|event| event.row_id),
    );
    Ok(rows)
}

fn normalize_demotion_ledger(bytes: &[u8]) -> Result<Vec<u8>, DemotionLedgerError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    if parse_demotion_events(bytes).is_ok() {
        let mut normalized = bytes.to_vec();
        if !normalized.ends_with(b"\n") {
            normalized.push(b'\n');
        }
        return Ok(normalized);
    }
    let entries = serde_json::from_slice::<BTreeMap<String, PersistedFault>>(bytes)
        .map_err(|_| DemotionLedgerError::Malformed)?;
    let mut normalized = Vec::new();
    for (row_id, fault) in entries {
        let event = PersistedDemotion {
            row_id,
            crashes: fault.crashes,
            demoted_at_ms: fault.window_started_at_ms.unwrap_or(fault.demoted_at_ms),
        };
        normalized.extend(serde_json::to_vec(&event).map_err(|_| DemotionLedgerError::Encode)?);
        normalized.push(b'\n');
    }
    Ok(normalized)
}

fn parse_demotion_events(bytes: &[u8]) -> Result<Vec<PersistedDemotion>, DemotionLedgerError> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .map(|line| serde_json::from_slice(line).map_err(|_| DemotionLedgerError::Malformed))
        .collect()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?
        .sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory fsync is unavailable on this platform",
    ))
}

/// Accept exactly one JSON object, with optional surrounding whitespace. The
/// streaming deserializer rejects a second value or trailing non-whitespace;
/// a prefix parse would let a child smuggle an unvalidated second reply.
fn single_json_object(bytes: &[u8]) -> bool {
    let mut values = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    matches!(values.next(), Some(Ok(value)) if value.is_object()) && values.next().is_none()
}

/// Observe completion without releasing the owned leader's PID, then close its
/// process group before reaping. Sole waiting ownership and an unchanged SIGCHLD
/// disposition keep that PID from being reused between observation and signaling.
fn poll_child_exit(
    child: &mut std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    #[cfg(unix)]
    {
        if !child_exited_unreaped(child)? {
            return Ok(None);
        }
        kill_process_group(child);
    }
    child.try_wait()
}

#[cfg(unix)]
fn child_wait_policy_safe() -> bool {
    // SAFETY: this only queries the current process disposition into initialized
    // plain data; it never installs a handler or changes signal policy.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
            && action.sa_sigaction != libc::SIG_IGN
            && action.sa_flags & libc::SA_NOCLDWAIT == 0
    }
}

#[cfg(unix)]
fn child_exited_unreaped(child: &std::process::Child) -> std::io::Result<bool> {
    // SAFETY: zeroed siginfo_t is valid, and waitid with WNOHANG|WNOWAIT
    // neither blocks nor consumes our owned child's exit disposition.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let result = libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if result == -1 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            };
        }
        Ok(info.si_pid() != 0)
    }
}

impl RowRunner for NodeRowRunner {
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
        if self.ledger_unavailable {
            return Err(RowFailure::DemotionLedger);
        }
        let relative = self.admitted_relative(request.source)?;
        // Materialize for this invocation only.  A child can write its own
        // 0600 private snapshot, so retaining it across calls would make a
        // previous row invocation an execution authority for the next one.
        let runtime = RuntimeMaterialization::create(&self.package.verified_bytes)
            .map_err(|error| runtime_unavailable(&error))?;
        let source = runtime.entry(&relative);
        let result = self.run_process(
            &source,
            &[],
            &serde_json::to_vec(request.payload).map_err(|_| RowFailure::Incomplete)?,
            request.cwd,
            request.deadline,
            false,
        );
        if matches!(result, Err(RowFailure::Crash))
            && request.row.pool == Pool::Repo
            && self.note_crash(&request.row.id).is_err()
        {
            return Err(RowFailure::DemotionLedger);
        }
        result
    }
}

#[cfg(unix)]
fn kill_process_group(child: &std::process::Child) {
    // Failed ownership probes (especially ECHILD after an external reaper)
    // cannot authorize a signal. A running child or unreaped zombie still
    // reserves the PID used as the group ID under sole-waiter ownership.
    if child_exited_unreaped(child).is_err() {
        return;
    }
    // SAFETY: `process_group(0)` made the child its own group leader before
    // spawn; the negative pid targets only that group, never the caller.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(unix)]
const MAX_TRACKED_DESCENDANTS: usize = 1024;

/// A descendant PID is only a reusable handle. Keep the process start
/// identity observed alongside it so cleanup cannot signal a later process
/// after the original descendant exits and the kernel recycles its PID.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DescendantIdentity {
    pid: libc::pid_t,
    started_at: u64,
}

#[cfg(unix)]
fn kill_descendants(pids: &BTreeSet<DescendantIdentity>) {
    // Kill descendants before the group leader.  This matters for a child
    // that has already escaped the group with setsid(2): once the leader is
    // dead, the escaped child may be reparented and no longer discoverable.
    for identity in pids {
        if identity.pid > 1
            && crate::sessions::ancestor_start(identity.pid as u32) == Some(identity.started_at)
        {
            // SAFETY: the PID's current start identity still matches the
            // descendant observed for this invocation. SIGKILL is bounded
            // cleanup for a timed-out or completed hook.
            unsafe {
                libc::kill(identity.pid, libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
fn process_descendants(root: u32) -> Vec<DescendantIdentity> {
    let root = root as libc::pid_t;
    let mut queue = vec![root];
    let mut seen = BTreeSet::new();
    let mut descendants = Vec::new();
    while let Some(parent) = queue.pop() {
        for child in direct_children(parent) {
            if !seen.insert(child) {
                continue;
            }
            // A PID whose identity cannot be read is not safe to retain as a
            // cleanup target. The fail-closed choice is to leave it alone;
            // the private process group still covers ordinary descendants.
            let Some(started_at) = crate::sessions::ancestor_start(child as u32) else {
                continue;
            };
            descendants.push(DescendantIdentity {
                pid: child,
                started_at,
            });
            if descendants.len() >= MAX_TRACKED_DESCENDANTS {
                return descendants;
            }
            queue.push(child);
        }
    }
    descendants
}

#[cfg(target_os = "linux")]
fn direct_children(parent: libc::pid_t) -> Vec<libc::pid_t> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let parent = parent.to_string();
    let mut children = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The command name may contain spaces and ')' characters.  The
        // parent-PID field is the second token after the final ") ".
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            continue;
        };
        if fields.split_whitespace().nth(1) == Some(parent.as_str()) {
            if let Ok(pid) = name.parse() {
                children.push(pid);
            }
        }
    }
    children
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listchildpids(
        ppid: libc::pid_t,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn direct_children(parent: libc::pid_t) -> Vec<libc::pid_t> {
    let mut pids = vec![0; 32];
    loop {
        // Apple's libproc.c wrapper already divides proc_listpids' byte
        // result by sizeof(int): this API returns a PID count even though
        // its buffer size argument is expressed in bytes.
        // SAFETY: pids is initialized writable storage of the advertised size.
        let count = unsafe {
            proc_listchildpids(
                parent,
                pids.as_mut_ptr().cast(),
                (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
            )
        };
        if count < 0 {
            return Vec::new();
        }
        let count = count as usize;
        if count < pids.len() {
            pids.truncate(count);
            return pids;
        }
        if pids.len() >= MAX_TRACKED_DESCENDANTS {
            pids.truncate(MAX_TRACKED_DESCENDANTS);
            return pids;
        }
        pids.resize((pids.len() * 2).min(MAX_TRACKED_DESCENDANTS), 0);
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn direct_children(_parent: libc::pid_t) -> Vec<libc::pid_t> {
    Vec::new()
}

#[cfg(not(unix))]
fn kill_process_group(_child: &std::process::Child) {}

fn read_bounded_pipe(reader: impl Read) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_ROW_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_ROW_OUTPUT_BYTES {
        return Err(());
    }
    Ok(bytes)
}

/// Kill and reap a child when setup fails before the main wait loop starts.
/// The same deadline governs cleanup, so a thread-table or pipe setup failure
/// cannot turn into an unbounded process wait.
fn terminate_child(child: std::process::Child, deadline: Instant) {
    kill_process_group(&child);
    #[cfg(not(unix))]
    let mut child = child;
    #[cfg(not(unix))]
    let _ = child.kill();
    reap_child_until_deadline(child, deadline);
}

/// Reap a child without allowing cleanup to extend the invocation deadline.
/// A direct `Child::wait` is allowed only while the deadline remains live;
/// after that point ownership moves to a detached reaper. The reaper is
/// best-effort and has no path back into the request, so a hostile process
/// cannot hold the hook runner open through cleanup.
fn reap_child_until_deadline(mut child: std::process::Child, deadline: Instant) {
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => {
                let _ = thread::Builder::new()
                    .name("csq-legacy-child-reaper".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(2)),
        }
    }
}

/// Event-level runtime invocation. This is the API used when the immutable
/// Loom runtime is activated: callers invoke at most one child for each
/// `(Pool, Event)` pair and send the event payload once on stdin.
pub struct NodePoolRunner {
    package: VerifiedPackage,
    entry: String,
    runtime_bytes: BTreeMap<String, Box<[u8]>>,
    node: PathBuf,
    environment: NodeEnvironment,
    fault_ledger: Option<PathBuf>,
    demoted: BTreeSet<String>,
    last_child_started: bool,
    last_protocol_refusal: bool,
    started: BTreeSet<(Pool, Event)>,
}

/// One row result emitted by the authenticated pool runtime.  The bytes are
/// retained so the ordinary dispatch fold can apply the same policy as the
/// row runner without starting another child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRowOutcome {
    pub row_id: String,
    pub source_sha256: String,
    pub status: String,
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolExecution {
    /// True only after the bounded subprocess returned a complete outer reply.
    pub child_started: bool,
    pub rows: Vec<PoolRowOutcome>,
}

/// A pool error always denies the whole invocation. Callers must never convert
/// it into per-row `continue` outcomes or replay the interrupted child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRunError {
    /// A named whole-call refusal. Callers must surface this refusal to the
    /// user; they must not synthesize per-row continue outcomes from it.
    Refusal(RowFailure),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolReply {
    schema: String,
    pool: String,
    event: String,
    payload_sha256: String,
    status: String,
    rows: Vec<PoolReplyRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolReplyRow {
    id: String,
    source_sha256: String,
    status: String,
    timeout_secs: Option<u64>,
    exit_code: i32,
    stdout_b64: String,
    stderr_b64: String,
}

impl NodePoolRunner {
    pub fn new(package: VerifiedPackage, entry: impl AsRef<Path>) -> Result<Self, PackageError> {
        if cfg!(windows) {
            return Err(PackageError::UnsupportedPlatform);
        }
        let entry = package.root.join(entry.as_ref());
        if !entry.starts_with(&package.root) || !package.is_runtime_entry(&entry) {
            return Err(PackageError::RuntimeClosure);
        }
        let relative = package
            .canonical_relative(&entry)
            .ok_or(PackageError::RuntimeClosure)?;
        let runtime_bytes = package.verified_bytes.clone();
        Ok(Self {
            package,
            entry: relative,
            runtime_bytes,
            node: PathBuf::from("node"),
            environment: NodeEnvironment::default(),
            fault_ledger: None,
            demoted: BTreeSet::new(),
            last_child_started: false,
            last_protocol_refusal: false,
            started: BTreeSet::new(),
        })
    }

    /// Activation constructor. `source_entry` must have been explicitly
    /// mapped and verified by `VerifiedPackage::verify_materialized`.
    pub fn new_materialized(
        package: VerifiedPackage,
        source_entry: &str,
    ) -> Result<Self, PackageError> {
        if cfg!(windows) {
            return Err(PackageError::UnsupportedPlatform);
        }
        if !package.materialized_runtime_union.contains(source_entry)
            || package.materialized_path(source_entry).is_none()
            || !package.materialized_bytes.contains_key(source_entry)
        {
            return Err(PackageError::RuntimeClosure);
        }
        let runtime_bytes = package.materialized_bytes.clone();
        Ok(Self {
            package,
            entry: source_entry.to_owned(),
            runtime_bytes,
            node: PathBuf::from("node"),
            environment: NodeEnvironment::default(),
            fault_ledger: None,
            demoted: BTreeSet::new(),
            last_child_started: false,
            last_protocol_refusal: false,
            started: BTreeSet::new(),
        })
    }

    pub fn with_node(mut self, node: impl Into<PathBuf>) -> Self {
        self.node = node.into();
        self
    }

    pub fn with_environment(mut self, environment: NodeEnvironment) -> Self {
        self.environment = environment;
        self
    }

    /// Persist crash demotions for every pool invocation.  The ledger is
    /// loaded once at construction and passed to the row runner created for
    /// each event; a pool child must never silently discard this policy.
    pub fn with_fault_ledger(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if let Ok(bytes) = read_demotion_ledger(&path) {
            if let Ok(rows) = load_demotion_rows(&bytes) {
                self.demoted.extend(rows);
            }
        }
        self.fault_ledger = Some(path);
        self
    }

    pub fn started_pairs(&self) -> impl Iterator<Item = &(Pool, Event)> {
        self.started.iter()
    }

    /// A durable repo-pool demotion must be observable by the caller so it can
    /// route that row through the per-row process runner.  Returning Process
    /// here is an execution decision, not permission to ignore a corrupt
    /// ledger; unreadable ledger state still refuses in `run_event_rows`.
    pub fn execution_mode(&self, row_id: &str, pool: Pool) -> ExecutionMode {
        if pool == Pool::Repo && self.demoted.contains(row_id) {
            ExecutionMode::Process
        } else {
            ExecutionMode::Pool
        }
    }

    /// Validate durable pool state before the caller starts its first child.
    /// This is separate from `execution_mode`: a corrupt or unreadable ledger
    /// must not be mistaken for an empty ledger with all rows still poolable.
    pub fn preflight_ledger(&self) -> Result<(), RowFailure> {
        let Some(path) = &self.fault_ledger else {
            return Ok(());
        };
        read_demotion_ledger(path)
            .and_then(|bytes| load_demotion_rows(&bytes))
            .map_err(|_| RowFailure::DemotionLedger)?;
        read_fault_state(&path.with_extension("faults")).map_err(|_| RowFailure::DemotionLedger)?;
        Ok(())
    }

    pub fn run_event(
        &mut self,
        pool: Pool,
        event: Event,
        payload: &[u8],
        cwd: &Path,
        deadline: Instant,
    ) -> Result<RowOutput, RowFailure> {
        self.run_event_output(pool, event, payload, cwd, deadline)
    }

    /// Execute one authenticated runtime and bind its complete, ordered row
    /// envelope to the caller's mapping.  A malformed, incomplete, duplicate,
    /// or extra row is a refusal; callers must never duplicate one aggregate
    /// child result across rows.
    pub fn run_event_rows(
        &mut self,
        binding: &RuntimePoolBinding,
        row_contracts: &[PoolRowContract],
        payload_sha256: &str,
        payload: &[u8],
        cwd: &Path,
        deadline: Instant,
    ) -> Result<PoolExecution, PoolRunError> {
        // Validate the complete authenticated request before materializing or
        // spawning the pool child.  A malformed binding must have no effects.
        if binding.pool == Pool::Repo
            && binding
                .row_ids
                .iter()
                .any(|row_id| self.demoted.contains(row_id))
        {
            return Err(PoolRunError::Refusal(RowFailure::DemotionLedger));
        }
        if payload_sha256.len() != 64
            || !payload_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || registry::sha256(payload) != payload_sha256
        {
            return Err(PoolRunError::Refusal(RowFailure::Incomplete));
        }
        if row_contracts.len() != binding.row_ids.len()
            || row_contracts
                .iter()
                .zip(&binding.row_ids)
                .any(|(contract, id)| contract.id != *id)
        {
            return Err(PoolRunError::Refusal(RowFailure::Incomplete));
        }
        let mut expected = BTreeSet::new();
        for contract in row_contracts {
            if !expected.insert(contract.id.clone())
                || contract.source_path.is_empty()
                || contract.source_path == self.entry
                || contract.source_sha256.len() != 64
                || !contract
                    .source_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                // A pool contract is a claim about bytes admitted by the
                // package, not merely a child-reported digest.  A registry
                // row whose source is absent from this package must refuse
                // before materialization or spawn; otherwise a missing row
                // can disappear into a continue-style aggregate result.
                || !self
                    .package
                    .files
                    .values()
                    .any(|file| file.sha256 == contract.source_sha256)
                || self
                    .runtime_bytes
                    .get(&contract.source_path)
                    .is_none_or(|bytes| registry::sha256(bytes) != contract.source_sha256)
            {
                return Err(PoolRunError::Refusal(RowFailure::Incomplete));
            }
        }
        let output = match self.run_event_output_with_context(
            binding.pool,
            binding.event,
            payload,
            cwd,
            deadline,
            PoolRequestContext {
                payload_sha256: Some(payload_sha256),
                row_contracts: Some(row_contracts),
            },
        ) {
            Ok(output) => output,
            Err(failure) => {
                if self.last_protocol_refusal || self.last_child_started {
                    return Err(self.incomplete_pool_refusal(&binding.row_ids, failure));
                }
                return Err(PoolRunError::Refusal(failure));
            }
        };
        // Exit status belongs to the outer transport.  A nonzero status must
        // never be treated as an authenticated row envelope: otherwise a
        // child could pair an exit-2 refusal with forged permissive rows.
        if output.exit_code != 0 {
            return Err(self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete));
        }
        let value = registry::strict_json(&output.stdout)
            .map_err(|_| self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete))?;
        let reply: PoolReply = serde_json::from_value(value)
            .map_err(|_| self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete))?;
        if reply.schema != "csq.gate.pool.v1"
            || reply.pool != pool_name(binding.pool)
            || reply.event != binding.event.as_str()
            || reply.payload_sha256 != payload_sha256
            || reply.status != "complete"
            || reply.rows.len() != binding.row_ids.len()
        {
            return Err(self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete));
        }
        let mut rows = Vec::with_capacity(reply.rows.len());
        let mut seen = BTreeSet::new();
        for (expected, row) in binding.row_ids.iter().zip(reply.rows) {
            if row.id != *expected
                || row_contracts
                    .iter()
                    .find(|contract| contract.id == *expected)
                    .is_none_or(|contract| {
                        contract.source_sha256 != row.source_sha256
                            || contract.timeout_secs != row.timeout_secs
                    })
                || !seen.insert(row.id.clone())
            {
                return Err(self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete));
            }
            let stdout = BASE64.decode(row.stdout_b64.as_bytes()).map_err(|_| {
                self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete)
            })?;
            let stderr = BASE64.decode(row.stderr_b64.as_bytes()).map_err(|_| {
                self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete)
            })?;
            if !matches!(
                row.status.as_str(),
                "executed" | "timeout" | "crash" | "incomplete"
            ) || stdout.len().saturating_add(stderr.len()) > MAX_ROW_OUTPUT_BYTES
            {
                return Err(self.incomplete_pool_refusal(&binding.row_ids, RowFailure::Incomplete));
            }
            rows.push(PoolRowOutcome {
                row_id: row.id,
                source_sha256: row.source_sha256,
                status: row.status,
                exit_code: row.exit_code,
                stdout,
                stderr,
            });
        }
        for row in &rows {
            if row.status == "crash" {
                self.record_pool_crash(std::slice::from_ref(&row.row_id))
                    .map_err(PoolRunError::Refusal)?;
            }
        }
        Ok(PoolExecution {
            child_started: true,
            rows,
        })
    }

    fn incomplete_pool_refusal(&mut self, row_ids: &[String], failure: RowFailure) -> PoolRunError {
        if self.last_child_started
            && matches!(
                failure,
                RowFailure::Crash | RowFailure::Timeout | RowFailure::Incomplete
            )
            && self.record_pool_crash(row_ids).is_err()
        {
            return PoolRunError::Refusal(RowFailure::DemotionLedger);
        }
        PoolRunError::Refusal(failure)
    }

    fn record_pool_crash(&mut self, row_ids: &[String]) -> Result<(), RowFailure> {
        let Some(path) = &self.fault_ledger else {
            return Ok(());
        };
        let mut tracker = NodeRowRunner::new(self.package.clone()).with_fault_ledger(path);
        for row_id in row_ids {
            tracker
                .note_crash(row_id)
                .map_err(|_| RowFailure::DemotionLedger)?;
            if tracker.execution_mode(row_id, Pool::Repo) == ExecutionMode::Process {
                self.demoted.insert(row_id.clone());
            }
        }
        Ok(())
    }

    fn run_event_output(
        &mut self,
        pool: Pool,
        event: Event,
        payload: &[u8],
        cwd: &Path,
        deadline: Instant,
    ) -> Result<RowOutput, RowFailure> {
        self.run_event_output_with_context(
            pool,
            event,
            payload,
            cwd,
            deadline,
            PoolRequestContext::default(),
        )
    }

    fn run_event_output_with_context(
        &mut self,
        pool: Pool,
        event: Event,
        payload: &[u8],
        cwd: &Path,
        deadline: Instant,
        context: PoolRequestContext<'_>,
    ) -> Result<RowOutput, RowFailure> {
        self.last_child_started = false;
        self.last_protocol_refusal = false;
        if !self.started.insert((pool, event)) {
            return Err(RowFailure::Incomplete);
        }
        let ledger_unavailable = self.fault_ledger.as_ref().is_some_and(|path| {
            read_demotion_ledger(path)
                .and_then(|bytes| load_demotion_rows(&bytes))
                .is_err()
                || read_fault_state(&path.with_extension("faults")).is_err()
        });
        if ledger_unavailable {
            return Err(RowFailure::DemotionLedger);
        }
        // Materialize a private runtime for this invocation only.  A previous
        // child can write a 0600 snapshot; retaining it across events would
        // turn that child-owned file into the next event's authority.
        let runtime = self
            .package
            .private_runtime(&self.runtime_bytes)
            .map_err(|error| runtime_unavailable(&error))?;
        let entry = runtime.entry(&self.entry);
        let runner = NodeRowRunner {
            package: self.package.clone(),
            node: self.node.clone(),
            environment: self.environment.clone(),
            faults: HashMap::new(),
            demoted: BTreeSet::new(),
            fault_ledger: self.fault_ledger.clone(),
            fault_state: self
                .fault_ledger
                .as_ref()
                .map(|path| path.with_extension("faults")),
            ledger_unavailable,
            child_started: Cell::new(false),
            protocol_refusal: Cell::new(false),
        };
        let mut args = vec![event.as_str().to_owned(), pool_name(pool).to_owned()];
        if let Some(payload_sha256) = context.payload_sha256 {
            args.push(payload_sha256.to_owned());
        }
        if let Some(row_contracts) = context.row_contracts {
            args.push(serde_json::to_string(row_contracts).map_err(|_| RowFailure::Incomplete)?);
        }
        let result = runner.run_process(&entry, &args, payload, cwd, deadline, true);
        self.last_child_started = runner.child_started.get();
        self.last_protocol_refusal = runner.protocol_refusal.get();
        result
    }
}

#[derive(Clone, Copy, Default)]
struct PoolRequestContext<'a> {
    payload_sha256: Option<&'a str>,
    row_contracts: Option<&'a [PoolRowContract]>,
}

pub fn pool_name(pool: Pool) -> &'static str {
    match pool {
        Pool::Template => "template",
        Pool::Repo => "repo",
    }
}

/// Adapter used after a pool child has returned its complete row envelope.
/// It never starts a child and refuses a row whose admitted source digest does
/// not match the envelope that supplied its output.
pub struct PoolCachedRunner {
    outcomes: BTreeMap<String, PoolRowOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PoolRowContract {
    pub id: String,
    /// Canonical UTF-8 repo-relative path of the admitted row source.
    pub source_path: String,
    pub source_sha256: String,
    pub timeout_secs: Option<u64>,
}

impl PoolCachedRunner {
    pub fn new(outcomes: impl IntoIterator<Item = PoolRowOutcome>) -> Result<Self, RowFailure> {
        let mut indexed = BTreeMap::new();
        for outcome in outcomes {
            if indexed.insert(outcome.row_id.clone(), outcome).is_some() {
                return Err(RowFailure::Incomplete);
            }
        }
        Ok(Self { outcomes: indexed })
    }
}

impl RowRunner for PoolCachedRunner {
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
        let Some(outcome) = self.outcomes.get(&request.row.id) else {
            return Err(RowFailure::Incomplete);
        };
        if registry::sha256(request.source.as_bytes()) != outcome.source_sha256 {
            return Err(RowFailure::Incomplete);
        }
        if outcome.status != "executed" {
            return Err(match outcome.status.as_str() {
                "timeout" => RowFailure::Timeout,
                "crash" => RowFailure::Crash,
                _ => RowFailure::Incomplete,
            });
        }
        Ok(RowOutput {
            exit_code: outcome.exit_code,
            stdout: outcome.stdout.clone(),
            stderr: outcome.stderr.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::gate::pin::Pin;
    #[cfg(unix)]
    use crate::gate::registry::{canonical_content_bytes, sha256, PRECEDENCE};
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir_all(root.join(".claude/hooks")).unwrap();
        let node = root.join("node-fixture");
        fs::write(
            &node,
            b"#!/bin/sh\nif [ -n \"${HOME-}\" ]; then printf 'home-leak'; else cat; fi\nprintf '\\n' >&2\n",
        )
        .unwrap();
        #[cfg(unix)]
        #[cfg(unix)]
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let source = root.join(".claude/hooks/row.js");
        fs::write(&source, b"ignored by fixture node").unwrap();
        let reviewer_pin = root.join("reviewer-settings.json");
        fs::write(&reviewer_pin, b"reviewer pin").unwrap();
        let files = [&node, &source];
        let file_json: Vec<_> = files
            .iter()
            .map(|path| {
                let rel = path.strip_prefix(&root).unwrap().to_string_lossy();
                let bytes = fs::read(path).unwrap();
                serde_json::json!({"path": rel, "sha256": digest(&bytes), "bytes": bytes.len()})
            })
            .collect();
        let pins: Vec<_> = files
            .iter()
            .map(|path| {
                let rel = path.strip_prefix(&root).unwrap().to_string_lossy();
                serde_json::json!({"path": rel, "sha256": digest(&fs::read(path).unwrap()), "source":"runtime_closure"})
            })
            .collect();
        let reviewer_bytes = fs::read(&reviewer_pin).unwrap();
        let mut pins = pins;
        pins.push(serde_json::json!({
            "path": "reviewer-settings.json",
            "sha256": digest(&reviewer_bytes),
            "source": "reviewer_pin"
        }));
        let manifest = serde_json::json!({
            "package":"loom-hook-runtime", "version":"1.0.0-20261007",
            "proposed_path":".claude/hook-runtime/1.0.0-20261007/",
            "invocation":"node runtime/dispatch.cjs Event", "commit_sha":"a".repeat(40),
            "commit_sha_convention":"pinned", "head_at_generation":"b".repeat(40),
            "runtime_clean_at_generation":true, "file_count":2, "files":file_json,
            "verification":{"pins":pins,"runtime_closure":{"entry_points":["node-fixture",".claude/hooks/row.js"],"reached_files":2,"gaps":[],"method":"lexical walk"}}
        });
        let manifest_path = root.join("PACKAGE-MANIFEST.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (dir, root, manifest_path)
    }

    /// A package-sized fixture for the activation denominator. The ordinary
    /// unit fixture intentionally stays small, but the acceptance path must
    /// prove that it binds every package file and every reached runtime file,
    /// rather than passing with the two-file fixture above.
    fn full_closure_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        Vec<String>,
        Vec<String>,
    ) {
        const PACKAGE_FILE_COUNT: usize = 22;
        const RUNTIME_FILE_COUNT: usize = 15;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        let runtime_paths: Vec<_> = (0..RUNTIME_FILE_COUNT)
            .map(|index| format!("runtime/entry-{index:02}.js"))
            .collect();
        let support_paths: Vec<_> = (0..(PACKAGE_FILE_COUNT - RUNTIME_FILE_COUNT))
            .map(|index| format!("support/asset-{index:02}.dat"))
            .collect();
        let mut package_paths = runtime_paths.clone();
        package_paths.extend(support_paths);

        for path in &package_paths {
            let destination = root.join(path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(
                destination,
                format!("full-closure-fixture:{path}\n").as_bytes(),
            )
            .unwrap();
        }

        let file_json: Vec<_> = package_paths
            .iter()
            .map(|path| {
                let bytes = fs::read(root.join(path)).unwrap();
                serde_json::json!({
                    "path": path,
                    "sha256": digest(&bytes),
                    "bytes": bytes.len(),
                })
            })
            .collect();
        let pins: Vec<_> = runtime_paths
            .iter()
            .map(|path| {
                let bytes = fs::read(root.join(path)).unwrap();
                serde_json::json!({
                    "path": path,
                    "sha256": digest(&bytes),
                    "source": "runtime_closure",
                })
            })
            .collect();
        let manifest = serde_json::json!({
            "package": "loom-hook-runtime",
            "version": "1.0.0-20261007",
            "proposed_path": ".claude/hook-runtime/1.0.0-20261007/",
            "invocation": "node runtime/dispatch.cjs Event",
            "commit_sha": "a".repeat(40),
            "commit_sha_convention": "pinned",
            "head_at_generation": "b".repeat(40),
            "runtime_clean_at_generation": true,
            "file_count": PACKAGE_FILE_COUNT,
            "files": file_json,
            "verification": {
                "pins": pins,
                "runtime_closure": {
                    "entry_points": runtime_paths,
                    "reached_files": RUNTIME_FILE_COUNT,
                    "gaps": [],
                    "method": "lexical walk",
                },
            },
        });
        let manifest_path = root.join("PACKAGE-MANIFEST.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (dir, root, manifest_path, package_paths, runtime_paths)
    }

    #[cfg(unix)]
    fn materialized_full_package_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        VerifiedPackage,
        Vec<String>,
        Vec<String>,
    ) {
        let (dir, root, manifest, package_paths, runtime_paths) = full_closure_fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let materialized = root.join("materialized");
        fs::create_dir_all(&materialized).unwrap();
        let mut mappings = BTreeMap::new();
        for source in &runtime_paths {
            let destination = materialized.join(source.replace('/', "_"));
            fs::copy(root.join(source), &destination).unwrap();
            mappings.insert(source.clone(), destination);
        }
        let package = package
            .verify_materialized(mappings, &runtime_paths)
            .unwrap();
        (dir, root, package, package_paths, runtime_paths)
    }

    #[test]
    fn canonical_membership_retains_manifest_keys_and_root_confinement() {
        let (_dir, root, manifest, package_paths, runtime_paths) = full_closure_fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        for key in &package_paths {
            let path = root.join(key);
            assert_eq!(
                package.canonical_relative(&path).as_deref(),
                Some(key.as_str())
            );
            assert_eq!(package.is_runtime_entry(&path), runtime_paths.contains(key));
        }
        let outside = root.parent().unwrap().join("outside.js");
        fs::write(&outside, b"outside the verified package").unwrap();
        assert!(package.canonical_relative(&outside).is_none());
        assert!(!package.contains(&outside));
        assert!(package.canonical_relative(&root).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_membership_refuses_backslash_filename_alias() {
        let (_dir, root, manifest, _, _) = full_closure_fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let alias = root.join("runtime\\entry-00.js");
        fs::write(&alias, b"not a manifest path").unwrap();
        assert!(package.canonical_relative(&alias).is_none());
        assert!(!package.contains(&alias));
    }

    #[test]
    fn verifier_binds_22_package_files_and_15_runtime_closure_files() {
        let (_dir, root, manifest, package_paths, runtime_paths) = full_closure_fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();

        assert_eq!(package.manifest().file_count, 22);
        assert_eq!(package.files.len(), 22);
        assert_eq!(runtime_paths.len(), 15);
        for path in &package_paths {
            assert!(
                package.contains(&root.join(path)),
                "package file missing: {path}"
            );
        }

        let closure_pins: BTreeSet<_> = package
            .manifest()
            .verification
            .pins
            .iter()
            .filter(|pin| pin.source == "runtime_closure")
            .map(|pin| pin.path.as_str())
            .collect();
        let expected_runtime: BTreeSet<_> = runtime_paths.iter().map(String::as_str).collect();
        assert_eq!(closure_pins, expected_runtime);
        assert_eq!(
            package
                .manifest()
                .verification
                .runtime_closure
                .entry_points
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_runtime
        );

        let materialized = root.join("materialized");
        fs::create_dir_all(&materialized).unwrap();
        let mut mappings = BTreeMap::new();
        for source in &runtime_paths {
            let destination = materialized.join(source.replace('/', "_"));
            fs::copy(root.join(source), &destination).unwrap();
            mappings.insert(source.clone(), destination);
        }
        let package = package
            .verify_materialized(mappings, &runtime_paths)
            .unwrap();
        assert!(package.verify_runtime_union(&runtime_paths).is_ok());
        for source in &runtime_paths {
            assert!(package.materialized_path(source).is_some());
        }
    }

    #[cfg(unix)]
    #[test]
    fn materialized_pool_refuses_support_only_row_digest_before_child() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, package, package_paths, runtime_paths) =
            materialized_full_package_fixture();
        let support = package_paths
            .iter()
            .find(|path| path.starts_with("support/"))
            .unwrap();
        let mut runner = NodePoolRunner::new_materialized(package, &runtime_paths[0]).unwrap();
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["support-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "support-row".into(),
            source_path: (*support).clone(),
            source_sha256: sha256(&fs::read(root.join(support)).unwrap()),
            timeout_secs: Some(2),
        }];
        let payload = br#"{}"#;
        let result = runner.run_event_rows(
            &binding,
            &contracts,
            &sha256(payload),
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            result,
            Err(PoolRunError::Refusal(RowFailure::Incomplete))
        ));
        assert_eq!(runner.started_pairs().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn materialized_pool_refuses_runtime_entry_as_row_before_child() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, package, _package_paths, runtime_paths) =
            materialized_full_package_fixture();
        let entry = runtime_paths[0].clone();
        let mut runner = NodePoolRunner::new_materialized(package, &entry).unwrap();
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["entry-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "entry-row".into(),
            source_path: entry.clone(),
            source_sha256: sha256(&fs::read(root.join(&entry)).unwrap()),
            timeout_secs: Some(2),
        }];
        let payload = br#"{}"#;
        let result = runner.run_event_rows(
            &binding,
            &contracts,
            &sha256(payload),
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            result,
            Err(PoolRunError::Refusal(RowFailure::Incomplete))
        ));
        assert_eq!(runner.started_pairs().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn verifier_checks_every_file_and_runtime_closure_before_runner_exists() {
        let (_dir, root, manifest) = fixture();
        let verified = VerifiedPackage::verify(&manifest, &root).unwrap();
        assert_eq!(verified.manifest().file_count, 2);
        assert!(verified.contains(&root.join("node-fixture")));
        fs::write(root.join("node-fixture"), b"tampered").unwrap();
        assert!(matches!(
            VerifiedPackage::verify(&manifest, &root),
            Err(PackageError::HashMismatch)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn row_runner_executes_admitted_row_and_dependency_after_repository_mutation() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        let hooks = root.join(".claude/hooks");
        fs::create_dir_all(&hooks).unwrap();
        let row_path = hooks.join("row.js");
        let dep_path = hooks.join("dep.sh");
        // The child owns its private 0400 snapshot and can chmod it before a
        // rewrite. Requiring that explicit step also works for non-root runners.
        let admitted_row =
            b"#!/bin/sh\nIFS= read -r dependency < \"${0%/*}/dep.sh\"\nprintf 'row-admitted:%s\\n' \"$dependency\"\n/bin/chmod u+w \"${0%/*}/dep.sh\"\nprintf 'private-mutated' > \"${0%/*}/dep.sh\"\n";
        let admitted_dep = b"dependency-admitted";
        fs::write(&row_path, admitted_row).unwrap();
        fs::write(&dep_path, admitted_dep).unwrap();

        let file = |path: &str, bytes: &[u8]| {
            serde_json::json!({
                "path": path,
                "sha256": sha256(bytes),
                "bytes": bytes.len(),
            })
        };
        let pin = |path: &str, bytes: &[u8]| serde_json::json!({"path": path, "sha256": sha256(bytes), "source": "runtime_closure"});
        let package_manifest_path = root.join("PACKAGE-MANIFEST.json");
        let package_manifest = serde_json::json!({
            "package": "loom-hook-runtime",
            "version": "1.0.0-test",
            "proposed_path": ".claude/hook-runtime/1.0.0-test/",
            "invocation": "node runtime/dispatch.cjs Event",
            "commit_sha": "a".repeat(40),
            "commit_sha_convention": "pinned",
            "head_at_generation": "b".repeat(40),
            "runtime_clean_at_generation": true,
            "file_count": 2,
            "files": [file(".claude/hooks/row.js", admitted_row), file(".claude/hooks/dep.sh", admitted_dep)],
            "verification": {
                "pins": [pin(".claude/hooks/row.js", admitted_row), pin(".claude/hooks/dep.sh", admitted_dep)],
                "runtime_closure": {
                    "entry_points": [".claude/hooks/row.js", ".claude/hooks/dep.sh"],
                    "reached_files": 2,
                    "gaps": [],
                    "method": "lexical walk",
                },
            },
        });
        fs::write(&package_manifest_path, package_manifest.to_string()).unwrap();
        let package = VerifiedPackage::verify(&package_manifest_path, &root).unwrap();

        let defaults: BTreeMap<_, _> = Event::ALL
            .into_iter()
            .map(|event| (event.as_str(), event.default_policy()))
            .collect();
        let mut registry = serde_json::json!({
            "$id": "loom.hook-registry/v1",
            "version": "1.0.0",
            "content_sha256": "",
            "content_sha256_scheme": "RFC 8785 JCS",
            "source_sha": "c".repeat(40),
            "generated_by": "loom/.claude/bin/emit-hook-registry.mjs",
            "unknown_major_policy": "fail-closed",
            "default_on_incomplete": defaults,
            "precedence": PRECEDENCE,
            "runtimes": [{"entry": ".claude/hooks/row.js", "entry_sha256": sha256(admitted_row), "deps": [{"path": ".claude/hooks/dep.sh", "sha256": sha256(admitted_dep)}]}],
            "hooks": [{
                "id": registry::stable_row_id(Event::PreToolUse, "*", ".claude/hooks/row.js"),
                "order": 1,
                "event": "PreToolUse",
                "matcher": "*",
                "file": ".claude/hooks/row.js",
                "file_sha256": sha256(admitted_row),
                "timeout": 2,
                "source": "repo-local",
                "pool": "repo",
                "deps": [{"path": ".claude/hooks/dep.sh", "sha256": sha256(admitted_dep)}],
                "surfaces": ["claude"],
                "on_incomplete": "deny",
                "on_crash": "deny",
                "on_timeout": "deny",
                "contract": {
                    "payload_stdin": {"claude": "cc-hook-json"},
                    "protocol": {"kind": "permission-decision", "exit_codes": [0, 2], "exit_codes_computed": false, "decision_fields": ["permissionDecision"], "severity": "block"},
                    "form": "legacy",
                    "runtime": "node-subprocess",
                    "cwd_scope": "payload",
                    "side_effects": {"fs_writes": [], "network": false, "spawns": [], "declared_by": "author"},
                    "idempotent": true,
                    "may_rewrite_input": false,
                },
            }],
        });
        registry["content_sha256"] = sha256(&canonical_content_bytes(&registry).unwrap()).into();
        let registry_path = root.join(".claude/hook-registry.json");
        fs::write(&registry_path, registry.to_string()).unwrap();
        let admitted = Pin::capture_operator(&root).unwrap().verify(&root).unwrap();
        let verified_row = admitted.rows.first().unwrap();
        let source = verified_row.admission.as_ref().unwrap();

        // Both authorities are changed after admission. The runner must use
        // the retained row/dependency bytes and never reopen these paths.
        let mutated_row =
            b"#!/bin/sh\nprintf 'row-mutated:%s\\n' \"$(cat \"$(dirname \"$0\")/dep.sh\")\"\n";
        let mutated_dep = b"dependency-mutated";
        fs::write(&row_path, mutated_row).unwrap();
        fs::write(&dep_path, mutated_dep).unwrap();

        // A separately valid package may now bind the mutated checkout, but
        // it must not be accepted as the authority for the already-admitted
        // pin closure retained above.
        let mut mutated_manifest: Value =
            serde_json::from_slice(&fs::read(&package_manifest_path).unwrap()).unwrap();
        mutated_manifest["files"][0]["sha256"] = sha256(mutated_row).into();
        mutated_manifest["files"][0]["bytes"] = mutated_row.len().into();
        mutated_manifest["files"][1]["sha256"] = sha256(mutated_dep).into();
        mutated_manifest["files"][1]["bytes"] = mutated_dep.len().into();
        mutated_manifest["verification"]["pins"][0]["sha256"] = sha256(mutated_row).into();
        mutated_manifest["verification"]["pins"][1]["sha256"] = sha256(mutated_dep).into();
        fs::write(
            &package_manifest_path,
            serde_json::to_vec(&mutated_manifest).unwrap(),
        )
        .unwrap();
        let mutated_package = VerifiedPackage::verify(&package_manifest_path, &root).unwrap();
        assert!(matches!(
            mutated_package.bind_verified_bytes(source),
            Err(PackageError::HashMismatch)
        ));

        let payload = serde_json::json!({"hook_event_name": "PreToolUse"});
        let mut runner = NodeRowRunner::new(package).with_node("/bin/sh");
        assert_eq!(
            runner.admitted_relative(source).unwrap(),
            ".claude/hooks/row.js"
        );
        let output = runner
            .run(RowRequest {
                row: &verified_row.row,
                source,
                payload: &payload,
                cwd: &root,
                deadline: Instant::now() + Duration::from_secs(3),
            })
            .unwrap();
        let second = runner
            .run(RowRequest {
                row: &verified_row.row,
                source,
                payload: &payload,
                cwd: &root,
                deadline: Instant::now() + Duration::from_secs(3),
            })
            .unwrap();
        for bytes in [output.stdout, second.stdout] {
            let stdout = String::from_utf8(bytes).unwrap();
            assert!(
                stdout.contains("row-admitted:dependency-admitted"),
                "{stdout:?}"
            );
            assert!(!stdout.contains("mutated"), "{stdout:?}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn verifier_accepts_paths_through_a_directory_alias() {
        let (_dir, root, manifest) = fixture();
        let alias = root.parent().unwrap().join("repo-alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let verified = VerifiedPackage::verify(&manifest, &root).unwrap();
        assert!(verified.contains(&alias.join("node-fixture")));
        assert!(verified.is_runtime_entry(&alias.join("node-fixture")));
    }

    #[cfg(unix)]
    #[test]
    fn pool_runner_canonicalizes_alias_runtime_entry_before_execution() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let alias = root.parent().unwrap().join("repo-alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "../repo-alias/node-fixture")
            .unwrap()
            .with_node("/bin/sh");
        let output = runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                br#"{}"#,
                &root,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(output.stdout, br#"{}"#);
    }

    #[test]
    #[cfg(unix)]
    fn verifier_rejects_oversized_package_file_before_reading_it() {
        let (_dir, root, manifest) = fixture();
        fs::write(
            root.join("node-fixture"),
            vec![b'x'; MAX_PACKAGE_FILE_BYTES + 1],
        )
        .unwrap();

        assert!(matches!(
            VerifiedPackage::verify(&manifest, &root),
            Err(PackageError::Limit)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn verifier_rejects_fifo_without_opening_or_blocking_on_it() {
        let (_dir, root, manifest) = fixture();
        let fifo = root.join("node-fixture");
        fs::remove_file(&fifo).unwrap();
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated private fixture path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        assert!(matches!(
            VerifiedPackage::verify(&manifest, &root),
            Err(PackageError::UnsafeFile)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn verifier_rejects_file_and_runtime_pin_digest_disagreement() {
        let (_dir, root, manifest) = fixture();
        let mut value: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        // The file entry still names the real bytes, but the runtime pin now
        // names a different digest. Admission must reject the disagreement
        // before a runner can retain or execute either byte set.
        value["verification"]["pins"][0]["sha256"] = Value::String("a".repeat(64));
        fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            VerifiedPackage::verify(&manifest, &root),
            Err(PackageError::HashMismatch)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn verifier_rejects_unlisted_runtime_closure_file() {
        let (_dir, root, manifest) = fixture();
        let mut value: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        value["verification"]["runtime_closure"]["entry_points"] =
            serde_json::json!(["missing.js"]);
        fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            VerifiedPackage::verify(&manifest, &root),
            Err(PackageError::RuntimeClosure)
        ));
    }

    #[test]
    fn json_protocol_requires_exactly_one_object() {
        assert!(single_json_object(b" \n {\"ok\":true} \n"));
        assert!(!single_json_object(b"{\"ok\":true}{\"second\":true}"));
        assert!(!single_json_object(b"{\"ok\":true} trailing"));
        assert!(!single_json_object(b"[]"));
    }

    #[cfg(unix)]
    #[test]
    #[cfg(unix)]
    fn materialized_runtime_requires_explicit_union_and_matching_bytes() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let materialized = root.join("materialized");
        fs::create_dir_all(&materialized).unwrap();
        let mut mappings = BTreeMap::new();
        for source in ["node-fixture", ".claude/hooks/row.js"] {
            let destination = materialized.join(source.replace('/', "_"));
            fs::copy(root.join(source), &destination).unwrap();
            mappings.insert(source.to_owned(), destination);
        }
        let package = package
            .verify_materialized(mappings, &["node-fixture".into()])
            .unwrap();
        assert!(package.materialized_path("node-fixture").is_some());
        assert!(package
            .verify_runtime_union(&["node-fixture".into()])
            .is_ok());
        assert!(package
            .verify_runtime_union(&["unlisted.js".into()])
            .is_err());
        assert!(package
            .verify_runtime_union(&[".claude/hooks/row.js".into()])
            .is_err());
        assert!(NodePoolRunner::new_materialized(package.clone(), ".claude/hooks/row.js").is_err());
        assert!(NodePoolRunner::new_materialized(package, "node-fixture").is_ok());
    }

    #[cfg(unix)]
    #[test]
    #[cfg(unix)]
    fn pool_runner_sends_stdin_and_allows_one_child_per_pool_and_event() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let marker = root.join("pool-child-count");
        let counting_node = root.join("counting-node");
        fs::write(
            &counting_node,
            "#!/bin/sh\nprintf x >> \"$CSQ_HANDLE_DIR/pool-child-count\"\nexec /bin/sh \"$1\" \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&counting_node, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(counting_node)
            .with_environment(NodeEnvironment {
                handle_dir: Some(root.to_string_lossy().into_owned()),
                ..NodeEnvironment::default()
            });
        let output = runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                br#"{"x":1}"#,
                &root,
                // Exercise successful subprocess startup with the real event
                // budget; a one-second fixture ceiling flakes in whole-suite CI.
                Instant::now() + super::super::dispatch::event_budget(Event::PreToolUse),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["x"],
            1
        );
        assert_eq!(output.stderr, b"\n");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("home-leak"));
        assert_eq!(runner.started_pairs().count(), 1);
        assert_eq!(fs::read(&marker).unwrap(), b"x");
        runner
            .run_event(
                Pool::Template,
                Event::PreToolUse,
                br#"{"x":1}"#,
                &root,
                Instant::now() + super::super::dispatch::event_budget(Event::PreToolUse),
            )
            .unwrap();
        assert_eq!(runner.started_pairs().count(), 2);
        assert_eq!(fs::read(&marker).unwrap(), b"xx");
        assert!(matches!(
            runner.run_event(
                Pool::Repo,
                Event::PreToolUse,
                br#"{"x":1}"#,
                &root,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(RowFailure::Incomplete)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn persisted_demotion_refuses_pool_before_child_start() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let mut tracker = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            tracker.note_crash("demoted-row").unwrap();
        }
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_fault_ledger(&ledger);
        assert_eq!(
            runner.execution_mode("demoted-row", Pool::Repo),
            ExecutionMode::Process
        );
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["demoted-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "demoted-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: "a".repeat(64),
            timeout_secs: Some(2),
        }];
        assert!(matches!(
            runner.run_event_rows(
                &binding,
                &contracts,
                &"b".repeat(64),
                br#"{}"#,
                &root,
                Instant::now() + Duration::from_secs(3),
            ),
            Err(PoolRunError::Refusal(RowFailure::DemotionLedger))
        ));
        assert_eq!(runner.started_pairs().count(), 0);

        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut digest_runner = NodePoolRunner::new(package, "node-fixture").unwrap();
        let valid_contract = [PoolRowContract {
            id: "admitted-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: "a".repeat(64),
            timeout_secs: Some(2),
        }];
        let valid_binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["admitted-row".into()],
        };
        assert!(matches!(
            digest_runner.run_event_rows(
                &valid_binding,
                &valid_contract,
                &"b".repeat(64),
                br#"{}"#,
                &root,
                Instant::now() + Duration::from_secs(3),
            ),
            Err(PoolRunError::Refusal(RowFailure::Incomplete))
        ));
        assert_eq!(digest_runner.started_pairs().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn invalid_pool_contract_refuses_before_child_start() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture").unwrap();
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["admitted-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "different-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: "a".repeat(64),
            timeout_secs: Some(2),
        }];
        assert!(matches!(
            runner.run_event_rows(
                &binding,
                &contracts,
                &"b".repeat(64),
                br#"{}"#,
                &root,
                Instant::now() + Duration::from_secs(3),
            ),
            Err(PoolRunError::Refusal(RowFailure::Incomplete))
        ));
        assert_eq!(runner.started_pairs().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn missing_registered_row_bytes_refuse_before_pool_child() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let registered_source = b"registered row admitted by the pin";
        // The source exists in the pinned checkout, but is intentionally not
        // one of this package's retained files.  This separates package
        // authority failure from an ordinary filesystem-missing-file error.
        fs::write(
            root.join(".claude/hooks/registered-row.js"),
            registered_source,
        )
        .unwrap();
        let marker = root.join("missing-row-child-started");
        let node = root.join("missing-row-node");
        fs::write(
            &node,
            format!("#!/bin/sh\nprintf started > {}\nexit 0\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(node);
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["registered-but-missing".into()],
        };
        let contracts = [PoolRowContract {
            id: "registered-but-missing".into(),
            source_path: ".claude/hooks/registered-row.js".into(),
            // This is a valid digest, but its admitted bytes are absent from
            // the package manifest.  The child must not be the authority that
            // decides whether that row exists.
            source_sha256: sha256(registered_source),
            timeout_secs: Some(2),
        }];
        let payload = br#"{}"#;
        let result = runner.run_event_rows(
            &binding,
            &contracts,
            &sha256(payload),
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(
            matches!(result, Err(PoolRunError::Refusal(RowFailure::Incomplete))),
            "{result:?}"
        );
        assert_eq!(runner.started_pairs().count(), 0);
        assert!(!marker.exists(), "missing row must not start the child");
    }

    #[cfg(unix)]
    #[test]
    fn outer_exit_two_without_json_is_a_refusal_not_continuable_execution() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["admitted-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "admitted-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: sha256(&fs::read(root.join(".claude/hooks/row.js")).unwrap()),
            timeout_secs: Some(2),
        }];
        let payload = br#"{}"#;
        let payload_sha256 = sha256(payload);

        for (name, body) in [
            (
                "plain-exit-two",
                b"#!/bin/sh\nprintf refused; exit 2\n".as_slice(),
            ),
            ("empty-exit-two", b"#!/bin/sh\nexit 2\n".as_slice()),
        ] {
            let node = root.join(name);
            fs::write(&node, body).unwrap();
            fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
            let mut runner = NodePoolRunner::new(package.clone(), "node-fixture")
                .unwrap()
                .with_node(node);
            let result = runner.run_event_rows(
                &binding,
                &contracts,
                &payload_sha256,
                payload,
                &root,
                Instant::now() + Duration::from_secs(2),
            );
            assert!(
                matches!(result, Err(PoolRunError::Refusal(RowFailure::Incomplete))),
                "{name}: {result:?}"
            );
            assert_eq!(runner.started_pairs().count(), 1, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_pool_is_named_refusal_and_demotes_later_calls_without_replay() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("pool-interruptions.ndjson");
        let marker = root.join("pool-interruption-attempts");
        let crashing_node = root.join("partial-crash-node");
        fs::write(
            &crashing_node,
            format!(
                "#!/bin/sh\nprintf x >> \"{}\"\nprintf '{{\"schema\":\"csq.gate.pool.v1\",\"rows\":['\nkill -TERM $$\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&crashing_node, fs::Permissions::from_mode(0o755)).unwrap();

        // These names model the dangerous sibling pair: one row would deny,
        // while the other could continue. An unknown executed prefix must
        // never be converted into two policy-fold inputs.
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["deny-sibling".into(), "continue-sibling".into()],
        };
        let source_sha256 = sha256(&fs::read(root.join(".claude/hooks/row.js")).unwrap());
        let contracts = [
            PoolRowContract {
                id: "deny-sibling".into(),
                source_path: ".claude/hooks/row.js".into(),
                source_sha256: source_sha256.clone(),
                timeout_secs: Some(2),
            },
            PoolRowContract {
                id: "continue-sibling".into(),
                source_path: ".claude/hooks/row.js".into(),
                source_sha256,
                timeout_secs: Some(2),
            },
        ];
        let payload = br#"{}"#;
        let payload_sha256 = sha256(payload);
        let environment = NodeEnvironment {
            handle_dir: Some(root.to_string_lossy().into_owned()),
            ..NodeEnvironment::default()
        };

        for attempt in 0..CRASH_DEMOTION_THRESHOLD {
            let mut runner = NodePoolRunner::new(package.clone(), "node-fixture")
                .unwrap()
                .with_node(&crashing_node)
                .with_environment(environment.clone())
                .with_fault_ledger(&ledger);
            let result = runner.run_event_rows(
                &binding,
                &contracts,
                &payload_sha256,
                payload,
                &root,
                Instant::now() + Duration::from_secs(2),
            );
            assert!(
                matches!(result, Err(PoolRunError::Refusal(RowFailure::Crash))),
                "attempt {attempt}: {result:?}"
            );
            assert_eq!(runner.started_pairs().count(), 1);
            if attempt + 1 < CRASH_DEMOTION_THRESHOLD {
                assert_eq!(
                    runner.execution_mode("deny-sibling", Pool::Repo),
                    ExecutionMode::Pool,
                    "demotion must not trigger before the third interruption"
                );
            }
        }
        assert_eq!(fs::read(&marker).unwrap(), b"xxx");

        // The threshold changes only later calls to row mode. The denied call
        // is never replayed, and the fourth pool attempt starts no child.
        let mut later = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&crashing_node)
            .with_environment(environment)
            .with_fault_ledger(&ledger);
        assert_eq!(
            later.execution_mode("deny-sibling", Pool::Repo),
            ExecutionMode::Process
        );
        assert_eq!(
            later.execution_mode("continue-sibling", Pool::Repo),
            ExecutionMode::Process
        );
        let result = later.run_event_rows(
            &binding,
            &contracts,
            &payload_sha256,
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            result,
            Err(PoolRunError::Refusal(RowFailure::DemotionLedger))
        ));
        assert_eq!(later.started_pairs().count(), 0);
        assert_eq!(fs::read(&marker).unwrap(), b"xxx");
    }

    #[cfg(unix)]
    fn write_native_gate_child(node: &Path, mode: &str, marker: &Path, survived: &Path) {
        // fd 3 preserves the runner's stdout while libtest's startup text goes
        // to /dev/null. The selected fixture restores it before producing bytes.
        let quote = |value: &Path| format!("'{}'", value.to_str().unwrap().replace('\'', "'\\''"));
        let script = format!(
            "#!/bin/sh\nCSQ_GATE_TEST_CHILD_MODE='{mode}' CSQ_GATE_TEST_CHILD_MARKER={marker} CSQ_GATE_TEST_CHILD_SURVIVED={survived} exec {exe} --exact gate::legacy::tests::native_gate_child_fixture --nocapture 3>&1 1>/dev/null 2>/dev/null\n",
            marker = quote(marker), survived = quote(survived), exe = quote(&std::env::current_exe().unwrap()),
        );
        fs::write(node, script).unwrap();
        fs::set_permissions(node, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_gate_child_fixture() {
        let _env = crate::platform::test_env::lock();
        let Ok(mode) = std::env::var("CSQ_GATE_TEST_CHILD_MODE") else {
            return;
        };
        assert!(matches!(mode.as_str(), "held" | "cleanup"));
        let marker =
            std::ffi::CString::new(std::env::var("CSQ_GATE_TEST_CHILD_MARKER").unwrap()).unwrap();
        let survived =
            std::ffi::CString::new(std::env::var("CSQ_GATE_TEST_CHILD_SURVIVED").unwrap()).unwrap();
        let cleanup = mode == "cleanup";
        let mut ready = [0; 2];
        // SAFETY: valid descriptor storage; the wrapper explicitly supplies fd 3.
        assert_eq!(unsafe { libc::dup2(3, 1) }, 1);
        // SAFETY: valid two-element descriptor buffer.
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
        // SAFETY: the fork child performs only libc calls on prebuilt buffers and
        // exits with _exit, so it never touches locks copied from the test harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: owned descriptors, valid NUL-terminated paths, and static
            // byte storage; _exit avoids inherited Rust destructors after fork.
            unsafe {
                libc::close(ready[0]);
                if libc::setsid() < 0 {
                    libc::_exit(71);
                }
                let fd = libc::open(
                    marker.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o600,
                );
                if fd < 0 {
                    libc::_exit(72);
                }
                libc::close(fd);
                libc::write(ready[1], b"x".as_ptr().cast(), 1);
                libc::close(ready[1]);
                libc::sleep(5);
                if cleanup {
                    let fd = libc::open(
                        survived.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        0o600,
                    );
                    if fd >= 0 {
                        libc::close(fd);
                    }
                }
                libc::_exit(0);
            }
        }
        let mut byte = [0u8];
        // SAFETY: owned pipe descriptors and a writable one-byte buffer.
        unsafe {
            libc::close(ready[1]);
            assert_eq!(libc::read(ready[0], byte.as_mut_ptr().cast(), 1), 1);
            libc::close(ready[0]);
        }
        if mode == "held" {
            fs::write(std::env::var("CSQ_GATE_TEST_CHILD_MARKER").unwrap(), b"x").unwrap();
            // SAFETY: stdout restored above and a static byte slice.
            unsafe {
                libc::write(1, b"{\"partial\":".as_ptr().cast(), 11);
                libc::_exit(1);
            }
        }
        // Keep the direct parent alive long enough for the runner's process-tree
        // observation to capture its detached descendant before the parent exits.
        thread::sleep(Duration::from_millis(200));
        let reply = b"{\"ok\":true}\n";
        // SAFETY: stdout restored above and a valid immutable buffer.
        unsafe {
            libc::write(1, reply.as_ptr().cast(), reply.len());
            libc::_exit(0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn exit_one_with_held_pipe_is_whole_call_refusal_without_sibling_replay() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let marker = root.join("exit-one-pool-attempts");
        let node = root.join("exit-one-held-pipe-node");
        write_native_gate_child(&node, "held", &marker, &root.join("unused-survival-marker"));

        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["deny-sibling".into(), "continue-sibling".into()],
        };
        let source_sha256 = sha256(&fs::read(root.join(".claude/hooks/row.js")).unwrap());
        let contracts = [
            PoolRowContract {
                id: "deny-sibling".into(),
                source_path: ".claude/hooks/row.js".into(),
                source_sha256: source_sha256.clone(),
                timeout_secs: Some(1),
            },
            PoolRowContract {
                id: "continue-sibling".into(),
                source_path: ".claude/hooks/row.js".into(),
                source_sha256,
                timeout_secs: Some(1),
            },
        ];
        let payload = br#"{}"#;
        let payload_sha256 = sha256(payload);
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&node);
        let result = runner.run_event_rows(
            &binding,
            &contracts,
            &payload_sha256,
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(
            matches!(
                result,
                Err(PoolRunError::Refusal(
                    RowFailure::Incomplete | RowFailure::Timeout
                ))
            ),
            "exit-one/held-pipe interruption must refuse the whole call: {result:?}"
        );
        assert_eq!(runner.started_pairs().count(), 1);
        assert_eq!(fs::read(&marker).unwrap(), b"x");
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_pool_interruptions_count_toward_three_call_demotion() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("pool-incomplete-demotions.ndjson");
        let node = root.join("incomplete-pool-node");
        fs::write(&node, b"#!/bin/sh\nprintf partial\nexit 1\n").unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();

        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["incomplete-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "incomplete-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: sha256(&fs::read(root.join(".claude/hooks/row.js")).unwrap()),
            timeout_secs: Some(1),
        }];
        let payload = br#"{}"#;
        let payload_sha256 = sha256(payload);

        for attempt in 0..CRASH_DEMOTION_THRESHOLD {
            let mut runner = NodePoolRunner::new(package.clone(), "node-fixture")
                .unwrap()
                .with_node(&node)
                .with_fault_ledger(&ledger);
            let result = runner.run_event_rows(
                &binding,
                &contracts,
                &payload_sha256,
                payload,
                &root,
                Instant::now() + Duration::from_secs(2),
            );
            assert!(
                matches!(result, Err(PoolRunError::Refusal(RowFailure::Incomplete))),
                "attempt {attempt}: {result:?}"
            );
            assert_eq!(runner.started_pairs().count(), 1);
            if attempt + 1 < CRASH_DEMOTION_THRESHOLD {
                assert_eq!(
                    runner.execution_mode("incomplete-row", Pool::Repo),
                    ExecutionMode::Pool,
                    "incomplete transport must not demote before the third failure"
                );
            }
        }

        let mut later = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&node)
            .with_fault_ledger(&ledger);
        assert_eq!(
            later.execution_mode("incomplete-row", Pool::Repo),
            ExecutionMode::Process
        );
        let result = later.run_event_rows(
            &binding,
            &contracts,
            &payload_sha256,
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            result,
            Err(PoolRunError::Refusal(RowFailure::DemotionLedger))
        ));
        assert_eq!(later.started_pairs().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn mixed_incomplete_pool_interruptions_share_one_demotion_window() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("mixed-pool-demotions.ndjson");
        let node = root.join("mixed-incomplete-pool-node");
        let binding = RuntimePoolBinding {
            runtime_index: 0,
            pool: Pool::Repo,
            event: Event::PreToolUse,
            row_ids: vec!["mixed-row".into()],
        };
        let contracts = [PoolRowContract {
            id: "mixed-row".into(),
            source_path: ".claude/hooks/row.js".into(),
            source_sha256: sha256(&fs::read(root.join(".claude/hooks/row.js")).unwrap()),
            timeout_secs: Some(1),
        }];
        let payload = br#"{}"#;
        let payload_sha256 = sha256(payload);
        let cases = [
            ("exit-two", b"#!/bin/sh\nexit 2\n".as_slice()),
            ("malformed", b"#!/bin/sh\nprintf '{'\nexit 0\n".as_slice()),
            ("timeout", b"#!/bin/sh\nsleep 5\n".as_slice()),
        ];

        for (index, (name, script)) in cases.into_iter().enumerate() {
            fs::write(&node, script).unwrap();
            fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
            let mut runner = NodePoolRunner::new(package.clone(), "node-fixture")
                .unwrap()
                .with_node(&node)
                .with_fault_ledger(&ledger);
            let result = runner.run_event_rows(
                &binding,
                &contracts,
                &payload_sha256,
                payload,
                &root,
                Instant::now() + Duration::from_secs(2),
            );
            assert!(
                matches!(
                    result,
                    Err(PoolRunError::Refusal(
                        RowFailure::Incomplete | RowFailure::Timeout
                    ))
                ),
                "{name}: {result:?}"
            );
            assert_eq!(runner.started_pairs().count(), 1, "{name}");
            assert!(
                runner.last_child_started,
                "{name}: fixture never entered child behavior"
            );
            let faults = read_fault_state(&ledger.with_extension("faults")).unwrap();
            assert_eq!(
                faults["mixed-row"].crashes,
                index + 1,
                "{name}: durable fault count"
            );
            if index < 2 {
                assert_eq!(
                    runner.execution_mode("mixed-row", Pool::Repo),
                    ExecutionMode::Pool,
                    "mixed interruptions must not demote after only {index} prior failures"
                );
            }
        }

        let mut later = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&node)
            .with_fault_ledger(&ledger);
        assert_eq!(
            later.execution_mode("mixed-row", Pool::Repo),
            ExecutionMode::Process
        );
        let result = later.run_event_rows(
            &binding,
            &contracts,
            &payload_sha256,
            payload,
            &root,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(
            result,
            Err(PoolRunError::Refusal(RowFailure::DemotionLedger))
        ));
        assert_eq!(later.started_pairs().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(unix)]
    fn pool_runner_passes_event_name_to_runtime_entry() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let argv_node = root.join("argv-fixture");
        fs::write(
            &argv_node,
            b"#!/bin/sh\nprintf '{\"event\":\"%s\"}' \"$2\"\n",
        )
        .unwrap();
        fs::set_permissions(&argv_node, fs::Permissions::from_mode(0o755)).unwrap();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(argv_node);
        let output = runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                b"{}",
                &root,
                Instant::now() + super::super::dispatch::event_budget(Event::PreToolUse),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["event"],
            "PreToolUse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pool_child_receives_only_explicit_home_and_tmpdir() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let wrapper = root.join("env-fixture");
        fs::write(
            &wrapper,
            b"#!/bin/sh\nprintf '%s|%s' \"$HOME\" \"$TMPDIR\" > \"$CSQ_HANDLE_DIR/env\"\nprintf '{\"ok\":true}'\n",
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(wrapper)
            .with_environment(NodeEnvironment {
                handle_dir: Some(root.to_string_lossy().into_owned()),
                home: Some("/private/test-home".into()),
                tmpdir: Some("/private/test-tmp".into()),
                ..NodeEnvironment::default()
            });
        runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                br#"{"x":1}"#,
                &root,
                Instant::now() + super::super::dispatch::event_budget(Event::PreToolUse),
            )
            .unwrap();
        assert_eq!(
            fs::read_to_string(root.join("env")).unwrap(),
            "/private/test-home|/private/test-tmp"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_node_pool_runner_requires_job_objects_before_activation() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();

        // Direct-child cleanup cannot contain a Windows descendant tree. Keep
        // activation refused until NodePoolRunner owns a Job Object for the
        // complete invocation, rather than silently running with weaker
        // cleanup guarantees than Unix hosts.
        assert!(matches!(
            NodePoolRunner::new(package.clone(), "node-fixture"),
            Err(PackageError::UnsupportedPlatform)
        ));

        let materialized = root.join("materialized");
        fs::create_dir_all(&materialized).unwrap();
        let mut mappings = BTreeMap::new();
        for source in ["node-fixture", ".claude/hooks/row.js"] {
            let destination = materialized.join(source.replace('/', "_"));
            fs::copy(root.join(source), &destination).unwrap();
            mappings.insert(source.to_owned(), destination);
        }
        let package = package
            .verify_materialized(mappings, &["node-fixture".into()])
            .unwrap();

        assert!(matches!(
            NodePoolRunner::new_materialized(package, "node-fixture"),
            Err(PackageError::UnsupportedPlatform)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn pool_runner_kills_a_setsid_descendant_before_joining_output() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let marker = root.join("detached-ready");
        let survived = root.join("detached-survived");
        let node = root.join("detached-fixture");
        write_native_gate_child(&node, "cleanup", &marker, &survived);
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&node);
        let output = runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                b"{}",
                &root,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["ok"],
            true
        );
        assert!(marker.exists(), "fixture did not create detached child");
        thread::sleep(Duration::from_millis(500));
        assert!(
            !survived.exists(),
            "setsid descendant survived runner cleanup"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pool_runner_returns_by_deadline_when_a_pipe_holder_escapes_cleanup() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let node = root.join("escaped-pipe-fixture");
        // The direct process exits immediately after forking. The child calls
        // setsid and inherits stdout/stderr, so it can outlive the direct
        // process and evade the post-exit process-tree walk. This is the
        // hostile shape that used to make reader joins wait for EOF forever.
        fs::write(
            &node,
            b"#!/usr/bin/python3\nimport os, time\nchild = os.fork()\nif child == 0:\n    os.setsid()\n    time.sleep(5)\n    os._exit(0)\nprint('{\\\"ok\\\":true}', flush=True)\nos._exit(0)\n",
        )
        .unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node(&node);
        let started = Instant::now();
        let result = runner.run_event(
            Pool::Repo,
            Event::PreToolUse,
            b"{}",
            &root,
            started + Duration::from_millis(250),
        );
        assert!(
            matches!(result, Err(RowFailure::Incomplete | RowFailure::Timeout)),
            "{result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "pipe cleanup exceeded the invocation deadline: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn descendant_cleanup_refuses_a_recycled_pid_identity() {
        // A bare program name resolves through the process PATH, which sibling tests swap
        // under the shared env lock; hold it so the spawn cannot see a mid-swap PATH.
        let _env_lock = crate::platform::test_env::lock();
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn identity fixture");
        let pid = child.id() as libc::pid_t;
        let started_at = crate::sessions::ancestor_start(child.id())
            .expect("live fixture must have a readable process identity");
        let mut forged = BTreeSet::new();
        forged.insert(DescendantIdentity {
            pid,
            // This is the same PID with a different incarnation. A raw PID
            // cleanup implementation would incorrectly kill the fixture.
            started_at: started_at.saturating_add(1),
        });

        kill_descendants(&forged);
        // kill(pid, 0) also succeeds for zombies, so it cannot prove that
        // cleanup left this child running. Poll its actual exit disposition.
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            assert!(
                child.try_wait().unwrap().is_none(),
                "cleanup must refuse a PID whose start identity changed"
            );
            thread::sleep(Duration::from_millis(2));
        }

        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn direct_children_includes_one_owned_child() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let found = direct_children(std::process::id() as libc::pid_t);
        // Always reap the private fixture, including on the pre-fix failure.
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            found.contains(&pid),
            "owned child {pid} missing from {found:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn owned_process_group_cleanup_kills_unobserved_holder_before_reaping_leader() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("holder-pid");
        let mut leader = Command::new("/usr/bin/python3");
        leader
            .arg("-c")
            .arg("import os, sys, time\npid = os.fork()\nif pid == 0:\n    time.sleep(30)\n    os._exit(0)\nwith open(sys.argv[1], 'w') as f: f.write(str(pid))\nos._exit(0)\n")
            .arg(&pid_file)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        std::os::unix::process::CommandExt::process_group(&mut leader, 0);
        let mut leader = leader.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waitid inspects our owned child without consuming its exit.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    leader.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            assert_eq!(result, 0);
            if unsafe { info.si_pid() } != 0 {
                break;
            }
            assert!(Instant::now() < deadline, "leader did not exit");
            thread::sleep(Duration::from_millis(2));
        }
        let holder: u32 = fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let identity = crate::sessions::ancestor_start(holder);
        // The parent has exited and its holder is reparented: no process-tree
        // observation can discover it now. The unreaped parent still anchors
        // the original process group until the production helper reaps it.
        let status = poll_child_exit(&mut leader).unwrap();
        let stdout = leader.stdout.take().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = done_tx.send(read_bounded_pipe(stdout));
        });
        let closed = done_rx.recv_timeout(Duration::from_millis(500));
        // Cleanup even under the broken implementation, before asserting RED.
        if identity.is_some() && crate::sessions::ancestor_start(holder) == identity {
            unsafe {
                libc::kill(holder as libc::pid_t, libc::SIGKILL);
            }
        }
        assert!(status.is_some(), "owned leader was not reaped");
        assert!(
            matches!(closed, Ok(Ok(_))),
            "unobserved pipe holder survived normal completion: {closed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn signaled_repo_row_counts_as_crash_and_demotes_after_three_failures() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let signal_node = root.join("signal-fixture");
        fs::write(&signal_node, b"#!/bin/sh\nkill -TERM $$\n").unwrap();
        fs::set_permissions(&signal_node, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runner = NodeRowRunner::new(package).with_node(&signal_node);
        let source = root.join("node-fixture");

        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            let result = runner.run_process(
                &source,
                &[],
                b"{}",
                &root,
                Instant::now() + super::super::dispatch::event_budget(Event::PreToolUse),
                false,
            );
            assert!(matches!(result, Err(RowFailure::Crash)), "{result:?}");
            // This is the same repo-row accounting performed by `run`; keeping
            // the direct process fixture here isolates the signal disposition
            // while still proving the threshold transition.
            runner.note_crash("signal-row").unwrap();
        }

        assert_eq!(
            runner.execution_mode("signal-row", Pool::Repo),
            ExecutionMode::Process
        );
        assert_eq!(runner.demotion_status(), vec!["signal-row"]);
    }

    #[cfg(unix)]
    #[test]
    fn maximal_admitted_fault_window_refuses_actual_crash_before_counter_wrap() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let signal_node = root.join("signal-overflow-fixture");
        fs::write(&signal_node, b"#!/bin/sh\nkill -TERM $$\n").unwrap();
        fs::set_permissions(&signal_node, fs::Permissions::from_mode(0o755)).unwrap();
        let ledger = root.join("overflow-demotions.ndjson");
        let state = ledger.with_extension("faults");
        let max_valid = usize::MAX - 1;
        let row_id =
            crate::gate::registry::stable_row_id(Event::PreToolUse, "*", ".claude/hooks/row.js");
        fs::write(&ledger, b"").unwrap();
        let persisted = BTreeMap::from([(
            row_id.clone(),
            PersistedFault {
                crashes: 1,
                demoted_at_ms: now_millis(),
                window_started_at_ms: Some(now_millis()),
            },
        )]);
        fs::write(&state, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let source_bytes = fs::read(root.join(".claude/hooks/row.js")).unwrap();
        let defaults: BTreeMap<_, _> = Event::ALL
            .into_iter()
            .map(|event| (event.as_str(), event.default_policy()))
            .collect();
        let mut registry = serde_json::json!({
            "$id": "loom.hook-registry/v1",
            "version": "1.0.0",
            "content_sha256": "",
            "content_sha256_scheme": "RFC 8785 JCS",
            "source_sha": "c".repeat(40),
            "generated_by": "fixture",
            "unknown_major_policy": "fail-closed",
            "default_on_incomplete": defaults,
            "precedence": PRECEDENCE,
            "runtimes": [{
                "entry": ".claude/hooks/row.js",
                "entry_sha256": sha256(&source_bytes),
                "deps": []
            }],
            "hooks": [{
                "id": crate::gate::registry::stable_row_id(Event::PreToolUse, "*", ".claude/hooks/row.js"),
                "order": 1,
                "event": "PreToolUse",
                "matcher": "*",
                "file": ".claude/hooks/row.js",
                "file_sha256": sha256(&source_bytes),
                "timeout": 2,
                "source": "repo-local",
                "pool": "repo",
                "deps": [],
                "surfaces": ["claude"],
                "on_incomplete": "deny",
                "on_crash": "deny",
                "on_timeout": "deny",
                "contract": {
                    "payload_stdin": {"claude": "cc-hook-json"},
                    "protocol": {"kind": "permission-decision", "exit_codes": [0, 2], "exit_codes_computed": false, "decision_fields": ["permissionDecision"], "severity": "block"},
                    "form": "legacy",
                    "runtime": "node-subprocess",
                    "cwd_scope": "payload",
                    "side_effects": {"fs_writes": [], "network": false, "spawns": [], "declared_by": "author"},
                    "idempotent": true,
                    "may_rewrite_input": false
                }
            }]
        });
        registry["content_sha256"] = sha256(&canonical_content_bytes(&registry).unwrap()).into();
        fs::write(
            root.join(".claude/hook-registry.json"),
            serde_json::to_vec(&registry).unwrap(),
        )
        .unwrap();
        let admitted = Pin::capture_operator(&root).unwrap().verify(&root).unwrap();
        let admitted_row = admitted.rows.first().unwrap();
        let source = admitted_row.admission.as_ref().unwrap();

        let mut runner = NodeRowRunner::new(package)
            .with_node(&signal_node)
            .with_fault_ledger(&ledger);
        assert!(
            !runner.ledger_unavailable,
            "fault state fixture must be readable"
        );
        runner.faults.insert(
            row_id.clone(),
            FaultWindow {
                first: Instant::now(),
                crashes: max_valid,
            },
        );
        // strict_json admits only safe JSON integers; the valid persisted
        // record above proves the ledger loads, then this exercises the
        // maximal already-admitted in-memory counter without claiming that a
        // raw usize::MAX persisted value is reachable through the parser.
        assert_eq!(runner.faults[&row_id].crashes, max_valid);
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner.run(RowRequest {
                row: &admitted_row.row,
                source,
                payload: &serde_json::json!({"hook_event_name": "PreToolUse"}),
                cwd: &root,
                deadline: Instant::now() + Duration::from_secs(2),
            })
        }));
        assert!(
            runner.child_started.get(),
            "actual crash fixture must spawn"
        );
        let result = run.expect("actual crash must not panic in the runner");
        assert!(
            matches!(result, Err(RowFailure::DemotionLedger)),
            "{result:?}"
        );
        let retained: BTreeMap<String, PersistedFault> =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(retained[&row_id].crashes, 1);
        assert!(runner.demoted_rows().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn demotion_ledger_preserves_one_durable_record_per_event() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let mut runner = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);

        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            runner.note_crash("first-row").unwrap();
        }
        let first = fs::read_to_string(&ledger).unwrap();
        let first_lines: Vec<_> = first.lines().collect();
        assert_eq!(first_lines.len(), 1);
        let first_event: PersistedDemotion = serde_json::from_str(first_lines[0]).unwrap();
        assert_eq!(first_event.row_id, "first-row");
        assert_eq!(first_event.crashes, CRASH_DEMOTION_THRESHOLD);

        let restored = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        assert_eq!(
            restored.execution_mode("first-row", Pool::Repo),
            ExecutionMode::Process
        );

        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            runner.note_crash("second-row").unwrap();
        }
        let second = fs::read_to_string(&ledger).unwrap();
        assert_eq!(second.lines().count(), 2);
        assert!(second.lines().any(|line| {
            serde_json::from_str::<PersistedDemotion>(line)
                .is_ok_and(|event| event.row_id == "second-row")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn demotion_fault_window_survives_separate_runner_instances() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");

        let mut first = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        first.note_crash("cross-process-row").unwrap();

        let mut second = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        second.note_crash("cross-process-row").unwrap();
        assert_eq!(
            second.execution_mode("cross-process-row", Pool::Repo),
            ExecutionMode::Pool
        );

        let mut third = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        third.note_crash("cross-process-row").unwrap();
        assert_eq!(
            third.execution_mode("cross-process-row", Pool::Repo),
            ExecutionMode::Process
        );
    }

    #[cfg(unix)]
    #[test]
    fn demotion_write_failure_does_not_advertise_persisted_process_mode() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("ledger-is-a-directory");
        fs::create_dir(&ledger).unwrap();
        let mut runner = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            let _ = runner.note_crash("failed-ledger-row");
        }
        assert_eq!(
            runner.execution_mode("failed-ledger-row", Pool::Repo),
            ExecutionMode::Pool
        );
        assert!(runner.note_crash("failed-ledger-row").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn demotion_ledger_refuses_symlink_oversize_and_malformed_state() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let target = root.join("foreign-target");
        fs::write(&target, b"do not touch").unwrap();
        let ledger = root.join("demotions.ndjson");
        std::os::unix::fs::symlink(&target, &ledger).unwrap();
        let mut runner = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        assert!(runner.note_crash("row").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do not touch");
        fs::remove_file(&ledger).unwrap();
        let file = File::create(&ledger).unwrap();
        file.set_len(MAX_DEMOTION_LEDGER_BYTES + 1).unwrap();
        assert!(read_demotion_ledger(&ledger).is_err());
        drop(file);
        fs::write(&ledger, b"not-json").unwrap();
        let mut runner = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        assert!(runner.note_crash("row").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn demotion_ledger_refuses_a_symlink_parent_without_writing() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let foreign = root.join("foreign-ledger-parent");
        fs::create_dir(&foreign).unwrap();
        let sentinel = foreign.join("sentinel");
        fs::write(&sentinel, b"foreign bytes").unwrap();
        let alias = root.join("ledger-parent-alias");
        std::os::unix::fs::symlink(&foreign, &alias).unwrap();
        let ledger = alias.join("demotions.ndjson");
        let mut runner = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        assert!(matches!(
            runner.note_crash("row"),
            Err(DemotionLedgerError::Read(_))
        ));
        assert_eq!(
            runner.execution_mode("row", Pool::Repo),
            ExecutionMode::Pool
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"foreign bytes");
        assert_eq!(
            fs::read_dir(&foreign).unwrap().count(),
            1,
            "no lock or ledger may be created"
        );
    }

    #[cfg(unix)]
    #[test]
    fn demotion_ledger_serializes_independent_writers_without_losing_history() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let mut first = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        let mut second = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            first.note_crash("first-row").unwrap();
        }
        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            second.note_crash("second-row").unwrap();
        }
        assert_eq!(
            load_demotion_rows(&read_demotion_ledger(&ledger).unwrap()).unwrap(),
            BTreeSet::from(["first-row".into(), "second-row".into()])
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&ledger).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn demotion_ledger_appends_after_valid_event_without_trailing_newline() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let event = PersistedDemotion {
            row_id: "first-row".into(),
            crashes: 3,
            demoted_at_ms: 1,
        };
        fs::write(&ledger, serde_json::to_vec(&event).unwrap()).unwrap();
        let mut runner = NodeRowRunner::new(package.clone()).with_fault_ledger(&ledger);
        for _ in 0..CRASH_DEMOTION_THRESHOLD {
            runner.note_crash("second-row").unwrap();
        }
        let restored = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        assert!(
            !restored.ledger_unavailable,
            "appended ledger must remain readable"
        );
        assert_eq!(restored.demotion_status(), vec!["first-row", "second-row"]);
    }

    #[test]
    fn demotion_ledger_fsync_failure_is_not_silent_or_green() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let runner = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        let error = runner
            .persist_demotion_with_hooks(
                "fsync-row",
                CRASH_DEMOTION_THRESHOLD,
                |_| Err(std::io::Error::other("injected fsync failure")),
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(error, DemotionLedgerError::SyncTemp(_)));
        assert!(!ledger.exists());
        assert_eq!(
            runner.execution_mode("fsync-row", Pool::Repo),
            ExecutionMode::Pool
        );
    }

    #[test]
    fn demotion_ledger_parent_fsync_failure_is_not_silent_or_green() {
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let ledger = root.join("demotions.ndjson");
        let runner = NodeRowRunner::new(package).with_fault_ledger(&ledger);
        let error = runner
            .persist_demotion_with_hooks(
                "parent-fsync-row",
                CRASH_DEMOTION_THRESHOLD,
                |file| file.sync_all(),
                |_| Err(std::io::Error::other("injected parent fsync failure")),
            )
            .unwrap_err();
        assert!(matches!(error, DemotionLedgerError::SyncParent(_)));
        assert_eq!(
            runner.execution_mode("parent-fsync-row", Pool::Repo),
            ExecutionMode::Pool
        );
    }

    #[cfg(unix)]
    #[test]
    fn pool_runner_executes_admitted_bytes_after_source_replacement() {
        let _env_guard = crate::platform::test_env::lock();
        let (_dir, root, manifest) = fixture();
        let package = VerifiedPackage::verify(&manifest, &root).unwrap();
        let mut runner = NodePoolRunner::new(package, "node-fixture")
            .unwrap()
            .with_node("/bin/sh");
        fs::write(root.join("node-fixture"), b"printf '{\"tampered\":true}'\n").unwrap();
        let output = runner
            .run_event(
                Pool::Repo,
                Event::PreToolUse,
                br#"{"x":1}"#,
                &root,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(output.stdout, br#"{"x":1}"#);
    }

    // M-3: the runtime tree is built only from directories this call created.
    #[cfg(unix)]
    #[test]
    fn runtime_tree_refuses_a_planted_child_directory_and_a_planted_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        make_private_dir(&root).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // A child that already exists and this call did not create is refused, not adopted.
        // Private and ours, so only the refusal to adopt an existing child can reject it.
        fs::create_dir(root.join("planted")).unwrap();
        fs::set_permissions(root.join("planted"), fs::Permissions::from_mode(0o700)).unwrap();
        let mut created = BTreeSet::new();
        assert!(matches!(
            write_private_runtime_file(&root, "planted/a.js", b"x", &mut created, close_checked),
            Err(PackageError::Io)
        ));
        assert!(!root.join("planted/a.js").exists());

        // A symlink planted where a child directory must be created is refused too.
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        let mut created = BTreeSet::new();
        assert!(matches!(
            write_private_runtime_file(&root, "link/a.js", b"x", &mut created, close_checked),
            Err(PackageError::Io)
        ));
        assert!(!outside.join("a.js").exists());

        // A fresh child is created private and the file lands 0400.
        let mut created = BTreeSet::new();
        write_private_runtime_file(&root, "fresh/sub/a.js", b"ok", &mut created, close_checked)
            .unwrap();
        for dir in ["fresh", "fresh/sub"] {
            assert_eq!(
                fs::metadata(root.join(dir)).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let file = fs::metadata(root.join("fresh/sub/a.js")).unwrap();
        assert_eq!(file.permissions().mode() & 0o777, 0o400);
        assert_eq!(fs::read(root.join("fresh/sub/a.js")).unwrap(), b"ok");
        // Non-normal components never reach the filesystem.
        for bad in ["../x.js", "/abs.js", "a/../b.js", ""] {
            assert!(matches!(
                write_private_runtime_file(&root, bad, b"x", &mut BTreeSet::new(), close_checked),
                Err(PackageError::Io)
            ));
        }
    }

    // L-1: with the fsync gone, close is where a deferred write error surfaces; a failing
    // close refuses the copy instead of letting Node execute a possibly torn file.
    #[test]
    fn runtime_file_with_a_failing_close_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        make_private_dir(&root).unwrap();
        let result =
            write_private_runtime_file(&root, "a.js", b"x", &mut BTreeSet::new(), |_file| {
                Err(std::io::Error::other("deferred write error"))
            });
        assert!(matches!(result, Err(PackageError::Io)));
        let mut created = BTreeSet::new();
        write_private_runtime_file(&root, "b.js", b"x", &mut created, close_checked).unwrap();
    }

    // The tree `create` returns is removed on drop (a failure part way is covered by
    // runtime_materialization_failing_part_way_leaves_nothing).
    #[test]
    fn runtime_materialization_create_builds_and_removes_a_private_tree() {
        let mut bytes = BTreeMap::new();
        bytes.insert("a/b/c.js".to_string(), b"c".to_vec().into_boxed_slice());
        bytes.insert("a/d.js".to_string(), b"d".to_vec().into_boxed_slice());
        let runtime = RuntimeMaterialization::create(&bytes).unwrap();
        let root = runtime.root.clone();
        assert_eq!(fs::read(root.join("a/b/c.js")).unwrap(), b"c");
        drop(runtime);
        assert!(!root.exists());
    }

    // MED-1: the base and its ancestors must be untouchable by other users.
    #[cfg(unix)]
    #[test]
    fn runtime_base_that_others_can_write_is_refused_and_named() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let outer = fs::canonicalize(temp.path()).unwrap().join("outer");
        let base = outer.join("base");
        fs::create_dir_all(&base).unwrap();
        let mut bytes = BTreeMap::new();
        bytes.insert("a.js".to_string(), b"a".to_vec().into_boxed_slice());

        // A trusted base works and leaves the tree under it.
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        drop(RuntimeMaterialization::create_in(&base, &bytes).unwrap());

        // A group/world-writable, non-sticky base is refused, and the error names it.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        let error = RuntimeMaterialization::create_in(&base, &bytes)
            .err()
            .unwrap();
        assert!(
            matches!(&error, PackageError::UnsafeRuntimeBase(m)
            if m.contains(base.to_str().unwrap()) && m.contains("writable")),
            "{error:?}"
        );
        assert_eq!(
            fs::read_dir(&base).unwrap().count(),
            0,
            "nothing was created"
        );

        // So is a writable ANCESTOR above an otherwise private base.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o777)).unwrap();
        let error = RuntimeMaterialization::create_in(&base, &bytes)
            .err()
            .unwrap();
        assert!(
            matches!(&error, PackageError::UnsafeRuntimeBase(m)
            if m.contains(outer.to_str().unwrap())),
            "{error:?}"
        );
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // MED-C: the reason a runtime tree could not be built is mapped, not dropped, and the
    // row outcome stays Incomplete.
    #[test]
    fn runtime_unavailable_keeps_the_row_incomplete() {
        let error = PackageError::UnsafeRuntimeBase("/shared refused".into());
        assert!(matches!(
            runtime_unavailable(&error),
            RowFailure::Incomplete
        ));
    }

    #[cfg(unix)]
    fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, root)
    }

    // MED-B: the base must be private to this user. A directory that is not group/other
    // writable (so the ancestor policy passes) but is readable and searchable by others
    // is still a shared base: the owner is the only user who may create entries beside
    // the trees.
    #[cfg(unix)]
    #[test]
    fn runtime_base_that_others_can_enter_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, root) = private_tempdir();
        let base = root.join("base");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let mut bytes = BTreeMap::new();
        bytes.insert("a.js".to_string(), b"a".to_vec().into_boxed_slice());
        let error = RuntimeMaterialization::create_in(&base, &bytes)
            .err()
            .unwrap();
        assert!(
            matches!(&error, PackageError::UnsafeRuntimeBase(m)
            if m.contains(base.to_str().unwrap()) && m.contains("private")),
            "{error:?}"
        );
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0, "nothing created");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_base_chooser_prefers_xdg_then_state_then_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, root) = private_tempdir();
        let xdg = root.join("run");
        let state = root.join("state");
        fs::create_dir(&xdg).unwrap();

        // XDG exists and is trusted: it wins and the directory is created private.
        let chosen = choose_runtime_base(Some(&xdg), Some(&state)).unwrap();
        assert_eq!(chosen, xdg.join("csq-gate"));
        assert_eq!(
            fs::metadata(&chosen).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            !state.exists(),
            "the fallback is not touched when XDG works"
        );

        // XDG missing: the state directory is used, created private.
        let missing = root.join("absent");
        let chosen = choose_runtime_base(Some(&missing), Some(&state)).unwrap();
        assert_eq!(chosen, state.join("gate-runtime"));
        assert!(!missing.exists(), "the XDG parent is never created");

        // XDG whose csq-gate is a shared directory falls through to the state directory.
        let shared_xdg = root.join("shared-run");
        fs::create_dir(&shared_xdg).unwrap();
        let gate = shared_xdg.join("csq-gate");
        fs::create_dir(&gate).unwrap();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o777)).unwrap();
        // `ensure_private_dir` tightens a directory we own, so make it foreign-looking by
        // turning the sibling parent writable instead: the chain check refuses it.
        fs::set_permissions(&shared_xdg, fs::Permissions::from_mode(0o777)).unwrap();
        let chosen = choose_runtime_base(Some(&shared_xdg), Some(&state)).unwrap();
        assert_eq!(chosen, state.join("gate-runtime"));
        fs::set_permissions(&shared_xdg, fs::Permissions::from_mode(0o700)).unwrap();

        // Nothing usable: refused, and every reason is carried.
        let error = choose_runtime_base(Some(&missing), None).err().unwrap();
        assert!(
            matches!(&error, PackageError::UnsafeRuntimeBase(m)
            if m.contains("XDG_RUNTIME_DIR") && m.contains("no csq state directory")),
            "{error:?}"
        );
    }

    // MED-B end to end: a package.json planted in the (shared) parent of the base cannot
    // change how our script loads, because the tree has its own root package.json.
    #[cfg(unix)]
    #[test]
    fn runtime_tree_has_its_own_root_package_json_and_ignores_a_planted_one() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, root) = private_tempdir();
        let base = root.join("base");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        // What another user could plant in a shared parent: ESM mode for everything below.
        fs::write(root.join("package.json"), br#"{"type":"module"}"#).unwrap();
        let mut bytes = BTreeMap::new();
        bytes.insert(
            "hook.js".to_string(),
            b"console.log(typeof require)".to_vec().into_boxed_slice(),
        );
        let runtime = RuntimeMaterialization::create_in(&base, &bytes).unwrap();
        assert_eq!(
            fs::read(runtime.root.join("package.json")).unwrap(),
            RUNTIME_ROOT_PACKAGE_JSON
        );
        // Both spawns resolve `node` through PATH, which sibling tests (cli_deps) empty or
        // replace while holding the shared env lock. Hold it too, so PATH is the same for the
        // probe and the run; without it the second spawn raced to NotFound in the full suite.
        let _env_guard = crate::platform::test_env::lock();
        let Ok(node) = Command::new("node").arg("--version").output() else {
            return;
        };
        assert!(node.status.success());
        let out = Command::new("node")
            .arg(runtime.root.join("hook.js"))
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "function",
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // A failure part way (here the second file has an invalid path) leaves nothing behind.
    #[cfg(unix)]
    #[test]
    fn runtime_materialization_failing_part_way_leaves_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap().join("base");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let mut bytes = BTreeMap::new();
        bytes.insert("a.js".to_string(), b"a".to_vec().into_boxed_slice());
        bytes.insert("z/../x.js".to_string(), b"x".to_vec().into_boxed_slice());
        assert!(RuntimeMaterialization::create_in(&base, &bytes).is_err());
        assert_eq!(
            fs::read_dir(&base).unwrap().count(),
            0,
            "the partial tree must be removed"
        );
    }
}
