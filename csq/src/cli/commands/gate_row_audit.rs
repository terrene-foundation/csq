//! Private, bounded storage for observations produced by a pool invocation.
//! This file writer does not execute rows or infer execution from registration.

use serde_json::{json, Value};
#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

pub(crate) const MAX_AUDIT_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_AUDIT_RECORDS: usize = 8192;

pub(crate) struct AuditWriter {
    file: File,
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
    parent_path: PathBuf,
    #[cfg(unix)]
    repo_path: PathBuf,
    #[cfg(unix)]
    parent_identity: Identity,
    #[cfg(unix)]
    repo_identity: Identity,
    #[cfg(unix)]
    file_identity: Identity,
    #[cfg(unix)]
    name: std::ffi::CString,
    bytes: u64,
    expected_prefix: Vec<u8>,
    records: usize,
    failed: bool,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
}

#[cfg(unix)]
fn identity(metadata: &fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    }
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "private audit custody")
}

impl AuditWriter {
    /// Create a new leaf beneath an existing owner-private directory outside
    /// the authenticated repository. Neither an existing leaf nor a symlink
    /// supplies authority to truncate or replace a file.
    pub(crate) fn open(path: &Path, repo: &Path, header: &Value) -> io::Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path, repo, header);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private audit platform",
            ))
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if !path.is_absolute() || header.get("type").and_then(Value::as_str) != Some("header") {
                return Err(refused());
            }
            let name = path.file_name().ok_or_else(refused)?;
            let parent_path = fs::canonicalize(path.parent().ok_or_else(refused)?)?;
            let repo_path = fs::canonicalize(repo)?;
            if parent_path.starts_with(&repo_path) {
                return Err(refused());
            }
            // SAFETY: geteuid takes no pointers and only observes caller identity.
            let uid = unsafe { libc::geteuid() };
            let before = fs::symlink_metadata(&parent_path)?;
            let repo_metadata = fs::symlink_metadata(&repo_path)?;
            if !before.is_dir()
                || before.uid() != uid
                || before.mode() & 0o077 != 0
                || !repo_metadata.is_dir()
            {
                return Err(refused());
            }
            let parent = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&parent_path)?;
            let parent_identity = identity(&parent.metadata()?);
            if parent_identity != identity(&before)
                || identity(&fs::symlink_metadata(&parent_path)?) != parent_identity
                || fs::canonicalize(&parent_path)? != parent_path
            {
                return Err(refused());
            }
            let name = std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| refused())?;
            // SAFETY: parent owns the directory fd; name is a live NUL-terminated
            // single leaf component. O_EXCL creates exactly one new private leaf.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat returned an owned fd transferred once.
            let file = unsafe { File::from_raw_fd(fd) };
            let file_identity = identity(&file.metadata()?);
            let mut writer = Self {
                file,
                parent,
                parent_path,
                repo_path,
                parent_identity,
                repo_identity: identity(&repo_metadata),
                file_identity,
                name,
                bytes: 0,
                expected_prefix: Vec::new(),
                records: 0,
                failed: false,
            };
            writer.write_value(header)?;
            Ok(writer)
        }
    }

    /// Persist one actual observation. The compiled pool observer owns its
    /// schema and provenance; this helper supplies file custody and limits.
    pub(crate) fn record(&mut self, value: &Value) -> io::Result<()> {
        if self.records >= MAX_AUDIT_RECORDS {
            return Err(self.fail(io::Error::other("audit record limit")));
        }
        self.write_value(value)?;
        self.records += 1;
        Ok(())
    }

    /// No completion marker is written after any failed custody/write check.
    /// The caller must call this only after all pool observations are admitted.
    pub(crate) fn complete(mut self) -> io::Result<()> {
        self.write_value(&json!({"type":"complete", "records":self.records}))
    }

    fn write_value(&mut self, value: &Value) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("audit already failed"));
        }
        if let Err(error) = self.guard() {
            return Err(self.fail(error));
        }
        let mut bytes =
            serde_json::to_vec(value).map_err(|_| self.fail(io::Error::other("audit encoding")))?;
        bytes.push(b'\n');
        if self.bytes.saturating_add(bytes.len() as u64) > MAX_AUDIT_BYTES {
            return Err(self.fail(io::Error::other("audit byte limit")));
        }
        if let Err(error) = self.file.write_all(&bytes).and_then(|_| self.file.flush()) {
            return Err(self.fail(error));
        }
        self.bytes += bytes.len() as u64;
        self.expected_prefix.extend_from_slice(&bytes);
        if let Err(error) = self
            .guard()
            .and_then(|_| self.file.sync_all())
            .and_then(|_| self.guard())
        {
            return Err(self.fail(error));
        }
        Ok(())
    }

    // libc stat field widths differ between Darwin and Linux.
    #[allow(clippy::unnecessary_cast)]
    fn guard(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || metadata.len() != self.bytes
            || self.expected_prefix.len() as u64 != self.bytes
        {
            return Err(refused());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no pointer arguments.
            let uid = unsafe { libc::geteuid() };
            let parent = self.parent.metadata()?;
            let named_parent = fs::symlink_metadata(&self.parent_path)?;
            let named_repo = fs::symlink_metadata(&self.repo_path)?;
            if identity(&metadata) != self.file_identity
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || !parent.is_dir()
                || parent.uid() != uid
                || parent.mode() & 0o077 != 0
                || identity(&parent) != self.parent_identity
                || identity(&named_parent) != self.parent_identity
                || !named_parent.is_dir()
                || fs::canonicalize(&self.parent_path)? != self.parent_path
                || identity(&named_repo) != self.repo_identity
                || !named_repo.is_dir()
                || fs::canonicalize(&self.repo_path)? != self.repo_path
                || self.parent_path.starts_with(&self.repo_path)
            {
                return Err(refused());
            }
            // Identity and length do not detect same-length in-place rewrites.
            // Read the held descriptor without changing its write cursor and
            // compare every already-admitted byte, including JSONL framing.
            let mut offset = 0;
            let mut chunk = [0_u8; 8192];
            while offset < self.expected_prefix.len() {
                let limit = chunk.len().min(self.expected_prefix.len() - offset);
                let read = self.file.read_at(&mut chunk[..limit], offset as u64)?;
                if read == 0 || chunk[..read] != self.expected_prefix[offset..offset + read] {
                    return Err(refused());
                }
                offset += read;
            }
            // SAFETY: stat is output-only; held parent/name remain valid. No
            // symlink is followed and no pathname is used to delete anything.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::fstatat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0
                || stat.st_dev as u64 != self.file_identity.dev
                || stat.st_ino as u64 != self.file_identity.ino
                || stat.st_uid != uid
                || stat.st_nlink != 1
                || stat.st_mode as u32 != self.file_identity.mode
            {
                return Err(refused());
            }
        }
        Ok(())
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        self.failed = true;
        error
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        // A hook subprocess fixture temporarily rewrites process TMPDIR; own
        // a stable root so its cleanup cannot delete this audit's custody.
        // Inside that fixture's CHILD process (see
        // `tmpdir_outlives_test_support`) a parent-owned sandbox root is
        // handed down so kill+reap is followed by exact owned cleanup.
        let root =
            std::env::var_os(crate::cli::commands::tmpdir_outlives_test_support::SANDBOX_ENV)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        let temp = tempfile::TempDir::new_in(root).unwrap();
        let repo = temp.path().join("repo");
        let private = temp.path().join("private");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, repo, private)
    }

    /// The audit custody root must be independent of the ambient TMPDIR: the
    /// test transiently points TMPDIR at a directory it deletes. PARENT/CHILD
    /// dispatch (one test name; see `tmpdir_outlives_test_support`): without
    /// the marker the parent re-executes THIS test in a bounded, hermetic
    /// child and never mutates TMPDIR itself; with the marker the child runs
    /// the original mutation/deletion/assertion (falsifier preserved: the
    /// custody assert fails if `fixture()` reverts to ambient
    /// `TempDir::new()`).
    #[test]
    fn pool_audit_fixture_outlives_a_transient_process_tmpdir() {
        if std::env::var_os(crate::cli::commands::tmpdir_outlives_test_support::CHILD_ENV).is_some()
        {
            // Witness: proves to the parent that THIS body ran (see
            // `spawn_outlives_child` on why the selector alone cannot).
            println!("outlives-witness:pool-audit-custody");
            let sandbox = PathBuf::from(
                std::env::var_os(crate::cli::commands::tmpdir_outlives_test_support::SANDBOX_ENV)
                    .expect("sandbox env set by the parent dispatch"),
            );
            let _env = csq_core::platform::test_env::lock();
            let transient =
                tempfile::TempDir::new_in(&sandbox).expect("child transient under the sandbox");
            let previous = std::env::var_os("TMPDIR");
            std::env::set_var("TMPDIR", transient.path());
            let (temp, repo, private) = fixture();
            match previous {
                Some(value) => std::env::set_var("TMPDIR", value),
                None => std::env::remove_var("TMPDIR"),
            }
            drop(transient);
            assert!(temp.path().is_dir(), "audit custody must own its root");
            let path = private.join("audit");
            let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
            writer.record(&json!({"type":"row"})).unwrap();
            writer.complete().unwrap();
            assert!(fs::read_to_string(path).unwrap().contains("complete"));
            return;
        }
        crate::cli::commands::tmpdir_outlives_test_support::spawn_outlives_child(
            "cli::commands::gate_row_audit::tests::pool_audit_fixture_outlives_a_transient_process_tmpdir",
            "outlives-witness:pool-audit-custody",
        );
    }

    #[test]
    fn pool_audit_records_exact_observations_and_one_terminal_marker() {
        let (_temp, repo, private) = fixture();
        let path = private.join("audit.jsonl");
        let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
        writer
            .record(&json!({"type":"row", "row_id":"actual-row", "stdout_sha256":"a".repeat(64)}))
            .unwrap();
        writer.complete().unwrap();
        let records: Vec<Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1]["row_id"], "actual-row");
        assert_eq!(records[2], json!({"type":"complete","records":1}));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn pool_audit_refuses_existing_symlink_public_and_repository_destinations() {
        let (_temp, repo, private) = fixture();
        let header = json!({"type":"header"});
        let existing = private.join("existing");
        fs::write(&existing, b"keep").unwrap();
        assert!(AuditWriter::open(&existing, &repo, &header).is_err());
        let link = private.join("link");
        symlink(&existing, &link).unwrap();
        assert!(AuditWriter::open(&link, &repo, &header).is_err());
        assert_eq!(fs::read(existing).unwrap(), b"keep");
        assert!(AuditWriter::open(&repo.join("audit"), &repo, &header).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AuditWriter::open(&private.join("public"), &repo, &header).is_err());
    }

    #[test]
    fn pool_audit_leaf_replacement_and_hardlink_cannot_complete() {
        for hardlink in [false, true] {
            let (_temp, repo, private) = fixture();
            let path = private.join("audit");
            let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
            if hardlink {
                fs::hard_link(&path, private.join("extra-link")).unwrap();
            } else {
                fs::rename(&path, private.join("original")).unwrap();
                fs::write(&path, b"replacement").unwrap();
            }
            assert!(writer.record(&json!({"type":"row"})).is_err());
            assert!(writer.complete().is_err());
            if !hardlink {
                assert_eq!(fs::read(&path).unwrap(), b"replacement");
            }
        }
    }

    #[test]
    fn pool_audit_parent_replacement_cannot_claim_completion() {
        let (_temp, repo, private) = fixture();
        let path = private.join("audit");
        let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
        let moved = private.with_file_name("moved");
        fs::rename(&private, &moved).unwrap();
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(writer.record(&json!({"type":"row"})).is_err());
        assert!(writer.complete().is_err());
        assert!(!path.exists());
        assert!(!fs::read_to_string(moved.join("audit"))
            .unwrap()
            .contains("complete"));
    }

    #[test]
    fn pool_audit_same_length_in_place_tamper_cannot_complete() {
        let (_temp, repo, private) = fixture();
        let path = private.join("audit");
        let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
        let before = fs::metadata(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[2] = if bytes[2] == b'x' { b'y' } else { b'x' };
        fs::write(&path, &bytes).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(identity(&before), identity(&after));
        assert_eq!(before.len(), after.len());
        assert!(writer.record(&json!({"type":"row"})).is_err());
        assert!(writer.complete().is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn pool_audit_real_serialized_byte_limit_prevents_completion() {
        let (_temp, repo, private) = fixture();
        let path = private.join("audit");
        let mut writer = AuditWriter::open(&path, &repo, &json!({"type":"header"})).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(writer
            .record(&json!({"type":"row","large":"x".repeat(MAX_AUDIT_BYTES as usize)}))
            .is_err());
        assert!(writer.complete().is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }
}
