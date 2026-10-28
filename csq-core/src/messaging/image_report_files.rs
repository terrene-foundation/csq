//! Descriptor-bound private image report publication and read-only collection.
use super::*;
use crate::sessions::directives::dirfd::DirFd;
use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};
fn unsafe_io(_: std::io::Error) -> ReportError {
    ReportError::Unsafe
}
fn check(meta: &Metadata, directory: bool) -> Result<(), ReportError> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid
        || meta.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(ReportError::Unsafe);
    }
    Ok(())
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
fn directory(path: &Path) -> Result<DirFd, ReportError> {
    if !path.is_absolute() || std::fs::canonicalize(path).map_err(unsafe_io)? != path {
        return Err(ReportError::Unsafe);
    }
    let dir = DirFd::open(path).map_err(unsafe_io)?;
    check(&dir.metadata().map_err(unsafe_io)?, true)?;
    Ok(dir)
}
fn regular(dir: &DirFd, name: &str, flags: libc::c_int) -> Result<File, ReportError> {
    let file = dir.regular(name, flags).map_err(unsafe_io)?;
    check(&file.metadata().map_err(unsafe_io)?, false)?;
    Ok(file)
}
fn recheck_file(dir: &DirFd, name: &str, file: &File) -> Result<(), ReportError> {
    let named = regular(dir, name, libc::O_RDONLY)?;
    let (a, b) = (
        file.metadata().map_err(unsafe_io)?,
        named.metadata().map_err(unsafe_io)?,
    );
    check(&a, false)?;
    if !same(&a, &b) {
        return Err(ReportError::Unsafe);
    }
    Ok(())
}
fn anchors(path: &Path, handle: &DirFd, reports: &DirFd) -> Result<(), ReportError> {
    let named = directory(path)?;
    let child = named.open_child(DIRECTORY).map_err(unsafe_io)?;
    let (a, b, c, d) = (
        handle.metadata().map_err(unsafe_io)?,
        named.metadata().map_err(unsafe_io)?,
        reports.metadata().map_err(unsafe_io)?,
        child.metadata().map_err(unsafe_io)?,
    );
    for m in [&a, &b, &c, &d] {
        check(m, true)?;
    }
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) || (c.dev(), c.ino()) != (d.dev(), d.ino()) {
        return Err(ReportError::Unsafe);
    }
    Ok(())
}
fn names(dir: &DirFd, creating: bool) -> Result<Vec<String>, ReportError> {
    let list = dir.names_strict(17).map_err(unsafe_io)?;
    if !list.complete {
        return Err(ReportError::Limit);
    }
    let (mut finals, mut temps) = (Vec::new(), 0usize);
    for name in list.names {
        if name == ".lock" {
            continue;
        }
        if name.strip_prefix(".tmp-").is_some_and(slot) {
            temps += 1;
        } else if name.strip_suffix(".json").is_some_and(slot) {
            finals.push(name);
        } else {
            return Err(ReportError::Unsafe);
        }
    }
    if finals.len() > MAX_REPORTS || temps > MAX_REPORTS || (creating && temps == MAX_REPORTS) {
        return Err(ReportError::Limit);
    }
    Ok(finals)
}
/// An acquired flock is released at the publication boundary, even when a
/// concurrent fork still retains the same open description until exec.
struct PublicationLock(File);
impl Drop for PublicationLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: this guard owns a live descriptor and is created only after
        // successful LOCK_EX. flock accesses no Rust memory; File closes next.
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            tracing::warn!(
                error_kind = "image_report_unlock_failed",
                "image report publication lock could not be released"
            );
        }
    }
}

pub(super) fn publish(who: &VerifiedSession, report: &ImageReport) -> Result<(), ReportError> {
    publish_with_lock_observer(who, report, |_| {})
}

// The normal publisher and deterministic fork regression share every guard
// and mutation. The observer receives an already-acquired lock only.
pub(super) fn publish_with_lock_observer(
    who: &VerifiedSession,
    report: &ImageReport,
    after_lock: impl FnOnce(&File),
) -> Result<(), ReportError> {
    let r = who.as_recipient();
    let surface = match r.surface {
        super::super::model::Surface::ClaudeCode => ImageSurface::ClaudeCode,
        super::super::model::Surface::Codex => ImageSurface::Codex,
    };
    if report.child.pid != std::process::id()
        || Some(report.child.start_exact) != crate::sessions::ancestor_start(std::process::id())
        || report.session.pid != r.pid
        || report.session.started_at != r.started_at
        || Some(report.session.start_exact) != r.started_exact
        || report.session.surface != surface
        || report.session.handle_sha256 != who.handle_dir_hash()
    {
        return Err(ReportError::Malformed);
    }
    let bytes = report.encode()?;
    let path = who.handle_dir();
    let handle = directory(path)?;
    match handle.mkdir_child(DIRECTORY) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(unsafe_io(e)),
    }
    let reports = handle.open_child(DIRECTORY).map_err(unsafe_io)?;
    check(&reports.metadata().map_err(unsafe_io)?, true)?;
    let lock = regular(&reports, ".lock", libc::O_RDWR | libc::O_CREAT)?;
    use std::os::fd::AsRawFd;
    // SAFETY: lock is an owned regular descriptor; flock accesses no Rust memory.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(ReportError::Busy);
    }
    // Busy never constructs this guard, so it cannot unlock another holder.
    let held = PublicationLock(lock);
    let lock = &held.0;
    after_lock(lock);
    recheck_file(&reports, ".lock", lock)?;
    anchors(path, &handle, &reports)?;
    let filename = report.filename();
    let list = names(&reports, true)?;
    if list.len() == MAX_REPORTS && !list.contains(&filename) {
        return Err(ReportError::Limit);
    }
    if list.contains(&filename) {
        let existing = regular(&reports, &filename, libc::O_RDONLY)?;
        recheck_file(&reports, &filename, &existing)?;
    }
    let temporary = format!(".tmp-{}-{}", report.child.pid, report.child.start_exact);
    let mut file = regular(
        &reports,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    let result = (|| {
        file.write_all(&bytes).map_err(unsafe_io)?;
        file.sync_all().map_err(unsafe_io)?;
        recheck_file(&reports, &temporary, &file)?;
        anchors(path, &handle, &reports)?;
        recheck_file(&reports, ".lock", lock)?;
        reports
            .rename_to(&temporary, &reports, &filename)
            .map_err(unsafe_io)?;
        // SAFETY: reports owns a live directory descriptor; fsync takes no pointers.
        if unsafe { libc::fsync(reports.raw_fd()) } != 0 {
            return Err(ReportError::Unsafe);
        }
        anchors(path, &handle, &reports)?;
        recheck_file(&reports, &filename, &file)
    })();
    if result.is_err()
        && recheck_file(&reports, &temporary, &file).is_ok()
        && reports.unlink(&temporary).is_err()
    {
        tracing::warn!(
            error_kind = "image_report_temp_cleanup_failed",
            "image report temporary file could not be removed"
        );
    }
    result
}
pub(super) fn read(path: &Path) -> Result<Vec<ImageReport>, ReportError> {
    Ok(read_observed(path, &|_| ())?
        .into_iter()
        .map(|row| row.report)
        .collect())
}
pub(super) fn read_observed<T>(
    path: &Path,
    observe: &impl Fn(&ChildIdentity) -> T,
) -> Result<Vec<ObservedReport<T>>, ReportError> {
    let handle = directory(path)?;
    let reports = match handle.open_child(DIRECTORY) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReportError::Unavailable),
        Err(e) => return Err(unsafe_io(e)),
    };
    check(&reports.metadata().map_err(unsafe_io)?, true)?;
    let list = names(&reports, false)?;
    let mut output = Vec::new();
    for name in list {
        // names already checked the whole canonical numeric filename and raw budget.
        let (pid, start) = name
            .strip_suffix(".json")
            .and_then(|s| s.split_once('-'))
            .ok_or(ReportError::Malformed)?;
        let child = ChildIdentity {
            pid: pid.parse().map_err(|_| ReportError::Malformed)?,
            start_exact: start.parse().map_err(|_| ReportError::Malformed)?,
        };
        let observed_before = observe(&child);
        let mut file = regular(&reports, &name, libc::O_RDONLY)?;
        let before = file.metadata().map_err(unsafe_io)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_REPORT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(unsafe_io)?;
        let after = file.metadata().map_err(unsafe_io)?;
        if !same(&before, &after) {
            return Err(ReportError::Unsafe);
        }
        recheck_file(&reports, &name, &file)?;
        let report = ImageReport::decode(&bytes)?;
        if report.filename() != name {
            return Err(ReportError::Malformed);
        }
        let observed_after = observe(&child);
        output.push(ObservedReport {
            report,
            before: observed_before,
            after: observed_after,
        });
    }
    anchors(path, &handle, &reports)?;
    Ok(output)
}
