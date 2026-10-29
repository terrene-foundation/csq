//! Bounded disk-footprint measurement for `csq doctor` (an internal ticket bundle):
//! `~/.claude/projects`, `~/.claude/accounts`, and any
//! `thread_history_*.sqlite` over 1 GiB under accounts.
//!
//! On unix the walk is by file descriptor: the root is opened `O_NOFOLLOW`, and
//! every sub-directory is opened with `openat(parent_fd, name,
//! O_DIRECTORY|O_NOFOLLOW)` and its entries classified with `fstatat(...,
//! AT_SYMLINK_NOFOLLOW)`. Replacing a directory OR any ancestor of it with a
//! symlink after that directory was opened therefore cannot redirect the walk: the
//! descriptor still names the original directory, and a symlink entry is never
//! followed. The ancestors of the root itself (`~/.claude`) are not checked. The
//! walk is capped by entry count and wall time (the latter checked between
//! entries: one stat hung on a stalled mount is not interrupted); exceeding either
//! cap, an unreadable entry or a swapped directory yields `Unknown`, never a
//! partial number. Non-unix builds report `Unknown`. Paths are reported relative to
//! home (`~/...`), never as raw home paths.

use serde::Serialize;
use std::path::Path;
use std::time::Duration;

/// A `thread_history_*.sqlite` at least this large is listed.
pub const BIG_THREAD_BYTES: u64 = 1 << 30;
/// Entry cap per tree.
pub const MAX_ENTRIES: usize = 200_000;
/// Wall-clock cap per tree (a budget guard, not logic input).
pub const MAX_WALK: Duration = Duration::from_secs(2);

/// Size of one tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "lowercase")]
pub enum Size {
    /// Total bytes.
    Bytes(u64),
    /// Could not be measured within bounds (reason).
    Unknown(String),
}

/// A large thread-history database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BigThread {
    /// Path shown as `~/...`.
    pub path: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// Result of [`measure`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Footprint {
    /// `~/.claude/projects`.
    pub projects: Size,
    /// `~/.claude/accounts`.
    pub accounts: Size,
    /// Thread-history databases over 1 GiB under accounts.
    pub big_threads: Vec<BigThread>,
}

/// Measure with the default bounds.
pub fn measure(home: &Path) -> Footprint {
    measure_with(home, MAX_ENTRIES, MAX_WALK)
}

/// Measure with explicit bounds (tests shrink them).
pub fn measure_with(home: &Path, max_entries: usize, max_walk: Duration) -> Footprint {
    measure_with_hook(home, max_entries, max_walk, &mut |_| {})
}

/// [`measure_with`] plus a hook called with each directory path just before the
/// walk enters it: tests use it to swap a directory mid-walk.
pub fn measure_with_hook(
    home: &Path,
    max_entries: usize,
    max_walk: Duration,
    hook: &mut dyn FnMut(&Path),
) -> Footprint {
    let claude = home.join(".claude");
    let (projects, _) = walk(
        home,
        &claude.join("projects"),
        max_entries,
        max_walk,
        0,
        hook,
    );
    let (accounts, big) = walk(
        home,
        &claude.join("accounts"),
        max_entries,
        max_walk,
        BIG_THREAD_BYTES,
        hook,
    );
    Footprint {
        projects,
        accounts,
        big_threads: big,
    }
}

/// Render `p` as `~/rel` when under `home`, else via `redact_path`.
pub fn display_rel(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => crate::cli_deps::sanitize::redact_path(p),
    }
}

#[cfg(not(unix))]
fn walk(
    _home: &Path,
    _root: &Path,
    _max_entries: usize,
    _max_walk: Duration,
    _big_min: u64,
    _hook: &mut dyn FnMut(&Path),
) -> (Size, Vec<BigThread>) {
    (
        Size::Unknown("fd-based walk is unix-only".into()),
        Vec::new(),
    )
}

#[cfg(unix)]
const MAX_DEPTH: usize = 64;

#[cfg(unix)]
struct Walk<'a> {
    home: &'a Path,
    max_entries: usize,
    max_walk: Duration,
    start: std::time::Instant,
    big_min: u64,
    hook: &'a mut dyn FnMut(&Path),
    seen: usize,
    total: u64,
    big: Vec<BigThread>,
    unreadable: bool,
}

#[cfg(unix)]
fn open_dir(
    parent: Option<std::os::fd::RawFd>,
    name: &std::ffi::CStr,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `name` is a valid NUL-terminated string; `parent`, when given, is a
    // descriptor owned by the caller for the duration of the call.
    let fd = unsafe {
        match parent {
            Some(p) => libc::openat(p, name.as_ptr(), flags),
            None => libc::open(name.as_ptr(), flags),
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by open/openat and is owned by nobody else.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Entry names of the directory behind `fd`, at most `limit` of them.
#[cfg(unix)]
fn list_dir(fd: &std::os::fd::OwnedFd, limit: usize) -> std::io::Result<Vec<std::ffi::CString>> {
    use std::os::fd::AsRawFd;
    // SAFETY: dup of a valid descriptor; fdopendir takes ownership of the dup on
    // success and we close it ourselves on failure.
    let dup = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        let e = std::io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: `dirp` is a live DIR* until closedir below.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() || out.len() >= limit {
            break;
        }
        // SAFETY: `d_name` is a NUL-terminated array inside the returned dirent,
        // read before the next readdir call.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            out.push(name.to_owned());
        }
    }
    // SAFETY: closes `dirp` and the dup'd descriptor it owns.
    unsafe { libc::closedir(dirp) };
    Ok(out)
}

#[cfg(unix)]
fn walk_fd(
    fd: &std::os::fd::OwnedFd,
    path: &Path,
    depth: usize,
    w: &mut Walk<'_>,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    if depth > MAX_DEPTH {
        w.unreadable = true;
        return Ok(());
    }
    let limit = w.max_entries.saturating_sub(w.seen).saturating_add(1);
    let names = match list_dir(fd, limit) {
        Ok(n) => n,
        Err(_) => {
            w.unreadable = true;
            return Ok(());
        }
    };
    for name in names {
        w.seen += 1;
        if w.seen > w.max_entries {
            return Err(format!("more than {} entries", w.max_entries));
        }
        if w.seen.is_multiple_of(256) && w.start.elapsed() > w.max_walk {
            return Err("walk time cap reached".into());
        }
        // SAFETY: zeroed `stat` is a valid out-parameter; `name` is NUL-terminated.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                fd.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            w.unreadable = true;
            continue;
        }
        // st_mode and S_IFMT share one type per platform (u16 on macOS, u32 on Linux).
        let kind = st.st_mode & libc::S_IFMT;
        let child = path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        if kind == libc::S_IFDIR {
            (w.hook)(&child);
            match open_dir(Some(fd.as_raw_fd()), &name) {
                Ok(cfd) => walk_fd(&cfd, &child, depth + 1, w)?,
                // swapped for a symlink or removed since it was listed
                Err(_) => w.unreadable = true,
            }
        } else if kind == libc::S_IFREG {
            let len = st.st_size as u64;
            w.total += len;
            if w.big_min > 0 && len >= w.big_min {
                let n = name.to_string_lossy();
                if n.starts_with("thread_history_") && n.ends_with(".sqlite") {
                    w.big.push(BigThread {
                        path: display_rel(w.home, &child),
                        bytes: len,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn walk(
    home: &Path,
    root: &Path,
    max_entries: usize,
    max_walk: Duration,
    big_min: u64,
    hook: &mut dyn FnMut(&Path),
) -> (Size, Vec<BigThread>) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(croot) = std::ffi::CString::new(root.as_os_str().as_bytes()) else {
        return (Size::Unknown("unreadable".into()), Vec::new());
    };
    let rfd = match open_dir(None, &croot) {
        Ok(f) => f,
        // Absent tree: zero bytes is a true measurement.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Size::Bytes(0), Vec::new()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
            return (Size::Unknown("not a directory".into()), Vec::new())
        }
        Err(e) => {
            return (
                Size::Unknown(format!("unreadable: {}", e.kind())),
                Vec::new(),
            )
        }
    };
    let mut w = Walk {
        home,
        max_entries,
        max_walk,
        start: std::time::Instant::now(),
        big_min,
        hook,
        seen: 0,
        total: 0,
        big: Vec::new(),
        unreadable: false,
    };
    if let Err(reason) = walk_fd(&rfd, root, 0, &mut w) {
        return (Size::Unknown(reason), Vec::new());
    }
    if w.unreadable {
        return (Size::Unknown("some entries unreadable".into()), Vec::new());
    }
    w.big
        .sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
    (Size::Bytes(w.total), w.big)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unix-only: the fd walk (and therefore a real byte count) does not exist
    // on Windows, where measure_with returns Size::Unknown by design. The
    // non-unix contract is asserted separately below rather than by weakening
    // these assertions.
    #[cfg(unix)]
    #[test]
    fn measures_sums_and_lists_big_threads_relative_to_home() {
        let h = tempfile::tempdir().unwrap();
        let acc = h.path().join(".claude/accounts/term-1");
        std::fs::create_dir_all(&acc).unwrap();
        std::fs::create_dir_all(h.path().join(".claude/projects/p")).unwrap();
        std::fs::write(h.path().join(".claude/projects/p/a.jsonl"), vec![0u8; 100]).unwrap();
        std::fs::write(acc.join("thread_history_x.sqlite"), vec![0u8; 50]).unwrap();
        std::fs::write(acc.join("thread_history_big.sqlite"), vec![0u8; 8]).unwrap();
        let f = measure_with(h.path(), 100, Duration::from_secs(5));
        assert_eq!(f.projects, Size::Bytes(100));
        assert_eq!(f.accounts, Size::Bytes(58));
        // Threshold is 1 GiB: sparse files avoid writing 1 GiB.
        let big = acc.join("thread_history_huge.sqlite");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(BIG_THREAD_BYTES + 1).unwrap();
        let f = measure_with(h.path(), 100, Duration::from_secs(5));
        assert_eq!(f.big_threads.len(), 1);
        assert_eq!(
            f.big_threads[0].path,
            "~/.claude/accounts/term-1/thread_history_huge.sqlite"
        );
        assert!(!f.big_threads[0].path.contains(h.path().to_str().unwrap()));
    }

    // Unix-only for a subtler reason than its neighbours: off unix this test
    // still passes, but vacuously — measure_with returns Unknown because there
    // is no fd walk at all, not because the entry cap fired. Left ungated it
    // would certify the cap on a platform that never reaches it.
    #[cfg(unix)]
    #[test]
    fn exceeding_entry_cap_is_unknown_not_partial() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join(".claude/projects");
        std::fs::create_dir_all(&p).unwrap();
        for i in 0..10 {
            std::fs::write(p.join(format!("f{i}")), b"x").unwrap();
        }
        let f = measure_with(h.path(), 5, Duration::from_secs(5));
        assert!(matches!(f.projects, Size::Unknown(_)), "{:?}", f.projects);
    }

    #[cfg(unix)]
    fn tree_with_outside() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let h = tempfile::tempdir().unwrap();
        let a = h.path().join(".claude/projects/a");
        std::fs::create_dir_all(a.join("b")).unwrap();
        std::fs::write(a.join("b/f"), vec![0u8; 100]).unwrap();
        let outside = h.path().join("outside");
        std::fs::create_dir_all(outside.join("b")).unwrap();
        std::fs::write(outside.join("b/g"), vec![0u8; 999]).unwrap();
        (h, a, outside)
    }

    #[cfg(unix)]
    #[test]
    fn a_queued_directory_swapped_for_a_symlink_is_not_followed() {
        let (h, a, outside) = tree_with_outside();
        let mut swapped = false;
        let f = measure_with_hook(h.path(), 100, Duration::from_secs(5), &mut |p| {
            if !swapped && p == a {
                swapped = true;
                std::fs::rename(&a, h.path().join("a_orig")).unwrap();
                std::os::unix::fs::symlink(&outside, &a).unwrap();
            }
        });
        assert!(swapped, "hook never saw the queued directory");
        match f.projects {
            Size::Unknown(_) => {}
            Size::Bytes(b) => assert!(b < 999, "outside tree counted: {b}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_ancestor_swapped_for_a_symlink_mid_walk_cannot_redirect_the_walk() {
        let (h, a, outside) = tree_with_outside();
        let b = a.join("b");
        let mut swapped = false;
        let f = measure_with_hook(h.path(), 100, Duration::from_secs(5), &mut |p| {
            if !swapped && p == b {
                swapped = true;
                std::fs::rename(&a, h.path().join("a_orig")).unwrap();
                std::os::unix::fs::symlink(&outside, &a).unwrap();
            }
        });
        assert!(swapped, "hook never saw the child directory");
        // The walk holds `a` by descriptor: it counts the ORIGINAL a/b/f (100), never
        // the symlink target's 999.
        assert_eq!(f.projects, Size::Bytes(100));
    }

    // Unix-only: zero bytes is the answer only where a walk actually ran.
    #[cfg(unix)]
    #[test]
    fn absent_trees_are_zero_bytes() {
        let h = tempfile::tempdir().unwrap();
        let f = measure_with(h.path(), 5, Duration::from_secs(5));
        assert_eq!(f.projects, Size::Bytes(0));
        assert!(f.big_threads.is_empty());
    }

    // The non-unix contract, asserted rather than implied: with no fd walk the
    // answer is Unknown, never zero. Zero and Unknown are different claims
    // about disk usage, and only one of them is true here.
    #[cfg(not(unix))]
    #[test]
    fn measure_with_is_unknown_off_unix_and_never_zero() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(h.path().join(".claude/projects/p")).unwrap();
        std::fs::write(h.path().join(".claude/projects/p/a.jsonl"), vec![0u8; 100]).unwrap();
        let acc = h.path().join(".claude/accounts/term-1");
        std::fs::create_dir_all(&acc).unwrap();
        std::fs::write(acc.join("thread_history_x.sqlite"), vec![0u8; 50]).unwrap();
        let f = measure_with(h.path(), 100, Duration::from_secs(5));
        assert!(matches!(f.projects, Size::Unknown(_)), "{:?}", f.projects);
        assert!(matches!(f.accounts, Size::Unknown(_)), "{:?}", f.accounts);
    }
}
