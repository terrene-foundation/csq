//! Private bounded lifecycle record IO. These unsigned bytes alone prove no launch ownership.
//! Kernel/context checks and trusted capture are separate from this storage primitive.
use serde::{Deserialize, Serialize};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
pub const MAX_RECORDS: usize = 4096;
pub const MAX_BYTES: usize = 8192;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub schema: u8,
    pub generation: String,
    pub boot: String,
    pub uid: u32,
    pub pid: u32,
    pub exact: u64,
    pub units: String,
    pub handle: PathBuf,
    pub handle_dev: u64,
    pub handle_ino: u64,
    pub cwd: PathBuf,
    pub created: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub uuid: String,
    pub scratch: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub observed: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct End {
    pub observed: u64,
    pub reason: String,
}
/// A directory on the way to the store is trusted only under the shared policy
/// (`platform::fs::untrusted_directory_reason`); the refusal names the directory and why.
fn ancestor_policy(file: &fs::File, uid: u32, at: &Path) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("session store ancestor {} is not a directory", at.display()),
        ));
    }
    let reason = crate::platform::fs::untrusted_directory_reason(meta.uid(), meta.mode(), uid)
        .map(str::to_owned)
        .or_else(|| crate::platform::fs::directory_acl_refusal(file.as_raw_fd()));
    match reason {
        None => Ok(()),
        Some(reason) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("session store ancestor {} refused: {reason}", at.display()),
        )),
    }
}
pub struct Dir(pub(crate) fs::File, std::sync::atomic::AtomicBool);
impl Dir {
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        if !path.is_absolute() {
            return Err(invalid());
        }
        // Ancestors are only traversed: on Linux hold them with `O_PATH` so a searchable but
        // unreadable ancestor (`0o710`, `0o711`, an ACL) does not refuse the store. The final
        // directory is opened readable because `names()` enumerates it.
        #[cfg(target_os = "linux")]
        const ANCESTOR: i32 = libc::O_PATH;
        // macOS spells the same intent `O_SEARCH` (`O_EXEC | O_DIRECTORY`): search permission
        // only, no read permission needed.
        #[cfg(target_os = "macos")]
        const ANCESTOR: i32 = libc::O_SEARCH;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        const ANCESTOR: i32 = libc::O_RDONLY;
        let last = path.components().count().saturating_sub(1);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | ANCESTOR)
            .open("/")?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let mut walked = PathBuf::from("/");
        ancestor_policy(&file, uid, &walked)?;
        for (index, component) in path.components().enumerate() {
            match component {
                std::path::Component::RootDir => (),
                std::path::Component::Normal(part) => {
                    let access = if index == last {
                        libc::O_RDONLY
                    } else {
                        ANCESTOR
                    };
                    let c = std::ffi::CString::new(part.as_bytes()).map_err(|_| invalid())?;
                    let fd = unsafe {
                        libc::openat(
                            file.as_raw_fd(),
                            c.as_ptr(),
                            access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    file = unsafe { fs::File::from_raw_fd(fd) };
                    // The final component gets the stricter private check below; every
                    // ancestor is held to the traversal policy, so a path component another
                    // user can rename or replace is refused, as in SecureDatabase.
                    walked.push(part);
                    if index != last {
                        ancestor_policy(&file, uid, &walked)?;
                    }
                }
                _ => return Err(invalid()),
            }
        }
        let dir = Self(file, std::sync::atomic::AtomicBool::new(false));
        dir.check()?;
        Ok(dir)
    }
    fn check(&self) -> io::Result<()> {
        let m = self.0.metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(invalid());
        }
        if crate::platform::fs::private_directory_acl_refusal(self.0.as_raw_fd()).is_some() {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn child(&self, name: &str, create: bool) -> io::Result<Self> {
        let c = component(name)?;
        if create {
            lock(self)?;
        }
        if create
            && name != "session-lifecycle"
            && (!valid_uuid(name) || self.names()?.len() >= MAX_RECORDS)
        {
            return Err(invalid());
        }
        if create {
            #[cfg(test)]
            tests::after_count();
            let rc = unsafe { libc::mkdirat(self.0.as_raw_fd(), c.as_ptr(), 0o700) };
            if rc != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
        }
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let d = Self(
            unsafe { fs::File::from_raw_fd(fd) },
            std::sync::atomic::AtomicBool::new(false),
        );
        d.check()?;
        if d.0.metadata()?.dev() != self.0.metadata()?.dev() {
            return Err(invalid());
        }
        Ok(d)
    }
    pub fn names(&self) -> io::Result<Vec<String>> {
        // Use a duplicate directory descriptor, never resolve a replaceable path again.
        let duplicate = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            unsafe { libc::close(duplicate) };
            return Err(io::Error::last_os_error());
        }
        let mut names = Vec::new();
        loop {
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            let e = unsafe { libc::readdir(stream) };
            if e.is_null() {
                let error = io::Error::last_os_error();
                unsafe { libc::closedir(stream) };
                return if error.raw_os_error() == Some(0) {
                    Ok(names)
                } else {
                    Err(error)
                };
            }
            let s = unsafe { std::ffi::CStr::from_ptr((*e).d_name.as_ptr()) }
                .to_str()
                .map(str::to_owned);
            match s {
                Ok(s) if s == "." || s == ".." => (),
                Ok(s) if valid_uuid(&s) && names.len() < MAX_RECORDS => names.push(s),
                _ => {
                    unsafe { libc::closedir(stream) };
                    return Err(invalid());
                }
            }
        }
    }
    pub fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> io::Result<Option<T>> {
        use std::io::Read;
        let c = component(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let f = unsafe { fs::File::from_raw_fd(fd) };
        let m = f.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || m.len() > MAX_BYTES as u64
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        f.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| invalid())
    }
    pub fn write<T: Serialize>(&self, name: &str, value: &T) -> io::Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let c = component(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut f = unsafe { fs::File::from_raw_fd(fd) };
        f.write_all(&bytes)?;
        f.sync_all()?;
        self.0.sync_all()
    }
}
pub fn store(base: &Path, create: bool) -> io::Result<Dir> {
    let base = Dir::open(base)?;
    base.child("session-lifecycle", create)
}
pub fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let d = Dir::open(path)?;
    let m = d.0.metadata()?;
    Ok((m.dev(), m.ino()))
}
pub fn lock(dir: &Dir) -> io::Result<()> {
    // SAFETY: `dir.0` is a live descriptor owned by `dir`; flock touches no memory.
    if unsafe { libc::flock(dir.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.1.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Take the shared (read) lock on the store directory, non-blocking. Marked so
/// `Dir::drop` releases it explicitly (a fork duplicate cannot pin it).
pub fn lock_shared(dir: &Dir) -> io::Result<()> {
    // SAFETY: `dir.0` is a live descriptor owned by `dir`; flock touches no memory.
    if unsafe { libc::flock(dir.0.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.1.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

impl Drop for Dir {
    fn drop(&mut self) {
        // G2b item 2: explicit release. `lock()` takes the flock on this
        // directory's descriptor (`child(..., create=true)` locks its
        // parent), and close-alone is not the release point while a fork
        // from any thread holds an inherited duplicate of the description
        // (`flock(2)`). LOCK_UN on any duplicate releases it.
        //
        // G2c item 4: only a Dir that ACTUALLY took the lock is unlocked, so
        // a Dir wrapping a descriptor flock cannot meaningfully lock (e.g. an
        // O_PATH-style ancestor) never logs a false failure.
        if !self.1.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        // SAFETY: `self.0` is a live descriptor owned by this value; flock
        // touches no memory.
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            // G2c item 5: the errno INTEGER is logged, never the formatted
            // io::Error (fixed vocabulary; `security.md` MUST-2).
            tracing::warn!(
                error_kind = "lifecycle_records_unlock_failed",
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "session lifecycle store lock could not be released"
            );
        }
    }
}
fn component(name: &str) -> io::Result<std::ffi::CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(invalid());
    }
    std::ffi::CString::new(name).map_err(|_| invalid())
}
pub fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|x| x.as_secs())
}
pub fn valid_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}
pub fn start_units() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos_microseconds"
    } else {
        "linux_boot_ticks"
    }
}
pub fn boot() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .filter(|x| x.len() <= 64)
            .map(|x| format!("linux:{}", x.trim()))
    }
    #[cfg(target_os = "macos")]
    {
        let mut value: libc::timeval = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::timeval>();
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                (&mut value as *mut libc::timeval).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && len == std::mem::size_of::<libc::timeval>() && value.tv_sec > 0)
            .then(|| format!("macos:{}:{}", value.tv_sec, value.tv_usec))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "lifecycle metadata undetermined",
    )
}
pub fn validate_launch(l: &Launch, generation: &str) -> io::Result<()> {
    if l.schema != 1
        || !valid_uuid(generation)
        || l.generation != generation
        || l.pid == 0
        || l.exact == 0
        || l.units != start_units()
        || !l.handle.is_absolute()
        || !l.cwd.is_absolute()
        || l.handle_dev == 0
        || l.handle_ino == 0
        || l.created == 0
        || l.boot != boot().ok_or_else(invalid)?
        || l.created > now().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    #[cfg(unix)]
    if l.uid != unsafe { libc::geteuid() } {
        return Err(invalid());
    }
    Ok(())
}
pub fn validate_event(event: Option<&End>, l: &Launch, allowed: &[&str]) -> io::Result<()> {
    if let Some(e) = event {
        if e.observed < l.created
            || e.observed > now().ok_or_else(invalid)?
            || !allowed.contains(&e.reason.as_str())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn scratch_tmp() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/private/tmp")
    } else {
        PathBuf::from("/tmp")
    }
}

#[cfg(test)]
#[path = "lifecycle_records_tests.rs"]
mod tests;
