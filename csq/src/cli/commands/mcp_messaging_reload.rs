//! Request-boundary reload of the stdio server. Peer text never enters this module.
//! The Unix checks authorize a same-UID installed file, not a trusted publisher.
//! Linux executes the opened descriptor. Darwin path exec retains a final same-UID
//! atomic-rename race after verification; no portable Darwin fd-exec exists here.

#[cfg(not(unix))]
use std::io;

#[cfg(unix)]
mod native {
    #[cfg(target_os = "linux")]
    use std::ffi::{CString, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{self, BufReader};
    #[cfg(target_os = "macos")]
    use std::io::{Read, Seek, SeekFrom};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const MARKER: &str = "CSQ_MCP_RELOAD_IMAGE";
    /// The predecessor's `mcp::tools_digest()`, carried across the exec. It only gates the
    /// `list_changed` notification; it never affects whether the exec is accepted.
    const DIGEST: &str = "CSQ_MCP_TOOLS_DIGEST";
    const VERIFY_BUDGET: Duration = Duration::from_secs(2);

    fn refused() -> io::Error {
        io::Error::other("mcp executable reload refused")
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Identity {
        dev: u64,
        ino: u64,
        len: u64,
        sec: i64,
        nsec: i64,
        csec: i64,
        cnsec: i64,
        uid: u32,
        mode: u32,
    }
    impl Identity {
        fn of(m: &Metadata) -> Self {
            Self {
                dev: m.dev(),
                ino: m.ino(),
                len: m.len(),
                sec: m.mtime(),
                nsec: m.mtime_nsec(),
                csec: m.ctime(),
                cnsec: m.ctime_nsec(),
                uid: m.uid(),
                mode: m.mode(),
            }
        }
        fn allowed(&self, uid: u32) -> bool {
            self.uid == uid && self.mode & 0o022 == 0 && self.mode & 0o111 != 0
        }
    }

    fn directories(path: &Path) -> io::Result<Vec<(u64, u64)>> {
        let mut ids = Vec::new();
        for parent in path.ancestors().skip(1) {
            let m = fs::symlink_metadata(parent)?;
            // SAFETY: geteuid has no arguments or pointer preconditions.
            if !m.is_dir()
                || m.file_type().is_symlink()
                || !matches!(m.uid(), 0) && m.uid() != unsafe { libc::geteuid() }
            {
                return Err(refused());
            }
            // Root-owned sticky temp roots are allowed; the owned fixture/install
            // directory below them still needs to forbid group/world writes.
            if m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0) {
                return Err(refused());
            }
            ids.push((m.dev(), m.ino()));
        }
        Ok(ids)
    }

    fn watched_path() -> io::Result<PathBuf> {
        resolve_startup_path(std::env::current_exe()?)
    }

    fn resolve_startup_path(path: PathBuf) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        let path = {
            let bytes = path.as_os_str().as_bytes();
            let clean = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
            PathBuf::from(OsString::from_vec(clean.to_vec()))
        };
        // Resolve a launch-time symlink only once. Every subsequent candidate is
        // checked at this canonical leaf with O_NOFOLLOW; replacement links are
        // never followed and cannot redirect this watch to a different image.
        let path = path.canonicalize()?;
        let metadata = fs::symlink_metadata(&path)?;
        // SAFETY: geteuid has no arguments or pointer preconditions.
        if !metadata.is_file() || !Identity::of(&metadata).allowed(unsafe { libc::geteuid() }) {
            return Err(refused());
        }
        directories(&path)?;
        Ok(path)
    }

    fn loaded_identity(path: &Path) -> io::Result<Identity> {
        #[cfg(target_os = "linux")]
        let m = fs::metadata("/proc/self/exe")?;
        #[cfg(not(target_os = "linux"))]
        let m = fs::metadata(path)?;
        let _ = path;
        Ok(Identity::of(&m))
    }

    fn marker(path: &Path, id: &Identity) -> String {
        let hex: String = path
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "1:{}:{}:{}:{}:{}:{hex}",
            std::process::id(),
            id.dev,
            id.ino,
            id.sec,
            id.nsec
        )
    }

    fn valid_marker(value: &std::ffi::OsStr, path: &Path, id: &Identity) -> bool {
        // This validates continuity only. A same-UID user can synthesize the
        // marker; it grants no filesystem approval and carries no request bytes.
        value
            .to_str()
            .is_some_and(|s| s.len() <= 16384 && s == marker(path, id))
    }

    /// Whether the new image's tool schema differs from its predecessor's. A missing,
    /// non-UTF-8 or otherwise unparseable old digest counts as changed: a missed
    /// `list_changed` leaves a client on a stale schema, which is worse than one extra refetch.
    fn tools_changed(old: Option<&std::ffi::OsStr>, current: &str) -> bool {
        !old.and_then(std::ffi::OsStr::to_str)
            .is_some_and(|v| v == current)
    }

    pub struct Reload {
        path: PathBuf,
        image: Identity,
        parents: Vec<(u64, u64)>,
        attempted: Option<Identity>,
        unavailable: Option<io::ErrorKind>,
        notify: bool,
    }

    impl Reload {
        pub fn new() -> io::Result<Self> {
            let path = watched_path()?;
            let image = loaded_identity(&path)?;
            let parents = directories(&path)?;
            let notify = std::env::var_os(MARKER).is_some_and(|v| valid_marker(&v, &path, &image))
                && tools_changed(
                    std::env::var_os(DIGEST).as_deref(),
                    &csq_core::messaging::mcp::tools_digest(),
                );
            Ok(Self {
                path,
                image,
                parents,
                attempted: None,
                unavailable: None,
                notify,
            })
        }
        pub fn take_notification(&mut self) -> bool {
            std::mem::take(&mut self.notify)
        }

        fn candidate(
            &mut self,
            verify: impl FnOnce(&Path, &File, Instant) -> io::Result<()>,
        ) -> io::Result<Option<File>> {
            let m = match fs::symlink_metadata(&self.path) {
                Ok(metadata) => {
                    self.unavailable = None;
                    metadata
                }
                Err(error) => {
                    let kind = error.kind();
                    if self.unavailable == Some(kind) {
                        return Ok(None);
                    }
                    self.unavailable = Some(kind);
                    return Err(error);
                }
            };
            let id = Identity::of(&m);
            if id == self.image || self.attempted.as_ref() == Some(&id) {
                return Ok(None);
            }
            self.attempted = Some(id.clone());
            if !m.is_file() || m.file_type().is_symlink() {
                return Err(refused());
            }
            // SAFETY: geteuid has no arguments or pointer preconditions.
            if !id.allowed(unsafe { libc::geteuid() }) || directories(&self.path)? != self.parents {
                return Err(refused());
            }
            let target = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.path)?;
            if Identity::of(&target.metadata()?) != id {
                return Err(refused());
            }
            let deadline = Instant::now() + VERIFY_BUDGET;
            verify(&self.path, &target, deadline)?;
            if Instant::now() >= deadline
                || Identity::of(&target.metadata()?) != id
                || Identity::of(&fs::symlink_metadata(&self.path)?) != id
                || directories(&self.path)? != self.parents
            {
                return Err(refused());
            }
            Ok(Some(target))
        }

        pub fn boundary(&mut self) -> io::Result<()> {
            if let Some(target) = self.candidate(verify_native)? {
                self.exec(target)?;
            }
            Ok(())
        }

        fn exec(&self, target: File) -> io::Result<()> {
            let id = Identity::of(&target.metadata()?);
            let value = marker(&self.path, &id);
            let digest = csq_core::messaging::mcp::tools_digest();
            #[cfg(target_os = "linux")]
            {
                let args = std::env::args_os()
                    .map(|a| CString::new(a.as_bytes()).map_err(|_| refused()))
                    .collect::<io::Result<Vec<_>>>()?;
                let env = std::env::vars_os()
                    .filter(|(k, _)| k != MARKER && k != DIGEST)
                    .map(|(k, v)| {
                        let mut entry = k.into_vec();
                        entry.push(b'=');
                        entry.extend(v.into_vec());
                        CString::new(entry).map_err(|_| refused())
                    })
                    .chain([
                        CString::new(format!("{MARKER}={value}")).map_err(|_| refused()),
                        CString::new(format!("{DIGEST}={digest}")).map_err(|_| refused()),
                    ])
                    .collect::<io::Result<Vec<_>>>()?;
                let argv = args
                    .iter()
                    .map(|a| a.as_ptr())
                    .chain(std::iter::once(std::ptr::null()))
                    .collect::<Vec<_>>();
                let envp = env
                    .iter()
                    .map(|e| e.as_ptr())
                    .chain(std::iter::once(std::ptr::null()))
                    .collect::<Vec<_>>();
                // SAFETY: target is an owned open executable descriptor; argv/envp
                // are null-terminated pointer arrays backed by live CStrings.
                // Native ELF execution resolves the fd before CLOEXEC closes it.
                unsafe {
                    libc::fexecve(target.as_raw_fd(), argv.as_ptr(), envp.as_ptr());
                }
                Err(io::Error::last_os_error())
            }
            #[cfg(not(target_os = "linux"))]
            {
                use std::os::unix::process::CommandExt;
                let mut args = std::env::args_os();
                let arg0 = args.next().ok_or_else(refused)?;
                let error = std::process::Command::new(&self.path)
                    .arg0(arg0)
                    .args(args)
                    .env(MARKER, value)
                    .env(DIGEST, digest)
                    .exec();
                Err(error)
            }
        }
    }

    pub fn raw_stdin() -> io::Result<BufReader<File>> {
        // SAFETY: duplicates fd0 into a new owned descriptor; fd0 itself remains
        // inherited by exec. Only the duplicate closes at image replacement.
        let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fcntl returned a new descriptor owned by this File.
        let file = unsafe { File::from_raw_fd(fd) };
        // A raw File is essential: std::Stdin's internal buffer prefetches even
        // if an outer BufReader has capacity one. No next-request byte is read.
        Ok(BufReader::with_capacity(1, file))
    }

    #[cfg(target_os = "linux")]
    fn verify_native(_path: &Path, target: &File, deadline: Instant) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let before = Identity::of(&target.metadata()?);
        let mut header = [0u8; 64];
        target.read_exact_at(&mut header, 0)?;
        if &header[..4] != b"\x7fELF" || header[6] != 1 {
            return Err(refused());
        }
        let little = match header[5] {
            1 => true,
            2 => false,
            _ => return Err(refused()),
        };
        let word = |bytes: &[u8]| -> u64 {
            if little {
                bytes.iter().rev().fold(0, |n, b| (n << 8) | u64::from(*b))
            } else {
                bytes.iter().fold(0, |n, b| (n << 8) | u64::from(*b))
            }
        };
        let (header_size, entry_size, offset, count) = match header[4] {
            1 if word(&header[40..42]) == 52 && word(&header[42..44]) == 32 => {
                (52, 32, word(&header[28..32]), word(&header[44..46]))
            }
            2 if word(&header[52..54]) == 64 && word(&header[54..56]) == 56 => {
                (64, 56, word(&header[32..40]), word(&header[56..58]))
            }
            _ => return Err(refused()),
        };
        if !matches!(word(&header[16..18]), 2 | 3)
            || word(&header[20..24]) != 1
            || count == 0
            || offset < header_size
            || offset
                .checked_add(count * entry_size)
                .is_none_or(|end| end > before.len)
        {
            return Err(refused());
        }
        let (section_offset, section_size, section_count) = if header[4] == 1 {
            (
                word(&header[32..36]),
                word(&header[46..48]),
                word(&header[48..50]),
            )
        } else {
            (
                word(&header[40..48]),
                word(&header[58..60]),
                word(&header[60..62]),
            )
        };
        if section_count > 0
            && (section_offset < header_size
                || section_size != if header[4] == 1 { 40 } else { 64 }
                || section_offset
                    .checked_add(section_count * section_size)
                    .is_none_or(|end| end > before.len))
        {
            return Err(refused());
        }
        // A magic-only check accepts truncated installs. Bound every declared
        // segment against the opened file so a stable incomplete image is refused.
        let mut load = false;
        let mut entry = [0u8; 56];
        for i in 0..count {
            if Instant::now() >= deadline {
                return Err(refused());
            }
            target.read_exact_at(&mut entry[..entry_size as usize], offset + i * entry_size)?;
            let kind = word(&entry[..4]);
            let (start, size) = if header[4] == 1 {
                (word(&entry[4..8]), word(&entry[16..20]))
            } else {
                (word(&entry[8..16]), word(&entry[32..40]))
            };
            if start.checked_add(size).is_none_or(|end| end > before.len) {
                return Err(refused());
            }
            load |= kind == 1;
        }
        if !load || Instant::now() >= deadline || Identity::of(&target.metadata()?) != before {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    fn verify_native(_path: &Path, _target: &File, _deadline: Instant) -> io::Result<()> {
        // Same-UID, regular-file, mode and identity gates apply on other Unix
        // platforms; no publisher-verification or ELF-format claim is made.
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn verify_native(_path: &Path, target: &File, deadline: Instant) -> io::Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        const MAX_IMAGE: u64 = 256 * 1024 * 1024;
        if target.metadata()?.len() > MAX_IMAGE {
            return Err(refused());
        }
        let scratch = std::env::temp_dir().join(format!(
            "csq-mcp-verify-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        struct Remove(PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _remove = Remove(scratch.clone());
        let snapshot = scratch.join("image");
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&snapshot)?;
        let mut source = target.try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        let mut count = 0u64;
        let mut buf = [0u8; 65536];
        loop {
            if Instant::now() >= deadline {
                return Err(refused());
            }
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > MAX_IMAGE {
                return Err(refused());
            }
            out.write_all(&buf[..n])?;
        }
        drop(out);
        let mut command = Command::new("/usr/bin/codesign");
        command
            .args(["--verify", "--strict"])
            .arg(&snapshot)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        bounded_verifier(&mut command, deadline)
    }

    #[cfg(any(target_os = "macos", test))]
    fn bounded_verifier(command: &mut std::process::Command, deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            return Err(refused());
        }
        let mut child = command.spawn()?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(refused())
                    }
                }
                Err(_) => return Err(refused()),
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                // A failed ownership probe never authorizes a PID-based signal.
                if matches!(child.try_wait(), Ok(None)) {
                    let _ = child.kill();
                }
                let cleanup = Instant::now() + Duration::from_millis(100);
                while Instant::now() < cleanup {
                    if !matches!(child.try_wait(), Ok(None)) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                return Err(refused());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::{Command, Stdio};

        fn fixture() -> (tempfile::TempDir, Reload) {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().canonicalize().unwrap().join("server");
            fs::write(&path, b"old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let image = Identity::of(&fs::metadata(&path).unwrap());
            let reload = Reload {
                parents: directories(&path).unwrap(),
                path,
                image,
                attempted: None,
                unavailable: None,
                notify: false,
            };
            (dir, reload)
        }
        fn replace(reload: &Reload, mode: u32) {
            let next = reload.path.with_extension("next");
            fs::write(&next, b"new").unwrap();
            fs::set_permissions(&next, fs::Permissions::from_mode(mode)).unwrap();
            fs::rename(next, &reload.path).unwrap();
        }

        #[test]
        fn token_reload_accepts_owned_replacement_and_refuses_writable_or_symlink() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, mut reload) = fixture();
            replace(&reload, 0o700);
            assert!(reload.candidate(|_, _, _| Ok(())).unwrap().is_some());
            let (_dir2, mut writable) = fixture();
            replace(&writable, 0o722);
            assert!(writable.candidate(|_, _, _| Ok(())).is_err());
            let (_dir3, mut link) = fixture();
            let other = link.path.with_extension("other");
            fs::write(&other, b"other").unwrap();
            fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_file(&link.path).unwrap();
            symlink(other, &link.path).unwrap();
            assert!(link.candidate(|_, _, _| Ok(())).is_err());
        }
        #[test]
        fn reload_watches_startup_symlink_target_but_refuses_replacement_symlink_once() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, mut reload) = fixture();
            let launcher = reload.path.with_extension("launcher");
            symlink(&reload.path, &launcher).unwrap();
            assert_eq!(resolve_startup_path(launcher.clone()).unwrap(), reload.path);
            fs::set_permissions(&reload.path, fs::Permissions::from_mode(0o722)).unwrap();
            assert!(resolve_startup_path(launcher).is_err());
            fs::set_permissions(&reload.path, fs::Permissions::from_mode(0o700)).unwrap();
            let other = reload.path.with_extension("other");
            fs::write(&other, b"other").unwrap();
            fs::remove_file(&reload.path).unwrap();
            symlink(other, &reload.path).unwrap();
            assert!(reload
                .candidate(|_, _, _| panic!("symlink must not reach verifier"))
                .is_err());
            for _ in 0..3 {
                assert!(reload
                    .candidate(|_, _, _| panic!("refused identity retried"))
                    .unwrap()
                    .is_none());
            }
        }

        #[test]
        fn reload_unavailable_path_warns_once_then_recovers_on_new_image() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, mut reload) = fixture();
            fs::remove_file(&reload.path).unwrap();
            assert!(reload
                .candidate(|_, _, _| panic!("missing leaf reached verifier"))
                .is_err());
            assert!(reload
                .candidate(|_, _, _| panic!("missing leaf retried"))
                .unwrap()
                .is_none());
            fs::write(&reload.path, b"recovered new image").unwrap();
            fs::set_permissions(&reload.path, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(reload.candidate(|_, _, _| Ok(())).unwrap().is_some());
        }

        #[test]
        fn list_changed_only_when_the_tool_digest_differs() {
            let current = csq_core::messaging::mcp::tools_digest();
            let same = std::ffi::OsString::from(&current);
            assert!(
                !tools_changed(Some(&same), &current),
                "same digest: no notify"
            );
            let other = std::ffi::OsString::from("0".repeat(64));
            assert!(
                tools_changed(Some(&other), &current),
                "different digest: notify"
            );
            assert!(tools_changed(None, &current), "missing digest: notify");
            for garbled in ["", "not-hex", &current[..63], &current.to_uppercase()] {
                let g = std::ffi::OsString::from(garbled);
                assert!(
                    tools_changed(Some(&g), &current),
                    "garbled {garbled:?}: notify"
                );
            }
            use std::os::unix::ffi::OsStringExt;
            let raw = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
            assert!(tools_changed(Some(&raw), &current), "non-UTF-8: notify");
        }

        #[test]
        fn token_reload_uid_gate_and_marker_continuity() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, reload) = fixture();
            assert!(reload.image.allowed(reload.image.uid));
            assert!(!reload.image.allowed(reload.image.uid.wrapping_add(1)));
            let value = marker(&reload.path, &reload.image);
            assert!(valid_marker(
                std::ffi::OsStr::new(&value),
                &reload.path,
                &reload.image
            ));
            assert!(!valid_marker(
                std::ffi::OsStr::new("1:other-pid"),
                &reload.path,
                &reload.image
            ));
            assert!(!valid_marker(
                std::ffi::OsStr::new(&value),
                &reload.path.with_extension("different"),
                &reload.image
            ));
        }
        #[test]
        fn token_reload_refuses_verifier_failure_timeout_and_path_swap() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, mut fail) = fixture();
            replace(&fail, 0o700);
            assert!(fail.candidate(|_, _, _| Err(refused())).is_err());
            let (_dir2, mut timeout) = fixture();
            replace(&timeout, 0o700);
            assert!(timeout
                .candidate(|_, _, deadline| {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(2),
                    );
                    Ok(())
                })
                .is_err());
            let (_dir3, mut race) = fixture();
            replace(&race, 0o700);
            assert!(race
                .candidate(|path, _, _| {
                    let swapped = path.with_extension("swapped");
                    fs::write(&swapped, b"different verified image").unwrap();
                    fs::set_permissions(&swapped, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::rename(swapped, path).unwrap();
                    Ok(())
                })
                .is_err());
        }
        #[test]
        fn token_reload_refuses_changed_open_image_and_parent_directory() {
            let _env = csq_core::platform::test_env::lock();
            let (_dir, mut changed) = fixture();
            replace(&changed, 0o700);
            assert!(changed
                .candidate(|path, _, _| {
                    fs::write(path, b"modified same inode").unwrap();
                    Ok(())
                })
                .is_err());
            let (_dir2, mut parent) = fixture();
            replace(&parent, 0o700);
            assert!(parent
                .candidate(|path, _, _| {
                    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o777))
                        .unwrap();
                    Ok(())
                })
                .is_err());
        }
        #[test]
        fn token_reload_verifier_process_is_bounded_and_owned() {
            let _env = csq_core::platform::test_env::lock();
            let home = tempfile::TempDir::new().unwrap();
            let mut good = Command::new("/bin/sh");
            good.args(["-c", "exit 0"])
                .env_clear()
                .env("HOME", home.path())
                .env("CSQ_BASE_DIR", home.path().join("base"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            assert!(bounded_verifier(&mut good, Instant::now() + Duration::from_secs(1)).is_ok());
            let mut hung = Command::new("/bin/sh");
            hung.args(["-c", "exec /bin/sleep 1"])
                .env_clear()
                .env("HOME", home.path())
                .env("CSQ_BASE_DIR", home.path().join("base"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let start = Instant::now();
            assert!(bounded_verifier(&mut hung, start + Duration::from_millis(30)).is_err());
            assert!(start.elapsed() < Duration::from_millis(500));
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn linux_reload_verifies_elf_and_refuses_truncated_install() {
            let _env = csq_core::platform::test_env::lock();
            let bytes = fs::read("/bin/true").unwrap();
            assert_eq!(&bytes[..4], b"\x7fELF");
            let (_dir, mut valid) = fixture();
            fs::write(&valid.path, &bytes).unwrap();
            assert!(valid.candidate(verify_native).unwrap().is_some());
            for length in [4, 64, bytes.len() / 2, bytes.len() - 1] {
                let (_dir, mut partial) = fixture();
                fs::write(&partial.path, &bytes[..length]).unwrap();
                assert!(
                    partial.candidate(verify_native).is_err(),
                    "accepted {length}-byte partial ELF"
                );
            }
            let (_dir, mut bad_magic) = fixture();
            let mut corrupt = bytes;
            corrupt[..4].copy_from_slice(b"NOPE");
            fs::write(&bad_magic.path, corrupt).unwrap();
            assert!(bad_magic.candidate(verify_native).is_err());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_reload_refuses_file_changed_after_native_elf_check() {
            let _env = csq_core::platform::test_env::lock();
            let bytes = fs::read("/bin/true").unwrap();
            let (_dir, mut reload) = fixture();
            fs::write(&reload.path, &bytes).unwrap();
            assert!(reload
                .candidate(|path, file, deadline| {
                    verify_native(path, file, deadline)?;
                    fs::write(path, &bytes[..bytes.len() / 2])?;
                    Ok(())
                })
                .is_err());
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn token_reload_native_codesign_accepts_signed_copy_refuses_corruption() {
            let _env = csq_core::platform::test_env::lock();
            let dir = tempfile::TempDir::new().unwrap();
            let image = dir.path().join("signed-image");
            fs::copy("/bin/echo", &image).unwrap();
            let target = File::open(&image).unwrap();
            let before = Identity::of(&target.metadata().unwrap());
            assert!(verify_native(&image, &target, Instant::now() + VERIFY_BUDGET).is_ok());
            assert_eq!(Identity::of(&target.metadata().unwrap()), before);
            let mut corrupt = OpenOptions::new().append(true).open(&image).unwrap();
            use std::io::Write;
            corrupt.write_all(b"corrupt signed image").unwrap();
            assert!(verify_native(&image, &target, Instant::now() + VERIFY_BUDGET).is_err());
        }
    }
}

#[cfg(unix)]
pub use native::{raw_stdin, Reload};

#[cfg(not(unix))]
pub struct Reload;
#[cfg(not(unix))]
impl Reload {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }
    pub fn take_notification(&mut self) -> bool {
        false
    }
    pub fn boundary(&mut self) -> io::Result<()> {
        // Windows has no in-place exec preserving this PID. Serve requests
        // normally; do not pretend that a spawned replacement is equivalent.
        Ok(())
    }
}

/// Initialize once; failure disables reload with a fixed, non-sensitive warning.
pub(super) fn reload_or_warn<T>(make: impl FnOnce() -> std::io::Result<T>) -> Option<T> {
    match make() {
        Ok(reload) => Some(reload),
        Err(_) => {
            tracing::warn!(
                error_kind = "mcp_reload_disabled",
                "MCP executable reload disabled"
            );
            None
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn fixture_tool(home: &std::path::Path, tool: &str) -> Command {
        let mut cmd = Command::new(tool);
        cmd.env_clear()
            .env("HOME", home)
            .env("CSQ_BASE_DIR", home.join("base"));
        for key in ["PATH", "LANG", "LC_ALL", "USER", "TMPDIR"] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        // Cargo uses the admitted toolchain/cache. Its installed toolchain must be
        // reachable despite sandbox HOME; this is not a csq state directory.
        if let Some(root) = std::env::var_os("RUSTUP_HOME").or_else(|| {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".rustup").into_os_string())
        }) {
            cmd.env("RUSTUP_HOME", root);
        }
        if let Some(root) = std::env::var_os("CARGO_HOME").or_else(|| {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".cargo").into_os_string())
        }) {
            cmd.env("CARGO_HOME", root);
        }
        cmd.env("CARGO_TARGET_DIR", home.join("target"))
            .env("CARGO_NET_OFFLINE", "true");
        cmd.current_dir(csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")));
        cmd
    }

    fn build_fixture(dir: &std::path::Path, version: &str) -> std::path::PathBuf {
        let result = produce_fixture(dir, version);
        match result {
            Ok(binary) => binary,
            Err(error) => panic!("fixture producer failed: {error}"),
        }
    }

    fn produce_fixture(
        dir: &std::path::Path,
        version: &str,
    ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let root = csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("fixture root")?
            .canonicalize()?;
        let project = dir.join("producer");
        fs::create_dir_all(project.join("src"))?;
        let root_manifest: toml::Value =
            toml::from_str(&fs::read_to_string(root.join("Cargo.toml"))?)?;
        let lock_bytes = fs::read(root.join("Cargo.lock"))?;
        let original_lock: toml::Value = toml::from_str(std::str::from_utf8(&lock_bytes)?)?;
        let mut manifest = toml::Table::new();
        let mut package = toml::Table::new();
        package.insert("name".into(), "csq-mcp-reload-fixture".into());
        package.insert("version".into(), "0.0.0".into());
        package.insert("edition".into(), "2021".into());
        manifest.insert("package".into(), package.into());
        manifest.insert("workspace".into(), toml::Table::new().into());
        let mut dependencies = toml::Table::new();
        dependencies.insert(
            "libc".into(),
            root_manifest["workspace"]["dependencies"]["libc"].clone(),
        );
        dependencies.insert(
            "serde_json".into(),
            root_manifest["workspace"]["dependencies"]["serde_json"].clone(),
        );
        dependencies.insert(
            "tracing".into(),
            root_manifest["workspace"]["dependencies"]["tracing"].clone(),
        );
        let mut core = toml::Table::new();
        core.insert(
            "path".into(),
            root.join("csq-core")
                .to_str()
                .ok_or("fixture core path")?
                .into(),
        );
        core.insert("default-features".into(), false.into());
        core.insert(
            "features".into(),
            toml::Value::Array(vec!["test-utils".into()]),
        );
        dependencies.insert("csq-core".into(), core.into());
        manifest.insert("dependencies".into(), dependencies.into());
        if let Some(patches) = root_manifest.get("patch") {
            let mut patches = patches.clone();
            for (_, registry) in patches
                .as_table_mut()
                .ok_or("fixture patch table")?
                .iter_mut()
            {
                for (_, patch) in registry
                    .as_table_mut()
                    .ok_or("fixture patch registry")?
                    .iter_mut()
                {
                    if let Some(path) = patch.get_mut("path") {
                        let absolute = root.join(path.as_str().ok_or("fixture patch path")?);
                        *path = absolute.to_str().ok_or("fixture patch utf8")?.into();
                    }
                }
            }
            manifest.insert("patch".into(), patches);
        }
        manifest.insert(
            "profile".into(),
            toml::toml! { dev = { incremental = false, debug = 0 } }.into(),
        );
        let manifest_path = project.join("Cargo.toml");
        fs::write(&manifest_path, toml::to_string(&manifest)?)?;
        fs::write(project.join("Cargo.lock"), &lock_bytes)?;
        let module = csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"))
            .join("src/cli/commands/mcp_messaging_reload.rs");
        let source = project.join("src/main.rs");
        let binary = dir.join(version);
        // This owned image runs the actual MCP lifecycle loop. The output adapter
        // models two installed versions with different tool descriptions and
        // blocks ID1 during response emission, with ID2 already queued on fd0.
        let template = r##"
#[path=@MODULE@] mod reload;
use std::io::Write;
use csq_core::messaging::{mcp, model::Recipient, limits::Liveness};
use csq_core::sessions::directives::{real_fs, DirectiveError};
fn error() -> DirectiveError { DirectiveError { code: csq_core::sdk::SdkErrorCode::Undetermined, message: "fixture unused".into(), cause: None, attempts: None, next_allowed_at: None } }
struct Output { stdout: std::io::Stdout, bytes: Vec<u8>, gate: std::path::PathBuf }
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        while let Some(end) = self.bytes.iter().position(|b| *b == b'\n') {
            let line = self.bytes.drain(..=end).collect::<Vec<_>>();
            let mut value: serde_json::Value = serde_json::from_slice(&line)?;
            if value["id"] == 1 {
                std::fs::write(self.gate.with_extension("entered"), b"entered")?;
                let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !self.gate.exists() { assert!(std::time::Instant::now() < end); std::thread::sleep(std::time::Duration::from_millis(1)); }
            }
            if value.get("result").is_some() {
                value["result"]["fixtureImage"] = serde_json::json!("@VERSION@");
                value["result"]["fixturePid"] = serde_json::json!(std::process::id());
                if value["result"]["tools"].is_array() { value["result"]["tools"][0]["description"] = serde_json::json!("@VERSION@"); }
            }
            serde_json::to_writer(&mut self.stdout, &value)?;
            self.stdout.write_all(b"\n")?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { self.stdout.flush() }
}
fn main() {
    let gate = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    let mut watcher = reload::Reload::new().unwrap();
    let mut input = reload::raw_stdin().unwrap();
    let mut output = Output { stdout: std::io::stdout(), bytes: vec![], gate: gate.clone() };
    if watcher.take_notification() { writeln!(output, "{}", mcp::tools_list_changed_notification()).unwrap(); }
    writeln!(output, "{}", serde_json::json!({"jsonrpc":"2.0", "method":"fixture/ready", "params":{"version":"@VERSION@", "pid":std::process::id()}})).unwrap();
    output.flush().unwrap();
    let fs = real_fs();
    let now = || Ok(1);
    let live = |_: &Recipient| Liveness::Live;
    let caller = || Err(error());
    let resolve = |_, _| Err(error());
    let sessions = || Ok(mcp::SessionList { entries: vec![], complete: true });
    let set_name = |_: &csq_core::messaging::model::VerifiedSession, _: Option<&str>| Ok(());
    let wake = |_: &Recipient| "queued_only";
    let be = mcp::Backend { base_dir: gate.parent().unwrap(), now: &now, fs: &fs, live: &live, caller: &caller, resolve: &resolve, sessions: &sessions, set_name: &set_name, wake: &wake };
    mcp::serve_with_lifecycle(&mut input, &mut output, &be, &mut |out| { out.flush()?; watcher.boundary() }).unwrap();
}
"##;
        fs::write(
            &source,
            template
                .replace("@MODULE@", &format!("{module:?}"))
                .replace("@VERSION@", version),
        )?;
        fn digest(path: &std::path::Path) -> std::io::Result<String> {
            Ok(csq_core::audit::persist::sha256_hex_test(&fs::read(path)?))
        }
        let mcp_source = root.join("csq-core/src/messaging/mcp.rs");
        let source_ids = [
            digest(&module)?,
            digest(&mcp_source)?,
            digest(&root.join("csq-core/Cargo.toml"))?,
        ];
        let compiler = producer_output(
            fixture_tool(dir, "rustc").args(["-vV"]),
            Duration::from_secs(10),
        )?;
        let compiler = std::str::from_utf8(&compiler)?;
        let host = compiler
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .ok_or("fixture compiler host")?;
        let metadata = producer_output(
            fixture_tool(dir, "cargo")
                .args([
                    "metadata",
                    "--offline",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    host,
                ])
                .arg("--manifest-path")
                .arg(&manifest_path),
            Duration::from_secs(60),
        )?;
        let metadata = parse_producer_json("cargo metadata stdout", &metadata)?;
        if metadata["target_directory"]
            .as_str()
            .map(std::path::Path::new)
            != Some(dir.join("target").as_path())
        {
            return Err("fixture private target binding".into());
        }
        let exact_core = root.join("csq-core/Cargo.toml").canonicalize()?;
        let core_packages = metadata["packages"]
            .as_array()
            .ok_or("fixture metadata packages")?
            .iter()
            .filter(|p| p["name"] == "csq-core")
            .collect::<Vec<_>>();
        if core_packages.len() != 1
            || std::path::Path::new(
                core_packages[0]["manifest_path"]
                    .as_str()
                    .ok_or("fixture manifest path")?,
            )
            .canonicalize()?
                != exact_core
        {
            return Err("fixture source binding".into());
        }
        let fixture_lock: toml::Value =
            toml::from_str(&fs::read_to_string(project.join("Cargo.lock"))?)?;
        type LockedExternal = (String, String, String, Option<String>);
        fn external_ids(
            lock: &toml::Value,
        ) -> Result<std::collections::BTreeSet<LockedExternal>, Box<dyn std::error::Error>>
        {
            lock["package"]
                .as_array()
                .ok_or("fixture lock packages")?
                .iter()
                .filter(|p| p.get("source").is_some())
                .map(|p| {
                    Ok((
                        p["name"].as_str().ok_or("fixture lock name")?.into(),
                        p["version"].as_str().ok_or("fixture lock version")?.into(),
                        p["source"].as_str().ok_or("fixture lock source")?.into(),
                        p.get("checksum")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned),
                    ))
                })
                .collect()
        }
        if !external_ids(&fixture_lock)?.is_subset(&external_ids(&original_lock)?) {
            return Err("fixture lock drift".into());
        }
        let output = producer_output(
            fixture_tool(dir, "cargo")
                .args(["build", "--frozen", "--message-format=json"])
                .arg("--manifest-path")
                .arg(&manifest_path),
            Duration::from_secs(300),
        )?;
        let mut artifacts = Vec::new();
        for line in output
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
        {
            let value = parse_producer_json("cargo build --message-format=json line", line)?;
            if value["reason"] == "compiler-artifact"
                && value["target"]["name"] == "csq-mcp-reload-fixture"
            {
                if let Some(path) = value["executable"].as_str() {
                    artifacts.push(std::path::PathBuf::from(path).canonicalize()?);
                }
            }
        }
        if artifacts.len() != 1 || !artifacts[0].starts_with(dir.join("target").canonicalize()?) {
            return Err("fixture artifact binding".into());
        }
        if source_ids
            != [
                digest(&module)?,
                digest(&mcp_source)?,
                digest(&root.join("csq-core/Cargo.toml"))?,
            ]
        {
            return Err("fixture source changed during build".into());
        }
        fs::copy(&artifacts[0], &binary)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        println!("fixture producer identity=csq-mcp-reload-fixture@0.0.0 core_features=test-utils default_features=false root_lock_sha256={} fixture_lock_sha256={} reload_sha256={} mcp_sha256={} core_manifest_sha256={} artifact={} artifact_sha256={}", csq_core::audit::persist::sha256_hex_test(&lock_bytes), digest(&project.join("Cargo.lock"))?, source_ids[0], source_ids[1], source_ids[2], artifacts[0].display(), digest(&binary)?);
        Ok(binary)
    }

    /// Parse one JSON document the fixture producer got from cargo. A bare
    /// `serde_json::Error` names neither the call nor the bytes ("expected value at
    /// line 1 column 4" was unattributable), so the error carries the call label and
    /// the first 200 bytes of the offending input, lossily UTF-8, control characters
    /// escaped. Test code only.
    fn parse_producer_json(
        label: &str,
        bytes: &[u8],
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        serde_json::from_slice(bytes).map_err(|error| {
            let prefix: String = String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
                .chars()
                .map(|c| {
                    if c.is_control() {
                        format!("\\x{:02x}", c as u32)
                    } else {
                        c.to_string()
                    }
                })
                .collect();
            format!(
                "fixture producer: {label}: {error}; input_bytes={} first 200 bytes: {prefix}",
                bytes.len()
            )
            .into()
        })
    }

    #[test]
    fn producer_json_error_names_the_call_and_quotes_escaped_bytes() {
        let error = parse_producer_json(
            "cargo build --message-format=json line",
            b"   Compiling foo\x1b[0m\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("cargo build --message-format=json line"),
            "{error}"
        );
        assert!(error.contains("   Compiling foo\\x1b[0m\\x0a"), "{error}");
        assert!(error.contains("column 4"), "{error}");
        let long = vec![b'x'; 500];
        let error = parse_producer_json("cargo metadata stdout", &long)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&"x".repeat(200)) && !error.contains(&"x".repeat(201)),
            "{error}"
        );
        assert!(error.contains("input_bytes=500"), "{error}");
        assert!(parse_producer_json("cargo metadata stdout", b"{\"a\":1}").is_ok());
    }

    fn producer_output(
        command: &mut Command,
        budget: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let invocation = format!(
            "{:?} {:?}",
            command.get_program(),
            command.get_args().collect::<Vec<_>>()
        );
        fn failure(invocation: &str, status: &str, out: &[u8], err: &[u8]) -> String {
            const CAP: usize = 16 * 1024;
            let bounded =
                |bytes: &[u8]| String::from_utf8_lossy(&bytes[..bytes.len().min(CAP)]).into_owned();
            let mut rendered = Vec::new();
            for line in out.split(|b| *b == b'\n') {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
                    if value["reason"] == "compiler-message" {
                        if let Some(text) = value["message"]["rendered"].as_str() {
                            let left = CAP.saturating_sub(rendered.len());
                            rendered.extend_from_slice(&text.as_bytes()[..text.len().min(left)]);
                        }
                    }
                }
            }
            format!("fixture producer command={invocation} status={status} stdout_bytes={} stderr_bytes={}\ncompiler diagnostics (cap {CAP}):\n{}\nstdout prefix (cap {CAP}):\n{}\nstderr prefix (cap {CAP}):\n{}", out.len(), err.len(), bounded(&rendered), bounded(out), bounded(err))
        }
        let deadline = Instant::now() + budget;
        if Instant::now() >= deadline {
            return Err(failure(&invocation, "expired before spawn", &[], &[]).into());
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(None)) {
                    let _ = self.0.kill();
                    let deadline = Instant::now() + Duration::from_millis(100);
                    while Instant::now() < deadline && matches!(self.0.try_wait(), Ok(None)) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        let stdout = child.stdout.take().ok_or("fixture producer stdout")?;
        let stderr = child.stderr.take().ok_or("fixture producer stderr")?;
        let mut child = Owned(child);
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            // SAFETY: both descriptors are live owned pipes; fcntl changes only flags.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err("fixture producer nonblocking".into());
                }
            }
        }
        fn drain(reader: &mut impl Read, data: &mut Vec<u8>, cap: usize) -> std::io::Result<()> {
            let mut bytes = [0u8; 8192];
            // Finite reads per poll prevent a continuously writing helper from
            // starving the deadline check; inherited writers never require EOF.
            for _ in 0..16 {
                match reader.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) if data.len() + n <= cap => data.extend_from_slice(&bytes[..n]),
                    Ok(_) => return Err(std::io::Error::other("fixture producer output cap")),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        let (mut stdout, mut stderr) = (stdout, stderr);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            if Instant::now() >= deadline {
                return Err(failure(&invocation, "deadline", &out, &err).into());
            }
            drain(&mut stdout, &mut out, 16 * 1024 * 1024)?;
            drain(&mut stderr, &mut err, 1024 * 1024)?;
            if let Some(status) = child.0.try_wait()? {
                drain(&mut stdout, &mut out, 16 * 1024 * 1024)?;
                drain(&mut stderr, &mut err, 1024 * 1024)?;
                if !status.success() {
                    return Err(failure(&invocation, &status.to_string(), &out, &err).into());
                }
                return Ok(out);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn token_reload_preserves_queued_request_pid_and_call_boundary() {
        use std::os::fd::AsRawFd;
        let _env = csq_core::platform::test_env::lock();
        let t = tempfile::TempDir::new().unwrap();
        let root = t.path().canonicalize().unwrap();
        let old = build_fixture(&root, "old");
        let new = build_fixture(&root, "new");
        let watched = root.join("server");
        fs::rename(old, &watched).unwrap();
        let gate = root.join("gate");
        let mut child = Command::new(&watched)
            .arg(&gate)
            .env_clear()
            .env("HOME", &root)
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        struct ChildGuard<'a>(&'a mut std::process::Child);
        impl Drop for ChildGuard<'_> {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(None)) {
                    let _ = self.0.kill();
                    let deadline = Instant::now() + Duration::from_millis(100);
                    while Instant::now() < deadline && matches!(self.0.try_wait(), Ok(None)) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        let pid = child.id();
        let mut input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        // Nonblocking parent reads prevent a lost request from hanging libtest.
        // SAFETY: output owns this live pipe descriptor; fcntl changes only its flags.
        unsafe {
            let fd = output.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
        }
        let mut output = BufReader::new(output);
        let _guard = ChildGuard(&mut child);
        fn line(reader: &mut impl BufRead) -> serde_json::Value {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut text = String::new();
            loop {
                match reader.read_line(&mut text) {
                    Ok(_) if text.ends_with('\n') => return serde_json::from_str(&text).unwrap(),
                    Ok(0) => panic!("fixture EOF before response"),
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("fixture read: {e}"),
                }
                assert!(Instant::now() < deadline, "missing response: {text}");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(line(&mut output)["params"]["version"], "old");
        input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n").unwrap();
        input.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !gate.with_extension("entered").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        fs::rename(new, &watched).unwrap();
        fs::write(&gate, b"release").unwrap();
        let first = line(&mut output);
        assert_eq!(first["id"], 1);
        assert_eq!(first["result"]["fixtureImage"], "old");
        assert_eq!(first["result"]["fixturePid"], pid);
        // Old and new images are built from the same csq-core, so their tool digests are
        // equal: the replacement must NOT send list_changed (the next line is its ready).
        let ready = line(&mut output);
        assert_eq!(
            ready["method"], "fixture/ready",
            "no list_changed for an unchanged schema"
        );
        assert_eq!(ready["params"]["version"], "new");
        assert_eq!(ready["params"]["pid"], pid);
        let second = line(&mut output);
        assert_eq!(second["id"], 2);
        assert_eq!(second["result"]["tools"][0]["description"], "new");
        assert_eq!(second["result"]["fixturePid"], pid);
        drop(input);
    }
}

#[cfg(test)]
mod initialization_tests {
    use super::reload_or_warn;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_reload_initialization_warns_once_with_fixed_tag() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Buffer(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, || {
            reload_or_warn(|| Err::<(), _>(std::io::Error::other("secret-path-do-not-log")))
        });
        assert!(result.is_none());
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(output.matches("mcp_reload_disabled").count(), 1);
        assert!(!output.contains("secret-path-do-not-log"));
    }
}
