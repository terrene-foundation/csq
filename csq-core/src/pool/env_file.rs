use super::{PoolError, PoolName, Result};
use secrecy::SecretString;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_ENV_BYTES: u64 = 1024 * 1024;

fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(not(windows))]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // Windows: the open itself opens the reparse point (no follow), checks owner and
    // DACL and the private label, stamping a missing label (it only tightens).
    #[cfg(windows)]
    let mut file = crate::chat_sessions::open_private_env_file(path)
        .map_err(|_| PoolError::EnvFileUnavailable)?;
    #[cfg(not(windows))]
    let mut file = opts.open(path).map_err(|_| PoolError::EnvFileUnavailable)?;
    let metadata = file.metadata().map_err(|_| PoolError::EnvFileUnavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_ENV_BYTES {
        return Err(PoolError::EnvFileUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or pointer preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(PoolError::EnvFileUnavailable);
        }
        refuse_extended_acl(&file)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Refuse every reparse type, even if Windows classifies it as a file.
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            return Err(PoolError::EnvFileUnavailable);
        }
    }
    // Allocate once from the admitted fstat length plus one growth sentinel.
    // A growing file is refused; no unwiped prefix is freed by reallocation.
    let admitted_len = metadata.len().min(MAX_ENV_BYTES) as usize;
    read_admitted(&mut file, admitted_len)
}

fn read_admitted(
    reader: &mut impl std::io::Read,
    admitted_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0; admitted_len + 1]);
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PoolError::EnvFileUnavailable),
        }
    }
    if used > admitted_len {
        return Err(PoolError::EnvFileUnavailable);
    }
    bytes.truncate(used);
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn refuse_extended_acl(file: &std::fs::File) -> Result<()> {
    use std::os::fd::AsRawFd;
    admit_linux_acl_metadata(|name| {
        // SAFETY: same borrowed live descriptor for both namespaces,
        // terminated attribute name, documented null-buffer size query.
        // No ACL is modified or payload read.
        let size =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size == -1 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ENODATA | libc::ENOTSUP) => Ok(None),
                _ => Err(error),
            }
        } else {
            Ok(Some(size as usize))
        }
    })
}

#[cfg(target_os = "linux")]
fn admit_linux_acl_metadata(
    mut query: impl FnMut(&std::ffi::CStr) -> std::io::Result<Option<usize>>,
) -> Result<()> {
    // Refuse any present POSIX or NFSv4 access ACL, including read-only ACLs.
    for name in [c"system.posix_acl_access", c"system.nfs4_acl"] {
        match query(name) {
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => return Err(PoolError::EnvFileUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn refuse_extended_acl(file: &std::fs::File) -> Result<()> {
    use std::{ffi::c_void, os::fd::AsRawFd, ptr};
    // ABI declarations pinned to the platform SDK's sys/acl.h. ACL_TYPE_EXTENDED
    // is 0x100 and ACL_FIRST_ENTRY is 0; returned storage belongs to acl_free.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry: libc::c_int,
            out: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_valid(acl: *mut c_void) -> libc::c_int;
        fn acl_free(acl: *mut c_void) -> libc::c_int;
    }
    // SAFETY: live borrowed file descriptor; only queries its extended ACL.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        // Apple's filesec_get_property reports ENOENT for an absent ACL; the
        // descriptor itself already passed fstat, and no path is re-opened.
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(PoolError::EnvFileUnavailable)
        };
    }
    let mut entry = ptr::null_mut();
    // SAFETY: allocated ACL remains live during validity/first-entry queries.
    let valid = unsafe { acl_valid(acl) } == 0;
    let first = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: exactly one release of the ACL returned by acl_get_fd_np.
    let released = unsafe { acl_free(acl) } == 0;
    // On Darwin acl_get_entry returns -1/EINVAL after the final entry, unlike
    // Linux's 0 end marker. A valid empty ACL therefore has no first entry.
    if valid && released && first == -1 && error == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(PoolError::EnvFileUnavailable)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn refuse_extended_acl(_file: &std::fs::File) -> Result<()> {
    Err(PoolError::EnvFileUnavailable)
}

fn assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
    if line.starts_with('#') || line.is_empty() {
        return None;
    }
    line.split_once('=')
        .map(|(name, value)| (name.trim(), value.trim()))
}

/// Checks the assignment name only; it never parses, exposes, or decrypts its value.
pub(crate) fn contains(path: &Path, name: &PoolName) -> Result<bool> {
    let bytes = read(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| PoolError::EnvFileInvalid)?;
    Ok(text
        .lines()
        .any(|line| assignment(line).is_some_and(|(key, _)| key == name.as_str())))
}

/// Literal dotenv subset: quotes are stripped, expansions and shell syntax are never executed.
/// Duplicate admitted names fail closed instead of selecting an ambiguous credential.
pub(crate) fn get(path: &Path, name: &PoolName) -> Result<SecretString> {
    let bytes = read(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| PoolError::EnvFileInvalid)?;
    let mut found = None;
    for line in text.lines() {
        let Some((key, raw)) = assignment(line) else {
            continue;
        };
        if key != name.as_str() {
            continue;
        }
        if found.is_some() {
            return Err(PoolError::EnvFileInvalid);
        }
        let value = if raw.starts_with(['\'', '"']) {
            let quote = raw.as_bytes()[0];
            if raw.len() < 2 || raw.as_bytes().last() != Some(&quote) {
                return Err(PoolError::EnvFileInvalid);
            }
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        super::validate_key(value)?;
        found = Some(SecretString::from(value.to_owned()));
    }
    found.ok_or(PoolError::KeyMissing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_acl_metadata_is_refused_and_query_errors_fail_closed() {
        let mut queried = Vec::new();
        let result = admit_linux_acl_metadata(|name| {
            queried.push(name.to_bytes().to_vec());
            Ok((name == c"system.nfs4_acl").then_some(64))
        });
        assert!(matches!(result, Err(PoolError::EnvFileUnavailable)));
        assert_eq!(
            queried,
            [
                b"system.posix_acl_access".to_vec(),
                b"system.nfs4_acl".to_vec()
            ]
        );
        assert!(admit_linux_acl_metadata(|_| Ok(None)).is_ok());
        assert!(matches!(
            admit_linux_acl_metadata(|name| {
                if name == c"system.nfs4_acl" {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                } else {
                    Ok(None)
                }
            }),
            Err(PoolError::EnvFileUnavailable)
        ));
    }

    #[test]
    fn admitted_buffer_is_sized_to_fstat_and_refuses_growth() {
        let bytes = read_admitted(&mut std::io::Cursor::new(b"short"), 5).unwrap();
        assert_eq!(&bytes[..], b"short");
        assert_eq!(bytes.capacity(), 6);
        assert!(matches!(
            read_admitted(&mut std::io::Cursor::new(b"growing"), 5),
            Err(PoolError::EnvFileUnavailable)
        ));
        assert_eq!(
            read_admitted(&mut std::io::Cursor::new(b""), 0)
                .unwrap()
                .capacity(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_regular_fixture_is_admitted_without_extended_acl() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env-fixture");
        std::fs::write(&path, b"fixture=synthetic").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&read(&path).unwrap()[..], b"fixture=synthetic");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extended_write_acl_is_refused_on_fixture_handle() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env-acl-fixture");
        std::fs::write(&path, b"fixture=synthetic").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(read(&path), Err(PoolError::EnvFileUnavailable)));
    }
}
