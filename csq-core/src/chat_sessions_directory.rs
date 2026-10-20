use super::*;

impl Directory {
    pub(super) fn child(
        self,
        name: &str,
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<Self, StoreError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let component = std::ffi::CString::new(name).map_err(|_| StoreError::UnsafePath)?;
            // SAFETY: owned directory fd and live one-component C string;
            // mkdirat creates with private permissions and retains no pointer.
            if unsafe { libc::mkdirat(self.file.as_raw_fd(), component.as_ptr(), 0o700) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(StoreError::io_os("mkdirat", &error));
                }
            }
        }
        #[cfg(windows)]
        {
            self.recheck()?;
            // Created at its final name with the owner-only DACL applied AT
            // creation (the unix `mkdirat` equivalent), so there is no window
            // for a rename. An existing entry is not trusted: it is opened and
            // judged below (`open_directory_child` -> `check_private_handle`).
            match create_private_directory(&self.path.join(name)) {
                Ok(()) | Err(StoreError::AlreadyExists) => (),
                Err(error) => return Err(error),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(StoreError::io("unsupported_platform"));
        }
        self.recheck()?;
        let path = self.path.join(name);
        let file = open_directory_child(&self, name)?;
        check(&file.metadata().map_err(io_error)?, true)?;
        // Always persist the parent entry, including retries after a prior
        // uncertain creation. Syncing only the child cannot persist its name.
        sync(&self.file).map_err(|_| StoreError::DurabilityUnknown)?;
        Ok(Self {
            file,
            path,
            parent: Some(Arc::new(self)),
        })
    }
}
