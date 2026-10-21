use super::*;

impl Directory {
    fn remove_temp(&self, name: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let name = std::ffi::CString::new(name)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: the retained directory fd and generated component remain
            // live; unlinkat removes this entry without following its target.
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            fs::remove_file(self.path.join(name))
        }
    }

    pub(super) fn cleanup(&self, name: &str) {
        if self
            .remove_temp(name)
            .is_err_and(|e| e.kind() != io::ErrorKind::NotFound)
        {
            tracing::warn!(
                error_kind = "chat_session_temp_cleanup_failed",
                "chat session temporary file could not be removed"
            );
        }
    }

    // Caller retains this session's exclusive writer lock throughout recovery.
    pub(super) fn sweep_orphan_temps(&self, id: &str) -> Result<(), StoreError> {
        self.recheck()?;
        let prefix = format!("{id}.tmp.");
        let mut removed = false;
        for entry in fs::read_dir(&self.path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            if canonical_id(suffix).is_err() {
                continue;
            }
            let file = self.file(name, false, false)?;
            check(&file.metadata().map_err(io_error)?, false)?;
            self.recheck()?;
            self.same_file(name, &file)?;
            drop(file);
            self.remove_temp(name).map_err(io_error)?;
            removed = true;
        }
        if removed {
            sync_directory(&self.file).map_err(|_| StoreError::DurabilityUnknown)?;
        }
        Ok(())
    }
}
