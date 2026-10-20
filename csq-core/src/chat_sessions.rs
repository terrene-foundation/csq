//! Bounded private JSONL transcripts. Caller-owned UUIDs also identify audit sessions.
//! Unix permissions and Windows owner-only store ACLs (protected DACL plus the
//! Medium no-read-up/no-write-up integrity label) are enforced. Windows binds
//! the replacement rename to the pinned parent directory handle and judges every
//! opened final component on its own handle (regular file, not a reparse point,
//! link count 1, owner, DACL, label) after a recheck that the pinned handle and
//! the path still name the same directory. Files are still OPENED by path, so
//! that recheck is not atomic with the open: Windows does NOT provide Unix dirfd
//! containment against a concurrent ancestor swap or junction replacement, and
//! the swapper need not be the same user: any principal holding delete-child or
//! add-subdirectory rights on the base directory can do it. The outcome csq
//! relies on is a failed recheck or ACL check (denial of service), not content
//! redirection; that outcome is enforced by those checks, not proven here.
//! Windows publishes by file sync, then a handle-bound rename, then a file flush
//! (the directory entry is not separately flushed);
//! native Windows runtime qualification is separate from cross compilation.
//! A failed Unix post-rename directory sync poisons the writer: disk may contain
//! the new snapshot, so reopen/resume instead of retrying append.
use csq_redact::redact_chat;
use serde::{Deserialize, Serialize};
#[cfg(not(any(unix, windows)))]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}
impl std::fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChatMessage { role: [REDACTED], content: [REDACTED] }")
    }
}
fn redact_message_checked(
    message: &ChatMessage,
    cap: u64,
    redact: impl Fn(&str) -> String,
) -> Result<ChatMessage, StoreError> {
    if message
        .role
        .len()
        .checked_add(message.content.len())
        .is_none_or(|n| n as u64 > cap)
    {
        return Err(StoreError::TooLarge);
    }
    Ok(ChatMessage {
        role: redact(&message.role),
        content: redact(&message.content),
    })
}
fn serialize_entry(buffer: &mut CappedBuffer, entry: &ChatMessage) -> Result<(), StoreError> {
    serde_json::to_writer(&mut *buffer, entry).map_err(|_| {
        if buffer.full {
            StoreError::TooLarge
        } else {
            StoreError::InvalidTranscript
        }
    })?;
    buffer.write_all(b"\n").map_err(|_| StoreError::TooLarge)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidId,
    Busy,
    TooLarge,
    InvalidUtf8,
    InvalidTranscript,
    AlreadyExists,
    NotFound,
    UnsafePath,
    DurabilityUnknown,
    Poisoned,
    Io(IoFailure),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "invalid chat session id",
            Self::Busy => "chat session writer busy",
            Self::TooLarge => "chat session exceeds size limit",
            Self::InvalidUtf8 => "chat session is not UTF-8",
            Self::InvalidTranscript => "invalid chat transcript",
            Self::AlreadyExists => "chat session already exists",
            Self::NotFound => "chat session not found",
            Self::UnsafePath => "unsafe chat session path",
            Self::DurabilityUnknown => "chat session publication durability unknown",
            Self::Poisoned => "chat session writer must be resumed",
            Self::Io(_) => "chat session storage operation failed",
        })
    }
}
impl std::error::Error for StoreError {}
#[path = "chat_sessions_failure.rs"]
mod failure;
use failure::io_error_at;
pub use failure::IoFailure;
fn io_error(error: io::Error) -> StoreError {
    io_error_at("io", error)
}
fn canonical_id(id: &str) -> Result<(), StoreError> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| StoreError::InvalidId)?;
    (parsed.hyphenated().to_string() == id)
        .then_some(())
        .ok_or(StoreError::InvalidId)
}

#[path = "chat_sessions_platform.rs"]
mod platform;
use platform::{check, node, open_directory, open_directory_child, sync_directory, CappedBuffer};
#[cfg(windows)]
use platform::{
    check_private_handle, check_single_link, create_private_directory, create_private_temp,
    open_private_file, open_private_readable, publish_handle,
};

/// Open the operator's pool `.env` read-only for the same owner-only private
/// shape as session storage (owner, protected DACL, Medium NW|NR label). A missing
/// label is stamped through this handle (it only tightens); a wrong owner, broad
/// DACL or another label is refused and never rewritten.
#[cfg(windows)]
pub(crate) fn open_private_env_file(path: &Path) -> Result<File, StoreError> {
    open_private_readable(path)
}
#[path = "chat_sessions_cleanup.rs"]
mod cleanup;
#[path = "chat_sessions_directory.rs"]
mod directory;

pub struct SessionStore {
    directory: Arc<Directory>,
    max_bytes: u64,
}
impl SessionStore {
    pub fn open(base_dir: impl AsRef<Path>, max_bytes: u64) -> Result<Self, StoreError> {
        Self::open_with_sync(base_dir.as_ref(), max_bytes, sync_directory)
    }
    // Per-call sync boundary: filesystem creation/validation remains real.
    fn open_with_sync(
        base_dir: &Path,
        max_bytes: u64,
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<Self, StoreError> {
        if max_bytes
            .checked_add(1)
            .and_then(|n| usize::try_from(n).ok())
            .is_none()
        {
            return Err(StoreError::TooLarge);
        }
        let base = Directory::open(base_dir)?;
        let directory = Arc::new(base.child("chat-sessions", sync)?);
        Ok(Self {
            directory,
            max_bytes,
        })
    }
    pub fn create(&self, id: &str) -> Result<SessionWriter, StoreError> {
        self.writer(id, true)
    }
    pub fn resume(&self, id: &str) -> Result<SessionWriter, StoreError> {
        self.writer(id, false)
    }
    fn writer(&self, id: &str, create: bool) -> Result<SessionWriter, StoreError> {
        canonical_id(id)?;
        self.directory.recheck()?;
        let lock_name = format!("{id}.lock");
        let lock_file = self.directory.file(&lock_name, true, false)?;
        check(&lock_file.metadata().map_err(io_error)?, false)?;
        match lock_file.try_lock() {
            Ok(()) => (),
            Err(fs::TryLockError::WouldBlock) => return Err(StoreError::Busy),
            Err(fs::TryLockError::Error(error)) => return Err(StoreError::io_os("lock", &error)),
        }
        let lock = WriterLock(lock_file);
        self.directory.sweep_orphan_temps(id)?;
        let name = format!("{id}.jsonl");
        let file = if create {
            self.directory.create_transcript(&name)?
        } else {
            self.directory.file(&name, false, false)?
        };
        let metadata = file.metadata().map_err(io_error)?;
        check(&metadata, false)?;
        let mut entries = Vec::new();
        let mut serialized = CappedBuffer {
            bytes: Vec::new(),
            cap: self.max_bytes,
            full: false,
        };
        if create {
            file.sync_all().map_err(io_error)?;
            sync_directory(&self.directory.file).map_err(|_| StoreError::DurabilityUnknown)?;
        } else {
            if metadata.len() > self.max_bytes {
                return Err(StoreError::TooLarge);
            }
            let mut bytes = Vec::new();
            file.take(self.max_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() as u64 > self.max_bytes {
                return Err(StoreError::TooLarge);
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| StoreError::InvalidUtf8)?;
            for line in text.split_inclusive('\n') {
                if !line.ends_with('\n') {
                    break;
                } // Never commit a torn final fragment.
                let entry: ChatMessage =
                    serde_json::from_str(line).map_err(|_| StoreError::InvalidTranscript)?;
                let entry = redact_message_checked(&entry, self.max_bytes, redact_chat)?;
                serialize_entry(&mut serialized, &entry)?;
                entries.push(entry);
            }
        }
        Ok(SessionWriter {
            directory: self.directory.clone(),
            max_bytes: self.max_bytes,
            id: id.into(),
            entries,
            serialized: serialized.bytes,
            lock_name,
            lock,
            poisoned: false,
        })
    }
}

struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        if self.0.unlock().is_err() {
            tracing::warn!(
                error_kind = "chat_session_unlock_failed",
                "chat session writer lock could not be released"
            );
        }
    }
}
pub struct SessionWriter {
    directory: Arc<Directory>,
    max_bytes: u64,
    id: String,
    entries: Vec<ChatMessage>,
    serialized: Vec<u8>,
    lock_name: String,
    lock: WriterLock,
    poisoned: bool,
}
impl SessionWriter {
    pub fn entries(&self) -> &[ChatMessage] {
        &self.entries
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn append(&mut self, message: ChatMessage) -> Result<(), StoreError> {
        self.append_with_sync(message, sync_directory)
    }
    // Only the final directory sync is injectable; write/fsync/rename are real.
    fn append_with_sync(
        &mut self,
        message: ChatMessage,
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.append_with_hooks(message, sync, |_| Ok(()))
    }
    fn append_with_hooks(
        &mut self,
        message: ChatMessage,
        sync: impl FnOnce(&File) -> io::Result<()>,
        before_replace: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.append_with_redactor(message, sync, before_replace, redact_chat)
    }
    fn append_with_redactor(
        &mut self,
        message: ChatMessage,
        sync: impl FnOnce(&File) -> io::Result<()>,
        before_replace: impl FnOnce(&Path) -> io::Result<()>,
        redact: impl Fn(&str) -> String,
    ) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let sanitized = redact_message_checked(&message, self.max_bytes, redact)?;
        self.directory.recheck()?;
        self.directory.same_file(&self.lock_name, &self.lock.0)?;
        let name = format!("{}.jsonl", self.id);
        let existing = self.directory.file(&name, false, false)?;
        let metadata = existing.metadata().map_err(io_error)?;
        check(&metadata, false)?;
        if metadata.len() > self.max_bytes {
            return Err(StoreError::TooLarge);
        }
        let mut buffer = CappedBuffer {
            bytes: self.serialized.clone(),
            cap: self.max_bytes,
            full: false,
        };
        serialize_entry(&mut buffer, &sanitized)?;
        let temporary = format!("{}.tmp.{}", self.id, uuid::Uuid::new_v4());
        let mut file = self.directory.temp_file(&temporary)?;
        let result = (|| {
            file.write_all(&buffer.bytes).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            check(&file.metadata().map_err(io_error)?, false)?;
            self.directory.recheck()?;
            self.directory.same_file(&self.lock_name, &self.lock.0)?;
            self.directory.same_file(&name, &existing)?;
            // Windows: `file` is the one handle from create to publish (share
            // READ only), so identity and content are fixed by construction.
            #[cfg(not(windows))]
            self.directory.same_file(&temporary, &file)?;
            before_replace(&self.directory.path.join(&temporary)).map_err(io_error)?;
            #[cfg(windows)]
            drop(existing);
            let published = self.directory.replace(&temporary, &name, &file);
            if published == Err(StoreError::DurabilityUnknown) {
                self.poisoned = true; // renamed, then a later step failed: published.
            }
            published?;
            // The rename has published. A sync failure is uncertain durability,
            // not proof of rollback; never permit a blind duplicate retry.
            if sync(&self.directory.file).is_err() {
                self.poisoned = true;
                return Err(StoreError::DurabilityUnknown);
            }
            Ok(())
        })();
        // Close the temp handle first: on Windows it denies delete sharing, so
        // cleanup by path could not remove it while open.
        drop(file);
        if result.is_err() {
            self.directory.cleanup(&temporary);
        }
        if self.poisoned {
            self.entries.push(sanitized); // Published snapshot; only durability is uncertain.
            self.serialized = buffer.bytes;
            return result;
        }
        result?;
        self.entries.push(sanitized);
        self.serialized = buffer.bytes;
        Ok(())
    }
}
struct Directory {
    file: File,
    path: PathBuf,
    parent: Option<Arc<Directory>>,
}
impl Directory {
    fn open(path: &Path) -> Result<Self, StoreError> {
        check(&fs::symlink_metadata(path).map_err(io_error)?, true)?;
        let file = open_directory(path)?;
        check(&file.metadata().map_err(io_error)?, true)?;
        let path = path.canonicalize().map_err(io_error)?;
        if node(&open_directory(&path)?)? != node(&file)? {
            return Err(StoreError::UnsafePath);
        }
        Ok(Self {
            file,
            path,
            parent: None,
        })
    }
    fn recheck(&self) -> Result<(), StoreError> {
        if let Some(parent) = &self.parent {
            parent.recheck()?;
        }
        check(&self.file.metadata().map_err(io_error)?, true)?;
        #[cfg(windows)]
        if self.parent.is_some() {
            check_private_handle(&self.file)?;
        }
        let named = open_directory(&self.path)?;
        #[cfg(windows)]
        if self.parent.is_some() {
            check_private_handle(&named)?;
        }
        check(&named.metadata().map_err(io_error)?, true)?;
        (node(&named)? == node(&self.file)?)
            .then_some(())
            .ok_or(StoreError::UnsafePath)
    }
    /// Create the exclusive publish temp. Unix: an `openat` fd renamed by dirfd.
    /// Windows: the single create-to-publish handle (`create_private_temp`).
    fn temp_file(&self, name: &str) -> Result<File, StoreError> {
        #[cfg(windows)]
        {
            self.recheck()?;
            let file = create_private_temp(&self.path.join(name))?;
            check(&file.metadata().map_err(io_error)?, false)?;
            check_single_link(&file)?;
            Ok(file)
        }
        #[cfg(not(windows))]
        {
            self.file(name, true, true)
        }
    }
    fn file(&self, name: &str, create: bool, exclusive: bool) -> Result<File, StoreError> {
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let name = std::ffi::CString::new(name).map_err(|_| StoreError::UnsafePath)?;
            let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
            if create {
                flags |= libc::O_CREAT;
            }
            if exclusive {
                flags |= libc::O_EXCL;
            }
            // SAFETY: owned directory fd and one-component generated name;
            // successful openat transfers one new fd to File.
            let fd = unsafe { libc::openat(self.file.as_raw_fd(), name.as_ptr(), flags, 0o600) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                return Err(match error.raw_os_error() {
                    Some(libc::ELOOP | libc::EISDIR) => StoreError::UnsafePath,
                    _ => io_error(error),
                });
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        #[cfg(windows)]
        {
            self.recheck()?;
            let file = open_private_file(&self.path.join(name), create, exclusive)?;
            check(&file.metadata().map_err(io_error)?, false)?;
            check_single_link(&file)?;
            Ok(file)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .create_new(exclusive)
                .open(self.path.join(name))
                .map_err(io_error)?;
            check(&file.metadata().map_err(io_error)?, false)?;
            Ok(file)
        }
    }

    fn same_file(&self, name: &str, file: &File) -> Result<(), StoreError> {
        let named = self.file(name, false, false)?;
        check(&named.metadata().map_err(io_error)?, false)?;
        (node(&named)? == node(file)?)
            .then_some(())
            .ok_or(StoreError::UnsafePath)
    }
    fn replace(&self, from: &str, to: &str, source: &File) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            let _ = source; // unix renames by dirfd + name; no post-rename step.
            use std::os::fd::AsRawFd;
            let from = std::ffi::CString::new(from).map_err(|_| StoreError::UnsafePath)?;
            let to = std::ffi::CString::new(to).map_err(|_| StoreError::UnsafePath)?;
            // SAFETY: both generated names and the owned directory fd live
            // through this atomic same-directory rename; no pointers retained.
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    from.as_ptr(),
                    self.file.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                return Err(StoreError::io_os("renameat", &io::Error::last_os_error()));
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            let _ = from; // the handle, not the name, is what is published.
            publish_handle(&self.file, source, to)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (from, to, source);
            Err(StoreError::io("unsupported_platform"))
        }
    }
    /// An exclusive create at the final name: unix `O_CREAT|O_EXCL`, Windows
    /// `CREATE_NEW` with the owner-only DACL applied at creation. An existing
    /// entry is refused (`AlreadyExists`), never replaced, and the returned handle
    /// is the very file created: no temp, no rename.
    fn create_transcript(&self, name: &str) -> Result<File, StoreError> {
        self.file(name, true, true)
    }
}

#[cfg(all(test, unix))]
#[path = "chat_sessions_fault_tests.rs"]
mod fault_tests;
