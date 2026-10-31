//! Held private database file acquisition on Windows.
//!
//! Same contract as the unix module in `secure.rs`: the directory ancestry, the
//! database and its sidecars are held open, checked before and after every
//! operation, and any doubt refuses. This does not open a SQLite connection.
//!
//! What the platform changes, and why none of it widens what is accepted:
//!
//! * There is no `openat(2)`, so a component cannot be pinned for a later
//!   RELATIVE open: every open here is a full path and the OS resolves the
//!   intermediate components. The containment is the cooperative one the
//!   chat-session store documents: handles are held on the checked ancestry and
//!   each held handle's identity is compared with a fresh no-follow open of its
//!   path before and after a caller's operation. A same-user writer that swaps an
//!   ancestor between an identity check and a following full-path open is not
//!   excluded — it is detected at the next recheck, and a file it substitutes is
//!   still judged by its own DACL, not by the directory it sits in.
//! * `0o700`/`0o600` and the owner UID become the private ACL shape
//!   (`platform::fs_windows_acl`): a protected owner-only DACL, the Medium NW|NR
//!   integrity label, a single hard link and no reparse point.
//! * The unix ancestor rule (`untrusted_directory_reason`) becomes
//!   [`check_no_foreign_write`]: no principal but the current user (or a
//!   system-level one) may hold a right that can remove, rename or re-secure an
//!   entry of an ancestor. That is looser than the private-leaf shape by design —
//!   a drive root and a profile path are never owner-only — and stricter than
//!   "readable by others", which no ancestor needs to be.
//! * Only the DATA and `DELETE` access bits take part in a Windows share
//!   check (R1 F6): a handle holding `DELETE` or a data read/write the peer's
//!   share mode does not cover makes that peer's open fail with a sharing
//!   violation, while `WRITE_OWNER`, `WRITE_DAC`, `READ_CONTROL` and
//!   `FILE_READ_ATTRIBUTES` are outside the mask and conflict with nothing.
//!   The held database and sidecar handles therefore carry only `GENERIC_READ`
//!   (or `GENERIC_READ | GENERIC_WRITE` for the database), no `DELETE`, which
//!   SQLite's `FILE_SHARE_READ | FILE_SHARE_WRITE` open covers; an object a
//!   pre-label csq wrote is upgraded through the ordinary owner handle first
//!   and then reopened this way.
//! * The leaf directory is the one directory a THIRD PARTY writes into: SQLite
//!   creates its `-journal`/`-wal`/`-shm` with the Win32 default security
//!   descriptor (`CreateFileW(..., NULL, ...)`), so those children receive only
//!   what the leaf propagates. A protected non-inheriting leaf propagates
//!   nothing, which would leave every sidecar with an empty DACL. The leaf must
//!   therefore carry the INHERITABLE owner-only shape
//!   ([`create_private_directory_inheriting`]): one `FILE_ALL_ACCESS` ACE for the
//!   current user, and one Medium NW|NR label ACE, both marked `OBJECT_INHERIT |
//!   CONTAINER_INHERIT`. A sidecar then inherits exactly the private grant and the
//!   no-read-up label, and is accepted by the inherited-aware sidecar check.
//!   Pre-creating the journal is not an alternative: beside a zero-page database
//!   SQLite deletes a journal that is not open (`hasHotJournal`), which would turn
//!   a held sidecar into `NamespaceChanged` on the first open.
use super::SecureDatabaseError as Error;
use crate::platform::fs_windows_acl::{
    apply_adopted_child_descriptor, apply_inheriting_directory_nonpropagating,
    check_adoption_child, check_no_foreign_write, check_no_foreign_write_for_adoption,
    check_private_directory_inheriting_as, check_private_handle_as,
    check_private_inherited_handle_as, create_new_private_file, create_private_directory,
    create_private_directory_inheriting, dacl_is_protected, observed_owner,
    open_adoption_child_handle, open_directory_adopt_handle, open_directory_check_handle,
    open_owner_write_handle, open_private_directory, open_private_directory_inheriting,
    open_private_file, open_private_readable, open_private_shared, open_unchecked_shared_handle,
    owner_is_user, set_owner_to_current_user, sidecar_default_owner,
    sidecar_owner_needs_tightening, PrivateAclError, UserSid,
};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};

const SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];
/// NTFS/SMB allow 255 UTF-16 units per component; the longest suffix is
/// `-journal` (8), so the database name itself is bounded to 247 as on unix.
const MAX_NAME_UNITS: usize = 247;

pub(super) struct HeldDatabase {
    directories: Vec<Entry>,
    pub(super) database: Entry,
    sidecars: std::sync::Mutex<Vec<Option<Entry>>>,
    user: UserSid,
    policy: super::LeafPolicy,
}

pub(super) struct Entry {
    pub(super) file: File,
    path: PathBuf,
}

fn invalid() -> Error {
    Error::InvalidPath
}

/// One path component: no separators, no drive/stream syntax, no reserved
/// characters, no Win32-trailing space or dot (which the OS would silently
/// normalize to a different name), and short enough for the longest sidecar.
fn validate_name(name: &OsStr) -> Result<(), Error> {
    let units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty() || units.len() > MAX_NAME_UNITS {
        return Err(invalid());
    }
    // `/` is a path separator in the Win32 APIs even though it is legal in an
    // NTFS name, so a name carrying one would silently address a subdirectory
    // (native run 41151503624: `nested/db` was accepted as a database name).
    if units
        .iter()
        .any(|unit| *unit < 0x20 || (*unit < 0x80 && b"\"*:<>?\\/|".contains(&(*unit as u8))))
    {
        return Err(invalid());
    }
    if units.iter().all(|unit| *unit == u16::from(b'.')) {
        return Err(invalid());
    }
    if units
        .last()
        .is_some_and(|unit| *unit == 0x20 || *unit == 0x2e)
    {
        return Err(invalid());
    }
    Ok(())
}

/// An absolute drive path with no `.`/`..` component and a disk prefix. UNC,
/// device and bare-verbatim prefixes are refused: the private directory must be
/// on a local volume, whose ACL and `FileId` semantics csq can check.
fn validate_directory(dir: &Path) -> Result<(), Error> {
    if !dir.is_absolute() {
        return Err(invalid());
    }
    let mut components = dir.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid());
    }
    if !components.all(|component| matches!(component, Component::Normal(_))) {
        return Err(invalid());
    }
    Ok(())
}

/// File identity: (volume, id, `wide`). `wide` records the 128-bit `FileIdInfo`
/// source and is `false` for the 32-bit-volume / 64-bit-index fallback, so two
/// identities read through DIFFERENT sources never compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Node {
    volume: u64,
    id: u128,
    wide: bool,
}

/// `FileIdInfo` is unsupported (some SMB redirectors, older filesystems) only for
/// these codes; anything else is a real failure. ERROR_INVALID_FUNCTION,
/// ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER.
fn file_id_unsupported(code: Option<i32>) -> bool {
    matches!(code, Some(1 | 50 | 87))
}

fn node(file: &File) -> std::io::Result<Node> {
    // SAFETY: zero is a valid initial buffer; the API fills exactly
    // size_of::<FILE_ID_INFO>() bytes synchronously from a live handle.
    let mut info: FILE_ID_INFO = unsafe { mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::addr_of_mut!(info).cast(),
            mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0
    {
        return Ok(Node {
            volume: info.VolumeSerialNumber,
            id: u128::from_le_bytes(info.FileId.Identifier),
            wide: true,
        });
    }
    let error = std::io::Error::last_os_error();
    if !file_id_unsupported(error.raw_os_error()) {
        return Err(error);
    }
    // SAFETY: zero is a valid buffer; the API fills it synchronously from the
    // live borrowed handle and retains no pointer.
    let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut basic) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Node {
        volume: u64::from(basic.dwVolumeSerialNumber),
        id: u128::from((u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow)),
        wide: false,
    })
}

fn basic(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, Error> {
    // SAFETY: zero is a valid buffer; the API fills it synchronously from the
    // live borrowed handle and retains no pointer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(Error::Unavailable);
    }
    Ok(info)
}

/// Opens `path` as itself (`O_NOFOLLOW` analogue) with the least access that
/// reads attributes and the security descriptor. Only the data and `DELETE`
/// access bits are checked against a peer's share mode; this handle requests
/// neither, so it conflicts with no peer open (R1 F6).
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// The held handle and a fresh no-follow open of its path are the same object.
/// A path that no longer opens, or opens a different `FileId`, has moved.
fn same_object(file: &File, path: &Path) -> Result<(), Error> {
    let fresh = open_no_follow(path).map_err(|_| Error::NamespaceChanged)?;
    let held = node(file).map_err(|_| Error::Unavailable)?;
    let named = node(&fresh).map_err(|_| Error::NamespaceChanged)?;
    if held != named {
        return Err(Error::NamespaceChanged);
    }
    Ok(())
}

fn directory_shape(file: &File) -> Result<(), Error> {
    let info = basic(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::UnsafeDirectory);
    }
    Ok(())
}

/// A held directory: unchanged identity, still a real (non-reparse) directory,
/// and — for the leaf — exactly private in the mode's shape, or — for an
/// ancestor — no foreign entry-removing right.
fn check_directory(
    entry: &Entry,
    private: bool,
    user: &UserSid,
    policy: super::LeafPolicy,
) -> Result<(), Error> {
    same_object(&entry.file, &entry.path)?;
    directory_shape(&entry.file)?;
    if private {
        match policy {
            // The strict leaf is a csq-created private directory.
            super::LeafPolicy::Strict => check_private_handle_as(&entry.file, user),
            // The pool leaf is the directory a third-party writer (SQLite)
            // creates its sidecars in, so it must carry the INHERITABLE shape.
            super::LeafPolicy::PoolLedger => {
                check_private_directory_inheriting_as(&entry.file, user)
            }
        }
        .map_err(|_| Error::UnsafeDirectory)
    } else {
        check_no_foreign_write(&entry.file).map_err(|_| Error::UnsafeDirectory)
    }
}

fn directories_recheck(
    entries: &[Entry],
    user: &UserSid,
    policy: super::LeafPolicy,
) -> Result<(), Error> {
    let last = entries.len().checked_sub(1).ok_or(Error::Unavailable)?;
    for (index, entry) in entries.iter().enumerate() {
        check_directory(entry, index == last, user, policy)?;
    }
    Ok(())
}

/// A held private FILE's identity and type: unchanged object, a regular
/// single-linked file with no reparse point.
fn entry_shape(entry: &Entry) -> Result<(), Error> {
    same_object(&entry.file, &entry.path)?;
    let info = basic(&entry.file)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error::UnsafeFile);
    }
    Ok(())
}

/// The database: csq creates it, so it must carry the at-creation protected shape.
fn database_entry(entry: &Entry, user: &UserSid) -> Result<(), Error> {
    entry_shape(entry)?;
    check_private_handle_as(&entry.file, user).map_err(|_| Error::UnsafeFile)
}

/// A sidecar in the mode's shape. Strict mode requires the at-creation protected
/// shape; pool mode requires ONLY the shape inherited from the pool leaf — csq
/// never creates a sidecar, so an at-creation-shaped file at a sidecar name can
/// only have been planted (R1 M1/F1).
fn sidecar_entry(entry: &Entry, user: &UserSid, policy: super::LeafPolicy) -> Result<(), Error> {
    entry_shape(entry)?;
    match policy {
        super::LeafPolicy::Strict => check_private_handle_as(&entry.file, user),
        super::LeafPolicy::PoolLedger => check_private_inherited_handle_as(&entry.file, user),
    }
    .map_err(|_| Error::UnsafeFile)
}

fn sidecar_name(name: &OsStr, suffix: &str) -> OsString {
    let mut full = name.to_os_string();
    full.push(suffix);
    full
}

/// A held sidecar handle in the mode's shape. Pool sidecars are created by
/// SQLite INSIDE the leaf with NULL security attributes, so they carry the
/// leaf's DACL and label by INHERITANCE and nothing else is accepted; there is
/// no stamping fallback (R1 M1). Strict sidecars are csq-created files.
fn open_sidecar_held(
    path: &Path,
    user: &UserSid,
    policy: super::LeafPolicy,
) -> Result<File, PrivateAclError> {
    let file = open_unchecked_shared_handle(path, false)?;
    match policy {
        super::LeafPolicy::Strict => check_private_handle_as(&file, user)?,
        super::LeafPolicy::PoolLedger => {
            check_private_inherited_handle_as(&file, user)?;
            // R2 NEW-3: the owner tightening happens only AFTER
            // `sidecar_entry` has validated the object (reparse, single link,
            // identity), in `open_sidecar`.
        }
    }
    Ok(file)
}

/// Set once the not-tightened WARN has been logged in this process.
static SIDECAR_NOT_TIGHTENED_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
fn warn_not_tightened_once() {
    if !SIDECAR_NOT_TIGHTENED_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!(
            error_kind = "pool_sidecar_owner_not_tightened",
            "an Administrators-owned pool sidecar could not be handed back to \
             the user SID; a later non-elevated run will refuse it (logged once \
             per process). Remediation: run the ledger once more from the same \
             ELEVATED context that owns the sidecar; do NOT delete a `-journal` \
             — it may hold a rollback the ledger still needs."
        );
    }
}

/// Outcome of [`tighten_sidecar_owner_with`]; the two refusing arms log the
/// once-per-process WARN and leave the file untouched.
#[derive(Debug, PartialEq, Eq)]
enum TightenOutcome {
    /// The owner already is the user SID.
    AlreadyTight,
    /// The identity-bound write handle named a DIFFERENT object.
    Mismatch,
    /// The check or the write handle could not be obtained, or the set failed.
    Skipped,
    /// The owner was handed back to the user SID.
    Tightened,
}

/// The elevated-run tightening (ROOT M3): an Administrators-owned sidecar is
/// given back to the token user SID so a later NON-elevated run is not locked
/// out. The write handle is IDENTITY-BOUND: opened no-follow, its volume+FileId
/// must equal the held handle's, and on any mismatch or failure the file is
/// left untouched and `pool_sidecar_owner_not_tightened` is logged. A failure
/// NEVER refuses the sidecar — it is a tightening, not a gate.
fn tighten_sidecar_owner(path: &Path, held: &File, user: &UserSid) {
    match tighten_sidecar_owner_with(path, held, user, false) {
        TightenOutcome::Mismatch | TightenOutcome::Skipped => warn_not_tightened_once(),
        TightenOutcome::AlreadyTight | TightenOutcome::Tightened => {}
    }
}

/// [`tighten_sidecar_owner`] with the needs-tightening verdict forced on for a
/// test, so the identity-mismatch refusal is exercised on hosts where a
/// NULL-attribute child is already user-owned (a non-elevated token).
#[cfg(test)]
fn tighten_sidecar_owner_for_test(
    path: &Path,
    held: &File,
    user: &UserSid,
    force_needs_tightening: bool,
) -> TightenOutcome {
    tighten_sidecar_owner_with(path, held, user, force_needs_tightening)
}

fn tighten_sidecar_owner_with(
    path: &Path,
    held: &File,
    user: &UserSid,
    force_needs_tightening: bool,
) -> TightenOutcome {
    let needs_tightening = if force_needs_tightening {
        true
    } else {
        // The production decision: tighten ONLY the Administrators
        // default-owner branch that the checker accepted (R1 M3). A user-owned
        // sidecar is already tight; an unreadable owner skips (never a gate).
        match (observed_owner(held), sidecar_default_owner()) {
            (Ok(observed), Ok(default_owner)) => {
                sidecar_owner_needs_tightening(&observed, user.bytes(), default_owner.bytes())
            }
            _ => return TightenOutcome::Skipped,
        }
    };
    if !needs_tightening {
        return TightenOutcome::AlreadyTight;
    }
    let fresh = match open_owner_write_handle(path) {
        Ok(file) => file,
        Err(_) => return TightenOutcome::Skipped,
    };
    let same = match (node(held), node(&fresh)) {
        (Ok(held_node), Ok(fresh_node)) => held_node == fresh_node,
        _ => false,
    };
    if !same {
        return TightenOutcome::Mismatch;
    }
    match set_owner_to_current_user(&fresh) {
        Ok(()) => TightenOutcome::Tightened,
        Err(_) => TightenOutcome::Skipped,
    }
}

/// An existing sidecar, validated; `None` only for genuine absence (a dangling
/// symlink at the name is not absence).
fn open_sidecar(
    dir: &Path,
    side: &OsStr,
    user: &UserSid,
    policy: super::LeafPolicy,
) -> Result<Option<Entry>, Error> {
    let path = dir.join(side);
    match open_sidecar_held(&path, user, policy) {
        Ok(file) => {
            let entry = Entry { file, path };
            // Validate the object BEFORE any owner change (R2 NEW-3): the
            // tightening must never land on a hardlinked, reparse or
            // identity-changed entry.
            sidecar_entry(&entry, user, policy)?;
            if matches!(policy, super::LeafPolicy::PoolLedger) {
                tighten_sidecar_owner(&entry.path, &entry.file, user);
            }
            Ok(Some(entry))
        }
        Err(PrivateAclError::Os(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(Error::UnsafeFile),
            }
        }
        Err(_) => Err(Error::UnsafeFile),
    }
}

fn sidecars_recheck(
    parent: &Entry,
    name: &OsStr,
    entries: &mut [Option<Entry>],
    user: &UserSid,
    policy: super::LeafPolicy,
) -> Result<(), Error> {
    for (index, suffix) in SUFFIXES.into_iter().enumerate() {
        if let Some(entry) = &entries[index] {
            sidecar_entry(entry, user, policy)?;
        }
        let side = sidecar_name(name, suffix);
        let current = open_sidecar(&parent.path, &side, user, policy)?;
        let changed = match (&entries[index], &current) {
            (Some(held), Some(fresh)) => {
                node(&held.file).map_err(|_| Error::Unavailable)?
                    != node(&fresh.file).map_err(|_| Error::Unavailable)?
            }
            (Some(_), None) => true,
            _ => false,
        };
        if changed {
            return Err(Error::NamespaceChanged);
        }
        if entries[index].is_none() {
            entries[index] = current;
        }
    }
    Ok(())
}

/// Opens an existing private file with only the access a peer's share mode
/// covers. A file csq wrote before the integrity label existed is upgraded
/// through the ordinary owner handle first (that handle asks for `WRITE_OWNER`,
/// which cannot coexist with a peer), then reopened this way.
fn open_held(path: &Path, write: bool) -> Result<File, PrivateAclError> {
    match open_private_shared(path, write) {
        Ok(file) => Ok(file),
        Err(PrivateAclError::UnsafePath) => {
            let upgrade = if write {
                open_private_file(path, false, false)
            } else {
                open_private_readable(path)
            };
            drop(upgrade?);
            open_private_shared(path, write)
        }
        Err(other) => Err(other),
    }
}

impl HeldDatabase {
    pub(super) fn acquire(
        dir: &Path,
        name: &OsStr,
        user: &UserSid,
        policy: super::LeafPolicy,
    ) -> Result<Self, Error> {
        Self::acquire_mode(dir, name, user, true, policy)
    }

    pub(super) fn acquire_existing(
        dir: &Path,
        name: &OsStr,
        user: &UserSid,
        policy: super::LeafPolicy,
    ) -> Result<Self, Error> {
        Self::acquire_mode(dir, name, user, false, policy)
    }

    fn acquire_mode(
        dir: &Path,
        name: &OsStr,
        user: &UserSid,
        create: bool,
        policy: super::LeafPolicy,
    ) -> Result<Self, Error> {
        validate_name(name)?;
        validate_directory(dir)?;
        // Root first, exactly like the unix walk: the leaf is opened privately,
        // every ancestor only under the entry-removing rule.
        let mut chain: Vec<&Path> = dir.ancestors().collect();
        chain.reverse();
        let (leaf, ancestors) = chain.split_last().ok_or(Error::Unavailable)?;
        let mut directories = Vec::with_capacity(ancestors.len() + 1);
        for ancestor in ancestors {
            let file = open_no_follow(ancestor).map_err(|_| Error::UnsafeDirectory)?;
            let entry = Entry {
                file,
                path: ancestor.to_path_buf(),
            };
            check_directory(&entry, false, user, policy)?;
            directories.push(entry);
        }
        let leaf_file = match open_leaf(leaf, policy) {
            Ok(file) => file,
            // Creating the leaf is the caller's intent on the create path only;
            // `acquire_existing` reports the same UnsafeDirectory as a missing
            // ancestor.
            Err(PrivateAclError::Os(error))
                if error.kind() == std::io::ErrorKind::NotFound && create =>
            {
                create_leaf(leaf, policy).map_err(|_| Error::UnsafeDirectory)?;
                open_leaf(leaf, policy).map_err(|_| Error::UnsafeDirectory)?
            }
            Err(_) => return Err(Error::UnsafeDirectory),
        };
        directories.push(Entry {
            file: leaf_file,
            path: leaf.to_path_buf(),
        });
        let parent = directories.last().ok_or(Error::Unavailable)?;
        let mut sidecars = Vec::with_capacity(SUFFIXES.len());
        for suffix in SUFFIXES {
            sidecars.push(open_sidecar(
                &parent.path,
                &sidecar_name(name, suffix),
                user,
                policy,
            )?);
        }
        let path = dir.join(name);
        let file = match open_held(&path, true) {
            Ok(file) => file,
            Err(PrivateAclError::Os(error))
                if error.kind() == std::io::ErrorKind::NotFound && create =>
            {
                directories_recheck(&directories, user, policy)?;
                sidecars_recheck(parent, name, &mut sidecars, user, policy)?;
                // Exclusive creation with the owner-only descriptor applied AT
                // creation; the handle carries `DELETE` for its own cleanup and is
                // then replaced by a share-compatible one, because a held `DELETE`
                // access would make SQLite's default share mode fail.
                drop(create_new_private_file(&path).map_err(|_| Error::Unavailable)?);
                open_held(&path, true).map_err(|_| Error::UnsafeFile)?
            }
            Err(PrivateAclError::Os(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Unavailable)
            }
            Err(_) => return Err(Error::UnsafeFile),
        };
        let database = Entry { file, path };
        database_entry(&database, user)?;
        let held = Self {
            directories,
            database,
            sidecars: std::sync::Mutex::new(sidecars),
            user: user.clone(),
            policy,
        };
        held.recheck()?;
        Ok(held)
    }

    pub(super) fn recheck(&self) -> Result<(), Error> {
        let last = self
            .directories
            .len()
            .checked_sub(1)
            .ok_or(Error::Unavailable)?;
        directories_recheck(&self.directories, &self.user, self.policy)?;
        database_entry(&self.database, &self.user)?;
        let parent = &self.directories[last];
        let name = self.database.path.file_name().ok_or_else(invalid)?;
        let mut sidecars = self.sidecars.lock().map_err(|_| Error::Unavailable)?;
        sidecars_recheck(parent, name, &mut sidecars, &self.user, self.policy)?;
        Ok(())
    }
}

/// Opens the leaf in the mode's shape; the pool mode additionally ADOPTS a
/// pre-existing default-DACL root (R1 F5).
fn open_leaf(path: &Path, policy: super::LeafPolicy) -> Result<File, PrivateAclError> {
    match policy {
        super::LeafPolicy::Strict => open_private_directory(path),
        super::LeafPolicy::PoolLedger => match open_private_directory_inheriting(path) {
            Ok(file) => Ok(file),
            Err(PrivateAclError::UnsafePath) => adopt_pool_root(path),
            Err(other) => Err(other),
        },
    }
}

fn create_leaf(path: &Path, policy: super::LeafPolicy) -> Result<(), PrivateAclError> {
    match policy {
        super::LeafPolicy::Strict => create_private_directory(path),
        super::LeafPolicy::PoolLedger => create_private_directory_inheriting(path),
    }
}

/// Set once the unsafe-root WARN has been logged in this process.
static POOL_ROOT_UNSAFE_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
fn warn_pool_root_unsafe_once() {
    if !POOL_ROOT_UNSAFE_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!(
            error_kind = "pool_root_unsafe",
            "a pre-existing pool root cannot be adopted: it must be a real \
             directory owned (byte-exactly) by the current user with no foreign \
             principal able to displace entries. Nothing was changed. \
             Remediation: move csq's base/pool aside while no csq session uses \
             the pool (or delete it), then let csq recreate it; csq never \
             repairs a root it cannot verify (logged once per process)."
        );
    }
}

/// R1 F5: v2.21.3 created `base/pool` with `create_dir_all`, so an upgraded
/// Windows user's root carries the DEFAULT DACL and the strict openers refuse
/// it forever. Adopt-and-tighten is allowed ONLY when every one of these holds:
/// the owner is byte-exactly the token user SID, the DACL is UNPROTECTED (a
/// protected leaf in the wrong shape is a real leaf, never a v2.21.3 root), and
/// every allow ACE of the root AND of every direct child names one of exactly
/// three principals, byte-exact — the current user SID, `S-1-5-18` (SYSTEM) or
/// `S-1-5-32-544` (BUILTIN\Administrators) — whatever the ACE's mask
/// ([`check_no_foreign_write_for_adoption`]); `Everyone`, `Users`,
/// `Authenticated Users`, service SIDs (`S-1-5-80-*`) and any other principal
/// are refused, and a deny ACE is harmless. It must also be a real non-reparse
/// directory, every child must be a single-link regular non-reparse file (a
/// v2.21.3 pool root is FLAT: its only direct entries are `.lock`,
/// `manifest.json`, `transaction.json` and `cleanup.json` — pool keys live in
/// the secret vault, not here), and the volume+FileId must be stable across the
/// operation.
///
/// The re-ACL is TWO-PHASE and does not propagate blind (R2 NEW-2): every child
/// is opened no-follow WITHOUT delete sharing and validated first; the root is
/// then re-ACLed through its IDENTITY-BOUND handle with
/// [`apply_inheriting_directory_nonpropagating`], which does not ask the
/// filesystem to push the inheritable ACEs down; each held child is then
/// re-ACLed explicitly to the shape a pool child must have and re-verified by
/// FileId. Anything else is refused untouched with `pool_root_unsafe`.
///
/// One residual is accepted as designed: a child CREATED between the `read_dir`
/// enumeration and the per-child re-ACL is not re-ACLed by this adoption and
/// keeps the DACL it was born with — the pre-adoption profile default, whose
/// principals this gate already limited to user/SYSTEM/Administrators. That
/// grants no foreign principal anything (a foreign ACE on the root refused the
/// adoption before this point, so only the same user can be racing), and the
/// child is judged by its own descriptor on every later open.
fn adopt_pool_root(path: &Path) -> Result<File, PrivateAclError> {
    let user = UserSid::current()?;
    let check = open_directory_check_handle(path).map_err(|_| {
        warn_pool_root_unsafe_once();
        PrivateAclError::UnsafePath
    })?;
    // F8: a PROTECTED leaf in the wrong private shape (the strict non-inheriting
    // form, one with an extra ACE, or one with no label) is not a v2.21.3 root;
    // it is refused, never adopted. Only a default-inherited root is adoptable.
    if directory_shape(&check).is_err()
        || !owner_is_user(&check, &user)?
        || dacl_is_protected(&check)?
        || check_no_foreign_write_for_adoption(&check).is_err()
    {
        warn_pool_root_unsafe_once();
        return Err(PrivateAclError::UnsafePath);
    }
    let before = node(&check).map_err(|_| PrivateAclError::UnsafePath)?;
    // (b) Validate and HOLD every child before touching the root. The handles
    // deny delete sharing, so no child can be swapped between this validation
    // and its re-ACL below.
    let mut children = Vec::new();
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => {
            warn_pool_root_unsafe_once();
            return Err(PrivateAclError::UnsafePath);
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                warn_pool_root_unsafe_once();
                return Err(PrivateAclError::UnsafePath);
            }
        };
        let child = match open_adoption_child_handle(&entry.path()) {
            Ok(child) => child,
            Err(_) => {
                warn_pool_root_unsafe_once();
                return Err(PrivateAclError::UnsafePath);
            }
        };
        let info = match basic(&child) {
            Ok(info) => info,
            Err(_) => {
                warn_pool_root_unsafe_once();
                return Err(PrivateAclError::UnsafePath);
            }
        };
        let private_shape_refused = check_adoption_child(&child).is_err();
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
            || info.nNumberOfLinks != 1
            || private_shape_refused
        {
            warn_pool_root_unsafe_once();
            return Err(PrivateAclError::UnsafePath);
        }
        let identity = match node(&child) {
            Ok(identity) => identity,
            Err(_) => {
                warn_pool_root_unsafe_once();
                return Err(PrivateAclError::UnsafePath);
            }
        };
        children.push((child, identity));
    }
    let adopt = open_directory_adopt_handle(path).map_err(|_| {
        warn_pool_root_unsafe_once();
        PrivateAclError::UnsafePath
    })?;
    let same = node(&adopt).map(|fresh| fresh == before).unwrap_or(false);
    if !same {
        warn_pool_root_unsafe_once();
        return Err(PrivateAclError::UnsafePath);
    }
    // (c) NON-PROPAGATING root re-ACL through the identity-bound handle.
    apply_inheriting_directory_nonpropagating(&adopt).map_err(|_| {
        warn_pool_root_unsafe_once();
        PrivateAclError::UnsafePath
    })?;
    // Seam for the native proof that step (c) left the children untouched; the
    // hook runs BEFORE the explicit child re-ACL below.
    #[cfg(test)]
    ADOPTION_ROOT_REACLED.with(|slot| {
        let hook = slot.borrow_mut().take();
        if let Some(hook) = hook {
            hook(path);
        }
    });
    // (d) Re-ACL each held child explicitly, then re-verify its identity.
    for (child, identity) in &children {
        if apply_adopted_child_descriptor(child).is_err()
            || node(child).map(|now| now != *identity).unwrap_or(true)
        {
            warn_pool_root_unsafe_once();
            return Err(PrivateAclError::UnsafePath);
        }
    }
    drop(children);
    drop(adopt);
    drop(check);
    // Verify through a fresh no-follow open: the shape must now be the exact
    // inheriting form and the object must not have moved.
    let file = open_private_directory_inheriting(path)?;
    if node(&file).map(|now| now == before).unwrap_or(false) {
        tracing::info!(
            event = "pool_root_adopted",
            "a pre-existing default-DACL pool root was adopted and re-ACLed to \
             the inheriting owner-only shape"
        );
        Ok(file)
    } else {
        warn_pool_root_unsafe_once();
        Err(PrivateAclError::UnsafePath)
    }
}

// Test seam after the root's non-propagating re-ACL and before any child is
// re-ACLed (R2 NEW-2's native proof).
#[cfg(all(test, windows))]
type AdoptionSeamHook = Box<dyn FnOnce(&Path)>;
#[cfg(all(test, windows))]
thread_local! {
    static ADOPTION_ROOT_REACLED: std::cell::RefCell<Option<AdoptionSeamHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(all(test, windows))]
pub(crate) fn with_adoption_root_reacled_hook<T>(
    hook: impl FnOnce(&Path) + 'static,
    op: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<AdoptionSeamHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ADOPTION_ROOT_REACLED.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore =
        Restore(ADOPTION_ROOT_REACLED.with(|slot| slot.borrow_mut().replace(Box::new(hook))));
    op()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::platform::fs_windows_acl::{
        current_user_sid_text, observed_acl_at, observed_owner, set_file_dacl, ObservedAcl,
    };
    // ROOT M3: the tightening's WRITE_OWNER handle is IDENTITY-BOUND. A handle
    // that names a different object (here a sibling file) is refused BEFORE any
    // owner write, leaving the held file's owner unchanged; the same path
    // passes the binding and the setter runs.
    #[test]
    fn the_tightening_write_handle_is_identity_bound() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let held_path = tmp.path().join("held-journal");
        let other_path = tmp.path().join("other-journal");
        drop(std::fs::File::create(&held_path).unwrap());
        drop(std::fs::File::create(&other_path).unwrap());
        let held = open_unchecked_shared_handle(&held_path, false).unwrap();
        let user = UserSid::current().unwrap();
        let before = observed_owner(&held).unwrap();
        assert_eq!(
            tighten_sidecar_owner_for_test(&other_path, &held, &user, true),
            TightenOutcome::Mismatch,
            "a write handle with a different volume+FileId must be refused"
        );
        assert_eq!(
            observed_owner(&held).unwrap(),
            before,
            "a mismatched write handle must leave the held file untouched"
        );
        // Control: the held path itself passes the identity binding.
        assert_eq!(
            tighten_sidecar_owner_for_test(&held_path, &held, &user, true),
            TightenOutcome::Tightened
        );
        assert!(owner_is_user(&held, &user).unwrap());
    }
    // R2 NEW-2: the root's re-ACL does NOT propagate into its children. The
    // seam captures every child descriptor AFTER the root's non-propagating
    // re-ACL and BEFORE the explicit per-child re-ACL; each must equal its
    // pre-adoption descriptor (only the root changed). The admission then
    // completes and every child carries the inherited shape the pool expects.
    #[test]
    fn the_adoption_root_re_acl_does_not_propagate_into_children() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("pool");
        std::fs::create_dir(&root).unwrap();
        let adopt = open_directory_adopt_handle(&root).unwrap();
        set_owner_to_current_user(&adopt).unwrap();
        drop(adopt);
        let sid = current_user_sid_text().unwrap();
        // The v2.21.3 profile-default DACL, made deterministic.
        set_file_dacl(
            &root,
            &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )
        .unwrap();
        let names = [".lock", "manifest.json", "transaction.json", "cleanup.json"];
        for name in names {
            drop(std::fs::File::create(root.join(name)).unwrap());
        }
        let before: Vec<ObservedAcl> = names
            .iter()
            .map(|name| observed_acl_at(&root.join(name)).unwrap())
            .collect();
        let captured: std::sync::Arc<std::sync::Mutex<Option<Vec<ObservedAcl>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = std::sync::Arc::clone(&captured);
        let hook_root = root.clone();
        let file = with_adoption_root_reacled_hook(
            move |_root: &Path| {
                let during: Vec<ObservedAcl> = names
                    .iter()
                    .map(|name| observed_acl_at(&hook_root.join(name)).unwrap())
                    .collect();
                *sink.lock().unwrap() = Some(during);
            },
            || adopt_pool_root(&root),
        )
        .expect("a clean v2.21.3 root is adopted");
        drop(file);
        let during = captured.lock().unwrap().take().expect("the seam ran");
        assert_eq!(
            during, before,
            "step (c) must leave every child descriptor unchanged"
        );
        for name in names {
            let after = observed_acl_at(&root.join(name)).unwrap();
            assert!(
                !after.dacl_protected(),
                "child {name} keeps an auto-inherited DACL: {after:?}"
            );
            assert_eq!(
                after.dacl.len(),
                1,
                "child {name} carries exactly the owner ACE: {after:?}"
            );
            let grant = &after.dacl[0];
            assert!(
                grant.is_access_allowed() && grant.is_file_all_access() && grant.sid == sid,
                "child {name} grants FILE_ALL_ACCESS to the user: {after:?}"
            );
            assert_eq!(
                after.label.len(),
                1,
                "child {name} carries exactly one label ACE: {after:?}"
            );
            assert!(
                after.label[0].is_label(),
                "child {name}'s label ACE is a mandatory label: {after:?}"
            );
        }
    }
}
