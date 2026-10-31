//! Secure file operations: permissions and atomic replacement.
//!
//! THRESHOLD — secure-write pattern home.
//! The canonical `unique_tmp_path → write → secure_file → atomic_replace`
//! pipeline (with §5a tmp-cleanup on every failure branch) is currently
//! documented in 4 places: `.claude/rules/security.md` §5a,
//! `.claude/skills/daemon-architecture` migration-pattern subsection,
//! `.claude/skills/provider-integration` Gemini provisioning subsection,
//! and the in-source doc-blocks at `daemon/migrate_legacy_api_key_helper.rs`
//! and `providers/gemini/provisioning.rs`. When a 5th subsystem adopts
//! the pattern (e.g. Bedrock or Vertex provisioning), move the
//! canonical doc into a doc-block on `unique_tmp_path` here per
//! an internal journal entry §FD #2 and an internal journal entry §FD #2 so there is a single
//! source of truth for the pipeline shape.

use crate::error::PlatformError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Why a directory on the path to a private store or runtime tree is not trusted, or `None`
/// when it is. A directory is trusted when it is owned by this user or root AND no one else
/// can rename entries in it: no group/other write bit, except a root-owned sticky directory
/// (`/tmp`). This is the single policy for `SecureDatabase`, the lifecycle store and the
/// gate runtime base; callers add the path to the message they raise.
#[cfg(unix)]
pub fn untrusted_directory_reason(owner: u32, mode: u32, uid: u32) -> Option<&'static str> {
    let mode = mode & 0o7777;
    if owner != uid && owner != 0 {
        return Some("owned by another user");
    }
    if mode & 0o022 != 0 && !(owner == 0 && mode & 0o1000 != 0) {
        return Some("writable by group or others and not a root-owned sticky directory");
    }
    None
}

/// macOS extended-ACL FFI (`<sys/acl.h>`); the `libc` crate does not bind it. Every
/// signature below is the SDK declaration: `acl_t`, `acl_entry_t` and `acl_permset_t` are
/// opaque pointers, `acl_type_t` is a C enum passed as `int` (the same declaration
/// `pool::env_file` uses; a differing one trips `clashing_extern_declarations`), `acl_tag_t`
/// is a C enum read through a 32-bit out value and `acl_permset_mask_t` is `uint64_t`.
#[cfg(target_os = "macos")]
mod acl_ffi {
    use std::ffi::{c_int, c_void};
    pub const ACL_TYPE_EXTENDED: c_int = 0x100;
    pub const ACL_FIRST_ENTRY: c_int = 0;
    pub const ACL_NEXT_ENTRY: c_int = -1;
    pub const ACL_EXTENDED_ALLOW: u32 = 1;
    /// `acl_flag_t` bits (`<sys/acl.h>`): the entry is inherited by new files / subdirectories.
    pub const ACL_ENTRY_FILE_INHERIT: c_int = 1 << 5;
    pub const ACL_ENTRY_DIRECTORY_INHERIT: c_int = 1 << 6;
    /// WRITE_DATA|ADD_FILE (1<<2), DELETE (1<<4), APPEND_DATA|ADD_SUBDIRECTORY (1<<5),
    /// DELETE_CHILD (1<<6): what lets a grantee add, replace or remove entries in a directory.
    /// WRITE_SECURITY (1<<12) and TAKE_OWNERSHIP (1<<13) (`sys/kauth.h`) let a grantee
    /// rewrite the ACL or take the directory over, which reaches every bit above.
    /// WRITE_ATTRIBUTES (1<<8) and WRITE_EXTATTRIBUTES (1<<10) are deliberately NOT refused.
    /// This is INFERENCE, not probed: xnu authorises adding, removing and re-owning
    /// entries through the bits above (`vnode_authorize` on the directory), while these
    /// two set times, flags and extended attributes, which change neither entries nor owner.
    /// The generic rights KAUTH_ACE_GENERIC_ALL (1<<21) and KAUTH_ACE_GENERIC_WRITE (1<<23)
    /// (`sys/kauth.h:177-180`; GENERIC_EXECUTE 1<<22 and GENERIC_READ 1<<24 only read or
    /// traverse) expand to those rights, so they are refused as well.
    pub const ENTRY_CHANGING: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 12) | (1 << 13) | (1 << 21) | (1 << 23);
    /// Every permission bit: a private file allows no ACL grant to anyone.
    pub const ANY_ALLOW: u64 = u64::MAX;
    extern "C" {
        pub fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        pub fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        pub fn acl_get_tag_type(entry: *mut c_void, tag: *mut u32) -> c_int;
        pub fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
        pub fn acl_get_flagset_np(entry: *mut c_void, flagset: *mut *mut c_void) -> c_int;
        pub fn acl_get_flag_np(flagset: *mut c_void, flag: c_int) -> c_int;
        pub fn acl_free(obj: *mut c_void) -> c_int;
    }
}

/// Why the directory held by `fd` (an ANCESTOR of a private store) carries an extended ACL
/// that lets someone other than the mode bits describe change its entries, or `None` when
/// it carries none. Any ALLOW entry granting write/add_file (`1<<2`), delete (`1<<4`),
/// add_subdirectory (`1<<5`), delete_child (`1<<6`), writesecurity (`1<<12`) or chown
/// (`1<<13`) is refused whoever it names (the owner needs no ACL for these), so a grant
/// that would let a third party plant or rename entries cannot hide behind clean mode
/// bits. DENY-only ACLs pass (they only remove access). Fail closed: an ACL that cannot be
/// read refuses, except where the filesystem has none (`ENOENT` no ACL set,
/// `ENOTSUP`/`EOPNOTSUPP` no ACL support).
/// Linux: reads the NFSv4 ACL (see `linux_nfs4`; a POSIX ACL cannot exceed its mask, which
/// the group mode bits already show). Other Unix: refuses, "unsupported ACL platform".
#[cfg(target_os = "macos")]
pub fn directory_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    acl_allow_refusal(
        fd,
        acl_ffi::ENTRY_CHANGING,
        false,
        "an ACL entry allows adding, replacing, deleting or re-owning entries",
    )
}

/// Why the LEAF private store directory held by `fd` carries an extended ACL ALLOW entry
/// for anyone, or `None`. The owner reaches a private directory through its mode bits
/// alone, so on macOS ANY ALLOW entry (read grants and inheritable entries included, which
/// would hand every new file a grant) refuses. Same fail-closed reading as
/// [`directory_acl_refusal`].
#[cfg(target_os = "macos")]
pub fn private_directory_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    acl_allow_refusal(
        fd,
        acl_ffi::ANY_ALLOW,
        true,
        "an ACL entry grants access to another principal or is inherited by new entries",
    )
}

/// Why the file held by `fd` carries an extended ACL ALLOW entry, or `None`. A private
/// file is readable by its owner through the mode bits alone, so any ALLOW entry (for
/// example a read grant inherited from the parent directory) widens access beyond what the
/// `0o600` mode shows and is refused. Same fail-closed reading as [`directory_acl_refusal`].
/// Linux: a non-owner NFSv4 ALLOW beyond the attribute/ACL-read/synchronize bits a server
/// synthesizes for a plain mode refuses. Other Unix: refuses, "unsupported ACL platform".
#[cfg(target_os = "macos")]
pub fn private_file_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    acl_allow_refusal(
        fd,
        acl_ffi::ANY_ALLOW,
        false,
        "an ACL entry grants access to another principal",
    )
}

/// Whether an ACL entry of tag `tag` is refused: an ALLOW that carries a `deny_mask` bit, or
/// (when the caller asked for inheritance to be refused) an inheritable one.
#[cfg(target_os = "macos")]
fn acl_entry_refused(tag: u32, mask: u64, deny_mask: u64, inherited: bool) -> bool {
    tag == acl_ffi::ACL_EXTENDED_ALLOW && (mask & deny_mask != 0 || inherited)
}

#[cfg(target_os = "macos")]
fn acl_allow_refusal(
    fd: std::os::fd::RawFd,
    deny_mask: u64,
    refuse_inherit: bool,
    allow_message: &str,
) -> Option<String> {
    use acl_ffi::*;
    // SAFETY: `fd` is a live descriptor owned by the caller for the whole call.
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTSUP) => None,
            _ => Some(format!("its ACL cannot be read: {error}")),
        };
    }
    let mut refusal = None;
    let mut which = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is a live ACL from `acl_get_fd_np`; `entry` is a valid out pointer.
        // Returns 0 for an entry, -1 at the end (or on error, which ends the walk).
        if unsafe { acl_get_entry(acl, which, &mut entry) } != 0 {
            let end = std::io::Error::last_os_error().raw_os_error();
            // errno is EINVAL at the end of the list; anything else is a failure to read.
            if end != Some(libc::EINVAL) {
                refusal = Some("its ACL cannot be walked".to_string());
            }
            break;
        }
        which = ACL_NEXT_ENTRY;
        let (mut tag, mut mask) = (0u32, 0u64);
        // SAFETY: `entry` came from `acl_get_entry` on the live `acl`; out pointers are valid.
        let ok = unsafe {
            acl_get_tag_type(entry, &mut tag) == 0 && acl_get_permset_mask_np(entry, &mut mask) == 0
        };
        if !ok {
            refusal = Some("an ACL entry cannot be read".to_string());
            break;
        }
        let mut inherited = false;
        if refuse_inherit {
            let mut flags = std::ptr::null_mut();
            // SAFETY: `entry` is a live entry of `acl`; `flags` is a valid out pointer and the
            // flagset it receives is owned by the entry (not freed separately).
            if unsafe { acl_get_flagset_np(entry, &mut flags) } != 0 {
                refusal = Some("an ACL entry cannot be read".to_string());
                break;
            }
            let mut unreadable = false;
            for flag in [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT] {
                // SAFETY: `flags` was just filled by `acl_get_flagset_np`.
                let set = unsafe { acl_get_flag_np(flags, flag) };
                if set < 0 {
                    unreadable = true;
                    break;
                }
                inherited |= set > 0;
            }
            if unreadable {
                refusal = Some("an ACL entry cannot be read".to_string());
                break;
            }
        }
        if acl_entry_refused(tag, mask, deny_mask, inherited) {
            refusal = Some(allow_message.to_string());
            break;
        }
    }
    // SAFETY: `acl` came from `acl_get_fd_np` and is freed exactly once.
    unsafe { acl_free(acl) };
    refusal
}

/// Non-macOS: see the macOS doc above. Linux additionally reads an NFSv4 ACL
/// (`system.nfs4_acl`), which the mode bits do not bound (a POSIX ACL cannot exceed its
/// mask, an NFSv4 ALLOW can). A Unix that is neither Linux nor macOS has no ACL reader here,
/// so it refuses rather than pass a directory it cannot inspect.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn directory_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux_nfs4::refusal(fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Some(UNSUPPORTED_ACL_PLATFORM.to_string())
    }
}

/// Leaf private store directory, non-macOS: on Linux a non-owner NFSv4 ALLOW beyond the
/// server-synthesized attribute/ACL-read/synchronize bits refuses, inheritable or not.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn private_directory_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux_nfs4::private_directory_refusal(fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Some(UNSUPPORTED_ACL_PLATFORM.to_string())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const UNSUPPORTED_ACL_PLATFORM: &str = "unsupported ACL platform";

/// Non-macOS private file: on Linux an NFSv4 ACL ALLOW beyond the synthesized bits to a
/// principal other than the owner refuses (the `0o600` mode does not bound it); other Unix:
/// refuses, "unsupported ACL platform".
#[cfg(all(unix, not(target_os = "macos")))]
pub fn private_file_acl_refusal(fd: std::os::fd::RawFd) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux_nfs4::private_file_refusal(fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Some(UNSUPPORTED_ACL_PLATFORM.to_string())
    }
}

/// Linux NFSv4 ACL (`system.nfs4_acl`, XDR: `u32 count`, then per ACE `u32 type`,
/// `u32 flag`, `u32 access_mask`, `u32 who_len`, `who` padded to 4 bytes; big endian).
#[cfg(target_os = "linux")]
mod linux_nfs4 {
    const ALLOW: u32 = 0;
    /// ACE4_IDENTIFIER_GROUP: a numeric `who` names a gid, never the owning uid.
    const IDENTIFIER_GROUP: u32 = 0x40;
    /// RFC 7530 ACE4 access mask bits that let a grantee change a directory's entries or
    /// take it over: ADD_FILE/WRITE_DATA 0x2, ADD_SUBDIRECTORY/APPEND_DATA 0x4,
    /// DELETE_CHILD 0x40, DELETE 0x1_0000, WRITE_ACL 0x4_0000, WRITE_OWNER 0x8_0000
    /// (READ_ACL is 0x2_0000 and only reads). Values per the SDK `nfsproto.h`.
    /// WRITE_ATTRIBUTES 0x100 and WRITE_NAMED_ATTRS 0x10 are deliberately NOT refused. This is
    /// INFERENCE, not probed: they set times, flags and named attributes, and xnu/knfsd
    /// authorise entry creation, removal and re-owning through the bits above, not these.
    pub const ENTRY_CHANGING: u32 = 0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000;
    /// What a private file or directory refuses for a non-owner: everything except
    /// READ_ATTRIBUTES 0x80, READ_ACL 0x2_0000 and SYNCHRONIZE 0x10_0000, which knfsd
    /// synthesizes for `GROUP@` and `EVERYONE@` on a plain 0600 mode (`A::GROUP@:tcy`).
    pub const PRIVATE: u32 = !(0x80 | 0x2_0000 | 0x10_0000);

    fn word(bytes: &[u8], at: usize) -> Option<u32> {
        let raw = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_be_bytes(raw.try_into().ok()?))
    }

    /// Why this ACL lets a principal other than the owner change entries, or `None`. An ALLOW
    /// is accepted only for `OWNER@` or the owning uid spelled numerically WITHOUT the group
    /// identifier flag; any other principal cannot be shown to be the owner, so it is
    /// refused. Malformed bytes refuse.
    #[cfg(test)]
    pub fn parse_refusal(bytes: &[u8], owner_uid: u32) -> Option<String> {
        parse_refusal_masked(bytes, owner_uid, ENTRY_CHANGING)
    }

    /// [`parse_refusal`] for an arbitrary set of refused access bits.
    pub fn parse_refusal_masked(bytes: &[u8], owner_uid: u32, refused: u32) -> Option<String> {
        parse(bytes, owner_uid, refused)
    }

    /// The leaf private directory policy: [`PRIVATE`] bits for a non-owner, inheritable or
    /// not (an inheritable entry is refused exactly when its bits would be: an inherit-only
    /// `GROUP@:tcy` is what knfsd synthesizes and carries nothing a private object refuses).
    pub fn parse_private_directory_refusal(bytes: &[u8], owner_uid: u32) -> Option<String> {
        parse(bytes, owner_uid, PRIVATE)
    }

    fn parse(bytes: &[u8], owner_uid: u32, refused: u32) -> Option<String> {
        let malformed = || Some("its NFSv4 ACL is malformed".to_string());
        let Some(count) = word(bytes, 0) else {
            return malformed();
        };
        // Every ACE is at least 16 bytes, so a larger count cannot be honest.
        if (count as usize) > bytes.len() / 16 {
            return malformed();
        }
        let owner = owner_uid.to_string();
        let mut at = 4usize;
        for _ in 0..count {
            let (Some(kind), Some(flag), Some(mask), Some(len)) = (
                word(bytes, at),
                word(bytes, at + 4),
                word(bytes, at + 8),
                word(bytes, at + 12),
            ) else {
                return malformed();
            };
            let len = len as usize;
            let Some(who) = at
                .checked_add(16)
                .and_then(|start| bytes.get(start..start.checked_add(len)?))
            else {
                return malformed();
            };
            let Some(next) = len
                .checked_add(3)
                .map(|n| n & !3)
                .and_then(|n| at.checked_add(16)?.checked_add(n))
            else {
                return malformed();
            };
            if next > bytes.len() {
                return malformed();
            }
            if kind == ALLOW && mask & refused != 0 {
                let is_owner =
                    who == b"OWNER@" || (who == owner.as_bytes() && flag & IDENTIFIER_GROUP == 0);
                if !is_owner {
                    return Some(
                        "an NFSv4 ACL entry grants a principal other than the owner access"
                            .to_string(),
                    );
                }
            }
            at = next;
        }
        if at != bytes.len() {
            return malformed();
        }
        None
    }

    /// Read `system.nfs4_acl` of the (possibly `O_PATH`) descriptor through `/proc/self/fd`,
    /// which `fgetxattr` cannot do for an `O_PATH` descriptor. `Ok(None)`: no such attribute
    /// (`ENODATA`) or no support (`ENOTSUP`), so no NFSv4 ACL.
    pub fn fetch_acl(fd: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let name = c"system.nfs4_acl";
        let mut capacity = 4096usize;
        loop {
            let mut buf = vec![0u8; capacity];
            // SAFETY: `path` and `name` are NUL-terminated; `buf` is writable for `capacity`.
            let n = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    capacity,
                )
            };
            if n >= 0 {
                buf.truncate(n as usize);
                return Ok(Some(buf));
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ENODATA | libc::ENOTSUP) => return Ok(None),
                Some(libc::ERANGE) if capacity < (1 << 20) => capacity *= 4,
                _ => return Err(error),
            }
        }
    }

    type Fetch = fn(std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>>;

    /// Ancestor directory policy ([`ENTRY_CHANGING`]).
    pub fn refusal(fd: std::os::fd::RawFd) -> Option<String> {
        read_refusal(fd, ENTRY_CHANGING, fetch_acl)
    }

    /// A private file allows no non-owner ALLOW beyond [`PRIVATE`]'s exclusions.
    pub fn private_file_refusal(fd: std::os::fd::RawFd) -> Option<String> {
        private_file_refusal_via(fd, fetch_acl)
    }

    /// [`private_file_refusal`] over an injectable ACL source (tmpfs carries no NFSv4 ACL).
    pub fn private_file_refusal_via(fd: std::os::fd::RawFd, fetch: Fetch) -> Option<String> {
        read_refusal(fd, PRIVATE, fetch)
    }

    /// The leaf private directory: [`PRIVATE`] bits for a non-owner, inheritable or not.
    pub fn private_directory_refusal(fd: std::os::fd::RawFd) -> Option<String> {
        private_directory_refusal_via(fd, fetch_acl)
    }

    /// [`private_directory_refusal`] over an injectable ACL source.
    pub fn private_directory_refusal_via(fd: std::os::fd::RawFd, fetch: Fetch) -> Option<String> {
        match fetch(fd) {
            Ok(None) => None,
            // SAFETY: geteuid takes no arguments and cannot fail.
            Ok(Some(buf)) => parse_private_directory_refusal(&buf, unsafe { libc::geteuid() }),
            Err(error) => Some(format!("its NFSv4 ACL cannot be read: {error}")),
        }
    }

    /// Every failure other than "no ACL" refuses (fail closed): `EACCES`, `EIO`, a bad fd.
    fn read_refusal(fd: std::os::fd::RawFd, refused: u32, fetch: Fetch) -> Option<String> {
        match fetch(fd) {
            Ok(None) => None,
            // SAFETY: geteuid takes no arguments and cannot fail.
            Ok(Some(buf)) => parse_refusal_masked(&buf, unsafe { libc::geteuid() }, refused),
            Err(error) => Some(format!("its NFSv4 ACL cannot be read: {error}")),
        }
    }
}

/// Walk `path` (canonicalized first) component by component, holding each directory by
/// descriptor (`O_NOFOLLOW`, search-only access so a `0o711` ancestor passes) and applying
/// [`untrusted_directory_reason`] to every one, `path` itself included. Returns the canonical
/// path on success; the error names the offending directory and the reason. Fail closed:
/// anything unreadable or not a directory refuses.
///
/// Each directory is also checked for an extended ACL with [`directory_acl_refusal`]
/// (macOS extended ACL; Linux NFSv4 ACL; other Unix refuses).
#[cfg(unix)]
pub fn check_trusted_directory_chain(path: &Path) -> Result<PathBuf, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "linux")]
    const SEARCH: i32 = libc::O_PATH;
    #[cfg(target_os = "macos")]
    const SEARCH: i32 = libc::O_SEARCH;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const SEARCH: i32 = libc::O_RDONLY;
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("directory {} cannot be resolved: {e}", path.display()))?;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let flags = SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut walked = PathBuf::from("/");
    let mut held = std::fs::OpenOptions::new();
    held.read(true);
    let mut held = {
        use std::os::unix::fs::OpenOptionsExt;
        held.custom_flags(flags)
            .open("/")
            .map_err(|e| format!("directory / cannot be opened: {e}"))?
    };
    let check = |file: &std::fs::File, at: &Path| -> Result<(), String> {
        let meta = file
            .metadata()
            .map_err(|e| format!("directory {} cannot be inspected: {e}", at.display()))?;
        if !meta.is_dir() {
            return Err(format!("{} is not a directory", at.display()));
        }
        if let Some(reason) = untrusted_directory_reason(meta.uid(), meta.mode(), uid) {
            return Err(format!(
                "directory {} refused: {reason} (owner {}, mode {:o})",
                at.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ));
        }
        match directory_acl_refusal(file.as_raw_fd()) {
            None => Ok(()),
            Some(reason) => Err(format!("directory {} refused: {reason}", at.display())),
        }
    };
    check(&held, &walked)?;
    for component in canonical.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(format!(
                "{} is not a plain absolute path",
                canonical.display()
            ));
        };
        walked.push(name);
        let c = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| format!("{} contains a NUL byte", canonical.display()))?;
        // SAFETY: `held` is a live descriptor and `c` a NUL-terminated single component.
        let fd = unsafe { libc::openat(held.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "directory {} cannot be opened: {}",
                walked.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: `openat` returned a new descriptor that nothing else owns.
        held = unsafe { std::fs::File::from_raw_fd(fd) };
        check(&held, &walked)?;
    }
    Ok(canonical)
}

/// Process-local counter to disambiguate temp file names within the same process
/// across threads. Combined with PID, this prevents the intra-process collision
/// that would occur if two threads in the same process wrote to the same path
/// simultaneously.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates a unique temporary file path next to `target`, using PID + a
/// per-process atomic counter. Returns `target.with_extension("tmp.{pid}.{counter}")`.
pub fn unique_tmp_path(target: &Path) -> PathBuf {
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    target.with_extension(format!("tmp.{}.{}", std::process::id(), counter))
}

/// Sets file permissions to owner-only read/write (0o600) on Unix.
/// No-op on Windows (ACL defaults handle this).
pub fn secure_file(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Sets file permissions to owner-only read (0o400) on Unix.
///
/// Sibling of [`secure_file`] for files that should be immutable outside of a
/// narrow refresh/write window — primarily canonical credential files
/// (`credentials/codex-<N>.json`, `credentials/<N>.json`). The refresh flow
/// acquires the per-account mutex, flips to 0o600 via [`secure_file`],
/// writes via [`atomic_replace`], then calls this helper to flip back to
/// 0o400 before releasing the mutex. Derived from spec 07 INV-P08
/// (credential mode-flip mutex coordination) + internal-design-docs
/// risk-analysis §2 R7 / ADR-C13.
///
/// No-op on Windows — ACL defaults produce read/write for the owner, and
/// Windows has no standard notion of "read-only but not readable-by-others"
/// at the POSIX mode level. The same security posture is achieved on
/// Windows via DACLs set at file-creation time in the credential writer.
pub fn secure_file_readonly(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o400);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Sets directory permissions to owner-only (0o700) on Unix.
///
/// Called after `create_dir_all` on the `identities/<UUID>/` directory to
/// prevent other users from enumerating credential filenames inside the dir
/// even though the credential files themselves are 0o600. Implements the
/// SEC-2.15 Phase 2 trust-boundary requirement.
///
/// No-op on Windows — ACL defaults produced at `create_dir_all` time restrict
/// access to the creating user; there is no equivalent `chmod` for directories.
pub fn secure_dir(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Creates `path` (including any missing parents) as an owner-only (0o700)
/// directory; a pre-existing directory is tightened by clearing its
/// group/other permission bits.
///
/// One helper for every SEC-2.15 directory creator (R1 M1): the restrictive
/// mode is applied AT CREATION — `DirBuilder::mode(0o700)` — so there is no
/// create-then-chmod window in which the directory is world-enumerable, and
/// the mode fix runs through the OPENED DIRECTORY FD (`O_DIRECTORY |
/// O_NOFOLLOW` + `fstat` + `fchmod`), so a symlink swapped in after the
/// no-follow pre-check cannot redirect it (R2 LOW 1); the owning uid is
/// verified on the same fd, and a foreign-owned directory is refused rather
/// than "secured" (R2 LOW 2). A directory that already exists at a
/// permissive mode (an older csq's umask-default 0o755) is tightened by the
/// same call — that is the upgrade path. The tighten clears ONLY the
/// group/other bits: the owner's own bits are preserved, so a deliberately
/// more restrictive pre-existing mode (e.g. a read-only 0o500 accounts
/// root) is never silently granted write access — operations into it fail
/// naturally and visibly instead of csq overriding an explicit
/// restriction.
///
/// Fail-closed: a path that exists as a symlink or as any non-directory is
/// refused BEFORE anything is created or chmod-ed, and the leaf is
/// re-verified through the fd, so a symlink planted mid-call is refused as
/// well; every create/verify/chmod failure is an error the caller
/// propagates. This is the STRICT variant for everything BELOW a root —
/// `identities/`, `identities/<UUID>/`, `credentials/` — which are csq-owned
/// and never legitimately symlinks. Operator-facing ROOTS that may
/// legitimately be symlinks (the document-supported `~/.claude/accounts` ->
/// external-drive setup, desktop `case_c_symlinked_path_canonicalizes_and_accepts`)
/// go through [`ensure_private_dir_root`] instead (R2 H1).
///
/// Scope: this governs directory MODE bits and the owning uid. It does not
/// inspect or strip macOS ACL entries (R2 LOW 3) — an extended ACL granting
/// a third party access is outside this helper's reach.
///
/// No-op on Windows beyond `create_dir_all` + the shared no-follow checks —
/// ACL defaults restrict access to the creating user (see [`secure_dir`]).
pub fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
    // No-follow pre-check (both platforms): refuse a symlink or any other
    // non-directory already occupying the path. Records whether the dir
    // pre-existed — the tighten policy below differs for the two cases.
    let pre_existing = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => true,
        Ok(_) => return Err(non_directory_refusal()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(PlatformError::Io(e)),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        // Mode at creation, for every level this call creates.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;

        secure_dir_fd(path, pre_existing)?;
    }
    #[cfg(not(unix))]
    {
        let _ = pre_existing;
        std::fs::create_dir_all(path)?;
        if !std::fs::symlink_metadata(path)?.is_dir() {
            return Err(non_directory_refusal());
        }
    }
    Ok(())
}

/// Root-variant of [`ensure_private_dir`]: the identical fail-closed
/// posture, EXCEPT that a leaf symlink is a SUPPORTED operator setup and is
/// resolved once (R2 H1) — `~/.claude/accounts` pointing at an external
/// drive, the documented `case_c_symlinked_path_canonicalizes_and_accepts`
/// contract. The resolved target must be a REAL directory owned by
/// `geteuid`; it is then secured fd-based like any other root. Everything
/// below a root keeps the strict refusal of [`ensure_private_dir`].
pub fn ensure_private_dir_root(path: &Path) -> Result<(), PlatformError> {
    let (target, pre_existing) = resolve_root_leaf(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        if !pre_existing {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&target)?;
        }
        secure_dir_fd(&target, pre_existing)?;
    }
    #[cfg(not(unix))]
    {
        let _ = pre_existing;
        std::fs::create_dir_all(&target)?;
        if !std::fs::symlink_metadata(&target)?.is_dir() {
            return Err(non_directory_refusal());
        }
    }
    Ok(())
}

/// Resolve a root path's leaf symlink ONCE (R2 H1): a symlink is resolved
/// with `canonicalize` — one call, parents included, which is exactly what
/// the supported external-drive setup needs; the resolved target must be a
/// real directory (re-verified through the fd by [`secure_dir_fd`]). A real
/// directory or a missing path is returned unchanged; anything else is
/// refused.
fn resolve_root_leaf(path: &Path) -> Result<(std::path::PathBuf, bool), PlatformError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let resolved = std::fs::canonicalize(path)?;
            match std::fs::symlink_metadata(&resolved) {
                Ok(m) if m.is_dir() => Ok((resolved, true)),
                _ => Err(non_directory_refusal()),
            }
        }
        Ok(meta) if meta.is_dir() => Ok((path.to_path_buf(), true)),
        Ok(_) => Err(non_directory_refusal()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((path.to_path_buf(), false)),
        Err(e) => Err(PlatformError::Io(e)),
    }
}

/// Tighten an EXISTING owner-only directory WITHOUT creating it (R2 M2):
/// the same fd-based no-follow tighten as [`ensure_private_dir`], but a
/// `NotFound` is an ERROR — a directory removed between a caller's
/// require-existing precheck and this call (orphan GC, logout) is never
/// resurrected, so a credential never lands in a recreated tree and a
/// logged-out identity stays logged out.
pub fn tighten_existing_private_dir(path: &Path) -> Result<(), PlatformError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            missing_dir_refusal()
        } else {
            PlatformError::Io(e)
        }
    })?;
    if !meta.is_dir() {
        return Err(non_directory_refusal());
    }
    #[cfg(unix)]
    secure_dir_fd(path, true)?;
    Ok(())
}

/// Open the directory through an fd and pin its mode: `O_DIRECTORY |
/// O_NOFOLLOW` refuses a symlink or non-directory at the leaf at open time,
/// `fstat` verifies directory-ness and the owning uid, and the mode fix is
/// an `fchmod` ON THAT FD — so nothing a racing path swap does can redirect
/// the chmod to another object (R2 LOW 1) and a foreign-owned directory is
/// refused, not "secured" (R2 LOW 2).
#[cfg(unix)]
fn secure_dir_fd(path: &Path, pre_existing: bool) -> Result<(), PlatformError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() {
        return Err(non_directory_refusal());
    }
    // SAFETY: geteuid has no memory or synchronization preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(foreign_owner_refusal());
    }
    let mode_now = meta.permissions().mode() & 0o7777;
    // Created here: `DirBuilder`'s mode is umask-masked, so this fchmod is
    // what guarantees a full 0o700. Pre-existing: TIGHTEN by clearing only
    // the group/other bits — the owner's own bits are preserved, so a
    // deliberately more restrictive mode (e.g. a read-only 0o500 root) is
    // never silently granted write access.
    let target = if pre_existing {
        mode_now & !0o077
    } else {
        0o700
    };
    if mode_now != target {
        file.set_permissions(std::fs::Permissions::from_mode(target))?;
    }
    Ok(())
}

/// Shared refusal for the secure/tighten helpers: names the cause and the
/// remedy WITHOUT the path itself. This error can surface at the desktop
/// renderer boundary, and paths are `$HOME`-rooted —
/// `desktop::commands::tests::gemini_provision_vertex_sa_error_does_not_leak_home_path`
/// (csq crate) pins the no-leak property.
fn non_directory_refusal() -> PlatformError {
    PlatformError::Io(std::io::Error::other(
        "refusing to secure a non-directory: a file or another non-directory entry occupies the path; remove it or restore the directory",
    ))
}

/// A directory owned by another user must not be treated as secure (R2 LOW
/// 2). Path-free for the same reason as [`non_directory_refusal`].
/// The foreign-owner refusal (R2 LOW 2) — unix-only: the uid check it
/// backs lives in `secure_dir_fd`, which is `#[cfg(unix)]`.
#[cfg(unix)]
fn foreign_owner_refusal() -> PlatformError {
    PlatformError::Io(std::io::Error::other(
        "refusing to secure a directory owned by another user; restore ownership to the current user or remove it",
    ))
}

/// The `NotFound` refusal for [`tighten_existing_private_dir`] (R2 M2):
/// tighten-only callers must never recreate what they were tightening.
/// Carries `ErrorKind::NotFound` (R3 LOW 6) so callers can map a
/// removed-mid-write directory to their own "identity removed" variant
/// rather than a generic corruption error — the `not_found` kind IS the
/// machine-readable part of this refusal; the message stays path-free.
fn missing_dir_refusal() -> PlatformError {
    PlatformError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "refusing to tighten a directory that no longer exists; re-create it through the normal login flow",
    ))
}

/// R3 LOW 2 FULL FIX — fd-relative REPAIR (`openat`): enumeration lists
/// NAMES via path-based `read_dir`; every repair then acts through a HELD,
/// no-follow, euid-verified directory fd. Every repair the startup pass
/// performs is opened RELATIVE to the fd held since enumeration
/// (`openat`), so no path component is re-resolved between enumerating an
/// entry and `fchmod`-ing it — a swap of ANY ancestor (the root itself
/// included) cannot redirect the open at a different object, which is the
/// residual the path-based identity-bound tighten could only narrow. The
/// `O_DIRECTORY | O_NOFOLLOW` flags refuse a symlink or non-directory at
/// the leaf at open time; `fstat` verifies directory-ness and the owning
/// uid; the optional `(dev, ino)` identity bind still refuses a LEAF
/// swapped after enumeration; and the `fchmod` is a `set_permissions` on
/// THAT fd. The tighten reports whether the mode ACTUALLY changed, so
/// repair accounting no longer re-reads a racy path either.
#[cfg(unix)]
pub struct DirFd {
    file: std::fs::File,
}

#[cfg(unix)]
impl DirFd {
    /// Open a directory as a handle: `O_DIRECTORY | O_NOFOLLOW` refuses a
    /// symlink or non-directory at the leaf, and the fd is verified to be
    /// a directory owned by `geteuid`. An operator-supported leaf symlink
    /// is resolved by the CALLER before this call (root-variant
    /// semantics); everything after is fd-relative.
    pub fn open(path: &Path) -> Result<Self, PlatformError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_dir() {
            return Err(non_directory_refusal());
        }
        // SAFETY: geteuid has no memory or synchronization preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(foreign_owner_refusal());
        }
        Ok(Self { file })
    }

    /// Tighten the directory THIS fd names — no path is resolved at all,
    /// so nothing a racing path swap does can redirect the chmod.
    pub fn tighten_self(&self, expected: Option<(u64, u64)>) -> Result<bool, PlatformError> {
        tighten_verify_fd(&self.file, expected)
    }

    /// Tighten the child currently registered under `name`, opened
    /// RELATIVE to this held fd with `openat(O_DIRECTORY | O_NOFOLLOW)`.
    /// A child swapped for a symlink fails at open (`ELOOP` → refusal);
    /// a removed child fails `ENOENT` (NotFound refusal); `expected`
    /// refuses a leaf whose inode changed since enumeration. Never
    /// creates: no `O_CREAT`.
    pub fn tighten_child(
        &self,
        name: &std::ffi::OsStr,
        expected: Option<(u64, u64)>,
    ) -> Result<bool, PlatformError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt as _;

        let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            PlatformError::Io(std::io::Error::other(
                "refusing to tighten an entry whose name is not a valid path component",
            ))
        })?;
        // SAFETY: `self.file` is a live directory fd for the duration of
        // the call; `cname` is a valid NUL-terminated C string; the
        // returned fd is owned here and wrapped immediately below.
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ENOENT) => missing_dir_refusal(),
                Some(libc::ELOOP) => non_directory_refusal(),
                _ => PlatformError::Io(e),
            });
        }
        // SAFETY: `fd` is freshly returned by openat and not owned elsewhere.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        tighten_verify_fd(&file, expected)
    }
}

/// Shared fd-side tail for [`DirFd`]: fstat checks (directory-ness, euid
/// owner), the optional identity bind, and the tighten itself — all on the
/// ONE fd the caller passes, so verify and `fchmod` share a single object
/// with no second swap window.
#[cfg(unix)]
fn tighten_verify_fd(
    file: &std::fs::File,
    expected: Option<(u64, u64)>,
) -> Result<bool, PlatformError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = file.metadata()?;
    if !meta.is_dir() {
        return Err(non_directory_refusal());
    }
    // SAFETY: geteuid has no memory or synchronization preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(foreign_owner_refusal());
    }
    if let Some(expected) = expected {
        if (meta.dev(), meta.ino()) != expected {
            return Err(PlatformError::Io(std::io::Error::other(
                "refusing to tighten an entry that changed identity since enumeration; re-run the repair pass",
            )));
        }
    }
    let mode_now = meta.permissions().mode() & 0o7777;
    let target = mode_now & !0o077;
    if mode_now != target {
        file.set_permissions(std::fs::Permissions::from_mode(target))?;
        return Ok(true);
    }
    Ok(false)
}

/// Non-unix: the POSIX mode-bit model does not apply; the handle REFUSES
/// missing or non-directory targets rather than creating them
/// (R3-fix-check LOW 3 — the repair pass never resurrects directories on
/// any platform, matching the unix tighten-only contract). No fd-relative
/// guarantee is claimed off unix.
#[cfg(not(unix))]
pub struct DirFd {
    path: PathBuf,
}

#[cfg(not(unix))]
impl DirFd {
    /// Open a directory handle: the leaf must be a real directory
    /// (symlinks refuse via the no-follow stat).
    pub fn open(path: &Path) -> Result<Self, PlatformError> {
        if !std::fs::symlink_metadata(path)?.is_dir() {
            return Err(non_directory_refusal());
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Tighten the held path — REFUSES a missing or non-directory entry
    /// instead of creating it (R3-fix-check LOW 3). There is no POSIX
    /// mode model off unix, so a verified directory is already as tight as
    /// this pass can make it.
    pub fn tighten_self(&self, _expected: Option<(u64, u64)>) -> Result<bool, PlatformError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.is_dir() => Ok(false),
            Ok(_) => Err(non_directory_refusal()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing_dir_refusal()),
            Err(e) => Err(PlatformError::Io(e)),
        }
    }

    /// Tighten the named child under the held path — same refusing shape
    /// as [`DirFd::tighten_self`] (R3-fix-check LOW 3).
    pub fn tighten_child(
        &self,
        name: &std::ffi::OsStr,
        _expected: Option<(u64, u64)>,
    ) -> Result<bool, PlatformError> {
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) if meta.is_dir() => Ok(false),
            Ok(_) => Err(non_directory_refusal()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing_dir_refusal()),
            Err(e) => Err(PlatformError::Io(e)),
        }
    }
}

/// Creates `path` and writes `bytes` to it, refusing if `path` already
/// exists — as a regular file OR as a symlink — and setting mode 0o600 AT
/// CREATION on Unix, ahead of the first byte.
///
/// This closes the window `unique_tmp_path → std::fs::write → secure_file`
/// leaves open: `std::fs::write` creates its target at the process's
/// umask-default mode (typically 0o644) and only the subsequent
/// `secure_file` call narrows it, so a secret-bearing tmp file is briefly
/// world-readable and — because `write` follows an existing path, including
/// a symlink — a pre-planted symlink at `path` would have its target
/// overwritten. `create_new(true)` refuses both: an existing regular file
/// and an existing symlink both make the `open` call fail with
/// `AlreadyExists`, before any byte is written.
///
/// On any error writing the bytes, the file this call created is removed
/// before the error is returned (`security.md` §5a) — this function never
/// leaves a partially-written file behind. It does not create parent
/// directories; the caller is expected to have done so already (matching
/// every existing `unique_tmp_path` callsite, which calls
/// `create_dir_all` on the parent before computing `tmp`).
///
/// Windows: the file is created with `CREATE_NEW` (same exclusivity: an
/// existing file or reparse point is refused with `AlreadyExists`) through
/// `platform::fs_windows_acl::create_new_private_file`, which applies the
/// protected owner-only DACL `O:<user-sid>D:P(A;;FA;;;<user-sid>)` plus a
/// protected Medium no-write-up/no-read-up integrity label AT creation and
/// re-checks both on the handle before any byte is written; a handle that fails
/// that check is deleted through the handle and the call returns `Err`. The
/// label is meant to keep a Low-integrity process of the same user from reading
/// the file; that holds only for files written by this version or later (a file
/// from an older csq has no label until csq next writes or opens it), and the
/// owner/DACL conditions still apply. The
/// DACL travels with the file through `atomic_replace` (handle-based rename keeps
/// the source's security descriptor), so the published target is
/// owner-only too. Readers must therefore run as the same user, which csq's
/// daemon and every spawned CLI do (the Windows secret backend refuses to
/// operate as `LocalSystem`).
///
/// Other non-unix targets: only the `create_new` exclusivity guarantee holds.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    write_new_private_impl(path, bytes, false).map(|_| ())
}

/// Like [`write_new_private`], but additionally `fsync`s the file before
/// returning success.
///
/// For callers where the write must be durable before the NEXT step reads
/// or acts on it (e.g. a config file a caller immediately hands to a
/// subprocess, or that a concurrent process may `rename`/swap onto) —
/// matching the fsync-before-rename discipline `copy_into_staging` already
/// applies to the `atomic_replace` `EXDEV` fallback. Plain
/// [`write_new_private`] does not fsync, matching the pre-existing
/// `std::fs::write`-based pipeline's behaviour at every site it replaced.
pub fn write_new_private_synced(path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    write_new_private_impl(path, bytes, true).map(|_| ())
}

/// Identity sampled from an open writer, not from a subsequent path lookup.
/// Windows records the queried file ID, its volume ID and its identity source.
/// Filesystems may reuse IDs after deletion. This comparison is not a content hash or a
/// perpetual identity proof.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenFileIdentity {
    #[cfg(windows)]
    windows: WindowsFileIdentity,
    _sealed: (),
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsFileId {
    Modern128([u8; 16]),
    Legacy64(u64),
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsFileIdentity {
    volume_serial: u64,
    file_id: WindowsFileId,
}

#[cfg(any(windows, test))]
impl WindowsFileIdentity {
    fn modern(volume_serial: u64, file_id: [u8; 16]) -> Self {
        Self {
            volume_serial,
            file_id: WindowsFileId::Modern128(file_id),
        }
    }

    fn legacy(volume_serial: u32, index_high: u32, index_low: u32) -> Self {
        Self {
            volume_serial: u64::from(volume_serial),
            file_id: WindowsFileId::Legacy64((u64::from(index_high) << 32) | u64::from(index_low)),
        }
    }
}

#[cfg(any(windows, test))]
fn query_windows_file_identity(
    modern: impl FnOnce() -> std::io::Result<WindowsFileIdentity>,
    legacy: impl FnOnce() -> std::io::Result<WindowsFileIdentity>,
) -> std::io::Result<WindowsFileIdentity> {
    match modern() {
        Err(error) if matches!(error.raw_os_error(), Some(1 | 50 | 87)) => legacy(),
        result => result,
    }
}

#[doc(hidden)]
pub fn written_file_identity(file: &std::fs::File) -> Result<WrittenFileIdentity, PlatformError> {
    #[cfg(windows)]
    {
        let identity =
            windows_written_file_identity(file).map_err(|error| PlatformError::Win32 {
                code: error.raw_os_error().unwrap_or(1) as u32,
                message: "Windows file identity query failed".to_owned(),
            })?;
        Ok(identity)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(WrittenFileIdentity { _sealed: () })
    }
}

#[cfg(windows)]
impl WrittenFileIdentity {
    fn from_information(info: &windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO) -> Self {
        Self {
            windows: WindowsFileIdentity::modern(info.VolumeSerialNumber, info.FileId.Identifier),
            _sealed: (),
        }
    }
}

#[doc(hidden)]
pub fn write_new_private_with_identity(
    path: &Path,
    bytes: &[u8],
) -> Result<WrittenFileIdentity, PlatformError> {
    write_new_private_impl(path, bytes, false)
}

#[doc(hidden)]
pub fn write_new_private_synced_with_identity(
    path: &Path,
    bytes: &[u8],
) -> Result<WrittenFileIdentity, PlatformError> {
    write_new_private_impl(path, bytes, true)
}

/// A private temporary file whose creator retains cleanup ownership. On Windows
/// the DELETE-capable writer denies other write/delete opens until publication.
/// Dropping an unpublished writer deletes through its handle on Windows. Unix
/// cleanup checks the original path's device/inode before a best-effort unlink;
/// publication there retains the existing path-based filesystem semantics.
#[derive(Debug)]
pub struct WrittenPrivateFile {
    file: Option<std::fs::File>,
    path: PathBuf,
}

/// Result of publishing a temporary file without replacing an existing target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Published,
    AlreadyExists,
}

impl WrittenPrivateFile {
    /// The actual temporary path owned by this writer, including collision retries.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the original writer without exposing a replaceable owned-handle slot.
    #[cfg(feature = "enterprise")]
    pub(crate) fn file_mut(&self) -> Result<&std::fs::File, PlatformError> {
        self.file
            .as_ref()
            .ok_or_else(|| PlatformError::Io(std::io::Error::other("private writer is closed")))
    }

    /// Atomically replace the target, retaining the writer through Windows rename.
    pub fn replace(mut self, target: &Path) -> Result<(), PlatformError> {
        #[cfg(windows)]
        windows_publish(&self.path, target, None, self.file.as_ref(), false)?;
        #[cfg(not(windows))]
        atomic_replace(&self.path, target)?;
        drop(self.file.take());
        Ok(())
    }

    /// Publish the complete file only when the target is absent. A collision is
    /// a typed outcome; it neither truncates nor replaces the existing entry.
    pub fn publish_noreplace(mut self, target: &Path) -> Result<PublishOutcome, PlatformError> {
        #[cfg(windows)]
        let outcome = windows_publish(&self.path, target, None, self.file.as_ref(), true)?;
        #[cfg(not(windows))]
        let outcome = match std::fs::hard_link(&self.path, target) {
            Ok(()) => PublishOutcome::Published,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                PublishOutcome::AlreadyExists
            }
            Err(error) => return Err(error.into()),
        };
        #[cfg(windows)]
        if outcome == PublishOutcome::Published {
            drop(self.file.take());
        }
        #[cfg(not(windows))]
        let _ = &mut self;
        Ok(outcome)
    }

    /// Explicitly discard this writer's temporary file (also done on Drop).
    pub fn discard(self) {}

    /// Leave the original temporary entry in place for caller-owned recovery.
    /// Closes the writer without unlinking it; does not relocate the file.
    pub fn keep(mut self) {
        drop(self.file.take());
    }
}

impl Drop for WrittenPrivateFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            discard_created(file, &self.path);
        }
    }
}

/// Create and write a private temporary file with automatic owned cleanup.
pub fn write_new_private_retained(
    path: &Path,
    bytes: &[u8],
) -> Result<WrittenPrivateFile, PlatformError> {
    write_new_private_retained_impl(path, bytes, false, true)
}

/// Like [`write_new_private_retained`], syncing the completed file before return.
pub fn write_new_private_synced_retained(
    path: &Path,
    bytes: &[u8],
) -> Result<WrittenPrivateFile, PlatformError> {
    write_new_private_retained_impl(path, bytes, true, true)
}

/// Create a private temporary beside `target`, retrying at most eight CREATE collisions.
/// Permission checks and diagnostics must use the returned writer's actual [`WrittenPrivateFile::path`].
pub fn write_private_tmp_retained(
    target: &Path,
    bytes: &[u8],
) -> Result<WrittenPrivateFile, PlatformError> {
    write_private_tmp_retained_impl(target, bytes, false)
}

/// Like [`write_private_tmp_retained`], syncing the completed file before return.
pub fn write_private_tmp_synced_retained(
    target: &Path,
    bytes: &[u8],
) -> Result<WrittenPrivateFile, PlatformError> {
    write_private_tmp_retained_impl(target, bytes, true)
}

#[cfg(any(test, feature = "test-utils"))]
type PrivateTmpCandidates = std::rc::Rc<dyn Fn(&Path, usize) -> PathBuf>;

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PRIVATE_TMP_CANDIDATES: std::cell::RefCell<Option<PrivateTmpCandidates>> =
        const { std::cell::RefCell::new(None) };
}

/// Scope deterministic temporary candidates to this thread and operation.
/// The callback receives the final target and zero-based CREATE attempt (0..8).
#[cfg(any(test, feature = "test-utils"))]
pub fn with_private_tmp_candidates_for_test<T>(
    candidate: impl Fn(&Path, usize) -> PathBuf + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct RestoreCandidates(Option<PrivateTmpCandidates>);
    impl Drop for RestoreCandidates {
        fn drop(&mut self) {
            PRIVATE_TMP_CANDIDATES.with(|slot| {
                *slot.borrow_mut() = self.0.take();
            });
        }
    }
    let previous =
        PRIVATE_TMP_CANDIDATES.with(|slot| slot.replace(Some(std::rc::Rc::new(candidate))));
    let _restore = RestoreCandidates(previous);
    operation()
}

fn private_tmp_candidate(target: &Path, attempt: usize) -> PathBuf {
    #[cfg(any(test, feature = "test-utils"))]
    {
        let candidate = PRIVATE_TMP_CANDIDATES.with(|slot| slot.borrow().clone());
        if let Some(candidate) = candidate {
            return candidate(target, attempt);
        }
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    let _ = attempt;
    unique_tmp_path(target)
}

#[cfg(any(test, feature = "test-utils"))]
type PrivateCreateObserver = std::rc::Rc<dyn Fn(&Path)>;

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PRIVATE_CREATE_OBSERVER: std::cell::RefCell<Option<PrivateCreateObserver>> =
        const { std::cell::RefCell::new(None) };
}

/// Observe the actual path immediately before an exclusive private-file create.
/// Shared by explicit-path and retrying constructors; this hook performs no cleanup.
#[cfg(any(test, feature = "test-utils"))]
pub fn with_private_create_observer_for_test<T>(
    observer: impl Fn(&Path) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct RestoreObserver(Option<PrivateCreateObserver>);
    impl Drop for RestoreObserver {
        fn drop(&mut self) {
            PRIVATE_CREATE_OBSERVER.with(|slot| {
                *slot.borrow_mut() = self.0.take();
            });
        }
    }
    let previous =
        PRIVATE_CREATE_OBSERVER.with(|slot| slot.replace(Some(std::rc::Rc::new(observer))));
    let _restore = RestoreObserver(previous);
    operation()
}

fn write_private_tmp_retained_impl(
    target: &Path,
    bytes: &[u8],
    sync: bool,
) -> Result<WrittenPrivateFile, PlatformError> {
    const CREATE_ATTEMPTS: usize = 8;
    let mut attempt = 0;
    loop {
        let path = private_tmp_candidate(target, attempt);
        match create_new_private_writer(&path, true) {
            Ok(file) => return finish_private_write(file, &path, bytes, sync),
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    && attempt + 1 < CREATE_ATTEMPTS =>
            {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
type PrivateSyncObserver = std::rc::Rc<dyn Fn(&Path)>;

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PRIVATE_SYNC_OBSERVER: std::cell::RefCell<Option<PrivateSyncObserver>> =
        const { std::cell::RefCell::new(None) };
}

/// Observe successful private-file syncs within this thread and operation only.
/// The prior observer is restored on return or unwind, including nested scopes.
#[cfg(any(test, feature = "test-utils"))]
pub fn with_private_sync_observer_for_test<T>(
    observer: impl Fn(&Path) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct RestoreObserver(Option<PrivateSyncObserver>);
    impl Drop for RestoreObserver {
        fn drop(&mut self) {
            PRIVATE_SYNC_OBSERVER.with(|slot| {
                *slot.borrow_mut() = self.0.take();
            });
        }
    }
    let previous =
        PRIVATE_SYNC_OBSERVER.with(|slot| slot.replace(Some(std::rc::Rc::new(observer))));
    let _restore = RestoreObserver(previous);
    operation()
}

fn write_new_private_impl(
    path: &Path,
    bytes: &[u8],
    sync: bool,
) -> Result<WrittenFileIdentity, PlatformError> {
    let mut writer = write_new_private_retained_impl(path, bytes, sync, false)?;
    let file = writer
        .file
        .as_ref()
        .ok_or_else(|| PlatformError::Io(std::io::Error::other("private writer is closed")))?;
    let identity = written_file_identity(file)?;
    drop(writer.file.take());
    Ok(identity)
}

fn write_new_private_retained_impl(
    path: &Path,
    bytes: &[u8],
    sync: bool,
    retained: bool,
) -> Result<WrittenPrivateFile, PlatformError> {
    let file = create_new_private_writer(path, retained)?;
    finish_private_write(file, path, bytes, sync)
}

fn create_new_private_writer(path: &Path, retained: bool) -> Result<std::fs::File, PlatformError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        let observer = PRIVATE_CREATE_OBSERVER.with(|slot| slot.borrow().clone());
        if let Some(observer) = observer {
            observer(path);
        }
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    // Windows: create through the owner-only DACL primitive, so the file
    // is born with a protected `D:P(A;;FA;;;<user-sid>)` DACL — no
    // inherited ACE from the parent ever applies — plus a protected
    // Medium no-read-up/no-write-up label (for files written since the label
    // was introduced; older files get it when csq next writes or opens them),
    // and the handle is re-checked before the first byte. `CREATE_NEW` refuses
    // an existing file/reparse point exactly as `create_new(true)` does on unix;
    // a failed post-create check deletes the file through the handle.
    #[cfg(windows)]
    let file = if retained {
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::FILE_SHARE_READ,
        };
        super::fs_windows_acl::create_new_private_file_with(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
        )
    } else {
        super::fs_windows_acl::create_new_private_file(path)
    }
    .map_err(|e| PlatformError::Io(e.into()))?;
    #[cfg(not(windows))]
    let _ = retained;
    #[cfg(not(any(unix, windows)))]
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    Ok(file)
}

fn finish_private_write(
    mut file: std::fs::File,
    path: &Path,
    bytes: &[u8],
    sync: bool,
) -> Result<WrittenPrivateFile, PlatformError> {
    use std::io::Write as _;

    // From here `path` exists and is ours: any failure removes it before
    // propagating, so the caller never has to distinguish "never created"
    // from "created but incomplete" — both look like `Err` with nothing on
    // disk (security.md §5a).
    if let Err(e) = file.write_all(bytes) {
        discard_created(file, path);
        return Err(e.into());
    }
    if sync {
        if let Err(e) = file.sync_all() {
            discard_created(file, path);
            return Err(e.into());
        }
    }
    let writer = WrittenPrivateFile {
        file: Some(file),
        path: path.to_path_buf(),
    };
    #[cfg(any(test, feature = "test-utils"))]
    if sync {
        let observer = PRIVATE_SYNC_OBSERVER.with(|slot| slot.borrow().clone());
        if let Some(observer) = observer {
            observer(path);
        }
    }
    Ok(writer)
}

/// Removes the file `write_new_private_impl` just created after a failed write.
/// Windows: through the handle held (it was created with `DELETE`), never by path.
fn discard_created(file: std::fs::File, path: &Path) {
    #[cfg(windows)]
    {
        let _ = path;
        super::fs_windows_delete::delete_created(&file);
        drop(file);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owns_path = file
            .metadata()
            .ok()
            .zip(std::fs::symlink_metadata(path).ok())
            .map(|(held, current)| (held.dev(), held.ino()) == (current.dev(), current.ino()))
            .unwrap_or(false);
        drop(file);
        if owns_path {
            let _ = std::fs::remove_file(path);
        } else {
            tracing::warn!(
                error_kind = "private_tmp_cleanup_ownership_unconfirmed",
                "private temporary file cleanup skipped"
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        drop(file);
    }
}

/// Atomically replaces `target` with `tmp_path`.
///
/// On Unix this is a single `rename(2)` call (atomic on the same filesystem),
/// with an explicit `EXDEV` fallback for the case where `tmp_path` and
/// `target` sit on different filesystems — see `atomic_replace_unix` for the
/// fallback contract and what it does and does not guarantee.
/// On Windows, source and target must have the same parent path; a different
/// parent returns `PlatformError::AtomicReplaceParentMismatch` before opening
/// either entry. The parent is pinned once and junctions in its path are followed.
/// POSIX-semantics rename replaces a file even with a reader holding
/// it open with delete sharing. An unsupported POSIX rename class tries the plain rename
/// class through the same validated source handle. Sharing, lock, or selected
/// access-denied failures are retried up to 5 times with 100ms delay; access-denied
/// on a directory target, and any other error, is returned on the first attempt. Other
/// permanent access-denied causes (read-only file, denying DACL) are retried
/// and then returned (see `is_transient_move_error`).
pub fn atomic_replace(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        atomic_replace_unix(tmp_path, target, |from, to| std::fs::rename(from, to))?;
    }
    #[cfg(windows)]
    {
        atomic_replace_windows(tmp_path, target, None)?;
    }
    Ok(())
}

/// Publish a private file only if the reopened Windows source matches the
/// identity captured from its writer. The writer must be closed before calling.
/// Windows requires the same parent path, as for [`atomic_replace`].
/// On other platforms this retains `atomic_replace` semantics, including EXDEV.
/// Failure leaves cleanup with the caller; removal of the tmp path is best effort
/// and cannot prove deletion of an original file relocated before this call.
#[doc(hidden)]
pub fn atomic_replace_written(
    tmp_path: &Path,
    target: &Path,
    expected: WrittenFileIdentity,
) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        atomic_replace_windows(tmp_path, target, Some(expected))
    }
    #[cfg(not(windows))]
    {
        let _ = expected;
        atomic_replace(tmp_path, target)
    }
}

/// `true` only for the kernel's cross-filesystem rename refusal.
///
/// Mechanism, so the claim is checkable rather than asserted: `rename(2)` is
/// specified to fail with `EXDEV` when `oldpath` and `newpath` are on
/// different mounted filesystems, and `io::Error` derived from that errno
/// reports `ErrorKind::CrossesDevices`. Both forms are accepted because an
/// error that never passed through errno (a test seam, or a std path that
/// synthesises the kind) carries only the kind, while one built from
/// `from_raw_os_error` carries both.
#[cfg(unix)]
fn is_cross_device(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EXDEV) || err.kind() == std::io::ErrorKind::CrossesDevices
}

/// Copies `tmp_path`'s bytes into an already-created staging file, then fsyncs.
///
/// Split out of [`atomic_replace_unix`] so the single caller has one failure
/// branch to clean up rather than three.
#[cfg(unix)]
fn copy_into_staging(tmp_path: &Path, dst: &mut std::fs::File) -> std::io::Result<()> {
    let mut src = std::fs::File::open(tmp_path)?;
    std::io::copy(&mut src, dst)?;
    // fsync before the rename: the rename is only atomic with respect to
    // WHICH inode `target` names, not to whether that inode's data reached
    // the disk. Without this, a crash between rename and writeback can leave
    // `target` pointing at a zero-length credential file.
    dst.sync_all()?;
    Ok(())
}

/// Unix `atomic_replace` with the rename step injected.
///
/// `rename` is `std::fs::rename` in production; tests substitute a closure to
/// drive the `EXDEV` branch, which is otherwise unreachable without mounting a
/// second filesystem. Only the FIRST rename goes through the seam — the
/// fallback's own rename is always the real one, because that step's whole
/// purpose is that it happens within the target directory.
///
/// # Fallback contract (`EXDEV` only)
///
/// Every other error propagates unchanged and unretried. On `EXDEV`:
///
/// 1. Stage a sibling of `target` (via [`unique_tmp_path`]), so the final step
///    is a same-directory rename and therefore still atomic AT THE TARGET: no
///    reader ever observes `target` absent or partially written.
/// 2. Create that staging file at 0o600 BEFORE the first byte is written, so a
///    secret never exists at umask-default mode (`security.md` MUST-5).
/// 3. Copy, `fsync`, then restore `tmp_path`'s own mode onto the staging file
///    — the same-filesystem `rename(2)` path carries the source's mode across,
///    so the fallback must too.
/// 4. Rename staging onto `target`, then remove `tmp_path`, because `rename(2)`
///    would have consumed it and callers rely on that.
///
/// # What is NOT preserved
///
/// The copy is not atomic with respect to `tmp_path`: a crash mid-fallback can
/// leave both `tmp_path` and a staging sibling on disk. Both are 0o600 and the
/// staging file is removed on every failure branch this function can observe
/// (`security.md` §5a); `tmp_path` is left for the caller to remove, exactly as
/// the same-filesystem path leaves it after a failed rename.
#[cfg(unix)]
fn atomic_replace_unix<R>(tmp_path: &Path, target: &Path, rename: R) -> Result<(), PlatformError>
where
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    match rename(tmp_path, target) {
        Ok(()) => Ok(()),
        Err(e) if is_cross_device(&e) => atomic_replace_cross_device(tmp_path, target),
        Err(e) => Err(e.into()),
    }
}

/// The `EXDEV` fallback body. See [`atomic_replace_unix`] for the contract.
#[cfg(unix)]
fn atomic_replace_cross_device(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let src_mode = std::fs::metadata(tmp_path)?.permissions().mode() & 0o7777;
    let staging = unique_tmp_path(target);

    // `create_new` so a pre-existing file at this path is never adopted — and
    // therefore never deleted by the cleanup branches below, which would
    // destroy a file this call did not create. `mode(0o600)` applies at
    // creation, ahead of the first byte.
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)?;

    // From here down `staging` exists and is ours: every failure branch
    // removes it before propagating (`security.md` §5a).
    if let Err(e) = copy_into_staging(tmp_path, &mut dst) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }
    drop(dst);

    if let Err(e) = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(src_mode)) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }

    if let Err(e) = std::fs::rename(&staging, target) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }

    // `rename(2)` consumes the source; the fallback must too, or the caller is
    // left holding a secret-bearing tmp file it believes was moved away.
    let _ = std::fs::remove_file(tmp_path);
    Ok(())
}

/// `true` for the rename failures that another process holding the
/// target can cause and that can clear on their own, so the retry loop in
/// [`atomic_replace_windows`] exists for them ("file may be locked"):
/// `ERROR_SHARING_VIOLATION` (32), `ERROR_LOCK_VIOLATION` (33), and
/// `ERROR_ACCESS_DENIED` (5).
///
/// A plain replacing rename returns 5 when the target is
/// briefly held open without `FILE_SHARE_DELETE` (antivirus, the indexer,
/// csq's own readers) or is delete-pending — a refreshed OAuth token must
/// not be lost to that on the first attempt. 5 is also returned for
/// PERMANENT refusals. A directory target (`target_is_dir`) is the one
/// permanent access-denied case this detects, so it fails fast and emits no
/// retry WARN rows. Other permanent forms — a read-only target file, a DACL
/// denying this user delete/write — are NOT distinguished from a held-open
/// target: they take the bounded retry (5 attempts, 100ms apart, a WARN row
/// per retry) and then fail with the last error, never a silent success.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_transient_move_error(code: u32, target_is_dir: bool) -> bool {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_SHARING_VIOLATION: u32 = 32;
    const ERROR_LOCK_VIOLATION: u32 = 33;
    match code {
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => true,
        ERROR_ACCESS_DENIED => !target_is_dir,
        _ => false,
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsReplaceStage {
    Open,
    Validate,
    Rename,
}

#[cfg(any(windows, test))]
fn windows_replace_retry(
    stage: WindowsReplaceStage,
    code: u32,
    target_is_dir: bool,
    attempt: u32,
) -> bool {
    attempt < 4
        && match stage {
            WindowsReplaceStage::Open => matches!(code, 32 | 33),
            WindowsReplaceStage::Validate => false,
            WindowsReplaceStage::Rename => is_transient_move_error(code, target_is_dir),
        }
}

#[cfg(any(windows, test))]
fn windows_replace_source_safe(attributes: u32, links: u32) -> bool {
    attributes & (0x400 | 0x10) == 0 && links == 1
}

#[cfg(any(windows, test))]
fn windows_rename_failed(status: i32) -> bool {
    status < 0
}

/// Whether Windows rejected the rename information class or its supported
/// flags, permitting a plain FileRenameInformation retry on the same handle.
pub fn windows_rename_class_unsupported(status: i32) -> bool {
    matches!(
        status as u32,
        0xC000_0003 | 0xC000_000D | 0xC000_0010 | 0xC000_00BB
    )
}

#[cfg(any(windows, test))]
fn windows_replace_leaf_safe(name: &[u16]) -> bool {
    !name.is_empty()
        && name.len() <= u16::MAX as usize / 2
        && !matches!(name.last().copied(), Some(0x20 | 0x2e))
        && !name.iter().any(|c| matches!(*c, 0 | 0x2f | 0x5c | 0x3a))
}

/// This is the production dispatcher; portable tests exercise these exact calls.
#[cfg(any(windows, test))]
fn dispatch_windows_rename<H>(
    source: &H,
    parent: &H,
    mut rename: impl FnMut(&H, &H, i32) -> i32,
) -> Result<(), (i32, Option<i32>)> {
    let posix = rename(source, parent, 65);
    if !windows_rename_failed(posix) {
        return Ok(());
    }
    if !windows_rename_class_unsupported(posix) {
        return Err((posix, None));
    }
    let plain = rename(source, parent, 10);
    if windows_rename_failed(plain) {
        Err((posix, Some(plain)))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn windows_file_information(
    file: &std::fs::File,
) -> std::io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: live borrowed handle, valid synchronous output buffer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

#[cfg(windows)]
fn windows_file_id(
    file: &std::fs::File,
) -> std::io::Result<windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };
    // SAFETY: live borrowed handle and a correctly sized/aligned output buffer.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as isize,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

#[cfg(windows)]
fn windows_written_file_identity(file: &std::fs::File) -> std::io::Result<WrittenFileIdentity> {
    query_windows_file_identity(
        || windows_file_id(file).map(|info| WrittenFileIdentity::from_information(&info).windows),
        || {
            windows_file_information(file).map(|info| {
                WindowsFileIdentity::legacy(
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                )
            })
        },
    )
    .map(|windows| WrittenFileIdentity {
        windows,
        _sealed: (),
    })
}

#[cfg(windows)]
struct WindowsReplaceFailure {
    stage: WindowsReplaceStage,
    code: u32,
    api: &'static str,
    nt: Option<(i32, Option<i32>)>,
}

#[cfg(windows)]
impl WindowsReplaceFailure {
    fn retry_code(&self) -> u32 {
        use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
        // SAFETY: pure status translation. The attempted fallback governs retry;
        // the original POSIX refusal remains the final reported primary code.
        self.nt
            .and_then(|(_, plain)| plain)
            .map(|status| unsafe { RtlNtStatusToDosError(status) })
            .unwrap_or(self.code)
    }
    fn io(stage: WindowsReplaceStage, api: &'static str, error: std::io::Error) -> Self {
        Self {
            stage,
            code: error.raw_os_error().unwrap_or(1) as u32,
            api,
            nt: None,
        }
    }
    fn invalid(api: &'static str) -> Self {
        Self {
            stage: WindowsReplaceStage::Validate,
            code: 87,
            api,
            nt: None,
        }
    }
    fn into_platform(self, source: &Path, target: &Path, attempt: u32) -> PlatformError {
        use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
        let statuses = self
            .nt
            .map(|(posix, plain)| {
                // SAFETY: pure status translation; GetLastError is unrelated.
                let posix_code = unsafe { RtlNtStatusToDosError(posix) };
                let plain = plain
                    .map(|plain| {
                        // SAFETY: pure NTSTATUS translation.
                        let code = unsafe { RtlNtStatusToDosError(plain) };
                        format!(" plain_nt_status={:#010x} plain_code={code}", plain as u32)
                    })
                    .unwrap_or_default();
                format!(
                    "; posix_nt_status={:#010x} posix_code={posix_code}{plain}",
                    posix as u32
                )
            })
            .unwrap_or_default();
        let exhausted = if attempt == 4 {
            " after 5 attempts"
        } else {
            ""
        };
        PlatformError::Win32 {
            code: self.code,
            message: format!(
                "atomic_replace: {} failed{exhausted}{statuses}: {} -> {}",
                self.api,
                source.file_name().unwrap_or_default().to_string_lossy(),
                target.file_name().unwrap_or_default().to_string_lossy()
            ),
        }
    }
}

#[cfg(windows)]
fn windows_replace_path(path: &Path) -> Result<(&Path, Vec<u16>), WindowsReplaceFailure> {
    use std::os::windows::ffi::OsStrExt;
    // Inspect the raw suffix: Path::file_name normalizes away a trailing dot
    // component or separator, which must not disguise the requested leaf.
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let leaf = wide
        .rsplit(|c| matches!(*c, 0x2f | 0x5c))
        .next()
        .unwrap_or(&[]);
    if !windows_replace_leaf_safe(leaf) {
        return Err(WindowsReplaceFailure::invalid("Windows leaf validation"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent, leaf.to_vec()))
}

#[cfg(windows)]
fn windows_open_parent(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_TRAVERSE,
    };
    // Follow parent junctions, matching the legacy traversal policy. Once opened
    // this object, rather than its potentially redirected pathname, is retained.
    std::fs::OpenOptions::new()
        .access_mode(FILE_ADD_FILE | FILE_TRAVERSE)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
fn windows_open_relative(
    parent: &std::fs::File,
    name: &[u16],
    access: u32,
    share: u32,
) -> Result<std::fs::File, i32> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_ptr() as *mut u16,
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as isize,
        ObjectName: &name,
        Attributes: 0x40,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = 0;
    // SAFETY: checked leaf length, live name and parent, initialized output
    // storage, and synchronous IO with SYNCHRONIZE; the API retains no pointers.
    let status = unsafe {
        let mut block: IO_STATUS_BLOCK = std::mem::zeroed();
        NtCreateFile(
            &mut handle,
            access | 0x0010_0000,
            &attributes,
            &mut block,
            std::ptr::null(),
            0,
            share,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        Err(status)
    } else {
        // SAFETY: successful NtCreateFile transfers this one owned handle.
        Ok(unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void) })
    }
}

#[cfg(all(windows, test))]
type BeforeRenameHook = Box<dyn FnMut(bool)>;
#[cfg(all(windows, test))]
type AfterReplaceFailureHook = Box<dyn FnMut(WindowsReplaceStage, u32)>;

#[cfg(all(windows, test))]
thread_local! {
    static REPLACE_FORCE_LEGACY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REPLACE_BEFORE_RENAME: std::cell::RefCell<Option<BeforeRenameHook>> =
        const { std::cell::RefCell::new(None) };
    static REPLACE_AFTER_PARENT_PIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static REPLACE_AFTER_FAILURE: std::cell::RefCell<Option<AfterReplaceFailureHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(any(windows, test))]
fn dispatch_windows_replace_parent<T>(
    source_parent: &Path,
    target_parent: &Path,
    dispatch: impl FnOnce() -> T,
) -> Result<T, PlatformError> {
    if source_parent != target_parent {
        return Err(PlatformError::AtomicReplaceParentMismatch {
            source_parent: source_parent.to_path_buf(),
            target_parent: target_parent.to_path_buf(),
        });
    }
    Ok(dispatch())
}

#[cfg(windows)]
fn atomic_replace_windows(
    tmp_path: &Path,
    target: &Path,
    expected: Option<WrittenFileIdentity>,
) -> Result<(), PlatformError> {
    windows_publish(tmp_path, target, expected, None, false).map(|_| ())
}

#[cfg(windows)]
fn windows_publish(
    tmp_path: &Path,
    target: &Path,
    expected: Option<WrittenFileIdentity>,
    retained: Option<&std::fs::File>,
    no_replace: bool,
) -> Result<PublishOutcome, PlatformError> {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    let (source_parent, source_name) =
        windows_replace_path(tmp_path).map_err(|e| e.into_platform(tmp_path, target, 0))?;
    let (target_parent, target_name) =
        windows_replace_path(target).map_err(|e| e.into_platform(tmp_path, target, 0))?;
    let mut parent = None;
    // One shared budget: unsuccessful parent opens consume attempts; after its
    // first successful open the same parent object survives every source retry.
    for attempt in 0..5 {
        let opening = if parent.is_none() {
            Some(dispatch_windows_replace_parent(
                source_parent,
                target_parent,
                || windows_open_parent(target_parent),
            )?)
        } else {
            None
        };
        let result = (|| {
            if let Some(opening) = opening {
                parent = Some(opening.map_err(|e| {
                    WindowsReplaceFailure::io(
                        WindowsReplaceStage::Rename,
                        "CreateFileW(destination parent)",
                        e,
                    )
                })?);
                #[cfg(test)]
                if let Some(hook) = REPLACE_AFTER_PARENT_PIN.with(|h| h.borrow_mut().take()) {
                    hook();
                }
            }
            let parent = parent
                .as_ref()
                .ok_or_else(|| WindowsReplaceFailure::invalid("parent acquisition"))?;
            windows_replace_attempt(
                parent,
                &source_name,
                &target_name,
                expected,
                retained,
                no_replace,
            )
        })();
        let failure = match result {
            Ok(()) => return Ok(PublishOutcome::Published),
            Err(failure) => failure,
        };
        let retry_code = failure.retry_code();
        if no_replace
            && failure.stage == WindowsReplaceStage::Rename
            && matches!(retry_code, 80 | 183)
        {
            return Ok(PublishOutcome::AlreadyExists);
        }
        #[cfg(test)]
        REPLACE_AFTER_FAILURE.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(failure.stage, retry_code);
            }
        });
        // A directory target is a permanent error5. Query its entry relative to
        // the pinned parent, without following a final reparse point. If no pin
        // or readable entry is available, retain the bounded retry on error5.
        let target_is_dir = retry_code == 5
            && parent
                .as_ref()
                .and_then(|p| windows_open_relative(p, &target_name, FILE_READ_ATTRIBUTES, 7).ok())
                .and_then(|file| windows_file_information(&file).ok())
                .map(|info| info.dwFileAttributes & 0x10 != 0)
                .unwrap_or(false);
        if !windows_replace_retry(failure.stage, retry_code, target_is_dir, attempt) {
            return Err(failure.into_platform(tmp_path, target, attempt));
        }
        tracing::warn!(
            attempt = attempt + 1,
            error_code = retry_code,
            "atomic_replace retry (file may be locked)"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    unreachable!()
}

#[cfg(windows)]
fn windows_replace_attempt(
    parent: &std::fs::File,
    source_name: &[u16],
    target_name: &[u16],
    expected: Option<WrittenFileIdentity>,
    retained: Option<&std::fs::File>,
    no_replace: bool,
) -> Result<(), WindowsReplaceFailure> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use WindowsReplaceStage::{Open, Rename, Validate};
    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory) == 8);
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength) == 16);
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, FileName) == 20);
    };
    // Query observes one regular, non-reparse, single-link entry. Denying DELETE
    // sharing pins that entry against competing rename/delete opens while held;
    // sharing READ|WRITE permits writers and does not freeze content or links.
    let access = if retained.is_some() {
        FILE_READ_ATTRIBUTES
    } else {
        DELETE | FILE_READ_ATTRIBUTES | if expected.is_some() { 0x0002_0000 } else { 0 }
    };
    let reopened = windows_open_relative(
        parent,
        source_name,
        access,
        if retained.is_some() { 7 } else { 3 },
    )
    .map_err(|status| WindowsReplaceFailure {
        stage: Open,
        code: unsafe { RtlNtStatusToDosError(status) },
        api: "NtCreateFile(source)",
        nt: None,
    })?;
    let identity = |file: &std::fs::File| {
        windows_written_file_identity(file)
            .map_err(|e| WindowsReplaceFailure::io(Validate, "Windows file identity query", e))
    };
    let source = if let Some(writer) = retained {
        if identity(writer)? != identity(&reopened)? {
            return Err(WindowsReplaceFailure::invalid(
                "retained source identity validation",
            ));
        }
        writer
    } else {
        &reopened
    };
    let info = windows_file_information(source).map_err(|e| {
        WindowsReplaceFailure::io(Validate, "GetFileInformationByHandle(source)", e)
    })?;
    if !windows_replace_source_safe(info.dwFileAttributes, info.nNumberOfLinks) {
        return Err(WindowsReplaceFailure::invalid("source entry validation"));
    }
    if let Some(expected) = expected {
        if identity(source)? != expected {
            return Err(WindowsReplaceFailure::invalid(
                "written source identity validation",
            ));
        }
    }
    if expected.is_some() || retained.is_some() {
        super::fs_windows_acl::check_private_handle(source).map_err(|e| {
            WindowsReplaceFailure::io(Validate, "check_private_handle(source)", e.into())
        })?;
    }
    // Inspect the destination itself, relative to the same pinned parent. POSIX
    // rename can unlink a directory reparse point successfully; a failure-only
    // probe therefore cannot enforce the directory-destination refusal. This is
    // a point-in-time check, not a destination identity pin across rename.
    if !no_replace {
        match windows_open_relative(parent, target_name, FILE_READ_ATTRIBUTES, 7) {
            Ok(target) => {
                let info = windows_file_information(&target).map_err(|e| {
                    WindowsReplaceFailure::io(Validate, "destination attribute validation", e)
                })?;
                if info.dwFileAttributes & 0x10 != 0 {
                    return Err(WindowsReplaceFailure::io(
                        Validate,
                        "destination directory validation",
                        std::io::Error::from_raw_os_error(5),
                    ));
                }
            }
            Err(status) => {
                // SAFETY: pure status translation; the missing leaf is allowed.
                let code = unsafe { RtlNtStatusToDosError(status) };
                if !matches!(code, 2 | 3) {
                    return Err(WindowsReplaceFailure {
                        stage: Rename,
                        code,
                        api: "NtCreateFile(destination validation)",
                        nt: None,
                    });
                }
            }
        }
    }
    let total = std::mem::size_of::<FILE_RENAME_INFO>() + target_name.len() * 2;
    let mut buffer = vec![0u64; total.div_ceil(8)];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: aligned storage includes the checked-length UTF-16 leaf; the live
    // parent is kept until dispatch completes. FileName excludes a trailing NUL.
    unsafe {
        (*rename).RootDirectory = parent.as_raw_handle() as isize;
        (*rename).FileNameLength = (target_name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            target_name.as_ptr(),
            std::ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            target_name.len(),
        );
    }
    let mut rename_call = |source: &std::fs::File, _parent: &std::fs::File, class| {
        #[cfg(test)]
        REPLACE_BEFORE_RENAME.with(|h| {
            if let Some(h) = h.borrow_mut().as_mut() {
                h(class == 10);
            }
        });
        #[cfg(test)]
        if class == 65 && REPLACE_FORCE_LEGACY.with(|f| f.get()) {
            return 0xC000_0003_u32 as i32;
        }
        // SAFETY: same validated DELETE handle for both synchronous calls. The
        // union is fully overwritten (class10's BOOLEAN is 0 for no-replace).
        unsafe {
            (*rename).Anonymous.Flags = if no_replace {
                0
            } else if class == 65 {
                3
            } else {
                1
            };
            let mut block: IO_STATUS_BLOCK = std::mem::zeroed();
            NtSetInformationFile(
                source.as_raw_handle() as isize,
                &mut block,
                rename.cast(),
                total as u32,
                class,
            )
        }
    };
    let result = if no_replace {
        let status = rename_call(source, parent, 10);
        if windows_rename_failed(status) {
            Err((status, None))
        } else {
            Ok(())
        }
    } else {
        dispatch_windows_rename(source, parent, &mut rename_call)
    };
    result.map_err(|(posix, plain)| WindowsReplaceFailure {
        stage: Rename,
        code: unsafe { RtlNtStatusToDosError(posix) },
        api: if no_replace {
            "NtSetInformationFile(FileRenameInformation; no-replace)"
        } else {
            "NtSetInformationFile(FileRenameInformation)"
        },
        nt: if no_replace {
            None
        } else {
            Some((posix, plain))
        },
    })
}

/// Creates a symlink at `link` pointing to `target`, failing if `link` already exists.
///
/// This is the cross-platform primitive for atomic-exclusive symlink creation.
/// It underpins the handle-dir model (Phase 3 of an internal ticket A++): each
/// `term-<pid>/` handle dir's symlinks are created via this function so that
/// two concurrent `csq swap` calls against the same link path produce exactly
/// one winner.
///
/// # Platform semantics
///
/// | Platform | Mechanism | TOCTOU window |
/// |----------|-----------|---------------|
/// | Linux | `symlinkat` + `renameat2(RENAME_NOREPLACE)` | None — kernel atomic |
/// | macOS | `fstatat(AT_SYMLINK_NOFOLLOW)` + `symlinkat` | Narrow — same-user threat model |
/// | Windows | NTFS junction via `FSCTL_SET_REPARSE_POINT` + `GetFileAttributesW` | Narrow — same-user threat model |
///
/// # Errors
///
/// - `PlatformError::AlreadyExists` — `link` already exists (including via race).
/// - `PlatformError::Io` — filesystem error (parent not found, permission denied, etc.).
/// - `PlatformError::Win32` — Windows-specific IOCTL failure.
///
/// # Zero production callsites in Phase 1
///
/// This function is intentionally unreferenced by production code in Phase 1.
/// It sits on the shelf and soaks in CI (Linux + macOS + Windows matrix) until
/// Phase 3 wires the handle-dir symlinks.
pub fn symlink_exclusive(target: &Path, link: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        super::fs_symlink_unix::symlink_exclusive(target, link)
    }
    #[cfg(windows)]
    {
        super::fs_symlink_windows::symlink_exclusive(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink_exclusive not implemented for this platform",
        )))
    }
}

/// Bumps `path`'s modification time strictly above `min_mtime_ns` and the
/// file's current mtime, advancing to at least `now()`.
///
/// an internal ticket motivation: `csq swap N` repoints the runtime
/// `<handle_dir>/.credentials.json` symlink. `repoint_handle_dir` selects
/// `<base_dir>/identities/<UUID>/credentials.json` when the target slot resolves
/// to a UUID; only when it does not resolve does it select the legacy
/// `<base_dir>/config-<N>/.credentials.json` path. The mtime bump uses that SAME
/// resolved target. CC re-stats the symlink before every API call and reloads
/// credentials only when `mtimeMs !== lastCredentialsMtimeMs` (spec 01 §1.4 —
/// strict inequality). When old and new targets share an mtime (refresh timing
/// or filesystem precision), CC can skip the reload and the swap "appears not
/// to take effect". Calling this helper before the rename addresses that
/// collision; it is not an atomic guarantee against concurrent target writes.
///
/// The new mtime is `max(now(), min_mtime_ns + 1, current_mtime_ns + 1)`.
/// Pass `min_mtime_ns = 0` when no baseline is required (current + 1 wins).
///
/// Errors are returned but the caller should typically log and continue —
/// observability MUST NOT alter swap semantics. The post-swap collision warn
/// in `repoint_handle_dir` (`session::handle_dir`) acts as a regression
/// detector if this helper silently fails to advance the mtime.
///
/// `repoint_handle_dir` passes the selected identity-keyed or legacy credential
/// target described above, not the handle-dir symlink. If a caller passes a
/// symlink, `OpenOptions::open` follows it on both Unix and Windows so the
/// target's mtime is advanced, not the link's.
pub fn bump_mtime_above(path: &Path, min_mtime_ns: i128) -> Result<(), PlatformError> {
    use std::time::{Duration, SystemTime};

    let current_mtime = std::fs::metadata(path)?.modified()?;
    // Defensive cast: `Duration::as_nanos` returns u128. A pathological
    // mtime far in the future could exceed i128::MAX (saturate, don't wrap)
    // — silent wrap to negative would mis-rank baseline against the max()
    // formula. saturating_to_i128 keeps the ordering monotone.
    let current_ns = current_mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0);

    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0);

    // Granularity 100ns — NTFS FILETIME stores mtime in 100-nanosecond
    // ticks (Windows kernel `SetFileTime` rounds DOWN to the nearest tick).
    // Writing `baseline + 1` on Windows rounds back to `baseline`, breaking
    // the strict-advance invariant. POSIX nanosecond-resolution filesystems
    // (ext4, APFS, btrfs) preserve 100ns increments trivially, so 100 is the
    // smallest cross-platform value that guarantees strict advance. Origin:
    // an internal ticket (Windows test `bump_mtime_above_advances_when_baseline_is_in_future`).
    const MTIME_TICK_NS: i128 = 100;
    let target_ns = now_ns
        .max(min_mtime_ns.saturating_add(MTIME_TICK_NS))
        .max(current_ns.saturating_add(MTIME_TICK_NS));
    // u64::MAX nanoseconds = year ~2554. Saturating to u64::MAX (rather
    // than falling back to 0 = epoch) preserves the strict-advance
    // invariant: an mtime regression to 1970 would still satisfy
    // `mtimeMs !== lastCredentialsMtimeMs` for the immediate swap, but
    // operators inspecting `ls -la` would see nonsense and a subsequent
    // bump from a baseline > 1970 would re-trigger the same regression.
    let target_ns_u64 = u64::try_from(target_ns).unwrap_or(u64::MAX);
    let target_time = SystemTime::UNIX_EPOCH + Duration::from_nanos(target_ns_u64);

    // Cross-platform mtime advance:
    //
    // - **Unix:** open read-only (not write(true)) so the call succeeds even
    //   when the target file is mode 0o400 (Codex canonical credential files
    //   per INV-P08). POSIX `futimens(fd, times)` requires the caller to own
    //   the file, NOT to have write permission on it, so an O_RDONLY fd is
    //   sufficient. Confirmed on macOS/Linux: `File::set_modified` uses
    //   `futimens` internally, and `open(O_WRONLY)` on a 0o400 file returns
    //   EACCES even for the file owner, while `open(O_RDONLY)` succeeds and
    //   `futimens` advances the mtime correctly.
    //
    // - **Windows:** `File::set_modified` calls `SetFileTime(HANDLE, ...)`
    //   which requires `FILE_WRITE_ATTRIBUTES` (0x0100) access on the handle.
    //   `OpenOptions::read(true)` maps to `GENERIC_READ` which does NOT
    //   include `FILE_WRITE_ATTRIBUTES`, so opening read-only fails
    //   `SetFileTime` with `ERROR_ACCESS_DENIED` (5). We need a handle that
    //   carries both `FILE_WRITE_ATTRIBUTES` (for the mtime write) and
    //   `FILE_READ_ATTRIBUTES` (0x0080, harmless to grant; some kernels
    //   require it implicitly for any attribute manipulation). This is the
    //   minimum-privilege handle that satisfies `SetFileTime` and does NOT
    //   require `GENERIC_WRITE`, so files whose Windows ACLs deny write data
    //   still allow the mtime bump. Origin: an internal ticket.
    #[cfg(unix)]
    let file = std::fs::OpenOptions::new().read(true).open(path)?;

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES — minimum access for
        // `SetFileTime`. Avoids GENERIC_READ + GENERIC_WRITE.
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .open(path)?
    };

    file.set_modified(target_time)?;
    Ok(())
}

/// Test helper: drives `op` with the parent directory read-only, then asserts
/// (a) `op` returns `Err`, and (b) no `*.tmp.*` files remain in `dir`.
///
/// This is the canonical §5a regression fixture. Every site that uses the
/// `unique_tmp_path → write → secure_file → atomic_replace` pipeline MUST
/// have a test using this helper (or an inline duplicate in csq-cli /
/// csq-desktop, which cannot reach `pub(crate)` across crate boundaries).
///
/// Origin: security.md §5a, an internal journal entry B2, /redteam round 3 (2026-05-09).
#[cfg(all(test, unix))]
pub(crate) fn assert_no_tmp_leak_on_readonly_parent<F, E>(dir: &std::path::Path, op: F)
where
    F: FnOnce() -> Result<(), E>,
    E: std::fmt::Debug,
{
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = op();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_err(),
        "op must fail under read-only parent; got Ok"
    );
    let leaked: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.contains(".tmp."))
                .unwrap_or(false)
        })
        .collect();
    assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
}

/// Reads a small regular file without following a symlink at the final component
/// and without ever blocking on a FIFO or device.
///
/// * `Ok(None)` — the path does not exist.
/// * `Ok(Some(bytes))` — a regular file of at most `max` bytes, read in full.
/// * `Err(InvalidData)` — the open handle is not a regular file, or it holds more than
///   `max` bytes (the read is bounded by `take(max + 1)`, so growth after the `fstat`
///   cannot defeat the cap).
/// * `Err(_)` — any other open/read failure, including a symlink (`ELOOP` under
///   `O_NOFOLLOW`).
///
/// On unix the open uses `O_NOFOLLOW | O_NONBLOCK`: `O_NONBLOCK` makes `open(2)` on a FIFO
/// return immediately instead of waiting for a writer, and the regular-file check runs on
/// the opened handle (`fstat`), so nothing can be swapped in between check and read.
///
/// On Windows the open uses `FILE_FLAG_OPEN_REPARSE_POINT`, so a symlink or junction is
/// opened as the reparse point itself rather than followed, and the same handle-level
/// `is_file()` check then rejects it. (Windows has no FIFO to block on.)
pub fn read_regular_nofollow_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    read_regular_nofollow_bounded_inner(path, max, false)
}

/// [`read_regular_nofollow_bounded`] for a file csq itself wrote privately: on unix the
/// opened handle must also be owned by the effective user and carry no group or other
/// WRITE bit (read bits are not checked: the content is slot numbers, not secrets). A
/// foreign-owned or group/other-writable file is `Err(PermissionDenied)`, so a caller that
/// treats `Err` as "unreadable" fails closed. On Windows the owner/mode check does not
/// apply (the file's ACL governs), matching `secure_file`.
pub fn read_private_regular_nofollow_bounded(
    path: &Path,
    max: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    read_regular_nofollow_bounded_inner(path, max, true)
}

fn read_regular_nofollow_bounded_inner(
    path: &Path,
    max: u64,
    private: bool,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point itself, do not follow it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no memory or synchronization preconditions.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not owned by this user or writable by group/other",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds size cap",
        ));
    }
    Ok(Some(buf))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Add an ACL entry with the system tool; the entries are what a user can set with
    /// `chmod +a` on a directory they own.
    #[cfg(target_os = "macos")]
    pub(crate) fn chmod_add_acl(dir: &Path, entry: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(dir)
            .status()
            .unwrap();
        assert!(status.success(), "chmod +a {entry:?} failed");
    }

    #[cfg(target_os = "macos")]
    fn acl_refusal_of(dir: &Path) -> Option<String> {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open(dir).unwrap();
        directory_acl_refusal(file.as_raw_fd())
    }

    /// RAII ACL stripper for the macOS ACL tests below.
    ///
    /// `everyone deny delete` on a scratch directory makes that directory
    /// undeletable, and `tempfile::TempDir`'s `Drop` IGNORES the failed
    /// removal — the directory silently leaks on the host (observed: 34
    /// undeletable csq scratch dirs on a darwin host). Declared AFTER the
    /// `TempDir`, this guard drops BEFORE it on both paths: normal scope
    /// exit and panic unwind. `-R` reaches the descendant entries the tests
    /// add; `-N` strips every ACL entry without touching the mode bits.
    #[cfg(target_os = "macos")]
    struct StripAclsOnDrop {
        root: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl StripAclsOnDrop {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
            }
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for StripAclsOnDrop {
        fn drop(&mut self) {
            // A panic may already be unwinding and a second panic here would
            // abort. A failed strip is NOT swallowed: the test's own
            // post-drop absence assertion turns red when the tree survives.
            let _ = std::process::Command::new("/bin/chmod")
                .arg("-R")
                .arg("-N")
                .arg(&self.root)
                .status();
        }
    }

    /// Drop the stripper and the `TempDir`, then assert the scratch tree is
    /// GONE. `TempDir`'s `Drop` ignores a failed removal, so this assertion
    /// is the instrument that makes a leaked ACL directory visible.
    ///
    /// RED without the stripper in the two DENY-DELETE directory tests
    /// (`directory_acl_refusal_flags_only_entry_changing_allow_entries` and
    /// `private_directory_acl_refusal_flags_any_allow_and_inheritable_entries`):
    /// the deny entry blocks the removal and `root` still exists. The
    /// private-FILE test adds only `deny write` / `allow read`, which do not
    /// block unlinking — its call here is a consistency check, not a RED.
    #[cfg(target_os = "macos")]
    fn assert_scratch_removed(strip: StripAclsOnDrop, temp: TempDir, root: &Path) {
        drop(strip);
        drop(temp);
        assert!(
            !root.exists(),
            "the ACL scratch dir must not survive the test: {}",
            root.display()
        );
    }

    // MED-A: an ALLOW ACL entry that lets a grantee change a directory's entries is refused
    // however clean the mode bits are; deny-only and read-only entries pass.
    #[cfg(target_os = "macos")]
    #[test]
    fn directory_acl_refusal_flags_only_entry_changing_allow_entries() {
        let temp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(temp.path()).unwrap();
        let strip = StripAclsOnDrop::new(&dir);
        assert_eq!(acl_refusal_of(&dir), None, "no ACL");

        chmod_add_acl(&dir, "everyone deny delete");
        assert_eq!(acl_refusal_of(&dir), None, "deny-only passes");
        chmod_add_acl(&dir, "everyone allow list,search");
        assert_eq!(acl_refusal_of(&dir), None, "read-only allow passes");

        for grant in [
            "add_file",
            "add_subdirectory",
            "delete",
            "delete_child",
            "writesecurity",
            "chown",
        ] {
            let sub = dir.join(format!("g-{grant}"));
            std::fs::create_dir(&sub).unwrap();
            chmod_add_acl(&sub, &format!("everyone allow {grant}"));
            assert!(
                acl_refusal_of(&sub).is_some_and(|r| r.contains("ACL")),
                "{grant} must be refused"
            );
        }
        // The entry-changing grant is found even when it is not the first entry.
        chmod_add_acl(&dir, "everyone allow add_file");
        assert!(acl_refusal_of(&dir).is_some());

        assert_scratch_removed(strip, temp, &dir);
    }

    // M1/M3: the leaf private directory refuses ANY ALLOW, read grants and inheritable
    // entries included; deny-only passes.
    #[cfg(target_os = "macos")]
    #[test]
    fn private_directory_acl_refusal_flags_any_allow_and_inheritable_entries() {
        use std::os::fd::AsRawFd;
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let strip = StripAclsOnDrop::new(&root);
        let refusal = |dir: &Path| {
            private_directory_acl_refusal(std::fs::File::open(dir).unwrap().as_raw_fd())
        };
        assert_eq!(refusal(&root), None, "no ACL");
        let make = |name: &str, entry: &str| {
            let dir = root.join(name);
            std::fs::create_dir(&dir).unwrap();
            chmod_add_acl(&dir, entry);
            dir
        };
        assert_eq!(
            refusal(&make("deny", "everyone deny delete")),
            None,
            "deny-only"
        );
        for (name, entry) in [
            ("read", "everyone allow list,search"),
            ("write", "everyone allow add_file"),
            ("filein", "everyone allow list,file_inherit"),
            ("dirin", "everyone allow list,directory_inherit"),
        ] {
            let dir = make(name, entry);
            assert!(refusal(&dir).is_some_and(|r| r.contains("ACL")), "{entry}");
        }
        // The ancestor reader still lets a read-only grant through (control).
        let read = root.join("read");
        let ancestor = directory_acl_refusal(std::fs::File::open(&read).unwrap().as_raw_fd());
        assert_eq!(ancestor, None, "ancestor policy unchanged for a read grant");

        assert_scratch_removed(strip, temp, &root);
    }

    // macOS generic rights (`sys/kauth.h:177-180`): GENERIC_ALL 1<<21 and GENERIC_WRITE 1<<23
    // refuse on an ancestor; GENERIC_EXECUTE 1<<22 and GENERIC_READ 1<<24 alone pass. The
    // literals are written here, not taken from the implementation.
    #[cfg(target_os = "macos")]
    #[test]
    fn ancestor_policy_refuses_generic_all_and_write_but_not_read_or_execute() {
        let ancestor = |mask: u64| {
            acl_entry_refused(
                acl_ffi::ACL_EXTENDED_ALLOW,
                mask,
                acl_ffi::ENTRY_CHANGING,
                false,
            )
        };
        assert!(ancestor(1 << 21), "GENERIC_ALL");
        assert!(ancestor(1 << 23), "GENERIC_WRITE");
        assert!(!ancestor(1 << 22), "GENERIC_EXECUTE alone");
        assert!(!ancestor(1 << 24), "GENERIC_READ alone");
        assert!(
            !acl_entry_refused(0, 1 << 21, acl_ffi::ENTRY_CHANGING, false),
            "a deny"
        );
    }

    // S-MED-2: a private file allows no ACL grant at all, a read grant included.
    #[cfg(target_os = "macos")]
    #[test]
    fn private_file_acl_refusal_flags_any_allow_entry() {
        use std::os::fd::AsRawFd;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret");
        let strip = StripAclsOnDrop::new(temp.path());
        std::fs::write(&path, b"x").unwrap();
        let refusal =
            |path: &Path| private_file_acl_refusal(std::fs::File::open(path).unwrap().as_raw_fd());
        assert_eq!(refusal(&path), None, "no ACL");
        chmod_add_acl(&path, "everyone deny write");
        assert_eq!(refusal(&path), None, "deny-only passes");
        chmod_add_acl(&path, "everyone allow read");
        assert!(
            refusal(&path).is_some_and(|r| r.contains("ACL")),
            "read grant refused"
        );

        let root = temp.path().to_path_buf();
        assert_scratch_removed(strip, temp, &root);
    }

    #[cfg(target_os = "linux")]
    fn nfs4_ace(kind: u32, flag: u32, mask: u32, who: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for word in [kind, flag, mask, who.len() as u32] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(who.as_bytes());
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    #[cfg(target_os = "linux")]
    fn nfs4_acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let mut out = (aces.len() as u32).to_be_bytes().to_vec();
        for ace in aces {
            out.extend_from_slice(ace);
        }
        out
    }

    // S-MED-1: the NFSv4 ACL is read as bytes, not bounded by the mode bits.
    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_acl_parser_refuses_entry_changing_allow_for_non_owners() {
        use linux_nfs4::parse_refusal;
        let uid = 1000;
        for mask in [0x2, 0x4, 0x40, 0x1_0000, 0x4_0000, 0x8_0000] {
            for who in ["EVERYONE@", "GROUP@", "alice@example.com", "1001"] {
                let acl = nfs4_acl(&[nfs4_ace(0, 0, mask, who)]);
                assert!(
                    parse_refusal(&acl, uid).is_some(),
                    "{who} {mask:x} accepted"
                );
            }
        }
        // Not the first entry, and an inherit-only entry still counts.
        let acl = nfs4_acl(&[
            nfs4_ace(0, 0, 0x1, "OWNER@"),
            nfs4_ace(0, 0x8, 0x2, "EVERYONE@"),
        ]);
        assert!(parse_refusal(&acl, uid).is_some());
    }

    /// RFC 7530 section 6.2.1.3.1 ACE4 access mask bits, written out here independently of
    /// the implementation's constants (SDK `nfsproto.h:826-828` for the ACL/owner bits).
    #[cfg(target_os = "linux")]
    const RFC7530_MASK: [(&str, u32, bool); 14] = [
        // (name, bit, lets a grantee change directory entries or take it over)
        ("READ_DATA", 0x1, false),
        ("WRITE_DATA", 0x2, true),
        ("APPEND_DATA", 0x4, true),
        ("READ_NAMED_ATTRS", 0x8, false),
        ("WRITE_NAMED_ATTRS", 0x10, false),
        ("EXECUTE", 0x20, false),
        ("DELETE_CHILD", 0x40, true),
        ("READ_ATTRIBUTES", 0x80, false),
        ("WRITE_ATTRIBUTES", 0x100, false),
        ("DELETE", 0x1_0000, true),
        ("READ_ACL", 0x2_0000, false),
        ("WRITE_ACL", 0x4_0000, true),
        ("WRITE_OWNER", 0x8_0000, true),
        ("SYNCHRONIZE", 0x10_0000, false),
    ];

    // H1: the refused bits come from the RFC table, not from the implementation's constants.
    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_entry_changing_mask_matches_the_rfc7530_table() {
        use linux_nfs4::parse_refusal;
        for (name, bit, changing) in RFC7530_MASK {
            let acl = nfs4_acl(&[nfs4_ace(0, 0, bit, "EVERYONE@")]);
            assert_eq!(
                parse_refusal(&acl, 1000).is_some(),
                changing,
                "EVERYONE@ {name} {bit:#x}"
            );
        }
        let owner_change = nfs4_acl(&[nfs4_ace(0, 0, 0x8_0000, "EVERYONE@")]);
        assert!(parse_refusal(&owner_change, 1000).is_some(), "WRITE_OWNER");
        let read_acl = nfs4_acl(&[nfs4_ace(0, 0, 0x2_0000, "EVERYONE@")]);
        assert_eq!(parse_refusal(&read_acl, 1000), None, "READ_ACL alone");
    }

    // H2: a numeric who with ACE4_IDENTIFIER_GROUP names a gid, never the owning uid.
    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_numeric_who_with_the_group_flag_is_never_the_owner() {
        use linux_nfs4::parse_refusal;
        let group = nfs4_acl(&[nfs4_ace(0, 0x40, 0x2, "1000")]);
        assert!(
            parse_refusal(&group, 1000).is_some(),
            "gid 1000 is not uid 1000"
        );
        let user = nfs4_acl(&[nfs4_ace(0, 0, 0x2, "1000")]);
        assert_eq!(parse_refusal(&user, 1000), None, "control: uid 1000");
    }

    // M2: knfsd synthesizes `A::GROUP@:tcy` / `A::EVERYONE@:tcy` for a plain 0600 object
    // (t READ_ATTRIBUTES 0x80, c READ_ACL 0x2_0000, y SYNCHRONIZE 0x10_0000).
    #[cfg(target_os = "linux")]
    #[test]
    fn private_mask_accepts_a_knfsd_synthesized_0600_acl() {
        use linux_nfs4::{parse_private_directory_refusal, parse_refusal_masked, PRIVATE};
        let tcy = 0x80 | 0x2_0000 | 0x10_0000;
        let acl = nfs4_acl(&[
            nfs4_ace(0, 0, 0x6_0006, "OWNER@"),
            nfs4_ace(0, 0, tcy, "GROUP@"),
            nfs4_ace(0, 0, tcy, "EVERYONE@"),
        ]);
        assert_eq!(parse_refusal_masked(&acl, 1000, PRIVATE), None, "file");
        assert_eq!(
            parse_private_directory_refusal(&acl, 1000),
            None,
            "directory"
        );
        for (name, bit, _) in RFC7530_MASK {
            if tcy & bit != 0 {
                continue;
            }
            let acl = nfs4_acl(&[nfs4_ace(0, 0, bit, "EVERYONE@")]);
            assert!(
                parse_refusal_masked(&acl, 1000, PRIVATE).is_some(),
                "file {name}"
            );
            assert!(
                parse_private_directory_refusal(&acl, 1000).is_some(),
                "dir {name}"
            );
        }
    }

    // M1/M3: an inheritable ALLOW on the leaf private directory is refused exactly when its
    // bits are non-owner and outside the synthesized attribute/ACL-read/synchronize set.
    #[cfg(target_os = "linux")]
    #[test]
    fn private_directory_refuses_an_inheritable_allow() {
        use linux_nfs4::parse_private_directory_refusal;
        for flag in [0x1, 0x2, 0x3, 0x1 | 0x8] {
            for who in ["EVERYONE@", "GROUP@", "1001"] {
                let acl = nfs4_acl(&[nfs4_ace(0, flag, 0x1, who)]);
                assert!(
                    parse_private_directory_refusal(&acl, 1000).is_some(),
                    "inheritable {who} with a data bit, flag {flag:#x}"
                );
            }
            // A numeric euid carrying the group flag is a gid, never the owner.
            let gid = nfs4_acl(&[nfs4_ace(0, flag | 0x40, 0x1, "1000")]);
            assert!(parse_private_directory_refusal(&gid, 1000).is_some());
        }
        // knfsd's inherit-only entries for a plain 0600 directory, and an owner's own.
        let tcy = 0x80 | 0x2_0000 | 0x10_0000;
        let synthesized = nfs4_acl(&[
            nfs4_ace(0, 0x3 | 0x8, 0x6_0006, "OWNER@"),
            nfs4_ace(0, 0x3 | 0x8, tcy, "GROUP@"),
            nfs4_ace(0, 0x3 | 0x8, tcy, "EVERYONE@"),
            nfs4_ace(0, 0x3, 0x1, "1000"),
        ]);
        assert_eq!(
            parse_private_directory_refusal(&synthesized, 1000),
            None,
            "inherit-only owner and tcy entries"
        );
        let plain = nfs4_acl(&[nfs4_ace(0, 0, 0x80, "EVERYONE@")]);
        assert_eq!(
            parse_private_directory_refusal(&plain, 1000),
            None,
            "control"
        );
    }

    // L2: the READER (not only the parser) applies the private mask. A mutant that reads a
    // private file or directory with the ancestor mask accepts READ_DATA and reds here.
    #[cfg(target_os = "linux")]
    #[test]
    fn private_readers_apply_the_private_mask_and_fail_closed() {
        use linux_nfs4::{private_directory_refusal_via, private_file_refusal_via};
        fn read_grant(_: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
            Ok(Some(nfs4_acl(&[nfs4_ace(0, 0, 0x1, "EVERYONE@")])))
        }
        fn none(_: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn denied(_: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        }
        fn io(_: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        }
        assert!(
            private_file_refusal_via(0, read_grant).is_some(),
            "file read grant"
        );
        assert!(
            private_directory_refusal_via(0, read_grant).is_some(),
            "dir read grant"
        );
        assert_eq!(private_file_refusal_via(0, none), None);
        assert_eq!(private_directory_refusal_via(0, none), None);
        for fetch in [denied, io] {
            assert!(
                private_file_refusal_via(0, fetch).is_some_and(|r| r.contains("cannot be read"))
            );
            assert!(private_directory_refusal_via(0, fetch)
                .is_some_and(|r| r.contains("cannot be read")));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_acl_parser_accepts_owner_only_deny_and_read_entries() {
        use linux_nfs4::parse_refusal;
        let uid = 1000;
        assert_eq!(parse_refusal(&nfs4_acl(&[]), uid), None, "empty");
        let owner = nfs4_acl(&[nfs4_ace(0, 0, 0x7_0046, "OWNER@")]);
        assert_eq!(parse_refusal(&owner, uid), None, "owner");
        let numeric = nfs4_acl(&[nfs4_ace(0, 0, 0x2, "1000")]);
        assert_eq!(parse_refusal(&numeric, uid), None, "owning uid");
        let deny = nfs4_acl(&[nfs4_ace(1, 0, 0x7_0046, "EVERYONE@")]);
        assert_eq!(parse_refusal(&deny, uid), None, "deny");
        let read = nfs4_acl(&[nfs4_ace(0, 0, 0x1 | 0x20, "EVERYONE@")]);
        assert_eq!(parse_refusal(&read, uid), None, "read/execute allow");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_acl_parser_refuses_malformed_input() {
        use linux_nfs4::parse_refusal;
        let good = nfs4_acl(&[nfs4_ace(0, 0, 0x1, "EVERYONE@")]);
        assert_eq!(parse_refusal(&good, 1000), None, "control");
        let mut cases: Vec<Vec<u8>> = vec![vec![], vec![0, 0], good[..good.len() - 1].to_vec()];
        let mut extra = good.clone();
        extra.push(0);
        cases.push(extra);
        let mut huge = good.clone();
        huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        cases.push(huge);
        let mut long_who = good.clone();
        long_who[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        cases.push(long_who);
        for case in cases {
            assert!(
                parse_refusal(&case, 1000).is_some_and(|r| r.contains("malformed")),
                "{case:?} accepted"
            );
        }
    }

    // Private files: any non-owner ALLOW (read included) refuses; owner, deny-only and empty pass.
    #[cfg(target_os = "linux")]
    #[test]
    fn nfs4_acl_parser_refuses_any_non_owner_allow_for_a_private_file() {
        use linux_nfs4::parse_refusal_masked;
        let uid = 1000;
        for who in ["EVERYONE@", "GROUP@", "alice@example.com", "1001"] {
            let acl = nfs4_acl(&[nfs4_ace(0, 0, 0x1, who)]);
            assert!(
                parse_refusal_masked(&acl, uid, u32::MAX).is_some(),
                "{who} read accepted"
            );
            assert_eq!(
                parse_refusal_masked(&acl, uid, 0x2),
                None,
                "control: mask-bounded"
            );
        }
        for acl in [
            nfs4_acl(&[]),
            nfs4_acl(&[nfs4_ace(0, 0, 0x7_0046, "OWNER@")]),
            nfs4_acl(&[nfs4_ace(0, 0, 0x1, "1000")]),
            nfs4_acl(&[nfs4_ace(1, 0, 0x7_0046, "EVERYONE@")]),
        ] {
            assert_eq!(parse_refusal_masked(&acl, uid, u32::MAX), None);
        }
        assert!(
            parse_refusal_masked(&[0, 0], uid, u32::MAX).is_some_and(|r| r.contains("malformed"))
        );
    }

    /// Skip (with a logged reason) ONLY when the temp directory itself carries an NFSv4 ACL;
    /// any other filesystem must report none.
    #[cfg(target_os = "linux")]
    fn tmpdir_is_nfsv4(fd: std::os::fd::RawFd) -> bool {
        match linux_nfs4::fetch_acl(fd) {
            Ok(Some(_)) => {
                eprintln!(
                    "SKIP: TMPDIR carries an NFSv4 ACL, so the clean-read assertion does not apply"
                );
                true
            }
            Ok(None) => false,
            Err(error) => panic!("probing the temp directory ACL failed: {error}"),
        }
    }

    // The read path for a held private file: clean where no NFSv4 ACL exists, refusing on a
    // descriptor whose ACL cannot be read.
    #[cfg(target_os = "linux")]
    #[test]
    fn private_file_acl_refusal_reads_the_descriptor_and_fails_closed() {
        use std::os::fd::AsRawFd;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        if tmpdir_is_nfsv4(file.as_raw_fd()) {
            return;
        }
        assert_eq!(private_file_acl_refusal(file.as_raw_fd()), None);
        assert!(private_file_acl_refusal(-1).is_some_and(|r| r.contains("cannot be read")));
    }

    // The read path itself: a directory on a filesystem with no NFSv4 ACL is clean, through
    // an `O_PATH` descriptor (the form the ancestor walks hold).
    #[cfg(target_os = "linux")]
    #[test]
    fn directory_acl_refusal_reads_an_o_path_descriptor() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let temp = tempfile::tempdir().unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(temp.path())
            .unwrap();
        if !tmpdir_is_nfsv4(file.as_raw_fd()) {
            assert_eq!(directory_acl_refusal(file.as_raw_fd()), None);
            assert_eq!(private_directory_acl_refusal(file.as_raw_fd()), None);
        }
        assert!(
            linux_nfs4::refusal(-1).is_some_and(|r| r.contains("cannot be read")),
            "an unreadable descriptor refuses"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn trusted_directory_chain_refuses_an_acl_on_any_component() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let inner = root.join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(check_trusted_directory_chain(&inner).unwrap(), inner);
        chmod_add_acl(&root, "everyone allow add_file");
        let error = check_trusted_directory_chain(&inner).unwrap_err();
        assert!(
            error.contains(root.to_str().unwrap()) && error.contains("ACL"),
            "{error}"
        );
    }

    // The shared directory-trust policy. Varies the OWNER as well as the mode, so dropping
    // either clause is caught (a mode-only test passed with the owner clause deleted).
    #[cfg(unix)]
    #[test]
    fn untrusted_directory_reason_varies_owner_and_mode() {
        let me = 501;
        assert_eq!(untrusted_directory_reason(me, 0o755, me), None);
        assert_eq!(untrusted_directory_reason(me, 0o700, me), None);
        assert_eq!(untrusted_directory_reason(0, 0o755, me), None, "root-owned");
        assert_eq!(
            untrusted_directory_reason(0, 0o1777, me),
            None,
            "root-owned sticky, like /tmp"
        );
        assert!(untrusted_directory_reason(me + 1, 0o755, me)
            .is_some_and(|r| r.contains("another user")));
        assert!(untrusted_directory_reason(me + 1, 0o700, me).is_some());
        assert!(untrusted_directory_reason(me, 0o777, me).is_some_and(|r| r.contains("writable")));
        assert!(untrusted_directory_reason(me, 0o770, me).is_some());
        assert!(untrusted_directory_reason(me, 0o707, me).is_some());
        assert!(
            untrusted_directory_reason(me, 0o1777, me).is_some(),
            "sticky does not excuse a directory root does not own"
        );
        assert!(
            untrusted_directory_reason(0, 0o777, me).is_some(),
            "root but not sticky"
        );
    }

    // A hardened host's ancestor is `root 0750` (or 0710) with an ACL: read bits and ACLs are
    // irrelevant to trust, write bits and a foreign owner are not.
    #[cfg(unix)]
    #[test]
    fn untrusted_directory_reason_ignores_read_bits_not_write_bits_or_owner() {
        let me = 501;
        for (owner, mode) in [(0, 0o750), (0, 0o710), (0, 0o700), (me, 0o750), (me, 0o100)] {
            assert_eq!(
                untrusted_directory_reason(owner, mode, me),
                None,
                "{owner} {mode:o}"
            );
        }
        for (owner, mode) in [
            (0, 0o770),
            (0, 0o757),
            (me, 0o770),
            (me, 0o307),
            (me + 1, 0o750),
        ] {
            assert!(
                untrusted_directory_reason(owner, mode, me).is_some(),
                "{owner} {mode:o}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_directory_chain_names_the_offending_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().unwrap();
        let outer = fs::canonicalize(temp.path()).unwrap().join("outer");
        let inner = outer.join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(check_trusted_directory_chain(&inner).unwrap(), inner);
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o777)).unwrap();
        let err = check_trusted_directory_chain(&inner).unwrap_err();
        assert!(
            err.contains(outer.to_str().unwrap()) && err.contains("writable"),
            "{err}"
        );
        fs::set_permissions(&outer, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o770)).unwrap();
        let err = check_trusted_directory_chain(&inner).unwrap_err();
        assert!(
            err.contains(inner.to_str().unwrap()),
            "the base itself is checked: {err}"
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn bounded_read_absent_regular_and_oversized() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("f");
        assert!(read_regular_nofollow_bounded(&p, 8).unwrap().is_none());
        fs::write(&p, b"12345678").unwrap();
        assert_eq!(
            read_regular_nofollow_bounded(&p, 8).unwrap().as_deref(),
            Some(&b"12345678"[..])
        );
        fs::write(&p, b"123456789").unwrap();
        let e = read_regular_nofollow_bounded(&p, 8).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_refuses_symlink_and_fifo_promptly() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_regular_nofollow_bounded(&link, 8).is_err());
        // A present dangling leaf is invalid metadata, not an absent optional record.
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &dangling).unwrap();
        assert!(read_regular_nofollow_bounded(&dangling, 8).is_err());
        assert!(read_regular_nofollow_bounded(dir.path(), 8).is_err());

        let fifo = dir.path().join("fifo");
        mkfifo(&fifo);
        let (tx, rx) = std::sync::mpsc::channel();
        let f = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular_nofollow_bounded(&f, 8));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("FIFO read must return, not hang");
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn atomic_replace_basic() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp.txt");
        let target = dir.path().join("target.txt");

        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();

        atomic_replace(&tmp, &target).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists(), "tmp file should be gone after rename");
    }

    #[test]
    fn atomic_replace_creates_target_if_missing() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp.txt");
        let target = dir.path().join("new_target.txt");

        fs::write(&tmp, b"data").unwrap();
        atomic_replace(&tmp, &target).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "data");
    }

    #[test]
    fn atomic_replace_nonexistent_tmp_fails() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("nonexistent.txt");
        let target = dir.path().join("target.txt");

        let result = atomic_replace(&tmp, &target);
        assert!(result.is_err());
    }

    // ---- EXDEV cross-filesystem fallback ------------------------------
    //
    // `rename(2)` refuses with EXDEV when source and destination are on
    // different mounted filesystems. csq now symlinks into `shared-state/`
    // and `identities/`, which an operator may place on another volume, so
    // the branch is reachable in production. It cannot be reached in a unit
    // test without mounting a second filesystem, so the rename step is
    // injected through the `atomic_replace_unix` seam instead.

    /// An `io::Error` shaped exactly like the kernel's EXDEV refusal:
    /// `raw_os_error() == Some(18)`, `kind() == CrossesDevices`.
    #[cfg(unix)]
    fn exdev_error() -> std::io::Error {
        std::io::Error::from_raw_os_error(libc::EXDEV)
    }

    /// Names of every `*.tmp.*` file left in `dir` — the §5a leak check.
    #[cfg(unix)]
    fn tmp_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .filter(|n| n.contains(".tmp."))
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_falls_back_to_copy_into_place() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, br#"{"access_token":"fresh"}"#).unwrap();
        secure_file(&tmp).unwrap();

        let calls = std::cell::Cell::new(0usize);
        let result = atomic_replace_unix(&tmp, &target, |_, _| {
            calls.set(calls.get() + 1);
            Err(exdev_error())
        });

        result.expect("EXDEV must be recovered, not propagated");
        assert_eq!(calls.get(), 1, "rename attempted exactly once");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            r#"{"access_token":"fresh"}"#,
            "target must hold the new bytes"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "security.md MUST-5: the replaced credential file stays 0o600"
        );
        assert!(
            !tmp.exists(),
            "the fallback must consume the source, as rename(2) would"
        );
        assert!(
            tmp_files(dir.path()).is_empty(),
            "security.md §5a: staging file leaked: {:?}",
            tmp_files(dir.path())
        );
    }

    /// The same-filesystem `rename(2)` carries the source's mode across, so
    /// the fallback must too — a canonical Codex credential sits at 0o400
    /// (INV-P08) and must not silently come back as 0o600.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_preserves_source_mode_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("codex-creds.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&tmp, b"canonical").unwrap();
        secure_file_readonly(&tmp).unwrap();

        atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()))
            .expect("EXDEV must be recovered");

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o400,
            "source mode must survive the copy fallback"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "canonical");
    }

    /// zero-tolerance Rule 3: only EXDEV is recovered. Any other errno keeps
    /// its current behaviour exactly — propagated, unretried, unchanged.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_non_exdev_error_is_not_retried() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, b"never-lands").unwrap();
        secure_file(&tmp).unwrap();

        let calls = std::cell::Cell::new(0usize);
        let result = atomic_replace_unix(&tmp, &target, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        });

        match result {
            Err(PlatformError::Io(e)) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EACCES),
                "the original errno must survive"
            ),
            other => panic!("expected the EACCES io error to propagate, got {other:?}"),
        }
        assert_eq!(calls.get(), 1, "a non-EXDEV failure must not be retried");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "stale",
            "target must be untouched when the rename fails"
        );
        assert!(
            tmp.exists(),
            "the caller owns tmp cleanup on a propagated error (§5a); the \
             fallback must not have consumed it"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "no staging file may be created on a non-EXDEV path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_happy_path_renames_without_fallback() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();

        let calls = std::cell::Cell::new(0usize);
        atomic_replace_unix(&tmp, &target, |from, to| {
            calls.set(calls.get() + 1);
            std::fs::rename(from, to)
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists());
        assert!(tmp_files(dir.path()).is_empty());
    }

    /// security.md §5a: when the fallback fails AFTER the staging file exists,
    /// that secret-bearing file must be removed before the error propagates.
    /// A non-empty directory at `target` makes the final rename fail with the
    /// staging file already written — the only reachable branch that leaves
    /// one behind.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_removes_staging_when_final_rename_fails() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("resident"), b"blocks the rename").unwrap();
        let tmp = unique_tmp_path(&target);
        fs::write(&tmp, b"secret").unwrap();
        secure_file(&tmp).unwrap();

        let result = atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()));

        assert!(
            result.is_err(),
            "renaming onto a non-empty directory must fail"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "§5a: the staging file must be removed before the error propagates"
        );
        assert!(target.is_dir(), "target must be untouched");
    }

    /// zero-tolerance Rule 3 again, from the other side: when the fallback
    /// itself cannot proceed it fails LOUDLY and leaks nothing.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_fails_loudly_when_staging_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, b"fresh").unwrap();
        secure_file(&tmp).unwrap();

        // Read-only parent: the staging file cannot be created.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "an unwritable target dir must surface, not be swallowed"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "stale",
            "target must be untouched"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "§5a: no staging file may survive a failed fallback"
        );
    }

    // ---- Production-wiring coverage: `atomic_replace` itself, real device --
    //
    // The six tests above drive `atomic_replace_unix` DIRECTLY through the
    // injected-rename seam. That proves the EXDEV fallback's logic; it does
    // NOT prove `atomic_replace` (the public production entry point, this
    // file's line ~111) actually reaches it — reverting that call site to a
    // bare `std::fs::rename(tmp_path, target)?` leaves every test above
    // green, because none of them ever calls `atomic_replace`.
    //
    // This test closes that gap by driving the PUBLIC entry point across a
    // genuine filesystem boundary: a throwaway HFS+ RAM disk, created and
    // torn down at runtime via `hdiutil`/`diskutil`, with device identity
    // (`st_dev`) verified BEFORE anything is asserted. Per
    // `.claude/skills/test-skip-discipline`, the gate is on environment
    // CAPABILITY (can a RAM disk be created here at all?), never on what
    // `atomic_replace` returns — so it skips loudly when the capability is
    // absent and otherwise asserts unconditionally.

    /// A throwaway HFS+ volume backed by a RAM-only block device
    /// (`hdiutil attach ram://`), unmounted on every exit path — including
    /// panic, via `Drop` — so a failed assertion never leaves a mounted
    /// volume behind. macOS-only: `hdiutil`/`diskutil ram://` have no analog
    /// exercised here on other platforms, and `/dev/shm` (the Linux
    /// equivalent used by `kailash-coc-rs`-style harnesses) does not exist
    /// on macOS.
    #[cfg(target_os = "macos")]
    struct RamDisk {
        device: String,
        mount_point: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl RamDisk {
        /// `None` on ANY failure — no admin rights, `hdiutil` sandboxed out,
        /// `diskutil` unavailable, etc. Every intermediate resource is torn
        /// down before returning `None`, so a partial failure never leaks a
        /// device or a mount.
        fn try_create(size_kb: u32) -> Option<Self> {
            let attach = std::process::Command::new("hdiutil")
                .args(["attach", "-nomount", &format!("ram://{size_kb}")])
                .output()
                .ok()?;
            if !attach.status.success() {
                return None;
            }
            let device = String::from_utf8_lossy(&attach.stdout).trim().to_string();
            if device.is_empty() {
                return None;
            }
            let volname = format!("csqtest{}", std::process::id());
            let erase_ok = std::process::Command::new("diskutil")
                .args(["eraseVolume", "HFS+", &volname, &device])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !erase_ok {
                let _ = std::process::Command::new("hdiutil")
                    .args(["detach", &device, "-force"])
                    .output();
                return None;
            }
            let mount_point = PathBuf::from(format!("/Volumes/{volname}"));
            if !mount_point.is_dir() {
                let _ = std::process::Command::new("hdiutil")
                    .args(["detach", &device, "-force"])
                    .output();
                return None;
            }
            Some(Self {
                device,
                mount_point,
            })
        }

        fn path(&self) -> &Path {
            &self.mount_point
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for RamDisk {
        fn drop(&mut self) {
            // `-force` so a lingering open fd (e.g. this test's own failure
            // path) does not leave the volume mounted after the test exits.
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", &self.device, "-force"])
                .output();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_replace_public_entry_point_crosses_real_device_boundary() {
        use std::os::unix::fs::MetadataExt;

        let Some(ram_disk) = RamDisk::try_create(2048) else {
            eprintln!(
                "SKIP atomic_replace_public_entry_point_crosses_real_device_boundary: \
                 could not create a throwaway RAM disk via `hdiutil attach ram://` + \
                 `diskutil eraseVolume` on this host (sandboxed CI, no hdiutil access, \
                 or similar) — no second filesystem is available to prove a genuine \
                 EXDEV boundary here. Test did not execute; this is NOT a pass."
            );
            return;
        };

        let same_fs_dir = TempDir::new().unwrap();
        let tmp = same_fs_dir.path().join("staged-credentials.tmp");
        let target = ram_disk.path().join("credentials.json");

        fs::write(&tmp, br#"{"access_token":"fresh-from-real-exdev"}"#).unwrap();
        secure_file(&tmp).unwrap();

        // Verify the boundary is real BEFORE asserting anything about the
        // call under test — a false "yes, cross-device" here would make the
        // whole test vacuous in the other direction (instrument-discipline
        // MUST-1: name what would falsify the setup, not just the claim).
        let tmp_dev = fs::metadata(&tmp).unwrap().dev();
        let target_dir_dev = fs::metadata(ram_disk.path()).unwrap().dev();
        assert_ne!(
            tmp_dev, target_dir_dev,
            "setup invalid: RAM disk reports the SAME st_dev as the tmpdir — \
             this host does not give the two paths distinct devices, so this \
             run cannot exercise a real EXDEV boundary"
        );

        atomic_replace(&tmp, &target)
            .expect("atomic_replace (the PUBLIC entry point) must recover a genuine EXDEV");

        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            r#"{"access_token":"fresh-from-real-exdev"}"#,
            "target on the RAM disk must hold the new bytes"
        );
        assert!(
            !tmp.exists(),
            "the fallback must consume tmp_path, as rename(2) would"
        );
        let leaked = tmp_files(ram_disk.path());
        assert!(
            leaked.is_empty(),
            "security.md §5a: staging file leaked on the RAM disk: {leaked:?}"
        );
    }

    #[test]
    fn bump_mtime_above_advances_when_baseline_equals_current() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        let baseline = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(baseline).unwrap();
        drop(f);

        let baseline_ns = baseline
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        bump_mtime_above(&path, baseline_ns).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > baseline,
            "bump_mtime_above must advance strictly above baseline; got {new_mtime:?} <= {baseline:?}"
        );
    }

    #[test]
    fn bump_mtime_above_advances_when_baseline_is_in_future() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        // Baseline far in the future — clock-skew defense. The bump must
        // still produce a strictly-greater mtime, not silently drop to now().
        let future = SystemTime::now() + Duration::from_secs(86_400 * 365);
        let future_ns = future
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        bump_mtime_above(&path, future_ns).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let new_ns = new_mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        assert!(
            new_ns > future_ns,
            "bump_mtime_above must advance above future baseline; got {new_ns} <= {future_ns}"
        );
    }

    #[test]
    fn bump_mtime_above_zero_baseline_advances_above_current() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        let original = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(original).unwrap();
        drop(f);

        // baseline = 0 means "no minimum, just advance above current"
        bump_mtime_above(&path, 0).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > original,
            "bump_mtime_above with baseline=0 must still advance above current mtime"
        );
    }

    #[test]
    fn bump_mtime_above_nonexistent_path_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let result = bump_mtime_above(&path, 0);
        assert!(
            result.is_err(),
            "bump_mtime_above on missing path must error"
        );
    }

    /// INV-P08 compatibility: `bump_mtime_above` MUST succeed on a 0o400
    /// (owner-read-only) file. Codex canonical credential files live at 0o400
    /// between refresh windows (per `secure_file_readonly`). The helper must
    /// use O_RDONLY + `futimens`, not O_WRONLY (which returns EACCES for the
    /// owner of a 0o400 file on POSIX).
    #[cfg(unix)]
    #[test]
    fn bump_mtime_above_succeeds_on_mode_400_file() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("codex-creds.json");
        fs::write(&path, b"{}").unwrap();

        // Pin mtime to a known past value.
        let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(pinned).unwrap();
        drop(f);

        // Flip to 0o400 — the INV-P08 mode that Codex canonicals sit at.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        let pinned_ns = pinned
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        // Must not return EACCES; must advance the mtime.
        bump_mtime_above(&path, pinned_ns).unwrap();

        // Restore to writable before reading metadata (just in case).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > pinned,
            "bump_mtime_above must advance mtime on a 0o400 file (INV-P08 \
             codex canonical compatibility); got {new_mtime:?} <= {pinned:?}"
        );
    }

    /// SEC-3-H3 (M3-4): extend the 0o400 coverage to the UUID-keyed credential
    /// path (`identities/<UUID>/credentials.json`).  The file is placed under
    /// an identity-style directory structure to prove that `bump_mtime_above`
    /// works correctly regardless of whether the file is at a slot path or an
    /// identity path.  This pins an internal journal entry D3 (test fixture matches production
    /// permission mode) for the identity-keyed case.
    ///
    /// The key invariant: `bump_mtime_above` uses `OpenOptions::new().read(true)`
    /// (POSIX `futimens` requires ownership, not write permission — an internal journal entry D1).
    /// Using `O_RDONLY` means a 0o400 file owned by the caller is accessible;
    /// `O_WRONLY` would fail with `EACCES` even for the owner on POSIX.
    #[cfg(unix)]
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn bump_mtime_above_succeeds_on_mode_0o400_identity_credentials_json() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};

        // Arrange: create an identity-style directory structure with credentials.json
        // at 0o400 — matching the production mode Codex auth files sit at.
        let dir = TempDir::new().unwrap();
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let identity_dir = dir.path().join("identities").join(uuid_str);
        fs::create_dir_all(&identity_dir).unwrap();
        let path = identity_dir.join("credentials.json");
        fs::write(&path, b"{}").unwrap();

        // Pin mtime to a known past value.
        let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);
        {
            let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.set_modified(pinned).unwrap();
        }

        // Flip to 0o400 — the INV-P08 mode.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        let pinned_ns = pinned
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        // Act: must NOT return EACCES; must advance the mtime on the UUID path.
        bump_mtime_above(&path, pinned_ns).unwrap();

        // Restore to writable so metadata() can be read.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // Assert: mtime advanced above the pinned baseline.
        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > pinned,
            "bump_mtime_above must advance mtime on a 0o400 identity credentials.json \
             (SEC-3-H3 / INV-P08 compatibility); got {new_mtime:?} <= {pinned:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_sets_600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        fs::write(&path, b"sensitive").unwrap();

        // Start with permissive mode
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        secure_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn secure_file_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.txt");
        // On Unix this should fail; on Windows it's a no-op so it succeeds
        #[cfg(unix)]
        assert!(secure_file(&path).is_err());
        #[cfg(windows)]
        assert!(secure_file(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_readonly_sets_400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("canonical-cred.json");
        fs::write(&path, b"\"token\":\"...\"").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    /// Canonical credential-file lifecycle (spec 07 INV-P08):
    /// 0o400 → flip to 0o600 for write → write → flip back to 0o400.
    #[cfg(unix)]
    #[test]
    fn secure_file_roundtrip_400_600_400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"initial").unwrap();

        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        // Begin refresh window — flip to writable.
        secure_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Refresh writes.
        fs::write(&path, b"refreshed").unwrap();

        // Close refresh window — flip back to read-only.
        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    #[test]
    fn secure_file_readonly_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.json");
        #[cfg(unix)]
        assert!(secure_file_readonly(&path).is_err());
        #[cfg(windows)]
        assert!(secure_file_readonly(&path).is_ok());
    }

    #[test]
    fn atomic_replace_concurrent_writers() {
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("shared.txt");
        fs::write(&target, b"initial").unwrap();

        let target_arc = Arc::new(target.clone());
        let dir_path = Arc::new(dir.path().to_path_buf());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let target = Arc::clone(&target_arc);
                let dir_path = Arc::clone(&dir_path);
                thread::spawn(move || {
                    for j in 0..100 {
                        let tmp = dir_path.join(format!("tmp_{i}_{j}.txt"));
                        let data = format!("writer_{i}_iter_{j}");
                        fs::write(&tmp, data.as_bytes()).unwrap();
                        // Ignore errors from concurrent renames — we only care
                        // that the final file is not corrupted
                        let _ = atomic_replace(&tmp, &target);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // The target file must exist and contain valid data from some writer
        let content = fs::read_to_string(&target).unwrap();
        assert!(content.starts_with("writer_"), "content: {content}");
    }

    // ---- write_new_private ---------------------------------------------
    //
    // security.md §5a: the write-then-secure window. These pin the three
    // properties the helper exists to guarantee — mode set AT creation
    // regardless of umask, and refusal of both an existing file and an
    // existing symlink so a pre-planted symlink's target is never touched.

    /// Mutation: drop `.mode(0o600)` from `write_new_private` -> this REDs,
    /// because the file would then be created at `0o666 & !umask`, and
    /// under the 0o022 umask set here that is 0o644, not 0o600.
    ///
    /// The umask is deliberately tightened to a KNOWN permissive value
    /// (0o022, a common default) for the duration of this test, rather than
    /// trusting the ambient umask — if the ambient umask already happened to
    /// be 0o077 or stricter, dropping `.mode(0o600)` would still yield 0o600
    /// by coincidence (0o666 & !0o077 == 0o600) and the mutation would NOT
    /// RED, silently masking the regression this test exists to catch.
    ///
    /// `libc::umask` is process-global (same hazard class as
    /// `platform::test_env::signal_lock`'s process-wide signal
    /// disposition), so this test serializes via the shared
    /// `platform::test_env` mutex rather than introducing a new one —
    /// the only non-test call site is `daemon::server`'s socket-bind path
    /// (which does not run under `cargo test`). Every test that exercises a
    /// process-global umask window — the SEC-2.15 identity-dir mode tests
    /// included — serializes on this SAME lock, so it stays the single guard.
    #[cfg(unix)]
    #[test]
    fn write_new_private_sets_mode_0o600_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");

        // LOW-7 (R1): UmaskGuard pins the permissive mask and restores it in
        // Drop under the shared test_env lock — the panic-safe replacement
        // for the manual save/restore pair.
        let _umask = crate::platform::test_env::UmaskGuard::pin(0o022);
        write_new_private(&path, b"secret-bytes")
            .expect("write_new_private must succeed for a fresh path");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "mode must be 0o600 regardless of a permissive process umask"
        );
    }

    // ---- ensure_private_dir --------------------------------------------
    //
    // The shared SEC-2.15 directory creator. These pin the four properties
    // it exists to guarantee: mode 0o700 AT CREATION for every created
    // level (no create-then-chmod window), the upgrade path (a pre-existing
    // 0o755 dir is tightened), and refusal — before any chmod — of both a
    // symlink (target untouched) and a regular file.

    /// Mutation: drop `.mode(0o700)` from the `DirBuilder` AND the trailing
    /// `set_permissions` -> this REDs, because each created level would then
    /// land at `0o777 & !umask` = 0o755 under the 0o022 umask pinned here.
    /// The umask is pinned to a KNOWN permissive value for the same reason
    /// the `write_new_private` test pins it: an ambient 0o077 would mask
    /// the mutation by coincidence.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_secures_every_created_level_under_umask_022() {
        use std::os::unix::fs::PermissionsExt;

        let _umask = crate::platform::test_env::UmaskGuard::pin(0o022);
        let dir = TempDir::new().unwrap();
        let leaf = dir.path().join("a").join("b").join("c");

        ensure_private_dir(&leaf).expect("ensure_private_dir must create the chain");

        let mode_of = |p: &std::path::Path| {
            std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode_of(&leaf), 0o700, "leaf must be created owner-only");
        assert_eq!(
            mode_of(&dir.path().join("a")),
            0o700,
            "the first created level must be owner-only — mode must apply to \
             every level in the chain, not just the leaf"
        );
        assert_eq!(
            mode_of(&dir.path().join("a").join("b")),
            0o700,
            "the middle level must be owner-only"
        );
    }

    /// Upgrade path: a directory already existing at a permissive mode (an
    /// older csq's umask-default 0o755) is tightened by the same call.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_tightens_pre_existing_0o755_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let leaf = dir.path().join("legacy");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();

        ensure_private_dir(&leaf).expect("must tighten an existing dir");

        assert_eq!(
            std::fs::symlink_metadata(&leaf)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "a pre-existing 0o755 dir must be tightened to 0o700"
        );
    }

    /// A symlink planted at the path must be refused BEFORE any chmod, and
    /// its target must be untouched — the chmod must never follow the link.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_refuses_symlink_without_touching_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = ensure_private_dir(&link).expect_err("a symlink must be refused");

        assert!(
            err.to_string().contains("non-directory"),
            "refusal must name the reason, got: {err}"
        );
        assert_eq!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the symlink target's mode must be untouched"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be left in place"
        );
    }

    /// A regular file at the path is refused the same way, and left in place.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_refuses_regular_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("occupied");
        std::fs::write(&file, b"x").unwrap();

        let err = ensure_private_dir(&file).expect_err("a regular file must be refused");

        assert!(
            err.to_string().contains("non-directory"),
            "refusal must name the reason, got: {err}"
        );
        assert!(file.is_file(), "the file must be left in place");
    }

    /// R2 H1: the root variant resolves a LEAF SYMLINK once and secures the
    /// real target — the documented external-drive accounts root. RED on the
    /// pre-R3 bytes, where the strict refusal rejected the symlink.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_root_resolves_leaf_symlink_and_secures_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("external-root");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("accounts");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        ensure_private_dir_root(&link).expect("a symlinked root resolves and secures");

        assert_eq!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the resolved target must be tightened to 0o700"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the operator's symlink itself must be left in place"
        );
    }

    /// R2 H1: the root variant still refuses a symlink to a non-directory
    /// and a dangling symlink, and creates an absent root at 0o700.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_root_refuses_bad_symlinks_and_creates_absent_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("plain-file");
        std::fs::write(&file, b"x").unwrap();
        let link = dir.path().join("bad-root");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        ensure_private_dir_root(&link).expect_err("a symlink to a file must be refused");
        assert!(file.is_file(), "the target file must be untouched");

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
        ensure_private_dir_root(&dangling).expect_err("a dangling symlink must be refused");

        let _umask = crate::platform::test_env::UmaskGuard::pin(0o022);
        let virgin = dir.path().join("new-root");
        ensure_private_dir_root(&virgin).expect("an absent root must be created");
        assert_eq!(
            std::fs::symlink_metadata(&virgin)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "a created root must be owner-only even under a permissive umask"
        );
    }

    /// R2 M2: the tighten-only variant tightens an existing dir, REFUSES a
    /// missing one without recreating it, and refuses a symlink.
    #[cfg(unix)]
    #[test]
    fn tighten_existing_private_dir_never_recreates() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("legacy");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        tighten_existing_private_dir(&existing).expect("an existing dir tightens");
        assert_eq!(
            std::fs::symlink_metadata(&existing)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let missing = dir.path().join("removed-by-gc");
        let err = tighten_existing_private_dir(&missing)
            .expect_err("a missing dir must fail, never be recreated");
        assert!(
            err.to_string().contains("no longer exists"),
            "refusal must name the cause, got: {err}"
        );
        assert!(
            !missing.exists(),
            "the tighten must NOT resurrect the directory"
        );

        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        tighten_existing_private_dir(&link).expect_err("a symlink must be refused");
    }

    /// `write_new_private_synced` shares `write_new_private_impl` with
    /// `sync=true`; this pins that it still creates at 0o600 (the shared
    /// mode/create_new guarantee) and additionally that the bytes are
    /// durable — read back via a FRESH `File::open`, not the writer's own
    /// handle, so a bug that skipped `sync_all` but left the OS page cache
    /// coherent would still be caught by anything that re-opens the path.
    #[test]
    fn write_new_private_synced_sets_mode_and_persists_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");

        write_new_private_synced(&path, b"durable-secret").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read(&path).unwrap(), b"durable-secret");
    }

    /// Mutation: drop `create_new(true)` (replace with plain `.write(true)`,
    /// which would need `.truncate(true)` or `.create(true)` to be usable at
    /// all) -> this REDs, because the call would then silently truncate and
    /// overwrite the pre-existing file's content instead of refusing.
    #[test]
    fn write_new_private_refuses_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");
        fs::write(&path, b"pre-existing").unwrap();

        let result = write_new_private(&path, b"new-secret");

        assert!(
            result.is_err(),
            "write_new_private must refuse an existing regular file"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"pre-existing",
            "the pre-existing file's content must be untouched"
        );
    }

    /// Mutation: same as above (`create_new(true)` removed) -> this REDs
    /// because `std::fs::write`-shaped semantics follow a symlink and would
    /// overwrite ITS TARGET — exactly the attack `create_new` exists to
    /// close (a pre-planted symlink at the tmp path pointing at a file the
    /// attacker wants overwritten with attacker-controlled or truncated
    /// content).
    #[cfg(unix)]
    #[test]
    fn write_new_private_refuses_existing_symlink_and_leaves_target_untouched() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim.txt");
        let link = dir.path().join("secret.tmp");
        fs::write(&victim, b"do-not-touch").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let result = write_new_private(&link, b"attacker-controlled");

        assert!(
            result.is_err(),
            "write_new_private must refuse a path that already exists as a symlink"
        );
        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do-not-touch",
            "the symlink's target must be untouched — create_new must not follow it"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be untouched, not replaced"
        );
    }

    // Cleanup-on-write-failure (the `write_all` Err branch removing the file
    // it just created) is NOT covered by an executed test: no portable,
    // non-fragile trigger for a write(2) failure AFTER a successful
    // create_new/open exists across this workspace's macOS + Linux + Windows
    // CI matrix. `/dev/full` is Linux-only; forcing EFBIG via
    // `setrlimit(RLIMIT_FSIZE)` requires handling `SIGXFSZ` (whose default
    // disposition is to terminate the process) and would itself mutate
    // process-global signal state guarded by `test_env::signal_lock` for an
    // unrelated reason. Stated per COMMON.md Evidence rather than claimed:
    // this branch is structurally identical in shape to
    // `atomic_replace_cross_device`'s `copy_into_staging` failure arm (same
    // "remove what this call created, then propagate" pattern), which IS
    // exercised via a forced rename failure in
    // `atomic_replace_unix_exdev_removes_staging_when_final_rename_fails`.

    /// R3 LOW 2 regression (fd-relative form): the identity bind refuses a
    /// LEAF swapped after enumeration — never chmod-ing the replacement —
    /// and tightens the CURRENT inode when the caller passes its observed
    /// identity, opened RELATIVE to the held parent fd.
    #[cfg(unix)]
    #[test]
    fn tighten_child_refuses_an_entry_that_changed_identity() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let victim = parent.join("victim-child-x9");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::symlink_metadata(&victim).unwrap();
        let observed = (meta.dev(), meta.ino());

        let parent_fd = DirFd::open(&parent).expect("parent opens");

        // The swap: the observed dir is renamed away and a DIFFERENT dir
        // takes its name.
        fs::rename(&victim, parent.join("moved-x9")).unwrap();
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();

        let err = parent_fd
            .tighten_child(std::ffi::OsStr::new("victim-child-x9"), Some(observed))
            .expect_err("a changed inode must be refused");
        assert!(
            format!("{err}").contains("changed identity"),
            "the refusal must name the cause: {err}"
        );
        assert_eq!(
            fs::symlink_metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755,
            "the replacement dir must NOT have been tightened"
        );

        // Positive direction: the CURRENT inode's observed identity passes
        // and the tighten applies, fd-relative to the held parent.
        let fresh = fs::symlink_metadata(&victim).unwrap();
        let changed = parent_fd
            .tighten_child(
                std::ffi::OsStr::new("victim-child-x9"),
                Some((fresh.dev(), fresh.ino())),
            )
            .expect("the CURRENT inode must tighten");
        assert!(changed, "0o755 -> 0o700 must report a change");
        assert_eq!(
            fs::symlink_metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o700,
            "the verified inode must be tightened"
        );
    }

    /// R3 LOW 2 FULL-FIX regression: the child open is fd-relative — after
    /// the handle is taken, renaming the parent path away and recreating a
    /// look-alike at the same path must NOT redirect the tighten. The
    /// ORIGINAL child (reached through the held fd) tightens; the
    /// look-alike's same-named child is untouched. RED against any
    /// path-resolving open: the look-alike's child would be refused as a
    /// changed identity, leaving the original at 0o755.
    #[cfg(unix)]
    #[test]
    fn tighten_child_is_fd_relative_a_parent_swap_does_not_redirect() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("parent-x9");
        fs::create_dir(&parent).unwrap();
        let victim = parent.join("victim-child-x9");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::symlink_metadata(&victim).unwrap();
        let observed = (meta.dev(), meta.ino());

        let parent_fd = DirFd::open(&parent).expect("parent opens");

        // The swap: the WHOLE parent is renamed away and a look-alike is
        // recreated at its path with a same-named child.
        let moved = dir.path().join("moved-parent-x9");
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let look_alike_child = parent.join("victim-child-x9");
        fs::create_dir(&look_alike_child).unwrap();
        fs::set_permissions(&look_alike_child, fs::Permissions::from_mode(0o755)).unwrap();

        let changed = parent_fd
            .tighten_child(std::ffi::OsStr::new("victim-child-x9"), Some(observed))
            .expect("the ORIGINAL child, reached through the held fd, must tighten");
        assert!(changed, "the original 0o755 child must report a change");
        assert_eq!(
            fs::symlink_metadata(moved.join("victim-child-x9"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the ORIGINAL parent's child must be tightened through the held fd"
        );
        assert_eq!(
            fs::symlink_metadata(&look_alike_child)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the recreated look-alike's child must be untouched"
        );
    }

    /// Sharing (32), lock (33) and access-denied (5) on a non-directory
    /// target are retried by `atomic_replace_windows`; access-denied on a
    /// directory target and not-found codes fail on the first attempt, so a
    /// permanent refusal emits no retry WARN rows.
    #[test]
    fn atomic_replace_retries_only_sharing_and_lock_violations() {
        for transient in [32, 33] {
            assert!(is_transient_move_error(transient, false));
            assert!(is_transient_move_error(transient, true));
        }
        assert!(
            is_transient_move_error(5, false),
            "access-denied on a held-open file target must be retried"
        );
        assert!(
            !is_transient_move_error(5, true),
            "access-denied on a directory target must fail fast"
        );
        for permanent in [0, 2, 3, 80, 183] {
            for is_dir in [false, true] {
                assert!(
                    !is_transient_move_error(permanent, is_dir),
                    "win32 error {permanent} must not be retried"
                );
            }
        }
    }

    #[test]
    fn windows_replace_policy_preserves_fallback_retry_and_source_dispositions() {
        use WindowsReplaceStage::{Open, Rename, Validate};
        for status in [0, 1, i32::MAX] {
            assert!(!windows_rename_failed(status));
        }
        // Failure severity and class support are separate decisions.
        for status in [
            0xC000_0003_u32,
            0xC000_000D,
            0xC000_0010,
            0xC000_00BB,
            0xC000_0022,
            0xC000_0043,
            0xC000_0035,
            0x8000_0001,
        ] {
            assert!(windows_rename_failed(status as i32), "{status:#x}");
        }
        for status in [0xC000_0003_u32, 0xC000_000D, 0xC000_0010, 0xC000_00BB] {
            assert!(windows_rename_class_unsupported(status as i32));
        }
        for status in [0_u32, 1, 0xC000_0022, 0xC000_0043, 0xC000_0035, 0x8000_0001] {
            assert!(!windows_rename_class_unsupported(status as i32));
        }
        for attempt in 0..5 {
            for code in [32, 33] {
                assert_eq!(
                    windows_replace_retry(Open, code, false, attempt),
                    attempt < 4
                );
                assert_eq!(
                    windows_replace_retry(Rename, code, true, attempt),
                    attempt < 4
                );
            }
            assert_eq!(
                windows_replace_retry(Rename, 5, false, attempt),
                attempt < 4
            );
            assert!(!windows_replace_retry(Rename, 5, true, attempt));
            for code in [0, 2, 3, 5, 80, 87, 183] {
                assert!(!windows_replace_retry(Open, code, false, attempt));
                assert!(!windows_replace_retry(Validate, code, false, attempt));
            }
        }
        assert!(windows_replace_source_safe(0x20, 1));
        for attributes in [0x400, 0x10, 0x410] {
            assert!(!windows_replace_source_safe(attributes, 1));
        }
        for links in [0, 2, u32::MAX] {
            assert!(!windows_replace_source_safe(0x20, links));
        }
    }

    #[test]
    fn windows_replace_dispatch_uses_actual_fallback_and_retains_both_statuses() {
        for first in [0xC000_0003_u32, 0xC000_000D, 0xC000_0010, 0xC000_00BB].map(|s| s as i32) {
            let mut trace = Vec::new();
            let result = dispatch_windows_rename(&17, &29, |source, parent, class| {
                trace.push((*source, *parent, class));
                if class == 65 {
                    first
                } else {
                    -7
                }
            });
            assert_eq!(trace, [(17, 29, 65), (17, 29, 10)]);
            assert_eq!(result, Err((first, Some(-7))));
            assert!(dispatch_windows_rename(&17, &29, |_, _, class| {
                if class == 65 {
                    first
                } else {
                    1
                }
            })
            .is_ok());
        }
        for first in [i32::MIN, -1, 0xC000_0022_u32 as i32, 0xC000_0043_u32 as i32] {
            let mut trace = Vec::new();
            let result = dispatch_windows_rename(&17, &29, |source, parent, class| {
                trace.push((*source, *parent, class));
                first
            });
            assert_eq!(trace, [(17, 29, 65)]);
            assert_eq!(result, Err((first, None)));
        }
        for success in [0, 1, i32::MAX] {
            let mut calls = 0;
            assert!(dispatch_windows_rename(&17, &29, |_, _, class| {
                calls += 1;
                assert_eq!(class, 65);
                success
            })
            .is_ok());
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn windows_replace_parent_dispatch_refuses_cross_parent_before_io() {
        let source = Path::new("source-parent");
        let target = Path::new("target-parent");
        let calls = std::cell::Cell::new(0);
        let error = dispatch_windows_replace_parent(source, target, || calls.set(1)).unwrap_err();
        match error {
            PlatformError::AtomicReplaceParentMismatch {
                source_parent,
                target_parent,
            } => {
                assert_eq!(source_parent.as_path(), source);
                assert_eq!(target_parent.as_path(), target);
            }
            other => panic!("expected typed parent refusal, got {other:?}"),
        }
        assert_eq!(
            calls.get(),
            0,
            "mismatch must refuse before the IO callback"
        );
        let value = dispatch_windows_replace_parent(source, source, || {
            calls.set(calls.get() + 1);
            17
        })
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(calls.get(), 1, "same-parent control must dispatch once");
    }

    #[test]
    fn windows_replace_leaf_rejects_aliases_before_dispatch() {
        for bad in [
            "",
            ".",
            "..",
            "name.",
            "name ",
            "name:stream",
            "a/b",
            "a\\b",
            "a\0b",
        ] {
            assert!(!windows_replace_leaf_safe(
                &bad.encode_utf16().collect::<Vec<_>>()
            ));
        }
        for good in ["tmp.123.4", "credentials.json", "non-bmp-😀"] {
            assert!(windows_replace_leaf_safe(
                &good.encode_utf16().collect::<Vec<_>>()
            ));
        }
        assert!(!windows_replace_leaf_safe(&vec![b'a' as u16; 32768]));
    }

    #[test]
    fn atomic_replace_written_private_writer_round_trip() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        let identity = write_new_private_synced_with_identity(&tmp, b"private").unwrap();
        atomic_replace_written(&tmp, &target, identity).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"private");
        assert!(!tmp.exists());
    }

    #[test]
    fn retained_private_writer_publishes_without_replacing_and_owns_cleanup() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let tmp = dir.path().join("tmp");
        let writer = write_new_private_synced_retained(&tmp, b"complete").unwrap();
        assert!(!target.exists());
        assert_eq!(
            writer.publish_noreplace(&target).unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(fs::read(&target).unwrap(), b"complete");
        assert!(!tmp.exists());
        let writer = write_new_private_retained(&tmp, b"second").unwrap();
        assert_eq!(
            writer.publish_noreplace(&target).unwrap(),
            PublishOutcome::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"complete");
        assert!(!tmp.exists());
        let writer = write_new_private_retained(&tmp, b"discarded").unwrap();
        writer.discard();
        assert!(!tmp.exists());
        let writer = write_new_private_retained(&tmp, b"recoverable").unwrap();
        writer.keep();
        assert_eq!(fs::read(&tmp).unwrap(), b"recoverable");
    }

    #[test]
    fn retained_private_writer_does_not_clean_an_uncreated_file() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("preexisting");
        fs::write(&tmp, b"foreign").unwrap();
        assert!(write_new_private_retained(&tmp, b"secret").is_err());
        assert_eq!(fs::read(&tmp).unwrap(), b"foreign");
    }

    #[test]
    fn private_tmp_writer_retries_a_real_create_collision_and_preserves_foreign_file() {
        for synced in [false, true] {
            let dir = TempDir::new().unwrap();
            let target = dir.path().join("target");
            let first = dir.path().join("stale");
            let second = dir.path().join("fresh");
            fs::write(&first, b"foreign").unwrap();
            let expected_target = target.clone();
            let candidates = [first.clone(), second.clone()];
            with_private_tmp_candidates_for_test(
                move |actual_target, attempt| {
                    assert_eq!(actual_target, expected_target.as_path());
                    candidates[attempt].clone()
                },
                || {
                    let writer = if synced {
                        write_private_tmp_synced_retained(&target, b"ours")
                    } else {
                        write_private_tmp_retained(&target, b"ours")
                    }
                    .expect("one pre-existing candidate must not fail the save");
                    assert_eq!(writer.path(), second.as_path());
                    secure_file(writer.path()).unwrap();
                    writer.replace(&target).unwrap();
                },
            );
            assert_eq!(fs::read(&first).unwrap(), b"foreign");
            assert_eq!(fs::read(&target).unwrap(), b"ours");
            assert!(!second.exists());
        }
    }

    #[test]
    fn private_tmp_writer_stops_after_eight_real_create_collisions() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let candidates: Vec<_> = (0..8)
            .map(|attempt| dir.path().join(format!("stale-{attempt}")))
            .collect();
        for candidate in &candidates {
            fs::write(candidate, b"foreign").unwrap();
        }
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let supplied = candidates.clone();
        let error = with_private_tmp_candidates_for_test(
            move |_, attempt| {
                assert_eq!(attempt, observed_calls.get());
                observed_calls.set(observed_calls.get() + 1);
                supplied[attempt].clone()
            },
            || write_private_tmp_synced_retained(&target, b"ours").unwrap_err(),
        );
        assert!(matches!(
            error,
            PlatformError::Io(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(calls.get(), 8);
        assert!(!target.exists());
        for candidate in candidates {
            assert_eq!(fs::read(candidate).unwrap(), b"foreign");
        }
    }

    #[test]
    fn private_tmp_writer_does_not_retry_other_create_errors() {
        let dir = TempDir::new().unwrap();
        let missing_parent = dir.path().join("absent-parent").join("tmp");
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        with_private_tmp_candidates_for_test(
            move |_, _| {
                observed_calls.set(observed_calls.get() + 1);
                missing_parent.clone()
            },
            || assert!(write_private_tmp_retained(&dir.path().join("target"), b"ours").is_err()),
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn private_create_observer_plants_real_collisions_for_both_constructor_paths() {
        for retrying in [false, true] {
            let dir = TempDir::new().unwrap();
            let target = dir.path().join("target");
            let collision = std::rc::Rc::new(std::cell::RefCell::new(None));
            let planted = collision.clone();
            let result = with_private_create_observer_for_test(
                move |path| {
                    if planted.borrow().is_none() {
                        fs::write(path, b"foreign").unwrap();
                        *planted.borrow_mut() = Some(path.to_path_buf());
                    }
                },
                || {
                    if retrying {
                        write_private_tmp_retained(&target, b"ours")
                    } else {
                        write_new_private_retained(&dir.path().join("explicit"), b"ours")
                    }
                },
            );
            let collision = collision.borrow().clone().unwrap();
            assert_eq!(fs::read(&collision).unwrap(), b"foreign");
            if retrying {
                let writer =
                    result.expect("a planted first-create collision must not fail the save");
                assert_ne!(writer.path(), collision.as_path());
                writer.replace(&target).unwrap();
                assert_eq!(fs::read(&target).unwrap(), b"ours");
            } else {
                assert!(matches!(
                    result,
                    Err(PlatformError::Io(ref error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists
                ));
            }
        }
    }

    #[test]
    fn private_create_observer_restores_outer_scope_after_unwind() {
        let dir = TempDir::new().unwrap();
        let outer = std::rc::Rc::new(std::cell::Cell::new(0));
        let outer_seen = outer.clone();
        with_private_create_observer_for_test(
            move |_| outer_seen.set(outer_seen.get() + 1),
            || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    with_private_create_observer_for_test(
                        |_| panic!("create observer unwind control"),
                        || {
                            let _ = write_new_private_retained(&dir.path().join("inner"), b"ours");
                        },
                    );
                }));
                assert!(result.is_err());
                assert!(!dir.path().join("inner").exists());
                write_new_private_retained(&dir.path().join("outer"), b"ours")
                    .unwrap()
                    .discard();
                assert_eq!(outer.get(), 1);
            },
        );
    }

    #[test]
    fn retained_private_writer_replaces_complete_target() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::write(&target, b"old").unwrap();
        write_new_private_synced_retained(&tmp, b"new")
            .unwrap()
            .replace(&target)
            .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists());
    }

    #[test]
    fn private_sync_observer_records_success_before_publication_only() {
        let dir = TempDir::new().unwrap();
        let synced = dir.path().join("synced");
        let target = dir.path().join("published");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed = seen.clone();
        with_private_sync_observer_for_test(
            move |path| observed.borrow_mut().push(path.to_path_buf()),
            || {
                write_new_private_retained(&dir.path().join("unsynced"), b"plain")
                    .unwrap()
                    .discard();
                assert!(seen.borrow().is_empty());
                let writer = write_new_private_synced_retained(&synced, b"durable").unwrap();
                assert_eq!(*seen.borrow(), vec![synced.clone()]);
                assert!(!target.exists(), "sync witness must precede publication");
                writer.replace(&target).unwrap();
                assert!(write_new_private_synced_retained(&target, b"collision").is_err());
                assert_eq!(
                    seen.borrow().len(),
                    1,
                    "failed creates must not report sync"
                );
            },
        );
        write_new_private_synced_retained(&dir.path().join("outside"), b"outside")
            .unwrap()
            .discard();
        assert_eq!(seen.borrow().len(), 1, "observer must be scoped");
    }

    #[test]
    fn private_sync_observer_restores_outer_scope_after_unwind() {
        let dir = TempDir::new().unwrap();
        let outer = std::rc::Rc::new(std::cell::Cell::new(0));
        let outer_seen = outer.clone();
        let inner = std::rc::Rc::new(std::cell::Cell::new(0));
        let inner_seen = inner.clone();
        let tmp = dir.path().join("tmp");
        with_private_sync_observer_for_test(
            move |_| outer_seen.set(outer_seen.get() + 1),
            || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    with_private_sync_observer_for_test(
                        move |_| {
                            inner_seen.set(inner_seen.get() + 1);
                            panic!("observer unwind control");
                        },
                        || {
                            let _ = write_new_private_synced_retained(&tmp, b"inner");
                        },
                    );
                }));
                assert!(result.is_err());
                assert!(!tmp.exists(), "panicking observers retain owned cleanup");
                write_new_private_synced_retained(&tmp, b"outer")
                    .unwrap()
                    .discard();
                assert_eq!(outer.get(), 1, "outer observer must be restored");
                assert_eq!(inner.get(), 1);
            },
        );
    }

    #[test]
    fn retained_private_writer_cleans_failed_replacement() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("resident"), b"unchanged").unwrap();
        let writer = write_new_private_retained(&tmp, b"secret").unwrap();
        assert!(writer.replace(&target).is_err());
        assert!(!tmp.exists());
        assert_eq!(fs::read(target.join("resident")).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn retained_private_writer_preserves_a_foreign_replacement_on_drop() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let parked = dir.path().join("parked");
        let writer = write_new_private_retained(&tmp, b"ours").unwrap();
        fs::rename(&tmp, &parked).unwrap();
        fs::write(&tmp, b"foreign").unwrap();
        drop(writer);
        assert_eq!(fs::read(&tmp).unwrap(), b"foreign");
        assert_eq!(fs::read(&parked).unwrap(), b"ours");
    }

    #[cfg(unix)]
    #[test]
    fn retained_private_writer_warns_when_foreign_replacement_prevents_cleanup() {
        type Fields = std::collections::BTreeMap<String, String>;
        type Events = std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, Fields)>>>;
        struct Capture(Events);
        struct Visitor(Fields);
        impl tracing::field::Visit for Visitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                *metadata.level() == tracing::Level::WARN
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut visitor = Visitor(Fields::new());
                event.record(&mut visitor);
                self.0
                    .lock()
                    .unwrap()
                    .push((*event.metadata().level(), visitor.0));
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("private-parent-payload.tmp");
        let parked = dir.path().join("parked");
        let writer = write_new_private_retained(&tmp, b"ours").unwrap();
        fs::rename(&tmp, &parked).unwrap();
        fs::write(&tmp, b"foreign").unwrap();
        let events: Events = Default::default();
        tracing::subscriber::with_default(Capture(events.clone()), || drop(writer));
        assert_eq!(fs::read(&tmp).unwrap(), b"foreign");
        assert_eq!(fs::read(&parked).unwrap(), b"ours");
        let events = events.lock().unwrap();
        assert_eq!(
            events.len(),
            1,
            "ownership skip must emit its fixed warning"
        );
        assert_eq!(events[0].0, tracing::Level::WARN);
        let expected = Fields::from([
            (
                "error_kind".to_owned(),
                "private_tmp_cleanup_ownership_unconfirmed".to_owned(),
            ),
            (
                "message".to_owned(),
                "private temporary file cleanup skipped".to_owned(),
            ),
        ]);
        assert_eq!(
            events[0].1, expected,
            "warning must expose no path or payload"
        );
    }

    #[test]
    fn windows_file_identity_prefers_modern_without_legacy_query() {
        let expected = WindowsFileIdentity::modern(1_u64 << 63, [0x80; 16]);
        let actual = query_windows_file_identity(
            || Ok(expected),
            || panic!("modern success must not query the legacy identity"),
        );
        assert_eq!(actual.unwrap(), expected);
    }

    #[test]
    fn windows_file_identity_unsupported_queries_legacy() {
        for code in [1, 50, 87] {
            let called = std::cell::Cell::new(false);
            let expected = WindowsFileIdentity::legacy(17, 0x8123_4567, 0x89ab_cdef);
            let actual = query_windows_file_identity(
                || Err(std::io::Error::from_raw_os_error(code)),
                || {
                    called.set(true);
                    Ok(expected)
                },
            );
            assert_eq!(actual.unwrap(), expected, "unsupported error {code}");
            assert!(called.get(), "unsupported error {code} must query legacy");
        }
    }

    #[test]
    fn windows_file_identity_hard_errors_do_not_query_legacy() {
        for code in [2, 5, 6, 32, 1117] {
            let error = query_windows_file_identity(
                || Err(std::io::Error::from_raw_os_error(code)),
                || panic!("hard error {code} must not query legacy"),
            )
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
        }
        let error = query_windows_file_identity(
            || Err(std::io::Error::other("unclassified query error")),
            || panic!("an error without an OS code must not query legacy"),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), None);
        assert_eq!(error.to_string(), "unclassified query error");
    }

    #[test]
    fn windows_file_identity_legacy_query_failure_propagates() {
        let error = query_windows_file_identity(
            || Err(std::io::Error::from_raw_os_error(50)),
            || Err(std::io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
    }

    #[test]
    fn windows_file_identity_sources_and_all_bits_compare_unequal() {
        let original = WindowsFileIdentity::modern(17, [0; 16]);
        assert_ne!(original, WindowsFileIdentity::legacy(17, 0, 0));
        let mut high_bit = [0; 16];
        high_bit[15] = 0x80;
        assert_ne!(original, WindowsFileIdentity::modern(17, high_bit));
        assert_ne!(
            original,
            WindowsFileIdentity::modern(17 | (1_u64 << 63), [0; 16])
        );
        let legacy = WindowsFileIdentity::legacy(17, 0x8123_4567, 0x89ab_cdef);
        assert_eq!(legacy.volume_serial, 17);
        assert_eq!(
            legacy.file_id,
            WindowsFileId::Legacy64(0x8123_4567_89ab_cdef)
        );
        assert_ne!(
            legacy,
            WindowsFileIdentity::legacy(18, 0x8123_4567, 0x89ab_cdef)
        );
        assert_ne!(
            legacy,
            WindowsFileIdentity::legacy(17, 0x8123_4566, 0x89ab_cdef)
        );
        assert_ne!(
            legacy,
            WindowsFileIdentity::legacy(17, 0x8123_4567, 0x89ab_cdee)
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_written_identity_compares_all_file_id_bits_and_volume() {
        use windows_sys::Win32::Storage::FileSystem::{FILE_ID_128, FILE_ID_INFO};
        let mut info = FILE_ID_INFO {
            VolumeSerialNumber: 17,
            FileId: FILE_ID_128 {
                Identifier: [0; 16],
            },
        };
        let original = WrittenFileIdentity::from_information(&info);
        info.FileId.Identifier[15] = 1;
        assert_ne!(WrittenFileIdentity::from_information(&info), original);
        info.FileId.Identifier[15] = 0;
        info.VolumeSerialNumber |= 1_u64 << 63;
        assert_ne!(WrittenFileIdentity::from_information(&info), original);
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_retained_noreplace_has_no_empty_claim_and_rejects_competing_writers() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::DELETE;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                drop(REPLACE_BEFORE_RENAME.with(|h| h.borrow_mut().take()));
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        let writer = write_new_private_retained(&tmp, b"complete").unwrap();
        let source = tmp.clone();
        let destination = target.clone();
        let called = std::rc::Rc::new(std::cell::Cell::new(false));
        let seen = called.clone();
        REPLACE_BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |plain| {
                assert!(plain, "no-replace uses FileRenameInformation");
                assert_eq!(
                    fs::symlink_metadata(&destination).unwrap_err().kind(),
                    std::io::ErrorKind::NotFound
                );
                assert!(fs::OpenOptions::new()
                    .write(true)
                    .share_mode(7)
                    .open(&source)
                    .is_err());
                assert!(fs::OpenOptions::new()
                    .access_mode(DELETE)
                    .share_mode(7)
                    .open(&source)
                    .is_err());
                assert!(fs::rename(&source, source.with_extension("moved")).is_err());
                seen.set(true);
            }))
        });
        assert_eq!(
            writer.publish_noreplace(&target).unwrap(),
            PublishOutcome::Published
        );
        assert!(called.get());
        assert_eq!(fs::read(&target).unwrap(), b"complete");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_retained_noreplace_maps_a_racing_collision_without_overwrite() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                drop(REPLACE_BEFORE_RENAME.with(|h| h.borrow_mut().take()));
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        let writer = write_new_private_retained(&tmp, b"secret").unwrap();
        let destination = target.clone();
        REPLACE_BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |plain| {
                assert!(plain);
                assert!(!destination.exists());
                fs::write(&destination, b"racer").unwrap();
            }))
        });
        assert_eq!(
            writer.publish_noreplace(&target).unwrap(),
            PublishOutcome::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"racer");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_retained_replace_keeps_original_writer_through_both_classes() {
        use std::os::windows::fs::OpenOptionsExt;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_FORCE_LEGACY.with(|f| f.set(false));
                drop(REPLACE_BEFORE_RENAME.with(|h| h.borrow_mut().take()));
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::write(&target, b"old").unwrap();
        let writer = write_new_private_synced_retained(&tmp, b"new").unwrap();
        let identity = written_file_identity(writer.file.as_ref().unwrap()).unwrap();
        let source = tmp.clone();
        let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = trace.clone();
        REPLACE_FORCE_LEGACY.with(|f| f.set(true));
        REPLACE_BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |plain| {
                seen.borrow_mut().push(plain);
                assert!(fs::OpenOptions::new()
                    .write(true)
                    .share_mode(7)
                    .open(&source)
                    .is_err());
                assert!(fs::rename(&source, source.with_extension("moved")).is_err());
            }))
        });
        writer.replace(&target).unwrap();
        assert_eq!(*trace.borrow(), [false, true]);
        let published = super::super::fs_windows_acl::open_private_readable(&target).unwrap();
        super::super::fs_windows_acl::check_private_handle(&published).unwrap();
        assert_eq!(written_file_identity(&published).unwrap(), identity);
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_retained_writer_rejects_a_different_parent_leaf_and_cleans_own_handle() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let foreign = dir.path().join("foreign");
        let target = dir.path().join("target");
        let mut writer = write_new_private_retained(&tmp, b"secret").unwrap();
        write_new_private(&foreign, b"foreign").unwrap();
        writer.path = foreign.clone();
        assert!(writer.replace(&target).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"foreign");
        assert!(!tmp.exists(), "cleanup follows the writer handle");
        assert!(!target.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_replace_failure_display_exposes_leaves_without_parent_paths() {
        let source = Path::new(r"C:\PRIVATE_USER_ROOT\SOURCE_ONLY\token.tmp");
        let target = Path::new(r"C:\PRIVATE_USER_ROOT\DESTINATION_ONLY\token.json");
        for attempt in [0, 4] {
            let error = WindowsReplaceFailure::io(
                WindowsReplaceStage::Open,
                "NtCreateFile(source)",
                std::io::Error::from_raw_os_error(32),
            )
            .into_platform(source, target, attempt);
            let message = error.to_string();
            assert!(message.contains("atomic_replace"), "{message}");
            for leaf in ["token.tmp", "token.json"] {
                assert!(message.contains(leaf), "missing leaf: {message}");
            }
            for parent in ["PRIVATE_USER_ROOT", "SOURCE_ONLY", "DESTINATION_ONLY"] {
                assert!(!message.contains(parent), "parent path leaked: {message}");
            }
            assert_eq!(message.contains("after 5 attempts"), attempt == 4);
        }
    }

    #[test]
    fn windows_atomic_replace_parent_mismatch_display_exposes_leaves_without_ancestors() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("source-parent");
        let target = dir.path().join("target-parent");
        let error = dispatch_windows_replace_parent(&source, &target, || ()).unwrap_err();
        let message = error.to_string();
        for expected in ["atomic_replace", "source-parent", "target-parent"] {
            assert!(message.contains(expected), "missing context: {message}");
        }
        assert!(
            !message.contains(dir.path().to_string_lossy().as_ref()),
            "{message}"
        );
        match error {
            PlatformError::AtomicReplaceParentMismatch {
                source_parent,
                target_parent,
            } => {
                assert_eq!(source_parent, source);
                assert_eq!(target_parent, target);
            }
            other => panic!("typed mismatch was lost: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_refuses_junction_before_both_rename_paths() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_FORCE_LEGACY.with(|f| f.set(false));
                let _ = REPLACE_BEFORE_RENAME.with(|h| h.borrow_mut().take());
            }
        }
        let _reset = Reset;
        for legacy in [false, true] {
            let dir = TempDir::new().unwrap();
            let real = dir.path().join("real-directory");
            fs::create_dir(&real).unwrap();
            fs::write(real.join("resident"), b"unchanged").unwrap();
            let target = dir.path().join("token.json");
            crate::platform::fs_symlink_windows::symlink_exclusive(&real, &target).unwrap();
            let tmp = dir.path().join("token.tmp");
            let identity = write_new_private_with_identity(&tmp, b"new").unwrap();
            let calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let seen = calls.clone();
            REPLACE_FORCE_LEGACY.with(|f| f.set(legacy));
            REPLACE_BEFORE_RENAME.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |_| seen.set(seen.get() + 1)));
            });
            for result in [
                atomic_replace(&tmp, &target),
                atomic_replace_written(&tmp, &target, identity),
            ] {
                let error = result.expect_err("junction destination must be refused before rename");
                assert!(matches!(error, PlatformError::Win32 { code: 5, .. }));
            }
            assert_eq!(
                calls.get(),
                0,
                "destination refusal must precede rename dispatch"
            );
            use std::os::windows::fs::MetadataExt;
            assert_eq!(
                fs::symlink_metadata(&target).unwrap().file_attributes() & 0x410,
                0x410
            );
            assert_eq!(fs::read(&tmp).unwrap(), b"new");
            assert_eq!(fs::read(real.join("resident")).unwrap(), b"unchanged");
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_replace_failure_keeps_posix_primary_and_plain_secondary() {
        use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
        let posix = 0xC000_0003_u32 as i32;
        let plain = 0xC000_0022_u32 as i32;
        // SAFETY: pure NTSTATUS translations with no pointer arguments.
        let code = unsafe { RtlNtStatusToDosError(posix) };
        let failure = WindowsReplaceFailure {
            stage: WindowsReplaceStage::Rename,
            code,
            api: "rename",
            nt: Some((posix, Some(plain))),
        };
        assert_eq!(failure.retry_code(), 5);
        match failure.into_platform(Path::new("tmp"), Path::new("target"), 0) {
            PlatformError::Win32 {
                code: reported,
                message,
            } => {
                assert_eq!(reported, code);
                assert!(message.contains("posix_nt_status=0xc0000003"));
                assert!(message.contains("plain_nt_status=0xc0000022"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_rejects_cross_parent_with_typed_paths() {
        let dir = TempDir::new().unwrap();
        let from = dir.path().join("from");
        let to = dir.path().join("to");
        fs::create_dir(&from).unwrap();
        fs::create_dir(&to).unwrap();
        let tmp = from.join("tmp");
        let target = to.join("target");
        let identity = write_new_private_with_identity(&tmp, b"source").unwrap();
        fs::write(&target, b"old").unwrap();
        for result in [
            atomic_replace(&tmp, &target),
            atomic_replace_written(&tmp, &target, identity),
        ] {
            match result.unwrap_err() {
                PlatformError::AtomicReplaceParentMismatch {
                    source_parent,
                    target_parent,
                } => {
                    assert_eq!(source_parent, from);
                    assert_eq!(target_parent, to);
                }
                other => panic!("expected typed parent refusal, got {other:?}"),
            }
        }
        assert_eq!(fs::read(&tmp).unwrap(), b"source");
        assert_eq!(fs::read(&target).unwrap(), b"old");
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_refuses_alias_leaves_before_lookup() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        fs::write(&tmp, b"source").unwrap();
        for bad in ["bad.", "bad ", "bad:stream", ".", ".."] {
            for result in [
                atomic_replace(&tmp, &dir.path().join(bad)),
                atomic_replace(&dir.path().join(bad), &dir.path().join("target")),
            ] {
                assert!(matches!(result, Err(PlatformError::Win32 { code: 87, .. })));
            }
        }
        assert_eq!(fs::read(&tmp).unwrap(), b"source");
        assert!(!dir.path().join("target").exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_written_refuses_changed_identity_and_broad_dacl() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::write(&target, b"old").unwrap();
        let original = write_new_private_with_identity(&tmp, b"original").unwrap();
        let parked = dir.path().join("parked");
        fs::rename(&tmp, &parked).unwrap();
        write_new_private(&tmp, b"substituted").unwrap();
        assert!(atomic_replace_written(&tmp, &target, original).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&parked).unwrap(), b"original");
        fs::remove_file(&tmp).unwrap();
        fs::write(&tmp, b"broad").unwrap();
        let file = fs::File::open(&tmp).unwrap();
        let broad = written_file_identity(&file).unwrap();
        drop(file);
        assert!(atomic_replace_written(&tmp, &target, broad).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        atomic_replace(&tmp, &target).expect("plain publication has no private-DACL policy");
        assert_eq!(fs::read(&target).unwrap(), b"broad");
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_accepts_delete_sharing_lingering_writer() {
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(7)
            .open(&tmp)
            .unwrap();
        writer.write_all(b"written").unwrap();
        atomic_replace(&tmp, &target).expect("READ|WRITE sharing accepts the open writer");
        drop(writer);
        assert_eq!(fs::read(&target).unwrap(), b"written");
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_pins_parent_before_relative_source_lookup() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::DELETE;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_AFTER_PARENT_PIN.with(|h| h.borrow_mut().take());
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original");
        let alternate = dir.path().join("alternate");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&alternate).unwrap();
        let alias = dir.path().join("alias");
        crate::platform::fs_symlink_windows::symlink_exclusive(&original, &alias).unwrap();
        let tmp = alias.join("tmp");
        let target = alias.join("target");
        let identity = write_new_private_with_identity(&tmp, b"original").unwrap();
        write_new_private(&alternate.join("tmp"), b"alternate").unwrap();
        let parked = dir.path().join("parked-alias");
        let moved_alias = alias.clone();
        let alternate_path = alternate.clone();
        let original_source = original.join("tmp");
        REPLACE_AFTER_PARENT_PIN.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let probe = fs::OpenOptions::new()
                    .access_mode(DELETE)
                    .share_mode(7)
                    .open(&original_source)
                    .expect("source must not be held before parent pinning");
                drop(probe);
                fs::rename(&moved_alias, &parked).unwrap();
                crate::platform::fs_symlink_windows::symlink_exclusive(
                    &alternate_path,
                    &moved_alias,
                )
                .unwrap();
            }))
        });
        atomic_replace_written(&tmp, &target, identity).unwrap();
        assert_eq!(fs::read(original.join("target")).unwrap(), b"original");
        assert!(!original.join("tmp").exists());
        assert_eq!(fs::read(alternate.join("tmp")).unwrap(), b"alternate");
        assert!(!alternate.join("target").exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_publishes_past_delete_sharing_reader() {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let tmp = dir.path().join("tmp");
        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();
        let mut reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(&target)
            .unwrap();
        atomic_replace(&tmp, &target).expect("POSIX replacement must unlink a held target");
        let mut old = Vec::new();
        reader.read_to_end(&mut old).unwrap();
        assert_eq!(old, b"old");
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_retries_source_open_sharing() {
        use std::os::windows::fs::OpenOptionsExt;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_AFTER_FAILURE.with(|h| h.borrow_mut().take());
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let tmp = dir.path().join("tmp");
        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();
        let mut held = Some(
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&tmp)
                .unwrap(),
        );
        let seen = std::rc::Rc::new(std::cell::Cell::new(0));
        let failures = seen.clone();
        REPLACE_AFTER_FAILURE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |stage, code| {
                assert_eq!(stage, WindowsReplaceStage::Open);
                assert_eq!(code, 32);
                failures.set(failures.get() + 1);
                drop(held.take());
            }))
        });
        atomic_replace(&tmp, &target)
            .expect("source open32 must retry after the deterministic release");
        assert_eq!(seen.get(), 1);
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_parent_and_source_share_five_attempts() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_AFTER_FAILURE.with(|h| h.borrow_mut().take());
                REPLACE_AFTER_PARENT_PIN.with(|h| h.borrow_mut().take());
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::write(&tmp, b"new").unwrap();
        fs::write(&target, b"old").unwrap();
        let source = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&tmp)
            .unwrap();
        let mut parent = Some(
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(dir.path())
                .unwrap(),
        );
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let failures = seen.clone();
        REPLACE_AFTER_FAILURE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |stage, code| {
                failures.borrow_mut().push((stage, code));
                drop(parent.take());
            }))
        });
        let pins = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = pins.clone();
        REPLACE_AFTER_PARENT_PIN
            .with(|h| *h.borrow_mut() = Some(Box::new(move || count.set(count.get() + 1))));
        let error = atomic_replace(&tmp, &target).unwrap_err();
        drop(source);
        assert_eq!(
            &*seen.borrow(),
            &[
                (WindowsReplaceStage::Rename, 32),
                (WindowsReplaceStage::Open, 32),
                (WindowsReplaceStage::Open, 32),
                (WindowsReplaceStage::Open, 32),
                (WindowsReplaceStage::Open, 32)
            ]
        );
        assert_eq!(pins.get(), 1);
        assert!(
            matches!(error, PlatformError::Win32 { code: 32, ref message }
            if message.contains("after 5 attempts"))
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&tmp).unwrap(), b"new");
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_refuses_post_validation_source_swap_in_both_rename_paths() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REPLACE_FORCE_LEGACY.with(|f| f.set(false));
                let _ = REPLACE_BEFORE_RENAME.with(|h| h.borrow_mut().take());
            }
        }
        let _reset = Reset;
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp");
        let target = dir.path().join("target");
        fs::write(&tmp, b"checked-source").unwrap();
        fs::write(&target, b"old").unwrap();
        let phases = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = phases.clone();
        let source = tmp.clone();
        let parked = dir.path().join("parked");
        REPLACE_FORCE_LEGACY.with(|f| f.set(true));
        REPLACE_BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |legacy| {
                seen.borrow_mut().push(legacy);
                assert!(
                    fs::rename(&source, &parked).is_err(),
                    "checked source must deny competing rename"
                );
                use std::os::windows::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::DELETE;
                assert!(
                    fs::OpenOptions::new()
                        .access_mode(DELETE)
                        .share_mode(7)
                        .open(&source)
                        .is_err(),
                    "checked source must deny competing delete opens"
                );
                assert!(
                    fs::OpenOptions::new()
                        .write(true)
                        .share_mode(7)
                        .open(&source)
                        .is_ok(),
                    "READ|WRITE sharing intentionally permits content writers"
                );
            }))
        });
        atomic_replace(&tmp, &target).expect("plain handle fallback must replace the target");
        assert_eq!(*phases.borrow(), [false, true]);
        assert_eq!(fs::read(&target).unwrap(), b"checked-source");
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_refuses_unsafe_source_entries() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let hardlink = dir.path().join("hardlink");
        fs::hard_link(&victim, &hardlink).unwrap();
        let directory = dir.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let junction = dir.path().join("junction");
        crate::platform::fs_symlink_windows::symlink_exclusive(&directory, &junction).unwrap();
        for source in [&hardlink, &directory, &junction] {
            let target = dir.path().join("absent-target");
            let err = atomic_replace(source, &target).expect_err("unsafe source must be refused");
            assert!(matches!(err, PlatformError::Win32 { code: 87, .. }));
            assert!(!target.exists());
            assert!(
                fs::symlink_metadata(source).is_ok(),
                "source entry must survive refusal"
            );
        }
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_follows_parent_junction_and_preserves_private_dacl() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let parent = dir.path().join("parent");
        crate::platform::fs_symlink_windows::symlink_exclusive(&real, &parent).unwrap();
        let tmp = parent.join("tmp");
        let target = parent.join("target");
        let identity = write_new_private_with_identity(&tmp, b"private").unwrap();
        // The destination starts broad; the protected source DACL must travel
        // with its inode instead of inheriting this destination's descriptor.
        fs::write(&target, b"old").unwrap();
        atomic_replace_written(&tmp, &target, identity)
            .expect("parent junction must retain legacy traversal");
        assert_eq!(fs::read(real.join("target")).unwrap(), b"private");
        let file = crate::platform::fs_windows_acl::open_private_readable(&target).unwrap();
        crate::platform::fs_windows_acl::check_private_handle(&file).unwrap();
        assert!(!real.join("tmp").exists());
        assert!(fs::symlink_metadata(&parent)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Native: a JUNCTION target (directory reparse point) is a permanent
    /// access-denied and must fail on the first attempt. RED under the old
    /// `Metadata::is_dir()` test, which reports a junction as a symlink, so
    /// the 5x100ms retry ran: that path cannot return before its four
    /// enforced 100ms sleeps (>= 400ms), while a fast fail returns in
    /// milliseconds — the 300ms bound separates the two with margin on both
    /// sides (a slow fast-fail can false-RED, never false-GREEN).
    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_fails_fast_on_junction_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-dir");
        std::fs::create_dir(&real).unwrap();
        let target = dir.path().join("token.json");
        crate::platform::fs_symlink_windows::symlink_exclusive(&real, &target).unwrap();
        let tmp = dir.path().join("token.json.tmp");
        std::fs::write(&tmp, b"new").unwrap();
        let started = std::time::Instant::now();
        let result = atomic_replace(&tmp, &target);
        let elapsed = started.elapsed();
        match result {
            Err(PlatformError::Win32 { code, message }) => {
                assert_eq!(code, 5, "junction target must be access-denied");
                assert!(
                    message.contains("destination directory validation"),
                    "destination refusal must name its validation operation: {message}"
                );
                assert!(
                    !message.contains("attempts"),
                    "junction target must not take the retry path: {message}"
                );
            }
            other => panic!("junction target must be refused, got {other:?}"),
        }
        assert!(
            elapsed < std::time::Duration::from_millis(300),
            "junction target must fail fast, took {elapsed:?}"
        );
        assert!(real.is_dir(), "junction's real directory must be untouched");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"new", "tmp must survive");
    }

    /// Native: a target held open with `share_mode(0)` makes rename
    /// fail transiently; once the holder releases it (~150ms, inside the
    /// 5x100ms budget) `atomic_replace` must succeed and publish the new
    /// bytes. RED if access-denied/sharing were not retried.
    #[cfg(windows)]
    #[test]
    fn native_windows_atomic_replace_survives_briefly_held_target() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("token.json");
        std::fs::write(&target, b"old").unwrap();
        let tmp = dir.path().join("token.json.tmp");
        std::fs::write(&tmp, b"new").unwrap();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder_path = target.clone();
        let holder = std::thread::spawn(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&holder_path)
                .unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(file);
        });
        held_rx.recv().unwrap();
        let result = atomic_replace(&tmp, &target);
        holder.join().unwrap();
        result.expect("atomic_replace must retry past a briefly held target");
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!tmp.exists(), "tmp must be consumed on success");
    }
}
