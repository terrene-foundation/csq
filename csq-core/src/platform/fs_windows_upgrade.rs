//! The Windows applier of `label_upgrade`: open without reparse traversal, prove the
//! object is still inside csq's locations, and ensure the private label.
use super::{
    fs_windows_acl::PrivateAclError,
    fs_windows_stamp::{ensure_private_handle_detailed, EnsureFailure, Ensured},
    label_upgrade::{Kind, Outcome, Roots},
};
use std::{
    fs::File,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_OWNER,
};

const READ_CONTROL: u32 = 0x0002_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// `path` resolved (links followed) to its final path by `GetFinalPathNameByHandleW`, the
/// SAME call that produces each object's final path in [`upgrade_label`], so the two
/// sides of the containment comparison are spelled identically and compare exactly.
fn resolved_path(path: &Path) -> Option<String> {
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    final_path(&file)
}

/// The per-object upgrade closure for a pass over `base` (and the gemini file under
/// `home`). Roots are canonicalised once, before any background hand-off.
pub(super) fn applier(
    base: &Path,
    home: Option<&Path>,
) -> impl Fn(&Path, Kind) -> Outcome + Send + 'static {
    let roots = Roots::from_final_paths(
        resolved_path(base).as_deref(),
        home.and_then(|h| resolved_path(&h.join(".gemini").join("oauth_creds.json")))
            .as_deref(),
    );
    roots.warn_if_base_unresolved();
    move |path, kind| upgrade_label(path, kind, &roots)
}

fn final_path(file: &File) -> Option<String> {
    let mut buffer = vec![0u16; 1024];
    for _ in 0..2 {
        // SAFETY: live handle; `buffer` is a valid writable slice of the stated length.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as isize,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                0, // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
            )
        } as usize;
        if written == 0 || written > 32_768 {
            return None;
        }
        if written < buffer.len() {
            return String::from_utf16(&buffer[..written]).ok();
        }
        buffer = vec![0u16; written + 1];
    }
    None
}

fn link_count(file: &File) -> Option<u32> {
    // SAFETY: zero is a valid buffer; filled synchronously from the live handle.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    (unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } != 0)
        .then_some(info.nNumberOfLinks)
}

/// Opens `path` with `READ_CONTROL|WRITE_OWNER` (a reparse point is opened itself,
/// never followed; sharing includes DELETE so a concurrent `atomic_replace` is not
/// refused by a sharing violation, though it can still see ACCESS_DENIED while the
/// handle is open, which its retry absorbs), requires the handle's final path to lie
/// inside `roots`, refuses a multiply-linked file, and stamps the private label iff
/// owner and DACL are exactly private. Anything else is left untouched.
pub(super) fn upgrade_label(path: &Path, kind: Kind, roots: &Roots) -> Outcome {
    use std::os::windows::fs::MetadataExt;
    let opened = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_OWNER | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Outcome::Gone,
        Err(_) => return Outcome::Denied,
    };
    let Ok(meta) = file.metadata() else {
        return Outcome::Denied;
    };
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Outcome::Reparse;
    }
    if meta.is_dir() != (kind == Kind::Dir) {
        return Outcome::Gone;
    }
    // An intermediate component swapped for a junction resolves elsewhere (`Reparse`); an
    // unreadable final path (`Unresolvable`) or an unresolved base (`OutsideRoots`)
    // cannot prove containment. Each is counted on its own.
    if let Some(refusal) = roots.refusal(final_path(&file).as_deref()) {
        return refusal;
    }
    if kind == Kind::File && link_count(&file) != Some(1) {
        return Outcome::Linked;
    }
    match ensure_private_handle_detailed(&file) {
        Ok(Ensured::Already) => Outcome::AlreadyLabeled,
        Ok(Ensured::Stamped) => Outcome::Stamped,
        Err(EnsureFailure::StampFailed) => Outcome::StampFailed,
        Err(EnsureFailure::Refused(PrivateAclError::InheritedLabel)) => Outcome::InheritedLabel,
        Err(EnsureFailure::Refused(_)) => Outcome::NotPrivate,
    }
}
