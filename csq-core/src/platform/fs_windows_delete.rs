//! Handle-bound deletion of a just-created private file.
use std::{fs::File, os::windows::io::AsRawHandle};

/// Removes the file this call just created and failed to verify, THROUGH the
/// handle held (`FileDispositionInfo`, needs `DELETE`; the file goes when the
/// handle closes), not by path: nothing can have been swapped in at that name
/// and deleted instead. Returns whether the deletion was requested; a failure (for
/// example a handle opened without `DELETE`) is logged, never silent, and the caller
/// still returns its own original error.
pub(super) fn delete_created(file: &File) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: live owned handle opened with DELETE; `info` is a valid
    // FILE_DISPOSITION_INFO of the stated size and is not retained.
    let done = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as isize,
            FileDispositionInfo,
            std::ptr::addr_of!(info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if done == 0 {
        tracing::warn!(
            error_kind = "private_acl_created_file_delete_failed",
            "a private file csq just created could not be removed after its check or write failed"
        );
    }
    done != 0
}
