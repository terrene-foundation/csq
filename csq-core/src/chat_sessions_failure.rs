//! Diagnostic carrier for `StoreError::Io`: a fixed-vocabulary stage tag plus the
//! raw OS error code, never a path, message or content.
use super::StoreError;
use std::io;

/// Where a [`StoreError::Io`] arose: a fixed-vocabulary stage tag (never a path
/// or content), the raw OS error code when the failing call had one, and, for a
/// fallback that also failed, the first attempt's Win32 code (`ex_os_error`) and
/// `NTSTATUS` (`ex_nt_status`), and the raw `NTSTATUS` (`nt_status`) of the failing
/// `Nt*` call. Diagnostic only; `Display`
/// stays the fixed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoFailure {
    pub stage: &'static str,
    pub os_error: Option<i32>,
    pub ex_os_error: Option<i32>,
    pub ex_nt_status: Option<i32>,
    pub nt_status: Option<i32>,
}
impl StoreError {
    /// An I/O failure at `stage` with no OS error code (e.g. a refused invariant).
    #[cfg(not(unix))]
    pub(crate) const fn io(stage: &'static str) -> Self {
        Self::Io(IoFailure {
            stage,
            os_error: None,
            ex_os_error: None,
            ex_nt_status: None,
            nt_status: None,
        })
    }
    /// An I/O failure at `stage` carrying the raw OS code of `error`, never
    /// reclassified to `NotFound` / `AlreadyExists` (unlike `io_error`).
    pub(crate) fn io_os(stage: &'static str, error: &io::Error) -> Self {
        Self::Io(IoFailure {
            stage,
            os_error: error.raw_os_error(),
            ex_os_error: None,
            ex_nt_status: None,
            nt_status: None,
        })
    }
}
/// [`io_error`] for a call whose failure should name its `stage` in the
/// resulting [`StoreError::Io`] (only the raw OS code is kept, never the message).
pub(super) fn io_error_at(stage: &'static str, error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::NotFound => StoreError::NotFound,
        io::ErrorKind::AlreadyExists => StoreError::AlreadyExists,
        _ => StoreError::Io(IoFailure {
            stage,
            os_error: error.raw_os_error(),
            ex_os_error: None,
            ex_nt_status: None,
            nt_status: None,
        }),
    }
}
