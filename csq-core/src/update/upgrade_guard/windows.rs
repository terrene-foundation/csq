//! Native process discovery and retained-handle authority for Windows upgrades.

use super::{Backend, Candidate, Inspected, QuitChannel, Role};
use anyhow::{bail, Context, Result};
use std::{
    ffi::OsString,
    io::Read,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
        UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Globalization::{CompareStringOrdinal, CSTR_EQUAL},
    Security::{EqualSid, GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    },
    UI::Shell::CommandLineToArgvW,
};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: every constructor transfers one valid, non-pseudo handle here.
        if unsafe { CloseHandle(self.0) } == 0 {
            tracing::warn!(
                error_kind = "upgrade_handle_close_failed",
                "upgrade handle close failed"
            );
        }
    }
}

/// A positively selected process, held open until the policy finishes.
pub struct VerifiedProcess {
    pid: u32,
    birth: u64,
    installed: bool,
    role: Role,
    handle: OwnedHandle,
}

impl VerifiedProcess {
    /// Keeps the retained handle's stop authority aligned with census selection.
    pub(crate) fn set_installed(&mut self, installed: bool) {
        self.installed = installed;
    }
}

/// Does not initialize accounts, a daemon, application state, or csq locks.
pub struct WindowsBackend {
    started: Instant,
    daemon_pid_file: Option<PathBuf>,
    legacy_seen: bool,
    selected_images: Vec<PathBuf>,
    #[cfg(any(test, feature = "test-utils"))]
    owner_fault: Option<OwnerFault>,
}
/// Negative-only native fixture faults. They cannot grant owner authority.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy)]
pub enum OwnerFault {
    Different,
    Unreadable,
}

impl WindowsBackend {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_owner_fault_for_test(mut self, fault: OwnerFault) -> Self {
        self.owner_fault = Some(fault);
        self
    }

    fn inspect_owner(&self, process: HANDLE) -> Result<bool> {
        #[cfg(any(test, feature = "test-utils"))]
        match self.owner_fault {
            Some(OwnerFault::Different) => return Ok(false),
            Some(OwnerFault::Unreadable) => bail!("injected owner query refusal"),
            None => {}
        }
        current_user(process)
    }

    pub fn new(daemon_pid_file: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            started: Instant::now(),
            daemon_pid_file,
            legacy_seen: false,
            selected_images: Vec::new(),
            #[cfg(any(test, feature = "test-utils"))]
            owner_fault: None,
        })
    }
}

fn canonical(path: &Path) -> Result<Vec<u16>> {
    if !path.is_absolute() || path.as_os_str().encode_wide().any(|ch| ch == 0) {
        bail!("upgrade image path must be absolute and contain no NUL");
    }
    let path = std::fs::canonicalize(path).context("cannot canonicalize upgrade image")?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.len() > 32768 {
        bail!("invalid canonical upgrade image path length");
    }
    Ok(wide)
}

fn same_path(a: &[u16], b: &[u16]) -> Result<bool> {
    // SAFETY: bounded UTF-16 slices remain alive for this length-delimited call.
    let result =
        unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).context("upgrade path comparison failed");
    }
    Ok(result == CSTR_EQUAL)
}

pub(super) fn basename_equal(a: &str, b: &str) -> Result<bool> {
    same_path(
        &a.encode_utf16().collect::<Vec<_>>(),
        &b.encode_utf16().collect::<Vec<_>>(),
    )
}

fn exited(handle: HANDLE) -> Result<bool> {
    // SAFETY: callers retain an owned process handle with SYNCHRONIZE access.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error()).context("upgrade process wait failed"),
    }
}

struct UserSid(Vec<usize>);
impl UserSid {
    fn read(process: HANDLE) -> Result<Self> {
        let mut raw = 0;
        // SAFETY: process is retained; TOKEN_QUERY is the only requested token right.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot query upgrade candidate user");
        }
        let token = OwnedHandle(raw);
        let mut size = 0;
        // SAFETY: documented size query with null, zero-length output.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size) };
        if size < std::mem::size_of::<TOKEN_USER>() as u32 || size > 65536 {
            bail!("invalid upgrade candidate token size");
        }
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let capacity = size;
        // SAFETY: aligned allocation has at least capacity bytes and stays live.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                data.as_mut_ptr().cast(),
                capacity,
                &mut size,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("cannot read upgrade candidate user");
        }
        if size > capacity || size < std::mem::size_of::<TOKEN_USER>() as u32 {
            bail!("invalid upgrade candidate token response");
        }
        let user = Self(data);
        let base = user.0.as_ptr() as usize;
        let end = base
            .checked_add(size as usize)
            .context("token range overflow")?;
        let sid = user.sid() as usize;
        if !sid.is_multiple_of(std::mem::align_of::<u32>())
            || sid < base
            || sid.checked_add(8).is_none_or(|last| last > end)
        {
            bail!("upgrade candidate SID lies outside token buffer");
        }
        // SAFETY: the eight-byte SID header was proved inside the allocation.
        let count = unsafe { *(sid as *const u8).add(1) } as usize;
        if count > 15 || sid.checked_add(8 + count * 4).is_none_or(|last| last > end) {
            bail!("invalid upgrade candidate SID length");
        }
        // SAFETY: the complete SID range is inside the live owned token buffer.
        if unsafe { IsValidSid(user.sid()) } == 0 {
            bail!("invalid upgrade candidate SID");
        }
        Ok(user)
    }
    fn sid(&self) -> *mut std::ffi::c_void {
        // SAFETY: initialized TOKEN_USER header resides in this aligned allocation.
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

fn current_user(process: HANDLE) -> Result<bool> {
    let target = UserSid::read(process)?;
    // SAFETY: current-process pseudo handle is borrowed, never closed.
    let current = UserSid::read(unsafe { GetCurrentProcess() })?;
    // SAFETY: both validated SIDs remain inside their owned token buffers.
    Ok(unsafe { EqualSid(target.sid(), current.sid()) } != 0)
}

/// Legacy signal authority: same user, retained PID/birth, exact selected image.
pub(crate) fn verify_legacy_stop_target(
    process: HANDLE,
    pid: u32,
    installed: &[PathBuf],
) -> Result<()> {
    use windows_sys::Win32::System::Threading::GetProcessId;
    // SAFETY: caller retains this query/synchronize process object throughout.
    if pid == 0 || unsafe { GetProcessId(process) } != pid {
        bail!("legacy daemon retained PID mismatch");
    }
    let _birth = super::quit_event::process_birth(process)?;
    if !current_user(process)? {
        bail!("legacy daemon is owned by another Windows account");
    }
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained query handle and writable buffer of the declared capacity.
    if unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut length) } == 0 {
        return Err(std::io::Error::last_os_error()).context("legacy daemon image query failed");
    }
    if length == 0 || length as usize >= image.len() {
        bail!("legacy daemon image unavailable");
    }
    let actual = canonical(&PathBuf::from(OsString::from_wide(
        &image[..length as usize],
    )))?;
    for selected in installed {
        if same_path(&actual, &canonical(selected)?)? {
            return Ok(());
        }
    }
    bail!("legacy daemon PID-file target is not an exact installed csq image")
}

/// CLI-only legacy authority, separate from the installer's all-target stop.
pub(crate) fn verify_sole_cli_legacy_daemon(
    process: HANDLE,
    pid: u32,
    installed: &[PathBuf],
) -> Result<bool> {
    let Some(birth) = verify_cli_legacy_identity(process, pid, installed)? else {
        return Ok(false);
    };
    let mut backend = WindowsBackend::new(None)?;
    backend.legacy_seen = true; // unknown owner facts must fail closed in this census.
                                // SAFETY: current PID query grants no signal authority.
    let own_pid = unsafe { GetCurrentProcessId() };
    super::require_sole_daemon(&mut backend, (pid, birth), own_pid, installed)?;
    Ok(true)
}

fn verify_cli_legacy_identity(
    process: HANDLE,
    pid: u32,
    installed: &[PathBuf],
) -> Result<Option<u64>> {
    verify_legacy_stop_target(process, pid, installed)?;
    if process_role(&process_argv(process)?)? != Role::Daemon {
        return Ok(None);
    }
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let (mut target_session, mut own_session) = (0, 0);
    // SAFETY: value-only session queries; process identity remains retained.
    if unsafe { ProcessIdToSessionId(pid, &mut target_session) } == 0
        || unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut own_session) } == 0
        || target_session != own_session
    {
        bail!("legacy daemon session cannot be verified");
    }
    Ok(Some(super::quit_event::process_birth(process)?))
}

/// Owned-fixture census only. The production entry above always enumerates
/// the whole host; this seam cannot be selected by production callers.
#[cfg(any(test, feature = "test-utils"))]
pub fn verify_sole_cli_legacy_daemon_scoped(
    process: HANDLE,
    pid: u32,
    installed: &[PathBuf],
    owned_fixture_pids: &[u32],
) -> Result<bool> {
    let Some(birth) = verify_cli_legacy_identity(process, pid, installed)? else {
        return Ok(false);
    };
    if !owned_fixture_pids.contains(&pid) {
        bail!("fixture target missing from scope");
    }
    struct Scoped<'a> {
        inner: WindowsBackend,
        pids: &'a [u32],
    }
    impl Backend for Scoped<'_> {
        type Handle = VerifiedProcess;
        fn scan(&mut self) -> Result<Vec<Candidate>> {
            Ok(self
                .inner
                .scan()?
                .into_iter()
                .filter(|row| self.pids.contains(&row.pid))
                .collect())
        }
        fn legacy_event_present(&mut self) -> Result<bool> {
            self.inner.legacy_event_present()
        }
        fn inspect(
            &mut self,
            row: &Candidate,
            images: &[PathBuf],
        ) -> Result<Option<Inspected<Self::Handle>>> {
            self.inner.inspect(row, images)
        }
        fn pid(h: &Self::Handle) -> u32 {
            WindowsBackend::pid(h)
        }
        fn birth(h: &Self::Handle) -> u64 {
            WindowsBackend::birth(h)
        }
        fn quit_channel(&mut self, h: &Self::Handle) -> Result<QuitChannel> {
            self.inner.quit_channel(h)
        }
        fn request_quit(&mut self, h: &Self::Handle, c: QuitChannel) -> Result<()> {
            self.inner.request_quit(h, c)
        }
        fn exited(&mut self, h: &Self::Handle) -> Result<bool> {
            self.inner.exited(h)
        }
        fn elapsed(&self) -> Duration {
            self.inner.elapsed()
        }
        fn pause(&mut self, d: Duration) {
            self.inner.pause(d)
        }
    }
    let mut inner = WindowsBackend::new(None)?;
    inner.legacy_seen = true;
    let mut backend = Scoped {
        inner,
        pids: owned_fixture_pids,
    };
    // SAFETY: borrowed identity only; no host process is signalled here.
    super::require_sole_daemon(
        &mut backend,
        (pid, birth),
        unsafe { GetCurrentProcessId() },
        installed,
    )?;
    Ok(true)
}

fn process_argv(process: HANDLE) -> Result<Vec<String>> {
    const CAP: usize = 128 * 1024;
    let mut data = vec![0usize; CAP / std::mem::size_of::<usize>()];
    let mut used = 0;
    // SAFETY: handle has query rights; aligned initialized storage covers CAP bytes.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            ProcessCommandLineInformation,
            data.as_mut_ptr().cast(),
            CAP as u32,
            &mut used,
        )
    };
    if status < 0 {
        bail!("upgrade candidate command-line query failed (NTSTATUS {status:#x})");
    }
    if used < std::mem::size_of::<UNICODE_STRING>() as u32 || used as usize > CAP {
        bail!("invalid upgrade candidate command-line response length");
    }
    // SAFETY: returned header is aligned and lies inside the initialized allocation.
    let text = unsafe { &*data.as_ptr().cast::<UNICODE_STRING>() };
    let base = data.as_ptr() as usize;
    let end = base
        .checked_add(used as usize)
        .context("command-line range overflow")?;
    let start = text.Buffer as usize;
    let length = usize::from(text.Length);
    if length == 0
        || length % 2 != 0
        || text.MaximumLength % 2 != 0
        || text.Length > text.MaximumLength
        || !start.is_multiple_of(2)
        || start < base + std::mem::size_of::<UNICODE_STRING>()
        || start
            .checked_add(usize::from(text.MaximumLength))
            .is_none_or(|last| last > end)
    {
        bail!("invalid upgrade candidate command-line buffer");
    }
    // SAFETY: entire aligned UTF-16 byte range was proved inside the owned buffer.
    let units = unsafe { std::slice::from_raw_parts(text.Buffer, length / 2) };
    let command =
        String::from_utf16(units).context("upgrade candidate command line is not UTF-16")?;
    if command.contains('\0') {
        bail!("upgrade candidate command line contains NUL");
    }
    let wide: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    // SAFETY: input is NUL-terminated UTF-16; API returns one LocalAlloc allocation.
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("cannot parse upgrade candidate arguments");
    }
    struct Args(*mut windows_sys::core::PWSTR);
    impl Drop for Args {
        fn drop(&mut self) {
            // SAFETY: sole ownership of CommandLineToArgvW's LocalAlloc result.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    let args = Args(raw);
    if count <= 0 || count as usize > wide.len() {
        bail!("invalid upgrade argument count");
    }
    let mut result = Vec::new();
    let mut remaining = wide.len();
    for index in 0..count as usize {
        // SAFETY: API guarantees count pointers and NUL-terminated argument storage.
        let ptr = unsafe { *args.0.add(index) };
        let mut size = 0;
        // SAFETY: API owns complete strings; cap avoids unbounded traversal.
        while size < remaining && unsafe { *ptr.add(size) } != 0 {
            size += 1;
        }
        if size == remaining {
            bail!("upgrade argument lengths exceed command-line cap");
        }
        // SAFETY: API-returned argument range was bounded and remains allocated.
        result.push(
            String::from_utf16(unsafe { std::slice::from_raw_parts(ptr, size) })
                .context("upgrade candidate argument is not UTF-16")?,
        );
        remaining -= size + 1;
    }
    Ok(result)
}

fn process_role(argv: &[String]) -> Result<Role> {
    if argv.is_empty() {
        bail!("upgrade candidate has no executable argument");
    }
    // mode::detect checks this flag anywhere, even after a CLI delimiter.
    if argv.iter().any(|arg| arg == "--desktop") {
        return Ok(Role::Desktop);
    }
    let mut args = argv[1..]
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .filter(|arg| !matches!(arg.as_str(), "--json" | "--trace"));
    match args.next().map(String::as_str) {
        Some("daemon") => match args.next().map(String::as_str) {
            Some("start") => Ok(Role::Daemon),
            Some("stop" | "status" | "posture" | "install" | "uninstall") => Ok(Role::Cli),
            _ => bail!("ambiguous daemon role; quit daemon-capable process manually"),
        },
        Some(flag)
            if flag.starts_with('-') && !matches!(flag, "--help" | "-h" | "--version" | "-V") =>
        {
            bail!("unrecognized root option prevents safe upgrade role classification")
        }
        _ => Ok(Role::Cli),
    }
}

fn validate_snapshot(rows: &[Candidate], own_pid: u32) -> Result<()> {
    if !rows.iter().any(|row| row.pid == own_pid) {
        bail!("upgrade process census is incomplete: helper PID {own_pid} missing");
    }
    Ok(())
}

/// Pure validator seam; it never enumerates or signals host processes.
#[cfg(any(test, feature = "test-utils"))]
pub fn validate_snapshot_for_test(rows: &[Candidate], own_pid: u32) -> Result<()> {
    validate_snapshot(rows, own_pid)
}

impl WindowsBackend {
    /// Exact-image census inspection, independent of the frozen S1 drain selection.
    /// S2 uses only bound quit channels; this cannot authorize legacy broadcast.
    pub(crate) fn inspect_actual_image(
        &mut self,
        candidate: &Candidate,
        actual: &Path,
    ) -> Result<Option<Inspected<VerifiedProcess>>> {
        self.inspect_image(candidate, &[actual.to_path_buf()])
    }
    fn inspect_image(
        &mut self,
        candidate: &Candidate,
        installed: &[PathBuf],
    ) -> Result<Option<Inspected<VerifiedProcess>>> {
        if candidate.pid == 0 {
            return Ok(None);
        }
        if installed.is_empty() {
            bail!("upgrade installed image list is empty");
        }
        let targets: Vec<Vec<u16>> = installed
            .iter()
            .map(|path| canonical(path))
            .collect::<Result<_>>()?;
        // SAFETY: current PID is queried without opening or signaling any process.
        if candidate.pid == unsafe { GetCurrentProcessId() } {
            let own = canonical(
                &std::env::current_exe().context("cannot identify upgrade helper image")?,
            )?;
            for target in &targets {
                if same_path(&own, target)? {
                    bail!("upgrade helper is a selected installed image; refusing self exclusion for PID {}", candidate.pid);
                }
            }
            // The standalone helper initializes no refresher or csq lock.
            return Ok(None);
        }
        // SAFETY: OpenProcess returns a fresh non-inherited handle; identity is
        // checked through that handle before it can authorize any action.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                candidate.pid,
            )
        };
        if raw == 0 {
            let error = std::io::Error::last_os_error();
            // ERROR_INVALID_PARAMETER on a nonzero PID means the snapshot
            // process disappeared before open. No authority or retained exit
            // proof is granted; any later arrival must pass a fresh census.
            if error.raw_os_error() == Some(87) {
                return Ok(None);
            }
            return Err(error).with_context(|| format!(
                "cannot open upgrade candidate PID {}: access denied or identity unavailable; another Windows account or protected process may require its own verified shutdown",
                candidate.pid
            ));
        }
        let handle = OwnedHandle(raw);
        if exited(handle.0)? {
            return Ok(None);
        }
        let birth = super::quit_event::process_birth(handle.0).with_context(|| {
            format!(
                "cannot read birth of upgrade candidate PID {}",
                candidate.pid
            )
        })?;
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        // SAFETY: handle has query access; buffer capacity and length agree.
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut length) } == 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("cannot identify upgrade candidate PID {}", candidate.pid)
            });
        }
        if length == 0 || length as usize >= image.len() {
            bail!("invalid upgrade image response for PID {}", candidate.pid);
        }
        let image_path = PathBuf::from(OsString::from_wide(&image[..length as usize]));
        let image = canonical(&image_path).with_context(|| {
            format!(
                "cannot resolve image for upgrade candidate PID {}",
                candidate.pid
            )
        })?;
        let mut installed = false;
        for target in targets {
            installed |= same_path(&image, &target)?;
        }
        match self.inspect_owner(handle.0) {
            Ok(true) => {}
            Ok(false) if !installed => return Ok(None),
            Err(_) if !installed && !self.legacy_seen => return Ok(None),
            Ok(false) => bail!("installed image PID {} is owned by another Windows account; token-safe completion must be verified in that account before this installer can continue", candidate.pid),
            Err(_) => bail!("cannot verify owner of installed/legacy-census PID {}; no token-safe completion proof", candidate.pid),
        }
        let role = process_role(&process_argv(handle.0).with_context(|| {
            format!(
                "cannot inspect arguments of upgrade candidate PID {}",
                candidate.pid
            )
        })?)
        .with_context(|| format!("cannot classify upgrade PID {}", candidate.pid))?;
        if !installed && role == Role::Cli {
            return Ok(None);
        }
        Ok(Some(Inspected {
            handle: VerifiedProcess {
                pid: candidate.pid,
                birth,
                installed,
                role,
                handle,
            },
            installed,
            role,
        }))
    }
}

impl Backend for WindowsBackend {
    type Handle = VerifiedProcess;
    fn legacy_event_present(&mut self) -> Result<bool> {
        let present = super::quit_event::legacy_event_exists()?;
        self.legacy_seen |= present;
        Ok(present)
    }

    fn scan(&mut self) -> Result<Vec<Candidate>> {
        // SAFETY: documented process snapshot request, not an owned process action.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("upgrade process snapshot failed");
        }
        let snapshot = OwnedHandle(raw);
        // SAFETY: zero initializes the C output struct; dwSize is set before use.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut rows = Vec::new();
        // SAFETY: snapshot is live and entry has the required size.
        let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        loop {
            if ok == 0 {
                // SAFETY: read immediately after the failed enumeration operation.
                let code = unsafe { GetLastError() };
                if code != ERROR_NO_MORE_FILES {
                    return Err(std::io::Error::from_raw_os_error(code as i32))
                        .context("upgrade process enumeration incomplete");
                }
                break;
            }
            let end = entry.szExeFile.iter().position(|ch| *ch == 0);
            rows.push(Candidate {
                pid: entry.th32ProcessID,
                basename: end
                    .filter(|end| *end != 0)
                    .map(|end| OsString::from_wide(&entry.szExeFile[..end])),
            });
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            // SAFETY: snapshot and output buffer remain live throughout enumeration.
            ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        // SAFETY: current process identity is queried without an owned handle.
        validate_snapshot(&rows, unsafe { GetCurrentProcessId() })?;
        Ok(rows)
    }

    fn inspect(
        &mut self,
        candidate: &Candidate,
        installed: &[PathBuf],
    ) -> Result<Option<Inspected<Self::Handle>>> {
        if self.selected_images.is_empty() {
            self.selected_images = installed.to_vec();
        } else if self.selected_images != installed {
            bail!("installed image selection changed during retained drain");
        }
        self.inspect_image(candidate, installed)
    }

    fn pid(handle: &Self::Handle) -> u32 {
        handle.pid
    }
    fn birth(handle: &Self::Handle) -> u64 {
        handle.birth
    }

    fn quit_channel(&mut self, handle: &Self::Handle) -> Result<QuitChannel> {
        if !handle.installed {
            bail!(
                "refusing quit preflight for non-installed PID {}",
                handle.pid
            );
        }
        if super::quit_event::desktop_quit_available(handle.pid, handle.handle.0)? {
            return Ok(QuitChannel::Bound);
        }
        if handle.role != Role::Daemon {
            return Ok(QuitChannel::Unavailable);
        }
        let Some(path) = &self.daemon_pid_file else {
            bail!("legacy daemon PID {} requires an explicit matching daemon PID file before any signal", handle.pid);
        };
        {
            let mut text = String::new();
            std::fs::File::open(path)
                .context("cannot cross-check explicit daemon PID file")?
                .take(65)
                .read_to_string(&mut text)
                .context("cannot read daemon PID cross-check")?;
            if text.len() > 64 || text.trim().parse::<u32>().ok() != Some(handle.pid) {
                bail!(
                    "daemon PID file does not match retained upgrade PID {}",
                    handle.pid
                );
            }
        }
        if self.legacy_event_present()? {
            Ok(QuitChannel::Legacy)
        } else {
            Ok(QuitChannel::Unavailable)
        }
    }

    fn request_quit(&mut self, handle: &Self::Handle, channel: QuitChannel) -> Result<()> {
        if !handle.installed {
            bail!(
                "refusing to signal non-installed upgrade PID {}",
                handle.pid
            );
        }
        if exited(handle.handle.0)? {
            return Ok(());
        }
        match channel {
            QuitChannel::Bound => {
                if !super::quit_event::signal_desktop_quit(handle.pid, handle.handle.0)? {
                    bail!("bound quit endpoint disappeared for PID {}", handle.pid);
                }
                Ok(())
            }
            QuitChannel::Legacy if handle.role == Role::Daemon => {
                crate::daemon::shutdown_windows::signal_legacy_for_retained(
                    handle.pid,
                    handle.handle.0,
                    &self.selected_images,
                    "",
                )?;
                // The controller retains this handle and proves exit within its
                // original shared deadline; this request grants no kill authority.
                Ok(())
            }
            QuitChannel::Legacy => bail!(
                "legacy quit requires a verified daemon role for PID {}",
                handle.pid
            ),
            QuitChannel::Unavailable => bail!(
                "no bound quit endpoint for PID {}; close that csq session before retrying",
                handle.pid
            ),
        }
    }

    fn exited(&mut self, handle: &Self::Handle) -> Result<bool> {
        exited(handle.handle.0)
            .with_context(|| format!("cannot wait for upgrade PID {}", handle.pid))
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod r1_regressions {
    use super::*;
    #[test]
    fn daemon_install_is_a_cli_role() {
        let argv = ["csq", "daemon", "install"].map(str::to_owned);
        assert_eq!(process_role(&argv).unwrap(), Role::Cli);
    }
    #[test]
    fn exited_before_open_is_gone_and_pid_zero_is_not_opened() {
        let mut backend = WindowsBackend::new(None).unwrap();
        let image = std::env::current_exe().unwrap();
        for pid in [0, u32::MAX] {
            let row = Candidate {
                pid,
                basename: Some("csq.exe".into()),
            };
            assert!(backend
                .inspect(&row, std::slice::from_ref(&image))
                .unwrap()
                .is_none());
        }
    }
}
