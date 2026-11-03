//! Actual Windows child ownership and atomic Job membership.
//!
//! Main-process handles are never inheritable. Qualified own standard streams
//! use automatic inheritance; owned streams are prepared by a private creator
//! already born in the main-owned nonbreakaway Job. This contains cooperative
//! descendants; it is not a same-user isolation boundary. A same-user process
//! with duplicate-handle access can obtain Job/process capabilities.
//! Quoting/environment comparisons follow the Rust 1.98.1 Windows process
//! implementation: <https://github.com/rust-lang/rust/tree/1.98.1/library/std/src/sys/process>.

use csq_core::platform::launch_plan::{LaunchArg, LaunchParts, LaunchPlan, LaunchStdio};
#[path = "windows_helper.rs"]
pub(crate) mod creator_helper;
#[path = "windows_helper_wire.rs"]
pub(crate) mod windows_helper_wire;

pub(crate) fn dispatch_helper(argv: &[OsString]) -> io::Result<Option<u32>> {
    creator_helper::dispatch_helper(argv)
}
use std::{
    cmp::Ordering,
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus},
    ptr,
};
#[cfg(test)]
use windows_sys::Win32::Foundation::DUPLICATE_CLOSE_SOURCE;
#[cfg(test)]
use windows_sys::Win32::System::Threading::{
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetLastError, SetLastError, DUPLICATE_SAME_ACCESS, ERROR_INVALID_HANDLE,
        ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    },
    Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_LESS_THAN},
    Storage::FileSystem::{
        GetFileAttributesW, GetFileType, GetFullPathNameW, FILE_TYPE_DISK, FILE_TYPE_PIPE,
        FILE_TYPE_UNKNOWN, INVALID_FILE_ATTRIBUTES,
    },
    System::{
        Console::{
            GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        },
        Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW},
        JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        },
        Pipes::CreatePipe,
        SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
            GetProcessId, GetProcessIdOfThread, GetProcessTimes, GetThreadId,
            InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NEW_PROCESS_GROUP,
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
    },
};

const CLEANUP_MS: u32 = 2_000;
const INVALID: &str = "login_windows_launch_invalid";
const BATCH: &str = "login_windows_batch_wrapper_unsupported";
const UNDETERMINED: &str = "login_custody_UNDETERMINED: Windows setup cleanup unconfirmed";
#[cfg(test)]
std::thread_local! {
    static CREATED_PROCESSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    // Finite injected refusals let mutation tests reach their own assertion;
    // the original native process must still be terminated and waited afterward.
    static TERMINATE_REFUSALS: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
    static TERMINATE_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CHECKPOINT_HOOK: std::cell::RefCell<Option<CheckpointHook>> = const { std::cell::RefCell::new(None) };
    static SPAWN_STAGE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("not_started") };
    static INITIALIZED_DONOR: std::cell::RefCell<Option<InitializedDonorProbe>> = const { std::cell::RefCell::new(None) };
}
// This selector and bootstrap do not exist in production. The unchanged
// never-resumed donor remains the baseline; this is an additional causal probe.
#[cfg(test)]
pub(crate) const DONOR_READY_EVENT: &str = "CSQ_PRIVATE_WINDOWS_DONOR_READY_EVENT";
#[cfg(test)]
pub(crate) const DONOR_CONFIGURED_FLAGS: &str = "CSQ_PRIVATE_WINDOWS_DONOR_CONFIGURED_FLAGS";
#[cfg(test)]
const PROBE_DONOR_CREATION_FLAGS: u32 = CREATE_SUSPENDED
    | CREATE_NEW_PROCESS_GROUP
    | CREATE_UNICODE_ENVIRONMENT
    | EXTENDED_STARTUPINFO_PRESENT;
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttributeProbeVariant {
    NoParent,
    ParentOnly,
    HandleOnly,
    JobOnly,
}
#[cfg(test)]
type InitializedDonorReadyObserver = Box<dyn Fn(u32, RawHandle) -> io::Result<()>>;
#[cfg(test)]
struct InitializedDonorProbe {
    command: Vec<u16>,
    environment: Vec<u16>,
    ready: OwnedHandle,
    observe_ready: InitializedDonorReadyObserver,
    keep_alive: bool,
    retained_donor: Option<NativeProcess>,
    variant: Option<AttributeProbeVariant>,
    configured_donor_flags: u32,
    vendor_in_requested_job: Option<bool>,
}
#[cfg(test)]
pub(crate) struct InitializedDonorProbeGuard {
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    configured_donor_flags: u32,
    variant: Option<AttributeProbeVariant>,
}
#[cfg(test)]
impl InitializedDonorProbeGuard {
    pub(crate) fn configured_donor_flags_for_test(&self) -> u32 {
        self.configured_donor_flags
    }
    pub(crate) fn variant_for_test(&self) -> Option<AttributeProbeVariant> {
        self.variant
    }
    pub(crate) fn vendor_in_requested_job_for_test(&self) -> Option<bool> {
        INITIALIZED_DONOR.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|probe| probe.vendor_in_requested_job)
        })
    }
    pub(crate) fn donor_alive_for_test(&self) -> io::Result<bool> {
        INITIALIZED_DONOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot
                .as_mut()
                .and_then(|probe| probe.retained_donor.as_mut())
            {
                Some(donor) => donor.try_wait().map(|status| status.is_none()),
                None => Ok(false),
            }
        })
    }
    pub(crate) fn finalize_for_test(&mut self) -> io::Result<()> {
        INITIALIZED_DONOR.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(probe) = slot.as_mut() {
                if let Some(donor) = probe.retained_donor.as_mut() {
                    // Explicit failure retains the original process for retry.
                    donor.terminate_and_confirm()?;
                }
                probe.retained_donor.take();
            }
            Ok(())
        })
    }
}
#[cfg(test)]
impl Drop for InitializedDonorProbeGuard {
    fn drop(&mut self) {
        while self.finalize_for_test().is_err() {
            // A failed kill/wait is UNKNOWN, never permission to close the last
            // owned process handle. Keep cleanup on this original test stack.
            eprintln!("initialized_donor_probe_cleanup_unconfirmed");
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        INITIALIZED_DONOR.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
pub(crate) fn initialized_donor_probe_for_test(
    plan: LaunchPlan,
    observe_ready: impl Fn(u32, RawHandle) -> io::Result<()> + 'static,
) -> io::Result<InitializedDonorProbeGuard> {
    initialized_donor_probe_with_lifetime_for_test(plan, observe_ready, false)
}
#[cfg(test)]
pub(crate) fn initialized_donor_probe_with_lifetime_for_test(
    mut plan: LaunchPlan,
    observe_ready: impl Fn(u32, RawHandle) -> io::Result<()> + 'static,
    keep_alive: bool,
) -> io::Result<InitializedDonorProbeGuard> {
    use windows_sys::Win32::System::Threading::CreateEventW;
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| io::Error::other("initialized_donor_probe_entropy_unavailable"))?;
    let mut suffix = String::with_capacity(32);
    for byte in random {
        for nibble in [byte >> 4, byte & 15] {
            suffix.push(char::from(b"0123456789abcdef"[usize::from(nibble)]));
        }
    }
    let name = format!("Local\\csq-private-donor-{suffix}");
    let encoded = wide(OsStr::new(&name))?;
    // SAFETY: default user DACL, non-inheritable handle, private unpredictable
    // name. No main-process handle is made inheritable for this probe.
    let (event, code) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let event = CreateEventW(ptr::null(), 1, 0, encoded.as_ptr());
        (event, GetLastError())
    };
    if event == 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: successful CreateEventW returned this newly owned handle.
    let ready = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
    if code == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS {
        return Err(io::Error::other("initialized_donor_probe_event_collision"));
    }
    plan.env(DONOR_READY_EVENT, name).env(
        DONOR_CONFIGURED_FLAGS,
        PROBE_DONOR_CREATION_FLAGS.to_string(),
    );
    let parts = plan.build_for_spawn()?;
    if parts.inherit_env || parts.program != std::env::current_exe()?.as_os_str() {
        return Err(io::Error::other("initialized_donor_probe_plan_invalid"));
    }
    let probe = InitializedDonorProbe {
        command: quote_command(&parts.program, &parts.args)?,
        environment: env_block(&environment(&parts)?),
        ready,
        observe_ready: Box::new(observe_ready),
        keep_alive,
        retained_donor: None,
        variant: None,
        configured_donor_flags: PROBE_DONOR_CREATION_FLAGS,
        vendor_in_requested_job: None,
    };
    INITIALIZED_DONOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(io::Error::other("initialized_donor_probe_already_selected"));
        }
        *slot = Some(probe);
        Ok(InitializedDonorProbeGuard {
            _thread: std::marker::PhantomData,
            configured_donor_flags: PROBE_DONOR_CREATION_FLAGS,
            variant: None,
        })
    })
}
#[cfg(test)]
pub(crate) fn initialized_donor_attribute_probe_for_test(
    plan: LaunchPlan,
    observe_ready: impl Fn(u32, RawHandle) -> io::Result<()> + 'static,
    variant: AttributeProbeVariant,
) -> io::Result<InitializedDonorProbeGuard> {
    let mut guard = initialized_donor_probe_with_lifetime_for_test(plan, observe_ready, true)?;
    INITIALIZED_DONOR.with(|slot| {
        slot.borrow_mut().as_mut().ok_or_else(invalid)?.variant = Some(variant);
        Ok::<_, io::Error>(())
    })?;
    guard.variant = Some(variant);
    Ok(guard)
}
#[cfg(test)]
fn retain_initialized_donor_for_test(donor: &mut Option<NativeProcess>) -> io::Result<bool> {
    INITIALIZED_DONOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut().filter(|probe| probe.keep_alive) else {
            return Ok(false);
        };
        if probe.retained_donor.is_some() {
            return Err(io::Error::other("initialized_donor_probe_already_retained"));
        }
        probe.retained_donor = Some(donor.take().ok_or_else(invalid)?);
        Ok(true)
    })
}
#[cfg(test)]
fn initialized_donor_configuration_for_test(command: &mut Vec<u16>, block: &[u16]) -> Vec<u16> {
    INITIALIZED_DONOR.with(|slot| match slot.borrow().as_ref() {
        Some(probe) => {
            command.clone_from(&probe.command);
            probe.environment.clone()
        }
        None => block.to_vec(),
    })
}
#[cfg(test)]
fn initialize_donor_for_test(donor: &NativeProcess) -> io::Result<()> {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    fn birth(donor: &NativeProcess) -> io::Result<u64> {
        // SAFETY: FILETIME is a pair of integer DWORDs; all-zero is valid.
        let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
        // SAFETY: retained original process and separate correctly typed outputs.
        let [created, exited, kernel, user] = &mut times;
        if unsafe { GetProcessTimes(raw(&donor.process), created, exited, kernel, user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    INITIALIZED_DONOR.with(|slot| {
        let slot = slot.borrow();
        let Some(probe) = slot.as_ref() else {
            return Ok(());
        };
        trace_spawn_stage_for_test("probe_resume_initialized_donor");
        let original_birth = birth(donor)?;
        // SAFETY: only this probe's retained original suspended donor thread.
        match unsafe { ResumeThread(raw(&donor.thread)) } {
            1 => {}
            u32::MAX => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("initialized_donor_probe_resume_refused")),
        }
        trace_spawn_stage_for_test("probe_wait_initialized_donor_ready");
        // SAFETY: owned non-inherited Event; timeout is UNKNOWN, never readiness.
        match unsafe { WaitForSingleObject(raw(&probe.ready), 5_000) } {
            0 => {}
            0xffff_ffff => return Err(io::Error::last_os_error()),
            _ => {
                // SAFETY: observe only the retained original donor, never a
                // process selected by a numeric PID. Exit is diagnostic UNKNOWN.
                if unsafe { WaitForSingleObject(raw(&donor.process), 0) } == 0 {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(raw(&donor.process), &mut code) } == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return Err(io::Error::other(format!(
                        "initialized_donor_probe_exited_before_readiness_0x{code:08X}"
                    )));
                }
                return Err(io::Error::other(
                    "initialized_donor_probe_readiness_unconfirmed",
                ));
            }
        }
        // The event cannot replace an observation of the retained original
        // donor. It must still be alive with its original creation identity.
        match unsafe { WaitForSingleObject(raw(&donor.process), 0) } {
            258 => {}
            0xffff_ffff => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("initialized_donor_probe_not_alive")),
        }
        if birth(donor)? != original_birth {
            return Err(io::Error::other(
                "initialized_donor_probe_identity_unconfirmed",
            ));
        }
        (probe.observe_ready)(donor.pid, donor.process.as_raw_handle())?;
        trace_spawn_stage_for_test("probe_initialized_donor_ready");
        Ok(())
    })
}
#[cfg(test)]
fn trace_spawn_stage_for_test(stage: &'static str) {
    SPAWN_STAGE.with(|value| value.set(stage));
}
#[cfg(test)]
pub(crate) fn last_spawn_stage_for_test() -> &'static str {
    SPAWN_STAGE.with(std::cell::Cell::get)
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpawnCheckpoint {
    DonorCreated,
    VendorCreated,
    AfterResume,
}
#[cfg(test)]
type CheckpointHook = Box<dyn FnMut(SpawnCheckpoint, u32, RawHandle) -> io::Result<()>>;
#[cfg(test)]
pub(crate) fn set_checkpoint_hook_for_test(
    hook: impl FnMut(SpawnCheckpoint, u32, RawHandle) -> io::Result<()> + 'static,
) {
    CHECKPOINT_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}
#[cfg(test)]
fn checkpoint(stage: SpawnCheckpoint, process: &NativeProcess) -> io::Result<()> {
    CHECKPOINT_HOOK.with(|slot| match slot.borrow_mut().as_mut() {
        Some(hook) => hook(stage, process.pid, process.process.as_raw_handle()),
        None => Ok(()),
    })
}

pub(crate) enum LoginRead {
    Stdout(ChildStdout),
    Stderr(ChildStderr),
    SyncPipe(File),
}
impl Read for LoginRead {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(pipe) => pipe.read(bytes),
            Self::Stderr(pipe) => pipe.read(bytes),
            Self::SyncPipe(pipe) => match pipe.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(0),
                result => result,
            },
        }
    }
}
pub(crate) enum LoginWrite {
    Stdin(ChildStdin),
    SyncPipe(File),
}
impl Write for LoginWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdin(pipe) => pipe.write(bytes),
            Self::SyncPipe(pipe) => pipe.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdin(pipe) => pipe.flush(),
            Self::SyncPipe(pipe) => pipe.flush(),
        }
    }
}
enum Process {
    Standard(Child),
    Native(NativeProcess),
}
pub(crate) struct CustodyChild {
    process: Process,
    creator: Option<CreatorLease>,
    #[cfg(test)]
    fixture_job: Option<HANDLE>,
    pub(crate) stdin: Option<LoginWrite>,
    pub(crate) stdout: Option<LoginRead>,
    pub(crate) stderr: Option<LoginRead>,
}
impl From<Child> for CustodyChild {
    fn from(mut child: Child) -> Self {
        Self {
            #[cfg(test)]
            fixture_job: None,
            creator: None,
            stdin: child.stdin.take().map(LoginWrite::Stdin),
            stdout: child.stdout.take().map(LoginRead::Stdout),
            stderr: child.stderr.take().map(LoginRead::Stderr),
            process: Process::Standard(child),
        }
    }
}
impl AsRawHandle for CustodyChild {
    fn as_raw_handle(&self) -> RawHandle {
        match &self.process {
            Process::Standard(child) => child.as_raw_handle(),
            Process::Native(child) => child.process.as_raw_handle(),
        }
    }
}
impl CustodyChild {
    #[cfg(test)]
    pub(crate) fn fixture_job_for_test(
        &self,
        group: &super::group::GroupControl,
    ) -> io::Result<HANDLE> {
        // The Group borrow keeps its original Job handle alive. This numeric
        // test-only observation creates no extra Job reference and cannot
        // extend kill-on-close lifetime.
        if group.id() != self.id() {
            return Err(invalid());
        }
        self.fixture_job.ok_or_else(invalid)
    }
    #[cfg(test)]
    pub(crate) fn creator_identity_for_test(&self) -> io::Result<Option<(u32, u64)>> {
        self.creator
            .as_ref()
            .map(|creator| {
                // Creation identity remains queryable through this original handle
                // even after exit. Callers separately prove liveness when required.
                Ok((
                    creator.process.pid,
                    process_birth(&creator.process.process)?,
                ))
            })
            .transpose()
    }
    #[cfg(test)]
    pub(crate) fn creator_lease_present_for_test(&self) -> bool {
        self.creator.is_some()
    }
    #[cfg(test)]
    pub(crate) fn creator_exit_for_test(&self) -> io::Result<Option<bool>> {
        self.creator
            .as_ref()
            .map(|creator| {
                // SAFETY: actual retained original creator object, read-only wait.
                match unsafe { WaitForSingleObject(raw(&creator.process.process), 0) } {
                    0 => Ok(true),
                    258 => Ok(false),
                    _ => Err(io::Error::last_os_error()),
                }
            })
            .transpose()
    }
    // This is deliberately separate from try_wait: the vendor's status always
    // comes from the actual vendor process, never from the creator's exit code.
    pub(crate) fn poll_creator_lifecycle(&mut self, job_stop_requested: bool) -> io::Result<bool> {
        let Some(creator) = self.creator.as_mut() else {
            return Ok(true);
        };
        let process = &mut self.process;
        let ready = super::group::creator_retirement_ready(
            job_stop_requested,
            || creator.process.try_wait().map(|status| status.is_some()),
            || match process {
                Process::Native(vendor) => vendor.try_wait().map(|status| status.is_some()),
                Process::Standard(vendor) => vendor.try_wait().map(|status| status.is_some()),
            },
        )?;
        if ready {
            self.creator.take();
        }
        Ok(ready)
    }
    pub(crate) fn id(&self) -> u32 {
        match &self.process {
            Process::Standard(child) => child.id(),
            Process::Native(child) => child.pid,
        }
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match &mut self.process {
            Process::Standard(child) => child.try_wait(),
            Process::Native(child) => child.try_wait(),
        }
    }
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.stdin.take();
        match &mut self.process {
            Process::Standard(child) => child.wait(),
            Process::Native(child) => {
                // SAFETY: owned original process handle; wait does not close it.
                if unsafe { WaitForSingleObject(raw(&child.process), u32::MAX) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                self.try_wait()?.ok_or_else(invalid)
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        match &mut self.process {
            Process::Standard(child) => child.kill(),
            Process::Native(child) => child.kill(),
        }
    }
}
struct CreatorLease {
    process: NativeProcess,
}
struct NativeProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    status: Option<ExitStatus>,
}
impl NativeProcess {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        // SAFETY: retained original process object, not a numeric PID lookup.
        match unsafe { WaitForSingleObject(raw(&self.process), 0) } {
            258 => return Ok(None),
            0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        let mut code = 0;
        // SAFETY: wait proved exit; initialized DWORD output. Exit 259 is valid.
        if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.status = Some(ExitStatus::from_raw(code));
        Ok(self.status)
    }
    fn kill(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: termination authority is this owned original process object.
        if unsafe { TerminateProcess(raw(&self.process), 130) } == 0 && self.try_wait()?.is_none() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn terminate_and_confirm(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if TERMINATE_REFUSALS.with(|slot| {
            slot.get().is_some_and(|remaining| {
                TERMINATE_ATTEMPTS.with(|count| count.set(count.get() + 1));
                slot.set(Some(remaining.saturating_sub(1)));
                remaining != 0
            })
        }) {
            return Err(io::Error::from_raw_os_error(
                windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32,
            ));
        }
        self.kill()?;
        // SAFETY: bounded wait on the same retained process after termination.
        if unsafe { WaitForSingleObject(raw(&self.process), CLEANUP_MS) } != 0
            || self.try_wait()?.is_none()
        {
            return Err(io::Error::other(UNDETERMINED));
        }
        Ok(())
    }
}
fn raw(handle: &impl AsRawHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, INVALID)
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut bytes: Vec<u16> = value.encode_wide().collect();
    if bytes.contains(&0) {
        return Err(invalid());
    }
    bytes.push(0);
    Ok(bytes)
}
fn duplicate(
    source_process: HANDLE,
    source: HANDLE,
    target: HANDLE,
    inherit: bool,
) -> io::Result<OwnedHandle> {
    let mut handle = 0;
    // SAFETY: input handles stay live; DuplicateHandle creates one owned handle.
    if unsafe {
        DuplicateHandle(
            source_process,
            source,
            target,
            &mut handle,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // This helper owns only duplicates in the main process. Donor duplicates
    // use a distinct remote-handle owner below.
    // SAFETY: successful main-process duplication transferred sole ownership.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
}
impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented size query with null list.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 65_536 {
            return Err(invalid());
        }
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        // SAFETY: aligned allocation covers queried bytes and remains owned.
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut bytes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            list,
            _storage: storage,
        })
    }
    fn set<T>(&mut self, key: u32, values: &[T]) -> io::Result<()> {
        // SAFETY: callers retain every referenced array through CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                key as usize,
                values.as_ptr().cast(),
                std::mem::size_of_val(values),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: one initialized attribute list; backing storage drops afterward.
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

struct Setup {
    job: Option<OwnedHandle>,
    donor: Option<NativeProcess>,
    vendor: Option<NativeProcess>,
    donor_handles: Vec<HANDLE>,
}
impl Setup {
    fn empty_job(&self) -> io::Result<bool> {
        let Some(job) = &self.job else {
            return Ok(true);
        };
        // SAFETY: plain Win32 output struct with exact initialized capacity.
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let mut bytes = 0;
        // SAFETY: owned Job handle and correctly sized/aligned accounting output.
        if unsafe {
            QueryInformationJobObject(
                raw(job),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                &mut bytes,
            )
        } == 0
            || bytes as usize != std::mem::size_of_val(&accounting)
        {
            return Err(io::Error::other(UNDETERMINED));
        }
        Ok(accounting.ActiveProcesses == 0)
    }
    fn request_stop(&mut self) -> io::Result<()> {
        if let Some(job) = &self.job {
            // SAFETY: the caller supplied this dedicated custody Job. Kill the
            // entire setup tree, including a vendor that ran before a failure.
            if unsafe { TerminateJobObject(raw(job), 130) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn close_donor_handles(&mut self) -> io::Result<()> {
        let donor = self.donor.as_ref().ok_or_else(invalid)?;
        let mut failed = false;
        for handle in self.donor_handles.drain(..) {
            let mut local = 0;
            // SAFETY: handle belongs only to this retained suspended donor;
            // CLOSE_SOURCE closes it even when duplication itself fails.
            let rc = unsafe {
                DuplicateHandle(
                    raw(&donor.process),
                    handle,
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                )
            };
            if rc == 0 {
                failed = true;
            } else {
                // SAFETY: successful duplicate now belongs to the main process.
                drop(unsafe { OwnedHandle::from_raw_handle(local as RawHandle) });
            }
        }
        if failed {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.vendor.is_none() && self.donor.is_none() {
            // Successful spawn transferred the vendor to CustodyChild. Only
            // release setup's extra Job reference; do not stop that vendor.
            self.job.take();
            return Ok(());
        }
        let _stop = self.request_stop();
        // Do not short circuit: independently attempt both owned terminations.
        let vendor = self
            .vendor
            .as_mut()
            .map(NativeProcess::terminate_and_confirm)
            .transpose();
        let donor = self
            .donor
            .as_mut()
            .map(NativeProcess::terminate_and_confirm)
            .transpose();
        if vendor.is_err() || donor.is_err() || !self.empty_job()? {
            return Err(io::Error::other(UNDETERMINED));
        }
        self.donor_handles.clear(); // donor death closed its entire handle table.
        self.vendor.take();
        self.donor.take();
        self.job.take();
        Ok(())
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            // A failed cleanup keeps actual process objects and the independent
            // Job reference in explicit quarantine, including during unwind.
            let retained = Self {
                job: self.job.take(),
                donor: self.donor.take(),
                vendor: self.vendor.take(),
                donor_handles: std::mem::take(&mut self.donor_handles),
            };
            std::mem::forget(retained);
            eprintln!("{UNDETERMINED}");
        }
    }
}
pub(crate) struct SetupQuarantine(Option<Setup>, Option<io::Error>);
impl SetupQuarantine {
    pub(crate) fn request_stop(&mut self) -> io::Result<()> {
        match self.0.as_mut() {
            Some(setup) => setup.request_stop(),
            None => Ok(()),
        }
    }
    pub(crate) fn try_finalize(&mut self) -> io::Result<bool> {
        if self
            .1
            .as_ref()
            .is_some_and(|error| !wire_cleanup_ready(error))
        {
            return Ok(false);
        }
        let Some(setup) = self.0.as_mut() else {
            return Ok(true);
        };
        let vendor = match setup.vendor.as_mut() {
            Some(child) => child.try_wait()?.is_some(),
            None => true,
        };
        let donor = match setup.donor.as_mut() {
            Some(child) => child.try_wait()?.is_some(),
            None => true,
        };
        if !vendor || !donor || !setup.empty_job()? {
            return Ok(false);
        }
        setup.vendor.take();
        setup.donor.take();
        setup.donor_handles.clear();
        setup.job.take();
        self.0.take();
        Ok(true)
    }
}
fn wire_cleanup_ready(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<windows_helper_wire::WireFailure>())
        .is_none_or(windows_helper_wire::WireFailure::retry_cleanup)
}
impl fmt::Debug for SetupQuarantine {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(UNDETERMINED)
    }
}
impl fmt::Display for SetupQuarantine {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(UNDETERMINED)
    }
}
impl std::error::Error for SetupQuarantine {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.1
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}
impl Drop for SetupQuarantine {
    fn drop(&mut self) {
        if let Some(setup) = self.0.take() {
            // Error disposal is not proof of child completion. Retain the Job
            // and original handles until an explicit recovery path owns them.
            std::mem::forget(setup);
        }
    }
}
pub(crate) fn is_setup_quarantine(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|error| error.is::<SetupQuarantine>())
}
pub(crate) fn take_quarantine(error: io::Error) -> Result<SetupQuarantine, io::Error> {
    if !is_setup_quarantine(&error) {
        return Err(error);
    }
    let kind = error.kind();
    match error.into_inner() {
        Some(inner) => match inner.downcast::<SetupQuarantine>() {
            Ok(retained) => Ok(*retained),
            Err(inner) => Err(io::Error::new(kind, inner)),
        },
        None => Err(io::Error::other(UNDETERMINED)),
    }
}

/// Attempt bounded cleanup on the spawning stack. If native completion cannot
/// be confirmed, return the typed quarantine with its original cause: disposal
/// retains the original Job/process capabilities and cannot authorize publication
/// or credential cleanup. No active recovery worker is promised by this retainer.
pub(crate) fn recover_setup_error(error: io::Error) -> io::Error {
    recover_setup_error_with_budget(error, std::time::Duration::from_millis(CLEANUP_MS.into()))
}
fn recover_setup_error_with_budget(error: io::Error, budget: std::time::Duration) -> io::Error {
    let mut retained = match take_quarantine(error) {
        Ok(retained) => retained,
        Err(error) => return error,
    };
    eprintln!("login_custody_retained: Windows setup cleanup pending");
    let end = std::time::Instant::now() + budget;
    loop {
        // Each observation may also spend the wire's single bounded cancellation
        // wait. Elapsed-budget expiry is a refusal, never an empty-Job receipt.
        if std::time::Instant::now() >= end {
            let kind = retained
                .1
                .as_ref()
                .map_or(io::ErrorKind::Other, io::Error::kind);
            return io::Error::new(kind, retained);
        }
        if retained.try_finalize().is_ok_and(|complete| complete) {
            // Cleanup latency cannot change the original spawn classification
            // or raw Win32 failure. FILE/PATH_NOT_FOUND must stay NotFound.
            return retained.1.take().unwrap_or_else(|| {
                io::Error::other("login_windows_setup_refused_after_confirmed_cleanup")
            });
        }
        // Setup abort already authorizes stopping only this operation's Job.
        // A failed stop/query is recoverable while this synchronous budget
        // remains. Expiry transfers the same capabilities to typed quarantine.
        let _ = retained.request_stop();
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn create_process(
    application: &[u16],
    command: &mut [u16],
    attrs: &Attributes,
    inherit: bool,
    stdio: Option<[HANDLE; 3]>,
    environment: Option<&[u16]>,
    cwd: Option<&[u16]>,
) -> io::Result<NativeProcess> {
    // SAFETY: zero initialization is valid for these Win32 input/output structs.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attrs.list;
    if let Some([stdin, stdout, stderr]) = stdio {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin;
        startup.StartupInfo.hStdOutput = stdout;
        startup.StartupInfo.hStdError = stderr;
    }
    // SAFETY: explicit application; writable NUL-terminated command; attributes,
    // arrays, environment, cwd and stdio handles live through this call.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            i32::from(inherit),
            CREATE_SUSPENDED
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.map_or(ptr::null(), |block| block.as_ptr().cast()),
            cwd.map_or(ptr::null(), |dir| dir.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    #[cfg(test)]
    CREATED_PROCESSES.with(|created| created.set(created.get() + 1));
    // SAFETY: successful creation transfers both original non-inherited handles.
    Ok(NativeProcess {
        process: unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) },
        pid: info.dwProcessId,
        status: None,
    })
}

struct PreparedStdio {
    child: OwnedHandle,
    parent: Option<File>,
}
// Broad inheritance exists only for the private plain-CreateProcess control.
// Every temporarily changed handle is a fresh prepared fixture endpoint, never
// a borrowed host standard handle. Restore before resuming the original child.
#[cfg(test)]
struct FixtureInheritanceGuard<'a> {
    handle: &'a OwnedHandle,
    flags: u32,
    restored: bool,
}
#[cfg(test)]
impl<'a> FixtureInheritanceGuard<'a> {
    fn new(handle: &'a OwnedHandle) -> io::Result<Self> {
        use windows_sys::Win32::Foundation::{
            GetHandleInformation, SetHandleInformation, HANDLE_FLAG_INHERIT,
        };
        let mut flags = 0;
        // SAFETY: borrowed exclusively owned fixture endpoint remains live.
        if unsafe { GetHandleInformation(raw(handle), &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: change only this private endpoint's inherit bit, not a host
        // handle or any other handle flags. The guard restores the original bit.
        if unsafe { SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            flags,
            restored: false,
        })
    }
    fn restore(&mut self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        if self.restored {
            return Ok(());
        }
        // SAFETY: the same private original endpoint is still borrowed/live.
        if unsafe {
            SetHandleInformation(
                raw(self.handle),
                HANDLE_FLAG_INHERIT,
                self.flags & HANDLE_FLAG_INHERIT,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}
#[cfg(test)]
impl Drop for FixtureInheritanceGuard<'_> {
    fn drop(&mut self) {
        if self.restore().is_err() {
            // The endpoint is private and its outer owner closes it on unwind;
            // this is a diagnostic failure, never a successful raw control.
            eprintln!("plain_fixture_inheritance_restore_unconfirmed");
        }
    }
}
#[cfg(test)]
struct PlainFixtureProcessGuard(Option<NativeProcess>);
#[cfg(test)]
impl Drop for PlainFixtureProcessGuard {
    fn drop(&mut self) {
        if let Some(process) = self.0.as_mut() {
            while process.terminate_and_confirm().is_err() {
                eprintln!("plain_fixture_original_process_cleanup_unconfirmed");
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}
/// Private raw control: no extended startup attributes, parent override, Job,
/// or donor. Only this function's owned stdio endpoints temporarily inherit.
#[cfg(test)]
pub(crate) fn spawn_plain_for_test(plan: &LaunchPlan) -> io::Result<CustodyChild> {
    spawn_plain_with_before_create_for_test(plan, |_| Ok(()))
}
#[cfg(test)]
fn spawn_plain_with_before_create_for_test(
    plan: &LaunchPlan,
    before_create: impl FnOnce([HANDLE; 3]) -> io::Result<()>,
) -> io::Result<CustodyChild> {
    use windows_sys::Win32::System::Threading::STARTUPINFOW;
    trace_spawn_stage_for_test("plain_validate_launch_plan");
    let parts = plan.build_for_spawn()?;
    let entries = environment(&parts)?;
    let changed_path = !parts.inherit_env
        || parts
            .env_changes
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"));
    let application = executable(&parts.program, &entries, changed_path)?;
    if application
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"))
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, BATCH));
    }
    let application = wide(application.as_os_str())?;
    let mut command = quote_command(&parts.program, &parts.args)?;
    let cwd = parts
        .current_dir
        .as_ref()
        .map(|path| current_directory(path))
        .transpose()?;
    let block = env_block(&entries);
    trace_spawn_stage_for_test("plain_prepare_local_stdin");
    let stdin = prepare_stdio(parts.stdin, STD_INPUT_HANDLE)?;
    trace_spawn_stage_for_test("plain_prepare_local_stdout");
    let stdout = prepare_stdio(parts.stdout, STD_OUTPUT_HANDLE)?;
    trace_spawn_stage_for_test("plain_prepare_local_stderr");
    let stderr = prepare_stdio(parts.stderr, STD_ERROR_HANDLE)?;
    trace_spawn_stage_for_test("plain_enable_fixture_stdio_inheritance");
    let mut inherited = Vec::with_capacity(3);
    for handle in [&stdin.child, &stdout.child, &stderr.child] {
        inherited.push(FixtureInheritanceGuard::new(handle)?);
    }
    // A private test gate can expose the entire eligible-handle window. The
    // existing plain controls use a no-op; production has no such hook.
    before_create([raw(&stdin.child), raw(&stdout.child), raw(&stderr.child)])?;
    // SAFETY: Win32 startup/process information are plain zeroable structs.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = raw(&stdin.child);
    startup.hStdOutput = raw(&stdout.child);
    startup.hStdError = raw(&stderr.child);
    trace_spawn_stage_for_test("plain_create_suspended_vendor");
    // SAFETY: explicit application and owned writable command, env/cwd, and
    // stdio live through creation. Plain STARTUPINFOW has no attributes/Job.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            cwd.as_ref().map_or(ptr::null(), |dir| dir.as_ptr()),
            &startup,
            &mut info,
        )
    };
    let create_error = (created == 0).then(io::Error::last_os_error);
    let mut pending = PlainFixtureProcessGuard(if created != 0 {
        CREATED_PROCESSES.with(|count| count.set(count.get() + 1));
        // SAFETY: successful creation transferred both actual original handles.
        Some(NativeProcess {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) },
            thread: unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) },
            pid: info.dwProcessId,
            status: None,
        })
    } else {
        None
    });
    if create_error.is_none() {
        trace_spawn_stage_for_test("plain_restore_fixture_stdio_inheritance");
    }
    let mut restore_error = None;
    for handle in &mut inherited {
        if let Err(error) = handle.restore() {
            restore_error.get_or_insert(error);
        }
    }
    if let Some(error) = create_error {
        return Err(error);
    }
    if let Some(error) = restore_error {
        return Err(error);
    }
    // End the private inheritance window before any child instruction executes.
    drop(inherited);
    let vendor = pending.0.as_ref().ok_or_else(invalid)?;
    trace_spawn_stage_for_test("plain_resume_vendor_primary_thread");
    // SAFETY: only the retained original suspended fixture primary thread.
    match unsafe { ResumeThread(raw(&vendor.thread)) } {
        1 => {}
        u32::MAX => return Err(io::Error::last_os_error()),
        _ => return Err(io::Error::other("plain_fixture_resume_refused")),
    }
    let vendor = pending.0.take().ok_or_else(invalid)?;
    trace_spawn_stage_for_test("plain_vendor_resumed");
    Ok(CustodyChild {
        #[cfg(test)]
        fixture_job: None,
        creator: None,
        process: Process::Native(vendor),
        stdin: stdin.parent.map(LoginWrite::SyncPipe),
        stdout: stdout.parent.map(LoginRead::SyncPipe),
        stderr: stderr.parent.map(LoginRead::SyncPipe),
    })
}
/// Functional coverage control for Windows automatic console/standard-handle
/// behavior. Requested plan streams are intentionally not prepared or wired.
#[cfg(test)]
pub(crate) fn spawn_automatic_stdio_for_test(plan: &LaunchPlan) -> io::Result<CustodyChild> {
    use windows_sys::Win32::System::Threading::STARTUPINFOW;
    trace_spawn_stage_for_test("automatic_validate_launch_plan");
    let parts = plan.build_for_spawn()?;
    let entries = environment(&parts)?;
    let changed_path = !parts.inherit_env
        || parts
            .env_changes
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"));
    let application = executable(&parts.program, &entries, changed_path)?;
    if application
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"))
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, BATCH));
    }
    let application = wide(application.as_os_str())?;
    let mut command = quote_command(&parts.program, &parts.args)?;
    let cwd = parts
        .current_dir
        .as_ref()
        .map(|path| current_directory(path))
        .transpose()?;
    let block = env_block(&entries);
    // SAFETY: Win32 startup/process information are plain zeroable structs.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // dwFlags and all hStd fields deliberately remain zero. There is no stdio
    // preparation, inheritable duplicate, attribute list, Job, or donor here.
    trace_spawn_stage_for_test("automatic_create_suspended_vendor");
    // SAFETY: explicit application and owned writable command/env/cwd remain
    // live. FALSE disables general inheritance; plain STARTUPINFOW uses defaults.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            cwd.as_ref().map_or(ptr::null(), |dir| dir.as_ptr()),
            &startup,
            &mut info,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    CREATED_PROCESSES.with(|count| count.set(count.get() + 1));
    // SAFETY: successful creation transferred both original owned handles.
    let mut pending = PlainFixtureProcessGuard(Some(NativeProcess {
        process: unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) },
        pid: info.dwProcessId,
        status: None,
    }));
    trace_spawn_stage_for_test("automatic_resume_vendor_primary_thread");
    // SAFETY: only this retained original suspended vendor primary thread.
    match unsafe { ResumeThread(raw(&pending.0.as_ref().ok_or_else(invalid)?.thread)) } {
        1 => {}
        u32::MAX => return Err(io::Error::last_os_error()),
        _ => return Err(io::Error::other("automatic_fixture_resume_refused")),
    }
    let vendor = pending.0.take().ok_or_else(invalid)?;
    trace_spawn_stage_for_test("automatic_vendor_resumed");
    Ok(CustodyChild {
        #[cfg(test)]
        fixture_job: None,
        creator: None,
        process: Process::Native(vendor),
        stdin: None,
        stdout: None,
        stderr: None,
    })
}
fn prepare_stdio(spec: LaunchStdio, id: u32) -> io::Result<PreparedStdio> {
    // SAFETY: pseudo handle is borrowed only for DuplicateHandle's duration.
    let current = unsafe { GetCurrentProcess() };
    let (child, parent) = match spec {
        LaunchStdio::Piped => {
            let (mut read, mut write) = (0, 0);
            // SAFETY: null security attributes make BOTH main handles non-inheritable.
            if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: each fresh synchronous pipe endpoint is owned exactly once.
            let read = unsafe { OwnedHandle::from_raw_handle(read as RawHandle) };
            let write = unsafe { OwnedHandle::from_raw_handle(write as RawHandle) };
            let (child, parent) = if id == STD_INPUT_HANDLE {
                (read, write)
            } else {
                (write, read)
            };
            (child, Some(File::from(parent)))
        }
        LaunchStdio::File(file) => (duplicate(current, raw(&file), current, false)?, None),
        LaunchStdio::Null => {
            let file = OpenOptions::new()
                .read(id == STD_INPUT_HANDLE)
                .write(id != STD_INPUT_HANDLE)
                .open(r"\\.\NUL")?;
            (OwnedHandle::from(file), None)
        }
        LaunchStdio::Inherit => {
            #[cfg(test)]
            trace_spawn_stage_for_test(match id {
                STD_INPUT_HANDLE => "get_inherited_stdin",
                STD_OUTPUT_HANDLE => "get_inherited_stdout",
                _ => "get_inherited_stderr",
            });
            // SAFETY: borrow the process standard handle; never transfer ownership.
            let (source, error) = unsafe {
                SetLastError(ERROR_SUCCESS);
                let source = GetStdHandle(id);
                (source, GetLastError())
            };
            if source == INVALID_HANDLE_VALUE
                && error != ERROR_SUCCESS
                && error != ERROR_INVALID_HANDLE
            {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            if source == 0 || source == INVALID_HANDLE_VALUE {
                return prepare_stdio(LaunchStdio::Null, id);
            }
            #[cfg(test)]
            trace_spawn_stage_for_test(match id {
                STD_INPUT_HANDLE => "resolve_inherited_stdin_file_type",
                STD_OUTPUT_HANDLE => "resolve_inherited_stdout_file_type",
                _ => "resolve_inherited_stderr_file_type",
            });
            // GetFileType distinguishes redirected files/pipes/devices at the
            // spawn boundary. CHAR is not a console classification. UNKNOWN
            // with NO_ERROR is valid; only INVALID_HANDLE maps to explicit NUL.
            // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype
            // SAFETY: read-only probe of this borrowed process-table handle;
            // reset last-error to distinguish a valid unknown device kind.
            let (kind, error) = unsafe {
                SetLastError(ERROR_SUCCESS);
                let kind = GetFileType(source);
                (kind, GetLastError())
            };
            if kind == FILE_TYPE_UNKNOWN && error != ERROR_SUCCESS {
                if error == ERROR_INVALID_HANDLE {
                    return prepare_stdio(LaunchStdio::Null, id);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            #[cfg(test)]
            trace_spawn_stage_for_test(match id {
                STD_INPUT_HANDLE => "duplicate_inherited_stdin_locally",
                STD_OUTPUT_HANDLE => "duplicate_inherited_stdout_locally",
                _ => "duplicate_inherited_stderr_locally",
            });
            (duplicate(current, source, current, false)?, None)
        }
    };
    Ok(PreparedStdio { child, parent })
}

fn quote_command(program: &OsStr, args: &[LaunchArg]) -> io::Result<Vec<u16>> {
    let name = wide(program)?;
    if name[..name.len() - 1].contains(&u16::from(b'"')) {
        return Err(invalid());
    }
    let mut result = vec![u16::from(b'"')];
    result.extend_from_slice(&name[..name.len() - 1]);
    result.push(u16::from(b'"'));
    for arg in args {
        result.push(u16::from(b' '));
        let (value, regular) = match arg {
            LaunchArg::Regular(value) => (value, true),
            LaunchArg::Raw(value) => (value, false),
        };
        let value = wide(value)?;
        let value = &value[..value.len() - 1];
        let quoted = regular && (value.is_empty() || value.iter().any(|c| *c == 32 || *c == 9));
        if quoted {
            result.push(34);
        }
        let mut slashes = 0;
        for &unit in value {
            if regular && unit == 92 {
                slashes += 1;
            } else {
                if regular && unit == 34 {
                    result.extend(std::iter::repeat_n(92, slashes + 1));
                }
                slashes = 0;
            }
            result.push(unit);
        }
        if quoted {
            result.extend(std::iter::repeat_n(92, slashes));
            result.push(34);
        }
    }
    result.push(0);
    if result.len() > 32_767 {
        return Err(invalid());
    }
    Ok(result)
}
fn compare_env(a: &[u16], b: &[u16]) -> Ordering {
    // SAFETY: validated lengths fit i32; Windows ordinal caseless comparison
    // matches its environment-key rules, including non-ASCII UTF-16 keys.
    match unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) }
    {
        CSTR_EQUAL => Ordering::Equal,
        CSTR_LESS_THAN => Ordering::Less,
        _ => Ordering::Greater,
    }
}
fn environment(parts: &LaunchParts) -> io::Result<Vec<(Vec<u16>, Vec<u16>)>> {
    let mut entries = Vec::new();
    if parts.inherit_env {
        // SAFETY: API allocates an immutable snapshot, freed exactly once below.
        let block = unsafe { GetEnvironmentStringsW() };
        if block.is_null() {
            return Err(io::Error::last_os_error());
        }
        struct Block(*mut u16);
        impl Drop for Block {
            fn drop(&mut self) {
                unsafe {
                    FreeEnvironmentStringsW(self.0);
                }
            }
        }
        let _block = Block(block);
        let mut cursor = block;
        // SAFETY: Windows returns a valid double-NUL-terminated environment
        // snapshot; each walk remains within its next NUL-terminated entry.
        unsafe {
            while *cursor != 0 {
                let mut len = 0;
                while *cursor.add(len) != 0 {
                    len += 1;
                }
                let entry = std::slice::from_raw_parts(cursor, len);
                let start = usize::from(entry.first() == Some(&61));
                let split = entry
                    .iter()
                    .enumerate()
                    .skip(start)
                    .find(|(_, c)| **c == 61)
                    .map(|(i, _)| i)
                    .ok_or_else(invalid)?;
                entries.push((entry[..split].to_vec(), entry[split + 1..].to_vec()));
                cursor = cursor.add(len + 1);
            }
        }
    }
    for (key, value) in &parts.env_changes {
        let mut key = wide(key)?;
        key.pop();
        if key.is_empty() || key.contains(&61) || key.len() > i32::MAX as usize {
            return Err(invalid());
        }
        entries.retain(|(existing, _)| compare_env(existing, &key) != Ordering::Equal);
        if let Some(value) = value {
            let mut value = wide(value)?;
            value.pop();
            entries.push((key, value));
        }
    }
    entries.sort_by(|(a, _), (b, _)| compare_env(a, b));
    Ok(entries)
}
// The private creator needs no vendor credentials, provider settings or PATH.
// Its executable is absolute; the vendor's complete env remains in the recipe.
fn creator_environment() -> io::Result<Vec<(Vec<u16>, Vec<u16>)>> {
    creator_environment_with(|key| std::env::var_os(key))
}
fn creator_environment_with(
    mut read: impl FnMut(&str) -> Option<OsString>,
) -> io::Result<Vec<(Vec<u16>, Vec<u16>)>> {
    let mut entries = Vec::new();
    for key in ["SystemRoot", "SystemDrive", "TEMP"] {
        if let Some(value) = read(key) {
            let mut key = wide(OsStr::new(key))?;
            key.pop();
            let mut value = wide(&value)?;
            value.pop();
            entries.push((key, value));
        }
    }
    entries.sort_by(|(left, _), (right, _)| compare_env(left, right));
    Ok(entries)
}

fn env_block(entries: &[(Vec<u16>, Vec<u16>)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(key);
        block.push(61);
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}
fn system_directory(windows: bool) -> io::Result<PathBuf> {
    let mut bytes = vec![0u16; 32_768];
    // SAFETY: writable allocation covers the supplied capacity.
    let size = unsafe {
        if windows {
            GetWindowsDirectoryW(bytes.as_mut_ptr(), bytes.len() as u32)
        } else {
            GetSystemDirectoryW(bytes.as_mut_ptr(), bytes.len() as u32)
        }
    };
    if size == 0 || size as usize >= bytes.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&bytes[..size as usize])))
}
fn full_path(path: &Path) -> io::Result<PathBuf> {
    let input = wide(path.as_os_str())?;
    let mut output = vec![0u16; 32_768];
    // SAFETY: NUL-terminated input and bounded writable output, no filepart needed.
    let size = unsafe {
        GetFullPathNameW(
            input.as_ptr(),
            output.len() as u32,
            output.as_mut_ptr(),
            ptr::null_mut(),
        )
    };
    if size == 0 || size as usize >= output.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&output[..size as usize])))
}
fn current_directory(path: &Path) -> io::Result<Vec<u16>> {
    let encoded = wide(path.as_os_str())?;
    let value = &encoded[..encoded.len() - 1];
    let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
    if let Some(rest) = value.strip_prefix(prefix.as_slice()) {
        let unc: Vec<u16> = r"UNC\".encode_utf16().collect();
        let candidate = if let Some(rest) = rest.strip_prefix(unc.as_slice()) {
            let mut candidate = vec![92, 92];
            candidate.extend(rest);
            candidate
        } else {
            rest.to_vec()
        };
        let candidate = PathBuf::from(OsString::from_wide(&candidate));
        if candidate.is_absolute() {
            return wide(candidate.as_os_str());
        }
    }
    Ok(encoded)
}
fn program_exists(path: &Path) -> bool {
    let Ok(path) = wide(path.as_os_str()) else {
        return false;
    };
    // SAFETY: valid NUL-terminated path. Match Rust's no-follow attribute probe
    // so an executable symlink is not rejected by a metadata-following check.
    unsafe { GetFileAttributesW(path.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}
fn executable(
    program: &OsStr,
    entries: &[(Vec<u16>, Vec<u16>)],
    changed_path: bool,
) -> io::Result<PathBuf> {
    let encoded = wide(program)?;
    if encoded.len() <= 1
        || encoded
            .get(encoded.len() - 2)
            .is_some_and(|c| *c == 92 || *c == 47)
    {
        return Err(invalid());
    }
    let path = Path::new(program);
    if encoded.iter().any(|c| *c == 92 || *c == 47 || *c == 58) || path.is_absolute() {
        let mut suffixed = program.to_os_string();
        suffixed.push(".exe");
        let has_exe = program.as_encoded_bytes().ends_with(b".exe")
            || program
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(".exe");
        let chosen = if !has_exe && program_exists(Path::new(&suffixed)) {
            Path::new(&suffixed)
        } else {
            path
        };
        return full_path(chosen);
    }
    let has_extension = encoded.contains(&46);
    let mut dirs = Vec::new();
    if changed_path {
        if let Some((_, value)) = entries
            .iter()
            .find(|(key, _)| compare_env(key, &[80, 65, 84, 72]) == Ordering::Equal)
        {
            dirs.extend(
                std::env::split_paths(&OsString::from_wide(value))
                    .filter(|path| !path.as_os_str().is_empty()),
            );
        }
    }
    if let Some(parent) = std::env::current_exe()?.parent() {
        dirs.push(parent.to_path_buf());
    }
    dirs.push(system_directory(false)?);
    dirs.push(system_directory(true)?);
    if let Some(paths) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&paths).filter(|path| !path.as_os_str().is_empty()));
    }
    for directory in dirs {
        let mut candidate = directory.join(path);
        if !has_extension {
            candidate.set_extension("exe");
        }
        if program_exists(&candidate) {
            return full_path(&candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "login_windows_program_missing",
    ))
}

#[cfg(test)]
fn spawn_attribute_variant_for_test(
    plan: &LaunchPlan,
    job: RawHandle,
    post_create: impl FnOnce(u32, RawHandle) -> io::Result<()>,
    variant: AttributeProbeVariant,
) -> io::Result<CustodyChild> {
    // Deliberately separate from production spawning. These native controls
    // vary one attribute set while preserving flags and actual stdio ownership.
    fn create(
        application: &[u16],
        command: &mut [u16],
        attrs: &Attributes,
        stdio: Option<[HANDLE; 3]>,
        environment: &[u16],
        cwd: Option<&[u16]>,
        flags: u32,
    ) -> io::Result<NativeProcess> {
        // SAFETY: Win32 startup/process outputs are plain zeroable structures.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attrs.list;
        if let Some([stdin, stdout, stderr]) = stdio {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = stdin;
            startup.StartupInfo.hStdOutput = stdout;
            startup.StartupInfo.hStdError = stderr;
        }
        // SAFETY: explicit owned application/command/env/cwd and exact live
        // attribute arrays. Configured flags are the actual argument, not an
        // inference from later process/console observations. Donor has no stdio
        // override and bInheritHandles FALSE; vendor has explicit stdio/TRUE.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                i32::from(stdio.is_some()),
                flags,
                environment.as_ptr().cast(),
                cwd.map_or(ptr::null(), |dir| dir.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        CREATED_PROCESSES.with(|count| count.set(count.get() + 1));
        // SAFETY: successful creation transfers these two original handles.
        Ok(NativeProcess {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) },
            thread: unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) },
            pid: info.dwProcessId,
            status: None,
        })
    }
    trace_spawn_stage_for_test("attribute_probe_validate_launch_plan");
    let parts = plan.build_for_spawn()?;
    let entries = environment(&parts)?;
    let changed_path = !parts.inherit_env
        || parts
            .env_changes
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"));
    let application = executable(&parts.program, &entries, changed_path)?;
    if application
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"))
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, BATCH));
    }
    let application = wide(application.as_os_str())?;
    let mut command = quote_command(&parts.program, &parts.args)?;
    let cwd = parts
        .current_dir
        .as_ref()
        .map(|path| current_directory(path))
        .transpose()?;
    let block = env_block(&entries);
    let donor_path = std::env::current_exe()?;
    let donor_application = wide(donor_path.as_os_str())?;
    let mut donor_command = Vec::new();
    let donor_block = initialized_donor_configuration_for_test(&mut donor_command, &block);
    let donor_flags = INITIALIZED_DONOR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|probe| probe.configured_donor_flags)
            .ok_or_else(invalid)
    })?;
    trace_spawn_stage_for_test("attribute_probe_prepare_local_stdin");
    let stdin = prepare_stdio(parts.stdin, STD_INPUT_HANDLE)?;
    trace_spawn_stage_for_test("attribute_probe_prepare_local_stdout");
    let stdout = prepare_stdio(parts.stdout, STD_OUTPUT_HANDLE)?;
    trace_spawn_stage_for_test("attribute_probe_prepare_local_stderr");
    let stderr = prepare_stdio(parts.stderr, STD_ERROR_HANDLE)?;
    // SAFETY: duplicate only this operation's retained dedicated Job.
    let current = unsafe { GetCurrentProcess() };
    let retained_job = duplicate(current, job as HANDLE, current, false)?;
    let jobs = [raw(&retained_job)];
    let mut setup = Setup {
        job: Some(retained_job),
        donor: None,
        vendor: None,
        donor_handles: Vec::with_capacity(3),
    };
    let result = (|| -> io::Result<()> {
        let mut donor_attrs = Attributes::new(1)?;
        donor_attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        trace_spawn_stage_for_test("attribute_probe_create_suspended_donor");
        setup.donor = Some(create(
            &donor_application,
            &mut donor_command,
            &donor_attrs,
            None,
            &donor_block,
            cwd.as_deref(),
            donor_flags,
        )?);
        checkpoint(
            SpawnCheckpoint::DonorCreated,
            setup.donor.as_ref().ok_or_else(invalid)?,
        )?;
        initialize_donor_for_test(setup.donor.as_ref().ok_or_else(invalid)?)?;
        let donor = raw(&setup.donor.as_ref().ok_or_else(invalid)?.process);
        let parent = [donor];
        let mut inherited = [0; 3];
        let mut local_inheritance = Vec::with_capacity(3);
        if variant == AttributeProbeVariant::ParentOnly {
            for (slot, source) in
                inherited
                    .iter_mut()
                    .zip([&stdin.child, &stdout.child, &stderr.child])
            {
                let mut remote = 0;
                trace_spawn_stage_for_test("attribute_probe_duplicate_stdio_into_donor");
                // SAFETY: only the retained donor receives each inheritable
                // duplicate. These numeric values belong to its handle table.
                if unsafe {
                    DuplicateHandle(
                        current,
                        raw(source),
                        donor,
                        &mut remote,
                        0,
                        1,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                *slot = remote;
                setup.donor_handles.push(remote);
            }
        } else {
            for (slot, source) in
                inherited
                    .iter_mut()
                    .zip([&stdin.child, &stdout.child, &stderr.child])
            {
                trace_spawn_stage_for_test("attribute_probe_enable_local_stdio_inheritance");
                local_inheritance.push(FixtureInheritanceGuard::new(source)?);
                *slot = raw(source);
            }
        }
        let mut attrs = Attributes::new(if variant == AttributeProbeVariant::NoParent {
            2
        } else {
            1
        })?;
        if matches!(
            variant,
            AttributeProbeVariant::NoParent | AttributeProbeVariant::JobOnly
        ) {
            trace_spawn_stage_for_test("attribute_probe_set_vendor_job");
            attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        }
        if variant == AttributeProbeVariant::ParentOnly {
            trace_spawn_stage_for_test("attribute_probe_set_vendor_parent");
            attrs.set(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent)?;
        }
        if matches!(
            variant,
            AttributeProbeVariant::NoParent | AttributeProbeVariant::HandleOnly
        ) {
            trace_spawn_stage_for_test("attribute_probe_set_vendor_handle_list");
            attrs.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
        }
        trace_spawn_stage_for_test("attribute_probe_create_suspended_vendor");
        let created = create(
            &application,
            &mut command,
            &attrs,
            Some(inherited),
            &block,
            cwd.as_deref(),
            PROBE_DONOR_CREATION_FLAGS,
        );
        let create_error = match created {
            Ok(vendor) => {
                setup.vendor = Some(vendor);
                None
            }
            Err(error) => Some(error),
        };
        let mut restore_error = None;
        for handle in &mut local_inheritance {
            if let Err(error) = handle.restore() {
                restore_error.get_or_insert(error);
            }
        }
        if let Some(error) = create_error {
            return Err(error);
        }
        if let Some(error) = restore_error {
            trace_spawn_stage_for_test("attribute_probe_restore_local_inheritance");
            return Err(error);
        }
        drop(local_inheritance);
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        let mut member = 0;
        trace_spawn_stage_for_test("attribute_probe_query_exact_job_membership");
        // PARENT_PROCESS itself may inherit a Job. Absence of JOB_LIST is not
        // proof of non-membership: query this exact original process and Job.
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
        // SAFETY: actual retained original vendor and dedicated Job handles.
        if unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                raw(&vendor.process),
                jobs[0],
                &mut member,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        INITIALIZED_DONOR.with(|slot| {
            if let Some(probe) = slot.borrow_mut().as_mut() {
                probe.vendor_in_requested_job = Some(member != 0);
            }
        });
        checkpoint(SpawnCheckpoint::VendorCreated, vendor)?;
        trace_spawn_stage_for_test("attribute_probe_post_create_observer");
        post_create(vendor.pid, vendor.process.as_raw_handle())?;
        if !setup.donor_handles.is_empty() {
            trace_spawn_stage_for_test("attribute_probe_close_donor_handles");
            setup.close_donor_handles()?;
        }
        if !retain_initialized_donor_for_test(&mut setup.donor)? {
            return Err(invalid());
        }
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        trace_spawn_stage_for_test("attribute_probe_resume_vendor_primary_thread");
        // SAFETY: only this retained original suspended vendor primary thread.
        match unsafe { ResumeThread(raw(&vendor.thread)) } {
            1 => {}
            u32::MAX => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("attribute_probe_resume_refused")),
        }
        checkpoint(SpawnCheckpoint::AfterResume, vendor)?;
        trace_spawn_stage_for_test("attribute_probe_vendor_resumed");
        Ok(())
    })();
    if let Err(error) = result {
        // Includes direct original-vendor termination even when this variant
        // omitted JOB_LIST and the dedicated Job does not contain the vendor.
        if setup.cleanup().is_err() {
            let mut retained = SetupQuarantine(Some(setup), Some(error));
            loop {
                if retained.try_finalize().is_ok_and(|done| done) {
                    return Err(retained.1.take().ok_or_else(invalid)?);
                }
                // These controls may omit the vendor Job assignment. Retrying
                // Job termination alone cannot stop an unassigned original
                // vendor, so keep its direct owned-handle authority throughout
                // synchronous quarantine recovery on this spawning stack.
                if let Some(setup) = retained.0.as_mut() {
                    if let Some(vendor) = setup.vendor.as_mut() {
                        let _ = vendor.kill();
                    }
                    if let Some(donor) = setup.donor.as_mut() {
                        let _ = donor.kill();
                    }
                }
                let _ = retained.request_stop();
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
        return Err(error);
    }
    let vendor = setup.vendor.take().ok_or_else(invalid)?;
    Ok(CustodyChild {
        #[cfg(test)]
        fixture_job: None,
        creator: None,
        process: Process::Native(vendor),
        stdin: stdin.parent.map(LoginWrite::SyncPipe),
        stdout: stdout.parent.map(LoginRead::SyncPipe),
        stderr: stderr.parent.map(LoginRead::SyncPipe),
    })
}

#[cfg(test)]
std::thread_local! {
    static HELPER_EXECUTABLE_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static FORCE_CREATOR_OVERRIDE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CREATOR_HELPER_LAUNCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CREATOR_MAIN_STDIO_HOOK: std::cell::RefCell<Option<CreatorMainStdioHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
type CreatorMainStdioHook =
    Box<dyn FnMut(u32, RawHandle, [Option<RawHandle>; 3]) -> io::Result<()>>;
#[cfg(test)]
fn set_creator_main_stdio_hook_for_test(
    hook: impl FnMut(u32, RawHandle, [Option<RawHandle>; 3]) -> io::Result<()> + 'static,
) {
    CREATOR_MAIN_STDIO_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}
#[cfg(test)]
pub(crate) fn creator_helper_launch_count_for_test() -> usize {
    CREATOR_HELPER_LAUNCHES.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(crate) struct HelperExecutableGuard {
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl Drop for HelperExecutableGuard {
    fn drop(&mut self) {
        HELPER_EXECUTABLE_OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
        FORCE_CREATOR_OVERRIDE.with(|slot| slot.set(false));
    }
}
#[cfg(test)]
pub(crate) fn helper_executable_override_for_test(
    path: PathBuf,
    force_creator: bool,
) -> io::Result<HelperExecutableGuard> {
    if !path.is_absolute() || !path.is_file() {
        return Err(invalid());
    }
    HELPER_EXECUTABLE_OVERRIDE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(invalid());
        }
        *slot = Some(path);
        FORCE_CREATOR_OVERRIDE.with(|slot| slot.set(force_creator));
        Ok(HelperExecutableGuard {
            _thread: std::marker::PhantomData,
        })
    })
}
fn process_birth(handle: &impl AsRawHandle) -> io::Result<u64> {
    process_birth_raw(raw(handle))
}
fn process_birth_raw(handle: HANDLE) -> io::Result<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    // SAFETY: FILETIME is a pair of integer DWORDs, zero is a valid initial value.
    let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: retained original process and separate typed outputs.
    if unsafe { GetProcessTimes(handle, created, exited, kernel, user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
fn console_handle(handle: HANDLE, kind: u32) -> io::Result<bool> {
    if kind != windows_sys::Win32::Storage::FileSystem::FILE_TYPE_CHAR {
        return Ok(false);
    }
    let mut mode = 0;
    // SAFETY: read-only query of a retained/borrowed standard handle.
    if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}
fn inherited_handle(id: u32) -> io::Result<Option<(HANDLE, u32)>> {
    // SAFETY: borrow only; clear error to classify absence without stale state.
    let (handle, error) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let h = GetStdHandle(id);
        (h, GetLastError())
    };
    if handle == 0 || handle == INVALID_HANDLE_VALUE {
        if error != ERROR_SUCCESS && error != ERROR_INVALID_HANDLE {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        return Ok(None);
    }
    // SAFETY: read-only handle kind probe, with documented UNKNOWN distinction.
    let (kind, error) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let kind = GetFileType(handle);
        (kind, GetLastError())
    };
    if kind == FILE_TYPE_UNKNOWN && error != ERROR_SUCCESS {
        if error == ERROR_INVALID_HANDLE {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(Some((handle, kind)))
}
fn automatic_own_stdio(parts: &LaunchParts) -> io::Result<bool> {
    if !matches!(&parts.stdin, LaunchStdio::Inherit)
        || !matches!(&parts.stdout, LaunchStdio::Inherit)
        || !matches!(&parts.stderr, LaunchStdio::Inherit)
    {
        return Ok(false);
    }
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let Some((handle, kind)) = inherited_handle(id)? else {
            return Ok(false);
        };
        if id == STD_OUTPUT_HANDLE && kind == FILE_TYPE_DISK {
            continue;
        }
        if !console_handle(handle, kind)? {
            return Ok(false);
        }
    }
    Ok(true)
}
struct CreatorStream {
    prepared: Option<PreparedStdio>,
    slot: windows_helper_wire::StdioSlot,
}
fn prepare_creator_stream(spec: LaunchStdio, id: u32) -> io::Result<CreatorStream> {
    use windows_helper_wire::{Direction, RemoteKind, StdioSlot};
    let direction = if id == STD_INPUT_HANDLE {
        Direction::Input
    } else {
        Direction::Output
    };
    let prepared = match spec {
        LaunchStdio::Null => {
            return Ok(CreatorStream {
                prepared: None,
                slot: StdioSlot::Null,
            })
        }
        LaunchStdio::Inherit => {
            let Some((source, kind)) = inherited_handle(id)? else {
                return Ok(CreatorStream {
                    prepared: None,
                    slot: StdioSlot::Null,
                });
            };
            if console_handle(source, kind)? {
                return Ok(CreatorStream {
                    prepared: None,
                    slot: StdioSlot::LocalConsole,
                });
            }
            // SAFETY: own a non-inheritable local duplicate before classifying
            // the retained object again. No remote console duplication occurs.
            let current = unsafe { GetCurrentProcess() };
            PreparedStdio {
                child: duplicate(current, source, current, false)?,
                parent: None,
            }
        }
        other => prepare_stdio(other, id)?,
    };
    // SAFETY: this newly retained local endpoint lives through remote transfer.
    let kind = unsafe { GetFileType(raw(&prepared.child)) };
    if console_handle(raw(&prepared.child), kind)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "login_explicit_console_stream_unsupported",
        ));
    }
    let kind = match kind {
        FILE_TYPE_PIPE => RemoteKind::Pipe,
        FILE_TYPE_DISK | windows_sys::Win32::Storage::FileSystem::FILE_TYPE_CHAR => {
            RemoteKind::File
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "login_stdio_kind_unsupported",
            ))
        }
    };
    Ok(CreatorStream {
        prepared: Some(prepared),
        slot: StdioSlot::RemotePipeOrFile {
            handle: 0,
            kind,
            direction,
        },
    })
}
// Before identity validation these capabilities may only be closed. In
// particular, a malformed Born packet never grants termination authority.
struct UnvalidatedVendorCaps {
    process: OwnedHandle,
    thread: OwnedHandle,
}
fn pull_vendor(
    helper: &NativeProcess,
    born: windows_helper_wire::Born,
    job: HANDLE,
) -> io::Result<NativeProcess> {
    let process_value = usize::try_from(born.process_handle).map_err(|_| invalid())?;
    let thread_value = usize::try_from(born.thread_handle).map_err(|_| invalid())?;
    if process_value == 0
        || thread_value == 0
        || process_value == usize::MAX
        || thread_value == usize::MAX
    {
        return Err(invalid());
    }
    // SAFETY: pull only from the retained original helper, never a PID lookup.
    let current = unsafe { GetCurrentProcess() };
    let caps = UnvalidatedVendorCaps {
        process: duplicate(
            raw(&helper.process),
            process_value as HANDLE,
            current,
            false,
        )?,
        thread: duplicate(raw(&helper.process), thread_value as HANDLE, current, false)?,
    };
    // SAFETY: read-only identity queries; no signal/resume before all checks.
    let actual_pid = unsafe { GetProcessId(raw(&caps.process)) };
    if actual_pid == 0 {
        return Err(io::Error::last_os_error());
    }
    let thread_pid = unsafe { GetProcessIdOfThread(raw(&caps.thread)) };
    if thread_pid == 0 {
        return Err(io::Error::last_os_error());
    }
    let actual_tid = unsafe { GetThreadId(raw(&caps.thread)) };
    if actual_tid == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut member = 0;
    if unsafe {
        windows_sys::Win32::System::JobObjects::IsProcessInJob(raw(&caps.process), job, &mut member)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if actual_pid != born.pid
        || thread_pid != born.pid
        || actual_tid != born.tid
        || member == 0
        || born.pid == helper.pid
        || born.pid == std::process::id()
        || process_birth(&caps.process)? != born.birth
    {
        return Err(io::Error::other("login_creator_born_identity_refused"));
    }
    for handle in [raw(&caps.process), raw(&caps.thread)] {
        // SAFETY: these pulled capabilities remain close-only until both
        // original process and primary thread are proven unsignalled.
        match unsafe { WaitForSingleObject(handle, 0) } {
            258 => {}
            0xffff_ffff => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("login_creator_born_already_exited")),
        }
    }
    Ok(NativeProcess {
        process: caps.process,
        thread: caps.thread,
        pid: born.pid,
        status: None,
    })
}

#[cfg(test)]
fn helper_bootstrap_stdio_for_test(
    executable_override: bool,
    uses_console: bool,
) -> Option<[HANDLE; 3]> {
    if !executable_override && !uses_console {
        // Rust libtest prints before the actor runs. Explicit NULL slots sink
        // that prelude without transferring parent streams or new handles.
        // Vendor stdio arrives later through the authenticated private recipe.
        Some([0; 3])
    } else {
        // Console recipes need actual console slots; executable overrides keep
        // the production startup shape. Neither is a libtest output sink.
        None
    }
}

pub(crate) fn spawn(
    plan: &LaunchPlan,
    job: RawHandle,
    post_create: impl FnOnce(u32, RawHandle) -> io::Result<()>,
) -> io::Result<CustodyChild> {
    #[cfg(test)]
    if INITIALIZED_DONOR.with(|slot| slot.borrow().is_some()) {
        return spawn_legacy_parent_for_test(plan, job, post_create);
    }
    #[cfg(test)]
    trace_spawn_stage_for_test("validate_launch_plan");
    let parts = plan.build_for_spawn()?;
    let entries = environment(&parts)?;
    let changed_path = !parts.inherit_env
        || parts
            .env_changes
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"));
    let application = executable(&parts.program, &entries, changed_path)?;
    if application
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"))
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, BATCH));
    }
    let application = wide(application.as_os_str())?;
    let command_line = quote_command(&parts.program, &parts.args)?;
    let current_dir = parts
        .current_dir
        .as_ref()
        .map(|path| current_directory(path))
        .transpose()?;
    let block = env_block(&entries);
    let automatic = automatic_own_stdio(&parts)?;
    #[cfg(test)]
    let automatic = automatic && !FORCE_CREATOR_OVERRIDE.with(std::cell::Cell::get);
    // All Job references remain non-inheritable in this main process.
    let current = unsafe { GetCurrentProcess() };
    let retained_job = duplicate(current, job as HANDLE, current, false)?;
    let jobs = [raw(&retained_job)];
    let mut setup = Setup {
        job: Some(retained_job),
        donor: None,
        vendor: None,
        donor_handles: Vec::new(),
    };
    let mut streams = if automatic {
        None
    } else {
        Some([
            prepare_creator_stream(parts.stdin, STD_INPUT_HANDLE)?,
            prepare_creator_stream(parts.stdout, STD_OUTPUT_HANDLE)?,
            prepare_creator_stream(parts.stderr, STD_ERROR_HANDLE)?,
        ])
    };
    let result = (|| -> io::Result<()> {
        let mut attrs = Attributes::new(1)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        if automatic {
            #[cfg(test)]
            trace_spawn_stage_for_test("automatic_create_suspended_vendor");
            let mut command_line = command_line.clone();
            setup.vendor = Some(create_process(
                &application,
                &mut command_line,
                &attrs,
                false,
                None,
                Some(&block),
                current_dir.as_deref(),
            )?);
        } else {
            let mut server = windows_helper_wire::Server::create()?;
            // SAFETY: borrowed current process pseudo handle only.
            let main_birth = process_birth_raw(current)?;
            let bootstrap = server.bootstrap_args(std::process::id(), main_birth);
            #[cfg(not(test))]
            let helper_path = std::env::current_exe()?;
            #[cfg(test)]
            let override_path = HELPER_EXECUTABLE_OVERRIDE.with(|slot| slot.borrow().clone());
            #[cfg(test)]
            let helper_path = override_path
                .clone()
                .map_or_else(std::env::current_exe, Ok)?;
            let helper_application = wide(helper_path.as_os_str())?;
            let args = bootstrap.to_argv();
            let helper_args: Vec<LaunchArg> =
                args.iter().cloned().map(LaunchArg::Regular).collect();
            let helper_entries = creator_environment()?;
            let helper_block = env_block(&helper_entries);
            #[cfg(test)]
            let (helper_args, helper_block) = if override_path.is_none() {
                let boot: Vec<String> = args
                    .iter()
                    .map(|arg| arg.to_str().map(str::to_owned).ok_or_else(invalid))
                    .collect::<io::Result<_>>()?;
                let mut helper_entries = helper_entries.clone();
                let carrier_key: Vec<u16> = "CSQ_PRIVATE_VENDOR_CREATOR_BOOTSTRAP_V1"
                    .encode_utf16()
                    .collect();
                helper_entries.retain(|(key, _)| compare_env(key, &carrier_key) != Ordering::Equal);
                helper_entries.push((
                    carrier_key,
                    serde_json::to_string(&boot)?.encode_utf16().collect(),
                ));
                helper_entries.sort_by(|(left, _), (right, _)| compare_env(left, right));
                let argv = ["login_child_custody::windows_process::creator_helper::tests::creator_helper_actor", "--exact", "--ignored", "--nocapture", "--quiet", "--test-threads=1"];
                (
                    argv.map(|arg| LaunchArg::Regular(arg.into()))
                        .into_iter()
                        .collect::<Vec<_>>(),
                    env_block(&helper_entries),
                )
            } else {
                (helper_args, helper_block)
            };
            let mut helper_command = quote_command(helper_path.as_os_str(), &helper_args)?;
            #[cfg(not(test))]
            let helper_stdio = None;
            #[cfg(test)]
            let helper_stdio = helper_bootstrap_stdio_for_test(
                override_path.is_some(),
                streams.as_ref().ok_or_else(invalid)?.iter().any(|stream| {
                    matches!(stream.slot, windows_helper_wire::StdioSlot::LocalConsole)
                }),
            );
            #[cfg(test)]
            trace_spawn_stage_for_test("creator_create_suspended_helper");
            setup.donor = Some(create_process(
                &helper_application,
                &mut helper_command,
                &attrs,
                false,
                helper_stdio,
                Some(&helper_block),
                current_dir.as_deref(),
            )?);
            #[cfg(test)]
            CREATOR_HELPER_LAUNCHES.with(|count| count.set(count.get() + 1));
            #[cfg(test)]
            checkpoint(
                SpawnCheckpoint::DonorCreated,
                setup.donor.as_ref().ok_or_else(invalid)?,
            )?;
            let helper = setup.donor.as_ref().ok_or_else(invalid)?;
            let streams = streams.as_mut().ok_or_else(invalid)?;
            for stream in streams.iter_mut() {
                if let (
                    Some(prepared),
                    windows_helper_wire::StdioSlot::RemotePipeOrFile { handle, .. },
                ) = (&stream.prepared, &mut stream.slot)
                {
                    let mut remote = 0;
                    // SAFETY: duplicate a qualified pipe/file endpoint only
                    // into the retained original suspended helper, FALSE.
                    if unsafe {
                        DuplicateHandle(
                            current,
                            raw(&prepared.child),
                            raw(&helper.process),
                            &mut remote,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS,
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    *handle = remote as u64;
                }
            }
            // Bootstrap recipe follows creation: remote handle values did not
            // exist when the helper's command line was constructed.
            let recipe = windows_helper_wire::Recipe {
                application: application.clone(),
                command_line: command_line.clone(),
                environment: block.clone(),
                current_dir: current_dir.clone(),
                stdio: [
                    std::mem::replace(&mut streams[0].slot, windows_helper_wire::StdioSlot::Null),
                    std::mem::replace(&mut streams[1].slot, windows_helper_wire::StdioSlot::Null),
                    std::mem::replace(&mut streams[2].slot, windows_helper_wire::StdioSlot::Null),
                ],
            };
            #[cfg(test)]
            CREATOR_MAIN_STDIO_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(
                        helper.pid,
                        helper.process.as_raw_handle(),
                        [
                            streams[0]
                                .prepared
                                .as_ref()
                                .map(|s| s.child.as_raw_handle()),
                            streams[1]
                                .prepared
                                .as_ref()
                                .map(|s| s.child.as_raw_handle()),
                            streams[2]
                                .prepared
                                .as_ref()
                                .map(|s| s.child.as_raw_handle()),
                        ],
                    )?;
                }
                Ok::<_, io::Error>(())
            })?;
            // SAFETY: resume only the original helper's suspended primary thread.
            match unsafe { ResumeThread(raw(&helper.thread)) } {
                1 => {}
                u32::MAX => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("login_creator_resume_count_refused")),
            }
            #[cfg(test)]
            trace_spawn_stage_for_test("creator_exchange_recipe_and_born");
            let born = server.exchange(
                helper.process.as_handle(),
                &recipe,
                std::time::Duration::from_secs(10),
            )?;
            #[cfg(test)]
            trace_spawn_stage_for_test("creator_pull_validate_vendor");
            setup.vendor = Some(pull_vendor(helper, born, jobs[0])?);
            if setup
                .donor
                .as_mut()
                .ok_or_else(invalid)?
                .try_wait()?
                .is_some()
            {
                return Err(io::Error::other("login_creator_exited_before_publication"));
            }
        }
        #[cfg(test)]
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        #[cfg(test)]
        checkpoint(SpawnCheckpoint::VendorCreated, vendor)?;
        if let Some(helper) = setup.donor.as_mut() {
            if helper.try_wait()?.is_some() {
                return Err(io::Error::other("login_creator_exited_before_publication"));
            }
        }
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("post_create_observer");
        post_create(vendor.pid, vendor.process.as_raw_handle())?;
        if let Some(helper) = setup.donor.as_mut() {
            if helper.try_wait()?.is_some() {
                return Err(io::Error::other("login_creator_exited_before_resume"));
            }
        }
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("resume_vendor_primary_thread");
        // Main is the sole authority that resumes the validated original vendor.
        match unsafe { ResumeThread(raw(&vendor.thread)) } {
            1 => {}
            u32::MAX => return Err(io::Error::last_os_error()),
            _ => return Err(io::Error::other("login_vendor_resume_count_refused")),
        }
        #[cfg(test)]
        checkpoint(SpawnCheckpoint::AfterResume, vendor)?;
        Ok(())
    })();
    if let Err(error) = result {
        let processes_clean = setup.cleanup().is_ok();
        if !processes_clean || !wire_cleanup_ready(&error) {
            return Err(io::Error::other(SetupQuarantine(Some(setup), Some(error))));
        }
        return Err(error);
    }
    let vendor = setup.vendor.take().ok_or_else(invalid)?;
    let creator = setup.donor.take().map(|process| CreatorLease { process });
    let [stdin, stdout, stderr] = streams.take().unwrap_or_else(|| {
        [
            CreatorStream {
                prepared: None,
                slot: windows_helper_wire::StdioSlot::Null,
            },
            CreatorStream {
                prepared: None,
                slot: windows_helper_wire::StdioSlot::Null,
            },
            CreatorStream {
                prepared: None,
                slot: windows_helper_wire::StdioSlot::Null,
            },
        ]
    });
    Ok(CustodyChild {
        #[cfg(test)]
        fixture_job: Some(job as HANDLE),
        process: Process::Native(vendor),
        creator,
        stdin: stdin
            .prepared
            .and_then(|stream| stream.parent)
            .map(LoginWrite::SyncPipe),
        stdout: stdout
            .prepared
            .and_then(|stream| stream.parent)
            .map(LoginRead::SyncPipe),
        stderr: stderr
            .prepared
            .and_then(|stream| stream.parent)
            .map(LoginRead::SyncPipe),
    })
}

#[cfg(test)]
fn spawn_legacy_parent_for_test(
    plan: &LaunchPlan,
    job: RawHandle,
    post_create: impl FnOnce(u32, RawHandle) -> io::Result<()>,
) -> io::Result<CustodyChild> {
    #[cfg(test)]
    if let Some(variant) =
        INITIALIZED_DONOR.with(|slot| slot.borrow().as_ref().and_then(|probe| probe.variant))
    {
        return spawn_attribute_variant_for_test(plan, job, post_create, variant);
    }
    #[cfg(test)]
    trace_spawn_stage_for_test("validate_launch_plan");
    let parts = plan.build_for_spawn()?;
    let entries = environment(&parts)?;
    let changed_path = !parts.inherit_env
        || parts
            .env_changes
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"));
    let application = executable(&parts.program, &entries, changed_path)?;
    // Refuse shell wrappers BEFORE creating even the donor. No shell joining.
    if application
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"))
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, BATCH));
    }
    let application = wide(application.as_os_str())?;
    let mut command = quote_command(&parts.program, &parts.args)?;
    let cwd = parts
        .current_dir
        .as_ref()
        .map(|path| current_directory(path))
        .transpose()?;
    let block = env_block(&entries);
    let donor_path = std::env::current_exe()?;
    let donor_application = wide(donor_path.as_os_str())?;
    let mut donor_command = quote_command(
        donor_path.as_os_str(),
        &[LaunchArg::Regular("--csq-suspended-handle-donor".into())],
    )?;
    #[cfg(test)]
    let donor_block = initialized_donor_configuration_for_test(&mut donor_command, &block);
    #[cfg(test)]
    let donor_environment = &donor_block;
    #[cfg(not(test))]
    let donor_environment = &block;
    #[cfg(test)]
    trace_spawn_stage_for_test("prepare_local_stdin");
    let stdin = prepare_stdio(parts.stdin, STD_INPUT_HANDLE)?;
    #[cfg(test)]
    trace_spawn_stage_for_test("prepare_local_stdout");
    let stdout = prepare_stdio(parts.stdout, STD_OUTPUT_HANDLE)?;
    #[cfg(test)]
    trace_spawn_stage_for_test("prepare_local_stderr");
    let stderr = prepare_stdio(parts.stderr, STD_ERROR_HANDLE)?;
    // SAFETY: caller retains the configured Job for this call. The duplicate
    // keeps that exact Job alive if setup cleanup becomes unconfirmed.
    let current = unsafe { GetCurrentProcess() };
    #[cfg(test)]
    trace_spawn_stage_for_test("retain_job");
    let retained_job = duplicate(current, job as HANDLE, current, false)?;
    let jobs = [raw(&retained_job)];
    let mut setup = Setup {
        job: Some(retained_job),
        donor: None,
        vendor: None,
        donor_handles: Vec::with_capacity(3),
    };
    let result = (|| -> io::Result<()> {
        #[cfg(test)]
        trace_spawn_stage_for_test("initialize_donor_attributes");
        let mut donor_attrs = Attributes::new(1)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("set_donor_job_attribute");
        donor_attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("create_suspended_donor");
        setup.donor = Some(create_process(
            &donor_application,
            &mut donor_command,
            &donor_attrs,
            false,
            None,
            Some(donor_environment),
            cwd.as_deref(),
        )?);
        #[cfg(test)]
        checkpoint(
            SpawnCheckpoint::DonorCreated,
            setup.donor.as_ref().ok_or_else(invalid)?,
        )?;
        #[cfg(test)]
        initialize_donor_for_test(setup.donor.as_ref().ok_or_else(invalid)?)?;
        let donor = raw(&setup.donor.as_ref().ok_or_else(invalid)?.process);
        let mut inherited = [0; 3];
        for (slot, source) in inherited
            .iter_mut()
            .zip([&stdin.child, &stdout.child, &stderr.child])
        {
            #[cfg(test)]
            trace_spawn_stage_for_test(match setup.donor_handles.len() {
                0 => "duplicate_stdin_into_donor",
                1 => "duplicate_stdout_into_donor",
                _ => "duplicate_stderr_into_donor",
            });
            let mut remote = 0;
            // SAFETY: only the suspended donor receives an inheritable duplicate;
            // no main-process handle ever becomes inheritable.
            if unsafe {
                DuplicateHandle(
                    current,
                    raw(source),
                    donor,
                    &mut remote,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            *slot = remote;
            setup.donor_handles.push(remote);
        }
        let parent = [donor];
        #[cfg(test)]
        trace_spawn_stage_for_test("initialize_vendor_attributes");
        let mut attrs = Attributes::new(3)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("set_vendor_job_attribute");
        attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("set_vendor_parent_attribute");
        attrs.set(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("set_vendor_handle_allowlist");
        attrs.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("create_suspended_vendor");
        setup.vendor = Some(create_process(
            &application,
            &mut command,
            &attrs,
            true,
            Some(inherited),
            Some(&block),
            cwd.as_deref(),
        )?);
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        #[cfg(test)]
        checkpoint(SpawnCheckpoint::VendorCreated, vendor)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("post_create_observer");
        post_create(vendor.pid, vendor.process.as_raw_handle())?;
        #[cfg(test)]
        trace_spawn_stage_for_test("close_donor_handles");
        setup.close_donor_handles()?;
        #[cfg(test)]
        trace_spawn_stage_for_test("terminate_and_reap_donor");
        #[cfg(test)]
        {
            if !retain_initialized_donor_for_test(&mut setup.donor)? {
                setup
                    .donor
                    .as_mut()
                    .ok_or_else(invalid)?
                    .terminate_and_confirm()?;
                setup.donor.take();
            }
        }
        #[cfg(not(test))]
        {
            setup
                .donor
                .as_mut()
                .ok_or_else(invalid)?
                .terminate_and_confirm()?;
            setup.donor.take();
        }
        let vendor = setup.vendor.as_ref().ok_or_else(invalid)?;
        // SAFETY: resume ONLY the original vendor's primary thread. The
        // production donor never ran (the initialized comparison is cfg(test)).
        #[cfg(test)]
        trace_spawn_stage_for_test("resume_vendor_primary_thread");
        if unsafe { ResumeThread(raw(&vendor.thread)) } != 1 {
            return Err(io::Error::other("login_windows_resume_refused"));
        }
        #[cfg(test)]
        checkpoint(SpawnCheckpoint::AfterResume, vendor)?;
        #[cfg(test)]
        trace_spawn_stage_for_test("vendor_resumed");
        Ok(())
    })();
    if let Err(error) = result {
        if setup.cleanup().is_err() {
            return Err(io::Error::other(SetupQuarantine(Some(setup), Some(error))));
        }
        return Err(error);
    }
    let vendor = setup.vendor.take().ok_or_else(invalid)?;
    Ok(CustodyChild {
        #[cfg(test)]
        fixture_job: None,
        creator: None,
        process: Process::Native(vendor),
        stdin: stdin.parent.map(LoginWrite::SyncPipe),
        stdout: stdout.parent.map(LoginRead::SyncPipe),
        stderr: stderr.parent.map(LoginRead::SyncPipe),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc, Arc, Mutex,
    };
    use std::time::{Duration, Instant};
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, FILETIME, HANDLE_FLAG_INHERIT},
        Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
        System::{
            JobObjects::{
                CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::GetProcessTimes,
        },
    };

    const STDIO_ENTRY: &str =
        "login_child_custody::windows_process::tests::private_stdio_isolation_actor";
    const STDIO_ROOT: &str = "CSQ_PRIVATE_STDIO_ISOLATION_ROOT";
    const STDIO_ROLE: &str = "CSQ_PRIVATE_STDIO_ISOLATION_ROLE";
    const STDIO_NONCE: &str = "CSQ_PRIVATE_STDIO_ISOLATION_NONCE";
    const STDIO_SENTINEL: &str = "CSQ_PRIVATE_STDIO_SENTINEL_HANDLE";
    const STDIO_NATIVE_LEAK: &str = "CSQ_PRIVATE_STDIO_NATIVE_LEAK_HANDLE";
    const STDIO_UNKNOWN: &str = "WINDOWS_STDIO_ISOLATION_UNDETERMINED";
    const STDIO_BUDGET: Duration = Duration::from_secs(5);

    #[test]
    fn finalized_setup_recovery_preserves_original_win32_error_and_source() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        };
        for code in [
            ERROR_FILE_NOT_FOUND,
            ERROR_PATH_NOT_FOUND,
            ERROR_ACCESS_DENIED,
        ] {
            let original = io::Error::from_raw_os_error(code as i32);
            let kind = original.kind();
            // Custody is already settled; this test exercises error transport,
            // not a fabricated process exit or a simulated cleanup verdict.
            let pending = SetupQuarantine(None, Some(original));
            let cause = std::error::Error::source(&pending)
                .and_then(|cause| cause.downcast_ref::<io::Error>())
                .expect("original typed I/O error remains in the source chain");
            assert_eq!(cause.raw_os_error(), Some(code as i32));
            let recovered = recover_setup_error(io::Error::other(pending));
            assert_eq!(recovered.raw_os_error(), Some(code as i32));
            assert_eq!(recovered.kind(), kind);
            if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
                assert_eq!(recovered.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    #[test]
    fn pull_vendor_rejects_actual_foreign_job_with_original_cleanup_custody_retained() {
        let _environment = csq_core::platform::test_env::lock();
        let observed = (|| -> io::Result<()> {
            let sandbox = tempfile::tempdir()?;
            for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
                std::fs::create_dir(sandbox.path().join(name))?;
            }
            let make_job = || -> io::Result<OwnedHandle> {
                // SAFETY: fresh unnamed, noninherited fixture-only Job.
                let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
                if job == 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: exactly one ownership transfer of successful creation.
                let job = unsafe { OwnedHandle::from_raw_handle(job as RawHandle) };
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
                    unsafe { std::mem::zeroed() };
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                // SAFETY: initialized policy for only this original Job.
                if unsafe {
                    SetInformationJobObject(
                        raw(&job),
                        JobObjectExtendedLimitInformation,
                        (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(job)
            };
            let cleanup_job = make_job()?;
            let foreign_job = make_job()?;
            let plan = stdio_plan(sandbox.path(), "FAKETEST_PULL_VENDOR", "vendor")?;
            let parts = plan.build_for_spawn()?;
            let application = wide(std::env::current_exe()?.as_os_str())?;
            let mut command = quote_command(&parts.program, &parts.args)?;
            let block = env_block(&environment(&parts)?);
            let cwd = current_directory(sandbox.path())?;
            let mut attrs = Attributes::new(1)?;
            let cleanup_jobs = [raw(&cleanup_job)];
            attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &cleanup_jobs)?;
            // The original PI is retained, suspended and never resumed. Its
            // cleanup authority remains the original Job plus original PI.
            let mut original = PlainFixtureProcessGuard(Some(create_process(
                &application,
                &mut command,
                &attrs,
                false,
                None,
                Some(&block),
                Some(&cwd),
            )?));
            let vendor = original.0.as_ref().ok_or_else(invalid)?;
            let pid = vendor.pid;
            let birth = process_birth(&vendor.process)?;
            // SAFETY: own process/thread pseudo handles are duplicated locally,
            // noninheritable. This is the real capability source process for
            // this direct pull test, not an invented helper identity or PID lookup.
            let current = unsafe { GetCurrentProcess() };
            let source = NativeProcess {
                process: duplicate(current, current, current, false)?,
                thread: duplicate(
                    current,
                    unsafe { windows_sys::Win32::System::Threading::GetCurrentThread() },
                    current,
                    false,
                )?,
                pid: std::process::id(),
                status: None,
            };
            let packet = || windows_helper_wire::Born {
                process_handle: raw(&vendor.process) as u64,
                thread_handle: raw(&vendor.thread) as u64,
                pid,
                tid: unsafe { GetThreadId(raw(&vendor.thread)) },
                birth,
            };
            let accepted = pull_vendor(&source, packet(), raw(&cleanup_job))?;
            if accepted.pid != pid || process_birth(&accepted.process)? != birth {
                return Err(invalid());
            }
            drop(accepted); // close pulled copies only; original remains suspended.
            let refusal = match pull_vendor(&source, packet(), raw(&foreign_job)) {
                Ok(_) => return Err(io::Error::other("foreign_job_pull_was_accepted")),
                Err(error) => error,
            };
            if refusal.to_string() != "login_creator_born_identity_refused" {
                return Err(refusal);
            }
            let vendor = original.0.as_mut().ok_or_else(invalid)?;
            if vendor.try_wait()?.is_some() || process_birth(&vendor.process)? != birth {
                return Err(invalid());
            }
            eprintln!("WINDOWS_PULL_VENDOR_FOREIGN_JOB_WITNESS: original_pid={pid}; original_birth={birth}; original_suspended_live=true; correct_job_pull=true; foreign_job_pull_refused=true");
            vendor.terminate_and_confirm()?;
            use windows_sys::Win32::System::JobObjects::{
                JobObjectBasicAccountingInformation, QueryInformationJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            };
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            // SAFETY: independent census of the retained original cleanup Job.
            if unsafe {
                QueryInformationJobObject(
                    raw(&cleanup_job),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if accounting.ActiveProcesses != 0 {
                return Err(io::Error::other(STDIO_UNKNOWN));
            }
            original.0.take();
            eprintln!("WINDOWS_PULL_VENDOR_ORIGINAL_CLEANUP_CONFIRMED");
            Ok(())
        })();
        observed.unwrap_or_else(|error| panic!("{STDIO_UNKNOWN}: direct pull control: {error}"));
    }

    fn stdio_birth(handle: RawHandle) -> io::Result<u64> {
        // SAFETY: initialized FILETIME outputs for this retained actual process.
        let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
        let [created, exited, kernel, user] = &mut times;
        if unsafe { GetProcessTimes(handle as HANDLE, created, exited, kernel, user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    fn stdio_plan(root: &Path, nonce: &str, role: &str) -> io::Result<LaunchPlan> {
        let mut plan = LaunchPlan::new(std::env::current_exe()?);
        plan.env_clear()
            .args([
                STDIO_ENTRY,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(root)
            .env(STDIO_ROOT, root)
            .env(STDIO_ROLE, role)
            .env(STDIO_NONCE, nonce)
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("PATH", root.join("bin"))
            .env("APPDATA", root.join("appdata"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("TMPDIR", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("CSQ_SECRET_BACKEND", "in-memory")
            .stdin(LaunchStdio::null())
            .stdout(LaunchStdio::null())
            .stderr(LaunchStdio::null());
        for key in [
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                plan.env(key, value);
            }
        }
        Ok(plan)
    }
    #[test]
    #[ignore = "private inert stdio isolation actor, entered only by sandboxed self-exec"]
    fn private_stdio_isolation_actor() {
        let _environment = csq_core::platform::test_env::lock();
        let run = || -> io::Result<()> {
            let root = PathBuf::from(
                std::env::var_os(STDIO_ROOT).ok_or_else(|| io::Error::other(STDIO_UNKNOWN))?,
            );
            let role = std::env::var(STDIO_ROLE).map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
            let nonce = std::env::var(STDIO_NONCE).map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
            if !["vendor", "unrelated"].contains(&role.as_str())
                || std::env::var_os("HOME").as_deref() != Some(root.join("home").as_os_str())
                || std::env::var_os("CSQ_BASE_DIR").as_deref()
                    != Some(root.join("base").as_os_str())
                || std::env::var("CSQ_SECRET_BACKEND").as_deref() != Ok("in-memory")
            {
                return Err(io::Error::other(STDIO_UNKNOWN));
            }
            // SAFETY: borrowed current-process pseudo handle, never owned/closed.
            let birth = stdio_birth(unsafe { GetCurrentProcess() } as RawHandle)?;
            let identity = format!("{}:{birth}:{nonce}", std::process::id());
            let mut pending = tempfile::NamedTempFile::new_in(&root)?;
            pending.write_all(identity.as_bytes())?;
            pending.flush()?;
            pending
                .persist(root.join(format!("{role}-ready")))
                .map_err(|error| error.error)?;
            if role == "vendor" {
                writeln!(std::io::stdout(), "PRIVATE_NATIVE_STDIO_{nonce}")?;
                std::io::stdout().flush()?;
            }
            let _sentinel = if role == "unrelated" {
                let inherited = std::env::var(STDIO_SENTINEL)
                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?
                    .parse::<usize>()
                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                // SAFETY: this creator-owned capability was passed explicitly
                // to this inert actor; verify the inherited object type first.
                if unsafe { GetFileType(inherited as HANDLE) } != FILE_TYPE_PIPE {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                // SAFETY: this fixture owns the deliberately inherited
                // synchronous pipe handle in its own process table.
                let mut pipe =
                    File::from(unsafe { OwnedHandle::from_raw_handle(inherited as RawHandle) });
                writeln!(pipe, "PRIVATE_STD_INHERITANCE_{nonce}")?;
                pipe.flush()?;
                Some(pipe)
            } else {
                None
            };
            // Only the additional preCreate control supplies this exact fresh
            // creator-owned capability. The original concurrency case omits it.
            let _native_leak = if role == "unrelated" {
                match std::env::var(STDIO_NATIVE_LEAK) {
                    Ok(value) => {
                        let inherited = value
                            .parse::<usize>()
                            .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                        // SAFETY: explicit fixture capability, never guessed or
                        // used to signal a PID. A nonce through the pipe binds
                        // the inherited object to the parent's actual read end.
                        if unsafe { GetFileType(inherited as HANDLE) } == FILE_TYPE_PIPE {
                            let mut pipe = File::from(unsafe {
                                OwnedHandle::from_raw_handle(inherited as RawHandle)
                            });
                            writeln!(pipe, "PRIVATE_NATIVE_INHERITANCE_LEAK_{nonce}")?;
                            pipe.flush()?;
                            Some(pipe)
                        } else {
                            None
                        }
                    }
                    Err(std::env::VarError::NotPresent) => None,
                    Err(_) => return Err(io::Error::other(STDIO_UNKNOWN)),
                }
            } else {
                None
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(io::Error::other(STDIO_UNKNOWN))
        };
        if let Err(error) = run() {
            eprintln!("{STDIO_UNKNOWN}: {error}");
            std::process::exit(2);
        }
    }
    fn sync_pipe() -> io::Result<(File, File)> {
        let (mut read, mut write) = (0, 0);
        // SAFETY: fresh synchronous pipe; null attributes make both ends non-inheritable.
        if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: transfer the two newly owned synchronous endpoints exactly once.
        Ok((
            File::from(unsafe { OwnedHandle::from_raw_handle(read as RawHandle) }),
            File::from(unsafe { OwnedHandle::from_raw_handle(write as RawHandle) }),
        ))
    }
    struct PipeObservation {
        eof: Arc<AtomicBool>,
        progress: Arc<Mutex<Vec<u8>>>,
        reader: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    }
    impl PipeObservation {
        fn start(mut pipe: File) -> io::Result<Self> {
            let eof = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&eof);
            let progress = Arc::new(Mutex::new(Vec::new()));
            let read_progress = Arc::clone(&progress);
            let reader = std::thread::Builder::new()
                .name("private-native-stdio-observer".into())
                .spawn(move || {
                    let mut bytes = Vec::new();
                    loop {
                        let mut buffer = [0; 4096];
                        match pipe.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(count) => {
                                bytes.extend_from_slice(&buffer[..count]);
                                read_progress
                                    .lock()
                                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?
                                    .extend_from_slice(&buffer[..count]);
                            }
                            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
                            Err(error) => return Err(error),
                        }
                    }
                    observed.store(true, AtomicOrdering::Release);
                    Ok(bytes)
                })?;
            Ok(Self {
                eof,
                progress,
                reader: Some(reader),
            })
        }
        fn contains(&self, expected: &[u8]) -> io::Result<bool> {
            let bytes = self
                .progress
                .lock()
                .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
            Ok(bytes
                .windows(expected.len())
                .any(|window| window == expected))
        }
        fn finish(&mut self) -> io::Result<Vec<u8>> {
            let deadline = Instant::now() + STDIO_BUDGET;
            while self
                .reader
                .as_ref()
                .is_some_and(|reader| !reader.is_finished())
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            match self.reader.take() {
                Some(reader) => reader.join().map_err(|_| io::Error::other(STDIO_UNKNOWN))?,
                None => Ok(Vec::new()),
            }
        }
    }
    struct StdioIsolation {
        sandbox: Option<tempfile::TempDir>,
        job: OwnedHandle,
        worker: Option<std::thread::JoinHandle<io::Result<CustodyChild>>>,
        gate: Option<mpsc::SyncSender<()>>,
        vendor: Option<CustodyChild>,
        unrelated: Option<Child>,
        sentinel_writer: Option<File>,
        native_pipe: PipeObservation,
        sentinel_pipe: PipeObservation,
        cleaned: bool,
    }
    impl StdioIsolation {
        fn cleanup(&mut self) -> io::Result<()> {
            if self.cleaned {
                return Ok(());
            }
            self.gate.take(); // disconnect a blocked checkpoint; never resume on cleanup.
            self.sentinel_writer.take();
            // SAFETY: this fixture's dedicated retained Job, owning only inert native actors.
            let _ = unsafe { TerminateJobObject(raw(&self.job), 98) };
            if let Some(child) = self.unrelated.as_mut() {
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
                // SAFETY: this exact owned standard child process object.
                if unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, CLEANUP_MS) } != 0
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                child.wait()?;
            }
            let deadline = Instant::now() + STDIO_BUDGET;
            while self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(worker) = self.worker.take() {
                match worker.join().map_err(|_| io::Error::other(STDIO_UNKNOWN))? {
                    Ok(child) => self.vendor = Some(child),
                    Err(error) if is_setup_quarantine(&error) => return Err(error),
                    Err(_) => {} // disconnected checkpoint took confirmed setup cleanup.
                }
            }
            if let Some(child) = self.vendor.as_mut() {
                // SAFETY: actual retained native process, after fixture Job termination.
                if unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, CLEANUP_MS) } != 0
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                child
                    .try_wait()?
                    .ok_or_else(|| io::Error::other(STDIO_UNKNOWN))?;
            }
            self.native_pipe.finish()?;
            self.sentinel_pipe.finish()?;
            self.cleaned = true;
            eprintln!("WINDOWS_STDIO_PRIVATE_CLEANUP: native_setup_accounted=true; original_unrelated_accounted=true; both_pipe_readers_joined=true; numeric_signals=false");
            Ok(())
        }
    }
    impl Drop for StdioIsolation {
        fn drop(&mut self) {
            if self.cleanup().is_err() {
                if let Some(sandbox) = self.sandbox.take() {
                    let _ = sandbox.keep();
                }
                eprintln!("{STDIO_UNKNOWN}: private cleanup incomplete");
            }
        }
    }
    #[test]
    fn concurrent_standard_spawn_cannot_inherit_native_vendor_stdio() {
        let _environment = csq_core::platform::test_env::lock();
        let run = || -> io::Result<()> {
            let sandbox = tempfile::tempdir()?;
            for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
                std::fs::create_dir(sandbox.path().join(name))?;
            }
            let root = sandbox.path().to_path_buf();
            let nonce = format!(
                "FAKETEST_{}",
                root.file_name().ok_or_else(invalid)?.to_string_lossy()
            );
            // SAFETY: unnamed non-inherited Job, exclusively this fixture's.
            let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if job == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: transfer one newly created owned Job handle.
            let job = unsafe { OwnedHandle::from_raw_handle(job as RawHandle) };
            // SAFETY: correctly initialized C policy structure.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    raw(&job),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let (native_read, native_write) = sync_pipe()?;
            let (sentinel_read, sentinel_write) = sync_pipe()?;
            // Positive control ONLY: ordinary std spawning must inherit this
            // deliberately eligible sentinel. Product handles stay non-inheritable.
            if unsafe {
                SetHandleInformation(
                    raw(&sentinel_write),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut fixture = StdioIsolation {
                sandbox: Some(sandbox),
                job,
                worker: None,
                gate: None,
                vendor: None,
                unrelated: None,
                sentinel_writer: Some(sentinel_write),
                native_pipe: PipeObservation::start(native_read)?,
                sentinel_pipe: PipeObservation::start(sentinel_read)?,
                cleaned: false,
            };
            let mut plan = stdio_plan(&root, &nonce, "vendor")?;
            plan.stdout(native_write);
            // SAFETY: non-inherited duplicate of this fixture's retained Job.
            let current = unsafe { GetCurrentProcess() };
            let worker_job = duplicate(current, raw(&fixture.job), current, false)?;
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let (gate_tx, gate_rx) = mpsc::sync_channel(1);
            fixture.gate = Some(gate_tx);
            fixture.worker = Some(
                std::thread::Builder::new()
                    .name("private-native-spawn".into())
                    .spawn(move || {
                        set_checkpoint_hook_for_test(move |stage, _, _| {
                            if stage == SpawnCheckpoint::VendorCreated {
                                ready_tx
                                    .send(())
                                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                                gate_rx
                                    .recv_timeout(STDIO_BUDGET)
                                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                            }
                            Ok(())
                        });
                        spawn(&plan, worker_job.as_raw_handle(), |_, _| Ok(()))
                    })?,
            );
            let observed = (|| -> io::Result<(bool, bool, bool)> {
                ready_rx
                    .recv_timeout(STDIO_BUDGET)
                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                let mut ordinary = stdio_plan(&root, &nonce, "unrelated")?.into_std_command()?;
                let sentinel = fixture
                    .sentinel_writer
                    .as_ref()
                    .ok_or_else(invalid)?
                    .as_raw_handle() as usize;
                ordinary.env(STDIO_SENTINEL, sentinel.to_string());
                fixture.unrelated = Some(ordinary.spawn()?);
                fixture.sentinel_writer.take();
                fixture
                    .gate
                    .take()
                    .ok_or_else(invalid)?
                    .send(())
                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                let deadline = Instant::now() + STDIO_BUDGET;
                while fixture
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.is_finished())
                {
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                fixture.vendor = Some(
                    fixture
                        .worker
                        .take()
                        .ok_or_else(invalid)?
                        .join()
                        .map_err(|_| io::Error::other(STDIO_UNKNOWN))??,
                );
                for (role, pid, handle) in [
                    (
                        "vendor",
                        fixture.vendor.as_ref().ok_or_else(invalid)?.id(),
                        fixture.vendor.as_ref().ok_or_else(invalid)?.as_raw_handle(),
                    ),
                    (
                        "unrelated",
                        fixture.unrelated.as_ref().ok_or_else(invalid)?.id(),
                        fixture
                            .unrelated
                            .as_ref()
                            .ok_or_else(invalid)?
                            .as_raw_handle(),
                    ),
                ] {
                    let expected = format!("{pid}:{}:{nonce}", stdio_birth(handle)?);
                    let deadline = Instant::now() + STDIO_BUDGET;
                    loop {
                        if std::fs::read_to_string(root.join(format!("{role}-ready")))
                            .ok()
                            .as_deref()
                            == Some(expected.as_str())
                        {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(STDIO_UNKNOWN));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                let expected_sentinel = format!("PRIVATE_STD_INHERITANCE_{nonce}");
                let deadline = Instant::now() + STDIO_BUDGET;
                while !fixture
                    .sentinel_pipe
                    .contains(expected_sentinel.as_bytes())?
                {
                    if Instant::now() >= deadline
                        || fixture
                            .unrelated
                            .as_mut()
                            .ok_or_else(invalid)?
                            .try_wait()?
                            .is_some()
                    {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                fixture.vendor.as_mut().ok_or_else(invalid)?.kill()?;
                let vendor = fixture.vendor.as_ref().ok_or_else(invalid)?;
                // SAFETY: original actual native child handle, never a PID reopen.
                if unsafe { WaitForSingleObject(vendor.as_raw_handle() as HANDLE, CLEANUP_MS) } != 0
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                while !fixture.native_pipe.eof.load(AtomicOrdering::Acquire)
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let native_eof = fixture.native_pipe.eof.load(AtomicOrdering::Acquire);
                let sentinel_held = fixture
                    .sentinel_pipe
                    .contains(expected_sentinel.as_bytes())?
                    && !fixture.sentinel_pipe.eof.load(AtomicOrdering::Acquire);
                let unrelated_alive = fixture
                    .unrelated
                    .as_mut()
                    .ok_or_else(invalid)?
                    .try_wait()?
                    .is_none();
                let nonce_output = if native_eof {
                    String::from_utf8_lossy(&fixture.native_pipe.finish()?)
                        .contains(&format!("PRIVATE_NATIVE_STDIO_{nonce}"))
                } else {
                    false
                };
                Ok((native_eof && nonce_output, sentinel_held, unrelated_alive))
            })();
            eprintln!("WINDOWS_STDIO_BEFORE_PRIVATE_CLEANUP: native_eof_and_nonce_sentinel_held_unrelated_alive={observed:?}");
            let cleanup = fixture.cleanup();
            cleanup?;
            let observed = observed?;
            assert_eq!(
                observed,
                (true, true, true),
                "WINDOWS_NATIVE_STDIO_MUST_NOT_LEAK_TO_CONCURRENT_STANDARD_CHILD"
            );
            Ok(())
        };
        run().unwrap_or_else(|error| panic!("{STDIO_UNKNOWN}: {error}"));
    }

    // Additional helper-window fixture; the original concurrency test and its
    // oracle above remain unchanged. Cleanup owns both direct process identity
    // and the exact dedicated Job, including pre-Born failures.
    struct PrivateGateIsolation(StdioIsolation);
    impl PrivateGateIsolation {
        fn cleanup(&mut self) -> io::Result<()> {
            if self.0.cleaned {
                return Ok(());
            }
            self.0.gate.take();
            // SAFETY: only this fixture's owned Job; cancels an in-flight
            // bootstrap before waiting for its original worker to return.
            let _ = unsafe { TerminateJobObject(raw(&self.0.job), 98) };
            let deadline = Instant::now() + STDIO_BUDGET;
            while self
                .0
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(worker) = self.0.worker.take() {
                match worker.join().map_err(|_| io::Error::other(STDIO_UNKNOWN))? {
                    Ok(child) => self.0.vendor = Some(child),
                    Err(error) if is_setup_quarantine(&error) => return Err(error),
                    Err(_) => {} // plain guard confirmed original cleanup before returning an error.
                }
            }
            if let Some(vendor) = self.0.vendor.as_mut() {
                if vendor.try_wait()?.is_none() {
                    vendor.kill()?;
                }
                // SAFETY: actual original native child, independent exit proof.
                if unsafe { WaitForSingleObject(vendor.as_raw_handle() as HANDLE, CLEANUP_MS) } != 0
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                vendor
                    .try_wait()?
                    .ok_or_else(|| io::Error::other(STDIO_UNKNOWN))?;
                if let Some(creator) = vendor.creator.as_mut() {
                    // SAFETY: original retained helper object, never PID lookup.
                    if unsafe { WaitForSingleObject(raw(&creator.process.process), CLEANUP_MS) }
                        != 0
                    {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                }
                if !vendor.poll_creator_lifecycle(false)? {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
            }
            let census_deadline = Instant::now() + Duration::from_millis(u64::from(CLEANUP_MS));
            loop {
                // SAFETY: exact owned Job and initialized accounting output.
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                    unsafe { std::mem::zeroed() };
                let mut returned = 0;
                if unsafe {
                    QueryInformationJobObject(
                        raw(&self.0.job),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        std::mem::size_of_val(&accounting) as u32,
                        &mut returned,
                    )
                } == 0
                    || returned as usize != std::mem::size_of_val(&accounting)
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                if Instant::now() >= census_deadline {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.0.cleanup()
        }
    }
    impl Drop for PrivateGateIsolation {
        fn drop(&mut self) {
            while self.cleanup().is_err() {
                // Keep the original handles until confirmed; actor watchdogs
                // are an independent bound and never evidence for a pass.
                eprintln!("{STDIO_UNKNOWN}: private gate original cleanup unconfirmed");
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    fn fixture_inherit_flags(handle: HANDLE) -> io::Result<u32> {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        let mut flags = 0;
        // SAFETY: caller retains the exact fixture/borrowed standard handle.
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags)
    }
    fn original_standard_inherit_snapshot() -> io::Result<[(HANDLE, Option<u32>); 3]> {
        let mut snapshot = [(0, None); 3];
        for (slot, id) in
            snapshot
                .iter_mut()
                .zip([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE])
        {
            // SAFETY: borrow only, never change or close a host standard handle.
            let handle = unsafe { GetStdHandle(id) };
            *slot = (
                handle,
                if handle == 0 || handle == INVALID_HANDLE_VALUE {
                    None
                } else {
                    Some(fixture_inherit_flags(handle)? & HANDLE_FLAG_INHERIT)
                },
            );
        }
        Ok(snapshot)
    }
    struct CreatorWindowEvents {
        ready: OwnedHandle,
        release: OwnedHandle,
        ready_name: String,
        release_name: String,
    }
    impl CreatorWindowEvents {
        fn new() -> io::Result<Self> {
            use windows_sys::Win32::System::Threading::CreateEventW;
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
            let suffix: String = nonce
                .iter()
                .copied()
                .flat_map(|b| [b >> 4, b & 15])
                .map(|n| char::from(b"0123456789abcdef"[usize::from(n)]))
                .collect();
            let create = |name: &str| -> io::Result<OwnedHandle> {
                let name = wide(OsStr::new(name))?;
                // SAFETY: private random128 name, default user DACL, FALSE inheritance.
                let (handle, code) = unsafe {
                    SetLastError(0);
                    let handle = CreateEventW(ptr::null(), 1, 0, name.as_ptr());
                    (handle, GetLastError())
                };
                if handle == 0 {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                // SAFETY: newly owned event returned by CreateEventW.
                let owned = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
                if code == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                Ok(owned)
            };
            let ready_name = format!("Local\\csq-creator-window-ready-{suffix}");
            let release_name = format!("Local\\csq-creator-window-release-{suffix}");
            Ok(Self {
                ready: create(&ready_name)?,
                release: create(&release_name)?,
                ready_name,
                release_name,
            })
        }
        fn release(&self) -> io::Result<()> {
            // SAFETY: this fixture owns the original private release event.
            if unsafe { windows_sys::Win32::System::Threading::SetEvent(raw(&self.release)) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl Drop for CreatorWindowEvents {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }
    struct CreatorMainWindow {
        helper: OwnedHandle,
        pid: u32,
        birth: u64,
        main_bits: [Option<u32>; 3],
    }
    #[derive(Debug)]
    struct CreatorWindowObservation {
        main_stdio_inherit_bits: [Option<u32>; 3],
        original_flags_unchanged: bool,
        actual_helper_bound: bool,
        helper_before_create_ready: bool,
        creator_environment_minimal: bool,
        creator_bootstrap_stdio_null: bool,
        actual_vendor_and_unrelated_bound: bool,
        vendor_nonce_observed: bool,
        sentinel_nonce_observed: bool,
        native_leak_nonce_observed: bool,
        sentinel_held: bool,
        unrelated_alive: bool,
        native_eof_before_unrelated_cleanup: bool,
    }
    #[test]
    fn creator_helper_before_create_must_not_leak_stdio_to_standard_child() {
        let _environment = csq_core::platform::test_env::lock();
        let run = || -> io::Result<()> {
            let sandbox = tempfile::tempdir()?;
            for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
                std::fs::create_dir(sandbox.path().join(name))?;
            }
            let root = sandbox.path().to_path_buf();
            let nonce = format!(
                "FAKETEST_{}",
                root.file_name().ok_or_else(invalid)?.to_string_lossy()
            );
            let events = CreatorWindowEvents::new()?;
            // SAFETY: unnamed noninheritable dedicated test Job.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: newly owned Job handle.
            let job = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
            // SAFETY: initialized policy structure for the exact owned Job.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    raw(&job),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let (native_read, native_write) = sync_pipe()?;
            let source = raw(&native_write);
            let source_flags = fixture_inherit_flags(source)?;
            if source_flags & HANDLE_FLAG_INHERIT != 0 {
                return Err(io::Error::other(STDIO_UNKNOWN));
            }
            let original_standard = original_standard_inherit_snapshot()?;
            let (sentinel_read, sentinel_write) = sync_pipe()?;
            // Positive eligibility belongs only to this newly created MAIN
            // sentinel. No main stdio endpoint is ever made inheritable.
            if unsafe {
                SetHandleInformation(
                    raw(&sentinel_write),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut owned = PrivateGateIsolation(StdioIsolation {
                sandbox: Some(sandbox),
                job,
                worker: None,
                gate: None,
                vendor: None,
                unrelated: None,
                sentinel_writer: Some(sentinel_write),
                native_pipe: PipeObservation::start(native_read)?,
                sentinel_pipe: PipeObservation::start(sentinel_read)?,
                cleaned: false,
            });
            let fixture = &mut owned.0;
            let mut plan = stdio_plan(&root, &nonce, "vendor")?;
            plan.stdout(native_write)
                .env(
                    "CSQ_PRIVATE_CREATOR_ENV_REPORT",
                    root.join("creator-env.json"),
                )
                .env(
                    "CSQ_PRIVATE_VENDOR_CREATOR_BEFORE_CREATE_READY",
                    &events.ready_name,
                )
                .env(
                    "CSQ_PRIVATE_VENDOR_CREATOR_BEFORE_CREATE_RELEASE",
                    &events.release_name,
                );
            // SAFETY: only another noninheritable MAIN reference to this Job.
            let current = unsafe { GetCurrentProcess() };
            let worker_job = duplicate(current, raw(&fixture.job), current, false)?;
            let (metadata_tx, metadata_rx) = mpsc::sync_channel(1);
            fixture.worker = Some(
                std::thread::Builder::new()
                    .name("private-creator-window".into())
                    .spawn(move || {
                        set_creator_main_stdio_hook_for_test(move |pid, helper, streams| {
                            let bits = streams.map(|handle| {
                                handle
                                    .map(|handle| {
                                        fixture_inherit_flags(handle as HANDLE)
                                            .map(|flags| flags & HANDLE_FLAG_INHERIT)
                                    })
                                    .transpose()
                            });
                            let [input, output, error] = bits;
                            // SAFETY: query/duplicate the actual original helper, FALSE.
                            let current = unsafe { GetCurrentProcess() };
                            let process = duplicate(current, helper as HANDLE, current, false)?;
                            let created = stdio_birth(process.as_raw_handle())?;
                            metadata_tx
                                .send(CreatorMainWindow {
                                    helper: process,
                                    pid,
                                    birth: created,
                                    main_bits: [input?, output?, error?],
                                })
                                .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                            Ok(())
                        });
                        spawn(&plan, worker_job.as_raw_handle(), |_, _| Ok(()))
                    })?,
            );
            let observed = (|| -> io::Result<CreatorWindowObservation> {
                // Kernel readiness is signalled inside the authenticated helper
                // after all HELPER stdio endpoints become eligible, before CreateProcess.
                if unsafe { WaitForSingleObject(raw(&events.ready), 5_000) } != 0 {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                let creator_keys: Vec<String> =
                    serde_json::from_slice(&std::fs::read(root.join("creator-env.json"))?)?;
                let creator_bootstrap_stdio_null: bool = serde_json::from_slice(&std::fs::read(
                    root.join("creator-env.bootstrap-stdio.json"),
                )?)?;
                let creator_environment_minimal = creator_keys.iter().all(|key| {
                    [
                        "SystemRoot",
                        "SystemDrive",
                        "TEMP",
                        "CSQ_PRIVATE_VENDOR_CREATOR_BOOTSTRAP_V1",
                    ]
                    .iter()
                    .any(|allowed| key.eq_ignore_ascii_case(allowed))
                });
                let main = metadata_rx
                    .recv_timeout(STDIO_BUDGET)
                    .map_err(|_| io::Error::other(STDIO_UNKNOWN))?;
                let mut member = 0;
                if unsafe { GetProcessId(raw(&main.helper)) } != main.pid
                    || stdio_birth(main.helper.as_raw_handle())? != main.birth
                    || unsafe { WaitForSingleObject(raw(&main.helper), 0) } != 258
                    || unsafe {
                        windows_sys::Win32::System::JobObjects::IsProcessInJob(
                            raw(&main.helper),
                            raw(&fixture.job),
                            &mut member,
                        )
                    } == 0
                    || member == 0
                    || main.main_bits != [None, Some(0), None]
                    || fixture
                        .worker
                        .as_ref()
                        .is_none_or(|worker| worker.is_finished())
                    || fixture_inherit_flags(source)? != source_flags
                    || original_standard_inherit_snapshot()? != original_standard
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                let mut ordinary = stdio_plan(&root, &nonce, "unrelated")?.into_std_command()?;
                let sentinel = fixture
                    .sentinel_writer
                    .as_ref()
                    .ok_or_else(invalid)?
                    .as_raw_handle() as usize;
                ordinary.env(STDIO_SENTINEL, sentinel.to_string());
                // The explicit MAIN source capability is noninheritable. The
                // actor's optional nonce challenge can prove an unexpected leak;
                // helper-local numeric values are never used in this process.
                ordinary.env(STDIO_NATIVE_LEAK, (source as usize).to_string());
                fixture.unrelated = Some(ordinary.spawn()?);
                fixture.sentinel_writer.take();
                let unrelated = fixture.unrelated.as_ref().ok_or_else(invalid)?;
                let expected = format!(
                    "{}:{}:{nonce}",
                    unrelated.id(),
                    stdio_birth(unrelated.as_raw_handle())?
                );
                let sentinel_nonce = format!("PRIVATE_STD_INHERITANCE_{nonce}");
                let leak_nonce = format!("PRIVATE_NATIVE_INHERITANCE_LEAK_{nonce}");
                let deadline = Instant::now() + STDIO_BUDGET;
                loop {
                    if std::fs::read_to_string(root.join("unrelated-ready"))
                        .ok()
                        .as_deref()
                        == Some(expected.as_str())
                        && fixture.sentinel_pipe.contains(sentinel_nonce.as_bytes())?
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if unsafe { WaitForSingleObject(raw(&main.helper), 0) } != 258
                    || fixture
                        .worker
                        .as_ref()
                        .is_none_or(|worker| worker.is_finished())
                    || fixture_inherit_flags(source)? != source_flags
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                events.release()?;
                let deadline = Instant::now() + STDIO_BUDGET;
                while fixture
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.is_finished())
                {
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                fixture.vendor = Some(
                    fixture
                        .worker
                        .take()
                        .ok_or_else(invalid)?
                        .join()
                        .map_err(|_| io::Error::other(STDIO_UNKNOWN))??,
                );
                let vendor = fixture.vendor.as_ref().ok_or_else(invalid)?;
                let expected = format!(
                    "{}:{}:{nonce}",
                    vendor.id(),
                    stdio_birth(vendor.as_raw_handle())?
                );
                let vendor_nonce = format!("PRIVATE_NATIVE_STDIO_{nonce}");
                let deadline = Instant::now() + STDIO_BUDGET;
                loop {
                    if std::fs::read_to_string(root.join("vendor-ready"))
                        .ok()
                        .as_deref()
                        == Some(expected.as_str())
                        && fixture.native_pipe.contains(vendor_nonce.as_bytes())?
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(STDIO_UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                fixture.vendor.as_mut().ok_or_else(invalid)?.kill()?;
                let vendor = fixture.vendor.as_mut().ok_or_else(invalid)?;
                // SAFETY: original vendor handle, independently confirm actual exit.
                if unsafe { WaitForSingleObject(vendor.as_raw_handle() as HANDLE, CLEANUP_MS) } != 0
                    || vendor.try_wait()?.is_none()
                {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                while !fixture.native_pipe.eof.load(AtomicOrdering::Acquire)
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let alive = fixture
                    .unrelated
                    .as_mut()
                    .ok_or_else(invalid)?
                    .try_wait()?
                    .is_none();
                let held = !fixture.sentinel_pipe.eof.load(AtomicOrdering::Acquire);
                if !alive || !held || original_standard_inherit_snapshot()? != original_standard {
                    return Err(io::Error::other(STDIO_UNKNOWN));
                }
                Ok(CreatorWindowObservation {
                    main_stdio_inherit_bits: main.main_bits,
                    original_flags_unchanged: true,
                    actual_helper_bound: true,
                    helper_before_create_ready: true,
                    creator_environment_minimal,
                    creator_bootstrap_stdio_null,
                    actual_vendor_and_unrelated_bound: true,
                    vendor_nonce_observed: true,
                    sentinel_nonce_observed: true,
                    native_leak_nonce_observed: fixture
                        .native_pipe
                        .contains(leak_nonce.as_bytes())?,
                    sentinel_held: held,
                    unrelated_alive: alive,
                    native_eof_before_unrelated_cleanup: fixture
                        .native_pipe
                        .eof
                        .load(AtomicOrdering::Acquire),
                })
            })();
            eprintln!("WINDOWS_CREATOR_PRE_CREATE_BEFORE_PRIVATE_CLEANUP: {observed:?}");
            let _release = events.release();
            let cleanup = owned.cleanup();
            let observed = match observed {
                Err(first) => {
                    if cleanup.is_err() {
                        eprintln!("{STDIO_UNKNOWN}: creator window secondary cleanup failure");
                    }
                    return Err(first);
                }
                Ok(observed) => {
                    cleanup?;
                    observed
                }
            };
            let eof_after = owned.0.native_pipe.eof.load(AtomicOrdering::Acquire);
            let joined =
                owned.0.native_pipe.reader.is_none() && owned.0.sentinel_pipe.reader.is_none();
            if !eof_after
                || !joined
                || observed.main_stdio_inherit_bits != [None, Some(0), None]
                || !observed.original_flags_unchanged
                || !observed.actual_helper_bound
                || !observed.helper_before_create_ready
                || !observed.actual_vendor_and_unrelated_bound
                || !observed.vendor_nonce_observed
                || !observed.sentinel_nonce_observed
                || !observed.sentinel_held
                || !observed.unrelated_alive
                || observed.native_eof_before_unrelated_cleanup
                    == observed.native_leak_nonce_observed
            {
                return Err(io::Error::other(STDIO_UNKNOWN));
            }
            eprintln!("WINDOWS_CREATOR_PRE_CREATE_AFTER_PRIVATE_CLEANUP: EOF=true; original_vendor_and_unrelated_reaped=true; actual_helper_retired=true; both_readers_joined=true");
            eprintln!("CREATOR_ENV_CLEANUP_CONFIRMED");
            if !observed.creator_bootstrap_stdio_null {
                eprintln!("CREATOR_LIBTEST_BOOTSTRAP_MUST_NOT_HAVE_PARENT_STDIO");
            }
            assert!(
                observed.creator_bootstrap_stdio_null,
                "Rust helper bootstrap inherited standard slots: {observed:?}"
            );
            if !observed.creator_environment_minimal {
                eprintln!("ACTUAL_CREATOR_ENVIRONMENT_MUST_BE_MINIMAL");
            }
            assert!(
                observed.creator_environment_minimal,
                "actual creator inherited vendor environment: {observed:?}"
            );
            assert!(
                observed.native_eof_before_unrelated_cleanup,
                "WINDOWS_CREATOR_PRE_CREATE_STDIO_LEAK: {observed:?}"
            );
            Ok(())
        };
        run().unwrap_or_else(|error| {
            panic!("{STDIO_UNKNOWN}: creator preCreate observation: {error}")
        });
    }

    #[test]
    fn rust_helper_bootstrap_sinks_nonconsole_stdio_and_preserves_console_overrides() {
        let actual = [
            helper_bootstrap_stdio_for_test(false, false),
            helper_bootstrap_stdio_for_test(false, true),
            helper_bootstrap_stdio_for_test(true, false),
            helper_bootstrap_stdio_for_test(true, true),
        ];
        let expected = [Some([0; 3]), None, None, None];
        // Pure startup-policy fixture: no process, stream or native owner was
        // created. Actual helper slot readback is a separate native test.
        eprintln!("CREATOR_BOOTSTRAP_POLICY_OWNER_FREE_CLEANUP_CONFIRMED");
        if actual != expected {
            eprintln!("CREATOR_LIBTEST_BOOTSTRAP_POLICY_MUST_SINK_PARENT_STDIO");
        }
        assert_eq!(actual, expected, "Rust helper bootstrap stdio policy");
    }

    #[test]
    fn regular_command_line_preserves_empty_space_quote_and_trailing_slash() {
        let args = ["", "a b", "a\"b", "a b\\"].map(|value| LaunchArg::Regular(value.into()));
        let actual = quote_command(OsStr::new("p.exe"), &args).unwrap();
        let expected = "\"p.exe\" \"\" \"a b\" a\\\"b \"a b\\\\\"";
        assert_eq!(actual, wide(OsStr::new(expected)).unwrap());
    }

    #[test]
    fn raw_arguments_remain_literal_and_embedded_nul_refuses_before_creation() {
        let raw_args = [LaunchArg::Raw("/fixed \"literal\"".into())];
        assert_eq!(
            quote_command(OsStr::new("p.exe"), &raw_args).unwrap(),
            wide(OsStr::new("\"p.exe\" /fixed \"literal\"")).unwrap()
        );
        let bad = [LaunchArg::Regular(OsString::from_wide(&[97, 0, 98]))];
        assert_eq!(
            quote_command(OsStr::new("p.exe"), &bad).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn cleared_environment_uses_windows_caseless_last_writer_and_double_nul() {
        let mut plan = LaunchPlan::new("p.exe");
        plan.env_clear()
            .env("MiXeD", "first")
            .env("mixed", "last")
            .env("REMOVE", "private")
            .env_remove("remove");
        let entries = environment(&plan.build_for_spawn().unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(OsString::from_wide(&entries[0].0), OsStr::new("mixed"));
        assert_eq!(OsString::from_wide(&entries[0].1), OsStr::new("last"));
        assert_eq!(env_block(&[]), vec![0, 0]);
        assert_eq!(compare_env(&[0x00e4], &[0x00c4]), Ordering::Equal);
    }

    #[test]
    fn creator_environment_is_minimal_and_never_reads_vendor_keys() {
        let mut requested = Vec::new();
        let entries = creator_environment_with(|key| {
            requested.push(key.to_owned());
            Some(OsString::from(format!("FAKETEST_{key}")))
        })
        .expect("minimal creator environment");
        assert_eq!(
            requested,
            ["SystemRoot", "SystemDrive", "TEMP"],
            "CREATOR_ENVIRONMENT_READS_ONLY_SYSTEM_KEYS"
        );
        let mut keys: Vec<_> = entries
            .iter()
            .map(|(key, _)| OsString::from_wide(key))
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                OsString::from("SystemDrive"),
                OsString::from("SystemRoot"),
                OsString::from("TEMP")
            ],
            "CREATOR_ENVIRONMENT_IS_MINIMAL"
        );
        // The recipe keeps an independently built full vendor environment.
        let mut vendor = LaunchPlan::new("p.exe");
        vendor
            .env_clear()
            .env("CSQ_PRIVATE_VENDOR_MARKER", "FAKETEST_vendor_recipe");
        let block = env_block(&environment(&vendor.build_for_spawn().unwrap()).unwrap());
        assert!(
            block
                .windows("FAKETEST_vendor_recipe".len())
                .any(|part| part == "FAKETEST_vendor_recipe".encode_utf16().collect::<Vec<_>>()),
            "VENDOR_RECIPE_ENVIRONMENT_PRESERVED"
        );
    }

    #[test]
    fn setup_recovery_budget_returns_typed_quarantine_with_original_error() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        let original = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        let recovered = recover_setup_error_with_budget(
            io::Error::other(SetupQuarantine(None, Some(original))),
            Duration::ZERO,
        );
        let typed = is_setup_quarantine(&recovered);
        let kind = recovered.kind();
        let retained_code = match take_quarantine(recovered) {
            Ok(retained) => std::error::Error::source(&retained)
                .and_then(|cause| cause.downcast_ref::<io::Error>())
                .and_then(io::Error::raw_os_error),
            Err(original) => original.raw_os_error(),
        };
        // This owner-free fixture has no native resource to terminate; it
        // discriminates the budget/refusal branch and original-cause transport.
        eprintln!("SETUP_BUDGET_OWNER_FREE_CLEANUP_CONFIRMED");
        let correct = typed
            && kind == io::ErrorKind::PermissionDenied
            && retained_code == Some(ERROR_ACCESS_DENIED as i32);
        if !correct {
            eprintln!("SETUP_BUDGET_MUST_RETAIN_TYPED_FIRST_CAUSE");
        }
        assert!(
            correct,
            "unconfirmed setup lost typed quarantine or first cause"
        );
    }

    #[test]
    fn batch_refusal_creates_neither_donor_nor_vendor() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        for name in ["inert.CmD", "inert.BaT"] {
            let path = sandbox.path().join(name);
            File::create(&path).unwrap();
            let mut plan = LaunchPlan::new(path);
            plan.env_clear();
            let before = CREATED_PROCESSES.with(std::cell::Cell::get);
            let result = spawn(&plan, ptr::null_mut(), |_, _| {
                panic!("batch vendor was created")
            });
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("batch launch accepted"),
            };
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(error.to_string(), BATCH);
            assert_eq!(CREATED_PROCESSES.with(std::cell::Cell::get), before);
        }
    }
}
