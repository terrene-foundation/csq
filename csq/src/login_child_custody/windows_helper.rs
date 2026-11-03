//! Single-spawn creator, entered only after mandatory installer admission.
//! Main owns the only dedicated Job handles and alone resumes the vendor.

use super::windows_helper_wire::{
    BootstrapArgs, Born, Client, Direction, Recipe, RemoteKind, StdioSlot,
};
use super::{create_process, raw, Attributes, NativeProcess};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io,
    os::windows::io::{FromRawHandle, OwnedHandle, RawHandle},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, GetLastError, SetHandleInformation, ERROR_INVALID_HANDLE, FILETIME,
        HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{GetFileType, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE},
    System::{
        Console::{
            AttachConsole, GetConsoleMode, GetConsoleProcessList, GetStdHandle,
            ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        },
        Threading::{
            GetCurrentProcess, GetProcessTimes, GetThreadId, WaitForSingleObject,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        },
    },
};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "login_windows_creator_recipe_refused",
    )
}

/// Called by the binary immediately after successful installer admission.
/// A malformed hidden invocation is an error, never normal CLI dispatch.
pub(crate) fn dispatch_helper(argv: &[OsString]) -> io::Result<Option<u32>> {
    let Some(bootstrap) = BootstrapArgs::parse(argv)? else {
        return Ok(None);
    };
    run_helper(&bootstrap).map(Some)
}

fn run_helper(bootstrap: &BootstrapArgs) -> io::Result<u32> {
    let mut client = Client::connect(bootstrap, BOOTSTRAP_TIMEOUT)?;
    let mut recipe = client.receive_recipe()?;
    #[cfg(test)]
    report_creator_environment_for_test(&recipe)?;
    let prepared = (|| -> io::Result<(RetainedVendor, Born)> {
        let stdio = prepare_stdio(&recipe)?;
        let handles: Vec<HANDLE> = stdio.iter().map(raw).collect();
        let mut attributes = Attributes::new(1)?;
        attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
        // Main transferred each endpoint FALSE. All admission, authentication and
        // recipe validation precede this helper-local eligibility window.
        for handle in &stdio {
            // SAFETY: each endpoint is owned exclusively by this single-spawn helper.
            if unsafe {
                SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(test)]
        before_create_for_test(&recipe, &stdio)?;
        let spawned = create_process(
            &recipe.application,
            &mut recipe.command_line,
            &attributes,
            true,
            Some([handles[0], handles[1], handles[2]]),
            Some(&recipe.environment),
            recipe.current_dir.as_deref(),
        );
        // No helper copy may keep the vendor's pipes open through its independent wait.
        drop(stdio);
        drop(attributes);
        let vendor = RetainedVendor(Some(spawned?));
        let process = vendor.0.as_ref().ok_or_else(refused)?;
        let birth = process_birth(raw(&process.process))?;
        // SAFETY: this is the retained original thread from CreateProcessW.
        let tid = unsafe { GetThreadId(raw(&process.thread)) };
        if tid == 0 {
            return Err(io::Error::last_os_error());
        }
        let born = Born {
            process_handle: raw(&process.process) as u64,
            thread_handle: raw(&process.thread) as u64,
            pid: process.pid,
            tid,
            birth,
        };
        Ok((vendor, born))
    })();
    let (mut vendor, born) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            // Include stdio/console and attribute setup failures, not only
            // CreateProcess failures. A failed reply never replaces the first
            // error; only its typed kind/raw code crosses this private pipe.
            let _reply = client.send_failure(&error);
            return Err(error);
        }
    };
    client.send_born(&born)?;
    // There is deliberately no adoption or completion ACK. Main pulls copies
    // from these original handles, validates them, then alone resumes the vendor.
    drop(client);
    #[cfg(test)]
    let retirement_barrier = retirement_barrier_for_test(&recipe)?;
    drop(recipe); // zeroizes command and environment before the vendor lifetime wait.
    let process = vendor.0.as_mut().ok_or_else(refused)?;
    loop {
        if let Some(status) = process.try_wait()? {
            #[cfg(test)]
            if let Some(barrier) = retirement_barrier.as_ref() {
                barrier.wait_after_vendor_exit()?;
            }
            // Windows exposes the full DWORD through code()'s signed i32;
            // casting preserves all status bits, including NTSTATUS failures.
            let code = status.code().ok_or_else(refused)? as u32;
            vendor.0.take();
            return Ok(code);
        }
        // SAFETY: wait only observes this retained original vendor object.
        match unsafe { WaitForSingleObject(raw(&process.process), 1_000) } {
            0 | 258 => {}
            _ => return Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(test)]
struct RetirementBarrier {
    ready: OwnedHandle,
    release: OwnedHandle,
}
#[cfg(test)]
impl RetirementBarrier {
    fn wait_after_vendor_exit(&self) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::SetEvent;
        // SAFETY: authenticated fixture event, noninheritable signaling reference.
        if unsafe { SetEvent(raw(&self.ready)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // A private release barrier, never a park or a completion ACK. Timeout
        // is an error and keeps the original process owner through cleanup.
        match unsafe { WaitForSingleObject(raw(&self.release), 15_000) } {
            0 => Ok(()),
            258 => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture_retirement_release_timeout",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
#[cfg(test)]
fn retirement_barrier_for_test(recipe: &Recipe) -> io::Result<Option<RetirementBarrier>> {
    use windows_sys::Win32::System::Threading::{OpenEventW, EVENT_MODIFY_STATE};
    let find = |key: &str| -> io::Result<Option<Vec<u16>>> {
        let prefix: Vec<u16> = format!("{key}=").encode_utf16().collect();
        let local: Vec<u16> = "Local\\".encode_utf16().collect();
        let mut found = None;
        for entry in recipe.environment.split(|unit| *unit == 0) {
            if let Some(value) = entry.strip_prefix(prefix.as_slice()) {
                if found.is_some() || !value.starts_with(&local) || value.len() > 260 {
                    return Err(refused());
                }
                found = Some(value.iter().copied().chain(Some(0)).collect());
            }
        }
        Ok(found)
    };
    let pair = match (
        find("CSQ_PRIVATE_CREATOR_RETIREMENT_READY")?,
        find("CSQ_PRIVATE_CREATOR_RETIREMENT_RELEASE")?,
    ) {
        (None, None) => return Ok(None),
        (Some(a), Some(b)) => (a, b),
        _ => return Err(refused()),
    };
    let open = |name: &[u16], rights| -> io::Result<OwnedHandle> {
        // SAFETY: authenticated recipe supplied a private Local event name;
        // both references are explicitly noninheritable.
        let handle = unsafe { OpenEventW(rights, 0, name.as_ptr()) };
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    };
    Ok(Some(RetirementBarrier {
        ready: open(&pair.0, EVENT_MODIFY_STATE)?,
        release: open(&pair.1, 0x0010_0000)?,
    }))
}

/// Before successful handoff, any error stops only the actual child we created.
/// If one bounded termination/wait attempt is uncertain, retain the original
/// handles as unresolved custody. Main independently owns the enclosing Job;
/// neither this deadline nor retained ownership certifies completion.
struct RetainedVendor(Option<NativeProcess>);
#[cfg(test)]
std::thread_local! {
    static CAPTURE_VENDOR_RETENTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RETAINED_VENDOR: std::cell::RefCell<Option<NativeProcess>> = const { std::cell::RefCell::new(None) };
}
fn retain_unresolved_vendor(vendor: NativeProcess) {
    #[cfg(test)]
    if CAPTURE_VENDOR_RETENTION.with(std::cell::Cell::get) {
        RETAINED_VENDOR.with(|slot| {
            let previous = slot.borrow_mut().replace(vendor);
            assert!(previous.is_none(), "retained vendor test owner collision");
        });
        return;
    }
    std::mem::forget(vendor);
}
impl Drop for RetainedVendor {
    fn drop(&mut self) {
        if let Some(mut vendor) = self.0.take() {
            // One native termination/wait attempt is bounded by CLEANUP_MS. A
            // failed wait is not permission to close our last process owner.
            if vendor.terminate_and_confirm().is_err() {
                retain_unresolved_vendor(vendor);
                eprintln!("login_windows_creator_cleanup_unconfirmed: original owner retained");
            }
        }
    }
}

fn process_birth(process: HANDLE) -> io::Result<u64> {
    // SAFETY: FILETIME is a plain Win32 output value.
    let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
    // SAFETY: process remains retained and the four outputs are distinct.
    let [created, exited, kernel, user] = &mut times;
    if unsafe { GetProcessTimes(process, created, exited, kernel, user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
}

fn prepare_stdio(recipe: &Recipe) -> io::Result<[OwnedHandle; 3]> {
    if recipe
        .stdio
        .iter()
        .any(|slot| matches!(slot, StdioSlot::LocalConsole))
    {
        ensure_console()?;
    }
    // Validate every remote capability before converting any raw value to an
    // owner, so duplicate slot values cannot create two owning wrappers.
    let mut remote = Vec::new();
    for (index, slot) in recipe.stdio.iter().enumerate() {
        if let StdioSlot::RemotePipeOrFile {
            handle,
            kind,
            direction,
        } = slot
        {
            if (*direction == Direction::Input) != (index == 0) || remote.contains(handle) {
                return Err(refused());
            }
            let handle_native = usize::try_from(*handle).map_err(|_| refused())? as HANDLE;
            validate_remote(handle_native, *kind)?;
            remote.push(*handle);
        }
    }
    let mut resolved = Vec::with_capacity(3);
    for (index, slot) in recipe.stdio.iter().enumerate() {
        resolved.push(match slot {
            StdioSlot::Null => open_null(index)?,
            StdioSlot::LocalConsole => local_console(index)?,
            StdioSlot::RemotePipeOrFile { handle, .. } => {
                // SAFETY: authenticated main transferred this distinct endpoint
                // into this helper, FALSE; validated above, ownership is consumed once.
                unsafe { OwnedHandle::from_raw_handle(*handle as usize as RawHandle) }
            }
        });
    }
    resolved.try_into().map_err(|_| refused())
}

fn validate_remote(handle: HANDLE, expected: RemoteKind) -> io::Result<()> {
    if handle == 0 || handle == INVALID_HANDLE_VALUE {
        return Err(refused());
    }
    let mut flags = 0;
    // SAFETY: query only; malformed values never become termination authority.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(refused());
    }
    // SAFETY: GetFileType only queries this candidate handle.
    let actual = unsafe { GetFileType(handle) };
    match expected {
        RemoteKind::Pipe if actual == FILE_TYPE_PIPE => Ok(()),
        RemoteKind::File if actual == FILE_TYPE_DISK => Ok(()),
        RemoteKind::File if actual == FILE_TYPE_CHAR => {
            let mut mode = 0;
            // NUL is a character file but is not a console handle. Refuse a
            // successful console query or ambiguous failure rather than copying
            // main's console-handle values across process boundaries.
            if unsafe { GetConsoleMode(handle, &mut mode) } == 0
                && unsafe { GetLastError() } == ERROR_INVALID_HANDLE
            {
                Ok(())
            } else {
                Err(refused())
            }
        }
        _ => Err(refused()),
    }
}

fn ensure_console() -> io::Result<()> {
    let mut pid = 0;
    // SAFETY: one initialized PID output; a larger required count still proves attachment.
    if unsafe { GetConsoleProcessList(&mut pid, 1) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INVALID_HANDLE as i32) {
        return Err(error);
    }
    // GUI-subsystem helpers may begin unattached. Attach exactly once to the
    // creator's console, only for an explicit console recipe. No allocation,
    // console switching, or fallback is permitted.
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn local_console(index: usize) -> io::Result<OwnedHandle> {
    let slot = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE][index];
    // SAFETY: query the helper's own standard slot after attachment.
    let handle = unsafe { GetStdHandle(slot) };
    let mut mode = 0;
    if handle == 0 || handle == INVALID_HANDLE_VALUE {
        return Err(refused());
    }
    // SAFETY: require an actual initialized console endpoint.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // Never change a borrowed standard handle's flags. This same-process
    // duplicate is owned by the helper and starts noninheritable.
    let current = unsafe { GetCurrentProcess() };
    super::duplicate(current, handle, current, false)
}

fn open_null(index: usize) -> io::Result<OwnedHandle> {
    let mut options = OpenOptions::new();
    options.read(index == 0).write(index != 0);
    options.open("NUL").map(OwnedHandle::from)
}

#[cfg(test)]
fn report_creator_environment_for_test(recipe: &Recipe) -> io::Result<()> {
    use std::os::windows::ffi::OsStringExt;
    let prefix: Vec<u16> = "CSQ_PRIVATE_CREATOR_ENV_REPORT=".encode_utf16().collect();
    for entry in recipe.environment.split(|unit| *unit == 0) {
        if let Some(path) = entry.strip_prefix(prefix.as_slice()) {
            // Fixture-only evidence uses the authenticated recipe's private
            // sandbox path. Values (including vendor secrets) are never copied.
            let keys: Vec<_> = std::env::vars_os()
                .map(|(key, _)| key.to_string_lossy().into_owned())
                .collect();
            let path = std::path::PathBuf::from(OsString::from_wide(path));
            std::fs::write(&path, serde_json::to_vec(&keys)?)?;
            // Observe bootstrap slots before recipe stdio is prepared. This is
            // evidence about the Rust fixture's libtest prelude, not vendor I/O.
            let bootstrap_stdio_null = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .into_iter()
                // SAFETY: query-only access to this helper's own standard slots.
                .all(|slot| unsafe { GetStdHandle(slot) } == 0);
            std::fs::write(
                path.with_extension("bootstrap-stdio.json"),
                serde_json::to_vec(&bootstrap_stdio_null)?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn before_create_for_test(recipe: &Recipe, stdio: &[OwnedHandle; 3]) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
    fn event_name(recipe: &Recipe, key: &str) -> io::Result<Option<Vec<u16>>> {
        let prefix: Vec<u16> = format!("{key}=").encode_utf16().collect();
        let mut found = None;
        for entry in recipe.environment.split(|unit| *unit == 0) {
            if let Some(value) = entry.strip_prefix(prefix.as_slice()) {
                let local: Vec<u16> = "Local\\".encode_utf16().collect();
                if found.is_some() || !value.starts_with(&local) || value.len() > 260 {
                    return Err(refused());
                }
                let mut value = value.to_vec();
                value.push(0);
                found = Some(value);
            }
        }
        Ok(found)
    }
    let ready = event_name(recipe, "CSQ_PRIVATE_VENDOR_CREATOR_BEFORE_CREATE_READY")?;
    let release = event_name(recipe, "CSQ_PRIVATE_VENDOR_CREATOR_BEFORE_CREATE_RELEASE")?;
    let (ready, release) = match (ready, release) {
        (None, None) => return Ok(()),
        (Some(ready), Some(release)) => (ready, release),
        _ => return Err(refused()),
    };
    // READY is a positive witness of the actual helper-local flags, rather
    // than merely evidence that execution reached a line after SetHandleInformation.
    for endpoint in stdio {
        let mut flags = 0;
        // SAFETY: query this helper's retained, freshly prepared endpoint only.
        if unsafe { GetHandleInformation(raw(endpoint), &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & HANDLE_FLAG_INHERIT == 0 {
            return Err(refused());
        }
    }
    // SAFETY: named-event values came from the authenticated private fixture
    // recipe; OpenEvent creates independent noninheritable local references.
    let ready = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, ready.as_ptr()) };
    if ready == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenEvent transferred one reference.
    let ready = unsafe { OwnedHandle::from_raw_handle(ready as RawHandle) };
    // SYNCHRONIZE standard right, with no event modification authority.
    let release = unsafe { OpenEventW(0x0010_0000, 0, release.as_ptr()) };
    if release == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenEvent transferred one reference.
    let release = unsafe { OwnedHandle::from_raw_handle(release as RawHandle) };
    if unsafe { SetEvent(raw(&ready)) } == 0 {
        return Err(io::Error::last_os_error());
    }
    match unsafe { WaitForSingleObject(raw(&release), 15_000) } {
        0 => Ok(()),
        258 => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "login_windows_creator_test_gate_timeout",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_vendor_drop_attempts_once_and_retains_original_process() {
        use super::super::{
            creator_environment, duplicate, env_block, quote_command, wide, TERMINATE_ATTEMPTS,
            TERMINATE_REFUSALS,
        };
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::{
            JobObjects::{
                CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::{GetCurrentProcess, PROC_THREAD_ATTRIBUTE_JOB_LIST},
        };
        let _env = csq_core::platform::test_env::lock();
        // Dedicated kill-on-close Job and never-resumed original process: no test
        // payload can run, and the independent Job remains through readback.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert_ne!(handle, 0);
        let job = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    raw(&job),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            },
            0
        );
        let jobs = [raw(&job)];
        let mut attrs = Attributes::new(1).unwrap();
        attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs).unwrap();
        let exe = std::env::current_exe().unwrap();
        let application = wide(exe.as_os_str()).unwrap();
        let mut command = quote_command(exe.as_os_str(), &[]).unwrap();
        let environment = env_block(&creator_environment().unwrap());
        let vendor = create_process(
            &application,
            &mut command,
            &attrs,
            false,
            None,
            Some(&environment),
            None,
        )
        .unwrap();
        let pid = vendor.pid;
        let original_process = raw(&vendor.process);
        let original_thread = raw(&vendor.thread);
        let birth = process_birth(raw(&vendor.process)).unwrap();
        let current = unsafe { GetCurrentProcess() };
        let observed = duplicate(current, raw(&vendor.process), current, false).unwrap();
        CAPTURE_VENDOR_RETENTION.with(|flag| flag.set(true));
        TERMINATE_ATTEMPTS.with(|count| count.set(0));
        TERMINATE_REFUSALS.with(|slot| slot.set(Some(2)));
        drop(RetainedVendor(Some(vendor)));
        let attempts = TERMINATE_ATTEMPTS.with(std::cell::Cell::get);
        TERMINATE_REFUSALS.with(|slot| slot.set(None));
        CAPTURE_VENDOR_RETENTION.with(|flag| flag.set(false));
        let mut retained = RETAINED_VENDOR.with(|slot| slot.borrow_mut().take());
        let same_owner = retained.as_ref().is_some_and(|vendor| {
            vendor.pid == pid
                && raw(&vendor.process) == original_process
                && raw(&vendor.thread) == original_thread
                && process_birth(raw(&vendor.process)).ok() == Some(birth)
        });
        let cleanup = retained
            .as_mut()
            .map(NativeProcess::terminate_and_confirm)
            .transpose();
        // Always prove actual original exit before any assertion about the fault
        // path. A mutation that retries reaches real native cleanup, not a hang.
        assert!(cleanup.is_ok(), "retained vendor fixture cleanup");
        assert_eq!(
            unsafe { WaitForSingleObject(observed.as_raw_handle() as HANDLE, 2_000) },
            0,
            "original vendor actually terminated"
        );
        eprintln!("RETAINED_VENDOR_CLEANUP_CONFIRMED");
        if attempts != 1 || !same_owner {
            eprintln!("VENDOR_DROP_MUST_ATTEMPT_ONCE_AND_RETAIN_ORIGINAL");
        }
        assert_eq!(attempts, 1, "vendor destructor retried on caller stack");
        assert!(
            same_owner,
            "vendor destructor lost original process/thread ownership"
        );
    }

    #[test]
    fn wrong_remote_kind_is_refused_without_consuming_the_handle() {
        let handle = open_null(0).expect("private null endpoint");
        assert!(validate_remote(raw(&handle), RemoteKind::Pipe).is_err());
        assert!(validate_remote(raw(&handle), RemoteKind::File).is_ok());
    }

    #[test]
    fn already_inheritable_remote_endpoint_is_refused() {
        let handle = open_null(0).expect("private null endpoint");
        // SAFETY: only this test's fresh endpoint is changed.
        assert_ne!(
            unsafe { SetHandleInformation(raw(&handle), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        assert!(validate_remote(raw(&handle), RemoteKind::File).is_err());
    }

    /// Bootstrap capability only. The launch recipe still crosses the bound pipe.
    #[test]
    #[ignore = "private subprocess actor; parent supplies authenticated bootstrap"]
    fn creator_helper_actor() {
        let _env = csq_core::platform::test_env::lock();
        let _admission = csq_core::update::installer_admission::windows::enter_process()
            .expect("private helper admission");
        let encoded = std::env::var("CSQ_PRIVATE_VENDOR_CREATOR_BOOTSTRAP_V1")
            .expect("private helper bootstrap");
        let argv: Vec<String> =
            serde_json::from_str(&encoded).expect("private helper bootstrap framing");
        let argv: Vec<OsString> = std::iter::once(OsString::from("csq-private-creator-actor"))
            .chain(argv.into_iter().map(OsString::from))
            .collect();
        match dispatch_helper(&argv) {
            Ok(Some(code)) => std::process::exit(code as i32),
            _ => std::process::exit(2),
        }
    }
}
