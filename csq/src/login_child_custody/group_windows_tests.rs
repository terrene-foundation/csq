//! Portable decision probes and native Windows production-Job qualification.
use super::{creator_retirement_ready, job_completion_ready};
use std::cell::Cell;
use std::io;

#[test]
fn creator_exit_observation_precedes_vendor_exit_observation() {
    let vendor_signaled = Cell::new(false);
    let ready = creator_retirement_ready(
        false,
        || {
            // The vendor and then its waiting creator exit between the two
            // old probes. Seeing creator exit makes this vendor state visible.
            vendor_signaled.set(true);
            Ok(true)
        },
        || Ok(vendor_signaled.get()),
    );
    assert!(
        matches!(ready, Ok(true)),
        "CREATOR_RETIREMENT_MUST_OBSERVE_CREATOR_EXIT_BEFORE_VENDOR: {ready:?}"
    );
}

#[test]
fn live_creator_is_pending_without_vendor_observation() {
    let vendor_queried = Cell::new(false);
    let ready = creator_retirement_ready(
        false,
        || Ok(false),
        || {
            vendor_queried.set(true);
            Ok(true)
        },
    );
    assert!(matches!(ready, Ok(false)) && !vendor_queried.get());
}

#[test]
fn exited_creator_with_live_vendor_refuses_retirement() {
    let error = creator_retirement_ready(false, || Ok(true), || Ok(false))
        .expect_err("live vendor must retain creator custody");
    assert_eq!(error.to_string(), "login_creator_exited_before_vendor");
}

#[test]
fn creator_observation_error_remains_error_without_vendor_observation() {
    let vendor_queried = Cell::new(false);
    let error = creator_retirement_ready(
        false,
        || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "creator observation",
            ))
        },
        || {
            vendor_queried.set(true);
            Ok(true)
        },
    )
    .expect_err("creator observation error must retain custody");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!vendor_queried.get());
}

#[test]
fn vendor_observation_error_after_creator_exit_remains_error() {
    let error = creator_retirement_ready(
        false,
        || Ok(true),
        || {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "vendor observation",
            ))
        },
    )
    .expect_err("vendor observation error must retain custody");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
}

#[test]
fn successful_job_stop_waits_for_actual_vendor_after_creator_exit() {
    let observation_order = Cell::new(0);
    let ready = creator_retirement_ready(
        true,
        || {
            observation_order.set(1);
            Ok(true)
        },
        || {
            assert_eq!(observation_order.get(), 1, "creator must be observed first");
            observation_order.set(2);
            Ok(false)
        },
    );
    assert!(
        observation_order.get() == 2 && matches!(ready, Ok(false)),
        "CREATOR_JOB_STOP_MUST_WAIT_FOR_ACTUAL_VENDOR_EXIT: {ready:?}"
    );
}

#[test]
fn successful_job_stop_retires_only_after_both_original_processes_exit() {
    assert!(creator_retirement_ready(true, || Ok(true), || Ok(true)).unwrap());
}

#[test]
fn successful_job_stop_with_live_creator_does_not_query_vendor() {
    let vendor_queried = Cell::new(false);
    let ready = creator_retirement_ready(
        true,
        || Ok(false),
        || {
            vendor_queried.set(true);
            Ok(true)
        },
    );
    assert!(matches!(ready, Ok(false)) && !vendor_queried.get());
}

#[test]
fn successful_job_stop_preserves_creator_observation_errors() {
    let vendor_queried = Cell::new(false);
    let error = creator_retirement_ready(
        true,
        || Err(io::Error::other("creator observation")),
        || {
            vendor_queried.set(true);
            Ok(true)
        },
    )
    .expect_err("stop context cannot replace actual creator observation");
    assert!(!vendor_queried.get());
    assert_eq!(error.to_string(), "creator observation");
}

#[test]
fn successful_job_stop_preserves_vendor_observation_errors() {
    let error = creator_retirement_ready(
        true,
        || Ok(true),
        || {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "vendor observation",
            ))
        },
    )
    .expect_err("stop context cannot replace actual vendor observation");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
}

#[test]
fn exited_leader_and_empty_job_allow_original_child_reap() {
    assert!(job_completion_ready(Ok(true), || Ok(0)).unwrap());
}

#[test]
fn nonempty_job_refuses_original_child_reap() {
    let result = job_completion_ready(Ok(true), || Ok(1));
    assert!(
        result.is_err(),
        "JOB_CENSUS_NONEMPTY_MUST_REFUSE_REAP: {result:?}"
    );
}

#[test]
fn failed_job_census_refuses_original_child_reap() {
    let result = job_completion_ready(Ok(true), || {
        Err(io::Error::other("injected census unavailable"))
    });
    assert!(
        result.is_err(),
        "JOB_CENSUS_UNAVAILABLE_MUST_REFUSE_REAP: {result:?}"
    );
}

#[test]
fn failed_exit_observation_refuses_reap_without_census() {
    let mut queried = false;
    let result = job_completion_ready(Err(io::Error::other("injected exit unavailable")), || {
        queried = true;
        Ok(0)
    });
    assert!(
        !queried && result.is_err(),
        "JOB_EXIT_UNAVAILABLE_MUST_REFUSE_REAP: queried={queried}; {result:?}"
    );
}

#[test]
fn live_leader_is_pending_without_job_census() {
    let mut queried = false;
    let result = job_completion_ready(Ok(false), || {
        queried = true;
        Ok(0)
    });
    // This decision's pending contract is separate from the causal census bug:
    // the original actual Child::try_wait normally also returns None here.
    assert!(
        !queried && matches!(result, Ok(false)),
        "JOB_LIVE_LEADER_MUST_REMAIN_PENDING: queried={queried}; {result:?}"
    );
}

#[test]
fn job_refusal_errors_keep_census_classification_and_fixed_reasons() {
    for (result, tag) in [
        (
            job_completion_ready(Ok(true), || Ok(1)),
            "login_job_census_nonempty",
        ),
        (
            job_completion_ready(Ok(true), || Err(io::Error::other("unavailable"))),
            "login_job_census_unavailable",
        ),
        (
            job_completion_ready(Err(io::Error::other("unavailable")), || Ok(0)),
            "login_job_exit_observation_unavailable",
        ),
    ] {
        let error = result.expect_err("must retain typed census refusal");
        assert!(
            super::is_census_refusal(&error),
            "JOB_REFUSAL_MUST_BYPASS_GENERIC_ERROR_BUDGET"
        );
        assert_eq!(error.to_string(), tag);
    }
    assert!(!super::is_census_refusal(&io::Error::other(
        "unrelated observation"
    )));
}

// Parse the on-disk PE headers, rather than trusting a filename or build command.
fn pe_subsystem(bytes: &[u8]) -> io::Result<u16> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "gui_creator_pe_refused");
    let u16_at = |at: usize| -> io::Result<u16> {
        let end = at.checked_add(2).ok_or_else(invalid)?;
        let value = bytes.get(at..end).ok_or_else(invalid)?;
        Ok(u16::from_le_bytes([value[0], value[1]]))
    };
    if bytes.get(..2) != Some(b"MZ") {
        return Err(invalid());
    }
    let offset = bytes.get(0x3c..0x40).ok_or_else(invalid)?;
    let pe = u32::from_le_bytes(offset.try_into().map_err(|_| invalid())?) as usize;
    let coff = pe.checked_add(4).ok_or_else(invalid)?;
    let optional = pe.checked_add(24).ok_or_else(invalid)?;
    if pe < 0x40 || bytes.get(pe..coff) != Some(b"PE\0\0") {
        return Err(invalid());
    }
    let size = usize::from(u16_at(coff.checked_add(16).ok_or_else(invalid)?)?);
    let characteristics = u16_at(coff.checked_add(18).ok_or_else(invalid)?)?;
    if characteristics & 0x0002 == 0 || characteristics & 0x2000 != 0 || size < 70 {
        return Err(invalid());
    }
    let end = optional.checked_add(size).ok_or_else(invalid)?;
    if bytes.get(optional..end).is_none() || !matches!(u16_at(optional)?, 0x10b | 0x20b) {
        return Err(invalid());
    }
    u16_at(optional.checked_add(68).ok_or_else(invalid)?)
}

#[test]
fn gui_creator_pe_parser_distinguishes_gui_console_and_malformed_images() {
    fn image(subsystem: u16) -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[84..86].copy_from_slice(&240u16.to_le_bytes());
        bytes[86..88].copy_from_slice(&2u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[156..158].copy_from_slice(&subsystem.to_le_bytes());
        bytes
    }
    assert_eq!(pe_subsystem(&image(2)).unwrap(), 2);
    assert_eq!(pe_subsystem(&image(3)).unwrap(), 3);
    let mut malformed = image(2);
    malformed[64] = 0;
    assert!(pe_subsystem(&malformed).is_err());
    let mut out_of_bounds = image(2);
    out_of_bounds[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(pe_subsystem(&out_of_bounds).is_err());
    assert!(pe_subsystem(&image(2)[..157]).is_err());
    let mut short_optional = image(2);
    short_optional[84..86].copy_from_slice(&69u16.to_le_bytes());
    assert!(pe_subsystem(&short_optional).is_err());
}

#[cfg(windows)]
mod native {
    use super::super::{self as group, WaitLease};
    use crate::login_child_custody::process::{Child, Command, Stdio};
    use std::ffi::c_void;
    use std::io::{self, BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::process::{Child as StdChild, Stdio as StdStdio};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Console::{
        AllocConsole, FreeConsole, GetConsoleMode, GetStdHandle, SetStdHandle, STD_ERROR_HANDLE,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    const ENTRY: &str =
        "login_child_custody::group::windows_tests::native::private_windows_job_actor";
    const ROOT: &str = "CSQ_PRIVATE_WINDOWS_JOB_ROOT";
    const ROLE: &str = "CSQ_PRIVATE_WINDOWS_JOB_ROLE";
    const NONCE: &str = "CSQ_PRIVATE_WINDOWS_JOB_NONCE";
    const ADDRESS: &str = "CSQ_PRIVATE_WINDOWS_JOB_ADDRESS";
    const UNKNOWN: &str = "WINDOWS_JOB_OBSERVATION_UNDETERMINED";
    const SETUP: Duration = Duration::from_secs(5);
    const OBSERVE: Duration = Duration::from_secs(2);
    // Normal setup+observation+cleanup budget is <=12s. Actor self-release at
    // 30s is an independent final bound, never a successful observation.
    const SAFETY: Duration = Duration::from_secs(30);

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessTimes(
            process: *mut c_void,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn GetExitCodeProcess(process: *mut c_void, code: *mut u32) -> i32;
        fn WaitForSingleObject(process: *mut c_void, milliseconds: u32) -> u32;
        fn TerminateProcess(process: *mut c_void, status: u32) -> i32;
    }
    fn birth(handle: *mut c_void) -> io::Result<u64> {
        let (mut created, mut exited, mut kernel, mut user) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        // SAFETY: retained or current-process handle, correctly aligned Win32
        // FILETIME outputs (two DWORDs), each independently initialized.
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.high) << 32) | u64::from(created.low))
    }
    fn exited(handle: *mut c_void) -> io::Result<bool> {
        // SAFETY: retained original process object; read-only zero-time wait.
        match unsafe { WaitForSingleObject(handle, 0) } {
            0 => Ok(true),
            258 => Ok(false),
            0xffff_ffff => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(UNKNOWN)),
        }
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct Identity {
        role: String,
        nonce: String,
        pid: u32,
        birth: u64,
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ReapObservation {
        reaped: bool,
        refused: bool,
        reason: String,
        active: u32,
        finalized: bool,
        helper_retired: bool,
        member_pids: Vec<u32>,
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct CompletionObservation {
        vendor_code: Option<i32>,
        active: u32,
        finalized: bool,
        helper_retired: bool,
        readers_joined: bool,
        operator_kill_intent: bool,
    }
    fn write_json(stream: &mut TcpStream, value: &impl serde::Serialize) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        stream.write_all(&bytes)
    }
    fn line(stream: &mut BufReader<TcpStream>) -> io::Result<String> {
        let mut text = String::new();
        if stream.read_line(&mut text)? == 0 || !text.ends_with('\n') {
            return Err(io::Error::other(UNKNOWN));
        }
        Ok(text)
    }
    fn command(root: &Path, nonce: &str, address: SocketAddr, role: &str) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.env_clear();
        for key in [
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .args([
                ENTRY,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(root)
            .env(ROOT, root)
            .env(NONCE, nonce)
            .env(ADDRESS, address.to_string())
            .env(ROLE, role)
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("APPDATA", root.join("appdata"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("PATH", root.join("bin"))
            .env("TMPDIR", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("CSQ_SECRET_BACKEND", "in-memory")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        Ok(command)
    }
    // Outer owners and inert descendants use ordinary std spawning. Only the
    // production owner-to-vendor boundary goes through group::spawn.
    fn standard_command(
        root: &Path,
        nonce: &str,
        address: SocketAddr,
        role: &str,
    ) -> io::Result<std::process::Command> {
        command(root, nonce, address, role)?.into_std_command()
    }
    fn private_record(root: &Path, name: &str, value: &impl serde::Serialize) -> io::Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > CONSOLE_RECORD_BYTES {
            return Err(console_unknown("console_record_exceeds_bound"));
        }
        let mut pending = tempfile::NamedTempFile::new_in(root)?;
        pending.write_all(&bytes)?;
        pending.flush()?;
        pending
            .persist(root.join(name))
            .map_err(|error| error.error)?;
        Ok(())
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct ConsoleReceipt {
        nonce: String,
        pid: u32,
        birth: u64,
        input_console: bool,
        output_console: bool,
        error_console: bool,
        input_mode_error: Option<i32>,
        output_mode_error: Option<i32>,
        error_mode_error: Option<i32>,
        input_ok: bool,
        input_eof: bool,
        stdout_ok: bool,
        stderr_ok: bool,
        input_error: Option<i32>,
        stdout_error: Option<i32>,
        stderr_error: Option<i32>,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ConsoleLaunchMode {
        Baseline,
        InitializedEarly,
        Standard,
        PlainRaw,
        Automatic,
        InitializedKeepalive,
        NoParent,
        ParentOnly,
        HandleOnly,
        JobOnly,
    }
    impl ConsoleLaunchMode {
        fn tag(self) -> &'static str {
            match self {
                Self::Baseline => "baseline",
                Self::InitializedEarly => "initialized_early",
                Self::Standard => "standard",
                Self::PlainRaw => "plain_raw",
                Self::Automatic => "automatic_stdio",
                Self::InitializedKeepalive => "initialized_keepalive",
                Self::NoParent => "attr_no_parent",
                Self::ParentOnly => "attr_parent_only",
                Self::HandleOnly => "attr_handle_only",
                Self::JobOnly => "attr_job_only",
            }
        }
        fn prefix(self) -> &'static str {
            match self {
                Self::Baseline => "",
                Self::InitializedEarly => "initialized-donor-",
                Self::Standard => "standard-control-",
                Self::PlainRaw => "plain-control-",
                Self::Automatic => "automatic-control-",
                Self::InitializedKeepalive => "keepalive-donor-",
                Self::NoParent => "attr-no-parent-",
                Self::ParentOnly => "attr-parent-only-",
                Self::HandleOnly => "attr-handle-only-",
                Self::JobOnly => "attr-job-only-",
            }
        }
        fn initialized(self) -> bool {
            matches!(
                self,
                Self::InitializedEarly
                    | Self::InitializedKeepalive
                    | Self::NoParent
                    | Self::ParentOnly
                    | Self::HandleOnly
                    | Self::JobOnly
            )
        }
        fn keeps_donor_alive(self) -> bool {
            self.initialized() && self != Self::InitializedEarly
        }
        fn explicit_job_attribute(self) -> bool {
            !matches!(
                self,
                Self::Standard
                    | Self::PlainRaw
                    | Self::Automatic
                    | Self::ParentOnly
                    | Self::HandleOnly
            )
        }
        fn attribute_variant(
            self,
        ) -> Option<crate::login_child_custody::windows_process::AttributeProbeVariant> {
            use crate::login_child_custody::windows_process::AttributeProbeVariant as Variant;
            match self {
                Self::NoParent => Some(Variant::NoParent),
                Self::ParentOnly => Some(Variant::ParentOnly),
                Self::HandleOnly => Some(Variant::HandleOnly),
                Self::JobOnly => Some(Variant::JobOnly),
                _ => None,
            }
        }
        fn parse(case: &str) -> (Self, &str) {
            for mode in [
                Self::InitializedEarly,
                Self::Standard,
                Self::PlainRaw,
                Self::Automatic,
                Self::InitializedKeepalive,
                Self::NoParent,
                Self::ParentOnly,
                Self::HandleOnly,
                Self::JobOnly,
            ] {
                if let Some(shape) = case.strip_prefix(mode.prefix()) {
                    return (mode, shape);
                }
            }
            (Self::Baseline, case)
        }
    }
    fn attribute_variant_tag(
        variant: crate::login_child_custody::windows_process::AttributeProbeVariant,
    ) -> &'static str {
        use crate::login_child_custody::windows_process::AttributeProbeVariant as Variant;
        match variant {
            Variant::NoParent => "no_parent",
            Variant::ParentOnly => "parent_only",
            Variant::HandleOnly => "handle_only",
            Variant::JobOnly => "job_only",
        }
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct DonorConsoleObservation {
        window_handle: u64,
        process_list_capacity: usize,
        process_count_returned: u32,
        process_list_complete: bool,
        // Read-only console query results, never authority to open or signal IDs.
        process_ids: Vec<u32>,
        process_list_error: Option<i32>,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct InitializedDonorEntry {
        role: String,
        nonce: String,
        pid: u32,
        birth: u64,
        creator_supplied_flags: Option<u32>,
        console: DonorConsoleObservation,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct HandleFileType {
        slot: String,
        slot_error: Option<i32>,
        raw_type: u32,
        type_error: Option<u32>,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleFileTypes {
        stdin: HandleFileType,
        stdout: HandleFileType,
        stderr: HandleFileType,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct VendorFileTypes {
        nonce: String,
        pid: u32,
        birth: u64,
        #[serde(flatten)]
        types: ConsoleFileTypes,
    }
    fn observed_file_type(id: u32) -> HandleFileType {
        use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
        use windows_sys::Win32::Storage::FileSystem::GetFileType;
        // SAFETY: inspect only this isolated actor's own standard handle slot.
        let handle = unsafe { GetStdHandle(id) };
        let slot_error = if handle == -1 {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        // SAFETY: GetFileType accepts this borrowed handle (invalid slots are
        // observed errors). Clear last-error to distinguish UNKNOWN success.
        let (raw_type, code) = unsafe {
            SetLastError(0);
            let kind = GetFileType(handle);
            (kind, GetLastError())
        };
        HandleFileType {
            slot: if handle == 0 {
                "null"
            } else if handle == -1 {
                "invalid"
            } else {
                "present"
            }
            .into(),
            slot_error,
            raw_type,
            type_error: if raw_type == 0 && code != 0 {
                Some(code)
            } else {
                None
            },
        }
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct AutomaticCreatorSourceContract {
        inherit_handles: bool,
        startup_flags: u32,
        standard_handle_overrides: bool,
        private_stdio_inheritable_duplicates: u32,
        creation_flags: u32,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleModeContext {
        launch_mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        automatic_creator_source_contract: Option<AutomaticCreatorSourceContract>,
        explicit_job_attribute: bool,
        observed_vendor_job_member: Option<bool>,
        creator_configured_donor_flags: Option<u32>,
        attribute_variant: Option<String>,
        donor_observation: Option<InitializedDonorEntry>,
        component_job: bool,
        job_empty: Option<bool>,
        donor_ready: bool,
        donor_keepalive_requested: bool,
        donor_alive_after_vendor_exit: Option<bool>,
        donor_reaped_before_census: Option<bool>,
    }
    impl ConsoleModeContext {
        fn new(mode: ConsoleLaunchMode) -> Self {
            use windows_sys::Win32::System::Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            };
            Self {
                launch_mode: mode.tag().into(),
                // Fixed arguments of spawn_automatic_stdio_for_test, not an OS
                // census of other inheritable handles in this process.
                automatic_creator_source_contract: (mode == ConsoleLaunchMode::Automatic)
                    .then_some(AutomaticCreatorSourceContract {
                        inherit_handles: false,
                        startup_flags: 0,
                        standard_handle_overrides: false,
                        private_stdio_inheritable_duplicates: 0,
                        creation_flags: CREATE_SUSPENDED
                            | CREATE_NEW_PROCESS_GROUP
                            | CREATE_UNICODE_ENVIRONMENT,
                    }),
                explicit_job_attribute: mode.explicit_job_attribute(),
                observed_vendor_job_member: None,
                creator_configured_donor_flags: None,
                attribute_variant: mode
                    .attribute_variant()
                    .map(attribute_variant_tag)
                    .map(str::to_owned),
                donor_observation: None,
                component_job: false,
                job_empty: None,
                donor_ready: false,
                donor_keepalive_requested: mode.keeps_donor_alive(),
                donor_alive_after_vendor_exit: None,
                donor_reaped_before_census: None,
            }
        }
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleProbe {
        case: String,
        mode_context: ConsoleModeContext,
        initialized_donor_comparison: bool,
        initialized_donor_ready_bound: bool,
        owner_pid: u32,
        owner_birth: u64,
        accepted: bool,
        vendor_exit_success: bool,
        actual_child_matched: bool,
        original_child_reaped: bool,
        readers_joined: bool,
        reader_count: usize,
        input_console: bool,
        output_console: bool,
        error_console: bool,
        input_mode_error: Option<i32>,
        output_mode_error: Option<i32>,
        error_mode_error: Option<i32>,
        input_ok: bool,
        input_eof: bool,
        stdout_ok: bool,
        stderr_ok: bool,
        stdout_nonce_observed: bool,
        stderr_nonce_observed: bool,
        input_error: Option<i32>,
        stdout_error: Option<i32>,
        stderr_error: Option<i32>,
        spawn_stage: String,
        spawn_error_code: Option<i32>,
        vendor_observation: Option<ConsoleVendorObservation>,
    }
    const CONSOLE_CAPTURE_BYTES: usize = 256;
    const CONSOLE_RECORD_BYTES: usize = 4096;
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleActorEntry {
        nonce: String,
        role: String,
        pid: u32,
        birth: Option<u64>,
        birth_error: Option<i32>,
        cwd_matches_bound_root: bool,
        cwd_error: Option<i32>,
        isolation_bindings_validated: bool,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleCapturedStream {
        state: String,
        eof_joined: bool,
        truncated: bool,
        captured_bytes: usize,
        prefix_hex: String,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleVendorObservation {
        nonce: String,
        pid: Option<u32>,
        birth: Option<u64>,
        birth_error: Option<i32>,
        exit_code: Option<u32>,
        exit_code_hex: Option<String>,
        exit_code_error: Option<i32>,
        actor_entry_state: String,
        actor_entry_error: Option<i32>,
        actor_entry: Option<ConsoleActorEntry>,
        file_types_state: String,
        file_types_error: Option<i32>,
        file_types: Option<ConsoleFileTypes>,
        stdout: ConsoleCapturedStream,
        stderr: ConsoleCapturedStream,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleFailure {
        stage: String,
        kind: String,
        code: Option<i32>,
        mode_context: Option<ConsoleModeContext>,
        vendor_observation: Option<Box<ConsoleVendorObservation>>,
        #[serde(default)]
        cleanup_confirmed: bool,
    }
    impl std::fmt::Display for ConsoleFailure {
        fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                out,
                "{}: stage={} kind={} win32={:?} mode={:?} vendor={:?}",
                if self.kind == "causal-oracle" {
                    "WINDOWS_FIXTURE_CAUSAL_OBSERVATION"
                } else {
                    UNKNOWN
                },
                self.stage,
                self.kind,
                self.code,
                self.mode_context,
                self.vendor_observation
            )
        }
    }
    impl std::error::Error for ConsoleFailure {}
    fn console_at<T>(stage: &'static str, result: io::Result<T>) -> io::Result<T> {
        result.map_err(|error| console_failure(stage, error))
    }
    fn console_failure(stage: &'static str, error: io::Error) -> io::Error {
        if error
            .get_ref()
            .is_some_and(|inner| inner.is::<ConsoleFailure>())
        {
            return error;
        }
        io::Error::new(
            error.kind(),
            ConsoleFailure {
                stage: stage.into(),
                kind: format!("{:?}", error.kind()),
                code: error.raw_os_error(),
                mode_context: None,
                vendor_observation: None,
                cleanup_confirmed: false,
            },
        )
    }
    fn console_with_vendor(
        error: io::Error,
        diagnostic: ConsoleVendorObservation,
        context: ConsoleModeContext,
    ) -> io::Error {
        let error = console_failure("vendor_observation", error);
        let Some(first) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ConsoleFailure>())
        else {
            return error;
        };
        let mut first = first.clone();
        first.mode_context = Some(context);
        if first.vendor_observation.is_none() {
            first.vendor_observation = Some(Box::new(diagnostic));
        }
        io::Error::new(error.kind(), first)
    }
    fn console_with_mode(error: io::Error, context: ConsoleModeContext) -> io::Error {
        let error = console_failure("console_mode_observation", error);
        let Some(first) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ConsoleFailure>())
        else {
            return error;
        };
        let mut first = first.clone();
        if first.mode_context.is_none() {
            first.mode_context = Some(context);
        }
        io::Error::new(error.kind(), first)
    }
    fn console_unknown(stage: &'static str) -> io::Error {
        io::Error::other(ConsoleFailure {
            stage: stage.into(),
            kind: "observation".into(),
            code: None,
            mode_context: None,
            vendor_observation: None,
            cleanup_confirmed: false,
        })
    }
    const CREATOR_LEASE_MISMATCH: &str =
        "WINDOWS_FIXTURE_CREATOR_LEASE_RETAINED_AFTER_POSITIVE_GATE";
    const LIVE_HELPER_MISMATCH: &str = "WINDOWS_FIXTURE_LIVE_HELPER_BLOCKS_RETIREMENT_GATE";
    const LIVE_HELPER_RELEASE_BARRIER: bool = false;
    fn console_causal(stage: &'static str) -> io::Error {
        let error = console_unknown(stage);
        let mut failure = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<ConsoleFailure>())
            .expect("typed console failure")
            .clone();
        failure.kind = "causal-oracle".into();
        io::Error::other(failure)
    }
    struct HelperRetirementControl {
        ready: OwnedHandle,
        release: OwnedHandle,
        ready_name: String,
        release_name: String,
    }
    impl HelperRetirementControl {
        fn new() -> io::Result<Self> {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::System::Threading::CreateEventW;
            let mut bytes = [0u8; 16];
            getrandom::getrandom(&mut bytes).map_err(|_| io::Error::other(UNKNOWN))?;
            let suffix: String = bytes
                .into_iter()
                .flat_map(|byte| [byte >> 4, byte & 15])
                .map(|digit| char::from(b"0123456789abcdef"[usize::from(digit)]))
                .collect();
            let open = |name: &str| -> io::Result<OwnedHandle> {
                let name: Vec<u16> = std::ffi::OsStr::new(name)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                // SAFETY: random128 Local name/default user DACL; FALSE inheritance.
                let (handle, error) = unsafe {
                    windows_sys::Win32::Foundation::SetLastError(0);
                    let h = CreateEventW(std::ptr::null(), 1, 0, name.as_ptr());
                    (h, windows_sys::Win32::Foundation::GetLastError())
                };
                if handle == 0 {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                let owned = unsafe { OwnedHandle::from_raw_handle(handle as *mut c_void) };
                if error == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS {
                    return Err(io::Error::other(UNKNOWN));
                }
                Ok(owned)
            };
            let ready_name = format!("Local\\csq-retirement-ready-{suffix}");
            let release_name = format!("Local\\csq-retirement-release-{suffix}");
            Ok(Self {
                ready: open(&ready_name)?,
                release: open(&release_name)?,
                ready_name,
                release_name,
            })
        }
        fn release(&self) -> io::Result<()> {
            // SAFETY: original private fixture event, held through helper wait.
            if unsafe {
                windows_sys::Win32::System::Threading::SetEvent(
                    self.release.as_raw_handle() as isize
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl Drop for HelperRetirementControl {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ConsoleOwnerFailure {
        nonce: String,
        pid: u32,
        birth: Option<u64>,
        failure: ConsoleFailure,
    }
    fn bounded_console_record(path: &Path) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(CONSOLE_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > CONSOLE_RECORD_BYTES {
            return Err(console_unknown("console_record_exceeds_bound"));
        }
        Ok(bytes)
    }
    fn record_console_failure(root: &Path, name: &str, nonce: &str, error: &io::Error) {
        let failure = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ConsoleFailure>())
            .cloned()
            .unwrap_or_else(|| ConsoleFailure {
                stage: "console_actor_unclassified".into(),
                kind: format!("{:?}", error.kind()),
                code: error.raw_os_error(),
                mode_context: None,
                vendor_observation: None,
                cleanup_confirmed: false,
            });
        // SAFETY: borrowed pseudo handle of this isolated actor only.
        let record = ConsoleOwnerFailure {
            nonce: nonce.into(),
            pid: std::process::id(),
            birth: birth(unsafe { GetCurrentProcess() }).ok(),
            failure,
        };
        if let Err(write_error) =
            console_at("console_error_record", private_record(root, name, &record))
        {
            eprintln!("{UNKNOWN}: first={record:?}; record_failure={write_error}");
        }
    }
    #[test]
    fn console_failure_record_with_max_capture_prefixes_fits_bound_and_keeps_first_error() {
        for mode in [
            ConsoleLaunchMode::NoParent,
            ConsoleLaunchMode::ParentOnly,
            ConsoleLaunchMode::HandleOnly,
            ConsoleLaunchMode::JobOnly,
            ConsoleLaunchMode::Automatic,
        ] {
            let nonce = "N".repeat(128);
            let mut context = ConsoleModeContext::new(mode);
            context.component_job = true;
            context.job_empty = Some(false);
            context.donor_ready = true;
            context.observed_vendor_job_member = Some(true);
            context.creator_configured_donor_flags = Some(u32::MAX);
            context.donor_alive_after_vendor_exit = Some(true);
            context.donor_reaped_before_census = Some(false);
            context.donor_observation = Some(InitializedDonorEntry {
                role: "initialized-donor-probe".into(),
                nonce: nonce.clone(),
                pid: u32::MAX,
                birth: u64::MAX,
                creator_supplied_flags: Some(u32::MAX),
                console: DonorConsoleObservation {
                    window_handle: u64::MAX,
                    process_list_capacity: 4,
                    process_count_returned: 4,
                    process_list_complete: true,
                    process_ids: vec![u32::MAX; 4],
                    process_list_error: Some(i32::MAX),
                },
            });
            if mode == ConsoleLaunchMode::Automatic {
                // This groupless control has no donor. Bound its complete wire
                // record independently rather than inventing donor evidence.
                context = ConsoleModeContext::new(mode);
            }
            let capture = ConsoleCapturedStream {
                state: "piped".into(),
                eof_joined: true,
                truncated: true,
                captured_bytes: CONSOLE_CAPTURE_BYTES,
                prefix_hex: "ff".repeat(CONSOLE_CAPTURE_BYTES),
            };
            let file_type = HandleFileType {
                slot: "present".into(),
                slot_error: Some(i32::MAX),
                raw_type: u32::MAX,
                type_error: Some(u32::MAX),
            };
            let diagnostic = ConsoleVendorObservation {
                nonce: nonce.clone(),
                pid: Some(u32::MAX),
                birth: Some(u64::MAX),
                birth_error: None,
                exit_code: Some(0xC0000142),
                exit_code_hex: Some("0xC0000142".into()),
                exit_code_error: None,
                actor_entry_state: "observed_identity_match".into(),
                actor_entry_error: None,
                actor_entry: Some(ConsoleActorEntry {
                    nonce: nonce.clone(),
                    role: "console-probe-vendor".into(),
                    pid: u32::MAX,
                    birth: Some(u64::MAX),
                    birth_error: None,
                    cwd_matches_bound_root: true,
                    cwd_error: None,
                    isolation_bindings_validated: true,
                }),
                file_types_state: "observed_identity_match".into(),
                file_types_error: None,
                file_types: Some(ConsoleFileTypes {
                    stdin: file_type.clone(),
                    stdout: file_type.clone(),
                    stderr: file_type,
                }),
                stdout: capture.clone(),
                stderr: capture,
            };
            let error = console_with_vendor(
                console_failure("vendor_receipt_read", io::Error::from_raw_os_error(2)),
                diagnostic,
                context.clone(),
            );
            let failure = error
                .get_ref()
                .unwrap()
                .downcast_ref::<ConsoleFailure>()
                .unwrap()
                .clone();
            let record = ConsoleOwnerFailure {
                nonce,
                pid: u32::MAX,
                birth: Some(u64::MAX),
                failure,
            };
            let bytes = serde_json::to_vec(&record).unwrap();
            assert!(
                bytes.len() <= CONSOLE_RECORD_BYTES,
                "maximum diagnostic exceeds bound: {}",
                bytes.len()
            );
            let decoded: ConsoleOwnerFailure = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded.failure.stage, "vendor_receipt_read");
            assert_eq!(decoded.failure.code, Some(2));
            let metadata = decoded.failure.mode_context.as_ref().unwrap();
            assert_eq!(metadata.launch_mode, mode.tag());
            if mode == ConsoleLaunchMode::Automatic {
                let creator = metadata.automatic_creator_source_contract.as_ref().unwrap();
                assert!(!creator.inherit_handles);
                assert!(!creator.standard_handle_overrides);
                assert_eq!(creator.startup_flags, 0);
                assert_eq!(creator.private_stdio_inheritable_duplicates, 0);
                assert!(!metadata.component_job);
                assert_eq!(metadata.job_empty, None);
                assert!(metadata.donor_observation.is_none());
            } else {
                assert!(metadata.donor_ready);
                assert_eq!(metadata.creator_configured_donor_flags, Some(u32::MAX));
            }
            let observed = decoded.failure.vendor_observation.unwrap();
            assert_eq!(observed.exit_code, Some(0xC0000142));
            assert_eq!(observed.exit_code_hex.as_deref(), Some("0xC0000142"));
            assert_eq!(observed.stderr.prefix_hex.len(), CONSOLE_CAPTURE_BYTES * 2);
            let probe = ConsoleProbe {
                case: format!("{}redirect-file", mode.prefix()),
                mode_context: context,
                initialized_donor_comparison: true,
                initialized_donor_ready_bound: true,
                owner_pid: u32::MAX,
                owner_birth: u64::MAX,
                accepted: true,
                vendor_exit_success: false,
                actual_child_matched: false,
                original_child_reaped: false,
                readers_joined: false,
                reader_count: 2,
                input_console: false,
                output_console: false,
                error_console: false,
                input_mode_error: Some(i32::MAX),
                output_mode_error: Some(i32::MAX),
                error_mode_error: Some(i32::MAX),
                input_ok: false,
                input_eof: false,
                stdout_ok: false,
                stderr_ok: false,
                stdout_nonce_observed: false,
                stderr_nonce_observed: false,
                input_error: Some(i32::MAX),
                stdout_error: Some(i32::MAX),
                stderr_error: Some(i32::MAX),
                spawn_stage: "attribute_probe_create_suspended_donor".into(),
                spawn_error_code: Some(i32::MAX),
                vendor_observation: Some(*observed),
            };
            let bytes = serde_json::to_vec(&probe).unwrap();
            assert!(
                bytes.len() <= CONSOLE_RECORD_BYTES,
                "maximum probe exceeds bound: {}",
                bytes.len()
            );
        }
    }
    fn require_private_console_mode(id: u32, stage: &'static str) -> io::Result<()> {
        // SAFETY: only this isolated owner's current standard slot is queried.
        let handle = unsafe { GetStdHandle(id) };
        if handle == -1 {
            return console_at(
                match id {
                    STD_INPUT_HANDLE => "owner_get_stdin_handle",
                    STD_OUTPUT_HANDLE => "owner_get_stdout_handle",
                    _ => "owner_get_stderr_handle",
                },
                Err(io::Error::last_os_error()),
            );
        }
        if handle == 0 {
            return Err(console_unknown(stage));
        }
        let mut mode = 0;
        // SAFETY: borrowed own standard handle and valid mode output.
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return console_at(stage, Err(io::Error::last_os_error()));
        }
        Ok(())
    }
    fn console_mode_observation(id: u32) -> (bool, Option<i32>) {
        // SAFETY: only the private actor's own borrowed slot is inspected.
        let handle = unsafe { GetStdHandle(id) };
        if handle == -1 {
            return (false, io::Error::last_os_error().raw_os_error());
        }
        if handle == 0 {
            return (false, None);
        }
        let mut mode = 0;
        // SAFETY: borrowed own standard handle, valid mode output.
        if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
            (true, None)
        } else {
            (false, io::Error::last_os_error().raw_os_error())
        }
    }
    fn console_mode(id: u32) -> bool {
        console_mode_observation(id).0
    }
    type ConsoleReader = JoinHandle<io::Result<(Vec<u8>, bool)>>;
    struct ConsoleChild {
        child: Option<Child>,
        group: Option<group::GroupControl>,
        donor_probe:
            Option<crate::login_child_custody::windows_process::InitializedDonorProbeGuard>,
        mode_context: ConsoleModeContext,
        readers: Vec<(bool, ConsoleReader)>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_piped: bool,
        stderr_piped: bool,
        stdout_eof_joined: bool,
        stderr_eof_joined: bool,
        stdout_truncated: bool,
        stderr_truncated: bool,
        reader_failed: bool,
        finalized: bool,
    }
    impl ConsoleChild {
        fn vendor_observation(
            &self,
            root: &Path,
            nonce: &str,
            case: &str,
        ) -> ConsoleVendorObservation {
            let mut observed = ConsoleVendorObservation {
                nonce: nonce.into(),
                pid: None,
                birth: None,
                birth_error: None,
                exit_code: None,
                exit_code_hex: None,
                exit_code_error: None,
                actor_entry_state: "actor_entry_unobserved".into(),
                actor_entry_error: None,
                actor_entry: None,
                file_types_state: "UNOBSERVED_actor_entry".into(),
                file_types_error: None,
                file_types: None,
                stdout: self.captured_stream(false, case),
                stderr: self.captured_stream(true, case),
            };
            if let Some(child) = self.child.as_ref() {
                observed.pid = Some(child.id());
                let created = birth(child.as_raw_handle());
                observed.birth = created.as_ref().ok().copied();
                observed.birth_error = created.as_ref().err().and_then(io::Error::raw_os_error);
                let mut code = 0u32;
                // SAFETY: original retained vendor HANDLE, valid DWORD output.
                // No process is reopened or identified through a numeric PID.
                if unsafe { GetExitCodeProcess(child.as_raw_handle(), &mut code) } != 0 {
                    observed.exit_code = Some(code);
                    observed.exit_code_hex = Some(format!("0x{code:08X}"));
                } else {
                    observed.exit_code_error = io::Error::last_os_error().raw_os_error();
                }
            }
            match bounded_console_record(&root.join("console-vendor-entry")) {
                Ok(bytes) => match serde_json::from_slice::<ConsoleActorEntry>(&bytes) {
                    Ok(entry) => {
                        observed.actor_entry_state = if entry.nonce == nonce
                            && entry.role == "console-probe-vendor"
                            && Some(entry.pid) == observed.pid
                            && entry.birth.is_some()
                            && entry.birth == observed.birth
                        {
                            "observed_identity_match"
                        } else {
                            "entry_identity_unconfirmed"
                        }
                        .into();
                        observed.actor_entry = Some(entry);
                    }
                    Err(_) => observed.actor_entry_state = "entry_record_parse_failed".into(),
                },
                Err(error) => {
                    observed.actor_entry_error = error.raw_os_error();
                    observed.actor_entry_state = if error.kind() == io::ErrorKind::NotFound {
                        // Absence does not distinguish loader, CRT, libtest or
                        // other work before this test actor's Rust body.
                        "actor_entry_unobserved_record_absent"
                    } else {
                        "entry_record_read_failed"
                    }
                    .into();
                }
            }
            if observed.actor_entry_state == "observed_identity_match" {
                match bounded_console_record(&root.join("console-vendor-file-types")) {
                    Ok(bytes) => match serde_json::from_slice::<VendorFileTypes>(&bytes) {
                        Ok(types)
                            if types.nonce == nonce
                                && Some(types.pid) == observed.pid
                                && Some(types.birth) == observed.birth =>
                        {
                            observed.file_types_state = "observed_identity_match".into();
                            observed.file_types = Some(types.types);
                        }
                        Ok(_) => observed.file_types_state = "UNOBSERVED_identity_mismatch".into(),
                        Err(_) => observed.file_types_state = "UNOBSERVED_record_parse".into(),
                    },
                    Err(error) => {
                        observed.file_types_error = error.raw_os_error();
                        observed.file_types_state = "UNOBSERVED_record_read".into();
                    }
                }
            }
            observed
        }
        fn captured_stream(&self, stderr: bool, case: &str) -> ConsoleCapturedStream {
            let (piped, bytes, eof_joined, truncated) = if stderr {
                (
                    self.stderr_piped,
                    &self.stderr,
                    self.stderr_eof_joined,
                    self.stderr_truncated,
                )
            } else {
                (
                    self.stdout_piped,
                    &self.stdout,
                    self.stdout_eof_joined,
                    self.stdout_truncated,
                )
            };
            let state = if piped {
                "piped"
            } else if case == "redirect-file" && !stderr {
                "redirected_file_not_captured"
            } else if case == "absent-inherit" {
                "inherited_absent_slot_not_captured"
            } else if case == "desktop" {
                "pipe_reader_not_started"
            } else {
                "inherited_console_not_captured"
            };
            let mut prefix_hex = String::with_capacity(bytes.len() * 2);
            use std::fmt::Write as _;
            for byte in bytes {
                let _ = write!(prefix_hex, "{byte:02x}");
            }
            ConsoleCapturedStream {
                state: state.into(),
                eof_joined,
                truncated,
                captured_bytes: bytes.len(),
                prefix_hex,
            }
        }
        fn join_readers(&mut self, deadline: Instant) -> io::Result<()> {
            if self.reader_failed {
                return Err(console_unknown("vendor_reader_previously_failed"));
            }
            while self.readers.iter().any(|(_, reader)| !reader.is_finished()) {
                if Instant::now() >= deadline {
                    return Err(console_unknown("vendor_reader_join_timeout"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut first_failure = None;
            for (stderr, reader) in self.readers.drain(..) {
                match reader.join() {
                    Ok(Ok((bytes, truncated))) => {
                        if stderr {
                            self.stderr.extend(bytes);
                            self.stderr_truncated = truncated;
                            self.stderr_eof_joined = true;
                        } else {
                            self.stdout.extend(bytes);
                            self.stdout_truncated = truncated;
                            self.stdout_eof_joined = true;
                        }
                    }
                    Ok(Err(error)) => {
                        self.reader_failed = true;
                        if first_failure.is_none() {
                            first_failure = console_at::<()>(
                                if stderr {
                                    "vendor_stderr_read"
                                } else {
                                    "vendor_stdout_read"
                                },
                                Err(error),
                            )
                            .err();
                        }
                    }
                    Err(_) => {
                        self.reader_failed = true;
                        if first_failure.is_none() {
                            first_failure = Some(console_unknown("vendor_reader_thread_panicked"));
                        }
                    }
                }
            }
            if self.reader_failed {
                Err(first_failure.unwrap_or_else(|| console_unknown("vendor_reader_failed")))
            } else {
                Ok(())
            }
        }
        fn cleanup(&mut self) -> io::Result<()> {
            if self.finalized {
                return Ok(());
            }
            if self.mode_context.component_job {
                if let Some(group) = self.group.as_ref() {
                    let _stop = group.signal(group::GroupSignal::Kill);
                }
            } else if let Some(child) = self.child.as_mut() {
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
            }
            if let Some(donor) = self.donor_probe.as_mut() {
                donor.finalize_for_test()?;
            }
            self.donor_probe.take();
            let deadline = Instant::now() + SETUP;
            self.join_readers(deadline)?;
            if let Some(group) = self.group.as_ref() {
                group.mark_readers_joined();
            }
            loop {
                let child = self
                    .child
                    .as_mut()
                    .ok_or_else(|| io::Error::other(UNKNOWN))?;
                let reaped = if self.mode_context.component_job {
                    self.group
                        .as_ref()
                        .ok_or_else(|| console_unknown("vendor_job_handle_missing"))?
                        .try_reap(child, true)
                } else {
                    child.try_wait()
                };
                match reaped {
                    Ok(Some(_)) => {
                        if child.creator_exit_for_test()? == Some(false) {
                            return Err(console_unknown("cleanup_original_creator_still_live"));
                        }
                        if self.mode_context.component_job
                            && self
                                .group
                                .as_ref()
                                .ok_or_else(|| console_unknown("cleanup_job_missing"))?
                                .0
                                .job
                                .active_count()?
                                != 0
                        {
                            return Err(console_unknown("cleanup_job_nonempty"));
                        }
                        self.finalized = true;
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(error) if group::is_census_refusal(&error) => {}
                    Err(error) => return Err(error),
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for ConsoleChild {
        fn drop(&mut self) {
            if self.cleanup().is_err() {
                std::mem::forget((
                    self.child.take(),
                    self.group.clone(),
                    std::mem::take(&mut self.readers),
                ));
                eprintln!("{UNKNOWN}: original console matrix child cleanup unconfirmed");
            }
        }
    }
    fn inject_private_console_line(input: &std::fs::File, nonce: &str) -> io::Result<()> {
        use windows_sys::Win32::System::Console::{
            WriteConsoleInputW, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD,
            KEY_EVENT_RECORD_0,
        };
        let mut events = Vec::new();
        for unit in nonce.encode_utf16().chain([13]) {
            for down in [1, 0] {
                events.push(INPUT_RECORD {
                    EventType: KEY_EVENT as u16,
                    Event: INPUT_RECORD_0 {
                        KeyEvent: KEY_EVENT_RECORD {
                            bKeyDown: down,
                            wRepeatCount: 1,
                            wVirtualKeyCode: if unit == 13 { 13 } else { 0 },
                            wVirtualScanCode: 0,
                            uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                            dwControlKeyState: 0,
                        },
                    },
                });
            }
        }
        let mut written = 0;
        // SAFETY: only the CONIN$ handle owned by this isolated AllocConsole
        // actor is injected. No host/test-runner console handle is accepted.
        if unsafe {
            WriteConsoleInputW(
                input.as_raw_handle() as isize,
                events.as_ptr(),
                events.len() as u32,
                &mut written,
            )
        } == 0
        {
            return console_at("owner_write_console_input", Err(io::Error::last_os_error()));
        }
        if written as usize != events.len() {
            return Err(console_unknown("owner_write_console_input_short"));
        }
        Ok(())
    }
    const GUI_CREATOR_PATH: &str = "CSQ_TEST_GUI_CREATOR_PATH";
    const GUI_CREATOR_SHA: &str = "CSQ_TEST_GUI_CREATOR_SHA256";
    const GUI_CREATOR_FORCE: &str = "CSQ_TEST_GUI_CREATOR_FORCE";
    struct GuiCreatorArtifact {
        path: PathBuf,
        sha256: String,
        // Deny write/delete sharing throughout qualification and actual launch.
        _pin: std::fs::File,
    }
    impl GuiCreatorArtifact {
        fn read(path: PathBuf, sha256: String) -> io::Result<Self> {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            if !path.is_absolute()
                || sha256.len() != 64
                || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(console_unknown("gui_creator_artifact_input"));
            }
            let mut pin = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&path)?;
            let metadata = pin.metadata()?;
            if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
                return Err(console_unknown("gui_creator_artifact_size"));
            }
            let mut bytes = Vec::new();
            pin.read_to_end(&mut bytes)?;
            let sha256 = sha256.to_ascii_lowercase();
            csq_core::update::verify::verify_checksum(
                &bytes,
                &format!("{sha256}  creator.exe"),
                "creator.exe",
            )
            .map_err(|_| console_unknown("gui_creator_artifact_checksum"))?;
            if super::pe_subsystem(&bytes)? != 2 {
                return Err(console_unknown("gui_creator_subsystem_not_gui"));
            }
            let prefix = b"CSQ-BUILD-FEATURES[";
            let mut markers = std::collections::BTreeSet::new();
            for (at, _) in bytes
                .windows(prefix.len())
                .enumerate()
                .filter(|(_, value)| *value == prefix)
            {
                let tail = &bytes[at + prefix.len()..];
                if let Some(end) = tail.iter().take(512).position(|b| *b == b']') {
                    if let Ok(marker) = std::str::from_utf8(&tail[..end]) {
                        if let Some((features, state)) =
                            marker.split_once(";csq-core-native-harness=")
                        {
                            if matches!(state, "0" | "1")
                                && features.bytes().all(|b| {
                                    b.is_ascii_lowercase()
                                        || b.is_ascii_digit()
                                        || matches!(b, b',' | b'-')
                                })
                            {
                                markers.insert(marker.to_owned());
                            }
                        }
                    }
                }
            }
            if markers.len() != 1
                || !markers.contains("desktop,test-utils;csq-core-native-harness=0")
            {
                return Err(console_unknown("gui_creator_build_features_refused"));
            }
            Ok(Self {
                path,
                sha256,
                _pin: pin,
            })
        }
        fn from_env() -> io::Result<Option<Self>> {
            match (
                std::env::var_os(GUI_CREATOR_PATH),
                std::env::var(GUI_CREATOR_SHA),
            ) {
                (None, Err(std::env::VarError::NotPresent)) => Ok(None),
                (Some(path), Ok(sha)) => Self::read(path.into(), sha).map(Some),
                _ => Err(console_unknown("gui_creator_artifact_pair_missing")),
            }
        }
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct GuiCreatorRoute {
        nonce: String,
        owner_pid: u32,
        owner_birth: u64,
        artifact_sha256: String,
        force_creator: bool,
        actual_helper_creations: usize,
    }
    fn console_owner(
        root: &Path,
        nonce: &str,
        case: &str,
        address: SocketAddr,
    ) -> io::Result<ConsoleProbe> {
        let probe_case = case;
        let (mode, case) = ConsoleLaunchMode::parse(case);
        let gui_artifact = GuiCreatorArtifact::from_env()?;
        let gui_force = match std::env::var(GUI_CREATOR_FORCE) {
            Ok(value) if value == "1" => true,
            Ok(value) if value == "0" => false,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err(console_unknown("gui_creator_force_invalid")),
        };
        if gui_force && gui_artifact.is_none() {
            return Err(console_unknown("gui_creator_force_without_artifact"));
        }
        let _gui_guard = gui_artifact
            .as_ref()
            .map(|artifact| {
                crate::login_child_custody::windows_process::helper_executable_override_for_test(
                    artifact.path.clone(),
                    gui_force,
                )
            })
            .transpose()?;
        let helper_count_before =
            crate::login_child_custody::windows_process::creator_helper_launch_count_for_test();
        let initialized_donor_comparison = mode.initialized();
        let donor_ready_bound = std::rc::Rc::new(std::cell::Cell::new(false));
        let donor_observation =
            std::rc::Rc::new(std::cell::RefCell::new(None::<InitializedDonorEntry>));
        let configured_donor_flags = std::cell::Cell::new(None::<u32>);
        let observed_membership = std::cell::Cell::new(None::<bool>);
        let observed_mode = (|| -> io::Result<ConsoleProbe> {
            let attached = matches!(case, "cli-codex" | "all-inherit" | "redirect-file");
            if !attached && !matches!(case, "desktop" | "absent-inherit") {
                return Err(console_unknown("owner_case_invalid"));
            }
            // All attachment and standard-handle changes are confined to this
            // separately spawned inert owner process, never the host/test runner.
            // Detachment was already best-effort: a service-launched process can
            // already have no console. Record its actual result without making it
            // a new precondition or hiding a subsequent allocation failure.
            // SAFETY: this separately spawned owner detaches only its own console.
            let detached = unsafe { FreeConsole() };
            let detach_code = if detached == 0 {
                io::Error::last_os_error().raw_os_error()
            } else {
                None
            };
            console_at(
                "owner_free_console_record",
                private_record(root, "console-detach-result", &(detached != 0, detach_code)),
            )?;
            // SAFETY: allocation is confined to this separately spawned owner.
            if attached && unsafe { AllocConsole() } == 0 {
                return console_at("owner_alloc_console", Err(io::Error::last_os_error()));
            }
            struct PrivateConsole;
            impl Drop for PrivateConsole {
                fn drop(&mut self) {
                    unsafe {
                        FreeConsole();
                    }
                }
            }
            let _console = PrivateConsole;
            let _console_handles = if attached {
                let input = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("CONIN$");
                let input = console_at("owner_open_conin", input)?;
                let output = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("CONOUT$");
                let output = console_at("owner_open_conout", output)?;
                let error = console_at("owner_clone_conout", output.try_clone())?;
                for (id, handle) in [
                    (STD_INPUT_HANDLE, input.as_raw_handle()),
                    (STD_OUTPUT_HANDLE, output.as_raw_handle()),
                    (STD_ERROR_HANDLE, error.as_raw_handle()),
                ] {
                    // SAFETY: these private console objects remain owned until child cleanup.
                    if unsafe { SetStdHandle(id, handle as isize) } == 0 {
                        return console_at(
                            match id {
                                STD_INPUT_HANDLE => "owner_set_stdin",
                                STD_OUTPUT_HANDLE => "owner_set_stdout",
                                _ => "owner_set_stderr",
                            },
                            Err(io::Error::last_os_error()),
                        );
                    }
                }
                require_private_console_mode(STD_INPUT_HANDLE, "owner_get_stdin_mode")?;
                require_private_console_mode(STD_OUTPUT_HANDLE, "owner_get_stdout_mode")?;
                require_private_console_mode(STD_ERROR_HANDLE, "owner_get_stderr_mode")?;
                inject_private_console_line(&input, nonce)?;
                Some((input, output, error))
            } else {
                if console_mode(STD_INPUT_HANDLE) || console_mode(STD_OUTPUT_HANDLE) {
                    return Err(console_unknown("owner_unexpected_console"));
                }
                None
            };
            let redirected = if case == "redirect-file" {
                let file = console_at(
                    "owner_create_redirect_file",
                    std::fs::File::create(root.join("redirected-stdout")),
                )?;
                // SAFETY: this private file remains owned throughout the inherited spawn.
                if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, file.as_raw_handle() as isize) } == 0 {
                    return console_at(
                        "owner_set_redirect_stdout",
                        Err(io::Error::last_os_error()),
                    );
                }
                Some(file)
            } else {
                None
            };
            let _redirected = redirected;
            if case == "absent-inherit" {
                for (id, handle) in [
                    (STD_INPUT_HANDLE, 0),
                    (STD_OUTPUT_HANDLE, -1),
                    (STD_ERROR_HANDLE, 0),
                ] {
                    // SAFETY: intentionally absent slots in this detached private actor only.
                    if unsafe { SetStdHandle(id, handle) } == 0 {
                        return console_at(
                            match id {
                                STD_INPUT_HANDLE => "owner_set_absent_stdin",
                                STD_OUTPUT_HANDLE => "owner_set_absent_stdout",
                                _ => "owner_set_absent_stderr",
                            },
                            Err(io::Error::last_os_error()),
                        );
                    }
                }
            }
            let mut probe = ConsoleProbe {
                case: probe_case.into(),
                mode_context: ConsoleModeContext::new(mode),
                initialized_donor_comparison,
                initialized_donor_ready_bound: false,
                owner_pid: std::process::id(),
                // SAFETY: borrowed pseudo handle for this isolated owner process.
                owner_birth: console_at("owner_birth", birth(unsafe { GetCurrentProcess() }))?,
                accepted: false,
                vendor_exit_success: false,
                actual_child_matched: false,
                original_child_reaped: false,
                readers_joined: false,
                reader_count: 0,
                input_console: false,
                output_console: false,
                error_console: false,
                input_mode_error: None,
                output_mode_error: None,
                error_mode_error: None,
                input_ok: false,
                input_eof: false,
                stdout_ok: false,
                stderr_ok: false,
                stdout_nonce_observed: false,
                stderr_nonce_observed: false,
                input_error: None,
                stdout_error: None,
                stderr_error: None,
                spawn_stage: "not_started".into(),
                spawn_error_code: None,
                vendor_observation: None,
            };
            let retirement_control = if LIVE_HELPER_RELEASE_BARRIER {
                Some(HelperRetirementControl::new()?)
            } else {
                None
            };
            let mut cmd = console_at(
                "owner_build_vendor_command",
                command(root, nonce, address, "console-probe-vendor"),
            )?;
            if let Some(control) = retirement_control.as_ref() {
                cmd.env("CSQ_PRIVATE_CREATOR_RETIREMENT_READY", &control.ready_name)
                    .env(
                        "CSQ_PRIVATE_CREATOR_RETIREMENT_RELEASE",
                        &control.release_name,
                    );
            }
            cmd.env("CSQ_PRIVATE_WINDOWS_STDIO_CASE", case)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            match case {
                "cli-codex" => {
                    cmd.stdout(Stdio::piped());
                }
                "desktop" => {
                    cmd.stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                }
                _ => {}
            }
            let mut donor_probe = if initialized_donor_comparison {
                let plan = console_at(
                    "owner_build_initialized_donor_command",
                    command(root, nonce, address, "initialized-donor-probe"),
                )?;
                let root = root.to_path_buf();
                let nonce = nonce.to_owned();
                let bound = donor_ready_bound.clone();
                let donor_observation = donor_observation.clone();
                let observe_ready = move |pid, handle| {
                    let bytes = console_at(
                        "initialized_donor_entry_read",
                        bounded_console_record(&root.join("initialized-donor-entry")),
                    )?;
                    let entry: InitializedDonorEntry = console_at(
                        "initialized_donor_entry_parse",
                        serde_json::from_slice(&bytes).map_err(io::Error::from),
                    )?;
                    if entry.role != "initialized-donor-probe"
                        || entry.nonce != nonce
                        || entry.pid != pid
                        || entry.birth != birth(handle)?
                    {
                        return Err(console_unknown("initialized_donor_entry_identity"));
                    }
                    donor_observation.replace(Some(entry));
                    bound.set(true);
                    Ok(())
                };
                let selected = if let Some(variant) = mode.attribute_variant() {
                    crate::login_child_custody::windows_process::initialized_donor_attribute_probe_for_test(plan, observe_ready, variant)
                } else if mode == ConsoleLaunchMode::InitializedKeepalive {
                    crate::login_child_custody::windows_process::initialized_donor_probe_with_lifetime_for_test(plan, observe_ready, true)
                } else {
                    crate::login_child_custody::windows_process::initialized_donor_probe_for_test(
                        plan,
                        observe_ready,
                    )
                };
                let selected = console_at("owner_select_initialized_donor_probe", selected)?;
                configured_donor_flags.set(Some(selected.configured_donor_flags_for_test()));
                if selected.variant_for_test() != mode.attribute_variant() {
                    return Err(console_unknown("donor_selected_attribute_variant_mismatch"));
                }
                Some(selected)
            } else {
                None
            };
            let launched = match mode {
                ConsoleLaunchMode::Standard => cmd
                    .into_std_command()
                    .and_then(|mut command| command.spawn())
                    .map(|child| (Child::from(child), None)),
                ConsoleLaunchMode::PlainRaw => {
                    crate::login_child_custody::windows_process::spawn_plain_for_test(&cmd)
                        .map(|child| (child, None))
                }
                ConsoleLaunchMode::Automatic => {
                    crate::login_child_custody::windows_process::spawn_automatic_stdio_for_test(
                        &cmd,
                    )
                    .map(|child| (child, None))
                }
                _ => group::spawn(&mut cmd, group::StdinPolicy::Caller)
                    .map(|(child, group)| (child, Some(group))),
            };
            if let Some(donor) = donor_probe.as_ref() {
                observed_membership.set(donor.vendor_in_requested_job_for_test());
            }
            if !mode.keeps_donor_alive() {
                drop(donor_probe.take());
            }
            // Early-termination probes restore the baseline selector here. Keepalive
            // retains its original donor guard through actual vendor I/O and exit.
            probe.initialized_donor_ready_bound = donor_ready_bound.get();
            probe.mode_context.donor_ready = donor_ready_bound.get();
            probe.mode_context.creator_configured_donor_flags = configured_donor_flags.get();
            probe.mode_context.observed_vendor_job_member = observed_membership.get();
            probe.mode_context.donor_observation = donor_observation.borrow().clone();
            probe.spawn_stage = match mode {
                ConsoleLaunchMode::Standard => "standard_command_spawn",
                ConsoleLaunchMode::PlainRaw => "plain_create_process_spawn",
                _ => crate::login_child_custody::windows_process::last_spawn_stage_for_test(),
            }
            .into();
            let (child, group) = match launched {
                Ok(owned) => owned,
                Err(error) => {
                    probe.spawn_error_code = error.raw_os_error();
                    if initialized_donor_comparison
                        && (probe.spawn_stage.starts_with("probe_")
                            || probe.spawn_stage == "create_suspended_donor"
                            || probe.spawn_stage == "attribute_probe_create_suspended_donor"
                            || probe.spawn_stage == "attribute_probe_query_exact_job_membership")
                    {
                        return console_at("owner_initialized_donor_bootstrap", Err(error));
                    }
                    return Ok(probe);
                }
            };
            probe.mode_context.component_job = group.is_some()
                && if mode.attribute_variant().is_some() {
                    observed_membership.get() == Some(true)
                } else {
                    mode.explicit_job_attribute()
                };
            let mut owned = ConsoleChild {
                child: Some(child),
                group,
                donor_probe,
                mode_context: probe.mode_context.clone(),
                readers: Vec::new(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_piped: false,
                stderr_piped: false,
                stdout_eof_joined: false,
                stderr_eof_joined: false,
                stdout_truncated: false,
                stderr_truncated: false,
                reader_failed: false,
                finalized: false,
            };
            let observed = (|| -> io::Result<ConsoleProbe> {
                if let Some(artifact) = gui_artifact.as_ref() {
                    private_record(root, "gui-creator-route", &GuiCreatorRoute {
                        nonce: nonce.to_owned(), owner_pid: probe.owner_pid,
                        owner_birth: probe.owner_birth, artifact_sha256: artifact.sha256.clone(),
                        force_creator: gui_force,
                        actual_helper_creations: crate::login_child_custody::windows_process::creator_helper_launch_count_for_test()
                            .checked_sub(helper_count_before).ok_or_else(|| console_unknown("gui_creator_counter_regressed"))?,
                    })?;
                }
                probe.accepted = true;
                if mode.attribute_variant().is_some()
                    && (observed_membership.get().is_none()
                        || (mode.explicit_job_attribute()
                            && observed_membership.get() != Some(true)))
                {
                    return Err(console_unknown(
                        "attribute_probe_vendor_membership_unconfirmed",
                    ));
                }
                if mode.attribute_variant().is_some()
                    && owned
                        .mode_context
                        .donor_observation
                        .as_ref()
                        .is_none_or(|donor| {
                            donor.creator_supplied_flags
                                != owned.mode_context.creator_configured_donor_flags
                                || donor.creator_supplied_flags.is_none()
                        })
                {
                    return Err(console_unknown("attribute_probe_creator_flags_unconfirmed"));
                }
                let child = owned
                    .child
                    .as_mut()
                    .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?;
                let pid = child.id();
                let created = console_at("vendor_birth_observation", birth(child.as_raw_handle()))?;
                for (stderr, pipe) in [(false, child.stdout.take()), (true, child.stderr.take())] {
                    if let Some(mut pipe) = pipe {
                        if stderr {
                            owned.stderr_piped = true;
                        } else {
                            owned.stdout_piped = true;
                        }
                        let reader = std::thread::Builder::new()
                            .name("private-console-matrix-output".into())
                            .spawn(move || {
                                use std::io::Read;
                                let mut bytes = Vec::new();
                                (&mut pipe)
                                    .take(CONSOLE_CAPTURE_BYTES as u64 + 1)
                                    .read_to_end(&mut bytes)?;
                                let remainder = std::io::copy(&mut pipe, &mut std::io::sink())?;
                                let truncated =
                                    bytes.len() > CONSOLE_CAPTURE_BYTES || remainder != 0;
                                bytes.truncate(CONSOLE_CAPTURE_BYTES);
                                Ok((bytes, truncated))
                            });
                        let reader = console_at("vendor_reader_start", reader)?;
                        owned.readers.push((stderr, reader));
                        probe.reader_count += 1;
                    }
                }
                let deadline = Instant::now() + SETUP;
                let status = loop {
                    if let Some(status) = owned
                        .child
                        .as_mut()
                        .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?
                        .try_wait()
                        .map_err(|error| console_failure("vendor_try_wait", error))?
                    {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        return Err(console_unknown("vendor_exit_timeout"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                console_at("vendor_join_readers", owned.join_readers(deadline))?;
                probe.readers_joined = true;
                if let Some(group) = owned.group.as_ref() {
                    group.mark_readers_joined();
                }
                probe.vendor_exit_success = status.success();
                if mode.keeps_donor_alive() {
                    let donor = owned
                        .donor_probe
                        .as_mut()
                        .ok_or_else(|| console_unknown("keepalive_donor_guard_missing"))?;
                    let alive = console_at(
                        "keepalive_donor_alive_after_vendor_exit",
                        donor.donor_alive_for_test(),
                    )?;
                    owned.mode_context.donor_alive_after_vendor_exit = Some(alive);
                    if !alive {
                        return Err(console_unknown(
                            "keepalive_donor_died_before_vendor_exit_observed",
                        ));
                    }
                    console_at(
                        "keepalive_donor_finalize_before_census",
                        donor.finalize_for_test(),
                    )?;
                    owned.mode_context.donor_reaped_before_census = Some(true);
                    owned.donor_probe.take();
                }
                let reaped = if owned.mode_context.component_job {
                    let group = owned
                        .group
                        .as_ref()
                        .ok_or_else(|| console_unknown("vendor_job_handle_missing"))?;
                    let creator_identity = owned
                        .child
                        .as_ref()
                        .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?
                        .creator_identity_for_test()?;
                    if let Some(control) = retirement_control.as_ref() {
                        // The authenticated helper reaches this event only after
                        // observing its original vendor exit. Keep it held through
                        // the real production reap loop and its existing deadline.
                        if unsafe { WaitForSingleObject(control.ready.as_raw_handle(), 5_000) } != 0
                        {
                            return Err(console_unknown("helper_release_barrier_unobserved"));
                        }
                    }
                    let deadline = Instant::now() + SETUP;
                    let reaped = loop {
                        match group.try_reap(
                            owned
                                .child
                                .as_mut()
                                .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?,
                            true,
                        ) {
                            Ok(Some(status)) => break status,
                            Ok(None) => {}
                            Err(error) if group::is_census_refusal(&error) => {}
                            Err(error) => return console_at("vendor_original_reap", Err(error)),
                        }
                        if Instant::now() >= deadline {
                            if let Some(control) = retirement_control.as_ref() {
                                let child = owned
                                    .child
                                    .as_mut()
                                    .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?;
                                let helper =
                                    child.creator_identity_for_test()?.ok_or_else(|| {
                                        console_unknown("held_helper_identity_missing")
                                    })?;
                                let helper_process = query_bound_process(&Identity {
                                    role: "helper".into(),
                                    nonce: nonce.into(),
                                    pid: helper.0,
                                    birth: helper.1,
                                })?;
                                let job = child.fixture_job_for_test(group)?;
                                require_job_membership(
                                    helper_process.as_raw_handle(),
                                    job,
                                    true,
                                    "WINDOWS_FIXTURE_HELD_HELPER_JOB_MISMATCH",
                                )?;
                                if creator_identity != Some(helper)
                                    || child.try_wait()?.is_none()
                                    || child.creator_exit_for_test()? != Some(false)
                                    || !owned.readers.is_empty()
                                    || owned.reader_failed
                                    || exact_job_pids(job)? != [helper.0]
                                    || group.0.job.active_count()? != 1
                                    || !matches!(group.try_reap(child, true), Ok(None))
                                {
                                    return Err(console_unknown("held_helper_control_unqualified"));
                                }
                                eprintln!("WINDOWS_FIXTURE_HELD_HELPER_WITNESS: pid={}; birth={}; original_vendor_exited=true; helper_alive=true; actual_job_active=1; readers_joined=true; production_gate=pending; original_reap_deadline_elapsed=true",helper.0,helper.1);
                                // Release only after the real timeout gate and all
                                // original-object witnesses, before owned cleanup.
                                control.release()?;
                                return Err(console_causal("vendor_original_reap_timeout"));
                            }
                            return Err(console_unknown("vendor_original_reap_timeout"));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    // The production gate retires the actual creator first.
                    // Independently verify zero only after its positive reap;
                    // never terminate the helper to manufacture this result.
                    let active =
                        console_at("vendor_job_census_after_reap", group.0.job.active_count())?;
                    owned.mode_context.job_empty = Some(active == 0);
                    if active != 0 {
                        return Err(console_unknown("vendor_job_nonempty_after_reap"));
                    }
                    let creator_retired = !owned
                        .child
                        .as_ref()
                        .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?
                        .creator_lease_present_for_test();
                    if !creator_retired {
                        if owned
                            .child
                            .as_ref()
                            .ok_or_else(|| console_unknown("vendor_owned_child_missing"))?
                            .creator_exit_for_test()?
                            != Some(true)
                        {
                            return Err(console_unknown("creator_retention_control_unqualified"));
                        }
                        return Err(console_causal("creator_lease_retained_after_positive_gate"));
                    }
                    eprintln!("WINDOWS_CONSOLE_PRODUCTION_RETIREMENT: actual_vendor_reaped=true; original_helper_pid_birth={creator_identity:?}; helper_lease_retired={creator_retired}; actual_job_active={active}; readers_joined=true");
                    Ok(Some(reaped))
                } else {
                    // No positive requested-Job membership is available for
                    // this vendor. Reap its original handle directly, even if
                    // a separate donor Group exists; no empty-Job claim.
                    owned
                        .child
                        .as_mut()
                        .ok_or_else(|| console_unknown("control_child_missing"))?
                        .try_wait()
                };
                if console_at("vendor_original_reap", reaped)?.is_none() {
                    return Err(console_unknown("vendor_original_reap_pending"));
                }
                owned.finalized = true;
                probe.original_child_reaped = true;
                probe.mode_context = owned.mode_context.clone();
                if console_at(
                    "vendor_error_record_presence",
                    root.join("console-vendor-error").try_exists(),
                )? {
                    let bytes = console_at(
                        "vendor_error_record_read",
                        bounded_console_record(&root.join("console-vendor-error")),
                    )?;
                    let failure: ConsoleOwnerFailure = console_at(
                        "vendor_error_record_parse",
                        serde_json::from_slice(&bytes).map_err(io::Error::from),
                    )?;
                    if failure.nonce != nonce
                        || failure.pid != pid
                        || failure.birth.is_some_and(|value| value != created)
                    {
                        return Err(console_unknown("vendor_error_record_identity"));
                    }
                    return Err(io::Error::other(failure.failure));
                }
                let receipt_bytes = console_at(
                    "vendor_receipt_read",
                    bounded_console_record(&root.join("console-vendor-receipt")),
                )?;
                let receipt: ConsoleReceipt = console_at(
                    "vendor_receipt_parse",
                    serde_json::from_slice(&receipt_bytes).map_err(io::Error::from),
                )?;
                if receipt.pid != pid || receipt.birth != created || receipt.nonce != nonce {
                    return Err(console_unknown("vendor_receipt_identity"));
                }
                probe.actual_child_matched = true;
                probe.input_console = receipt.input_console;
                probe.output_console = receipt.output_console;
                probe.error_console = receipt.error_console;
                probe.input_mode_error = receipt.input_mode_error;
                probe.output_mode_error = receipt.output_mode_error;
                probe.error_mode_error = receipt.error_mode_error;
                probe.input_ok = receipt.input_ok;
                probe.input_eof = receipt.input_eof;
                probe.stdout_ok = receipt.stdout_ok;
                probe.stderr_ok = receipt.stderr_ok;
                probe.input_error = receipt.input_error;
                probe.stdout_error = receipt.stdout_error;
                probe.stderr_error = receipt.stderr_error;
                let output = format!("PRIVATE_MATRIX_STDOUT_{nonce}");
                let error = format!("PRIVATE_MATRIX_STDERR_{nonce}");
                probe.stdout_nonce_observed = match case {
                    "cli-codex" | "desktop" => {
                        String::from_utf8_lossy(&owned.stdout).contains(&output)
                    }
                    "redirect-file" => console_at(
                        "vendor_redirect_output_read",
                        std::fs::read(root.join("redirected-stdout")),
                    )
                    .map(|bytes| String::from_utf8_lossy(&bytes).contains(&output))?,
                    _ => receipt.stdout_ok,
                };
                probe.stderr_nonce_observed = if case == "desktop" {
                    String::from_utf8_lossy(&owned.stderr).contains(&error)
                } else {
                    receipt.stderr_ok
                };
                Ok(probe)
            })();
            // Observe through the actual retained child before cleanup, independent
            // of the receipt whose absence may be the first failure being reported.
            let diagnostic = owned.vendor_observation(root, nonce, case);
            let observed = observed
                .map(|mut probe| {
                    probe.vendor_observation = Some(diagnostic.clone());
                    probe
                })
                .map_err(|error| {
                    console_with_vendor(error, diagnostic.clone(), owned.mode_context.clone())
                });
            if let Some(control) = retirement_control.as_ref() {
                control.release()?;
            }
            let cleanup = console_at("vendor_owned_cleanup", owned.cleanup()).map_err(|error| {
                console_with_vendor(error, diagnostic, owned.mode_context.clone())
            });
            match observed {
                Err(first) => {
                    let confirmed = cleanup.is_ok();
                    if let Err(error) = cleanup {
                        eprintln!("{UNKNOWN}: secondary cleanup: {error}");
                    }
                    if confirmed {
                        if let Some(failure) = first
                            .get_ref()
                            .and_then(|e| e.downcast_ref::<ConsoleFailure>())
                        {
                            let mut failure = failure.clone();
                            failure.cleanup_confirmed = true;
                            return Err(io::Error::new(first.kind(), failure));
                        }
                    }
                    Err(first)
                }
                Ok(probe) => {
                    cleanup?;
                    Ok(probe)
                }
            }
        })();
        observed_mode.map_err(|error| {
            let mut context = ConsoleModeContext::new(mode);
            context.donor_ready = donor_ready_bound.get();
            context.creator_configured_donor_flags = configured_donor_flags.get();
            context.observed_vendor_job_member = observed_membership.get();
            context.donor_observation = donor_observation.borrow().clone();
            console_with_mode(error, context)
        })
    }
    struct Peer {
        identity: Identity,
        process: OwnedHandle,
        stream: BufReader<TcpStream>,
    }
    impl Peer {
        fn gone(&self) -> io::Result<bool> {
            exited(self.process.as_raw_handle())
        }
        fn challenge(&mut self) -> io::Result<bool> {
            self.stream.get_mut().write_all(b"P")?;
            let current: Identity = serde_json::from_str(&line(&mut self.stream)?)?;
            if current != self.identity || birth(self.process.as_raw_handle())? != current.birth {
                return Err(io::Error::other(UNKNOWN));
            }
            self.gone().map(|gone| !gone)
        }
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ArmedTopology {
        kind: String,
        vendor: Identity,
        descendant: Identity,
        helper: Option<Identity>,
        owner_outside: bool,
        member_pids: Vec<u32>,
        active: u32,
    }
    // Every numeric PID here is only a read-only lookup bound to an already
    // authenticated original handle/birth. No fixture signals a numeric PID.
    fn query_bound_process(identity: &Identity) -> io::Result<OwnedHandle> {
        // SAFETY: query/synchronize only; original actor is retained at its barrier.
        let handle = unsafe { OpenProcess(0x0010_0000 | 0x1000, 0, identity.pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcess transfers one owned query-only handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        if birth(handle.as_raw_handle())? != identity.birth || exited(handle.as_raw_handle())? {
            return Err(io::Error::other(UNKNOWN));
        }
        Ok(handle)
    }
    const ORACLE_MODE: &str = "CSQ_PRIVATE_JOB_ORACLE_MODE";
    const SKIP_DESCENDANT: &str = "CSQ_PRIVATE_JOB_ORACLE_SKIP_DESCENDANT";
    const OWNED_CLEANUP: &str = "WINDOWS_FIXTURE_OWNED_CLEANUP_CONFIRMED";
    const VENDOR_JOB_MISMATCH: &str = "WINDOWS_FIXTURE_VENDOR_REQUESTED_JOB_MISMATCH";
    const DESCENDANT_JOB_MISMATCH: &str = "WINDOWS_FIXTURE_DESCENDANT_REQUESTED_JOB_MISMATCH";
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ArmingOracle {
        Requested,
        ForeignVendorJob,
        OutsideDescendant,
    }
    impl ArmingOracle {
        fn tag(self) -> &'static str {
            match self {
                Self::Requested => "requested",
                Self::ForeignVendorJob => "foreign-vendor",
                Self::OutsideDescendant => "outside-descendant",
            }
        }
        fn current() -> io::Result<Self> {
            match std::env::var(ORACLE_MODE).as_deref() {
                Ok("requested") | Err(std::env::VarError::NotPresent) => Ok(Self::Requested),
                Ok("foreign-vendor") => Ok(Self::ForeignVendorJob),
                Ok("outside-descendant") => Ok(Self::OutsideDescendant),
                _ => Err(io::Error::other(UNKNOWN)),
            }
        }
    }
    #[derive(Debug)]
    struct OracleRejection(String);
    impl std::fmt::Display for OracleRejection {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for OracleRejection {}
    fn oracle_rejection(marker: &str) -> io::Error {
        io::Error::other(OracleRejection(marker.into()))
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct ArmingReply {
        topology: Option<ArmedTopology>,
        helper: Option<Identity>,
        rejection: Option<String>,
    }
    fn independent_foreign_job() -> io::Result<OwnedHandle> {
        // SAFETY: independent unnamed noninheritable empty Job. No process is
        // assigned to it; the original cleanup Job remains the sole supervisor.
        let handle = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transferred this one empty Job reference.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut c_void) })
    }
    fn require_job_membership(
        process: *mut c_void,
        job: isize,
        expected: bool,
        marker: &str,
    ) -> io::Result<()> {
        let mut member = 0;
        // SAFETY: retained original/query-bound process and exact retained Job.
        if unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                process as isize,
                job,
                &mut member,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if (member != 0) != expected {
            return Err(oracle_rejection(marker));
        }
        Ok(())
    }
    fn exact_job_pids(job: isize) -> io::Result<Vec<u32>> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicProcessIdList, QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
        };
        const MAX_MEMBERS: usize = 8;
        let mut storage = [0usize; 10];
        let capacity = 8 + MAX_MEMBERS * std::mem::size_of::<usize>();
        let mut returned = 0;
        let pointer = storage
            .as_mut_ptr()
            .cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        // SAFETY: usize-aligned storage covers the DWORD header and eight
        // ULONG_PTR entries on both supported pointer widths. Truncation refuses.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                pointer.cast(),
                capacity as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful query initialized this fixed header.
        let header = unsafe { &*pointer };
        let count = header.NumberOfProcessIdsInList as usize;
        if count > MAX_MEMBERS
            || header.NumberOfAssignedProcesses != header.NumberOfProcessIdsInList
            || returned < 8
            || returned as usize > capacity
        {
            return Err(io::Error::other(UNKNOWN));
        }
        // SAFETY: the validated count lies within the initialized flexible array.
        let entries = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*pointer).ProcessIdList).cast::<usize>(),
                count,
            )
        };
        let mut pids = entries
            .iter()
            .map(|pid| u32::try_from(*pid).map_err(|_| io::Error::other(UNKNOWN)))
            .collect::<io::Result<Vec<_>>>()?;
        pids.sort_unstable();
        if pids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(io::Error::other(UNKNOWN));
        }
        Ok(pids)
    }
    fn arm_exact_topology(
        child: &Child,
        group: &group::GroupControl,
        descendant: Identity,
        nonce: &str,
        requested_job: Option<isize>,
    ) -> io::Result<ArmedTopology> {
        if descendant.role != "descendant" || descendant.nonce != nonce {
            return Err(io::Error::other(UNKNOWN));
        }
        let cleanup_job = child.fixture_job_for_test(group)?;
        let job = requested_job.unwrap_or(cleanup_job);
        let vendor = Identity {
            role: "vendor".into(),
            nonce: nonce.into(),
            pid: child.id(),
            birth: birth(child.as_raw_handle())?,
        };
        if exited(child.as_raw_handle())? {
            return Err(io::Error::other(UNKNOWN));
        }
        require_job_membership(
            child.as_raw_handle(),
            cleanup_job,
            true,
            "WINDOWS_FIXTURE_VENDOR_CLEANUP_JOB_MISMATCH",
        )?;
        require_job_membership(child.as_raw_handle(), job, true, VENDOR_JOB_MISMATCH)?;
        let descendant_handle = query_bound_process(&descendant)?;
        require_job_membership(
            descendant_handle.as_raw_handle(),
            job,
            true,
            DESCENDANT_JOB_MISMATCH,
        )?;
        let helper = child
            .creator_identity_for_test()?
            .map(|(pid, birth)| Identity {
                role: "helper".into(),
                nonce: nonce.into(),
                pid,
                birth,
            });
        if let Some(helper) = helper.as_ref() {
            let process = query_bound_process(helper)?;
            require_job_membership(
                process.as_raw_handle(),
                job,
                true,
                "WINDOWS_FIXTURE_HELPER_REQUESTED_JOB_MISMATCH",
            )?;
        }
        // SAFETY: current owner pseudo handle is borrowed, never closed.
        require_job_membership(
            unsafe { GetCurrentProcess() },
            job,
            false,
            "WINDOWS_FIXTURE_OWNER_MUST_REMAIN_OUTSIDE_JOB",
        )?;
        let mut expected = vec![vendor.pid, descendant.pid];
        if let Some(helper) = helper.as_ref() {
            expected.push(helper.pid);
        }
        expected.sort_unstable();
        let member_pids = exact_job_pids(job)?;
        let active = group.0.job.active_count()?;
        if member_pids != expected || active as usize != expected.len() {
            return Err(oracle_rejection(
                "WINDOWS_FIXTURE_EXACT_JOB_PID_SET_MISMATCH",
            ));
        }
        Ok(ArmedTopology {
            kind: "ARMED".into(),
            vendor,
            descendant,
            helper,
            owner_outside: true,
            member_pids,
            active,
        })
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct SafetyArmed {
        owner: Identity,
        descendant: Identity,
        helper: Option<Identity>,
        member_pids: Vec<u32>,
        active: u32,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SafetyHelperObserved {
        owner: Identity,
        helper: Identity,
        descendant: Identity,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct SafetyCleaned {
        owner: Identity,
        descendant: Identity,
        active: u32,
        helper_retired: bool,
        status: Option<i32>,
    }
    struct SafetyOwner {
        child: StdChild,
        armed: Option<SafetyArmed>,
        helper: Option<OwnedHandle>,
    }
    impl SafetyOwner {
        fn start(root: &Path, nonce: &str, address: SocketAddr) -> io::Result<Self> {
            // This ordinary actor owns its diagnostic output before libtest
            // starts. Helper existence is established by a private typed record
            // and original kernel handles, never by test-harness stdout banners.
            let mut command = standard_command(root, nonce, address, "safety-owner")?;
            command
                .stdin(StdStdio::null())
                .stdout(std::fs::File::create(root.join("safety-owner-stdout"))?)
                .stderr(std::fs::File::create(root.join("safety-owner-stderr"))?);
            Ok(Self {
                child: command.spawn()?,
                armed: None,
                helper: None,
            })
        }
        fn bind(&mut self, root: &Path, descendant: &Identity) -> io::Result<()> {
            let until = Instant::now() + SETUP;
            while !root.join("safety-armed").is_file() {
                if self.child.try_wait()?.is_some() || Instant::now() >= until {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let armed: SafetyArmed =
                serde_json::from_slice(&bounded_console_record(&root.join("safety-armed"))?)?;
            if armed.owner.role != "safety-owner"
                || armed.owner.nonce != descendant.nonce
                || armed.owner.pid != self.child.id()
                || armed.owner.birth != birth(self.child.as_raw_handle())?
                || self.child.try_wait()?.is_some()
                || armed.descendant != *descendant
            {
                return Err(io::Error::other(UNKNOWN));
            }
            let mut expected = vec![descendant.pid];
            let helper = armed
                .helper
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            if helper.role != "helper" || helper.nonce != descendant.nonce {
                return Err(io::Error::other(UNKNOWN));
            }
            self.helper = Some(query_bound_process(helper)?);
            expected.push(helper.pid);
            expected.sort_unstable();
            if expected != armed.member_pids
                || armed.active as usize != expected.len()
                || expected.contains(&armed.owner.pid)
            {
                return Err(io::Error::other(UNKNOWN));
            }
            self.armed = Some(armed);
            Ok(())
        }
        fn finish(&mut self, root: &Path, original_descendant: *mut c_void) -> io::Result<()> {
            let until = Instant::now() + SETUP + SETUP;
            let status = loop {
                if let Some(status) = self.child.try_wait()? {
                    break status;
                }
                if Instant::now() >= until {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if !status.success() {
                return Err(io::Error::other(UNKNOWN));
            }
            let armed = self
                .armed
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let cleaned: SafetyCleaned =
                serde_json::from_slice(&bounded_console_record(&root.join("safety-cleaned"))?)?;
            if cleaned.owner != armed.owner
                || cleaned.descendant != armed.descendant
                || cleaned.active != 0
                || !cleaned.helper_retired
                || cleaned.status.is_none()
            {
                return Err(io::Error::other(UNKNOWN));
            }
            let helper_identity = armed
                .helper
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let helper = self
                .helper
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let observed: SafetyHelperObserved = serde_json::from_slice(&bounded_console_record(
                &root.join("safety-helper-observed"),
            )?)?;
            if observed.owner != armed.owner
                || observed.helper != *helper_identity
                || observed.descendant != armed.descendant
                || self.child.id() != armed.owner.pid
                || birth(self.child.as_raw_handle())? != armed.owner.birth
                || birth(helper.as_raw_handle())? != helper_identity.birth
                || !exited(helper.as_raw_handle())?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            if birth(original_descendant)? != armed.descendant.birth
                || !exited(original_descendant)?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            let mut actual_code = 0;
            // SAFETY: outer retained this authenticated original descendant
            // object before release; exit was independently observed above.
            if unsafe { GetExitCodeProcess(original_descendant, &mut actual_code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if cleaned.status.map(|code| code as u32) != Some(actual_code) {
                return Err(io::Error::other(UNKNOWN));
            }
            // The helper's test bootstrap intentionally uses Null stdout. The
            // private observation binds all three full identities; the retained
            // original handles and completed production cleanup independently
            // prove actual exit and empty Job without replaying captured text.
            eprintln!("WINDOWS_FIXTURE_PRIVATE_HELPER_OBSERVED: original_safety_owner_pid={}; original_helper_pid={}; original_helper_birth={}; original_safety_owner_reaped=true; private_identity_record_verified=true; actual_safety_job_active=0; helper_retired=true; stdout_used_as_oracle=false",armed.owner.pid,helper_identity.pid,helper_identity.birth);
            Ok(())
        }
    }
    impl Drop for SafetyOwner {
        fn drop(&mut self) {
            // Cleanup authority is only this retained original fixture Child.
            // Its owned Job closes with the actor; uncertain cleanup stays UNKNOWN.
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                let _kill = self.child.kill();
                let until = Instant::now() + SETUP;
                while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !matches!(self.child.try_wait(), Ok(Some(_))) {
                    eprintln!("{UNKNOWN}: original safety owner cleanup unconfirmed");
                }
            }
        }
    }
    fn safety_owner(root: &Path, nonce: &str, address: SocketAddr) -> io::Result<()> {
        // SAFETY: borrow only this private actor's own process pseudo handle.
        let owner = Identity {
            role: "safety-owner".into(),
            nonce: nonce.into(),
            pid: std::process::id(),
            birth: birth(unsafe { GetCurrentProcess() })?,
        };
        let mut command = command(root, nonce, address, "descendant")?;
        command.stdout(Stdio::null()).stderr(Stdio::null());
        // This separate nonbreakaway Job is an oracle safety fixture, not a
        // production escape or a modification of the requested cleanup Job.
        let (mut child, group) = group::spawn(&mut command, group::StdinPolicy::Null)?;
        let descendant = Identity {
            role: "descendant".into(),
            nonce: nonce.into(),
            pid: child.id(),
            birth: birth(child.as_raw_handle())?,
        };
        let observed = (|| -> io::Result<()> {
            let job = child.fixture_job_for_test(&group)?;
            require_job_membership(
                child.as_raw_handle(),
                job,
                true,
                "WINDOWS_FIXTURE_OUTSIDER_SAFETY_JOB_MISMATCH",
            )?;
            // SAFETY: read-only membership of this actor's borrowed pseudo handle.
            require_job_membership(
                unsafe { GetCurrentProcess() },
                job,
                false,
                "WINDOWS_FIXTURE_SAFETY_OWNER_MUST_REMAIN_OUTSIDE_JOB",
            )?;
            let helper = child
                .creator_identity_for_test()?
                .map(|(pid, birth)| Identity {
                    role: "helper".into(),
                    nonce: nonce.into(),
                    pid,
                    birth,
                })
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let handle = query_bound_process(&helper)?;
            require_job_membership(
                handle.as_raw_handle(),
                job,
                true,
                "WINDOWS_FIXTURE_SAFETY_HELPER_JOB_MISMATCH",
            )?;
            let mut expected = vec![child.id(), helper.pid];
            expected.sort_unstable();
            let member_pids = exact_job_pids(job)?;
            let active = group.0.job.active_count()?;
            if member_pids != expected
                || active as usize != expected.len()
                || exited(child.as_raw_handle())?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            private_record(
                root,
                "safety-helper-observed",
                &SafetyHelperObserved {
                    owner: owner.clone(),
                    helper: helper.clone(),
                    descendant: descendant.clone(),
                },
            )?;
            private_record(
                root,
                "safety-armed",
                &SafetyArmed {
                    owner: owner.clone(),
                    descendant: descendant.clone(),
                    helper: Some(helper),
                    member_pids,
                    active,
                },
            )?;
            let until = Instant::now() + SAFETY;
            while !root.join("release").exists() {
                if Instant::now() >= until {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        })();
        // No captured vendor streams exist: both are explicit Null. The actor
        // retains original Child+Job until the real production gate completes.
        let cleanup = (|| -> io::Result<()> {
            group.signal(group::GroupSignal::Kill)?;
            group.mark_readers_joined();
            let until = Instant::now() + SETUP;
            let status = loop {
                match group.try_reap(&mut child, true) {
                    Ok(Some(status)) => break status,
                    Ok(None) => {}
                    Err(error) if group::is_census_refusal(&error) => {}
                    Err(error) => return Err(error),
                }
                if Instant::now() >= until {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let active = group.0.job.active_count()?;
            let helper_retired = !child.creator_lease_present_for_test();
            if active != 0 || !helper_retired {
                return Err(io::Error::other(UNKNOWN));
            }
            private_record(
                root,
                "safety-cleaned",
                &SafetyCleaned {
                    owner,
                    descendant,
                    active,
                    helper_retired,
                    status: status.code(),
                },
            )
        })();
        if cleanup.is_err() {
            eprintln!("{UNKNOWN}: safety actor original Job cleanup unconfirmed");
        }
        observed?;
        cleanup
    }
    struct Fixture {
        sandbox: Option<tempfile::TempDir>,
        root: PathBuf,
        owner: Option<StdChild>,
        peers: Vec<Peer>,
        helper: Option<(Identity, OwnedHandle)>,
        safety: Option<SafetyOwner>,
        eof: Arc<AtomicBool>,
        reader: Option<JoinHandle<io::Result<()>>>,
        cleaned: bool,
    }
    impl Fixture {
        fn start() -> io::Result<Self> {
            Self::start_with_oracle(ArmingOracle::Requested)
        }
        fn start_with_oracle(oracle: ArmingOracle) -> io::Result<Self> {
            let sandbox = tempfile::tempdir()?;
            let root = sandbox.path().to_path_buf();
            for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
                std::fs::create_dir(root.join(name))?;
            }
            let nonce = format!(
                "FAKETEST_{}",
                root.file_name()
                    .ok_or_else(|| io::Error::other(UNKNOWN))?
                    .to_string_lossy()
            );
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let mut fixture = Self {
                sandbox: Some(sandbox),
                root,
                owner: None,
                peers: Vec::new(),
                helper: None,
                safety: None,
                eof: Arc::new(AtomicBool::new(false)),
                reader: None,
                cleaned: false,
            };
            let mut cmd = standard_command(&fixture.root, &nonce, address, "owner")?;
            cmd.env(ORACLE_MODE, oracle.tag());
            cmd.stdout(StdStdio::piped())
                .stderr(std::fs::File::create(fixture.root.join("stderr"))?);
            fixture.owner = Some(cmd.spawn()?);
            let mut stdout = fixture
                .owner
                .as_mut()
                .and_then(|child| child.stdout.take())
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let eof = Arc::clone(&fixture.eof);
            fixture.reader = Some(
                std::thread::Builder::new()
                    .name("windows-job-private-stdout".into())
                    .spawn(move || {
                        io::copy(&mut stdout, &mut io::sink())?;
                        eof.store(true, Ordering::Release);
                        Ok(())
                    })?,
            );
            if oracle == ArmingOracle::OutsideDescendant {
                fixture.safety = Some(SafetyOwner::start(&fixture.root, &nonce, address)?);
            }
            let deadline = Instant::now() + SETUP;
            while fixture.peers.len() < 3 && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Accepted sockets inherit nonblocking mode on Windows.
                        // The authenticated handshake uses bounded blocking reads.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
                        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
                        let mut stream = BufReader::new(stream);
                        let identity: Identity = serde_json::from_str(&line(&mut stream)?)?;
                        if identity.nonce != nonce
                            || !["owner", "vendor", "descendant"].contains(&identity.role.as_str())
                            || fixture
                                .peers
                                .iter()
                                .any(|peer| peer.identity.role == identity.role)
                        {
                            return Err(io::Error::other(UNKNOWN));
                        }
                        // SAFETY: read-only handle opened while the authenticated
                        // original actor is still held at the startup barrier.
                        let raw = unsafe { OpenProcess(0x0010_0000 | 0x1000, 0, identity.pid) };
                        if raw.is_null() {
                            return Err(io::Error::last_os_error());
                        }
                        // SAFETY: successful OpenProcess transfers one owned,
                        // non-inheritable kernel handle to this guard.
                        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
                        if birth(process.as_raw_handle())? != identity.birth
                            || exited(process.as_raw_handle())?
                        {
                            return Err(io::Error::other(UNKNOWN));
                        }
                        fixture.peers.push(Peer {
                            identity,
                            process,
                            stream,
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => return Err(error),
                }
            }
            let owner_pid = fixture
                .owner
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?
                .id();
            if fixture.peer("owner")?.identity.pid != owner_pid {
                return Err(io::Error::other(UNKNOWN));
            }
            if oracle == ArmingOracle::OutsideDescendant {
                let identity = fixture.peer("descendant")?.identity.clone();
                fixture
                    .safety
                    .as_mut()
                    .ok_or_else(|| io::Error::other(UNKNOWN))?
                    .bind(&fixture.root, &identity)?;
            }
            let vendor_pid = fixture.peer("vendor")?.identity.pid;
            if line(&mut fixture.peer("owner")?.stream)? != format!("SPAWN {vendor_pid}\n") {
                return Err(io::Error::other(UNKNOWN));
            }
            let descendant = fixture.peer("descendant")?.identity.clone();
            if !fixture.peer("descendant")?.challenge()? {
                return Err(io::Error::other(UNKNOWN));
            }
            let mut arm = vec![b'A'];
            arm.extend(serde_json::to_vec(&descendant)?);
            arm.push(b'\n');
            fixture.peer("owner")?.stream.get_mut().write_all(&arm)?;
            let reply: ArmingReply =
                serde_json::from_str(&line(&mut fixture.peer("owner")?.stream)?)?;
            if let Some(helper) = reply.helper.as_ref() {
                if helper.role != "helper" || helper.nonce != nonce {
                    return Err(io::Error::other(UNKNOWN));
                }
                fixture.helper = Some((helper.clone(), query_bound_process(helper)?));
            }
            if let Some(marker) = reply.rejection {
                // The actor remains live at its authenticated barrier. Confirm
                // BOTH original Jobs/process trees before exposing causal RED.
                fixture.cleanup()?;
                return Err(oracle_rejection(&marker));
            }
            let topology = reply.topology.ok_or_else(|| io::Error::other(UNKNOWN))?;
            let vendor = fixture.peer("vendor")?.identity.clone();
            let mut expected = vec![vendor.pid, descendant.pid];
            if let Some(helper) = topology.helper.as_ref() {
                if helper.role != "helper" || helper.nonce != nonce {
                    return Err(io::Error::other(UNKNOWN));
                }
                let process = query_bound_process(helper)?;
                fixture.helper = Some((helper.clone(), process));
                expected.push(helper.pid);
            }
            expected.sort_unstable();
            if topology.kind != "ARMED"
                || topology.vendor != vendor
                || topology.descendant != descendant
                || !topology.owner_outside
                || topology.member_pids != expected
                || topology.active as usize != expected.len()
                || expected.contains(&owner_pid)
                || !fixture.peer("vendor")?.challenge()?
                || !fixture.peer("descendant")?.challenge()?
                || fixture.eof.load(Ordering::Acquire)
            {
                return Err(io::Error::other(UNKNOWN));
            }
            eprintln!("WINDOWS_JOB_TOPOLOGY: original_owner_pid={owner_pid}; original_handles_bound=true; exact_membership={topology:?}; eof=false");
            Ok(fixture)
        }
        fn peer(&mut self, role: &str) -> io::Result<&mut Peer> {
            self.peers
                .iter_mut()
                .find(|peer| peer.identity.role == role)
                .ok_or_else(|| io::Error::other(UNKNOWN))
        }
        fn kill_owner(&mut self) -> io::Result<()> {
            let owner = self
                .owner
                .as_mut()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            owner.kill()?;
            let deadline = Instant::now() + SETUP;
            while Instant::now() < deadline {
                if owner.try_wait()?.is_some() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(io::Error::other(UNKNOWN))
        }
        fn helper_gone(&self) -> io::Result<bool> {
            match self.helper.as_ref() {
                Some((identity, process)) => {
                    if birth(process.as_raw_handle())? != identity.birth {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    exited(process.as_raw_handle())
                }
                None => Ok(true),
            }
        }
        fn cleanup(&mut self) -> io::Result<()> {
            if self.cleaned {
                return Ok(());
            }
            std::fs::write(self.root.join("release"), b"release")?;
            for peer in &mut self.peers {
                let _ = peer.stream.get_mut().write_all(b"E");
            }
            let owner_live = match self.owner.as_mut() {
                Some(owner) => owner.try_wait()?.is_none(),
                None => false,
            };
            if owner_live {
                self.kill_owner()?;
            }
            if self.safety.is_some() {
                let descendant = self
                    .peers
                    .iter()
                    .find(|peer| peer.identity.role == "descendant")
                    .ok_or_else(|| io::Error::other(UNKNOWN))?
                    .process
                    .as_raw_handle();
                self.safety
                    .as_mut()
                    .ok_or_else(|| io::Error::other(UNKNOWN))?
                    .finish(&self.root, descendant)?;
            }
            self.safety.take();
            let deadline = Instant::now() + SETUP;
            loop {
                let reaped = match self.owner.as_mut() {
                    Some(owner) => owner.try_wait()?.is_some(),
                    None => true,
                };
                let gone = self
                    .peers
                    .iter()
                    .try_fold(true, |all, peer| Ok::<_, io::Error>(peer.gone()? && all))?;
                let joined = self
                    .reader
                    .as_ref()
                    .is_none_or(|reader| reader.is_finished());
                if reaped
                    && gone
                    && self.helper_gone()?
                    && joined
                    && self.eof.load(Ordering::Acquire)
                {
                    if let Some(reader) = self.reader.take() {
                        reader.join().map_err(|_| io::Error::other(UNKNOWN))??;
                    }
                    self.cleaned = true;
                    eprintln!("WINDOWS_JOB_PRIVATE_CLEANUP: original_owner_reaped=true; original_actor_and_optional_helper_handles_signaled=true; captured_eof_joined=true; numeric_signals=false");
                    eprintln!("{OWNED_CLEANUP}");
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                if let Some(sandbox) = self.sandbox.take() {
                    let _ = sandbox.keep();
                }
                eprintln!("{UNKNOWN}: private cleanup incomplete: {error}");
            }
        }
    }
    fn actor() -> io::Result<()> {
        let root = PathBuf::from(std::env::var_os(ROOT).ok_or_else(|| io::Error::other(UNKNOWN))?);
        let role = std::env::var(ROLE).map_err(|_| io::Error::other(UNKNOWN))?;
        let nonce = std::env::var(NONCE).map_err(|_| io::Error::other(UNKNOWN))?;
        let address: SocketAddr = std::env::var(ADDRESS)
            .map_err(|_| io::Error::other(UNKNOWN))?
            .parse()
            .map_err(|_| io::Error::other(UNKNOWN))?;
        if !address.ip().is_loopback()
            || std::env::var_os("HOME").as_deref() != Some(root.join("home").as_os_str())
            || std::env::var_os("CSQ_BASE_DIR").as_deref() != Some(root.join("base").as_os_str())
            || std::env::var("CSQ_SECRET_BACKEND").as_deref() != Ok("in-memory")
        {
            return Err(io::Error::other(UNKNOWN));
        }
        if role == "safety-owner" {
            return safety_owner(&root, &nonce, address);
        }
        if role == "initialized-donor-probe" {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
            // This entry exists only in the ignored isolated test actor. Its
            // sandbox bindings and Rust actor initialization precede readiness.
            let expected_nonce = format!(
                "FAKETEST_CONSOLE_{}",
                root.file_name()
                    .ok_or_else(|| console_unknown("initialized_donor_root_name"))?
                    .to_string_lossy()
            );
            if nonce != expected_nonce || std::env::current_dir()? != root {
                return Err(console_unknown("initialized_donor_actor_bindings"));
            }
            let actor_entry = Identity {
                role: role.clone(),
                nonce: nonce.clone(),
                pid: std::process::id(),
                // SAFETY: own borrowed process pseudo handle, no numeric lookup.
                birth: birth(unsafe { GetCurrentProcess() })?,
            };
            console_at(
                "initialized_donor_actor_entry_record",
                private_record(&root, "initialized-donor-actor-entry", &actor_entry),
            )?;
            use windows_sys::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
            let mut process_ids = [0u32; 4];
            // SAFETY: these queries affect no console state and inspect only
            // this isolated donor's current console. The array has four slots.
            // A zero window is recorded as zero, never interpreted alone as
            // proof of detachment; process-list result/error is independent.
            let window_handle = unsafe { GetConsoleWindow() } as usize as u64;
            // SAFETY: non-null four-DWORD output buffer; query is local to this donor.
            let process_count_returned = unsafe {
                GetConsoleProcessList(process_ids.as_mut_ptr(), process_ids.len() as u32)
            };
            let process_list_error = if process_count_returned == 0 {
                io::Error::last_os_error().raw_os_error()
            } else {
                None
            };
            let process_list_complete =
                process_count_returned != 0 && process_count_returned as usize <= process_ids.len();
            // A too-small buffer contains NO valid identifiers per Win32. Never
            // label that case as an empty console or a complete truncated list.
            let observed_ids = if process_list_complete {
                process_ids[..process_count_returned as usize].to_vec()
            } else {
                Vec::new()
            };
            let creator_supplied_flags = match std::env::var_os(
                crate::login_child_custody::windows_process::DONOR_CONFIGURED_FLAGS,
            ) {
                Some(value) => Some(
                    value
                        .into_string()
                        .map_err(|_| console_unknown("donor_flags_non_unicode"))?
                        .parse::<u32>()
                        .map_err(|_| console_unknown("donor_flags_parse"))?,
                ),
                None => None,
            };
            let identity = InitializedDonorEntry {
                role,
                nonce,
                pid: std::process::id(),
                birth: actor_entry.birth,
                creator_supplied_flags,
                console: DonorConsoleObservation {
                    window_handle,
                    process_list_capacity: process_ids.len(),
                    process_count_returned,
                    process_list_complete,
                    process_ids: observed_ids,
                    process_list_error,
                },
            };
            private_record(&root, "initialized-donor-entry", &identity)?;
            let name =
                std::env::var_os(crate::login_child_custody::windows_process::DONOR_READY_EVENT)
                    .ok_or_else(|| console_unknown("initialized_donor_event_missing"))?;
            let name: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
            // SAFETY: creator supplied a private CSPRNG event name in this
            // donor-only cleared environment; request only signaling authority.
            let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
            if event == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful OpenEventW returned this owned handle.
            let event = unsafe { OwnedHandle::from_raw_handle(event as *mut c_void) };
            // SAFETY: owned event with EVENT_MODIFY_STATE, no inherited handles.
            if unsafe { SetEvent(event.as_raw_handle() as isize) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // No stdio use or vendor work after readiness. Early probes stop
            // this donor before vendor resume; keepalive probes retain it through
            // vendor I/O, then confirm its death before any Job-empty gate.
            std::thread::sleep(SAFETY);
            return Err(console_unknown("initialized_donor_watchdog_expired"));
        }
        if role == "console-probe-vendor" || role.starts_with("console-owner-") {
            // This is evidence of Rust actor entry, not evidence about a loader
            // when absent. No console API or receipt operation precedes it.
            let cwd = std::env::current_dir();
            // SAFETY: own borrowed process pseudo handle only.
            let created = birth(unsafe { GetCurrentProcess() });
            let entry = ConsoleActorEntry {
                nonce: nonce.clone(),
                role: role.clone(),
                pid: std::process::id(),
                birth: created.as_ref().ok().copied(),
                birth_error: created.as_ref().err().and_then(io::Error::raw_os_error),
                cwd_matches_bound_root: cwd.as_ref().is_ok_and(|path| path == &root),
                cwd_error: cwd.as_ref().err().and_then(io::Error::raw_os_error),
                isolation_bindings_validated: true,
            };
            let (name, error_name) = if role == "console-probe-vendor" {
                ("console-vendor-entry", "console-vendor-error")
            } else {
                ("console-owner-entry", "console-owner-error")
            };
            if let Err(error) = console_at(
                "private_actor_entry_record",
                private_record(&root, name, &entry),
            ) {
                record_console_failure(&root, error_name, &nonce, &error);
                return Err(error);
            }
            if role == "console-probe-vendor" {
                let types = VendorFileTypes {
                    nonce: nonce.clone(),
                    pid: entry.pid,
                    birth: entry
                        .birth
                        .ok_or_else(|| console_unknown("vendor_file_types_birth_unobserved"))?,
                    types: ConsoleFileTypes {
                        stdin: observed_file_type(STD_INPUT_HANDLE),
                        stdout: observed_file_type(STD_OUTPUT_HANDLE),
                        stderr: observed_file_type(STD_ERROR_HANDLE),
                    },
                };
                if let Err(error) = console_at(
                    "vendor_file_types_record",
                    private_record(&root, "console-vendor-file-types", &types),
                ) {
                    record_console_failure(&root, "console-vendor-error", &nonce, &error);
                    return Err(error);
                }
            }
        }
        if let Some(case) = role.strip_prefix("console-owner-") {
            let observed = console_owner(&root, &nonce, case, address).and_then(|probe| {
                console_at(
                    "owner_result_record",
                    private_record(&root, "console-probe-result", &probe),
                )
            });
            if let Err(error) = observed {
                record_console_failure(&root, "console-owner-error", &nonce, &error);
                return Err(error);
            }
            // Private console handles were released by console_owner. Avoid
            // libtest trying to print through those now-closed standard handles.
            std::process::exit(0);
        }
        if role == "console-probe-vendor" {
            let observed = (|| -> io::Result<()> {
                use windows_sys::Win32::System::Console::GetNumberOfConsoleInputEvents;
                let case = std::env::var("CSQ_PRIVATE_WINDOWS_STDIO_CASE")
                    .map_err(|_| io::Error::other(UNKNOWN))?;
                let console_expected =
                    matches!(case.as_str(), "cli-codex" | "all-inherit" | "redirect-file");
                if !console_expected && !matches!(case.as_str(), "desktop" | "absent-inherit") {
                    return Err(io::Error::other(UNKNOWN));
                }
                let (input_console, input_mode_error) = console_mode_observation(STD_INPUT_HANDLE);
                let (output_console, output_mode_error) =
                    console_mode_observation(STD_OUTPUT_HANDLE);
                let (error_console, error_mode_error) = console_mode_observation(STD_ERROR_HANDLE);
                let mut input = String::new();
                let input_result = if console_expected != input_console {
                    // A measured mode mismatch is a functional refusal, not permission
                    // to block on an uninjected or unexpected input source.
                    None
                } else if input_console {
                    let mut queued = 0;
                    // SAFETY: this actual vendor's own inherited input handle only.
                    if unsafe {
                        GetNumberOfConsoleInputEvents(GetStdHandle(STD_INPUT_HANDLE), &mut queued)
                    } == 0
                    {
                        Some(Err(io::Error::last_os_error()))
                    } else if queued == 0 {
                        None
                    } else {
                        Some(std::io::stdin().read_line(&mut input))
                    }
                } else {
                    Some(std::io::stdin().read_line(&mut input))
                };
                let input_eof = matches!(&input_result, Some(Ok(0)));
                let input_ok = match &input_result {
                    Some(Ok(count)) if console_expected => {
                        *count > 0 && input.trim_end_matches(['\r', '\n']) == nonce
                    }
                    Some(Ok(0)) if !console_expected => true,
                    _ => false,
                };
                let stdout_result = writeln!(std::io::stdout(), "PRIVATE_MATRIX_STDOUT_{nonce}")
                    .and_then(|()| std::io::stdout().flush());
                let stderr_result = writeln!(std::io::stderr(), "PRIVATE_MATRIX_STDERR_{nonce}")
                    .and_then(|()| std::io::stderr().flush());
                let receipt = ConsoleReceipt {
                    nonce: nonce.clone(),
                    pid: std::process::id(),
                    // SAFETY: this inert vendor's retained current-process object.
                    birth: console_at(
                        "vendor_receipt_birth",
                        birth(unsafe { GetCurrentProcess() }),
                    )?,
                    input_console,
                    output_console,
                    error_console,
                    input_mode_error,
                    output_mode_error,
                    error_mode_error,
                    input_ok,
                    input_eof,
                    stdout_ok: stdout_result.is_ok(),
                    stderr_ok: stderr_result.is_ok(),
                    input_error: input_result
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .and_then(io::Error::raw_os_error),
                    stdout_error: stdout_result
                        .as_ref()
                        .err()
                        .and_then(io::Error::raw_os_error),
                    stderr_error: stderr_result
                        .as_ref()
                        .err()
                        .and_then(io::Error::raw_os_error),
                };
                let success = receipt.input_ok && receipt.stdout_ok && receipt.stderr_ok;
                console_at(
                    "vendor_receipt_write",
                    private_record(&root, "console-vendor-receipt", &receipt),
                )?;
                std::process::exit(if success { 0 } else { 23 });
            })();
            if let Err(error) = &observed {
                record_console_failure(&root, "console-vendor-error", &nonce, error);
            }
            return observed;
        }
        if role == "checkpoint-inert-vendor" {
            let identity = Identity {
                role: role.clone(),
                nonce,
                pid: std::process::id(),
                // SAFETY: this process's borrowed pseudo handle, never closed.
                birth: birth(unsafe { GetCurrentProcess() })?,
            };
            let mut pending = tempfile::NamedTempFile::new_in(&root)?;
            pending.write_all(&serde_json::to_vec(&identity)?)?;
            pending.flush()?;
            pending
                .persist(root.join("checkpoint-running"))
                .map_err(|error| error.error)?;
            let deadline = Instant::now() + SAFETY;
            while Instant::now() < deadline && !root.join("release").exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(io::Error::other(UNKNOWN));
        }
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_millis(20)))?;
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        // SAFETY: pseudo handle names only this live process; it is not closed.
        let own_birth = birth(unsafe { GetCurrentProcess() })?;
        let identity = Identity {
            role: role.clone(),
            nonce: nonce.clone(),
            pid: std::process::id(),
            birth: own_birth,
        };
        write_json(&mut stream, &identity)?;
        let mut child: Option<Child> = None;
        let mut production_group = None;
        match role.as_str() {
            "donor-created-owner" | "vendor-created-owner" | "after-resume-owner" => {
                use crate::login_child_custody::windows_process::{self, SpawnCheckpoint};
                let (target, label) = match role.as_str() {
                    "donor-created-owner" => (SpawnCheckpoint::DonorCreated, "donor-created"),
                    "vendor-created-owner" => (SpawnCheckpoint::VendorCreated, "vendor-created"),
                    _ => (SpawnCheckpoint::AfterResume, "after-resume"),
                };
                let mut barrier = stream.try_clone()?;
                let barrier_nonce = nonce.clone();
                windows_process::set_checkpoint_hook_for_test(move |stage, pid, handle| {
                    if stage != target {
                        return Ok(());
                    }
                    let original = Identity {
                        role: label.into(),
                        nonce: barrier_nonce.clone(),
                        pid,
                        birth: birth(handle)?,
                    };
                    write_json(&mut barrier, &original)?;
                    let deadline = Instant::now() + SAFETY;
                    while Instant::now() < deadline {
                        let mut byte = [0];
                        match std::io::Read::read(&mut barrier, &mut byte) {
                            Ok(_) if byte[0] == b'P' => {
                                if birth(handle)? != original.birth || exited(handle)? {
                                    return Err(io::Error::other(UNKNOWN));
                                }
                                write_json(&mut barrier, &original)?;
                            }
                            Ok(_) => return Err(io::Error::other(UNKNOWN)),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::Interrupted
                                ) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(io::Error::other(UNKNOWN))
                });
                let mut cmd = command(&root, &nonce, address, "checkpoint-inert-vendor")?;
                let _ = group::spawn(&mut cmd, group::StdinPolicy::Null)?;
                return Err(io::Error::other(UNKNOWN));
            }
            "pre-resume-owner" => {
                let mut barrier = stream.try_clone()?;
                let barrier_nonce = nonce.clone();
                group::win::set_post_create_before_resume_hook_for_test(move |pid, handle| {
                    // This identity comes from the actual original suspended
                    // child handle, before resume, not a PID lookup.
                    let original = Identity {
                        role: "suspended-vendor".into(),
                        nonce: barrier_nonce,
                        pid,
                        birth: birth(handle)?,
                    };
                    write_json(&mut barrier, &original)?;
                    let deadline = Instant::now() + SAFETY;
                    while Instant::now() < deadline {
                        let mut byte = [0];
                        match std::io::Read::read(&mut barrier, &mut byte) {
                            Ok(0) => return Err(io::Error::other(UNKNOWN)),
                            Ok(_) if byte[0] == b'P' => {
                                if birth(handle)? != original.birth || exited(handle)? {
                                    return Err(io::Error::other(UNKNOWN));
                                }
                                write_json(&mut barrier, &original)?;
                            }
                            Ok(_) => return Err(io::Error::other(UNKNOWN)),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::Interrupted
                                ) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    // Watchdog expiration is a setup failure. Returning Err
                    // takes spawn's existing suspended-child cleanup branch.
                    Err(io::Error::other(UNKNOWN))
                });
                let mut cmd = command(&root, &nonce, address, "descendant")?;
                let _ = group::spawn(&mut cmd, group::StdinPolicy::Null)?;
                return Err(io::Error::other(UNKNOWN));
            }
            "owner" => {
                let mut cmd = command(&root, &nonce, address, "vendor")?;
                if ArmingOracle::current()? == ArmingOracle::OutsideDescendant {
                    cmd.env(SKIP_DESCENDANT, "1");
                }
                let (spawned, group) = group::spawn(&mut cmd, group::StdinPolicy::Null)?;
                writeln!(stream, "SPAWN {}", spawned.id())?;
                child = Some(spawned);
                production_group = Some(group);
            }
            "vendor" if std::env::var(SKIP_DESCENDANT).as_deref() == Ok("1") => {}
            "vendor" => {
                let standard: StdChild =
                    standard_command(&root, &nonce, address, "descendant")?.spawn()?;
                // CustodyChild preserves the actual standard child and typed
                // asynchronous streams; this is not a raw-handle reconstruction.
                child = Some(standard.into());
            }
            "descendant" => {}
            _ => return Err(io::Error::other(UNKNOWN)),
        }
        let deadline = Instant::now() + SAFETY;
        let mut armed = false;
        let mut armed_descendant: Option<Identity> = None;
        while Instant::now() < deadline && !root.join("release").exists() {
            let mut byte = [0];
            match std::io::Read::read(&mut stream, &mut byte) {
                Ok(0) => break,
                Ok(_) => match byte[0] {
                    b'P' => write_json(&mut stream, &identity)?,
                    b'A' if role == "owner" => {
                        let group = production_group
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?;
                        let descendant: Identity =
                            serde_json::from_str(&line(&mut BufReader::new(stream.try_clone()?))?)?;
                        let child = child.as_ref().ok_or_else(|| io::Error::other(UNKNOWN))?;
                        let helper =
                            child
                                .creator_identity_for_test()?
                                .map(|(pid, birth)| Identity {
                                    role: "helper".into(),
                                    nonce: nonce.clone(),
                                    pid,
                                    birth,
                                });
                        let foreign = if ArmingOracle::current()? == ArmingOracle::ForeignVendorJob
                        {
                            Some(independent_foreign_job()?)
                        } else {
                            None
                        };
                        let result = arm_exact_topology(
                            child,
                            group,
                            descendant.clone(),
                            &nonce,
                            foreign.as_ref().map(|job| job.as_raw_handle() as isize),
                        );
                        let reply = match result {
                            Ok(topology) => {
                                armed_descendant = Some(descendant);
                                armed = true;
                                ArmingReply {
                                    topology: Some(topology),
                                    helper,
                                    rejection: None,
                                }
                            }
                            Err(error) => {
                                let Some(rejection) = error
                                    .get_ref()
                                    .and_then(|e| e.downcast_ref::<OracleRejection>())
                                else {
                                    return Err(error);
                                };
                                ArmingReply {
                                    topology: None,
                                    helper,
                                    rejection: Some(rejection.0.clone()),
                                }
                            }
                        };
                        write_json(&mut stream, &reply)?;
                    }
                    b'X' if role == "vendor" => std::process::exit(0),
                    b'F' if role == "owner" && armed => {
                        let group = production_group
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?;
                        write_json(&mut stream, &group.0.job.limit_flags_for_test()?)?;
                    }
                    b'R' if role == "owner" && armed => {
                        let group = production_group
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?;
                        // This owner captures no vendor reader: stdout is
                        // inherited. Outer stdout is a separate observer pipe.
                        group.mark_readers_joined();
                        let until = Instant::now() + SETUP;
                        let descendant = armed_descendant
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?;
                        let descendant_handle = query_bound_process(descendant)?;
                        let (active, member_pids, result) = loop {
                            let child = child.as_mut().ok_or_else(|| io::Error::other(UNKNOWN))?;
                            let result = group.try_reap(child, true);
                            if result
                                .as_ref()
                                .is_err_and(|error| !group::is_census_refusal(error))
                            {
                                return Err(result
                                    .err()
                                    .ok_or_else(|| io::Error::other(UNKNOWN))?);
                            }
                            let retired = !child.creator_lease_present_for_test();
                            let active = group.0.job.active_count()?;
                            let job = child.fixture_job_for_test(group)?;
                            let member_pids = exact_job_pids(job)?;
                            if retired
                                && exited(child.as_raw_handle())?
                                && active == 1
                                && member_pids == [descendant.pid]
                            {
                                require_job_membership(
                                    descendant_handle.as_raw_handle(),
                                    job,
                                    true,
                                    DESCENDANT_JOB_MISMATCH,
                                )?;
                                break (active, member_pids, result);
                            }
                            if Instant::now() >= until {
                                return Err(io::Error::other(UNKNOWN));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        };
                        eprintln!("WINDOWS_JOB_RETIREMENT: helper_retired_by_production_gate=true; actual_vendor_exited=true; exact_descendant_pid={}; actual_job_active={active}; actual_job_pids={member_pids:?}", descendant.pid);
                        let observation = ReapObservation {
                            active,
                            reaped: matches!(result, Ok(Some(_))),
                            refused: result.is_err(),
                            reason: result
                                .err()
                                .map(|error| error.to_string())
                                .unwrap_or_default(),
                            finalized: *group
                                .0
                                .lease
                                .lock()
                                .map_err(|_| io::Error::other(UNKNOWN))?
                                == WaitLease::Finalized,
                            helper_retired: true,
                            member_pids,
                        };
                        write_json(&mut stream, &observation)?;
                    }
                    b'C' if role == "owner" && armed => {
                        let group = production_group
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?;
                        // This fixture captures no vendor streams: stdout is
                        // inherited. Its outer observer pipe is independent.
                        group.mark_readers_joined();
                        let child = child.as_mut().ok_or_else(|| io::Error::other(UNKNOWN))?;
                        let until = Instant::now() + SETUP;
                        let mut status = None;
                        loop {
                            match group.try_reap(child, true) {
                                Ok(Some(actual)) => {
                                    status = Some(actual);
                                    break;
                                }
                                Ok(None) => {}
                                Err(error) if group::is_census_refusal(&error) => {}
                                Err(error) => return Err(error),
                            }
                            if Instant::now() >= until {
                                // A measured live survivor is a product failure,
                                // not an unobservable socket/setup timeout. Keep
                                // the exact Job for the parent's private cleanup.
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        write_json(
                            &mut stream,
                            &CompletionObservation {
                                vendor_code: status.and_then(|status| status.code()),
                                active: group.0.job.active_count()?,
                                finalized: *group
                                    .0
                                    .lease
                                    .lock()
                                    .map_err(|_| io::Error::other(UNKNOWN))?
                                    == WaitLease::Finalized,
                                helper_retired: !child.creator_lease_present_for_test(),
                                readers_joined: group.readers_joined(),
                                operator_kill_intent: group.kill_requested_at().is_some(),
                            },
                        )?;
                    }
                    b'E' => break,
                    _ => return Err(io::Error::other(UNKNOWN)),
                },
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if let Some(mut child) = child {
            let until = Instant::now() + SETUP;
            while Instant::now() < until {
                if child.try_wait()?.is_some() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(io::Error::other(UNKNOWN));
        }
        Ok(())
    }
    #[test]
    #[ignore = "private inert Windows Job actor, entered only by isolated self-exec"]
    fn private_windows_job_actor() {
        let _environment = csq_core::platform::test_env::lock();
        if let Err(error) = actor() {
            eprintln!("{UNKNOWN}: actor: {error}");
            std::process::exit(2);
        }
    }

    // This fixture needs only the owner to connect: its original vendor is
    // suspended inside the production post-create hook and cannot announce
    // readiness. Keep it separate from Fixture's three-running-actor protocol.
    struct PreResumeFixture {
        sandbox: Option<tempfile::TempDir>,
        owner: StdChild,
        stream: Option<BufReader<TcpStream>>,
        original: Option<(Identity, OwnedHandle)>,
        eof: Arc<AtomicBool>,
        reader: Option<JoinHandle<io::Result<()>>>,
        cleaned: bool,
    }
    impl PreResumeFixture {
        fn start() -> io::Result<Self> {
            Self::start_role("pre-resume-owner", "suspended-vendor")
        }
        fn start_role(owner_role: &str, target_role: &str) -> io::Result<Self> {
            let sandbox = tempfile::tempdir()?;
            let root = sandbox.path();
            for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
                std::fs::create_dir(root.join(name))?;
            }
            let nonce = format!(
                "FAKETEST_PRE_RESUME_{}",
                root.file_name()
                    .ok_or_else(|| io::Error::other(UNKNOWN))?
                    .to_string_lossy()
            );
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let mut cmd = standard_command(root, &nonce, listener.local_addr()?, owner_role)?;
            cmd.stdout(StdStdio::piped())
                .stderr(std::fs::File::create(root.join("stderr"))?);
            let mut owner = cmd.spawn()?;
            let mut stdout = owner
                .stdout
                .take()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let eof = Arc::new(AtomicBool::new(false));
            let reader_eof = Arc::clone(&eof);
            let mut fixture = Self {
                sandbox: Some(sandbox),
                owner,
                stream: None,
                original: None,
                eof,
                reader: None,
                cleaned: false,
            };
            fixture.reader = Some(
                std::thread::Builder::new()
                    .name("windows-pre-resume-private-stdout".into())
                    .spawn(move || {
                        io::copy(&mut stdout, &mut io::sink())?;
                        reader_eof.store(true, Ordering::Release);
                        Ok(())
                    })?,
            );
            let deadline = Instant::now() + SETUP;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(UNKNOWN));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(SETUP))?;
            stream.set_write_timeout(Some(Duration::from_millis(100)))?;
            fixture.stream = Some(BufReader::new(stream));
            let stream = fixture
                .stream
                .as_mut()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let owner_identity: Identity = serde_json::from_str(&line(stream)?)?;
            if owner_identity.role != owner_role
                || owner_identity.nonce != nonce
                || owner_identity.pid != fixture.owner.id()
                || owner_identity.birth != birth(fixture.owner.as_raw_handle())?
                || exited(fixture.owner.as_raw_handle())?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            let original: Identity = serde_json::from_str(&line(stream)?)?;
            if original.role != target_role || original.nonce != nonce {
                return Err(io::Error::other(UNKNOWN));
            }
            // SAFETY: the authenticated original owner retains its original
            // Child at the post-create/pre-resume barrier. Bind this one
            // opened object to the creation time obtained from that Child.
            let raw = unsafe { OpenProcess(0x0010_0000 | 0x1000 | 0x0001, 0, original.pid) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful OpenProcess transfers one non-inherited handle.
            let process = unsafe { OwnedHandle::from_raw_handle(raw) };
            if birth(process.as_raw_handle())? != original.birth || exited(process.as_raw_handle())?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            fixture.original = Some((original, process));
            fixture.challenge_barrier()?;
            if target_role == "after-resume" {
                let deadline = Instant::now() + SETUP;
                loop {
                    let path = fixture
                        .sandbox
                        .as_ref()
                        .ok_or_else(|| io::Error::other(UNKNOWN))?
                        .path()
                        .join("checkpoint-running");
                    if let Ok(bytes) = std::fs::read(path) {
                        let running: Identity = serde_json::from_slice(&bytes)?;
                        let original = &fixture
                            .original
                            .as_ref()
                            .ok_or_else(|| io::Error::other(UNKNOWN))?
                            .0;
                        if running.role != "checkpoint-inert-vendor"
                            || running.pid != original.pid
                            || running.birth != original.birth
                            || running.nonce != original.nonce
                        {
                            return Err(io::Error::other(UNKNOWN));
                        }
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(fixture)
        }
        fn challenge_barrier(&mut self) -> io::Result<()> {
            let (original, process) = self
                .original
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            let stream = self
                .stream
                .as_mut()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            stream.get_mut().write_all(b"P")?;
            let current: Identity = serde_json::from_str(&line(stream)?)?;
            if current != *original
                || birth(process.as_raw_handle())? != original.birth
                || exited(process.as_raw_handle())?
                || exited(self.owner.as_raw_handle())?
                || self.eof.load(Ordering::Acquire)
            {
                return Err(io::Error::other(UNKNOWN));
            }
            Ok(())
        }
        fn observe_owner_crash(&mut self) -> io::Result<bool> {
            self.challenge_barrier()?;
            let (_, process) = self
                .original
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            // Positive control: with the original owner alive at the barrier,
            // this exact checkpoint child must remain alive for the full wait.
            // SAFETY: retained, identity-bound fixture process object only.
            if unsafe { WaitForSingleObject(process.as_raw_handle(), 100) } != 258 {
                return Err(io::Error::other(UNKNOWN));
            }
            self.challenge_barrier()?;
            let (original, _) = self
                .original
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            eprintln!(
                "WINDOWS_PRE_RESUME_BARRIER: original_owner_pid={}; original_child_pid={}; original_child_birth={}; original_handles_bound=true; original_child_alive_with_owner=true; captured_eof=false",
                self.owner.id(), original.pid, original.birth
            );
            self.owner.kill()?;
            let deadline = Instant::now() + SETUP;
            while self.owner.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let (original, process) = self
                .original
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?;
            if birth(process.as_raw_handle())? != original.birth {
                return Err(io::Error::other(UNKNOWN));
            }
            // SAFETY: bounded wait on the same retained object, never a PID lookup.
            match unsafe {
                WaitForSingleObject(process.as_raw_handle(), OBSERVE.as_millis() as u32)
            } {
                0 => Ok(true),
                258 => Ok(false),
                _ => Err(io::Error::other(UNKNOWN)),
            }
        }
        fn cleanup(&mut self) -> io::Result<()> {
            if self.cleaned {
                return Ok(());
            }
            // On partial setup, EOF asks the hook to take production's existing
            // failure cleanup. Do not kill an owner whose child is still unbound.
            if let Some(stream) = self.stream.take() {
                // A crashed owner may already have reset the socket. Closing
                // the observer channel must not skip retained-handle cleanup.
                let _ = stream.get_ref().shutdown(std::net::Shutdown::Both);
            }
            if let Some((original, process)) = &self.original {
                if birth(process.as_raw_handle())? != original.birth {
                    return Err(io::Error::other(UNKNOWN));
                }
                if !exited(process.as_raw_handle())? {
                    // SAFETY: independent cleanup authority is limited to the
                    // retained handle bound to this fixture's original Child.
                    if unsafe { TerminateProcess(process.as_raw_handle(), 97) } == 0
                        && !exited(process.as_raw_handle())?
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                // SAFETY: same identity-bound object; cleanup deadline is explicit.
                if unsafe { WaitForSingleObject(process.as_raw_handle(), SETUP.as_millis() as u32) }
                    != 0
                {
                    return Err(io::Error::other(UNKNOWN));
                }
                if self.owner.try_wait()?.is_none() {
                    self.owner.kill()?;
                }
            }
            let original_bound = self.original.is_some();
            let deadline = Instant::now()
                + if original_bound {
                    SETUP
                } else {
                    SAFETY + SETUP
                };
            loop {
                let reaped = self.owner.try_wait()?.is_some();
                let joined = self
                    .reader
                    .as_ref()
                    .is_none_or(|reader| reader.is_finished());
                if reaped && joined && self.eof.load(Ordering::Acquire) {
                    if let Some(reader) = self.reader.take() {
                        reader.join().map_err(|_| io::Error::other(UNKNOWN))??;
                    }
                    self.cleaned = true;
                    eprintln!("WINDOWS_PRE_RESUME_PRIVATE_CLEANUP: original_owner_reaped=true; original_child_handle_bound_and_signaled={original_bound}; captured_eof_joined=true; numeric_signals=false");
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for PreResumeFixture {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                if let Some(sandbox) = self.sandbox.take() {
                    let _ = sandbox.keep();
                }
                eprintln!("{UNKNOWN}: pre-resume private cleanup incomplete: {error}");
            }
        }
    }
    #[test]
    fn production_job_parent_crash_between_original_create_and_resume_terminates_original_child() {
        let _environment = csq_core::platform::test_env::lock();
        let mut fixture = PreResumeFixture::start()
            .unwrap_or_else(|error| panic!("{UNKNOWN}: pre-resume setup: {error}"));
        let observed = fixture.observe_owner_crash();
        eprintln!("WINDOWS_PRE_RESUME_BEFORE_PRIVATE_CLEANUP: original_child_gone={observed:?}");
        let cleanup = fixture.cleanup();
        assert!(
            cleanup.is_ok(),
            "{UNKNOWN}: pre-resume cleanup: {cleanup:?}"
        );
        let gone =
            observed.unwrap_or_else(|error| panic!("{UNKNOWN}: pre-resume observation: {error}"));
        assert!(gone, "WINDOWS_JOB_PRE_RESUME_PARENT_DEATH_SURVIVOR");
    }
    fn checkpoint_owner_death(owner_role: &str, target_role: &str) {
        let mut fixture = PreResumeFixture::start_role(owner_role, target_role)
            .unwrap_or_else(|error| panic!("{UNKNOWN}: checkpoint setup: {error}"));
        let observed = fixture.observe_owner_crash();
        eprintln!("WINDOWS_ATOMIC_CHECKPOINT_BEFORE_PRIVATE_CLEANUP: checkpoint={target_role}; original_gone={observed:?}");
        let cleanup = fixture.cleanup();
        assert!(
            cleanup.is_ok(),
            "{UNKNOWN}: checkpoint cleanup: {cleanup:?}"
        );
        let gone =
            observed.unwrap_or_else(|error| panic!("{UNKNOWN}: checkpoint observation: {error}"));
        assert!(
            gone,
            "WINDOWS_ATOMIC_CHECKPOINT_PARENT_DEATH_SURVIVOR: {target_role}"
        );
    }
    #[test]
    fn atomic_donor_created_owner_death_terminates_original_donor() {
        let _environment = csq_core::platform::test_env::lock();
        checkpoint_owner_death("donor-created-owner", "donor-created");
    }
    #[test]
    fn atomic_vendor_created_owner_death_terminates_original_vendor() {
        let _environment = csq_core::platform::test_env::lock();
        checkpoint_owner_death("vendor-created-owner", "vendor-created");
    }
    #[test]
    fn atomic_after_resume_owner_death_terminates_original_running_vendor() {
        let _environment = csq_core::platform::test_env::lock();
        checkpoint_owner_death("after-resume-owner", "after-resume");
    }
    fn inherited_console_probe(case: &str) {
        inherited_console_probe_mode(case, false);
    }
    fn inherited_console_probe_mode(case: &str, initialized_donor: bool) {
        inherited_console_probe_variant(
            case,
            if initialized_donor {
                ConsoleLaunchMode::InitializedEarly
            } else {
                ConsoleLaunchMode::Baseline
            },
        );
    }
    fn inherited_console_probe_variant(case: &str, mode: ConsoleLaunchMode) {
        inherited_console_probe_variant_with_gui(case, mode, None, false);
    }
    fn inherited_console_probe_variant_with_gui(
        case: &str,
        mode: ConsoleLaunchMode,
        gui_artifact: Option<&GuiCreatorArtifact>,
        force_creator: bool,
    ) {
        let initialized_donor = mode.initialized();
        let (expected_input, expected_output, expected_error, expected_readers) = match case {
            "cli-codex" => (true, false, true, 1),
            "all-inherit" => (true, true, true, 0),
            "redirect-file" => (true, false, true, 0),
            "desktop" => (false, false, false, 2),
            "absent-inherit" => (false, false, false, 0),
            _ => panic!("invalid private stdio matrix case"),
        };
        let sandbox = tempfile::tempdir().expect("private console sandbox");
        let root = sandbox.path();
        for name in ["home", "base", "bin", "tmp", "appdata", "local"] {
            std::fs::create_dir(root.join(name)).expect("private console directories");
        }
        let nonce = format!(
            "FAKETEST_CONSOLE_{}",
            root.file_name()
                .expect("private root name")
                .to_string_lossy()
        );
        let address = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9));
        let probe_case = format!("{}{case}", mode.prefix());
        let mut command = standard_command(
            root,
            &nonce,
            address,
            &format!("console-owner-{probe_case}"),
        )
        .expect("private console command");
        if let Some(artifact) = gui_artifact {
            command
                .env(GUI_CREATOR_PATH, &artifact.path)
                .env(GUI_CREATOR_SHA, &artifact.sha256)
                .env(GUI_CREATOR_FORCE, if force_creator { "1" } else { "0" });
        }
        command.stdout(StdStdio::null()).stderr(
            std::fs::File::create(root.join("console-stderr")).expect("private console stderr"),
        );
        let mut owner =
            console_at("outer_owner_spawn", command.spawn()).expect("private console owner");
        let owner_pid = owner.id();
        let owner_birth = console_at("outer_owner_birth", birth(owner.as_raw_handle()))
            .expect("actual console owner birth");
        let deadline = Instant::now()
            + SETUP
            + SETUP
            + if initialized_donor {
                SETUP
            } else {
                Duration::ZERO
            }
            + if LIVE_HELPER_RELEASE_BARRIER {
                SETUP
            } else {
                Duration::ZERO
            };
        let observed = (|| -> io::Result<ConsoleProbe> {
            loop {
                if let Some(status) = console_at("outer_owner_wait", owner.try_wait())? {
                    if !status.success() {
                        let bytes = console_at(
                            "outer_owner_error_read",
                            bounded_console_record(&root.join("console-owner-error")),
                        )?;
                        let failure: ConsoleOwnerFailure = console_at(
                            "outer_owner_error_parse",
                            serde_json::from_slice(&bytes).map_err(io::Error::from),
                        )?;
                        if failure.nonce != nonce
                            || failure.pid != owner_pid
                            || failure.birth.is_some_and(|value| value != owner_birth)
                        {
                            return Err(console_unknown("outer_owner_error_identity"));
                        }
                        return Err(io::Error::other(failure.failure));
                    }
                    let bytes = console_at(
                        "outer_owner_result_read",
                        bounded_console_record(&root.join("console-probe-result")),
                    )?;
                    let probe: ConsoleProbe = console_at(
                        "outer_owner_result_parse",
                        serde_json::from_slice(&bytes).map_err(io::Error::from),
                    )?;
                    if probe.owner_pid != owner_pid
                        || probe.owner_birth != owner_birth
                        || probe.case != probe_case
                        || probe.initialized_donor_comparison != initialized_donor
                        || probe.mode_context.launch_mode != mode.tag()
                    {
                        return Err(console_unknown("outer_owner_result_identity"));
                    }
                    return Ok(probe);
                }
                if Instant::now() >= deadline {
                    return Err(console_unknown("outer_owner_wait_timeout"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        let observed =
            observed.map_err(|error| console_with_mode(error, ConsoleModeContext::new(mode)));
        let detach = console_at(
            "outer_detach_record_read",
            bounded_console_record(&root.join("console-detach-result")),
        )
        .and_then(|bytes| {
            console_at(
                "outer_detach_record_parse",
                serde_json::from_slice::<(bool, Option<i32>)>(&bytes).map_err(io::Error::from),
            )
        });
        eprintln!("WINDOWS_STDIO_MATRIX_DETACH: case={probe_case}; FreeConsole={detach:?}");
        eprintln!(
            "WINDOWS_STDIO_MATRIX_BEFORE_PRIVATE_CLEANUP: case={probe_case}; observation={observed:?}"
        );
        let automatic_log = if mode == ConsoleLaunchMode::Automatic {
            // Direct writes bypass libtest's per-test print capture, including
            // on successful controls. Only bounded, private fixture metadata is
            // present in observed; no environment values or filesystem paths.
            let mut stderr = std::io::stderr().lock();
            writeln!(stderr, "WINDOWS_AUTOMATIC_STDIO_SOURCE_CONTRACT_AND_OBSERVATION: case={probe_case}; observation={observed:?}")
                .and_then(|()| stderr.flush())
        } else {
            Ok(())
        };
        if initialized_donor {
            eprintln!(
                "WINDOWS_INITIALIZED_DONOR_COMPARISON: case={case}; observation={observed:?}"
            );
        }
        let gui_route = gui_artifact.map(|artifact| -> io::Result<GuiCreatorRoute> {
            let record: GuiCreatorRoute =
                serde_json::from_slice(&bounded_console_record(&root.join("gui-creator-route"))?)
                    .map_err(|_| console_unknown("gui_creator_route_parse"))?;
            let expected_helpers =
                usize::from(force_creator || !matches!(case, "all-inherit" | "redirect-file"));
            if record.nonce != nonce
                || record.owner_pid != owner_pid
                || record.owner_birth != owner_birth
                || record.artifact_sha256 != artifact.sha256
                || record.force_creator != force_creator
                || record.actual_helper_creations != expected_helpers
            {
                return Err(console_unknown("gui_creator_route_identity_or_coverage"));
            }
            Ok(record)
        });
        let gui_route_log = if let Some(route) = gui_route.as_ref() {
            let mut stderr = std::io::stderr().lock();
            writeln!(
                stderr,
                "WINDOWS_GUI_CREATOR_ARTIFACT_ROUTE: case={probe_case}; route={route:?}"
            )
            .and_then(|()| stderr.flush())
        } else {
            Ok(())
        };
        let cleanup = (|| -> io::Result<()> {
            if console_at("outer_owner_cleanup_probe", owner.try_wait())?.is_none() {
                console_at("outer_owner_cleanup_kill", owner.kill())?;
            }
            // SAFETY: actual original private console owner, never a numeric PID signal.
            match unsafe { WaitForSingleObject(owner.as_raw_handle(), CLEANUP_CONSOLE_MS) } {
                0 => {}
                0xffff_ffff => {
                    return console_at("outer_owner_cleanup_wait", Err(io::Error::last_os_error()))
                }
                258 => return Err(console_unknown("outer_owner_cleanup_wait_timeout")),
                _ => return Err(console_unknown("outer_owner_cleanup_wait_unexpected")),
            }
            console_at("outer_owner_cleanup_reap", owner.wait())?;
            Ok(())
        })();
        if cleanup.is_err() {
            let _ = sandbox.keep();
        }
        assert!(cleanup.is_ok(), "{UNKNOWN}: console cleanup: {cleanup:?}");
        assert!(
            gui_route_log.is_ok(),
            "GUI qualification route output failed"
        );
        if let Some(route) = gui_route {
            route.expect("GUI artifact identity and actual helper coverage");
        }
        let probe = observed.unwrap_or_else(|error| {
            if let Some(failure) = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<ConsoleFailure>())
            {
                if failure.kind == "causal-oracle" && failure.cleanup_confirmed {
                    let marker = match failure.stage.as_str() {
                        "creator_lease_retained_after_positive_gate" => {
                            Some(CREATOR_LEASE_MISMATCH)
                        }
                        "vendor_original_reap_timeout" => Some(LIVE_HELPER_MISMATCH),
                        _ => None,
                    };
                    if let Some(marker) = marker {
                        eprintln!("{OWNED_CLEANUP}");
                        eprintln!("{marker}");
                        panic!(
                            "native retirement oracle rejected a measured causal violation at {}",
                            failure.stage
                        );
                    }
                }
            }
            panic!("{UNKNOWN}: console observation: {error}")
        });
        assert!(
            automatic_log.is_ok(),
            "{UNKNOWN}: automatic observation log: {automatic_log:?}"
        );
        let expected_component_job = if mode.attribute_variant().is_some() {
            probe.mode_context.observed_vendor_job_member == Some(true)
        } else {
            !matches!(
                mode,
                ConsoleLaunchMode::Standard
                    | ConsoleLaunchMode::PlainRaw
                    | ConsoleLaunchMode::Automatic
            )
        };
        let expected_job_empty = expected_component_job.then_some(true);
        assert!(
            probe.accepted
                && probe.mode_context.launch_mode == mode.tag()
                && probe.mode_context.component_job == expected_component_job
                && probe.mode_context.job_empty == expected_job_empty
                && probe.mode_context.explicit_job_attribute == mode.explicit_job_attribute()
                && (mode != ConsoleLaunchMode::Automatic
                    || probe
                        .mode_context
                        .automatic_creator_source_contract
                        .as_ref()
                        .is_some_and(|creator| {
                            !creator.inherit_handles
                                && creator.startup_flags == 0
                                && !creator.standard_handle_overrides
                                && creator.private_stdio_inheritable_duplicates == 0
                        }))
                && (mode.attribute_variant().is_none()
                    || probe.mode_context.observed_vendor_job_member.is_some())
                && (!mode.keeps_donor_alive()
                    || (probe.mode_context.donor_alive_after_vendor_exit == Some(true)
                        && probe.mode_context.donor_reaped_before_census == Some(true)))
                && probe.initialized_donor_ready_bound == initialized_donor
                && (!initialized_donor || probe.mode_context.donor_observation.is_some())
                && probe
                    .vendor_observation
                    .as_ref()
                    .is_some_and(|vendor| vendor.file_types_state == "observed_identity_match")
                && probe.vendor_exit_success
                && probe.actual_child_matched
                && probe.original_child_reaped
                && probe.readers_joined
                && probe.reader_count == expected_readers
                && probe.input_ok
                && probe.input_eof != expected_input
                && probe.stdout_ok
                && probe.stderr_ok
                && probe.stdout_nonce_observed
                && probe.stderr_nonce_observed
                && probe.error_console == expected_error
                && probe.input_console == expected_input
                && probe.output_console == expected_output,
            "WINDOWS_STDIO_MATRIX_NATIVE_IO_REFUSED: {probe:?}"
        );
    }
    #[test]
    #[ignore = "requires explicit SHA-bound desktop-only release GUI creator artifact"]
    fn desktop_only_release_gui_creator_performs_real_stdio_matrix() {
        let _environment = csq_core::platform::test_env::lock();
        let artifact = GuiCreatorArtifact::from_env()
            .expect("GUI artifact validation")
            .expect("CSQ_TEST_GUI_CREATOR_PATH and CSQ_TEST_GUI_CREATOR_SHA256 are required");
        for case in [
            "cli-codex",
            "all-inherit",
            "redirect-file",
            "desktop",
            "absent-inherit",
        ] {
            inherited_console_probe_variant_with_gui(
                case,
                ConsoleLaunchMode::Baseline,
                Some(&artifact),
                false,
            );
        }
        // Supplemental forced-B cases exercise GUI AttachConsole with console
        // stdio; normal A all-inherit/redirect controls explicitly report zero
        // helper creations and are not presented as helper coverage. Redirected
        // stdout also exercises remote file transfer through the helper.
        for case in ["all-inherit", "redirect-file"] {
            inherited_console_probe_variant_with_gui(
                case,
                ConsoleLaunchMode::Baseline,
                Some(&artifact),
                true,
            );
        }
    }
    const CLEANUP_CONSOLE_MS: u32 = 2_000;
    #[test]
    fn native_cli_codex_console_input_piped_stdout_console_stderr_performs_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("cli-codex");
    }
    #[test]
    fn native_all_inherit_private_console_performs_real_input_output() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("all-inherit");
    }
    #[test]
    fn native_all_inherit_redirected_file_preserves_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("redirect-file");
    }
    #[test]
    fn comparison_standard_cli_codex_console_input_piped_stdout_console_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("cli-codex", ConsoleLaunchMode::Standard);
    }
    #[test]
    fn comparison_standard_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::Standard);
    }
    #[test]
    fn comparison_standard_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::Standard);
    }
    #[test]
    fn comparison_plain_create_process_cli_codex_console_input_piped_stdout_console_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("cli-codex", ConsoleLaunchMode::PlainRaw);
    }
    #[test]
    fn comparison_plain_create_process_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::PlainRaw);
    }
    #[test]
    fn comparison_plain_create_process_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::PlainRaw);
    }
    #[test]
    fn comparison_attributes_no_parent_cli_codex_console_input_piped_stdout_console_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("cli-codex", ConsoleLaunchMode::NoParent);
    }
    #[test]
    fn comparison_attributes_no_parent_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::NoParent);
    }
    #[test]
    fn comparison_attributes_no_parent_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::NoParent);
    }
    #[test]
    fn comparison_attributes_handle_only_cli_codex_console_input_piped_stdout_console_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("cli-codex", ConsoleLaunchMode::HandleOnly);
    }
    #[test]
    fn comparison_attributes_handle_only_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::HandleOnly);
    }
    #[test]
    fn comparison_attributes_handle_only_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::HandleOnly);
    }
    #[test]
    fn comparison_attributes_job_only_cli_codex_console_input_piped_stdout_console_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("cli-codex", ConsoleLaunchMode::JobOnly);
    }
    #[test]
    fn comparison_attributes_job_only_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::JobOnly);
    }
    #[test]
    fn comparison_attributes_job_only_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::JobOnly);
    }
    #[test]
    fn native_desktop_null_input_two_pipes_performs_real_io_without_console() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("desktop");
    }
    #[test]
    fn native_no_console_absent_inherited_handles_map_to_null_and_eof() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("absent-inherit");
    }
    #[test]
    fn comparison_automatic_stdio_all_inherit_private_console_real_io() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("all-inherit", ConsoleLaunchMode::Automatic);
    }
    #[test]
    fn comparison_automatic_stdio_redirected_file_console_input_and_stderr() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe_variant("redirect-file", ConsoleLaunchMode::Automatic);
    }
    fn assert_arming_positive(oracle: ArmingOracle) {
        match Fixture::start_with_oracle(oracle) {
            Ok(mut fixture) => fixture
                .cleanup()
                .unwrap_or_else(|error| panic!("{UNKNOWN}: {error}")),
            Err(error) => {
                if let Some(rejection) = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<OracleRejection>())
                {
                    // start_with_oracle emits owned-cleanup confirmation before
                    // returning any causal rejection to this positive testcase.
                    eprintln!("{}", rejection.0);
                    panic!("native arming oracle rejected the requested Job");
                }
                panic!("{UNKNOWN}: arming observation: {error}");
            }
        }
    }
    #[test]
    fn fixture_exact_job_arming_positive_control() {
        let _environment = csq_core::platform::test_env::lock();
        assert_arming_positive(ArmingOracle::Requested);
    }
    fn assert_arming_rejection(oracle: ArmingOracle, marker: &str) {
        let error = match Fixture::start_with_oracle(oracle) {
            Ok(mut fixture) => {
                fixture.cleanup().expect("owned control cleanup");
                panic!("oracle accepted a real kernel nonmember");
            }
            Err(error) => error,
        };
        let rejection = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<OracleRejection>())
            .unwrap_or_else(|| {
                panic!("{UNKNOWN}: negative control could not be observed: {error}")
            });
        assert_eq!(rejection.0, marker);
    }
    #[test]
    fn fixture_vendor_foreign_requested_job_is_rejected_with_original_cleanup_job_retained() {
        let _environment = csq_core::platform::test_env::lock();
        assert_arming_rejection(ArmingOracle::ForeignVendorJob, VENDOR_JOB_MISMATCH);
    }
    #[test]
    fn fixture_authenticated_descendant_in_safety_job_is_rejected_at_descendant_site() {
        let _environment = csq_core::platform::test_env::lock();
        assert_arming_rejection(ArmingOracle::OutsideDescendant, DESCENDANT_JOB_MISMATCH);
    }
    #[test]
    fn fixture_creator_retirement_positive_control() {
        let _environment = csq_core::platform::test_env::lock();
        inherited_console_probe("cli-codex");
    }
    #[test]
    fn production_job_parent_crash_terminates_original_vendor_and_descendant_before_private_cleanup(
    ) {
        let _environment = csq_core::platform::test_env::lock();
        let mut fixture =
            Fixture::start().unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
        let observed = (|| -> io::Result<(bool, bool, bool, bool)> {
            fixture.kill_owner()?;
            eprintln!("WINDOWS_JOB_OWNER_REAP: actual_original_owner_reaped=true");
            let deadline = Instant::now() + OBSERVE;
            loop {
                let vendor_gone = fixture.peer("vendor")?.gone()?;
                let descendant_gone = fixture.peer("descendant")?.gone()?;
                let helper_gone = fixture.helper_gone()?;
                let eof = fixture.eof.load(Ordering::Acquire);
                if vendor_gone && descendant_gone && eof && helper_gone {
                    return Ok((true, true, true, true));
                }
                if Instant::now() >= deadline {
                    if vendor_gone && descendant_gone && helper_gone {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    if !vendor_gone && !fixture.peer("vendor")?.challenge()? {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    if !descendant_gone && !fixture.peer("descendant")?.challenge()? {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    return Ok((vendor_gone, descendant_gone, eof, helper_gone));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        eprintln!("WINDOWS_JOB_BEFORE_PRIVATE_CLEANUP: observation={observed:?}");
        let cleanup = fixture.cleanup();
        assert!(cleanup.is_ok(), "{UNKNOWN}: cleanup: {cleanup:?}");
        let observed = observed.unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
        assert_eq!(
            observed,
            (true, true, true, true),
            "WINDOWS_JOB_PARENT_DEATH_SURVIVOR"
        );
    }
    #[test]
    fn production_job_kernel_flags_enable_kill_on_close_without_breakaway() {
        let _environment = csq_core::platform::test_env::lock();
        let mut fixture =
            Fixture::start().unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
        let observed = (|| -> io::Result<u32> {
            fixture.peer("owner")?.stream.get_mut().write_all(b"F")?;
            Ok(serde_json::from_str(&line(
                &mut fixture.peer("owner")?.stream,
            )?)?)
        })();
        eprintln!("WINDOWS_JOB_KERNEL_FLAGS_BEFORE_PRIVATE_CLEANUP: {observed:?}");
        let cleanup = fixture.cleanup();
        assert!(cleanup.is_ok(), "{UNKNOWN}: cleanup: {cleanup:?}");
        let flags = observed.unwrap_or_else(|error| panic!("{UNKNOWN}: kernel flags: {error}"));
        assert_eq!(flags, 0x2000, "WINDOWS_JOB_KERNEL_KILL_ON_CLOSE_POLICY");
        assert_eq!(
            flags & (0x800 | 0x1000),
            0,
            "WINDOWS_JOB_MUST_NOT_ALLOW_BREAKAWAY"
        );
    }
    #[test]
    fn exited_leader_with_live_descendant_retains_job_and_refuses_finalized_receipt() {
        let _environment = csq_core::platform::test_env::lock();
        let mut fixture =
            Fixture::start().unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
        let descendant_pid = fixture
            .peer("descendant")
            .expect("original bound descendant")
            .identity
            .pid;
        let observed = (|| -> io::Result<ReapObservation> {
            fixture.peer("vendor")?.stream.get_mut().write_all(b"X")?;
            let deadline = Instant::now() + SETUP;
            while !fixture.peer("vendor")?.gone()? {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !fixture.peer("descendant")?.challenge()? {
                return Err(io::Error::other(UNKNOWN));
            }
            fixture.peer("owner")?.stream.get_mut().write_all(b"R")?;
            Ok(serde_json::from_str(&line(
                &mut fixture.peer("owner")?.stream,
            )?)?)
        })();
        eprintln!("WINDOWS_JOB_REAP_BEFORE_PRIVATE_CLEANUP: {observed:?}");
        let cleanup = fixture.cleanup();
        assert!(cleanup.is_ok(), "{UNKNOWN}: cleanup: {cleanup:?}");
        let observed = observed.unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
        assert!(
            observed.active == 1
                && observed.helper_retired
                && observed.member_pids == [descendant_pid]
                && observed.refused
                && !observed.reaped
                && !observed.finalized
                && !observed.reason.is_empty(),
            "WINDOWS_JOB_LIVE_DESCENDANT_MUST_RETAIN_COMPLETION_CUSTODY: {observed:?}"
        );
    }

    #[test]
    fn exited_vendor_leftover_descendant_is_killed_after_grace_then_finalized_without_cancellation()
    {
        let _environment = csq_core::platform::test_env::lock();
        let mut fixture =
            Fixture::start().unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
        let observed = (|| -> io::Result<(ReapObservation, CompletionObservation, bool, bool)> {
            let descendant_pid = fixture.peer("descendant")?.identity.pid;
            fixture.peer("vendor")?.stream.get_mut().write_all(b"X")?;
            let until = Instant::now() + SETUP;
            while !fixture.peer("vendor")?.gone()? {
                if Instant::now() >= until {
                    return Err(io::Error::other(UNKNOWN));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !fixture.peer("descendant")?.challenge()? {
                return Err(io::Error::other(UNKNOWN));
            }
            fixture.peer("owner")?.stream.get_mut().write_all(b"R")?;
            let initial: ReapObservation =
                serde_json::from_str(&line(&mut fixture.peer("owner")?.stream)?)?;
            if initial.active != 1
                || initial.member_pids != [descendant_pid]
                || !initial.helper_retired
                || initial.reaped
                || initial.finalized
                || !initial.refused
                || !fixture.peer("descendant")?.challenge()?
            {
                return Err(io::Error::other(UNKNOWN));
            }
            // The production grace is 2s. This peer response budget covers
            // the actor's full 5s observation bound plus 1s transport margin;
            // an uncleaned member remains live until the independent 30s
            // actor safety bound. An omitted kill therefore returns a measured
            // survivor, rather than timing out before the intended assertion.
            fixture
                .peer("owner")?
                .stream
                .get_mut()
                .set_read_timeout(Some(SETUP + Duration::from_secs(1)))?;
            fixture.peer("owner")?.stream.get_mut().write_all(b"C")?;
            let complete: CompletionObservation =
                serde_json::from_str(&line(&mut fixture.peer("owner")?.stream)?)?;
            let until = Instant::now() + OBSERVE;
            while !fixture.peer("descendant")?.gone()? && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok((
                initial,
                complete,
                fixture.peer("descendant")?.gone()?,
                fixture.helper_gone()?,
            ))
        })();
        eprintln!("WINDOWS_JOB_LEFTOVER_COMPLETION_BEFORE_PRIVATE_CLEANUP: {observed:?}");
        let cleanup = fixture.cleanup();
        assert!(cleanup.is_ok(), "{UNKNOWN}: cleanup: {cleanup:?}");
        let (_, complete, descendant_gone, helper_gone) =
            observed.unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
        eprintln!("WINDOWS_JOB_LEFTOVER_CLEANUP_CONFIRMED");
        let completed = descendant_gone
            && helper_gone
            && complete.vendor_code == Some(0)
            && complete.active == 0
            && complete.finalized
            && complete.helper_retired
            && complete.readers_joined;
        if !completed {
            eprintln!("WINDOWS_JOB_LEFTOVER_MUST_BE_KILLED_AND_FINALIZED");
        }
        assert!(
            completed,
            "WINDOWS_JOB_LEFTOVER_MUST_BE_KILLED_AND_FINALIZED: descendant_gone={descendant_gone}; helper_gone={helper_gone}; {complete:?}"
        );
        if complete.operator_kill_intent {
            eprintln!("WINDOWS_JOB_COMPLETION_CLEANUP_MUST_NOT_CANCEL_SUCCESSFUL_VENDOR");
        }
        assert!(
            !complete.operator_kill_intent,
            "WINDOWS_JOB_COMPLETION_CLEANUP_MUST_NOT_CANCEL_SUCCESSFUL_VENDOR: {complete:?}"
        );
    }
}
