//! Native-only production lease/main-gate tests. Run only in a newly provisioned
//! disposable Windows principal; setup/artifact failure is a failing test.
//! This does not exercise NSIS File/rollback or credential-write drain.
#![cfg(feature = "native-installer-tests")]

#[cfg(not(windows))]
compile_error!(
    "native-installer-tests requires a Windows target; native qualification cannot be empty"
);
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{c_void, OsStr, OsString},
    fs::{self, File},
    mem,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    ptr, thread,
    time::{Duration, Instant},
};

type H = isize;
const TIMEOUT: Duration = Duration::from_secs(120);
const REFUSED: &[u8] = b"csq: installer admission refused; error_kind=lease_busy\n\
csq: installation in progress or admission unavailable; retry after the installer exits\n";
const MODE: &str = "CSQ_NATIVE_INSTALLER_CONTROLLER";
const CONFIG: &str = "CSQ_NATIVE_INSTALLER_CONFIG";
#[repr(C)]
struct Startup {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    cx: u32,
    cy: u32,
    xchars: u32,
    ychars: u32,
    fill: u32,
    flags: u32,
    show: u16,
    reserved_len: u16,
    reserved_bytes: *mut u8,
    input: H,
    output: H,
    error: H,
}
#[repr(C)]
#[derive(Default)]
struct Pi {
    process: H,
    thread: H,
    pid: u32,
    tid: u32,
}
#[repr(C)]
#[derive(Default)]
struct BasicLimit {
    process_time: i64,
    job_time: i64,
    flags: u32,
    min_working: usize,
    max_working: usize,
    active: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
#[repr(C)]
#[derive(Default)]
struct ExtendedLimit {
    basic: BasicLimit,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
}
#[repr(C)]
#[derive(Default)]
struct Ft {
    low: u32,
    high: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(h: H) -> i32;
    fn GetCurrentProcess() -> H;
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> H;
    fn OpenJobObjectW(access: u32, inherit: i32, name: *const u16) -> H;
    fn SetInformationJobObject(job: H, class: i32, data: *const c_void, size: u32) -> i32;
    fn QueryInformationJobObject(
        job: H,
        class: i32,
        data: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: H, process: H) -> i32;
    fn IsProcessInJob(process: H, job: H, result: *mut i32) -> i32;
    fn TerminateJobObject(job: H, code: u32) -> i32;
    fn TerminateProcess(process: H, code: u32) -> i32;
    fn CreateProcessW(
        app: *const u16,
        command: *mut u16,
        pa: *const c_void,
        ta: *const c_void,
        inherit: i32,
        flags: u32,
        environment: *const c_void,
        cwd: *const u16,
        startup: *const Startup,
        info: *mut Pi,
    ) -> i32;
    fn ResumeThread(thread: H) -> u32;
    fn WaitForSingleObject(h: H, millis: u32) -> u32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> H;
    fn GetExitCodeProcess(process: H, code: *mut u32) -> i32;
    fn GetProcessTimes(
        process: H,
        birth: *mut Ft,
        exit: *mut Ft,
        kernel: *mut Ft,
        user: *mut Ft,
    ) -> i32;
    fn QueryFullProcessImageNameW(process: H, flags: u32, buffer: *mut u16, size: *mut u32) -> i32;
    fn GetHandleInformation(handle: H, flags: *mut u32) -> i32;
    fn GetFinalPathNameByHandleW(file: H, path: *mut u16, size: u32, flags: u32) -> u32;
    fn LocalFree(value: *mut c_void) -> *mut c_void;
}
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
#[derive(Default)]
struct ObjectBasic {
    attributes: u32,
    access: u32,
    handles: u32,
    pointers: u32,
    reserved: [u32; 10],
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: H,
        class: i32,
        data: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: H, access: u32, token: *mut H) -> i32;
    fn GetTokenInformation(
        token: H,
        class: i32,
        data: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, result: *mut *mut u16) -> i32;
    fn IsValidSid(sid: *const c_void) -> i32;
}
struct Handle(H);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: owns one valid, nonpseudo handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
impl Handle {
    fn checked_close(self) -> Result<()> {
        let h = self.0;
        mem::forget(self); // SAFETY: consumes the only local owner.
        if unsafe { CloseHandle(h) } == 0 {
            bail!("SETUP/UNDETERMINED: CloseHandle failed");
        }
        Ok(())
    }
    fn alive(&self) -> Result<bool> {
        // SAFETY: retained synchronize process handle.
        match unsafe { WaitForSingleObject(self.0, 0) } {
            0 => Ok(false),
            258 => Ok(true),
            _ => bail!("SETUP/UNDETERMINED: process wait"),
        }
    }
    fn wait(&self) -> Result<()> {
        // SAFETY: retained synchronize process handle.
        if unsafe { WaitForSingleObject(self.0, 10_000) } != 0 {
            bail!("SETUP/UNDETERMINED: owned process not reaped");
        }
        Ok(())
    }
    fn kill_owned(&self, job: &Job) -> Result<()> {
        job.contains(self)?;
        if !self.alive()? {
            bail!("SETUP/UNDETERMINED: owned target exited before crash action");
        } // SAFETY: retained handle positively bound to this test's job before termination.
        if unsafe { TerminateProcess(self.0, 99) } == 0 {
            bail!("SETUP/UNDETERMINED: owned target terminate failed");
        }
        self.wait()
    }
}
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}
fn birth(h: &Handle) -> Result<u64> {
    let (mut b, mut e, mut k, mut u) = (Ft::default(), Ft::default(), Ft::default(), Ft::default()); // SAFETY: valid query process handle and initialized outputs.
    if unsafe { GetProcessTimes(h.0, &mut b, &mut e, &mut k, &mut u) } == 0 {
        bail!("SETUP: process birth");
    }
    let value = (u64::from(b.high) << 32) | u64::from(b.low);
    if value == 0 {
        bail!("SETUP: missing process birth");
    }
    Ok(value)
}
fn process(pid: u32) -> Result<Handle> {
    // SAFETY: noninherited query/sync/terminate handle; not used for action until job+identity proof.
    let h = unsafe { OpenProcess(0x1000 | 0x100000 | 1, 0, pid) };
    if h == 0 {
        bail!("SETUP: process open");
    }
    Ok(Handle(h))
}
fn process_image(h: &Handle) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let mut n = buffer.len() as u32; // SAFETY: live query handle and bounded output.
    if unsafe { QueryFullProcessImageNameW(h.0, 0, buffer.as_mut_ptr(), &mut n) } == 0
        || n == 0
        || n as usize >= buffer.len()
    {
        bail!("SETUP: process image");
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..n as usize])).canonicalize()?)
}
fn sid() -> Result<String> {
    let mut token = 0; // SAFETY: current pseudo handle borrowed, token output owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        bail!("SETUP: token");
    }
    let token = Handle(token);
    let mut size = 0; // SAFETY: documented zero-length size query.
    unsafe {
        GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut size);
    }
    if !(16..=65536).contains(&size) {
        bail!("SETUP: token size");
    }
    let mut data = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    let capacity = size; // SAFETY: aligned allocation has capacity bytes.
    if unsafe { GetTokenInformation(token.0, 1, data.as_mut_ptr().cast(), capacity, &mut size) }
        == 0
        || size > capacity
    {
        bail!("SETUP: token user");
    }
    // SAFETY: TOKEN_USER begins with one PSID, in initialized aligned storage.
    let p = unsafe { *data.as_ptr().cast::<*const c_void>() };
    let at = p as usize;
    let base = data.as_ptr() as usize;
    let end = base + size as usize;
    if at < base || at.checked_add(8).is_none_or(|v| v > end) {
        bail!("SETUP: SID header");
    } // SAFETY: eight-byte SID header range proved.
    let count = unsafe { *(p.cast::<u8>().add(1)) } as usize;
    if count > 15
        || at.checked_add(8 + count * 4).is_none_or(|v| v > end)
        || unsafe { IsValidSid(p) } == 0
    {
        bail!("SETUP: SID range");
    }
    let mut text = ptr::null_mut(); // SAFETY: validated SID; API allocates NUL terminated result.
    if unsafe { ConvertSidToStringSidW(p, &mut text) } == 0 {
        bail!("SETUP: SID text");
    }
    let mut n = 0; // SAFETY: bounded scan of API string.
    unsafe {
        while n < 256 && *text.add(n) != 0 {
            n += 1;
        }
    }
    let result = if n < 256 {
        // SAFETY: measured string remains allocated.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) })
            .context("SETUP: SID utf16")
    } else {
        Err(anyhow::anyhow!("SETUP: SID length"))
    }; // SAFETY: sole LocalAlloc allocation after final read.
    unsafe {
        LocalFree(text.cast());
    }
    result
}
fn guid(path: &Path) -> Result<PathBuf> {
    let file = File::open(path)?;
    let mut text = vec![0u16; 32768]; // SAFETY: retained file handle, bounded output; VOLUME_NAME_GUID=1.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as H,
            text.as_mut_ptr(),
            text.len() as u32,
            1,
        )
    };
    if n == 0 || n as usize >= text.len() {
        bail!("SETUP: GUID path");
    }
    let path = PathBuf::from(OsString::from_wide(&text[..n as usize]));
    if !path.to_string_lossy().starts_with(r"\\?\Volume{") {
        bail!("SETUP: no GUID namespace");
    }
    Ok(path)
}
struct Job {
    handle: Handle,
}
impl Job {
    fn create(name: &str) -> Result<Self> {
        // SAFETY: unique test name, default noninheritable handle.
        let h = unsafe { CreateJobObjectW(ptr::null(), wide(OsStr::new(name)).as_ptr()) };
        if h == 0 {
            bail!("SETUP: create job");
        }
        let job = Self { handle: Handle(h) };
        let mut limit = ExtendedLimit::default();
        limit.basic.flags = 0x2000; // KILL_ON_JOB_CLOSE
                                    // SAFETY: initialized documented extended limit layout.
        if unsafe {
            SetInformationJobObject(
                h,
                9,
                (&limit as *const ExtendedLimit).cast(),
                mem::size_of::<ExtendedLimit>() as u32,
            )
        } == 0
        {
            bail!("SETUP: kill-on-close job");
        }
        Ok(job)
    }
    fn open(name: &str) -> Result<Self> {
        // SAFETY: exact unique current fixture job, QUERY access only.
        let h = unsafe { OpenJobObjectW(4, 0, wide(OsStr::new(name)).as_ptr()) };
        if h == 0 {
            bail!("SETUP: open owned job");
        }
        Ok(Self { handle: Handle(h) })
    }
    fn members(&self) -> Result<Vec<u32>> {
        let mut data = vec![0usize; 258]; // SAFETY: aligned buffer fits header plus256 native ULONG_PTR PIDs.
        if unsafe {
            QueryInformationJobObject(
                self.handle.0,
                3,
                data.as_mut_ptr().cast(),
                (data.len() * mem::size_of::<usize>()) as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            bail!("SETUP: query job members");
        }
        // SAFETY: successful JOB_OBJECT_BASIC_PROCESS_ID_LIST output.
        let count = unsafe { *data.as_ptr().cast::<u32>().add(1) } as usize;
        if count > 256 {
            bail!("SETUP: job member bound");
        }
        // SAFETY: header is8bytes and allocation proved enough for count entries.
        Ok(unsafe {
            std::slice::from_raw_parts(data.as_ptr().cast::<u8>().add(8).cast::<usize>(), count)
        }
        .iter()
        .map(|v| *v as u32)
        .collect())
    }
    fn contains(&self, h: &Handle) -> Result<()> {
        let mut yes = 0; // SAFETY: retained process+exact owned job handles.
        if unsafe { IsProcessInJob(h.0, self.handle.0, &mut yes) } == 0 || yes == 0 {
            bail!("SETUP: process is outside owned job");
        }
        Ok(())
    }
    fn empty(&self) -> Result<()> {
        let start = Instant::now();
        while !self.members()?.is_empty() {
            if start.elapsed() > Duration::from_secs(10) {
                bail!("UNDETERMINED: owned job still has processes");
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
struct JobOwner(Job);
impl Drop for JobOwner {
    fn drop(&mut self) {
        // SAFETY: termination scoped to this fixture's exact job; closes descendants on panic.
        unsafe {
            TerminateJobObject(self.0.handle.0, 98);
        }
        if let Err(e) = self.0.empty() {
            eprintln!("UNDETERMINED cleanup: {e}");
            if !thread::panicking() {
                panic!("owned native job cleanup failed");
            }
        }
    }
}
#[derive(Serialize, Deserialize, Clone)]
struct Config {
    base: PathBuf,
    helper: PathBuf,
    probe: PathBuf,
    job: String,
    system: OsString,
    expected_sid: String,
    mutant: bool,
}
#[derive(Serialize, Deserialize)]
struct BrokerReceipt {
    pid: u32,
    birth: u64,
}
fn required(name: &str) -> Result<OsString> {
    std::env::var_os(name).with_context(|| format!("SETUP/UNDETERMINED: missing {name}"))
}
fn checksum(path: &Path, expected: &str) -> Result<()> {
    csq_core::update::verify::verify_checksum(
        &fs::read(path)?,
        &format!("{expected}  artifact.exe"),
        "artifact.exe",
    )
    .context("SETUP: artifact SHA256")
}
fn clean_env(c: &Config) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for key in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
        env.insert(key.into(), c.system.clone());
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "CSQ_BASE_DIR",
    ] {
        env.insert(key.into(), c.base.join("home").into_os_string());
    }
    env.insert("PATH".into(), c.system.clone());
    env.insert("CSQ_SECRET_BACKEND".into(), "in-memory".into());
    env.insert("CSQ_TEST_BYPASS_TTY".into(), "1".into());
    env.insert(
        "CSQ_TEST_FRESH_PRINCIPAL_SID".into(),
        c.expected_sid.clone().into(),
    );
    env
}
fn clean_command(path: &Path, c: &Config) -> Command {
    let mut cmd = Command::new(path);
    cmd.env_clear().envs(clean_env(c)).current_dir(&c.base);
    cmd
}
fn probe(c: &Config, blocked: bool) -> Result<Vec<u8>> {
    let out = clean_command(&c.probe, c).arg("--version").output()?;
    if blocked {
        if out.status.code() != Some(2)
            || out.stderr.replace_crlf() != REFUSED
            || !out.stdout.is_empty()
        {
            bail!("ASSERTION: production main gate did not refuse exactly: {out:?}");
        }
    } else if !out.status.success()
        || !out.stderr.is_empty()
        || !String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION"))
    {
        bail!("ASSERTION: production main positive version failed: {out:?}");
    }
    Ok(out.stdout)
}
trait Crlf {
    fn replace_crlf(&self) -> Vec<u8>;
}
impl Crlf for Vec<u8> {
    fn replace_crlf(&self) -> Vec<u8> {
        self.windows(2)
            .enumerate()
            .filter_map(|(i, v)| if v == b"\r\n" { None } else { Some(self[i]) })
            .chain(self.last().copied())
            .collect()
    }
}
fn helper(c: &Config, operation: &str, extra: &[&str]) -> Result<String> {
    let mut cmd = clean_command(&c.helper, c);
    cmd.arg(operation);
    if operation != "lease-object-name" {
        cmd.arg("--installer-pid")
            .arg(std::process::id().to_string());
    }
    if operation == "begin" {
        cmd.arg("--install-root")
            .arg(c.probe.parent().context("SETUP: root")?)
            .arg("--image")
            .arg(&c.probe);
    }
    cmd.args(extra);
    let out: Output = cmd.output()?;
    if !out.status.success() {
        bail!("SETUP/helper refusal: {out:?}");
    }
    let reply = String::from_utf8(out.stdout)?.replace("\r\n", "\n");
    if !reply.ends_with('\n') || reply[..reply.len() - 1].contains('\n') || !out.stderr.is_empty() {
        bail!("SETUP: helper framing");
    }
    Ok(reply.trim_end_matches('\n').to_owned())
}
fn ready(reply: &str) -> Result<Handle> {
    let token = reply
        .strip_prefix("CSQ_INSTALL_V1 READY 0x")
        .context("SETUP: READY prefix")?;
    if token.len() != 8
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        bail!("SETUP: READY grammar");
    }
    let value = u32::from_str_radix(token, 16)?;
    if value == 0 || value == u32::MAX {
        bail!("SETUP: pseudo handle");
    }
    let h = Handle(value as H);
    let mut flags = 0; // SAFETY: READY gives this actual installer process's local handle; read flags, no action yet.
    if unsafe { GetHandleInformation(h.0, &mut flags) } == 0 || flags & 3 != 0 {
        mem::forget(h);
        bail!("SETUP: READY invalid/inheritable/protected local handle");
    }
    let mut info = ObjectBasic::default();
    // SAFETY: read-only ObjectBasicInformation query on the retained valid local
    // reference, fixed documented PUBLIC_OBJECT_BASIC_INFORMATION layout.
    if unsafe {
        NtQueryObject(
            h.0,
            0,
            (&mut info as *mut ObjectBasic).cast(),
            mem::size_of::<ObjectBasic>() as u32,
            ptr::null_mut(),
        )
    } < 0
        || info.access != 0x20000
    {
        mem::forget(h);
        bail!("SETUP: READY reference is not READ_CONTROL-only");
    }
    Ok(h)
}
fn reference_name(handle: &Handle) -> Result<String> {
    let mut storage = vec![0usize; 8192];
    let capacity = storage.len() * mem::size_of::<usize>();
    // SAFETY: initialized aligned bounded output for ObjectNameInformation.
    if unsafe {
        NtQueryObject(
            handle.0,
            1,
            storage.as_mut_ptr().cast(),
            capacity as u32,
            ptr::null_mut(),
        )
    } < 0
    {
        bail!("SETUP: lease reference name query");
    }
    // SAFETY: successful output starts with a UnicodeString header.
    let value = unsafe { &*storage.as_ptr().cast::<UnicodeString>() };
    if value.length == 0 {
        return Ok(String::new());
    }
    let base = storage.as_ptr() as usize;
    let at = value.buffer as usize;
    if value.length % 2 != 0
        || at < base
        || at
            .checked_add(value.length as usize)
            .is_none_or(|end| end > base + capacity)
    {
        bail!("SETUP: lease object name bounds");
    }
    // SAFETY: complete UTF16 string range was proved within retained output.
    Ok(String::from_utf16(unsafe {
        std::slice::from_raw_parts(value.buffer, value.length as usize / 2)
    })?)
}
fn broker(c: &Config, job: &Job) -> Result<(Handle, u32)> {
    let target = c.helper.canonicalize()?;
    let mut found = None;
    for pid in job.members()? {
        if pid == std::process::id() {
            continue;
        }
        let h = process(pid)?;
        job.contains(&h)?;
        if process_image(&h)? == target {
            if found.is_some() {
                bail!("SETUP: ambiguous owned helper broker");
            }
            found = Some((h, pid));
        }
    }
    found.context("SETUP: no retained owned broker")
}
fn controller(c: &Config, mode: &str) -> Result<()> {
    if sid()? != c.expected_sid {
        bail!("SETUP: principal SID mismatch");
    }
    let job = Job::open(&c.job)?;
    job.contains(&process(std::process::id())?)?;
    if mode == "probe" {
        let actual = probe(c, false)?;
        if actual != fs::read(c.base.join("baseline"))? {
            bail!("ASSERTION: same-hash version changed");
        }
        return Ok(());
    }
    let positive = probe(c, false)?;
    fs::write(c.base.join("baseline"), positive)?;
    let expected_name_reply = helper(c, "lease-object-name", &[])?;
    let expected_name = expected_name_reply
        .strip_prefix("CSQ_INSTALL_V1 LEASE_OBJECT_NAME ")
        .context("SETUP: expected native lease name framing")?;
    if !expected_name.starts_with(r"\Sessions")
        || expected_name.len() > 480
        || expected_name.bytes().any(|b| !b.is_ascii_graphic())
    {
        bail!("SETUP: expected native lease name grammar");
    }
    let reply = helper(c, "begin", &[])?;
    let lease = Some(ready(&reply)?);
    let name = reference_name(lease.as_ref().context("SETUP: missing lease")?)?;
    if c.mutant {
        if !name.is_empty() {
            bail!("SETUP: retention mutant must duplicate unrelated UNNAMED object");
        }
    } else if name != expected_name {
        bail!("SETUP: production READY does not refer to exact per-user named lease");
    }
    probe(c, true)?;
    let (held, pid) = broker(c, &job)?;
    if mode == "installer-death" {
        fs::write(
            c.base.join("ready.tmp"),
            serde_json::to_vec(&BrokerReceipt {
                pid,
                birth: birth(&held)?,
            })?,
        )?;
        fs::rename(c.base.join("ready.tmp"), c.base.join("ready.json"))?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
    if mode == "helper-crash" || mode == "counterfactual" {
        held.kill_owned(&job)?;
        let actual = clean_command(&c.probe, c).arg("--version").output()?;
        let refused = actual.status.code() == Some(2)
            && actual.stderr.replace_crlf() == REFUSED
            && actual.stdout.is_empty();
        let admitted = actual.status.success()
            && actual.stderr.is_empty()
            && actual.stdout == fs::read(c.base.join("baseline"))?;
        if c.mutant {
            if !admitted {
                bail!("SETUP/ASSERTION: compiled retention mutant did not reach expected post-crash version witness: {actual:?}");
            }
            fs::write(c.base.join("expected-red"),b"EXPECTED_ASSERTION_FAILURE: actual-main-refused-after-helper-crash; observed exit0 same-binary version while installer alive")?;
            // Dedicated exit classification AFTER actual production probe evidence;
            // malformed READY, compile/setup errors and other failures never reach42.
            std::process::exit(42);
        }
        if !refused {
            bail!("ASSERTION: actual main opened after helper crash while installer reference remained live: {actual:?}");
        }
        fs::write(
            c.base.join("crash-observed"),
            b"owned helper exited; installer still alive; main refused",
        )?;
        // Retain the installer reference until actual installer process death, rather
        // than manufacturing the death case by explicitly closing it early.
        std::process::exit(0);
    }
    if mode != "commit" {
        bail!("SETUP: unknown controller mode");
    }
    if helper(c, "recheck", &["--phase", "copy"])? != "CSQ_INSTALL_V1 RECHECK_OK copy" {
        bail!("ASSERTION: recheck result");
    }
    if helper(
        c,
        "commit-release",
        &["--transaction-committed", "--rollback-closed"],
    )? != "CSQ_INSTALL_V1 RELEASED"
    {
        bail!("ASSERTION: release result");
    }
    lease
        .context("SETUP: missing installer reference")?
        .checked_close()?;
    if probe(c, false)? != fs::read(c.base.join("baseline"))? {
        bail!("ASSERTION: version changed after commit");
    }
    held.wait()?;
    Ok(())
}
fn quote(value: &OsStr) -> OsString {
    let mut result = OsString::from("\"");
    let mut slash = 0;
    for ch in value.encode_wide() {
        if ch == 92 {
            slash += 1;
            continue;
        }
        if ch == 34 {
            for _ in 0..slash * 2 + 1 {
                result.push("\\");
            }
            result.push("\"");
        } else {
            for _ in 0..slash {
                result.push("\\");
            }
            result.push(OsString::from_wide(&[ch]));
        }
        slash = 0;
    }
    for _ in 0..slash * 2 {
        result.push("\\");
    }
    result.push("\"");
    result
}
fn spawn_controller(c: &Config, mode: &str, job: &Job) -> Result<Handle> {
    let exe = std::env::current_exe()?;
    let mut command = quote(exe.as_os_str());
    command.push(" --exact native_installer_lease_suite --nocapture");
    let mut command = wide(&command);
    let mut env = clean_env(c);
    env.insert(MODE.into(), mode.into());
    env.insert(CONFIG.into(), serde_json::to_string(c)?.into());
    let mut block = Vec::new();
    for (k, v) in env {
        block.extend(k.encode_wide());
        block.push(61);
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0); // SAFETY: STARTUPINFOW is a C POD structure; required cb set immediately.
    let mut startup: Startup = unsafe { mem::zeroed() };
    startup.cb = mem::size_of::<Startup>() as u32;
    startup.flags = 0;
    let mut pi = Pi::default(); // SAFETY: initialized CreateProcessW structures, explicit cleared Unicode env, no inherited handles, suspended creation.
    if unsafe {
        CreateProcessW(
            wide(exe.as_os_str()).as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            4 | 0x400,
            block.as_ptr().cast(),
            wide(c.base.as_os_str()).as_ptr(),
            &startup,
            &mut pi,
        )
    } == 0
    {
        bail!("SETUP: suspended controller create");
    }
    let process = Handle(pi.process);
    let thread_handle = Handle(pi.thread);
    // SAFETY: newly created suspended child is owned by retained handle and cannot spawn before assignment.
    if unsafe { AssignProcessToJobObject(job.handle.0, process.0) } == 0 {
        unsafe {
            TerminateProcess(process.0, 97);
        }
        process.wait()?;
        bail!("SETUP: assign controller before resume");
    }
    // SAFETY: resumes only the retained primary thread after successful owned-job assignment.
    if unsafe { ResumeThread(thread_handle.0) } == u32::MAX {
        process.kill_owned(job)?;
        bail!("SETUP: resume controller");
    }
    Ok(process)
}
fn wait_success(process: &Handle) -> Result<()> {
    let start = Instant::now();
    while process.alive()? {
        if start.elapsed() > TIMEOUT {
            bail!("UNDETERMINED: owned controller observer timeout");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let mut code = 0; // SAFETY: retained process handle after signaled exit.
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 || code != 0 {
        bail!("ASSERTION/SETUP: controller exit {code}; inspect controller-error");
    }
    Ok(())
}
fn run_case(
    base: &Path,
    system: &OsStr,
    sid: &str,
    helper_source: &Path,
    helper_sha: &str,
    mode: &str,
    mutant: bool,
) -> Result<()> {
    let tmp = tempfile::tempdir_in(base)?;
    for name in ["home", "install", "stage"] {
        fs::create_dir(tmp.path().join(name))?;
    }
    let source = PathBuf::from(env!("CARGO_BIN_EXE_csq"));
    let probe = tmp.path().join("install/probe.exe");
    fs::copy(&source, &probe)?;
    if fs::read(&source)? != fs::read(&probe)? {
        bail!("SETUP: actual csq copy differs");
    }
    checksum(helper_source, helper_sha)?;
    let helper = tmp.path().join("stage/csq-installer-admission.exe");
    fs::copy(helper_source, &helper)?;
    checksum(&helper, helper_sha)?;
    let mut c = Config {
        base: tmp.path().to_path_buf(),
        helper: guid(&helper)?,
        probe,
        job: format!(
            r"Local\csq-installer-native-{}-{}",
            std::process::id(),
            tmp.path()
                .file_name()
                .context("SETUP: temp name")?
                .to_string_lossy()
        ),
        system: system.to_os_string(),
        expected_sid: sid.into(),
        mutant,
    };
    {
        let owner = JobOwner(Job::create(&c.job)?);
        let installer = spawn_controller(&c, mode, &owner.0)?;
        if mode == "installer-death" {
            let start = Instant::now();
            while !c.base.join("ready.json").exists() {
                if !installer.alive()? || start.elapsed() > TIMEOUT {
                    bail!("SETUP: installer READY receipt unavailable");
                }
                thread::sleep(Duration::from_millis(10));
            }
            let receipt: BrokerReceipt =
                serde_json::from_slice(&fs::read(c.base.join("ready.json"))?)?;
            let held = process(receipt.pid)?;
            owner.0.contains(&held)?;
            if birth(&held)? != receipt.birth || process_image(&held)? != c.helper.canonicalize()? {
                bail!("SETUP: broker receipt identity mismatch");
            }
            installer.kill_owned(&owner.0)?;
            held.wait()?;
        } else if mutant {
            let start = Instant::now();
            while installer.alive()? {
                if start.elapsed() > TIMEOUT {
                    bail!("UNDETERMINED: mutant observer timeout");
                }
                thread::sleep(Duration::from_millis(10));
            }
            let mut code = 0;
            // SAFETY: retained owned installer handle, now signaled.
            if unsafe { GetExitCodeProcess(installer.0,&mut code) }==0||code!=42||fs::read(c.base.join("expected-red"))?!=b"EXPECTED_ASSERTION_FAILURE: actual-main-refused-after-helper-crash; observed exit0 same-binary version while installer alive" {bail!("SETUP/ASSERTION: no qualified retention-mutant assertion RED");}
        } else {
            wait_success(&installer).with_context(|| {
                format!(
                    "controller-error: {}",
                    fs::read_to_string(c.base.join("controller-error"))
                        .unwrap_or_else(|_| "missing structured controller error".into())
                )
            })?;
        }
        owner.0.empty()?;
    }
    if mode != "commit" {
        c.job.push_str("-after");
        let owner = JobOwner(Job::create(&c.job)?);
        let next = spawn_controller(&c, "probe", &owner.0)?;
        wait_success(&next)?;
        owner.0.empty()?;
    }
    tmp.close()
        .context("UNDETERMINED: owned fixture files still pinned")?;
    Ok(())
}
#[test]
fn native_installer_lease_suite() {
    let _env_guard = csq_core::platform::test_env::lock();
    let result = (|| -> Result<()> {
        if let Some(mode) = std::env::var_os(MODE) {
            let c: Config = serde_json::from_str(
                &required(CONFIG)?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("SETUP: config unicode"))?,
            )?;
            let result = controller(
                &c,
                &mode
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("SETUP: mode unicode"))?,
            );
            if let Err(ref e) = result {
                let _ = fs::write(c.base.join("controller-error"), format!("{e:#}"));
            }
            result?;
            return Ok(());
        }
        let expected = required("CSQ_TEST_FRESH_PRINCIPAL_SID")?
            .into_string()
            .map_err(|_| anyhow::anyhow!("SETUP: principal unicode"))?;
        if sid()? != expected {
            bail!("SETUP: runner is not the explicitly provisioned disposable principal");
        }
        let base = PathBuf::from(required("CSQ_TEST_NATIVE_SANDBOX_ROOT")?);
        if !base.is_absolute() || !base.is_dir() {
            bail!("SETUP: explicit fresh sandbox root required");
        }
        let system = required("SystemRoot")?;
        let helper = PathBuf::from(required("CSQ_TEST_INSTALLER_HELPER_PATH")?);
        let sha = required("CSQ_TEST_INSTALLER_HELPER_SHA256")?
            .into_string()
            .map_err(|_| anyhow::anyhow!("SETUP: helper SHA unicode"))?;
        let mutant = PathBuf::from(required("CSQ_TEST_RETENTION_MUTANT_HELPER_PATH")?);
        let mutant_sha = required("CSQ_TEST_RETENTION_MUTANT_HELPER_SHA256")?
            .into_string()
            .map_err(|_| anyhow::anyhow!("SETUP: counterfactual SHA unicode"))?;
        for mode in ["commit", "helper-crash", "installer-death"] {
            run_case(&base, &system, &expected, &helper, &sha, mode, false)?;
        }
        run_case(
            &base,
            &system,
            &expected,
            &mutant,
            &mutant_sha,
            "counterfactual",
            true,
        )?;
        Ok(())
    })();
    result.expect("native lease ASSERTION or SETUP/UNDETERMINED; never skipped");
}

// ROOT-only native landing gates. Provision two disposable principals in one
// nonzero session. Never run these on a maintainer profile. Fixture JSON carries
// no credentials/secrets; only owner/foreign SIDs, session, paths and HMAC names.
mod namespace_native_gates {
    use super::*;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        owner_sid: String,
        foreign_sid: String,
        session: u32,
        secret_path: PathBuf,
        native_lease: String,
        pipe_component: String,
        receipts: PathBuf,
    }
    #[repr(C)]
    struct Attributes {
        length: u32,
        root: H,
        name: *const UnicodeString,
        flags: u32,
        descriptor: *const c_void,
        qos: *const c_void,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenDirectoryObject(out: *mut H, access: u32, attrs: *const Attributes) -> i32;
        fn NtQueryDirectoryObject(
            h: H,
            out: *mut c_void,
            length: u32,
            single: u8,
            restart: u8,
            context: *mut u32,
            returned: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(attrs: *const c_void, owned: i32, name: *const u16) -> H;
        fn GetLastError() -> u32;
    }
    fn fixture(owner: bool) -> Result<Fixture> {
        let path = std::env::var_os("CSQ_NAMESPACE_DISPOSABLE_FIXTURE")
            .context("SETUP: ROOT disposable two-principal fixture required")?;
        let f: Fixture = serde_json::from_slice(&fs::read(path)?)?;
        let expected = if owner { &f.owner_sid } else { &f.foreign_sid };
        if f.session == 0
            || f.owner_sid == f.foreign_sid
            || &sid()? != expected
            || !f.secret_path.is_absolute()
            || !f.receipts.is_absolute()
            || !f.native_lease.starts_with(&format!(
                r"\Sessions\{}\BaseNamedObjects\csq-installer-lease-v2-",
                f.session
            ))
            || !f.pipe_component.starts_with("csq-installer-pipe-v2-")
        {
            bail!("SETUP: disposable principal fixture identity mismatch");
        }
        let mut raw = 0;
        // SAFETY: borrowed process and initialized token output.
        if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0 {
            bail!("SETUP: session token");
        }
        let token = Handle(raw);
        let (mut session, mut size) = (0u32, 0u32);
        // SAFETY: TokenSessionId returns a DWORD into live storage.
        if unsafe {
            GetTokenInformation(token.0, 12, (&mut session as *mut u32).cast(), 4, &mut size)
        } == 0
            || size != 4
            || session != f.session
        {
            bail!("SETUP: same-session proof failed");
        }
        Ok(f)
    }
    fn enumerate_local(directory: &str) -> Result<Option<Vec<String>>> {
        let words = wide(OsStr::new(directory));
        let name = UnicodeString {
            length: ((words.len() - 1) * 2) as u16,
            maximum: (words.len() * 2) as u16,
            buffer: words.as_ptr(),
        };
        let attrs = Attributes {
            length: mem::size_of::<Attributes>() as u32,
            root: 0,
            name: &name,
            flags: 0x40,
            descriptor: ptr::null(),
            qos: ptr::null(),
        };
        let mut raw = 0;
        // SAFETY: live OBJECT_ATTRIBUTES graph, DIRECTORY_QUERY only.
        let status = unsafe { NtOpenDirectoryObject(&mut raw, 1, &attrs) };
        if status as u32 == 0xc0000022 {
            return Ok(None);
        }
        if status < 0 {
            bail!("SETUP: Local directory open status {status:x}");
        }
        let handle = Handle(raw);
        let mut context = 0;
        let mut names = Vec::new();
        for index in 0..65536 {
            let mut storage = vec![0usize; 4096];
            let capacity = storage.len() * mem::size_of::<usize>();
            let mut returned = 0;
            // SAFETY: initialized aligned output, one entry per call, retained directory.
            let status = unsafe {
                NtQueryDirectoryObject(
                    handle.0,
                    storage.as_mut_ptr().cast(),
                    capacity as u32,
                    1,
                    u8::from(index == 0),
                    &mut context,
                    &mut returned,
                )
            };
            if status as u32 == 0x8000001a {
                return Ok(Some(names));
            }
            if status < 0 {
                bail!("SETUP: Local enumeration status {status:x}");
            }
            // SAFETY: successful single-entry output begins with UnicodeString.
            let value = unsafe { &*storage.as_ptr().cast::<UnicodeString>() };
            let base = storage.as_ptr() as usize;
            let at = value.buffer as usize;
            if value.length % 2 != 0
                || at < base
                || at
                    .checked_add(value.length as usize)
                    .is_none_or(|end| end > base + capacity)
            {
                bail!("SETUP: Local enumeration output bounds");
            }
            // SAFETY: counted UTF-16 range proved inside retained allocation.
            names.push(String::from_utf16(unsafe {
                std::slice::from_raw_parts(value.buffer, value.length as usize / 2)
            })?);
        }
        bail!("SETUP: Local enumeration did not terminate")
    }
    #[test]
    #[ignore = "requires ROOT disposable same-session distinct SID with owner lease+pipe active; run exact --ignored on foreign principal"]
    fn foreign_secret_read_refuses_and_enumeration_records_hmac_exposure() -> Result<()> {
        let _env = csq_core::platform::test_env::lock();
        let f = fixture(false)?;
        let error = File::open(&f.secret_path)
            .err()
            .context("ASSERTION: foreign SID read secret")?;
        if error.kind() != std::io::ErrorKind::PermissionDenied {
            bail!("SETUP: secret visibility not established; require access denied");
        }
        let dir = f
            .native_lease
            .rsplit_once('\\')
            .context("SETUP: native name")?
            .0;
        let local = enumerate_local(dir)?;
        let pipes: Vec<_> = fs::read_dir(r"\\.\pipe\")?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?;
        let component = f
            .native_lease
            .rsplit('\\')
            .next()
            .context("SETUP: lease component")?;
        // NPFS is an exposure oracle: owner-only DACLs do not hide pipe names.
        if !pipes.iter().any(|name| name == &f.pipe_component) {
            bail!("SETUP: active owner pipe not visible to enumeration oracle");
        }
        fs::write(
            f.receipts.join("enumeration.json"),
            serde_json::to_vec(&serde_json::json!({
                "foreign_sid": f.foreign_sid, "session": f.session,
                "secret_read": "access_denied", "pipe_hmac_seen": true,
                "local_query_denied": local.is_none(),
                "lease_hmac_seen": local.as_ref().is_some_and(|v| v.iter().any(|n| n == component))
            }))?,
        )?;
        Ok(())
    }
    #[test]
    #[ignore = "requires ROOT disposable foreign SID after observed owner lease closes; run exact --ignored alongside owner replay gate"]
    fn foreign_replays_observed_lease_until_owner_refuses() -> Result<()> {
        let _env = csq_core::platform::test_env::lock();
        let f = fixture(false)?;
        let component = f
            .native_lease
            .rsplit('\\')
            .next()
            .context("SETUP: lease component")?;
        let name = wide(OsStr::new(&format!("Local\\{component}")));
        // SAFETY: foreign fixture creates its own default-DACL object.
        let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        let existed = unsafe { GetLastError() } == 183;
        if raw == 0 {
            bail!("SETUP: foreign replay create failed");
        }
        let held = Handle(raw);
        if existed {
            bail!("SETUP: previous owner reference is still live");
        }
        fs::write(f.receipts.join("replay-ready"), f.foreign_sid.as_bytes())?;
        let until = Instant::now() + TIMEOUT;
        while !f.receipts.join("owner-refused").exists() {
            if Instant::now() >= until {
                bail!("ASSERTION: owner did not prove replay refusal");
            }
            thread::sleep(Duration::from_millis(20));
        }
        drop(held);
        Ok(())
    }
    #[test]
    #[ignore = "requires ROOT disposable owner SID while foreign gate holds replay mutex; run exact --ignored on owner principal"]
    fn owner_refuses_foreign_replayed_hmac_lease() -> Result<()> {
        let _env = csq_core::platform::test_env::lock();
        let f = fixture(true)?;
        let until = Instant::now() + TIMEOUT;
        while !f.receipts.join("replay-ready").exists() {
            if Instant::now() >= until {
                bail!("SETUP: foreign replay not ready");
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(f.receipts.join("replay-ready"))?,
            f.foreign_sid
        );
        let error = csq_core::update::installer_admission::windows::check()
            .err()
            .context("ASSERTION: replay admitted owner startup")?;
        assert!(error.chain().any(|e| matches!(
            e.to_string().as_str(),
            "foreign_user" | "control_unavailable"
        )));
        fs::write(f.receipts.join("owner-refused"), b"fail_closed")?;
        Ok(())
    }
}
