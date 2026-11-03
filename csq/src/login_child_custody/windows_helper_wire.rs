//! One-shot creator bootstrap. Payloads and handle values are never formatted.
//! A Born packet conveys values only: the receiver must pull and validate the
//! actual objects before granting them process-control authority. There is no ACK.

use std::{
    ffi::{c_void, OsStr, OsString},
    fmt, io, mem,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
        ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetProcessId, GetProcessTimes, OpenProcess,
            OpenProcessToken, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        },
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const HELPER_FLAG: &str = "--csq-private-vendor-creator-v1";
const PIPE_PREFIX: &str = r"\\.\pipe\csq-login-helper-v1-";
const MAX_FRAME: usize = 1_048_576;
const MAX_TEXT: usize = 32_767;
const HEADER: usize = 23;
const CANCEL_DRAIN: u32 = 2_000;

pub(crate) struct WireFailure {
    pub(crate) stage: &'static str,
    pub(crate) code: Option<i32>,
    pub(crate) cleanup_unconfirmed: bool,
    cause: io::Error,
    retained: Option<Mutex<Option<PendingIo>>>,
}
impl fmt::Debug for WireFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireFailure")
            .field("stage", &self.stage)
            .field("code", &self.code)
            .field("cleanup_unconfirmed", &self.cleanup_unconfirmed)
            .finish()
    }
}
impl WireFailure {
    /// Retry observation of the same pending operation. False retains every
    /// allocation and capability in this error for the next custody observation.
    pub(crate) fn retry_cleanup(&self) -> bool {
        let Some(retained) = self.retained.as_ref() else {
            return true;
        };
        let mut owner = match retained.lock() {
            Ok(owner) => owner,
            Err(poison) => poison.into_inner(),
        };
        let complete = owner.as_mut().is_none_or(PendingIo::drain);
        if complete {
            owner.take();
        }
        complete
    }
}
impl fmt::Display for WireFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "login_helper_wire stage={} win32={:?} cleanup_unconfirmed={}",
            self.stage, self.code, self.cleanup_unconfirmed
        )
    }
}
impl std::error::Error for WireFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
// Field disposal delegates to PendingIo::drop exactly once; doing an explicit
// retry here would spend a second cancellation wait before that destructor.
fn failure(stage: &'static str, error: io::Error, cleanup_unconfirmed: bool) -> io::Error {
    io::Error::new(
        error.kind(),
        WireFailure {
            stage,
            code: error.raw_os_error(),
            cleanup_unconfirmed,
            cause: error,
            retained: None,
        },
    )
}
fn retained_failure(stage: &'static str, error: io::Error, pending: PendingIo) -> io::Error {
    io::Error::new(
        error.kind(),
        WireFailure {
            stage,
            code: error.raw_os_error(),
            cleanup_unconfirmed: true,
            cause: error,
            retained: Some(Mutex::new(Some(pending))),
        },
    )
}
fn invalid() -> io::Error {
    failure(
        "invalid_packet",
        io::Error::from(io::ErrorKind::InvalidData),
        false,
    )
}
fn os_error(stage: &'static str) -> io::Error {
    failure(stage, io::Error::last_os_error(), false)
}
fn timed_out(stage: &'static str) -> io::Error {
    failure(stage, io::Error::from(io::ErrorKind::TimedOut), false)
}
fn raw(handle: &impl AsRawHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}
fn deadline(budget: Duration) -> io::Result<Instant> {
    if budget.is_zero() || budget > Duration::from_secs(60) {
        return Err(invalid());
    }
    Instant::now().checked_add(budget).ok_or_else(invalid)
}
fn milliseconds(end: Instant) -> u32 {
    end.saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32
}

pub(crate) struct BootstrapArgs {
    pub(crate) pipe_name: OsString,
    pub(crate) nonce: [u8; 16],
    pub(crate) creator_pid: u32,
    pub(crate) creator_birth: u64,
}
impl BootstrapArgs {
    /// Input includes `argv[0]`; output from `to_argv` deliberately does not.
    pub(crate) fn parse(argv: &[OsString]) -> io::Result<Option<Self>> {
        if !argv.iter().any(|arg| arg == HELPER_FLAG) {
            return Ok(None);
        }
        if argv.len() != 6 || argv.get(1).is_none_or(|arg| arg != HELPER_FLAG) {
            return Err(invalid());
        }
        let name = argv[2].to_str().ok_or_else(invalid)?;
        let suffix = name.strip_prefix(PIPE_PREFIX).ok_or_else(invalid)?;
        decode_hex(suffix)?;
        let nonce = decode_hex(argv[3].to_str().ok_or_else(invalid)?)?;
        let pid = decimal(&argv[4])?;
        let creator_pid = u32::try_from(pid).map_err(|_| invalid())?;
        let creator_birth = decimal(&argv[5])?;
        Ok(Some(Self {
            pipe_name: argv[2].clone(),
            nonce,
            creator_pid,
            creator_birth,
        }))
    }
    pub(crate) fn to_argv(&self) -> Vec<OsString> {
        vec![
            HELPER_FLAG.into(),
            self.pipe_name.clone(),
            hex(&self.nonce).into(),
            self.creator_pid.to_string().into(),
            self.creator_birth.to_string().into(),
        ]
    }
}
fn decimal(value: &OsStr) -> io::Result<u64> {
    let value = value.to_str().ok_or_else(invalid)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(invalid)
}
fn hex(value: &[u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in value {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
fn decode_hex(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32 {
        return Err(invalid());
    }
    let mut out = [0; 16];
    for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(invalid()),
        };
        out[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteKind {
    File,
    Pipe,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Input,
    Output,
}
pub(crate) enum StdioSlot {
    Null,
    LocalConsole,
    RemotePipeOrFile {
        handle: u64,
        kind: RemoteKind,
        direction: Direction,
    },
}
pub(crate) struct Recipe {
    /// All strings carry their Win32 terminators; environment has two.
    pub(crate) application: Vec<u16>,
    pub(crate) command_line: Vec<u16>,
    pub(crate) environment: Vec<u16>,
    pub(crate) current_dir: Option<Vec<u16>>,
    pub(crate) stdio: [StdioSlot; 3],
}
impl Drop for Recipe {
    fn drop(&mut self) {
        self.application.zeroize();
        self.command_line.zeroize();
        self.environment.zeroize();
        if let Some(value) = self.current_dir.as_mut() {
            value.zeroize();
        }
    }
}
pub(crate) struct Born {
    pub(crate) process_handle: u64,
    pub(crate) thread_handle: u64,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) birth: u64,
}
fn valid_handle(value: u64) -> bool {
    value != 0 && value != u64::MAX && usize::try_from(value).is_ok()
}
fn text(value: &[u16]) -> bool {
    (2..=MAX_TEXT).contains(&value.len())
        && value.last() == Some(&0)
        && !value[..value.len() - 1].contains(&0)
}
fn absolute(value: &[u16]) -> bool {
    text(value)
        && std::path::Path::new(&OsString::from_wide(&value[..value.len() - 1])).is_absolute()
}
impl Recipe {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if !absolute(&self.application)
            || !text(&self.command_line)
            || self
                .current_dir
                .as_ref()
                .is_some_and(|value| !absolute(value))
            || self.environment.len() < 2
            || !self.environment.ends_with(&[0, 0])
            || self.environment.len() > MAX_FRAME / 2
        {
            return Err(invalid());
        }
        let mut cursor = 0;
        while cursor < self.environment.len() - 1 {
            let count = self.environment[cursor..]
                .iter()
                .position(|unit| *unit == 0)
                .ok_or_else(invalid)?;
            if count == 0 {
                if cursor != self.environment.len() - 2 {
                    return Err(invalid());
                }
                break;
            }
            if count > MAX_TEXT {
                return Err(invalid());
            }
            let entry = &self.environment[cursor..cursor + count];
            let start = usize::from(entry[0] == 61);
            if !entry
                .iter()
                .enumerate()
                .skip(start)
                .any(|(index, unit)| index != 0 && *unit == 61)
            {
                return Err(invalid());
            }
            cursor += count + 1;
        }
        let mut seen = Vec::new();
        for (index, slot) in self.stdio.iter().enumerate() {
            if let StdioSlot::RemotePipeOrFile {
                handle, direction, ..
            } = slot
            {
                if !valid_handle(*handle)
                    || (*direction == Direction::Input) != (index == 0)
                    || seen.contains(handle)
                {
                    return Err(invalid());
                }
                seen.push(*handle);
            }
        }
        Ok(())
    }
}
struct Encoder(Zeroizing<Vec<u8>>);
impl Encoder {
    fn bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len > MAX_FRAME)
        {
            return Err(invalid());
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn units(&mut self, units: &[u16]) -> io::Result<()> {
        self.bytes(
            &u32::try_from(units.len())
                .map_err(|_| invalid())?
                .to_le_bytes(),
        )?;
        if units.len() > (MAX_FRAME - self.0.len()) / 2 {
            return Err(invalid());
        }
        for unit in units {
            self.bytes(&unit.to_le_bytes())?;
        }
        Ok(())
    }
}
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn bytes(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(invalid)?;
        let value = &self.bytes[self.at..end];
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(
            self.bytes(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            self.bytes(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn units(&mut self) -> io::Result<Vec<u16>> {
        let count = self.u32()? as usize;
        let bytes = self.bytes(count.checked_mul(2).ok_or_else(invalid)?)?;
        Ok(bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect())
    }
    fn end(self) -> io::Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
fn envelope(kind: u8, nonce: &[u8; 16]) -> io::Result<Encoder> {
    let mut out = Encoder(Zeroizing::new(Vec::new()));
    out.bytes(b"CSQH")?;
    out.bytes(&1u16.to_le_bytes())?;
    out.bytes(&[kind])?;
    out.bytes(nonce)?;
    Ok(out)
}
fn payload<'a>(bytes: &'a [u8], kind: u8, nonce: &[u8; 16]) -> io::Result<Decoder<'a>> {
    if !(HEADER..=MAX_FRAME).contains(&bytes.len())
        || bytes[..4] != *b"CSQH"
        || bytes[4..6] != 1u16.to_le_bytes()
        || bytes[6] != kind
        || bytes[7..23] != nonce[..]
    {
        return Err(invalid());
    }
    Ok(Decoder { bytes, at: HEADER })
}
fn encode_recipe(recipe: &Recipe, nonce: &[u8; 16]) -> io::Result<Zeroizing<Vec<u8>>> {
    recipe.validate()?;
    let mut out = envelope(1, nonce)?;
    out.units(&recipe.application)?;
    out.units(&recipe.command_line)?;
    out.units(&recipe.environment)?;
    match recipe.current_dir.as_ref() {
        Some(value) => {
            out.bytes(&[1])?;
            out.units(value)?;
        }
        None => out.bytes(&[0])?,
    }
    for slot in &recipe.stdio {
        match slot {
            StdioSlot::Null => out.bytes(&[0])?,
            StdioSlot::LocalConsole => out.bytes(&[1])?,
            StdioSlot::RemotePipeOrFile {
                handle,
                kind,
                direction,
            } => {
                out.bytes(&[
                    2,
                    if *kind == RemoteKind::File { 0 } else { 1 },
                    if *direction == Direction::Input { 0 } else { 1 },
                ])?;
                out.bytes(&handle.to_le_bytes())?;
            }
        }
    }
    Ok(out.0)
}
fn decode_recipe(bytes: &[u8], nonce: &[u8; 16]) -> io::Result<Recipe> {
    let mut input = payload(bytes, 1, nonce)?;
    let mut recipe = Recipe {
        application: Vec::new(),
        command_line: Vec::new(),
        environment: Vec::new(),
        current_dir: None,
        stdio: [StdioSlot::Null, StdioSlot::Null, StdioSlot::Null],
    };
    recipe.application = input.units()?;
    recipe.command_line = input.units()?;
    recipe.environment = input.units()?;
    match input.bytes(1)?[0] {
        0 => {}
        1 => recipe.current_dir = Some(input.units()?),
        _ => return Err(invalid()),
    }
    for slot in &mut recipe.stdio {
        *slot = match input.bytes(1)?[0] {
            0 => StdioSlot::Null,
            1 => StdioSlot::LocalConsole,
            2 => {
                let kind = match input.bytes(1)?[0] {
                    0 => RemoteKind::File,
                    1 => RemoteKind::Pipe,
                    _ => return Err(invalid()),
                };
                let direction = match input.bytes(1)?[0] {
                    0 => Direction::Input,
                    1 => Direction::Output,
                    _ => return Err(invalid()),
                };
                StdioSlot::RemotePipeOrFile {
                    handle: input.u64()?,
                    kind,
                    direction,
                }
            }
            _ => return Err(invalid()),
        };
    }
    input.end()?;
    recipe.validate()?;
    Ok(recipe)
}
fn encode_born(born: &Born, nonce: &[u8; 16]) -> io::Result<Zeroizing<Vec<u8>>> {
    if !valid_handle(born.process_handle)
        || !valid_handle(born.thread_handle)
        || born.process_handle == born.thread_handle
        || born.pid == 0
        || born.tid == 0
        || born.birth == 0
    {
        return Err(invalid());
    }
    let mut out = envelope(2, nonce)?;
    out.bytes(&born.process_handle.to_le_bytes())?;
    out.bytes(&born.thread_handle.to_le_bytes())?;
    out.bytes(&born.pid.to_le_bytes())?;
    out.bytes(&born.tid.to_le_bytes())?;
    out.bytes(&born.birth.to_le_bytes())?;
    Ok(out.0)
}
fn decode_born(bytes: &[u8], nonce: &[u8; 16]) -> io::Result<Born> {
    let mut input = payload(bytes, 2, nonce)?;
    let born = Born {
        process_handle: input.u64()?,
        thread_handle: input.u64()?,
        pid: input.u32()?,
        tid: input.u32()?,
        birth: input.u64()?,
    };
    input.end()?;
    encode_born(&born, nonce)?;
    Ok(born)
}
fn kind_code(kind: io::ErrorKind) -> u8 {
    use io::ErrorKind::*;
    match kind {
        NotFound => 1,
        PermissionDenied => 2,
        InvalidInput => 3,
        InvalidData => 4,
        TimedOut => 5,
        Interrupted => 6,
        Unsupported => 7,
        AlreadyExists => 8,
        WouldBlock => 9,
        UnexpectedEof => 10,
        BrokenPipe => 11,
        WriteZero => 12,
        _ => 0,
    }
}
fn decode_kind(code: u8) -> io::Result<io::ErrorKind> {
    use io::ErrorKind::*;
    Ok(match code {
        0 => Other,
        1 => NotFound,
        2 => PermissionDenied,
        3 => InvalidInput,
        4 => InvalidData,
        5 => TimedOut,
        6 => Interrupted,
        7 => Unsupported,
        8 => AlreadyExists,
        9 => WouldBlock,
        10 => UnexpectedEof,
        11 => BrokenPipe,
        12 => WriteZero,
        _ => return Err(invalid()),
    })
}
fn encode_failure(error: &io::Error, nonce: &[u8; 16]) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = envelope(3, nonce)?;
    out.bytes(&[kind_code(error.kind())])?;
    match error.raw_os_error() {
        Some(code) => {
            out.bytes(&[1])?;
            out.bytes(&code.to_le_bytes())?;
        }
        None => out.bytes(&[0])?,
    }
    Ok(out.0)
}
fn decode_failure(bytes: &[u8], nonce: &[u8; 16]) -> io::Result<io::Error> {
    let mut input = payload(bytes, 3, nonce)?;
    let kind = decode_kind(input.bytes(1)?[0])?;
    let result = match input.bytes(1)?[0] {
        0 => io::Error::from(kind),
        1 => io::Error::from_raw_os_error(i32::from_le_bytes(
            input.bytes(4)?.try_into().map_err(|_| invalid())?,
        )),
        _ => return Err(invalid()),
    };
    input.end()?;
    Ok(result)
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: sole owner of a successful LocalAlloc-backed API allocation.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn owner_security() -> io::Result<Local> {
    let mut token = 0;
    // SAFETY: pseudo process handle and initialized owned-handle output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_error("token_open"));
    }
    // SAFETY: successful call transferred one token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
    let mut needed = 0;
    // SAFETY: documented zero-size token-user query.
    let queried =
        unsafe { GetTokenInformation(raw(&token), TokenUser, ptr::null_mut(), 0, &mut needed) };
    if queried == 0 {
        // SAFETY: capture the actual size-query failure before another API call.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(failure(
                "token_user_size",
                io::Error::from_raw_os_error(code as i32),
                false,
            ));
        }
    }
    if !(mem::size_of::<TOKEN_USER>() as u32..=65_536).contains(&needed) {
        return Err(invalid());
    }
    let mut user = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
    // SAFETY: aligned storage has at least needed bytes; output remains live.
    if unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            user.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(os_error("token_user"));
    }
    // SAFETY: buffer was filled as TOKEN_USER and lives through SID conversion.
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut sid_text = ptr::null_mut();
    // SAFETY: valid token SID, LocalAlloc-owned string output.
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
        return Err(os_error("token_sid"));
    }
    let sid_owner = Local(sid_text.cast());
    let mut length = 0;
    // SAFETY: successful conversion returns a terminated SID string. Bound the
    // scan to the maximum textual SID representation before copying it.
    while length < 184 && unsafe { *sid_text.add(length) } != 0 {
        length += 1;
    }
    if length == 184 {
        return Err(invalid());
    }
    // SAFETY: the bounded prefix belongs to the retained SID string.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .map_err(|_| invalid())?;
    drop(sid_owner);
    let text: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: terminated SDDL; descriptor becomes uniquely LocalAlloc-owned.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error("pipe_security"));
    }
    Ok(Local(descriptor))
}
fn process_identity(handle: HANDLE) -> io::Result<(u32, u64)> {
    // SAFETY: caller retains the actual process handle throughout these queries.
    let pid = unsafe { GetProcessId(handle) };
    if pid == 0 {
        return Err(os_error("peer_pid"));
    }
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
    );
    // SAFETY: retained process and four valid FILETIME output slots.
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(os_error("peer_birth"));
    }
    let birth = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    // SAFETY: bounded liveness observation on the same original object.
    match unsafe { WaitForSingleObject(handle, 0) } {
        258 if birth != 0 => Ok((pid, birth)),
        u32::MAX => Err(os_error("peer_live")),
        _ => Err(failure(
            "peer_exited",
            io::Error::from(io::ErrorKind::BrokenPipe),
            false,
        )),
    }
}

#[cfg(test)]
std::thread_local! {
    static DRAIN_REFUSALS: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
    static DRAIN_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CAPTURE_IO_RETENTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RETAINED_IO: std::cell::RefCell<Option<PendingIo>> = const { std::cell::RefCell::new(None) };
}
struct PendingIo {
    pipe: Arc<OwnedHandle>,
    event: Option<OwnedHandle>,
    overlapped: Option<Box<OVERLAPPED>>,
    buffer: Option<Zeroizing<Vec<u8>>>,
    pending: bool,
}
// SAFETY: all kernel-facing addresses are heap-stable and exclusively owned.
// A moved pending owner is accessed only under WireFailure's Mutex; its buffer
// is neither read nor freed until the operation is confirmed complete.
unsafe impl Send for PendingIo {}
impl PendingIo {
    fn new(pipe: Arc<OwnedHandle>, buffer: Vec<u8>) -> io::Result<Self> {
        // SAFETY: unnamed noninheritable manual-reset event, initially clear.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event == 0 {
            return Err(os_error("io_event"));
        }
        // SAFETY: successful event creation transfers unique ownership.
        let event = unsafe { OwnedHandle::from_raw_handle(event as _) };
        // SAFETY: OVERLAPPED is a zeroable Win32 input/output structure.
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { mem::zeroed() });
        overlapped.hEvent = raw(&event);
        Ok(Self {
            pipe,
            event: Some(event),
            overlapped: Some(overlapped),
            buffer: Some(Zeroizing::new(buffer)),
            pending: false,
        })
    }
    fn ov(&mut self) -> *mut OVERLAPPED {
        self.overlapped
            .as_mut()
            .map_or(ptr::null_mut(), |value| &mut **value)
    }
    fn drain(&mut self) -> bool {
        #[cfg(test)]
        if DRAIN_REFUSALS.with(|slot| {
            slot.get().is_some_and(|remaining| {
                DRAIN_ATTEMPTS.with(|count| count.set(count.get() + 1));
                slot.set(Some(remaining.saturating_sub(1)));
                remaining != 0
            })
        }) {
            return false;
        }
        if !self.pending {
            return true;
        }
        let ov = self.ov();
        // SAFETY: the exact operation, pipe, event and heap buffer remain owned.
        unsafe {
            CancelIoEx(raw(self.pipe.as_ref()), ov);
        }
        // SAFETY: retained operation event, bounded cancellation drain.
        let Some(event) = self.event.as_ref() else {
            return false;
        };
        if unsafe { WaitForSingleObject(raw(event), CANCEL_DRAIN) } != 0 {
            return false;
        }
        let mut transferred = 0;
        // SAFETY: signaled operation; query only, never a blocking wait.
        let done = unsafe { GetOverlappedResult(raw(self.pipe.as_ref()), ov, &mut transferred, 0) };
        // SAFETY: immediately inspect this call's actual failure code.
        if done == 0 && unsafe { GetLastError() } == ERROR_IO_INCOMPLETE {
            return false;
        }
        self.pending = false;
        true
    }
    fn run(mut self, kind: u8, end: Instant) -> io::Result<Zeroizing<Vec<u8>>> {
        if Instant::now() >= end {
            return Err(timed_out("io_deadline"));
        }
        let ov = self.ov();
        let buffer = self.buffer.as_mut().ok_or_else(invalid)?;
        // SAFETY: all pointers reference retained heap allocations; no borrowed
        // caller buffer can disappear while the operation is pending.
        let started = unsafe {
            match kind {
                0 => ConnectNamedPipe(raw(self.pipe.as_ref()), ov),
                1 => ReadFile(
                    raw(self.pipe.as_ref()),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    ov,
                ),
                _ => WriteFile(
                    raw(self.pipe.as_ref()),
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    ov,
                ),
            }
        };
        if started == 0 {
            // SAFETY: immediately retain the actual start failure.
            let code = unsafe { GetLastError() };
            if kind == 0 && code == ERROR_PIPE_CONNECTED {
                return Ok(Zeroizing::new(Vec::new()));
            }
            if code != ERROR_IO_PENDING {
                return Err(failure(
                    "io_start",
                    io::Error::from_raw_os_error(code as i32),
                    false,
                ));
            }
            self.pending = true;
            // SAFETY: own event and whole-operation deadline.
            let wait = unsafe {
                WaitForSingleObject(
                    raw(self.event.as_ref().ok_or_else(invalid)?),
                    milliseconds(end),
                )
            };
            if wait != 0 {
                let error = if wait == 258 {
                    io::Error::from(io::ErrorKind::TimedOut)
                } else {
                    io::Error::last_os_error()
                };
                if !self.drain() {
                    return Err(retained_failure("io_wait", error, self));
                }
                return Err(failure("io_wait", error, false));
            }
        }
        let mut count = 0;
        // SAFETY: either immediate success or a signaled retained OVERLAPPED.
        let complete = unsafe { GetOverlappedResult(raw(self.pipe.as_ref()), ov, &mut count, 0) };
        if complete == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32) {
                self.pending = true;
                if !self.drain() {
                    return Err(retained_failure("io_complete", error, self));
                }
                return Err(failure("io_complete", error, false));
            }
            self.pending = false;
            return Err(failure("io_complete", error, false));
        }
        self.pending = false;
        let mut buffer = self.buffer.take().ok_or_else(invalid)?;
        if count as usize > buffer.len() {
            return Err(invalid());
        }
        if kind == 2 {
            buffer.zeroize();
            buffer.resize(count as usize, 0);
        } else {
            buffer.truncate(count as usize);
        }
        Ok(buffer)
    }
}
impl Drop for PendingIo {
    fn drop(&mut self) {
        // One cancellation wait is bounded by CANCEL_DRAIN. Failed cancellation
        // cannot free a kernel-facing OVERLAPPED, buffer, event or endpoint.
        if !self.drain() {
            let retained = Self {
                pipe: Arc::clone(&self.pipe),
                event: self.event.take(),
                overlapped: self.overlapped.take(),
                buffer: self.buffer.take(),
                pending: std::mem::replace(&mut self.pending, false),
            };
            retain_unresolved_io(retained);
            eprintln!("login_windows_wire_cleanup_unconfirmed: original I/O retained");
        }
    }
}

fn retain_unresolved_io(pending: PendingIo) {
    #[cfg(test)]
    if CAPTURE_IO_RETENTION.with(std::cell::Cell::get) {
        RETAINED_IO.with(|slot| {
            let previous = slot.borrow_mut().replace(pending);
            assert!(previous.is_none(), "retained I/O test owner collision");
        });
        return;
    }
    std::mem::forget(pending);
}

struct Channel {
    pipe: Arc<OwnedHandle>,
    end: Instant,
    nonce: [u8; 16],
}
impl Channel {
    fn read_exact(&self, count: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        if count > MAX_FRAME {
            return Err(invalid());
        }
        let mut out = Zeroizing::new(Vec::with_capacity(count));
        while out.len() < count {
            let bytes =
                PendingIo::new(self.pipe.clone(), vec![0; count - out.len()])?.run(1, self.end)?;
            if bytes.is_empty() {
                return Err(failure(
                    "pipe_eof",
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                    false,
                ));
            }
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
    fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let mut at = 0;
        while at < bytes.len() {
            let written = PendingIo::new(self.pipe.clone(), bytes[at..].to_vec())?
                .run(2, self.end)?
                .len();
            if written == 0 {
                return Err(failure(
                    "pipe_zero_write",
                    io::Error::from(io::ErrorKind::WriteZero),
                    false,
                ));
            }
            at += written;
        }
        Ok(())
    }
    fn read_frame(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let prefix = self.read_exact(4)?;
        let count = u32::from_le_bytes(prefix[..].try_into().map_err(|_| invalid())?) as usize;
        if !(HEADER..=MAX_FRAME).contains(&count) {
            return Err(invalid());
        }
        self.read_exact(count)
    }
    fn write_frame(&self, bytes: &[u8]) -> io::Result<()> {
        if !(HEADER..=MAX_FRAME).contains(&bytes.len()) {
            return Err(invalid());
        }
        self.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.write_all(bytes)
    }
}
pub(crate) struct Server {
    pipe: Option<Arc<OwnedHandle>>,
    name: OsString,
    nonce: [u8; 16],
}
impl Server {
    pub(crate) fn create() -> io::Result<Self> {
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut random[..])
            .map_err(|_| failure("random", io::Error::from(io::ErrorKind::Other), false))?;
        let mut name_random = [0; 16];
        name_random.copy_from_slice(&random[..16]);
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&random[16..]);
        let name: OsString = format!("{PIPE_PREFIX}{}", hex(&name_random)).into();
        let wide: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
        let security = owner_security()?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        // SAFETY: terminated random name, explicit current-user-only protected
        // DACL, one first-instance server, remote rejection, no handle inheritance.
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65_536,
                65_536,
                0,
                &attrs,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(os_error("pipe_create"));
        }
        // SAFETY: successful creation transferred a unique pipe handle.
        let pipe = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        Ok(Self {
            pipe: Some(Arc::new(pipe)),
            name,
            nonce,
        })
    }
    pub(crate) fn bootstrap_args(&self, creator_pid: u32, creator_birth: u64) -> BootstrapArgs {
        BootstrapArgs {
            pipe_name: self.name.clone(),
            nonce: self.nonce,
            creator_pid,
            creator_birth,
        }
    }
    pub(crate) fn exchange(
        &mut self,
        helper: BorrowedHandle<'_>,
        recipe: &Recipe,
        budget: Duration,
    ) -> io::Result<Born> {
        let pipe = self.pipe.take().ok_or_else(invalid)?;
        let channel = Channel {
            pipe,
            end: deadline(budget)?,
            nonce: self.nonce,
        };
        let expected = process_identity(raw(&helper))?;
        let encoded = encode_recipe(recipe, &self.nonce)?;
        PendingIo::new(channel.pipe.clone(), Vec::new())?.run(0, channel.end)?;
        let mut observed = 0;
        // SAFETY: connected server pipe and valid kernel client-PID output.
        if unsafe { GetNamedPipeClientProcessId(raw(channel.pipe.as_ref()), &mut observed) } == 0 {
            return Err(os_error("client_pid"));
        }
        if observed != expected.0 || process_identity(raw(&helper))? != expected {
            return Err(failure(
                "client_identity",
                io::Error::from(io::ErrorKind::PermissionDenied),
                false,
            ));
        }
        channel.write_frame(&encoded)?;
        let reply = channel.read_frame()?;
        if reply.get(6) == Some(&3) {
            return Err(decode_failure(&reply, &self.nonce)?);
        }
        let born = decode_born(&reply, &self.nonce)?;
        if process_identity(raw(&helper))? != expected {
            return Err(invalid());
        }
        Ok(born)
    }
}
enum ClientState {
    Recipe,
    Born,
    Closed,
}
pub(crate) struct Client {
    channel: Channel,
    state: ClientState,
    _creator: OwnedHandle,
}
impl Client {
    pub(crate) fn connect(args: &BootstrapArgs, budget: Duration) -> io::Result<Self> {
        // Revalidate even programmatically constructed args; never connect to an
        // arbitrary device pathname supplied through a forged bootstrap value.
        let mut argv = vec![OsString::from("csq")];
        argv.extend(args.to_argv());
        BootstrapArgs::parse(&argv)?.ok_or_else(invalid)?;
        let end = deadline(budget)?;
        // SAFETY: query/synchronize rights only. This handle grants no terminate,
        // duplicate-handle, VM-write or Job authority over the creator.
        let creator = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
                0,
                args.creator_pid,
            )
        };
        if creator == 0 {
            return Err(os_error("server_open"));
        }
        // SAFETY: successful OpenProcess transferred unique ownership.
        let creator = unsafe { OwnedHandle::from_raw_handle(creator as _) };
        if process_identity(raw(&creator))? != (args.creator_pid, args.creator_birth) {
            return Err(invalid());
        }
        let name: Vec<u16> = args.pipe_name.encode_wide().chain(Some(0)).collect();
        let pipe = loop {
            if Instant::now() >= end {
                return Err(timed_out("client_connect"));
            }
            // SAFETY: validated local pipe name, noninheritable client handle,
            // overlapped I/O and identification-only server impersonation level.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    0,
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                // SAFETY: successful open transferred unique client ownership.
                break unsafe { OwnedHandle::from_raw_handle(handle as _) };
            }
            let error = io::Error::last_os_error();
            if !error
                .raw_os_error()
                .is_some_and(|code| code == 2 || code == ERROR_PIPE_BUSY as i32)
            {
                return Err(failure("client_connect", error, false));
            }
            if process_identity(raw(&creator))? != (args.creator_pid, args.creator_birth) {
                return Err(invalid());
            }
            std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            );
        };
        let mut pid = 0;
        // SAFETY: connected client handle and initialized server-PID output.
        if unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut pid) } == 0 {
            return Err(os_error("server_pid"));
        }
        if pid != args.creator_pid
            || process_identity(raw(&creator))? != (args.creator_pid, args.creator_birth)
        {
            return Err(failure(
                "server_identity",
                io::Error::from(io::ErrorKind::PermissionDenied),
                false,
            ));
        }
        Ok(Self {
            channel: Channel {
                pipe: Arc::new(pipe),
                end,
                nonce: args.nonce,
            },
            state: ClientState::Recipe,
            _creator: creator,
        })
    }
    pub(crate) fn receive_recipe(&mut self) -> io::Result<Recipe> {
        if !matches!(self.state, ClientState::Recipe) {
            return Err(invalid());
        }
        self.state = ClientState::Closed;
        let recipe = decode_recipe(&self.channel.read_frame()?, &self.channel.nonce)?;
        self.state = ClientState::Born;
        Ok(recipe)
    }
    pub(crate) fn send_born(&mut self, born: &Born) -> io::Result<()> {
        if !matches!(self.state, ClientState::Born) {
            return Err(invalid());
        }
        self.state = ClientState::Closed;
        self.channel
            .write_frame(&encode_born(born, &self.channel.nonce)?)
    }
    pub(crate) fn send_failure(&mut self, error: &io::Error) -> io::Result<()> {
        if !matches!(self.state, ClientState::Born) {
            return Err(invalid());
        }
        self.state = ClientState::Closed;
        // Only classification and the original numeric OS code cross the wire;
        // arbitrary upstream messages, paths and error chains are never copied.
        self.channel
            .write_frame(&encode_failure(error, &self.channel.nonce)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_pending_io_drop_attempts_once_and_retains_kernel_storage() {
        let mut server = Server::create().expect("private pipe");
        let pipe = server.pipe.take().expect("owned endpoint");
        let mut pending = PendingIo::new(pipe, vec![0; 32]).unwrap();
        let ov = pending.ov();
        // Start a real overlapped connect with no client. The retained owner
        // must keep the exact kernel-facing allocation alive after Drop refuses.
        assert_eq!(
            unsafe { ConnectNamedPipe(raw(pending.pipe.as_ref()), ov) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
        pending.pending = true;
        let pipe_handle = raw(pending.pipe.as_ref());
        let event_handle = raw(pending.event.as_ref().unwrap());
        let current = unsafe { GetCurrentProcess() };
        let event_observer = super::super::duplicate(current, event_handle, current, false)
            .expect("independent observation of the original I/O event");
        let buffer_ptr = pending.buffer.as_ref().unwrap().as_ptr();
        CAPTURE_IO_RETENTION.with(|flag| flag.set(true));
        DRAIN_ATTEMPTS.with(|count| count.set(0));
        DRAIN_REFUSALS.with(|slot| slot.set(Some(2)));
        drop(pending);
        let attempts = DRAIN_ATTEMPTS.with(std::cell::Cell::get);
        DRAIN_REFUSALS.with(|slot| slot.set(None));
        CAPTURE_IO_RETENTION.with(|flag| flag.set(false));
        let mut retained = RETAINED_IO.with(|slot| slot.borrow_mut().take());
        let same_storage = retained.as_mut().is_some_and(|pending| {
            pending.ov() == ov
                && raw(pending.pipe.as_ref()) == pipe_handle
                && pending
                    .event
                    .as_ref()
                    .is_some_and(|event| raw(event) == event_handle)
                && pending
                    .buffer
                    .as_ref()
                    .is_some_and(|buffer| buffer.as_ptr() == buffer_ptr)
        });
        let cleanup = retained.as_mut().is_none_or(PendingIo::drain);
        assert!(cleanup, "actual retained OVERLAPPED cancellation completed");
        drop(retained);
        // No code signals this dedicated event: the native I/O completion is
        // independently observed even when a mutant consumed the owner itself.
        assert_eq!(
            unsafe { WaitForSingleObject(raw(&event_observer), CANCEL_DRAIN) },
            0,
            "original overlapped operation actually completed"
        );
        eprintln!("PENDING_IO_CLEANUP_CONFIRMED");
        if attempts != 1 || !same_storage {
            eprintln!("PENDING_IO_DROP_MUST_ATTEMPT_ONCE_AND_RETAIN_STORAGE");
        }
        assert_eq!(
            attempts, 1,
            "pending I/O destructor retried on caller stack"
        );
        assert!(
            same_storage,
            "pending I/O destructor lost kernel-facing storage"
        );
    }
    fn recipe() -> Recipe {
        Recipe {
            application: vec![67, 58, 92, 65, 0],
            command_line: vec![34, 65, 34, 0],
            environment: vec![65, 61, 0xd800, 0, 0],
            current_dir: Some(vec![67, 58, 92, 0]),
            stdio: [
                StdioSlot::LocalConsole,
                StdioSlot::RemotePipeOrFile {
                    handle: 4,
                    kind: RemoteKind::Pipe,
                    direction: Direction::Output,
                },
                StdioSlot::Null,
            ],
        }
    }
    #[test]
    fn recipe_preserves_surrogates_and_rejects_wrong_nonce_trailing_and_truncation() {
        let mut source = recipe();
        source.command_line = vec![65, 0xd800, 0];
        let encoded = encode_recipe(&source, &[7; 16]).unwrap();
        let decoded = decode_recipe(&encoded, &[7; 16]).unwrap();
        assert!(
            decoded.command_line == source.command_line
                && decoded.environment == source.environment
        );
        assert!(decode_recipe(&encoded, &[8; 16]).is_err());
        for end in 0..encoded.len() {
            assert!(decode_recipe(&encoded[..end], &[7; 16]).is_err());
        }
        let mut extra = encoded.to_vec();
        extra.push(0);
        assert!(decode_recipe(&extra, &[7; 16]).is_err());
    }
    #[test]
    fn recipe_refuses_oversize_bad_terminators_modes_and_handle_values() {
        let mut value = recipe();
        value.application = vec![65; MAX_TEXT + 1];
        assert!(encode_recipe(&value, &[0; 16]).is_err());
        value = recipe();
        value.environment = vec![65, 61, 66, 0, 0, 65, 61, 66, 0, 0];
        assert!(value.validate().is_err());
        value = recipe();
        value.command_line = vec![65, 0, 66, 0];
        assert!(value.validate().is_err());
        value = recipe();
        value.stdio[0] = StdioSlot::RemotePipeOrFile {
            handle: 4,
            kind: RemoteKind::File,
            direction: Direction::Output,
        };
        assert!(value.validate().is_err());
        value = recipe();
        value.stdio[1] = StdioSlot::RemotePipeOrFile {
            handle: u64::MAX,
            kind: RemoteKind::Pipe,
            direction: Direction::Output,
        };
        assert!(value.validate().is_err());
        value = recipe();
        value.stdio[2] = StdioSlot::RemotePipeOrFile {
            handle: 4,
            kind: RemoteKind::Pipe,
            direction: Direction::Output,
        };
        assert!(value.validate().is_err());
        value = recipe();
        value.application = vec![65, 0];
        assert!(value.validate().is_err());
        value = recipe();
        value.environment = vec![65; MAX_FRAME];
        assert!(encode_recipe(&value, &[0; 16]).is_err());
    }
    #[test]
    fn born_is_one_exact_nonce_bound_packet_without_ack_or_extra_fields() {
        let value = Born {
            process_handle: 4,
            thread_handle: 8,
            pid: 1,
            tid: 2,
            birth: 3,
        };
        let bytes = encode_born(&value, &[9; 16]).unwrap();
        assert_eq!(decode_born(&bytes, &[9; 16]).unwrap().birth, 3);
        assert!(decode_born(&bytes, &[8; 16]).is_err());
        assert!(decode_recipe(&bytes, &[9; 16]).is_err());
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(decode_born(&extra, &[9; 16]).is_err());
    }
    #[test]
    fn bootstrap_is_exact_bounded_and_contains_no_recipe_or_remote_handles() {
        let args = BootstrapArgs {
            pipe_name: format!("{PIPE_PREFIX}{}", hex(&[1; 16])).into(),
            nonce: [2; 16],
            creator_pid: 3,
            creator_birth: 4,
        };
        let mut argv = vec![OsString::from("csq")];
        argv.extend(args.to_argv());
        let parsed = BootstrapArgs::parse(&argv).unwrap().unwrap();
        assert_eq!(parsed.nonce, [2; 16]);
        assert_eq!(parsed.creator_birth, 4);
        argv.push("extra".into());
        assert!(BootstrapArgs::parse(&argv).is_err());
        argv.pop();
        argv.swap(1, 2);
        assert!(BootstrapArgs::parse(&argv).is_err());
        assert!(BootstrapArgs::parse(&["csq".into(), "normal".into()])
            .unwrap()
            .is_none());
    }
    #[test]
    fn helper_failure_preserves_native_code_but_drops_secret_messages() {
        let native = io::Error::from_raw_os_error(2);
        let packet = encode_failure(&native, &[7; 16]).unwrap();
        let decoded = decode_failure(&packet, &[7; 16]).unwrap();
        assert_eq!(decoded.kind(), io::ErrorKind::NotFound);
        assert_eq!(decoded.raw_os_error(), Some(2));
        let secret = io::Error::new(io::ErrorKind::Unsupported, "FAKETEST_PRIVATE_PAYLOAD");
        let packet = encode_failure(&secret, &[7; 16]).unwrap();
        assert!(!packet.windows(8).any(|part| part == b"FAKETEST"));
        assert_eq!(
            decode_failure(&packet, &[7; 16]).unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(decode_failure(&packet, &[8; 16]).is_err());
    }
    fn own_process() -> OwnedHandle {
        // SAFETY: open only this test process, query/synchronize permissions.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
                0,
                std::process::id(),
            )
        };
        assert_ne!(handle, 0);
        // SAFETY: successful open transferred a single owned process handle.
        unsafe { OwnedHandle::from_raw_handle(handle as _) }
    }
    #[test]
    fn real_private_pipe_authenticates_and_permits_only_one_recipe_reply() {
        use std::os::windows::io::AsHandle;
        let process = own_process();
        let (pid, birth) = process_identity(raw(&process)).unwrap();
        let mut server = Server::create().unwrap();
        let args = server.bootstrap_args(pid, birth);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut client = Client::connect(&args, Duration::from_secs(5)).unwrap();
            ready_tx.send(()).unwrap();
            let received = client.receive_recipe().unwrap();
            assert_eq!(received.environment, vec![65, 61, 0xd800, 0, 0]);
            assert!(client.receive_recipe().is_err());
            let born = Born {
                process_handle: 4,
                thread_handle: 8,
                pid: 10,
                tid: 11,
                birth: 12,
            };
            client.send_born(&born).unwrap();
            assert!(client.send_born(&born).is_err());
        });
        // Force the legitimate client to connect before ConnectNamedPipe so
        // ERROR_PIPE_CONNECTED is also exercised without a guessed timing sleep.
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let born = server
            .exchange(process.as_handle(), &recipe(), Duration::from_secs(5))
            .unwrap();
        assert_eq!(born.birth, 12);
        assert!(server
            .exchange(process.as_handle(), &recipe(), Duration::from_secs(1))
            .is_err());
        worker.join().unwrap();
    }
    #[test]
    fn real_private_pipe_returns_original_helper_failure_and_closes_one_shot() {
        use std::os::windows::io::AsHandle;
        let process = own_process();
        let (pid, birth) = process_identity(raw(&process)).unwrap();
        let mut server = Server::create().unwrap();
        let args = server.bootstrap_args(pid, birth);
        let worker = std::thread::spawn(move || {
            let mut client = Client::connect(&args, Duration::from_secs(5)).unwrap();
            let _recipe = client.receive_recipe().unwrap();
            client
                .send_failure(&io::Error::from_raw_os_error(2))
                .unwrap();
            assert!(client
                .send_failure(&io::Error::from_raw_os_error(5))
                .is_err());
        });
        let error = match server.exchange(process.as_handle(), &recipe(), Duration::from_secs(5)) {
            Ok(_) => panic!("failure was converted to success"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.raw_os_error(), Some(2));
        worker.join().unwrap();
    }
    #[test]
    fn missing_client_timeout_cancels_and_confirms_actual_overlapped_connect() {
        use std::os::windows::io::AsHandle;
        let process = own_process();
        let mut server = Server::create().unwrap();
        let error = match server.exchange(process.as_handle(), &recipe(), Duration::from_millis(20))
        {
            Ok(_) => panic!("missing client produced a reply"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let failure = error
            .get_ref()
            .unwrap()
            .downcast_ref::<WireFailure>()
            .unwrap();
        assert_eq!(failure.stage, "io_wait");
        assert!(failure.retry_cleanup());
    }
    #[test]
    fn bootstrap_client_refuses_wrong_creator_birth_before_recipe() {
        let process = own_process();
        let (pid, birth) = process_identity(raw(&process)).unwrap();
        let server = Server::create().unwrap();
        let args = server.bootstrap_args(pid, birth + 1);
        assert!(Client::connect(&args, Duration::from_secs(1)).is_err());
    }
    #[test]
    fn real_private_pipe_streams_recipe_larger_than_its_kernel_buffer() {
        use std::os::windows::io::AsHandle;
        let process = own_process();
        let (pid, birth) = process_identity(raw(&process)).unwrap();
        let mut server = Server::create().unwrap();
        let args = server.bootstrap_args(pid, birth);
        let worker = std::thread::spawn(move || {
            let mut client = Client::connect(&args, Duration::from_secs(5)).unwrap();
            let received = client.receive_recipe().unwrap();
            assert!(received.environment.len() * 2 > 65_536);
            assert_eq!(
                received
                    .environment
                    .iter()
                    .filter(|unit| **unit == 0xd800)
                    .count(),
                36_000
            );
            client
                .send_born(&Born {
                    process_handle: 4,
                    thread_handle: 8,
                    pid: 1,
                    tid: 2,
                    birth: 3,
                })
                .unwrap();
        });
        let mut large = recipe();
        large.environment.clear();
        for key in 65..69 {
            large.environment.extend([key, 61]);
            large.environment.extend(std::iter::repeat_n(0xd800, 9_000));
            large.environment.push(0);
        }
        large.environment.push(0);
        let reply = server.exchange(process.as_handle(), &large, Duration::from_secs(5));
        let joined = worker.join();
        assert!(reply.is_ok());
        joined.unwrap();
    }
    #[test]
    fn real_private_pipe_rejects_oversized_prefix_before_payload_allocation() {
        let process = own_process();
        let (pid, birth) = process_identity(raw(&process)).unwrap();
        let mut server = Server::create().unwrap();
        let args = server.bootstrap_args(pid, birth);
        let worker = std::thread::spawn(move || {
            let mut client = Client::connect(&args, Duration::from_secs(5)).unwrap();
            match client.receive_recipe() {
                Ok(_) => panic!("oversized frame accepted"),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            }
        });
        let channel = Channel {
            pipe: server.pipe.take().unwrap(),
            end: deadline(Duration::from_secs(5)).unwrap(),
            nonce: server.nonce,
        };
        let connected = PendingIo::new(channel.pipe.clone(), Vec::new())
            .unwrap()
            .run(0, channel.end);
        let sent =
            connected.and_then(|_| channel.write_all(&((MAX_FRAME + 1) as u32).to_le_bytes()));
        drop(channel);
        let joined = worker.join();
        assert!(sent.is_ok());
        joined.unwrap();
    }
}
