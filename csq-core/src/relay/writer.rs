//! The pump's sole master writer and its borrowed, fail-stop injection view.
//!
//! This module is a physical mechanism, not an authorization source. The
//! audited coordinator must bind its transaction and durable intent before
//! constructing an injection view. Kernel acceptance never proves CLI use.

use super::control::RequestLease;
use super::inject_audit::{CapturedResult, PendingAudit, PreparedIntent};
use super::owner::{DeliveryAuthority, OwnerAuthError, OwnerVerifier};
use super::pty::process_identity_start;
use super::state::{Outcome, RelayState, Terminal, Transaction, TxMetadata, WriterLock};
use super::types::{InjectOutcome, SessionIdentity};
use crate::sdk::SdkErrorCode;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Owned by the pump; an injection's exclusive borrow prevents ordinary input
/// from interleaving through this writer. No connection worker receives it.
pub(super) struct MasterWriter {
    fd: OwnedFd,
    pending_human: Vec<u8>,
}

/// Ordinary forwarding capacity; injection's future classified hold is separate.
pub(super) const HUMAN_INPUT_MAX: usize = 64 * 1024;

impl MasterWriter {
    pub(super) const fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            pending_human: Vec::new(),
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending_human.len()
    }
    pub(super) fn pending_room(&self) -> usize {
        HUMAN_INPUT_MAX - self.pending_len()
    }
    pub(super) fn queue_human(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > self.pending_room() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "relay_writer_busy_input",
            ));
        }
        self.pending_human.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn discard_pending(&mut self) {
        self.pending_human.clear();
    }
    pub(super) fn forward_pending(&mut self) -> io::Result<usize> {
        let n = Self::write_fd(self.master_raw_fd(), &self.pending_human)?;
        self.pending_human.drain(..n);
        Ok(n)
    }
    fn master_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        // SAFETY: this owned descriptor and the writable buffer remain valid.
        let n = unsafe { libc::read(self.master_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    pub(super) fn set_winsize(&self, size: &libc::winsize) -> io::Result<()> {
        super::term::set_winsize(self.master_raw_fd(), size)
    }
    /// The descriptor is installed only during poll, never returned to callers.
    pub(super) fn poll(
        &self,
        fds: &mut [libc::pollfd],
        slot: usize,
        enabled: bool,
        timeout: libc::c_int,
    ) -> io::Result<usize> {
        let entry = fds
            .get_mut(slot)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "relay_writer_poll_slot"))?;
        entry.fd = if enabled { self.master_raw_fd() } else { -1 };
        // SAFETY: the exclusive slice borrow keeps all entries valid for poll.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        fds[slot].fd = -1;
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write_once(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Self::write_fd(self.master_raw_fd(), bytes)
    }
    fn write_fd(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: the descriptor is owned and bytes remain valid for the call.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn injection(
        &mut self,
        lease: RequestLease,
        expected: SessionIdentity,
        authority: WriteAuthority,
    ) -> Result<InjectionWriter<'_>, WriterFault> {
        if !self.pending_human.is_empty() {
            return Err(WriterFault::BusyInput);
        }
        let writer = InjectionWriter {
            master: self,
            lease,
            expected,
            authority,
            accepted: 0,
            fault: None,
            binding: None,
        };
        physical_check(&writer)?;
        Ok(writer)
    }

    #[cfg(test)]
    fn test_injection(
        &mut self,
        lease: &RequestLease,
        expected: SessionIdentity,
    ) -> io::Result<InjectionWriter<'_>> {
        self.injection(lease.clone(), expected, WriteAuthority::Mechanism)
            .map_err(WriterFault::error)
    }

    /// A durable intent and a freshly revalidated opaque owner capability are
    /// both consumed before this returns the state-bound physical writer.
    pub(super) fn audited_transaction<'a>(
        &'a mut self,
        tx: &Transaction,
        gate: &RelayState,
        prepared: PreparedIntent,
        verifier: &mut OwnerVerifier,
        wall_ms: Option<u64>,
    ) -> Result<(WriterLock<InjectionWriter<'a>>, PendingAudit), Box<CapturedResult>> {
        let (owner, pending) = prepared.into_parts();
        let metadata = pending.metadata();
        if tx.audit_metadata(gate) != Ok(metadata)
            || verifier.target() != metadata.target
            || verifier.relay() != metadata.caller
        {
            return Err(Box::new(pending.reject(BeforeWriteRefusal {
                metadata,
                code: SdkErrorCode::NotAuthorized,
            })));
        }
        let authority = match verifier.authorize_delivery(owner, wall_ms) {
            Ok(authority)
                if metadata.kind == super::state::EntryKind::Slash(authority.command())
                    && authority.target() == metadata.target
                    && authority.relay() == metadata.caller =>
            {
                authority
            }
            result => {
                let code = result
                    .err()
                    .map_or(SdkErrorCode::NotAuthorized, owner_refusal);
                return Err(Box::new(
                    pending.reject(BeforeWriteRefusal { metadata, code }),
                ));
            }
        };
        let lease = pending.lease();
        if lease.deadline() > authority.deadline() {
            return Err(Box::new(pending.reject(BeforeWriteRefusal {
                metadata,
                code: SdkErrorCode::NotAuthorized,
            })));
        }
        let mut writer =
            match self.injection(lease, metadata.target, WriteAuthority::Owner(authority)) {
                Ok(writer) => writer,
                Err(fault) => {
                    return Err(Box::new(pending.reject(BeforeWriteRefusal {
                        metadata,
                        code: fault.refusal(),
                    })));
                }
            };
        writer.binding = Some(metadata);
        match gate.writer_lock(writer) {
            Ok(lock) => Ok((lock, pending)),
            Err(code) => Err(Box::new(
                pending.reject(BeforeWriteRefusal { metadata, code }),
            )),
        }
    }
}

impl PendingAudit {
    /// Capture after a terminal state step, then release the lock before I/O.
    pub(super) fn capture(
        self,
        lock: &WriterLock<InjectionWriter<'_>>,
        terminal: Outcome,
    ) -> CapturedResult {
        let writer = lock.inspect_guard();
        let metadata = self.metadata();
        let outcome = if writer.binding != Some(metadata)
            || terminal.id != Some(metadata.id)
            || terminal.kind != metadata.kind
        {
            InjectOutcome::Undetermined
        } else if writer.accepted_bytes() > 0 {
            if terminal.terminal == Terminal::Delivered
                && metadata.byte_len.checked_add(1) == Some(writer.accepted_bytes())
                && writer.fault().is_none()
            {
                InjectOutcome::DeliveredToPty
            } else {
                InjectOutcome::Undetermined
            }
        } else {
            match (writer.fault(), terminal.terminal) {
                (Some(fault), _) if fault != WriterFault::Write => {
                    InjectOutcome::Refused(fault.refusal())
                }
                (_, Terminal::Refused(code)) if code != SdkErrorCode::Undetermined => {
                    InjectOutcome::Refused(code)
                }
                _ => InjectOutcome::Undetermined,
            }
        };
        self.result(WriterTerminalProof { metadata, outcome })
    }
}

/// A zero-byte refusal witness. Only factory branches that return before any
/// write construct it; no witness is returned alongside a live writer lock.
pub(super) struct BeforeWriteRefusal {
    metadata: TxMetadata,
    code: SdkErrorCode,
}

impl BeforeWriteRefusal {
    pub(super) fn into_parts(self) -> (TxMetadata, SdkErrorCode) {
        (self.metadata, self.code)
    }
}

/// Only this module can turn a physical observation into a terminal proof.
pub(super) struct WriterTerminalProof {
    metadata: TxMetadata,
    outcome: InjectOutcome,
}

impl WriterTerminalProof {
    pub(super) fn into_parts(self) -> (TxMetadata, InjectOutcome) {
        (self.metadata, self.outcome)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriterFault {
    Deadline,
    Owner(OwnerAuthError),
    Identity,
    Foreground,
    Blocking,
    BusyInput,
    Write,
}

fn owner_refusal(error: OwnerAuthError) -> SdkErrorCode {
    match error {
        OwnerAuthError::Disabled => SdkErrorCode::DisabledByOperator,
        OwnerAuthError::Expired => SdkErrorCode::RequestExpired,
        _ => SdkErrorCode::NotAuthorized,
    }
}

impl WriterFault {
    fn refusal(self) -> SdkErrorCode {
        match self {
            Self::Deadline => SdkErrorCode::RequestExpired,
            Self::Owner(error) => owner_refusal(error),
            Self::Identity | Self::Blocking => SdkErrorCode::NotAuthorized,
            Self::Foreground => SdkErrorCode::ForegroundChanged,
            Self::BusyInput => SdkErrorCode::BusyInput,
            Self::Write => SdkErrorCode::Undetermined,
        }
    }
    fn error(self) -> io::Error {
        let (kind, tag) = match self {
            Self::Deadline => (io::ErrorKind::TimedOut, "relay_writer_expired"),
            Self::Owner(_) => (
                io::ErrorKind::PermissionDenied,
                "relay_writer_owner_revoked",
            ),
            Self::Identity => (io::ErrorKind::PermissionDenied, "relay_writer_identity"),
            Self::Foreground => (io::ErrorKind::PermissionDenied, "relay_writer_foreground"),
            Self::Blocking => (io::ErrorKind::InvalidInput, "relay_writer_blocking"),
            Self::BusyInput => (io::ErrorKind::WouldBlock, "relay_writer_busy_input"),
            Self::Write => (io::ErrorKind::Other, "relay_writer_failed"),
        };
        io::Error::new(kind, tag)
    }
}

/// A fault is permanent. A syscall racing the cutoff can still accept bytes;
/// that acceptance is counted, then the fault fails the next write/flush.
/// There is no zero-side-effects-after-cutoff guarantee and no safe retry.
enum WriteAuthority {
    Owner(DeliveryAuthority),
    #[cfg(test)]
    Mechanism,
}

pub(super) struct InjectionWriter<'a> {
    master: &'a mut MasterWriter,
    lease: RequestLease,
    authority: WriteAuthority,
    expected: SessionIdentity,
    accepted: usize,
    fault: Option<WriterFault>,
    binding: Option<TxMetadata>,
}

impl InjectionWriter<'_> {
    pub(super) const fn accepted_bytes(&self) -> usize {
        self.accepted
    }

    pub(super) const fn fault(&self) -> Option<WriterFault> {
        self.fault
    }

    fn enforce(&mut self, check: impl FnOnce(&Self) -> Result<(), WriterFault>) -> io::Result<()> {
        let result = self.fault.map_or_else(|| check(self), Err);
        if let Err(fault) = result {
            self.fault = Some(fault);
            return Err(fault.error());
        }
        Ok(())
    }

    fn write_checked(
        &mut self,
        bytes: &[u8],
        mut check: impl FnMut(&Self) -> Result<(), WriterFault>,
        write: impl FnOnce(&mut MasterWriter, &[u8]) -> io::Result<usize>,
    ) -> io::Result<usize> {
        self.enforce(&mut check)?;
        let result = write(self.master, bytes);
        let postcheck = self.enforce(&mut check);
        match result {
            Ok(n) => {
                self.accepted = self.accepted.saturating_add(n);
                if n == 0 {
                    self.fault.get_or_insert(WriterFault::Write);
                }
                // Returning Err here would conceal n from state::write_counted.
                Ok(n)
            }
            Err(error) => {
                postcheck?;
                if error.kind() != io::ErrorKind::Interrupted {
                    self.fault = Some(WriterFault::Write);
                }
                Err(error)
            }
        }
    }
}

fn physical_check(writer: &InjectionWriter<'_>) -> Result<(), WriterFault> {
    match &writer.authority {
        WriteAuthority::Owner(authority) => authority.check().map_err(WriterFault::Owner)?,
        #[cfg(test)]
        WriteAuthority::Mechanism => {}
    }
    if writer.lease.is_expired() {
        return Err(WriterFault::Deadline);
    }
    if process_identity_start(writer.expected.pid) != Some(writer.expected.started_at) {
        return Err(WriterFault::Identity);
    }
    let fd = writer.master.master_raw_fd();
    // SAFETY: queries only, on the master retained by this exclusive borrow.
    let (foreground, flags) = unsafe { (libc::tcgetpgrp(fd), libc::fcntl(fd, libc::F_GETFL)) };
    if foreground <= 0 || u32::try_from(foreground).ok() != Some(writer.expected.pid) {
        return Err(WriterFault::Foreground);
    }
    if flags < 0 || flags & libc::O_NONBLOCK == 0 {
        return Err(WriterFault::Blocking);
    }
    if writer.lease.is_expired() {
        return Err(WriterFault::Deadline);
    }
    Ok(())
}

impl Write for InjectionWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_checked(bytes, physical_check, MasterWriter::write_once)
    }

    fn flush(&mut self) -> io::Result<()> {
        // There is no userspace buffer and no blocking tcdrain operation.
        self.enforce(physical_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::control::{ControlRequest, OwnerAdmission};
    use crate::relay::inject_audit::IntentInput;
    use crate::relay::owner::{mint, OwnerCommand, OwnerCommandFields};
    use crate::relay::pty::Pty;
    use crate::relay::state::SlashCmd;
    use crate::relay::types::CliKind;
    use std::cell::Cell;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn lease() -> RequestLease {
        ControlRequest::for_test(
            SessionIdentity {
                pid: 1,
                started_at: 1,
            },
            b"{}".to_vec(),
            Instant::now() + Duration::from_secs(600),
        )
        .lease()
    }

    // Failure injection reaches the same write_checked state machine used by
    // Write, without claiming these deterministic gate values are live evidence.
    fn steps<'a>(master: &'a mut MasterWriter, lease: &'a RequestLease) -> InjectionWriter<'a> {
        InjectionWriter {
            master,
            lease: lease.clone(),
            authority: WriteAuthority::Mechanism,
            expected: SessionIdentity {
                pid: 1,
                started_at: 1,
            },
            accepted: 0,
            fault: None,
            binding: None,
        }
    }

    fn master() -> MasterWriter {
        MasterWriter::new(std::fs::File::open("/dev/null").unwrap().into())
    }

    #[test]
    fn observed_fault_before_write_permanently_refuses_without_syscall() {
        for fault in [
            WriterFault::Deadline,
            WriterFault::Identity,
            WriterFault::Foreground,
            WriterFault::Blocking,
        ] {
            let mut master = master();
            let lease = lease();
            let mut writer = steps(&mut master, &lease);
            let writes = Cell::new(0);
            assert!(writer
                .write_checked(
                    b"/clear",
                    |_| Err(fault),
                    |_, _| {
                        writes.set(writes.get() + 1);
                        Ok(6)
                    }
                )
                .is_err());
            assert!(writer
                .write_checked(
                    b"\r",
                    |_| Ok(()),
                    |_, _| {
                        writes.set(writes.get() + 1);
                        Ok(1)
                    }
                )
                .is_err());
            assert_eq!(
                (writes.get(), writer.accepted_bytes(), writer.fault()),
                (0, 0, Some(fault))
            );
        }
    }

    #[test]
    fn postwrite_cutoff_counts_kernel_acceptance_and_suppresses_cr() {
        for fault in [
            WriterFault::Deadline,
            WriterFault::Identity,
            WriterFault::Foreground,
            WriterFault::Blocking,
        ] {
            for accepted in [3, 6] {
                let mut master = master();
                let lease = lease();
                let mut writer = steps(&mut master, &lease);
                let checks = Cell::new(0);
                let n = writer
                    .write_checked(
                        b"/clear",
                        |_| {
                            checks.set(checks.get() + 1);
                            if checks.get() == 1 {
                                Ok(())
                            } else {
                                Err(fault)
                            }
                        },
                        |_, _| Ok(accepted),
                    )
                    .unwrap();
                assert_eq!(
                    (n, writer.accepted_bytes(), writer.fault()),
                    (accepted, accepted, Some(fault))
                );
                assert!(writer
                    .write_checked(b"\r", |_| Ok(()), |_, _| panic!("CR after cutoff"))
                    .is_err());
                assert!(writer.flush().is_err());
            }
        }
    }

    #[test]
    fn interrupted_attempt_rechecks_before_retry() {
        let mut master = master();
        let lease = lease();
        let mut writer = steps(&mut master, &lease);
        assert_eq!(
            writer
                .write_checked(
                    b"/clear",
                    |_| Ok(()),
                    |_, _| { Err(io::Error::from(io::ErrorKind::Interrupted)) }
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(writer.fault(), None);
        assert!(writer
            .write_checked(
                b"/clear",
                |_| Err(WriterFault::Deadline),
                |_, _| { panic!("retry after observed expiry") }
            )
            .is_err());
        assert_eq!(writer.accepted_bytes(), 0);
    }

    #[test]
    fn zero_and_would_block_are_terminal_without_later_submission() {
        for zero in [true, false] {
            let mut master = master();
            let lease = lease();
            let mut writer = steps(&mut master, &lease);
            let result = writer.write_checked(
                b"/clear",
                |_| Ok(()),
                |_, _| {
                    if zero {
                        Ok(0)
                    } else {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                },
            );
            if zero {
                assert_eq!(result.unwrap(), 0);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            }
            assert_eq!(writer.fault(), Some(WriterFault::Write));
            assert_eq!(writer.accepted_bytes(), 0);
            assert!(writer
                .write_checked(b"\r", |_| Ok(()), |_, _| panic!("resumed failed writer"))
                .is_err());
        }
    }

    #[test]
    fn partial_then_error_preserves_accepted_total_and_latches_failure() {
        let mut master = master();
        let lease = lease();
        let mut writer = steps(&mut master, &lease);
        assert_eq!(
            writer
                .write_checked(b"/clear", |_| Ok(()), |_, _| Ok(2))
                .unwrap(),
            2
        );
        assert!(writer
            .write_checked(
                b"lear",
                |_| Ok(()),
                |_, _| Err(io::Error::from_raw_os_error(libc::EIO))
            )
            .is_err());
        assert_eq!(
            (writer.accepted_bytes(), writer.fault()),
            (2, Some(WriterFault::Write))
        );
        assert!(writer
            .write_checked(b"\r", |_| Ok(()), |_, _| panic!("CR after partial failure"))
            .is_err());
    }

    struct ScratchChild(libc::pid_t);
    impl Drop for ScratchChild {
        fn drop(&mut self) {
            // SAFETY: this PID is our unreaped fork child, never a live session.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                while libc::waitpid(self.0, std::ptr::null_mut(), 0) < 0 {
                    if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
            }
        }
    }

    fn scratch() -> (MasterWriter, OwnedFd, ScratchChild, UnixStream) {
        let Pty { master, slave } = Pty::open(None, None).unwrap();
        // SAFETY: termios queries and edits affect only this scratch slave.
        unsafe {
            let mut termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &mut termios), 0);
            libc::cfmakeraw(&mut termios);
            assert_eq!(
                libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios),
                0
            );
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
            let flags = libc::fcntl(slave.as_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(slave.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        let (mut ready, child_ready) = UnixStream::pair().unwrap();
        let (stop, child_stop) = UnixStream::pair().unwrap();
        // Preserve the three needed descriptions above stderr before fork;
        // mapping them to 0/1/2 in the child cannot overwrite another source.
        let keep = [
            slave.as_raw_fd(),
            child_ready.as_raw_fd(),
            child_stop.as_raw_fd(),
        ]
        .map(|fd| {
            // SAFETY: duplicating our own scratch description close-on-exec.
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(copy >= 3);
            // SAFETY: fcntl returned a fresh descriptor now owned by this value.
            unsafe { std::os::fd::FromRawFd::from_raw_fd(copy) }
        });
        let keep: [OwnedFd; 3] = keep;
        let ceiling = crate::relay::pty::open_fd_ceiling();
        // SAFETY: the child uses only async-signal-safe libc calls, then _exit;
        // it never enters the Rust runtime or touches inherited live sessions.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: all descriptors are inherited valid scratch handles.
            unsafe {
                libc::alarm(10);
                for (fd, target) in keep.iter().zip(0..3) {
                    if libc::dup2(fd.as_raw_fd(), target) < 0 {
                        libc::_exit(3);
                    }
                }
                crate::relay::pty::close_from(3, ceiling);
                if libc::setsid() < 0
                    || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0
                    || libc::tcsetpgrp(0, libc::getpid()) < 0
                {
                    libc::_exit(2);
                }
                libc::write(1, b"R".as_ptr().cast(), 1);
                let mut byte = 0u8;
                libc::read(2, std::ptr::addr_of_mut!(byte).cast(), 1);
                libc::_exit(0);
            }
        }
        let child = ScratchChild(pid);
        drop((child_ready, child_stop, keep));
        ready
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        ready.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"R");
        (MasterWriter::new(master), slave, child, stop)
    }

    #[test]
    fn real_scratch_pty_ordinary_and_injected_bytes_share_master() {
        let (mut master, slave, child, _stop) = scratch();
        let expected = SessionIdentity {
            pid: child.0 as u32,
            started_at: process_identity_start(child.0 as u32).unwrap(),
        };
        let lease = lease();
        master.queue_human(b"human:").unwrap();
        assert_eq!(master.forward_pending().unwrap(), 6);
        let mut writer = master.test_injection(&lease, expected).unwrap();
        writer.write_all(b"/clear").unwrap();
        writer.write_all(b"\r").unwrap();
        writer.flush().unwrap();
        assert_eq!((writer.accepted_bytes(), writer.fault()), (7, None));
        let mut received = [0; 13];
        let mut slave = std::fs::File::from(slave);
        slave.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"human:/clear\r");
    }

    #[test]
    fn actual_pending_human_queue_refuses_injection_and_preserves_order() {
        let (mut master, slave, child, _stop) = scratch();
        let identity = SessionIdentity {
            pid: child.0 as u32,
            started_at: process_identity_start(child.0 as u32).unwrap(),
        };
        let lease = lease();
        master.queue_human(b"first").unwrap();
        let refused = master.test_injection(&lease, identity);
        assert!(
            refused.is_err(),
            "pending_human_queue_must_refuse_injection"
        );
        assert_eq!(
            refused.err().unwrap().to_string(),
            "relay_writer_busy_input"
        );
        let mut slave = std::fs::File::from(slave);
        assert_eq!(
            slave.read(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        master.queue_human(b"second").unwrap();
        assert_eq!(master.forward_pending().unwrap(), 11);
        assert_eq!(master.pending_len(), 0);
        let mut writer = master.test_injection(&lease, identity).unwrap();
        writer.write_all(b"/clear\r").unwrap();
        writer.flush().unwrap();
        let mut bytes = [0; 18];
        slave.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"firstsecond/clear\r");
    }

    #[test]
    fn human_queue_keeps_its_64k_bound_without_dropping_prior_input() {
        let mut master = master();
        master.queue_human(&vec![b'x'; HUMAN_INPUT_MAX]).unwrap();
        assert_eq!(master.pending_room(), 0);
        assert_eq!(
            master.queue_human(b"y").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(master.pending_human, vec![b'x'; HUMAN_INPUT_MAX]);
    }

    #[test]
    fn poll_never_returns_the_master_descriptor() {
        let (master, _slave, _child, _stop) = scratch();
        let mut entries = [libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        }];
        master.poll(&mut entries, 0, true, 0).unwrap();
        assert_eq!(entries[0].fd, -1);
    }

    #[test]
    fn scratch_child_closes_inherited_listener_while_still_running() {
        // A Unix listener at a private path, probed by CONNECT: only a process
        // holding the listening descriptor can accept, so a refused connect
        // after the parent drops its copy proves the child holds none. (A TCP
        // port rebind also failed when an unrelated process on a busy host took
        // the freed ephemeral port — a false red, not a retained descriptor.)
        //
        // The probe retries for up to 2 s while the child is still running. A
        // fork elsewhere in this test binary (another test's scratch child, before
        // its own close_from) can hold a copy for an instant, so one accepted
        // connect is not proof; but a descriptor THIS child retained stays
        // accepting for the child's whole life (alarm 10 s, held until `_stop`
        // drops), so it is still refused-never within the window and the test
        // still fails. The final waitpid proves the child was alive throughout.
        // Short root: a deep runner TMPDIR overflows sun_path at bind.
        let dir = crate::testing::socket_fixture::short_root("rw-").unwrap();
        let path = dir.path().join("l.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (_master, _slave, child, _stop) = scratch();
        drop(listener);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut last = UnixStream::connect(&path);
        while last.is_ok() && std::time::Instant::now() < deadline {
            drop(last);
            std::thread::sleep(Duration::from_millis(20));
            last = UnixStream::connect(&path);
        }
        assert_eq!(
            last.as_ref().map_err(|e| e.kind()).err(),
            Some(io::ErrorKind::ConnectionRefused),
            "scratch child retained unrelated listener for 2 s: {last:?}"
        );
        // SAFETY: query only our own unreaped child, without consuming its status.
        assert_eq!(
            unsafe { libc::waitpid(child.0, std::ptr::null_mut(), libc::WNOHANG) },
            0
        );
    }

    #[test]
    fn real_scratch_pty_postwrite_change_counts_bytes_and_suppresses_cr() {
        let (mut master, slave, child, _stop) = scratch();
        let expected = SessionIdentity {
            pid: child.0 as u32,
            started_at: process_identity_start(child.0 as u32).unwrap(),
        };
        let lease = lease();
        let mut writer = master.test_injection(&lease, expected).unwrap();
        let accepted = writer
            .write_checked(b"/compact", physical_check, |master, bytes| {
                let n = master.write_once(bytes)?;
                // SAFETY: change only this scratch master's flag after acceptance;
                // physical_check must observe it before reporting completion.
                unsafe {
                    let flags = libc::fcntl(master.master_raw_fd(), libc::F_GETFL);
                    assert!(flags >= 0);
                    assert_eq!(
                        libc::fcntl(
                            master.master_raw_fd(),
                            libc::F_SETFL,
                            flags & !libc::O_NONBLOCK
                        ),
                        0
                    );
                }
                Ok(n)
            })
            .unwrap();
        assert_eq!(
            (accepted, writer.accepted_bytes(), writer.fault()),
            (8, 8, Some(WriterFault::Blocking))
        );
        assert!(writer.write(b"\r").is_err());
        assert!(writer.flush().is_err());
        let mut slave = std::fs::File::from(slave);
        let mut bytes = [0; 32];
        let count = slave.read(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"/compact");
    }

    #[test]
    fn real_scratch_pty_refuses_expired_identity_foreground_and_blocking() {
        let (mut master, _slave, child, _stop) = scratch();
        let identity = SessionIdentity {
            pid: child.0 as u32,
            started_at: process_identity_start(child.0 as u32).unwrap(),
        };
        let expired = ControlRequest::for_test(identity, vec![], Instant::now()).lease();
        assert_eq!(
            master
                .test_injection(&expired, identity)
                .err()
                .unwrap()
                .to_string(),
            "relay_writer_expired"
        );
        let lease = lease();
        assert_eq!(
            master
                .test_injection(
                    &lease,
                    SessionIdentity {
                        started_at: identity.started_at.saturating_add(1),
                        ..identity
                    }
                )
                .err()
                .unwrap()
                .to_string(),
            "relay_writer_identity"
        );
        let this = std::process::id();
        assert_eq!(
            master
                .test_injection(
                    &lease,
                    SessionIdentity {
                        pid: this,
                        started_at: process_identity_start(this).unwrap()
                    }
                )
                .err()
                .unwrap()
                .to_string(),
            "relay_writer_foreground"
        );
        // SAFETY: only this scratch master changes; the guard must refuse it.
        unsafe {
            let flags = libc::fcntl(master.master_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(
                    master.master_raw_fd(),
                    libc::F_SETFL,
                    flags & !libc::O_NONBLOCK
                ),
                0
            );
        }
        assert_eq!(
            master
                .test_injection(&lease, identity)
                .err()
                .unwrap()
                .to_string(),
            "relay_writer_blocking"
        );
    }

    const OWNER_NOW: u64 = 1_000_000; // Injected verifier time, never host wall time.
    const OWNER_KEY: [u8; 32] = [0x5a; 32]; // Fixture-only signing material.

    /// Everything the master has written to the slave so far.
    ///
    /// The pty delivers master writes to the slave through the tty line
    /// discipline, which on Linux flushes on a worker thread: ONE non-blocking
    /// read can return only a prefix of bytes the writer already wrote
    /// (`/clear` without its trailing `\r`). So read until the slave has been
    /// quiet for `SETTLE` after the last byte, bounded by `DEADLINE`; an empty
    /// result after the deadline is returned as empty so the caller's assertion
    /// fails on the real mismatch.
    fn read_settled(slave: &mut std::fs::File) -> Vec<u8> {
        read_settled_with(slave, &|| {})
    }

    /// [`read_settled`] with a hook fired ONCE, immediately after the first
    /// successful read. The late-byte regression test uses it to write the
    /// trailing byte at a deterministic point in the read sequence instead of
    /// racing a fixed sleep against the settle window.
    fn read_settled_with(slave: &mut std::fs::File, on_first_read: &dyn Fn()) -> Vec<u8> {
        const SETTLE: Duration = Duration::from_millis(50);
        const DEADLINE: Duration = Duration::from_secs(5);
        let start = Instant::now();
        let mut out = Vec::new();
        let mut quiet_since: Option<Instant> = None;
        let mut first_read = true;
        loop {
            let mut chunk = [0; 64];
            match slave.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&chunk[..n]);
                    quiet_since = None;
                    if first_read {
                        first_read = false;
                        on_first_read();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if !out.is_empty() {
                        let since = *quiet_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= SETTLE {
                            break;
                        }
                    }
                    if start.elapsed() >= DEADLINE {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("slave read failed: {e}"),
            }
        }
        out
    }

    #[test]
    fn read_settled_returns_bytes_that_arrive_after_the_first_read() {
        // Discriminating regression for the pty prefix race: the trailing CR is
        // written by the hook immediately AFTER the first successful read, so a
        // single non-blocking read returns only `/clear` while the settled read
        // returns both. The ordering is enforced by the read itself — no sleep
        // racing the 50 ms settle window.
        let Pty { master, slave } = Pty::open(None, None).unwrap();
        // SAFETY: termios/fcntl calls touch only this test's own pty pair.
        unsafe {
            let mut termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &mut termios), 0);
            libc::cfmakeraw(&mut termios);
            assert_eq!(
                libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios),
                0
            );
            let flags = libc::fcntl(slave.as_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(slave.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        let mut slave: std::fs::File = slave.into();
        let master: std::fs::File = master.into();
        let master = std::rc::Rc::new(std::cell::RefCell::new(master));
        master.borrow_mut().write_all(b"/clear").unwrap();
        let late_master = std::rc::Rc::clone(&master);
        let out = read_settled_with(&mut slave, &move || {
            late_master.borrow_mut().write_all(b"\r").unwrap();
        });
        assert_eq!(out, b"/clear\r");
    }

    struct AuditedFixture {
        master: MasterWriter,
        slave: std::fs::File,
        gate: RelayState,
        tx: Option<Transaction>,
        now: u64,
        verifier: OwnerVerifier,
        command: SlashCmd,
        request_lease: RequestLease,
        wall: std::sync::Arc<std::sync::atomic::AtomicU64>,
        base: tempfile::TempDir,
        _child: ScratchChild,
        _stop: UnixStream,
    }

    impl AuditedFixture {
        fn new(command: SlashCmd) -> Self {
            let (master, slave, child, stop) = scratch();
            let target = SessionIdentity {
                pid: child.0 as u32,
                started_at: process_identity_start(child.0 as u32).unwrap(),
            };
            let pid = std::process::id();
            let caller = SessionIdentity {
                pid,
                started_at: process_identity_start(pid).unwrap(),
            };
            let (gate, tx, now) =
                crate::relay::state::test_owner_transaction(target, caller, command);
            let wall = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(OWNER_NOW));
            let clock = wall.clone();
            let mut verifier =
                OwnerVerifier::new(zeroize::Zeroizing::new(OWNER_KEY), target, caller).unwrap();
            verifier.set_clock_for_test(std::sync::Arc::new(move || {
                Some(clock.load(std::sync::atomic::Ordering::Acquire))
            }));
            Self {
                master,
                slave: slave.into(),
                gate,
                tx: Some(tx),
                now,
                verifier,
                command,
                request_lease: lease(),
                wall,
                base: tempfile::TempDir::new().unwrap(),
                _child: child,
                _stop: stop,
            }
        }

        fn wire(&self, command: SlashCmd, update_id: u64) -> Vec<u8> {
            let target = self.verifier.target();
            let relay = self.verifier.relay();
            let wire = mint(
                OwnerCommandFields {
                    version: 1,
                    target_pid: target.pid,
                    target_started_at: target.started_at,
                    relay_pid: relay.pid,
                    relay_started_at: relay.started_at,
                    generation: self.verifier.generation(),
                    update_id,
                    issued_at_ms: OWNER_NOW,
                    expires_at_ms: OWNER_NOW + 30_000,
                    command: match command {
                        SlashCmd::Clear => OwnerCommand::Clear,
                        SlashCmd::Compact => OwnerCommand::Compact,
                    },
                },
                &OWNER_KEY,
            )
            .unwrap();
            serde_json::to_vec(&wire).unwrap()
        }

        fn admission(&mut self, command: SlashCmd) -> OwnerAdmission {
            let request = ControlRequest::for_test_with_lease(
                self.verifier.relay(),
                self.wire(command, 7),
                self.request_lease.clone(),
            );
            let (admission, _reply) = request
                .admit_owner(&mut self.verifier, CliKind::Claude, Some(OWNER_NOW))
                .unwrap();
            admission
        }

        fn input(&mut self) -> IntentInput {
            let admission = self.admission(self.command);
            IntentInput::capture(self.tx.as_ref().unwrap(), &self.gate, admission).unwrap()
        }

        fn prepare(&mut self) -> PreparedIntent {
            self.input()
                .persist(self.base.path().to_path_buf())
                .unwrap()
        }

        fn records(&self) -> Vec<crate::audit::types::SignedRecord> {
            let root = self.base.path().join("csq-runs");
            let genesis: crate::audit::persist::ChainGenesis =
                serde_json::from_slice(&std::fs::read(root.join("chain.json")).unwrap()).unwrap();
            std::fs::read_to_string(root.join(format!("{}.jsonl", genesis.chain_id)))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        fn bytes(&mut self) -> Vec<u8> {
            read_settled(&mut self.slave)
        }

        fn no_bytes(&mut self) {
            assert_eq!(
                self.slave.read(&mut [0; 64]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn swapped_control_request_lease_never_creates_owner_or_writer_authority() {
        let _env = crate::platform::test_env::lock();
        for cancelled in [false, true] {
            let mut f = AuditedFixture::new(SlashCmd::Clear);
            let peer = f.verifier.relay();
            let a = ControlRequest::for_test(
                peer,
                f.wire(SlashCmd::Clear, 7),
                if cancelled {
                    Instant::now() + Duration::from_secs(600)
                } else {
                    Instant::now()
                },
            );
            if cancelled {
                a.lease().revoke();
            }
            let b = ControlRequest::for_test(
                peer,
                f.wire(SlashCmd::Clear, 8),
                Instant::now() + Duration::from_secs(600),
            );
            assert!(a.is_expired());
            assert!(!b.is_expired());
            // Only A's selected root lease changes. Its authentic frame origin,
            // peer, target, Clear command and fresh owner lifetime remain A's.
            let swapped = a.with_lease_from_for_test(&b);
            let denied = swapped.admit_owner(&mut f.verifier, CliKind::Claude, Some(OWNER_NOW));
            assert!(
                denied.is_err(),
                "SWAPPED_REQUEST_MUST_NOT_CREATE_OWNER_OR_WRITER_AUTHORITY"
            );
            let (outcome, _a_reply) = denied.err().unwrap().into_parts();
            assert_eq!(outcome, InjectOutcome::Refused(SdkErrorCode::NotAuthorized));
            assert!(!f.base.path().join("csq-runs").exists());
            f.no_bytes();

            // B is untouched: use its actual admission, durable intent and the
            // same physical writer/state path as normal audited delivery.
            let (admission, b_reply) = b
                .admit_owner(&mut f.verifier, CliKind::Claude, Some(OWNER_NOW))
                .unwrap();
            let prepared = IntentInput::capture(f.tx.as_ref().unwrap(), &f.gate, admission)
                .unwrap()
                .persist(f.base.path().to_path_buf())
                .unwrap();
            assert_eq!(f.records().len(), 1, "untouched_b_intent_before_any_byte");
            f.no_bytes();
            let (mut lock, pending) = f
                .master
                .audited_transaction(
                    f.tx.as_ref().unwrap(),
                    &f.gate,
                    prepared,
                    &mut f.verifier,
                    Some(OWNER_NOW),
                )
                .unwrap();
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .unwrap()
                .submit(&mut f.gate, true, f.now, || true)
                .unwrap();
            let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
            drop(lock);
            assert_eq!(result.persist(), InjectOutcome::DeliveredToPty);
            assert_eq!(f.bytes(), b"/clear\r", "untouched_b_exact_clear_and_cr");
            f.no_bytes();
            let records = f.records();
            assert_eq!(records.len(), 2);
            assert!(matches!(&records[0].payload,
                crate::audit::types::EventPayload::SessionInject(p)
                    if p.outcome == crate::audit::types::SessionInjectOutcome::Intent));
            assert!(matches!(&records[1].payload,
                crate::audit::types::EventPayload::SessionInject(p)
                    if p.outcome == crate::audit::types::SessionInjectOutcome::DeliveredToPty
                        && p.error_code.is_none()));
            assert!(!b_reply.is_expired(), "untouched_b_original_reply_window");
        }
    }

    #[test]
    fn coherent_expired_or_cancelled_transport_does_not_consume_owner_replay() {
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        for (cancelled, update_id) in [(false, 7), (true, 8)] {
            let wire = f.wire(SlashCmd::Clear, update_id);
            let expired = ControlRequest::for_test(
                f.verifier.relay(),
                wire.clone(),
                if cancelled {
                    Instant::now() + Duration::from_secs(600)
                } else {
                    Instant::now()
                },
            );
            if cancelled {
                expired.lease().revoke();
            }
            let refusal = expired.admit_owner(&mut f.verifier, CliKind::Claude, Some(OWNER_NOW));
            let (outcome, _reply) = refusal.err().unwrap().into_parts();
            assert_eq!(
                outcome,
                InjectOutcome::Refused(SdkErrorCode::RequestExpired)
            );
            let fresh = ControlRequest::for_test(
                f.verifier.relay(),
                wire,
                Instant::now() + Duration::from_secs(600),
            );
            assert!(
                fresh
                    .admit_owner(&mut f.verifier, CliKind::Claude, Some(OWNER_NOW))
                    .is_ok(),
                "transport_refusal_must_preserve_owner_replay"
            );
            assert!(!f.base.path().join("csq-runs").exists());
            f.no_bytes();
        }
    }

    #[test]
    fn failed_durable_intent_returns_no_writer_and_no_pty_bytes() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        std::fs::create_dir(f.base.path().join("csq-runs")).unwrap();
        std::fs::write(
            f.base.path().join("csq-runs/.chain-broken"),
            b"integrity_broken",
        )
        .unwrap();
        assert!(matches!(
            f.input().persist(f.base.path().to_path_buf()),
            Err(SdkErrorCode::AuditUnavailable)
        ));
        f.no_bytes();
    }

    #[test]
    fn slash_state_alone_does_not_authorize_a_different_owner_command() {
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let admission = f.admission(SlashCmd::Compact);
        assert!(matches!(
            IntentInput::capture(f.tx.as_ref().unwrap(), &f.gate, admission),
            Err(SdkErrorCode::NotAuthorized)
        ));
        assert!(!f.base.path().join("csq-runs").exists());
        f.no_bytes();
    }

    #[test]
    fn queued_owner_transaction_never_captures_intent() {
        for command in [SlashCmd::Clear, SlashCmd::Compact] {
            let mut f = AuditedFixture::new(command);
            let (gate, tx, now) = crate::relay::state::test_owner_queued_transaction(
                f.verifier.target(),
                f.verifier.relay(),
                command,
            );
            drop(f.tx.take());
            f.gate = gate;
            f.tx = Some(tx);
            f.now = now;
            assert!(
                !f.tx
                    .as_ref()
                    .unwrap()
                    .audit_metadata(&f.gate)
                    .unwrap()
                    .immediate
            );
            let admission = f.admission(command);
            assert!(matches!(
                IntentInput::capture(f.tx.as_ref().unwrap(), &f.gate, admission),
                Err(SdkErrorCode::NotAuthorized)
            ));
            assert!(!f.base.path().join("csq-runs").exists());
            f.no_bytes();
        }
    }

    #[test]
    fn owner_revoked_after_intent_cannot_obtain_physical_writer() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        f.verifier.disable();
        let rejected = match f.master.audited_transaction(
            f.tx.as_ref().unwrap(),
            &f.gate,
            prepared,
            &mut f.verifier,
            Some(OWNER_NOW),
        ) {
            Ok(_) => panic!("revoked owner obtained writer"),
            Err(result) => result,
        };
        assert_eq!(
            rejected.persist(),
            InjectOutcome::Refused(SdkErrorCode::DisabledByOperator)
        );
        f.no_bytes();
    }

    #[test]
    fn durable_pair_records_only_complete_state_and_kernel_delivery() {
        let _env = crate::platform::test_env::lock();
        for (command, expected) in [
            (SlashCmd::Clear, &b"/clear\r"[..]),
            (SlashCmd::Compact, &b"/compact\r"[..]),
        ] {
            let mut f = AuditedFixture::new(command);
            let prepared = f.prepare();
            let (mut lock, pending) = f
                .master
                .audited_transaction(
                    f.tx.as_ref().unwrap(),
                    &f.gate,
                    prepared,
                    &mut f.verifier,
                    Some(OWNER_NOW),
                )
                .unwrap();
            let pasted =
                f.tx.take()
                    .unwrap()
                    .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                    .unwrap();
            pasted.submit(&mut f.gate, true, f.now, || true).unwrap();
            let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
            drop(lock);
            assert_eq!(result.persist(), InjectOutcome::DeliveredToPty);
            assert_eq!(f.bytes(), expected);
            let records = f.records();
            assert_eq!(records.len(), 2);
            assert!(
                matches!(&records[1].payload, crate::audit::types::EventPayload::SessionInject(p) if p.outcome == crate::audit::types::SessionInjectOutcome::DeliveredToPty)
            );
        }
    }

    #[test]
    fn expiry_after_intent_is_audited_zero_byte_refusal() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        f.request_lease.revoke();
        let rejected = match f.master.audited_transaction(
            f.tx.as_ref().unwrap(),
            &f.gate,
            prepared,
            &mut f.verifier,
            Some(OWNER_NOW),
        ) {
            Ok(_) => panic!("expired intent obtained writer"),
            Err(result) => result,
        };
        assert_eq!(
            rejected.persist(),
            InjectOutcome::Refused(SdkErrorCode::RequestExpired)
        );
        f.no_bytes();
        assert_eq!(f.records().len(), 2);
    }

    #[test]
    fn cancellation_between_body_and_cr_preserves_partial_and_undetermined() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let cancel = f.request_lease.clone();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        let pasted =
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .unwrap();
        cancel.revoke();
        assert!(cancel.is_expired());
        assert_eq!(
            pasted.submit(&mut f.gate, true, f.now, || true),
            Err(SdkErrorCode::Undetermined)
        );
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/clear");
        assert!(f.gate.snapshot().line_dirty);
    }

    #[test]
    fn result_persistence_failure_never_returns_delivery_success() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        f.tx.take()
            .unwrap()
            .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
            .unwrap()
            .submit(&mut f.gate, true, f.now, || true)
            .unwrap();
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        std::fs::write(
            f.base.path().join("csq-runs/.chain-broken"),
            b"integrity_broken",
        )
        .unwrap();
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/clear\r");
        assert_eq!(f.records().len(), 1, "intent survives failed result append");
    }

    #[test]
    fn mismatched_state_receipt_cannot_certify_kernel_delivery() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        f.tx.take()
            .unwrap()
            .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
            .unwrap()
            .submit(&mut f.gate, true, f.now, || true)
            .unwrap();
        let mut outcome = f.gate.drain_outcomes()[0];
        outcome.id = outcome.id.map(|id| id + 1);
        let result = pending.capture(&lock, outcome);
        drop(lock);
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/clear\r");
    }

    #[test]
    fn intent_from_another_gate_with_equal_visible_fields_cannot_obtain_writer() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (other_gate, other_tx, _) = crate::relay::state::test_owner_transaction(
            f.verifier.target(),
            f.verifier.relay(),
            SlashCmd::Clear,
        );
        let rejected = match f.master.audited_transaction(
            &other_tx,
            &other_gate,
            prepared,
            &mut f.verifier,
            Some(OWNER_NOW),
        ) {
            Ok(_) => panic!("ticket from another gate obtained writer"),
            Err(result) => result,
        };
        assert_eq!(
            rejected.persist(),
            InjectOutcome::Refused(SdkErrorCode::NotAuthorized)
        );
        f.no_bytes();
        assert_eq!(f.records().len(), 2);
    }

    #[test]
    fn refusal_proof_from_another_gate_is_undetermined() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (other_gate, other_tx, _) = crate::relay::state::test_owner_transaction(
            f.verifier.target(),
            f.verifier.relay(),
            SlashCmd::Clear,
        );
        let mismatched_metadata = other_tx.audit_metadata(&other_gate).unwrap();
        let (_owner, pending) = prepared.into_parts();
        // Tests inside the defining module can construct this negative witness;
        // a sibling relay module cannot construct its private fields.
        let proof = BeforeWriteRefusal {
            metadata: mismatched_metadata,
            code: SdkErrorCode::NotIdle,
        };
        assert_eq!(pending.reject(proof).persist(), InjectOutcome::Undetermined);
        f.no_bytes();
        let records = f.records();
        assert_eq!(records.len(), 2);
        assert!(matches!(&records[1].payload,
            crate::audit::types::EventPayload::SessionInject(payload)
                if payload.outcome == crate::audit::types::SessionInjectOutcome::Undetermined
                    && payload.error_code.is_none()));
    }

    #[test]
    fn abandoned_audit_completion_retains_intent_without_repeating_bytes() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, mut pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        f.tx.take()
            .unwrap()
            .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
            .unwrap()
            .submit(&mut f.gate, true, f.now, || true)
            .unwrap();
        let settled = pending.observe_settlement_for_test();
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        drop(result); // Model an audit worker/response task that never completes.
        assert_eq!(
            settled.recv_timeout(Duration::from_secs(10)),
            Ok(true),
            "abandoned_result_terminal_append_must_complete"
        );
        let records = f.records();
        assert_eq!(records.len(), 2);
        assert!(
            matches!(&records[1].payload, crate::audit::types::EventPayload::SessionInject(p)
            if p.outcome == crate::audit::types::SessionInjectOutcome::Undetermined)
        );
        assert_eq!(f.bytes(), b"/clear\r");
        f.no_bytes();
    }

    #[test]
    fn short_kernel_acceptance_cannot_certify_complete_state_receipt() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let (owner, pending) = f.prepare().into_parts();
        let metadata = pending.metadata();
        assert_eq!(
            f.verifier
                .authorize_delivery(owner, Some(OWNER_NOW))
                .unwrap()
                .command(),
            SlashCmd::Clear
        );
        let physical_lease = lease();
        let mut writer = f
            .master
            .test_injection(&physical_lease, metadata.target)
            .unwrap();
        writer.binding = Some(metadata);
        let accepted = writer
            .write_checked(b"/clear", physical_check, |master, bytes| {
                master.write_once(&bytes[..3])
            })
            .unwrap();
        assert_eq!(accepted, 3);
        assert_eq!(writer.accepted_bytes(), 3);
        assert_eq!(writer.fault(), None);
        let lock = f.gate.writer_lock(writer).unwrap();
        // The public receipt is deliberately counterfeit. Only three real
        // bytes were accepted; matching state metadata cannot certify a CR.
        let fabricated = Outcome {
            id: Some(metadata.id),
            kind: metadata.kind,
            terminal: Terminal::Delivered,
        };
        let result = pending.capture(&lock, fabricated);
        drop(lock);
        assert_eq!(
            result.persist(),
            InjectOutcome::Undetermined,
            "short_kernel_acceptance_never_certifies_delivered"
        );
        assert_eq!(f.bytes(), b"/cl");
        f.no_bytes();
        assert!(matches!(&f.records()[1].payload,
            crate::audit::types::EventPayload::SessionInject(payload)
                if payload.outcome == crate::audit::types::SessionInjectOutcome::Undetermined));
    }

    #[test]
    fn abandoned_submission_is_dirty_without_cr_and_retains_honest_result() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        drop(
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .unwrap(),
        );
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/clear");
        assert!(f.gate.snapshot().line_dirty);
    }
    #[test]
    fn owner_disable_between_body_and_cr_revokes_physical_writer() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        let pasted =
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .unwrap();
        f.verifier.disable();
        let submission = pasted.submit(&mut f.gate, true, f.now, || true);
        assert_eq!(
            submission,
            Err(SdkErrorCode::Undetermined),
            "owner_disable_must_suppress_cr"
        );
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/clear", "owner_disable_body_only_no_cr");
        f.no_bytes();
        assert!(f.gate.snapshot().line_dirty);
    }

    #[test]
    fn owner_wall_expiry_between_body_and_cr_suppresses_submission() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Compact);
        let prepared = f.prepare();
        let (mut lock, pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        let pasted =
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .unwrap();
        f.wall
            .store(OWNER_NOW + 30_000, std::sync::atomic::Ordering::Release);
        assert_eq!(
            pasted.submit(&mut f.gate, true, f.now, || true),
            Err(SdkErrorCode::Undetermined),
            "owner_wall_expiry_must_suppress_cr"
        );
        let result = pending.capture(&lock, f.gate.drain_outcomes()[0]);
        drop(lock);
        assert_eq!(result.persist(), InjectOutcome::Undetermined);
        assert_eq!(f.bytes(), b"/compact");
        f.no_bytes();
        assert!(
            !f.request_lease.is_expired(),
            "owner_cutoff_must_preserve_original_reply_window"
        );
    }

    #[test]
    fn caller_must_equal_verified_relay_before_intent_append() {
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let caller = f.verifier.relay();
        let (gate, tx, _) = crate::relay::state::test_owner_transaction(
            f.verifier.target(),
            SessionIdentity {
                pid: caller.pid + 1,
                started_at: caller.started_at,
            },
            SlashCmd::Clear,
        );
        let admission = f.admission(SlashCmd::Clear);
        assert!(
            matches!(
                IntentInput::capture(&tx, &gate, admission),
                Err(SdkErrorCode::NotAuthorized)
            ),
            "caller_must_bind_verified_relay"
        );
        assert!(!f.base.path().join("csq-runs").exists());
        f.no_bytes();
    }

    #[test]
    fn blocking_and_unknown_owner_clock_are_closed_before_byte_refusals() {
        let _env = crate::platform::test_env::lock();
        for unknown_clock in [false, true] {
            let mut f = AuditedFixture::new(SlashCmd::Clear);
            let prepared = f.prepare();
            if !unknown_clock {
                let fd = f.master.master_raw_fd();
                // SAFETY: fixture owns this master for the test duration.
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    assert!(flags >= 0);
                    assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK), 0);
                }
            }
            let wall = if unknown_clock { None } else { Some(OWNER_NOW) };
            let result = match f.master.audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                wall,
            ) {
                Ok(_) => panic!("closed_before_byte_fault_obtained_writer"),
                Err(result) => result,
            };
            assert_eq!(
                result.persist(),
                InjectOutcome::Refused(SdkErrorCode::NotAuthorized),
                "zero_byte_known_fault_must_be_closed_refusal"
            );
            f.no_bytes();
        }
        assert_eq!(
            owner_refusal(OwnerAuthError::GenerationUnavailable),
            SdkErrorCode::NotAuthorized
        );
    }

    #[test]
    fn dropped_pending_audit_revokes_write_only_and_persists_undetermined() {
        let _env = crate::platform::test_env::lock();
        let mut f = AuditedFixture::new(SlashCmd::Clear);
        let prepared = f.prepare();
        let (mut lock, mut pending) = f
            .master
            .audited_transaction(
                f.tx.as_ref().unwrap(),
                &f.gate,
                prepared,
                &mut f.verifier,
                Some(OWNER_NOW),
            )
            .unwrap();
        let settled = pending.observe_settlement_for_test();
        drop(pending);
        assert!(
            f.tx.take()
                .unwrap()
                .paste(&mut f.gate, &mut lock, true, true, f.now, || true)
                .is_err(),
            "dropped_pending_must_revoke_child_write_lease"
        );
        drop(lock);
        assert_eq!(
            settled.recv_timeout(Duration::from_secs(10)),
            Ok(true),
            "dropped_pending_must_settle_undetermined"
        );
        assert!(
            !f.request_lease.is_expired(),
            "dropped_pending_must_preserve_reply_authority"
        );
        f.no_bytes();
        let records = f.records();
        assert_eq!(records.len(), 2);
        assert!(
            matches!(&records[1].payload, crate::audit::types::EventPayload::SessionInject(p)
            if p.outcome == crate::audit::types::SessionInjectOutcome::Undetermined)
        );
    }
}
