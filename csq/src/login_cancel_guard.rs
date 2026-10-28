//! Scoped foreground cancellation for the default CLI vendor login.
//!
//! The handler only changes an atomic latch. The child receives terminal signals
//! from the terminal; this owner does not forward, repeat, or escalate them.

use std::cell::Cell;
use std::fmt;
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Context;

#[path = "login_cancel_guard/piped.rs"]
mod piped;
#[cfg(test)]
pub(crate) use piped::spawn_cli_piped_login;
pub(crate) use piped::spawn_cli_piped_login_scoped;
#[cfg(test)]
pub(crate) use piped::{
    spawn_cli_piped_login_observed_receipt, spawn_cli_piped_login_receipt,
    spawn_cli_piped_login_scoped_observed_receipt, PipedLoginObservation, PipedLoginSpawnOutcome,
    PipedLoginTestHooks,
};

use crate::login_child_custody::{
    DeliveryPhase, LoginChildRefusal, LoginWatchdog, OwnedLoginChild, RefusalReason,
    TimeoutDisposition, TimeoutNotice,
};

const INACTIVE: u8 = 0;
const ACTIVE: u8 = 1;
const CANCELLED: u8 = 2;
const SEALED: u8 = 3;
const SEALED_CANCELLED: u8 = 4;
static INTERRUPTS: AtomicU8 = AtomicU8::new(0);
#[cfg(unix)]
static TERMINATION_SIGNALS: AtomicU8 = AtomicU8::new(0);
static CANCELLATION: AtomicU8 = AtomicU8::new(INACTIVE);
/// One scoped cancellation guard per process; a second `install` refuses.
///
/// Test contract: every test in the `csq` test binary that can reach
/// [`ScopedLoginCancellation::install`] — directly, through
/// [`with_cli_login_session`], through an unscoped `spawn_cli_*` wrapper, or
/// through a `cli::commands::login` handle (`handle_codex`, `handle_native`,
/// `handle_direct`) — MUST hold `csq_core::platform::test_env::lock()` for
/// its whole body. An unserialized installer makes a sibling's `install`
/// refuse with "another foreground login owns the cancellation handler".
static INSTALLATION: Mutex<()> = Mutex::new(());

// This CAS is the cancellation linearization point. Inactive callbacks do not
// alter the latch. OS unregistration does not synchronize callbacks that were
// already dispatched; no stronger kernel-delivery boundary is claimed here.
fn latch_cancelled() -> bool {
    loop {
        let state = CANCELLATION.load(Ordering::SeqCst);
        let cancelled = match state {
            ACTIVE => CANCELLED,
            SEALED => SEALED_CANCELLED,
            CANCELLED | SEALED_CANCELLED => return true,
            _ => return false,
        };
        if CANCELLATION
            .compare_exchange(state, cancelled, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

fn request_interrupt() -> bool {
    if !latch_cancelled() {
        return false;
    }
    let _ = INTERRUPTS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
        Some(count.saturating_add(1).min(2))
    });
    true
}

#[cfg(unix)]
fn request_termination(flag: u8) {
    if latch_cancelled() {
        TERMINATION_SIGNALS.fetch_or(flag, Ordering::SeqCst);
    }
}

fn attach_signal_pump(group: &crate::login_child_custody::group::GroupControl) {
    use crate::login_child_custody::group::GroupSignal;
    let mut interrupts = 0;
    #[cfg(unix)]
    let mut termination = 0;
    group.set_signal_pump(move |group| {
        let count = INTERRUPTS.load(Ordering::SeqCst);
        while interrupts < count {
            group.signal(if interrupts == 0 {
                GroupSignal::Interrupt
            } else {
                GroupSignal::Kill
            })?;
            interrupts += 1;
        }
        #[cfg(unix)]
        {
            let flags = TERMINATION_SIGNALS.load(Ordering::SeqCst);
            for (flag, signal) in [
                (1, GroupSignal::Terminate),
                (2, GroupSignal::Hangup),
                (4, GroupSignal::Quit),
            ] {
                if flags & flag != 0 && termination & flag == 0 {
                    group.signal(signal)?;
                    termination |= flag;
                }
            }
        }
        Ok(())
    });
}

/// CLI-only notice: the shared desktop notice has a different explicit action.
pub(crate) fn print_cli_notice(notice: TimeoutNotice, account: csq_core::types::AccountNum) {
    match notice.disposition {
        TimeoutDisposition::Retained => eprintln!("{}: sign-in program is still running; press Ctrl-C to request cancellation, then Ctrl-C again to end its process group (account {account})", notice.tag()),
        TimeoutDisposition::Terminated => eprintln!("{}: sign-in program was terminated at the deadline; canonical login publication refused (account {account})", notice.tag()),
    }
}

/// Owns one installed handler until the foreground child has actually reaped.
/// Declare before the child owner so unwinding drains the child before restoring.
pub(crate) struct ScopedLoginCancellation {
    installed: Option<platform::Installed>,
    closed: bool,
    was_cancelled: bool,
    was_sealed: bool,
    committed: Cell<bool>,
    _installation: MutexGuard<'static, ()>,
}

impl ScopedLoginCancellation {
    pub(crate) fn install() -> io::Result<Self> {
        let installation = match INSTALLATION.try_lock() {
            Ok(installation) => installation,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::other(
                    "another foreground login owns the cancellation handler",
                ));
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let installation = poisoned.into_inner();
                // This mutex guards no data; lifecycle state is CANCELLATION.
                // Unwind drops the reader and child before this guard restores
                // the handler and commits INACTIVE. Its MutexGuard then poisons
                // on drop because the original panic is still unwinding.
                // Recover only with exclusive ownership and that close commit;
                // an unfinished restoration must remain refused and poisoned.
                if CANCELLATION.load(Ordering::SeqCst) != INACTIVE {
                    return Err(io::Error::other(
                        "scoped terminal cancellation handler restoration is incomplete",
                    ));
                }
                INSTALLATION.clear_poison();
                installation
            }
        };
        INTERRUPTS.store(0, Ordering::SeqCst);
        #[cfg(unix)]
        TERMINATION_SIGNALS.store(0, Ordering::SeqCst);
        CANCELLATION.store(ACTIVE, Ordering::SeqCst);
        // SCOPED_LOGIN_HANDLER_INSTALL: baseline/mutant changes only this line.
        let installed = match platform::Installed::install() {
            Ok(installed) => Some(installed),
            Err(error) => {
                CANCELLATION.store(INACTIVE, Ordering::SeqCst);
                return Err(error);
            }
        };
        Ok(Self {
            installed,
            closed: false,
            was_cancelled: false,
            was_sealed: false,
            committed: Cell::new(false),
            _installation: installation,
        })
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.was_cancelled
            || (!self.closed
                && matches!(
                    CANCELLATION.load(Ordering::SeqCst),
                    CANCELLED | SEALED_CANCELLED
                ))
    }

    /// This CAS is the publication boundary, immediately before the first
    /// canonical write. A later cancellation must finish the sealed commit.
    pub(crate) fn seal_publication(&self) -> anyhow::Result<()> {
        match CANCELLATION.compare_exchange(ACTIVE, SEALED, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => Ok(()),
            Err(CANCELLED) => Err(cancelled_before_spawn()),
            Err(SEALED | SEALED_CANCELLED) => {
                Err(anyhow::anyhow!("login publication already sealed"))
            }
            Err(_) => Err(anyhow::anyhow!("login publication guard is inactive")),
        }
    }

    pub(crate) fn mark_publication_committed(&self) {
        self.committed.set(true);
    }

    pub(crate) fn publication_sealed(&self) -> bool {
        self.was_sealed
            || (!self.closed
                && matches!(
                    CANCELLATION.load(Ordering::SeqCst),
                    SEALED | SEALED_CANCELLED
                ))
    }

    /// Close only after actual reap/reader join and, for a caller-owned session,
    /// after sealed publication/finalization completes. Restore first, then
    /// atomically close/read the cancellation latch.
    pub(crate) fn close(&mut self) -> io::Result<bool> {
        if !self.closed {
            if let Some(installed) = self.installed.as_mut() {
                installed.restore()?;
            }
            self.installed = None;
            let state = CANCELLATION.swap(INACTIVE, Ordering::SeqCst);
            self.was_cancelled = matches!(state, CANCELLED | SEALED_CANCELLED);
            self.was_sealed = matches!(state, SEALED | SEALED_CANCELLED);
            self.closed = true;
        }
        Ok(self.was_cancelled)
    }
}

impl Drop for ScopedLoginCancellation {
    fn drop(&mut self) {
        if self.close().is_err() {
            // The spawn helpers declare this guard before their child owner, so
            // the owner's Drop has already drained the actual child before this
            // final retry can fail. Before spawn there is no child to retain.
            // Refuse reuse/publication without producing a process-memory dump.
            eprintln!("login_cancel_handler_restore_refused: unable to restore terminal handler");
            std::process::exit(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct CliLoginCustodyUnresolved;
impl fmt::Display for CliLoginCustodyUnresolved {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("login_custody_unresolved: vendor group custody was not proved complete; publication refused")
    }
}
impl std::error::Error for CliLoginCustodyUnresolved {}
pub(crate) fn custody_unresolved(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CliLoginCustodyUnresolved>().is_some()
}

#[derive(Debug)]
struct CliLoginFinalizationCancelled;
impl fmt::Display for CliLoginFinalizationCancelled {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("login_commit_interrupted: cancellation followed publication seal; finalization failed; inspect the account before retry")
    }
}
impl std::error::Error for CliLoginFinalizationCancelled {}

#[derive(Debug)]
struct CliLoginCommittedCancelled(csq_core::types::AccountNum);
impl fmt::Display for CliLoginCommittedCancelled {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "login_committed_cancelled: account {} WAS signed in before cancellation; sign-in finalization completed", self.0)
    }
}
impl std::error::Error for CliLoginCommittedCancelled {}

/// Retains signal custody across vendor wait, publication seal and finalization.
pub(crate) fn with_cli_login_session(
    account: csq_core::types::AccountNum,
    body: impl FnOnce(&ScopedLoginCancellation) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut cancellation = ScopedLoginCancellation::install()?;
    let result = body(&cancellation);
    let sealed = cancellation.publication_sealed();
    let committed = cancellation.committed.get() || (sealed && result.is_ok());
    let cancelled = cancellation
        .close()
        .context("failed to restore terminal cancellation handler")?;
    if result.as_ref().is_err_and(custody_unresolved) {
        return result;
    }
    if cancelled {
        if committed {
            return match result {
                Ok(()) => Err(CliLoginCommittedCancelled(account).into()),
                Err(error) => Err(error.context(CliLoginCommittedCancelled(account))),
            };
        }
        if sealed {
            return Err(result
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("sealed login did not finalize"))
                .context(CliLoginFinalizationCancelled));
        }
        return match result {
            Ok(()) => Err(cancelled_before_spawn()),
            Err(error) => Err(error.context(cancelled_before_spawn())),
        };
    }
    result
}

/// Positive authority attached only before any spawn attempt or after actual
/// owner reap and every captured reader join. Absence of UND is insufficient.
#[derive(Debug)]
pub(crate) struct CliLoginCustodyFinalized;
impl fmt::Display for CliLoginCustodyFinalized {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("vendor_login_custody_finalized")
    }
}
impl std::error::Error for CliLoginCustodyFinalized {}

/// Keep the typed cancellation/error chain when a completion fence fails.
pub(crate) fn complete_vendor_grant<T>(
    grant: &std::sync::Arc<
        std::sync::Mutex<csq_core::accounts::credential_transaction::VendorLoginGrant>,
    >,
    result: anyhow::Result<T>,
) -> anyhow::Result<T> {
    if result.is_ok()
        || result
            .as_ref()
            .is_err_and(|error| error.downcast_ref::<CliLoginCustodyFinalized>().is_some())
    {
        let completion = grant
            .lock()
            .map_err(|_| anyhow::anyhow!("vendor grant lock poisoned"))
            .and_then(|mut grant| grant.mark_completed());
        if let Err(error) = completion {
            return match result {
                Ok(_) => Err(error),
                Err(original) => Err(original.context(error)),
            };
        }
    }
    result
}

/// Spawning grants refuse cleanup themselves and retain their private home.
/// Cleanup diagnostics never replace the original typed cancellation receipt.
pub(crate) fn cleanup_vendor_grant<T>(
    grant: &std::sync::Arc<
        std::sync::Mutex<csq_core::accounts::credential_transaction::VendorLoginGrant>,
    >,
    result: anyhow::Result<T>,
) -> anyhow::Result<T> {
    let cleanup = grant
        .lock()
        .map_err(|_| anyhow::anyhow!("vendor grant lock poisoned"))
        .and_then(|mut grant| grant.cleanup());
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(original), Err(error)) => Err(original.context(error)),
    }
}

#[derive(Debug)]
pub(crate) struct CliLoginCancelled {
    prior_refusal: Option<LoginChildRefusal>,
    #[cfg(test)]
    child_id: Option<u32>,
    #[cfg(test)]
    reaped_status: Option<std::process::ExitStatus>,
    #[cfg(test)]
    joined_reader_thread_id: Option<std::thread::ThreadId>,
}

#[cfg(test)]
impl CliLoginCancelled {
    pub(crate) fn child_id(&self) -> Option<u32> {
        self.child_id
    }
    pub(crate) fn reaped_status(&self) -> Option<std::process::ExitStatus> {
        self.reaped_status
    }
    pub(crate) fn reader_joined_thread_id(&self) -> Option<std::thread::ThreadId> {
        self.joined_reader_thread_id
    }
}

impl fmt::Display for CliLoginCancelled {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(
            "login_cancelled_refused: user cancelled login; canonical login publication refused",
        )
    }
}
impl std::error::Error for CliLoginCancelled {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.prior_refusal.as_ref().map(|refusal| refusal as _)
    }
}

/// Used by main's actual CLI error dispatch, after all operation guards drop.
pub(crate) fn cli_error_exit_code(error: &anyhow::Error) -> i32 {
    if error.downcast_ref::<CliLoginCancelled>().is_some()
        || error.downcast_ref::<CliLoginCommittedCancelled>().is_some()
        || error
            .downcast_ref::<CliLoginFinalizationCancelled>()
            .is_some()
    {
        130
    } else {
        1
    }
}

fn cancelled_before_spawn() -> anyhow::Error {
    CliLoginCancelled {
        prior_refusal: None,
        #[cfg(test)]
        child_id: None,
        #[cfg(test)]
        reaped_status: None,
        #[cfg(test)]
        joined_reader_thread_id: None,
    }
    .into()
}

/// Actual completion from the single owned spawn/wait body. The test receipt
/// adds the original Child identity; status comes from the actual owner below.
pub(crate) struct CliLoginReceipt {
    status: std::process::ExitStatus,
    #[cfg(test)]
    child_id: u32,
    #[cfg(test)]
    joined_reader_thread_id: Option<std::thread::ThreadId>,
}

#[cfg(test)]
impl CliLoginReceipt {
    pub(crate) fn child_id(&self) -> u32 {
        self.child_id
    }
    pub(crate) fn reaped_status(&self) -> std::process::ExitStatus {
        self.status
    }
    pub(crate) fn reader_joined_thread_id(&self) -> Option<std::thread::ThreadId> {
        self.joined_reader_thread_id
    }
}

/// Shared production seam: Command is fully built before entry. K can retain an
/// actual account lock; the caller's enclosing account lock also spans this call.
#[cfg(test)]
pub(crate) fn spawn_cli_login<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    notice: impl FnMut(TimeoutNotice),
) -> anyhow::Result<bool> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        "Claude",
        notice,
        None,
        DeadlineStop::TerminateGroup,
        &mut false,
    )
    .map(|receipt| receipt.status.success())
}

/// Test receipt from the same production body, including actual owner reap proof.
#[cfg(test)]
pub(crate) fn spawn_cli_login_receipt<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    notice: impl FnMut(TimeoutNotice),
) -> anyhow::Result<CliLoginReceipt> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        "Claude",
        notice,
        None,
        DeadlineStop::TerminateGroup,
        &mut false,
    )
}

/// Vendor-labelled inherited-stdio sibling used by native CLI login runners.
#[cfg(test)]
pub(crate) fn spawn_cli_inherited_login<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    notice: impl FnMut(TimeoutNotice),
) -> anyhow::Result<std::process::ExitStatus> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        notice,
        None,
        DeadlineStop::Retain,
        &mut false,
    )
    .map(|receipt| receipt.status)
}

#[cfg(test)]
pub(crate) fn spawn_cli_inherited_login_receipt<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    notice: impl FnMut(TimeoutNotice),
) -> anyhow::Result<CliLoginReceipt> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        notice,
        None,
        DeadlineStop::Retain,
        &mut false,
    )
}

/// `deadline_stopped` is an OUT parameter: the wait loop records whether the
/// caller's deadline stop ACTUALLY SUCCEEDED, and the CLI's operator paragraph
/// keys on that fact after the actual reap — on the success AND the refusal
/// path alike (a setup refusal that came first does not suppress it).
pub(crate) fn spawn_cli_login_scoped<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    notice: impl FnMut(TimeoutNotice),
    cancellation: &ScopedLoginCancellation,
    deadline_stopped: &mut bool,
) -> anyhow::Result<bool> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        "Claude",
        notice,
        Some(cancellation),
        DeadlineStop::TerminateGroup,
        deadline_stopped,
    )
    .map(|receipt| receipt.status.success())
}

pub(crate) fn spawn_cli_inherited_login_scoped<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    notice: impl FnMut(TimeoutNotice),
    cancellation: &ScopedLoginCancellation,
) -> anyhow::Result<std::process::ExitStatus> {
    spawn_cli_inherited_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        notice,
        Some(cancellation),
        DeadlineStop::Retain,
        &mut false,
    )
    .map(|receipt| receipt.status)
}

/// What the deadline may do to the vendor once the watchdog refuses it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineStop {
    /// Custody only: refuse publication and wait for the actual reap.
    Retain,
    /// dev's CLI contract for `csq login`: kill the whole vendor process group
    /// at the deadline, then STILL wait for the actual reap before refusing
    /// publication. Only paths where dev killed at a deadline pass this.
    TerminateGroup,
}

// One shared production seam: every wrapper differs only in these parameters,
// and the out-parameter must be set on the refusal path too (no receipt).
#[allow(clippy::too_many_arguments)]
fn spawn_cli_inherited_login_inner<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    mut notice: impl FnMut(TimeoutNotice),
    scope: Option<&ScopedLoginCancellation>,
    deadline_stop: DeadlineStop,
    deadline_stopped: &mut bool,
) -> anyhow::Result<CliLoginReceipt> {
    let watchdog = LoginWatchdog::new(timeout, DeliveryPhase::Unknown);
    watchdog
        .check_spawn_allowed()
        .context(CliLoginCustodyFinalized)?;
    // Guard precedes actual spawn AND the owner declaration: error/unwind drops
    // the owner (which drains actual Child custody) before restoring the handler.
    let mut local_cancellation = if scope.is_none() {
        Some(
            ScopedLoginCancellation::install()
                .context("failed to install scoped terminal cancellation handler")
                .context(CliLoginCustodyFinalized)?,
        )
    } else {
        None
    };
    let cancellation = scope
        .or(local_cancellation.as_ref())
        .expect("local or caller cancellation guard");
    if cancellation.cancelled() {
        eprintln!("Cancelling — waiting for {vendor} login to exit");
        return Err(cancelled_before_spawn().context(CliLoginCustodyFinalized));
    }
    let (child, group) = match crate::login_child_custody::group::spawn(command) {
        Ok(child) => child,
        Err(error) => {
            if cancellation.cancelled() {
                eprintln!("Cancelling — waiting for {vendor} login to exit");
                return Err(cancelled_before_spawn());
            }
            return Err(error).context("failed to spawn sign-in program");
        }
    };
    #[cfg(test)]
    let child_id = child.id();
    let mut owned = OwnedLoginChild::adopt_group(child, group.clone(), watchdog.clone(), keepalive);
    attach_signal_pump(&group);
    let group_for_deadline = group.clone();
    let mut announced_cancel = false;
    let result = owned.wait_vendor_cancelled(
        || Ok(true), // inherited stdio: no csq-owned reader/forwarder to join.
        |event| {
            if event.reason != RefusalReason::Cancelled {
                notice(event);
            }
        },
        move || match deadline_stop {
            // The lane's group primitive: killpg on Unix, the Job on Windows.
            // Reap and custody completion still run in the loop below.
            DeadlineStop::TerminateGroup => {
                group_for_deadline.signal(crate::login_child_custody::group::GroupSignal::Kill)
            }
            DeadlineStop::Retain => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "opaque vendor login has no proven PRE-delivery stop path",
            )),
        },
        || {
            let cancelled = cancellation.cancelled();
            if cancelled && !announced_cancel {
                eprintln!("Cancelling — waiting for {vendor} login to exit");
                announced_cancel = true;
            }
            cancelled
        },
    );
    // Carry the SUCCEEDED deadline stop out of the wait before ANY error path:
    // the operator paragraph prints after the reap on the refusal path too.
    *deadline_stopped = owned.deadline_stopped();
    // wait_vendor_cancelled returns only after actual child reap. The final
    // restore/read also rejects a signal latched after the watchdog's seal check.
    if !owned.custody_finalized() {
        return Err(CliLoginCustodyUnresolved.into());
    }
    let mut was_cancelled = cancellation.cancelled();
    if let Some(local) = local_cancellation.as_mut() {
        was_cancelled |= local
            .close()
            .context("failed to restore terminal cancellation handler")
            .context(CliLoginCustodyFinalized)?;
    }
    if was_cancelled {
        if !announced_cancel {
            eprintln!("Cancelling — waiting for {vendor} login to exit");
        }
        return Err(anyhow::Error::new(CliLoginCancelled {
            prior_refusal: result.err(),
            #[cfg(test)]
            child_id: Some(child_id),
            #[cfg(test)]
            reaped_status: owned.reaped_status(),
            #[cfg(test)]
            joined_reader_thread_id: None,
        }))
        .context(CliLoginCustodyFinalized);
    }
    let status = result.context(CliLoginCustodyFinalized)?;
    #[cfg(test)]
    let actual_reaped_status = owned
        .reaped_status()
        .context("login child completed without an actual owner reap receipt")?;
    #[cfg(test)]
    if actual_reaped_status != status {
        return Err(anyhow::anyhow!(
            "login child completion disagrees with actual owner reap receipt"
        ));
    }
    Ok(CliLoginReceipt {
        #[cfg(not(test))]
        status,
        #[cfg(test)]
        status: actual_reaped_status,
        #[cfg(test)]
        child_id,
        #[cfg(test)]
        joined_reader_thread_id: None,
    })
}

#[cfg(unix)]
mod platform {
    use super::{io, request_interrupt, request_termination};
    extern "C" fn on_signal(signal: libc::c_int) {
        match signal {
            libc::SIGINT => {
                request_interrupt();
            }
            libc::SIGTERM => request_termination(1),
            libc::SIGHUP => request_termination(2),
            libc::SIGQUIT => request_termination(4),
            _ => {}
        }
    }
    pub(super) struct Installed {
        previous: Vec<(libc::c_int, libc::sigaction)>,
    }
    impl Installed {
        pub(super) fn install() -> io::Result<Self> {
            let mut installed = Self {
                previous: Vec::with_capacity(4),
            };
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                // SAFETY: initialize a complete action before passing it to libc.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = on_signal as *const () as usize;
                action.sa_flags = libc::SA_RESTART;
                // SAFETY: action owns the initialized writable mask.
                if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
                    let error = io::Error::last_os_error();
                    if installed.restore().is_err() {
                        std::process::exit(1);
                    }
                    return Err(error);
                }
                let mut previous = std::mem::MaybeUninit::<libc::sigaction>::uninit();
                // SAFETY: valid action and previous output; only initialized on success.
                if unsafe { libc::sigaction(signal, &action, previous.as_mut_ptr()) } != 0 {
                    let error = io::Error::last_os_error();
                    if installed.restore().is_err() {
                        std::process::exit(1);
                    }
                    return Err(error);
                }
                // SAFETY: successful sigaction initialized the previous action.
                installed
                    .previous
                    .push((signal, unsafe { previous.assume_init() }));
            }
            Ok(installed)
        }
        pub(super) fn restore(&mut self) -> io::Result<()> {
            for (signal, previous) in self.previous.iter().rev() {
                // SAFETY: restore complete actions obtained from successful sigaction.
                if unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{io, request_interrupt};

    type Handler = Option<unsafe extern "system" fn(u32) -> i32>;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Handler, add: i32) -> i32;
    }
    unsafe extern "system" fn on_console_control(event: u32) -> i32 {
        // CTRL_C_EVENT = 0; CTRL_BREAK_EVENT = 1. FALSE lets every other event
        // continue through the prior handler list. CLOSE/LOGOFF/SHUTDOWN have OS
        // deadlines and are outside retained-custody guarantees. Group work runs
        // only in the caller/cleanup pump, never in this OS callback.
        if event <= 1 && request_interrupt() {
            1
        } else {
            0
        }
    }
    pub(super) struct Installed;
    impl Installed {
        pub(super) fn install() -> io::Result<Self> {
            // SAFETY: callback has the documented kernel32 ABI and static
            // lifetime. Adding this entry preserves the existing handler list.
            if unsafe { SetConsoleCtrlHandler(Some(on_console_control), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self)
        }
        pub(super) fn restore(&mut self) -> io::Result<()> {
            // SAFETY: remove exactly the callback this guard successfully added;
            // prior handler entries and the inherited default remain registered.
            if unsafe { SetConsoleCtrlHandler(Some(on_console_control), 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::io;
    pub(super) struct Installed;
    impl Installed {
        pub(super) fn install() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "scoped login cancellation is unavailable on this platform",
            ))
        }
        pub(super) fn restore(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use std::process::Stdio;

    fn inert_command(root: &std::path::Path, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command
            .env_clear()
            .current_dir(root)
            .env("HOME", root)
            .env("USERPROFILE", root)
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("CLAUDE_CONFIG_DIR", root.join("config"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("APPDATA", root.join("appdata"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("PATH", root.join("bin"))
            .env("TMPDIR", root)
            .env("TEMP", root)
            .env("TMP", root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Windows loader essentials only; user HOME/config/auth state stays private.
        for key in ["SystemRoot", "SYSTEMROOT", "WINDIR", "ComSpec", "PATHEXT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
    }

    #[test]
    fn receipt_accessors_preserve_actual_owned_child_and_error_mapping() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            assert_eq!(
                csq_core::platform::secret::open_default_vault()
                    .expect("LOGIN_CLI_RECEIPT_HERMETIC_BACKEND: unavailable")
                    .backend_id(),
                "in-memory",
                "LOGIN_CLI_RECEIPT_HERMETIC_BACKEND"
            );
            let sandbox = tempfile::tempdir().expect("private receipt fixture root");
            for directory in ["base", "config", "appdata", "local", "bin"] {
                std::fs::create_dir(sandbox.path().join(directory))
                    .expect("private fixture directory");
            }
            // Libtest --list enumerates names and exits without executing any test,
            // auth, discovery or keychain path. The production owner reaps this child.
            let mut command = inert_command(
                sandbox.path(),
                std::env::current_exe().expect("actual inert test harness"),
            );
            command.arg("--list");
            let grant = std::sync::Arc::new(std::sync::Mutex::new(
                csq_core::accounts::credential_transaction::VendorLoginGrant::new(
                    &sandbox.path().join("base"),
                )
                .expect("private grant"),
            ));
            let home = grant.lock().unwrap().config_dir().to_path_buf();
            grant
                .lock()
                .unwrap()
                .begin_launch()
                .expect("actual launch fence");
            let result = spawn_cli_login_receipt(
                &mut command,
                Duration::from_secs(30),
                std::sync::Arc::clone(&grant),
                |_| panic!("inert receipt control unexpectedly refused"),
            );
            let receipt =
                complete_vendor_grant(&grant, result).expect("actual inert child completion");
            cleanup_vendor_grant(&grant, Ok(())).expect("actual finalized grant cleanup");
            assert!(!home.exists(), "LOGIN_CLI_ACTUAL_REAP_GRANT_CLEANUP");
            assert!(receipt.child_id() > 0);
            assert!(receipt.reaped_status().success());

            // Accessor/mapping check only: these values come from the real success
            // receipt above. Actual terminal cancellation is tested by signal fixtures.
            let cancelled = CliLoginCancelled {
                prior_refusal: None,
                child_id: Some(receipt.child_id()),
                reaped_status: Some(receipt.reaped_status()),
                joined_reader_thread_id: None,
            };
            assert_eq!(cancelled.child_id(), Some(receipt.child_id()));
            assert_eq!(cancelled.reaped_status(), Some(receipt.reaped_status()));
            assert!(cancelled.reader_joined_thread_id().is_none());
            assert!(receipt.reader_joined_thread_id().is_none());
            let error: anyhow::Error = cancelled.into();
            assert_eq!(
                cli_error_exit_code(&error.context("receipt mapping control")),
                130
            );

            // Exercise the unchanged production bool API and its install/spawn-error
            // cleanup through a private nonexistent executable, with no PATH search.
            let mut missing = inert_command(
                sandbox.path(),
                sandbox.path().join("missing-sign-in-program"),
            );
            let error = spawn_cli_login(&mut missing, Duration::from_secs(30), (), |_| {
                panic!("a spawn error has no running child timeout")
            })
            .expect_err("nonexistent private executable must fail");
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
            assert_eq!(cli_error_exit_code(&error), 1);
        });
    }

    #[test]
    fn inherited_vendor_receipt_preserves_actual_child_and_spawn_error() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private inherited vendor receipt root");
        for directory in ["base", "config", "appdata", "local", "bin"] {
            std::fs::create_dir(sandbox.path().join(directory)).expect("private fixture directory");
        }
        let mut command = inert_command(
            sandbox.path(),
            std::env::current_exe().expect("actual inherited vendor test harness"),
        );
        command.args(["--list", "receipt_tests"]);
        let receipt = spawn_cli_inherited_login_receipt(
            &mut command,
            Duration::from_secs(30),
            (),
            "Kimi",
            |_| panic!("inert inherited receipt unexpectedly refused"),
        )
        .expect("actual inherited child completion");
        assert!(receipt.child_id() > 0);
        assert!(receipt.reaped_status().success());
        assert!(receipt.reader_joined_thread_id().is_none());
        let mut missing = inert_command(
            sandbox.path(),
            sandbox.path().join("missing-native-sign-in-program"),
        );
        let error =
            spawn_cli_inherited_login(&mut missing, Duration::from_secs(30), (), "Grok", |_| {
                panic!("nonexistent native child cannot reach timeout")
            })
            .expect_err("nonexistent private inherited executable");
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
        assert_eq!(cli_error_exit_code(&error), 1);
    }

    #[test]
    fn piped_receipt_joins_actual_reader_and_callbacks_stay_on_caller() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private piped receipt root");
        for directory in ["base", "config", "appdata", "local", "bin"] {
            std::fs::create_dir(sandbox.path().join(directory)).expect("private fixture directory");
        }
        let mut command = inert_command(
            sandbox.path(),
            std::env::current_exe().expect("actual inert test harness"),
        );
        // Enumerate only these inert API tests; --list executes none of them.
        command
            .args(["--list", "receipt_tests"])
            .stdout(Stdio::piped());
        let caller = std::thread::current().id();
        let eof_thread = std::sync::Arc::new(std::sync::Mutex::new(None));
        let gate_thread = std::sync::Arc::clone(&eof_thread);
        let stdout = std::io::stdout();
        let mut held_stdout = stdout.lock();
        let mut lines = 0;
        let receipt = spawn_cli_piped_login_receipt(
            &mut command,
            Duration::from_secs(30),
            (),
            "Codex",
            |_| {
                assert_eq!(std::thread::current().id(), caller);
                std::io::Write::flush(&mut held_stdout).expect("caller-owned stdout lock");
                lines += 1;
            },
            |_| panic!("inert piped receipt unexpectedly refused"),
            move || {
                *gate_thread.lock().expect("actual EOF thread receipt") =
                    Some(std::thread::current().id());
            },
        )
        .expect("actual piped child and reader completion");
        assert!(receipt.child_id() > 0);
        assert!(receipt.reaped_status().success());
        assert!(lines > 0);
        let joined = receipt
            .reader_joined_thread_id()
            .expect("actual reader join");
        assert_ne!(joined, caller);
        assert_eq!(
            Some(joined),
            *eof_thread.lock().expect("actual EOF receipt")
        );

        let mut observed_command = inert_command(
            sandbox.path(),
            std::env::current_exe().expect("actual observed test harness"),
        );
        observed_command
            .args(["--list", "receipt_tests"])
            .stdout(Stdio::piped());
        let mut actual_join_observed = None;
        let mut actual_child_observed = None;
        let mut actual_status_observed = None;
        let mut actual_reader_finished = false;
        let mut terminal_observations = 0_usize;
        let adopted_child = std::sync::Arc::new(std::sync::Mutex::new(None));
        let adopted_callback = std::sync::Arc::clone(&adopted_child);
        let spawn_phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let phase_callback = std::sync::Arc::clone(&spawn_phases);
        let observed = spawn_cli_piped_login_observed_receipt(
            &mut observed_command,
            Duration::from_secs(30),
            (),
            "Codex",
            |_| assert_eq!(std::thread::current().id(), caller),
            |_| panic!("inert observed receipt unexpectedly refused"),
            PipedLoginTestHooks::new(
                || {},
                |observation: PipedLoginObservation| {
                    assert_eq!(std::thread::current().id(), caller);
                    if observation.reader_joined_thread_id.is_some() {
                        if observation.reaped_status.is_some() {
                            terminal_observations += 1;
                        }
                        actual_join_observed = observation.reader_joined_thread_id;
                        actual_child_observed = Some(observation.child_id);
                        actual_status_observed = observation.reaped_status;
                        actual_reader_finished = observation.reader_is_finished;
                    }
                },
            )
            .with_adopted_child(move |child| {
                *adopted_callback
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(child);
            })
            .with_spawn_outcome(move |phase| {
                phase_callback
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(phase);
            }),
        )
        .expect("actual observed reader join");
        assert_eq!(actual_join_observed, observed.reader_joined_thread_id());
        assert_eq!(actual_child_observed, Some(observed.child_id()));
        assert_eq!(actual_status_observed, Some(observed.reaped_status()));
        assert!(actual_reader_finished);
        assert_eq!(
            terminal_observations, 1,
            "exactly one terminal owner snapshot"
        );
        let adopted = adopted_child
            .lock()
            .expect("actual adopted child storage")
            .take()
            .expect("actual child was adopted before stdout handoff");
        assert_eq!(
            adopted.lock().expect("actual adopted Child").id(),
            observed.child_id()
        );
        // No second try_wait/wait: production's receipt supplies the actual reap.
        assert_eq!(
            *spawn_phases.lock().expect("actual spawn phases"),
            vec![
                PipedLoginSpawnOutcome::NoVendorBeforeSpawn,
                PipedLoginSpawnOutcome::SpawnAttemptStarted,
            ]
        );

        let failed_phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let failed_phase_callback = std::sync::Arc::clone(&failed_phases);
        let failed_adopted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed_adopted_callback = std::sync::Arc::clone(&failed_adopted);
        let mut failed_command = inert_command(
            sandbox.path(),
            sandbox.path().join("missing-custody-hook-program"),
        );
        failed_command.stdout(Stdio::piped());
        let failed = spawn_cli_piped_login_observed_receipt(
            &mut failed_command,
            Duration::from_secs(30),
            (),
            "Codex",
            |_| panic!("nonexistent child cannot produce output"),
            |_| panic!("nonexistent child cannot reach a deadline"),
            PipedLoginTestHooks::new(|| {}, |_| panic!("no child was adopted"))
                .with_adopted_child(move |_| {
                    failed_adopted_callback.store(true, std::sync::atomic::Ordering::SeqCst);
                })
                .with_spawn_outcome(move |phase| {
                    failed_phase_callback
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(phase);
                }),
        );
        let failed = match failed {
            Ok(_) => panic!("nonexistent custody-hook program must fail"),
            Err(error) => error,
        };
        assert!(failed.chain().any(|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
        assert!(!failed_adopted.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            *failed_phases.lock().expect("failed spawn phases"),
            vec![
                PipedLoginSpawnOutcome::NoVendorBeforeSpawn,
                PipedLoginSpawnOutcome::SpawnAttemptStarted,
                PipedLoginSpawnOutcome::NotSpawned,
            ]
        );

        let setup_phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let setup_phase_callback = std::sync::Arc::clone(&setup_phases);
        let mut setup_command = inert_command(
            sandbox.path(),
            sandbox.path().join("not-attempted-custody-hook-program"),
        );
        let setup = spawn_cli_piped_login_observed_receipt(
            &mut setup_command,
            Duration::MAX,
            (),
            "Codex",
            |_| panic!("deadline overflow cannot produce output"),
            |_| panic!("deadline overflow refuses before notices"),
            PipedLoginTestHooks::new(|| {}, |_| panic!("deadline overflow has no child"))
                .with_adopted_child(|_| panic!("deadline overflow cannot adopt a child"))
                .with_spawn_outcome(move |phase| {
                    setup_phase_callback
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(phase);
                }),
        );
        let setup = match setup {
            Ok(_) => panic!("deadline overflow must refuse before spawn"),
            Err(error) => error,
        };
        assert!(setup
            .downcast_ref::<LoginChildRefusal>()
            .is_some_and(|refusal| refusal.reason == RefusalReason::DeadlineOverflow));
        assert_eq!(
            *setup_phases.lock().expect("pre-spawn setup phases"),
            vec![PipedLoginSpawnOutcome::NoVendorBeforeSpawn,]
        );

        // Cover the production ExitStatus API and pre-child spawn-error cleanup.
        let mut missing = inert_command(
            sandbox.path(),
            sandbox.path().join("missing-piped-sign-in-program"),
        );
        missing.stdout(Stdio::piped());
        let error = spawn_cli_piped_login(
            &mut missing,
            Duration::from_secs(30),
            (),
            "Codex",
            |_| panic!("nonexistent child cannot produce a line"),
            |_| panic!("nonexistent child cannot reach a timeout"),
        )
        .expect_err("nonexistent private piped executable");
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
        assert_eq!(cli_error_exit_code(&error), 1);
    }

    #[test]
    fn piped_adoption_hook_panic_hands_actual_stdout_to_reader() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private adopted-panic root");
        for directory in ["base", "config", "appdata", "local", "bin"] {
            std::fs::create_dir(sandbox.path().join(directory)).expect("private fixture directory");
        }
        let mut command = inert_command(
            sandbox.path(),
            std::env::current_exe().expect("actual adopted-panic test harness"),
        );
        command
            .args(["--list", "receipt_tests"])
            .stdout(Stdio::piped());
        let adopted = std::sync::Arc::new(std::sync::Mutex::new(None));
        let adopted_callback = std::sync::Arc::clone(&adopted);
        let eof_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let eof_callback = std::sync::Arc::clone(&eof_seen);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            spawn_cli_piped_login_observed_receipt(
                &mut command,
                Duration::from_secs(30),
                (),
                "Codex",
                |_| panic!("adoption panic must precede normal line callbacks"),
                |_| panic!("inert adoption-panic cleanup must not reach a deadline"),
                PipedLoginTestHooks::new(
                    move || eof_callback.store(true, std::sync::atomic::Ordering::SeqCst),
                    |_| panic!("adoption panic must precede wait observations"),
                )
                .with_adopted_child(move |child| {
                    // Store first, before the deliberate callback panic.
                    *adopted_callback
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(child);
                    panic!("deliberate inert adoption callback panic");
                }),
            )
        }));
        assert!(caught.is_err());
        assert!(eof_seen.load(std::sync::atomic::Ordering::SeqCst));
        let child = adopted
            .lock()
            .expect("actual panic child storage")
            .take()
            .expect("panic hook received the original adopted Child");
        // The actual stdout was handed to and exhausted by the reader on unwind.
        // No test kill/wait/try_wait occurs and no fallback reap credit is claimed.
        assert!(child
            .lock()
            .expect("actual panic Child handle")
            .stdout
            .is_none());

        // Restore committed before the panicking guard released its installation
        // mutex. This is actual unwind poison, never a fixture-global reset.
        assert_eq!(CANCELLATION.load(Ordering::SeqCst), INACTIVE);
        assert!(INSTALLATION.is_poisoned());
        let mut next = inert_command(
            sandbox.path(),
            std::env::current_exe().expect("actual post-panic test harness"),
        );
        next.args(["--list", "receipt_tests"])
            .stdout(Stdio::piped());
        let original_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let adopted_id = std::sync::Arc::clone(&original_id);
        let next_eof = std::sync::Arc::new(std::sync::Mutex::new(None));
        let next_eof_callback = std::sync::Arc::clone(&next_eof);
        let caller = std::thread::current().id();
        let mut next_lines = 0_usize;
        let receipt = spawn_cli_piped_login_observed_receipt(
            &mut next,
            Duration::from_secs(30),
            (),
            "Codex",
            |_| {
                assert_eq!(std::thread::current().id(), caller);
                next_lines += 1;
            },
            |_| panic!("inert post-panic child unexpectedly refused"),
            PipedLoginTestHooks::new(
                move || {
                    *next_eof_callback
                        .lock()
                        .expect("actual post-panic EOF thread") = Some(std::thread::current().id());
                },
                |_| {},
            )
            .with_adopted_child(move |child| {
                adopted_id.store(
                    child.lock().expect("actual post-panic adopted Child").id(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }),
        )
        .expect("LOGIN_CANCEL_HANDLER_REUSE_AFTER_PANIC: actual second child must complete");
        let joined = receipt
            .reader_joined_thread_id()
            .expect("LOGIN_CANCEL_HANDLER_REUSE_AFTER_PANIC: actual second reader must join");
        assert!(
            receipt.child_id() > 0
                && receipt.child_id() == original_id.load(std::sync::atomic::Ordering::SeqCst)
                && receipt.reaped_status().code() == Some(0)
                && receipt.reaped_status().success()
                && next_lines > 0
                && joined != caller
                && Some(joined) == *next_eof.lock().expect("actual post-panic EOF receipt")
                && CANCELLATION.load(Ordering::SeqCst) == INACTIVE
                && !INSTALLATION.is_poisoned(),
            "LOGIN_CANCEL_HANDLER_REUSE_AFTER_PANIC"
        );
    }

    #[test]
    fn cli_publication_seal_rejects_prior_cancellation() {
        let _environment = csq_core::platform::test_env::lock();
        let mut cancellation =
            ScopedLoginCancellation::install().expect("private publication guard");
        assert!(latch_cancelled());
        let seal = cancellation.seal_publication();
        let sealed = cancellation.publication_sealed();
        let cancelled = cancellation
            .close()
            .expect("restore private publication guard");
        assert!(
            seal.is_err() && !sealed && cancelled,
            "LOGIN_CLI_PUBLICATION_CANCEL_BEFORE_SEAL"
        );
    }

    #[test]
    fn cli_publication_seal_retains_cancellation_after_commit_boundary() {
        let _environment = csq_core::platform::test_env::lock();
        let mut cancellation =
            ScopedLoginCancellation::install().expect("private publication guard");
        cancellation
            .seal_publication()
            .expect("publication allowed before cancellation");
        let before = cancellation.publication_sealed();
        assert!(latch_cancelled());
        let after = cancellation.publication_sealed();
        let cancelled = cancellation
            .close()
            .expect("restore private publication guard");
        assert!(
            before && after && cancelled,
            "LOGIN_CLI_PUBLICATION_CANCEL_AFTER_SEAL"
        );
    }

    #[test]
    fn scoped_inherited_spawn_errors_keep_publication_guard_available() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private scoped adapter root");
        let account = csq_core::types::AccountNum::try_from(1_u16).unwrap();
        with_cli_login_session(account, |guard| {
            let mut command = inert_command(sandbox.path(), sandbox.path().join("absent-claude"));
            let error = spawn_cli_login_scoped(
                &mut command,
                Duration::from_secs(30),
                (),
                |notice| print_cli_notice(notice, account),
                guard,
                &mut false,
            )
            .unwrap_err();
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
            let mut command = inert_command(sandbox.path(), sandbox.path().join("absent-native"));
            let error = spawn_cli_inherited_login_scoped(
                &mut command,
                Duration::from_secs(30),
                (),
                "Kimi",
                |notice| print_cli_notice(notice, account),
                guard,
            )
            .unwrap_err();
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
            let mut command = inert_command(sandbox.path(), sandbox.path().join("absent-piped"));
            command.stdout(Stdio::piped());
            let error = spawn_cli_piped_login_scoped(
                &mut command,
                Duration::from_secs(30),
                (),
                "Codex",
                |_| panic!("missing executable has no output"),
                |notice| print_cli_notice(notice, account),
                guard,
            )
            .unwrap_err();
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
            let mut command =
                inert_command(sandbox.path(), sandbox.path().join("absent-observed-piped"));
            command.stdout(Stdio::piped());
            let error = spawn_cli_piped_login_scoped_observed_receipt(
                &mut command,
                Duration::from_secs(30),
                (),
                "Codex",
                |_| panic!("missing executable has no output"),
                |notice| print_cli_notice(notice, account),
                (PipedLoginTestHooks::new(|| {}, |_| {}), guard),
            )
            .err()
            .expect("actual missing executable must refuse");
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound)));
            guard.seal_publication()?;
            guard.mark_publication_committed();
            Ok(())
        })
        .expect("scoped spawn-error cleanup must preserve the real publication guard");
    }

    /// R2 item 5: the deadline stop's SUCCESS is carried out of the wait for
    /// the operator paragraph, and its TERMINATED notice fires exactly once,
    /// after the actual reap, on the refusal path.
    #[cfg(unix)]
    #[test]
    fn scoped_deadline_stop_is_reported_to_the_operator_after_the_reap() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private scoped deadline root");
        let account = csq_core::types::AccountNum::try_from(1_u16).unwrap();
        with_cli_login_session(account, |guard| {
            // An ABSOLUTE path: inert_command clears PATH to an empty bin dir.
            let mut command = inert_command(sandbox.path(), "/bin/sleep");
            command.arg("30");
            let notices = std::cell::RefCell::new(Vec::new());
            let mut deadline_stopped = false;
            let error = spawn_cli_login_scoped(
                &mut command,
                Duration::from_millis(300),
                (),
                |notice| notices.borrow_mut().push(notice.disposition),
                guard,
                &mut deadline_stopped,
            )
            .expect_err("a hung vendor login must refuse at the deadline");
            assert!(
                deadline_stopped,
                "DEADLINE_STOP_NOT_CARRIED_OUT_OF_THE_WAIT"
            );
            assert_eq!(
                notices.into_inner().as_slice(),
                [TimeoutDisposition::Terminated],
                "the terminated notice must fire exactly once, after the reap"
            );
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<LoginChildRefusal>()
                .is_some_and(|refusal| refusal.reason == RefusalReason::Timeout)));
            Ok(())
        })
        .expect("scoped deadline stop must finish with the actual reap");
    }
}
