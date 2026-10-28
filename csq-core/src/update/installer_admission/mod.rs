//! Per-user NSIS replacement admission. This is a cooperative gate, not an OS
//! execution fence or a serialized startup rendezvous. Legacy builds refuse.
//! Windows v2 names are session-local and keyed by one persistent protected
//! profile secret. Missing/unsafe secret state refuses; it is never repaired or
//! rotated because that could hide an existing retained installer lease.

#[cfg(any(windows, test))]
mod namespace_acl;

#[cfg(windows)]
pub mod windows;

use super::upgrade_guard::{Backend, Candidate, Inspected, QuitChannel};
use anyhow::{bail, Result};
use std::{path::PathBuf, time::Duration};

/// Adds the S2 capability preflight to the existing no-force drain policy.
/// The legacy/S1 bound quit endpoint alone never authorizes an installer stop.
pub struct S2Backend<B, F> {
    inner: B,
    capability: F,
}
impl<B, F> S2Backend<B, F> {
    pub fn new(inner: B, capability: F) -> Self {
        Self { inner, capability }
    }
}
impl<B: Backend, F: FnMut(u32, u64) -> Result<bool>> Backend for S2Backend<B, F> {
    type Handle = B::Handle;
    fn scan(&mut self) -> Result<Vec<Candidate>> {
        self.inner.scan()
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
    fn pid(handle: &Self::Handle) -> u32 {
        B::pid(handle)
    }
    fn birth(handle: &Self::Handle) -> u64 {
        B::birth(handle)
    }
    fn quit_channel(&mut self, handle: &Self::Handle) -> Result<QuitChannel> {
        if !(self.capability)(B::pid(handle), B::birth(handle))? {
            bail!("legacy_running");
        }
        match self.inner.quit_channel(handle)? {
            QuitChannel::Bound => Ok(QuitChannel::Bound),
            _ => bail!("legacy_running"),
        }
    }
    fn request_quit(&mut self, handle: &Self::Handle, channel: QuitChannel) -> Result<()> {
        if channel != QuitChannel::Bound || !(self.capability)(B::pid(handle), B::birth(handle))? {
            bail!("legacy_running");
        }
        self.inner.request_quit(handle, channel)
    }
    fn exited(&mut self, handle: &Self::Handle) -> Result<bool> {
        self.inner.exited(handle)
    }
    fn elapsed(&self) -> Duration {
        self.inner.elapsed()
    }
    fn pause(&mut self, duration: Duration) {
        self.inner.pause(duration)
    }
}

/// Old uninstallers may use basename-based process checks before removal;
/// reject that full collision set, including CLIs from another installation.
#[cfg(any(windows, test))]
fn refuses_live(
    installed: bool,
    role: super::upgrade_guard::Role,
    old_uninstall: bool,
    main_basename: bool,
    live: bool,
) -> bool {
    live && (installed
        || role != super::upgrade_guard::Role::Cli
        || (old_uninstall && main_basename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::upgrade_guard::{stop_installed, Limits, Role};
    use std::{cell::RefCell, rc::Rc};
    struct Fake {
        signals: Rc<RefCell<Vec<u32>>>,
        gone: bool,
    }
    impl Backend for Fake {
        type Handle = u32;
        fn scan(&mut self) -> Result<Vec<Candidate>> {
            Ok(if self.gone {
                vec![]
            } else {
                (1..=2)
                    .map(|pid| Candidate {
                        pid,
                        basename: Some("csq.exe".into()),
                    })
                    .collect()
            })
        }
        fn inspect(&mut self, row: &Candidate, _: &[PathBuf]) -> Result<Option<Inspected<u32>>> {
            Ok(Some(Inspected {
                handle: row.pid,
                installed: true,
                role: Role::Desktop,
            }))
        }
        fn pid(h: &u32) -> u32 {
            *h
        }
        fn birth(h: &u32) -> u64 {
            u64::from(*h)
        }
        fn quit_channel(&mut self, _: &u32) -> Result<QuitChannel> {
            Ok(QuitChannel::Bound)
        }
        fn request_quit(&mut self, h: &u32, _: QuitChannel) -> Result<()> {
            self.signals.borrow_mut().push(*h);
            if self.signals.borrow().len() == 2 {
                self.gone = true;
            }
            Ok(())
        }
        fn exited(&mut self, _: &u32) -> Result<bool> {
            Ok(self.gone)
        }
        fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
        fn pause(&mut self, _: Duration) {}
    }
    #[test]
    fn s1_bound_event_does_not_authorize_stop_and_all_targets_preflight() {
        let signals = Rc::new(RefCell::new(vec![]));
        let fake = Fake {
            signals: signals.clone(),
            gone: false,
        };
        let mut guarded = S2Backend::new(fake, |pid, _| Ok(pid == 1));
        let result = stop_installed(
            &mut guarded,
            &[PathBuf::from(if cfg!(windows) {
                r"C:\csq.exe"
            } else {
                "/csq.exe"
            })],
            Limits {
                total: Duration::from_secs(1),
                poll: Duration::from_millis(1),
            },
        );
        assert!(result.is_err());
        assert!(signals.borrow().is_empty());
    }
    #[test]
    fn capable_targets_receive_only_bound_graceful_requests() {
        let signals = Rc::new(RefCell::new(vec![]));
        let fake = Fake {
            signals: signals.clone(),
            gone: false,
        };
        let mut guarded = S2Backend::new(fake, |_, _| Ok(true));
        let report = stop_installed(
            &mut guarded,
            &[PathBuf::from(if cfg!(windows) {
                r"C:\csq.exe"
            } else {
                "/csq.exe"
            })],
            Limits {
                total: Duration::from_secs(1),
                poll: Duration::from_millis(1),
            },
        )
        .unwrap();
        assert_eq!(report.verified_exits, 2);
        assert_eq!(*signals.borrow(), vec![1, 2]);
    }
    #[test]
    fn old_uninstall_refuses_noninstalled_main_cli_but_signalled_handles_are_absent() {
        assert!(refuses_live(false, Role::Cli, true, true, true));
        assert!(!refuses_live(false, Role::Cli, false, true, true));
        assert!(!refuses_live(false, Role::Cli, true, false, true));
        for role in [Role::Cli, Role::Daemon, Role::Desktop] {
            assert!(!refuses_live(true, role, true, true, false));
        }
    }
}
