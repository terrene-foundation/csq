//! Policy/model tests. Native Windows behavior is covered separately.
use super::{
    basename_may_match, stop_installed, Backend, Candidate, Inspected, Limits, QuitChannel, Role,
};
use anyhow::{bail, Result};
use std::{collections::BTreeSet, ffi::OsString, path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity(u32, u64);

struct Process {
    id: Identity,
    name: Option<OsString>,
    path: PathBuf,
    arrives: Duration,
    exits: Option<Duration>,
    denied: bool,
    quit_exits: bool,
    role: Role,
    channel: QuitChannel,
    quit_delay: Duration,
}

impl Process {
    fn new(pid: u32, path: &str) -> Self {
        Self {
            id: Identity(pid, u64::from(pid)),
            name: PathBuf::from(path).file_name().map(OsString::from),
            path: model_path(path),
            arrives: Duration::ZERO,
            exits: None,
            denied: false,
            quit_exits: false,
            role: Role::Cli,
            channel: QuitChannel::Bound,
            quit_delay: Duration::from_millis(1),
        }
    }
    fn live(&self, now: Duration) -> bool {
        self.arrives <= now && self.exits.is_none_or(|at| now < at)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Scan(usize),
    Open(u32),
    Quit(Identity),
    Probe(Identity, QuitChannel),
    Signal(Identity, QuitChannel),
    Exit(Identity, bool),
    Continue,
}

#[derive(Default)]
struct Model {
    processes: Vec<Process>,
    now: Duration,
    log: Vec<(Duration, Op)>,
    scans: usize,
    fail_scan: Option<usize>,
    fail_op: Option<&'static str>,
    legacy_present: bool,
    legacy_on_probe: Option<usize>,
    legacy_probes: usize,
    exit_inside_probe: Option<Identity>,
    max_elapsed: Duration,
}

impl Model {
    fn with(processes: Vec<Process>) -> Self {
        Self {
            processes,
            ..Self::default()
        }
    }
    fn record(&mut self, op: Op) {
        self.log.push((self.now, op));
    }
    fn process(&mut self, id: Identity) -> &mut Process {
        self.processes.iter_mut().find(|p| p.id == id).unwrap()
    }
    // This models the CALLER'S continuation gate, not an installer integration.
    fn run(&mut self) -> Result<super::StopReport> {
        let result = stop_installed(self, &installed(), limits())?;
        self.record(Op::Continue);
        Ok(result)
    }
    fn never_continued(&self) {
        assert!(!self.log.iter().any(|(_, op)| *op == Op::Continue));
    }
    fn no_signals(&self) {
        assert!(!self.log.iter().any(|(_, op)| matches!(op, Op::Signal(..))));
    }
}

impl Backend for Model {
    type Handle = Identity;
    fn legacy_event_present(&mut self) -> Result<bool> {
        self.legacy_probes += 1;
        Ok(self.legacy_present
            || self
                .legacy_on_probe
                .is_some_and(|at| self.legacy_probes >= at))
    }
    fn scan(&mut self) -> Result<Vec<Candidate>> {
        self.scans += 1;
        if self.fail_scan == Some(self.scans) {
            bail!("snapshot denied");
        }
        let candidates: Vec<_> = self
            .processes
            .iter()
            .filter(|p| p.live(self.now))
            .map(|p| Candidate {
                pid: p.id.0,
                basename: p.name.clone(),
            })
            .collect();
        self.record(Op::Scan(candidates.len()));
        Ok(candidates)
    }
    fn inspect(&mut self, c: &Candidate, paths: &[PathBuf]) -> Result<Option<Inspected<Identity>>> {
        self.record(Op::Open(c.pid));
        let p = self
            .processes
            .iter()
            .find(|p| p.id.0 == c.pid && p.live(self.now));
        match p {
            Some(p) if p.denied => bail!("candidate {} access denied", c.pid),
            Some(p) if paths.contains(&p.path) || p.role != Role::Cli => Ok(Some(Inspected {
                handle: p.id,
                installed: paths.contains(&p.path),
                role: p.role,
            })),
            _ => Ok(None),
        }
    }
    fn pid(handle: &Identity) -> u32 {
        handle.0
    }
    fn birth(handle: &Identity) -> u64 {
        handle.1
    }
    fn quit_channel(&mut self, id: &Identity) -> Result<QuitChannel> {
        if self.fail_op == Some("channel") {
            bail!("endpoint probe failed");
        }
        let channel = self.process(*id).channel;
        self.record(Op::Probe(*id, channel));
        Ok(channel)
    }
    fn request_quit(&mut self, id: &Identity, channel: QuitChannel) -> Result<()> {
        self.record(Op::Quit(*id));
        if self.fail_op == Some("quit") {
            bail!("quit failed");
        }
        if channel != QuitChannel::Unavailable {
            self.record(Op::Signal(*id, channel));
        }
        let now = self.now;
        let p = self.process(*id);
        if p.quit_exits {
            p.exits = Some(now + p.quit_delay);
        }
        Ok(())
    }
    fn exited(&mut self, id: &Identity) -> Result<bool> {
        if self.fail_op == Some("exit") {
            bail!("wait failed");
        }
        let now = self.now;
        if self.exit_inside_probe == Some(*id) {
            self.process(*id).exits = Some(now);
            self.exit_inside_probe = None;
        }
        let exited = !self.process(*id).live(now);
        self.record(Op::Exit(*id, exited));
        Ok(exited)
    }
    fn elapsed(&self) -> Duration {
        self.now
    }
    fn pause(&mut self, duration: Duration) {
        assert!(
            !duration.is_zero(),
            "busy poll does not advance the monotonic model"
        );
        self.now += duration;
        assert!(
            self.now
                <= if self.max_elapsed.is_zero() {
                    Duration::from_millis(11)
                } else {
                    self.max_elapsed
                },
            "deadline was reset or exceeded"
        );
    }
}

fn model_path(path: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("C:{path}"))
    } else {
        path.into()
    }
}
fn installed() -> Vec<PathBuf> {
    vec![model_path("/installed/csq.exe")]
}
fn limits() -> Limits {
    Limits {
        total: Duration::from_millis(10),
        poll: Duration::from_millis(1),
    }
}

#[test]
fn exact_path_authority_excludes_foreign_same_basename() {
    let mut own = Process::new(1, "/installed/csq.exe");
    own.quit_exits = true;
    let mut different = Process::new(3, "/foreign/editor.exe");
    different.denied = true; // A known different basename is a NEGATIVE prefilter.
    let mut model = Model::with(vec![own, Process::new(2, "/foreign/csq.exe"), different]);
    assert_eq!(model.run().unwrap().selected, 1);
    assert!(model.log.iter().any(|(_, op)| *op == Op::Open(2)));
    assert!(!model.log.iter().any(|(_, op)| *op == Op::Open(3)));
    assert!(model.processes[1].live(model.now));
    assert!(!model
        .log
        .iter()
        .any(|(_, op)| matches!(op, Op::Quit(Identity(2, _)))));
}

#[test]
fn matching_unknown_and_case_variant_names_cannot_bypass_denied_identity() {
    for name in [None, Some("csq.exe"), Some("CSQ.EXE")] {
        let candidate = Candidate {
            pid: 1,
            basename: name.map(OsString::from),
        };
        assert!(basename_may_match(&candidate, &installed()));
        let mut process = Process::new(1, "/installed/csq.exe");
        process.name = candidate.basename;
        process.denied = true;
        let mut model = Model::with(vec![process]);
        assert!(model.run().is_err());
        assert!(model.log.iter().any(|(_, op)| *op == Op::Open(1)));
        assert!(!model.log.iter().any(|(_, op)| matches!(op, Op::Quit(_))));
        model.never_continued();
    }
}

#[test]
fn graceful_exit_has_handle_exit_proof() {
    let mut process = Process::new(1, "/installed/csq.exe");
    process.quit_exits = true;
    let mut model = Model::with(vec![process]);
    let report = model.run().unwrap();
    assert_eq!((report.selected, report.verified_exits), (1, 1));
    assert!(model
        .log
        .iter()
        .any(|(_, op)| *op == Op::Exit(Identity(1, 1), true)));
    assert_eq!(model.log.last().unwrap().1, Op::Continue);
}

#[test]
fn delayed_graceful_exit_and_zero_scan_precede_continuation() {
    let mut process = Process::new(1, "/installed/csq.exe");
    process.quit_exits = true;
    process.quit_delay = Duration::from_millis(4);
    let mut model = Model::with(vec![process]);
    let report = model.run().unwrap();
    assert_eq!((report.selected, report.verified_exits), (1, 1));
    let index = |wanted: Op| model.log.iter().position(|(_, op)| *op == wanted).unwrap();
    let quit = index(Op::Quit(Identity(1, 1)));
    let proof = index(Op::Exit(Identity(1, 1), true));
    let zero = model
        .log
        .iter()
        .rposition(|(_, op)| *op == Op::Scan(0))
        .unwrap();
    let continuation = index(Op::Continue);
    assert!(quit < proof && proof < continuation && zero < continuation);
    assert!(model.log[proof].0 >= Duration::from_millis(4));
}

#[test]
fn unavailable_cli_gets_bounded_manual_refusal_without_quit_request() {
    let mut process = Process::new(1, "/installed/csq.exe");
    process.channel = QuitChannel::Unavailable;
    process.id = Identity(1, 4660);
    let mut model = Model::with(vec![process]);
    let error = model.run().unwrap_err().to_string();
    assert!(
        error.contains("close the csq terminal sessions listed below, then re-run the installer")
    );
    assert!(
        error.contains("PID 1")
            && error.contains("role=Cli")
            && error.contains("start_filetime=4660"),
        "identity missing: {error}"
    );
    assert!(!model
        .log
        .iter()
        .any(|(_, op)| matches!(op, Op::Quit(_) | Op::Signal(..))));
    assert!(model.processes[0].live(model.now));
    assert!(model.now <= limits().total);
    model.never_continued();
}

#[test]
fn snapshot_and_action_errors_refuse_without_continuation() {
    for scan in [1, 2] {
        let mut process = Process::new(1, "/installed/csq.exe");
        process.quit_exits = true;
        let mut model = Model::with(vec![process]);
        model.fail_scan = Some(scan);
        assert!(model.run().is_err(), "scan {scan} failure was hidden");
        model.never_continued();
    }
    for operation in ["channel", "quit", "exit"] {
        let mut model = Model::with(vec![Process::new(1, "/installed/csq.exe")]);
        model.fail_op = Some(operation);
        assert!(model.run().is_err(), "{operation} error was hidden");
        model.never_continued();
    }
}

#[test]
fn late_arrival_is_stopped_and_reuses_the_original_deadline() {
    let mut late = Process::new(2, "/installed/csq.exe");
    late.arrives = Duration::from_millis(4);
    let mut early = Process::new(1, "/installed/csq.exe");
    early.quit_exits = true;
    early.quit_delay = Duration::from_millis(5);
    let mut model = Model::with(vec![early, late]);
    assert!(model.run().is_err());
    assert!(model
        .log
        .iter()
        .any(|(_, op)| *op == Op::Quit(Identity(2, 2))));
    assert!(model.now <= limits().total);
    model.never_continued();
}

#[test]
fn reused_pid_different_birth_never_signals_foreign_replacement() {
    let mut own = Process::new(7, "/installed/csq.exe");
    own.quit_exits = true;
    let mut replacement = Process::new(7, "/foreign/csq.exe");
    replacement.id = Identity(7, 700);
    replacement.arrives = Duration::from_millis(1);
    let mut model = Model::with(vec![own, replacement]);
    assert_eq!(model.run().unwrap().selected, 1);
    assert!(model.processes[1].live(model.now));
    assert!(!model
        .log
        .iter()
        .any(|(_, op)| matches!(op, Op::Quit(Identity(_, 700)))));
    let births: BTreeSet<_> = model
        .log
        .iter()
        .filter_map(|(_, op)| match op {
            Op::Quit(id) => Some(id.1),
            _ => None,
        })
        .collect();
    assert_eq!(births, BTreeSet::from([7]));

    let mut old = Process::new(8, "/installed/csq.exe");
    old.quit_exits = true;
    let mut new = Process::new(8, "/installed/csq.exe");
    new.id = Identity(8, 800);
    new.arrives = Duration::from_millis(1);
    new.quit_exits = true;
    let mut model = Model::with(vec![old, new]);
    assert_eq!(
        model.run().unwrap().selected,
        2,
        "PID reuse must not suppress a newly verified birth"
    );
    assert!(model
        .log
        .iter()
        .any(|(_, op)| *op == Op::Quit(Identity(8, 800))));
}

#[test]
fn empty_install_set_and_invalid_limits_are_refused() {
    let mut model = Model::default();
    assert!(stop_installed(&mut model, &[], limits()).is_err());
    for invalid in [
        Limits {
            total: Duration::ZERO,
            ..limits()
        },
        Limits {
            poll: Duration::ZERO,
            ..limits()
        },
        Limits {
            poll: Duration::from_millis(11),
            ..limits()
        },
    ] {
        assert!(stop_installed(&mut model, &installed(), invalid).is_err());
    }
    assert!(model.log.is_empty());
}

fn host(pid: u32, role: Role, channel: QuitChannel) -> Process {
    let mut process = Process::new(pid, "/installed/csq.exe");
    process.role = role;
    process.channel = channel;
    process.quit_exits = true;
    process
}

#[test]
fn refresher_preflight_order_and_manual_refusal_contract() {
    let mut exclusive = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy)]);
    assert_eq!(exclusive.run().unwrap().verified_exits, 1);

    for other_role in [Role::Daemon, Role::Desktop] {
        let mut ambiguous = Model::with(vec![
            host(1, Role::Daemon, QuitChannel::Legacy),
            host(2, other_role, QuitChannel::Bound),
        ]);
        assert_eq!(ambiguous.run().unwrap().verified_exits, 2);
    }
    for other_role in [Role::Daemon, Role::Desktop] {
        let mut foreign = host(2, other_role, QuitChannel::Bound);
        foreign.path = model_path("/foreign/csq-ee.exe");
        foreign.name = Some(OsString::from("csq-ee.exe"));
        let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy), foreign]);
        assert!(
            model.run().is_err(),
            "non-installed refresher host must refuse"
        );
        model.no_signals();
        model.never_continued();
    }
    let mut denied = Process::new(2, "/installed/csq.exe");
    denied.denied = true;
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy), denied]);
    assert!(model.run().is_err());
    model.no_signals();
    model.never_continued();

    for (role, manual) in [
        (
            Role::Daemon,
            "token-safe shutdown is unverified; leave this host running; S2/S3 migration is required before retrying the installer",
        ),
        (
            Role::Desktop,
            "token-safe shutdown is unverified; leave this host running; S2/S3 migration is required before retrying the installer",
        ),
        (
            Role::Cli,
            "close the csq terminal sessions listed below, then re-run the installer",
        ),
    ] {
        let mut process = host(1, role, QuitChannel::Bound);
        process.quit_exits = false;
        let mut model = Model::with(vec![process]);
        let error = model.run().unwrap_err().to_string();
        assert!(
            error.contains(manual),
            "actionable refusal missing: {error}"
        );
        assert!(model.processes[0].live(model.now));
        assert!(model.now <= limits().total);
        model.never_continued();
    }
    let mut missing = Model::with(vec![host(1, Role::Desktop, QuitChannel::Unavailable)]);
    let error = missing.run().unwrap_err().to_string();
    assert!(error.contains("token-safe shutdown is unverified; leave this host running; S2/S3 migration is required before retrying the installer"));
    missing.no_signals();
    missing.never_continued();

    let mut daemon = host(1, Role::Daemon, QuitChannel::Bound);
    daemon.quit_delay = Duration::from_millis(3);
    let mut desktop = host(2, Role::Desktop, QuitChannel::Bound);
    desktop.quit_delay = Duration::from_millis(2);
    let mut cli = host(3, Role::Cli, QuitChannel::Bound);
    cli.quit_delay = Duration::from_millis(2);
    // Reverse discovery order forces the policy to choose stages by role.
    let mut order = Model::with(vec![cli, desktop, daemon]);
    assert_eq!(order.run().unwrap().selected, 3);
    let index = |wanted: Op| order.log.iter().position(|(_, op)| *op == wanted).unwrap();
    let daemon_gone = index(Op::Exit(Identity(1, 1), true));
    let desktop_quit = index(Op::Quit(Identity(2, 2)));
    let desktop_gone = index(Op::Exit(Identity(2, 2), true));
    let cli_quit = index(Op::Quit(Identity(3, 3)));
    let cli_gone = index(Op::Exit(Identity(3, 3), true));
    assert!(daemon_gone < desktop_quit && desktop_gone < cli_quit && cli_quit < cli_gone);
}

#[test]
fn r1_legacy_daemon_has_graceful_signal_and_retained_exit_proof() {
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy)]);
    model.legacy_present = true;
    assert_eq!(model.run().unwrap().verified_exits, 1);
    assert!(model
        .log
        .iter()
        .any(|(_, op)| *op == Op::Signal(Identity(1, 1), QuitChannel::Legacy)));
}

#[test]
fn r1_legacy_daemon_deadline_names_unexited_retained_handle() {
    let mut daemon = host(1, Role::Daemon, QuitChannel::Legacy);
    daemon.quit_exits = false;
    let mut model = Model::with(vec![daemon]);
    let error = model.run().unwrap_err().to_string();
    assert!(
        error.contains("legacy daemon retained handle did not exit"),
        "{error}"
    );
    assert!(model.processes[0].live(model.now));
    model.never_continued();
}

#[test]
fn r1_unsignalable_cli_preflights_before_legacy_daemon_signal() {
    let mut model = Model::with(vec![
        host(1, Role::Daemon, QuitChannel::Legacy),
        host(2, Role::Cli, QuitChannel::Unavailable),
    ]);
    assert!(model.run().is_err());
    model.no_signals();
}

#[test]
fn r1_legacy_presence_still_refuses_unreadable_unknown_name() {
    let mut own = host(1, Role::Daemon, QuitChannel::Bound);
    own.quit_exits = true;
    let mut unknown = Process::new(2, "/unrelated/editor.exe");
    unknown.denied = true;
    unknown.name = None;
    let mut model = Model::with(vec![own, unknown]);
    model.legacy_present = true;
    assert!(
        model.run().is_err(),
        "legacy census skipped an unclassifiable listener candidate"
    );
    assert!(model.log.iter().any(|(_, op)| *op == Op::Open(2)));
    model.no_signals();
    model.never_continued();
}

#[test]
fn r1_legacy_appearance_keeps_known_other_basename_negative_filter() {
    let mut unrelated = Process::new(4, "/windows/System");
    unrelated.denied = true;
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Bound), unrelated]);
    model.legacy_on_probe = Some(2);
    assert_eq!(model.run().unwrap().verified_exits, 1);
    assert!(!model.log.iter().any(|(_, op)| *op == Op::Open(4)));
}

#[test]
fn r1_old_build_refusal_never_prescribes_unsafe_exit() {
    for role in [Role::Daemon, Role::Desktop] {
        let mut model = Model::with(vec![host(1, role, QuitChannel::Unavailable)]);
        let error = model.run().unwrap_err().to_string();
        assert!(
            error.contains("token-safe") && error.contains("migration"),
            "missing migration explanation: {error}"
        );
        assert!(!error.contains("csq daemon stop") && !error.contains("tray/menu"));
        model.no_signals();
        model.never_continued();
    }
}

#[test]
fn r1_helper_dll_policy_is_system32_and_helper_only() {
    let helper = include_str!("../../bin/csq-upgrade-guard.rs");
    assert!(
        helper.contains("SetDefaultDllDirectories")
            && helper.contains("LOAD_LIBRARY_SEARCH_SYSTEM32"),
        "helper runtime DLL policy missing"
    );
    let source = std::fs::read_to_string(
        crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")).join("build.rs"),
    )
    .unwrap_or_default();
    assert!(source.contains("CARGO_CFG_TARGET_OS") && source.contains("CARGO_CFG_TARGET_ENV"));
    assert!(source.contains("== \"windows\"") && source.contains("== \"msvc\""));
    assert!(source.contains("cargo:rustc-link-arg-bin=csq-upgrade-guard=/DEPENDENTLOADFLAG:0x800"));
    assert!(source
        .contains("cargo:rustc-link-arg-bin=csq-installer-admission=/DEPENDENTLOADFLAG:0x800"));
    assert!(
        !source.contains("cargo:rustc-link-arg="),
        "DLL policy widened beyond the helper"
    );
}

#[test]
fn r1_unsignalable_cli_refuses_before_any_host_signal() {
    for channel in [QuitChannel::Unavailable, QuitChannel::Legacy] {
        let mut daemon = host(1, Role::Daemon, QuitChannel::Bound);
        daemon.quit_exits = true;
        let desktop = host(2, Role::Desktop, QuitChannel::Bound);
        let cli = host(3, Role::Cli, channel);
        let mut model = Model::with(vec![daemon, desktop, cli]);
        assert!(model.run().is_err());
        model.no_signals();
        assert!(model.processes.iter().all(|p| p.live(model.now)));
        model.never_continued();
    }
}

#[tokio::test(start_paused = true)]
async fn r1_guard_default_covers_derived_drain_plus_margin() {
    // Paused Tokio time makes this the exact production policy duration.
    let now = tokio::time::Instant::now();
    let drain_budget = super::drain::derived_shutdown_deadline()
        .unwrap()
        .duration_since(now);
    assert_eq!(
        Limits::default().total,
        drain_budget + Duration::from_secs(5)
    );
    assert!(Limits::default().total > drain_budget);
}

#[test]
fn r1_final_snapshot_follows_exit_observed_inside_probe() {
    let process = Process::new(1, "/installed/csq.exe");
    let id = process.id;
    let mut model = Model::with(vec![process]);
    model.exit_inside_probe = Some(id);
    assert_eq!(model.run().unwrap().verified_exits, 1);
    let exit = model
        .log
        .iter()
        .position(|(_, op)| *op == Op::Exit(id, true))
        .unwrap();
    let scan = model
        .log
        .iter()
        .rposition(|(_, op)| matches!(op, Op::Scan(_)))
        .unwrap();
    assert!(
        exit < scan,
        "completion requires a census after the retained exit proof"
    );
}

#[test]
fn r1_legacy_census_skips_inaccessible_system_known_other_basename() {
    let mut system = Process::new(4, "/windows/System");
    system.name = Some(OsString::from("System"));
    system.denied = true;
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Bound), system]);
    model.legacy_present = true;
    assert_eq!(model.run().unwrap().verified_exits, 1);
    assert!(!model.log.iter().any(|(_, op)| *op == Op::Open(4)));
}

#[test]
fn r1_legacy_census_refuses_inaccessible_csq_family() {
    let mut family = Process::new(4, "/other/csq-ee.exe");
    family.denied = true;
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Bound), family]);
    model.legacy_present = true;
    assert!(model.run().is_err());
    assert!(model.log.iter().any(|(_, op)| *op == Op::Open(4)));
    model.no_signals();
}

#[cfg(any(unix, windows))]
#[test]
fn r1_legacy_census_refuses_inaccessible_non_unicode_name() {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![0xff])
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xd800])
    };
    let mut unknown = Process::new(4, "/other/unknown");
    unknown.name = Some(name);
    unknown.denied = true;
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Bound), unknown]);
    model.legacy_present = true;
    assert!(model.run().is_err());
    assert!(model.log.iter().any(|(_, op)| *op == Op::Open(4)));
    model.no_signals();
}

#[test]
fn s2_sequential_roles_each_get_budget_from_first_signal() {
    let mut processes = Vec::new();
    for (pid, role) in [(1, Role::Daemon), (2, Role::Desktop), (3, Role::Cli)] {
        let mut process = host(pid, role, QuitChannel::Bound);
        process.quit_delay = Duration::from_millis(7);
        processes.push(process);
    }
    let mut model = Model::with(processes);
    model.max_elapsed = Duration::from_millis(30);
    assert_eq!(model.run().unwrap().verified_exits, 3);
    assert_eq!(model.now, Duration::from_millis(21));
}

#[test]
fn s2_late_cli_after_daemon_exit_names_restart_recovery() {
    let daemon = host(1, Role::Daemon, QuitChannel::Bound);
    let mut desktop = host(2, Role::Desktop, QuitChannel::Bound);
    desktop.quit_delay = Duration::from_millis(5);
    let mut cli = host(3, Role::Cli, QuitChannel::Unavailable);
    cli.arrives = Duration::from_millis(2);
    let mut model = Model::with(vec![daemon, desktop, cli]);
    let error = model.run().unwrap_err().to_string();
    assert!(
        error.contains("daemon already stopped") && error.contains("csq daemon start"),
        "{error}"
    );
    model.never_continued();
}

#[test]
fn s2_late_cli_during_daemon_drain_names_pending_restart() {
    let mut daemon = host(1, Role::Daemon, QuitChannel::Bound);
    daemon.quit_delay = Duration::from_millis(5);
    let mut cli = host(2, Role::Cli, QuitChannel::Unavailable);
    cli.arrives = Duration::from_millis(1);
    let mut model = Model::with(vec![daemon, cli]);
    let error = model.run().unwrap_err().to_string();
    assert!(
        error.contains("already requested") && error.contains("csq daemon start"),
        "{error}"
    );
    assert!(model.processes[0].live(model.now));
}

#[test]
fn s2_cli_legacy_census_allows_only_retained_daemon() {
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy)]);
    super::require_sole_daemon(&mut model, (1, 1), 99, &installed()).unwrap();
    model.no_signals();
}
#[test]
fn s2_cli_legacy_census_refuses_second_live_daemon_without_signals() {
    let mut bystander = host(2, Role::Daemon, QuitChannel::Legacy);
    bystander.path = model_path("/other/csq-ee.exe");
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy), bystander]);
    assert!(super::require_sole_daemon(&mut model, (1, 1), 99, &installed()).is_err());
    model.no_signals();
}
#[test]
fn s2_cli_legacy_census_refuses_reused_birth_identity() {
    let mut model = Model::with(vec![host(1, Role::Daemon, QuitChannel::Legacy)]);
    assert!(super::require_sole_daemon(&mut model, (1, 999), 99, &installed()).is_err());
    model.no_signals();
}
