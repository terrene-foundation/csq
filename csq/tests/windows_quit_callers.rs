//! Portable caller regression checks, not native Windows/UI/write verification.
//!
//! The child compiles complete production items, plus the exact synchronous
//! quit_after_drain prefix ending immediately after admission acquisition. Carriers
//! replace OS/runtime boundaries only. Removing a production guard or a UI
//! dispatch therefore changes the executed item, not an independently copied model.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SOURCE: &str = include_str!("../src/desktop/windows_upgrade.rs");
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "csq-windows-quit-callers-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create private caller-test directory");
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    assert_eq!(source.matches(start).count(), 1, "ambiguous start: {start}");
    let body = source.split_once(start).unwrap().1;
    assert_eq!(body.matches(end).count(), 1, "ambiguous end: {end}");
    body.split_once(end).unwrap().0
}

fn item_until(start: &str, end: &str) -> String {
    format!("{start}{}", between(SOURCE, start, end))
}

fn child(program: impl AsRef<std::ffi::OsStr>, root: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .current_dir(root)
        .env("CSQ_BASE_DIR", root);
    // Compiler infrastructure only. In particular, no Git variables, application
    // config, credentials, terminal identity or the parent's HOME reach children.
    for name in [
        "PATH",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "CARGO_HOME",
        // MSVC's linker and SDK inputs are compiler infrastructure, not app state.
        "LIB",
        "LIBPATH",
        "INCLUDE",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "VCINSTALLDIR",
        "VSINSTALLDIR",
        "VCToolsInstallDir",
        "VCToolsVersion",
        "VSCMD_ARG_TGT_ARCH",
        "WindowsSdkDir",
        "WindowsSdkVersion",
        "UniversalCRTSdkDir",
        "UCRTVersion",
        // rustc/cc locate MSVC link.exe via vswhere and the registry; without these
        // a bare `link` from PATH (Git's coreutils `link`) can be picked instead.
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "PATHEXT",
        "COMSPEC",
        "NUMBER_OF_PROCESSORS",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for name in ["HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP"] {
        command.env(name, root);
    }
    command.stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
}

fn run(mut command: Command, root: &Path, label: &str) -> String {
    let stdout = root.join(format!("{label}.stdout"));
    let stderr = root.join(format!("{label}.stderr"));
    command.stdout(fs::File::create(&stdout).unwrap());
    command.stderr(fs::File::create(&stderr).unwrap());
    let mut process = command.spawn().expect("spawn portable caller-test child");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = process.try_wait().expect("observe caller-test child") {
            break status;
        }
        if Instant::now() >= deadline {
            // rustc may own a linker child: terminate its group on Unix, then
            // always reap our direct child before Scratch removes its directory.
            #[cfg(unix)]
            {
                unsafe extern "C" {
                    fn kill(pid: i32, signal: i32) -> i32;
                }
                unsafe {
                    kill(-(process.id() as i32), 9);
                }
            }
            let _ = process.kill();
            let _ = process.wait();
            panic!(
                "{label} exceeded 30s\n{}\n{}",
                fs::read_to_string(stdout).unwrap(),
                fs::read_to_string(stderr).unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = fs::read_to_string(stdout).unwrap();
    assert!(
        status.success(),
        "{label}: {status}\n{}\n{}",
        output,
        fs::read_to_string(stderr).unwrap()
    );
    output
}

#[test]
fn production_quit_reopen_and_signin_callers_preserve_refusal_and_reset() {
    let scratch = Scratch::new();
    let pending = item_until(
        "struct PendingInstall {",
        "\n/// One canonical admission owner",
    );
    let admission = item_until("enum Admission {", "\n/// Rust-owned signed update only.");
    let ui = item_until(
        "fn restore_running_ui(app: &AppHandle) {",
        "\nfn show_recovery(",
    );
    let reopen = item_until("fn reopen_unstopped(", "\nfn request_supervisor_resume(");
    let unstopped = item_until("fn refuse_unstopped(", "\n/// Retain recovery separately");
    // Keep every production statement before the first admission observation;
    // this includes the guard, its return, and the first destructive boundary.
    let quit = format!(
        "{}\n}}",
        item_until(
            "async fn quit_after_drain(app: AppHandle, mode: QuitMode, transferred: Option<Admission>) {",
            "    let joined = observe_admission(async {"
        )
    );
    let mut generated = CARRIERS.to_owned();
    for (token, production) in [
        ("@@PENDING@@", pending),
        ("@@ADMISSION@@", admission),
        ("@@UI@@", ui),
        ("@@REOPEN@@", reopen),
        ("@@UNSTOPPED@@", unstopped),
        ("@@QUIT@@", quit),
        (
            "@@INTENT@@",
            between(
                SOURCE,
                "// BEGIN PORTABLE_STICKY_INTENT",
                "// END PORTABLE_STICKY_INTENT",
            )
            .to_owned(),
        ),
        (
            "@@APPROVAL@@",
            between(
                SOURCE,
                "// BEGIN PORTABLE_INSTALL_APPROVAL",
                "// END PORTABLE_INSTALL_APPROVAL",
            )
            .to_owned(),
        ),
        (
            "@@DECISION@@",
            between(
                SOURCE,
                "// BEGIN PORTABLE_REFUSAL_DECISION",
                "// END PORTABLE_REFUSAL_DECISION",
            )
            .to_owned(),
        ),
    ] {
        assert_eq!(generated.matches(token).count(), 1);
        generated = generated.replace(token, &production);
    }
    let input = scratch.0.join("callers.rs");
    let executable = scratch.0.join(if cfg!(windows) {
        "callers.exe"
    } else {
        "callers"
    });
    fs::write(&input, generated).unwrap();
    let mut compile = child(
        std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()),
        &scratch.0,
    );
    compile
        .args(["--test", "--edition=2021", "-o"])
        .arg(&executable)
        .arg(&input);
    run(compile, &scratch.0, "compile");
    let mut execute = child(&executable, &scratch.0);
    execute.arg("--test-threads=1");
    let output = run(execute, &scratch.0, "callers");
    for name in [
        "early_reopen_completes_install_refusal_before_restoring_ui",
        "active_or_unreadable_signins_refuse_before_admission_close",
        "last_signin_resets_phase_and_dispatches_title_and_tray_restore",
        "active_unknown_and_writer_deadline_refusals_keep_presentation",
        "unreadable_signin_observations_log_fixed_cause_in_each_caller",
        "unreadable_refusal_title_distinguishes_gate_failure_from_work_to_finish",
    ] {
        assert!(
            output.contains(&format!(
                "test desktop::windows_upgrade::tests::{name} ... ok"
            )),
            "required production-caller check did not execute: {name}\n{output}"
        );
    }
}

const CARRIERS: &str = r#"
#![allow(dead_code, unused_variables, unused_mut)]
extern crate self as csq_core;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex, atomic::{AtomicU8, Ordering}};
// Capture the actual field and message expressions from the extracted production
// calls. There is no catch-all arm that could silently discard a diagnostic.
macro_rules! capture_log {
    (error_kind = $kind:expr, $message:literal $(,)?) => {{ crate::record_log($kind, $message); }};
}
mod tracing { pub(crate) use capture_log as warn; pub(crate) use capture_log as error; }
fn record_log(kind: &str, message: &str) {
    ACTIVE.with(|active| {
        let active = active.borrow();
        let app = active.as_ref().unwrap();
        app.0.logs.borrow_mut().push((kind.to_owned(), message.to_owned()));
    });
}
mod tokio { pub mod sync { pub mod oneshot {
    pub struct Sender<T>(pub std::sync::mpsc::Sender<T>);
    impl<T> Sender<T> { pub fn send(self, value:T) -> Result<(),T> {
        self.0.send(value).map_err(|error| error.0)
    }}
}}}
pub mod update { pub mod upgrade_guard { pub mod drain {
    pub fn derived_shutdown_deadline() -> Result<(), ()> { Ok(()) }
}}}
#[derive(Clone)]
struct AppHandle(Rc<Host>);
struct Config { product_name: Option<String> }
struct Host {
    state: desktop::windows_upgrade::QuitState,
    config: Config,
    trace: RefCell<Vec<&'static str>>,
    title: RefCell<String>,
    logs: RefCell<Vec<(String, String)>>,
    at_reopen: RefCell<Option<Box<dyn FnOnce()>>>,
}
impl AppHandle {
    fn new(phase: u8) -> Self {
        let app = Self(Rc::new(Host {
            state: desktop::windows_upgrade::QuitState {
                phase: AtomicU8::new(phase), task: Mutex::new(Default::default()) },
            config: Config { product_name: Some("csq running".into()) },
            trace: RefCell::new(Vec::new()), title: RefCell::new("refused".into()),
            logs: RefCell::new(Vec::new()), at_reopen: RefCell::new(None),
        }));
        ACTIVE.with(|active| *active.borrow_mut() = Some(app.clone()));
        app
    }
    fn try_state<T: StateCarrier>(&self) -> Option<&T> { T::read(self) }
    fn config(&self) -> &Config { &self.0.config }
    fn get_webview_window(&self, _: &str) -> Option<Window> { Some(Window(self.clone())) }
    fn tray_by_id(&self, _: &str) -> Option<Tray> { Some(Tray) }
    fn record(&self, event: &'static str) { self.0.trace.borrow_mut().push(event); }
}
trait StateCarrier: Sized { fn read(app: &AppHandle) -> Option<&Self>; }
struct Window(AppHandle);
impl Window {
    fn set_title(&self, title: &str) -> Result<(), ()> {
        self.0.record("title"); *self.0.0.title.borrow_mut() = title.into(); Ok(())
    }
}
struct Tray;
#[derive(Clone)]
pub struct Signin { provider: &'static str, account: u16 }
thread_local! {
    static ACTIVE: RefCell<Option<AppHandle>> = const { RefCell::new(None) };
    static SIGNINS: RefCell<Result<Vec<Signin>, &'static str>> = const { RefCell::new(Ok(Vec::new())) };
}
mod desktop {
    use super::*;
    fn refresh_tray_menu(app: &AppHandle, _: &Tray) { app.record("tray"); }
    pub mod credential_writes {
        use super::*;
        pub struct Gate;
        pub fn global() -> &'static Gate { &Gate }
        impl Gate {
            pub fn active_signins(&self) -> Result<Vec<Signin>, &'static str> { SIGNINS.with(|v| v.borrow().clone()) }
        }
        // Admission acquisition is the synchronous prefix's OS boundary. The
        // production sign-in guard must run before this carrier is reached.
        pub fn close_for_quit_tag(_: &Gate) -> Result<Drain, &'static str> {
            ACTIVE.with(|app| {
                let app = app.borrow().as_ref().unwrap().clone();
                app.record("close");
                Ok(Drain(app))
            })
        }
        pub struct Drain(pub AppHandle);
        impl Drain {
            pub async fn wait(&self) -> Result<(), String> {
                panic!("portable caller prefix must not observe native admission joins")
            }
            pub fn reopen(&self) -> Result<(), String> {
            if let Some(check) = self.0.0.at_reopen.borrow_mut().take() { check(); }
            self.0.record("reopen"); Ok(())
        } }
    }
    pub mod login_custody {
        // Only the type surface is needed to compile actual Admission items.
        // Lease outcomes belong to production custody tests; executing these
        // inert APIs here is a scope error, never fabricated lease success.
        pub struct UpdateLease;
        impl UpdateLease {
            pub async fn wait(&self) -> Result<(), String> {
                panic!("portable caller fixture does not own native update joins")
            }
            pub fn release(self) -> Result<(), String> {
                panic!("portable caller fixture does not own native update release")
            }
        }
    }
    pub mod windows_upgrade {
        use super::*;
        pub struct QuitState { pub phase: AtomicU8, pub task: Mutex<QuitTask> }
        #[derive(Default)]
        pub struct QuitTask { intent: ExitIntent, install: Option<PendingInstall> }
        impl StateCarrier for QuitState { fn read(app: &AppHandle) -> Option<&Self> { Some(&app.0.state) } }
        fn phase(app: &AppHandle, value:u8) { app.0.state.phase.store(value, Ordering::Release); }
        fn show_recovery(app: &AppHandle) { app.record("recovery"); }
        fn refused(app: &AppHandle, _: &'static str, _: QuitMode) { app.record("refused"); }
        fn rearm_finished_listener(_: &AppHandle) -> Result<(), ()> { Ok(()) }
        @@INTENT@@
        @@APPROVAL@@
        @@DECISION@@
        @@PENDING@@
        @@ADMISSION@@
        @@UI@@
        @@UNSTOPPED@@
        @@REOPEN@@
        @@QUIT@@

        #[cfg(test)]
        mod tests {
            use super::*;
            use std::future::Future;
            use std::task::{Context, Poll, Waker};
            fn observed(app:&AppHandle) -> Vec<&'static str> { app.0.trace.borrow().clone() }
            fn run_quit(app:AppHandle, mode:QuitMode) {
                let mut future = std::pin::pin!(quit_after_drain(app, mode, None));
                assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(())));
            }
            #[test]
            fn early_reopen_completes_install_refusal_before_restoring_ui() {
                let app = AppHandle::new(1);
                let (sender, receiver) = std::sync::mpsc::channel();
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let operation_calls = Arc::clone(&calls);
                {
                    let mut owner = app.0.state.task.lock().unwrap();
                    assert_eq!(owner.intent.request(QuitMode::Upgrade, 0), Some(QuitMode::Upgrade));
                    owner.install = Some(PendingInstall {
                        operation: InstallCallback(Some(Box::new(move |_| {
                            operation_calls.fetch_add(1, Ordering::SeqCst); Ok(())
                        }))), result: Some(tokio::sync::oneshot::Sender(sender)),
                    });
                }
                let completed = Rc::new(std::cell::Cell::new(false));
                let observed_completion = Rc::clone(&completed);
                *app.0.at_reopen.borrow_mut() = Some(Box::new(move || {
                    assert_eq!(receiver.try_recv(), Ok(Err("desktop_install_refused")),
                        "callback must finish with desktop_install_refused before reopening admission");
                    observed_completion.set(true);
                }));
                reopen_unstopped(&app, Admission::Quit(credential_writes::Drain(app.clone())), QuitMode::Upgrade, "fixture");
                assert!(completed.get(), "actual reopen boundary must execute the callback-result check");
                assert!(app.0.state.task.lock().unwrap().install.is_none());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(app.0.state.phase.load(Ordering::Acquire), 0);
                assert_eq!(observed(&app), ["reopen", "title", "tray"]);
            }
            #[test]
            fn active_or_unreadable_signins_refuse_before_admission_close() {
                for mode in [QuitMode::User, QuitMode::Upgrade] {
                    for signins in [Ok(vec![Signin { provider: "Claude", account: 4 }]), Err("raw-registry-error-sentinel")] {
                        let app = AppHandle::new(1);
                        SIGNINS.with(|v| *v.borrow_mut() = signins);
                        run_quit(app.clone(), mode);
                        assert_eq!(observed(&app), ["title", "recovery"], "refusal must precede admission close");
                        assert_eq!(app.0.state.phase.load(Ordering::Acquire),
                            if mode == QuitMode::User { 6 } else { 8 });
                    }
                    let app = AppHandle::new(1);
                    SIGNINS.with(|v| *v.borrow_mut() = Ok(Vec::new()));
                    run_quit(app.clone(), mode);
                    assert_eq!(observed(&app), ["close"]);
                }
            }
            #[test]
            fn last_signin_resets_phase_and_dispatches_title_and_tray_restore() {
                for current in [6, 8] {
                    let app = AppHandle::new(current);
                    SIGNINS.with(|v| *v.borrow_mut() = Ok(Vec::new()));
                    signin_status_changed(&app);
                    assert_eq!(app.0.state.phase.load(Ordering::Acquire), 0);
                    assert_eq!(&*app.0.title.borrow(), "csq running");
                    assert_eq!(observed(&app), ["title", "tray"]);
                }
            }
            #[test]
            fn active_unknown_and_writer_deadline_refusals_keep_presentation() {
                for current in [6, 8, 9, 10] {
                    for signins in [Ok(vec![Signin { provider: "Claude", account: 4 }]), Err("raw-registry-error-sentinel"), Ok(Vec::new())] {
                        if matches!(current, 6 | 8) && matches!(&signins, Ok(v) if v.is_empty()) { continue; }
                        let app = AppHandle::new(current);
                        SIGNINS.with(|v| *v.borrow_mut() = signins);
                        signin_status_changed(&app);
                        assert_eq!(app.0.state.phase.load(Ordering::Acquire), current);
                        assert_eq!(&*app.0.title.borrow(), "refused");
                        assert!(observed(&app).is_empty());
                    }
                }
                let app = AppHandle::new(9);
                restore_running_ui(&app);
                assert!(observed(&app).is_empty(), "non-running phase must guard both UI dispatches");
            }
            fn assert_poison_logs(app: &AppHandle, expected: usize) {
                let logs = app.0.logs.borrow();
                assert_eq!(logs.len(), expected, "every unreadable observation must emit its own fixed cause");
                assert!(logs.iter().all(|(kind, message)|
                    kind == "credential_write_gate_poisoned" &&
                    message == "desktop credential state unavailable"),
                    "diagnostics must capture the actual fixed production literal, not a drain deadline or raw error: {logs:?}");
                assert!(!format!("{logs:?}").contains("raw-registry-error-sentinel"));
            }
            #[test]
            fn unreadable_signin_observations_log_fixed_cause_in_each_caller() {
                for mode in [QuitMode::User, QuitMode::Upgrade] {
                    SIGNINS.with(|v| *v.borrow_mut() = Err("raw-registry-error-sentinel"));
                    let app = AppHandle::new(6);
                    signin_status_changed(&app);
                    assert_poison_logs(&app, 1);
                    assert!(observed(&app).is_empty());
                    let app = AppHandle::new(1);
                    refuse_unstopped(&app, None, mode, true);
                    // One title observation, then one presentation-cleanup observation.
                    assert_poison_logs(&app, 2);
                    let app = AppHandle::new(1);
                    run_quit(app.clone(), mode);
                    // Quit preflight adds one observation to the real refusal caller.
                    assert_poison_logs(&app, 3);
                    assert!(!observed(&app).contains(&"close"));
                }
                for signins in [Ok(Vec::new()), Ok(vec![Signin { provider: "Claude", account: 4 }])] {
                    let app = AppHandle::new(6);
                    SIGNINS.with(|v| *v.borrow_mut() = signins);
                    signin_status_changed(&app);
                    assert!(app.0.logs.borrow().is_empty(), "known state is not a poisoned gate");
                }
            }
            #[test]
            fn unreadable_refusal_title_distinguishes_gate_failure_from_work_to_finish() {
                for mode in [QuitMode::User, QuitMode::Upgrade] {
                    for signins_refused in [true, false] {
                        let app = AppHandle::new(1);
                        SIGNINS.with(|v| *v.borrow_mut() = Err("raw-registry-error-sentinel"));
                        refuse_unstopped(&app, None, mode, signins_refused);
                        let action = if mode == QuitMode::User { "Quit" } else { "Upgrade" };
                        assert_eq!(&*app.0.title.borrow(),
                            &format!("csq — {action} refused; credential state unavailable"),
                            "unreadable state must have a distinct non-retry title from the actual refusal caller");
                        assert_eq!(app.0.state.phase.load(Ordering::Acquire), refusal_phase(mode, signins_refused));
                        assert!(!observed(&app).contains(&"close"));
                    }
                    let app = AppHandle::new(1);
                    SIGNINS.with(|v| *v.borrow_mut() = Ok(vec![Signin { provider: "Claude", account: 4 }]));
                    refuse_unstopped(&app, None, mode, true);
                    assert!(app.0.title.borrow().contains("Claude slot 4; finish or close the sign-in browser and retry"),
                        "known active sign-in must retain provider/account and its actual retry guidance");
                    assert_eq!(app.0.logs.borrow().iter().map(|(kind, _)| kind.clone()).collect::<Vec<_>>(),
                        vec!["desktop_signin_active".to_owned()],
                        "active sign-in refusal must emit desktop_signin_active from the actual caller");
                    let app = AppHandle::new(1);
                    SIGNINS.with(|v| *v.borrow_mut() = Ok(vec![Signin { provider: "Claude", account: 4 }]));
                    refuse_unstopped(&app, None, mode, false);
                    assert_eq!(app.0.logs.borrow().iter().map(|(kind, _)| kind.clone()).collect::<Vec<_>>(),
                        vec!["desktop_write_drain_deadline".to_owned()],
                        "writer deadline must retain its own diagnostic without desktop_signin_active");
                    let app = AppHandle::new(1);
                    SIGNINS.with(|v| *v.borrow_mut() = Ok(Vec::new()));
                    refuse_unstopped(&app, None, mode, false);
                    assert!(app.0.title.borrow().contains("finish credential writes and retry"));
                    assert_eq!(app.0.state.phase.load(Ordering::Acquire), if mode == QuitMode::User { 9 } else { 10 });
                }
            }
        }
    }
}
"#;
