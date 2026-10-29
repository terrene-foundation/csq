//! Idempotent integrity-label upgrade of csq's own secret files (Windows).
//!
//! csq versions before the private integrity label wrote secret files with the
//! owner-only DACL but no label, so a Low-integrity process of the same user can
//! still READ them until csq rewrites them, which for a long-lived file may be
//! never. At daemon start (`daemon::run_reconciler`, shared by `csq daemon start`
//! and the desktop supervisor's embedded daemon) this pass walks csq's known secret
//! locations (`secret_targets`) and calls the ensure-private upgrade on each
//! existing regular file or directory: the label is stamped ONLY when the owner and
//! DACL are exactly the private shape; anything else is left untouched and counted.
//!
//! Containment. A reparse point (symlink or junction) is never traversed or stamped.
//! Directories are listed by path, so an intermediate component could be swapped for
//! a junction between a parent's check and the listing; that is not prevented. What
//! is enforced is that EVERY object is opened without following links and its
//! `GetFinalPathNameByHandleW` path must lie under the canonical base (or equal the
//! exact canonical gemini file), compared EXACTLY (both sides come from
//! `GetFinalPathNameByHandleW`, which spells each object one way; no case folding), else
//! it is treated as a reparse point (`reparse_skipped`) and neither stamped nor
//! descended into; a final path that cannot be read (`unresolvable`) or an unresolvable
//! base (`outside_roots`, with a WARN) is counted on its own and makes the pass incomplete; a file with more than one hard link is refused. A
//! swapped listing can therefore at worst make the pass skip objects, never stamp one
//! outside csq's locations. Not listing children relative to the parent handle is a
//! known limit of this implementation.
//!
//! Concurrency. The pass does not take the per-account credential mutex. Each
//! object's handle is opened with sharing that includes DELETE and is held only for
//! the inspect-and-stamp (microseconds), never across the walk; a concurrent
//! `atomic_replace` (`MoveFileExW` REPLACE_EXISTING) can still get ACCESS_DENIED while
//! it is open, which `atomic_replace`'s bounded retry (5 attempts, 100 ms apart)
//! absorbs. Because the background continuation would keep competing with the live
//! refresher long after startup, it never walks `credentials/`, `identities/` or the
//! `config-*/` slot directories (which hold the live `.credentials.json` the refresher
//! writes): the foreground pass must finish those (they come first in
//! `secret_targets` and are small); if the foreground budget cut them short that is
//! logged as incomplete (`hot_unfinished`) and the rest is picked up at the next daemon
//! start.
//!
//! Bounds: depth is per target; the pass is capped in entries and the foreground part
//! in time, after which the remainder continues on one background thread
//! (single-flight; a daemon stop request ends it) under its own time budget. Logs carry
//! counts by kind, never a path or content, and WARN when the pass was incomplete or a
//! stamp failed. Non-Windows: the pass does nothing.
// `Denied`/`Gone` etc. are produced only by the Windows applier; off Windows (tests
// included) some variants are never constructed.
#![cfg_attr(not(windows), allow(dead_code))]
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

/// Total entries one start may visit (foreground plus background).
const MAX_ENTRIES: usize = 20_000;
/// How long daemon start waits on the pass before the rest runs in the background.
const FOREGROUND_BUDGET: Duration = Duration::from_millis(1_500);
/// Wall-clock allowance of the background continuation.
const BACKGROUND_BUDGET: Duration = Duration::from_secs(60);

/// What kind of object the walker found (decided without following links).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
}
/// The result of one upgrade attempt, as reported by the platform applier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The label was missing on an exactly-private object and was stamped.
    Stamped,
    /// Already carries the exact private label.
    AlreadyLabeled,
    /// Owner, DACL or an existing label is not exactly private: untouched.
    NotPrivate,
    /// Private except for the label, and the stamp failed: STILL unlabeled.
    StampFailed,
    /// An inherited mandatory label that csq cannot sit beside: untouched.
    InheritedLabel,
    /// More than one hard link: untouched.
    Linked,
    /// The object could not be opened with `READ_CONTROL|WRITE_OWNER` (not ours).
    Denied,
    /// A reparse point, or a final path that resolved outside csq's locations (an
    /// intermediate component is a link): never stamped.
    Reparse,
    /// The object's final path could not be read, so containment cannot be proven:
    /// never stamped.
    Unresolvable,
    /// There is no root to be inside (the base directory could not be resolved), so
    /// every object is outside: never stamped.
    OutsideRoots,
    /// Vanished between listing and open, or changed kind.
    Gone,
}

/// Counts by kind. Nothing here identifies a path or content.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LabelUpgradeReport {
    pub files_stamped: usize,
    pub dirs_stamped: usize,
    pub already_labeled: usize,
    pub not_private: usize,
    pub stamp_failed: usize,
    pub inherited_label_refused: usize,
    pub multi_linked: usize,
    pub denied: usize,
    pub reparse_skipped: usize,
    /// Objects whose final path could not be read (`GetFinalPathNameByHandleW` failed).
    pub unresolvable: usize,
    /// Objects refused because the base root could not be resolved (nothing is inside).
    pub outside_roots: usize,
    pub gone: usize,
    pub entries_seen: usize,
    /// The foreground budget ran out; the rest continues on a background thread.
    pub continued_in_background: bool,
    /// The entry cap ended the pass: later entries were not visited.
    pub capped: bool,
    /// The time budget (foreground, or the background run's) ended the pass.
    pub budget_exhausted: bool,
    /// The foreground ended with `credentials/`/`identities/`/`config-*/` work left;
    /// the background never walks them, so it waits for the next start.
    pub hot_unfinished: bool,
    /// A background run was already in flight, so none was started.
    pub background_overlap: bool,
    /// A daemon stop request ended the background run.
    pub stopped: bool,
}
impl LabelUpgradeReport {
    fn incomplete(&self) -> bool {
        self.capped
            || self.budget_exhausted
            || self.hot_unfinished
            || self.stopped
            || self.unresolvable > 0
            || self.outside_roots > 0
    }
    /// Whether `phase`'s log line must be a WARN about coverage. A foreground that ran out
    /// of budget and HANDED the rest to the background is not a problem to report (the
    /// background reports its own outcome); anything that leaves locations uncovered is:
    /// the entry cap, a stop, `credentials/`/`identities/`/`config-*/` work the
    /// background will not do, an overlapping run, an unresolvable object or base, and a
    /// budget that ran out with nothing continuing it (an overlap, a failed spawn, or the
    /// background's own budget).
    fn needs_coverage_warning(&self, phase: &str) -> bool {
        let handed_off = phase == "foreground" && self.continued_in_background;
        self.capped
            || self.stopped
            || self.hot_unfinished
            || self.background_overlap
            || self.unresolvable > 0
            || self.outside_roots > 0
            || (self.budget_exhausted && !handed_off)
    }
}

/// One location to visit: `depth` levels of children below `path` (0 = the object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub path: PathBuf,
    pub depth: usize,
}

/// csq's secret locations in priority order, derived from the `write_new_private` /
/// `atomic_replace` writers (a cap or budget cut therefore drops the least
/// sensitive part). `home` is the user's home directory, resolved by the same helper the gemini OAuth
/// writer uses (`platform::home::home_dir`).
///
/// - `credentials/` (`<N>.json`, `codex-<N>.json`): `credentials::file`
/// - `identities/<uuid>/` (`credentials*.json`, `settings.json`, `identity.json`)
/// - `config-*/` (`.credentials.json`, `settings.json`, `.claude.json`, codex
///   `config.toml` / `auth.json`): `providers::{settings,codex::surface}`
/// - `pool/` and `pool-vault-store.json`: `pool::store`, `platform::secret::file`
/// - `csq-runs/keys/<chain>/`: audit key custody (`audit::key_custody::file_store`)
/// - `chat-sessions/`: the chat transcript store, when under this base
/// - `term-*/` handle dirs and the base's own files (`profiles.json`, `quota.json`,
///   `settings-*.json`, markers)
/// - every other top-level directory, two levels (messaging, gate pins, ...)
/// - `<home>/.gemini/oauth_creds.json`: `providers::gemini::oauth_flow`
pub(crate) fn secret_targets(base_dir: &Path, home: Option<&Path>) -> Vec<Target> {
    let at = |name: &str, depth| Target {
        path: base_dir.join(name),
        depth,
    };
    let mut targets = vec![
        at("credentials", 1),
        at("identities", 2),
        at("pool", 2),
        Target {
            path: base_dir.join("csq-runs").join("keys"),
            depth: 3,
        },
        at("chat-sessions", 1),
    ];
    let named = [
        "credentials",
        "identities",
        "pool",
        "chat-sessions",
        "csq-runs",
    ];
    let mut others = Vec::new();
    let mut slots = Vec::new();
    let mut handles = Vec::new();
    if let Ok(entries) = fs::read_dir(base_dir) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if !is_dir || named.contains(&name.as_str()) {
                continue;
            }
            if name.starts_with("config-") {
                slots.push(at(&name, 1));
            } else if name.starts_with("term-") {
                handles.push(at(&name, 1));
            } else {
                others.push(at(&name, 2));
            }
        }
    }
    for group in [&mut slots, &mut handles, &mut others] {
        group.sort_by(|a, b| a.path.cmp(&b.path));
    }
    targets.append(&mut slots);
    targets.append(&mut handles);
    targets.push(Target {
        path: base_dir.to_path_buf(),
        depth: 1,
    });
    targets.append(&mut others);
    if let Some(home) = home {
        targets.push(Target {
            path: home.join(".gemini").join("oauth_creds.json"),
            depth: 0,
        });
    }
    targets
}

/// Why [`Walk::advance`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    Done,
    Budget,
    Capped,
    Stopped,
}

/// Resumable walk state: the remaining work, the deepest remaining depth each path
/// was visited with, and the entry count. A path reached again with MORE depth left
/// (the base dir lists `messaging/` at depth 0 before its own depth-2 target) is
/// re-expanded, never skipped.
struct Walk {
    stack: Vec<(PathBuf, usize)>,
    /// path -> (deepest depth expanded, may descend)
    visited: HashMap<PathBuf, (usize, bool)>,
    seen: usize,
}
impl Walk {
    fn new(targets: Vec<Target>) -> Self {
        Self {
            stack: targets
                .into_iter()
                .rev()
                .map(|t| (t.path, t.depth))
                .collect(),
            visited: HashMap::new(),
            seen: 0,
        }
    }
    /// Removes pending work for which `hot` holds; returns how many entries were dropped.
    fn drop_matching(&mut self, hot: &dyn Fn(&Path) -> bool) -> usize {
        let before = self.stack.len();
        self.stack.retain(|(path, _)| !hot(path));
        before - self.stack.len()
    }
    fn push_children(&mut self, path: &Path, depth: usize) {
        if let Ok(children) = fs::read_dir(path) {
            let mut names: Vec<_> = children.flatten().map(|c| c.path()).collect();
            names.sort();
            self.stack
                .extend(names.into_iter().rev().map(|child| (child, depth - 1)));
        }
    }
    /// Visit entries until the stack is empty, `deadline` passes, the entry cap is hit
    /// or `stop` is set (`None` ignores it).
    fn advance(
        &mut self,
        deadline: Instant,
        stop: Option<&AtomicBool>,
        apply: &dyn Fn(&Path, Kind) -> Outcome,
        report: &mut LabelUpgradeReport,
    ) -> Progress {
        while let Some((path, depth)) = self.stack.pop() {
            if self.seen >= MAX_ENTRIES {
                self.stack.push((path, depth));
                return Progress::Capped;
            }
            if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                self.stack.push((path, depth));
                return Progress::Stopped;
            }
            if Instant::now() >= deadline {
                self.stack.push((path, depth));
                return Progress::Budget;
            }
            let prior = self.visited.get(&path).copied();
            if prior.is_some_and(|(done, _)| depth <= done) {
                continue;
            }
            // `symlink_metadata` never follows: a link is a link, whatever it names.
            let Ok(meta) = fs::symlink_metadata(&path) else {
                report.gone += 1;
                continue;
            };
            if let Some((_, descend)) = prior {
                // Seen shallower before: it was already applied and counted; only
                // the deeper listing is new.
                self.visited.insert(path.clone(), (depth, descend));
                if descend && depth > 0 && meta.is_dir() && !meta.file_type().is_symlink() {
                    self.push_children(&path, depth);
                }
                continue;
            }
            self.seen += 1;
            report.entries_seen += 1;
            let kind = if meta.file_type().is_symlink() {
                report.reparse_skipped += 1;
                self.visited.insert(path, (depth, false));
                continue;
            } else if meta.is_dir() {
                Kind::Dir
            } else if meta.is_file() {
                Kind::File
            } else {
                continue;
            };
            let outcome = apply(&path, kind);
            match outcome {
                Outcome::Stamped if kind == Kind::Dir => report.dirs_stamped += 1,
                Outcome::Stamped => report.files_stamped += 1,
                Outcome::AlreadyLabeled => report.already_labeled += 1,
                Outcome::NotPrivate => report.not_private += 1,
                Outcome::StampFailed => report.stamp_failed += 1,
                Outcome::InheritedLabel => report.inherited_label_refused += 1,
                Outcome::Linked => report.multi_linked += 1,
                Outcome::Denied => report.denied += 1,
                Outcome::Reparse => report.reparse_skipped += 1,
                Outcome::Unresolvable => report.unresolvable += 1,
                Outcome::OutsideRoots => report.outside_roots += 1,
                Outcome::Gone => report.gone += 1,
            }
            // Never descend into a reparse point the applier found (a junction the
            // metadata did not flag), into an object whose containment could not be
            // proven, or into something that vanished.
            let descend = !matches!(
                outcome,
                Outcome::Reparse | Outcome::Unresolvable | Outcome::OutsideRoots | Outcome::Gone
            );
            self.visited.insert(path.clone(), (depth, descend));
            if kind == Kind::Dir && depth > 0 && descend {
                self.push_children(&path, depth);
            }
        }
        Progress::Done
    }
}

/// Process-wide single-flight state of the background continuation, and the stop token
/// of every run in flight.
///
/// Stop is per run, never a shared flag that a later run resets: a global flag cleared
/// when the background slot is claimed would erase a stop request that arrived DURING
/// the foreground, and the background walk would start after the daemon was told to stop.
/// A run registers its token BEFORE its foreground starts ([`Control::register`]); a stop
/// request sets every registered token and a run's token lives until its last thread
/// ends. A request made while no run is registered affects no run (there is nothing to
/// stop, and a run that starts later is a new session's).
pub(crate) struct Control {
    background_running: AtomicBool,
    runs: Mutex<Vec<Arc<AtomicBool>>>,
}
impl Control {
    pub(crate) const fn new() -> Self {
        Self {
            background_running: AtomicBool::new(false),
            runs: Mutex::new(Vec::new()),
        }
    }
    /// Registers a new run's stop token. Call before the run does any work.
    fn register(&'static self) -> RunToken {
        let stop = Arc::new(AtomicBool::new(false));
        self.runs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::clone(&stop));
        RunToken {
            control: self,
            stop,
        }
    }
    /// Sets the stop token of every run in flight.
    pub(crate) fn request_stop(&self) {
        for token in self.runs.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            token.store(true, Ordering::SeqCst);
        }
    }
}
/// One run's stop token; deregisters itself when the run's last thread drops it.
struct RunToken {
    control: &'static Control,
    stop: Arc<AtomicBool>,
}
impl RunToken {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}
impl Drop for RunToken {
    fn drop(&mut self) {
        self.control
            .runs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|token| !Arc::ptr_eq(token, &self.stop));
    }
}
static CONTROL: Control = Control::new();

/// Asks the runs in flight to end at their next entry (daemon stop): the background
/// continuation stops walking, and a foreground that is still running does not start
/// one. The foreground part is short and bounded and is not interrupted.
pub fn stop_label_upgrade() {
    CONTROL.request_stop();
}

/// Keeps a daemon's shutdown token wired to [`stop_label_upgrade`] for the whole session.
/// The task must outlive `run_reconciler` (the background continuation runs after it
/// returns), so the caller holds this guard for the rest of the session; dropping it
/// aborts the task. Every early return of the daemon entry point therefore ends the
/// watcher instead of leaving it parked on a token that will never be cancelled.
#[must_use = "dropping the watcher aborts it"]
pub struct StopWatcher(tokio::task::JoinHandle<()>);
impl Drop for StopWatcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawns the task that calls [`stop_label_upgrade`] when `shutdown` is cancelled. Must
/// run inside a tokio runtime.
pub fn spawn_stop_watcher(shutdown: tokio_util::sync::CancellationToken) -> StopWatcher {
    spawn_stop_watcher_for(shutdown, &CONTROL)
}

fn spawn_stop_watcher_for(
    shutdown: tokio_util::sync::CancellationToken,
    control: &'static Control,
) -> StopWatcher {
    StopWatcher(tokio::spawn(async move {
        shutdown.cancelled().await;
        control.request_stop();
    }))
}

struct ClearOnDrop(&'static Control);
impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.background_running.store(false, Ordering::SeqCst);
    }
}

fn record(progress: Progress, report: &mut LabelUpgradeReport) {
    match progress {
        Progress::Done => {}
        Progress::Budget => report.budget_exhausted = true,
        Progress::Capped => report.capped = true,
        Progress::Stopped => report.stopped = true,
    }
}

/// Whether `path` is under a location the live refresher / login code writes while the
/// daemon runs: `credentials/`, `identities/` and every `config-*/` slot directory
/// (`.credentials.json`, `settings.json`) directly below `base_dir`. The background
/// continuation never walks these.
pub(crate) fn is_hot(base_dir: &Path, path: &Path) -> bool {
    path.strip_prefix(base_dir)
        .ok()
        .and_then(|rel| rel.components().next())
        .and_then(|first| first.as_os_str().to_str())
        .is_some_and(|name| {
            name == "credentials" || name == "identities" || name.starts_with("config-")
        })
}

/// Runs the pass with `apply` as the per-object upgrade. Foreground up to
/// [`FOREGROUND_BUDGET`]; any remainder continues on one detached background thread
/// that skips every path for which `hot` holds. `control` carries the single-flight
/// and stop state.
pub(crate) fn run_with<F>(
    targets: Vec<Target>,
    hot: impl Fn(&Path) -> bool,
    control: &'static Control,
    apply: F,
) -> LabelUpgradeReport
where
    F: Fn(&Path, Kind) -> Outcome + Send + 'static,
{
    // Registered BEFORE the foreground: a stop request that arrives while it runs must be
    // seen when the background is about to start (and by the background itself).
    let token = control.register();
    let mut walk = Walk::new(targets);
    let mut report = LabelUpgradeReport::default();
    let progress = walk.advance(
        Instant::now() + FOREGROUND_BUDGET,
        None,
        &apply,
        &mut report,
    );
    if progress == Progress::Budget {
        // The background never walks the hot locations (see module doc).
        report.hot_unfinished = walk.drop_matching(&hot) > 0;
    }
    if progress == Progress::Done || progress == Progress::Capped {
        record(progress, &mut report);
        log(&report, "foreground");
        return report;
    }
    report.budget_exhausted = true;
    // A stop requested during the foreground: the daemon is going down, start nothing.
    if token.stopped() {
        report.stopped = true;
        log(&report, "foreground");
        return report;
    }
    if control.background_running.swap(true, Ordering::SeqCst) {
        report.background_overlap = true;
        log(&report, "foreground");
        return report;
    }
    report.continued_in_background = true;
    log(&report, "foreground");
    let guard = ClearOnDrop(control);
    let spawned = std::thread::Builder::new()
        .name("csq-label-upgrade".into())
        .spawn(move || {
            let _guard = guard;
            let mut rest = LabelUpgradeReport::default();
            let progress = walk.advance(
                Instant::now() + BACKGROUND_BUDGET,
                Some(&token.stop),
                &apply,
                &mut rest,
            );
            record(progress, &mut rest);
            log(&rest, "background");
        });
    if spawned.is_err() {
        control.background_running.store(false, Ordering::SeqCst);
        report.continued_in_background = false;
        tracing::warn!(
            error_kind = "label_upgrade_background_spawn_failed",
            "integrity-label upgrade could not continue in the background"
        );
    }
    report
}

fn log(report: &LabelUpgradeReport, phase: &'static str) {
    tracing::info!(
        phase,
        files_stamped = report.files_stamped,
        dirs_stamped = report.dirs_stamped,
        already_labeled = report.already_labeled,
        not_private = report.not_private,
        inherited_label_refused = report.inherited_label_refused,
        multi_linked = report.multi_linked,
        denied = report.denied,
        reparse_skipped = report.reparse_skipped,
        unresolvable = report.unresolvable,
        outside_roots = report.outside_roots,
        gone = report.gone,
        entries_seen = report.entries_seen,
        incomplete = report.incomplete(),
        "integrity-label upgrade pass"
    );
    if report.stamp_failed > 0 {
        tracing::warn!(
            error_kind = "label_upgrade_stamp_failed",
            phase,
            stamp_failed = report.stamp_failed,
            "private files remain without the integrity label"
        );
    }
    if report.needs_coverage_warning(phase) {
        tracing::warn!(
            error_kind = "label_upgrade_incomplete",
            phase,
            capped = report.capped,
            budget_exhausted = report.budget_exhausted,
            continued_in_background = report.continued_in_background,
            background_overlap = report.background_overlap,
            hot_unfinished = report.hot_unfinished,
            stopped = report.stopped,
            unresolvable = report.unresolvable,
            outside_roots = report.outside_roots,
            entries_seen = report.entries_seen,
            "integrity-label upgrade did not cover every location"
        );
    }
}

/// `\\?\C:\a\B` / `//?/C:/a/B/` -> `C:\a\B`: the comparable form of a Windows path.
///
/// Comparison is EXACT, never case-folded: both sides come from
/// `GetFinalPathNameByHandleW` (`FILE_NAME_NORMALIZED`), which reports each component in
/// the case stored on disk, so one object has one spelling. Folding case would only add
/// false matches (`str::to_lowercase` maps U+212A KELVIN SIGN to `k`, so a look-alike
/// directory `\u{212A}ids` would "contain" itself in `Kids`).
pub(crate) fn normalize_path(path: &str) -> String {
    let unified = path.replace('/', "\\");
    let trimmed = unified
        .strip_prefix("\\\\?\\UNC\\")
        .map(|rest| format!("\\\\{rest}"))
        .or_else(|| unified.strip_prefix("\\\\?\\").map(str::to_owned))
        .unwrap_or(unified);
    trimmed.trim_end_matches('\\').to_owned()
}
/// Whether the normalised `candidate` is `root` or lies below it (component-wise).
pub(crate) fn path_within(candidate: &str, root: &str) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// Where an opened object's final path may lie: under the resolved base, or exactly the
/// resolved gemini file. Built from paths already resolved by `GetFinalPathNameByHandleW`
/// (the Windows applier), compared exactly ([`normalize_path`]).
#[derive(Debug, Default)]
pub(crate) struct Roots {
    base: String,
    exact: Vec<String>,
}
/// Where one object's final path lies relative to the [`Roots`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Containment {
    Inside,
    /// Resolved, but not under the base and not an exact root.
    Outside,
    /// The base root is unresolved, so nothing can be inside it.
    NoRoots,
}
impl Roots {
    /// `base` / `gemini_file` are the resolved final paths, `None` when they could not be
    /// resolved (an unresolved base contains nothing).
    pub(crate) fn from_final_paths(base: Option<&str>, gemini_file: Option<&str>) -> Self {
        Self {
            base: base.map(normalize_path).unwrap_or_default(),
            exact: gemini_file
                .map(|p| vec![normalize_path(p)])
                .unwrap_or_default(),
        }
    }
    pub(crate) fn base_unresolved(&self) -> bool {
        self.base.is_empty()
    }
    /// WARNs (once per pass; the applier is built once) when the base root is empty: every
    /// object will then be refused, which is otherwise indistinguishable from a clean pass.
    pub(crate) fn warn_if_base_unresolved(&self) {
        if self.base_unresolved() {
            tracing::warn!(
                error_kind = "label_upgrade_base_unresolved",
                "the accounts directory could not be resolved; no secret file will be labeled"
            );
        }
    }
    pub(crate) fn classify(&self, final_path: &str) -> Containment {
        let candidate = normalize_path(final_path);
        if (!self.base.is_empty() && path_within(&candidate, &self.base))
            || self.exact.contains(&candidate)
        {
            Containment::Inside
        } else if self.base.is_empty() {
            Containment::NoRoots
        } else {
            Containment::Outside
        }
    }
    /// The outcome that refuses an object (`None`: inside, go on). An unreadable final path
    /// is [`Outcome::Unresolvable`], never folded into the reparse count.
    pub(crate) fn refusal(&self, final_path: Option<&str>) -> Option<Outcome> {
        match final_path.map(|p| self.classify(p)) {
            None => Some(Outcome::Unresolvable),
            Some(Containment::Inside) => None,
            Some(Containment::Outside) => Some(Outcome::Reparse),
            Some(Containment::NoRoots) => Some(Outcome::OutsideRoots),
        }
    }
}

/// The user's home for the gemini target. Tests and `test-utils` builds never fall
/// back to the real home: only an explicit `CSQ_HOME` is honoured, so no run of the
/// reconciler can touch the developer's real `~/.gemini`.
fn gemini_home() -> Option<PathBuf> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        std::env::var_os("CSQ_HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        super::home::home_dir()
    }
}

/// The daemon-start entry point. `None` on non-Windows (nothing to do).
pub fn run_label_upgrade(base_dir: &Path) -> Option<LabelUpgradeReport> {
    run_label_upgrade_with(base_dir, gemini_home().as_deref())
}

/// [`run_label_upgrade`] with the home directory injected (hermetic tests).
pub fn run_label_upgrade_with(base_dir: &Path, home: Option<&Path>) -> Option<LabelUpgradeReport> {
    #[cfg(windows)]
    {
        let targets = secret_targets(base_dir, home);
        let hot_base = base_dir.to_path_buf();
        let apply = super::fs_windows_upgrade::applier(base_dir, home);
        Some(run_with(
            targets,
            move |path| is_hot(&hot_base, path),
            &CONTROL,
            apply,
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = (base_dir, home);
        None
    }
}

/// Test seam: one call of the Windows applier, exactly as the walk would make it (roots
/// resolved from `base` / `home`), so a native test can hand it a path the listing could
/// not have produced (an intermediate component swapped for a junction after the listing).
#[cfg(all(windows, test))]
pub(crate) fn apply_one_for_test(
    base: &Path,
    home: Option<&Path>,
    path: &Path,
    kind: Kind,
) -> Outcome {
    super::fs_windows_upgrade::applier(base, home)(path, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashSet};

    /// Tests that run `run_with` reach the same `log()` callsites the capture tests of this
    /// module assert on (and the background test does so from a second thread), so they hold
    /// the shared capture lock: a first hit with no dispatcher during a capture would cache
    /// the callsite as disabled. This lock has nothing to do with the refresher's
    /// `tick_warns_once_per_suppressed_slot_per_window` flake, which reproduced with it held
    /// (see `crate::testing::settle_capture_interest`).
    fn capture_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    /// Every tracing event as `(level, "name=value ...")`, captured on this thread only.
    struct Events(std::sync::Arc<Mutex<Vec<(tracing::Level, String)>>>);
    struct FieldText<'a>(&'a mut String);
    impl tracing::field::Visit for FieldText<'_> {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", f.name(), v);
        }
    }
    impl tracing::Subscriber for Events {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut text = String::new();
            event.record(&mut FieldText(&mut text));
            self.0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), text));
        }
    }
    /// Runs `run` with this thread's events captured (serialised on the shared capture lock).
    fn capture<T>(run: impl FnOnce() -> T) -> (T, Vec<(tracing::Level, String)>) {
        let _lock = capture_lock();
        let events = std::sync::Arc::new(Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(Events(events.clone()), || {
            tracing::callsite::rebuild_interest_cache();
            run()
        });
        let got = events.lock().unwrap().clone();
        (out, got)
    }
    fn leaked_control() -> &'static Control {
        Box::leak(Box::new(Control::new()))
    }
    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    // The enumeration comes from the writers' locations and is ordered most-sensitive
    // first, so a cap or time cut drops the least sensitive part. Reds if a location
    // were dropped, duplicated, or the audit chain dir (csq-runs) swept as "other".
    #[test]
    fn targets_are_the_known_secret_locations_in_priority_order() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        for dir in [
            "config-2",
            "config-1",
            "term-9",
            "messaging",
            "csq-runs",
            "credentials",
        ] {
            fs::create_dir_all(base.path().join(dir)).unwrap();
        }
        touch(&base.path().join("profiles.json"));
        let got = secret_targets(base.path(), Some(home.path()));
        let rel = |t: &Target| {
            (
                t.path
                    .strip_prefix(base.path())
                    .or_else(|_| t.path.strip_prefix(home.path()))
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                t.depth,
            )
        };
        let names: Vec<_> = got.iter().map(rel).collect();
        let expected = [
            ("credentials", 1),
            ("identities", 2),
            ("pool", 2),
            ("csq-runs/keys", 3),
            ("chat-sessions", 1),
            ("config-1", 1),
            ("config-2", 1),
            ("term-9", 1),
            ("", 1),
            ("messaging", 2),
            (".gemini/oauth_creds.json", 0),
        ];
        let expected: Vec<_> = expected.iter().map(|(n, d)| (n.to_string(), *d)).collect();
        assert_eq!(names, expected);
        assert_eq!(
            got.iter().map(|t| &t.path).collect::<HashSet<_>>().len(),
            got.len(),
            "no target is listed twice"
        );
        assert!(secret_targets(base.path(), None).len() == got.len() - 1);
    }

    // Depth is per target and a link is never traversed (nor reported as a file or
    // directory to stamp). Reds if recursion ignored the depth, or followed the link.
    #[test]
    fn the_walk_honours_depth_and_never_follows_links() {
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/1.json"));
        touch(&base.path().join("credentials/nested/2.json"));
        touch(&base.path().join("credentials/nested/deeper/3.json"));
        let outside = tempfile::tempdir().unwrap();
        touch(&outside.path().join("secret.json"));
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), base.path().join("credentials/link")).unwrap();
        let seen = RefCell::new(Vec::new());
        let mut walk = Walk::new(vec![Target {
            path: base.path().join("credentials"),
            depth: 2,
        }]);
        let mut report = LabelUpgradeReport::default();
        let progress = walk.advance(
            Instant::now() + Duration::from_secs(30),
            None,
            &|path, kind| {
                seen.borrow_mut().push((path.to_path_buf(), kind));
                Outcome::Stamped
            },
            &mut report,
        );
        assert_eq!(progress, Progress::Done);
        let names: Vec<String> = seen
            .borrow()
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        for expected in ["credentials", "1.json", "nested", "2.json", "deeper"] {
            assert!(
                names.contains(&expected.to_string()),
                "{expected}: {names:?}"
            );
        }
        assert!(
            !names.contains(&"3.json".to_string()),
            "depth limit: {names:?}"
        );
        assert!(!names.contains(&"secret.json".to_string()), "{names:?}");
        #[cfg(unix)]
        {
            assert!(!names.contains(&"link".to_string()), "{names:?}");
            assert_eq!(report.reparse_skipped, 1);
        }
        assert_eq!(report.files_stamped, 2);
        assert_eq!(report.dirs_stamped, 3);
    }

    // A directory the applier reports as a reparse point is never listed, whatever the
    // metadata said. Reds if the walk descended after `Outcome::Reparse`.
    #[test]
    fn the_walk_does_not_descend_into_a_reparse_outcome() {
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/inner/1.json"));
        let seen = RefCell::new(Vec::new());
        let mut walk = Walk::new(vec![Target {
            path: base.path().join("credentials"),
            depth: 3,
        }]);
        let mut report = LabelUpgradeReport::default();
        walk.advance(
            Instant::now() + Duration::from_secs(30),
            None,
            &|path, _| {
                seen.borrow_mut().push(path.to_path_buf());
                if path.ends_with("inner") {
                    Outcome::Reparse
                } else {
                    Outcome::AlreadyLabeled
                }
            },
            &mut report,
        );
        assert!(seen.borrow().iter().any(|p| p.ends_with("inner")));
        assert!(!seen.borrow().iter().any(|p| p.ends_with("1.json")));
        assert_eq!(report.reparse_skipped, 1);
    }

    // A pass cut by its time budget keeps its remaining work and resumes to the same
    // totals as an uninterrupted pass. Reds if the cut dropped the stack or skipped
    // the entry it stopped on.
    #[test]
    fn a_budget_cut_pass_resumes_to_the_same_totals() {
        let base = tempfile::tempdir().unwrap();
        for n in 0..5 {
            touch(&base.path().join(format!("credentials/{n}.json")));
        }
        let target = || {
            vec![Target {
                path: base.path().join("credentials"),
                depth: 1,
            }]
        };
        let count = |walk: &mut Walk, deadline| {
            let mut report = LabelUpgradeReport::default();
            let progress =
                walk.advance(deadline, None, &|_, _| Outcome::AlreadyLabeled, &mut report);
            (progress, report)
        };
        let (more, none) = count(&mut Walk::new(target()), Instant::now());
        assert!(
            more == Progress::Budget && none.entries_seen == 0,
            "an expired budget visits nothing"
        );
        let mut walk = Walk::new(target());
        let (more, first) = count(&mut walk, Instant::now());
        assert_eq!(more, Progress::Budget);
        let (more, rest) = count(&mut walk, Instant::now() + Duration::from_secs(30));
        assert_eq!(more, Progress::Done);
        let (_, whole) = count(
            &mut Walk::new(target()),
            Instant::now() + Duration::from_secs(30),
        );
        assert_eq!(first.entries_seen + rest.entries_seen, whole.entries_seen);
        assert_eq!(rest.already_labeled, 6);
    }

    // `run_with` completes within the foreground budget on a small tree and reports.
    #[test]
    fn run_with_reports_counts_and_continues_nothing_when_done() {
        let _lock = capture_lock();
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/1.json"));
        let report = run_with(
            secret_targets(base.path(), None),
            |_| false,
            leaked_control(),
            |_, kind| match kind {
                Kind::File => Outcome::Stamped,
                Kind::Dir => Outcome::NotPrivate,
            },
        );
        assert_eq!(report.files_stamped, 1);
        assert!(report.not_private >= 1);
        assert!(!report.continued_in_background);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_a_no_op() {
        assert_eq!(run_label_upgrade(Path::new("/nonexistent")), None);
    }

    fn visited_names(targets: Vec<Target>) -> Vec<String> {
        let seen = RefCell::new(Vec::new());
        let mut walk = Walk::new(targets);
        let mut report = LabelUpgradeReport::default();
        let progress = walk.advance(
            Instant::now() + Duration::from_secs(30),
            None,
            &|path, _| {
                seen.borrow_mut().push(path.to_path_buf());
                Outcome::AlreadyLabeled
            },
            &mut report,
        );
        assert_eq!(progress, Progress::Done);
        seen.into_inner()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    // The base dir (depth 1) lists `messaging/` at depth 0 BEFORE messaging's own
    // depth-2 target is reached. The deeper visit must re-expand it, so a file two
    // levels down under the messaging subtree is covered. Reds with a plain
    // visited-set.
    #[test]
    fn a_deeper_later_target_re_expands_a_directory_first_seen_shallow() {
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("messaging/x/secret.json"));
        let names = visited_names(secret_targets(base.path(), None));
        assert!(names.contains(&"secret.json".to_string()), "{names:?}");
        assert_eq!(
            names.iter().filter(|n| *n == "messaging").count(),
            1,
            "re-expansion must not apply the directory twice"
        );
    }

    // The budget expires while a directory's children are already pushed (the apply of
    // the directory itself outlasts the deadline); resuming reaches the same totals. The
    // 300 ms between the 500 ms deadline and the 800 ms apply is the margin a loaded host
    // must not eat (the first 30 ms / 80 ms pair could invert under scheduling delay).
    #[test]
    fn a_cut_after_a_directorys_children_are_pushed_resumes_losslessly() {
        let base = tempfile::tempdir().unwrap();
        for n in 0..4 {
            touch(&base.path().join(format!("credentials/{n}.json")));
        }
        let target = || {
            vec![Target {
                path: base.path().join("credentials"),
                depth: 1,
            }]
        };
        let mut walk = Walk::new(target());
        let mut first = LabelUpgradeReport::default();
        let progress = walk.advance(
            Instant::now() + Duration::from_millis(500),
            None,
            &|path, kind| {
                if kind == Kind::Dir && path.ends_with("credentials") {
                    std::thread::sleep(Duration::from_millis(800));
                }
                Outcome::AlreadyLabeled
            },
            &mut first,
        );
        assert_eq!(progress, Progress::Budget);
        assert_eq!(first.entries_seen, 1, "only the directory was applied");
        let mut rest = LabelUpgradeReport::default();
        let progress = walk.advance(
            Instant::now() + Duration::from_secs(30),
            None,
            &|_, _| Outcome::AlreadyLabeled,
            &mut rest,
        );
        assert_eq!(progress, Progress::Done);
        assert_eq!(first.entries_seen + rest.entries_seen, 5);
    }

    // Which paths the background never walks: `credentials/`, `identities/` and every
    // `config-*/` slot dir directly under the base, nothing else. Reds if `config-*` were
    // dropped from the predicate (the refresher writes `config-N/.credentials.json`).
    #[test]
    fn hot_locations_are_credentials_identities_and_config_slots() {
        let base = Path::new("/accts");
        for hot in [
            "/accts/credentials",
            "/accts/credentials/1.json",
            "/accts/identities/u/credentials.json",
            "/accts/config-3",
            "/accts/config-3/.credentials.json",
        ] {
            assert!(is_hot(base, Path::new(hot)), "{hot}");
        }
        for cold in [
            "/accts",
            "/accts/pool/1.json",
            "/accts/configuration/x",
            "/accts/config",
            "/accts/pool/config-1",
            "/accts/term-1/config-1",
            "/other/credentials/1.json",
        ] {
            assert!(!is_hot(base, Path::new(cold)), "{cold}");
        }
    }

    // Pending work under the hot locations is dropped before the background hand-off.
    #[test]
    fn hot_roots_are_dropped_from_the_pending_work() {
        let base = tempfile::tempdir().unwrap();
        let mut walk = Walk::new(vec![
            Target {
                path: base.path().join("credentials"),
                depth: 1,
            },
            Target {
                path: base.path().join("identities/u"),
                depth: 1,
            },
            Target {
                path: base.path().join("config-1"),
                depth: 1,
            },
            Target {
                path: base.path().join("pool"),
                depth: 1,
            },
        ]);
        let dropped = walk.drop_matching(&|path| is_hot(base.path(), path));
        assert_eq!(dropped, 3);
        assert_eq!(walk.stack.len(), 1);
        assert!(walk.stack[0].0.ends_with("pool"));
    }

    // A stop request ends the walk at the next entry.
    #[test]
    fn a_stop_request_ends_the_walk() {
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/1.json"));
        let stop = AtomicBool::new(true);
        let mut walk = Walk::new(vec![Target {
            path: base.path().join("credentials"),
            depth: 1,
        }]);
        let mut report = LabelUpgradeReport::default();
        let progress = walk.advance(
            Instant::now() + Duration::from_secs(30),
            Some(&stop),
            &|_, _| Outcome::AlreadyLabeled,
            &mut report,
        );
        assert_eq!(progress, Progress::Stopped);
        assert_eq!(report.entries_seen, 0);
    }

    // The entry cap is reported as `capped`, and the flags land in the report.
    #[test]
    fn progress_is_recorded_in_the_report() {
        let mut report = LabelUpgradeReport::default();
        record(Progress::Capped, &mut report);
        assert!(report.capped && report.incomplete());
        let mut report = LabelUpgradeReport::default();
        record(Progress::Budget, &mut report);
        assert!(report.budget_exhausted && report.incomplete());
        assert!(!LabelUpgradeReport::default().incomplete());
    }

    // An over-budget foreground hands the rest to ONE background run and reports
    // `hot_unfinished` when credentials work was left; a second pass while the first
    // still runs starts no second walker. The first apply blocks until released.
    #[test]
    fn the_background_run_is_single_flight_and_skips_hot_roots() {
        use std::sync::{mpsc, Arc, Mutex};
        let _lock = capture_lock();
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/1.json"));
        for n in 0..3 {
            touch(&base.path().join(format!("pool/{n}.json")));
        }
        let control = leaked_control();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let visited = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let targets = || {
            vec![
                Target {
                    path: base.path().join("pool"),
                    depth: 1,
                },
                Target {
                    path: base.path().join("credentials"),
                    depth: 1,
                },
                Target {
                    path: base.path().join("config-1"),
                    depth: 1,
                },
            ]
        };
        touch(&base.path().join("config-1/.credentials.json"));
        let hot = |path: &Path| is_hot(base.path(), path);
        let (rx, seen) = (release_rx.clone(), visited.clone());
        // The first apply (foreground) outlasts the foreground budget.
        let first = run_with(targets(), hot, control, move |path, _| {
            seen.lock().unwrap().push(path.to_path_buf());
            if path.ends_with("pool") {
                std::thread::sleep(FOREGROUND_BUDGET + Duration::from_millis(200));
            } else if path.extension().is_some_and(|e| e == "json") {
                // background: wait for the release so the overlap can be observed
                let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(20));
            }
            Outcome::AlreadyLabeled
        });
        assert!(
            first.budget_exhausted && first.continued_in_background,
            "{first:?}"
        );
        assert!(first.hot_unfinished, "{first:?}");
        let second = run_with(targets(), hot, control, |path, _| {
            if path.ends_with("pool") {
                std::thread::sleep(FOREGROUND_BUDGET + Duration::from_millis(200));
            }
            Outcome::AlreadyLabeled
        });
        assert!(second.background_overlap, "{second:?}");
        drop(release_tx);
        let deadline = Instant::now() + Duration::from_secs(20);
        while control.background_running.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!control.background_running.load(Ordering::SeqCst));
        let seen = visited.lock().unwrap();
        assert!(
            !seen
                .iter()
                .any(|p| p.starts_with(base.path().join("credentials"))),
            "the background must not walk credentials/: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|p| p.starts_with(base.path().join("config-1"))),
            "the background must not walk config-*/: {seen:?}"
        );
        assert!(
            seen.iter().any(|p| p.ends_with("2.json")),
            "pool covered: {seen:?}"
        );
    }

    // A stop request that arrives while the foreground runs is not erased: no background
    // walk starts, and the report says it stopped. Reds if the stop token is registered
    // only after the foreground (the old shared flag was reset when the background slot was
    // claimed, with the same effect): the request then reaches no run and the background
    // visits `pool/*.json`.
    #[test]
    fn a_stop_during_the_foreground_starts_no_background_walk() {
        use std::sync::{Arc, Mutex};
        let _lock = capture_lock();
        let base = tempfile::tempdir().unwrap();
        for n in 0..3 {
            touch(&base.path().join(format!("pool/{n}.json")));
        }
        let control = leaked_control();
        let visited = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let seen = visited.clone();
        let report = run_with(
            vec![Target {
                path: base.path().join("pool"),
                depth: 1,
            }],
            |_| false,
            control,
            move |path, _| {
                seen.lock().unwrap().push(path.to_path_buf());
                if path.ends_with("pool") {
                    // The daemon is told to stop while the foreground is still busy, and
                    // the foreground then runs out of budget.
                    control.request_stop();
                    std::thread::sleep(FOREGROUND_BUDGET + Duration::from_millis(200));
                }
                Outcome::AlreadyLabeled
            },
        );
        assert!(report.stopped && report.budget_exhausted, "{report:?}");
        assert!(!report.continued_in_background, "{report:?}");
        // A background walk would have visited the three files within moments.
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline
            && !visited
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.extension().is_some_and(|e| e == "json"))
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let seen = visited.lock().unwrap();
        assert!(
            !seen
                .iter()
                .any(|p| p.extension().is_some_and(|e| e == "json")),
            "no background walk after a stop: {seen:?}"
        );
        assert!(!control.background_running.load(Ordering::SeqCst));
        assert!(
            control.runs.lock().unwrap().is_empty(),
            "token deregistered"
        );
    }

    // The watcher turns a cancelled shutdown token into a stop of the runs in flight, and
    // dropping it (an early return of the daemon entry point) ends it: a cancel after the
    // drop stops nothing. Reds if `Drop` did not abort the task (the task would still be
    // parked on the token and would stop the run once cancelled).
    #[test]
    fn the_stop_watcher_stops_runs_on_cancel_and_dies_with_its_guard() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let control = leaked_control();
            let live = control.register();
            let token = tokio_util::sync::CancellationToken::new();
            let watcher = spawn_stop_watcher_for(token.clone(), control);
            tokio::task::yield_now().await;
            assert!(!live.stopped());
            token.cancel();
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            assert!(live.stopped(), "a cancelled shutdown stops the run");
            drop(watcher);

            let control = leaked_control();
            let live = control.register();
            let token = tokio_util::sync::CancellationToken::new();
            let watcher = spawn_stop_watcher_for(token.clone(), control);
            tokio::task::yield_now().await;
            drop(watcher);
            token.cancel();
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            assert!(!live.stopped(), "a dropped watcher must not act");
        });
    }

    // The three reasons an object is refused on containment are told apart, so a
    // clean-looking pass cannot hide that nothing was labeled. Reds if any two collapse
    // to one outcome again (the old code returned `Reparse` for all three).
    #[test]
    fn containment_refusals_are_told_apart() {
        let roots = Roots::from_final_paths(
            Some("\\\\?\\C:\\acct"),
            Some("\\\\?\\C:\\home\\.gemini\\oauth_creds.json"),
        );
        assert_eq!(
            roots.refusal(Some("\\\\?\\C:\\acct\\credentials\\1.json")),
            None
        );
        assert_eq!(
            roots.refusal(Some("\\\\?\\C:\\home\\.gemini\\oauth_creds.json")),
            None
        );
        assert_eq!(
            roots.refusal(Some("\\\\?\\C:\\elsewhere\\1.json")),
            Some(Outcome::Reparse),
            "resolved outside the base: an intermediate link"
        );
        assert_eq!(roots.refusal(None), Some(Outcome::Unresolvable));
        let no_base = Roots::from_final_paths(None, Some("C:\\home\\.gemini\\oauth_creds.json"));
        assert!(no_base.base_unresolved());
        assert_eq!(
            no_base.refusal(Some("C:\\acct\\1.json")),
            Some(Outcome::OutsideRoots)
        );
        assert_eq!(
            no_base.refusal(Some("C:\\home\\.gemini\\oauth_creds.json")),
            None,
            "the exact gemini root still matches"
        );
        assert_eq!(no_base.refusal(None), Some(Outcome::Unresolvable));
    }

    // Both new outcomes are counted separately, make the pass incomplete, and are never
    // descended into.
    #[test]
    fn unresolvable_and_outside_roots_are_counted_and_make_the_pass_incomplete() {
        let base = tempfile::tempdir().unwrap();
        touch(&base.path().join("credentials/a/1.json"));
        touch(&base.path().join("credentials/b/2.json"));
        touch(&base.path().join("credentials/c/3.json"));
        let seen = RefCell::new(Vec::new());
        let mut walk = Walk::new(vec![Target {
            path: base.path().join("credentials"),
            depth: 3,
        }]);
        let mut report = LabelUpgradeReport::default();
        walk.advance(
            Instant::now() + Duration::from_secs(30),
            None,
            &|path, _| {
                seen.borrow_mut().push(path.to_path_buf());
                match path.file_name().and_then(|n| n.to_str()) {
                    Some("a") => Outcome::Unresolvable,
                    Some("b") => Outcome::OutsideRoots,
                    _ => Outcome::AlreadyLabeled,
                }
            },
            &mut report,
        );
        assert_eq!((report.unresolvable, report.outside_roots), (1, 1));
        assert_eq!(report.reparse_skipped, 0);
        assert!(report.incomplete(), "{report:?}");
        let seen = seen.borrow();
        assert!(!seen
            .iter()
            .any(|p| p.ends_with("1.json") || p.ends_with("2.json")));
        assert!(seen.iter().any(|p| p.ends_with("3.json")));
        let only_unresolvable = LabelUpgradeReport {
            unresolvable: 1,
            ..Default::default()
        };
        let only_outside = LabelUpgradeReport {
            outside_roots: 1,
            ..Default::default()
        };
        assert!(only_unresolvable.incomplete() && only_outside.incomplete());
    }

    // An unresolved base WARNs (fixed tag, no path); a resolved one is silent.
    #[test]
    fn an_unresolved_base_root_warns() {
        let ((), none) =
            capture(|| Roots::from_final_paths(Some("C:\\acct"), None).warn_if_base_unresolved());
        assert!(none.is_empty(), "{none:?}");
        let ((), warned) =
            capture(|| Roots::from_final_paths(None, None).warn_if_base_unresolved());
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert_eq!(warned[0].0, tracing::Level::WARN);
        assert!(
            warned[0].1.contains("label_upgrade_base_unresolved"),
            "{warned:?}"
        );
    }

    fn warns(report: &LabelUpgradeReport, phase: &'static str) -> Vec<String> {
        let ((), events) = capture(|| log(report, phase));
        events
            .into_iter()
            .filter(|(level, text)| {
                *level == tracing::Level::WARN && text.contains("label_upgrade_incomplete")
            })
            .map(|(_, text)| text)
            .collect()
    }

    // A foreground that ran out of budget and continued in the background logs no
    // "incomplete" WARN (the background reports its own outcome), but every reason that
    // really leaves locations uncovered still WARNs, with fields that name the real
    // reason. Reds if the foreground WARNed on `budget_exhausted` alone (the old
    // behaviour) or reported `budget_exhausted=false` for an overlap.
    #[test]
    fn only_a_real_coverage_gap_warns_and_the_fields_name_the_reason() {
        let handed_off = LabelUpgradeReport {
            budget_exhausted: true,
            continued_in_background: true,
            ..Default::default()
        };
        assert!(warns(&handed_off, "foreground").is_empty());

        let hot = LabelUpgradeReport {
            hot_unfinished: true,
            ..handed_off.clone()
        };
        let got = warns(&hot, "foreground");
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("hot_unfinished=true"), "{got:?}");

        let overlap = LabelUpgradeReport {
            budget_exhausted: true,
            background_overlap: true,
            ..Default::default()
        };
        let got = warns(&overlap, "foreground");
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("background_overlap=true"), "{got:?}");
        assert!(got[0].contains("budget_exhausted=true"), "{got:?}");

        let background_budget = LabelUpgradeReport {
            budget_exhausted: true,
            ..Default::default()
        };
        let got = warns(&background_budget, "background");
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("budget_exhausted=true"), "{got:?}");

        let capped = LabelUpgradeReport {
            capped: true,
            ..Default::default()
        };
        assert_eq!(warns(&capped, "foreground").len(), 1);
        assert!(warns(&LabelUpgradeReport::default(), "foreground").is_empty());
    }

    // Final-path comparison: verbatim/UNC prefixes, separators, the component boundary
    // (`C:\base2` is NOT inside `C:\base`) and EXACT case. Reds if `normalize_path`
    // folded case (`to_lowercase`): the case variants and the Kelvin-sign look-alike
    // below would then count as inside.
    #[test]
    fn final_path_containment_is_component_wise_and_exact() {
        let root = normalize_path("\\\\?\\C:\\Users\\Me\\.claude\\accounts");
        assert_eq!(root, "C:\\Users\\Me\\.claude\\accounts");
        for inside in [
            "\\\\?\\C:\\Users\\Me\\.claude\\accounts",
            "\\\\?\\C:\\Users\\Me\\.claude\\accounts\\credentials\\1.json",
            "C:/Users/Me/.claude/accounts/config-1/",
        ] {
            assert!(path_within(&normalize_path(inside), &root), "{inside}");
        }
        for outside in [
            "\\\\?\\C:\\Users\\Me\\.claude\\accounts2\\x",
            "\\\\?\\C:\\Users\\Me\\.claude",
            "\\\\?\\D:\\Users\\Me\\.claude\\accounts",
            "\\\\?\\UNC\\host\\share\\accounts",
            // Case differs: GetFinalPathNameByHandleW reports one spelling per object, so
            // another spelling is another object.
            "\\\\?\\c:\\users\\me\\.CLAUDE\\accounts\\credentials\\1.json",
            "\\\\?\\C:\\Users\\Me\\.claude\\Accounts",
        ] {
            assert!(!path_within(&normalize_path(outside), &root), "{outside}");
        }
        assert_eq!(
            normalize_path("\\\\?\\UNC\\Host\\Share\\A"),
            "\\\\Host\\Share\\A"
        );
    }

    // U+212A KELVIN SIGN lower-cases to ASCII `k`, so a case-folding comparison would
    // treat a directory named with it as the root `Kids`. Non-vacuity: the premise below
    // proves the look-alike folds to the same text.
    #[test]
    fn a_kelvin_sign_look_alike_is_not_inside_the_root() {
        assert_eq!("\u{212A}ids".to_lowercase(), "kids", "premise");
        let root = normalize_path("\\\\?\\C:\\Users\\Me\\Kids");
        let look_alike = normalize_path("\\\\?\\C:\\Users\\Me\\\u{212A}ids\\secret.json");
        assert!(!path_within(&look_alike, &root));
        assert!(path_within(
            &normalize_path("\\\\?\\C:\\Users\\Me\\Kids\\secret.json"),
            &root
        ));
    }
}
