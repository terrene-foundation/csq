//! Archive health: warns when the operator's R2 auto-upload or local
//! auto-delete is not active (an internal ticket).
//!
//! The archive lives in `<home>/.config/csq-archive` and is OPT-IN BY
//! PRESENCE: when that directory does not exist, [`check`] returns
//! [`ArchiveHealth::NotConfigured`] and no surface shows anything.
//!
//! Five checks, each three-state ([`CheckState`]): launchd jobs loaded, nightly
//! upload recent (`log/last-success.json`, 26 h), hourly upload recent
//! (`log/heartbeat-A.json`, 2 h), local delete active
//! (`log/heartbeat-delete.json`, 26 h, plus the newest outcome in
//! `log/deleted.jsonl`), pause marker. Each heartbeat is
//! `{"last_success":"<RFC3339 UTC>"}`. Unreadable or malformed state is
//! `Unknown`, never `Ok`. The module is read-only: it never starts or stops a
//! job, touches no keychain and reads no secret (only the heartbeat
//! `last_success` fields, the `event` field of the capped `deleted.jsonl` tail,
//! the `PAUSED` marker's first line, and `launchctl print`). Every state file is
//! opened `O_NOFOLLOW|O_NONBLOCK` and must be a regular file, so a symlink
//! cannot redirect a read and a FIFO cannot block a render. The clock is
//! injected (`now`), never read here.
//!
//! WRITER CONTRACT (the archive scripts, pinned in spec 13 §9 v35):
//! `log/last-success.json` is written when the nightly upload exits 0;
//! `log/heartbeat-A.json` only when `archive.sh A` (the hourly job) exits 0;
//! `log/heartbeat-delete.json` ONLY when the delete step exits 0 (also when
//! nothing was deletable). Each is `{"last_success":"<RFC3339 UTC>"}`, written
//! atomically (tmp + mv). A failing run writes no heartbeat, so its age grows
//! and the check warns; the next successful run clears it.

pub mod footprint;

use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The hourly upload heartbeat (`log/heartbeat-A.json`) is stale past this. The
/// margin is one whole missed hourly run (2 x the 1 h cadence): a single slow or
/// skipped run does not warn; two in a row does.
pub const HOT_STALE_AFTER_SECS: i64 = 2 * 3600;
/// An upload or delete older than this is stale (26 h = a nightly cadence plus slack).
pub const STALE_AFTER_SECS: i64 = 26 * 3600;
/// Clock skew tolerated before a timestamp counts as "in the future".
const FUTURE_SKEW_SECS: i64 = 300;
/// The two upload LaunchAgents, named by the ROLE in their plist file name:
/// `<stem>.csq-archive.<role>.plist`. The stem is the operator's own
/// reverse-DNS prefix, so it is DISCOVERED from `~/Library/LaunchAgents`,
/// never assumed here — no organisation label belongs in shipped code.
pub const UPLOAD_ROLES: [&str; 2] = ["hot", "nightly"];
/// Cap on any state file read.
const READ_CAP: u64 = 64 * 1024;
/// Longest pause reason shown.
const REASON_MAX_CHARS: usize = 200;
/// Wall-clock cap on the `launchctl` probe.
pub const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(2);

/// Three-state result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "lowercase")]
pub enum CheckState {
    /// The check passed.
    Ok,
    /// The check failed; the string says why.
    Warn(String),
    /// The state could not be read or judged; the string says why.
    Unknown(String),
}

impl CheckState {
    /// True only for `Ok`.
    pub fn is_ok(&self) -> bool {
        matches!(self, CheckState::Ok)
    }
}

/// The four checks, evaluated when the archive is configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveChecks {
    /// Both upload LaunchAgents are loaded.
    pub upload_jobs: CheckState,
    /// `log/last-success.json` (nightly upload) is younger than 26 h.
    pub upload_recent: CheckState,
    /// `log/heartbeat-A.json` (hourly upload) is younger than 2 h.
    pub upload_recent_hot: CheckState,
    /// `log/heartbeat-delete.json` is younger than 26 h and the last delete
    /// run recorded in `log/deleted.jsonl` did not end in a failure.
    pub delete_active: CheckState,
    /// No `PAUSED` marker (WARN carries its date and reason).
    pub paused: CheckState,
    /// Per-check fix hints, computed where the discovery and probe results are
    /// known. `serde(skip)`: each finding carries its own `hint` on the wire.
    #[serde(skip)]
    hints: [String; 5],
}

/// One non-OK check, with a one-line fix hint, for any surface to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveFinding {
    /// Stable id: `upload_jobs`, `upload_recent`, `delete_active` or `paused`.
    pub check: &'static str,
    /// `Warn` or `Unknown` (never `Ok`).
    pub state: CheckState,
    /// One-line fix hint. Dynamic because it names the agent discovered for
    /// THIS role: a bootstrap command for the exact plist, never a wildcard.
    pub hint: String,
}

impl ArchiveChecks {
    /// Every non-OK check, in a fixed order, each with the hint computed for
    /// its own state (see [`check_jobs`] for the upload-job hints).
    pub fn findings(&self) -> Vec<ArchiveFinding> {
        let rows: [(&'static str, &CheckState); 5] = [
            ("upload_jobs", &self.upload_jobs),
            ("upload_recent", &self.upload_recent),
            ("upload_recent_hot", &self.upload_recent_hot),
            ("delete_active", &self.delete_active),
            ("paused", &self.paused),
        ];
        rows.into_iter()
            .enumerate()
            .filter(|(_, (_, s))| !s.is_ok())
            .map(|(i, (check, s))| ArchiveFinding {
                check,
                state: s.clone(),
                hint: self.hints[i].clone(),
            })
            .collect()
    }

    /// True when any check is WARN (an UNKNOWN alone is not a confirmed failure).
    pub fn any_warn(&self) -> bool {
        self.findings()
            .iter()
            .any(|f| matches!(f.state, CheckState::Warn(_)))
    }
}

/// Overall archive health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveHealth {
    /// `<home>/.config/csq-archive` does not exist: show nothing anywhere.
    NotConfigured,
    /// The archive exists; here are its checks.
    ///
    /// Boxed: `ArchiveChecks` is five `CheckState`s plus five hint `String`s
    /// (~280 bytes), and every `ArchiveHealth` that is `NotConfigured` — the
    /// common case on a host with no archive — would otherwise pay that size
    /// twice over (`clippy::large_enum_variant`, `-D warnings` in CI).
    Configured(Box<ArchiveChecks>),
}

impl ArchiveHealth {
    /// The checks, or `None` when not configured.
    pub fn checks(&self) -> Option<&ArchiveChecks> {
        match self {
            ArchiveHealth::NotConfigured => None,
            ArchiveHealth::Configured(c) => Some(c.as_ref()),
        }
    }
}

/// Answer of a launchd probe for one label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchdState {
    /// The job is loaded.
    Loaded,
    /// launchd says the job is not loaded.
    NotLoaded,
    /// The probe could not answer (reason).
    Unknown(String),
}

/// Injectable launchd query, so tests never shell out.
pub trait LaunchdProbe {
    /// Is the LaunchAgent `label` loaded in the current user's GUI domain?
    fn state(&self, label: &str) -> LaunchdState;

    /// `Some(reason)` when this host cannot answer at all (no launchd), so the
    /// caller reports UNKNOWN instead of inventing a not-loaded verdict from a
    /// label it could never have found.
    fn unavailable(&self) -> Option<String> {
        None
    }
}

/// The real probe: `launchctl print gui/<uid>/<label>`, macOS only, 2 s cap.
pub struct SystemLaunchd;

impl LaunchdProbe for SystemLaunchd {
    #[cfg(target_os = "macos")]
    fn state(&self, label: &str) -> LaunchdState {
        use std::process::{Command, Stdio};
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut child = match Command::new("/bin/launchctl")
            .args(["print", &format!("gui/{uid}/{label}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return LaunchdState::Unknown(format!("launchctl did not start: {}", e.kind()))
            }
        };
        let deadline = std::time::Instant::now() + LAUNCHCTL_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return match status.code() {
                        Some(0) => LaunchdState::Loaded,
                        // 113: "Could not find service" — the job is not loaded.
                        Some(113) => LaunchdState::NotLoaded,
                        other => LaunchdState::Unknown(format!(
                            "launchctl exited {}",
                            other.map_or("by signal".to_string(), |c| c.to_string())
                        )),
                    };
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return LaunchdState::Unknown("launchctl timed out".into());
                }
                Err(e) => {
                    return LaunchdState::Unknown(format!("launchctl wait failed: {}", e.kind()))
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn state(&self, _label: &str) -> LaunchdState {
        LaunchdState::Unknown("no launchd".into())
    }

    #[cfg(not(target_os = "macos"))]
    fn unavailable(&self) -> Option<String> {
        Some("no launchd".into())
    }
}

/// A probe that never runs `launchctl`: every label is `Unknown("skipped")`.
/// The statusline path uses it so a render never spawns a process.
pub struct SkipLaunchd;

impl LaunchdProbe for SkipLaunchd {
    fn state(&self, _label: &str) -> LaunchdState {
        LaunchdState::Unknown("launchd not checked on this path".into())
    }

    fn unavailable(&self) -> Option<String> {
        Some("launchd not checked on this path".into())
    }
}

/// `<home>` when `base_dir` is `<home>/.claude/accounts`; `None` otherwise (a
/// relocated base dir must not make a caller read the real `$HOME`).
pub fn home_of_base(base_dir: &Path) -> Option<PathBuf> {
    let claude = base_dir.parent()?;
    if base_dir.file_name()? != "accounts" || claude.file_name()? != ".claude" {
        return None;
    }
    claude.parent().map(Path::to_path_buf)
}

/// Short fixed statusline badges, deduplicated, in a fixed order. Fixed strings
/// only: no file content ever reaches the statusline. WARN on a job, the pause
/// marker, an upload or the delete gives `backup off` / `backup stale` /
/// `delete off`; UNKNOWN on any FILE-based check gives `backup ?` (an
/// unreadable or malformed state must not look healthy). Only the launchd check
/// stays silent when UNKNOWN, because the statusline path skips it by design
/// ([`SkipLaunchd`]); `csq doctor` shows it.
pub fn statusline_badges(c: &ArchiveChecks) -> Vec<&'static str> {
    let warn = |s: &CheckState| matches!(s, CheckState::Warn(_));
    let unknown = |s: &CheckState| matches!(s, CheckState::Unknown(_));
    let mut out = Vec::new();
    if warn(&c.upload_jobs) || warn(&c.paused) {
        out.push("\u{26a0} backup off");
    }
    if warn(&c.upload_recent) || warn(&c.upload_recent_hot) {
        out.push("\u{26a0} backup stale");
    }
    if warn(&c.delete_active) {
        out.push("\u{26a0} delete off");
    }
    if [
        &c.upload_recent,
        &c.upload_recent_hot,
        &c.delete_active,
        &c.paused,
    ]
    .into_iter()
    .any(unknown)
    {
        out.push("\u{26a0} backup ?");
    }
    out
}

/// The archive directory under `home`.
pub fn archive_dir(home: &Path) -> PathBuf {
    home.join(".config").join("csq-archive")
}

/// Evaluate archive health. `now` is injected; nothing here reads the clock.
pub fn check(home: &Path, now: SystemTime, launchd: &dyn LaunchdProbe) -> ArchiveHealth {
    let dir = archive_dir(home);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ArchiveHealth::NotConfigured,
        Err(e) => {
            // Present-but-unstat-able is still "configured": fail visible.
            let u = CheckState::Unknown(format!("archive dir unreadable: {}", e.kind()));
            let hint = "make ~/.config/csq-archive readable".to_string();
            return ArchiveHealth::Configured(Box::new(ArchiveChecks {
                upload_jobs: u.clone(),
                upload_recent: u.clone(),
                upload_recent_hot: u.clone(),
                delete_active: u.clone(),
                paused: u,
                hints: std::array::from_fn(|_| hint.clone()),
            }));
        }
    }
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (upload_jobs, upload_jobs_hint) = check_jobs(launchd, home);
    ArchiveHealth::Configured(Box::new(ArchiveChecks {
        upload_jobs,
        upload_recent: check_heartbeat(
            &dir,
            "log/last-success.json",
            STALE_AFTER_SECS,
            "upload has never succeeded (no last-success.json)",
            "last upload",
            "26h",
            now_secs,
        ),
        upload_recent_hot: check_heartbeat(
            &dir,
            "log/heartbeat-A.json",
            HOT_STALE_AFTER_SECS,
            "hourly upload has never reported (no heartbeat-A.json)",
            "last hourly upload",
            "2h",
            now_secs,
        ),
        delete_active: check_delete_active(&dir, now_secs),
        paused: check_paused(&dir),
        hints: [
            upload_jobs_hint,
            "run the nightly archive upload and check ~/.config/csq-archive/log/launchd-nightly.err"
                .to_string(),
            "run the hourly upload job and check ~/.config/csq-archive/log/launchd-hot.err"
                .to_string(),
            "the next successful delete run clears this: schedule confirm-uploaded.sh then delete-confirmed.sh --apply (nightly step or LaunchAgent) and check its log".to_string(),
            "remove ~/.config/csq-archive/PAUSED to resume once the pending fix is installed"
                .to_string(),
        ],
    }))
}

/// What discovery found for one upload role.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleLabel {
    /// Exactly one regular, uid-owned, safely-named plist matched.
    Found { label: String, path: PathBuf },
    /// No plist matched: the role is not installed for this user.
    Absent,
    /// More than one matched: a caller must never pick one.
    Ambiguous(usize),
    /// The directory or a candidate could not be read, or a candidate is not a
    /// safe name. Never a silent skip: an unmeasured role is not a healthy one.
    Unknown(String),
}

/// A label that may be rendered and passed to `launchctl` verbatim: it starts
/// with an ASCII alphanumeric and holds only `[A-Za-z0-9._-]`, 1..=200 bytes.
fn label_is_safe(stem: &str) -> bool {
    let mut chars = stem.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && stem.len() <= 200
        && stem
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The current real uid, the same identity the launchctl probe uses.
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

fn discover_role(home: &Path, role: &str) -> RoleLabel {
    discover_role_as(home, role, current_uid())
}

/// Discover one role's LaunchAgent label from `<home>/Library/LaunchAgents`.
///
/// Only a REGULAR file owned by `uid` counts. A symlink is never followed
/// (`symlink_metadata` decides), plist CONTENT is never read — the label is the
/// file name without its `.plist` suffix — and the stem must pass
/// [`label_is_safe`]. A missing directory is Absent; any other read failure, an
/// unreadable candidate, a non-UTF-8 name that carries the role suffix, or an
/// unsafe stem is Unknown, never a silent skip.
fn discover_role_as(home: &Path, role: &str, uid: u32) -> RoleLabel {
    // The ownership filter below is `#[cfg(unix)]`; off Unix the parameter has
    // no reader and would be an unused-variable warning under `-D warnings`.
    #[cfg(not(unix))]
    let _ = uid;
    let dir = home.join("Library").join("LaunchAgents");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RoleLabel::Absent,
        Err(e) => {
            return RoleLabel::Unknown(format!("LaunchAgents unreadable: {}", e.kind()));
        }
    };
    let suffix = format!(".csq-archive.{}.plist", role);
    let mut matches = 0usize;
    let mut found: Option<(String, PathBuf)> = None;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                return RoleLabel::Unknown(format!("LaunchAgents entry unreadable: {}", e.kind()))
            }
        };
        let name_os = entry.file_name();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            if !name_os.as_bytes().ends_with(suffix.as_bytes()) {
                continue;
            }
        }
        #[cfg(not(unix))]
        {
            if !name_os.to_string_lossy().ends_with(&suffix) {
                continue;
            }
        }
        let Some(name) = name_os.to_str() else {
            // It carries the role suffix but its bytes are not a name we can
            // render: refuse the role rather than pretend it is absent.
            return RoleLabel::Unknown("LaunchAgent name is not valid UTF-8".to_string());
        };
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => return RoleLabel::Unknown(format!("LaunchAgent unreadable: {}", e.kind())),
        };
        if !meta.file_type().is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                continue;
            }
        }
        let stem = name.strip_suffix(".plist").unwrap_or(name);
        if !label_is_safe(stem) {
            // The name itself is NEVER echoed: it failed validation precisely
            // because it is not safe to render, so quoting it (sanitized or
            // not) would hand the terminal the bytes the check rejects.
            return RoleLabel::Unknown(
                "a LaunchAgent file carrying the role has an unsafe label name".to_string(),
            );
        }
        matches += 1;
        if matches == 1 {
            found = Some((stem.to_string(), path));
        }
    }
    match matches {
        0 => RoleLabel::Absent,
        1 => match found {
            Some((label, path)) => RoleLabel::Found { label, path },
            // Unreachable by construction, but a lost candidate must never
            // read as a healthy role.
            None => RoleLabel::Unknown("LaunchAgent candidate lost during scan".to_string()),
        },
        n => RoleLabel::Ambiguous(n),
    }
}

/// The `$HOME/Library/LaunchAgents/<filename>` spelling of a discovered agent,
/// for a hint. Never the absolute path: the operator's home directory does not
/// belong on a surface that another surface has to redact afterwards.
///
/// `$HOME` rather than `~` because a hint is a command an operator copies into
/// their shell, and tilde expansion applies ONLY to an UNQUOTED tilde-prefix
/// (plus a few assignment contexts): `'~/x'` reaches `launchctl` as the literal
/// three characters, and `"~/x"` is not expanded either. `$HOME` DOES expand
/// inside the double quotes the hint uses, and the file name is already
/// `[A-Za-z0-9._-]` (`label_is_safe`), so no character that the quotes would
/// have to escape can appear inside them.
fn agent_path_for_hint(path: &Path) -> String {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => format!("$HOME/Library/LaunchAgents/{name}"),
        None => "$HOME/Library/LaunchAgents".to_string(),
    }
}

/// The launchd check AND its hint. WARN outranks UNKNOWN: one missing agent is
/// a confirmed failure whatever the other role's measurement says, so an
/// ambiguous or unreadable role never hides it.
fn check_jobs(launchd: &dyn LaunchdProbe, home: &Path) -> (CheckState, String) {
    if let Some(reason) = launchd.unavailable() {
        return (
            CheckState::Unknown(reason),
            "run `launchctl print gui/$UID/<label>` on a host with launchd".to_string(),
        );
    }
    let mut warn: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut hints: Vec<String> = Vec::new();
    for role in UPLOAD_ROLES {
        match discover_role(home, role) {
            RoleLabel::Found { label, path } => {
                let at = agent_path_for_hint(&path);
                match launchd.state(&label) {
                    LaunchdState::Loaded => {}
                    LaunchdState::NotLoaded => {
                        warn.push(format!("upload job not loaded: {}", label));
                        hints.push(format!(
                            "review \"{at}\", then: launchctl bootstrap gui/$UID \"{at}\""
                        ));
                    }
                    LaunchdState::Unknown(r) => {
                        unknown.push(r);
                        hints.push(format!(
                            "check \"launchctl print gui/$UID/{label}\" for \"{at}\""
                        ));
                    }
                }
            }
            RoleLabel::Absent => {
                warn.push(format!(
                    "upload job not installed (no *.csq-archive.{}.plist)",
                    role
                ));
                hints.push(format!(
                    "create \"$HOME/Library/LaunchAgents/<label>.csq-archive.{}.plist\"",
                    role
                ));
            }
            RoleLabel::Ambiguous(n) => {
                unknown.push(format!(
                    "{} LaunchAgents match *.csq-archive.{}.plist; refusing to pick one",
                    n, role
                ));
                hints.push(format!(
                    "keep exactly one *.csq-archive.{}.plist ({} found)",
                    role, n
                ));
            }
            RoleLabel::Unknown(r) => {
                unknown.push(r);
                hints.push(format!("fix ~/Library/LaunchAgents for role {}", role));
            }
        }
    }
    let hint = hints.join("; ");
    if !warn.is_empty() {
        (CheckState::Warn(warn.join("; ")), hint)
    } else if !unknown.is_empty() {
        // Every unmeasurable role is named: reporting only the first would hide
        // the second role's unknown behind the first's.
        (CheckState::Unknown(unknown.join("; ")), hint)
    } else {
        (CheckState::Ok, String::new())
    }
}

/// Why a state file could not be opened as a regular file.
enum OpenErr {
    NotRegular,
    Io(std::io::ErrorKind),
}

impl OpenErr {
    fn why(&self) -> String {
        match self {
            OpenErr::NotRegular => "not a regular file".to_string(),
            OpenErr::Io(k) => k.to_string(),
        }
    }
}

/// Opens a state file read-only WITHOUT following a symlink (`O_NOFOLLOW`) and
/// WITHOUT blocking on a FIFO (`O_NONBLOCK`), then `fstat`s the OPENED handle and
/// requires a regular file. `Ok(None)` = absent. A symlink fails the open, a
/// FIFO/device/directory fails the fstat check: so a state file can neither
/// redirect a read at a credential file nor hang a statusline render.
fn open_regular(path: &Path) -> Result<Option<std::fs::File>, OpenErr> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err(OpenErr::NotRegular),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let f = match o.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(OpenErr::Io(e.kind())),
    };
    match f.metadata() {
        Ok(m) if m.is_file() => Ok(Some(f)),
        Ok(_) => Err(OpenErr::NotRegular),
        Err(e) => Err(OpenErr::Io(e.kind())),
    }
}

/// Age in seconds of an RFC3339 or epoch-seconds JSON value, or why not.
fn age_of(v: &serde_json::Value, now_secs: i64) -> Result<i64, String> {
    let ts = match v {
        serde_json::Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|_| "timestamp is not RFC3339".to_string())?
            .timestamp(),
        serde_json::Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
            .ok_or_else(|| "timestamp is not a number".to_string())?,
        _ => return Err("timestamp has an unexpected type".into()),
    };
    let age = now_secs
        .checked_sub(ts)
        .ok_or_else(|| "timestamp is out of range".to_string())?;
    if age < -FUTURE_SKEW_SECS {
        return Err("timestamp is in the future".into());
    }
    Ok(age.max(0))
}

fn fmt_age(secs: i64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}m", secs / 60)
    }
}

/// Reads one `{"last_success":"<RFC3339>"}` heartbeat file under the archive dir:
/// `Ok(None)` = absent, `Ok(Some((ts, age)))` = unix seconds and age, `Err` =
/// UNKNOWN for an unreadable, malformed, out-of-range or future file.
fn read_heartbeat(dir: &Path, rel: &str, now_secs: i64) -> Result<Option<(i64, i64)>, CheckState> {
    let file = match open_regular(&dir.join(rel)) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(CheckState::Unknown(format!(
                "{rel} unreadable: {}",
                e.why()
            )))
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = file.take(READ_CAP).read_to_end(&mut buf) {
        return Err(CheckState::Unknown(format!(
            "{rel} unreadable: {}",
            e.kind()
        )));
    }
    let json: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|_| CheckState::Unknown(format!("{rel} is not valid JSON")))?;
    let Some(field) = json.get("last_success") else {
        return Err(CheckState::Unknown(format!("{rel} has no last_success")));
    };
    let age = age_of(field, now_secs)
        .map_err(|r| CheckState::Unknown(format!("{rel} last_success: {r}")))?;
    Ok(Some((now_secs - age, age)))
}

/// One heartbeat check: absent = WARN(`absent_msg`), older than `limit_secs` =
/// WARN, unreadable, malformed or out-of-range = UNKNOWN, never OK.
fn check_heartbeat(
    dir: &Path,
    rel: &str,
    limit_secs: i64,
    absent_msg: &str,
    what: &str,
    limit_label: &str,
    now_secs: i64,
) -> CheckState {
    match read_heartbeat(dir, rel, now_secs) {
        Err(u) => u,
        Ok(None) => CheckState::Warn(absent_msg.to_string()),
        Ok(Some((_, age))) if age >= limit_secs => {
            CheckState::Warn(format!("{what} {} ago (limit {limit_label})", fmt_age(age)))
        }
        Ok(Some(_)) => CheckState::Ok,
    }
}

/// A trailing `intent` older than this is a delete run that died mid-unlink.
const STALE_INTENT_SECS: i128 = 600;

/// `delete_active`. WRITER CONTRACT (pinned in spec 13 §9, v35): the nightly delete
/// step writes `log/heartbeat-delete.json` ONLY when `delete-confirmed.sh --apply`
/// exits 0 (also when nothing was deletable), so a run with any failure writes no
/// heartbeat. The check is OK only when all three hold. First, the heartbeat is
/// younger than 26 h. Second, no `failed_after_intent` / `aborted_*` record in the
/// capped tail of `log/deleted.jsonl` has an `at_ns` NEWER than the heartbeat (a
/// failure inside a run that later recovered still counts: that run exited
/// non-zero). Third, the newest record is not an `intent` older than 10 minutes (a
/// run that died between intent and outcome). The next successful run rewrites the
/// heartbeat and clears the second and third. Records are
/// `{path, sha256, snapshot, size, event, at_ns}` from `delete-confirmed.sh`.
fn check_delete_active(dir: &Path, now_secs: i64) -> CheckState {
    let hb = match read_heartbeat(dir, "log/heartbeat-delete.json", now_secs) {
        Err(u) => return u,
        Ok(None) => {
            return CheckState::Warn("local delete has never run / is not scheduled".into())
        }
        Ok(Some((ts, age))) => {
            if age >= STALE_AFTER_SECS {
                return CheckState::Warn(format!(
                    "last local delete {} ago (limit 26h)",
                    fmt_age(age)
                ));
            }
            ts
        }
    };
    match delete_tail_failure(
        dir,
        i128::from(hb) * 1_000_000_000,
        i128::from(now_secs) * 1_000_000_000,
    ) {
        Ok(None) => CheckState::Ok,
        Ok(Some(why)) => CheckState::Warn(why.to_string()),
        Err(u) => u,
    }
}

/// Scans the capped tail of `deleted.jsonl` per the [`check_delete_active`] contract.
/// `Ok(None)` = no failure newer than the heartbeat and no stale trailing intent.
fn delete_tail_failure(
    dir: &Path,
    hb_ns: i128,
    now_ns: i128,
) -> Result<Option<&'static str>, CheckState> {
    use std::io::{Seek, SeekFrom};
    let unreadable = |w: String| CheckState::Unknown(format!("deleted.jsonl unreadable: {w}"));
    let mut file = match open_regular(&dir.join("log/deleted.jsonl")) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(None),
        Err(e) => return Err(unreadable(e.why())),
    };
    let len = file
        .metadata()
        .map_err(|e| unreadable(e.kind().to_string()))?
        .len();
    let truncated = len > READ_CAP;
    if truncated {
        file.seek(SeekFrom::Start(len - READ_CAP))
            .map_err(|e| unreadable(e.kind().to_string()))?;
    }
    let mut buf = Vec::new();
    file.take(READ_CAP)
        .read_to_end(&mut buf)
        .map_err(|e| unreadable(e.kind().to_string()))?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if truncated {
        lines.next(); // the first line of a mid-file window is partial
    }
    let mut failure: Option<&'static str> = None;
    // newest known record: (is_intent, at_ns)
    let mut newest: Option<(bool, Option<i128>)> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let kind = match v.get("event").and_then(|e| e.as_str()) {
            Some("intent") => "intent",
            Some("deleted") => "deleted",
            Some("failed_after_intent") => "failed_after_intent",
            Some("aborted_tomb_left") => "aborted_tomb_left",
            Some("aborted_restored") => "aborted_restored",
            _ => continue, // unknown events carry no verdict
        };
        let at_ns = v.get("at_ns").and_then(|n| n.as_i64()).map(i128::from);
        newest = Some((kind == "intent", at_ns));
        if kind.starts_with("failed_") || kind.starts_with("aborted_") {
            // no usable at_ns: it cannot be proven older than the heartbeat
            if at_ns.is_none_or(|t| t > hb_ns) {
                failure = Some(match kind {
                    "failed_after_intent" => "last delete run ended in failed_after_intent",
                    "aborted_tomb_left" => "last delete run ended in aborted_tomb_left",
                    _ => "last delete run ended in aborted_restored",
                });
            }
        }
    }
    if failure.is_some() {
        return Ok(failure);
    }
    Ok(match newest {
        Some((true, at)) if at.is_none_or(|t| now_ns - t > STALE_INTENT_SECS * 1_000_000_000) => {
            Some("last delete run left an unfinished unlink (intent older than 10 min)")
        }
        _ => None,
    })
}

/// Invisible "format" characters that `is_control` misses and that can reorder,
/// spoof or smuggle text: the whole Unicode general category Cf, the line and
/// paragraph separators (Zl/Zp), the entire Tag block U+E0000..U+E007F, and the
/// invisible combining/filler characters that render as nothing but re-present
/// the glyphs around them — the variation selectors (U+FE00..=U+FE0F,
/// U+E0100..=U+E01EF), the combining grapheme joiner (U+034F) and the Hangul
/// fillers (U+115F, U+1160, U+3164, U+FFA0). The Cf ranges are those of Unicode
/// 15.1 (`DerivedGeneralCategory`).
///
/// The variation selectors are stripped HERE and only here, not in the shared
/// display predicate: they are load-bearing inside emoji presentation (❤️), so
/// stripping them from arbitrary third-party output would corrupt it, while a
/// PAUSE REASON is prose where they can only hide a glyph (R3 security
/// review's S-3).
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891
        | 0x08E2 | 0x115F..=0x1160 | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
        | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0000..=0xE007F | 0xE0100..=0xE01EF)
}

/// `PAUSED` present means the archive scripts are paused, whatever the marker's
/// content: present-but-unreadable (a directory, a FIFO, a symlink, no
/// permission) is therefore WARN, never UNKNOWN. The reason is the first line,
/// filtered of control and format characters, token-redacted over the WHOLE line
/// (bounded by `READ_CAP`), and only THEN truncated: a key that straddles the cut
/// cannot escape a length-thresholded redaction pattern.
fn check_paused(dir: &Path) -> CheckState {
    let path = dir.join("PAUSED");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CheckState::Ok,
        Err(_) => return CheckState::Warn("archive paused (marker state unreadable)".into()),
        Ok(_) => {}
    }
    let unreadable = || CheckState::Warn("archive paused (reason unreadable)".into());
    let file = match open_regular(&path) {
        Ok(Some(f)) => f,
        Ok(None) => return CheckState::Ok, // removed between the two calls
        Err(_) => return unreadable(),
    };
    let mut buf = Vec::new();
    if file.take(READ_CAP).read_to_end(&mut buf).is_err() {
        return unreadable();
    }
    let text = String::from_utf8_lossy(&buf);
    let filtered: String = text
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .collect();
    let redacted = crate::error::redact_tokens(filtered.trim());
    let line: String = redacted.chars().take(REASON_MAX_CHARS).collect();
    CheckState::Warn(if line.is_empty() {
        "archive paused (marker has no reason)".to_string()
    } else {
        format!("archive paused: {line}")
    })
}

#[cfg(test)]
mod tests;
